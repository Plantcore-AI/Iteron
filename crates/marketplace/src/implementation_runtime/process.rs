use super::{
    ImplementationRuntime, ImplementationRuntimeError, Input, Output, RuntimeEvidence, RuntimeState,
};
use crate::implementation::{
    IMPLEMENTATION_PROCESS_PROTOCOL_VERSION, MAX_IMPLEMENTATION_ARG_BYTES, MAX_IMPLEMENTATION_ARGV,
    MAX_IMPLEMENTATION_ARGV_BYTES, MAX_IMPLEMENTATION_CANCELLATION_MS,
    MAX_IMPLEMENTATION_EVIDENCE_BYTES, MAX_IMPLEMENTATION_OBSERVATIONS,
    MAX_IMPLEMENTATION_RUNTIME_MS, ProcessLaunchPlan,
};
use crate::implementation_protocol::{
    ImplementationProtocolError, MAX_IMPLEMENTATION_MESSAGE_BYTES,
};
use iteron_tunables::{
    CapabilitySeamNode, ModuleId, capability_seam_graph, validate_capability_seam_graph,
};
use sha2::Digest as _;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

impl ImplementationRuntime {
    /// Spawn a direct child from a registry-minted plan after revalidating its content binding.
    pub fn launch(plan: ProcessLaunchPlan) -> Result<Self, ImplementationRuntimeError> {
        validate_plan(&plan)?;
        let seam = seam(plan.module())?;
        let expected = normalized_digest(plan.artifact_sha256())?;
        let program = canonical_program(plan.program())?;
        verify_program(&program, expected)?;

        let mut command = Command::new(&program);
        command
            .args(plan.argv())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        let mut child = command.spawn().map_err(|error| io("spawn", error))?;
        let child_pid = Some(child.id());
        if let Err(error) = verify_program(&program, expected) {
            kill_process_group(child_pid);
            kill_and_reap(&mut child);
            return Err(error);
        }
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            kill_process_group(child_pid);
            kill_and_reap(&mut child);
            return Err(ImplementationRuntimeError::InvalidPlan(
                "provider pipe unavailable",
            ));
        };
        let (input_tx, input_rx) = mpsc::channel();
        let (output_tx, output_rx) = mpsc::channel();
        let threads = vec![
            spawn_writer(stdin, input_rx, output_tx.clone()),
            spawn_stdout(
                stdout,
                plan.evidence_limits().stdout_bytes,
                output_tx.clone(),
            ),
            spawn_stderr(stderr, plan.evidence_limits().stderr_bytes, output_tx),
        ];
        Ok(Self {
            plan,
            seam,
            child: Some(child),
            child_pid,
            input: Some(input_tx),
            output: output_rx,
            threads,
            started_at: Instant::now(),
            next_request: 1,
            stdin_bytes: 0,
            evidence: RuntimeEvidence {
                stdout_bytes: 0,
                stderr: Vec::new(),
                observation_bytes: 0,
                observations: 0,
            },
            state: RuntimeState::Spawned,
            active_run: None,
            last_sequence: None,
            pending_observations: VecDeque::new(),
            stdout_eof: false,
            stderr_eof: false,
        })
    }

    pub(super) fn runtime_end(&self) -> Instant {
        self.started_at + Duration::from_millis(self.plan.runtime_deadline_ms())
    }

    pub(super) fn fail<T>(
        &mut self,
        error: ImplementationRuntimeError,
    ) -> Result<T, ImplementationRuntimeError> {
        self.state = RuntimeState::Failed;
        self.terminate();
        Err(error)
    }

    pub(super) fn wait_for_exit(&mut self, end: Instant) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child.take();
                    return true;
                }
                Err(_) => return false,
                Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(2)),
                Ok(None) => return false,
            }
        }
    }

    pub(super) fn drain_after_exit(
        &mut self,
        end: Instant,
    ) -> Result<(), ImplementationRuntimeError> {
        let mut stdout_eof = self.stdout_eof;
        let mut stderr_eof = self.stderr_eof;
        while !stdout_eof || !stderr_eof {
            let Some(remaining) = end.checked_duration_since(Instant::now()) else {
                return Err(ImplementationRuntimeError::Deadline {
                    operation: "output drain",
                });
            };
            let event = self.output.recv_timeout(remaining).map_err(|_| {
                ImplementationRuntimeError::Deadline {
                    operation: "output drain",
                }
            })?;
            match event {
                Output::Stdout(bytes) => {
                    self.evidence.stdout_bytes += bytes.len() + 1;
                    return Err(ImplementationProtocolError::Operation.into());
                }
                Output::Stderr(bytes) => self.evidence.stderr.extend_from_slice(&bytes),
                Output::StdoutEof => {
                    stdout_eof = true;
                    self.stdout_eof = true;
                }
                Output::StderrEof => {
                    stderr_eof = true;
                    self.stderr_eof = true;
                }
                Output::TooLarge(stream, max) => {
                    return Err(ImplementationRuntimeError::OutputTooLarge { stream, max });
                }
                Output::Io(operation, message) => {
                    return Err(ImplementationRuntimeError::Io { operation, message });
                }
            }
        }
        Ok(())
    }

    pub(super) fn terminate(&mut self) {
        self.input.take();
        kill_process_group(self.child_pid);
        if let Some(mut child) = self.child.take() {
            kill_and_reap(&mut child);
        }
        self.child_pid = None;
        self.finish_threads();
    }

    pub(super) fn finish_threads(&mut self) {
        // Joining a malicious provider's inherited pipe could outlive its deadline. Detaching is
        // bounded: readers retain at most the configured byte allowance and the group is killed.
        self.threads.clear();
    }
}

impl Drop for ImplementationRuntime {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn validate_plan(plan: &ProcessLaunchPlan) -> Result<(), ImplementationRuntimeError> {
    let argv_bytes = plan.argv().iter().map(String::len).sum::<usize>();
    if !plan.clears_environment() || !plan.environment().is_empty() {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "environment must be empty and cleared",
        ));
    }
    if plan.protocol_version() != IMPLEMENTATION_PROCESS_PROTOCOL_VERSION {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "unsupported protocol version",
        ));
    }
    if plan.argv().len() > MAX_IMPLEMENTATION_ARGV
        || argv_bytes > MAX_IMPLEMENTATION_ARGV_BYTES
        || plan.argv().iter().any(|arg| {
            arg.len() > MAX_IMPLEMENTATION_ARG_BYTES || arg.chars().any(char::is_control)
        })
    {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "invalid argv bounds",
        ));
    }
    let limits = plan.evidence_limits();
    if plan.runtime_deadline_ms() == 0
        || plan.runtime_deadline_ms() > MAX_IMPLEMENTATION_RUNTIME_MS
        || plan.cancellation_deadline_ms() == 0
        || plan.cancellation_deadline_ms() > MAX_IMPLEMENTATION_CANCELLATION_MS
        || limits.stdout_bytes == 0
        || limits.stdout_bytes > MAX_IMPLEMENTATION_EVIDENCE_BYTES
        || limits.stderr_bytes == 0
        || limits.stderr_bytes > MAX_IMPLEMENTATION_EVIDENCE_BYTES
        || limits.observations == 0
        || limits.observations > MAX_IMPLEMENTATION_OBSERVATIONS
    {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "invalid deadline or evidence bounds",
        ));
    }
    normalized_digest(plan.artifact_sha256())?;
    Ok(())
}

fn seam(module: ModuleId) -> Result<CapabilitySeamNode, ImplementationRuntimeError> {
    let graph = capability_seam_graph();
    validate_capability_seam_graph(&graph).map_err(|_| ImplementationProtocolError::Contract)?;
    graph
        .nodes
        .into_iter()
        .find(|node| node.module == module)
        .ok_or(ImplementationProtocolError::Contract.into())
}

fn canonical_program(program: &str) -> Result<PathBuf, ImplementationRuntimeError> {
    let path = Path::new(program);
    if !path.is_absolute() {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "program must be absolute",
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| io("canonicalize", error))?;
    if !canonical.is_absolute()
        || !canonical
            .metadata()
            .map_err(|error| io("metadata", error))?
            .is_file()
    {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "program must be a regular file",
        ));
    }
    Ok(canonical)
}

fn normalized_digest(value: &str) -> Result<&str, ImplementationRuntimeError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(digest)
    } else {
        Err(ImplementationRuntimeError::InvalidPlan(
            "invalid artifact SHA-256",
        ))
    }
}

fn verify_program(path: &Path, expected: &str) -> Result<(), ImplementationRuntimeError> {
    let mut file = File::open(path).map_err(|error| io("open executable", error))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io("hash executable", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual == expected {
        Ok(())
    } else {
        Err(ImplementationRuntimeError::ContentMismatch {
            expected: expected.to_owned(),
            actual,
        })
    }
}

fn spawn_writer(
    mut stdin: std::process::ChildStdin,
    receiver: Receiver<Input>,
    output: Sender<Output>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(Input::Frame(frame)) = receiver.recv() {
            if let Err(error) = stdin.write_all(&frame).and_then(|_| stdin.write_all(b"\n")) {
                let _ = output.send(Output::Io("stdin", error.to_string()));
                return;
            }
            if let Err(error) = stdin.flush() {
                let _ = output.send(Output::Io("stdin flush", error.to_string()));
                return;
            }
        }
    })
}

fn spawn_stdout(
    mut stdout: std::process::ChildStdout,
    limit: usize,
    output: Sender<Output>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut total = 0_usize;
        let mut frame = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) => {
                    let _ = output.send(Output::Io("stdout", error.to_string()));
                    return;
                }
            };
            total = total.saturating_add(read);
            if total > limit {
                let _ = output.send(Output::TooLarge("stdout", limit));
                return;
            }
            for byte in &buffer[..read] {
                if *byte == b'\n' {
                    let _ = output.send(Output::Stdout(std::mem::take(&mut frame)));
                } else {
                    frame.push(*byte);
                    if frame.len() > MAX_IMPLEMENTATION_MESSAGE_BYTES {
                        let _ = output.send(Output::TooLarge(
                            "stdout message",
                            MAX_IMPLEMENTATION_MESSAGE_BYTES,
                        ));
                        return;
                    }
                }
            }
        }
        if !frame.is_empty() {
            let _ = output.send(Output::Stdout(frame));
        }
        let _ = output.send(Output::StdoutEof);
    })
}

fn spawn_stderr(
    mut stderr: std::process::ChildStderr,
    limit: usize,
    output: Sender<Output>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut total = 0_usize;
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) => {
                    let _ = output.send(Output::Io("stderr", error.to_string()));
                    return;
                }
            };
            total = total.saturating_add(read);
            if total > limit {
                let _ = output.send(Output::TooLarge("stderr", limit));
                return;
            }
            let _ = output.send(Output::Stderr(buffer[..read].to_vec()));
        }
        let _ = output.send(Output::StderrEof);
    })
}

fn kill_and_reap(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    const SIGKILL: i32 = 9;
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: launch creates a process group whose id is the provider pid. A negative id
        // therefore addresses only that provider and descendants, never the host's group.
        unsafe {
            let _ = kill(-pid, SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: Option<u32>) {}

fn io(operation: &'static str, error: impl std::fmt::Display) -> ImplementationRuntimeError {
    ImplementationRuntimeError::Io {
        operation,
        message: error.to_string(),
    }
}

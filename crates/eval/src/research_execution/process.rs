//! Shell-free child ownership, bounded pipe capture, and process-group reaping.

use super::{ExecutionSnapshot, finish_natural_run, terminal_snapshot};
use crate::adapter_registry::ExecutableIdentity;
use crate::research_protocol::{ResearchRunState, RunSpec};
use crate::terminal_bench::AdapterCommand;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub(super) fn execute_command(
    adapter: &AdapterCommand,
    executable: Option<&ExecutableIdentity>,
    run: &RunSpec,
    sidecar_path: Option<&str>,
    cancel: &AtomicBool,
) -> ExecutionSnapshot {
    if cancel.load(Ordering::Acquire) {
        return terminal_snapshot(ResearchRunState::Cancelled, "run cancelled before spawn");
    }
    #[cfg(not(unix))]
    {
        let _ = (adapter, run, sidecar_path);
        return terminal_snapshot(
            ResearchRunState::Failed,
            "execute mode requires Unix process-group and address-space enforcement",
        );
    }
    #[cfg(unix)]
    {
        if executable.is_some_and(|identity| identity.verify().is_err()) {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "Iteron CLI executable identity changed before spawn",
            );
        }
        let stdout_file = match open_output_file(&adapter.stdout_path) {
            Ok(file) => file,
            Err(_) => {
                return terminal_snapshot(
                    ResearchRunState::Failed,
                    "stdout artifact could not be opened safely",
                );
            }
        };
        let mut command = Command::new(&adapter.program);
        command
            .args(&adapter.argv)
            .current_dir(&adapter.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if adapter.clear_environment {
            command.env_clear();
        }
        command.envs(&adapter.environment);
        for name in &adapter.inherit_environment {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.process_group(0);
        let memory_limit = run.max_memory_bytes();
        // SAFETY: only async-signal-safe setrlimit runs between fork and exec. Darwin rejects
        // RLIMIT_AS for ordinary spawned processes, so macOS uses a host-side, process-group
        // physical-footprint probe below instead of silently dropping the bound.
        #[cfg(not(target_os = "macos"))]
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: memory_limit as libc::rlim_t,
                    rlim_max: memory_limit as libc::rlim_t,
                };
                (libc::setrlimit(libc::RLIMIT_AS, &limit) == 0)
                    .then_some(())
                    .ok_or_else(std::io::Error::last_os_error)
            });
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let detail = format!(
                    "registry command could not be spawned: {:?} ({:?})",
                    error.kind(),
                    error.raw_os_error()
                );
                return terminal_snapshot(ResearchRunState::Failed, &detail);
            }
        };
        let pid = child.id();
        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap(&mut child, pid);
            return terminal_snapshot(ResearchRunState::Failed, "stdout pipe was unavailable");
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_and_reap(&mut child, pid);
            return terminal_snapshot(ResearchRunState::Failed, "stderr pipe was unavailable");
        };
        let stdout_exceeded = Arc::new(AtomicBool::new(false));
        let stderr_exceeded = Arc::new(AtomicBool::new(false));
        let stdout_worker = spawn_capture(
            stdout,
            Some(stdout_file),
            adapter.stdout_limit_bytes,
            Arc::clone(&stdout_exceeded),
        );
        let stderr_worker = spawn_capture(
            stderr,
            None,
            adapter.stderr_limit_bytes,
            Arc::clone(&stderr_exceeded),
        );
        let started = Instant::now();
        let deadline = Duration::from_secs(run.max_wall_secs());
        let (terminal, detail) = loop {
            let terminal = if cancel.load(Ordering::Acquire) {
                Some((
                    ResearchRunState::Cancelled,
                    "run cancelled and child process reaped",
                ))
            } else if stdout_exceeded.load(Ordering::Acquire) {
                Some((
                    ResearchRunState::StdoutLimit,
                    "stdout byte bound reached; child process reaped",
                ))
            } else if stderr_exceeded.load(Ordering::Acquire) {
                Some((
                    ResearchRunState::StderrLimit,
                    "stderr byte bound reached; child process reaped",
                ))
            } else if started.elapsed() >= deadline {
                Some((
                    ResearchRunState::TimedOut,
                    "wall-time bound reached; child process reaped",
                ))
            } else if evidence_usage(run, &adapter.stdout_path, sidecar_path).is_err() {
                Some((
                    ResearchRunState::EvidenceLimit,
                    "evidence byte bound reached; child process reaped",
                ))
            } else {
                match process_group_memory_within_limit(pid, memory_limit) {
                    Ok(true) => None,
                    Ok(false) => Some((
                        ResearchRunState::Failed,
                        "memory byte bound reached; child process reaped",
                    )),
                    Err(()) => Some((
                        ResearchRunState::Failed,
                        "memory usage could not be measured; child process reaped",
                    )),
                }
            };
            if let Some(terminal) = terminal {
                terminate_and_reap(&mut child, pid);
                break terminal;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    kill_residual_group(pid);
                    return finish_natural_run(
                        status,
                        join_capture(stdout_worker),
                        join_capture(stderr_worker),
                        run,
                        sidecar_path,
                    );
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    terminate_and_reap(&mut child, pid);
                    break (
                        ResearchRunState::Failed,
                        "child process wait failed; child process reaped",
                    );
                }
            }
        };
        let stdout = join_capture(stdout_worker);
        let stderr = join_capture(stderr_worker);
        let mut snapshot = terminal_snapshot(terminal, detail);
        snapshot.stdout_bytes = stdout.bytes;
        snapshot.stderr_bytes = stderr.bytes;
        snapshot
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn process_group_memory_within_limit(_pid: u32, _limit: u64) -> Result<bool, ()> {
    // RLIMIT_AS is installed before exec on these targets.
    Ok(true)
}

#[cfg(target_os = "macos")]
fn process_group_memory_within_limit(pid: u32, limit: u64) -> Result<bool, ()> {
    const PROC_PGRP_ONLY: u32 = 2;
    const MAX_GROUP_PROCESSES: usize = 4096;

    let mut pids = [0_i32; MAX_GROUP_PROCESSES];
    let bytes = unsafe {
        // SAFETY: `pids` is a writable fixed-size buffer and the kernel receives its exact size.
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            pid,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as libc::c_int,
        )
    };
    if bytes < 0 {
        return Err(());
    }
    let count = usize::try_from(bytes).map_err(|_| ())? / std::mem::size_of::<i32>();
    if count > pids.len() {
        return Err(());
    }
    let mut total = 0_u64;
    for process in pids.into_iter().take(count).filter(|process| *process > 0) {
        let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v0>::zeroed();
        let status = unsafe {
            // SAFETY: the kernel writes exactly a V0 rusage record into an aligned buffer.
            libc::proc_pid_rusage(process, libc::RUSAGE_INFO_V0, usage.as_mut_ptr().cast())
        };
        if status != 0 {
            // A group member may exit between the group listing and its rusage read.
            continue;
        }
        let usage = unsafe {
            // SAFETY: a zero status means proc_pid_rusage initialized the V0 record.
            usage.assume_init()
        };
        total = total.checked_add(usage.ri_phys_footprint).ok_or(())?;
        if total > limit {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Default)]
pub(super) struct CaptureSummary {
    pub(super) bytes: u64,
    pub(super) io_failed: bool,
}

fn spawn_capture<R: Read + Send + 'static>(
    reader: R,
    output: Option<File>,
    limit: u64,
    exceeded: Arc<AtomicBool>,
) -> JoinHandle<CaptureSummary> {
    thread::spawn(move || {
        let mut reader = reader;
        let mut output = output;
        let mut summary = CaptureSummary::default();
        let mut chunk = [0_u8; 8192];
        loop {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => {
                    summary.io_failed = true;
                    break;
                }
            };
            let retained = summary.bytes.min(limit);
            summary.bytes = summary.bytes.saturating_add(read as u64);
            let keep = (limit.saturating_sub(retained) as usize).min(read);
            if let Some(file) = &mut output
                && keep > 0
                && file.write_all(&chunk[..keep]).is_err()
            {
                summary.io_failed = true;
            }
            if summary.bytes > limit {
                exceeded.store(true, Ordering::Release);
                break;
            }
        }
        if let Some(file) = &mut output
            && file.flush().is_err()
        {
            summary.io_failed = true;
        }
        summary
    })
}

fn join_capture(worker: JoinHandle<CaptureSummary>) -> CaptureSummary {
    worker.join().unwrap_or(CaptureSummary {
        bytes: 0,
        io_failed: true,
    })
}

fn open_output_file(path: &str) -> std::io::Result<File> {
    let path = Path::new(path);
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(std::io::Error::other("unsafe output target"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(unix)]
fn signal_process_group(pid: u32, signal: libc::c_int) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: children are spawned into a dedicated group whose id is pid.
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

#[cfg(unix)]
fn kill_residual_group(pid: u32) {
    signal_process_group(pid, libc::SIGKILL);
}

#[cfg(not(unix))]
fn kill_residual_group(_pid: u32) {}

fn terminate_and_reap(child: &mut Child, pid: u32) {
    #[cfg(unix)]
    signal_process_group(pid, libc::SIGTERM);
    for _ in 0..5 {
        if child.try_wait().ok().flatten().is_some() {
            kill_residual_group(pid);
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    #[cfg(unix)]
    signal_process_group(pid, libc::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
}

pub(super) fn evidence_usage(
    run: &RunSpec,
    stdout: &str,
    sidecar: Option<&str>,
) -> Result<u64, ()> {
    let limit = run.max_evidence_bytes();
    let mut total = file_size_if_regular(Path::new(stdout))?;
    total = total
        .checked_add(file_size_if_regular(Path::new(
            run.effective_profile_path(),
        ))?)
        .ok_or(())?;
    total = total
        .checked_add(directory_size_bounded(
            Path::new(run.runs_dir()),
            sidecar.map(Path::new),
            limit,
        )?)
        .ok_or(())?;
    (total <= limit).then_some(total).ok_or(())
}

fn directory_size_bounded(path: &Path, exclude: Option<&Path>, limit: u64) -> Result<u64, ()> {
    if exclude.is_some_and(|excluded| excluded == path) {
        return Ok(0);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(()),
    };
    if metadata.file_type().is_symlink() {
        return Err(());
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Err(());
    }
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in fs::read_dir(path).map_err(|_| ())? {
        entries += 1;
        if entries > 4096 {
            return Err(());
        }
        total = total
            .checked_add(directory_size_bounded(
                &entry.map_err(|_| ())?.path(),
                exclude,
                limit,
            )?)
            .ok_or(())?;
        if total > limit {
            return Err(());
        }
    }
    Ok(total)
}

fn file_size_if_regular(path: &Path) -> Result<u64, ()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(()),
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(()),
    }
}

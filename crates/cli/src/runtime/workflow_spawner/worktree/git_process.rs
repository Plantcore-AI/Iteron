//! Finite native Git process and pipe ownership for isolated writer transactions.
//! A missing terminal or pipe proof is a failed merge observation, never a successful cleanup.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::{Duration, Instant};

use super::{GitOutput, MergeFailure, MergeFailureKind};

const PROCESS_DEADLINE: Duration = Duration::from_secs(60);
const PIPE_DEADLINE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

struct ProcessOwner {
    child: Child,
    reaped: bool,
}

impl ProcessOwner {
    fn stop(&mut self) {
        #[cfg(unix)]
        unsafe {
            // Command::process_group(0) established this private child group before exec.
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
    }
}

impl Drop for ProcessOwner {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        self.stop();
        let deadline = Instant::now() + PIPE_DEADLINE;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
}

fn capture_pipe(mut pipe: impl Read, limit: usize) -> std::io::Result<Capture> {
    let mut captured = Capture {
        bytes: Vec::new(),
        overflow: false,
    };
    let mut buffer = [0_u8; 8192];
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            return Ok(captured);
        }
        let retain = read.min(limit.saturating_sub(captured.bytes.len()));
        captured.bytes.extend_from_slice(&buffer[..retain]);
        captured.overflow |= retain < read;
        // Continue draining after the memory ceiling. The process deadline, not unbounded
        // allocation or an abandoned full pipe, terminates an excessive producer.
    }
}

fn spawn<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Receiver<T> {
    let (tx, rx) = sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx
}

fn receive<T>(rx: &Receiver<T>, deadline: Instant) -> Result<T, MergeFailure> {
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| unavailable())
}

fn unavailable() -> MergeFailure {
    MergeFailure::new(
        MergeFailureKind::WorktreeState,
        "native Git process or pipe did not reach a bounded terminal",
    )
}

pub(super) fn capture(
    command: Command,
    input: Option<Vec<u8>>,
    stdout_limit: usize,
    require_complete: bool,
) -> Result<GitOutput, MergeFailure> {
    capture_until(
        command,
        input,
        stdout_limit,
        require_complete,
        PROCESS_DEADLINE,
    )
}

fn capture_until(
    mut command: Command,
    input: Option<Vec<u8>>,
    stdout_limit: usize,
    require_complete: bool,
    timeout: Duration,
) -> Result<GitOutput, MergeFailure> {
    if input
        .as_ref()
        .is_some_and(|bytes| bytes.len() as u64 > super::MAX_WRITER_PATCH_BYTES)
    {
        return Err(unavailable());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut process = ProcessOwner {
        child: command.spawn().map_err(|_| unavailable())?,
        reaped: false,
    };
    let out = process.child.stdout.take().ok_or_else(unavailable)?;
    let err = process.child.stderr.take().ok_or_else(unavailable)?;
    let out = spawn(move || capture_pipe(out, stdout_limit));
    let err = spawn(move || capture_pipe(err, super::MAX_GIT_MESSAGE_BYTES));
    let writer = if let Some(input) = input {
        let mut stdin = process.child.stdin.take().ok_or_else(unavailable)?;
        Some(spawn(move || stdin.write_all(&input)))
    } else {
        None
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = process.child.try_wait().map_err(|_| unavailable())? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let pipes = Instant::now() + PIPE_DEADLINE;
    let result = (|| {
        let stdout = receive(&out, pipes)?.map_err(|_| unavailable())?;
        let stderr = receive(&err, pipes)?.map_err(|_| unavailable())?;
        if let Some(writer) = writer {
            if let Err(error) = receive(&writer, pipes)?
                && error.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(unavailable());
            }
        }
        if require_complete && stdout.overflow {
            return Err(unavailable());
        }
        Ok(GitOutput {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    })();
    if result.is_err() {
        process.stop();
    }
    process.reaped = true;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_stalled_native_process_does_not_keep_a_writer_transaction_waiting() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        let started = Instant::now();
        assert!(capture_until(command, None, 32, true, Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn complete_path_evidence_refuses_overflow_but_diagnostics_remain_bounded() {
        let command = || {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf abcdef"]);
            command
        };
        assert!(capture(command(), None, 3, true).is_err());
        let diagnostic = capture(command(), None, 3, false).unwrap();
        assert!(diagnostic.status.success());
        assert_eq!(diagnostic.stdout, b"abc");
    }
}

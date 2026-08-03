//! Killable, bounded transcript-export helper process and private pipe protocol.

#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::time::Duration;

#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::transcript_export;

#[cfg(target_os = "linux")]
const EXPORT_DEADLINE: Duration = Duration::from_secs(5);
pub(super) const REAP_DEADLINE: Duration = Duration::from_secs(1);
const WORKER_ENV: &str = "CORE_INTERNAL_TRANSCRIPT_EXPORT_V1";
#[cfg(target_os = "linux")]
const WORKER_MAGIC: &[u8; 8] = b"COREXP01";
#[cfg(target_os = "linux")]
const MAX_WORKSPACE_BYTES: usize = 16 * 1024;
const MAX_WORKER_RESPONSE_BYTES: usize = 32 * 1024;
#[cfg(target_os = "linux")]
const WORKER_HEADER_BYTES: usize = WORKER_MAGIC.len() + 1 + 4 + 4 + 4;
#[cfg(target_os = "linux")]
const MAX_WORKER_FRAME_BYTES: usize = WORKER_HEADER_BYTES
    + MAX_WORKSPACE_BYTES
    + 4 * 1024
    + transcript_export::MAX_TRANSCRIPT_EXPORT_BYTES;

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum WorkerRun {
    Completed(Result<PathBuf, String>),
    TimedOut { reaped: bool },
    Cancelled,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) async fn cancelled(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) async fn kill_and_reap(child: &mut tokio::process::Child) -> bool {
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(REAP_DEADLINE, child.wait()).await,
        Ok(Ok(_))
    )
}

#[cfg(target_os = "linux")]
pub(super) async fn run_export_worker(
    workspace: &Path,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
    bytes: &[u8],
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> WorkerRun {
    let frame = match encode_worker_request(workspace, requested, collision, bytes) {
        Ok(frame) => frame,
        Err(error) => return WorkerRun::Completed(Err(error)),
    };
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => {
            return WorkerRun::Completed(Err("export helper executable is unavailable".into()));
        }
    };
    let mut command = tokio::process::Command::new(executable);
    command
        .env_clear()
        .env(WORKER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // SAFETY: this closure runs after fork and before exec and invokes only async-signal-safe libc
    // syscalls. Rechecking the parent closes the race where it died immediately before `prctl`.
    unsafe {
        use std::os::unix::process::CommandExt as _;

        command.as_std_mut().pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() == 1 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return WorkerRun::Completed(Err("export helper could not start".into())),
    };
    let Some(mut stdin) = child.stdin.take() else {
        let _ = kill_and_reap(&mut child).await;
        return WorkerRun::Completed(Err("export helper stdin was unavailable".into()));
    };
    let deadline = tokio::time::Instant::now() + EXPORT_DEADLINE;
    let write = async {
        stdin.write_all(&frame).await?;
        stdin.shutdown().await
    };
    tokio::select! {
        _ = cancelled(cancelled_rx) => {
            drop(stdin);
            let _ = kill_and_reap(&mut child).await;
            return WorkerRun::Cancelled;
        }
        result = tokio::time::timeout_at(deadline, write) => match result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                drop(stdin);
                let _ = kill_and_reap(&mut child).await;
                return WorkerRun::Completed(Err("export helper request failed after dispatch".into()));
            }
            Err(_) => {
                drop(stdin);
                let reaped = kill_and_reap(&mut child).await;
                return WorkerRun::TimedOut { reaped };
            }
        }
    }
    drop(stdin);

    let status = tokio::select! {
        _ = cancelled(cancelled_rx) => {
            let _ = kill_and_reap(&mut child).await;
            return WorkerRun::Cancelled;
        }
        result = tokio::time::timeout_at(deadline, child.wait()) => match result {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                let _ = kill_and_reap(&mut child).await;
                return WorkerRun::Completed(Err("export helper wait failed after dispatch".into()));
            }
            Err(_) => {
                let reaped = kill_and_reap(&mut child).await;
                return WorkerRun::TimedOut { reaped };
            }
        }
    };
    if !status.success() {
        return WorkerRun::Completed(Err("export helper failed after dispatch".into()));
    }
    let Some(stdout) = child.stdout.take() else {
        return WorkerRun::Completed(Err("export helper response was unavailable".into()));
    };
    let mut response = Vec::new();
    if stdout
        .take((MAX_WORKER_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .is_err()
        || response.len() > MAX_WORKER_RESPONSE_BYTES
    {
        return WorkerRun::Completed(Err("export helper response exceeded its bound".into()));
    }
    WorkerRun::Completed(decode_worker_response(workspace, &response))
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn run_export_worker(
    _workspace: &Path,
    _requested: &str,
    _collision: transcript_export::CollisionPolicy,
    _bytes: &[u8],
    _cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> WorkerRun {
    WorkerRun::Completed(Err(
        "secure transcript export requires Linux anonymous-inode publication".into(),
    ))
}

#[cfg(target_os = "linux")]
fn encode_worker_request(
    workspace: &Path,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    use std::os::unix::ffi::OsStrExt as _;

    let workspace = workspace.as_os_str().as_bytes();
    if workspace.is_empty() || workspace.len() > MAX_WORKSPACE_BYTES {
        return Err("export workspace path exceeds its 16 KiB bound".into());
    }
    if requested.len() > 4 * 1024 || body.len() > transcript_export::MAX_TRANSCRIPT_EXPORT_BYTES {
        return Err("export helper request exceeds its bound".into());
    }
    let workspace_len = u32::try_from(workspace.len()).map_err(|_| "workspace path is too long")?;
    let requested_len = u32::try_from(requested.len()).map_err(|_| "export path is too long")?;
    let body_len = u32::try_from(body.len()).map_err(|_| "transcript body is too large")?;
    let mut frame =
        Vec::with_capacity(WORKER_HEADER_BYTES + workspace.len() + requested.len() + body.len());
    frame.extend_from_slice(WORKER_MAGIC);
    frame.push(match collision {
        transcript_export::CollisionPolicy::Refuse => 0,
        transcript_export::CollisionPolicy::Versioned => 1,
    });
    frame.extend_from_slice(&workspace_len.to_le_bytes());
    frame.extend_from_slice(&requested_len.to_le_bytes());
    frame.extend_from_slice(&body_len.to_le_bytes());
    frame.extend_from_slice(workspace);
    frame.extend_from_slice(requested.as_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn encode_worker_response(result: Result<&str, String>) -> Vec<u8> {
    let (mut status, mut message) = match result {
        Ok(path) => (0u8, path.as_bytes().to_vec()),
        Err(error) => (1u8, error.into_bytes()),
    };
    const OVERSIZED: &[u8] = b"export helper response exceeded its bound";
    if message.len() > MAX_WORKER_RESPONSE_BYTES.saturating_sub(5) {
        status = 1;
        message = OVERSIZED.to_vec();
    }
    let mut response = Vec::with_capacity(5 + message.len());
    response.push(status);
    response.extend_from_slice(&(message.len() as u32).to_le_bytes());
    response.extend_from_slice(&message);
    response
}

#[cfg(any(target_os = "linux", test))]
fn decode_worker_response(workspace: &Path, response: &[u8]) -> Result<PathBuf, String> {
    if response.len() < 5 {
        return Err("export helper returned a malformed response".into());
    }
    let status = response[0];
    let length =
        u32::from_le_bytes(response[1..5].try_into().expect("fixed response length")) as usize;
    if length > MAX_WORKER_RESPONSE_BYTES.saturating_sub(5) || response.len() != 5 + length {
        return Err("export helper returned a malformed response".into());
    }
    let message = std::str::from_utf8(&response[5..])
        .map_err(|_| "export helper returned non-UTF-8 status".to_string())?;
    match status {
        0 => {
            if message.is_empty() {
                return Err("export helper returned an empty result path".into());
            }
            let relative = Path::new(message);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err("export helper returned an invalid relative path".into());
            }
            Ok(workspace.join(relative))
        }
        1 => Err(message.to_string()),
        _ => Err("export helper returned an unknown status".into()),
    }
}

pub(crate) fn worker_requested() -> bool {
    std::env::var_os(WORKER_ENV).as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Entry point used before normal CLI argument/config parsing. The protocol is deliberately private,
/// versioned, bounded, and carried only over inherited stdin/stdout pipes.
pub(crate) fn worker_main() -> u8 {
    let result = worker_request_from_stdin();
    let response = match result {
        Ok((workspace, requested, collision, body)) => {
            let exported = transcript_export::export_bytes(
                &workspace, &requested, &body, collision,
            )
            .and_then(|path| {
                path.strip_prefix(&workspace)
                    .ok()
                    .and_then(Path::to_str)
                    .map(str::to_owned)
                    .ok_or_else(|| "export helper produced an invalid result path".to_string())
            });
            encode_worker_response(exported.as_deref().map_err(|error| error.to_string()))
        }
        Err(error) => encode_worker_response(Err(error)),
    };
    if std::io::stdout().lock().write_all(&response).is_ok() {
        0
    } else {
        1
    }
}

type WorkerRequest = (PathBuf, String, transcript_export::CollisionPolicy, Vec<u8>);

fn worker_request_from_stdin() -> Result<WorkerRequest, String> {
    #[cfg(not(target_os = "linux"))]
    {
        Err("secure transcript export requires Linux anonymous-inode publication".into())
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let mut frame = Vec::new();
        std::io::stdin()
            .lock()
            .take((MAX_WORKER_FRAME_BYTES + 1) as u64)
            .read_to_end(&mut frame)
            .map_err(|_| "export helper could not read its request".to_string())?;
        if frame.len() > MAX_WORKER_FRAME_BYTES || frame.len() < WORKER_HEADER_BYTES {
            return Err("export helper request exceeds its bound or is truncated".into());
        }
        if &frame[..WORKER_MAGIC.len()] != WORKER_MAGIC {
            return Err("export helper request has an unsupported protocol".into());
        }
        let collision = match frame[WORKER_MAGIC.len()] {
            0 => transcript_export::CollisionPolicy::Refuse,
            1 => transcript_export::CollisionPolicy::Versioned,
            _ => return Err("export helper request has an invalid collision policy".into()),
        };
        let mut cursor = WORKER_MAGIC.len() + 1;
        let mut next_length = || {
            let end = cursor + 4;
            let bytes: [u8; 4] = frame[cursor..end]
                .try_into()
                .expect("header length was checked");
            cursor = end;
            u32::from_le_bytes(bytes) as usize
        };
        let workspace_len = next_length();
        let requested_len = next_length();
        let body_len = next_length();
        if workspace_len == 0
            || workspace_len > MAX_WORKSPACE_BYTES
            || requested_len > 4 * 1024
            || body_len > transcript_export::MAX_TRANSCRIPT_EXPORT_BYTES
            || cursor
                .checked_add(workspace_len)
                .and_then(|end| end.checked_add(requested_len))
                .and_then(|end| end.checked_add(body_len))
                != Some(frame.len())
        {
            return Err("export helper request has invalid lengths".into());
        }
        let workspace_end = cursor + workspace_len;
        let workspace = PathBuf::from(OsString::from_vec(frame[cursor..workspace_end].to_vec()));
        cursor = workspace_end;
        let requested_end = cursor + requested_len;
        let requested = std::str::from_utf8(&frame[cursor..requested_end])
            .map_err(|_| "export helper path must be UTF-8".to_string())?
            .to_string();
        let body = frame[requested_end..].to_vec();
        Ok((workspace, requested, collision, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_worker_responses_and_paths_fail_closed() {
        let workspace = Path::new("/workspace");
        assert!(decode_worker_response(workspace, b"").is_err());
        let absolute = encode_worker_response(Ok("/outside"));
        assert!(decode_worker_response(workspace, &absolute).is_err());
        let traversal = encode_worker_response(Ok("../outside"));
        assert!(decode_worker_response(workspace, &traversal).is_err());
    }
}

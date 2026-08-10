//! Private, versioned, bounded stdin/stdout protocol for the export helper process.

#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::super::super::transcript_export;

pub(super) const WORKER_ENV: &str = "ITERON_INTERNAL_TRANSCRIPT_EXPORT_V1";
#[cfg(target_os = "linux")]
const WORKER_MAGIC: &[u8; 8] = b"COREXP01";
#[cfg(target_os = "linux")]
const MAX_WORKSPACE_BYTES: usize = 16 * 1024;
pub(super) const MAX_WORKER_RESPONSE_BYTES: usize = 32 * 1024;
#[cfg(target_os = "linux")]
const WORKER_HEADER_BYTES: usize = WORKER_MAGIC.len() + 1 + 4 + 4 + 4;
#[cfg(target_os = "linux")]
const MAX_WORKER_FRAME_BYTES: usize = WORKER_HEADER_BYTES
    + MAX_WORKSPACE_BYTES
    + 4 * 1024
    + transcript_export::MAX_TRANSCRIPT_EXPORT_BYTES;

#[cfg(target_os = "linux")]
pub(super) fn encode_worker_request(
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

fn encode_worker_response(result: Result<&str, transcript_export::ExportError>) -> Vec<u8> {
    let (mut status, mut message) = match result {
        Ok(path) => (0u8, path.as_bytes().to_vec()),
        Err(transcript_export::ExportError::KnownFailure(error)) => (1u8, error.into_bytes()),
        Err(transcript_export::ExportError::OutcomeUnknown(error)) => (2u8, error.into_bytes()),
    };
    const OVERSIZED: &[u8] = b"export helper response exceeded its bound";
    if message.len() > MAX_WORKER_RESPONSE_BYTES.saturating_sub(5) {
        // An oversized response destroys the evidence needed to distinguish helper success from
        // failure. The parent therefore treats this fallback as outcome-unknown too.
        status = 2;
        message = OVERSIZED.to_vec();
    }
    let mut response = Vec::with_capacity(5 + message.len());
    response.push(status);
    response.extend_from_slice(&(message.len() as u32).to_le_bytes());
    response.extend_from_slice(&message);
    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
pub(super) enum WorkerResponse {
    Published(PathBuf),
    KnownFailure(String),
    OutcomeUnknown(String),
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn decode_worker_response(
    workspace: &Path,
    response: &[u8],
) -> Result<WorkerResponse, String> {
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
            Ok(WorkerResponse::Published(workspace.join(relative)))
        }
        1 => Ok(WorkerResponse::KnownFailure(message.to_string())),
        2 => Ok(WorkerResponse::OutcomeUnknown(message.to_string())),
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
            let exported =
                match transcript_export::export_bytes(&workspace, &requested, &body, collision) {
                    Ok(path) => path
                        .strip_prefix(&workspace)
                        .ok()
                        .and_then(Path::to_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            transcript_export::ExportError::OutcomeUnknown(
                                "export completed but its result path could not be encoded".into(),
                            )
                        }),
                    Err(error) => Err(error),
                };
            encode_worker_response(exported.as_deref().map_err(Clone::clone))
        }
        Err(error) => {
            encode_worker_response(Err(transcript_export::ExportError::KnownFailure(error)))
        }
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
        let absolute: Result<&str, transcript_export::ExportError> = Ok("/outside");
        let absolute = encode_worker_response(absolute);
        assert!(decode_worker_response(workspace, &absolute).is_err());
        let traversal: Result<&str, transcript_export::ExportError> = Ok("../outside");
        let traversal = encode_worker_response(traversal);
        assert!(decode_worker_response(workspace, &traversal).is_err());
    }

    #[test]
    fn helper_protocol_preserves_known_and_unknown_failure_types() {
        let workspace = Path::new("/workspace");
        let known = encode_worker_response(Err(transcript_export::ExportError::KnownFailure(
            "collision".into(),
        )));
        assert_eq!(
            decode_worker_response(workspace, &known),
            Ok(WorkerResponse::KnownFailure("collision".into()))
        );
        let unknown = encode_worker_response(Err(transcript_export::ExportError::OutcomeUnknown(
            "directory sync".into(),
        )));
        assert_eq!(
            decode_worker_response(workspace, &unknown),
            Ok(WorkerResponse::OutcomeUnknown("directory sync".into()))
        );
    }
}

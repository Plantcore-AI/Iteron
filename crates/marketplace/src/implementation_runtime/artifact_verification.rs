//! Complete native artifact hashes under one admitted absolute deadline. A blocked read keeps
//! its private worker slot and file handle until it actually stops; timeout never mints proof.
use super::ImplementationRuntimeError;
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

const MAX_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROGRAM_PATH_BYTES: usize = 4096;
const MAX_WORKERS: usize = 4;
static WORKERS: AtomicUsize = AtomicUsize::new(0);

struct WorkerSlot;
impl Drop for WorkerSlot {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) fn verify_program(
    path: &Path,
    expected: &str,
    end: Instant,
) -> Result<(), ImplementationRuntimeError> {
    check_deadline(end)?;
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PROGRAM_PATH_BYTES
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "invalid executable verification scope",
        ));
    }
    WORKERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_WORKERS).then_some(count + 1)
        })
        .map_err(|_| {
            ImplementationRuntimeError::InvalidPlan("executable verification capacity occupied")
        })?;
    let slot = WorkerSlot;
    let path = path.to_owned();
    let expected = expected.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("iteron-artifact-verify".into())
        .spawn(move || {
            let _slot = slot;
            let result = verify_native(&path, &expected, end);
            let _ = send.send(result);
        })
        .map_err(|error| io("start executable verification", error))?;
    let remaining = end
        .checked_duration_since(Instant::now())
        .ok_or_else(deadline)?;
    match receive.recv_timeout(remaining) {
        Ok(result) => {
            check_deadline(end)?;
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(deadline()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io(
            "executable verification",
            "worker stopped without a result",
        )),
    }
}

fn verify_native(
    path: &Path,
    expected: &str,
    end: Instant,
) -> Result<(), ImplementationRuntimeError> {
    check_deadline(end)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // A replaced leaf cannot turn the verification worker into a blocking FIFO opener.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|error| io("open executable", error))?;
    validate_file(&file)?;
    let bytes = file
        .metadata()
        .map_err(|error| io("executable metadata", error))?
        .len();
    if bytes > MAX_EXECUTABLE_BYTES {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "executable exceeds its byte bound",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        check_deadline(end)?;
        let read_limit = (bytes - total + 1).min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..read_limit])
            .map_err(|error| io("hash executable", error))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > bytes {
            return Err(ImplementationRuntimeError::InvalidPlan(
                "executable changed during verification",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    check_deadline(end)?;
    if total != bytes
        || file
            .metadata()
            .map_err(|error| io("executable metadata", error))?
            .len()
            != bytes
    {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "executable changed during verification",
        ));
    }
    let actual = hex::encode(hasher.finalize());
    check_deadline(end)?;
    if actual != expected {
        return Err(ImplementationRuntimeError::ContentMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn validate_file(file: &File) -> Result<(), ImplementationRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|error| io("executable metadata", error))?;
    if !metadata.is_file() {
        return Err(ImplementationRuntimeError::InvalidPlan(
            "executable must be a regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK, GetFileType,
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        {
            return Err(ImplementationRuntimeError::InvalidPlan(
                "executable must be a regular non-reparse disk file",
            ));
        }
    }
    Ok(())
}

fn deadline() -> ImplementationRuntimeError {
    ImplementationRuntimeError::Deadline {
        operation: "executable verification",
    }
}
fn check_deadline(end: Instant) -> Result<(), ImplementationRuntimeError> {
    if Instant::now() >= end {
        Err(deadline())
    } else {
        Ok(())
    }
}
fn io(operation: &'static str, error: impl std::fmt::Display) -> ImplementationRuntimeError {
    ImplementationRuntimeError::Io {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
#[path = "artifact_verification/tests.rs"]
mod tests;

//! Bounded native Windows transport for the startup keyboard-capability query.

use super::{KEYBOARD_ENHANCEMENT_QUERY, exact_keyboard_query_write, wait_millis_until};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, WriteFile,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};

const CANCEL_TIMEOUT: Duration = Duration::from_millis(50);
static QUERY_STARTED: AtomicBool = AtomicBool::new(false);

pub(super) fn terminal_pair_is_supported() -> bool {
    fn is_console(handle: HANDLE) -> bool {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode = 0;
        // SAFETY: GetConsoleMode only reads metadata for the process-owned standard handle.
        unsafe { GetConsoleMode(handle, &mut mode) != 0 }
    }

    // SAFETY: GetStdHandle returns process-owned handles without transferring ownership.
    let (stdin, stdout) = unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
        )
    };
    is_console(stdin) && is_console(stdout)
}

pub(super) fn write_keyboard_query(deadline: Instant) -> std::io::Result<()> {
    if QUERY_STARTED.swap(true, Ordering::AcqRel) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "keyboard capability query was already attempted in this process",
        ));
    }

    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .open("CONOUT$")?;
    let output_handle = output.as_raw_handle() as HANDLE;
    let mut operation = Box::new(OVERLAPPED::default());
    // SAFETY: the output handle was opened for overlapped writes. The query has static lifetime and
    // `operation` remains pinned at its Box allocation until completion or process exit.
    let started = unsafe {
        WriteFile(
            output_handle,
            KEYBOARD_ENHANCEMENT_QUERY.as_ptr(),
            KEYBOARD_ENHANCEMENT_QUERY.len() as u32,
            std::ptr::null_mut(),
            &mut *operation,
        )
    };
    if started == 0 {
        let start_error = std::io::Error::last_os_error();
        if start_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(start_error);
        }
    }

    match wait_for_write(output_handle, &operation, deadline) {
        OverlappedWrite::Complete(result) => exact_keyboard_query_write(result? as usize),
        OverlappedWrite::Pending => {
            // SAFETY: the handle and OVERLAPPED belong to this exact operation. Cancellation may
            // race with normal completion, so its return value is not treated as completion.
            let _ = unsafe { CancelIoEx(output_handle, &*operation) };
            if matches!(
                wait_for_write(output_handle, &operation, Instant::now() + CANCEL_TIMEOUT),
                OverlappedWrite::Pending
            ) {
                // Windows forbids freeing an OVERLAPPED while its I/O may still be pending. This
                // process-wide one-shot path therefore retains exactly one small operation and
                // handle until process exit instead of detaching a worker or risking use-after-free.
                std::mem::forget(operation);
                std::mem::forget(output);
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "keyboard capability query write timed out",
            ))
        }
    }
}

enum OverlappedWrite {
    Complete(std::io::Result<u32>),
    Pending,
}

fn wait_for_write(output: HANDLE, operation: &OVERLAPPED, deadline: Instant) -> OverlappedWrite {
    let mut written = 0;
    // SAFETY: output and operation identify the same live overlapped write, and `written` remains
    // valid for the duration of this finite wait.
    let completed = unsafe {
        GetOverlappedResultEx(
            output,
            operation,
            &mut written,
            wait_millis_until(Instant::now(), deadline),
            0,
        )
    };
    if completed != 0 {
        return OverlappedWrite::Complete(Ok(written));
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_IO_INCOMPLETE as i32 || code == WAIT_TIMEOUT as i32
    ) {
        OverlappedWrite::Pending
    } else {
        // GetOverlappedResultEx reports terminal I/O errors, including cancellation, only after the
        // operation has completed and its OVERLAPPED storage can be released.
        OverlappedWrite::Complete(Err(error))
    }
}

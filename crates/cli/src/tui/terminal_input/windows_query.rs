//! Bounded native Windows transport for the startup keyboard-capability query.

use super::{
    KEYBOARD_ENHANCEMENT_PROTOCOL_QUERY, KeyboardQueryGate, KeyboardQueryRequest,
    exact_keyboard_query_write,
};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE, WriteFile};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;

const CANCEL_TIMEOUT: Duration = Duration::from_millis(50);
const CANCEL_RETRY_INTERVAL: Duration = Duration::from_millis(5);
const MAX_CANCEL_RETRIES: usize = 9;
static QUERY_GATE: KeyboardQueryGate = KeyboardQueryGate::new();
// Confirmed completion drops the thread handle without joining. If cancellation cannot retire the
// synchronous kernel I/O, this slot keeps the one worker tracked until ExitProcess without ever
// allowing a second worker or request.
static WORKER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

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
    if !QUERY_GATE.try_start() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "keyboard capability query was already attempted in this process",
        ));
    }

    let request = KeyboardQueryRequest::new(deadline);
    let (request_sender, request_receiver) = sync_channel::<KeyboardQueryRequest>(1);
    let (result_sender, result_receiver) = sync_channel::<std::io::Result<usize>>(1);
    let worker = match std::thread::Builder::new()
        .name("core-keyboard-query".into())
        .spawn(move || {
            let Ok(request) = request_receiver.recv() else {
                return;
            };
            let result = if request.should_abort(Instant::now()) {
                Err(query_cancelled())
            } else {
                write_keyboard_query_once(&request)
            };
            let _ = result_sender.send(result);
        }) {
        Ok(worker) => worker,
        Err(error) => {
            QUERY_GATE.poison();
            return Err(error);
        }
    };
    {
        let mut slot = worker_slot();
        debug_assert!(slot.is_none(), "one-shot gate permits only one worker");
        *slot = Some(worker);
    }
    if request_sender.send(request.clone()).is_err() {
        finish_confirmed_worker();
        return Err(worker_disconnected());
    }

    await_worker_result(result_receiver, &request)
}

fn await_worker_result(
    receiver: Receiver<std::io::Result<usize>>,
    request: &KeyboardQueryRequest,
) -> std::io::Result<()> {
    let first_wait = request
        .deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map_or(Err(RecvTimeoutError::Timeout), |remaining| {
            receiver.recv_timeout(remaining)
        });
    match first_wait {
        Ok(result) => {
            let result = result.and_then(exact_keyboard_query_write);
            finish_confirmed_worker();
            result
        }
        Err(RecvTimeoutError::Disconnected) => {
            finish_confirmed_worker();
            Err(worker_disconnected())
        }
        Err(RecvTimeoutError::Timeout) => {
            request.cancel();
            if await_cancellation_grace(&receiver) {
                finish_confirmed_worker();
            } else {
                // The kernel operation may outlive this query. Poisoning is permanent: the live
                // worker and its CONOUT$ handle remain tracked, and no second worker can start.
                QUERY_GATE.poison();
            }
            Err(query_cancelled())
        }
    }
}

fn await_cancellation_grace(receiver: &Receiver<std::io::Result<usize>>) -> bool {
    let grace_deadline = Instant::now()
        + iteron_tunables::param_duration(
            "cli.tui.terminal_input.windows_query.cancel_timeout",
            CANCEL_TIMEOUT,
        );
    let mut retry_cancel = matches!(cancel_worker_write(), CancelAttempt::NoCurrentIo);
    for retry in 0..=iteron_tunables::param_integer(
        "cli.tui.terminal_input.windows_query.max_cancel_retries",
        MAX_CANCEL_RETRIES,
    ) {
        let Some(remaining) = grace_deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        let wait = if retry_cancel
            && retry
                < iteron_tunables::param_integer(
                    "cli.tui.terminal_input.windows_query.max_cancel_retries",
                    MAX_CANCEL_RETRIES,
                ) {
            remaining.min(iteron_tunables::param_duration(
                "cli.tui.terminal_input.windows_query.cancel_retry_interval",
                CANCEL_RETRY_INTERVAL,
            ))
        } else {
            remaining
        };
        match receiver.recv_timeout(wait) {
            Ok(_) | Err(RecvTimeoutError::Disconnected) => return true,
            Err(RecvTimeoutError::Timeout) => {
                if Instant::now() >= grace_deadline {
                    return false;
                }
                if retry_cancel
                    && retry
                        < iteron_tunables::param_integer(
                            "cli.tui.terminal_input.windows_query.max_cancel_retries",
                            MAX_CANCEL_RETRIES,
                        )
                {
                    retry_cancel = matches!(cancel_worker_write(), CancelAttempt::NoCurrentIo);
                }
            }
        }
    }
    false
}

enum CancelAttempt {
    Requested,
    NoCurrentIo,
    Failed,
}

fn cancel_worker_write() -> CancelAttempt {
    let slot = worker_slot();
    let Some(worker) = slot.as_ref() else {
        return CancelAttempt::NoCurrentIo;
    };
    // SAFETY: WORKER retains the live Windows thread handle through process exit. Cancellation is
    // best-effort and targets only synchronous I/O issued by this one-purpose worker.
    if unsafe { CancelSynchronousIo(worker.as_raw_handle() as HANDLE) } != 0 {
        CancelAttempt::Requested
    } else if std::io::Error::last_os_error().raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        CancelAttempt::NoCurrentIo
    } else {
        CancelAttempt::Failed
    }
}

fn worker_slot() -> MutexGuard<'static, Option<JoinHandle<()>>> {
    WORKER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn finish_confirmed_worker() {
    QUERY_GATE.complete();
    // A reply or channel disconnect proves no synchronous write remains. Dropping (not joining)
    // closes the Windows thread handle without adding an unbounded wait to the caller.
    drop(worker_slot().take());
}

fn write_keyboard_query_once(request: &KeyboardQueryRequest) -> std::io::Result<usize> {
    if request.should_abort(Instant::now()) {
        return Err(query_cancelled());
    }
    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open("CONOUT$")?;
    if request.should_abort(Instant::now()) {
        return Err(query_cancelled());
    }
    let mut written = 0_u32;
    // SAFETY: output is a live worker-owned console handle, the query is a live static byte slice,
    // `written` is valid for this call, and no OVERLAPPED pointer is supplied. Cancellation can
    // still land in the final check-to-syscall window; the caller retries CancelSynchronousIo and,
    // if completion remains unconfirmed, permanently poisons and retains this sole worker.
    let succeeded = unsafe {
        WriteFile(
            output.as_raw_handle() as HANDLE,
            KEYBOARD_ENHANCEMENT_PROTOCOL_QUERY.as_ptr(),
            KEYBOARD_ENHANCEMENT_PROTOCOL_QUERY.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

fn query_cancelled() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "keyboard capability query write timed out",
    )
}

fn worker_disconnected() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "keyboard capability query worker stopped without a result",
    )
}

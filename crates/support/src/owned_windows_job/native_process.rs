//! One retained process handle created by the ConPTY launcher. Numeric PID data never authorizes
//! a kill or a wait, and a real signaled-handle/status observation retires the handle exactly once.
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
};

#[derive(Debug)]
pub(super) struct NativeProcess {
    handle: Option<OwnedHandle>,
    pid: u32,
    status: Option<ExitStatus>,
}

impl NativeProcess {
    pub(super) fn created(handle: OwnedHandle, pid: u32) -> Self {
        Self {
            handle: Some(handle),
            pid,
            status: None,
        }
    }

    pub(super) fn handle(&self) -> io::Result<&OwnedHandle> {
        self.handle
            .as_ref()
            .ok_or_else(|| io::Error::other("native process reference already retired"))
    }

    pub(super) fn id(&self) -> Option<u32> {
        self.handle.as_ref().map(|_| self.pid)
    }

    pub(super) fn kill(&self) -> io::Result<()> {
        let Some(handle) = &self.handle else {
            return Ok(());
        };
        if unsafe { TerminateProcess(handle.as_raw_handle(), super::CLEANUP_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let handle = self.handle()?;
        match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // A signaled process can legitimately have exit code STILL_ACTIVE (259); the
                // wait receipt, not that code, proves termination. Release its Job reference.
                let status = ExitStatus::from_raw(code);
                self.status = Some(status);
                self.handle = None;
                Ok(Some(status))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
}

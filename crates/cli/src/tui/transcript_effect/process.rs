//! Exact subprocess registration and joined owner-drop cleanup.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ProcessState {
    closing: bool,
    pids: HashSet<u32>,
}

/// Spawn/reap authority shared by every subprocess owned by one effect supervisor. The mutex is
/// held across spawn plus pid registration, so `Drop` cannot miss a child in the spawn/register
/// gap. Normal async waits unregister only after reaping; emergency owner-drop kills and joins
/// every registered child synchronously before ownership returns.
#[derive(Clone, Default)]
pub(in crate::tui) struct ProcessRegistry(Arc<Mutex<ProcessState>>);

impl ProcessRegistry {
    pub(in crate::tui) fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> std::io::Result<tokio::process::Child> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closing {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "effect supervisor is closing",
            ));
        }
        let child = command.spawn()?;
        if let Some(pid) = child.id() {
            state.pids.insert(pid);
        }
        Ok(child)
    }

    pub(in crate::tui) fn reaped(&self, pid: Option<u32>) {
        let Some(pid) = pid else {
            return;
        };
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pids
            .remove(&pid);
    }

    /// Force-kill and synchronously join one exact registered child. This is the fallback after an
    /// async reap deadline expires or its wait evidence errors; it deliberately has no detached
    /// continuation, because returning while the helper can still publish is not an ownership
    /// boundary.
    pub(in crate::tui) fn reap_exact(&self, pid: Option<u32>) {
        let Some(pid) = pid else {
            return;
        };
        #[cfg(unix)]
        {
            let pid = pid as libc::pid_t;
            // SAFETY: the registry contains only exact child pids returned by `Child::id`. SIGKILL
            // is used solely during cleanup; `waitpid` joins that exact child, retrying EINTR.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                loop {
                    let waited = libc::waitpid(pid, std::ptr::null_mut(), 0);
                    if waited == pid {
                        break;
                    }
                    if waited == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    {
                        continue;
                    }
                    // ECHILD means an async waiter won the reap race; either result is joined.
                    break;
                }
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_TERMINATE, SYNCHRONIZE, TerminateProcess, WaitForSingleObject,
            };

            // SAFETY: this opens, terminates, joins, and closes the exact registered child process.
            unsafe {
                let process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid);
                if !process.is_null() {
                    TerminateProcess(process, 1);
                    WaitForSingleObject(process, u32::MAX);
                    CloseHandle(process);
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        let _ = pid;
        self.reaped(Some(pid));
    }

    pub(in crate::tui) fn close_and_reap(&self) {
        let pids = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.closing = true;
            state.pids.iter().copied().collect::<Vec<_>>()
        };
        for pid in pids {
            self.reap_exact(Some(pid));
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(in crate::tui) fn is_empty(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pids
            .is_empty()
    }
}

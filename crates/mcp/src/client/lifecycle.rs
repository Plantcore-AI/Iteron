//! Exclusive child/process-group ownership and bounded cleanup.

use std::{io, process::ExitStatus, time::Duration};
use tokio::process::{Child, ChildStdin, ChildStdout};

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const SYNCHRONOUS_REAP_CEILING: Duration = Duration::from_secs(2);
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Owns the direct child and the one-shot authority to signal its process group. The group token
/// is always spent while the direct pid is live or an unreaped zombie, before any operation that
/// can make the pid reusable.
pub(super) struct OwnedProcess {
    child: Option<Child>,
    #[cfg(unix)]
    group: ProcessGroupToken,
}

impl OwnedProcess {
    pub(super) fn new(child: Child) -> Self {
        #[cfg(unix)]
        let group = ProcessGroupToken::new(child.id());
        Self {
            child: Some(child),
            #[cfg(unix)]
            group,
        }
    }

    pub(super) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    pub(super) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    /// Reconcile direct-child liveness without reaping before descendant cleanup. `false` means
    /// the exited child and every remaining member of its owned process group were force-cleaned.
    pub(super) fn reconcile_liveness(&mut self) -> io::Result<bool> {
        let Some(child) = self.child.as_mut() else {
            return Ok(false);
        };

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        {
            match child_exit_is_pending(child.id()) {
                Ok(false) => Ok(true),
                Ok(true) => {
                    self.force_cleanup_sync();
                    Ok(false)
                }
                Err(error) => {
                    // An observation error breaks the exclusive-pid proof. Never retain a numeric
                    // group token that could later address a reused pgid.
                    self.group.abandon();
                    Err(error)
                }
            }
        }

        #[cfg(all(
            unix,
            not(any(target_os = "linux", target_os = "android", target_os = "macos"))
        ))]
        {
            // These targets have no reviewed WNOWAIT ABI in this crate. Fail closed and spend the
            // still-pinned group token instead of reaping first and retaining a reusable pgid.
            self.force_cleanup_sync();
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "safe MCP child liveness observation is unavailable on this Unix target",
            ))
        }

        #[cfg(not(unix))]
        {
            match child.try_wait()? {
                Some(_) => {
                    self.child = None;
                    Ok(false)
                }
                None => Ok(true),
            }
        }
    }

    /// Terminate the process group, then reap the direct child. The normal async stop path keeps a
    /// short grace period, while group authority remains pinned by the unreaped direct pid.
    pub(super) async fn terminate_and_reap(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;

        #[cfg(unix)]
        self.group.signal(SIGTERM);

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        {
            let grace_deadline = tokio::time::Instant::now() + TERMINATION_GRACE;
            loop {
                match child_exit_is_pending(child.id()) {
                    Ok(true) => break,
                    Ok(false) if tokio::time::Instant::now() < grace_deadline => {
                        tokio::time::sleep(REAP_POLL_INTERVAL).await;
                    }
                    Ok(false) => break,
                    Err(_) => {
                        self.group.abandon();
                        break;
                    }
                }
            }
        }

        #[cfg(unix)]
        self.group.force_kill();
        let _ = child.start_kill();
        let waited = tokio::time::timeout(SYNCHRONOUS_REAP_CEILING, child.wait())
            .await
            .ok()
            .and_then(Result::ok);
        if waited.is_some() {
            self.child = None;
        } else {
            self.reap_direct_child_sync();
        }
        waited
    }

    pub(super) fn force_cleanup_sync(&mut self) {
        #[cfg(unix)]
        self.group.force_kill();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        self.reap_direct_child_sync();
    }

    fn reap_direct_child_sync(&mut self) {
        let deadline = std::time::Instant::now() + SYNCHRONOUS_REAP_CEILING;
        loop {
            let result = match self.child.as_mut() {
                Some(child) => child.try_wait(),
                None => return,
            };
            match result {
                Ok(Some(_)) => {
                    self.child = None;
                    return;
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(REAP_POLL_INTERVAL);
                }
                Ok(None) | Err(_) => return,
            }
        }
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // This path is intentionally synchronous: it also runs after the spawning Tokio runtime
        // has been dropped and never delegates ownership to an unjoined task.
        self.force_cleanup_sync();
    }
}

#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
const SIGTERM: i32 = 15;

#[cfg(unix)]
struct ProcessGroupToken {
    pid: Option<i32>,
    armed: bool,
}

#[cfg(unix)]
impl ProcessGroupToken {
    fn new(pid: Option<u32>) -> Self {
        Self {
            pid: pid.and_then(|pid| i32::try_from(pid).ok()),
            armed: true,
        }
    }

    fn signal(&self, signal: i32) {
        if self.armed {
            signal_process_group(self.pid, signal);
        }
    }

    fn force_kill(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        signal_process_group(self.pid, SIGKILL);
    }

    fn abandon(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
fn signal_process_group(pid: Option<i32>, signal: i32) {
    let Some(pid) = pid.filter(|pid| *pid > 0) else {
        return;
    };
    // SAFETY: the negative id addresses the process group created for this exclusively owned
    // direct child. Callers spend the token before reaping, while that pid cannot be reused.
    unsafe {
        unix_ffi::kill(-pid, signal);
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn child_exit_is_pending(pid: Option<u32>) -> io::Result<bool> {
    let pid = pid.ok_or_else(|| io::Error::other("MCP child has no process id"))?;
    let mut info = unix_ffi::SigInfo::default();
    // SAFETY: `info` is an aligned, oversized zeroed buffer for siginfo_t. P_PID scopes the query
    // to the exclusively owned child and WNOWAIT deliberately leaves it unreaped.
    let result = unsafe {
        unix_ffi::waitid(
            unix_ffi::P_PID,
            pid,
            &mut info,
            unix_ffi::WEXITED | unix_ffi::WNOWAIT | unix_ffi::WNOHANG,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.0.iter().any(|byte| *byte != 0))
}

#[cfg(unix)]
mod unix_ffi {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    pub(super) const P_PID: i32 = 1;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    pub(super) const WNOHANG: i32 = 1;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    pub(super) const WEXITED: i32 = 4;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) const WNOWAIT: i32 = 0x0100_0000;
    #[cfg(target_os = "macos")]
    pub(super) const WNOWAIT: i32 = 0x20;

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[repr(C, align(16))]
    pub(super) struct SigInfo(pub(super) [u8; 256]);

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    impl Default for SigInfo {
        fn default() -> Self {
            Self([0; 256])
        }
    }

    unsafe extern "C" {
        pub(super) fn kill(pid: i32, signal: i32) -> i32;
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        pub(super) fn waitid(id_type: i32, id: u32, info: *mut SigInfo, options: i32) -> i32;
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[tokio::test]
    async fn exit_observation_leaves_the_direct_child_unreaped() {
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 23"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        core_sandbox::configure_process_group(&mut command);
        let child = command.spawn().unwrap();
        let mut process = OwnedProcess::new(child);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if child_exit_is_pending(process.child.as_ref().and_then(Child::id)).unwrap() {
                    break;
                }
                tokio::time::sleep(REAP_POLL_INTERVAL).await;
            }
        })
        .await
        .expect("child never became waitable without reap");
        assert!(process.child.as_ref().and_then(Child::id).is_some());
        assert!(!process.reconcile_liveness().unwrap());
        assert!(process.child.is_none());
    }
}

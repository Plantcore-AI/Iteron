//! Confined persistent child processes with explicit pipe semantics.
//!
//! This is deliberately not a PTY abstraction. Linux uses the same bubblewrap confinement as the
//! one-shot sandbox plus its PID namespace and parent-death semantics, while giving an owning
//! controller bounded access to stdin/stdout/stderr. Other platforms refuse before spawn: macOS
//! process groups cannot contain a descendant that calls `setsid`, and Windows needs a Job Object.

use crate::{Confinement, SandboxError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
use std::process::Stdio;

/// The confinement backend and transport actually used by a persistent process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentBackend {
    LinuxBubblewrapPipes,
}

impl PersistentBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxBubblewrapPipes => "linux-bubblewrap-pipes",
        }
    }
}

/// A confined child whose direct process is killed on drop.
///
/// The caller must additionally impose a wall-clock deadline and drain both output pipes. The
/// tools supervisor does both and explicitly kills the process group before abnormal drop.
pub struct ConfinedProcess {
    child: tokio::process::Child,
    backend: PersistentBackend,
    control: ConfinedProcessControl,
    #[cfg(unix)]
    exit_signal: tokio::signal::unix::Signal,
}

struct ProcessGroupToken {
    #[cfg(unix)]
    pid: Option<u32>,
    armed: AtomicBool,
}

/// An opaque cleanup capability minted for one confined process group.
///
/// The raw pid is never exposed, so callers cannot turn model-controlled numbers into signals for
/// arbitrary host processes. Normal completion spends the token while the direct child is still
/// unreaped; abnormal ownership loss spends it immediately so a reusable pgid is never retained.
#[derive(Clone)]
pub struct ConfinedProcessControl(Arc<ProcessGroupToken>);

impl ConfinedProcessControl {
    #[cfg(unix)]
    fn signal_while_owned(&self, signal: libc::c_int) {
        if self.0.armed.load(Ordering::Acquire) {
            crate::signal_process_group(self.0.pid, signal);
        }
    }

    #[cfg(unix)]
    fn abandon(&self) {
        self.0.armed.swap(false, Ordering::AcqRel);
    }

    /// Spend this process-specific cleanup capability exactly once.
    ///
    /// One-shot consumption is load-bearing: retaining an armed numeric process-group token after
    /// an uncertain reap could later signal an unrelated group if the kernel reused the pgid.
    pub fn force_kill(&self) {
        if !self.0.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        #[cfg(unix)]
        crate::signal_process_group(self.0.pid, libc::SIGKILL);
    }
}

impl ConfinedProcess {
    pub fn backend(&self) -> PersistentBackend {
        self.backend
    }

    pub fn control(&self) -> ConfinedProcessControl {
        self.control.clone()
    }

    pub fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }

    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(unix)]
        {
            // `Child::wait` reaps immediately, after which the numeric pgid can be reused. Observe
            // the exit with WNOWAIT, kill residual group members while the zombie still pins the
            // pid, and only then reap the direct child.
            if let Err(error) = self.wait_until_exit_unreaped().await {
                // An observation failure breaks the exclusive-pid proof. Leak/quarantine is safer
                // than retaining a numeric kill capability that could later address a reused pgid.
                self.control.abandon();
                return Err(error);
            }
            self.control.force_kill();
        }
        self.child.wait().await
    }

    pub async fn terminate_and_reap(&mut self) -> Option<std::process::ExitStatus> {
        #[cfg(unix)]
        {
            self.control.signal_while_owned(libc::SIGTERM);
            let observed = tokio::time::timeout(
                std::time::Duration::from_millis(crate::TERMINATION_GRACE_MS),
                self.wait_until_exit_unreaped(),
            )
            .await;
            if matches!(observed, Ok(Err(_))) {
                self.control.abandon();
                return None;
            }
            // Whether the child is still live or is an unreaped zombie, its pid cannot yet have
            // been reused. Spend the group token before the direct-child reap below.
            self.control.force_kill();
        }
        let _ = self.child.start_kill();
        tokio::time::timeout(
            std::time::Duration::from_secs(crate::POST_KILL_DRAIN_SECS),
            self.child.wait(),
        )
        .await
        .ok()
        .and_then(Result::ok)
    }

    #[cfg(unix)]
    async fn wait_until_exit_unreaped(&mut self) -> std::io::Result<()> {
        loop {
            if child_exit_is_pending(self.child.id())? {
                return Ok(());
            }
            if self.exit_signal.recv().await.is_none() {
                return Err(std::io::Error::other(
                    "SIGCHLD observer closed before the child became waitable",
                ));
            }
        }
    }
}

impl Drop for ConfinedProcess {
    fn drop(&mut self) {
        self.control.force_kill();
    }
}

/// Spawn one command under the platform confinement with piped standard streams.
///
/// Linux uses a capability-probed root-owned bubblewrap with `--unshare-pid` and
/// `--die-with-parent`. Every other platform returns [`SandboxError::Unsupported`] before child
/// spawn. This function never falls back to an unconfined process.
pub async fn spawn_confined_process(
    command: &str,
    conf: &Confinement,
) -> Result<ConfinedProcess, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        let Some(binary) = crate::bubblewrap::Bubblewrap::usable_bwrap_off_worker().await else {
            return Err(SandboxError::Unsupported);
        };
        let mut process = tokio::process::Command::new(binary);
        process.args(crate::bubblewrap::bwrap_args(conf, command));
        configure_pipes(&mut process, conf);
        spawn_checked(process, PersistentBackend::LinuxBubblewrapPipes).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, conf);
        Err(SandboxError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
fn configure_pipes(process: &mut tokio::process::Command, conf: &Confinement) {
    crate::confine_env_with_exact(process, &conf.sensitive_env_names);
    process
        .env("TERM", "dumb")
        .env("PAGER", "cat")
        .env("MANPAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("PIP_PROGRESS_BAR", "off")
        .env("TQDM_DISABLE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    crate::configure_process_group(process);
}

#[cfg(target_os = "linux")]
async fn spawn_checked(
    mut command: tokio::process::Command,
    backend: PersistentBackend,
) -> Result<ConfinedProcess, SandboxError> {
    let exit_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .map_err(|error| SandboxError::Spawn(format!("install SIGCHLD observer: {error}")))?;
    let child = command
        .spawn()
        .map_err(|error| SandboxError::Spawn(error.to_string()))?;
    let control = ConfinedProcessControl(Arc::new(ProcessGroupToken {
        #[cfg(unix)]
        pid: child.id(),
        armed: AtomicBool::new(true),
    }));
    if child.stdin.is_none() || child.stdout.is_none() || child.stderr.is_none() {
        let mut process = ConfinedProcess {
            child,
            backend,
            control,
            exit_signal,
        };
        let _ = process.terminate_and_reap().await;
        return Err(SandboxError::Spawn(
            "persistent child did not expose all configured pipes".into(),
        ));
    }
    Ok(ConfinedProcess {
        control,
        child,
        backend,
        exit_signal,
    })
}

#[cfg(unix)]
fn child_exit_is_pending(pid: Option<u32>) -> std::io::Result<bool> {
    let pid = pid.ok_or_else(|| std::io::Error::other("persistent child has no process id"))?;
    let id: libc::id_t = pid;
    // SAFETY: a zeroed siginfo_t is the documented WNOHANG sentinel. P_PID scopes observation to
    // the child exclusively owned by ConfinedProcess, and WNOWAIT deliberately leaves it
    // unreaped so its pid/pgid cannot be reused before group cleanup.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        if libc::waitid(
            libc::P_PID,
            id,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        ) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.si_pid() != 0)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::child_exit_is_pending;
    use std::process::Stdio;
    use std::time::Duration;

    #[tokio::test]
    async fn exit_observation_does_not_reap_or_lose_the_status() {
        let mut exit_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).unwrap();
        let mut command = tokio::process::Command::new(crate::confined_shell());
        command
            .arg("-c")
            .arg("exit 23")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        crate::configure_process_group(&mut command);
        let mut child = command.spawn().unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if child_exit_is_pending(child.id()).unwrap() {
                    break;
                }
                exit_signal.recv().await.unwrap();
            }
        })
        .await
        .expect("child never became waitable without reap");

        let status = child.wait().await.unwrap();
        assert_eq!(status.code(), Some(23));
    }
}

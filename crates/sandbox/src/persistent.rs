//! Confined persistent child processes with explicit pipe semantics.
//!
//! This is deliberately not a PTY abstraction. Linux uses the same bubblewrap confinement as the
//! one-shot sandbox plus its PID namespace and parent-death semantics. macOS uses Seatbelt plus a
//! dedicated process group for protocol-style children that require distinct stdin/stdout/stderr.
//! Windows still refuses before spawn because it needs a Job Object.

use crate::{Confinement, SandboxError};
use std::fs::File;
use std::sync::Arc;
use std::sync::Mutex;

#[cfg(unix)]
use std::process::Stdio;

/// The confinement backend and transport actually used by a persistent process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentBackend {
    LinuxBubblewrapPipes,
    LinuxBubblewrapPty,
    MacOsSeatbeltPipes,
    MacOsSeatbeltPty,
}

impl PersistentBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxBubblewrapPipes => "linux-bubblewrap-pipes",
            Self::LinuxBubblewrapPty => "linux-bubblewrap-pty",
            Self::MacOsSeatbeltPipes => "macos-seatbelt-pipes",
            Self::MacOsSeatbeltPty => "macos-seatbelt-pty",
        }
    }
}

/// A confined child whose process-group capability is finitely spent on drop. The implementation
/// makes a bounded direct-child reap attempt; callers that require a confirmed terminal state must
/// call `wait` or `terminate_and_reap` and inspect the result before returning.
///
/// The caller must additionally impose a wall-clock deadline and drain both output pipes. The
/// tools supervisor does both and explicitly kills the process group before abnormal drop.
pub struct ConfinedProcess {
    child: tokio::process::Child,
    backend: PersistentBackend,
    control: ConfinedProcessControl,
    #[cfg(unix)]
    exit_signal: tokio::signal::unix::Signal,
    #[cfg(target_os = "macos")]
    _scratch: Option<crate::seatbelt::ScratchCleanup>,
}

struct ProcessGroupToken {
    #[cfg(unix)]
    pid: Option<u32>,
    armed: Mutex<bool>,
}

/// An opaque cleanup capability minted for one confined process group.
///
/// The raw pid is never exposed, so callers cannot turn model-controlled numbers into signals for
/// arbitrary host processes. Normal completion spends the token while the direct child is still
/// unreaped; abnormal ownership loss spends it immediately so a reusable pgid is never retained.
#[derive(Clone)]
pub struct ConfinedProcessControl(Arc<ProcessGroupToken>);

impl ConfinedProcessControl {
    pub(crate) fn for_child(_pid: Option<u32>) -> Self {
        Self(Arc::new(ProcessGroupToken {
            #[cfg(unix)]
            pid: _pid,
            armed: Mutex::new(true),
        }))
    }

    #[cfg(unix)]
    pub(crate) fn signal_while_owned(&self, signal: libc::c_int) {
        let armed = self
            .0
            .armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *armed {
            crate::signal_process_group(self.0.pid, signal);
        }
    }

    #[cfg(unix)]
    pub(crate) fn abandon(&self) {
        *self
            .0
            .armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }

    /// Spend this process-specific cleanup capability exactly once.
    ///
    /// One-shot consumption is load-bearing: retaining an armed numeric process-group token after
    /// an uncertain reap could later signal an unrelated group if the kernel reused the pgid.
    pub fn force_kill(&self) {
        // The signal syscall and the armed -> spent transition are one mutex-serialized action.
        // A process owner that lost this race cannot observe `spent` and reap the direct child
        // until the winner has finished addressing the still-pinned pgid. An atomic swap before
        // `kill(2)` would leave a PID-reuse window between those two operations.
        self.spend_with(|| {
            #[cfg(unix)]
            crate::signal_process_group(self.0.pid, libc::SIGKILL);
        });
    }

    fn spend_with(&self, action: impl FnOnce()) {
        let mut armed = self
            .0
            .armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*armed {
            return;
        }
        action();
        *armed = false;
    }
}

impl ConfinedProcess {
    pub fn backend(&self) -> PersistentBackend {
        self.backend
    }

    pub fn control(&self) -> ConfinedProcessControl {
        self.control.clone()
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn direct_pid(&self) -> Option<u32> {
        self.child.id()
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

    /// Cancellation/no-runtime fallback: spend the group capability before any reap, then poll the
    /// exact owned direct child for a fixed interval. This never starts detached runtime work and
    /// never retains a numeric process-group identity after returning.
    pub fn terminate_and_reap_blocking(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<std::process::ExitStatus> {
        self.control.force_kill();
        let _ = self.child.start_kill();
        let deadline = std::time::Instant::now().checked_add(timeout)?;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(
                        iteron_tunables::param_integer(
                            "sandbox.lib.blocking_reap_poll_ms",
                            crate::BLOCKING_REAP_POLL_MS,
                        ),
                    ));
                }
                Ok(None) | Err(_) => return None,
            }
        }
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
        let _ = self.terminate_and_reap_blocking(std::time::Duration::from_secs(
            crate::POST_KILL_DRAIN_SECS,
        ));
    }
}

/// Spawn one command under the platform confinement with piped standard streams.
///
/// Linux uses a capability-probed root-owned bubblewrap with `--unshare-pid` and
/// `--die-with-parent`; macOS uses Seatbelt and a dedicated process group. This function never
/// falls back to an unconfined process.
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
        process.args(crate::bubblewrap::bwrap_args_for_persistent(conf, command));
        configure_pipes(&mut process, conf);
        spawn_checked(process, PersistentBackend::LinuxBubblewrapPipes, None).await
    }

    #[cfg(target_os = "macos")]
    {
        spawn_macos_pipes(command, conf, None).await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (command, conf);
        Err(SandboxError::Unsupported)
    }
}

/// Spawn against an already-open workspace directory capability.
///
/// On Linux a CLOEXEC duplicate is made inheritable only in the exact fork child, then supplied to
/// bubblewrap's native `--bind-fd`. Bubblewrap verifies the mounted dev/inode and closes the fd
/// before the fixed server command is executed. This closes both pathname substitution and
/// concurrent-spawn descriptor leakage windows.
pub async fn spawn_confined_process_from_workspace(
    command: &str,
    conf: &Confinement,
    workspace: &File,
) -> Result<ConfinedProcess, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;

        let Some(binary) = crate::bubblewrap::Bubblewrap::usable_bwrap_off_worker().await else {
            return Err(SandboxError::Unsupported);
        };
        let inherited = crate::bubblewrap::duplicate_for_child(
            workspace,
            crate::bubblewrap::CHILD_INHERITED_FD_FLOOR,
        )
        .map_err(|_| SandboxError::Profile("workspace descriptor admission failed".into()))?;
        let descriptor = inherited.as_raw_fd();
        let mut process = tokio::process::Command::new(binary);
        process.args(crate::bubblewrap::bwrap_args_with_workspace_fd(
            conf, command, descriptor,
        ));
        crate::bubblewrap::inherit_fd_in_tokio_command(&mut process, descriptor);
        configure_pipes(&mut process, conf);
        let spawned = spawn_checked(process, PersistentBackend::LinuxBubblewrapPipes, None).await;
        drop(inherited);
        spawned
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt as _;

        let pinned = workspace.metadata().map_err(|error| {
            SandboxError::Profile(format!("inspect workspace capability: {error}"))
        })?;
        let visible = std::fs::metadata(&conf.workspace)
            .map_err(|error| SandboxError::Profile(format!("inspect workspace path: {error}")))?;
        if pinned.dev() != visible.dev() || pinned.ino() != visible.ino() {
            return Err(SandboxError::Profile(
                "workspace path no longer names the admitted directory capability".into(),
            ));
        }
        spawn_macos_pipes(command, conf, Some(workspace)).await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (command, conf, workspace);
        Err(SandboxError::Unsupported)
    }
}

#[cfg(target_os = "macos")]
async fn spawn_macos_pipes(
    command: &str,
    conf: &Confinement,
    workspace: Option<&File>,
) -> Result<ConfinedProcess, SandboxError> {
    use std::os::fd::AsRawFd as _;

    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(SandboxError::Unsupported);
    }
    crate::seatbelt::prepare_private_scratch(&conf.scratch)?;
    let scratch = crate::seatbelt::ScratchCleanup(conf.scratch.clone());
    let profile = crate::seatbelt::profile(conf)?;
    let mut process = tokio::process::Command::new("/usr/bin/sandbox-exec");
    process
        .arg("-p")
        .arg(profile)
        .arg(crate::confined_shell())
        .arg("-c")
        .arg(command);
    if let Some(workspace) = workspace {
        let pinned = workspace.try_clone().map_err(|error| {
            SandboxError::Profile(format!("duplicate workspace capability: {error}"))
        })?;
        let descriptor = pinned.as_raw_fd();
        // SAFETY: `fchdir` is async-signal-safe and the owned CLOEXEC duplicate is captured by the
        // callback, so it remains live in the fork child until cwd has been bound to that exact
        // directory vnode. Exec then closes it rather than leaking the capability to the server.
        unsafe {
            process.pre_exec(move || {
                let _keep_capability_live = &pinned;
                if libc::fchdir(descriptor) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        process.current_dir(&conf.workspace);
    }
    configure_pipes(&mut process, conf);
    spawn_checked(
        process,
        PersistentBackend::MacOsSeatbeltPipes,
        Some(scratch),
    )
    .await
}

#[cfg(unix)]
fn configure_pipes(process: &mut tokio::process::Command, conf: &Confinement) {
    crate::apply_confinement_environment(process, conf);
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

#[cfg(unix)]
async fn spawn_checked(
    mut command: tokio::process::Command,
    backend: PersistentBackend,
    #[cfg(target_os = "macos")] scratch: Option<crate::seatbelt::ScratchCleanup>,
    #[cfg(not(target_os = "macos"))] _scratch: Option<()>,
) -> Result<ConfinedProcess, SandboxError> {
    let exit_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .map_err(|error| SandboxError::Spawn(format!("install SIGCHLD observer: {error}")))?;
    let child = command
        .spawn()
        .map_err(|error| SandboxError::Spawn(error.to_string()))?;
    let control = ConfinedProcessControl(Arc::new(ProcessGroupToken {
        #[cfg(unix)]
        pid: child.id(),
        armed: Mutex::new(true),
    }));
    if child.stdin.is_none() || child.stdout.is_none() || child.stderr.is_none() {
        let mut process = ConfinedProcess {
            child,
            backend,
            control,
            exit_signal,
            #[cfg(target_os = "macos")]
            _scratch: scratch,
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
        #[cfg(target_os = "macos")]
        _scratch: scratch,
    })
}

#[cfg(unix)]
pub(crate) fn child_exit_is_pending(pid: Option<u32>) -> std::io::Result<bool> {
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
    use super::{
        ConfinedProcess, ConfinedProcessControl, PersistentBackend, ProcessGroupToken,
        child_exit_is_pending,
    };
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    #[cfg(target_os = "macos")]
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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

    #[tokio::test]
    async fn blocking_fallback_kills_group_and_reaps_the_direct_child() {
        let exit_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).unwrap();
        let mut command = tokio::process::Command::new(crate::confined_shell());
        command
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        crate::configure_process_group(&mut command);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let control = ConfinedProcessControl(Arc::new(ProcessGroupToken {
            pid: Some(pid),
            armed: Mutex::new(true),
        }));
        let mut process = ConfinedProcess {
            child,
            backend: PersistentBackend::LinuxBubblewrapPipes,
            control,
            exit_signal,
            #[cfg(target_os = "macos")]
            _scratch: None,
        };
        assert!(
            process
                .terminate_and_reap_blocking(Duration::from_secs(2))
                .is_some()
        );
        // SAFETY: signal zero performs no mutation and only tests the exact formerly owned pid.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn seatbelt_pipe_child_uses_pinned_workspace_and_round_trips_protocol_bytes() {
        let workspace = std::env::temp_dir().join(format!(
            "core-seatbelt-pipes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("workspace-marker"), b"yes").unwrap();
        let root = std::fs::File::open(&workspace).unwrap();
        let confinement = crate::Confinement::egress_off(&workspace);
        let mut process = super::spawn_confined_process_from_workspace(
            "test -f workspace-marker || exit 17; IFS= read -r line; printf 'reply:%s' \"$line\"",
            &confinement,
            &root,
        )
        .await
        .unwrap();
        assert_eq!(process.backend(), PersistentBackend::MacOsSeatbeltPipes);
        let mut stdin = process.take_stdin().unwrap();
        let mut stdout = process.take_stdout().unwrap();
        let mut stderr = process.take_stderr().unwrap();
        stdin.write_all(b"ping\n").await.unwrap();
        drop(stdin);
        let mut output = String::new();
        let mut diagnostics = String::new();
        let (status, stdout_result, stderr_result) = tokio::join!(
            process.wait(),
            stdout.read_to_string(&mut output),
            stderr.read_to_string(&mut diagnostics),
        );
        assert!(
            status.unwrap().success(),
            "seatbelt diagnostics: {diagnostics}"
        );
        stdout_result.unwrap();
        stderr_result.unwrap();
        assert_eq!(output, "reply:ping");
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn losing_cleanup_cannot_pass_the_winning_signal_boundary() {
        let control = ConfinedProcessControl(Arc::new(ProcessGroupToken {
            pid: None,
            armed: Mutex::new(true),
        }));
        let claimed = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let winner = {
            let control = control.clone();
            let claimed = Arc::clone(&claimed);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                control.spend_with(|| {
                    claimed.wait();
                    release.wait();
                });
            })
        };
        claimed.wait();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let loser = {
            let control = control.clone();
            std::thread::spawn(move || {
                control.spend_with(|| {});
                done_tx.send(()).unwrap();
            })
        };
        assert!(
            done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "a losing owner must not proceed to reap before the winning signal action finishes"
        );
        release.wait();
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        winner.join().unwrap();
        loser.join().unwrap();
    }
}

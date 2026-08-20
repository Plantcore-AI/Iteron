//! Confined long-lived children backed by a real kernel pseudo-terminal.

use crate::persistent::{ConfinedProcessControl, PersistentBackend, child_exit_is_pending};
use crate::pty::{PtyPair, WindowSize, make_controlling_terminal};
use crate::pty_async::{AsyncPty, PtyInput, PtyOutput, PtyResize};
use crate::{Confinement, SandboxError};
use std::os::fd::AsRawFd as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct ConfinedPtyInput(PtyInput);

impl ConfinedPtyInput {
    pub async fn send_eof(&mut self) -> std::io::Result<()> {
        self.0.send_eof().await
    }
}

impl AsyncWrite for ConfinedPtyInput {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}

pub struct ConfinedPtyOutput(PtyOutput);

impl AsyncRead for ConfinedPtyOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(context, buffer)
    }
}

#[derive(Clone)]
pub struct ConfinedPtyResize(PtyResize);

impl ConfinedPtyResize {
    pub fn resize(&self, rows: u16, cols: u16) -> std::io::Result<()> {
        self.0.resize(WindowSize::new(rows, cols)?)
    }
}

pub struct ConfinedPtyProcess {
    child: tokio::process::Child,
    backend: PersistentBackend,
    control: ConfinedProcessControl,
    exit_signal: tokio::signal::unix::Signal,
    input: Option<ConfinedPtyInput>,
    output: Option<ConfinedPtyOutput>,
    resize: ConfinedPtyResize,
    #[cfg(target_os = "macos")]
    _scratch: Option<crate::seatbelt::ScratchCleanup>,
}

impl ConfinedPtyProcess {
    pub fn backend(&self) -> PersistentBackend {
        self.backend
    }

    pub fn control(&self) -> ConfinedProcessControl {
        self.control.clone()
    }

    pub fn resize_control(&self) -> ConfinedPtyResize {
        self.resize.clone()
    }

    pub fn take_input(&mut self) -> Option<ConfinedPtyInput> {
        self.input.take()
    }

    pub fn take_output(&mut self) -> Option<ConfinedPtyOutput> {
        self.output.take()
    }

    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if let Err(error) = self.wait_until_exit_unreaped().await {
            self.control.abandon();
            return Err(error);
        }
        self.control.force_kill();
        self.child.wait().await
    }

    pub async fn terminate_and_reap(&mut self) -> Option<std::process::ExitStatus> {
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
        self.control.force_kill();
        let _ = self.child.start_kill();
        tokio::time::timeout(
            std::time::Duration::from_secs(crate::POST_KILL_DRAIN_SECS),
            self.child.wait(),
        )
        .await
        .ok()
        .and_then(Result::ok)
    }

    fn terminate_and_reap_blocking(
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

    async fn wait_until_exit_unreaped(&mut self) -> std::io::Result<()> {
        loop {
            if child_exit_is_pending(self.child.id())? {
                return Ok(());
            }
            if self.exit_signal.recv().await.is_none() {
                return Err(std::io::Error::other(
                    "SIGCHLD observer closed before the pty child became waitable",
                ));
            }
        }
    }
}

impl Drop for ConfinedPtyProcess {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap_blocking(std::time::Duration::from_secs(
            crate::POST_KILL_DRAIN_SECS,
        ));
    }
}

pub async fn spawn_confined_pty_process(
    command: &str,
    conf: &Confinement,
    size: WindowSize,
) -> Result<ConfinedPtyProcess, SandboxError> {
    // Before any platform probe, because there is nothing here for a sandbox to enforce.
    //
    // Every non-PTY backend already did this -- `bubblewrap.rs`, `seatbelt.rs` and the one-shot
    // path in `lib.rs` each delegate to `run_direct` on this bit, and the comment on that function
    // claims "every backend delegates here when `conf.unconfined` is set". These two branches did
    // not, which made that claim false and had two consequences an operator could see: on macOS a
    // default `bash` was handed to `/usr/bin/sandbox-exec` and could not reach a path outside the
    // workspace despite the unconfined contract, and on Linux it refused to start at all when
    // bubblewrap was absent -- an unconfined process failing on a tool it has no reason to use.
    //
    // `configure_pty_environment` is given no scratch here for the same reason `run_direct` skips
    // it: a private temp directory exists to keep a CONFINED child out of the ambient one, so an
    // unconfined child keeps the operator's own `TMPDIR`.
    if conf.unconfined {
        let mut process = tokio::process::Command::new(crate::confined_shell());
        process.arg("-c").arg(command).current_dir(&conf.workspace);
        configure_pty_environment(&mut process, conf, None);
        return spawn_checked(process, PersistentBackend::DirectPty, size, None, None).await;
    }

    #[cfg(target_os = "linux")]
    {
        let Some(binary) = crate::bubblewrap::Bubblewrap::usable_bwrap_off_worker().await else {
            return Err(SandboxError::Unsupported);
        };
        let mut process = tokio::process::Command::new(binary);
        process.args(crate::bubblewrap::bwrap_args_for_persistent_pty(
            conf, command,
        ));
        configure_pty_environment(&mut process, conf, None);
        return spawn_checked(
            process,
            PersistentBackend::LinuxBubblewrapPty,
            size,
            None,
            None,
        )
        .await;
    }

    #[cfg(target_os = "macos")]
    {
        if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
            return Err(SandboxError::Unsupported);
        }
        crate::seatbelt::prepare_private_scratch(&conf.scratch)?;
        let scratch = crate::seatbelt::ScratchCleanup(conf.scratch.clone());
        let pair = PtyPair::open(size)
            .map_err(|error| SandboxError::Spawn(format!("allocate pty: {error}")))?;
        let profile = crate::seatbelt::profile_with_terminal(conf, pair.slave_name())?;
        let mut process = tokio::process::Command::new("/usr/bin/sandbox-exec");
        process
            .arg("-p")
            .arg(profile)
            .arg(crate::confined_shell())
            .arg("-c")
            .arg(command)
            .current_dir(&conf.workspace);
        configure_pty_environment(&mut process, conf, Some(&conf.scratch));
        return spawn_checked(
            process,
            PersistentBackend::MacOsSeatbeltPty,
            size,
            Some(pair),
            Some(scratch),
        )
        .await;
    }

    #[allow(unreachable_code)]
    Err(SandboxError::Unsupported)
}

fn configure_pty_environment(
    process: &mut tokio::process::Command,
    conf: &Confinement,
    scratch: Option<&std::path::Path>,
) {
    crate::apply_confinement_environment(process, conf);
    process
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("PAGER", "cat")
        .env("MANPAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("PIP_PROGRESS_BAR", "off")
        .env("TQDM_DISABLE", "1")
        .kill_on_drop(true);
    if let Some(scratch) = scratch {
        process
            .env("TMPDIR", scratch)
            .env("TMP", scratch)
            .env("TEMP", scratch);
    }
}

async fn spawn_checked(
    mut command: tokio::process::Command,
    backend: PersistentBackend,
    size: WindowSize,
    pair: Option<PtyPair>,
    #[cfg(target_os = "macos")] scratch: Option<crate::seatbelt::ScratchCleanup>,
    #[cfg(not(target_os = "macos"))] _scratch: Option<()>,
) -> Result<ConfinedPtyProcess, SandboxError> {
    let pair = match pair {
        Some(pair) => pair,
        None => PtyPair::open(size)
            .map_err(|error| SandboxError::Spawn(format!("allocate pty: {error}")))?,
    };
    let slave = pair
        .try_clone_slave()
        .map_err(|error| SandboxError::Spawn(format!("duplicate pty slave: {error}")))?;
    let slave_descriptor = slave.as_raw_fd();
    // SAFETY: the callback runs in the freshly forked child and uses only async-signal-safe calls.
    unsafe {
        command.pre_exec(move || make_controlling_terminal(slave_descriptor));
    }
    let exit_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .map_err(|error| SandboxError::Spawn(format!("install SIGCHLD observer: {error}")))?;
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::Spawn(error.to_string()))?;
    drop(slave);
    let control = ConfinedProcessControl::for_child(child.id());
    let AsyncPty {
        input,
        output,
        resize,
    } = match AsyncPty::from_pair(pair) {
        Ok(pty) => pty,
        Err(error) => {
            control.force_kill();
            let _ = child.start_kill();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(crate::POST_KILL_DRAIN_SECS),
                child.wait(),
            )
            .await;
            return Err(SandboxError::Spawn(format!(
                "register pty with async runtime: {error}"
            )));
        }
    };
    Ok(ConfinedPtyProcess {
        child,
        backend,
        control,
        exit_signal,
        input: Some(ConfinedPtyInput(input)),
        output: Some(ConfinedPtyOutput(output)),
        resize: ConfinedPtyResize(resize),
        #[cfg(target_os = "macos")]
        _scratch: scratch,
    })
}

//! Windows native terminal transport behind the existing confinement decision. A Job owns and
//! retires the process tree; it is never evidence of filesystem, token, or network isolation.
use crate::persistent::{ConfinedProcessControl, PersistentBackend};
use crate::pty::WindowSize;
use crate::{Confinement, SandboxError};
use iteron_support::owned_windows_job::{
    OwnedWindowsPty, WindowsPtyInput, WindowsPtyOutput, WindowsPtyResize,
};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_SHELL_PATH_ENTRIES: usize = 256;

pub struct ConfinedPtyInput(WindowsPtyInput);
impl ConfinedPtyInput {
    pub async fn send_eof(&mut self) -> io::Result<()> {
        self.0.send_eof().await
    }
}
impl AsyncWrite for ConfinedPtyInput {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(context, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}

pub struct ConfinedPtyOutput(WindowsPtyOutput);
impl AsyncRead for ConfinedPtyOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(context, buffer)
    }
}
#[derive(Clone)]
pub struct ConfinedPtyResize(WindowsPtyResize);
impl ConfinedPtyResize {
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        let size = WindowSize::new(rows, cols)?;
        self.0.resize(size.rows(), size.cols())
    }
}

pub struct ConfinedPtyProcess {
    child: OwnedWindowsPty,
    control: ConfinedProcessControl,
}
impl ConfinedPtyProcess {
    pub fn backend(&self) -> PersistentBackend {
        PersistentBackend::WindowsJobConPty
    }
    pub fn control(&self) -> ConfinedProcessControl {
        self.control.clone()
    }
    pub fn resize_control(&self) -> ConfinedPtyResize {
        ConfinedPtyResize(self.child.resize_control())
    }
    pub fn take_input(&mut self) -> Option<ConfinedPtyInput> {
        self.child.take_input().map(ConfinedPtyInput)
    }
    pub fn take_output(&mut self) -> Option<ConfinedPtyOutput> {
        self.child.take_output().map(ConfinedPtyOutput)
    }
    pub async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }
    pub async fn terminate_and_reap(&mut self) -> Option<std::process::ExitStatus> {
        self.control.force_kill();
        self.child.stop_and_reap().await
    }
}

pub async fn spawn_confined_pty_process(
    command: &str,
    confinement: &Confinement,
    size: WindowSize,
) -> Result<ConfinedPtyProcess, SandboxError> {
    // First, before even creating a console or its lifetime workers. There is no Windows OS
    // isolation backend here; explicit unconfined posture is never a fallback for this request.
    if !confinement.unconfined {
        return Err(SandboxError::Unsupported);
    }
    let mut environment = match &confinement.child_environment {
        Some(environment) => {
            let bytes = environment.iter().try_fold(0_usize, |bytes, (key, value)| {
                bytes
                    .checked_add(key.as_encoded_bytes().len())
                    .and_then(|bytes| bytes.checked_add(value.as_encoded_bytes().len()))
                    .and_then(|bytes| bytes.checked_add(1))
            });
            if environment.len() > MAX_ENVIRONMENT_ENTRIES
                || bytes.is_none_or(|bytes| bytes > MAX_ENVIRONMENT_BYTES)
            {
                return Err(SandboxError::Profile(
                    "Windows PTY frozen environment exceeds its physical envelope".into(),
                ));
            }
            environment.clone()
        }
        None => crate::bounded_child_environment(
            true,
            MAX_ENVIRONMENT_ENTRIES,
            MAX_ENVIRONMENT_BYTES,
            &[],
            &confinement.sensitive_env_names,
        )
        .map_err(|reason| SandboxError::Profile(reason.into()))?,
    };
    environment.retain(|(name, _)| {
        name.to_str().is_some_and(|name| {
            !crate::is_shell_startup_env_key(name)
                && !crate::is_secret_env_key(name)
                && !confinement
                    .sensitive_env_names
                    .iter()
                    .any(|blocked| blocked.eq_ignore_ascii_case(name))
        })
    });
    let shell =
        shell_from_snapshot(&environment).map_err(|reason| SandboxError::Profile(reason.into()))?;
    for (name, value) in [
        ("TERM", "xterm-256color"),
        ("COLORTERM", "truecolor"),
        ("PAGER", "cat"),
        ("MANPAGER", "cat"),
        ("GIT_PAGER", "cat"),
        ("PIP_PROGRESS_BAR", "off"),
        ("TQDM_DISABLE", "1"),
    ] {
        environment.retain(|(key, _)| {
            !key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case(name))
        });
        environment.push((name.into(), value.into()));
    }
    let child = OwnedWindowsPty::spawn(
        &shell,
        &[OsString::from("-c"), OsString::from(command)],
        &confinement.workspace,
        &environment,
        size.rows(),
        size.cols(),
    )
    .await
    .map_err(|error| SandboxError::WindowsLaunch(Box::new(error)))?;
    let control = ConfinedProcessControl::for_windows_job(child.job());
    Ok(ConfinedPtyProcess { child, control })
}

fn shell_from_snapshot(environment: &[(OsString, OsString)]) -> Result<PathBuf, &'static str> {
    let path = environment
        .iter()
        .find(|(key, _)| {
            key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case("PATH"))
        })
        .map(|(_, value)| value)
        .ok_or("Windows PTY needs an admitted PATH containing Git Bash")?;
    for (index, directory) in std::env::split_paths(path).enumerate() {
        if index >= MAX_SHELL_PATH_ENTRIES {
            return Err("Windows PTY shell search exceeds its fixed bound");
        }
        if !directory.is_absolute() {
            continue;
        }
        let executable = directory.join("bash.exe");
        if executable.is_file() {
            return executable
                .canonicalize()
                .map_err(|_| "Windows PTY shell identity unavailable");
        }
    }
    Err("Windows PTY needs Git Bash in the admitted absolute PATH")
}

#[cfg(test)]
mod tests {
    use super::shell_from_snapshot;
    #[test]
    fn shell_selection_never_falls_back_to_ambient_or_relative_search() {
        assert!(shell_from_snapshot(&[]).is_err());
        assert!(shell_from_snapshot(&[("PATH".into(), "relative-directory".into())]).is_err());
    }
}

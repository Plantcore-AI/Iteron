//! Windows native terminal transport behind the existing confinement decision. A Job owns and
//! retires the process tree; it is never evidence of filesystem, token, or network isolation.
use crate::persistent::{ConfinedProcessControl, PersistentBackend};
use crate::pty::WindowSize;
use crate::{Confinement, SandboxError};
use iteron_support::owned_windows_job::{
    OwnedWindowsPty, WindowsPtyInput, WindowsPtyOutput, WindowsPtyResize,
};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::windows_launch_plan::Plan;

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
    backend: PersistentBackend,
}
impl ConfinedPtyProcess {
    pub fn backend(&self) -> PersistentBackend {
        self.backend
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
    let plan = Plan::capture(command, confinement, None, true).await?;
    let sandbox = plan.sandbox().await?;
    let confined = sandbox.is_some();
    let child = match sandbox {
        Some(sandbox) => {
            OwnedWindowsPty::spawn_in_sandbox(
                &plan.executable,
                &plan.arguments,
                &plan.directory,
                &plan.environment,
                sandbox,
                size.rows(),
                size.cols(),
            )
            .await
        }
        None => {
            OwnedWindowsPty::spawn(
                &plan.executable,
                &plan.arguments,
                &plan.directory,
                &plan.environment,
                size.rows(),
                size.cols(),
            )
            .await
        }
    }
    .map_err(|error| SandboxError::WindowsLaunch(Box::new(error)))?;
    let control = ConfinedProcessControl::for_windows_job(child.job());
    Ok(ConfinedPtyProcess {
        child,
        control,
        backend: if confined {
            PersistentBackend::WindowsLpacConPty
        } else {
            PersistentBackend::WindowsJobConPty
        },
    })
}

#[cfg(test)]
mod tests {
    use crate::windows_launch_plan::shell_from_snapshot;
    #[test]
    fn shell_selection_never_falls_back_to_ambient_or_relative_search() {
        assert!(shell_from_snapshot(&[]).is_err());
        assert!(shell_from_snapshot(&[("PATH".into(), "relative-directory".into())]).is_err());
    }
}

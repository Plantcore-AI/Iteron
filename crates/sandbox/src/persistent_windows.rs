//! Actual same-Job/same-isolation pipe process ownership. No tokio/std child is created here.
use crate::persistent::{ConfinedProcessControl, PersistentBackend};
use crate::windows_launch_plan::Plan;
use crate::{Confinement, SandboxError};
use iteron_support::owned_windows_job::{OwnedWindowsPipes, WindowsPipeInput, WindowsPipeOutput};
use std::fs::File;
use std::io;
use std::process::ExitStatus;
use std::time::Duration;
pub type ConfinedProcessInput = WindowsPipeInput;
pub type ConfinedProcessOutput = WindowsPipeOutput;
pub type ConfinedProcessError = WindowsPipeOutput;
pub struct ConfinedProcess {
    child: OwnedWindowsPipes,
    control: ConfinedProcessControl,
    backend: PersistentBackend,
}
impl ConfinedProcess {
    pub fn backend(&self) -> PersistentBackend {
        self.backend
    }
    pub fn control(&self) -> ConfinedProcessControl {
        self.control.clone()
    }
    pub fn take_stdin(&mut self) -> Option<ConfinedProcessInput> {
        self.child.take_input()
    }
    pub fn take_stdout(&mut self) -> Option<ConfinedProcessOutput> {
        self.child.take_output()
    }
    pub fn take_stderr(&mut self) -> Option<ConfinedProcessError> {
        self.child.take_error()
    }
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }
    pub async fn terminate_and_reap(&mut self) -> Option<ExitStatus> {
        self.control.force_kill();
        self.child.stop_and_reap().await
    }
    pub fn terminate_and_reap_blocking(&mut self, _timeout: Duration) -> Option<ExitStatus> {
        self.control.force_kill();
        // No async runtime or blocking disk retirement is fabricated here. Dropping the retained
        // owner transfers its exact child/Job/reservation to the bounded physical cleanup worker.
        None
    }
    pub(crate) fn into_child(self) -> OwnedWindowsPipes {
        self.child
    }
}
pub(crate) async fn spawn(
    command: &str,
    conf: &Confinement,
    workspace: Option<&File>,
) -> Result<ConfinedProcess, SandboxError> {
    let plan = Plan::capture(command, conf, workspace, false).await?;
    let sandbox = plan.sandbox().await?;
    let confined = sandbox.is_some();
    let child = match sandbox {
        Some(sandbox) => {
            OwnedWindowsPipes::spawn_in_sandbox(
                &plan.executable,
                &plan.arguments,
                &plan.directory,
                &plan.environment,
                sandbox,
            )
            .await
        }
        None => {
            OwnedWindowsPipes::spawn_with_isolation(
                &plan.executable,
                &plan.arguments,
                &plan.directory,
                &plan.environment,
                None,
            )
            .await
        }
    }
    .map_err(|error| SandboxError::WindowsLaunch(Box::new(error)))?;
    let control = ConfinedProcessControl::for_windows_job(child.job());
    Ok(ConfinedProcess {
        child,
        control,
        backend: if confined {
            PersistentBackend::WindowsLpacPipes
        } else {
            PersistentBackend::WindowsJobPipes
        },
    })
}

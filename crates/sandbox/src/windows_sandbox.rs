//! One-shot Windows execution consumes the same concrete native pipe owner as persistent tools.
use crate::{Confinement, RunOutput, Sandbox, SandboxError};
pub(crate) struct WindowsSandbox;
#[async_trait::async_trait]
impl Sandbox for WindowsSandbox {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
        run(command, conf).await
    }
}
pub(crate) async fn run(command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
    let mut process = crate::persistent_windows::spawn(command, conf, None)
        .await
        .map_err(|error| {
            crate::publish_output_io_failure(conf, None);
            error
        })?;
    let stdout = process.take_stdout().ok_or_else(|| {
        crate::publish_output_io_failure(conf, Some(crate::OutputStream::Stdout));
        SandboxError::Spawn("native stdout pipe missing".into())
    })?;
    let stderr = process.take_stderr().ok_or_else(|| {
        crate::publish_output_io_failure(conf, Some(crate::OutputStream::Stderr));
        SandboxError::Spawn("native stderr pipe missing".into())
    })?;
    drop(process.take_stdin()); // Actual byte-pipe EOF, exactly the one-shot Stdio::null posture.
    crate::collect_owned_child_output(process.into_child(), stdout, stderr, conf).await
}

#[cfg(test)]
mod tests;

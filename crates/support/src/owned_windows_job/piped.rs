//! Private synchronous child pipe handles plus async parent endpoints, retained under one Job.
//! This constructor composes a sealed isolation lease or the explicitly supplied None posture;
//! it does not grant confinement merely because a Job exists.
mod channels;
use super::{
    CLEANUP_POLL, LaunchCustody, MAX_CLEANUP_WAIT, OwnedWindowsJob, WindowsJobLaunchError, custody,
    native_launch::{Launch, Transport},
    native_process::NativeProcess,
    native_retirement::{NativeLaunchRetirement, RetirementCompletion},
    native_setup::{IsolationSetup, Prepared, WindowsSandboxLaunch},
};
use crate::windows_process_isolation::WindowsProcessIsolation;
use channels::Channels;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::System::Threading::{GetProcessIdOfThread, ResumeThread};

pub struct WindowsPipeInput(Option<NamedPipeServer>);
impl AsyncWrite for WindowsPipeInput {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().0.as_mut() {
            Some(pipe) => Pin::new(pipe).poll_write(cx, bytes),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native input closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(pipe) => Pin::new(pipe).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0 = None; // Actual byte-pipe EOF, distinct from a terminal's EOT key.
        Poll::Ready(Ok(()))
    }
}
pub struct WindowsPipeOutput(NamedPipeServer);
impl AsyncRead for WindowsPipeOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().0).poll_read(cx, buffer) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

pub struct OwnedWindowsPipes {
    child: Option<NativeProcess>,
    job: Arc<OwnedWindowsJob>,
    admission: Option<custody::Admission>,
    status: Option<ExitStatus>,
    input: Option<WindowsPipeInput>,
    output: Option<WindowsPipeOutput>,
    error: Option<WindowsPipeOutput>,
    retirement: Option<NativeLaunchRetirement>,
    retirement_wait: Option<Arc<RetirementCompletion>>,
}
impl fmt::Debug for OwnedWindowsPipes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedWindowsPipes")
            .field("wait_observed", &self.status.is_some())
            .finish_non_exhaustive()
    }
}
impl OwnedWindowsPipes {
    pub async fn spawn_in_sandbox(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
        sandbox: WindowsSandboxLaunch,
    ) -> Result<Self, WindowsJobLaunchError> {
        if !sandbox.matches(executable, directory, environment) {
            return Err(sandbox
                .refuse(
                    "native sandbox launch binding",
                    io::Error::other("native sandbox launch differs from its frozen scope"),
                )
                .await);
        }
        let launch = match Launch::capture(executable, arguments, directory, environment) {
            Ok(launch) => launch,
            Err(error) => return Err(sandbox.refuse("pipe sandbox ABI projection", error).await),
        };
        Self::spawn_prepared(
            launch,
            sandbox.take(),
            #[cfg(test)]
            None,
        )
        .await
    }
    pub async fn spawn_with_isolation(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
        isolation: Option<Arc<WindowsProcessIsolation>>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let launch =
            Launch::capture(executable, arguments, directory, environment).map_err(|error| {
                WindowsJobLaunchError::before_creation("pipe ABI projection", error)
            })?;
        Self::spawn_captured(
            launch,
            isolation.map(|isolation| IsolationSetup {
                isolation,
                executable: executable.to_owned(),
                directory: directory.to_owned(),
                environment: environment.to_vec(),
            }),
            #[cfg(test)]
            None,
        )
        .await
    }
    async fn spawn_captured(
        launch: Launch,
        setup: Option<IsolationSetup>,
        #[cfg(test)] before_resume: Option<fn(&NativeProcess, &OwnedWindowsJob) -> io::Result<()>>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let prepared = Prepared::admit(setup).await?;
        Self::spawn_prepared(
            launch,
            prepared,
            #[cfg(test)]
            before_resume,
        )
        .await
    }
    async fn spawn_prepared(
        mut launch: Launch,
        prepared: Prepared,
        #[cfg(test)] before_resume: Option<fn(&NativeProcess, &OwnedWindowsJob) -> io::Result<()>>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let channels = match Channels::create().await {
            Ok(channels) => channels,
            Err(error) => return Err(prepared.refuse("private pipe transport", error).await),
        };
        let (admission, job, retirement) = prepared.into_parts(None);
        let mut owned = Self {
            child: None,
            job,
            admission: Some(admission),
            status: None,
            input: Some(WindowsPipeInput(Some(channels.input))),
            output: Some(WindowsPipeOutput(channels.output)),
            error: Some(WindowsPipeOutput(channels.error)),
            retirement: Some(retirement),
            retirement_wait: None,
        };
        let [input, output, error] = &channels.child_handles;
        let isolation = owned
            .retirement
            .as_ref()
            .and_then(NativeLaunchRetirement::isolation);
        let created = launch
            .create_suspended(
                Transport::Pipes {
                    input,
                    output,
                    error,
                },
                isolation,
            )
            .map(|info| unsafe {
                (
                    OwnedHandle::from_raw_handle(info.hProcess),
                    OwnedHandle::from_raw_handle(info.hThread),
                    info.dwProcessId,
                )
            });
        let (process, primary, pid) = match created {
            Ok(value) => value,
            Err(error) => {
                drop(channels.child_handles);
                return Err(owned
                    .refuse("pipe suspended process creation", error, false)
                    .await);
            }
        };
        owned.child = Some(NativeProcess::created(process, pid));
        drop(channels.child_handles); // Only the actual child holds its three inherited peers now.
        let prepared = owned
            .child
            .as_ref()
            .ok_or_else(|| io::Error::other("pipe process missing"))
            .and_then(|child| {
                let process = child.handle()?;
                let pid = child
                    .id()
                    .ok_or_else(|| io::Error::other("pipe process retired"))?;
                if unsafe { GetProcessIdOfThread(primary.as_raw_handle()) } != pid {
                    return Err(io::Error::other("pipe primary thread identity mismatch"));
                }
                owned
                    .job
                    .assign_suspended_process(process.as_raw_handle(), pid)
                    .map_err(|(_, error)| error)?;
                if let Some(isolation) = owned
                    .retirement
                    .as_ref()
                    .and_then(NativeLaunchRetirement::isolation)
                {
                    isolation.verify_child(process.as_handle())?;
                }
                Ok(())
            });
        if let Err(error) = prepared {
            drop(primary);
            return Err(owned
                .refuse("pipe suspended Job/token membership", error, false)
                .await);
        }
        #[cfg(test)]
        if let Some(observe) = before_resume {
            let observed = owned
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("pipe process missing"))
                .and_then(|child| observe(child, &owned.job));
            if let Err(error) = observed {
                drop(primary);
                return Err(owned.refuse("pipe pre-resume fixture", error, false).await);
            }
        }
        let previous = unsafe { ResumeThread(primary.as_raw_handle()) };
        if previous != 1 {
            let error = if previous == u32::MAX {
                io::Error::last_os_error()
            } else {
                io::Error::other("pipe initial suspend count differs from one")
            };
            drop(primary);
            return Err(owned.refuse("pipe primary resume", error, true).await);
        }
        drop(primary);
        Ok(owned)
    }
    pub fn take_input(&mut self) -> Option<WindowsPipeInput> {
        self.input.take()
    }
    pub fn take_output(&mut self) -> Option<WindowsPipeOutput> {
        self.output.take()
    }
    pub fn take_error(&mut self) -> Option<WindowsPipeOutput> {
        self.error.take()
    }
    pub fn job(&self) -> Arc<OwnedWindowsJob> {
        self.job.clone()
    }
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().and_then(NativeProcess::id)
    }
    pub fn start_kill(&self) -> io::Result<()> {
        let job = self.job.terminate();
        let child = self.child.as_ref().map_or(Ok(()), NativeProcess::kill);
        job.and(child)
    }
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.cleanup()
            .await?
            .ok_or_else(|| io::Error::other("pipe process was not created"))
    }
    pub(super) async fn cleanup(&mut self) -> io::Result<Option<ExitStatus>> {
        while self.status.is_none() && self.child.is_some() {
            self.status = self.child.as_mut().expect("tested above").try_wait()?;
            if self.status.is_some() {
                self.child = None;
            } else {
                tokio::time::sleep(CLEANUP_POLL).await;
            }
        }
        let _ = self.job.terminate();
        if !self.job.confirm_empty(MAX_CLEANUP_WAIT).await {
            return Err(io::Error::other("pipe tree cleanup remains unknown"));
        }
        if let Some(mut retirement) = self.retirement.take() {
            if retirement.needs_worker() {
                let observation = retirement.observation();
                let Some(admission) = self.admission.take() else {
                    self.retirement = Some(retirement);
                    return Err(io::Error::other(
                        "pipe retirement custody admission missing",
                    ));
                };
                self.retirement_wait = Some(observation);
                admission.defer_native(None, self.job.clone(), true, Some(retirement));
            } else if !retirement.retire() {
                self.retirement = Some(retirement);
                return Err(io::Error::other(
                    "pipe isolation retirement remains unknown",
                ));
            }
        }
        if let Some(observation) = &self.retirement_wait {
            if !observation.observe(MAX_CLEANUP_WAIT).await {
                return Err(io::Error::other(
                    "pipe isolation retirement remains unknown",
                ));
            }
            self.retirement_wait = None;
        }
        Ok(self.status)
    }
    pub async fn stop_and_reap(&mut self) -> Option<ExitStatus> {
        self.terminate();
        tokio::time::timeout(MAX_CLEANUP_WAIT * 2, self.wait())
            .await
            .ok()
            .and_then(Result::ok)
    }
    fn terminate(&self) {
        let _ = self.job.terminate();
        if let Some(child) = &self.child {
            let _ = child.kill();
        }
    }
    async fn refuse(
        mut self,
        stage: &'static str,
        error: io::Error,
        execution_may_have_started: bool,
    ) -> WindowsJobLaunchError {
        self.input = None;
        self.output = None;
        self.error = None;
        self.terminate();
        let cleanup_known = tokio::time::timeout(MAX_CLEANUP_WAIT * 2, self.cleanup())
            .await
            .is_ok_and(|result| result.is_ok());
        WindowsJobLaunchError {
            stage,
            os_error: error.raw_os_error(),
            execution_may_have_started,
            cleanup_known,
            custody: (!cleanup_known).then(|| LaunchCustody::Pipes(Box::new(self))),
        }
    }
}
impl Drop for OwnedWindowsPipes {
    fn drop(&mut self) {
        self.terminate();
        if self.child.is_some()
            || self.job.active_processes().ok() != Some(0)
            || self.retirement.is_some()
        {
            if let Some(admission) = self.admission.take() {
                let wait_observed = self.status.is_some() || self.child.is_none();
                admission.defer_native(
                    self.child.take(),
                    self.job.clone(),
                    wait_observed,
                    self.retirement.take(),
                );
            }
        }
    }
}
#[cfg(test)]
mod tests;

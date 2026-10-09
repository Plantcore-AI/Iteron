//! Native persistent terminal ownership. Job/ConPTY provide lifecycle and terminal transport;
//! they deliberately make no claim of filesystem, network, credential, or token confinement.
pub(super) mod console;
pub(super) mod pipes;

use super::native_launch::{Launch, Transport};
use super::native_retirement::{NativeLaunchRetirement, RetirementCompletion};
use super::native_setup::{IsolationSetup, Prepared, WindowsSandboxLaunch};
use super::{
    CLEANUP_POLL, LaunchCustody, LaunchFailure, MAX_CLEANUP_WAIT, OwnedWindowsJob,
    WindowsJobLaunchError, custody, native_process::NativeProcess,
};
use crate::windows_process_isolation::WindowsProcessIsolation;
use console::Console;
use pipes::Pipes;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::System::Threading::{GetProcessIdOfThread, ResumeThread};

pub struct WindowsPtyInput(Option<NamedPipeServer>);
impl WindowsPtyInput {
    /// The shell receives the actual terminal EOT key. This is not an invented pipe EOF receipt.
    pub async fn send_eof(&mut self) -> io::Result<()> {
        self.write_all(&[4]).await
    }
}
impl AsyncWrite for WindowsPtyInput {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().0.as_mut() {
            Some(pipe) => Pin::new(pipe).poll_write(context, bytes),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ConPTY input already closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(pipe) => Pin::new(pipe).poll_flush(context),
            None => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0 = None; // Close the exact overlapped input handle; no blocking flush.
        Poll::Ready(Ok(()))
    }
}

pub struct WindowsPtyOutput(NamedPipeServer);
impl AsyncRead for WindowsPtyOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().0).poll_read(context, buffer) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

#[derive(Clone)]
pub struct WindowsPtyResize(Arc<Console>);
impl WindowsPtyResize {
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        self.0.resize(rows, cols)
    }
}

pub struct OwnedWindowsPty {
    child: Option<NativeProcess>,
    job: Arc<OwnedWindowsJob>,
    admission: Option<custody::Admission>,
    status: Option<ExitStatus>,
    console: Arc<Console>,
    input: Option<WindowsPtyInput>,
    output: Option<WindowsPtyOutput>,
    retirement: Option<NativeLaunchRetirement>,
    retirement_wait: Option<Arc<RetirementCompletion>>,
}

impl fmt::Debug for OwnedWindowsPty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedWindowsPty")
            .field("wait_observed", &self.status.is_some())
            .finish_non_exhaustive()
    }
}

impl OwnedWindowsPty {
    pub async fn spawn_in_sandbox(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
        sandbox: WindowsSandboxLaunch,
        rows: u16,
        cols: u16,
    ) -> Result<Self, WindowsJobLaunchError> {
        if !sandbox.matches(executable, directory, environment) {
            return Err(sandbox
                .refuse_isolation(
                    "native sandbox terminal binding",
                    io::Error::other("native sandbox terminal differs from its frozen scope"),
                )
                .await);
        }
        let launch = match Launch::capture(executable, arguments, directory, environment) {
            Ok(launch) => launch,
            Err(error) => return Err(sandbox.refuse("PTY sandbox ABI projection", error).await),
        };
        Self::spawn_prepared(
            launch,
            rows,
            cols,
            sandbox.take(),
            #[cfg(test)]
            None,
        )
        .await
    }
    pub async fn spawn(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
        rows: u16,
        cols: u16,
    ) -> Result<Self, WindowsJobLaunchError> {
        Self::spawn_with_isolation(
            executable,
            arguments,
            directory,
            environment,
            None,
            rows,
            cols,
        )
        .await
    }

    pub async fn spawn_with_isolation(
        executable: &Path,
        arguments: &[OsString],
        directory: &Path,
        environment: &[(OsString, OsString)],
        isolation: Option<Arc<WindowsProcessIsolation>>,
        rows: u16,
        cols: u16,
    ) -> Result<Self, WindowsJobLaunchError> {
        let launch = Launch::capture(executable, arguments, directory, environment)
            .map_err(|error| WindowsJobLaunchError::before_creation("PTY ABI projection", error))?;
        Self::spawn_captured(
            launch,
            rows,
            cols,
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
        rows: u16,
        cols: u16,
        setup: Option<IsolationSetup>,
        #[cfg(test)] before_resume: Option<fn(&NativeProcess, &OwnedWindowsJob) -> io::Result<()>>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let prepared = Prepared::admit(setup).await?;
        Self::spawn_prepared(
            launch,
            rows,
            cols,
            prepared,
            #[cfg(test)]
            before_resume,
        )
        .await
    }
    async fn spawn_prepared(
        mut launch: Launch,
        rows: u16,
        cols: u16,
        prepared: Prepared,
        #[cfg(test)] before_resume: Option<fn(&NativeProcess, &OwnedWindowsJob) -> io::Result<()>>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let pipes = match Pipes::create().await {
            Ok(pipes) => pipes,
            Err(error) => return Err(prepared.refuse("PTY private channels", error).await),
        };
        let console = match Console::create(
            pipes.console_input.as_raw_handle(),
            pipes.console_output.as_raw_handle(),
            rows,
            cols,
        ) {
            Ok(console) => console,
            Err(error) => {
                drop(pipes);
                return Err(prepared.refuse("PTY native console creation", error).await);
            }
        };
        let (admission, job, retirement) = prepared.into_parts(Some(console.clone()));
        let mut owned = Self {
            child: None,
            job,
            admission: Some(admission),
            status: None,
            console: console.clone(),
            input: Some(WindowsPtyInput(Some(pipes.input))),
            output: Some(WindowsPtyOutput(pipes.output)),
            retirement: Some(retirement),
            retirement_wait: None,
        };
        let isolation = owned
            .retirement
            .as_ref()
            .and_then(NativeLaunchRetirement::isolation);
        let created = launch
            .create_suspended(Transport::Console(&owned.console), isolation)
            .map(|information| {
                // Successful native creation returns both valid owned handles. This synchronous
                // projection ensures no raw HANDLE-bearing ABI value crosses an async suspension.
                unsafe {
                    (
                        OwnedHandle::from_raw_handle(information.hProcess),
                        OwnedHandle::from_raw_handle(information.hThread),
                        information.dwProcessId,
                    )
                }
            });
        let (process, primary, pid) = match created {
            Ok(created) => created,
            Err(error) => {
                drop(pipes.console_input);
                drop(pipes.console_output);
                return Err(owned
                    .refuse_failure("PTY suspended process creation", error, false)
                    .await);
            }
        };
        // A successful CreateProcessW contract transfers these actual non-inheritable handles.
        // Adopt the process before any fallible observation or await can lose suspended custody.
        owned.child = Some(NativeProcess::created(process, pid));
        // ConPTY retains its own copies. Leaving our synchronous copies open would suppress EOF.
        drop(pipes.console_input);
        drop(pipes.console_output);
        let prepared = owned
            .child
            .as_ref()
            .ok_or_else(|| io::Error::other("PTY process missing"))
            .map_err(LaunchFailure::from)
            .and_then(|child| {
                let process = child.handle()?;
                let pid = child
                    .id()
                    .ok_or_else(|| io::Error::other("PTY process already retired"))?;
                if unsafe { GetProcessIdOfThread(primary.as_raw_handle()) } != pid {
                    return Err(io::Error::other("PTY primary thread identity mismatch").into());
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
                    isolation
                        .verify_child(process.as_handle())
                        .map_err(LaunchFailure::isolation)?;
                }
                Ok(())
            });
        if let Err(error) = prepared {
            drop(primary);
            return Err(owned
                .refuse_failure("PTY suspended Job membership", error, false)
                .await);
        }
        #[cfg(test)]
        if let Some(before_resume) = before_resume {
            let observed = owned
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("PTY process missing"))
                .and_then(|child| before_resume(child, &owned.job));
            if let Err(error) = observed {
                drop(primary);
                return Err(owned.refuse("PTY pre-resume fixture", error, false).await);
            }
        }
        let previous = unsafe { ResumeThread(primary.as_raw_handle()) };
        if previous != 1 {
            let error = if previous == u32::MAX {
                io::Error::last_os_error()
            } else {
                io::Error::other("PTY initial suspend count differs from one")
            };
            drop(primary);
            return Err(owned.refuse("PTY primary resume", error, true).await);
        }
        drop(primary);
        Ok(owned)
    }

    pub fn take_input(&mut self) -> Option<WindowsPtyInput> {
        self.input.take()
    }
    pub fn take_output(&mut self) -> Option<WindowsPtyOutput> {
        self.output.take()
    }
    pub fn resize_control(&self) -> WindowsPtyResize {
        WindowsPtyResize(self.console.clone())
    }
    pub fn job(&self) -> Arc<OwnedWindowsJob> {
        self.job.clone()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("PTY process wait reference missing"))?
                .try_wait()?;
            if self.status.is_some() {
                self.child = None;
            }
        }
        Ok(self.status)
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.cleanup()
            .await?
            .ok_or_else(|| io::Error::other("PTY process was not created"))
    }

    pub(super) async fn cleanup(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = loop {
            if self.child.is_none() && self.status.is_none() {
                break None;
            }
            if let Some(status) = self.try_wait()? {
                break Some(status);
            }
            tokio::time::sleep(CLEANUP_POLL).await;
        };
        // Kill any descendant whose output was redirected, using only this retained Job.
        let _ = self.job.terminate();
        if !self.job.confirm_empty(MAX_CLEANUP_WAIT).await
            || !self.console.close_observed(MAX_CLEANUP_WAIT).await
        {
            return Err(io::Error::other("PTY terminal cleanup remains unknown"));
        }
        if let Some(mut retirement) = self.retirement.take() {
            if retirement.needs_worker() {
                let observation = retirement.observation();
                let Some(admission) = self.admission.take() else {
                    self.retirement = Some(retirement);
                    return Err(io::Error::other("PTY retirement custody admission missing"));
                };
                // Disk/profile retirement can stall despite a finite number of syscalls. The
                // pre-admitted worker owns the exact resource; async cancellation cannot lose it.
                self.retirement_wait = Some(observation);
                admission.defer_native(None, self.job.clone(), true, Some(retirement));
            } else if !retirement.retire() {
                self.retirement = Some(retirement);
                return Err(io::Error::other("PTY isolation retirement remains unknown"));
            }
        }
        if let Some(observation) = &self.retirement_wait {
            if !observation.observe(MAX_CLEANUP_WAIT).await {
                return Err(io::Error::other("PTY isolation retirement remains unknown"));
            }
            self.retirement_wait = None;
        }
        Ok(status)
    }

    pub async fn stop_and_reap(&mut self) -> Option<ExitStatus> {
        let _ = self.job.terminate();
        if let Some(child) = &self.child {
            let _ = child.kill();
        }
        // No elapsed-time or leader-only result is upgraded to known cleanup. The actual Job
        // accounting and native console close must both complete inside this existing grace.
        tokio::time::timeout(MAX_CLEANUP_WAIT * 2, self.wait())
            .await
            .ok()
            .and_then(Result::ok)
    }

    async fn refuse(
        self,
        stage: &'static str,
        error: io::Error,
        execution_may_have_started: bool,
    ) -> WindowsJobLaunchError {
        self.refuse_failure(stage, error.into(), execution_may_have_started)
            .await
    }
    async fn refuse_failure(
        mut self,
        stage: &'static str,
        failure: LaunchFailure,
        execution_may_have_started: bool,
    ) -> WindowsJobLaunchError {
        self.input = None;
        self.output = None;
        let _ = self.job.terminate();
        if let Some(child) = &self.child {
            let _ = child.kill();
        }
        let cleanup_known = tokio::time::timeout(MAX_CLEANUP_WAIT * 2, self.cleanup())
            .await
            .is_ok_and(|result| result.is_ok());
        WindowsJobLaunchError {
            stage,
            os_error: failure.error.raw_os_error(),
            execution_may_have_started,
            cleanup_known,
            custody: (!cleanup_known).then(|| LaunchCustody::Pty(Box::new(self))),
            origin: failure.origin,
        }
    }
}
impl Drop for OwnedWindowsPty {
    fn drop(&mut self) {
        let _ = self.job.terminate();
        if let Some(child) = &self.child {
            let _ = child.kill();
        }
        self.console.begin_close();
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
#[path = "conpty/tests.rs"]
mod tests;

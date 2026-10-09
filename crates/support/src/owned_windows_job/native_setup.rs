//! One bounded pre-native isolation transaction. Observer cancellation cannot drop a partially
//! installed grant: this guard retains its sole sealed reservation and physical custody slot.
use super::{
    LaunchCustody, MAX_CLEANUP_WAIT, OwnedWindowsJob, WindowsJobLaunchError,
    conpty::console::Console,
    custody,
    native_retirement::{NativeLaunchRetirement, RetirementCompletion},
};
use crate::windows_process_isolation::WindowsProcessIsolation;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
const MAX_SETUP_WAIT: Duration = Duration::from_secs(10);
pub(super) struct IsolationSetup {
    pub(super) isolation: Arc<WindowsProcessIsolation>,
    pub(super) executable: PathBuf,
    pub(super) directory: PathBuf,
    pub(super) environment: Vec<(OsString, OsString)>,
}
pub(super) struct Prepared {
    job: Arc<OwnedWindowsJob>,
    admission: Option<custody::Admission>,
    retirement: Option<NativeLaunchRetirement>,
}
impl Prepared {
    pub(super) async fn admit(
        setup: Option<IsolationSetup>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let admission = custody::Admission::acquire().map_err(|error| {
            WindowsJobLaunchError::before_creation("native custody admission", error)
        })?;
        let job = Arc::new(OwnedWindowsJob::create().map_err(|error| {
            WindowsJobLaunchError::before_creation("native private Job", error)
        })?);
        let retirement =
            NativeLaunchRetirement::new(None, setup.as_ref().map(|setup| setup.isolation.clone()))
                .map_err(|error| {
                    WindowsJobLaunchError::before_creation("native isolation reservation", error)
                })?;
        let prepared = Self {
            job,
            admission: Some(admission),
            retirement: Some(retirement),
        };
        let Some(setup) = setup else {
            return Ok(prepared);
        }; // No optional clock/task/env clone.
        let observation = prepared
            .retirement
            .as_ref()
            .expect("constructed above")
            .observation();
        let work = tokio::task::spawn_blocking(move || {
            // The actual slot/lease stay in this guard even when the observing future is dropped.
            let result = prepared
                .retirement
                .as_ref()
                .expect("retained in guard")
                .isolation()
                .ok_or_else(|| io::Error::other("native isolation reservation missing"))
                .and_then(|isolation| {
                    isolation.validate_launch(&setup.executable, &setup.directory)
                })
                .and_then(|()| setup.isolation.validate_environment(&setup.environment))
                .and_then(|()| {
                    prepared
                        .retirement
                        .as_ref()
                        .expect("retained in guard")
                        .install()
                });
            (prepared, result)
        });
        match tokio::time::timeout(MAX_SETUP_WAIT, work).await {
            Ok(Ok((prepared, Ok(())))) => Ok(prepared),
            Ok(Ok((prepared, Err(error)))) => {
                Err(prepared.refuse("native isolation setup", error).await)
            }
            Ok(Err(_)) | Err(_) => Err(WindowsJobLaunchError {
                stage: "native isolation setup observation",
                os_error: None,
                execution_may_have_started: false,
                cleanup_known: false,
                custody: Some(LaunchCustody::Setup(observation)),
            }),
        }
    }
    pub(super) fn into_parts(
        mut self,
        console: Option<Arc<Console>>,
    ) -> (
        custody::Admission,
        Arc<OwnedWindowsJob>,
        NativeLaunchRetirement,
    ) {
        let mut retirement = self
            .retirement
            .take()
            .expect("prepared resource consumed once");
        if let Some(console) = console {
            retirement.bind_console(console);
        }
        (
            self.admission
                .take()
                .expect("prepared admission consumed once"),
            self.job.clone(),
            retirement,
        )
    }
    pub(super) async fn refuse(
        mut self,
        stage: &'static str,
        error: io::Error,
    ) -> WindowsJobLaunchError {
        let observation = self
            .retirement
            .as_ref()
            .expect("prepared resource retained")
            .observation();
        self.defer();
        let cleanup_known = observation.observe(MAX_CLEANUP_WAIT).await;
        WindowsJobLaunchError {
            stage,
            os_error: error.raw_os_error(),
            execution_may_have_started: false,
            cleanup_known,
            custody: (!cleanup_known).then_some(LaunchCustody::Setup(observation)),
        }
    }
    fn defer(&mut self) {
        if let Some(admission) = self.admission.take() {
            // No CreateProcess call has happened in this owner; the private Job proves empty.
            admission.defer_native(None, self.job.clone(), true, self.retirement.take());
        }
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.defer();
    }
}

impl std::fmt::Debug for RetirementCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRetirementObservation")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;

//! One bounded pre-native isolation transaction. Observer cancellation cannot drop a partially
//! installed grant: this guard retains its sole sealed reservation and physical custody slot.
use super::{
    LaunchCustody, MAX_CLEANUP_WAIT, OwnedWindowsJob, WindowsJobLaunchError,
    conpty::console::Console,
    custody,
    native_retirement::{NativeLaunchRetirement, RetirementCompletion},
};
use crate::durable_windows_state::WindowsPrivateScratch;
use crate::windows_process_isolation::{WindowsIsolationPolicy, WindowsProcessIsolation};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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

/// One non-Clone prepared native sandbox. Its real Job/admission, newly created private scratch,
/// profile reservation and installed permissions remain with the physical launch or its worker.
pub struct WindowsSandboxLaunch {
    prepared: Option<Prepared>,
    captured: CapturedPolicy,
}
struct CapturedPolicy {
    workspace: PathBuf,
    scratch: PathBuf,
    executable: PathBuf,
    environment: Vec<(OsString, OsString)>,
    write_roots: Vec<PathBuf>,
    read_only_roots: Vec<PathBuf>,
    allow_egress: bool,
    workspace_file: Option<File>,
}
impl CapturedPolicy {
    fn capture(policy: WindowsIsolationPolicy<'_>, workspace: Option<&File>) -> io::Result<Self> {
        if policy
            .write_roots
            .len()
            .saturating_add(policy.read_only_roots.len())
            > 128
            || policy.environment.len() > 1024
        {
            return Err(io::Error::other("native policy envelope exceeded"));
        }
        for path in std::iter::once(policy.workspace)
            .chain([policy.scratch, policy.executable])
            .chain(policy.write_roots.iter().map(PathBuf::as_path))
            .chain(policy.read_only_roots.iter().map(PathBuf::as_path))
        {
            if !path.is_absolute() || path.as_os_str().encode_wide().take(32768).count() > 32767 {
                return Err(io::Error::other("native policy path envelope exceeded"));
            }
        }
        let mut units = 0usize;
        for (key, value) in policy.environment {
            for _ in key.encode_wide().chain(value.encode_wide()) {
                units += 1;
                if units > 128 * 1024 {
                    return Err(io::Error::other("native environment envelope exceeded"));
                }
            }
        }
        Ok(Self {
            workspace: policy.workspace.to_owned(),
            scratch: policy.scratch.to_owned(),
            executable: policy.executable.to_owned(),
            environment: policy.environment.to_vec(),
            write_roots: policy.write_roots.to_vec(),
            read_only_roots: policy.read_only_roots.to_vec(),
            allow_egress: policy.allow_egress,
            workspace_file: workspace.map(File::try_clone).transpose()?,
        })
    }
    fn policy(&self) -> WindowsIsolationPolicy<'_> {
        WindowsIsolationPolicy {
            workspace: &self.workspace,
            scratch: &self.scratch,
            executable: &self.executable,
            environment: &self.environment,
            write_roots: &self.write_roots,
            read_only_roots: &self.read_only_roots,
            allow_egress: self.allow_egress,
        }
    }
}
impl WindowsSandboxLaunch {
    pub async fn prepare(
        policy: WindowsIsolationPolicy<'_>,
        workspace: Option<&File>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let captured = CapturedPolicy::capture(policy, workspace).map_err(|error| {
            WindowsJobLaunchError::before_creation("native sandbox policy capture", error)
        })?;
        let prepared = Prepared::admit(None).await?;
        let observation = prepared
            .retirement
            .as_ref()
            .expect("retained")
            .observation();
        let work = tokio::task::spawn_blocking(move || {
            let mut prepared = prepared;
            let result = (|| {
                let retirement = prepared.retirement.as_mut().expect("retained");
                retirement.bind_scratch(WindowsPrivateScratch::bind(&captured.scratch)?);
                retirement.provision_scratch()?;
                let isolation = match &captured.workspace_file {
                    Some(workspace) => WindowsProcessIsolation::prepare_from_workspace(
                        captured.policy(),
                        workspace,
                    )?,
                    None => WindowsProcessIsolation::prepare(captured.policy())?,
                };
                // The scratch handle is held without delete sharing throughout scope admission.
                let _ = retirement.scratch_file()?;
                retirement.bind_isolation(&isolation)?;
                isolation.validate_launch(&captured.executable, &captured.workspace)?;
                isolation.validate_environment(&captured.environment)?;
                retirement.install()
            })();
            (prepared, captured, result)
        });
        match tokio::time::timeout(MAX_SETUP_WAIT, work).await {
            Ok(Ok((prepared, captured, Ok(())))) => Ok(Self {
                prepared: Some(prepared),
                captured,
            }),
            Ok(Ok((prepared, _, Err(error)))) => {
                Err(prepared.refuse("native sandbox preparation", error).await)
            }
            Ok(Err(_)) | Err(_) => Err(WindowsJobLaunchError {
                stage: "native sandbox preparation observation",
                os_error: None,
                execution_may_have_started: false,
                cleanup_known: false,
                custody: Some(LaunchCustody::Setup(observation)),
            }),
        }
    }
    pub(super) fn take(mut self) -> Prepared {
        self.prepared.take().expect("native sandbox consumed once")
    }
    pub(super) fn matches(
        &self,
        executable: &Path,
        directory: &Path,
        environment: &[(OsString, OsString)],
    ) -> bool {
        self.captured.executable == executable
            && self.captured.workspace == directory
            && self.captured.environment == environment
    }
    pub(super) async fn refuse(
        self,
        stage: &'static str,
        error: io::Error,
    ) -> WindowsJobLaunchError {
        self.take().refuse(stage, error).await
    }
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

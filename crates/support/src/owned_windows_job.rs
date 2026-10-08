//! The exact native process tree started suspended and admitted to one private Windows Job.
//!
//! There is no normal-spawn/late-assign window and no public handle/assignment API. The only
//! successful constructor resumes the actual primary thread after membership is confirmed.
//! Querying this retained Job proves its members, not arbitrary processes outside that scope.

use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::process::{Child as StdChild, Command as StdCommand, ExitStatus};
use std::ptr::null;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{ChildStderr, ChildStdout};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, GetProcessId, GetProcessIdOfThread, OpenThread, ResumeThread,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

#[path = "owned_windows_job/custody.rs"]
mod custody;

const MAX_ACTIVE_PROCESSES: u32 = 256;
const MAX_THREAD_ROWS: usize = 65_536;
const MAX_THREAD_SCAN: Duration = Duration::from_secs(1);
const MAX_CLEANUP_WAIT: Duration = Duration::from_secs(1);
const CLEANUP_POLL: Duration = Duration::from_millis(10);
const CLEANUP_EXIT_CODE: u32 = 1;

/// A launch refusal is known before execution only after the suspended child is also reaped.
/// An uncertain ResumeThread result or cleanup can never become NotDispatched.
#[derive(Debug)]
pub struct WindowsJobLaunchError {
    stage: &'static str,
    os_error: Option<i32>,
    execution_may_have_started: bool,
    cleanup_known: bool,
    custody: Option<Box<OwnedWindowsChild>>,
}

impl WindowsJobLaunchError {
    pub fn not_dispatched(&self) -> bool {
        !self.execution_may_have_started && self.cleanup_known
    }

    pub fn cleanup_known(&self) -> bool {
        self.cleanup_known
    }

    /// Retry only the retained physical cleanup; this cannot clear uncertain dispatched effects.
    pub async fn retry_cleanup(&mut self) -> bool {
        if let Some(child) = self.custody.as_mut() {
            self.cleanup_known = child.stop_and_reap().await;
            if self.cleanup_known {
                self.custody = None;
            }
        }
        self.cleanup_known
    }

    fn before_creation(stage: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            os_error: error.raw_os_error(),
            execution_may_have_started: false,
            cleanup_known: true,
            custody: None,
        }
    }
}

impl fmt::Display for WindowsJobLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Windows owned process launch refused at {}",
            self.stage
        )?;
        if let Some(code) = self.os_error {
            write!(formatter, " (OS error {code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for WindowsJobLaunchError {}

/// This kernel handle is private, unnamed and non-inheritable. No breakaway flag is installed.
/// Its whole-tree cleanup remains available after a real wait retires the direct process handle.
pub struct OwnedWindowsJob {
    handle: OwnedHandle,
}

impl fmt::Debug for OwnedWindowsJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedWindowsJob")
            .finish_non_exhaustive()
    }
}

/// The actual standard Child remains owned through Job assignment, stdio adaptation and resume.
/// Tokio Command::spawn is deliberately bypassed: an adaptation error after native creation must
/// not lose the suspended process handle. Public stdio fields are the original private pipes.
pub struct OwnedWindowsChild {
    child: Option<StdChild>,
    original_pid: u32,
    custody: Option<custody::Admission>,
    job: Arc<OwnedWindowsJob>,
    status: Option<ExitStatus>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}
impl fmt::Debug for OwnedWindowsChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedWindowsChild")
            .field("pid", &self.original_pid)
            .field("wait_observed", &self.status.is_some())
            .finish_non_exhaustive()
    }
}

impl OwnedWindowsChild {
    /// The native spawn syscall has the same synchronous boundary as Command::spawn. All native
    /// thread scans and cleanup waits are bounded. Callers retain their existing run deadlines.
    pub async fn spawn(command: &mut StdCommand) -> Result<Self, WindowsJobLaunchError> {
        Self::spawn_inner(command, None).await
    }

    async fn spawn_inner(
        command: &mut StdCommand,
        before_resume: Option<&(dyn Fn(&StdChild, &OwnedWindowsJob) -> io::Result<()> + Sync)>,
    ) -> Result<Self, WindowsJobLaunchError> {
        let custody = custody::Admission::acquire().map_err(|error| {
            WindowsJobLaunchError::before_creation("physical cleanup admission", error)
        })?;
        let job = Arc::new(OwnedWindowsJob::create().map_err(|error| {
            WindowsJobLaunchError::before_creation("private Job creation", error)
        })?);
        // No running-start or BREAKAWAY_FROM_JOB caller flag survives this constructor.
        command.creation_flags(CREATE_SUSPENDED);
        let child = command.spawn().map_err(|error| {
            WindowsJobLaunchError::before_creation("suspended process creation", error)
        })?;
        let mut owned = Self {
            original_pid: child.id(),
            child: Some(child),
            custody: Some(custody),
            job,
            status: None,
            stdout: None,
            stderr: None,
        };
        let prepared = owned
            .child
            .as_ref()
            .ok_or_else(|| {
                (
                    "suspended process ownership",
                    io::Error::other("process handle unavailable"),
                )
            })
            .and_then(|child| owned.job.prepare_primary_thread(child));
        let primary = match prepared {
            Ok(primary) => primary,
            Err((stage, error)) => return Err(owned.refuse(stage, error, false).await),
        };
        if let Err(error) = owned.adapt_output() {
            drop(primary);
            return Err(owned
                .refuse("suspended stdio adaptation", error, false)
                .await);
        }
        if let Some(observe) = before_resume {
            let observation = owned
                .child
                .as_ref()
                .ok_or_else(|| io::Error::other("suspended process handle unavailable"))
                .and_then(|child| observe(child, &owned.job));
            if let Err(error) = observation {
                drop(primary);
                return Err(owned.refuse("pre-resume observation", error, false).await);
            }
        }
        // Exactly the initial suspended primary thread resumes, after actual Job membership.
        let previous = unsafe { ResumeThread(primary.as_raw_handle()) };
        if previous != 1 {
            let error = if previous == u32::MAX {
                io::Error::last_os_error()
            } else {
                io::Error::other("primary thread suspend count differs from one")
            };
            drop(primary);
            return Err(owned.refuse("primary thread resume", error, true).await);
        }
        drop(primary);
        Ok(owned)
    }

    fn adapt_output(&mut self) -> io::Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("suspended process handle unavailable"))?;
        if child.stdin.is_some() {
            // These bounded collector ports accept closed/inherited input, never a forgotten
            // writable pipe that could keep the launched command blocked after activation.
            return Err(io::Error::other("owned child stdin must not be piped"));
        }
        self.stdout = child.stdout.take().map(ChildStdout::from_std).transpose()?;
        self.stderr = child.stderr.take().map(ChildStderr::from_std).transpose()?;
        if self.stdout.is_none() || self.stderr.is_none() {
            return Err(io::Error::other("owned child output must be piped"));
        }
        Ok(())
    }

    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(StdChild::id)
    }
    pub fn job(&self) -> Arc<OwnedWindowsJob> {
        Arc::clone(&self.job)
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("owned process wait handle unavailable"))?
                .try_wait()?;
            if self.status.is_some() {
                // Job ActiveProcesses retires only after all process references are released.
                // First retain the real exit-status receipt, then close this exact process
                // handle. The unnamed Job remains live; no later operation uses a numeric PID.
                self.child = None;
            }
        }
        Ok(self.status)
    }
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    }
    pub fn start_kill(&mut self) -> io::Result<()> {
        let job_result = self.job.terminate();
        // This exact retained handle also covers a failed Job assignment while still suspended.
        let child_result = match self.child.as_mut() {
            Some(child) => child.kill(),
            None => Ok(()),
        };
        job_result.and(child_result)
    }
    async fn stop_and_reap(&mut self) -> bool {
        let _ = self.start_kill();
        let reaped = matches!(
            tokio::time::timeout(MAX_CLEANUP_WAIT, self.wait()).await,
            Ok(Ok(_))
        );
        reaped && self.job.confirm_empty(MAX_CLEANUP_WAIT).await
    }
    async fn refuse(
        mut self,
        stage: &'static str,
        error: io::Error,
        execution_may_have_started: bool,
    ) -> WindowsJobLaunchError {
        self.stdout = None;
        self.stderr = None;
        if let Some(child) = self.child.as_mut() {
            child.stdin = None;
            child.stdout = None;
            child.stderr = None;
        }
        let cleanup_known = self.stop_and_reap().await;
        WindowsJobLaunchError {
            stage,
            os_error: error.raw_os_error(),
            execution_may_have_started,
            cleanup_known,
            custody: (!cleanup_known).then(|| Box::new(self)),
        }
    }
}
impl Drop for OwnedWindowsChild {
    fn drop(&mut self) {
        // Future drop owns both real handles; never signal a numeric PID after a consumed wait.
        let _ = self.start_kill();
        if self.child.is_some() || self.job.active_processes().ok() != Some(0) {
            if let Some(custody) = self.custody.take() {
                custody.defer(self.child.take(), self.job.clone(), self.status.is_some());
            }
        }
    }
}

impl OwnedWindowsJob {
    fn create() -> io::Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        let handle = own_handle(raw)?;
        let job = Self { handle };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = MAX_ACTIVE_PROCESSES;
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    fn prepare_primary_thread(
        &self,
        child: &StdChild,
    ) -> Result<OwnedHandle, (&'static str, io::Error)> {
        let pid = child.id();
        let process = child.as_raw_handle();
        if unsafe { GetProcessId(process) } != pid {
            return Err((
                "suspended process identity",
                io::Error::other("child PID mismatch"),
            ));
        }
        if unsafe { AssignProcessToJobObject(self.raw(), process) } == 0 {
            return Err(("Job assignment", io::Error::last_os_error()));
        }
        let mut member = 0;
        if unsafe { IsProcessInJob(process, self.raw(), &mut member) } == 0 || member == 0 {
            return Err(("Job membership confirmation", io::Error::last_os_error()));
        }
        if self
            .active_processes()
            .map_err(|error| ("Job accounting", error))?
            != 1
        {
            return Err((
                "Job initial process count",
                io::Error::other("not one process"),
            ));
        }
        primary_thread(pid).map_err(|error| ("primary thread lookup", error))
    }

    /// An actual retained-handle query, never PID lookup or a report inferred from leader exit.
    pub fn active_processes(&self) -> io::Result<u32> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0;
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if returned as usize != size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() {
            return Err(io::Error::other("Job accounting length mismatch"));
        }
        Ok(accounting.ActiveProcesses)
    }

    /// Stop the exact Job, including descendants whose standard streams were redirected.
    pub fn terminate(&self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.raw(), CLEANUP_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// This alone is not an effect/result receipt. The caller also requires its actual direct
    /// child wait-status and both output EOF observations before publishing known cleanup.
    pub async fn confirm_empty(&self, allowance: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + allowance.min(MAX_CLEANUP_WAIT);
        loop {
            match self.active_processes() {
                Ok(0) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    }
}

impl Drop for OwnedWindowsJob {
    fn drop(&mut self) {
        // Termination also works if another local test/read handle keeps the Job alive. Close
        // follows via OwnedHandle and KILL_ON_JOB_CLOSE is the final process-crash safeguard.
        let _ = self.terminate();
    }
}

fn own_handle(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // Win32 returned one owned, non-inheritable kernel handle. OwnedHandle closes it exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn primary_thread(pid: u32) -> io::Result<OwnedHandle> {
    let snapshot = own_handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
    let deadline = Instant::now() + MAX_THREAD_SCAN;
    let mut row = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut available = unsafe { Thread32First(snapshot.as_raw_handle(), &mut row) };
    let mut found = None;
    let mut scanned = 0_usize;
    loop {
        if available == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(error);
            }
            break;
        }
        scanned += 1;
        if scanned > MAX_THREAD_ROWS || Instant::now() >= deadline {
            return Err(io::Error::other(
                "primary thread snapshot exceeds its finite bound",
            ));
        }
        if row.dwSize as usize != size_of::<THREADENTRY32>() {
            return Err(io::Error::other("thread snapshot record length mismatch"));
        }
        if row.th32OwnerProcessID == pid {
            if found.is_some() {
                return Err(io::Error::other("multiple initial process threads"));
            }
            let thread = own_handle(unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    row.th32ThreadID,
                )
            })?;
            if unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } != pid {
                return Err(io::Error::other("thread process identity mismatch"));
            }
            found = Some(thread);
        }
        row.dwSize = size_of::<THREADENTRY32>() as u32;
        available = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut row) };
    }
    found.ok_or_else(|| io::Error::other("initial process thread unavailable"))
}

#[cfg(test)]
#[path = "owned_windows_job/tests.rs"]
mod tests;

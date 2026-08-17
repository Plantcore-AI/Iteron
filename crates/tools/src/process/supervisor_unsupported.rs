use super::policy::{InstalledProcessLaunchPolicy, ProcessRuntimePolicy};
use super::types::{
    ActionError, ProcessHealth, ProcessSnapshot, ProcessSummary, StreamingExecReceipt,
    WriteReceipt, lock,
};
use super::{ProcessLifecycleObserver, ProcessOutputObserver};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// Compile-time fallback for platforms that do not have a code-execution sandbox backend.
///
/// The registry and its non-process tools remain usable, but every operation that could start or
/// control a child fails before crossing an effect boundary. This must not grow an unconfined
/// Windows spawn path: Windows support is intentionally honest about the missing sandbox.
pub(crate) struct Supervisor {
    policy: Mutex<ProcessRuntimePolicy>,
}

impl Supervisor {
    pub(super) fn new() -> Result<Self, String> {
        Ok(Self {
            policy: Mutex::new(ProcessRuntimePolicy::default()),
        })
    }

    pub(super) fn configure_policy(
        &self,
        requested: ProcessRuntimePolicy,
    ) -> Result<(), ActionError> {
        let policy = ProcessRuntimePolicy::new(
            requested.backend,
            requested.max_background_jobs,
            requested.idle_stall_milliseconds,
            requested.stdin_wait,
        )
        .map_err(|error| ActionError::Definite(error.to_string()))?;
        *lock(&self.policy) = policy;
        Ok(())
    }

    pub(super) fn policy(&self) -> ProcessRuntimePolicy {
        *lock(&self.policy)
    }

    pub(super) fn bind_lifecycle_observer(&self, _observer: ProcessLifecycleObserver) {}

    pub(super) fn bind_output_observer(&self, _observer: ProcessOutputObserver) {}

    pub(super) async fn start(
        &self,
        _root: &Path,
        _command: &str,
        _rows: u16,
        _cols: u16,
        _launch: InstalledProcessLaunchPolicy,
    ) -> Result<ProcessSnapshot, ActionError> {
        Err(unsupported())
    }

    pub(crate) async fn exec_yield(
        &self,
        _root: &Path,
        _command: &str,
        _launch: InstalledProcessLaunchPolicy,
        _confine: bool,
        _yield_after: Duration,
        _timeout_seconds: u64,
    ) -> Result<StreamingExecReceipt, ActionError> {
        Err(unsupported())
    }

    pub(super) async fn poll(
        &self,
        _raw_id: &str,
        _stdout_cursor: u64,
        _stderr_cursor: u64,
        _wait_ms: u64,
    ) -> Result<ProcessSnapshot, ActionError> {
        Err(unsupported())
    }

    pub(super) async fn write(
        &self,
        _raw_id: &str,
        _bytes: Vec<u8>,
        _eof: bool,
    ) -> Result<WriteReceipt, ActionError> {
        Err(unsupported())
    }

    pub(super) async fn stop(&self, _raw_id: &str) -> Result<ProcessSnapshot, ActionError> {
        Err(unsupported())
    }

    pub(super) fn resize(
        &self,
        _raw_id: &str,
        _rows: u16,
        _cols: u16,
    ) -> Result<ProcessSnapshot, ActionError> {
        Err(unsupported())
    }

    pub(super) async fn clean(&self) -> Result<Vec<ProcessSnapshot>, ActionError> {
        Ok(Vec::new())
    }

    pub(super) fn list(&self) -> Vec<ProcessSummary> {
        Vec::new()
    }

    pub(super) fn health(&self) -> ProcessHealth {
        ProcessHealth {
            schema_version: 1,
            policy: self.policy(),
            retained_jobs: 0,
            active_jobs: 0,
            terminal_jobs: 0,
            cleanup_unknown_jobs: 0,
            awaiting_stdin_jobs: 0,
        }
    }
}

fn unsupported() -> ActionError {
    ActionError::Definite(
        "process execution is unavailable: this platform has no Iteron code-execution sandbox"
            .into(),
    )
}

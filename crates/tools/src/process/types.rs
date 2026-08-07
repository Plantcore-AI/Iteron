use super::output::{OutputFrame, OutputRing};
use serde::Serialize;
use std::fmt;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[derive(Debug)]
pub(super) enum ActionError {
    Definite(String),
    Unknown(String),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct JobId {
    pub(super) instance: u64,
    pub(super) sequence: u32,
}

impl JobId {
    pub(super) fn parse(raw: &str) -> Result<Self, ActionError> {
        let encoded = raw.strip_prefix("job-").ok_or_else(invalid_job_id)?;
        let (instance, sequence) = encoded.split_once('-').ok_or_else(invalid_job_id)?;
        if instance.len() != 16
            || sequence.len() != 8
            || !instance.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_job_id());
        }
        let instance = u64::from_str_radix(instance, 16).map_err(|_| invalid_job_id())?;
        let sequence = u32::from_str_radix(sequence, 16).map_err(|_| invalid_job_id())?;
        if sequence == 0 {
            return Err(invalid_job_id());
        }
        Ok(Self { instance, sequence })
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "job-{:016x}-{:08x}",
            self.instance, self.sequence
        )
    }
}

fn invalid_job_id() -> ActionError {
    ActionError::Definite("job_id must match job-<16 hex>-<8 hex>".into())
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum JobState {
    Running,
    Stopping,
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Stopped {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    TimedOut {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    OutputLimitExceeded {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    IoFailed {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    CleanupUnknown {
        trigger: &'static str,
    },
}

impl JobState {
    pub(super) fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running | Self::Stopping)
    }

    pub(super) fn is_reconciled_terminal(&self) -> bool {
        self.is_terminal() && !matches!(self, Self::CleanupUnknown { .. })
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ProcessSnapshot {
    pub(super) schema_version: u8,
    pub(super) job_id: String,
    pub(super) backend: &'static str,
    pub(super) state: JobState,
    pub(super) stdout: OutputFrame,
    pub(super) stderr: OutputFrame,
}

/// Output-free inventory row. Listing jobs must stay cheap even when every retained output ring is
/// full; cursors disclose how much output exists without copying any of it into the list response.
#[derive(Debug, Serialize)]
pub(super) struct ProcessSummary {
    pub(super) schema_version: u8,
    pub(super) job_id: String,
    pub(super) backend: &'static str,
    pub(super) command: String,
    pub(super) state: JobState,
    pub(super) stdout_cursor: u64,
    pub(super) stderr_cursor: u64,
}

impl ProcessSnapshot {
    pub(super) fn should_wait(&self) -> bool {
        matches!(self.state, JobState::Running)
            && self.stdout.text.is_empty()
            && self.stderr.text.is_empty()
            && !self.stdout.gap
            && !self.stderr.gap
    }
}

#[derive(Debug, Serialize)]
pub(super) struct WriteReceipt {
    pub(super) schema_version: u8,
    pub(super) job_id: String,
    pub(super) accepted_bytes: usize,
    pub(super) stdin_closed: bool,
    pub(super) state: JobState,
}

pub(super) struct JobShared {
    pub(super) state: Mutex<JobState>,
    pub(super) stdout: Arc<Mutex<OutputRing>>,
    pub(super) stderr: Arc<Mutex<OutputRing>>,
    pub(super) revision: watch::Sender<u64>,
}

impl JobShared {
    pub(super) fn notify(&self) {
        self.revision
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }
}

pub(super) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

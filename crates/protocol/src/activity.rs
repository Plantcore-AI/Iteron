//! Content-free live activity vocabulary for frontends.
//!
//! Durable [`crate::Phase`] events remain the authority for replay.  This additive projection is
//! deliberately bounded and carries no prompts, model output, paths, arguments, or error prose.

use serde::{Deserialize, Serialize};

pub const ACTIVITY_SCHEMA_VERSION: u8 = 1;
pub const MAX_ACTIVITY_ID_BYTES: usize = 96;
pub const MAX_ACTIVITY_ATTEMPTS: u16 = 1_000;
pub const MAX_ACTIVITY_PROGRESS_UNITS: u64 = 1_000_000_000;

fn max_activity_id_bytes() -> usize {
    iteron_tunables::param_usize(
        "protocol.activity.max_activity_id_bytes",
        iteron_tunables::param_integer(
            "protocol.activity.max_activity_id_bytes",
            MAX_ACTIVITY_ID_BYTES,
        ),
    )
    .clamp(1, MAX_ACTIVITY_ID_BYTES)
}

fn max_activity_attempts() -> u16 {
    iteron_tunables::param_integer(
        "protocol.activity.max_activity_attempts",
        MAX_ACTIVITY_ATTEMPTS,
    )
    .clamp(1, MAX_ACTIVITY_ATTEMPTS)
}

fn max_activity_progress_units() -> u64 {
    iteron_tunables::param_u64(
        "protocol.activity.max_activity_progress_units",
        iteron_tunables::param_integer(
            "protocol.activity.max_activity_progress_units",
            MAX_ACTIVITY_PROGRESS_UNITS,
        ),
    )
    .clamp(1, MAX_ACTIVITY_PROGRESS_UNITS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Startup,
    HistoryHydration,
    SessionIndex,
    WorkflowHydration,
    TerminalProbe,
    Attachment,
    Completion,
    ModelRequest,
    ProviderReasoning,
    Tool,
    Workflow,
    Verification,
    Persistence,
    Finalization,
    Cancellation,
}

impl ActivityKind {
    /// Only this provider-owned semantic may be presented as “thinking”.
    pub const fn is_reasoning(self) -> bool {
        matches!(self, Self::ProviderReasoning)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Queued,
    Running,
    Waiting,
    Retrying,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl ActivityState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityOwner {
    Frontend,
    Runtime,
    Provider,
    Tool,
    Workflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityCancelability {
    None,
    Cooperative,
    Strong,
}

/// Exact semantic UI activity vocabulary required by `governance/uiux-slo.json`. Keeping this
/// closed prevents an arbitrary status/error string from becoming accidental wire content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityDetailCode {
    Boot,
    Config,
    AgentDiscovery,
    PluginVerification,
    ProviderRefresh,
    FirstPaint,
    HistoryHydrate,
    SessionIndex,
    WorkflowRehydrate,
    SubmissionAdmission,
    ContextAssembly,
    HookGate,
    RoutePermit,
    RequestSerialization,
    TransportConnect,
    RequestSent,
    WaitingFirstByte,
    WaitingFirstToken,
    Reasoning,
    Responding,
    ToolProposed,
    ToolHook,
    ToolApproval,
    ToolQueued,
    ToolRunning,
    ToolPostProcessing,
    RetryBackoff,
    RouteFailover,
    Compaction,
    Verification,
    Checkpoint,
    RecordCommit,
    StopHooks,
    WorkflowResultPersist,
    AnswerComplete,
    Finalizing,
    InputReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityProgress {
    pub completed: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityEvent {
    pub schema_version: u8,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub kind: ActivityKind,
    pub state: ActivityState,
    pub owner: ActivityOwner,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub attempt: u16,
    pub limit: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_retry_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ms: Option<u64>,
    pub cancelability: ActivityCancelability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<ActivityDetailCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<ActivityProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityValidationError {
    UnsupportedVersion,
    InvalidId,
    InvalidParentId,
    InvalidTimestamp,
    InvalidAttempt,
    InvalidProgress,
}

impl ActivityEvent {
    pub fn validate(&self) -> Result<(), ActivityValidationError> {
        if self.schema_version != ACTIVITY_SCHEMA_VERSION {
            return Err(ActivityValidationError::UnsupportedVersion);
        }
        let max_id_bytes = max_activity_id_bytes();
        if !valid_code(&self.id, max_id_bytes) {
            return Err(ActivityValidationError::InvalidId);
        }
        if self
            .parent_id
            .as_deref()
            .is_some_and(|id| !valid_code(id, max_id_bytes))
        {
            return Err(ActivityValidationError::InvalidParentId);
        }
        if self.updated_at_unix_ms < self.started_at_unix_ms {
            return Err(ActivityValidationError::InvalidTimestamp);
        }
        if self.limit > max_activity_attempts()
            || self.attempt > self.limit
            || (self.limit == 0 && self.attempt != 0)
        {
            return Err(ActivityValidationError::InvalidAttempt);
        }
        if self.progress.is_some_and(|progress| {
            progress.total == 0
                || progress.total > max_activity_progress_units()
                || progress.completed > progress.total
        }) {
            return Err(ActivityValidationError::InvalidProgress);
        }
        Ok(())
    }
}

fn valid_code(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_contract_rejects_content_and_unbounded_progress() {
        let mut event = ActivityEvent {
            schema_version: ACTIVITY_SCHEMA_VERSION,
            id: "run-1:provider".into(),
            parent_id: Some("run-1".into()),
            kind: ActivityKind::ModelRequest,
            state: ActivityState::Running,
            owner: ActivityOwner::Provider,
            started_at_unix_ms: 10,
            updated_at_unix_ms: 11,
            attempt: 1,
            limit: 3,
            next_retry_at_unix_ms: None,
            deadline_unix_ms: Some(1_000),
            cancelability: ActivityCancelability::Cooperative,
            detail_code: Some(ActivityDetailCode::WaitingFirstToken),
            progress: None,
        };
        assert_eq!(event.validate(), Ok(()));
        event.id = "prompt content is forbidden".into();
        assert_eq!(event.validate(), Err(ActivityValidationError::InvalidId));
    }
}

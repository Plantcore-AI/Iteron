use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::task_dag::{BudgetUsage, TaskBudget};

pub const WORKFLOW_SCHEDULER_PORT_VERSION: u32 = 1;
pub const MAX_PLAN_NODES: usize = 512;
pub const MAX_PLAN_EDGES: usize = 2_048;
pub const MAX_PLAN_DEPTH: usize = 64;
pub const MAX_PLAN_CHANGES: usize = 512;
pub const MAX_PLAN_REVISIONS: u64 = 1_024;
pub const MAX_SCHEDULER_EVENTS: u64 = 65_536;
pub const MAX_PLAN_REQUESTS: usize = 8_192;
pub const MAX_NODE_TASK_BYTES: usize = 16 * 1_024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 2_048;
pub const MAX_PLAN_STORE_BYTES: u64 = 32 * 1_024 * 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowConfigV1 {
    pub workflow_id: String,
    pub budget: TaskBudget,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_concurrency: usize,
    pub started_at_unix_ms: u64,
    /// Absolute deadline from the host clock, retained across restart.
    pub deadline_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeV1 {
    pub id: u64,
    pub label: String,
    pub task: String,
    pub dependencies: Vec<u64>,
    /// Existing, host-admitted agent. This field cannot mint identity or execution authority.
    pub assigned_agent: u64,
    pub input_digest: String,
    pub budget: TaskBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowPlanChangeV1 {
    Add {
        node: WorkflowNodeV1,
    },
    ReplacePending {
        node: WorkflowNodeV1,
    },
    RemovePending {
        node_id: u64,
    },
    /// Definite failed/cancelled work may be explicitly reassigned. Successful work is immutable.
    Retry {
        node: WorkflowNodeV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReplanV1 {
    pub expected_revision: u64,
    pub changes: Vec<WorkflowPlanChangeV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurnLeaseV1 {
    pub agent_id: u64,
    pub incarnation: u64,
    pub turn: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledTaskV1 {
    pub workflow_id: String,
    pub node_id: u64,
    pub attempt: u64,
    pub input_digest: String,
    pub assigned_agent: u64,
    pub task: String,
    pub budget: TaskBudget,
    pub deadline_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowNodeStateV1 {
    Pending,
    /// Durable intent precedes any call to the controller. Restart requires reconciliation.
    Dispatching {
        attempt: u64,
        deadline_unix_ms: u64,
    },
    Running {
        attempt: u64,
        lease: AgentTurnLeaseV1,
        deadline_unix_ms: u64,
    },
    Cancelling {
        attempt: u64,
        lease: AgentTurnLeaseV1,
        deadline_unix_ms: u64,
    },
    Succeeded {
        attempt: u64,
        result_digest: String,
    },
    Failed {
        attempt: u64,
        detail: String,
    },
    Cancelled {
        attempt: u64,
        detail: String,
    },
    RecoveryRequired {
        attempt: u64,
        lease: Option<AgentTurnLeaseV1>,
        reason: String,
    },
    Removed,
}

impl WorkflowNodeStateV1 {
    pub fn active(&self) -> bool {
        matches!(
            self,
            Self::Dispatching { .. } | Self::Running { .. } | Self::Cancelling { .. }
        )
    }

    pub fn lease(&self) -> Option<AgentTurnLeaseV1> {
        match self {
            Self::Running { lease, .. } | Self::Cancelling { lease, .. } => Some(*lease),
            Self::RecoveryRequired { lease, .. } => *lease,
            _ => None,
        }
    }

    pub fn attempt(&self) -> Option<u64> {
        match self {
            Self::Pending | Self::Removed => None,
            Self::Dispatching { attempt, .. }
            | Self::Running { attempt, .. }
            | Self::Cancelling { attempt, .. }
            | Self::Succeeded { attempt, .. }
            | Self::Failed { attempt, .. }
            | Self::Cancelled { attempt, .. }
            | Self::RecoveryRequired { attempt, .. } => Some(*attempt),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeRecordV1 {
    pub node: WorkflowNodeV1,
    pub state: WorkflowNodeStateV1,
    /// Monotonic across graph edits, retries and restart. Old outputs cannot settle new work.
    pub next_attempt: u64,
    pub usage: BudgetUsage,
    /// Cumulative receipt for the active attempt. Reconciliation never charges it twice.
    pub attempt_usage: BudgetUsage,
    pub reserved_budget: BudgetUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPlanReceiptV1 {
    pub version: u32,
    pub revision: u64,
    pub sequence: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReceipt {
    pub digest: String,
    pub receipt: WorkflowPlanReceiptV1,
}

/// Immutable observation and durable store envelope. Fields are private to the state owner;
/// adapters may serialize the value, but cannot acquire authority by constructing a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSchedulerSnapshotV1 {
    pub(crate) version: u32,
    pub(crate) config: WorkflowConfigV1,
    pub(crate) sequence: u64,
    pub(crate) revision: u64,
    pub(crate) nodes: BTreeMap<u64, WorkflowNodeRecordV1>,
    pub(crate) reserved: BudgetUsage,
    pub(crate) receipts: BTreeMap<String, StoredReceipt>,
}

impl WorkflowSchedulerSnapshotV1 {
    pub fn config(&self) -> &WorkflowConfigV1 {
        &self.config
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn nodes(&self) -> impl Iterator<Item = &WorkflowNodeRecordV1> {
        self.nodes.values()
    }
    pub fn node(&self, id: u64) -> Option<&WorkflowNodeRecordV1> {
        self.nodes.get(&id)
    }
    pub fn reserved_budget(&self) -> BudgetUsage {
        self.reserved
    }
}

/// The host submits this only after authenticating the admitted lease and collecting actual usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowCompletionV1 {
    Succeeded { result_digest: String },
    Failed { detail: String },
    Cancelled { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkflowStoreError {
    #[error("workflow store unavailable before publication")]
    Unavailable,
    #[error("workflow publication outcome unknown; reopen and reconcile")]
    OutcomeUnknown,
    #[error("workflow store revision conflict")]
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkflowDispatchError {
    #[error("controller did not dispatch: {0}")]
    NotApplied(String),
    #[error("controller dispatch outcome unknown: {0}")]
    OutcomeUnknown(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowSchedulerError {
    #[error("invalid workflow command: {0}")]
    Invalid(&'static str),
    #[error("workflow revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("workflow request id already bound to a different command")]
    RequestConflict,
    #[error("workflow capacity exhausted: {0}")]
    Capacity(&'static str),
    #[error("workflow budget refused: {0}")]
    Budget(&'static str),
    #[error("workflow node {0} does not exist")]
    UnknownNode(u64),
    #[error("workflow node transition refused: {0}")]
    Transition(&'static str),
    #[error("workflow lease/attempt is stale")]
    StaleLease,
    #[error("workflow requires durable recovery")]
    Poisoned,
    #[error(transparent)]
    Store(#[from] WorkflowStoreError),
    #[error("workflow serialization failed")]
    Serialization,
}

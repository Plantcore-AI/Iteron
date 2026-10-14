//! Typed operator requests and immutable live graph observations; no client authority fields.

use iteron_workflow::live_scheduler::{
    WorkflowConfigV1, WorkflowNodeRecordV1, WorkflowPlanReceiptV1, WorkflowReplanV1,
    WorkflowSchedulerError, WorkflowStoreError,
};
use iteron_workflow::task_dag::{BudgetUsage, TaskBudget};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const LIVE_WORKFLOW_CONTRACT_VERSION: u32 = 1;
pub(super) const MAX_WORKFLOWS: usize = 16;
pub(super) const MAX_REQUESTS: usize = 16;
pub(super) const MAX_PUMP_OPERATIONS: usize = 4;
pub(super) const MAX_BACKGROUND_TICKS: usize = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LiveWorkflowCommandV1 {
    Open {
        workflow_id: String,
    },
    Read {
        workflow_id: String,
    },
    Replan {
        workflow_id: String,
        request_id: String,
        plan: WorkflowReplanV1,
    },
    Pump {
        workflow_id: String,
    },
    Interrupt {
        workflow_id: String,
        node_id: u64,
    },
    Reconcile {
        workflow_id: String,
        node_id: u64,
    },
}

impl LiveWorkflowCommandV1 {
    pub(crate) fn is_read_only(&self) -> bool {
        matches!(self, Self::Read { .. })
    }
    pub(crate) fn workflow_id(&self) -> &str {
        match self {
            Self::Open { workflow_id }
            | Self::Read { workflow_id }
            | Self::Replan { workflow_id, .. }
            | Self::Pump { workflow_id }
            | Self::Interrupt { workflow_id, .. }
            | Self::Reconcile { workflow_id, .. } => workflow_id,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), LiveWorkflowError> {
        validate_id(self.workflow_id())?;
        if let Self::Replan {
            request_id, plan, ..
        } = self
        {
            validate_id(request_id)?;
            if plan.changes.is_empty()
                || plan.changes.len() > iteron_workflow::live_scheduler::MAX_PLAN_CHANGES
            {
                return Err(LiveWorkflowError::Invalid(
                    "plan change count is outside its bound",
                ));
            }
        }
        if matches!(
            self,
            Self::Interrupt { node_id: 0, .. } | Self::Reconcile { node_id: 0, .. }
        ) {
            return Err(LiveWorkflowError::Invalid("node identity must be nonzero"));
        }
        Ok(())
    }
}

pub(super) fn validate_id(id: &str) -> Result<(), LiveWorkflowError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || id == "."
        || id == ".."
    {
        return Err(LiveWorkflowError::Invalid(
            "invalid bounded workflow/request identity",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveWorkflowViewV1 {
    pub version: u32,
    pub config: WorkflowConfigV1,
    pub revision: u64,
    pub sequence: u64,
    pub nodes: Vec<WorkflowNodeRecordV1>,
    pub reserved: BudgetUsage,
    pub ready: Vec<u64>,
    pub observed_at_unix_ms: u64,
    pub driver_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveWorkflowReplyV1 {
    pub view: LiveWorkflowViewV1,
    pub receipt: Option<WorkflowPlanReceiptV1>,
}

/// Trusted, immutable session admission ceilings. This value is never decoded from wire JSON.
#[derive(Debug, Clone)]
pub(crate) struct LiveWorkflowPolicy {
    pub root_agent_id: u64,
    pub aggregate_budget: TaskBudget,
    pub graph_budget: TaskBudget,
    pub max_workflows: usize,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_concurrency: usize,
}

impl LiveWorkflowPolicy {
    pub(crate) fn validate(&self) -> Result<(), LiveWorkflowError> {
        self.aggregate_budget
            .validate()
            .map_err(LiveWorkflowError::Invalid)?;
        self.graph_budget
            .validate()
            .map_err(LiveWorkflowError::Invalid)?;
        if self.root_agent_id == 0
            || self.graph_budget.max_turns == 0
            || self.graph_budget.max_tokens == 0
            || self.graph_budget.max_wall_ms == 0
            || !budget_fits(self.graph_budget, self.aggregate_budget)
            || self.max_workflows == 0
            || self.max_workflows > MAX_WORKFLOWS
            || self.max_nodes == 0
            || self.max_nodes > iteron_workflow::live_scheduler::MAX_PLAN_NODES
            || self.max_edges == 0
            || self.max_edges > iteron_workflow::live_scheduler::MAX_PLAN_EDGES
            || self.max_concurrency == 0
            || self.max_concurrency > 64
            || self.max_concurrency > self.max_nodes
        {
            return Err(LiveWorkflowError::Invalid(
                "workflow policy exceeds host bounds",
            ));
        }
        Ok(())
    }
}

pub(super) fn budget_fits(value: TaskBudget, limit: TaskBudget) -> bool {
    value.max_turns <= limit.max_turns
        && value.max_tokens <= limit.max_tokens
        && value.max_cost_microusd <= limit.max_cost_microusd
        && value.max_wall_ms <= limit.max_wall_ms
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LiveWorkflowError {
    #[error("invalid live workflow: {0}")]
    Invalid(&'static str),
    #[error("live workflow not found")]
    NotFound,
    #[error("live workflow command admission is busy")]
    Busy,
    #[error("live workflow registry capacity/budget exhausted")]
    Capacity,
    #[error("live workflow durable state unavailable: {0}")]
    Store(#[from] WorkflowStoreError),
    #[error("live workflow graph refused: {0}")]
    Scheduler(#[from] WorkflowSchedulerError),
    #[error("live workflow controller proof unavailable")]
    Controller,
    #[error("live workflow host clock unavailable")]
    Clock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryEntry {
    pub config: WorkflowConfigV1,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryIndex {
    pub revision: u64,
    pub root_agent_id: u64,
    pub entries: BTreeMap<String, RegistryEntry>,
}

//! Versioned live planning, separate from persistent agent identity and execution.
//!
//! The scheduler is the only writer of its dependency graph. A controller port owns agent
//! lifecycle, contexts, permissions and processes; a journal port owns durable publication. A
//! revision updates future work, never silently restarts completed work or an unknown effect.

pub mod file_journal;
mod owner;
pub mod ports;
pub mod types;
mod validation;

pub use owner::WorkflowScheduler;
pub use ports::{WorkflowControllerPort, WorkflowPlanJournal};
pub use types::{
    AgentTurnLeaseV1, MAX_DIAGNOSTIC_BYTES, MAX_NODE_TASK_BYTES, MAX_PLAN_CHANGES, MAX_PLAN_DEPTH,
    MAX_PLAN_EDGES, MAX_PLAN_NODES, MAX_PLAN_REQUESTS, MAX_PLAN_REVISIONS, MAX_PLAN_STORE_BYTES,
    MAX_SCHEDULER_EVENTS, ScheduledTaskV1, WORKFLOW_SCHEDULER_PORT_VERSION, WorkflowCompletionV1,
    WorkflowConfigV1, WorkflowDispatchError, WorkflowNodeRecordV1, WorkflowNodeStateV1,
    WorkflowNodeV1, WorkflowPlanChangeV1, WorkflowPlanReceiptV1, WorkflowReplanV1,
    WorkflowSchedulerError, WorkflowSchedulerSnapshotV1, WorkflowStoreError,
};

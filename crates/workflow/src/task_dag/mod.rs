//! Durable, replay-safe task DAG state for bounded multi-agent collaboration.
//!
//! This module owns only the deterministic state machine and its append-only store. It does not
//! spawn agents, grant tools, or widen a task's authority. The composition root remains responsible
//! for translating a ready task into an admitted child runtime and for feeding durable commands
//! back through this API.
//!
//! Turn/token/cost reservations are deliberately monotonic: unused child capacity is not refunded
//! without a separately verified usage receipt. Wall-clock ceilings are per hierarchy path rather
//! than additive across parallel children; the runtime must also enforce the graph's absolute
//! deadline. The hash chain detects accidental corruption and incomplete writes, but is not a MAC
//! and therefore is not evidence against an attacker who can rewrite the entire state file.
//!
//! # Runtime integration boundary
//!
//! `TaskSpec` is a bounded scheduling projection, not a complete or authenticated spawn record.
//! Before dispatch, a trusted effect broker must durably bind the task to an immutable agent
//! catalog and `AgentDef` digest, effective tool-set digest, provider/model route, effective
//! turn/token/cost/wall budgets, input digest, and broker-issued child/runtime identity. A model
//! must never be allowed to mint `Actor::Controller`; task commands and completion receipts need
//! authenticated runtime identities rather than self-asserted enum values.
//!
//! The composition root must additionally provide write-ahead spawn intent, an explicit
//! dispatched/unknown outcome, orphan reconciliation, an absolute graph deadline, and durable
//! effect acknowledgement for cancellation, message delivery, and joins. This pure module records
//! deterministic requested state only; it does not prove a process was started or stopped, that a
//! message reached a runtime, or that a completion came from the admitted child.

mod graph;
mod hash;
mod reducer;
mod shape;
mod store;
mod types;
mod validation;
mod validation_support;

pub use reducer::{ApplyReceipt, Snapshot, TaskDag};
pub use store::TaskDagStore;
pub use types::{
    Actor, BudgetUsage, Command, CommandId, Completion, Config, DeliveryState, JoinId, JoinPolicy,
    JoinSpec, JoinState, Limits, MessageId, MessageKind, Task, TaskBudget, TaskId, TaskMessage,
    TaskSpec, TaskState,
};

#[derive(Debug, thiserror::Error)]
pub enum DagError {
    #[error("invalid task-DAG configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("task-DAG event limit reached")]
    EventLimit,
    #[error("command id must be non-zero")]
    InvalidCommandId,
    #[error("command id {0} was already used for a different command")]
    CommandConflict(u64),
    #[error("task {0} does not exist")]
    UnknownTask(u64),
    #[error("task {0} already exists")]
    DuplicateTask(u64),
    #[error("message {0} already exists")]
    DuplicateMessage(u64),
    #[error("message {0} does not exist")]
    UnknownMessage(u64),
    #[error("join {0} already exists")]
    DuplicateJoin(u64),
    #[error("join {0} does not exist")]
    UnknownJoin(u64),
    #[error("task-DAG {kind} limit reached")]
    Capacity { kind: &'static str },
    #[error("task-DAG authority refused command: {0}")]
    Authority(&'static str),
    #[error("invalid task-DAG command: {0}")]
    Invalid(&'static str),
    #[error("invalid transition for task {task}: {reason}")]
    Transition { task: u64, reason: &'static str },
    #[error("budget admission refused: {0}")]
    Budget(&'static str),
    #[error("task-DAG replay is corrupt: {0}")]
    Corrupt(String),
    #[error("task-DAG durable store is unavailable: {0}")]
    Io(#[from] std::io::Error),
    #[error("task-DAG serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("task-DAG append crossed dispatch but durability is unknown: {0}")]
    DurabilityUnknown(String),
    #[error("task-DAG store is poisoned after a durability failure: {0}")]
    Poisoned(String),
}

#[cfg(test)]
mod tests;

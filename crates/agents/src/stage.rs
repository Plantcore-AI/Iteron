//! The stage vocabulary — re-scoped to `Fan` + `Reduce` only (the R5 design review gate).
//!
//! The R5 design proposed a six-variant Stage DAG (`Fan`, `Reduce`, `Pipe`, `Judge`, `LoopUntilDry`,
//! `AdversarialVerify`). The review cut it to the two that are justified and buildable today. The
//! other four are **deferred, recorded as rejected-for-now** (see the crate module docs): `Pipe` is
//! the existing single-agent loop, `Judge`/sample-N need the not-yet-built disposable-workspace
//! substrate, and `LoopUntilDry`/`AdversarialVerify` have no proven consumer. Keeping the enum to
//! two variants is the honest surface: it cannot express a topology the engine cannot execute.

use core_protocol::Budget;

use serde::{Deserialize, Serialize};

use crate::decompose::TaskClass;

/// One fan-out leaf: a fully-specified delegation to a read-only investigator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTask {
    /// Stable zero-based declaration id, assigned after normalization/deduplication. The id is the
    /// join key used by observation and reduction; it never depends on worker completion order.
    #[serde(default)]
    pub id: usize,
    /// Names an `AgentDef` in the catalog; `None` = the built-in generic investigator.
    pub agent_type: Option<String>,
    /// The one question this investigator owns. It is normalized, bounded, and self-contained.
    #[serde(default)]
    pub objective: String,
    /// Explicit authority boundary. Investigators may inspect repository state but never write.
    #[serde(default)]
    pub scope: String,
    /// The evidence shape the writer can verify and either adopt or reject.
    #[serde(default)]
    pub deliverable: String,
    /// Fully-specified compatibility prompt consumed by the current kernel. The structured fields
    /// above are authoritative; this rendered form keeps older executors useful while they migrate
    /// to the typed contract. There is no implicit sibling coordination — anything a worker must
    /// know is stated here (ADR-001).
    pub prompt: String,
}

/// Current investigator authority boundary. Kept as data so the executor and future policy slot
/// can render the same contract without inventing different permissions.
pub const INVESTIGATOR_SCOPE: &str =
    "Read-only repository inspection. Do not edit files, run mutating commands, or delegate.";

/// Minimum evidence contract for every fan leaf. A worker may report uncertainty, but may not turn
/// guesses into evidence.
pub const INVESTIGATOR_DELIVERABLE: &str = "Return: (1) a direct conclusion; (2) concrete evidence \
    with exact file:line references or named symbols; (3) conflicts, uncertainty, and uncovered \
    areas; (4) a recommended next action. Clearly label inference. Do not claim changes were made.";

impl AgentTask {
    /// Build the generic read-only investigator contract from a normalized objective.
    pub(crate) fn investigator(id: usize, objective: String) -> Self {
        let scope = INVESTIGATOR_SCOPE.to_string();
        let deliverable = INVESTIGATOR_DELIVERABLE.to_string();
        let prompt =
            format!("Assigned question: {objective}\nScope: {scope}\nDeliverable: {deliverable}");
        Self {
            id,
            agent_type: None,
            objective,
            scope,
            deliverable,
            prompt,
        }
    }
}

/// A stage of the workflow. Exactly two variants (see the module docs for what was cut and why).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Fan topology with a join barrier: N read-only investigators, `Governor`-capped at
    /// `FAN_CAP`, whose results are read in DECLARATION order. The current kernel executes workers
    /// sequentially; `Fan` describes isolation and synthesis topology, not a latency claim. Reduce
    /// waits for every admitted worker — never the first finisher.
    Fan { tasks: Vec<AgentTask> },
    /// The single writer consumes the ordered fan bundle. In core this IS the parent writer, not
    /// a separate agent — one synthesizer, and it is the one writer (ADR-001).
    Reduce,
}

/// A concrete workflow: a `Fan` followed by a `Reduce`, plus the aggregate budget and provenance.
///
/// The R5 design typed this as `{ root: Stage, aggregate: Budget }`, assuming the deferred `Pipe`
/// variant to compose stages. With `Pipe` cut, a `Vec<Stage>` is the honest composition: this crate
/// only ever produces `[Fan{..}, Reduce]`, and the vector says exactly that without a variant the
/// engine cannot walk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowPlan {
    /// The stages, in execution order (always `[Fan, Reduce]` today).
    pub stages: Vec<Stage>,
    /// One shared run budget for the whole fan — never per-agent (ADR-013: per-agent budgets would
    /// multiply the ceiling past the cost gate). The kernel splits it across the fan and reconciles.
    pub aggregate: Budget,
    /// The task class that selected this topology (recorded for observability/replay).
    pub class: TaskClass,
    /// `Some(n)` if the decomposer truncated `n` leaves to fit `FAN_CAP` — surfaced, never silent
    /// (度量诚实: no silent truncation). `None` = every emitted leaf was kept.
    pub truncated: Option<usize>,
    /// Candidate leaves removed as case-insensitive duplicates before applying `FAN_CAP`.
    #[serde(default)]
    pub duplicates_removed: usize,
    /// Empty, unsafe, or over-limit candidate leaves rejected before applying `FAN_CAP`.
    #[serde(default)]
    pub invalid_removed: usize,
}

impl WorkflowPlan {
    /// The fan stage's tasks (convenience for the executor and tests).
    pub fn fan_tasks(&self) -> &[AgentTask] {
        match self.stages.first() {
            Some(Stage::Fan { tasks }) => tasks,
            _ => &[],
        }
    }
}

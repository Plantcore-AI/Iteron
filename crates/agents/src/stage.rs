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
    /// `min(FAN_CAP, cores-2, admitted)`, whose results are read in DECLARATION order. The kernel
    /// runs the workers bounded-concurrent (owned tasks under the permit cap); `Fan` describes
    /// isolation and synthesis topology, and Reduce waits for every admitted worker — never the
    /// first finisher, so completion order never leaks into the writer decision.
    Fan { tasks: Vec<AgentTask> },
    /// The single writer consumes the ordered fan bundle. In core this IS the parent writer, not
    /// a separate agent — one synthesizer, and it is the one writer (ADR-001).
    Reduce,
}

/// A concrete workflow topology: a `Fan` followed by a `Reduce`, plus provenance.
///
/// The R5 design typed this as `{ root: Stage, aggregate: Budget }`, assuming the deferred `Pipe`
/// variant to compose stages. With `Pipe` cut, a `Vec<Stage>` is the honest composition: this crate
/// only ever produces `[Fan{..}, Reduce]`, and the vector says exactly that without a variant the
/// engine cannot walk. Budget allocation happens after fan normalization determines the admitted
/// task count, so an unbudgeted topology deliberately has no `aggregate` field. Call
/// [`WorkflowPlan::with_aggregate`] only after the caller has computed the real shared ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowPlan {
    /// The stages, in execution order (always `[Fan, Reduce]` today).
    pub stages: Vec<Stage>,
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

    /// Finalize this topology with the real shared fan ceiling.
    ///
    /// The transition consumes the unbudgeted plan, so callers cannot accidentally execute a
    /// placeholder and overwrite it later. Zero turn/wall ceilings remain valid explicit stop
    /// conditions; monetary values receive [`Budget::validate`] validation at this boundary.
    pub fn with_aggregate(self, aggregate: Budget) -> Result<BudgetedWorkflowPlan, &'static str> {
        aggregate.validate()?;
        Ok(BudgetedWorkflowPlan {
            topology: self,
            aggregate,
        })
    }
}

/// An executable workflow plan whose shared fan ceiling has been finalized.
///
/// The aggregate is private and immutable. Executors may inspect it through [`Self::aggregate`]
/// but cannot replace it with a post-construction value, eliminating the former placeholder state.
#[derive(Debug, Clone)]
pub struct BudgetedWorkflowPlan {
    topology: WorkflowPlan,
    aggregate: Budget,
}

impl BudgetedWorkflowPlan {
    /// The finalized topology and its routing/truncation provenance.
    pub fn topology(&self) -> &WorkflowPlan {
        &self.topology
    }

    /// The one shared run budget for the whole fan — never per-agent (ADR-013: per-agent budgets
    /// would multiply the ceiling past the cost gate). The executor splits and reconciles it.
    pub fn aggregate(&self) -> &Budget {
        &self.aggregate
    }

    /// The admitted fan tasks in declaration order.
    pub fn fan_tasks(&self) -> &[AgentTask] {
        self.topology.fan_tasks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> WorkflowPlan {
        WorkflowPlan {
            stages: vec![
                Stage::Fan {
                    tasks: vec![AgentTask::investigator(0, "inspect caller".into())],
                },
                Stage::Reduce,
            ],
            class: TaskClass::MultiFile,
            truncated: None,
            duplicates_removed: 0,
            invalid_removed: 0,
        }
    }

    #[test]
    fn aggregate_is_only_visible_after_finalization_and_is_immutable() {
        let plan = topology();
        let json = serde_json::to_value(&plan).unwrap();
        assert!(
            json.get("aggregate").is_none(),
            "topology records must not imply that a final budget already exists"
        );

        let budget = Budget {
            max_turns: 12,
            max_usd: Some(3.5),
            max_tokens: Some(50_000),
            max_wall_secs: 90,
            max_consecutive_tool_errors: 2,
        };
        let budgeted = plan.with_aggregate(budget).unwrap();
        assert_eq!(budgeted.aggregate().max_turns, 12);
        assert_eq!(budgeted.aggregate().max_usd, Some(3.5));
        assert_eq!(budgeted.aggregate().max_wall_secs, 90);
        assert_eq!(budgeted.fan_tasks()[0].objective, "inspect caller");
        assert_eq!(budgeted.topology().class, TaskClass::MultiFile);
    }

    #[test]
    fn finalization_rejects_an_invalid_monetary_ceiling() {
        let invalid = Budget {
            max_usd: Some(f64::NAN),
            max_tokens: None,
            ..Budget::default()
        };
        assert_eq!(
            topology().with_aggregate(invalid).unwrap_err(),
            "max_usd must be finite"
        );
    }
}

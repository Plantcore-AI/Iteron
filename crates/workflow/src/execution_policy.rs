//! Bounded workflow execution policies owned by the host, never by workflow JavaScript.

use std::time::Duration;

use serde::Serialize;

/// Maximum duplicate read-only workers an explicit speculative call may request.
pub const MAX_SPECULATIVE_SIBLINGS: usize = 1_024;
/// Maximum task attempts, including the first assigned worker.
pub const MAX_TASK_ATTEMPTS: usize = 64;
/// Shortest accepted loser-cleanup window. Below one second a cancelled sibling cannot be observed
/// to have quit, so the reconciliation would report unknown effects on every run.
const MIN_SPECULATIVE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest accepted loser-cleanup window: one hour, past which a stuck loser is an operator problem
/// rather than something the host should keep waiting on.
const MAX_SPECULATIVE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3_600);
/// Built-in duplicate-worker count: one extra sibling, the smallest amount of speculation that can
/// win a race at all.
const DEFAULT_SPECULATIVE_SIBLINGS: usize = 2;
/// Built-in loser-cleanup window, sized for a cancelled child to unwind without holding the run.
const DEFAULT_SPECULATIVE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Built-in task attempt ceiling: the assigned worker plus exactly one reassignment, so a transient
/// negative terminal is retried once without letting a genuinely impossible task loop on budget.
const DEFAULT_TASK_ATTEMPTS: usize = 2;

/// Immutable recursion ceiling for workflow-launched agents. A child may run tools but may never
/// become a second workflow composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpawnDepthControl {
    max_depth: u32,
}

impl SpawnDepthControl {
    pub const fn owner() -> Self {
        Self { max_depth: 1 }
    }

    pub const fn max_depth(self) -> u32 {
        self.max_depth
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadyTaskTieBreak {
    Fifo,
}

impl ReadyTaskTieBreak {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
        }
    }
}

/// Exact ready-queue owner. The reducer consumes this policy when it materializes ready tasks;
/// dependency admission remains a prerequisite and one level intentionally means no caller-
/// supplied priority can reorder durable declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TaskPrioritySchedulingPolicy {
    priority_levels: usize,
    tie_break: ReadyTaskTieBreak,
    dependency_ready_only: bool,
}

impl TaskPrioritySchedulingPolicy {
    pub const fn owner() -> Self {
        Self {
            priority_levels: 1,
            tie_break: ReadyTaskTieBreak::Fifo,
            dependency_ready_only: true,
        }
    }

    pub const fn priority_levels(self) -> usize {
        self.priority_levels
    }

    pub const fn tie_break(self) -> ReadyTaskTieBreak {
        self.tie_break
    }

    pub const fn dependency_ready_only(self) -> bool {
        self.dependency_ready_only
    }

    pub(crate) fn order_ready(self, ready: &mut [crate::task_dag::TaskId]) {
        debug_assert!(self.dependency_ready_only);
        match self.tie_break {
            ReadyTaskTieBreak::Fifo => ready.sort_unstable(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMessagingTopology {
    ParentMediated,
}

impl AgentMessagingTopology {
    pub const fn owner() -> Self {
        Self::ParentMediated
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ParentMediated => "parent_mediated",
        }
    }

    pub(crate) const fn durable_sender(self) -> Option<crate::task_dag::TaskId> {
        match self {
            Self::ParentMediated => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanWriterDisposition {
    Serialize,
}

impl CleanWriterDisposition {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Serialize => "serialize",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictDisposition {
    Reject,
}

impl ConflictDisposition {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reject => "reject",
        }
    }
}

/// Single-writer policy enforced when the production spawner converts a catalog definition into
/// an executable child. A writer is admissible only as the harness-authored isolated writer, with
/// a host-owned worktree and validating serialized merge controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WriterMergePolicy {
    writer_worktree_isolation: bool,
    on_clean: CleanWriterDisposition,
    on_conflict: ConflictDisposition,
    require_verification: bool,
}

impl WriterMergePolicy {
    pub const fn isolated_writer() -> Self {
        Self {
            writer_worktree_isolation: true,
            on_clean: CleanWriterDisposition::Serialize,
            on_conflict: ConflictDisposition::Reject,
            require_verification: true,
        }
    }

    /// Compatibility posture for a host that deliberately exposes no writer child at all.
    pub const fn parent_only() -> Self {
        Self {
            writer_worktree_isolation: false,
            on_clean: CleanWriterDisposition::Serialize,
            on_conflict: ConflictDisposition::Reject,
            require_verification: true,
        }
    }

    pub const fn writer_worktree_isolation(self) -> bool {
        self.writer_worktree_isolation
    }

    pub const fn on_clean(self) -> CleanWriterDisposition {
        self.on_clean
    }

    pub const fn on_conflict(self) -> ConflictDisposition {
        self.on_conflict
    }

    pub const fn require_verification(self) -> bool {
        self.require_verification
    }

    /// Admission seam for the executable child path. Write authority and worktree isolation are a
    /// pair: neither may be requested without the other.
    pub fn admit_child(
        self,
        requests_write_capability: bool,
        requests_worktree: bool,
    ) -> Result<(), &'static str> {
        if requests_write_capability != requests_worktree {
            return Err("workflow writer authority requires an isolated worktree");
        }
        if requests_write_capability && !self.writer_worktree_isolation {
            return Err("workflow writer worktree isolation is disabled");
        }
        Ok(())
    }
}

impl Default for WriterMergePolicy {
    fn default() -> Self {
        Self::isolated_writer()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeculativeWinnerEvidence {
    FirstVerified,
}

impl SpeculativeWinnerEvidence {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FirstVerified => "first_verified",
        }
    }
}

/// Policy for `agent(..., { speculativeSiblings })`.
///
/// Speculation is never implicit: the script must request it, the host clamps it to this immutable
/// ceiling, and the production spawner independently limits every child to a read-only registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpeculativeSiblingPolicy {
    max_siblings: usize,
    winner_evidence: SpeculativeWinnerEvidence,
    cancel_losers: bool,
    cleanup_timeout: Duration,
    reconcile_unknown_effects: bool,
}

impl SpeculativeSiblingPolicy {
    pub fn new(max_siblings: usize, cleanup_timeout: Duration) -> Result<Self, &'static str> {
        if max_siblings
            > iteron_tunables::param_usize(
                "workflow.execution_policy.max_speculative_siblings",
                iteron_tunables::param_integer(
                    "workflow.execution_policy.max_speculative_siblings",
                    MAX_SPECULATIVE_SIBLINGS,
                ),
            )
        {
            return Err("speculative sibling ceiling exceeds 1024");
        }
        if !(iteron_tunables::param_duration(
            "workflow.execution_policy.min_speculative_cleanup_timeout",
            MIN_SPECULATIVE_CLEANUP_TIMEOUT,
        )
            ..=iteron_tunables::param_duration(
                "workflow.execution_policy.max_speculative_cleanup_timeout",
                MAX_SPECULATIVE_CLEANUP_TIMEOUT,
            ))
            .contains(&cleanup_timeout)
        {
            return Err("speculative cleanup timeout must be in 1..=3600 seconds");
        }
        Ok(Self {
            max_siblings,
            winner_evidence: SpeculativeWinnerEvidence::FirstVerified,
            cancel_losers: true,
            cleanup_timeout,
            reconcile_unknown_effects: true,
        })
    }

    pub const fn max_siblings(self) -> usize {
        self.max_siblings
    }

    pub const fn winner_evidence(self) -> SpeculativeWinnerEvidence {
        self.winner_evidence
    }

    pub const fn cancel_losers(self) -> bool {
        self.cancel_losers
    }

    pub const fn cleanup_timeout(self) -> Duration {
        self.cleanup_timeout
    }

    pub const fn reconcile_unknown_effects(self) -> bool {
        self.reconcile_unknown_effects
    }
}

impl Default for SpeculativeSiblingPolicy {
    fn default() -> Self {
        Self::new(
            iteron_tunables::param_usize(
                "workflow.execution_policy.default_speculative_siblings",
                iteron_tunables::param_integer(
                    "workflow.execution_policy.default_speculative_siblings",
                    DEFAULT_SPECULATIVE_SIBLINGS,
                ),
            ),
            iteron_tunables::param_duration(
                "workflow.execution_policy.default_speculative_cleanup_timeout",
                DEFAULT_SPECULATIVE_CLEANUP_TIMEOUT,
            ),
        )
        .expect("built-in speculation policy is valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailureAction {
    Stop,
    RetrySame,
    Reassign,
}

impl TaskFailureAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::RetrySame => "retry_same",
            Self::Reassign => "reassign",
        }
    }
}

/// Bounded reassignment after a child returns a definite negative terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TaskRetryPolicy {
    max_attempts: usize,
    on_failure: TaskFailureAction,
    preserve_evidence: bool,
}

impl TaskRetryPolicy {
    pub fn new(
        max_attempts: usize,
        on_failure: TaskFailureAction,
        preserve_evidence: bool,
    ) -> Result<Self, &'static str> {
        if max_attempts
            > iteron_tunables::param_usize(
                "workflow.execution_policy.max_task_attempts",
                iteron_tunables::param_integer(
                    "workflow.execution_policy.max_task_attempts",
                    MAX_TASK_ATTEMPTS,
                ),
            )
        {
            return Err("task attempt ceiling exceeds 64");
        }
        Ok(Self {
            max_attempts,
            on_failure,
            preserve_evidence,
        })
    }

    pub const fn max_attempts(self) -> usize {
        self.max_attempts
    }

    pub const fn on_failure(self) -> TaskFailureAction {
        self.on_failure
    }

    pub const fn preserve_evidence(self) -> bool {
        self.preserve_evidence
    }
}

impl Default for TaskRetryPolicy {
    fn default() -> Self {
        Self::new(
            iteron_tunables::param_usize(
                "workflow.execution_policy.default_task_attempts",
                iteron_tunables::param_integer(
                    "workflow.execution_policy.default_task_attempts",
                    DEFAULT_TASK_ATTEMPTS,
                ),
            ),
            TaskFailureAction::Reassign,
            true,
        )
        .expect("built-in task retry policy is valid")
    }
}

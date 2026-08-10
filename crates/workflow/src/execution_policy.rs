//! Bounded workflow execution policies owned by the host, never by workflow JavaScript.

use std::time::Duration;

use serde::Serialize;

/// Maximum duplicate read-only workers an explicit speculative call may request.
pub const MAX_SPECULATIVE_SIBLINGS: usize = 1_024;
/// Maximum task attempts, including the first assigned worker.
pub const MAX_TASK_ATTEMPTS: usize = 64;

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
        if max_siblings > MAX_SPECULATIVE_SIBLINGS {
            return Err("speculative sibling ceiling exceeds 1024");
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(3_600)).contains(&cleanup_timeout) {
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
        Self::new(2, Duration::from_secs(5)).expect("built-in speculation policy is valid")
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
        if max_attempts > MAX_TASK_ATTEMPTS {
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
        Self::new(2, TaskFailureAction::Reassign, true)
            .expect("built-in task retry policy is valid")
    }
}

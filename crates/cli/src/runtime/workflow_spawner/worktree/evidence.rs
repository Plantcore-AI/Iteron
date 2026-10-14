//! Physical writer observations shared with native workers, never inferred from model reports.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use super::{MergeFailure, MergeFailureKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime) enum WriterSettlementProof {
    KnownDiscarded,
    KnownMerged,
    Unknown,
}

impl WriterSettlementProof {
    pub(in crate::runtime) fn known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Pending observations survive a dropped async waiter while its native worker still executes.
/// An uncertain process/pipe terminal is absorbing; successful later deletion is insufficient.
#[derive(Default)]
pub(super) struct WriterEvidence {
    pending: AtomicUsize,
    unknown: AtomicBool,
    parent_apply: AtomicU8,
    witness_pending: AtomicBool,
}

impl WriterEvidence {
    pub(super) fn begin(&self) {
        // Each worktree has one caller-owned transaction; nested workers are bounded by its phase.
        if self.pending.fetch_add(1, Ordering::AcqRel) >= 8 {
            self.unknown.store(true, Ordering::Release);
        }
    }

    pub(super) fn complete<T>(&self, result: &Result<T, MergeFailure>) {
        if result
            .as_ref()
            .is_err_and(|error| error.kind == MergeFailureKind::NativeProcessUncertain)
        {
            self.unknown.store(true, Ordering::Release);
        }
        self.pending.fetch_sub(1, Ordering::AcqRel);
    }

    pub(super) fn mark_unknown(&self) {
        self.unknown.store(true, Ordering::Release);
    }

    pub(super) fn applying(&self) {
        self.parent_apply.store(1, Ordering::Release);
    }

    pub(super) fn applied(&self) {
        self.parent_apply.store(2, Ordering::Release);
    }

    pub(super) fn require_witness(&self) {
        self.witness_pending.store(true, Ordering::Release);
    }

    pub(super) fn confirm_witness(&self) {
        self.witness_pending.store(false, Ordering::Release);
    }

    pub(super) fn proof(&self, removed: bool) -> WriterSettlementProof {
        if !removed
            || self.pending.load(Ordering::Acquire) != 0
            || self.unknown.load(Ordering::Acquire)
            || self.witness_pending.load(Ordering::Acquire)
        {
            return WriterSettlementProof::Unknown;
        }
        match self.parent_apply.load(Ordering::Acquire) {
            0 => WriterSettlementProof::KnownDiscarded,
            2 => WriterSettlementProof::KnownMerged,
            _ => WriterSettlementProof::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_apply_terminal_is_not_repaired_by_a_confirmed_discard() {
        let evidence = WriterEvidence::default();
        evidence.begin();
        evidence.applying();
        evidence.complete(&Ok::<(), MergeFailure>(()));
        assert_eq!(evidence.proof(true), WriterSettlementProof::Unknown);
    }

    #[test]
    fn dropped_native_waiter_cannot_be_promoted_to_a_completed_cleanup() {
        let evidence = WriterEvidence::default();
        evidence.begin();
        assert_eq!(evidence.proof(true), WriterSettlementProof::Unknown);
    }

    #[test]
    fn an_unconfirmed_controller_publication_preserves_writer_quarantine() {
        let evidence = WriterEvidence::default();
        evidence.require_witness();
        evidence.applying();
        evidence.applied();
        assert_eq!(evidence.proof(true), WriterSettlementProof::Unknown);
        evidence.confirm_witness();
        assert_eq!(evidence.proof(true), WriterSettlementProof::KnownMerged);
    }
}

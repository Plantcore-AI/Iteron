//! Bounded non-blocking stores for context and memory decision evidence.
//!
//! The runtime writes complete per-turn snapshots after a decision boundary. TUI diagnostics read
//! clones; contention drops an observation and increments a counter instead of delaying a model
//! request.

use crate::{ContextLedger, ContextObservation, ContextObserver, MemoryDecisionTrace};
use crate::{MemoryObservation, MemoryObserver};
use iteron_protocol::TurnId;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

pub const MAX_DECISION_TURNS: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct ContextLedgerStore {
    inner: Arc<ContextInner>,
}

#[derive(Debug, Default)]
struct ContextInner {
    ledgers: Mutex<VecDeque<ContextLedger>>,
    dropped_oldest: AtomicU64,
    dropped_contention: AtomicU64,
    dropped_unmatched: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryTraceStore {
    inner: Arc<MemoryInner>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    traces: Mutex<VecDeque<MemoryDecisionTrace>>,
    dropped_oldest: AtomicU64,
    dropped_contention: AtomicU64,
    dropped_unmatched: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct ContextLedgerSnapshot {
    pub ledgers: Vec<ContextLedger>,
    pub dropped_oldest: u64,
    pub dropped_contention: u64,
    pub dropped_unmatched: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryTraceSnapshot {
    pub traces: Vec<MemoryDecisionTrace>,
    pub dropped_oldest: u64,
    pub dropped_contention: u64,
    pub dropped_unmatched: u64,
}

impl ContextLedgerStore {
    pub fn publish(&self, ledger: ContextLedger) {
        match self.inner.ledgers.try_lock() {
            Ok(mut ledgers) => {
                if let Some(existing) = ledgers
                    .iter_mut()
                    .find(|existing| existing.turn_id == ledger.turn_id)
                {
                    *existing = ledger;
                    return;
                }
                if ledgers.len() == MAX_DECISION_TURNS {
                    ledgers.pop_front();
                    self.inner.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                }
                ledgers.push_back(ledger);
            }
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                self.inner
                    .dropped_contention
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> ContextLedgerSnapshot {
        let ledgers = self
            .inner
            .ledgers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        ContextLedgerSnapshot {
            ledgers,
            dropped_oldest: self.inner.dropped_oldest.load(Ordering::Relaxed),
            dropped_contention: self.inner.dropped_contention.load(Ordering::Relaxed),
            dropped_unmatched: self.inner.dropped_unmatched.load(Ordering::Relaxed),
        }
    }
}

impl ContextObserver for ContextLedgerStore {
    fn observe(&self, turn_id: TurnId, observation: ContextObservation) {
        let Ok(mut ledgers) = self.inner.ledgers.try_lock() else {
            self.inner
                .dropped_contention
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(ledger) = ledgers
            .iter_mut()
            .rev()
            .find(|ledger| ledger.turn_id == turn_id)
        else {
            self.inner.dropped_unmatched.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match observation {
            ContextObservation::Segment(evidence) => ledger.record_segment(evidence),
            ContextObservation::Transform(evidence) => ledger.record_transform(evidence),
            ContextObservation::Compaction(evidence) => ledger.compaction = Some(evidence),
            ContextObservation::ProviderUsage {
                actual_input_tokens,
            } => ledger.totals.actual_input_tokens = Some(actual_input_tokens),
        }
    }
}

impl MemoryTraceStore {
    pub fn publish(&self, trace: MemoryDecisionTrace) {
        match self.inner.traces.try_lock() {
            Ok(mut traces) => {
                if let Some(existing) = traces
                    .iter_mut()
                    .find(|existing| existing.turn_id == trace.turn_id)
                {
                    *existing = trace;
                    return;
                }
                if traces.len() == MAX_DECISION_TURNS {
                    traces.pop_front();
                    self.inner.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                }
                traces.push_back(trace);
            }
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                self.inner
                    .dropped_contention
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> MemoryTraceSnapshot {
        let traces = self
            .inner
            .traces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        MemoryTraceSnapshot {
            traces,
            dropped_oldest: self.inner.dropped_oldest.load(Ordering::Relaxed),
            dropped_contention: self.inner.dropped_contention.load(Ordering::Relaxed),
            dropped_unmatched: self.inner.dropped_unmatched.load(Ordering::Relaxed),
        }
    }
}

impl MemoryObserver for MemoryTraceStore {
    fn observe(&self, turn_id: TurnId, observation: MemoryObservation) {
        let Ok(mut traces) = self.inner.traces.try_lock() else {
            self.inner
                .dropped_contention
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(trace) = traces
            .iter_mut()
            .rev()
            .find(|trace| trace.turn_id == turn_id)
        else {
            self.inner.dropped_unmatched.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match observation {
            MemoryObservation::Store(evidence) => trace.record_store(evidence),
            MemoryObservation::Candidate(evidence) => trace.record_candidate(evidence),
            MemoryObservation::Budget(evidence) => trace.budget = evidence,
            MemoryObservation::Selection(evidence) => trace.record_selection(evidence),
            MemoryObservation::Injection(evidence) => trace.injection = Some(evidence),
            MemoryObservation::Visibility(evidence) => trace.record_visibility(evidence),
            MemoryObservation::Contamination(evidence) => trace.contamination = Some(evidence),
            MemoryObservation::Attribution(evidence) => trace.attribution.push(evidence),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenizerIdentity;

    #[test]
    fn context_store_replaces_same_turn_and_bounds_history() {
        let store = ContextLedgerStore::default();
        for turn in 0..=MAX_DECISION_TURNS {
            store.publish(ContextLedger::new(
                TurnId(u32::try_from(turn).unwrap()),
                TokenizerIdentity {
                    catalog_id: "heuristic".into(),
                    version: 1,
                    exact: false,
                },
            ));
        }
        let snapshot = store.snapshot();
        assert_eq!(snapshot.ledgers.len(), MAX_DECISION_TURNS);
        assert_eq!(snapshot.dropped_oldest, 1);
    }
}

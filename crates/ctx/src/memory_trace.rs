//! Content-free evidence for memory retrieval, admission, mutation and same-session visibility.

use iteron_protocol::{Trust, TurnId};
use serde::{Deserialize, Serialize};

pub const MAX_MEMORY_TRACE_STORES: usize = 16;
pub const MAX_MEMORY_TRACE_CANDIDATES: usize = 512;
pub const MAX_MEMORY_TRACE_SELECTIONS: usize = 128;
pub const MAX_MEMORY_TRACE_VISIBILITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryQueryId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryFactId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTierClass {
    User,
    Project,
    Local,
    Dependency,
    Session,
    BenchmarkAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryQueryEvidence {
    pub query_id: MemoryQueryId,
    pub query_digest_sha256: [u8; 32],
    pub bytes: u64,
    pub estimated_tokens: u64,
    pub rewrite_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScopeClass {
    User,
    Workspace,
    Session,
    BenchmarkAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryScopeEvidence {
    pub class: MemoryScopeClass,
    pub scope_digest_sha256: [u8; 32],
    pub isolation_enabled: bool,
    pub parent_access_rejections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStoreEvidence {
    pub store_id: u16,
    pub tier: MemoryTierClass,
    pub store_digest_sha256: [u8; 32],
    pub opened: bool,
    pub scanned_items: u32,
    pub elapsed_us: u64,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCandidateDecision {
    Selected,
    BelowThreshold,
    BudgetDenied,
    Duplicate,
    Contradiction,
    Superseded,
    Expired,
    ScopeDenied,
    TrustDenied,
}

/// Scores are signed parts-per-million integers. Floating point would make replay comparisons and
/// stable serialization needlessly platform-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidateEvidence {
    pub fact_id: MemoryFactId,
    pub fact_digest_sha256: [u8; 32],
    pub store_id: u16,
    pub tier: MemoryTierClass,
    pub trust: Trust,
    pub bm25_term_ppm: i64,
    pub bm25_length_ppm: i64,
    pub semantic_ppm: Option<i64>,
    pub recency_ppm: i64,
    pub confidence_ppm: i64,
    pub combined_ppm: i64,
    pub threshold_ppm: i64,
    pub rank: u32,
    pub requested_bytes: u64,
    pub requested_tokens: u64,
    pub decision: MemoryCandidateDecision,
    pub related_fact_id: Option<MemoryFactId>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBudgetEvidence {
    pub requested_bytes: u64,
    pub granted_bytes: u64,
    pub requested_tokens: u64,
    pub granted_tokens: u64,
    pub candidate_limit: u32,
    pub selected_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySelectionEvidence {
    pub fact_id: MemoryFactId,
    pub ordinal: u32,
    pub granted_bytes: u64,
    pub granted_tokens: u64,
    pub segment_id: Option<crate::context_ledger::ContextSegmentId>,
    pub token_range: Option<crate::context_ledger::TokenRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInjectionEvidence {
    pub segment_digest_sha256: [u8; 32],
    pub fact_count: u32,
    pub bytes: u64,
    pub estimated_tokens: u64,
    pub actual_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVisibilityState {
    Scheduled,
    Activated,
    Used,
    Unused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryVisibilityEvidence {
    pub fact_id: MemoryFactId,
    pub fact_digest_sha256: [u8; 32],
    pub source_turn: TurnId,
    pub destination_turn: TurnId,
    pub state: MemoryVisibilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContaminationEvidence {
    pub scope_digest_sha256: [u8; 32],
    pub checked_candidates: u32,
    pub rejected_candidates: u32,
    pub canary_matches: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAttributionEvidence {
    pub fact_id: MemoryFactId,
    pub cited: bool,
    pub used_by_tool: bool,
    pub later_turns_visible: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDecisionTrace {
    pub turn_id: TurnId,
    pub query: MemoryQueryEvidence,
    pub scope: MemoryScopeEvidence,
    pub stores: Vec<MemoryStoreEvidence>,
    pub candidates: Vec<MemoryCandidateEvidence>,
    pub budget: MemoryBudgetEvidence,
    pub selected: Vec<MemorySelectionEvidence>,
    pub injection: Option<MemoryInjectionEvidence>,
    pub visibility: Vec<MemoryVisibilityEvidence>,
    pub contamination: Option<ContaminationEvidence>,
    pub attribution: Vec<MemoryAttributionEvidence>,
    pub dropped_stores: u32,
    pub dropped_candidates: u32,
    pub dropped_selections: u32,
    pub dropped_visibility: u32,
}

impl MemoryDecisionTrace {
    pub fn new(turn_id: TurnId, query: MemoryQueryEvidence, scope: MemoryScopeEvidence) -> Self {
        Self {
            turn_id,
            query,
            scope,
            stores: Vec::new(),
            candidates: Vec::new(),
            budget: MemoryBudgetEvidence::default(),
            selected: Vec::new(),
            injection: None,
            visibility: Vec::new(),
            contamination: None,
            attribution: Vec::new(),
            dropped_stores: 0,
            dropped_candidates: 0,
            dropped_selections: 0,
            dropped_visibility: 0,
        }
    }

    pub fn record_store(&mut self, evidence: MemoryStoreEvidence) {
        push_bounded(
            &mut self.stores,
            evidence,
            iteron_tunables::param_integer(
                "ctx.memory_trace.max_memory_trace_stores",
                MAX_MEMORY_TRACE_STORES,
            ),
            &mut self.dropped_stores,
        );
    }

    pub fn record_candidate(&mut self, evidence: MemoryCandidateEvidence) {
        push_bounded(
            &mut self.candidates,
            evidence,
            iteron_tunables::param_integer(
                "ctx.memory_trace.max_memory_trace_candidates",
                MAX_MEMORY_TRACE_CANDIDATES,
            ),
            &mut self.dropped_candidates,
        );
    }

    pub fn record_selection(&mut self, evidence: MemorySelectionEvidence) {
        push_bounded(
            &mut self.selected,
            evidence,
            iteron_tunables::param_integer(
                "ctx.memory_trace.max_memory_trace_selections",
                MAX_MEMORY_TRACE_SELECTIONS,
            ),
            &mut self.dropped_selections,
        );
    }

    pub fn record_visibility(&mut self, evidence: MemoryVisibilityEvidence) {
        push_bounded(
            &mut self.visibility,
            evidence,
            iteron_tunables::param_integer(
                "ctx.memory_trace.max_memory_trace_visibility",
                MAX_MEMORY_TRACE_VISIBILITY,
            ),
            &mut self.dropped_visibility,
        );
    }
}

fn push_bounded<T>(values: &mut Vec<T>, value: T, limit: usize, dropped: &mut u32) {
    if values.len() == limit {
        *dropped = dropped.saturating_add(1);
    } else {
        values.push(value);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryObservation {
    Store(MemoryStoreEvidence),
    Candidate(MemoryCandidateEvidence),
    Budget(MemoryBudgetEvidence),
    Selection(MemorySelectionEvidence),
    Injection(MemoryInjectionEvidence),
    Visibility(MemoryVisibilityEvidence),
    Contamination(ContaminationEvidence),
    Attribution(MemoryAttributionEvidence),
}

pub trait MemoryObserver: Send + Sync {
    fn observe(&self, turn_id: TurnId, observation: MemoryObservation);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NullMemoryObserver;

impl MemoryObserver for NullMemoryObserver {
    fn observe(&self, _turn_id: TurnId, _observation: MemoryObservation) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_overflow_is_explicit() {
        let mut trace = MemoryDecisionTrace::new(
            TurnId(1),
            MemoryQueryEvidence {
                query_id: MemoryQueryId(1),
                query_digest_sha256: [0; 32],
                bytes: 1,
                estimated_tokens: 1,
                rewrite_count: 0,
            },
            MemoryScopeEvidence {
                class: MemoryScopeClass::Workspace,
                scope_digest_sha256: [0; 32],
                isolation_enabled: false,
                parent_access_rejections: 0,
            },
        );
        let candidate = MemoryCandidateEvidence {
            fact_id: MemoryFactId(1),
            fact_digest_sha256: [0; 32],
            store_id: 0,
            tier: MemoryTierClass::Project,
            trust: Trust::Workspace,
            bm25_term_ppm: 0,
            bm25_length_ppm: 0,
            semantic_ppm: None,
            recency_ppm: 0,
            confidence_ppm: 0,
            combined_ppm: 0,
            threshold_ppm: 0,
            rank: 0,
            requested_bytes: 0,
            requested_tokens: 0,
            decision: MemoryCandidateDecision::Selected,
            related_fact_id: None,
        };
        for _ in 0..=MAX_MEMORY_TRACE_CANDIDATES {
            trace.record_candidate(candidate.clone());
        }
        assert_eq!(trace.candidates.len(), MAX_MEMORY_TRACE_CANDIDATES);
        assert_eq!(trace.dropped_candidates, 1);
    }
}

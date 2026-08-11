//! iteron-ctx — context assembly and management.
//!
//! Two jobs, both from the recon:
//!   1. **Localization ladder** (Agentless): repo tree -> skeleton (declaration headers only)
//!      -> bodies -> lines, never widening. The skeleton beats whole-file by +5.3pp AND is
//!      7.5x cheaper (`docs/intake/agentless-counter-thesis.md`). This is late materialization
//!      (ADR-003): carry positions, materialize bytes only at the point of action.
//!   2. **Compaction** at the window boundary (ADR-002): when the transcript approaches the
//!      budget, summarize old turns so long tasks don't overflow — a lossy codec fighting the
//!      append-only cache constraint. Compaction is a cache bomb by construction; we do it only
//!      at the boundary and keep the task + recent turns verbatim.
//!
//! This crate holds the *policy* (token estimate, when to compact, what to keep, the summary
//! prompt, how to build the outline). The LLM summarization call is the kernel's to make,
//! because ctx must not depend on a provider (keeps the layering clean and this crate testable).

pub mod compact;
mod compact_obligations;
mod compaction_runtime;
mod context_assembly;
pub mod context_ledger;
mod context_materialization;
mod context_port;
mod context_strategy;
pub mod decision_store;
pub mod instructions;
pub mod memory;
mod memory_runtime;
pub mod memory_trace;
pub mod outline;
mod runtime_policy;
pub mod skills;
pub mod source;
mod token_estimator;

pub use compact::{
    CompactionPlan, CompactionPolicy, ContextEstimate, RequestEstimator, TokenEstimateProvenance,
    compaction_seed, compaction_summary_message, compaction_summary_range,
    estimate_request_context, replay_compaction,
};
pub use compaction_runtime::{CompactionHysteresis, SummaryProfile, SummaryTopology};
pub use context_assembly::{assemble_recorded_context, assemble_system_prompt};
pub use context_ledger::{
    CacheClass, CacheEvidence, CompactionEvidence, ContextDecision, ContextDecisionReason,
    ContextLedger, ContextObservation, ContextObserver, ContextSegmentEvidence, ContextSegmentId,
    ContextSourceClass, ContextTotals, ContextTransformEvidence, ContextTransformKind,
    NullContextObserver, TokenRange, TokenizerIdentity,
};
pub use context_materialization::ContextMaterializationAudit;
pub use context_port::{
    ContextPort, ContextPortError, ContextPortInput, ContextValue, DefaultContextPort, PortStub,
};
pub use context_strategy::{
    CONTEXT_SLOT_VERSION, ContextPlan, ContextSlotDecision, ContextSlotObservation,
    ContextStrategy, MAX_CONTEXT_OUTLINE_DEPTH,
};
pub use decision_store::{
    ContextLedgerSnapshot, ContextLedgerStore, MemoryTraceSnapshot, MemoryTraceStore,
};
pub use instructions::{
    InstructionBundle, InstructionDiscoveryPolicy, InstructionRejection, InstructionSource,
    Instructions, MAX_INSTRUCTION_CONTENT_BYTES, MAX_MERGED_INSTRUCTION_BYTES, discover,
    discover_hierarchy, discover_hierarchy_with_policy, framed,
};
pub use memory::{
    Fact, FactRef, FileMemory, Framed, MAX_MEMORY_CANDIDATE_TEXT_BYTES, MAX_MEMORY_CANDIDATES,
    MAX_MEMORY_SLUG_BYTES, MAX_MEMORY_TASK_BYTES, MEMORY_SLOT_VERSION, MemBudget, MemError,
    MemIndex, MemStore, MemTier, MemoryCandidate, MemoryRecallAudit, MemoryRecallDisposition,
    MemoryRecallExclusion, MemoryRecallExclusionKind, MemoryRecallPlan, MemoryRecallProposal,
    MemoryRecallStrategy, MemorySegment, MemorySlotDecision, MemorySlotError,
    MemorySlotObservation, MemoryStore, MemoryStrategy, MemoryWriteProposal, StoredFact,
    merged_index,
};
pub use memory_runtime::{MemoryRetrievalPolicy, SCORE_SCALE};
pub use memory_trace::{
    ContaminationEvidence, MAX_MEMORY_TRACE_VISIBILITY, MemoryAttributionEvidence,
    MemoryBudgetEvidence, MemoryCandidateDecision, MemoryCandidateEvidence, MemoryDecisionTrace,
    MemoryFactId, MemoryInjectionEvidence, MemoryObservation, MemoryObserver, MemoryQueryEvidence,
    MemoryQueryId, MemoryScopeClass, MemoryScopeEvidence, MemorySelectionEvidence,
    MemoryStoreEvidence, MemoryTierClass, MemoryVisibilityEvidence, MemoryVisibilityState,
    NullMemoryObserver,
};
pub use outline::{repo_outline, repo_outline_for_task, repo_outline_for_task_with_limits};
pub use runtime_policy::{
    ContextBudgetClass, ContextBudgetPolicy, ContextBudgetViolation, ContextComponentUsage,
    ContextMaterializationPolicy,
};
pub use token_estimator::{
    ROUTE_AWARE_ESTIMATOR_POLICY_ID, TokenEstimatorPolicy, TokenEstimatorProfile,
};

/// A fast, provider-agnostic token upper bound. Real tokenization is the provider's; until a route
/// is known this deliberately charges one token per UTF-8 byte and is labelled as an inexact,
/// conservative fallback.
pub fn estimate_tokens(text: &str) -> usize {
    TokenEstimatorProfile::GenericBytesPerToken35.estimate(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_estimate_biases_high() {
        // The unidentified-route fallback is an explicit byte-level upper bound.
        let n = estimate_tokens(&"x".repeat(3500));
        assert_eq!(n, 3500);
        assert_eq!(estimate_tokens("上下文"), "上下文".len());
    }
}

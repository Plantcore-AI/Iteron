//! core-ctx — context assembly and management.
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
mod context_assembly;
mod context_port;
mod context_strategy;
pub mod instructions;
pub mod memory;
pub mod outline;
pub mod skills;
pub mod source;

pub use compact::{
    CompactionPlan, CompactionPolicy, ContextEstimate, TokenEstimateProvenance, compaction_seed,
    compaction_summary_message, compaction_summary_range, estimate_request_context,
    replay_compaction,
};
pub use context_assembly::{assemble_recorded_context, assemble_system_prompt};
pub use context_port::{
    ContextPort, ContextPortError, ContextPortInput, ContextValue, DefaultContextPort, PortStub,
};
pub use context_strategy::{
    CONTEXT_SLOT_VERSION, ContextPlan, ContextSlotDecision, ContextSlotObservation,
    ContextStrategy, MAX_CONTEXT_OUTLINE_DEPTH,
};
pub use instructions::{
    InstructionBundle, InstructionRejection, InstructionSource, Instructions,
    MAX_INSTRUCTION_CONTENT_BYTES, MAX_MERGED_INSTRUCTION_BYTES, discover, discover_hierarchy,
    framed,
};
pub use memory::{
    Fact, FactRef, FileMemory, Framed, MemBudget, MemError, MemIndex, MemStore, MemTier,
    MemorySegment, MemoryStore, MemoryStrategy, StoredFact, merged_index,
};
pub use outline::{repo_outline, repo_outline_for_task};

/// A fast, provider-agnostic token estimate. Real tokenization is the provider's; for policy
/// decisions this byte heuristic is deterministic and deliberately biased high for ASCII/code.
/// It is not guaranteed conservative for every language/tokenizer and must be labelled estimated.
pub fn estimate_tokens(text: &str) -> usize {
    // ~4 chars/token for English+code is the well-known rule of thumb; we use 3.5 to bias high.
    ((text.len() as f64) / 3.5).ceil() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_estimate_biases_high() {
        // 3.5 chars/token over-estimates vs the ~4 reality, so we never compact too late.
        let n = estimate_tokens(&"x".repeat(3500));
        assert!(n >= 1000, "estimate should be conservative (>= chars/3.5)");
    }
}

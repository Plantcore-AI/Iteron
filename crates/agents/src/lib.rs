//! core-agents — provider-free policy + data for the ultracode orchestration engine.
//!
//! This crate owns the *what* of ultracode orchestration — the agent catalog, the stage
//! vocabulary, the task-class router, and the deterministic `reduce()` — as **pure data and pure
//! functions**. It holds no provider, no kernel, no tokio (see `Cargo.toml`), so the plan and the
//! reduction are unit-testable without a network — the reproducibility invariant (Principal §可复现:
//! "a run can be replayed from its record and produce the same decisions"). The executor that
//! spawns real subagents lives in `kernel::orchestrator`; the split mirrors the existing
//! `ctx`/`kernel` seam (ctx holds compaction *policy*; the kernel makes the LLM call).
//!
//! # Scope (re-scoped by the R5 design review, `docs/reviews/R5-design-review.md`)
//!
//! The R5 design (`docs/design/r5-design-effort-orchestration.md`) proposed a six-variant Stage DAG.
//! The review is the gate and it **cut the engine to `Fan` + `Reduce` only**. `Pipe`, `Judge`,
//! `LoopUntilDry`, and `AdversarialVerify` are **deferred, not built**: `Pipe` is the existing
//! single-agent loop, `Judge`/sample-N need the not-yet-built disposable-workspace substrate, and
//! `LoopUntilDry`/`AdversarialVerify` have no proven consumer. Only `Fan → declaration-order Reduce
//! → single writer` is justified and buildable today (it is `spawn_subagent` + `Governor` +
//! index-ordered collect, all already present in the kernel). This crate therefore ships exactly
//! those two variants.
//!
//! # The honest benefit (do not overstate)
//!
//! The review corrected the R5 draft's rationale: ultracode fans out **only read-only
//! investigation** and forbids parallel edit/verify (ADR-001, the single-writer invariant). The
//! current kernel executes those workers sequentially, so this release makes no wall-clock speedup
//! claim. The honest, defensible benefit is
//! **context-window management and investigation breadth**: N read-only workers each explore an
//! isolated slice in their own context window and return ~1–2k tokens, so the single writer sees a
//! wide, bounded synthesis instead of drowning in raw file contents. No "2.9× speedup" claim
//! appears anywhere in this crate, by design.
//!
//! # What makes it worth building in-house
//!
//! `reduce()` reads worker results in **declaration (index) order, never completion order** — the
//! exact discipline the kernel already proves at the tool layer, lifted to the subagent layer. An
//! imported orchestrator (LangGraph/CrewAI) branches on the first finisher, which is
//! non-deterministic and breaks replay. Determinism is the whole reason for the hand-built engine,
//! and it is unit-tested here (`reduce::tests`).

#![allow(dead_code)]

mod catalog;
mod decompose;
mod def;
mod reduce;
mod stage;

pub use catalog::{AgentCatalog, LoadError};
pub use decompose::{
    Decomposer, FAN_CAP, LEAF_MAX_CHARS, NormalizedLeaves, RepoSignals, TaskClass,
};
pub use def::{AgentDef, READ_ONLY_TOOLS, ToolFilter};
pub use reduce::{OrderedBundle, Summary, SummaryOutcome, reduce};
pub use stage::{AgentTask, INVESTIGATOR_DELIVERABLE, INVESTIGATOR_SCOPE, Stage, WorkflowPlan};

/// Scan for control / bidi / zero-width characters that make rendered text differ from bytes.
///
/// A local, zero-dependency reimplementation of `ctx::instructions::suspicious_unicode`
/// (`crates/ctx/src/instructions.rs:27`) — this crate must not depend on `ctx`. The concern is
/// identical: a tree-discovered agent definition (especially from a cloned dependency) is a
/// prompt-injection vector, and the classic trick is invisible / bidirectional Unicode that renders
/// differently than it parses (ADR-007). Returns the first offending code point, or `None`.
pub(crate) fn suspicious_unicode(s: &str) -> Option<u32> {
    s.chars().map(|c| c as u32).find(
        |&c| matches!(c, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x00AD | 0xFEFF),
    )
}

/// A coarse token estimate (≈4 chars/token, ceiling), matching `ctx::estimate_tokens` closely
/// enough for a *bounding* budget. Reimplemented locally to keep the zero-dependency-on-ctx rule.
pub(crate) fn estimate_tokens(s: &str) -> usize {
    s.chars().count().div_ceil(4)
}

/// Collapse a description to a single bounded line for the compact catalog listing.
pub(crate) fn one_line(s: &str, max_chars: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars {
        return flat;
    }
    let mut out: String = flat.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod util_tests {
    use super::*;

    #[test]
    fn suspicious_unicode_catches_bidi() {
        assert!(suspicious_unicode("normal text").is_none());
        assert_eq!(suspicious_unicode("a\u{202E}b"), Some(0x202E));
        assert_eq!(suspicious_unicode("zero\u{200B}width"), Some(0x200B));
    }

    #[test]
    fn one_line_bounds_and_flattens() {
        assert_eq!(one_line("a  b\nc", 10), "a b c");
        let long = one_line(&"x".repeat(50), 8);
        assert_eq!(long.chars().count(), 8);
        assert!(long.ends_with('…'));
    }
}

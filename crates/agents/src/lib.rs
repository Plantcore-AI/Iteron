//! iteron-agents — provider-free agent definitions and bounded orchestration policy utilities.
//!
//! This crate owns the agent catalog plus optional typed decomposition, planning, stage, and
//! reduction strategies as pure data and pure functions. It holds no provider, kernel, or Tokio
//! dependency (see `Cargo.toml`), so policy decisions remain unit-testable without a network and
//! reproducible from their recorded inputs. The workflow topology itself belongs to model-authored
//! scripts executed by `crates/workflow`; the CLI's `KernelSpawner` supplies bounded, governed
//! children without imposing a fixed plan.
//!
//! The helpers retain the runtime's safety properties when a script chooses to use them. Fan tasks
//! are read-only, concurrency is governed, writer authority is isolated and serialized, and
//! `reduce()` consumes worker results in declaration order rather than completion order. Scripts
//! may compose these utilities or use the generic bounded workflow engine directly.

mod catalog;
mod decompose;
mod def;
mod planner;
mod policy;
mod reduce;
mod snapshot;
mod stage;

pub use catalog::{AgentCatalog, AgentCatalogRuntimeIdentity, LoadError};
pub use decompose::{
    Decomposer, FAN_CAP, LEAF_MAX_CHARS, MAX_ROUTER_TASK_BYTES, NormalizedLeaves,
    ROUTER_SLOT_VERSION, RepoSignals, RouterProposal, RouterRoute, RouterSlotDecision,
    RouterSlotError, RouterSlotObservation, RouterStrategy, TaskClass, router_slot,
};
pub use def::{
    AgentDef, DecompositionProfile, ISOLATED_WRITER_NAME, ISOLATED_WRITER_TOOLS,
    MIN_SUBAGENT_TURNS, READ_ONLY_TOOLS, ToolFilter, subagent_budget, subagent_budget_ceiling,
};
pub use planner::{
    PLANNER_SLOT_VERSION, PlannerDecision, PlannerError, PlannerObservation, PlannerPlan,
    PlannerProposal, PlannerStrategy,
};
pub use policy::{BootBundle, ToolPreference, narrow_under, tool_policy_slot};
pub use reduce::{
    CoverageError, CoverageExpectation, JoinMode, JoinReducePolicy, OrderedBundle, ReduceOrder,
    Summary, SummaryOutcome, join_reduce_policy, reduce, reduce_checked,
    reduce_checked_with_profile, reduce_with_profile,
};
pub use snapshot::AgentCatalogSnapshot;
pub use stage::{
    AgentTask, BudgetedWorkflowPlan, INVESTIGATOR_DELIVERABLE, INVESTIGATOR_SCOPE, Stage,
    WorkflowPlan,
};

/// Scan for control / bidi / zero-width characters that make rendered text differ from bytes.
///
/// A local, zero-dependency reimplementation of `ctx::instructions::suspicious_unicode`
/// (`crates/ctx/src/instructions.rs:27`) — this crate must not depend on `ctx`. The concern is
/// identical: a tree-discovered agent definition (especially from a cloned dependency) is a
/// prompt-injection vector, and the classic trick is invisible / bidirectional Unicode that renders
/// differently than it parses (ADR-007). Returns the first offending code point, or `None`.
pub(crate) fn suspicious_unicode(s: &str) -> Option<u32> {
    s.chars().find_map(|character| {
        let codepoint = character as u32;
        (matches!(codepoint, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x00AD | 0xFEFF)
            || (character.is_control() && !matches!(character, '\n' | '\r' | '\t')))
        .then_some(codepoint)
    })
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
        assert_eq!(suspicious_unicode("terminal\u{1b}[31m"), Some(0x1B));
        assert_eq!(suspicious_unicode("nul\0byte"), Some(0));
        assert!(suspicious_unicode("multiline\nbody\tindent").is_none());
    }

    #[test]
    fn one_line_bounds_and_flattens() {
        assert_eq!(one_line("a  b\nc", 10), "a b c");
        let long = one_line(&"x".repeat(50), 8);
        assert_eq!(long.chars().count(), 8);
        assert!(long.ends_with('…'));
    }
}

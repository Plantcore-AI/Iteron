//! The tool ABI. Purity and capability are *types* (ADR-004 R4, ADR-007 R12/R16), because
//! purity licenses early dispatch / memoization / speculation, and a mislabel is a security
//! bug, not a style issue.

use crate::trust::Trust;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Whether a tool has observable side effects. Purity licenses the flagship overlap: a
/// `Pure` tool may be dispatched at `content_block_stop`, before the turn ends (ADR-004).
///
/// ADR-007 §5 makes this true *by construction*, not by honor: a `Pure` tool runs in a
/// no-egress read-only cell, so a mislabel fails closed (it errors, it does not leak).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purity {
    /// No observable effect. Safe to dispatch early, memoize, hedge, speculate.
    /// e.g. read_file, grep, ls, git log, LSP query.
    Pure,
    /// Has effects. Gated at message_stop + policy (never dispatched early). e.g. edit, bash.
    Effecting,
}

/// The capability class that sets the risk tier (ADR-007 R12). Tier by what the tool *can
/// do*, not by whether a human could undo it — that was the wrong axis R2 caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reads only. Never prompts.
    ReadOnly,
    /// Edits tracked source under the workspace, behind a checkpoint. Post-hoc audit.
    ReversibleLocal,
    /// Runs repo-controlled code (bash, build, test, install). Isolated no-egress cell.
    CodeExecuting,
    /// Writes under .git/, git-config, CI config, instruction files. Pre-hoc approval, always.
    TrustMutating,
    /// push / publish / send / any egress-effecting action. Approval + Trusted context.
    IrreversibleExternal,
}

impl Capability {
    /// May this run without a per-call human prompt? Only reads and reversible-local edits.
    /// (The fatigue argument holds — Bainbridge, METR — but the majority is defined by
    /// capability, and the code-executing case is no longer in it.)
    pub fn runs_unattended(self) -> bool {
        matches!(self, Capability::ReadOnly | Capability::ReversibleLocal)
    }
    /// Does this class egress? Egress is gated on Trusted context (ADR-007 §1).
    pub fn is_egress(self) -> bool {
        matches!(self, Capability::IrreversibleExternal)
    }
}

/// A tool's declared contract. The purity/capability coupling is checked at registration:
/// `Pure` coupled with an egress capability is a build/registration error (tools crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the input (grammar-constrained at the provider where supported).
    pub input_schema: Value,
    pub purity: Purity,
    pub capability: Capability,
}

/// A tool invocation emitted by the model (one `tool_use` block).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// The result of running a tool. Carries the trust tier of its output (ADR-007): a
/// read of repo content yields `Workspace`; a web fetch yields `Untrusted`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
    pub trust: Trust,
    /// Wall-clock the tool took, for `obs` (tau_wall) — measured, never estimated.
    pub latency_ms: u64,
}

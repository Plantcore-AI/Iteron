//! Permission modes and the capability-lattice gate (ADR-007 §3, R5 design
//! `docs/design/r5-design-tui-commands.md` §4). The four modes are one policy *table* over the
//! existing `Capability` lattice — not four tool registries — so switching mode never rewrites
//! `TurnRequest.tools` and never busts the prompt cache (ADR-002; the "plan mode is a tool, not a
//! mode-swap" insight, `claude-code-public.md:238`).
//!
//! The load-bearing property: `gate` is a **pure function of `(mode, rules, capability)`** — the
//! model never influences its own gate ("a constraint the model enforces on itself is not a
//! constraint", Plan.md). Deny-by-default is a lattice property, not a dismissible dialog: even
//! `Yolo` cannot auto-approve a `TrustMutating` (`.git/hooks`, CI config) or `IrreversibleExternal`
//! (push/publish) call. There is no unbounded bypass — core states its carve-outs as capability
//! *classes*, which is stronger than pattern-matching command text (the leading agent's approach).
//!
//! HONEST LIMIT (stated, per the truth gate). The carve-out protects declared trust-mutating TOOL
//! operations: the kernel elevates a WRITE whose target path is `.git`/CI/instruction/`.core`
//! (any case) to `TrustMutating` before gating (`kernel::effective_capability`). It does NOT parse
//! arbitrary code: under `Yolo`, `bash` (CodeExecuting) auto-runs, and code can write anywhere the
//! egress-off sandbox permits — including `.git/` inside the workspace. That is the deliberate Yolo
//! tradeoff (auto-run code), not a gate hole: `bash` still asks under Default/AcceptEdits, and Yolo
//! on an untrusted repo is the operator's explicit choice. Reliably detecting a trust-mutating write
//! *inside* a shell command is undecidable, so we do not claim it; the declared-operation carve-out
//! is what the gate guarantees.

use crate::tool::Capability;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The operator's permission posture. Cycled by Shift+Tab, set by `/mode`, or by a CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    /// Reads auto; every write/exec asks. The safe default.
    #[default]
    Default,
    /// Reversible-local edits auto (behind a checkpoint); code/exec still ask.
    AcceptEdits,
    /// Read-only overlay: everything above `ReadOnly` is denied. The model explores and writes a
    /// plan as text; the operator flips out of Plan to execute it.
    Plan,
    /// Auto-run reads, edits, and code (code still in the egress-off cell) — but `TrustMutating`
    /// and `IrreversibleExternal` STILL ask. "yolo" is bounded; it is not `bypassPermissions`.
    Yolo,
}

impl PermissionMode {
    /// Parse from a CLI/command string (accepts a few common spellings).
    pub fn parse(s: &str) -> Option<PermissionMode> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "default" | "normal" | "ask" => Some(PermissionMode::Default),
            "acceptedits" | "accept" | "edits" => Some(PermissionMode::AcceptEdits),
            "plan" => Some(PermissionMode::Plan),
            "yolo" | "auto" => Some(PermissionMode::Yolo),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            PermissionMode::Default => "default",
            PermissionMode::AcceptEdits => "acceptEdits",
            PermissionMode::Plan => "plan",
            PermissionMode::Yolo => "yolo",
        }
    }
    /// The Shift+Tab cycle: default -> acceptEdits -> plan -> yolo -> default (the leading agent's
    /// order, `claude-code-public.md:236`).
    pub fn next(self) -> PermissionMode {
        match self {
            PermissionMode::Default => PermissionMode::AcceptEdits,
            PermissionMode::AcceptEdits => PermissionMode::Plan,
            PermissionMode::Plan => PermissionMode::Yolo,
            PermissionMode::Yolo => PermissionMode::Default,
        }
    }
}

/// The gate verdict for one (mode, capability) decision. `Ask` means a human must answer before
/// the tool runs; with no interactive channel present it fails **closed** (deny) — never open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Auto,
    Ask,
    Deny,
}

/// Session-scoped allow/ask/deny overrides — the `/permissions` surface and the memory behind an
/// operator's "always allow (this capability)" answer. A rule on an exact tool name wins over a
/// rule on its capability class; both win over the mode default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRules {
    by_tool: BTreeMap<String, Verdict>,
    by_cap: BTreeMap<Capability, Verdict>,
}

impl PermissionRules {
    pub fn new() -> Self {
        Self::default()
    }
    /// Remember "always allow this capability" for the session (the `a` answer / `/permissions
    /// allow <cap>`). This is how AcceptEdits-style "remember it" and the grant surface unify.
    pub fn allow_cap(&mut self, c: Capability) {
        self.by_cap.insert(c, Verdict::Auto);
    }
    pub fn set_cap(&mut self, c: Capability, v: Verdict) {
        self.by_cap.insert(c, v);
    }
    /// Return the explicit session override for a capability, if one exists. Frontends use this to
    /// mark the current `/permissions` choice without reimplementing the gate or exposing the maps.
    pub fn cap_rule(&self, c: Capability) -> Option<Verdict> {
        self.by_cap.get(&c).copied()
    }
    /// Set an operator-facing capability rule only when it can affect the gate truthfully. Reads
    /// are constitutionally automatic, while the two carve-outs can be tightened to Ask/Deny but
    /// never relaxed to Auto.
    pub fn try_set_cap(&mut self, c: Capability, v: Verdict) -> Result<(), &'static str> {
        if c == Capability::ReadOnly {
            return Err("read-only operations are always allowed and are not configurable");
        }
        if matches!(
            c,
            Capability::TrustMutating | Capability::IrreversibleExternal
        ) && v == Verdict::Auto
        {
            return Err("this capability always requires approval and cannot be auto-allowed");
        }
        self.set_cap(c, v);
        Ok(())
    }
    pub fn set_tool(&mut self, tool: &str, v: Verdict) {
        self.by_tool.insert(tool.to_string(), v);
    }
    pub fn is_empty(&self) -> bool {
        self.by_tool.is_empty() && self.by_cap.is_empty()
    }
    /// Render the active rules for `/permissions` (deterministic order — BTreeMap).
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (cap, v) in &self.by_cap {
            out.push(format!("{} -> {}", capability_name(*cap), verdict_name(*v)));
        }
        for (tool, v) in &self.by_tool {
            out.push(format!("{tool} -> {}", verdict_name(*v)));
        }
        out
    }
}

fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::ReadOnly => "read_only",
        Capability::ReversibleLocal => "reversible_local",
        Capability::CodeExecuting => "code_executing",
        Capability::TrustMutating => "trust_mutating",
        Capability::IrreversibleExternal => "irreversible_external",
    }
}

fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Auto => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
    }
}

/// The gate: a pure function of `(mode, rules, tool, capability)`. Deny-by-default over the
/// ADR-007 lattice. An explicit rule (tool then capability) wins; otherwise the mode×capability
/// table decides.
pub fn gate(mode: PermissionMode, rules: &PermissionRules, tool: &str, cap: Capability) -> Verdict {
    use Capability::*;
    use PermissionMode::*;
    // Reads are always auto — no mode, and no rule, ever prompts for a read.
    if cap == ReadOnly {
        return Verdict::Auto;
    }
    // Plan is a HARD read-only overlay: it denies everything above ReadOnly regardless of any
    // session rule. A deliberate "explore, don't touch" posture must not be punched through by a
    // stale earlier "always allow" — so the Plan check precedes the rule lookup (a stronger,
    // safer reading than the design draft's rules-first order).
    if mode == Plan {
        return Verdict::Deny;
    }
    // The two carve-outs (invariant #5): no MODE and no capability-CLASS rule may auto-approve a
    // TrustMutating (.git/hooks, CI config, instruction-file write) or an IrreversibleExternal
    // (push/publish, external egress) call — a blanket `remember`/`/permissions allow <class>` was
    // an unbounded, unaudited bypass, so a class-wide Auto stays impossible (`try_set_cap` refuses
    // it and `by_cap` Auto is never consulted here). What IS honored is a rule on the EXACT tool
    // name: that is a bounded, audited, per-tool operator/harness decision, so it wins — it may
    // pre-approve (Auto) or tighten (Ask/Deny) one named tool without approving the class. This is
    // how the first-party egress tools (web_fetch/web_search) are auto-approved by default while
    // `git push`, publish, and arbitrary external effects still prompt: the default names only the
    // web tools, never the class.
    if matches!(cap, TrustMutating | IrreversibleExternal) {
        // A capability-CLASS Deny hard-stops the whole class first.
        if rules.by_cap.get(&cap) == Some(&Verdict::Deny) {
            return Verdict::Deny;
        }
        // An exact-tool-name rule (from `/permissions` or the harness default seed) wins.
        if let Some(v) = rules.by_tool.get(tool) {
            return *v;
        }
        return Verdict::Ask;
    }
    // Outside the carve-outs, an explicit rule (exact tool, then capability class) wins over the
    // mode default.
    if let Some(v) = rules.by_tool.get(tool) {
        return *v;
    }
    if let Some(v) = rules.by_cap.get(&cap) {
        return *v;
    }
    match (mode, cap) {
        // ReadOnly + Plan handled above.
        (_, ReadOnly) | (Plan, _) => Verdict::Auto, // unreachable; keeps the match exhaustive
        // Reversible-local edits: ask in Default, auto (behind a checkpoint) in AcceptEdits/Yolo.
        (Default, ReversibleLocal) => Verdict::Ask,
        (AcceptEdits, ReversibleLocal) => Verdict::Auto,
        (Yolo, ReversibleLocal) => Verdict::Auto,
        // Code execution: Yolo auto-runs it (still in the egress-off cell); everyone else asks.
        // NOTE: the Yolo arm MUST precede the general CodeExecuting arm or it is unreachable
        // (the design draft had them reversed).
        (Yolo, CodeExecuting) => Verdict::Auto,
        (_, CodeExecuting) => Verdict::Ask,
        // The two carve-outs with NO auto in ANY mode — this is invariant #5, non-negotiable.
        (_, TrustMutating) => Verdict::Ask,
        (_, IrreversibleExternal) => Verdict::Ask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::Capability::*;

    #[test]
    fn reads_are_always_auto() {
        let r = PermissionRules::new();
        for m in [
            PermissionMode::Default,
            PermissionMode::AcceptEdits,
            PermissionMode::Plan,
            PermissionMode::Yolo,
        ] {
            assert_eq!(gate(m, &r, "read_file", ReadOnly), Verdict::Auto);
        }
    }

    #[test]
    fn plan_denies_everything_above_read() {
        let r = PermissionRules::new();
        for cap in [
            ReversibleLocal,
            CodeExecuting,
            TrustMutating,
            IrreversibleExternal,
        ] {
            assert_eq!(gate(PermissionMode::Plan, &r, "edit", cap), Verdict::Deny);
        }
    }

    #[test]
    fn yolo_auto_runs_code_but_never_the_two_carve_outs() {
        let r = PermissionRules::new();
        assert_eq!(
            gate(PermissionMode::Yolo, &r, "edit", ReversibleLocal),
            Verdict::Auto
        );
        // the reachability fix: Yolo actually auto-runs CodeExecuting (was shadowed in the draft)
        assert_eq!(
            gate(PermissionMode::Yolo, &r, "bash", CodeExecuting),
            Verdict::Auto
        );
        // the load-bearing bound: even yolo asks for these — no unbounded bypass.
        assert_eq!(
            gate(PermissionMode::Yolo, &r, "git_hook_write", TrustMutating),
            Verdict::Ask
        );
        assert_eq!(
            gate(PermissionMode::Yolo, &r, "git_push", IrreversibleExternal),
            Verdict::Ask
        );
    }

    #[test]
    fn default_asks_for_edits_acceptedits_auto() {
        let r = PermissionRules::new();
        assert_eq!(
            gate(PermissionMode::Default, &r, "edit", ReversibleLocal),
            Verdict::Ask
        );
        assert_eq!(
            gate(PermissionMode::AcceptEdits, &r, "edit", ReversibleLocal),
            Verdict::Auto
        );
        assert_eq!(
            gate(PermissionMode::AcceptEdits, &r, "bash", CodeExecuting),
            Verdict::Ask
        );
    }

    #[test]
    fn explicit_rules_win_tool_over_cap_over_mode() {
        let mut r = PermissionRules::new();
        // a capability rule overrides the mode default (an "always allow" answer)
        r.allow_cap(CodeExecuting);
        assert_eq!(
            gate(PermissionMode::Default, &r, "bash", CodeExecuting),
            Verdict::Auto
        );
        // a tool rule wins over the capability rule
        r.set_tool("bash", Verdict::Deny);
        assert_eq!(
            gate(PermissionMode::Default, &r, "bash", CodeExecuting),
            Verdict::Deny
        );
        // a different code tool still follows the capability rule
        assert_eq!(
            gate(PermissionMode::Default, &r, "make", CodeExecuting),
            Verdict::Auto
        );
    }

    #[test]
    fn class_wide_allow_never_loosens_carve_outs_but_deny_tightens() {
        // A session "always allow" on the whole CAPABILITY CLASS must NOT loosen the two carve-outs
        // to Auto (invariant #5) — only an exact-tool rule can pre-approve a single named tool.
        let mut r = PermissionRules::new();
        r.allow_cap(TrustMutating);
        r.allow_cap(IrreversibleExternal);
        for m in [
            PermissionMode::Default,
            PermissionMode::AcceptEdits,
            PermissionMode::Yolo,
        ] {
            assert_eq!(
                gate(m, &r, "hook_write", TrustMutating),
                Verdict::Ask,
                "a class-wide allow must NOT auto-approve TrustMutating"
            );
            assert_eq!(
                gate(m, &r, "git_push", IrreversibleExternal),
                Verdict::Ask,
                "a class-wide allow must NOT auto-approve IrreversibleExternal"
            );
        }
        // but a DENY rule may still tighten a carve-out to Deny.
        let mut d = PermissionRules::new();
        d.set_cap(IrreversibleExternal, Verdict::Deny);
        assert_eq!(
            gate(PermissionMode::Yolo, &d, "git_push", IrreversibleExternal),
            Verdict::Deny
        );
    }

    #[test]
    fn named_tool_rule_wins_inside_a_carve_out() {
        // A rule on the EXACT tool name is a bounded, audited per-tool decision and is honored even
        // inside a carve-out — this is how web_fetch/web_search auto-approve by default while the
        // rest of the IrreversibleExternal class keeps prompting.
        let mut r = PermissionRules::new();
        r.set_tool("web_fetch", Verdict::Auto);
        r.set_tool("web_search", Verdict::Auto);
        for m in [
            PermissionMode::Default,
            PermissionMode::AcceptEdits,
            PermissionMode::Yolo,
        ] {
            assert_eq!(
                gate(m, &r, "web_fetch", IrreversibleExternal),
                Verdict::Auto,
                "a named-tool Auto pre-approves that one egress tool"
            );
            // an unnamed sibling in the same class still prompts (the class default is unchanged)
            assert_eq!(
                gate(m, &r, "git_push", IrreversibleExternal),
                Verdict::Ask,
                "the class default is unchanged for tools without a rule"
            );
        }
        // Plan still hard-denies even a pre-approved egress tool (read-only-explore overlay wins).
        assert_eq!(
            gate(PermissionMode::Plan, &r, "web_fetch", IrreversibleExternal),
            Verdict::Deny
        );
        // A per-tool Deny still tightens a carve-out tool to Deny.
        let mut d = PermissionRules::new();
        d.set_tool("web_fetch", Verdict::Deny);
        assert_eq!(
            gate(PermissionMode::Yolo, &d, "web_fetch", IrreversibleExternal),
            Verdict::Deny
        );
    }

    #[test]
    fn plan_overlay_is_not_punched_through_by_a_stale_allow_rule() {
        let mut r = PermissionRules::new();
        r.allow_cap(CodeExecuting); // a leftover "always allow" from before entering Plan
        // Plan must STILL deny code execution — the overlay wins over the rule.
        assert_eq!(
            gate(PermissionMode::Plan, &r, "bash", CodeExecuting),
            Verdict::Deny
        );
        // but reads remain auto even in Plan.
        assert_eq!(
            gate(PermissionMode::Plan, &r, "read_file", ReadOnly),
            Verdict::Auto
        );
    }

    #[test]
    fn operator_rule_api_rejects_impossible_states_and_describes_humanly() {
        let mut rules = PermissionRules::new();
        assert!(rules.try_set_cap(ReadOnly, Verdict::Deny).is_err());
        assert!(rules.try_set_cap(TrustMutating, Verdict::Auto).is_err());
        assert!(
            rules
                .try_set_cap(IrreversibleExternal, Verdict::Auto)
                .is_err()
        );
        rules.try_set_cap(TrustMutating, Verdict::Deny).unwrap();
        rules.try_set_cap(CodeExecuting, Verdict::Auto).unwrap();
        assert_eq!(rules.cap_rule(TrustMutating), Some(Verdict::Deny));
        assert_eq!(rules.cap_rule(CodeExecuting), Some(Verdict::Auto));
        assert_eq!(rules.cap_rule(ReversibleLocal), None);
        let description = rules.describe().join("\n");
        assert!(description.contains("code_executing -> allow"));
        assert!(description.contains("trust_mutating -> deny"));
        assert!(!description.contains("CodeExecuting"));
        assert!(!description.contains("Auto"));
    }

    #[test]
    fn mode_parse_and_cycle() {
        assert_eq!(
            PermissionMode::parse("acceptEdits"),
            Some(PermissionMode::AcceptEdits)
        );
        assert_eq!(PermissionMode::parse("YOLO"), Some(PermissionMode::Yolo));
        assert_eq!(PermissionMode::parse("bogus"), None);
        // full Shift+Tab cycle returns to start
        let mut m = PermissionMode::Default;
        for _ in 0..4 {
            m = m.next();
        }
        assert_eq!(m, PermissionMode::Default);
    }
}

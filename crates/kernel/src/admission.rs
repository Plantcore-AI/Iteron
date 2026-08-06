//! Pure authority admission at the microkernel boundary.
//!
//! Capability classification is supplied by an injected tool adapter. The kernel then intersects
//! the task and selected-policy ceilings, applies the trust-egress conjunct, and only then consults
//! the frozen permission gate. None of these inputs can add authority held by another input.

use core_protocol::capability_set::CapabilitySet;
use core_protocol::{Capability, PermissionMode, PermissionRules, Trust, Verdict, gate};

/// Apply task/policy/trust constraints to a gate decision.
///
/// This lower-level form also protects explicitly recorded operator bypasses: a bypass may replace
/// the final gate decision, but it cannot clear a task ceiling. See
/// [`constrain_under_authority`] for the one conjunct an operator bypass does now clear, and for
/// what that costs.
pub fn constrain(
    gate_verdict: Verdict,
    effective_capability: Capability,
    task_ceiling: CapabilitySet,
    policy_capabilities: CapabilitySet,
    governing_trust: Option<Trust>,
) -> Verdict {
    constrain_under_authority(
        gate_verdict,
        effective_capability,
        task_ceiling,
        policy_capabilities,
        governing_trust,
        OperatorAuthority::Constrained,
    )
}

/// Whether the caller is running as the operator's own authority (the shipped default since
/// 2026-08-06) or under the constrained posture `--ask-permissions` restores.
///
/// It is an enum rather than a `bool` because the two readings of a bare `true` here are opposite
/// and both plausible at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAuthority {
    /// Ceilings and the trust conjunct both apply. What every caller had before this parameter.
    Constrained,
    /// The session was explicitly launched as the operator, so the trust-egress conjunct does not
    /// apply.
    ///
    /// **What this surrenders, stated rather than implied:** with the conjunct off, a turn that has
    /// read untrusted content may still reach the network. That conjunct was the last thing
    /// standing between a prompt-injection payload in a repository and an egress tool, and it is
    /// now the operator's own authority doing the reaching. It was already true of `bash` — that
    /// tool is `CodeExecuting`, never classified as egress, so `curl` inside it was never held by
    /// this rule — and this makes the declared egress tools agree with the shell rather than
    /// pretending a boundary exists on one path and not the other.
    ///
    /// Ceilings are NOT surrendered. `task_ceiling ∩ policy_capabilities` still decides what a task
    /// may do at all, which is why a read-only sub-agent stays read-only under any posture.
    Operator,
}

/// [`constrain`], with the trust conjunct made conditional on the operator's posture.
pub fn constrain_under_authority(
    gate_verdict: Verdict,
    effective_capability: Capability,
    task_ceiling: CapabilitySet,
    policy_capabilities: CapabilitySet,
    governing_trust: Option<Trust>,
    authority: OperatorAuthority,
) -> Verdict {
    let admitted = task_ceiling.intersect(policy_capabilities);
    if !admitted.contains(effective_capability) {
        return Verdict::Deny;
    }
    let tainted_egress =
        effective_capability.is_egress() && governing_trust != Some(Trust::Trusted);
    if tainted_egress && authority == OperatorAuthority::Constrained {
        return Verdict::Deny;
    }
    gate_verdict
}

/// Complete normal admission in its fixed order: classified capability, ceiling intersection,
/// trust-egress conjunct, and the unchanged frozen permission gate.
pub fn admit(
    mode: PermissionMode,
    rules: &PermissionRules,
    tool: &str,
    effective_capability: Capability,
    task_ceiling: CapabilitySet,
    policy_capabilities: CapabilitySet,
    governing_trust: Option<Trust>,
) -> Verdict {
    constrain(
        gate(mode, rules, tool, effective_capability),
        effective_capability,
        task_ceiling,
        policy_capabilities,
        governing_trust,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPABILITIES: [Capability; 5] = [
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ];
    const TRUSTS: [Option<Trust>; 4] = [
        None,
        Some(Trust::Untrusted),
        Some(Trust::Workspace),
        Some(Trust::Trusted),
    ];
    const MODES: [PermissionMode; 4] = [
        PermissionMode::Default,
        PermissionMode::AcceptEdits,
        PermissionMode::Plan,
        PermissionMode::Yolo,
    ];

    fn all_capabilities() -> CapabilitySet {
        CapabilitySet::from_iter_capabilities(CAPABILITIES)
    }

    /// The operator posture clears exactly one conjunct, and the test says which one in both
    /// directions — the cost of the default is only visible if the suite states it.
    #[test]
    fn operator_authority_clears_the_trust_conjunct_and_nothing_else() {
        let all = all_capabilities();
        let egress = Capability::IrreversibleExternal;

        assert_eq!(
            constrain(Verdict::Auto, egress, all, all, Some(Trust::Untrusted)),
            Verdict::Deny,
            "the constrained posture still refuses tainted egress"
        );
        assert_eq!(
            constrain_under_authority(
                Verdict::Auto,
                egress,
                all,
                all,
                Some(Trust::Untrusted),
                OperatorAuthority::Operator,
            ),
            Verdict::Auto,
            "the operator's own authority reaches the network after reading untrusted content — \
             this is the guarantee the default surrenders"
        );

        // The ceiling is NOT surrendered: a task that never held the capability still cannot use it,
        // whatever posture the session is in.
        let read_only = CapabilitySet::from_iter_capabilities([Capability::ReadOnly]);
        for authority in [OperatorAuthority::Constrained, OperatorAuthority::Operator] {
            assert_eq!(
                constrain_under_authority(
                    Verdict::Auto,
                    Capability::CodeExecuting,
                    read_only,
                    all,
                    Some(Trust::Trusted),
                    authority,
                ),
                Verdict::Deny,
                "a ceiling holds under {authority:?}"
            );
        }
    }

    #[test]
    fn complete_capability_trust_mode_and_rule_truth_table_is_executable() {
        let all = all_capabilities();
        let rule_sets = [
            PermissionRules::new(),
            {
                let mut rules = PermissionRules::new();
                rules.set_tool("fixture", Verdict::Auto);
                rules
            },
            {
                let mut rules = PermissionRules::new();
                rules.set_tool("fixture", Verdict::Deny);
                rules
            },
        ];
        let mut cases = 0;
        for capability in CAPABILITIES {
            for trust in TRUSTS {
                for mode in MODES {
                    for rules in &rule_sets {
                        let expected = if capability.is_egress() && trust != Some(Trust::Trusted) {
                            Verdict::Deny
                        } else {
                            gate(mode, rules, "fixture", capability)
                        };
                        assert_eq!(
                            admit(mode, rules, "fixture", capability, all, all, trust),
                            expected,
                            "capability={capability:?}, trust={trust:?}, mode={mode:?}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 5 * 4 * 4 * 3);
    }

    #[test]
    fn task_and_candidate_policy_intersection_can_only_narrow() {
        let task = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]);
        let policy = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::IrreversibleExternal,
        ]);
        assert_eq!(
            admit(
                PermissionMode::Yolo,
                &PermissionRules::new(),
                "bash",
                Capability::CodeExecuting,
                task,
                policy,
                Some(Trust::Trusted),
            ),
            Verdict::Deny
        );
        assert_eq!(
            admit(
                PermissionMode::Yolo,
                &PermissionRules::new(),
                "read_file",
                Capability::ReadOnly,
                task,
                policy,
                Some(Trust::Trusted),
            ),
            Verdict::Auto
        );
    }

    #[test]
    fn exact_allow_and_operator_bypass_cannot_clear_tainted_egress() {
        let all = all_capabilities();
        let mut rules = PermissionRules::new();
        rules.set_tool("git_push", Verdict::Auto);
        for trust in [None, Some(Trust::Untrusted), Some(Trust::Workspace)] {
            assert_eq!(
                admit(
                    PermissionMode::Yolo,
                    &rules,
                    "git_push",
                    Capability::IrreversibleExternal,
                    all,
                    all,
                    trust,
                ),
                Verdict::Deny
            );
            assert_eq!(
                constrain(
                    Verdict::Auto,
                    Capability::IrreversibleExternal,
                    all,
                    all,
                    trust,
                ),
                Verdict::Deny
            );
        }
    }

    #[test]
    fn no_union_or_ordering_escape_hatch_exists_in_the_admission_source() {
        let source = include_str!("admission.rs");
        for forbidden in [
            concat!(".", "union("),
            concat!("CapabilitySet::", "all("),
            concat!("task_ceiling.", "max("),
            concat!("<", "="),
        ] {
            assert!(
                !source.contains(forbidden),
                "admission must not contain widening primitive `{forbidden}`"
            );
        }
    }
}

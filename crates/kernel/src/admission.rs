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
/// the final gate decision, but it cannot clear a task ceiling or launder tainted egress.
pub fn constrain(
    gate_verdict: Verdict,
    effective_capability: Capability,
    task_ceiling: CapabilitySet,
    policy_capabilities: CapabilitySet,
    governing_trust: Option<Trust>,
) -> Verdict {
    let admitted = task_ceiling.intersect(policy_capabilities);
    if !admitted.contains(effective_capability)
        || (effective_capability.is_egress() && governing_trust != Some(Trust::Trusted))
    {
        Verdict::Deny
    } else {
        gate_verdict
    }
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

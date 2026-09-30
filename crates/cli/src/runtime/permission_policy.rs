//! Capability classification and durable runtime-policy transitions.
//!
//! This module owns the permission decision vocabulary and the write-ahead ordering required when
//! operator policy changes. It deliberately has no access to `Agent`: callers provide only the
//! current snapshot and the durable log seam they intend to mutate.

use iteron_kernel::admission::{OperatorAuthority, constrain_under_authority};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{
    Capability, Effort, Event, EventKind, PermissionMode, PermissionRules,
    RuntimePolicyEventVersion, RuntimePolicySource, Seq, Trust, TurnId, Verdict,
};
use iteron_record::Rollout;
use iteron_tools::OperationEffects;

/// Narrow input to the host's permission decision. No runtime state or executor is exposed.
pub(super) struct OperationPolicy<'a> {
    pub mode: PermissionMode,
    pub rules: &'a PermissionRules,
    pub bypass: bool,
    pub task_ceiling: CapabilitySet,
    pub policy_capabilities: CapabilitySet,
    pub governing_trust: Trust,
    pub authority: OperatorAuthority,
}

pub(super) struct OperationAdmission {
    pub capability: Capability,
    pub verdict: Verdict,
    pub ceiling_blocks: bool,
    pub taint_blocks: bool,
}

/// Every required class must pass. Code permission alone cannot authorize unknown external or
/// trust effects, and an external permission cannot implicitly authorize code execution.
pub(super) fn evaluate_operation(
    tool: &str,
    effects: &OperationEffects,
    policy: OperationPolicy<'_>,
) -> OperationAdmission {
    let admitted = policy.task_ceiling.intersect(policy.policy_capabilities);
    let ceiling_blocks = !effects.required.is_subset_of(admitted);
    let taint_blocks = effects.required.iter().any(|cap| cap.is_egress())
        && policy.governing_trust != Trust::Trusted
        && policy.authority == OperatorAuthority::Constrained;
    let mut result = OperationAdmission {
        capability: effects
            .required
            .iter()
            .next()
            .unwrap_or(Capability::ReadOnly),
        verdict: Verdict::Auto,
        ceiling_blocks,
        taint_blocks,
    };
    for capability in effects.required.iter() {
        // A blanket interpreter/file-writer grant does not authorize extra trust/external
        // effects. Their exact named class remains separately configurable and deniable.
        let interpreter = matches!(tool, "bash" | "process_start" | "process_write");
        let operation_name = if interpreter && capability == Capability::IrreversibleExternal {
            format!("{tool}:external")
        } else if capability == Capability::TrustMutating
            && (interpreter || effects.required.contains(Capability::ReversibleLocal))
        {
            format!("{tool}:trust_mutating")
        } else {
            tool.to_owned()
        };
        let gate_verdict = if policy.rules.tool_rule(tool) == Some(Verdict::Deny) {
            Verdict::Deny
        } else if policy.bypass && policy.mode != PermissionMode::Plan {
            bypass_verdict(policy.rules, &operation_name, capability)
        } else {
            iteron_protocol::gate(policy.mode, policy.rules, &operation_name, capability)
        };
        let verdict = constrain_under_authority(
            gate_verdict,
            capability,
            policy.task_ceiling,
            policy.policy_capabilities,
            Some(policy.governing_trust),
            policy.authority,
        );
        let rank = |value| match value {
            Verdict::Auto => 0,
            Verdict::Ask => 1,
            Verdict::Deny => 2,
        };
        if rank(verdict) >= rank(result.verdict) {
            result.capability = capability;
            result.verdict = verdict;
        }
    }
    if effects.required.is_empty() {
        result.verdict = Verdict::Deny;
    }
    result
}

/// A path whose write is trust-mutating regardless of the writing tool's static class.
#[cfg(test)]
pub(super) fn is_trust_mutating_path(path: &str) -> bool {
    // Case-insensitive because macOS and Windows may resolve `.GIT/config` to `.git/config`.
    iteron_tools::is_trust_path(path)
}

/// Return the capability actually at stake for one structured tool call.
#[cfg(test)]
pub(super) fn effective_capability(input: &serde_json::Value, base: Capability) -> Capability {
    if base == Capability::ReversibleLocal
        && let Some(path) = input.get("path").and_then(|value| value.as_str())
        && is_trust_mutating_path(path)
    {
        return Capability::TrustMutating;
    }
    base
}

/// Bypass-mode still honors an explicit deny on either the exact tool or its capability class.
pub(super) fn bypass_verdict(
    rules: &PermissionRules,
    tool: &str,
    capability: Capability,
) -> Verdict {
    if rules.tool_rule(tool) == Some(Verdict::Deny)
        || rules.cap_rule(capability) == Some(Verdict::Deny)
    {
        Verdict::Deny
    } else {
        Verdict::Auto
    }
}

/// Narrow journal seam for runtime-policy transactions.
pub(super) trait RuntimePolicyLog {
    fn append_runtime_policy(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError>;
}

impl RuntimePolicyLog for Rollout {
    fn append_runtime_policy(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError> {
        self.append(event)
    }
}

pub(super) fn commit_effort_transition(
    log: &mut impl RuntimePolicyLog,
    turn: TurnId,
    current: &mut Effort,
    next: Effort,
    source: RuntimePolicySource,
) -> Result<bool, iteron_record::RecordError> {
    if *current == next {
        return Ok(false);
    }
    log.append_runtime_policy(&Event {
        seq: Seq::ZERO,
        turn,
        kind: EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            effort: next,
        },
    })?;
    *current = next;
    Ok(true)
}

pub(super) fn commit_permission_policy_transition(
    log: &mut impl RuntimePolicyLog,
    turn: TurnId,
    current_mode: &mut PermissionMode,
    current_rules: &mut PermissionRules,
    next_mode: PermissionMode,
    next_rules: PermissionRules,
    source: RuntimePolicySource,
) -> Result<bool, iteron_record::RecordError> {
    if *current_mode == next_mode && *current_rules == next_rules {
        return Ok(false);
    }
    log.append_runtime_policy(&Event {
        seq: Seq::ZERO,
        turn,
        kind: EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            mode: next_mode,
            rules: next_rules.clone(),
        },
    })?;
    *current_mode = next_mode;
    *current_rules = next_rules;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::ToolUse;
    use serde_json::json;

    fn all() -> CapabilitySet {
        CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ])
    }

    fn operation(
        command: &str,
        rules: &PermissionRules,
        ceiling: CapabilitySet,
        bypass: bool,
    ) -> OperationAdmission {
        let effects = OperationEffects::classify(
            &ToolUse {
                id: "call".into(),
                name: "bash".into(),
                input: json!({"command":command}),
            },
            Capability::CodeExecuting,
        );
        evaluate_operation(
            "bash",
            &effects,
            OperationPolicy {
                mode: PermissionMode::Yolo,
                rules,
                bypass,
                task_ceiling: ceiling,
                policy_capabilities: all(),
                governing_trust: Trust::Trusted,
                authority: OperatorAuthority::Constrained,
            },
        )
    }

    #[test]
    fn code_allow_and_interpreter_allow_do_not_approve_external_operations() {
        let mut rules = PermissionRules::new();
        rules.allow_cap(Capability::CodeExecuting);
        rules.set_tool("bash", Verdict::Auto);
        assert_eq!(
            operation("printf ok", &rules, all(), false).verdict,
            Verdict::Auto
        );
        assert_eq!(
            operation("git push origin main", &rules, all(), false).verdict,
            Verdict::Ask
        );
        assert_eq!(
            operation("python unknown.py", &rules, all(), false).verdict,
            Verdict::Ask
        );
    }

    #[test]
    fn every_required_class_holds_even_when_operator_bypass_is_explicit() {
        let rules = PermissionRules::new();
        let ceiling = CapabilitySet::only(Capability::CodeExecuting);
        let refused = operation("curl https://example.invalid", &rules, ceiling, true);
        assert_eq!(refused.verdict, Verdict::Deny);
        assert!(refused.ceiling_blocks);
        assert_eq!(
            operation("curl https://example.invalid", &rules, all(), true).verdict,
            Verdict::Auto
        );
        let mut deny = PermissionRules::new();
        deny.set_cap(Capability::ReversibleLocal, Verdict::Deny);
        assert_eq!(
            operation("python unknown.py", &deny, all(), true).verdict,
            Verdict::Deny
        );
        let mut exact = PermissionRules::new();
        exact.set_tool("bash:external", Verdict::Deny);
        assert_eq!(
            operation("curl https://example.invalid", &exact, all(), true).verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn external_permission_does_not_implicitly_authorize_execution() {
        let effects = OperationEffects::classify(
            &ToolUse {
                id: "call".into(),
                name: "bash".into(),
                input: json!({"command":"curl https://example.invalid"}),
            },
            Capability::CodeExecuting,
        );
        let mut rules = PermissionRules::new();
        rules.set_cap(Capability::CodeExecuting, Verdict::Deny);
        let result = evaluate_operation(
            "bash",
            &effects,
            OperationPolicy {
                mode: PermissionMode::Yolo,
                rules: &rules,
                bypass: true,
                task_ceiling: all(),
                policy_capabilities: all(),
                governing_trust: Trust::Trusted,
                authority: OperatorAuthority::Operator,
            },
        );
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[derive(Default)]
    struct FakePolicyLog {
        events: Vec<Event>,
        fail: bool,
    }

    impl RuntimePolicyLog for FakePolicyLog {
        fn append_runtime_policy(
            &mut self,
            event: &Event,
        ) -> Result<Seq, iteron_record::RecordError> {
            if self.fail {
                return Err(std::io::Error::other("injected policy append failure").into());
            }
            let seq = Seq(self.events.len() as u64);
            self.events.push(event.clone());
            Ok(seq)
        }
    }

    #[test]
    fn effort_commits_only_after_append_and_noop_writes_nothing() {
        let mut log = FakePolicyLog {
            fail: true,
            ..Default::default()
        };
        let mut current = Effort::Medium;
        assert!(
            commit_effort_transition(
                &mut log,
                TurnId(3),
                &mut current,
                Effort::High,
                RuntimePolicySource::Operator,
            )
            .is_err()
        );
        assert_eq!(current, Effort::Medium, "failed WAL must not change memory");
        assert!(log.events.is_empty());

        log.fail = false;
        assert!(
            commit_effort_transition(
                &mut log,
                TurnId(3),
                &mut current,
                Effort::High,
                RuntimePolicySource::Operator,
            )
            .unwrap()
        );
        assert_eq!(current, Effort::High);
        assert_eq!(log.events.len(), 1);
        assert!(
            !commit_effort_transition(
                &mut log,
                TurnId(3),
                &mut current,
                Effort::High,
                RuntimePolicySource::Operator,
            )
            .unwrap()
        );
        assert_eq!(log.events.len(), 1, "no-op must not append");
    }

    #[test]
    fn permission_snapshot_commits_atomically_after_append() {
        let mut log = FakePolicyLog {
            fail: true,
            ..Default::default()
        };
        let mut mode = PermissionMode::Default;
        let mut rules = PermissionRules::new();
        let mut next_rules = PermissionRules::new();
        next_rules.set_cap(Capability::CodeExecuting, Verdict::Deny);

        assert!(
            commit_permission_policy_transition(
                &mut log,
                TurnId(8),
                &mut mode,
                &mut rules,
                PermissionMode::AcceptEdits,
                next_rules.clone(),
                RuntimePolicySource::Operator,
            )
            .is_err()
        );
        assert_eq!(mode, PermissionMode::Default);
        assert!(rules.is_empty(), "failed WAL must retain the old snapshot");

        log.fail = false;
        assert!(
            commit_permission_policy_transition(
                &mut log,
                TurnId(8),
                &mut mode,
                &mut rules,
                PermissionMode::AcceptEdits,
                next_rules.clone(),
                RuntimePolicySource::Operator,
            )
            .unwrap()
        );
        assert_eq!(mode, PermissionMode::AcceptEdits);
        assert_eq!(rules, next_rules);
        assert!(matches!(
            &log.events[0].kind,
            EventKind::PolicyChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Operator,
                mode: PermissionMode::AcceptEdits,
                ..
            }
        ));
        assert!(
            !commit_permission_policy_transition(
                &mut log,
                TurnId(8),
                &mut mode,
                &mut rules,
                PermissionMode::AcceptEdits,
                next_rules,
                RuntimePolicySource::Operator,
            )
            .unwrap()
        );
        assert_eq!(log.events.len(), 1);
    }
}

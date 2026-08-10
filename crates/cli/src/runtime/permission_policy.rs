//! Capability classification and durable runtime-policy transitions.
//!
//! This module owns the permission decision vocabulary and the write-ahead ordering required when
//! operator policy changes. It deliberately has no access to `Agent`: callers provide only the
//! current snapshot and the durable log seam they intend to mutate.

use iteron_protocol::{
    Capability, Effort, Event, EventKind, PermissionMode, PermissionRules,
    RuntimePolicyEventVersion, RuntimePolicySource, Seq, TurnId, Verdict,
};
use iteron_record::Rollout;

/// A path whose write is trust-mutating regardless of the writing tool's static class.
pub(super) fn is_trust_mutating_path(path: &str) -> bool {
    // Case-insensitive because macOS and Windows may resolve `.GIT/config` to `.git/config`.
    let lower = path.trim_start_matches("./").to_ascii_lowercase();
    lower
        .split(['/', '\\'])
        .any(|segment| matches!(segment, ".git" | ".github" | ".iteron" | ".claude"))
        || lower.ends_with("claude.md")
        || lower.ends_with("agents.md")
}

/// Return the capability actually at stake for one structured tool call.
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

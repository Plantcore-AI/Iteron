//! Read-only facts from the installed executable hook owner; no command body or new discovery.
use super::{HookEvent, Hooks};
use iteron_protocol::HookCapability;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

impl Hooks {
    pub fn inventory_snapshot(&self) -> Vec<Value> {
        self.by_event.iter().map(|(event, commands)| {
            let canonical = iteron_protocol::lifecycle::event_spec(event);
            let capability = canonical.map(|spec| spec.hook_capability).unwrap_or_else(|| {
                if event == HookEvent::PreToolUse.key() { HookCapability::Gate } else { HookCapability::Observe }
            });
            let deadline_ms = if canonical.is_some() {
                let duration = if capability == HookCapability::Gate {
                    iteron_tunables::param_duration("cli.runtime.hooks.lifecycle_gate_timeout", super::LIFECYCLE_GATE_TIMEOUT)
                } else {
                    iteron_tunables::param_duration("cli.runtime.hooks.lifecycle_observer_timeout", super::LIFECYCLE_OBSERVER_TIMEOUT)
                };
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            } else { self.timeout_secs.saturating_mul(1000) };
            let handlers = commands.iter().enumerate().map(|(index, command)| json!({
                "configured_index":index,"source":self.handler_sources.get(&(event.clone(),index)).copied().unwrap_or("source_owner_not_captured"),
                "command_digest_sha256":hex::encode(Sha256::digest(command.as_bytes())),
                "dispatch_currently_admitted":self.extension_dispatch_admitted(event,command),
                "source_link":"verified package binding can be joined by event and handler digest; command text remains private"
            })).collect::<Vec<_>>();
            json!({"event":event,"handlers":commands.len(),"handler_sources":handlers,
                "hook_capability":capability,"deadline_ms":deadline_ms,
                "failure_policy":if capability==HookCapability::Gate {"missing, cancelled, timed out or failed decision denies action"} else {"advisory; cannot deny action"},
                "authority":"trusted operator configuration or verified capability-intersected plugin; executable hook uses sanitized helper environment",
                "concurrency_upper_bound":super::MAX_PARALLEL_HOOKS,"available_process_permits":self.parallelism.available_permits(),
                "ordering":"handlers run concurrently; outcomes apply in configured order",
                "cancellation":"bounded process cleanup; public terminal requires owner outcome, not observer loss",
                "recovery":"unmatched durable intents remain unknown; this inventory does not authorize command replay",
                "context_cost":{"model_prompt_bytes":null,"model_requests":null,"helper_input":"bounded live hook input","charged_prompt_tokens":null,"cost_status":"not_attributed_per_handler","observation_scope":"hook driver does not account arbitrary command external requests or later augmentation prompt bytes"},
                "stop_finalization_budget_ms":(event==HookEvent::Stop.key()).then(||u64::try_from(super::stop_hook_terminal_budget().as_millis()).unwrap_or(u64::MAX))})
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn installed_hook_inventory_preserves_source_order_without_command_bodies() {
        let mut hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "PreToolUse".into(),
            vec!["echo private-command-body".into()],
        )])));
        hooks
            .append_verified_plugin("session.created", "echo other-private-body".into())
            .unwrap();
        let rows = hooks.inventory_snapshot();
        let gate = rows
            .iter()
            .find(|row| row["event"] == "PreToolUse")
            .unwrap();
        assert_eq!(gate["hook_capability"], "gate");
        assert_eq!(gate["handler_sources"][0]["source"], "trusted_user_config");
        let observer = rows
            .iter()
            .find(|row| row["event"] == "session.created")
            .unwrap();
        assert_eq!(
            observer["handler_sources"][0]["source"],
            "signature_verified_plugin_manifest"
        );
        assert_eq!(
            observer["deadline_ms"],
            super::super::LIFECYCLE_OBSERVER_TIMEOUT.as_millis() as u64
        );
        let encoded = serde_json::to_string(&rows).unwrap();
        assert!(!encoded.contains("private-command-body"));
        assert!(!encoded.contains("other-private-body"));
        assert!(
            hooks
                .inventory_snapshot()
                .iter()
                .any(|row| row["context_cost"]["charged_prompt_tokens"].is_null())
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn real_canonical_gate_failed_exit_denies_while_observer_cannot_block() {
        let gate = "tool.call_proposed";
        let observer = "tool.call_completed";
        let hooks = Hooks::from_user_config(Some(&BTreeMap::from([
            (
                gate.into(),
                vec!["exit 7".into(), "echo later-denial >&2; exit 2".into()],
            ),
            (observer.into(), vec!["exit 7".into()]),
        ])));
        let report = hooks.run_lifecycle(gate, "{}").await.unwrap();
        assert_eq!((report.completed, report.failed), (2, 1));
        assert!(
            matches!(report.decision, super::super::HookDecision::Deny(ref reason) if reason.contains("failed without an allow decision") && !reason.contains("later-denial"))
        );
        assert!(matches!(
            hooks.run_lifecycle(observer, "{}").await.unwrap().decision,
            super::super::HookDecision::Allow
        ));
    }
}

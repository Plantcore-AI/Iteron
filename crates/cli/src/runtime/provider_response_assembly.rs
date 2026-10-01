//! Disjoint composition ports for the logical response owner and the existing early collection.
use super::Agent;
use super::early_tool_collection::EarlyToolCollectionScope;
use super::hook_execution::HookExecutionScope;
use super::provider_response_recovery::{ProviderResponseJournal, ProviderResponseScope};
use super::tool_execution_journal::ToolExecutionJournal;
use iteron_protocol::TurnId;

impl Agent {
    pub(super) fn provider_response_ports(
        &mut self,
        turn: TurnId,
    ) -> (ProviderResponseJournal<'_>, ProviderResponseScope<'_>) {
        let events = self.tool_events(turn);
        let hooks = HookExecutionScope {
            turn,
            workspace: self.workspace.as_path(),
            hooks: &self.hooks,
            command_journal: self.hook_effect_journal.clone(),
            interrupt: self.control.interrupt().cloned(),
            drain: self.control.drain().clone(),
            activity: self.activity.clone(),
            emitter: self.lifecycle_emitter.clone(),
            dispatcher: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        let plantcore = self.plantcore_runtime_enabled();
        let terminal = self.plantcore_terminal();
        (
            ProviderResponseJournal {
                tools: ToolExecutionJournal {
                    rollout: &mut self.rollout,
                    effects: &mut self.effect_journal,
                    ledger: &mut self.ledger,
                    failed_actions: &mut self.failed_actions,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                publications: &mut self.turn_publications,
                assistant_source: &mut self.last_assistant_source,
            },
            ProviderResponseScope {
                early: EarlyToolCollectionScope {
                    turn,
                    registry: &self.registry,
                    hooks,
                    events,
                    deadline: self.run_deadline.current(),
                },
                control: &self.control,
                usd: self.usd_budget.clone(),
                plantcore,
                terminal,
                retry: self.retry_policy,
            },
        )
    }
}

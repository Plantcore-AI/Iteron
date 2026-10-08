//! Composition-only capture of the same physical cleanup, writer and usage/calibration owners.
use super::Agent;
use super::context_runtime::ContextBudgetInspection;
use super::context_usage_reconciliation::ContextUsageReconciliation;
use super::early_tool_collection::EarlyToolCollectionScope;
use super::hook_execution::HookExecutionScope;
use super::provider_response_commit::{
    ProviderCommitScope, ProviderCommitSession, ProviderOutputState,
};
use super::provider_response_recovery::ProviderResponseJournal;
use super::provider_usage_journal::ProviderUsageJournal;
use super::session_transcript::TranscriptAdmissionJournal;
use super::tool_execution_journal::ToolExecutionJournal;
use iteron_ctx::ContextEstimate;
use iteron_protocol::TurnId;
use iteron_provider::EffortApplication;

impl Agent {
    pub(super) fn provider_usage_journal(&mut self, turn: TurnId) -> ProviderUsageJournal<'_> {
        let events = self.tool_events(turn);
        ProviderUsageJournal {
            transcript: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            usd: self.usd_budget.clone(),
            pricing: self.provider_selection.pricing_port().cloned(),
            attribution: self.projection_attribution.clone(),
            events,
        }
    }
    pub(super) fn provider_commit_session(
        &mut self,
        turn: TurnId,
        estimate: ContextEstimate,
        inspection: ContextBudgetInspection,
        effort: EffortApplication,
    ) -> ProviderCommitSession<'_> {
        let events = self.tool_events(turn);
        let context_events = self.context_preparation_events();
        let hooks = HookExecutionScope {
            turn,
            workspace: &self.workspace,
            hooks: &self.hooks,
            command_journal: self.hook_effect_journal.clone(),
            interrupt: self.control.interrupt().cloned(),
            drain: self.control.drain().clone(),
            activity: self.activity.clone(),
            emitter: self.lifecycle_emitter.clone(),
            dispatcher: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        let (provider_id, model_id) = self.provider_selection.selected().map_or_else(
            || {
                (
                    self.provider.provider_instance_id().unwrap_or("unbound"),
                    self.model.as_str(),
                )
            },
            |selected| {
                (
                    selected.route.provider_id.as_str(),
                    selected.route.model_id.as_str(),
                )
            },
        );
        ProviderCommitSession {
            journal: ProviderResponseJournal {
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
            early: EarlyToolCollectionScope {
                turn,
                registry: &self.registry,
                hooks,
                events,
                deadline: self.run_deadline.current(),
            },
            context: ContextUsageReconciliation {
                ledgers: &self.context_ledgers,
                baselines: &mut self.token_estimate_baselines,
                calibration: &mut self.token_calibration,
                provider_id,
                model_id,
                events: context_events,
            },
            output: ProviderOutputState {
                last_text: &mut self.last_assistant_text,
                run_text: &mut self.run_assistant_text,
                observed_trust: &mut self.observed_trust,
            },
            scope: ProviderCommitScope {
                turn,
                usd: self.usd_budget.clone(),
                pricing: self.provider_selection.pricing_port().cloned(),
                attribution: self.projection_attribution.clone(),
                estimate,
                inspection,
                window: self.model_context_window,
                compaction: self.compaction,
                effort,
            },
        }
    }
}

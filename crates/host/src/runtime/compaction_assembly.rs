//! Disjoint concrete compaction writer and observation ports. Candidate decisions, publication
//! and lifetime state stay in their owners; no compaction executor receives an Agent reference.
use super::Agent;
use super::compaction_journal::{
    CompactionCommitJournal, CompactionCommitScope, CompactionStateOwner,
};
use super::context_preparation_events::ContextPreparationEvents;
use iteron_ctx::RequestEstimator;

impl Agent {
    pub(super) fn context_preparation_events(&self) -> ContextPreparationEvents {
        ContextPreparationEvents {
            lifecycle: self.lifecycle_emitter.clone(),
            hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(None),
        }
    }

    pub(super) fn compaction_commit_ports(
        &mut self,
    ) -> (
        CompactionCommitJournal<'_>,
        CompactionCommitScope,
        &mut RequestEstimator,
        &mut CompactionStateOwner,
    ) {
        let scope = CompactionCommitScope {
            system: self.effective_system(),
            tools: self.registry.specs(),
            policy: self.compaction,
            context_window: self.execution_context_window(),
            output_reserve: self
                .model_max_output_tokens
                .unwrap_or(crate::runtime_tunables::core_facts::DEFAULT_REQUEST_OUTPUT_TOKENS),
            context_ledgers: self.context_ledgers.clone(),
            events: self.context_preparation_events(),
        };
        (
            CompactionCommitJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            scope,
            &mut self.context_estimator,
            &mut self.compaction_state,
        )
    }
}

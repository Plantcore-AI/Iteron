//! Bind the existing actual writer, monetary and runtime policy owners. No Agent enters a port.
use super::Agent;
use super::invocation_funding::InvocationFundingTransaction;
use super::session_transcript::TranscriptAdmissionJournal;
impl Agent {
    pub(super) fn invocation_funding(&mut self) -> InvocationFundingTransaction<'_> {
        InvocationFundingTransaction {
            journal: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            budget: &mut self.budget,
            usd: &mut self.usd_budget,
            persisted: &mut self.usd_budget_persisted_microusd,
            pricing: self
                .provider_selection
                .pricing_port()
                .map(|port| port.as_ref()),
            provenance: &mut self.runtime_policy_provenance,
            effort: self.effort,
            permission_mode: self.permission_mode,
            permission_rules: &self.permission_rules,
        }
    }
}

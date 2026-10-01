//! Trusted composition of current concrete intake/media owners. Execution chooses the bounded
//! leaf or orchestration future after these ports have released their mutable host borrows.
use super::Agent;
use super::invocation_admission::{
    InvocationAdmission, InvocationAdmissionSession, InvocationMediaSession, InvocationMemoryReset,
    InvocationMode,
};
use super::invocation_funding::InvocationFundingTransaction;
use super::session_transcript::TranscriptAdmissionJournal;
use super::submission_invocation::InvocationScope;
use super::{KernelError, file_submission::InputFileEvidence};
use iteron_protocol::{ImageContent, TurnId};

impl Agent {
    pub(super) fn prepare_invocation(
        &mut self,
        mode: InvocationMode,
        file: Option<InputFileEvidence>,
    ) -> Result<InvocationAdmission, KernelError> {
        let turn = TurnId(self.seq_turn);
        let events = self.tool_events(turn);
        InvocationAdmissionSession {
            funding: InvocationFundingTransaction {
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
            },
            effects: &mut self.effect_journal,
            policy: &mut self.policy_evidence,
            policy_identity: self.tunables_pin.as_ref().map(|pin| {
                (
                    pin.resolution_digest_sha256(),
                    self.compiled_policy_bundle.policy_runtime_bindings(),
                )
            }),
            inbox: &mut self.inbox,
            control: &mut self.control,
            force_cancel: self.force_cancel_seam.as_mut(),
            events,
            file: &mut self.input_file_evidence,
            compaction_closed: self.compaction_state.failed_closed(),
        }
        .prepare(mode, turn, file)
    }
    pub(super) fn stage_invocation(
        &mut self,
        invocation: InvocationAdmission,
        task: &str,
        images: &[ImageContent],
        file: Option<InputFileEvidence>,
    ) -> Result<InvocationAdmission, KernelError> {
        invocation.stage(
            task,
            images,
            file,
            InvocationMediaSession {
                scope: InvocationScope {
                    runs: self.rollout.path().parent().ok_or_else(|| {
                        KernelError::ContextResolution("record store resolution failed".into())
                    })?,
                    tenant: self.rollout.tenant().clone(),
                    run: self.rollout.run_id().clone(),
                    turn: TurnId(self.seq_turn),
                    wall_secs: self.budget.max_wall_secs,
                },
                deadlines: &mut self.run_deadline,
                compaction: &mut self.compaction_state,
                memory: InvocationMemoryReset {
                    enabled: self.memory_workspace.is_some(),
                    requested: &mut self.context_refresh_requested,
                    injected: &mut self.injected,
                    trust: &mut self.injected_trust,
                    evidence: &mut self.context_source_evidence,
                    registry: &self.registry,
                },
                selection: &self.provider_selection,
                usd: self.usd_budget.as_ref(),
                ledger: &self.ledger,
            },
        )
    }
}

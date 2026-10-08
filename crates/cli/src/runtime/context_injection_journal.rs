//! The actual injection writer and frozen-slot recorder. A materialization cannot install bytes
//! until this journal confirms its required context receipt; no proposal grants record authority.
use super::KernelError;
use super::policy_evidence::PolicyDecisionDraft;
use super::policy_evidence_recorder::{
    PolicyEvidenceRecorder, PolicyEvidenceRecorderError, PolicyOpportunity,
};
use super::session_transcript::TranscriptAdmissionJournal;
use iteron_protocol::{DurableInstructionContext, EventKind, Trust, TurnId, slot::SlotId};

pub(super) struct ContextInjectionJournal<'a> {
    pub(super) transcript: TranscriptAdmissionJournal<'a>,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
}

impl ContextInjectionJournal<'_> {
    pub(super) fn begin_policy(
        &mut self,
        slot: &'static str,
        turn: TurnId,
    ) -> Result<Option<PolicyOpportunity>, KernelError> {
        self.transcript.ensure_healthy()?;
        let Some(recorder) = self.policy.as_mut() else {
            return Ok(None);
        };
        recorder
            .begin_opportunity(&SlotId(slot.into()), Some(turn))
            .map(Some)
            .map_err(|error| self.policy_error(error))
    }

    pub(super) fn decision(
        &mut self,
        opportunity: Option<PolicyOpportunity>,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let Some(opportunity) = opportunity else {
            return Ok(());
        };
        self.transcript.ensure_healthy()?;
        let recorder = self.policy.as_mut().ok_or_else(|| {
            KernelError::PolicyEvidence("context policy recorder ownership was lost".into())
        })?;
        let started = std::time::Instant::now();
        let result =
            recorder.append_decision(self.transcript.rollout, &opportunity, draft.into_input());
        self.transcript
            .ledger
            .record_fsync_latency_us(super::provider_accounting::elapsed_us(started));
        result.map(|_| ()).map_err(|error| self.policy_error(error))
    }

    pub(super) fn injection(
        &mut self,
        turn: TurnId,
        text: String,
        trust: Trust,
        instructions: Option<DurableInstructionContext>,
    ) -> Result<(), KernelError> {
        self.transcript
            .append(
                turn,
                EventKind::ContextInjection {
                    text,
                    trust,
                    instructions,
                },
            )
            .map(|_| ())
    }

    pub(super) fn frontend_scope(&self) -> Result<[u8; 32], KernelError> {
        use sha2::Digest;
        let bytes = serde_json::to_vec(&(
            self.transcript.rollout.tenant(),
            self.transcript.rollout.run_id(),
        ))
        .map_err(|_| KernelError::ContextResolution("context journal scope unavailable".into()))?;
        Ok(sha2::Sha256::digest(bytes).into())
    }

    fn policy_error(&mut self, error: PolicyEvidenceRecorderError) -> KernelError {
        match error.into_record_error() {
            Ok(error) => {
                *self.transcript.record_failed = true;
                self.transcript
                    .diagnostics
                    .emit(iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {});
                KernelError::Record(error)
            }
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
}

//! Concrete journal/accepted-request evidence composition; no executable Agent callback.
use super::Agent;
use super::coding_run_driver::CodingRequestEvidence;
use super::provider_response_commit::ProviderCommitSession;
impl Agent {
    pub(super) fn coding_commit_session(
        &mut self,
        evidence: CodingRequestEvidence,
    ) -> ProviderCommitSession<'_> {
        self.provider_commit_session(
            evidence.turn,
            evidence.estimate,
            evidence.inspection,
            evidence.effort,
        )
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn coding_transcript_journal(
        &mut self,
    ) -> super::session_transcript::TranscriptAdmissionJournal<'_> {
        super::session_transcript::TranscriptAdmissionJournal {
            rollout: &mut self.rollout,
            ledger: &mut self.ledger,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            publications: &mut self.turn_publications,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
        }
    }
}

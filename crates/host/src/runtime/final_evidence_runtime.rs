//! Narrow final-evidence assembly over the actual writer/effect owner and immutable frontend.
use super::{Agent, RuntimeFrontendEvent, UiEvent};
use iteron_protocol::final_evidence::HostFinalEvidenceV1;
use iteron_protocol::{Seq, TurnId};

impl Agent {
    /// Absence means no live host final-evidence receipt for this owner/run, never test success.
    pub fn host_final_evidence(&self) -> Option<HostFinalEvidenceV1> {
        self.effect_journal.final_evidence()
    }
    pub(super) fn publish_host_final_evidence(&mut self, turn: TurnId, source: Seq) {
        let Some(evidence) = self.effect_journal.publish_final_evidence(
            &self.rollout,
            turn,
            source,
            !self.record_failed,
            &self.last_assistant_text,
        ) else {
            return;
        };
        if let Some(correction) = evidence.correction {
            self.ui(UiEvent::Notice(correction.message().into()));
        }
        if let Some(tx) = self.resident_ui_tx.as_ref() {
            self.frontend_saturation
                .try_send_runtime(tx, RuntimeFrontendEvent::HostFinalEvidence(evidence));
        }
    }
}

//! Actual writer/store/vision scope for confirmed tool image retention.
use super::Agent;
use super::session_transcript::TranscriptAdmissionJournal;
use super::tool_image_projection::ToolImageProjection;
use iteron_protocol::TurnId;
impl Agent {
    pub(super) fn tool_image_projection(&mut self, turn: TurnId) -> ToolImageProjection<'_> {
        let vision = self.provider.supports_image_input();
        let events = self.tool_events(turn);
        ToolImageProjection {
            journal: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            workspace: &self.workspace,
            vision,
            events,
        }
    }
}

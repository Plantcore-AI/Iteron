//! Compose the real pending-intake writer and its bounded host-resolved reference evidence.
use super::Agent;
use super::session_transcript::TranscriptAdmissionJournal;
use super::steering_admission::{SteeringAdmission, SteeringScope};
use iteron_protocol::TurnId;

impl Agent {
    pub(super) fn steering_admission(&mut self, turn: TurnId) -> SteeringAdmission<'_> {
        let events = self.tool_events(turn);
        SteeringAdmission {
            scope: SteeringScope {
                turn,
                registry: &self.registry,
                mailbox: self.persistent_mailbox.as_ref(),
                memory_workspace: self.memory_workspace.as_deref(),
                max_bytes: iteron_tunables::param_integer(
                    "cli.runtime.max_steer_bytes",
                    super::MAX_STEER_BYTES,
                ),
                events,
            },
            journal: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            inbox: &mut self.inbox,
            estimator: &mut self.context_estimator,
            plan: &mut self.task_plan,
            trust: &mut self.observed_trust,
            visibility: &mut self.session_memory_visibility,
        }
    }
}

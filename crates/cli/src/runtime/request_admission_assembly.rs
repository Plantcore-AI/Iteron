//! Composition of frozen request evidence and actual disjoint observation writers. These ports
//! borrow existing single owners; request admission never receives the resident Agent.
use super::Agent;
use super::context_preparation_events::ContextPreparationEvents;
use super::request_admission_journal::RequestAdmissionJournal;
use super::request_context_evidence::RequestContextScope;
use super::request_context_publication::RequestContextPublication;
use super::request_preparation::RequestConfiguration;
use iteron_protocol::{Message, TurnId};

impl Agent {
    pub(super) fn request_admission_ports(
        &mut self,
        turn: TurnId,
    ) -> (RequestAdmissionJournal<'_>, ContextPreparationEvents) {
        let events = self.tool_events(turn);
        let context_events = self.context_preparation_events();
        (
            RequestAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                events,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            context_events,
        )
    }

    pub(super) fn request_context_publication(
        &self,
        messages: &[Message],
    ) -> RequestContextPublication<'_> {
        RequestContextPublication {
            sources: &self.context_source_evidence,
            scope: RequestContextScope {
                execution_window: self.execution_context_window(),
                request_trust: self.governing_turn_trust(messages),
                estimator: &self.context_estimator,
                file: self.input_file_evidence,
                image: self.input_image_evidence,
            },
            ledgers: self.context_ledgers.clone(),
            events: self.context_preparation_events(),
        }
    }

    pub(super) fn request_configuration(&self) -> RequestConfiguration {
        RequestConfiguration {
            model: self.model.clone(),
            cache_system: self.provider_cache_system_enabled(),
            thinking_budget: self.effort_thinking_budget(self.effort),
            reasoning_effort: self.effort_reasoning(self.effort),
            controls: self.provider_controls,
        }
    }
}

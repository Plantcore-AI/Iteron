//! Thin composition of the actual final-context admission owners. All executable sequencing
//! belongs to CodingRequestSession; this factory does not retain the resident Agent.
use super::Agent;
use super::coding_execution_journal::CodingExecutionJournal;
use super::coding_request_session::{CodingRequestControl, CodingRequestSession};
use super::hook_execution::HookExecutionScope;
use super::request_context_evidence::RequestContextScope;
use super::request_context_publication::RequestContextPublication;
use super::tool_image_admission::ToolImageAdmission;
use iteron_protocol::{ImageContent, Message, TurnId};

impl Agent {
    pub(super) fn coding_request_session<'a>(
        &'a mut self,
        turn: TurnId,
        messages: &[Message],
        input_images: &'a [ImageContent],
    ) -> CodingRequestSession<'a> {
        let events = self.tool_events(turn);
        let context_events = self.context_preparation_events();
        let publication_events = self.context_preparation_events();
        let configuration = self.request_configuration();
        let request_trust = self.governing_turn_trust(messages);
        let execution_window = self.execution_context_window();
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
        CodingRequestSession {
            journal: CodingExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                failed_actions: &mut self.failed_actions,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                policy: &mut self.policy_evidence,
                terminal: &mut self.terminal_record,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            hooks,
            control: CodingRequestControl {
                inbox: &mut self.inbox,
                state: &mut self.control,
                force_cancel: self.force_cancel_seam.as_mut(),
            },
            events,
            context_events,
            publication: RequestContextPublication {
                sources: &self.context_source_evidence,
                scope: RequestContextScope {
                    execution_window,
                    request_trust,
                    estimator: &self.context_estimator,
                    file: self.input_file_evidence,
                    image: self.input_image_evidence,
                },
                ledgers: self.context_ledgers.clone(),
                events: publication_events,
            },
            configuration,
            media: ToolImageAdmission {
                vision: self.provider.supports_image_input(),
                policy: &self.binary_media_policy,
                envelope: self.multimodal_decode_envelope,
                estimator: &self.context_estimator,
                budget: &self.context_budget_policy,
            },
            input_images,
        }
    }
}

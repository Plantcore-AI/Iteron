//! Admit the existing bounded inbox at a real turn safe point. Reference and agent input remain
//! low-trust data; only a confirmed Message receipt advances the transcript or client receipt.
use super::KernelError;
use super::frontend_events::UiEvent;
use super::memory_request_exposure::MemoryVisibilityOwner;
use super::persistent_agents::LiveAgentMailbox;
use super::session_inbox::SessionSubmissionInbox;
use super::session_transcript::TranscriptAdmissionJournal;
use super::stream_tool_events::StreamToolEvents;
use super::task_plan::TaskPlanOwner;
use super::tool_presentation::strict_utf8_head;
use super::transcript::merge_adjacent_user_message;
use iteron_ctx::RequestEstimator;
use iteron_protocol::{LifecyclePayload, Message, Trust, TurnId};
use iteron_tools::Registry;
use std::path::Path;

pub(super) struct SteeringScope<'a> {
    pub(super) turn: TurnId,
    pub(super) registry: &'a Registry,
    pub(super) mailbox: Option<&'a LiveAgentMailbox>,
    pub(super) memory_workspace: Option<&'a Path>,
    pub(super) max_bytes: usize,
    pub(super) events: StreamToolEvents,
}
pub(super) struct SteeringAdmission<'a> {
    pub(super) scope: SteeringScope<'a>,
    pub(super) journal: TranscriptAdmissionJournal<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) estimator: &'a mut RequestEstimator,
    pub(super) plan: &'a mut TaskPlanOwner,
    pub(super) trust: &'a mut Trust,
    pub(super) visibility: &'a mut MemoryVisibilityOwner,
}
impl SteeringAdmission<'_> {
    pub(super) fn admit(mut self, messages: &mut Vec<Message>) -> Result<usize, KernelError> {
        let mut admitted = 0usize;
        let mut legacy_visible = 0usize;
        while let Some(steer) = self.inbox.pop() {
            if steer.text.trim().is_empty() {
                continue;
            }
            let agent = if let Some(activation) = &steer.agent_input {
                match activation.resolve(self.scope.mailbox, &steer.text) {
                    Ok(resolved) => Some(resolved),
                    Err(error) => {
                        self.inbox.restore_front(steer);
                        self.invalidate(admitted);
                        return Err(KernelError::AgentControl(error));
                    }
                }
            } else {
                None
            };
            let memory = if let Some(activation) = &steer.memory {
                let Some(workspace) = self.scope.memory_workspace else {
                    continue;
                };
                match activation.resolve(workspace, self.scope.max_bytes) {
                    Ok(resolved) => Some(resolved),
                    Err(_) => {
                        self.scope.registry.invalidate_pure_cache();
                        self.scope.events.emit(
                            "memory.recall.unused",
                            None,
                            LifecyclePayload {
                                reason_code: Some("memory_receipt_no_longer_valid".into()),
                                ..Default::default()
                            },
                        );
                        continue;
                    }
                }
            } else {
                None
            };
            let text = memory.as_ref().map_or_else(
                || strict_utf8_head(&steer.text, self.scope.max_bytes),
                |resolved| resolved.text.clone(),
            );
            let runtime_notification = steer.memory.is_none()
                && !steer.client_visible
                && text.starts_with(super::RUNTIME_NOTIFICATION_PREFIX);
            let message = if let Some(resolved) = &agent {
                Message::user_text(resolved.text.clone())
            } else if runtime_notification || memory.is_some() {
                Message::user_text(text)
            } else {
                Message::user_text(super::persistent_agents::prepared_mailbox::steer_text(
                    &text,
                ))
            };
            if let Some(admission) = agent
                .as_ref()
                .and_then(|resolved| resolved.admission.as_ref())
            {
                let result = self
                    .journal
                    .agent_input(self.scope.turn, admission.clone())
                    .and_then(|_| {
                        *self.trust = (*self.trust).min(Trust::Untrusted);
                        self.scope
                            .mailbox
                            .ok_or(KernelError::AgentControl(
                                iteron_agents::ControllerError::StaleEpoch,
                            ))?
                            .confirm_source_admission(admission)
                            .map_err(KernelError::AgentControl)
                    });
                if let Err(error) = result {
                    self.inbox.restore_front(steer);
                    self.invalidate(admitted);
                    return Err(error);
                }
            }
            if let Some(resolved) = &memory {
                if let Err(error) = self
                    .journal
                    .memory_reference(self.scope.turn, resolved.evidence.clone())
                {
                    self.inbox.restore_front(steer);
                    self.invalidate(admitted);
                    return Err(error);
                }
                *self.trust = (*self.trust).min(Trust::Untrusted);
            }
            let receipt = match self.journal.message(self.scope.turn, message.clone()) {
                Ok(receipt) => receipt,
                Err(error) => {
                    self.inbox.restore_front(steer);
                    self.invalidate(admitted);
                    return Err(error);
                }
            };
            self.plan.observe_submission(receipt);
            if let Some(resolved) = memory {
                self.scope.registry.invalidate_pure_cache();
                if !resolved.evidence.deleted {
                    self.visibility.schedule_reference(
                        self.scope.turn,
                        resolved.source_turn,
                        resolved.body_digest,
                    );
                }
            }
            if let Some(id) = steer.submission_id {
                self.scope
                    .events
                    .present(UiEvent::SteerSubmissionApplied { id });
            }
            merge_adjacent_user_message(messages, message);
            admitted = admitted.saturating_add(1);
            legacy_visible = legacy_visible.saturating_add(usize::from(
                steer.client_visible && steer.submission_id.is_none(),
            ));
        }
        self.invalidate(admitted);
        if legacy_visible > 0 {
            self.scope.events.present(UiEvent::SteerApplied {
                count: legacy_visible,
            });
        }
        Ok(admitted)
    }
    fn invalidate(&mut self, admitted: usize) {
        if admitted > 0 {
            self.estimator.invalidate_transcript();
        }
    }
}

pub(super) const MAX_STEER_BYTES: usize = 64 * 1024;

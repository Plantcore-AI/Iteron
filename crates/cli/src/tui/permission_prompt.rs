//! Actual blocking permission presentation and response correlation. Queue acceptance is retained
//! until the exact runtime receipt/resolution; a key or another submission never clears authority.

use super::capability_can_be_remembered;
use crossterm::event::KeyCode;
use iteron_protocol::{Capability, SubmissionId, SubmissionLifecycleState};

/// A pending capability approval the operator must answer (mode produced an `Ask` verdict).
pub(super) struct Pending {
    pub(super) id: SubmissionId,
    pub(super) tool: String,
    pub(super) cap: Capability,
    pub(super) reason: String,
    pub(super) arguments: serde_json::Value,
    pub(super) workspace: String,
    /// An incomplete public prompt cannot authorize an effect, even if a legacy EQ copy was
    /// available. The App Server product projection is the visible approval authority.
    pub(super) prompt_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApprovalChoice {
    Once,
    Session,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApprovalInput {
    Consumed,
    Answer { approved: bool, remember: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResponseObservation {
    Applied,
    Refused,
}

pub(super) struct PermissionPromptOwner {
    pending: Option<Pending>,
    choice: ApprovalChoice,
    response: Option<SubmissionId>,
}
impl Default for PermissionPromptOwner {
    fn default() -> Self {
        Self {
            pending: None,
            choice: ApprovalChoice::Deny,
            response: None,
        }
    }
}
impl PermissionPromptOwner {
    pub(super) fn read(&self) -> Option<&Pending> {
        self.pending.as_ref()
    }
    pub(super) fn choice(&self) -> ApprovalChoice {
        self.choice
    }
    pub(super) fn present(&mut self, prompt: Pending) {
        if self.pending.as_ref().is_none_or(|old| old.id != prompt.id) {
            self.response = None;
        }
        self.pending = Some(prompt);
        self.choice = ApprovalChoice::Deny;
    }
    pub(super) fn resolve(&mut self, id: SubmissionId) -> bool {
        if self.pending.as_ref().is_none_or(|pending| pending.id != id) {
            return false;
        }
        self.clear();
        true
    }
    pub(super) fn clear(&mut self) {
        self.pending = None;
        self.response = None;
        self.choice = ApprovalChoice::Deny;
    }
    pub(super) fn awaiting_response(&self) -> bool {
        self.response.is_some()
    }
    pub(super) fn response_queued(
        &mut self,
        prompt: SubmissionId,
        submission: SubmissionId,
    ) -> bool {
        if self.response.is_some()
            || self
                .pending
                .as_ref()
                .is_none_or(|pending| pending.id != prompt)
        {
            return false;
        }
        self.response = Some(submission);
        true
    }
    pub(super) fn observe_response(
        &mut self,
        id: SubmissionId,
        state: SubmissionLifecycleState,
    ) -> Option<ResponseObservation> {
        if self.response != Some(id) {
            return None;
        }
        match state {
            SubmissionLifecycleState::Applied => Some(ResponseObservation::Applied),
            SubmissionLifecycleState::Rejected | SubmissionLifecycleState::Expired => {
                self.response = None;
                Some(ResponseObservation::Refused)
            }
            _ => None,
        }
    }
    /// Route one physical key through the blocking permission control. Navigation only changes
    /// focus; Enter emits exactly one answer for that focus. Direct y/a/n shortcuts remain
    /// available, but an impossible session-wide grant is never constructed.
    pub(super) fn key(&mut self, code: KeyCode) -> ApprovalInput {
        let Some(pending) = self.pending.as_ref() else {
            return ApprovalInput::Consumed;
        };
        let choices: &[ApprovalChoice] = if !pending.prompt_complete {
            &[ApprovalChoice::Deny]
        } else if capability_can_be_remembered(pending.cap) {
            &[
                ApprovalChoice::Once,
                ApprovalChoice::Session,
                ApprovalChoice::Deny,
            ]
        } else {
            &[ApprovalChoice::Once, ApprovalChoice::Deny]
        };
        if !choices.contains(&self.choice) {
            self.choice = ApprovalChoice::Deny;
        }
        let position = choices
            .iter()
            .position(|choice| *choice == self.choice)
            .unwrap_or(choices.len() - 1);
        match code {
            KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
                self.choice = choices[(position + choices.len() - 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
                self.choice = choices[(position + 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Enter => match self.choice {
                ApprovalChoice::Once => ApprovalInput::Answer {
                    approved: true,
                    remember: false,
                },
                ApprovalChoice::Session
                    if pending.prompt_complete && capability_can_be_remembered(pending.cap) =>
                {
                    ApprovalInput::Answer {
                        approved: true,
                        remember: true,
                    }
                }
                ApprovalChoice::Session | ApprovalChoice::Deny => ApprovalInput::Answer {
                    approved: false,
                    remember: false,
                },
            },
            KeyCode::Char('y') | KeyCode::Char('Y') if pending.prompt_complete => {
                ApprovalInput::Answer {
                    approved: true,
                    remember: false,
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A')
                if pending.prompt_complete && capability_can_be_remembered(pending.cap) =>
            {
                ApprovalInput::Answer {
                    approved: true,
                    remember: true,
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ApprovalInput::Answer {
                approved: false,
                remember: false,
            },
            _ => ApprovalInput::Consumed,
        }
    }

    #[cfg(test)]
    pub(super) fn response_id(&self) -> Option<SubmissionId> {
        self.response
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalInput, Pending, PermissionPromptOwner, ResponseObservation};
    use crossterm::event::KeyCode;
    use iteron_protocol::{Capability, SubmissionId, SubmissionLifecycleState};

    fn prompt(id: u64, complete: bool) -> Pending {
        Pending {
            id: SubmissionId(id),
            tool: "write_file".into(),
            cap: Capability::ReversibleLocal,
            reason: "actual runtime prompt".into(),
            arguments: serde_json::json!({"path":"src/a.rs"}),
            workspace: "workspace".into(),
            prompt_complete: complete,
        }
    }
    #[test]
    fn exact_prompt_and_response_receipts_are_retained_until_observed_resolution() {
        let mut owner = PermissionPromptOwner::default();
        owner.present(prompt(7, true));
        assert_eq!(
            owner.key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: false,
                remember: false
            }
        );
        assert!(owner.response_queued(SubmissionId(7), SubmissionId(12)));
        assert!(!owner.response_queued(SubmissionId(7), SubmissionId(13)));
        assert_eq!(
            owner.observe_response(SubmissionId(13), SubmissionLifecycleState::Rejected),
            None
        );
        assert!(owner.awaiting_response());
        assert_eq!(
            owner.observe_response(SubmissionId(12), SubmissionLifecycleState::Applied),
            Some(ResponseObservation::Applied)
        );
        assert!(
            owner.awaiting_response(),
            "applied submission is not the tool permission resolution"
        );
        assert!(!owner.resolve(SubmissionId(8)));
        assert_eq!(owner.read().unwrap().id, SubmissionId(7));
        owner.present(prompt(7, true));
        assert!(owner.awaiting_response());
        assert_eq!(
            owner.observe_response(SubmissionId(12), SubmissionLifecycleState::Rejected),
            Some(ResponseObservation::Refused)
        );
        assert!(!owner.awaiting_response());
        assert!(owner.resolve(SubmissionId(7)));
        assert!(owner.read().is_none());
    }
    #[test]
    fn incomplete_prompt_keys_cannot_construct_approval_and_new_scope_resets_correlations() {
        let mut owner = PermissionPromptOwner::default();
        owner.present(prompt(3, false));
        assert_eq!(owner.key(KeyCode::Char('y')), ApprovalInput::Consumed);
        assert_eq!(owner.key(KeyCode::Char('a')), ApprovalInput::Consumed);
        owner.key(KeyCode::Left);
        assert_eq!(
            owner.key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: false,
                remember: false
            }
        );
        owner.response_queued(SubmissionId(3), SubmissionId(20));
        owner.present(prompt(4, true));
        assert!(!owner.awaiting_response());
        assert!(!owner.response_queued(SubmissionId(3), SubmissionId(21)));
        owner.clear();
        assert_eq!(owner.key(KeyCode::Char('y')), ApprovalInput::Consumed);
    }
}

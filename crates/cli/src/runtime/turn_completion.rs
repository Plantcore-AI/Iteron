//! The actual completion decision lifetime. Steering, configured verification, guidance and
//! transcript barriers run once in this owner; final physical terminal/turn advance remain
//! separate host operations that consume the returned action.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::completion_session::CompletionSession;
use super::frontend_events::UiEvent;
use super::investigation_convergence::{CandidateWorkspaceBaseline, InvestigationConvergence};
use super::model_response::ModelResponseDecision;
use super::strong_verification::VerificationGateDisposition;
use super::tool_response::ToolResponseMessage;
use iteron_protocol::{AgentLoopState, LifecyclePayload, Message, Outcome};

pub(super) enum CompletionAction {
    Continue {
        applying_steer: bool,
    },
    Finish {
        outcome: Outcome,
        publish_answer: bool,
    },
    Drain,
    RequestedControl,
}
pub(super) struct TurnCompletion<'a> {
    session: CompletionSession<'a>,
}
impl<'a> TurnCompletion<'a> {
    pub(super) fn new(session: CompletionSession<'a>) -> Self {
        Self { session }
    }

    /// Consumes the model's actual closed no-tool response decision. A future dropped during
    /// verification cannot be re-entered through this controller or publish an unproved answer.
    pub(super) async fn model(
        mut self,
        decision: ModelResponseDecision,
        messages: &mut Vec<Message>,
        baseline: &mut CandidateWorkspaceBaseline,
        convergence: &mut InvestigationConvergence,
        loop_state: &mut AgentLoopGuard,
    ) -> Result<CompletionAction, KernelError> {
        if let Some(notice) = decision.notice() {
            self.session.notice(notice.durable);
            self.session
                .events()
                .present(UiEvent::Notice(notice.visible.into()));
            if let Some((event, reason, outcome)) = notice.lifecycle {
                self.session.events().emit(
                    event,
                    None,
                    LifecyclePayload {
                        reason_code: Some(reason.into()),
                        outcome_code: outcome.map(str::to_owned),
                        ..Default::default()
                    },
                );
            }
        }
        match decision {
            ModelResponseDecision::Continue { guidance, .. } => {
                self.session
                    .message(messages, Message::user_text(guidance))?;
                Ok(CompletionAction::Continue {
                    applying_steer: false,
                })
            }
            ModelResponseDecision::Finish { outcome, .. } => Ok(CompletionAction::Finish {
                outcome,
                publish_answer: false,
            }),
            ModelResponseDecision::Refused(error) => Err(error),
            ModelResponseDecision::Candidate { .. } => {
                let steered = self.session.admit_steering(messages)?;
                if self.session.requested() {
                    return Ok(CompletionAction::RequestedControl);
                }
                if steered > 0 {
                    return Ok(CompletionAction::Continue {
                        applying_steer: true,
                    });
                }
                if self.session.verification.is_some() {
                    loop_state.transition(AgentLoopState::Verifying)?;
                    let candidate = baseline.diff_state().await;
                    if let Some(disposition) = self.session.verify(candidate, convergence).await?
                        && let Some(action) = self.verification_result(disposition, messages)?
                    {
                        return Ok(action);
                    }
                }
                // A configured oracle may take time. The actual ordered inbox/control must be
                // observed after it settles, before the host's AnswerAvailable/Done barriers.
                self.candidate_safe_point(messages, true)
            }
        }
    }

    /// Tool terminals are already settled and declaration-complete. This owner writes their
    /// single model response before acting on the optional existing automatic verifier result.
    pub(super) async fn tools(
        mut self,
        mut message: ToolResponseMessage,
        automatic_candidate: bool,
        messages: &mut Vec<Message>,
        baseline: &mut CandidateWorkspaceBaseline,
        convergence: &mut InvestigationConvergence,
    ) -> Result<CompletionAction, KernelError> {
        let disposition = if automatic_candidate && self.session.verification.is_some() {
            self.session
                .verify(baseline.diff_state().await, convergence)
                .await?
        } else {
            None
        };
        match &disposition {
            Some(VerificationGateDisposition::Retry(guidance))
            | Some(VerificationGateDisposition::Cancelled(guidance))
            | Some(VerificationGateDisposition::Finish {
                guidance: Some(guidance),
                ..
            }) => {
                message.guidance(guidance.clone());
            }
            _ => {}
        }
        self.session.message(messages, message.into_message())?;
        if let Some(disposition) = disposition {
            return Ok(match disposition {
                VerificationGateDisposition::Passed => {
                    self.candidate_safe_point(messages, false)?
                }
                VerificationGateDisposition::Retry(_) => CompletionAction::Continue {
                    applying_steer: false,
                },
                VerificationGateDisposition::Finish { outcome, .. } => CompletionAction::Finish {
                    outcome,
                    publish_answer: false,
                },
                VerificationGateDisposition::Drained => CompletionAction::Drain,
                VerificationGateDisposition::Cancelled(_) => CompletionAction::RequestedControl,
            });
        }
        self.session.poll();
        if self.session.requested() {
            return Ok(CompletionAction::RequestedControl);
        }
        Ok(if let Some(reason) = self.session.exhausted() {
            CompletionAction::Finish {
                outcome: Outcome::BudgetExhausted(reason),
                publish_answer: false,
            }
        } else {
            CompletionAction::Continue {
                applying_steer: false,
            }
        })
    }

    fn verification_result(
        &mut self,
        disposition: VerificationGateDisposition,
        messages: &mut Vec<Message>,
    ) -> Result<Option<CompletionAction>, KernelError> {
        Ok(match disposition {
            VerificationGateDisposition::Passed => None,
            VerificationGateDisposition::Retry(guidance) => {
                self.session
                    .message(messages, Message::user_text(guidance))?;
                Some(CompletionAction::Continue {
                    applying_steer: false,
                })
            }
            VerificationGateDisposition::Finish { outcome, guidance } => {
                if let Some(guidance) = guidance {
                    self.session
                        .message(messages, Message::user_text(guidance))?;
                }
                Some(CompletionAction::Finish {
                    outcome,
                    publish_answer: false,
                })
            }
            VerificationGateDisposition::Drained => Some(CompletionAction::Drain),
            VerificationGateDisposition::Cancelled(guidance) => {
                self.session
                    .message(messages, Message::user_text(guidance))?;
                Some(CompletionAction::RequestedControl)
            }
        })
    }
    fn candidate_safe_point(
        &mut self,
        messages: &mut Vec<Message>,
        publish_answer: bool,
    ) -> Result<CompletionAction, KernelError> {
        let steered = self.session.admit_steering(messages)?;
        if self.session.requested() {
            return Ok(CompletionAction::RequestedControl);
        }
        Ok(if steered > 0 {
            // The first model candidate safe point projects ApplyingSteer; after verifier/tool
            // settlement the original loop simply advances. No additional phase is invented.
            CompletionAction::Continue {
                applying_steer: false,
            }
        } else {
            CompletionAction::Finish {
                outcome: Outcome::Done,
                publish_answer,
            }
        })
    }
}

#[cfg(all(test, unix))]
#[path = "turn_completion_tests.rs"]
mod tests;

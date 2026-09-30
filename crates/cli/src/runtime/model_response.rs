//! Actual no-tool model response decision boundary. It consumes the existing invocation recovery
//! and optional candidate owners, returning instructions without journal or execution authority.
use super::KernelError;
use super::completion_semantics::{self, EmptyEndTurnDecision};
use super::investigation_convergence::InvestigationConvergence;
use super::submitted_turn_state::SubmittedTurnState;
use iteron_protocol::{Outcome, StopReason};

pub(super) struct ModelResponseScope<'a> {
    pub(super) exhausted: Option<&'static str>,
    pub(super) interactive: bool,
    pub(super) configured_verifier: bool,
    pub(super) task: &'a str,
    pub(super) answer: &'a str,
    pub(super) recovered_stream: bool,
}
pub(super) struct ModelResponseInterpreter<'a> {
    pub(super) submitted: &'a mut SubmittedTurnState,
    pub(super) convergence: &'a mut InvestigationConvergence,
    pub(super) scope: ModelResponseScope<'a>,
}

pub(super) struct ResponseNotice {
    pub(super) durable: &'static str,
    pub(super) visible: &'static str,
    pub(super) lifecycle: Option<(&'static str, &'static str, Option<&'static str>)>,
}
pub(super) enum ModelResponseDecision {
    Continue {
        notice: ResponseNotice,
        guidance: &'static str,
    },
    Candidate {
        notice: Option<ResponseNotice>,
    },
    Finish {
        notice: Option<ResponseNotice>,
        outcome: Outcome,
    },
    Refused(KernelError),
}
impl ModelResponseDecision {
    pub(super) fn notice(&self) -> Option<&ResponseNotice> {
        match self {
            Self::Continue { notice, .. } => Some(notice),
            Self::Candidate { notice } | Self::Finish { notice, .. } => notice.as_ref(),
            Self::Refused(_) => None,
        }
    }
}
impl ModelResponseInterpreter<'_> {
    pub(super) fn decide(self, stop: &StopReason) -> ModelResponseDecision {
        // Budget proof is supplied by the real completed-turn accounting owner. An adapter error
        // or refusal cannot be converted to a success merely because a ceiling is also exhausted.
        match stop {
            StopReason::MaxTokens | StopReason::PauseTurn | StopReason::EndTurn => {
                if let Some(reason) = self.scope.exhausted {
                    return ModelResponseDecision::Finish {
                        notice: None,
                        outcome: Outcome::BudgetExhausted(reason),
                    };
                }
            }
            _ => {}
        }
        match stop {
            StopReason::MaxTokens => ModelResponseDecision::Continue {
                notice: ResponseNotice {
                    durable: "model output reached max tokens; requesting a bounded continuation",
                    visible: "model output reached max tokens; continuing",
                    lifecycle: None,
                },
                guidance: "The previous response reached its output-token limit. Continue from the exact stopping point. Do not repeat completed work. If a tool call was cut off, emit that tool call again with its complete arguments.",
            },
            StopReason::PauseTurn => ModelResponseDecision::Continue {
                notice: ResponseNotice {
                    durable: if self.scope.recovered_stream {
                        "provider stream recovery; requesting a bounded continuation"
                    } else {
                        "provider paused the turn; requesting a bounded continuation"
                    },
                    visible: if self.scope.recovered_stream {
                        "provider disconnected; reconnecting"
                    } else {
                        "provider paused the turn; continuing"
                    },
                    lifecycle: None,
                },
                guidance: if self.scope.recovered_stream {
                    "The connection interrupted the previous response. Continue from the stopping point without repeating completed work. Re-emit only tool calls whose arguments were incomplete."
                } else {
                    "The provider paused the previous turn. Continue from the exact stopping point without repeating completed work."
                },
            },
            StopReason::EndTurn => self.end_turn(),
            StopReason::ToolUse => ModelResponseDecision::Refused(
                iteron_provider::ProviderError::Decode(
                    "provider ended with tool_use but emitted no complete tool call".into(),
                )
                .into(),
            ),
            StopReason::StopSequence => ModelResponseDecision::Refused(
                iteron_provider::ProviderError::Decode(
                    "provider returned an unsolicited stop_sequence terminal".into(),
                )
                .into(),
            ),
            StopReason::Refusal => {
                ModelResponseDecision::Refused(iteron_provider::ProviderError::Refusal.into())
            }
            StopReason::Unknown(code) => ModelResponseDecision::Refused(
                iteron_provider::ProviderError::UnknownStopReason {
                    code: Box::new(code.clone()),
                }
                .into(),
            ),
        }
    }
    fn end_turn(self) -> ModelResponseDecision {
        let promised = self.convergence.enabled()
            && !self.scope.interactive
            && completion_semantics::task_requests_candidate_action(self.scope.task)
            && completion_semantics::commits_to_immediate_candidate_action(self.scope.answer);
        if promised && self.submitted.candidate_recovery_used() {
            let notice = "provider repeated an immediate edit promise after its bounded action continuation without creating a candidate";
            return ModelResponseDecision::Finish {
                notice: Some(ResponseNotice {
                    durable: notice,
                    visible: notice,
                    lifecycle: None,
                }),
                outcome: Outcome::Stuck,
            };
        }
        if promised && self.convergence.reopen_immediate_candidate_action() {
            self.submitted.claim_candidate_recovery();
            let notice = "provider promised an immediate candidate edit but ended without one; requesting one bounded action continuation";
            return ModelResponseDecision::Continue {
                notice: ResponseNotice {
                    durable: notice,
                    visible: notice,
                    lifecycle: Some((
                        "session.idle",
                        "immediate_candidate_action_continuation",
                        None,
                    )),
                },
                guidance: "You committed to an immediate candidate edit but ended the turn without making it. Execute that stated minimal edit now. If the visible evidence does not support it, explicitly conclude evidence-insufficient without promising future action.",
            };
        }
        if !self.scope.answer.trim().is_empty() {
            return ModelResponseDecision::Candidate { notice: None };
        }
        let decision = completion_semantics::empty_end_turn_decision(
            self.scope.configured_verifier,
            self.convergence.candidate_handoff_terminal(),
        );
        let notice = if decision == EmptyEndTurnDecision::AcceptCandidateHandoff {
            let notice = "provider ended without prose after stable candidate convergence; controller accepted the diff handoff";
            ResponseNotice {
                durable: notice,
                visible: notice,
                lifecycle: Some((
                    "session.idle",
                    "stable_candidate_empty_end_turn_handoff",
                    Some("accepted"),
                )),
            }
        } else {
            let notice = if self.scope.interactive {
                "provider ended the turn without an answer; completion was not accepted"
            } else {
                "provider ended the automated turn without an answer; completion requires a configured oracle"
            };
            ResponseNotice {
                durable: notice,
                visible: notice,
                lifecycle: Some(("session.failed", "empty_end_turn", None)),
            }
        };
        if decision == EmptyEndTurnDecision::Reject {
            ModelResponseDecision::Finish {
                notice: Some(notice),
                outcome: Outcome::HarnessError,
            }
        } else {
            ModelResponseDecision::Candidate {
                notice: Some(notice),
            }
        }
    }
}

#[cfg(test)]
#[path = "model_response_tests.rs"]
mod tests;

use super::{ModelResponseDecision, ModelResponseInterpreter, ModelResponseScope};
use crate::runtime::KernelError;
use crate::runtime::investigation_convergence::InvestigationConvergence;
use crate::runtime::submitted_turn_state::SubmittedTurnState;
use iteron_protocol::{Outcome, StopReason};

fn decision(
    stop: StopReason,
    answer: &str,
    verifier: bool,
    exhausted: Option<&'static str>,
    recovered: bool,
) -> ModelResponseDecision {
    ModelResponseInterpreter {
        submitted: &mut SubmittedTurnState::default(),
        convergence: &mut InvestigationConvergence::for_general_run(),
        scope: ModelResponseScope {
            exhausted,
            interactive: false,
            configured_verifier: verifier,
            task: "implement the change",
            answer,
            recovered_stream: recovered,
        },
    }
    .decide(&stop)
}

#[test]
fn empty_completion_requires_real_oracle_without_manufacturing_done() {
    assert!(matches!(
        decision(StopReason::EndTurn, " ", false, None, false),
        ModelResponseDecision::Finish {
            outcome: Outcome::HarnessError,
            ..
        }
    ));
    assert!(matches!(
        decision(StopReason::EndTurn, " ", true, None, false),
        ModelResponseDecision::Candidate { .. }
    ));
    // A candidate is only a semantic disposition: ordinary response handling creates no extra
    // verifier, no authorization and no terminal receipt. The real steering/verification ports
    // must still settle before the host may publish Done.
    assert!(matches!(
        decision(StopReason::EndTurn, "implemented", false, None, false),
        ModelResponseDecision::Candidate { notice: None }
    ));
}

#[test]
fn actual_budget_bounds_every_continuation_but_never_erases_adapter_refusal() {
    for stop in [
        StopReason::MaxTokens,
        StopReason::PauseTurn,
        StopReason::EndTurn,
    ] {
        assert!(matches!(
            decision(stop, "partial", false, Some("max_turns"), false),
            ModelResponseDecision::Finish {
                outcome: Outcome::BudgetExhausted("max_turns"),
                notice: None
            }
        ));
    }
    assert!(matches!(
        decision(
            StopReason::ToolUse,
            "partial",
            false,
            Some("max_turns"),
            false
        ),
        ModelResponseDecision::Refused(KernelError::Provider(
            iteron_provider::ProviderError::Decode(_)
        ))
    ));
    assert!(matches!(
        decision(
            StopReason::Refusal,
            "partial",
            false,
            Some("max_turns"),
            false
        ),
        ModelResponseDecision::Refused(KernelError::Provider(
            iteron_provider::ProviderError::Refusal
        ))
    ));
}

#[test]
fn interrupted_stream_receipt_changes_only_the_explicit_pause_guidance() {
    let ordinary = decision(StopReason::PauseTurn, "partial", false, None, false);
    let recovered = decision(StopReason::PauseTurn, "partial", false, None, true);
    let ModelResponseDecision::Continue {
        notice: ordinary,
        guidance: ordinary_guidance,
    } = ordinary
    else {
        panic!("ordinary pause must continue");
    };
    let ModelResponseDecision::Continue {
        notice: recovered,
        guidance: recovered_guidance,
    } = recovered
    else {
        panic!("recovered pause must continue");
    };
    assert!(!ordinary_guidance.contains("connection"));
    assert!(recovered_guidance.contains("connection"));
    assert_ne!(ordinary.durable, recovered.durable);
    assert!(ordinary.lifecycle.is_none() && recovered.lifecycle.is_none());
    // The same exact generation's recovery latch remains solely in SubmittedTurnState; this
    // response flow does not reset it or invent a second counter for repeated pauses.
    let mut state = SubmittedTurnState::default();
    state.note_stream_recovery();
    let _ = ModelResponseInterpreter {
        submitted: &mut state,
        convergence: &mut InvestigationConvergence::for_general_run(),
        scope: ModelResponseScope {
            exhausted: None,
            interactive: false,
            configured_verifier: false,
            task: "task",
            answer: "partial",
            recovered_stream: true,
        },
    }
    .decide(&StopReason::PauseTurn);
    assert_eq!(state.stream_recoveries(), 1);
}

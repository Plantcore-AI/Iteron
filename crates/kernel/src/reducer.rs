//! The pure reducer: `reduce(state, command) -> (state, action_requests)`.
//!
//! This is the runtime's heart, expressed as a total function over values. It performs no IO, reads
//! no clock, spawns nothing, and names no world module. Every branch the imperative `drive` loop
//! reached by falling through a procedure is an explicit transition here, which is what makes the
//! set of ways a run can end enumerable rather than something you establish by reading 1,100 lines.
//!
//! # The determinism ban, and how it is enforced
//!
//! `SystemTime::now`, `Instant::now`, `rand`, `std::process`, hash-map iteration order and the
//! `core_provider` / `core_sandbox` / `core_ctx` crates are all forbidden in this module. Not by
//! convention — `crate::reducer_tests` scans this file and fails the build if any of them appear.
//! Every external reading enters as a command field, collected by the driver at a defined point.
//!
//! # Why it is total
//!
//! A command that cannot happen in the current phase is a driver bug, and a silent no-op would hide
//! it until a run behaved strangely in production. Such a pair transitions to `HarnessError` with
//! `HarnessFault::ProtocolViolation`, so the loop stops at a safe point and says why.

use crate::turn_action::{ActionRequest, ContinueReason, NoticeKind};
use crate::turn_command::Command;
use crate::turn_protocol::{
    BudgetCeiling, ControlSignal, HarnessFault, ProviderFailure, ProviderTermination, TurnPhase,
    VerifyOutcome,
};
use crate::turn_state::TurnState;
use core_protocol::Outcome;

/// What the driver must do next, in order.
pub type Actions = Vec<ActionRequest>;

/// Fold one command into the turn state.
///
/// Returns the new state and the actions the driver owes the world. Calling it twice with the same
/// inputs returns the same outputs, byte for byte, forever.
pub fn reduce(state: &TurnState, command: Command) -> (TurnState, Actions) {
    // A finished run is absorbing. Late commands are normal — a port can answer after the loop has
    // already decided — and must not disturb a committed outcome.
    if state.is_finished() {
        return (state.clone(), Vec::new());
    }

    match command {
        // ---- always meaningful, whatever the phase ----
        Command::RecordFailed => {
            let mut next = state.clone();
            next.record_healthy = false;
            (
                next.finished(Outcome::HarnessError, Some(HarnessFault::RecordUnhealthy)),
                vec![
                    ActionRequest::Notice {
                        text: NoticeKind::RecordUnhealthy,
                    },
                    ActionRequest::Finish {
                        outcome: Outcome::HarnessError,
                    },
                ],
            )
        }
        Command::UnresolvedEffectsObserved { count } => {
            let mut next = state.clone();
            next.unresolved_effects = count;
            if count == 0 {
                return (next, Vec::new());
            }
            (
                next.finished(Outcome::HarnessError, Some(HarnessFault::UnresolvedEffects)),
                vec![
                    ActionRequest::Notice {
                        text: NoticeKind::UnresolvedEffects,
                    },
                    ActionRequest::Finish {
                        outcome: Outcome::HarnessError,
                    },
                ],
            )
        }
        Command::ControlObserved { signal } => {
            let mut next = state.clone();
            next.control = next.control.latch(signal);
            // Latching only. A stop is *acted on* at a safe point, never wherever the observation
            // happened to land — that is the difference between quiescing and aborting.
            (next, Vec::new())
        }

        // ---- admission ----
        Command::Admitted if state.phase == TurnPhase::Admitting => {
            (state.clone(), vec![ActionRequest::SelectContext])
        }
        Command::ContextResolved if state.phase == TurnPhase::Admitting => {
            let mut next = state.clone();
            next.phase = TurnPhase::Boundary;
            (next, boundary_probe())
        }

        // ---- the turn boundary: the one place a run may stop ----
        Command::BudgetSampled { ceiling } if state.phase == TurnPhase::Boundary => {
            boundary_decision(state, ceiling)
        }

        // ---- a provider turn came back ----
        Command::ProviderCompleted {
            termination,
            tool_calls,
        } if state.phase == TurnPhase::AwaitingProvider => {
            provider_completed(state, termination, tool_calls)
        }
        Command::ProviderFailed { failure } if state.phase == TurnPhase::AwaitingProvider => {
            provider_failed(state, failure)
        }

        // ---- tools finished ----
        Command::ToolsCompleted { any_error } if state.phase == TurnPhase::AwaitingTools => {
            let mut next = state.clone();
            next.consecutive_tool_errors = if any_error {
                next.consecutive_tool_errors.saturating_add(1)
            } else {
                0
            };
            (next_turn(next), advance_and_probe(state.turn))
        }

        // ---- the verifier answered ----
        Command::VerifyCompleted { outcome } if state.phase == TurnPhase::AwaitingVerify => {
            verify_completed(state, outcome)
        }

        // ---- late operator guidance, immediately before committing Done ----
        Command::Steered { count } if state.phase == TurnPhase::Settling => settle(state, count),

        // ---- anything else is a driver protocol error ----
        other => protocol_violation(state, other),
    }
}

/// The two readings every boundary decision needs, in the order the driver must collect them.
fn boundary_probe() -> Actions {
    vec![ActionRequest::ObserveControl, ActionRequest::SampleBudget]
}

/// Close the current turn, open the next, and probe again.
fn advance_and_probe(turn: u32) -> Actions {
    let mut actions = vec![ActionRequest::AdvanceTurn { turn }];
    actions.extend(boundary_probe());
    actions
}

/// Move to the next turn at the boundary phase.
fn next_turn(mut state: TurnState) -> TurnState {
    state.turn = state.turn.saturating_add(1);
    state.phase = TurnPhase::Boundary;
    state
}

/// Every way a run may stop, evaluated in one place and in a fixed order.
///
/// The order is the contract, not an accident. A broken record outranks everything because nothing
/// downstream can be trusted once the audit trail has a hole. A drain outranks a budget ceiling
/// because the operator asked for a checkpoint and a ceiling would exit without one.
fn boundary_decision(state: &TurnState, ceiling: Option<BudgetCeiling>) -> (TurnState, Actions) {
    let next = state.clone();

    if !next.record_healthy {
        return finish_with(
            next,
            Outcome::HarnessError,
            Some(HarnessFault::RecordUnhealthy),
            Some(NoticeKind::RecordUnhealthy),
        );
    }
    if next.unresolved_effects > 0 {
        return finish_with(
            next,
            Outcome::HarnessError,
            Some(HarnessFault::UnresolvedEffects),
            Some(NoticeKind::UnresolvedEffects),
        );
    }
    match next.control {
        ControlSignal::Drain => {
            // Drain is the only path that owes a durable workspace checkpoint before the terminal.
            let turn = next.turn;
            let mut finished = next.finished(Outcome::Drained, None);
            finished.control = ControlSignal::Drain;
            return (
                finished,
                vec![
                    ActionRequest::Checkpoint { turn },
                    ActionRequest::Finish {
                        outcome: Outcome::Drained,
                    },
                ],
            );
        }
        ControlSignal::Interrupt => {
            return finish_with(next, Outcome::Interrupted, None, None);
        }
        ControlSignal::None => {}
    }
    if let Some(ceiling) = ceiling {
        return finish_with(next, Outcome::BudgetExhausted(ceiling.reason()), None, None);
    }
    if next.turn_ceiling_reached() {
        return finish_with(
            next,
            Outcome::BudgetExhausted(BudgetCeiling::MaxTurns.reason()),
            None,
            None,
        );
    }
    if next.stuck() {
        return finish_with(next, Outcome::Stuck, None, None);
    }

    let turn = next.turn;
    let mut running = next;
    running.phase = TurnPhase::AwaitingProvider;
    (running, vec![ActionRequest::CallProvider { turn }])
}

fn provider_completed(
    state: &TurnState,
    termination: ProviderTermination,
    tool_calls: u32,
) -> (TurnState, Actions) {
    let mut next = state.clone();
    // A turn that reached a terminal is a turn spent, whatever the terminal says.
    next.completed_turns = next.completed_turns.saturating_add(1);

    if tool_calls > 0 {
        // The imperative loop refused a transcript whose terminal disagreed with its tool calls,
        // because a provider adapter could otherwise execute one projection and commit another.
        if termination != ProviderTermination::ToolUse {
            return undecodable(next);
        }
        next.phase = TurnPhase::AwaitingTools;
        let turn = next.turn;
        return (
            next,
            vec![ActionRequest::DispatchTools {
                turn,
                calls: tool_calls,
            }],
        );
    }

    match termination {
        // The model answered. Ask the gate if there is one, then check for late guidance.
        ProviderTermination::EndTurn => {
            if next.verify_gate {
                let turn = next.turn;
                let attempt = next.verify_attempts;
                next.phase = TurnPhase::AwaitingVerify;
                (next, vec![ActionRequest::RunVerify { turn, attempt }])
            } else {
                let turn = next.turn;
                next.phase = TurnPhase::Settling;
                (next, vec![ActionRequest::AdmitSteers { turn }])
            }
        }
        ProviderTermination::MaxTokens => continue_turn(
            next,
            NoticeKind::MaxTokensContinuation,
            ContinueReason::MaxTokens,
        ),
        ProviderTermination::PauseTurn => continue_turn(
            next,
            NoticeKind::ProviderPausedContinuation,
            ContinueReason::ProviderPaused,
        ),
        // A tool_use terminal with no complete tool call, an unsolicited stop sequence, a refusal
        // and an unrecognised code are all terminals the kernel has no safe next step for.
        ProviderTermination::ToolUse
        | ProviderTermination::StopSequence
        | ProviderTermination::Refusal
        | ProviderTermination::Unknown => undecodable(next),
    }
}

fn provider_failed(state: &TurnState, failure: ProviderFailure) -> (TurnState, Actions) {
    let next = state.clone();
    match failure {
        ProviderFailure::DeadlineExceeded => finish_with(
            next,
            Outcome::BudgetExhausted(BudgetCeiling::MaxWallSecs.reason()),
            None,
            None,
        ),
        ProviderFailure::Interrupted => finish_with(next, Outcome::Interrupted, None, None),
        ProviderFailure::Rejected | ProviderFailure::Unobservable => undecodable(next),
    }
}

fn verify_completed(state: &TurnState, outcome: VerifyOutcome) -> (TurnState, Actions) {
    let mut next = state.clone();
    match outcome {
        VerifyOutcome::Pass => {
            let turn = next.turn;
            next.phase = TurnPhase::Settling;
            (
                next,
                vec![
                    ActionRequest::Notice {
                        text: NoticeKind::VerifyPassed,
                    },
                    ActionRequest::AdmitSteers { turn },
                ],
            )
        }
        VerifyOutcome::TestFailure => {
            // Only a graded failure consumes an attempt. A timeout or a cancellation proves nothing
            // about the candidate, so charging it a retry would spend the budget on infrastructure.
            next.verify_attempts = next.verify_attempts.saturating_add(1);
            if next.verify_ceiling_reached() {
                let mut actions = vec![ActionRequest::Notice {
                    text: NoticeKind::VerifyCeilingReached,
                }];
                let (finished, finish_actions) = finish_with(
                    next,
                    Outcome::BudgetExhausted("verify_attempts"),
                    None,
                    None,
                );
                actions.extend(finish_actions);
                return (finished, actions);
            }
            let mut actions = vec![ActionRequest::Notice {
                text: NoticeKind::VerifyTestFailure,
            }];
            let (state, continue_actions) =
                continue_turn_without_notice(next, ContinueReason::VerifyFeedback);
            actions.extend(continue_actions);
            (state, actions)
        }
        VerifyOutcome::TimedOut => {
            let mut actions = vec![ActionRequest::Notice {
                text: NoticeKind::VerifyTimedOut,
            }];
            let (finished, finish_actions) = finish_with(
                next,
                Outcome::BudgetExhausted(BudgetCeiling::MaxWallSecs.reason()),
                None,
                None,
            );
            actions.extend(finish_actions);
            (finished, actions)
        }
        VerifyOutcome::InfrastructureFailure => {
            let mut actions = vec![ActionRequest::Notice {
                text: NoticeKind::VerifyInfrastructureFailure,
            }];
            let (finished, finish_actions) = finish_with(
                next,
                Outcome::HarnessError,
                Some(HarnessFault::VerifierUnusable),
                None,
            );
            actions.extend(finish_actions);
            (finished, actions)
        }
        VerifyOutcome::Cancelled => {
            let mut actions = vec![ActionRequest::Notice {
                text: NoticeKind::VerifyCancelled,
            }];
            let (finished, finish_actions) = finish_with(next, Outcome::Interrupted, None, None);
            actions.extend(finish_actions);
            (finished, actions)
        }
    }
}

/// The model says it is done. Commit that only if the operator has not just said something.
fn settle(state: &TurnState, steered: u32) -> (TurnState, Actions) {
    let next = state.clone();
    // A stop observed while the oracle was running still wins here; the run is stopping either way,
    // and Drain still owes its checkpoint.
    match next.control {
        ControlSignal::Drain => {
            let turn = next.turn;
            let finished = next.finished(Outcome::Drained, None);
            return (
                finished,
                vec![
                    ActionRequest::Checkpoint { turn },
                    ActionRequest::Finish {
                        outcome: Outcome::Drained,
                    },
                ],
            );
        }
        ControlSignal::Interrupt => return finish_with(next, Outcome::Interrupted, None, None),
        ControlSignal::None => {}
    }
    if steered > 0 {
        return continue_turn_without_notice(next, ContinueReason::Steered);
    }
    finish_with(next, Outcome::Done, None, None)
}

fn continue_turn(
    state: TurnState,
    notice: NoticeKind,
    reason: ContinueReason,
) -> (TurnState, Actions) {
    let mut actions = vec![ActionRequest::Notice { text: notice }];
    let (state, continue_actions) = continue_turn_without_notice(state, reason);
    actions.extend(continue_actions);
    (state, actions)
}

fn continue_turn_without_notice(state: TurnState, reason: ContinueReason) -> (TurnState, Actions) {
    let turn = state.turn;
    let mut actions = vec![ActionRequest::Continue { turn, reason }];
    actions.extend(advance_and_probe(turn));
    (next_turn(state), actions)
}

fn undecodable(state: TurnState) -> (TurnState, Actions) {
    finish_with(
        state,
        Outcome::HarnessError,
        Some(HarnessFault::UndecodableTurn),
        None,
    )
}

fn protocol_violation(state: &TurnState, command: Command) -> (TurnState, Actions) {
    // Deliberately loud. The alternative — ignoring the command — turns a driver bug into a run
    // that hangs or silently skips a step, which is the failure mode this whole split exists to
    // make impossible.
    let _ = command;
    finish_with(
        state.clone(),
        Outcome::HarnessError,
        Some(HarnessFault::ProtocolViolation),
        None,
    )
}

fn finish_with(
    state: TurnState,
    outcome: Outcome,
    fault: Option<HarnessFault>,
    notice: Option<NoticeKind>,
) -> (TurnState, Actions) {
    let mut actions = Vec::new();
    if let Some(text) = notice {
        actions.push(ActionRequest::Notice { text });
    }
    actions.push(ActionRequest::Finish {
        outcome: outcome.clone(),
    });
    (state.finished(outcome, fault), actions)
}

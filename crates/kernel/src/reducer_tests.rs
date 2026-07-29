//! Conformance for the pure reducer (#15).
//!
//! Four claims, each failing differently:
//!
//! 1. **It is pure.** A source gate over the reducer and its vocabulary refuses the determinism
//!    ban — no clock, no RNG, no process, no hash-map iteration order, no world crate.
//! 2. **It is reproducible.** The same command stream produces a byte-identical action-request
//!    sequence, compared on the serialised bytes rather than on `PartialEq`.
//! 3. **Every stop is a transition.** A table enumerates each way a run can end and asserts the
//!    reducer reaches it explicitly.
//! 4. **A broken record makes zero provider calls.** The invariant the imperative loop's
//!    `drive_turn_intent_append_failure_makes_zero_provider_calls` encoded, re-expressed against
//!    the split: it is now a property of the action sequence, not of a mock's call count.

use crate::reducer::reduce;
use crate::turn_action::ActionRequest;
use crate::turn_command::Command;
use crate::turn_protocol::{
    BudgetCeiling, ControlSignal, HarnessFault, ProviderFailure, ProviderTermination, TurnPhase,
    VerifyOutcome,
};
use crate::turn_state::{TurnLimits, TurnState};
use core_protocol::Outcome;
use std::collections::BTreeSet;

/// Fold a whole command stream, collecting every action in order.
fn drive(mut state: TurnState, commands: &[Command]) -> (TurnState, Vec<ActionRequest>) {
    let mut actions = Vec::new();
    for command in commands {
        let (next, produced) = reduce(&state, command.clone());
        state = next;
        actions.extend(produced);
    }
    (state, actions)
}

fn wire(actions: &[ActionRequest]) -> String {
    serde_json::to_string(actions).expect("action sequences serialise")
}

// ---------------------------------------------------------------------------------------------
// 1. Purity
// ---------------------------------------------------------------------------------------------

/// The modules that together are "the reducer": the fold and the closed vocabulary it folds over.
const REDUCER_SOURCES: &[&str] = &[
    "src/reducer.rs",
    "src/turn_state.rs",
    "src/turn_command.rs",
    "src/turn_action.rs",
    "src/turn_protocol.rs",
];

/// What a pure reducer may not name. The first six are issue #15's list verbatim; the rest are the
/// same argument applied to the other obvious doors out of a pure function.
const BANNED: &[(&str, &str)] = &[
    (
        "SystemTime::now",
        "a wall clock reading must arrive as a command field",
    ),
    (
        "Instant::now",
        "a monotonic clock reading must arrive as a command field",
    ),
    ("core_provider", "the reducer must not name a world module"),
    ("core_sandbox", "the reducer must not name a world module"),
    ("core_ctx", "the reducer must not name a world module"),
    (
        "std::process",
        "the reducer must not start or inspect a process",
    ),
    (
        "HashMap",
        "hash-map iteration order is not reproducible; use a BTreeMap",
    ),
    (
        "HashSet",
        "hash-set iteration order is not reproducible; use a BTreeSet",
    ),
    ("std::fs", "the reducer must not touch the filesystem"),
    ("std::env", "the reducer must not read the environment"),
    ("tokio::", "the reducer must not await anything"),
];

/// Source lines with comments and doc comments removed.
///
/// The ban is on what the code *names*, not on what the prose *explains* — this module's own
/// documentation discusses `Instant::now` at length, and a gate that could not tell the two apart
/// would force the reasoning out of the file that most needs it.
fn code_lines(source: &str) -> Vec<(usize, String)> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(index, line)| {
            let code = match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            };
            (index + 1, code.to_string())
        })
        .collect()
}

#[test]
fn the_reducer_names_nothing_that_could_make_it_irreproducible() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for relative in REDUCER_SOURCES {
        let source = std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("reducer source {relative} must be readable: {error}"));
        for (number, line) in code_lines(&source) {
            for (needle, why) in BANNED {
                if line.contains(needle) {
                    violations.push(format!("{relative}:{number} names `{needle}` — {why}"));
                }
            }
            // `rand` as a bare word, so `rand::random` is caught while an identifier that merely
            // contains the letters is not.
            for token in line.split(|c: char| !c.is_alphanumeric() && c != '_') {
                if token == "rand" {
                    violations.push(format!(
                        "{relative}:{number} names `rand` — a reducer may not sample randomness"
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "the reducer broke the determinism ban:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_purity_gate_would_actually_catch_a_violation() {
    // A gate nobody has seen fail is a gate nobody knows works. This proves the scanner reacts to
    // the real thing while ignoring the prose around it.
    let offending = "fn f() { let t = std::time::Instant::now(); }";
    assert!(
        code_lines(offending)
            .iter()
            .any(|(_, line)| line.contains("Instant::now"))
    );
    let prose = "//! We deliberately never call Instant::now here.";
    assert!(
        !code_lines(prose)
            .iter()
            .any(|(_, line)| line.contains("Instant::now")),
        "documentation that explains the ban must not trip it"
    );
    let trailing = "let x = 1; // Instant::now would be wrong here";
    assert!(
        !code_lines(trailing)
            .iter()
            .any(|(_, line)| line.contains("Instant::now")),
        "a trailing comment must not trip the gate either"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. Byte-identical replay
// ---------------------------------------------------------------------------------------------

/// A command stream that walks a whole run: context, a tool turn, a continuation, a verify failure,
/// a verify pass, and a late steer.
fn recorded_stream() -> Vec<Command> {
    vec![
        Command::Admitted,
        Command::ContextResolved,
        Command::ControlObserved {
            signal: ControlSignal::None,
        },
        Command::BudgetSampled { ceiling: None },
        Command::ProviderCompleted {
            termination: ProviderTermination::ToolUse,
            tool_calls: 2,
        },
        Command::ToolsCompleted { any_error: false },
        Command::ControlObserved {
            signal: ControlSignal::None,
        },
        Command::BudgetSampled { ceiling: None },
        Command::ProviderCompleted {
            termination: ProviderTermination::MaxTokens,
            tool_calls: 0,
        },
        Command::ControlObserved {
            signal: ControlSignal::None,
        },
        Command::BudgetSampled { ceiling: None },
        Command::ProviderCompleted {
            termination: ProviderTermination::EndTurn,
            tool_calls: 0,
        },
        Command::VerifyCompleted {
            outcome: VerifyOutcome::TestFailure,
        },
        Command::ControlObserved {
            signal: ControlSignal::None,
        },
        Command::BudgetSampled { ceiling: None },
        Command::ProviderCompleted {
            termination: ProviderTermination::EndTurn,
            tool_calls: 0,
        },
        Command::VerifyCompleted {
            outcome: VerifyOutcome::Pass,
        },
        Command::Steered { count: 0 },
    ]
}

#[test]
fn replaying_a_command_stream_produces_a_byte_identical_action_sequence() {
    let limits = TurnLimits {
        max_turns: 16,
        ..TurnLimits::default()
    };
    let stream = recorded_stream();

    let (first_state, first_actions) = drive(TurnState::new(limits, true), &stream);
    let (second_state, second_actions) = drive(TurnState::new(limits, true), &stream);

    let first = wire(&first_actions);
    let second = wire(&second_actions);
    assert_eq!(
        first, second,
        "the same command stream must produce byte-identical action requests"
    );
    assert_eq!(
        serde_json::to_string(&first_state).unwrap(),
        serde_json::to_string(&second_state).unwrap(),
        "the same command stream must produce a byte-identical final state"
    );
    assert_eq!(first_state.outcome, Some(Outcome::Done));
    assert!(
        first_actions.len() > 20,
        "the replay corpus must actually exercise the loop, not a single transition"
    );
}

#[test]
fn replay_is_stable_across_an_independent_fold_order_of_the_same_stream() {
    // Replaying one command at a time from a cloned state must equal replaying the whole stream:
    // the fold has no hidden accumulator outside `TurnState`.
    let limits = TurnLimits {
        max_turns: 16,
        ..TurnLimits::default()
    };
    let stream = recorded_stream();
    let (_, whole) = drive(TurnState::new(limits, true), &stream);

    let mut state = TurnState::new(limits, true);
    let mut piecewise = Vec::new();
    for command in &stream {
        let snapshot = state.clone();
        let (next, actions) = reduce(&snapshot, command.clone());
        state = next;
        piecewise.extend(actions);
    }
    assert_eq!(wire(&whole), wire(&piecewise));
}

// ---------------------------------------------------------------------------------------------
// 3. The state-transition table
// ---------------------------------------------------------------------------------------------

/// Reach the point where a provider turn is in flight.
fn awaiting_provider(limits: TurnLimits, verify_gate: bool) -> TurnState {
    let (state, _) = drive(
        TurnState::new(limits, verify_gate),
        &[
            Command::Admitted,
            Command::ContextResolved,
            Command::ControlObserved {
                signal: ControlSignal::None,
            },
            Command::BudgetSampled { ceiling: None },
        ],
    );
    assert_eq!(state.phase, TurnPhase::AwaitingProvider);
    state
}

struct TransitionCase {
    name: &'static str,
    state: TurnState,
    commands: Vec<Command>,
    outcome: Outcome,
    fault: Option<HarnessFault>,
}

fn transition_table() -> Vec<TransitionCase> {
    let limits = TurnLimits {
        max_turns: 4,
        max_consecutive_tool_errors: 2,
        max_verify_attempts: 2,
    };
    let boundary = |verify_gate: bool| {
        let (state, _) = drive(
            TurnState::new(limits, verify_gate),
            &[Command::Admitted, Command::ContextResolved],
        );
        state
    };

    vec![
        TransitionCase {
            name: "the model answered and nothing was queued behind it",
            state: awaiting_provider(limits, false),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::EndTurn,
                    tool_calls: 0,
                },
                Command::Steered { count: 0 },
            ],
            outcome: Outcome::Done,
            fault: None,
        },
        TransitionCase {
            name: "a sampled cost ceiling stops the run at the boundary",
            state: boundary(false),
            commands: vec![
                Command::ControlObserved {
                    signal: ControlSignal::None,
                },
                Command::BudgetSampled {
                    ceiling: Some(BudgetCeiling::MaxUsd),
                },
            ],
            outcome: Outcome::BudgetExhausted("max_usd"),
            fault: None,
        },
        TransitionCase {
            name: "the wall-clock deadline is reached while the stream is in flight",
            state: awaiting_provider(limits, false),
            commands: vec![Command::ProviderFailed {
                failure: ProviderFailure::DeadlineExceeded,
            }],
            outcome: Outcome::BudgetExhausted("max_wall_secs"),
            fault: None,
        },
        TransitionCase {
            name: "the operator interrupts while the stream is in flight",
            state: awaiting_provider(limits, false),
            commands: vec![Command::ProviderFailed {
                failure: ProviderFailure::Interrupted,
            }],
            outcome: Outcome::Interrupted,
            fault: None,
        },
        TransitionCase {
            name: "an interrupt observed earlier is acted on at the next boundary",
            state: boundary(false),
            commands: vec![
                Command::ControlObserved {
                    signal: ControlSignal::Interrupt,
                },
                Command::BudgetSampled { ceiling: None },
            ],
            outcome: Outcome::Interrupted,
            fault: None,
        },
        TransitionCase {
            name: "a drain checkpoints before it stops",
            state: boundary(false),
            commands: vec![
                Command::ControlObserved {
                    signal: ControlSignal::Drain,
                },
                Command::BudgetSampled { ceiling: None },
            ],
            outcome: Outcome::Drained,
            fault: None,
        },
        TransitionCase {
            name: "the stability floor trips after repeated tool errors",
            state: awaiting_provider(limits, false),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::ToolUse,
                    tool_calls: 1,
                },
                Command::ToolsCompleted { any_error: true },
                Command::ControlObserved {
                    signal: ControlSignal::None,
                },
                Command::BudgetSampled { ceiling: None },
                Command::ProviderCompleted {
                    termination: ProviderTermination::ToolUse,
                    tool_calls: 1,
                },
                Command::ToolsCompleted { any_error: true },
                Command::ControlObserved {
                    signal: ControlSignal::None,
                },
                Command::BudgetSampled { ceiling: None },
            ],
            outcome: Outcome::Stuck,
            fault: None,
        },
        TransitionCase {
            name: "the verification gate stops asking after its ceiling",
            state: awaiting_provider(limits, true),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::EndTurn,
                    tool_calls: 0,
                },
                Command::VerifyCompleted {
                    outcome: VerifyOutcome::TestFailure,
                },
                Command::ControlObserved {
                    signal: ControlSignal::None,
                },
                Command::BudgetSampled { ceiling: None },
                Command::ProviderCompleted {
                    termination: ProviderTermination::EndTurn,
                    tool_calls: 0,
                },
                Command::VerifyCompleted {
                    outcome: VerifyOutcome::TestFailure,
                },
            ],
            outcome: Outcome::BudgetExhausted("verify_attempts"),
            fault: None,
        },
        TransitionCase {
            name: "a cancelled verification stops at a resumable safe point",
            state: awaiting_provider(limits, true),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::EndTurn,
                    tool_calls: 0,
                },
                Command::VerifyCompleted {
                    outcome: VerifyOutcome::Cancelled,
                },
            ],
            outcome: Outcome::Interrupted,
            fault: None,
        },
        TransitionCase {
            name: "a verifier that cannot run is a harness fault, not a failed gate",
            state: awaiting_provider(limits, true),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::EndTurn,
                    tool_calls: 0,
                },
                Command::VerifyCompleted {
                    outcome: VerifyOutcome::InfrastructureFailure,
                },
            ],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::VerifierUnusable),
        },
        TransitionCase {
            name: "a broken durable record halts the run wherever it is noticed",
            state: awaiting_provider(limits, false),
            commands: vec![Command::RecordFailed],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::RecordUnhealthy),
        },
        TransitionCase {
            name: "recovery found effects nobody can prove a terminal for",
            state: boundary(false),
            commands: vec![Command::UnresolvedEffectsObserved { count: 2 }],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::UnresolvedEffects),
        },
        TransitionCase {
            name: "a terminal the kernel has no safe next step for",
            state: awaiting_provider(limits, false),
            commands: vec![Command::ProviderCompleted {
                termination: ProviderTermination::Refusal,
                tool_calls: 0,
            }],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::UndecodableTurn),
        },
        TransitionCase {
            name: "tool calls arriving under a non-tool terminal",
            state: awaiting_provider(limits, false),
            commands: vec![Command::ProviderCompleted {
                termination: ProviderTermination::EndTurn,
                tool_calls: 3,
            }],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::UndecodableTurn),
        },
        TransitionCase {
            name: "a command the phase cannot accept is a driver bug, stated loudly",
            state: awaiting_provider(limits, false),
            commands: vec![Command::ToolsCompleted { any_error: false }],
            outcome: Outcome::HarnessError,
            fault: Some(HarnessFault::ProtocolViolation),
        },
        TransitionCase {
            name: "the turn ceiling is judged on completed turns",
            state: awaiting_provider(
                TurnLimits {
                    max_turns: 1,
                    ..limits
                },
                false,
            ),
            commands: vec![
                Command::ProviderCompleted {
                    termination: ProviderTermination::MaxTokens,
                    tool_calls: 0,
                },
                Command::ControlObserved {
                    signal: ControlSignal::None,
                },
                Command::BudgetSampled { ceiling: None },
            ],
            outcome: Outcome::BudgetExhausted("max_turns"),
            fault: None,
        },
    ]
}

#[test]
fn every_way_a_run_can_end_is_an_explicit_transition() {
    let mut reached = BTreeSet::new();
    for case in transition_table() {
        let (state, actions) = drive(case.state.clone(), &case.commands);
        assert_eq!(
            state.outcome.as_ref(),
            Some(&case.outcome),
            "case `{}` did not reach its outcome",
            case.name
        );
        assert_eq!(state.fault, case.fault, "case `{}` fault", case.name);
        assert_eq!(
            state.phase,
            TurnPhase::Finished,
            "case `{}` must be terminal",
            case.name
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, ActionRequest::Finish { .. })),
            "case `{}` must ask the driver to finish",
            case.name
        );
        reached.insert(format!("{:?}", case.outcome));
    }

    // Every variant of the frozen `Outcome` must be reachable. A stop condition nothing can reach
    // is a stop condition nobody is testing.
    let expected: BTreeSet<String> = [
        Outcome::Done,
        Outcome::Drained,
        Outcome::Interrupted,
        Outcome::Stuck,
        Outcome::HarnessError,
        Outcome::BudgetExhausted("max_usd"),
        Outcome::BudgetExhausted("max_wall_secs"),
        Outcome::BudgetExhausted("max_turns"),
        Outcome::BudgetExhausted("verify_attempts"),
    ]
    .iter()
    .map(|outcome| format!("{outcome:?}"))
    .collect();
    assert_eq!(reached, expected, "the transition table lost coverage");
}

#[test]
fn a_drain_is_the_only_terminal_that_checkpoints() {
    for case in transition_table() {
        let (_, actions) = drive(case.state.clone(), &case.commands);
        let checkpoints = actions
            .iter()
            .filter(|action| matches!(action, ActionRequest::Checkpoint { .. }))
            .count();
        let expected = usize::from(case.outcome == Outcome::Drained);
        assert_eq!(
            checkpoints, expected,
            "case `{}` produced {checkpoints} checkpoints",
            case.name
        );
    }
}

#[test]
fn nothing_is_asked_of_the_world_after_the_run_is_finished() {
    for case in transition_table() {
        let (state, _) = drive(case.state.clone(), &case.commands);
        // Every command, including ones that would normally dispatch, must be inert now.
        for command in [
            Command::ContextResolved,
            Command::BudgetSampled { ceiling: None },
            Command::ProviderCompleted {
                termination: ProviderTermination::EndTurn,
                tool_calls: 0,
            },
            Command::ToolsCompleted { any_error: false },
            Command::RecordFailed,
        ] {
            let (after, actions) = reduce(&state, command.clone());
            assert!(
                actions.is_empty(),
                "case `{}` asked for {:?} after finishing",
                case.name,
                actions
            );
            assert_eq!(
                serde_json::to_string(&after).unwrap(),
                serde_json::to_string(&state).unwrap(),
                "case `{}` changed state after finishing on {}",
                case.name,
                command.label()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 4. The invariant the imperative loop encoded
// ---------------------------------------------------------------------------------------------

#[test]
fn a_second_admission_is_refused_rather_than_resolving_context_twice() {
    // `SelectContext` is routed to a port that appends durably. A duplicate admission that produced
    // a second one would put a context resolution on the record that never happened once.
    let (state, actions) = drive(
        TurnState::new(TurnLimits::default(), false),
        &[Command::Admitted, Command::Admitted],
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, ActionRequest::SelectContext))
            .count(),
        1,
        "context must be resolved exactly once, whatever the operator submits"
    );
    assert_eq!(state.fault, Some(HarnessFault::ProtocolViolation));
}

#[test]
fn a_run_whose_record_cannot_be_written_makes_zero_provider_calls() {
    // The imperative form asserted a mock provider saw no requests. The split states it more
    // strongly: no `CallProvider` is ever *asked for*, so the property holds for every port
    // implementation rather than for the one the test happened to inject.
    let limits = TurnLimits::default();
    let streams: [Vec<Command>; 2] = [
        // The record breaks before the loop ever reaches a boundary.
        vec![
            Command::Admitted,
            Command::RecordFailed,
            Command::ContextResolved,
            Command::ControlObserved {
                signal: ControlSignal::None,
            },
            Command::BudgetSampled { ceiling: None },
        ],
        // The record is already known-bad when the boundary is evaluated.
        vec![
            Command::Admitted,
            Command::ContextResolved,
            Command::RecordFailed,
            Command::ControlObserved {
                signal: ControlSignal::None,
            },
            Command::BudgetSampled { ceiling: None },
        ],
    ];

    for stream in streams {
        let (state, actions) = drive(TurnState::new(limits, false), &stream);
        assert_eq!(state.outcome, Some(Outcome::HarnessError));
        assert_eq!(state.fault, Some(HarnessFault::RecordUnhealthy));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, ActionRequest::CallProvider { .. })),
            "a run with a broken audit record must not ask for a provider turn: {actions:?}"
        );
        assert!(
            !actions.iter().any(ActionRequest::is_effecting),
            "a run with a broken audit record must ask for no effect at all: {actions:?}"
        );
    }
}

#[test]
fn a_stopping_run_asks_for_no_effect_other_than_the_drain_checkpoint() {
    for case in transition_table() {
        let (_, actions) = drive(case.state.clone(), &case.commands);
        let after_finish: Vec<&ActionRequest> = actions
            .iter()
            .skip_while(|action| !matches!(action, ActionRequest::Finish { .. }))
            .skip(1)
            .collect();
        assert!(
            after_finish.is_empty(),
            "case `{}` emitted {after_finish:?} after Finish",
            case.name
        );
    }
}

//! Conformance for the universal effect boundary (#16).
//!
//! Three separate claims are proved here, because they fail in different ways:
//!
//! 1. **Every class crosses the same sequence.** For each of the seven effect classes, a fsynced
//!    `EffectIntent` is appended before the executor runs and exactly one terminal after it.
//! 2. **Nothing bypasses it.** A source-level gate over the kernel's production code asserts that
//!    every effect-dispatch primitive appears only inside the function the boundary sanctions. This
//!    is the check that catches the *next* effect somebody adds, which no runtime test can.
//! 3. **What cannot be proven is never replayed.** A dispatch killed between intent and terminal
//!    resumes as `EffectUnknown` with zero re-executions.

use crate::effect_admission::{EffectAdmissionError, EffectAdmissions};
use crate::effect_class::{EffectClass, effect_id, harness_correlation_id};
use crate::effect_journal::EffectJournal;
use crate::effects::{
    BrokerError, BrokeredEffect, BrokeredOutcome, DurableEffectLog, EffectDisposition, Settlement,
    broker_effect, open_effect, settle_effect,
};
use core_protocol::{Capability, Event, EventKind, Seq, TurnId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A durable log that records what it was asked to append and can be told to fail one append,
/// standing in for an fsync failure at an exact position in the sequence.
#[derive(Default)]
struct ProbeLog {
    events: Vec<Event>,
    fail_on_append: Option<usize>,
    appends: usize,
}

impl DurableEffectLog for ProbeLog {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, core_record::RecordError> {
        let index = self.appends;
        self.appends += 1;
        if self.fail_on_append == Some(index) {
            return Err(core_record::RecordError::Io(std::io::Error::other(
                "probe: durable append refused",
            )));
        }
        self.events.push(event.clone());
        Ok(Seq::ZERO)
    }
}

fn effect_for(turn: TurnId, class: EffectClass, ordinal: usize) -> BrokeredEffect {
    BrokeredEffect {
        turn,
        effect_id: effect_id(turn, class, ordinal),
        tool_use_id: match class {
            // A registry tool carries the provider's own correlation id; every harness class mints
            // one in its reserved namespace.
            EffectClass::RegistryTool => format!("call-{ordinal}"),
            other => harness_correlation_id(turn, other, ordinal),
        },
        kind: class.label().unwrap_or("edit").to_string(),
        capability: Capability::ReversibleLocal,
        audit_arguments: serde_json::json!({ "probe": ordinal }),
        workspace: "/repo".to_string(),
    }
}

#[tokio::test]
async fn every_effect_class_crosses_intent_then_executor_then_exactly_one_terminal() {
    for (index, class) in EffectClass::ALL.into_iter().enumerate() {
        let turn = TurnId(1);
        let mut log = ProbeLog::default();
        let mut admissions = EffectAdmissions::default();
        let effect = effect_for(turn, class, index);
        let id = effect.effect_id.clone();
        // Records the log length the executor observed, which is the only way to prove ordering
        // rather than merely asserting on the events afterwards.
        let seen_before_execute = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = seen_before_execute.clone();
        let terminal = EventKind::EffectDone {
            id: id.clone(),
            tool: class.label().unwrap_or("edit").to_string(),
        };

        let outcome: BrokeredOutcome<()> =
            broker_effect(&mut log, &mut admissions, effect, move || {
                let observer = observer.clone();
                async move {
                    observer.store(1, Ordering::SeqCst);
                    EffectDisposition::Definite {
                        terminal,
                        value: (),
                    }
                }
            })
            .await
            .unwrap_or_else(|error| panic!("{class:?} must cross the boundary cleanly: {error}"));
        assert!(
            matches!(outcome, BrokeredOutcome::Definite(())),
            "{class:?} proved a terminal, so it must not be reported unknown"
        );
        assert_eq!(
            seen_before_execute.load(Ordering::SeqCst),
            1,
            "{class:?} executor must have run"
        );

        assert_eq!(
            log.events.len(),
            2,
            "{class:?} must record exactly two events"
        );
        match &log.events[0].kind {
            EventKind::EffectIntent {
                id: intent_id,
                tool,
                ..
            } => {
                assert_eq!(intent_id, &id, "{class:?} intent must carry its identity");
                assert_eq!(
                    tool,
                    class.label().unwrap_or("edit"),
                    "{class:?} intent must record its durable kind"
                );
            }
            other => panic!("{class:?} must write its intent first, got {other:?}"),
        }
        assert!(
            matches!(&log.events[1].kind, EventKind::EffectDone { id: done, .. } if done == &id),
            "{class:?} must write exactly one terminal, correlated to its intent"
        );

        // The same events, folded by the pure journal, agree: nothing pending, nothing unknown.
        let journal = EffectJournal::replay(&log.events).expect("journal folds the probe log");
        assert!(
            journal.pending().is_empty(),
            "{class:?} left a pending intent"
        );
        assert_eq!(
            journal.unknown_count(),
            0,
            "{class:?} left an unknown effect"
        );
    }
}

#[tokio::test]
async fn a_failed_intent_append_never_enters_the_executor() {
    for (index, class) in EffectClass::ALL.into_iter().enumerate() {
        let mut log = ProbeLog {
            fail_on_append: Some(0),
            ..ProbeLog::default()
        };
        let mut admissions = EffectAdmissions::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let result: Result<BrokeredOutcome<()>, BrokerError> = broker_effect(
            &mut log,
            &mut admissions,
            effect_for(TurnId(2), class, index),
            move || {
                let executor_calls = executor_calls.clone();
                async move {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    EffectDisposition::Definite {
                        terminal: EventKind::Notice {
                            text: "unreachable".into(),
                        },
                        value: (),
                    }
                }
            },
        )
        .await;
        assert!(
            matches!(result, Err(BrokerError::Record(_))),
            "{class:?}: a refused fsync must fail the effect as a record error"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{class:?}: the executor must never run without a durable intent"
        );
        assert!(
            log.events.is_empty(),
            "{class:?}: a refused intent leaves nothing on the log"
        );
    }
}

#[tokio::test]
async fn a_duplicate_effect_identity_is_refused_before_the_executor() {
    let turn = TurnId(3);
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let calls = Arc::new(AtomicUsize::new(0));

    for attempt in 0..2 {
        let executor_calls = calls.clone();
        let effect = effect_for(turn, EffectClass::Subagent, 0);
        let terminal = EventKind::EffectDone {
            id: effect.effect_id.clone(),
            tool: "subagent".into(),
        };
        let result: Result<BrokeredOutcome<()>, BrokerError> =
            broker_effect(&mut log, &mut admissions, effect, move || {
                let executor_calls = executor_calls.clone();
                async move {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    EffectDisposition::Definite {
                        terminal,
                        value: (),
                    }
                }
            })
            .await;
        if attempt == 0 {
            assert!(result.is_ok(), "the first submission is admitted");
        } else {
            assert!(
                matches!(
                    result,
                    Err(BrokerError::Admission(EffectAdmissionError::Duplicate(_)))
                ),
                "the second submission of one identity must be refused"
            );
        }
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "at-most-once means the executor runs once, not twice"
    );
    assert_eq!(
        log.events.len(),
        2,
        "a refused duplicate must not append a second intent"
    );
}

#[tokio::test]
async fn a_proposal_that_cannot_be_recorded_honestly_is_refused_before_the_log() {
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let mut effect = effect_for(TurnId(4), EffectClass::Checkpoint, 0);
    // The exact hole `EffectProposal::validate` exists to close: a new record whose correlation id
    // is empty becomes completable by a model-chosen tool id of the (fully predictable) effect-id
    // shape.
    effect.tool_use_id = String::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = calls.clone();
    let result: Result<BrokeredOutcome<()>, BrokerError> =
        broker_effect(&mut log, &mut admissions, effect, move || {
            let executor_calls = executor_calls.clone();
            async move {
                executor_calls.fetch_add(1, Ordering::SeqCst);
                EffectDisposition::Definite {
                    terminal: EventKind::Notice {
                        text: "unreachable".into(),
                    },
                    value: (),
                }
            }
        })
        .await;
    assert!(matches!(result, Err(BrokerError::Proposal(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(log.events.is_empty());
}

#[test]
fn a_dispatch_killed_between_intent_and_terminal_resumes_unknown_and_never_re_executes() {
    // Phase one: the process opens an effect and dies. Dropping the ticket is exactly what a kill
    // looks like to the log — an intent with no terminal.
    let turn = TurnId(5);
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let effect = effect_for(turn, EffectClass::Verify, 0);
    let id = effect.effect_id.clone();
    let ticket = open_effect(&mut log, &mut admissions, effect).expect("intent is durable");
    drop(ticket);

    // Phase two: recovery replays the log.
    let journal = EffectJournal::replay(&log.events).expect("a dangling intent still folds");
    let pending = journal.pending();
    assert_eq!(pending.len(), 1, "the killed dispatch is pending, not lost");
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].tool, "verify");

    // Recovery materialises the pending intent as unknown. It never re-runs it: the only thing it
    // appends is the marker.
    let mut recovered = log.events.clone();
    recovered.push(Event {
        seq: Seq::ZERO,
        turn,
        kind: EventKind::EffectUnknown {
            id: id.clone(),
            tool: "verify".into(),
            reason: "recovery found a durable intent without a durable terminal".into(),
        },
    });
    let after = EffectJournal::replay(&recovered).expect("recovered journal folds");
    assert!(after.pending().is_empty());
    assert_eq!(after.unknown_count(), 1);

    // And the resumed process cannot re-mint that identity, so no second dispatch can ever be
    // admitted under it.
    let mut resumed = EffectAdmissions::from_journal(&after);
    assert!(
        matches!(
            resumed.admit(turn, &id),
            Err(EffectAdmissionError::Duplicate(_))
        ),
        "a resumed run must not re-admit an identity the previous process already used"
    );
}

#[test]
fn replay_reconstructs_pending_and_unknown_across_every_class() {
    let turn = TurnId(6);
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let mut expected_unknown = 0usize;
    let mut expected_pending = 0usize;

    for (index, class) in EffectClass::ALL.into_iter().enumerate() {
        let effect = effect_for(turn, class, index);
        let id = effect.effect_id.clone();
        let kind = effect.kind.clone();
        let ticket = open_effect(&mut log, &mut admissions, effect).expect("intent");
        match index % 3 {
            // Proven success.
            0 => settle_effect(
                &mut log,
                ticket,
                Settlement::Definite(EventKind::EffectDone { id, tool: kind }),
            )
            .expect("settle done"),
            // Proven failure — still a terminal, so still not pending and not unknown.
            1 => settle_effect(
                &mut log,
                ticket,
                Settlement::Definite(EventKind::EffectFailed {
                    id,
                    tool: kind,
                    reason: "probe failure".into(),
                }),
            )
            .expect("settle failed"),
            // Dispatched, no observable terminal.
            _ => {
                expected_unknown += 1;
                settle_effect(
                    &mut log,
                    ticket,
                    Settlement::Unknown("probe unknown".into()),
                )
                .expect("settle unknown");
            }
        }
    }
    // One more that is simply abandoned, standing for a kill mid-dispatch.
    let abandoned = effect_for(turn, EffectClass::Hook, 99);
    let ticket = open_effect(&mut log, &mut admissions, abandoned).expect("intent");
    drop(ticket);
    expected_pending += 1;

    let journal = EffectJournal::replay(&log.events).expect("mixed journal folds");
    assert_eq!(journal.unknown_count(), expected_unknown);
    assert_eq!(journal.pending().len(), expected_pending);
    assert_eq!(
        journal.admitted().count(),
        EffectClass::ALL.len() + 1,
        "every admitted identity is visible to the resume ledger, whatever state it ended in"
    );
}

// ---------------------------------------------------------------------------------------------
// The source-level gate: nothing dispatches an effect outside the boundary.
// ---------------------------------------------------------------------------------------------

/// One way the kernel can touch the world, and the functions allowed to do it.
struct EffectPrimitive {
    /// Source substring that marks a dispatch.
    needle: &'static str,
    /// Functions permitted to contain it. A declaration site counts as its own function.
    allowed_in: &'static [&'static str],
    /// What a reviewer should do when this fails.
    guidance: &'static str,
}

const EFFECT_PRIMITIVES: &[EffectPrimitive] = &[
    EffectPrimitive {
        needle: "hooks.run(",
        allowed_in: &["brokered_hook"],
        guidance: "a lifecycle hook starts an operator-controlled process; route it through \
                   Agent::brokered_hook so it crosses the effect boundary",
    },
    EffectPrimitive {
        needle: "registry.run_effect(",
        allowed_in: &["drive_admitted"],
        guidance: "an effecting registry tool must be dispatched by effects::execute_registry_tool, \
                   never called directly",
    },
    EffectPrimitive {
        needle: "self.bounded_provider_turn(",
        allowed_in: &["brokered_provider_turn", "drive_admitted"],
        guidance: "a provider request is a paid, externally visible effect; dispatch it through \
                   Agent::brokered_provider_turn, or open/settle around it as drive_admitted does",
    },
    EffectPrimitive {
        needle: "checkpoint_excluding_runtime_state(",
        allowed_in: &["finish_drained"],
        guidance: "a checkpoint writes the workspace tree; it must be opened at the boundary before \
                   the copy and settled after it",
    },
    EffectPrimitive {
        needle: "self.run_bounded_verify(",
        allowed_in: &["dispatch_verify"],
        guidance: "a verifier oracle runs repository-controlled code; reach it through \
                   Agent::run_verify, which owns the intent/terminal pair",
    },
    EffectPrimitive {
        needle: "self.launch_workflow(",
        allowed_in: &["drive_admitted"],
        guidance: "an in-turn workflow launch fans out real children that spend budget; it crosses \
                   the boundary under EffectClass::Workflow",
    },
    EffectPrimitive {
        needle: "self.run_child_with_control(",
        allowed_in: &["spawn_subagent"],
        guidance: "spawning a subagent is an effect of the parent; open the boundary before the \
                   child runs",
    },
    EffectPrimitive {
        needle: "tokio::process::Command::new(",
        allowed_in: &["run_one_with_sensitive_env_names"],
        guidance: "the kernel starts exactly one kind of child process directly — a hook — and it \
                   does so behind Agent::brokered_hook. Anything else belongs in a world module \
                   reached through the boundary",
    },
];

/// Kernel source files that may contain production effect dispatch.
const KERNEL_SOURCES: &[&str] = &[
    "src/lib.rs",
    "src/driver.rs",
    "src/reducer.rs",
    "src/turn_action.rs",
    "src/turn_command.rs",
    "src/turn_protocol.rs",
    "src/turn_state.rs",
    "src/effects.rs",
    "src/effect_admission.rs",
    "src/effect_class.rs",
    "src/effect_journal.rs",
    "src/hooks.rs",
    "src/workflow_spawner.rs",
    "src/diagnostics.rs",
    "src/pricing.rs",
];

/// Production lines only: every `#[cfg(test)]` item is removed, tracking brace depth from the
/// attribute so nested test modules disappear whole.
///
/// Tests legitimately call the dispatch primitives directly — that is how they test them — so a
/// gate that read them would either be permanently red or would have to list every test function,
/// which is the kind of allowlist that rots into meaninglessness.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut kept = Vec::new();
    let mut skipping = false;
    let mut depth: i32 = 0;
    let mut armed = false;
    for (index, line) in source.lines().enumerate() {
        if !skipping && line.trim_start().starts_with("#[cfg(test)]") {
            skipping = true;
            armed = false;
            depth = 0;
            continue;
        }
        if skipping {
            let opens = line.matches('{').count() as i32;
            let closes = line.matches('}').count() as i32;
            if opens > 0 {
                armed = true;
            }
            depth += opens - closes;
            if armed && depth <= 0 {
                skipping = false;
            }
            continue;
        }
        kept.push((index + 1, line));
    }
    kept
}

/// The nearest enclosing `fn` for each retained line, by the crate's consistent indentation.
fn enclosing_functions(lines: &[(usize, &str)]) -> BTreeMap<usize, String> {
    let mut current = String::from("<file scope>");
    let mut map = BTreeMap::new();
    for (number, line) in lines {
        if let Some(name) = function_name(line) {
            current = name;
        }
        map.insert(*number, current.clone());
    }
    map
}

fn function_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("pub(crate) ")
        .or_else(|| trimmed.strip_prefix("pub "))
        .unwrap_or(trimmed);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

#[test]
fn no_effect_producing_call_site_bypasses_the_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    let mut found: BTreeMap<&str, usize> = BTreeMap::new();

    for relative in KERNEL_SOURCES {
        let path = root.join(relative);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("kernel source {relative} must be readable: {error}"));
        let lines = production_lines(&source);
        let functions = enclosing_functions(&lines);
        for (number, line) in &lines {
            // A doc comment naming a primitive is documentation, not a dispatch.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for primitive in EFFECT_PRIMITIVES {
                if !line.contains(primitive.needle) {
                    continue;
                }
                *found.entry(primitive.needle).or_default() += 1;
                let enclosing = functions
                    .get(number)
                    .map(String::as_str)
                    .unwrap_or("<file scope>");
                if !primitive.allowed_in.contains(&enclosing) {
                    violations.push(format!(
                        "{relative}:{number} dispatches `{}` inside `{enclosing}`, which is not one \
                         of {:?}. {}",
                        primitive.needle, primitive.allowed_in, primitive.guidance
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "effect dispatch escaped the boundary:\n  {}",
        violations.join("\n  ")
    );

    // A gate that silently stops matching is worse than no gate: if a primitive is renamed and the
    // needle finds nothing, the test would pass while checking nothing at all.
    let unmatched: Vec<&str> = EFFECT_PRIMITIVES
        .iter()
        .map(|primitive| primitive.needle)
        .filter(|needle| !found.contains_key(needle))
        .collect();
    assert!(
        unmatched.is_empty(),
        "these effect primitives no longer appear in the kernel, so the gate is checking nothing: \
         {unmatched:?}. Update EFFECT_PRIMITIVES to match how the effect is dispatched now."
    );
}

#[test]
fn every_effect_class_is_reachable_from_a_dispatch_site() {
    // The vocabulary and the code must not drift: a class nobody dispatches is dead weight that
    // makes the boundary look wider than it is, and the source gate above cannot notice.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/lib.rs")).expect("kernel lib source");
    let production: String = production_lines(&source)
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    let missing: BTreeSet<String> = EffectClass::ALL
        .into_iter()
        .filter(|class| !production.contains(&format!("EffectClass::{class:?}")))
        .map(|class| format!("{class:?}"))
        .collect();
    assert!(
        missing.is_empty(),
        "these effect classes are declared but never dispatched: {missing:?}"
    );
}

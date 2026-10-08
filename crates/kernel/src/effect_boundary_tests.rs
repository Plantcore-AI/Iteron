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
use iteron_protocol::{
    Block, Capability, Effort, Event, EventKind, Message, ProviderRouteAttemptAccounting,
    ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity, ProviderRouteCostTruth,
    ProviderRouteCostUnknownReason, ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason,
    RunId, Seq, TenantId, TurnId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
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
    fn append_effect(&mut self, event: &Event) -> Result<Seq, iteron_record::RecordError> {
        let index = self.appends;
        self.appends += 1;
        if self.fail_on_append == Some(index) {
            return Err(iteron_record::RecordError::Io(std::io::Error::other(
                "probe: durable append refused",
            )));
        }
        self.events.push(event.clone());
        Ok(Seq::ZERO)
    }
}

fn effect_for(turn: TurnId, class: EffectClass, ordinal: usize) -> BrokeredEffect {
    let provider_route_attempt =
        (class == EffectClass::Provider).then(|| ProviderRouteAttemptIdentity {
            version: ProviderRouteAttemptAccountingVersion::V1,
            route_id: format!("sha256:{:064x}", ordinal.saturating_add(1)),
            physical_attempt: u32::try_from(ordinal).unwrap_or(u32::MAX).saturating_add(1),
            max_cost_reservation_microusd: None,
        });
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
        provider_route_attempt,
    }
}

fn provider_success_without_usage_accounting(
    identity: ProviderRouteAttemptIdentity,
) -> ProviderRouteAttemptAccounting {
    ProviderRouteAttemptAccounting {
        version: identity.version,
        route_id: identity.route_id,
        physical_attempt: identity.physical_attempt,
        max_cost_reservation_microusd: identity.max_cost_reservation_microusd,
        usage: ProviderRouteUsageTruth::Unknown {
            reason: ProviderRouteUsageUnknownReason::ProviderOmitted,
        },
        cost: ProviderRouteCostTruth::Unknown {
            reason: ProviderRouteCostUnknownReason::UsageIncomplete,
        },
    }
}

fn provider_failure_without_usage_accounting(
    identity: ProviderRouteAttemptIdentity,
) -> ProviderRouteAttemptAccounting {
    ProviderRouteAttemptAccounting {
        version: identity.version,
        route_id: identity.route_id,
        physical_attempt: identity.physical_attempt,
        max_cost_reservation_microusd: identity.max_cost_reservation_microusd,
        usage: ProviderRouteUsageTruth::Unknown {
            reason: ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage,
        },
        cost: ProviderRouteCostTruth::Unknown {
            reason: ProviderRouteCostUnknownReason::ProvenFailureWithoutBillingEvidence,
        },
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
        let provider_route_attempt = effect
            .provider_route_attempt
            .clone()
            .map(provider_success_without_usage_accounting);
        // Records the log length the executor observed, which is the only way to prove ordering
        // rather than merely asserting on the events afterwards.
        let seen_before_execute = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = seen_before_execute.clone();
        let terminal = EventKind::EffectDone {
            id: id.clone(),
            tool: class.label().unwrap_or("edit").to_string(),
            duration_ms: None,
            provider_route_attempt,
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
async fn provider_unknown_settlement_preserves_intent_identity_and_marks_truth_unobservable() {
    let turn = TurnId(9);
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let effect = effect_for(turn, EffectClass::Provider, 0);
    let expected = effect
        .provider_route_attempt
        .clone()
        .expect("provider fixture identity");

    let outcome = broker_effect(&mut log, &mut admissions, effect, || async {
        EffectDisposition::Unknown {
            reason: "process exited before a terminal was observable".into(),
            value: (),
        }
    })
    .await
    .expect("unknown remains a durable terminal");
    assert!(matches!(outcome, BrokeredOutcome::Unknown(())));
    let EventKind::EffectUnknown {
        provider_route_attempt: Some(accounting),
        ..
    } = &log.events[1].kind
    else {
        panic!("provider unknown terminal must carry accounting")
    };
    assert_eq!(accounting.identity(), expected);
    assert!(matches!(
        accounting.usage,
        ProviderRouteUsageTruth::Unknown {
            reason: ProviderRouteUsageUnknownReason::OutcomeUnobservable
        }
    ));
    assert!(matches!(
        accounting.cost,
        ProviderRouteCostTruth::Unknown {
            reason: ProviderRouteCostUnknownReason::OutcomeUnobservable
        }
    ));
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
            duration_ms: None,
            provider_route_attempt: None,
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
            provider_route_attempt: None,
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

#[tokio::test]
async fn fsynced_intent_crash_reconciles_unknown_without_replay_then_forks_a_divergent_chain() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock is after the Unix epoch")
        .as_nanos();
    let runs_dir = std::env::temp_dir().join(format!(
        "core-effect-reconcile-fork-{}-{nonce}",
        std::process::id()
    ));
    let tenant = TenantId::default();
    let parent = RunId("effect-crash-parent".into());
    let turn = TurnId(1);
    let effect = effect_for(turn, EffectClass::Verify, 0);
    let id = effect.effect_id.clone();

    // Process one: a real Rollout append crosses fsync before the ticket is returned. The process
    // then disappears before it can append any terminal.
    {
        let mut rollout =
            iteron_record::Rollout::open(&runs_dir, &parent, tenant.clone()).expect("open parent");
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: "/repo".into(),
                    model: "fixture-model".into(),
                    effort: Effort::Medium,
                    created_at: 0,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "fixture-config".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .expect("fsync genesis");
        let mut admissions = EffectAdmissions::default();
        let ticket =
            open_effect(&mut rollout, &mut admissions, effect).expect("fsync effect intent");
        drop(ticket);
        // Dropping the writer models a hard process boundary: no in-memory admission state survives.
    }

    // Process two: replay is the only authority. It writes Unknown, seeds admission from that
    // durable state, and proves that attempting the same identity never reaches the executor.
    let parent_events;
    {
        let parent_path = runs_dir.join(format!("{}.jsonl", parent.0));
        let before = iteron_record::replay(&parent_path).expect("replay the crashed journal");
        let crashed = EffectJournal::replay(&before).expect("fold the crashed journal");
        let pending = crashed.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);

        let mut rollout = iteron_record::Rollout::open_existing(&runs_dir, &parent, tenant.clone())
            .expect("resume parent");
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn,
                kind: EventKind::EffectUnknown {
                    id: id.clone(),
                    tool: "verify".into(),
                    reason: "recovery found a durable intent without a durable terminal".into(),
                    provider_route_attempt: None,
                },
            })
            .expect("fsync recovery marker");

        parent_events = iteron_record::replay(&parent_path).expect("replay reconciled parent");
        let reconciled =
            EffectJournal::replay(&parent_events).expect("fold the reconciled journal");
        assert!(reconciled.pending().is_empty());
        assert_eq!(reconciled.unknown_count(), 1);

        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let mut resumed = EffectAdmissions::from_journal(&reconciled);
        let duplicate = broker_effect(
            &mut rollout,
            &mut resumed,
            effect_for(turn, EffectClass::Verify, 0),
            move || {
                let executor_calls = executor_calls.clone();
                async move {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    EffectDisposition::Unknown {
                        reason: "unreachable replay".into(),
                        value: (),
                    }
                }
            },
        )
        .await;
        assert!(matches!(
            duplicate,
            Err(BrokerError::Admission(EffectAdmissionError::Duplicate(_)))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "reconciliation must never replay the effect"
        );
    }

    // Fork the exact reconciled commit. Logical replay shares the immutable parent prefix, while
    // the child's physical hash chain starts from zero and diverges with its own committed suffix.
    let fork_at = parent_events
        .last()
        .expect("reconciled parent has a tail")
        .seq;
    let child =
        iteron_record::fork(&runs_dir, &parent, fork_at, &tenant).expect("fork reconciled parent");
    {
        let mut rollout =
            iteron_record::Rollout::open(&runs_dir, &child, tenant.clone()).expect("open child");
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(2),
                kind: EventKind::Message {
                    message: Message::user_text("fork-diverged"),
                },
            })
            .expect("fsync child suffix");
    }

    let parent_lines = read_chain_values(&runs_dir, &parent);
    let child_lines = read_chain_values(&runs_dir, &child);
    let parent_commit = parent_lines
        .last()
        .and_then(|line| line.get("hash"))
        .and_then(serde_json::Value::as_str)
        .expect("parent commit hash");
    let child_genesis = child_lines.first().expect("child genesis");
    assert_eq!(
        child_genesis
            .get("prev")
            .and_then(serde_json::Value::as_str),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );
    assert_ne!(
        child_genesis
            .get("hash")
            .and_then(serde_json::Value::as_str),
        Some(parent_commit),
        "the child must have an independently committed physical chain"
    );
    let provenance = iteron_record::meta(&runs_dir, &child)
        .expect("child metadata")
        .parent
        .expect("fork provenance");
    assert_eq!(provenance.parent_hash_at_seq, parent_commit);

    let logical = iteron_record::load_forked(&runs_dir, &child).expect("load logical fork");
    assert_eq!(
        serde_json::to_value(&logical[..parent_events.len()]).expect("serialize logical prefix"),
        serde_json::to_value(&parent_events).expect("serialize parent prefix"),
        "the fork must retain the exact reconciled committed prefix"
    );
    assert!(logical.iter().any(|event| {
        matches!(
            &event.kind,
            EventKind::Message { message }
                if matches!(
                    message.content.as_slice(),
                    [Block::Text { text }] if text == "fork-diverged"
                )
        )
    }));

    std::fs::remove_dir_all(&runs_dir).ok();
}

fn read_chain_values(runs_dir: &std::path::Path, run: &RunId) -> Vec<serde_json::Value> {
    let path: PathBuf = runs_dir.join(format!("{}.jsonl", run.0));
    std::fs::read_to_string(path)
        .expect("read chain")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse chain line"))
        .collect()
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
        let provider_route_attempt = effect.provider_route_attempt.clone();
        let ticket = open_effect(&mut log, &mut admissions, effect).expect("intent");
        match index % 3 {
            // Proven success.
            0 => settle_effect(
                &mut log,
                ticket,
                Settlement::Definite(EventKind::EffectDone {
                    id,
                    tool: kind,
                    duration_ms: None,
                    provider_route_attempt: provider_route_attempt
                        .clone()
                        .map(provider_success_without_usage_accounting),
                }),
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
                    duration_ms: None,
                    provider_route_attempt: provider_route_attempt
                        .clone()
                        .map(provider_failure_without_usage_accounting),
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

// `run_one_with_sensitive_env_names` was split too: the outer function resolves the interpreter
// (the musl artifact's natural home has `/bin/sh` and no `/bin/bash`, and a platform with neither
// must say so rather than no-op forever) and the spawn moved to `run_one_with_shell` with the body.
// The shell hook and the fixed PlantCore workspace hook are still the only child processes the
// kernel starts directly, both behind brokered_hook.
//
// `drive_admitted` was split: the outer function now only captures the working set the loop
// finished with (so an in-process follow-up need not rebuild it from the rollout), and the body
// moved to `drive_admitted_loop`. Both names are admitted because the boundary semantics did not
// move with it — the loop still opens and settles every effect it dispatches.
//
// Turn-end checkpointing now shares `checkpoint_at_turn_end` between ordinary completion and
// drain. The helper itself owns the exact open/copy/settle sequence, so it is the one admitted
// physical checkpoint dispatch site.
//
// `gate_concurrent_deferred_batch` is the batched PreToolUse equivalent of `dispatch_one`: it
// refuses to start without the HookEffectJournal, opens every kernel effect ticket in model order
// before `join_all` can poll a command, and settles every ticket in that same order afterward.
// Admitting the enclosing function keeps concurrent non-conflicting tool gates possible without
// weakening either durable effect boundary.
//
// Session/submission compatibility hooks moved to the resident AppServer so RunEnded/InputReady
// need not await them. `run_lifecycle_gate` fails closed without the shared HookEffectJournal;
// `run_legacy_hook` uses that same journal and publishes its terminal lifecycle independently.
// The AppServer source is therefore scanned alongside the runtime rather than becoming an
// unaudited composition-root escape hatch.
const EFFECT_PRIMITIVES: &[EffectPrimitive] = &[
    EffectPrimitive {
        needle: ".run_cancellable_journaled(",
        allowed_in: &["run_legacy_hook"],
        guidance: "a lifecycle hook starts an operator-controlled process; route it through \
                   Agent::brokered_hook so it crosses the effect boundary",
    },
    EffectPrimitive {
        needle: ".run_lifecycle_cancellable_journaled(",
        allowed_in: &[
            "brokered_lifecycle_gate_correlated",
            "dispatch_one",
            "gate_concurrent_deferred_batch",
            "run_lifecycle_gate",
        ],
        guidance: "a lifecycle hook starts operator-controlled processes; synchronous gates use \
                   the universal effect boundary, while bounded asynchronous observe/augment \
                   dispatch must hold the fsynced HookEffectJournal before starting a command",
    },
    EffectPrimitive {
        needle: "registry.run_admitted_intent(",
        allowed_in: &[
            "drive_admitted",
            "drive_admitted_loop",
            "run_concurrent_deferred_batch",
        ],
        guidance: "an admitted registry intent must be dispatched by \
                   effects::execute_registry_tool, or opened and settled around it the way \
                   run_concurrent_deferred_batch does when a batch runs concurrently — one \
                   intent appended before the executor is entered, exactly one terminal after, \
                   and the correlation id restored from the admitted call, never from the result",
    },
    EffectPrimitive {
        needle: "iteron_provider::turn_cancellable_any(",
        allowed_in: &["execute_admitted_provider_turn"],
        guidance: "a provider request is a paid, externally visible effect; dispatch it through \
                   execute_admitted_provider_turn only after its caller has durably opened the \
                   exact provider route attempt",
    },
    EffectPrimitive {
        needle: "execute_admitted_provider_turn(",
        allowed_in: &[
            "execute_admitted_provider_turn",
            "brokered_provider_turn",
            "drive_admitted_loop",
            "run_attempt",
        ],
        guidance: "the admitted provider helper may only be declared once or called by the three \
                   owners that durably open and settle an exact provider route attempt",
    },
    EffectPrimitive {
        needle: "checkpoint_excluding_runtime_state(",
        allowed_in: &["checkpoint_at_turn_end"],
        guidance: "a checkpoint writes the workspace tree; it must be opened at the boundary before \
                   the copy and settled after it",
    },
    EffectPrimitive {
        needle: ".run_bounded_verify_observed(",
        allowed_in: &["dispatch_verify_task"],
        guidance: "a verifier oracle runs repository-controlled code; the exact \
                   StrongVerificationGate::run_verify owner must first commit its ticket and \
                   bind the physical task, then dispatch and settle through VerificationJournal",
    },
    EffectPrimitive {
        needle: ".dispatch_verify_task(",
        allowed_in: &["run_verify"],
        guidance: "the actual optional verifier caller must own the fsynced Verify ticket and \
                   its exact VerificationTask before entering the physical dispatcher",
    },
    EffectPrimitive {
        needle: "self.launch_workflow(",
        allowed_in: &["drive_admitted", "drive_admitted_loop", "run_orchestrated"],
        guidance: "an in-turn workflow launch fans out real children that spend budget; it crosses \
                   the boundary under EffectClass::Workflow",
    },
    EffectPrimitive {
        needle: ".run_child_with_control(",
        allowed_in: &["spawn_subagent"],
        guidance: "spawning a subagent is an effect of the parent; open the boundary before the \
                   child runs",
    },
    EffectPrimitive {
        needle: "tokio::process::Command::new(",
        allowed_in: &[
            "run_one_with_sensitive_env_names",
            "run_one_with_shell",
            "run_plantcore_workspace_hook",
        ],
        guidance: "the kernel starts exactly one kind of child process directly — a hook — and it \
                   does so behind Agent::brokered_hook. Anything else belongs in a world module \
                   reached through the boundary",
    },
];

/// Fixed kernel sources. The CLI runtime is discovered recursively below because the composition
/// root is intentionally split into small modules; a static module allowlist would silently stop
/// auditing every newly extracted dispatcher.
const KERNEL_SOURCES: &[&str] = &[
    "crates/kernel/src/lib.rs",
    "crates/kernel/src/driver.rs",
    "crates/kernel/src/reducer.rs",
    "crates/kernel/src/turn_action.rs",
    "crates/kernel/src/turn_command.rs",
    "crates/kernel/src/turn_protocol.rs",
    "crates/kernel/src/turn_state.rs",
    "crates/kernel/src/effects.rs",
    "crates/kernel/src/effect_admission.rs",
    "crates/kernel/src/effect_class.rs",
    "crates/kernel/src/effect_journal.rs",
    "crates/kernel/src/diagnostics.rs",
];

fn collect_runtime_sources(directory: &std::path::Path, sources: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("runtime source directory must be readable: {error}"));
    for entry in entries {
        let path = entry.expect("runtime source entry must be readable").path();
        if path.is_dir() {
            collect_runtime_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_name().is_none_or(|name| name != "tests.rs")
        {
            sources.push(path);
        }
    }
}

fn runtime_source_paths(root: &std::path::Path) -> Vec<PathBuf> {
    let mut sources = vec![root.join("crates/cli/src/runtime.rs")];
    collect_runtime_sources(&root.join("crates/cli/src/runtime"), &mut sources);
    sources.sort();
    sources
}

fn effect_source_paths(root: &std::path::Path) -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = KERNEL_SOURCES
        .iter()
        .map(|relative| root.join(relative))
        .collect();
    sources.extend(runtime_source_paths(root));
    sources.push(root.join("crates/cli/src/app_server.rs"));
    sources
}

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
        .or_else(|| trimmed.strip_prefix("pub(super) "))
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

/// Mask comments and literals before looking for executable ownership markers. In particular,
/// an unused string mentioning a durable append must never authorize a physical dispatcher.
fn executable_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let start = cursor;
        let end = if bytes[cursor..].starts_with(b"//") {
            bytes[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| cursor + offset)
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor += 2;
            let mut depth = 1;
            while cursor < bytes.len() && depth != 0 {
                if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            cursor
        } else if bytes[cursor] == b'r' {
            let mut quote = cursor + 1;
            while quote < bytes.len() && bytes[quote] == b'#' {
                quote += 1;
            }
            if bytes.get(quote) != Some(&b'"') {
                cursor += 1;
                continue;
            }
            let hashes = quote - cursor - 1;
            cursor = quote + 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'"'
                    && bytes.get(cursor + 1..cursor + 1 + hashes) == Some(&bytes[start + 1..quote])
                {
                    cursor += 1 + hashes;
                    break;
                }
                cursor += 1;
            }
            cursor
        } else if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'"' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            cursor
        } else if bytes[cursor] == b'\''
            && (bytes.get(cursor + 2) == Some(&b'\'')
                || (bytes.get(cursor + 1) == Some(&b'\\') && bytes.get(cursor + 3) == Some(&b'\'')))
        {
            // Do not mask Rust lifetimes: unlike a character literal they have no closing quote.
            cursor + if bytes[cursor + 1] == b'\\' { 4 } else { 3 }
        } else {
            cursor += 1;
            continue;
        };
        for byte in &mut masked[start..end] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
        cursor = end;
    }
    String::from_utf8(masked).expect("masking complete comments/literals preserves UTF-8")
}

fn compact_source(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

/// Select an actual production method of the canonical imported owner. Comments, literals,
/// fixture methods and an unrelated/unused Agent facade do not participate in this proof.
fn verification_method(source: &str, wanted: &str) -> Result<String, &'static str> {
    let source = executable_source(source);
    let lines = production_lines(&source);
    let import = "use super::strong_verification::StrongVerificationGate;";
    let imports: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, (_, line))| line.trim() == import)
        .collect();
    if imports.len() != 1
        || (imports[0].0 != 0 && lines[imports[0].0 - 1].1.trim_start().starts_with("#["))
    {
        return Err("verifier must import its exact unconditional StrongVerificationGate owner");
    }
    let mut owner = None;
    let mut depth = 0_i32;
    let mut found = Vec::new();
    let mut collecting: Option<(String, bool)> = None;
    let mut pending_active_attribute = false;
    let mut attribute_depth = 0_i32;
    for (_, line) in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("#[") || attribute_depth != 0 {
            let is_doc = trimmed.strip_prefix("#[doc").is_some_and(|suffix| {
                suffix.chars().next().is_some_and(|character| {
                    character.is_whitespace() || matches!(character, '=' | '(' | ']')
                })
            });
            if attribute_depth == 0 && !is_doc {
                pending_active_attribute = true;
                if collecting.is_some() {
                    return Err(
                        "actual verifier executable markers cannot be conditional or attributed",
                    );
                }
            }
            attribute_depth += line.matches('[').count() as i32 - line.matches(']').count() as i32;
            continue;
        }
        if pending_active_attribute
            && (trimmed == import
                || compact_source(trimmed) == "implStrongVerificationGate<'_>{"
                || (owner
                    .as_ref()
                    .is_some_and(|(name, _)| name == "implStrongVerificationGate<'_>{")
                    && function_name(line).as_deref() == Some(wanted)))
        {
            return Err(
                "actual verifier owner/import/method must be unconditional and free of active attributes",
            );
        }
        pending_active_attribute = false;
        if trimmed.starts_with("impl ") {
            owner = Some((compact_source(trimmed), depth + 1));
        }
        if collecting.is_none()
            && owner.as_ref().is_some_and(|(name, level)| {
                name == "implStrongVerificationGate<'_>{" && *level == depth
            })
            && function_name(line).as_deref() == Some(wanted)
        {
            collecting = Some((String::new(), false));
        }
        if let Some((body, armed)) = &mut collecting {
            body.push_str(line);
            body.push('\n');
            *armed |= line.contains('{');
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if collecting.as_ref().is_some_and(|(_, armed)| *armed)
            && owner.as_ref().is_some_and(|(_, level)| depth == *level)
        {
            found.push(compact_source(
                &collecting.take().expect("method collection exists").0,
            ));
        }
        if owner.as_ref().is_some_and(|(_, level)| depth < *level) {
            owner = None;
        }
    }
    if found.len() != 1 {
        return Err(
            "verifier method must have exactly one actual production StrongVerificationGate owner",
        );
    }
    Ok(found.pop().expect("one method"))
}

fn validate_verifier_source_owner(source: &str) -> Result<(), &'static str> {
    let run = verification_method(source, "run_verify")?;
    if run.matches(".dispatch_verify_task(").count() != 1
        || run.matches("self.journal.open(").count() != 1
    {
        return Err(
            "each optional verification owns exactly one intent and one physical dispatcher",
        );
    }
    let markers = [
        "letclass=effect_class::EffectClass::Verify;",
        "letticket=self.journal.open(",
        "lettask=matchself.tasks.begin(self.journal.rollout.run_id(),&ticket)",
        "letdispatch=self.dispatch_verify_task(command,Some(&task)).await;",
        "self.journal.settle(ticket,settlement)?;",
        "task.settled(known_terminal,&verdict,observed);",
    ];
    let mut previous = None;
    for marker in markers {
        let positions: Vec<_> = run.match_indices(marker).map(|(index, _)| index).collect();
        if positions.len() != 1 || previous.is_some_and(|prior| positions[0] <= prior) {
            return Err(
                "actual Verify ticket/task/dispatch/terminal observations must remain unique and ordered",
            );
        }
        previous = Some(positions[0]);
    }
    let dispatch = verification_method(source, "dispatch_verify_task")?;
    let oracle = dispatch
        .find("iteron_verify::TestOracle::new(")
        .ok_or("actual verifier dispatcher must build the sandbox oracle")?;
    let physical = "self.run_bounded_verify_observed(std::sync::Arc::new(oracle),Some(output_observer),Some(output_receiver),task,).await";
    let positions: Vec<_> = dispatch
        .match_indices(physical)
        .map(|(index, _)| index)
        .collect();
    if positions.len() != 1
        || positions[0] <= oracle
        || dispatch.matches(".run_bounded_verify_observed(").count() != 1
    {
        return Err(
            "native verifier dispatch must retain this exact admitted task and sandbox oracle",
        );
    }
    Ok(())
}

fn verifier_primitive_owner(needle: &str, relative: &std::path::Path, enclosing: &str) -> bool {
    let required = match needle {
        ".run_bounded_verify_observed(" => "dispatch_verify_task",
        ".dispatch_verify_task(" => "run_verify",
        _ => return true,
    };
    relative == std::path::Path::new("crates/cli/src/runtime/verification_execution.rs")
        && enclosing == required
}

#[test]
fn verifier_source_guard_tracks_the_actual_ticket_owner_and_rejects_facade_or_literal_bait() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let source =
        std::fs::read_to_string(root.join("crates/cli/src/runtime/verification_execution.rs"))
            .expect("real production verifier owner");
    validate_verifier_source_owner(&source).expect("actual optional verifier owner");
    let call = "let dispatch = self.dispatch_verify_task(command, Some(&task)).await;";
    assert!(source.contains(call));
    for broken in [
        source.replace("impl StrongVerificationGate<'_> {", "#[documentary]\nimpl StrongVerificationGate<'_> {"),
        source.replace("use super::strong_verification::StrongVerificationGate;", "#[cfg(any())]\n\nuse super::strong_verification::StrongVerificationGate;"),
        source.replace("impl StrongVerificationGate<'_> {", "#[cfg(any())]\n\nimpl StrongVerificationGate<'_> {"),
        source.replace("    pub(super) async fn run_verify(", "    #[cfg_attr(any(), allow(dead_code))]\n    pub(super) async fn run_verify("),
        source.replace("        let ticket = self.journal.open(", "        #[cfg(any())]\n        let ticket = self.journal.open("),
        source.replace("let ticket = self.journal.open(", "let escaped = self.dispatch_verify_task(command, None).await; let ticket = self.journal.open("),
        source.replace(call, "let dispatch = self.dispatch_verify_task(command, None).await;"),
        source.replace("self.journal.settle(ticket, settlement)?;", "task.settled(known_terminal, &verdict, observed); self.journal.settle(ticket, settlement)?;"),
        source.replace("impl StrongVerificationGate<'_> {", "impl Agent {"),
        source.replace("use super::strong_verification::StrongVerificationGate;", "use evil::StrongVerificationGate;"),
        source.replace("self.journal.open(", "self.journal.open_without_commit("),
        source.replace("    pub(super) async fn run_verify(", "    #[cfg(test)]\n    pub(super) async fn run_verify("),
    ] {
        assert!(validate_verifier_source_owner(&broken).is_err());
    }
    let no_ticket = source.replace(
        "let ticket = self.journal.open(",
        "let ticket = self.journal.not_a_durable_open(",
    );
    let bait = no_ticket.replace("let class = effect_class::EffectClass::Verify;", "let bait = r###\"let ticket = self.journal.open(\"###; let class = effect_class::EffectClass::Verify;");
    assert!(
        validate_verifier_source_owner(&bait).is_err(),
        "raw literal cannot claim a durable ticket"
    );
    assert!(!verifier_primitive_owner(
        ".run_bounded_verify_observed(",
        std::path::Path::new("crates/cli/src/runtime/verification.rs"),
        "dispatch_verify_task"
    ));
    assert!(!verifier_primitive_owner(
        ".dispatch_verify_task(",
        std::path::Path::new("crates/cli/src/runtime/verification_execution.rs"),
        "dispatch_verify"
    ));
}

#[test]
fn no_effect_producing_call_site_bypasses_the_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("kernel is two directories below the repository root");
    let verifier_source =
        std::fs::read_to_string(root.join("crates/cli/src/runtime/verification_execution.rs"))
            .expect("actual verifier execution owner must be readable");
    validate_verifier_source_owner(&verifier_source)
        .expect("actual verifier owner must retain ticket/task/dispatch/terminal order");
    let mut violations = Vec::new();
    let mut found: BTreeMap<&str, usize> = BTreeMap::new();

    for path in effect_source_paths(root) {
        let relative = path.strip_prefix(root).unwrap_or(&path).display();
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
                let exact_verifier_owner = verifier_primitive_owner(
                    primitive.needle,
                    path.strip_prefix(root)
                        .expect("effect source is in this workspace"),
                    enclosing,
                );
                if !primitive.allowed_in.contains(&enclosing) || !exact_verifier_owner {
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
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("kernel is two directories below the repository root");
    let production = runtime_source_paths(root)
        .into_iter()
        .map(|path| std::fs::read_to_string(path).expect("runtime source"))
        .map(|source| {
            production_lines(&source)
                .into_iter()
                .map(|(_, line)| line)
                .collect::<Vec<_>>()
                .join("\n")
        })
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

// -------------------------------------------------------------------------------------------
// #101: the boundary measures every class it admits
// -------------------------------------------------------------------------------------------

/// The whole claim of #101 in one assertion: measuring `open -> settle` ONCE covers all seven
/// classes. A hand-placed timer per dispatch site would pass a test written per dispatch site and
/// still miss the eighth class somebody adds next quarter; enumerating `EffectClass::ALL` here is
/// what makes that impossible.
#[test]
fn every_effect_class_records_a_duration_on_its_proven_terminal() {
    for (ordinal, class) in EffectClass::ALL.iter().copied().enumerate() {
        let mut log = ProbeLog::default();
        let mut admissions = EffectAdmissions::default();
        let turn = TurnId(1);
        let effect = effect_for(turn, class, ordinal);
        let provider_route_attempt = effect
            .provider_route_attempt
            .clone()
            .map(provider_success_without_usage_accounting);
        let ticket = open_effect(&mut log, &mut admissions, effect).expect("open");
        let id = ticket.effect_id().clone();
        settle_effect(
            &mut log,
            ticket,
            Settlement::Definite(EventKind::EffectDone {
                id,
                tool: class.label().unwrap_or("edit").to_string(),
                // The caller does NOT measure. The boundary must fill this in, which is exactly
                // what stops seven dispatch sites from each inventing their own scope.
                duration_ms: None,
                provider_route_attempt,
            }),
        )
        .expect("settle");
        match &log.events[1].kind {
            EventKind::EffectDone { duration_ms, .. } => assert!(
                duration_ms.is_some(),
                "{class:?} settled without a duration; the boundary did not measure it"
            ),
            other => panic!("{class:?} settled as {other:?}"),
        }
    }
}

/// A proven failure has a real duration. Reporting `None` here would make every honest failure
/// look instantaneous, which is the opposite of what an operator debugging a slow failing hook
/// needs to see.
#[test]
fn a_proven_failure_carries_its_duration_too() {
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let turn = TurnId(1);
    let ticket = open_effect(
        &mut log,
        &mut admissions,
        effect_for(turn, EffectClass::Hook, 0),
    )
    .expect("open");
    let id = ticket.effect_id().clone();
    settle_effect(
        &mut log,
        ticket,
        Settlement::Definite(EventKind::EffectFailed {
            id,
            tool: "hook".into(),
            reason: "probe failure".into(),
            duration_ms: None,
            provider_route_attempt: None,
        }),
    )
    .expect("settle");
    assert!(matches!(
        &log.events[1].kind,
        EventKind::EffectFailed { duration_ms, .. } if duration_ms.is_some()
    ));
}

/// The honest gap. `EffectUnknown` means no terminal was observed, so there is no duration to
/// report; a number here would claim knowledge the boundary just said it lacks. The field does not
/// exist on the variant at all, which makes the guarantee structural rather than a convention.
#[test]
fn an_unknown_terminal_never_reports_a_duration() {
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let turn = TurnId(1);
    let ticket = open_effect(
        &mut log,
        &mut admissions,
        effect_for(turn, EffectClass::Provider, 0),
    )
    .expect("open");
    settle_effect(
        &mut log,
        ticket,
        Settlement::Unknown("probe: no terminal observed".into()),
    )
    .expect("settle");
    let encoded = serde_json::to_value(&log.events[1].kind).expect("serialise");
    assert_eq!(encoded["kind"], "effect_unknown");
    assert!(
        encoded.get("duration_ms").is_none(),
        "an unproven terminal must not carry a duration: {encoded}"
    );
}

/// A registry tool settles as `ToolDone`, whose `ToolResult` already carries `latency_ms` measured
/// at the registry. The boundary must leave it alone: two disagreeing durations for one effect
/// would be worse than one, and a reader would have no way to know which to trust.
#[test]
fn a_registry_tool_terminal_is_not_restamped_by_the_boundary() {
    let mut log = ProbeLog::default();
    let mut admissions = EffectAdmissions::default();
    let turn = TurnId(1);
    let ticket = open_effect(
        &mut log,
        &mut admissions,
        effect_for(turn, EffectClass::RegistryTool, 0),
    )
    .expect("open");
    let effect_id = ticket.effect_id().clone();
    settle_effect(
        &mut log,
        ticket,
        Settlement::Definite(EventKind::ToolDone {
            result: iteron_protocol::ToolResult {
                tool_use_id: "call-0".into(),
                content: "fixture".into(),
                is_error: false,
                latency_ms: 7,
                trust: iteron_protocol::Trust::Workspace,
            },
            effect_id: Some(effect_id),
            tool: Some("edit".into()),
        }),
    )
    .expect("settle");
    match &log.events[1].kind {
        EventKind::ToolDone { result, .. } => assert_eq!(
            result.latency_ms, 7,
            "the boundary overwrote the registry's own measurement"
        ),
        other => panic!("registry tool settled as {other:?}"),
    }
}

/// `None` must not reach the wire. An absent key is the honest encoding of "not measured", and it
/// is also what keeps every rollout frozen before this change re-serialising byte-identically —
/// the property `d13_14_frozen_rollouts_hash_verify_replay_and_preserve_shape` pins.
#[test]
fn an_unmeasured_terminal_omits_the_key_rather_than_writing_null() {
    let encoded = serde_json::to_value(EventKind::EffectDone {
        id: iteron_protocol::EffectId("effect-1".into()),
        tool: "provider".into(),
        duration_ms: None,
        provider_route_attempt: None,
    })
    .expect("serialise");
    assert!(
        encoded.get("duration_ms").is_none(),
        "an unmeasured duration must be absent, not null: {encoded}"
    );
    let measured = serde_json::to_value(EventKind::EffectDone {
        id: iteron_protocol::EffectId("effect-1".into()),
        tool: "provider".into(),
        duration_ms: Some(0),
        provider_route_attempt: None,
    })
    .expect("serialise");
    assert_eq!(
        measured["duration_ms"], 0,
        "a measured zero is a real observation and must survive the wire"
    );
}

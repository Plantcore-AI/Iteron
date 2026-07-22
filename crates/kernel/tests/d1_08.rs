//! D1-08 — the effect broker must be universal, not registry-only.
//!
//! The single durable WAL boundary (`EffectIntent` fsynced -> exactly one execution -> durable
//! terminal, with `EffectUnknown` as the fail-closed fallback) used to be reachable only through
//! `AdmittedRegistryTool` / `execute_registry_tool`, i.e. only for calls routed through
//! `core_tools::Registry`. This test drives the SAME boundary through the public `broker_effect`
//! entry point for effects that are NOT registry tools (a harness-internal "memory_write" and a
//! "provider_request" with no model `tool_use` id at all), and asserts every WAL invariant holds:
//!   * the durable intent is appended before the executor runs (and if the intent append fails, the
//!     executor never runs and nothing is journaled);
//!   * a proven outcome records exactly one terminal, correlated by the harness-minted effect id
//!     even when there is no provider `tool_use_id`;
//!   * an unprovable outcome is journaled as `EffectUnknown` and never fabricates a terminal;
//!   * a terminal append failure leaves a single recoverable pending intent.
//!
//! On a codebase without the universal broker these symbols do not exist, so this file cannot even
//! compile (RED). With the broker it compiles and the invariants hold (GREEN).

use core_kernel::effects::{
    BrokeredEffect, BrokeredOutcome, DurableEffectLog, EffectDisposition, EffectJournal, broker_effect,
    effect_id,
};
use core_protocol::{
    Capability, EffectId, Event, EventKind, Seq, ToolResult, Trust, TurnId,
};
use core_record::RecordError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct FakeLog {
    events: Vec<Event>,
    fail_on_append: Option<usize>,
}

impl DurableEffectLog for FakeLog {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, RecordError> {
        if self.fail_on_append == Some(self.events.len()) {
            return Err(std::io::Error::other("injected append failure").into());
        }
        self.events.push(event.clone());
        Ok(Seq((self.events.len() - 1) as u64))
    }
}

/// A non-registry effect descriptor: a harness-internal memory write. It has NO provider
/// `tool_use_id`, so the harness-minted effect id is the only correlation key.
fn memory_write_effect() -> (EffectId, BrokeredEffect) {
    let id = effect_id(TurnId(11), 0);
    (
        id.clone(),
        BrokeredEffect {
            turn: TurnId(11),
            effect_id: id,
            tool_use_id: String::new(),
            kind: "memory_write".into(),
            capability: Capability::ReversibleLocal,
            audit_arguments: serde_json::json!({"key": "profile", "bytes": 42}),
            workspace: "/repo".into(),
        },
    )
}

fn terminal_for(id: &EffectId) -> EventKind {
    EventKind::ToolDone {
        result: ToolResult {
            tool_use_id: String::new(),
            content: "committed".into(),
            is_error: false,
            trust: Trust::Workspace,
            latency_ms: 3,
        },
        effect_id: Some(id.clone()),
    }
}

#[tokio::test]
async fn universal_broker_records_intent_then_terminal_for_a_non_registry_effect() {
    let mut log = FakeLog::default();
    let (id, effect) = memory_write_effect();
    let terminal_id = id.clone();

    let outcome: BrokeredOutcome<&'static str> = broker_effect(&mut log, effect, move || async move {
        EffectDisposition::Definite {
            terminal: terminal_for(&terminal_id),
            value: "memory-committed",
        }
    })
    .await
    .expect("brokered effect must record cleanly");

    // The executor value is only handed back once its terminal is durable.
    match outcome {
        BrokeredOutcome::Definite(value) => assert_eq!(value, "memory-committed"),
        BrokeredOutcome::Unknown(_) => panic!("a proven effect must not be reported as unknown"),
    }

    // Exactly intent-then-terminal, in that order, on the durable log.
    assert_eq!(log.events.len(), 2);
    match &log.events[0].kind {
        EventKind::EffectIntent {
            tool,
            tool_use_id,
            capability,
            ..
        } => {
            assert_eq!(tool, "memory_write");
            assert!(
                tool_use_id.is_empty(),
                "a harness-internal effect carries no provider tool_use_id"
            );
            assert_eq!(*capability, Capability::ReversibleLocal);
        }
        other => panic!("first durable event must be the intent, got {other:?}"),
    }
    assert!(matches!(
        log.events[1].kind,
        EventKind::ToolDone {
            effect_id: Some(_),
            ..
        }
    ));

    // The journal — a pure fold of the same durable events — sees a completed, non-pending effect,
    // correlated purely by the harness-minted effect id (there was no provider tool_use_id).
    let journal = EffectJournal::replay(&log.events).expect("journal replays");
    assert!(journal.pending().is_empty());
    assert_eq!(journal.unknown_count(), 0);
    assert_eq!(id.0, "fx1-0000000b-0000");
}

#[tokio::test]
async fn universal_broker_never_executes_before_a_durable_intent() {
    // The intent append itself fails, so a NON-registry effect must never touch the world.
    let mut log = FakeLog {
        fail_on_append: Some(0),
        ..FakeLog::default()
    };
    let (_id, effect) = memory_write_effect();
    let calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = calls.clone();

    let result: Result<BrokeredOutcome<()>, RecordError> =
        broker_effect(&mut log, effect, move || async move {
            executor_calls.fetch_add(1, Ordering::SeqCst);
            EffectDisposition::Definite {
                terminal: EventKind::Notice {
                    text: "should never be reached".into(),
                },
                value: (),
            }
        })
        .await;

    assert!(result.is_err(), "a failed intent append must fail the effect");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the executor must not run before a durable intent"
    );
    assert!(log.events.is_empty());
}

#[tokio::test]
async fn universal_broker_journals_unknown_and_never_fabricates_a_terminal() {
    let mut log = FakeLog::default();
    // A provider request that we dispatched but whose remote outcome we cannot prove.
    let id = effect_id(TurnId(4), 1);
    let effect = BrokeredEffect {
        turn: TurnId(4),
        effect_id: id,
        tool_use_id: "prov-req-1".into(),
        kind: "provider_request".into(),
        capability: Capability::IrreversibleExternal,
        audit_arguments: serde_json::json!({"endpoint": "/v1/messages"}),
        workspace: "/repo".into(),
    };

    let outcome: BrokeredOutcome<u8> = broker_effect(&mut log, effect, move || async move {
        EffectDisposition::Unknown {
            reason: "dispatched but no authoritative terminal observed".into(),
            value: 7,
        }
    })
    .await
    .expect("recording an unknown is itself durable");

    match outcome {
        BrokeredOutcome::Unknown(value) => assert_eq!(value, 7),
        BrokeredOutcome::Definite(_) => panic!("an unprovable effect must not be reported definite"),
    }

    assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
    assert!(matches!(log.events[1].kind, EventKind::EffectUnknown { .. }));
    assert!(
        !log.events
            .iter()
            .any(|event| matches!(event.kind, EventKind::ToolDone { .. })),
        "an unknown outcome must never fabricate a ToolDone terminal"
    );

    let journal = EffectJournal::replay(&log.events).expect("journal replays");
    assert_eq!(journal.unknown_count(), 1);
    assert!(journal.pending().is_empty());
}

#[tokio::test]
async fn universal_broker_terminal_failure_leaves_one_recoverable_pending_intent() {
    // Intent append (index 0) succeeds; the terminal append (index 1) fails.
    let mut log = FakeLog {
        fail_on_append: Some(1),
        ..FakeLog::default()
    };
    let (id, effect) = memory_write_effect();
    let terminal_id = id.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = calls.clone();

    let result: Result<BrokeredOutcome<()>, RecordError> =
        broker_effect(&mut log, effect, move || async move {
            executor_calls.fetch_add(1, Ordering::SeqCst);
            EffectDisposition::Definite {
                terminal: terminal_for(&terminal_id),
                value: (),
            }
        })
        .await;

    assert!(result.is_err(), "a failed terminal append must surface as an error");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the effect ran exactly once");

    // The durable log holds only the intent; replay reports exactly one recoverable pending effect.
    let journal = EffectJournal::replay(&log.events).expect("journal replays");
    let pending = journal.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].tool, "memory_write");
    assert_eq!(journal.unknown_count(), 0);
}

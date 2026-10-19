use super::{eligible_answer, recorded_outcome, recover};
use iteron_protocol::turn_publication::{MAX_TURN_PUBLICATION_EVENTS, TurnPublicationFactV1};
use iteron_protocol::{
    Block, Event, EventKind, Message, Role, RunId, Seq, TenantId, ToolUse, TurnId,
};
use iteron_record::ScopedEvent;

fn scoped(seq: u64, turn: u32, kind: EventKind) -> ScopedEvent {
    ScopedEvent {
        event: Event {
            seq: Seq(seq),
            turn: TurnId(turn),
            kind,
        },
        tenant: TenantId::default(),
        run_id: RunId("current".into()),
    }
}

fn message(text: &str) -> Message {
    Message {
        role: Role::Assistant,
        content: vec![Block::Text { text: text.into() }],
    }
}

#[test]
fn answer_survives_without_a_terminal_and_partial_text_never_implies_availability() {
    let tenant = TenantId::default();
    let run = RunId("current".into());
    let mut events = vec![scoped(
        4,
        0,
        EventKind::Message {
            message: message("real answer"),
        },
    )];
    assert!(recover(&events, &tenant, &run).unwrap().is_empty());
    events.push(scoped(
        5,
        0,
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 4 },
        },
    ));
    let available = recover(&events, &tenant, &run).unwrap();
    assert_eq!(available.len(), 1);
    assert_eq!(available[0].source_seq, 5);
    assert_eq!(available[0].turn_id, TurnId(0));
    events.push(scoped(
        7,
        0,
        EventKind::Done {
            outcome: "HarnessError".into(),
        },
    ));
    let recovered = recover(&events, &tenant, &run).unwrap();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[1].source_seq, 7);
    assert_eq!(
        recovered[1].fact,
        TurnPublicationFactV1::finalized(&iteron_protocol::Outcome::HarnessError).unwrap()
    );
}

#[test]
fn inherited_scope_and_tool_messages_cannot_supply_this_runs_answer_witness() {
    let mut ancestor = scoped(
        4,
        0,
        EventKind::Message {
            message: message("parent"),
        },
    );
    ancestor.run_id = RunId("ancestor".into());
    let tag = scoped(
        5,
        0,
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 4 },
        },
    );
    assert!(
        recover(
            &[ancestor, tag.clone()],
            &TenantId::default(),
            &RunId("current".into())
        )
        .is_err()
    );
    let mut tool = message("tool preamble");
    tool.content.push(Block::ToolUse(ToolUse {
        id: "call".into(),
        name: "read".into(),
        input: serde_json::json!({"path":"f"}),
    }));
    assert!(!eligible_answer(&tool));
    assert!(
        recover(
            &[scoped(4, 0, EventKind::Message { message: tool }), tag],
            &TenantId::default(),
            &RunId("current".into())
        )
        .is_err()
    );
}

#[test]
fn forged_message_reference_and_standalone_finalization_tag_are_unavailable() {
    let message = scoped(
        4,
        1,
        EventKind::Message {
            message: message("answer"),
        },
    );
    let wrong_turn = scoped(
        5,
        2,
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 4 },
        },
    );
    let run = RunId("current".into());
    assert!(recover(&[message, wrong_turn], &TenantId::default(), &run).is_err());
    let forged = scoped(
        7,
        1,
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::finalized(&iteron_protocol::Outcome::Done).unwrap(),
        },
    );
    assert!(recover(&[forged], &TenantId::default(), &run).is_err());
    assert!(recorded_outcome("done").is_none());
    assert!(recorded_outcome("BudgetExhausted(\"unknown\")").is_none());
}

#[test]
fn retained_window_stays_bounded_and_uses_exact_canonical_done_sequences() {
    let events: Vec<_> = (0..MAX_TURN_PUBLICATION_EVENTS + 25)
        .map(|index| {
            scoped(
                index as u64 + 3,
                index as u32,
                EventKind::Done {
                    outcome: "Done".into(),
                },
            )
        })
        .collect();
    let recovered = recover(&events, &TenantId::default(), &RunId("current".into())).unwrap();
    assert_eq!(recovered.len(), MAX_TURN_PUBLICATION_EVENTS);
    assert_eq!(recovered.first().unwrap().source_seq, 28);
    assert_eq!(
        recovered.last().unwrap().source_seq,
        events.last().unwrap().event.seq.0
    );
}

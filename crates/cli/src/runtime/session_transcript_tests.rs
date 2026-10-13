use super::{SessionTranscriptOwner, TranscriptAdmissionJournal};
use crate::runtime::DurableAppendFault;
use crate::runtime::task_plan::TaskPlanOwner;
use crate::runtime::turn_publication::TurnPublicationOwner;
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::{EventKind, Message, RunId, TenantId, TurnId};
use iteron_record::Rollout;

#[test]
fn actual_message_append_refusal_preserves_the_restored_transcript_and_no_new_instruction() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "iteron-submission-refusal-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let mut rollout =
        Rollout::open(&directory, &RunId("refusal".into()), TenantId::default()).unwrap();
    let mut publications = TurnPublicationOwner::for_rollout(&rollout);
    let original = vec![Message::user_text("restored exact instruction")];
    let mut transcript = SessionTranscriptOwner::default();
    transcript.replace_restored(Some(original.clone()));
    let mut ledger = Ledger::default();
    let mut failed = false;
    let mut fault = Some(DurableAppendFault::SteerMessage);
    let diagnostics = DiagnosticEmitter::default();
    let mut plan = TaskPlanOwner::default();
    let refused = transcript.admit_submission(
        TurnId(1),
        "new refused instruction",
        &mut TranscriptAdmissionJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            publications: &mut publications,
            fault: &mut fault,
        },
        &mut plan,
    );
    assert!(refused.is_err());
    assert!(failed);
    assert_eq!(
        serde_json::to_value(transcript.restored()).unwrap(),
        serde_json::to_value(Some(original)).unwrap()
    );
    let path = rollout.path().to_path_buf();
    drop(rollout);
    let events = iteron_record::replay(&path).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::Message { .. }))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn empty_recovery_is_not_an_input_and_real_new_instruction_has_one_durable_receipt() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "iteron-submission-commit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let mut rollout =
        Rollout::open(&directory, &RunId("commit".into()), TenantId::default()).unwrap();
    let mut publications = TurnPublicationOwner::for_rollout(&rollout);
    let original = vec![Message::user_text("restored exact instruction")];
    let mut transcript = SessionTranscriptOwner::default();
    transcript.replace_restored(Some(original.clone()));
    let mut ledger = Ledger::default();
    let mut failed = false;
    let mut fault = None;
    let diagnostics = DiagnosticEmitter::default();
    let mut plan = TaskPlanOwner::default();
    let mut journal = TranscriptAdmissionJournal {
        rollout: &mut rollout,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        publications: &mut publications,
        fault: &mut fault,
    };
    let recovered = transcript
        .admit_submission(TurnId(1), " ", &mut journal, &mut plan)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&recovered).unwrap(),
        serde_json::to_value(&original).unwrap()
    );
    transcript.replace_restored(Some(recovered));
    let admitted = transcript
        .admit_submission(TurnId(2), "actual new instruction", &mut journal, &mut plan)
        .unwrap();
    assert_eq!(admitted.len(), 1);
    assert!(admitted[0].content.iter().any(|block| matches!(block,
        iteron_protocol::Block::Text { text } if text == "actual new instruction"
    )));
    let path = journal.rollout.path().to_path_buf();
    drop(rollout);
    let events = iteron_record::replay(&path).unwrap();
    let messages = events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::Message { .. }))
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].turn, TurnId(2));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interrupted_reopen_preserves_new_operator_boundary_and_exact_input_on_replay() {
    use crate::runtime::transcript::{project_messages_from_events, reconcile_transcript};
    use iteron_protocol::{Block, Event, Role, Seq};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "iteron-interrupted-submission-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let run_id = RunId("interrupted-submission".into());
    let old_task = " Explain the sorting algorithm in many numbered points.\n";
    let new_task = "\n  改为回答新的问题：二加三是多少？不需要工具。  \n";
    let mut rollout = Rollout::open(&directory, &run_id, TenantId::default()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::Message {
                message: Message::user_text(old_task),
            },
        })
        .unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::Done {
                outcome: "Interrupted".into(),
            },
        })
        .unwrap();
    let path = rollout.path().to_path_buf();
    drop(rollout);
    // A cancelled streamed answer has no completed assistant message to separate the inputs.
    let restored = project_messages_from_events(iteron_record::replay(&path).unwrap());
    assert_eq!(restored.len(), 1);
    let mut rollout = Rollout::open(&directory, &run_id, TenantId::default()).unwrap();
    let mut publications = TurnPublicationOwner::for_rollout(&rollout);
    let mut transcript = SessionTranscriptOwner::default();
    transcript.replace_restored(Some(restored));
    let mut ledger = Ledger::default();
    let mut failed = false;
    let mut fault = None;
    let diagnostics = DiagnosticEmitter::default();
    let mut plan = TaskPlanOwner::default();
    let admitted = transcript
        .admit_submission(
            TurnId(1),
            new_task,
            &mut TranscriptAdmissionJournal {
                rollout: &mut rollout,
                ledger: &mut ledger,
                record_failed: &mut failed,
                diagnostics: &diagnostics,
                publications: &mut publications,
                fault: &mut fault,
            },
            &mut plan,
        )
        .unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].role, Role::User);
    assert!(matches!(admitted[0].content.first(), Some(Block::Text { text }) if text == old_task));
    assert!(matches!(admitted[0].content.last(), Some(Block::Text { text }) if text == new_task));
    let flattened: String = admitted[0]
        .content
        .iter()
        .filter_map(|block| match block {
            Block::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        flattened.find(old_task).unwrap() < flattened.find("Later conversation message").unwrap()
    );
    assert!(
        flattened.find("Later conversation message").unwrap() < flattened.find(new_task).unwrap()
    );
    assert!(!flattened.contains("New direct operator instruction"));
    drop(rollout);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(events.len(), 3, "only the new user message was appended");
    assert!(matches!(
        &events[1].kind,
        EventKind::Done { outcome } if outcome == "Interrupted"
    ));
    // The canonical record and public/UI history projection keep the exact two inputs,
    // without provider-only chronological markers or invented operator provenance.
    let recorded: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::Message { message } => Some(message),
            _ => None,
        })
        .collect();
    assert_eq!(
        serde_json::to_value(&recorded).unwrap(),
        serde_json::to_value([Message::user_text(old_task), Message::user_text(new_task),])
            .unwrap()
    );
    let scoped: Vec<_> = events
        .iter()
        .cloned()
        .map(|event| iteron_record::ScopedEvent {
            event,
            tenant: TenantId::default(),
            run_id: run_id.clone(),
        })
        .collect();
    let public = crate::session_transcript::project(&scoped);
    assert_eq!(public.total_blocks, 2);
    assert_eq!(public.blocks.len(), 2);
    let shown: Vec<_> = public
        .blocks
        .iter()
        .map(|row| match &row.content {
            iteron_protocol::session_navigation::SessionTranscriptContentV1::User { text } => {
                text.as_str()
            }
            _ => panic!("unexpected display block"),
        })
        .collect();
    assert_eq!(shown, [old_task, new_task]);
    let replayed = project_messages_from_events(events);
    assert_eq!(
        serde_json::to_value(&replayed).unwrap(),
        serde_json::to_value(&admitted).unwrap()
    );
    assert_eq!(
        serde_json::to_value(reconcile_transcript(replayed)).unwrap(),
        serde_json::to_value(admitted).unwrap()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

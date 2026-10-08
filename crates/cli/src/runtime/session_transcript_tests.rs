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

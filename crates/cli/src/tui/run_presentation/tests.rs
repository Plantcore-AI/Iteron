use super::{MAX_RETRY_BYTES, ReceiptObservation, RunPresentation};
use iteron_protocol::{SubmissionId, SubmissionLifecycleState};
use std::time::{Duration, Instant};

#[test]
fn accepted_stops_remain_live_until_actual_resident_completion() {
    let mut owner = RunPresentation::default();
    let started = Instant::now();
    owner.interrupt_accepted(started);
    owner.drain_accepted();
    owner.stronger_cancel_accepted();
    assert!(!owner.running());
    owner.submission_accepted(SubmissionId(42), started);
    owner.stronger_cancel_accepted();
    assert!(
        !owner.force_cancelling(),
        "stronger cancellation requires a cooperative request"
    );
    owner.interrupt_accepted(started + Duration::from_secs(2));
    owner.drain_accepted();
    owner.stronger_cancel_accepted();
    assert!(owner.running());
    assert!(owner.interrupting());
    assert!(owner.force_cancelling());
    assert!(owner.draining());
    assert!(owner.last_latency().is_none());
    owner.run_ended(started + Duration::from_secs(9));
    assert!(!owner.running());
    assert!(!owner.interrupting());
    assert!(!owner.draining());
    assert_eq!(owner.last_latency(), Some(Duration::from_secs(9)));
}
#[test]
fn wrong_or_late_submission_receipts_cannot_release_an_admitted_run() {
    let mut owner = RunPresentation::default();
    owner.submission_accepted(SubmissionId(10), Instant::now());
    owner.retain_receipt(SubmissionId(10), 7, true, "actual input".into());
    assert!(matches!(
        owner.observe_receipt(SubmissionId(9), SubmissionLifecycleState::Rejected),
        ReceiptObservation::None
    ));
    assert!(owner.running());
    assert!(matches!(
        owner.observe_receipt(SubmissionId(10), SubmissionLifecycleState::Received),
        ReceiptObservation::None
    ));
    assert!(
        matches!(owner.observe_receipt(SubmissionId(10), SubmissionLifecycleState::Applied), ReceiptObservation::Applied { display_text, editor_revision: 7, clear_composer: true } if display_text == "actual input")
    );
    assert!(matches!(
        owner.observe_receipt(SubmissionId(10), SubmissionLifecycleState::Applied),
        ReceiptObservation::None
    ));
    assert!(matches!(
        owner.observe_receipt(SubmissionId(10), SubmissionLifecycleState::Expired),
        ReceiptObservation::None
    ));
    assert!(owner.running());
    owner.run_ended(Instant::now());
    assert!(matches!(
        owner.observe_receipt(SubmissionId(10), SubmissionLifecycleState::Received),
        ReceiptObservation::None
    ));
}
#[test]
fn actual_pre_admission_refusal_releases_without_inventing_completed_latency() {
    let mut owner = RunPresentation::default();
    owner.submission_accepted(SubmissionId(1), Instant::now());
    owner.retain_plain_text_retry(Some("retry".into()));
    assert!(matches!(
        owner.observe_receipt(SubmissionId(1), SubmissionLifecycleState::Rejected),
        ReceiptObservation::Refused
    ));
    assert!(!owner.running());
    assert!(owner.retry_text().is_none());
    assert!(owner.last_latency().is_none());
}
#[test]
fn selected_run_clears_old_receipts_result_retry_and_clock_and_retry_is_bounded() {
    let mut owner = RunPresentation::default();
    owner.submission_accepted(SubmissionId(1), Instant::now());
    owner.retain_receipt(SubmissionId(1), 2, true, "old".into());
    owner.retain_plain_text_retry(Some("actual failed input".into()));
    owner.observe_terminal_result(serde_json::json!({"outcome":"harness_error"}));
    owner.select_verified_run();
    assert!(!owner.running());
    assert!(owner.pending_id().is_none());
    assert!(owner.terminal_result().is_none());
    assert!(owner.retry_text().is_none());
    assert!(owner.started().is_none());
    let mut overallocated = String::with_capacity(MAX_RETRY_BYTES + 1);
    overallocated.push_str("small");
    owner.retain_plain_text_retry(Some(overallocated));
    assert!(owner.retry_text().is_none());
}

#[test]
fn transport_receipt_does_not_consume_composer_before_admission() {
    let mut owner = RunPresentation::default();
    let id = SubmissionId(7);
    owner.submission_accepted(id, Instant::now());
    owner.retain_receipt(id, 19, true, "draft with attachments".into());
    assert!(owner.awaiting_composer_admission(19));
    assert!(!owner.awaiting_composer_admission(20));
    assert!(matches!(
        owner.observe_receipt(id, SubmissionLifecycleState::Received),
        ReceiptObservation::None
    ));
    assert!(owner.running());
    assert_eq!(owner.pending_id(), Some(id));
    assert!(matches!(
        owner.observe_receipt(id, SubmissionLifecycleState::Rejected),
        ReceiptObservation::Refused
    ));
    assert!(!owner.running());
    assert!(!owner.awaiting_composer_admission(19));
    assert!(owner.last_latency().is_none());
}

#[test]
fn failed_applied_draft_restores_exact_attachments_only_on_explicit_empty_editor_recovery() {
    let mut owner = RunPresentation::default();
    let mut editor = crate::editor::Editor::new();
    editor.insert_str("review ");
    editor.capture_paste("first line\n第二行").unwrap();
    const GIF: &[u8] = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";
    editor.attach_image_bytes("draft image", GIF).unwrap();
    editor
        .attach_context(
            crate::file_input::ContextKind::Diff,
            "diff",
            "retained file bytes".into(),
        )
        .unwrap();
    let raw = editor.text();
    let expanded = editor.submission_text();
    let revision = editor.persistence_revision();
    let id = SubmissionId(31);
    owner.submission_accepted(id, Instant::now());
    owner.retain_draft_recovery(editor.owned_draft());
    owner.retain_receipt(id, revision, true, expanded.clone());
    assert!(matches!(
        owner.observe_receipt(id, SubmissionLifecycleState::Received),
        ReceiptObservation::None
    ));
    assert!(!owner.has_draft_recovery());
    assert!(matches!(
        owner.observe_receipt(id, SubmissionLifecycleState::Applied),
        ReceiptObservation::Applied { .. }
    ));
    editor.take_submit();
    owner.run_ended(Instant::now());
    owner.finish_draft_recovery(false);
    assert!(owner.has_draft_recovery());
    editor.insert_str("newer unsent draft");
    assert!(!owner.restore_draft_recovery(&mut editor));
    assert_eq!(editor.text(), "newer unsent draft");
    editor.clear();
    assert!(owner.restore_draft_recovery(&mut editor));
    assert_eq!(editor.text(), raw);
    assert_eq!(editor.submission_text(), expanded);
    assert_eq!(editor.chip_count(), 3);
    assert!(!owner.running(), "recovery is never submission");
    assert!(!owner.has_draft_recovery());
    assert!(!owner.restore_draft_recovery(&mut editor));

    owner.submission_accepted(SubmissionId(32), Instant::now());
    owner.retain_draft_recovery(editor.owned_draft());
    owner.observe_receipt(SubmissionId(32), SubmissionLifecycleState::Applied);
    owner.run_ended(Instant::now());
    owner.finish_draft_recovery(true);
    assert!(
        !owner.has_draft_recovery(),
        "successful turns release the recovery payload"
    );
}

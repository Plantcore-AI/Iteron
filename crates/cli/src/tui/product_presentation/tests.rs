use super::*;
use crate::tui::{App, SubmissionId};
use std::time::Instant;

fn selected() -> ProductPresentation {
    let mut owner = ProductPresentation::default();
    owner.select_run(&RunId("selected".into()));
    owner
}
#[test]
fn exact_once_owned_answer_and_content_terminal_do_not_release_submission() {
    let mut app = App::new();
    app.run.submission_accepted(SubmissionId(7), Instant::now());
    app.product.select_run(&RunId("selected".into()));
    app.product.begin_turn();
    app.product.append_final("完整答案 🦀");
    let answer = app.product.finish_terminal(true).unwrap();
    assert_eq!(answer.text(), "完整答案 🦀");
    assert!(app.product.retain_terminal(answer));
    assert!(
        app.run.running(),
        "only real resident RunEnded releases the turn"
    );
    assert!(app.product.finish_terminal(true).is_none());
    assert_eq!(app.product.take_terminal().as_deref(), Some("完整答案 🦀"));
    assert!(app.product.take_terminal().is_none());
}
#[test]
fn incomplete_oversized_and_nonexact_observations_never_certify_terminal_text() {
    let mut owner = selected();
    owner.append_final("observed fragment");
    owner.mark_incomplete();
    assert!(owner.finish_terminal(true).is_none());
    owner.begin_turn();
    owner.append_final(&"x".repeat(MAX_TERMINAL_TEXT_BYTES + 1));
    assert!(owner.finish_terminal(true).is_none());
    assert!(owner.final_text.capacity() <= MAX_TERMINAL_TEXT_BYTES);
    owner.begin_turn();
    owner.append_final("complete");
    assert!(owner.finish_terminal(false).is_none());
}
#[test]
fn selected_run_replacement_and_same_run_reset_reject_old_owned_answers() {
    let mut owner = selected();
    owner.begin_turn();
    owner.append_final("old answer");
    let answer = owner.finish_terminal(true).unwrap();
    owner.select_run(&RunId("new".into()));
    assert!(!owner.retain_terminal(answer));
    owner.begin_turn();
    owner.append_final("same identity earlier generation");
    let answer = owner.finish_terminal(true).unwrap();
    owner.clear_selected_run();
    owner.select_run(&RunId("new".into()));
    assert!(!owner.retain_terminal(answer));
    assert!(owner.terminal_answer().is_none());
}
#[test]
fn unavailable_contract_falls_back_without_inventing_turn_counts() {
    let mut owner = selected();
    let mut snapshot = ThreadSnapshotV1 {
        contract_version: PRODUCT_CONTRACT_VERSION,
        thread_id: iteron_protocol::SessionId("thread".into()),
        run_id: RunId("selected".into()),
        source_event_seq: 0,
        turn: None,
        submissions: vec![],
        evicted_submissions: 0,
    };
    owner.observe_snapshot(&snapshot);
    assert!(owner.stream_active());
    assert!(owner.turn_status().is_none());
    snapshot.contract_version += 1;
    owner.observe_snapshot(&snapshot);
    assert!(!owner.stream_active());
    assert!(owner.turn_status().is_none());
}

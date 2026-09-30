use super::{InboundControl, SessionControlState};
use crate::runtime::inbound_control::{PendingSteer, TurnSubmission};
use crate::runtime::session_inbox::SessionSubmissionInbox;
use iteron_protocol::product_contract::ProductTurnId;
use iteron_protocol::{Op, SubmissionId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[tokio::test]
async fn real_queue_stop_keeps_the_tail_and_refuses_without_deadline_or_atomic() {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    for (id, op) in [
        (
            1,
            Op::Steer {
                text: "first".into(),
            },
        ),
        (2, Op::Interrupt),
        (
            3,
            Op::Steer {
                text: "tail".into(),
            },
        ),
    ] {
        tx.send(TurnSubmission::identified(SubmissionId(id), op))
            .await
            .unwrap();
    }
    let mut inbox = SessionSubmissionInbox::default();
    let mut controls = SessionControlState::default();
    inbox.bind_receiver(rx);
    let receipt = inbox.poll(&mut controls, 256, false);
    assert_eq!(receipt.control, InboundControl::Interrupt);
    assert_eq!(receipt.control_submission, Some(SubmissionId(2)));
    assert_eq!(inbox.len(), 1);
    assert!(controls.provider_refusal(None).is_some());
    // This queue-only embedder has no installed atomic. A backoff still observes the true latch.
    assert!(
        controls
            .wait_retry(Duration::from_secs(1), None, Duration::from_millis(1))
            .await
            .is_err()
    );
    controls.clear_interrupt_after_terminal();
    assert!(controls.provider_refusal(None).is_none());
    inbox.poll(&mut controls, 256, false);
    let (tail, visible) = inbox.reclaim();
    assert_eq!(visible, 2);
    assert_eq!(tail[0].submission_id, Some(SubmissionId(1)));
    assert_eq!(tail[1].submission_id, Some(SubmissionId(3)));
    assert_eq!(tail[1].text, "tail");
}

#[tokio::test]
async fn exact_product_epoch_refuses_stale_stop_before_accepting_current_stop() {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut stale = TurnSubmission::identified(SubmissionId(11), Op::Drain);
    stale.expected_product_turn_id = Some(ProductTurnId(7));
    let mut current = TurnSubmission::identified(SubmissionId(12), Op::ForceCancel);
    current.expected_product_turn_id = Some(ProductTurnId(8));
    tx.send(stale).await.unwrap();
    tx.send(current).await.unwrap();
    let mut controls = SessionControlState::default();
    let mut inbox = SessionSubmissionInbox::default();
    inbox.bind_product_turn(Some(ProductTurnId(8)));
    inbox.bind_receiver(rx);
    let receipt = inbox.poll(&mut controls, 256, false);
    assert_eq!(receipt.stale, vec![SubmissionId(11)]);
    assert_eq!(receipt.control_submission, Some(SubmissionId(12)));
    assert_eq!(controls.requested(), InboundControl::ForceCancel);
    assert!(!controls.drain().load(Ordering::Relaxed));
}

#[test]
fn inherited_child_terminal_cannot_clear_parent_drain() {
    let shared = Arc::new(AtomicBool::new(false));
    let mut parent = SessionControlState::default();
    let mut child = SessionControlState::default();
    parent.bind_drain(shared.clone());
    child.inherit_drain(shared.clone());
    parent.request(InboundControl::Drain);
    child.clear_drain_after_terminal();
    assert_eq!(child.requested(), InboundControl::Drain);
    assert_eq!(parent.requested(), InboundControl::Drain);
    parent.clear_drain_after_terminal();
    assert_eq!(child.requested(), InboundControl::None);
    assert!(!shared.load(Ordering::Relaxed));
}

#[test]
fn failed_append_restore_retains_source_order_and_overflow_never_evicts_a_steer() {
    let mut inbox = SessionSubmissionInbox::default();
    inbox
        .push(PendingSteer::internal("internal".into()))
        .unwrap();
    for id in 1..=255 {
        inbox
            .push(PendingSteer::from_steer(
                format!("steer-{id}"),
                SubmissionId(id),
            ))
            .unwrap();
    }
    let overflow = inbox
        .push(PendingSteer::from_steer(
            "overflow".into(),
            SubmissionId(256),
        ))
        .unwrap_err();
    assert_eq!(overflow.submission_id, Some(SubmissionId(256)));
    let failed = inbox.pop().unwrap();
    inbox.restore_front(failed);
    let (entries, visible) = inbox.reclaim();
    assert_eq!(entries.len(), 256);
    assert_eq!(visible, 255);
    assert!(!entries[0].client_visible);
    assert_eq!(entries[1].submission_id, Some(SubmissionId(1)));
    assert_eq!(entries[255].submission_id, Some(SubmissionId(255)));
    assert!(inbox.is_empty());
}

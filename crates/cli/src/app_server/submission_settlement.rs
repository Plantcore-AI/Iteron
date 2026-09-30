//! Ordered submission receipt settlement and bounded queue expiry.

use super::{
    EventPublisher, KernelSubmissionKind, LifecyclePayload, PendingKernelSubmission,
    QueuedSubmission, ServerEvent, SessionSnapshot, SubmissionDeduplicator, SubmissionId,
    SubmissionIdentityAdmission, SubmissionLifecycleState, TurnId, UiEvent, mpsc, product_contract,
};

pub(super) fn product_turn_accepts(
    expected: Option<iteron_protocol::product_contract::ProductTurnId>,
    contract: &product_contract::ContractReader,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    contract
        .snapshot()
        .and_then(|snapshot| snapshot.turn)
        .is_some_and(|turn| {
            turn.turn_id == expected
                && turn.state == iteron_protocol::product_contract::TurnStateV1::Running
        })
}

pub(super) async fn settle_kernel_submission_events(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<PendingKernelSubmission>,
    event: &UiEvent,
) {
    if let UiEvent::SubmissionRejected { id, reason_code } = event {
        if let Some(index) = pending.iter().position(|entry| entry.id == *id) {
            pending.remove(index);
            publish_submission(
                events,
                *id,
                SubmissionLifecycleState::Rejected,
                Some(*reason_code),
            )
            .await;
        }
        return;
    }
    if let UiEvent::ControlSubmissionApplied { id, kind } = event {
        let expected = match kind {
            crate::runtime::ControlSubmissionKind::Interrupt
            | crate::runtime::ControlSubmissionKind::ForceCancel => KernelSubmissionKind::Interrupt,
            crate::runtime::ControlSubmissionKind::Drain => KernelSubmissionKind::Drain,
        };
        if let Some(index) = pending
            .iter()
            .position(|entry| entry.id == *id && entry.kind == expected)
        {
            pending.remove(index);
            publish_submission(events, *id, SubmissionLifecycleState::Applied, None).await;
        }
        return;
    }
    if let UiEvent::ApprovalResolved {
        response_submission_id: Some(id),
        ..
    } = event
    {
        let Some(index) = pending
            .iter()
            .position(|entry| entry.kind == KernelSubmissionKind::Approval && entry.id == *id)
        else {
            return;
        };
        pending.remove(index);
        publish_submission(events, *id, SubmissionLifecycleState::Applied, None).await;
        return;
    }
    let UiEvent::SteerSubmissionApplied { id } = event else {
        return;
    };
    let Some(index) = pending
        .iter()
        .position(|entry| entry.kind == KernelSubmissionKind::Steer && entry.id == *id)
    else {
        return;
    };
    pending.remove(index);
    publish_submission(events, *id, SubmissionLifecycleState::Applied, None).await;
}

pub(super) fn forward_runtime_notifications(
    snapshot: &mut SessionSnapshot,
    pending_runtime: &mut std::collections::VecDeque<String>,
) {
    pending_runtime.extend(snapshot.unadmitted_internal_notifications.drain(..));
}

pub(super) fn discard_expired_product_steers(
    snapshot: &mut SessionSnapshot,
    pending: &std::collections::VecDeque<PendingKernelSubmission>,
) {
    let ids = std::mem::take(&mut snapshot.unadmitted_steer_submission_ids);
    let texts = std::mem::take(&mut snapshot.unadmitted_steers);
    for (index, text) in texts.into_iter().enumerate() {
        let id = ids.get(index).copied().flatten();
        let expired = id.is_some_and(|id| {
            pending.iter().any(|entry| {
                entry.id == id
                    && entry.kind == KernelSubmissionKind::Steer
                    && entry.expected_product_turn_id.is_some()
            })
        });
        if !expired {
            snapshot.unadmitted_steers.push(text);
            snapshot.unadmitted_steer_submission_ids.push(id);
        }
    }
    snapshot.unadmitted_client_steers = snapshot.unadmitted_steers.len();
}

pub(super) async fn settle_kernel_submissions_at_turn_end(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<PendingKernelSubmission>,
    unadmitted_steer_ids: &[Option<SubmissionId>],
) {
    while let Some(entry) = pending.pop_front() {
        let (state, reason) = match entry.kind {
            KernelSubmissionKind::Steer if entry.expected_product_turn_id.is_some() => {
                (SubmissionLifecycleState::Expired, Some("turn_expired"))
            }
            KernelSubmissionKind::Steer if unadmitted_steer_ids.contains(&Some(entry.id)) => (
                SubmissionLifecycleState::Requeued,
                Some("safe_point_missed"),
            ),
            KernelSubmissionKind::Steer => (
                SubmissionLifecycleState::Rejected,
                Some("application_unconfirmed"),
            ),
            KernelSubmissionKind::Approval => (
                SubmissionLifecycleState::Rejected,
                Some("application_unconfirmed"),
            ),
            KernelSubmissionKind::Interrupt | KernelSubmissionKind::Drain => (
                SubmissionLifecycleState::Rejected,
                Some("application_unconfirmed"),
            ),
        };
        publish_submission(events, entry.id, state, reason).await;
    }
}

pub(super) async fn publish_submission(
    events: &mut EventPublisher,
    id: SubmissionId,
    state: SubmissionLifecycleState,
    reason_code: Option<&'static str>,
) {
    events.record_submission_lifecycle(id, state, reason_code);
    let _ = events
        .publish(ServerEvent::Submission {
            id,
            state,
            reason_code,
        })
        .await;
}

pub(super) async fn receive_next_submission(
    priority: &mut mpsc::Receiver<QueuedSubmission>,
    data: &mut mpsc::Receiver<QueuedSubmission>,
) -> Option<QueuedSubmission> {
    loop {
        let priority_done = priority.is_closed() && priority.is_empty();
        let data_done = data.is_closed() && data.is_empty();
        if priority_done && data_done {
            return None;
        }
        tokio::select! {
            biased;
            queued = priority.recv(), if !priority_done => {
                if queued.is_some() {
                    return queued;
                }
            }
            queued = data.recv(), if !data_done => {
                if queued.is_some() {
                    return queued;
                }
            }
        }
    }
}

pub(super) fn queue_population(
    data: &mpsc::Receiver<QueuedSubmission>,
    priority: &mpsc::Receiver<QueuedSubmission>,
    pending_turns: usize,
) -> u64 {
    u64::try_from(
        data.len()
            .saturating_add(priority.len())
            .saturating_add(pending_turns),
    )
    .unwrap_or(u64::MAX)
}

pub(super) async fn expire_pending_turns(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<QueuedSubmission>,
    reason: &'static str,
) {
    while let Some(queued) = pending.pop_front() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some(reason),
        )
        .await;
    }
}

pub(super) async fn expire_queued_after_drain(
    events: &mut EventPublisher,
    data: &mut mpsc::Receiver<QueuedSubmission>,
    priority: &mut mpsc::Receiver<QueuedSubmission>,
) {
    while let Ok(queued) = priority.try_recv() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some("drain_settled"),
        )
        .await;
    }
    while let Ok(queued) = data.try_recv() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some("drain_settled"),
        )
        .await;
    }
}

pub(super) async fn reject_replayed_submission(
    events: &mut EventPublisher,
    identities: &mut SubmissionDeduplicator,
    id: SubmissionId,
    turn_id: Option<TurnId>,
) -> bool {
    let admission = identities.admit(id);
    let (event_id, reason) = match admission {
        SubmissionIdentityAdmission::Fresh => return false,
        SubmissionIdentityAdmission::Duplicate => ("submission.deduplicated", "duplicate_id"),
        SubmissionIdentityAdmission::Stale => ("control.stale_rejected", "stale_id"),
    };
    events.record_lifecycle(
        event_id,
        turn_id,
        Some(id),
        LifecyclePayload {
            reason_code: Some(reason.into()),
            ..LifecyclePayload::default()
        },
    );
    publish_submission(events, id, SubmissionLifecycleState::Rejected, Some(reason)).await;
    true
}

use super::*;

pub(super) fn stale_product_epoch(
    active: Option<iteron_protocol::product_contract::ProductTurnId>,
    envelope: &SqEnvelope,
) -> bool {
    envelope
        .expected_product_turn_id
        .is_some_and(|expected| Some(expected) != active)
}

/// A profile may choose a smaller control batch, but it cannot disable the only queue that
/// carries interrupt, drain, and steering. Keep the physical upper bound as well.
pub(super) fn inbound_poll_limit() -> usize {
    bounded_inbound_poll_limit(iteron_tunables::param_integer(
        "cli.runtime.max_inbound_ops_per_poll",
        MAX_INBOUND_OPS_PER_POLL,
    ))
}

fn bounded_inbound_poll_limit(configured: usize) -> usize {
    configured.clamp(1, MAX_INBOUND_OPS_PER_POLL)
}

#[derive(Debug, Clone)]
pub(super) struct PendingSteer {
    text: String,
    /// Internal runtime notifications must never consume a client's steer receipt.
    client_visible: bool,
    submission_id: Option<SubmissionId>,
}

/// One message reclaimed at the run boundary. The source bit is authoritative for frontend
/// receipt reconciliation; a user can write text resembling an internal notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnadmittedSteer {
    pub(crate) text: String,
    pub(crate) client_visible: bool,
    pub(crate) submission_id: Option<SubmissionId>,
}

impl PendingSteer {
    pub(super) fn user(text: String) -> Self {
        Self {
            text,
            client_visible: true,
            submission_id: None,
        }
    }

    pub(super) fn internal(text: String) -> Self {
        Self {
            text,
            client_visible: false,
            submission_id: None,
        }
    }

    pub(super) fn from_steer(text: String, submission_id: SubmissionId) -> Self {
        // The App Server mints nonzero IDs for every client submission. Zero is reserved for its
        // own legacy/internal notification producer; never infer internal authority from a
        // client-authored text prefix when an identified submission is present.
        if submission_id.0 == 0 && text.starts_with(RUNTIME_NOTIFICATION_PREFIX) {
            Self::internal(text)
        } else {
            Self {
                text,
                client_visible: true,
                submission_id: (submission_id.0 != 0).then_some(submission_id),
            }
        }
    }
}

impl Agent {
    /// Drain frontend submissions without waiting. Steering is retained in FIFO order; interrupt
    /// and drain stop admission at that exact queue position and flip the cooperative stop flag.
    pub(super) fn collect_inbound_ops(&mut self, turn: TurnId) -> InboundControl {
        self.collect_inbound_ops_with_limit(turn, inbound_poll_limit())
    }

    /// The explicit limit keeps the one-item poll and spillover case deterministically testable.
    pub(super) fn collect_inbound_ops_with_limit(
        &mut self,
        turn: TurnId,
        limit: usize,
    ) -> InboundControl {
        let mut steering = Vec::new();
        let mut unknown = 0usize;
        let mut version_mismatch = 0usize;
        let mut stale_ids = Vec::new();
        let mut control = InboundControl::None;
        let mut control_submission_id = None;
        let active_product_turn_id = self.active_product_turn_id;
        if let Some(rx) = self.approvals_rx.as_mut() {
            for _ in 0..limit.clamp(1, MAX_INBOUND_OPS_PER_POLL) {
                let Ok(envelope) = rx.try_recv() else {
                    break;
                };
                if stale_product_epoch(active_product_turn_id, &envelope) {
                    stale_ids.push(envelope.submission_id);
                    continue;
                }
                let Ok((submission_id, op)) = envelope.into_current_identified() else {
                    version_mismatch = version_mismatch.saturating_add(1);
                    continue;
                };
                match op {
                    Op::Steer { text } => {
                        steering.push(PendingSteer::from_steer(text, submission_id));
                    }
                    Op::UserInput { text } => steering.push(PendingSteer::user(text)),
                    Op::Interrupt => {
                        control = InboundControl::Interrupt;
                        control_submission_id = (submission_id.0 != 0).then_some(submission_id);
                        break;
                    }
                    Op::ForceCancel => {
                        control = InboundControl::ForceCancel;
                        control_submission_id = (submission_id.0 != 0).then_some(submission_id);
                        break;
                    }
                    Op::Drain => {
                        control = InboundControl::Drain;
                        control_submission_id = (submission_id.0 != 0).then_some(submission_id);
                        break;
                    }
                    // An approval response has meaning only while `await_approval` owns the queue.
                    Op::ApprovalResponse { .. } => {}
                    Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
                        unknown = unknown.saturating_add(1)
                    }
                }
            }
        }
        self.pending_steers.extend(steering);
        self.reject_stale_product_submissions(stale_ids);
        self.record_rejected_submissions(
            turn,
            unknown,
            SubmissionRejectionReason::UnsupportedOperation,
            UNSUPPORTED_SUBMISSION_NOTICE,
        );
        self.record_rejected_submissions(
            turn,
            version_mismatch,
            SubmissionRejectionReason::ProtocolVersionMismatch,
            VERSION_MISMATCH_SUBMISSION_NOTICE,
        );
        match control {
            InboundControl::Interrupt => {
                self.interrupt_requested = true;
                if let Some(interrupt) = &self.interrupt {
                    interrupt.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
            InboundControl::ForceCancel => {
                self.force_cancel_requested = true;
                self.force_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
                let requested = self
                    .force_cancel_seam
                    .as_mut()
                    .is_some_and(|seam| seam.request(turn));
                self.lifecycle_event(
                    "cancel.forced",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some(
                            if requested {
                                "process_reap_requested"
                            } else {
                                "process_reap_unwired"
                            }
                            .into(),
                        ),
                        ..LifecyclePayload::default()
                    },
                );
            }
            InboundControl::Drain => {
                self.drain_requested = true;
                self.drain.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            InboundControl::None => {}
        }
        if let Some(id) = control_submission_id {
            let kind = match control {
                InboundControl::Interrupt => ControlSubmissionKind::Interrupt,
                InboundControl::ForceCancel => ControlSubmissionKind::ForceCancel,
                InboundControl::Drain => ControlSubmissionKind::Drain,
                InboundControl::None => unreachable!("control id requires an applied control"),
            };
            self.ui(UiEvent::ControlSubmissionApplied { id, kind });
        }
        control
    }

    pub(super) fn reject_stale_product_submissions(&mut self, ids: Vec<SubmissionId>) {
        for id in ids {
            if id.0 != 0 {
                self.ui(UiEvent::SubmissionRejected {
                    id,
                    reason_code: "turn_mismatch_or_terminal",
                });
            }
        }
    }

    /// Persist a closed rejection reason before exposing it to the frontend. `Op::Unknown` has
    /// already erased the unrecognized tag and payload, and neither is accepted as an argument.
    pub(super) fn record_rejected_submissions(
        &mut self,
        turn: TurnId,
        count: usize,
        reason: SubmissionRejectionReason,
        notice: &'static str,
    ) {
        debug_assert!(count <= inbound_poll_limit());
        for _ in 0..count {
            if self
                .emit_durable(turn, EventKind::SubmissionRejected { reason })
                .is_err()
            {
                break;
            }
            self.ui(UiEvent::Notice(notice.into()));
        }
    }

    /// Compatibility shim for the runtime's text-only reclaim tests. Production consumers use
    /// `take_unadmitted_steers_with_client_count` so source identity is never discarded.
    #[cfg(test)]
    pub fn take_unadmitted_steers(&mut self) -> Vec<String> {
        self.take_unadmitted_steers_with_client_count()
            .0
            .into_iter()
            .map(|steer| steer.text)
            .collect()
    }

    /// Exact App Server handoff after joining the completed run: keep each steer source beside
    /// its text and report the number of client-visible submissions. Internal notifications
    /// cannot consume a user receipt or be misclassified by a user-authored prefix.
    pub(crate) fn take_unadmitted_steers_with_client_count(
        &mut self,
    ) -> (Vec<UnadmittedSteer>, usize) {
        let mut unknown = 0usize;
        let mut version_mismatch = 0usize;
        let mut stale_ids = Vec::new();
        let active_product_turn_id = self.active_product_turn_id;
        if let Some(rx) = self.approvals_rx.as_mut() {
            for _ in 0..inbound_poll_limit() {
                let Ok(envelope) = rx.try_recv() else {
                    break;
                };
                if stale_product_epoch(active_product_turn_id, &envelope) {
                    stale_ids.push(envelope.submission_id);
                    continue;
                }
                let Ok((submission_id, op)) = envelope.into_current_identified() else {
                    version_mismatch = version_mismatch.saturating_add(1);
                    continue;
                };
                match op {
                    Op::Steer { text } => self
                        .pending_steers
                        .push_back(PendingSteer::from_steer(text, submission_id)),
                    Op::UserInput { text } => {
                        self.pending_steers.push_back(PendingSteer::user(text));
                    }
                    Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
                        unknown = unknown.saturating_add(1)
                    }
                    Op::ApprovalResponse { .. } | Op::Interrupt | Op::ForceCancel | Op::Drain => {}
                }
            }
        }
        self.reject_stale_product_submissions(stale_ids);
        self.record_rejected_submissions(
            TurnId(self.seq_turn),
            unknown,
            SubmissionRejectionReason::UnsupportedOperation,
            UNSUPPORTED_SUBMISSION_NOTICE,
        );
        self.record_rejected_submissions(
            TurnId(self.seq_turn),
            version_mismatch,
            SubmissionRejectionReason::ProtocolVersionMismatch,
            VERSION_MISMATCH_SUBMISSION_NOTICE,
        );
        let entries = self
            .pending_steers
            .drain(..)
            .map(|steer| UnadmittedSteer {
                text: steer.text,
                client_visible: steer.client_visible,
                submission_id: steer.submission_id,
            })
            .collect::<Vec<_>>();
        let client_visible_count = entries.iter().filter(|steer| steer.client_visible).count();
        (entries, client_visible_count)
    }

    /// Admit queued steering at a turn boundary. The durable message is written before the working
    /// transcript changes; replay merges adjacent user messages to reconstruct the same request.
    pub(super) fn admit_pending_steers(
        &mut self,
        turn: TurnId,
        messages: &mut Vec<Message>,
    ) -> Result<usize, KernelError> {
        let _ = self.collect_inbound_ops(turn);
        let mut admitted = 0usize;
        let mut legacy_client_visible = 0usize;
        while let Some(steer) = self.pending_steers.pop_front() {
            if steer.text.trim().is_empty() {
                continue;
            }
            let text = strict_utf8_head(
                &steer.text,
                iteron_tunables::param_integer("cli.runtime.max_steer_bytes", MAX_STEER_BYTES),
            );
            let runtime_notification =
                !steer.client_visible && text.starts_with(RUNTIME_NOTIFICATION_PREFIX);
            let memory_added =
                !steer.client_visible && text.starts_with(MEMORY_ADDED_NOTIFICATION_PREFIX);
            if memory_added {
                // `/memory add` writes through the TUI's explicit project-memory authority rather
                // than a registry tool. This runtime notification is the matching mutation signal:
                // advance the pure-tool generation before the new fact can be read this session.
                self.registry.invalidate_pure_cache();
            }
            let message = if runtime_notification || memory_added {
                Message::user_text(text)
            } else {
                Message::user_text(format!(
                    "Operator steering received while the run was active:\n{text}"
                ))
            };
            if let Err(error) = self.emit_durable(
                turn,
                EventKind::Message {
                    message: message.clone(),
                },
            ) {
                // The rejected append has no receipt and may not consume an identified steer.
                // Preserve it ahead of the tail for the App Server's exact-ID requeue handoff.
                self.pending_steers.push_front(steer);
                if admitted > 0 {
                    self.context_estimator.invalidate_transcript();
                }
                return Err(error);
            }
            if let Some(id) = steer.submission_id {
                self.ui(UiEvent::SteerSubmissionApplied { id });
            }
            merge_adjacent_user_message(messages, message);
            admitted = admitted.saturating_add(1);
            legacy_client_visible = legacy_client_visible.saturating_add(usize::from(
                steer.client_visible && steer.submission_id.is_none(),
            ));
        }
        if admitted > 0 {
            // Steering merges into the trailing user message rather than appending, so an
            // already-counted message changed underneath the running total (I-60).
            self.context_estimator.invalidate_transcript();
            if legacy_client_visible > 0 {
                self.ui(UiEvent::SteerApplied {
                    count: legacy_client_visible,
                });
            }
        }
        Ok(admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_queue_batch_cannot_be_disabled_or_made_unbounded_by_a_profile() {
        assert_eq!(bounded_inbound_poll_limit(0), 1);
        assert_eq!(bounded_inbound_poll_limit(1), 1);
        assert_eq!(bounded_inbound_poll_limit(8), 8);
        assert_eq!(
            bounded_inbound_poll_limit(usize::MAX),
            MAX_INBOUND_OPS_PER_POLL
        );
    }
}

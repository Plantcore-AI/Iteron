use super::*;

/// Host-only routing metadata around the unchanged public SQ wire envelope. The expected
/// Product turn travels through both bounded queues and is checked at the runtime consume point,
/// so a control delayed past a terminal boundary cannot act on the next user turn.
#[derive(Debug, Clone)]
pub(crate) struct TurnSubmission {
    envelope: SqEnvelope,
    pub(crate) expected_product_turn_id: Option<iteron_protocol::product_contract::ProductTurnId>,
}

impl TurnSubmission {
    pub(crate) fn current(op: Op) -> Self {
        SqEnvelope::current(op).into()
    }

    #[cfg(test)]
    pub(crate) fn identified(submission_id: SubmissionId, op: Op) -> Self {
        SqEnvelope::identified(submission_id, op).into()
    }

    #[cfg(test)]
    pub(crate) fn with_version(protocol_version: u32, op: Op) -> Self {
        SqEnvelope::with_version(protocol_version, op).into()
    }

    pub(crate) fn with_version_and_id(
        protocol_version: u32,
        submission_id: SubmissionId,
        op: Op,
    ) -> Self {
        SqEnvelope::with_version_and_id(protocol_version, submission_id, op).into()
    }

    pub(crate) fn into_current_identified(
        self,
    ) -> Result<(SubmissionId, Op), iteron_protocol::ProtocolVersionError> {
        self.envelope.into_current_identified()
    }

    #[cfg(test)]
    pub(crate) fn into_current(self) -> Result<Op, iteron_protocol::ProtocolVersionError> {
        self.envelope.into_current()
    }
}

impl From<SqEnvelope> for TurnSubmission {
    fn from(envelope: SqEnvelope) -> Self {
        Self {
            envelope,
            expected_product_turn_id: None,
        }
    }
}

impl From<Op> for TurnSubmission {
    fn from(op: Op) -> Self {
        Self::current(op)
    }
}

impl std::ops::Deref for TurnSubmission {
    type Target = SqEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.envelope
    }
}

pub(super) fn stale_product_epoch(
    active: Option<iteron_protocol::product_contract::ProductTurnId>,
    envelope: &TurnSubmission,
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
    pub(super) text: String,
    /// Internal runtime notifications must never consume a client's steer receipt.
    pub(super) client_visible: bool,
    pub(super) submission_id: Option<SubmissionId>,
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
        let receipt = self.inbox.poll(&mut self.control, limit, false);
        let control = receipt.control;
        let control_submission_id = receipt.control_submission;
        let unknown = receipt.unknown;
        let version_mismatch = receipt.versions;
        let stale_ids = receipt.stale;
        self.reject_saturated_steers(receipt.saturated, turn);
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
            InboundControl::ForceCancel => {
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
            _ => {}
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

    fn reject_saturated_steers(&mut self, ids: Vec<SubmissionId>, turn: TurnId) {
        for id in ids {
            if self
                .emit_durable(
                    turn,
                    EventKind::Notice {
                        text: "steering queue capacity exceeded; submission was not applied".into(),
                    },
                )
                .is_err()
            {
                break;
            }
            if id.0 != 0 {
                self.ui(UiEvent::SubmissionRejected {
                    id,
                    reason_code: "steering_queue_saturated",
                });
            }
        }
    }
    pub(super) fn retain_pending_steer(&mut self, steer: PendingSteer) {
        if let Err(steer) = self.inbox.push(steer) {
            self.reject_saturated_steers(
                vec![steer.submission_id.unwrap_or(SubmissionId(0))],
                TurnId(self.seq_turn),
            );
        }
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
        let receipt = self
            .inbox
            .poll(&mut self.control, inbound_poll_limit(), true);
        let unknown = receipt.unknown;
        let version_mismatch = receipt.versions;
        let stale_ids = receipt.stale;
        self.reject_saturated_steers(receipt.saturated, TurnId(self.seq_turn));
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
        self.inbox.reclaim()
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
        while let Some(steer) = self.inbox.pop() {
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
                self.inbox.restore_front(steer);
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
    fn host_turn_binding_preserves_the_public_wire_and_protocol_admission() {
        use iteron_protocol::product_contract::ProductTurnId;

        let wire = iteron_protocol::SqEnvelope::identified(SubmissionId(7), Op::Interrupt);
        let encoded = serde_json::to_value(&wire).unwrap();
        let mut bound = TurnSubmission::from(wire);
        assert_eq!(bound.expected_product_turn_id, None);
        bound.expected_product_turn_id = Some(ProductTurnId(42));
        assert_eq!(serde_json::to_value(&bound.envelope).unwrap(), encoded);
        assert!(encoded.get("expected_product_turn_id").is_none());
        assert!(!stale_product_epoch(Some(ProductTurnId(42)), &bound));
        assert!(stale_product_epoch(Some(ProductTurnId(43)), &bound));
        assert!(stale_product_epoch(None, &bound));
        assert!(matches!(
            bound.into_current_identified(),
            Ok((SubmissionId(7), Op::Interrupt))
        ));

        let mut skewed =
            TurnSubmission::with_version(iteron_protocol::PROTOCOL_VERSION + 1, Op::Interrupt);
        skewed.expected_product_turn_id = Some(ProductTurnId(42));
        assert!(!stale_product_epoch(Some(ProductTurnId(42)), &skewed));
        assert!(skewed.into_current_identified().is_err());
    }

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

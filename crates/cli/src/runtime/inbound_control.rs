use super::*;

impl Agent {
    /// Drain frontend submissions without waiting. Steering is retained in FIFO order; interrupt
    /// and drain stop admission at that exact queue position and flip the cooperative stop flag.
    pub(super) fn collect_inbound_ops(&mut self, turn: TurnId) -> InboundControl {
        let mut steering = Vec::new();
        let mut unknown = 0usize;
        let mut version_mismatch = 0usize;
        let mut control = InboundControl::None;
        if let Some(rx) = self.approvals_rx.as_mut() {
            for _ in 0..iteron_tunables::param_integer(
                "cli.runtime.max_inbound_ops_per_poll",
                MAX_INBOUND_OPS_PER_POLL,
            ) {
                let Ok(envelope) = rx.try_recv() else {
                    break;
                };
                let Ok(op) = envelope.into_current() else {
                    version_mismatch = version_mismatch.saturating_add(1);
                    continue;
                };
                match op {
                    Op::Steer { text } | Op::UserInput { text } => steering.push(text),
                    Op::Interrupt | Op::ForceCancel => {
                        control = InboundControl::Interrupt;
                        break;
                    }
                    Op::Drain => {
                        control = InboundControl::Drain;
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
            InboundControl::Drain => {
                self.drain_requested = true;
                self.drain.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            InboundControl::None => {}
        }
        control
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
        debug_assert!(
            count
                <= iteron_tunables::param_integer(
                    "cli.runtime.max_inbound_ops_per_poll",
                    MAX_INBOUND_OPS_PER_POLL
                )
        );
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

    /// Reclaim steering operations that reached the legacy session channel but were not admitted at
    /// a turn boundary. The TUI calls this only after joining the completed run, then reclassifies
    /// the returned texts as ordered after-turn submissions. Draining here prevents the same input
    /// from remaining in `approvals_rx` and being injected again on the next run.
    pub fn take_unadmitted_steers(&mut self) -> Vec<String> {
        let mut unknown = 0usize;
        let mut version_mismatch = 0usize;
        if let Some(rx) = self.approvals_rx.as_mut() {
            for _ in 0..iteron_tunables::param_integer(
                "cli.runtime.max_inbound_ops_per_poll",
                MAX_INBOUND_OPS_PER_POLL,
            ) {
                let Ok(envelope) = rx.try_recv() else {
                    break;
                };
                let Ok(op) = envelope.into_current() else {
                    version_mismatch = version_mismatch.saturating_add(1);
                    continue;
                };
                match op {
                    Op::Steer { text } | Op::UserInput { text } => {
                        self.pending_steers.push_back(text);
                    }
                    Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
                        unknown = unknown.saturating_add(1)
                    }
                    Op::ApprovalResponse { .. } | Op::Interrupt | Op::ForceCancel | Op::Drain => {}
                }
            }
        }
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
        self.pending_steers.drain(..).collect()
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
        while let Some(text) = self.pending_steers.pop_front() {
            if text.trim().is_empty() {
                continue;
            }
            let text = strict_utf8_head(
                &text,
                iteron_tunables::param_integer("cli.runtime.max_steer_bytes", MAX_STEER_BYTES),
            );
            let runtime_notification = text.starts_with(RUNTIME_NOTIFICATION_PREFIX);
            let memory_added = text.starts_with(MEMORY_ADDED_NOTIFICATION_PREFIX);
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
            self.emit_durable(
                turn,
                EventKind::Message {
                    message: message.clone(),
                },
            )?;
            merge_adjacent_user_message(messages, message);
            admitted = admitted.saturating_add(1);
        }
        if admitted > 0 {
            // Steering merges into the trailing user message rather than appending, so an
            // already-counted message changed underneath the running total (I-60).
            self.context_estimator.invalidate_transcript();
            self.ui(UiEvent::SteerApplied { count: admitted });
        }
        Ok(admitted)
    }
}

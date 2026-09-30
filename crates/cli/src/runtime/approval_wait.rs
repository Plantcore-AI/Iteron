//! Actual single approval transaction: bounded ingress, durable verdict and read-only presentation.
//! Permission widening is a separate host policy transaction after this receipt succeeds.
use super::KernelError;
use super::force_cancel::ForceCancelSeam;
use super::frontend_events::{ApprovalResolution, ControlSubmissionKind, UiEvent};
use super::inbound_control::{PendingSteer, stale_product_epoch};
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use super::turn_activity::{ActivitySink, ActivitySpan, ActivityStage};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{
    Capability, Event, EventKind, Op, Seq, SubmissionId, SubmissionRejectionReason, TurnId, Verdict,
};
use iteron_record::{RecordError, Rollout};
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub(super) struct ApprovalRequest {
    pub(super) turn: TurnId,
    pub(super) id: SubmissionId,
    pub(super) call_id: String,
    pub(super) tool: String,
    pub(super) capability: Capability,
    pub(super) arguments: Value,
    pub(super) workspace: String,
    pub(super) reason: String,
    pub(super) interactive: bool,
    pub(super) deadline: Option<Instant>,
    pub(super) poll: Duration,
}

pub(super) struct ApprovalJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<super::DurableAppendFault>,
}
impl ApprovalJournal<'_> {
    fn append(&mut self, turn: TurnId, kind: EventKind) -> Result<(), KernelError> {
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "approval cannot continue after the durable record failed",
            ))));
        }
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::Notice)
            && matches!(kind, EventKind::Notice { .. })
        {
            *self.fault = None;
            return Err(self.failed(RecordError::Io(std::io::Error::other(
                "injected durable append failure",
            ))));
        }
        let started = Instant::now();
        let result = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind,
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result.map(|_| ()).map_err(|error| self.failed(error))
    }
    fn failed(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    fn verdict(&mut self, request: &ApprovalRequest, verdict: Verdict) -> Result<(), KernelError> {
        self.append(
            request.turn,
            EventKind::Approval {
                id: request.id,
                tool_use_id: request.call_id.clone(),
                tool: request.tool.clone(),
                capability: request.capability,
                arguments: request.arguments.clone(),
                workspace: request.workspace.clone(),
                verdict,
            },
        )
    }
}

pub(super) struct ApprovalWait<'a> {
    pub(super) journal: ApprovalJournal<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) activity: ActivitySink,
    pub(super) events: StreamToolEvents,
}
pub(super) struct ApprovalDecision {
    pub(super) approved: bool,
    pub(super) remember: bool,
    id: SubmissionId,
    resolution: ApprovalResolution,
    reason: &'static str,
    response: Option<SubmissionId>,
    already_presented: bool,
    activity: Option<ActivitySpan>,
}
impl ApprovalDecision {
    /// Called only after any remembered-policy fsync. A true verdict without delivered resolution
    /// cannot authorize execution; the operator must see the same decision as the durable writer.
    pub(super) fn publish(mut self, events: &StreamToolEvents) -> Result<bool, KernelError> {
        if !self.already_presented
            && !events.present(UiEvent::ApprovalResolved {
                id: self.id,
                resolution: self.resolution,
                reason_code: self.reason,
                response_submission_id: self.response,
            })
            && self.approved
        {
            return Err(KernelError::EffectBoundary(
                "approval resolution could not reach the frontend".into(),
            ));
        }
        if let Some(activity) = self.activity.take() {
            activity.complete();
        }
        Ok(self.approved)
    }
    pub(super) fn policy_persist_failed(self, events: &StreamToolEvents) {
        events.present(UiEvent::ApprovalResolved {
            id: self.id,
            resolution: ApprovalResolution::Cancelled,
            reason_code: "remember_policy_persist_failed",
            response_submission_id: None,
        });
    }
}
impl ApprovalWait<'_> {
    pub(super) async fn run(
        mut self,
        request: ApprovalRequest,
    ) -> Result<ApprovalDecision, KernelError> {
        self.journal.verdict(&request, Verdict::Ask)?;
        if !request.interactive {
            self.journal.verdict(&request, Verdict::Deny)?;
            return Ok(self.present_refused(&request, "noninteractive_approval_unavailable"));
        }
        let activity = self
            .activity
            .span(ActivityStage::AwaitingApproval, Some(request.turn));
        if !self.events.present(UiEvent::ApprovalRequest {
            id: request.id,
            tool: request.tool.clone(),
            capability: request.capability,
            reason: request.reason.clone(),
            arguments: request.arguments.clone(),
            workspace: request.workspace.clone(),
        }) {
            activity.fail_unclassified();
            self.journal.verdict(&request, Verdict::Deny)?;
            self.events.emit(
                "tool.policy_evaluated",
                None,
                iteron_protocol::LifecyclePayload {
                    outcome_code: Some("denied".into()),
                    reason_code: Some("frontend_queue_saturated_or_closed".into()),
                    ..Default::default()
                },
            );
            return Ok(self.present_refused(&request, "frontend_queue_saturated_or_closed"));
        }
        // The receiver remains the single session-owned queue. Restoration precedes every terminal
        // append or policy operation, including failure, so the next resident turn retains ingress.
        let Some(mut receiver) = self.inbox.take_receiver() else {
            self.journal.verdict(&request, Verdict::Deny)?;
            return Ok(ApprovalDecision {
                approved: false,
                remember: false,
                id: request.id,
                resolution: ApprovalResolution::Cancelled,
                reason: "approval_channel_closed",
                response: None,
                already_presented: false,
                activity: Some(activity),
            });
        };
        let mut approved = false;
        let mut remember = false;
        let mut response = None;
        let mut resolution = ApprovalResolution::Cancelled;
        let mut reason = "approval_channel_closed";
        loop {
            if request
                .deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                resolution = ApprovalResolution::TimedOut;
                reason = "run_deadline_exhausted";
                break;
            }
            match self.control.requested() {
                InboundControl::Drain => {
                    reason = "drain_requested";
                    break;
                }
                InboundControl::ForceCancel => {
                    reason = "force_cancel_requested";
                    break;
                }
                InboundControl::Interrupt => {
                    reason = "interrupt_requested";
                    break;
                }
                InboundControl::None => {}
            }
            match tokio::time::timeout(request.poll.max(Duration::from_millis(1)), receiver.recv())
                .await
            {
                Ok(Some(envelope)) => {
                    if stale_product_epoch(self.inbox.product_turn(), &envelope) {
                        if envelope.submission_id.0 != 0 {
                            self.events.present(UiEvent::SubmissionRejected {
                                id: envelope.submission_id,
                                reason_code: "turn_mismatch_or_terminal",
                            });
                        }
                        continue;
                    }
                    let (id, op) = match envelope.into_current_identified() {
                        Ok(value) => value,
                        Err(_) => {
                            self.reject(
                                request.turn,
                                SubmissionRejectionReason::ProtocolVersionMismatch,
                                super::VERSION_MISMATCH_SUBMISSION_NOTICE,
                            );
                            if *self.journal.record_failed {
                                break;
                            }
                            continue;
                        }
                    };
                    match op {
                        Op::ApprovalResponse {
                            id: answer_id,
                            approved: answer,
                            remember: retain,
                        } if answer_id == request.id => {
                            response = (id.0 != 0).then_some(id);
                            approved = answer;
                            resolution = if answer {
                                ApprovalResolution::Approved
                            } else {
                                ApprovalResolution::Denied
                            };
                            reason = if answer {
                                "operator_approved"
                            } else {
                                "operator_denied"
                            };
                            remember = answer
                                && retain
                                && !matches!(
                                    request.capability,
                                    Capability::TrustMutating | Capability::IrreversibleExternal
                                );
                            break;
                        }
                        Op::ApprovalResponse { .. } => {}
                        Op::Interrupt | Op::ForceCancel | Op::Drain => {
                            let control = match op {
                                Op::Interrupt => InboundControl::Interrupt,
                                Op::ForceCancel => InboundControl::ForceCancel,
                                _ => InboundControl::Drain,
                            };
                            self.control.request(control);
                            let kind = match control {
                                InboundControl::Interrupt => {
                                    reason = "interrupt_requested";
                                    ControlSubmissionKind::Interrupt
                                }
                                InboundControl::Drain => {
                                    reason = "drain_requested";
                                    ControlSubmissionKind::Drain
                                }
                                InboundControl::ForceCancel => {
                                    reason = "force_cancel_requested";
                                    self.control.force_cancel().store(true, Ordering::Release);
                                    let requested = self
                                        .force_cancel
                                        .as_deref_mut()
                                        .is_some_and(|seam| seam.request(request.turn));
                                    self.events.emit(
                                        "cancel.forced",
                                        None,
                                        iteron_protocol::LifecyclePayload {
                                            reason_code: Some(
                                                if requested {
                                                    "process_reap_requested"
                                                } else {
                                                    "process_reap_unwired"
                                                }
                                                .into(),
                                            ),
                                            ..Default::default()
                                        },
                                    );
                                    ControlSubmissionKind::ForceCancel
                                }
                                InboundControl::None => unreachable!("control operation"),
                            };
                            if id.0 != 0 {
                                self.events
                                    .present(UiEvent::ControlSubmissionApplied { id, kind });
                            }
                            break;
                        }
                        Op::Steer { text } => {
                            self.retain(PendingSteer::from_steer(text, id), request.turn)
                        }
                        Op::UserInput { text } => {
                            self.retain(PendingSteer::user(text), request.turn)
                        }
                        Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => self
                            .reject(
                                request.turn,
                                SubmissionRejectionReason::UnsupportedOperation,
                                iteron_tunables::param_str(
                                    "cli.runtime.unsupported_submission_notice",
                                    super::UNSUPPORTED_SUBMISSION_NOTICE,
                                ),
                            ),
                    }
                    if *self.journal.record_failed {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }
        self.inbox.bind_receiver(receiver);
        self.journal.verdict(
            &request,
            if approved {
                Verdict::Auto
            } else {
                Verdict::Deny
            },
        )?;
        Ok(ApprovalDecision {
            approved,
            remember,
            id: request.id,
            resolution,
            reason,
            response,
            already_presented: false,
            activity: Some(activity),
        })
    }
    fn present_refused(&self, request: &ApprovalRequest, reason: &'static str) -> ApprovalDecision {
        self.events.present(UiEvent::ApprovalResolved {
            id: request.id,
            resolution: ApprovalResolution::Denied,
            reason_code: reason,
            response_submission_id: None,
        });
        ApprovalDecision {
            approved: false,
            remember: false,
            id: request.id,
            resolution: ApprovalResolution::Denied,
            reason,
            response: None,
            already_presented: true,
            activity: None,
        }
    }
    fn reject(&mut self, turn: TurnId, reason: SubmissionRejectionReason, notice: &'static str) {
        if self
            .journal
            .append(turn, EventKind::SubmissionRejected { reason })
            .is_ok()
        {
            self.events.present(UiEvent::Notice(notice.into()));
        }
    }
    fn retain(&mut self, steer: PendingSteer, turn: TurnId) {
        if let Err(steer) = self.inbox.push(steer) {
            if self
                .journal
                .append(
                    turn,
                    EventKind::Notice {
                        text: "steering queue capacity exceeded; submission was not applied".into(),
                    },
                )
                .is_ok()
                && let Some(id) = steer.submission_id.filter(|id| id.0 != 0)
            {
                self.events.present(UiEvent::SubmissionRejected {
                    id,
                    reason_code: "steering_queue_saturated",
                });
            }
        }
    }
}

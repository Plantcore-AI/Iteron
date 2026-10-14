//! Actual bounded control-queue poll and physical receipt projection. The existing inbox and
//! cooperative signal owners remain exclusive; this adapter admits no provider/tool effects.
use super::approval_wait::ApprovalJournal;
use super::force_cancel::ForceCancelSeam;
use super::frontend_events::{ControlSubmissionKind, UiEvent};
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use super::{UNSUPPORTED_SUBMISSION_NOTICE, VERSION_MISMATCH_SUBMISSION_NOTICE};
use iteron_protocol::{EventKind, LifecyclePayload, SubmissionRejectionReason, TurnId};

pub(super) struct ControlIngress<'a> {
    pub(super) journal: ApprovalJournal<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) events: StreamToolEvents,
}
impl ControlIngress<'_> {
    pub(super) fn poll(&mut self, turn: TurnId, limit: usize) -> InboundControl {
        let receipt = self.inbox.poll(self.control, limit, false);
        for id in receipt.saturated {
            if self
                .journal
                .append(
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
                self.events.present(UiEvent::SubmissionRejected {
                    id,
                    reason_code: "steering_queue_saturated",
                });
            }
        }
        for id in receipt.stale {
            if id.0 != 0 {
                self.events.present(UiEvent::SubmissionRejected {
                    id,
                    reason_code: "turn_mismatch_or_terminal",
                });
            }
        }
        self.rejected(
            turn,
            receipt.unknown,
            SubmissionRejectionReason::UnsupportedOperation,
            UNSUPPORTED_SUBMISSION_NOTICE,
        );
        self.rejected(
            turn,
            receipt.versions,
            SubmissionRejectionReason::ProtocolVersionMismatch,
            VERSION_MISMATCH_SUBMISSION_NOTICE,
        );
        if receipt.control == InboundControl::ForceCancel {
            let requested = self
                .force_cancel
                .as_mut()
                .is_some_and(|seam| seam.request(turn));
            self.events.emit(
                "cancel.forced",
                None,
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
        if let Some(id) = receipt.control_submission {
            let kind = match receipt.control {
                InboundControl::Interrupt => ControlSubmissionKind::Interrupt,
                InboundControl::ForceCancel => ControlSubmissionKind::ForceCancel,
                InboundControl::Drain => ControlSubmissionKind::Drain,
                InboundControl::None => {
                    unreachable!("control id requires an actual applied control")
                }
            };
            self.events
                .present(UiEvent::ControlSubmissionApplied { id, kind });
        }
        receipt.control
    }
    fn rejected(
        &mut self,
        turn: TurnId,
        count: usize,
        reason: SubmissionRejectionReason,
        notice: &'static str,
    ) {
        for _ in 0..count {
            if self
                .journal
                .append(turn, EventKind::SubmissionRejected { reason })
                .is_err()
            {
                break;
            }
            self.events.present(UiEvent::Notice(notice.into()));
        }
    }
}

//! Actual cancellation settlement owner. Signal acknowledgement, physical reap and durable
//! run terminal are separate facts; inherited atomics remain owned by their original caller.
use super::force_cancel::{ForceCancelSeam, ProcessReapProof};
use super::session_control::{InboundControl, SessionControlState};
use super::stream_tool_events::StreamToolEvents;
use super::turn_activity::{ActivitySink, ActivityStage};
use iteron_protocol::{LifecyclePayload, Outcome, TurnId};
use std::time::Duration;

pub(super) struct ControlTerminal<'a> {
    pub(super) seam: Option<&'a mut ForceCancelSeam>,
    pub(super) activity: ActivitySink,
    pub(super) events: StreamToolEvents,
}
pub(super) struct RequestedTerminal {
    control: InboundControl,
    turn: TurnId,
}
impl RequestedTerminal {
    pub(super) fn drained(&self) -> bool {
        self.control == InboundControl::Drain
    }
    pub(super) fn outcome(&self) -> Outcome {
        if self.drained() {
            Outcome::Drained
        } else {
            Outcome::Interrupted
        }
    }
    /// The host calls this only with the terminal returned by the actual finalization writer.
    /// A refused append preserves all latches and no Drop path can erase an external stop.
    pub(super) fn acknowledge(
        self,
        turn: TurnId,
        outcome: &Outcome,
        control: &mut SessionControlState,
    ) {
        if self.turn != turn || &self.outcome() != outcome {
            return;
        }
        match self.control {
            InboundControl::ForceCancel => control.clear_cancel_after_terminal(),
            InboundControl::Interrupt => control.clear_interrupt_after_terminal(),
            InboundControl::Drain => control.clear_drain_after_terminal(),
            InboundControl::None => {}
        }
    }
}
impl ControlTerminal<'_> {
    pub(super) async fn resolve(
        mut self,
        turn: TurnId,
        control: InboundControl,
    ) -> Option<RequestedTerminal> {
        match control {
            InboundControl::None => return None,
            InboundControl::Drain => {}
            InboundControl::Interrupt => self
                .activity
                .span(ActivityStage::Cancellation, Some(turn))
                .complete(),
            InboundControl::ForceCancel => {
                let activity = self.activity.span(ActivityStage::Cancellation, Some(turn));
                let proof = if let Some(seam) = self.seam.as_deref_mut() {
                    let observed = seam.latest_proof(turn);
                    if matches!(observed, ProcessReapProof::Unavailable) {
                        let _ = seam.request(turn);
                        seam.await_proof(
                            turn,
                            iteron_tunables::param_duration(
                                "cli.runtime.force_cancel_reap_terminal_budget",
                                Duration::from_secs(1),
                            ),
                        )
                        .await
                    } else {
                        // latest_proof drains the actual bounded queue. Preserve that physical
                        // receipt; polling again would consume it twice and invent unavailability.
                        observed
                    }
                } else {
                    ProcessReapProof::Unavailable
                };
                let completed = matches!(
                    proof,
                    ProcessReapProof::NoTrackedProcesses | ProcessReapProof::Reaped { .. }
                );
                self.events.emit(
                    if completed {
                        "cancel.completed"
                    } else {
                        "cancel.failed"
                    },
                    None,
                    LifecyclePayload {
                        reason_code: Some(proof.reason_code().into()),
                        ..Default::default()
                    },
                );
                let notice=match proof {
                    ProcessReapProof::NoTrackedProcesses=>"Force cancel completed; no tracked process groups remained.".to_owned(),
                    ProcessReapProof::Reaped {process_groups}=>format!("Force cancel completed; {process_groups} tracked process group(s) were killed and reaped."),
                    ProcessReapProof::Partial {reaped,unresolved}=>format!("Force cancel failed closed: {reaped} process group(s) reaped, {unresolved} unresolved."),
                    ProcessReapProof::Unavailable=>"Force cancel failed closed: process cleanup could not be proven within 1 second.".to_owned(),
                };
                self.events.present(super::UiEvent::Notice(notice));
                if completed {
                    activity.complete();
                } else {
                    activity.fail_unclassified();
                }
            }
        }
        Some(RequestedTerminal { control, turn })
    }
}

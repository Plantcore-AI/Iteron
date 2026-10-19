//! Existing submission/signal ownership projected through an actual bounded journal poll.
use super::{
    control_ingress::ControlIngress,
    force_cancel::ForceCancelSeam,
    kernel_dispatch_journal::KernelDispatchJournal,
    session_control::{InboundControl, SessionControlState},
    session_inbox::SessionSubmissionInbox,
    stream_tool_events::StreamToolEvents,
};
use iteron_protocol::TurnId;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(super) struct KernelDispatchControl<'a> {
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) events: StreamToolEvents,
}
impl KernelDispatchControl<'_> {
    pub(super) fn poll(
        &mut self,
        journal: &mut KernelDispatchJournal<'_>,
        turn: TurnId,
    ) -> InboundControl {
        ControlIngress {
            journal: journal.record(),
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            events: self.events.clone(),
        }
        .poll(turn, 64);
        self.control.requested()
    }
    pub(super) fn child_stop(
        &mut self,
        journal: &mut KernelDispatchJournal<'_>,
        turn: TurnId,
        stop: &Arc<AtomicBool>,
    ) {
        if matches!(
            self.poll(journal, turn),
            InboundControl::Interrupt | InboundControl::ForceCancel
        ) {
            stop.store(true, Ordering::Release);
        }
    }
    pub(super) fn force(&self) -> Arc<AtomicBool> {
        self.control.force_cancel().clone()
    }
    pub(super) fn drain(&self) -> Arc<AtomicBool> {
        self.control.drain().clone()
    }
}

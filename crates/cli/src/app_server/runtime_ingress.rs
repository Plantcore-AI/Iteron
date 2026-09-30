//! Ordered frontend ingress and exact kernel receipt settlement, with no runtime ownership.

use super::{
    EventPublisher, PendingKernelSubmission, ServerEvent, settle_kernel_submission_events,
};
use crate::runtime::{FrontendChannelHealth, RuntimeFrontendEvent};
use std::collections::VecDeque;

pub(super) async fn publish_runtime_event(
    events: &mut EventPublisher,
    pending: &mut VecDeque<PendingKernelSubmission>,
    channels: &FrontendChannelHealth,
    event: RuntimeFrontendEvent,
) {
    let bytes = channels.runtime_event_bytes(&event);
    let projected = match event {
        RuntimeFrontendEvent::Ui(ui) => {
            settle_kernel_submission_events(events, pending, &ui).await;
            ServerEvent::Ui(ui)
        }
        RuntimeFrontendEvent::Plantcore(event) => ServerEvent::Plantcore(event),
        RuntimeFrontendEvent::TurnPublication(event) => ServerEvent::TurnPublication(event),
    };
    // Presentation disconnection does not drop the resident future in the middle of an effect.
    let _ = events.publish(projected).await;
    channels.release_ui_bytes(bytes);
}

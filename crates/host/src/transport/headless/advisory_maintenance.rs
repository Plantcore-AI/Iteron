//! Independent maintenance snapshots never consume the frozen result/replay cursor.
use super::framing::{ServerFrame, send_frame};
use crate::app_server::{AppServerClient, ServerEvent};
use anyhow::Result;
use iteron_protocol::PROTOCOL_VERSION;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::sync::Semaphore;

#[allow(clippy::too_many_arguments)]
pub(super) async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    client: &AppServerClient,
    budget: &Arc<Semaphore>,
    preparers: &Arc<Semaphore>,
    encoders: &Arc<Semaphore>,
    last: &mut Option<(String, u64)>,
    event: ServerEvent,
) -> Result<()> {
    let Some(current) = client.thread_snapshot_v1() else {
        return Ok(());
    };
    let frame = match event {
        ServerEvent::AdvisoryMaintenance(event)
            if event.validate().is_ok()
                && current.thread_id == event.thread_id
                && current.run_id == event.run_id =>
        {
            if last.as_ref().is_some_and(|(run, revision)| {
                *run == event.run_id.0 && *revision >= event.observation.journal_revision
            }) {
                return Ok(());
            }
            *last = Some((event.run_id.0.clone(), event.observation.journal_revision));
            ServerFrame::AdvisoryMaintenanceV1 {
                protocol_version: PROTOCOL_VERSION,
                event,
            }
        }
        ServerEvent::MaintenanceAvailability(observation)
            if current.thread_id == observation.thread_id
                && current.run_id == observation.run_id =>
        {
            ServerFrame::MaintenanceAvailabilityV1 {
                protocol_version: PROTOCOL_VERSION,
                observation,
            }
        }
        _ => return Ok(()),
    };
    send_frame(writer, budget, preparers, encoders, frame).await
}

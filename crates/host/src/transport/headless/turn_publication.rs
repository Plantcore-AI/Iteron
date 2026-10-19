//! Optional publication frames use their record source, independently of legacy replay cursors.

use super::framing::{ServerFrame, send_frame};
use crate::app_server::AppServerClient;
use anyhow::Result;
use iteron_protocol::PROTOCOL_VERSION;
use iteron_protocol::turn_publication::TurnPublicationEventV1;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::sync::Semaphore;

pub(super) async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    client: &AppServerClient,
    budget: &Arc<Semaphore>,
    preparers: &Arc<Semaphore>,
    encoders: &Arc<Semaphore>,
    publication: TurnPublicationEventV1,
) -> Result<()> {
    let current = client.thread_snapshot_v1();
    if publication.validate().is_ok()
        && current
            .as_ref()
            .is_some_and(|thread| thread.run_id == publication.run_id)
    {
        send_frame(
            writer,
            budget,
            preparers,
            encoders,
            ServerFrame::TurnPublicationV1 {
                protocol_version: PROTOCOL_VERSION,
                publication,
            },
        )
        .await?;
    }
    Ok(())
}

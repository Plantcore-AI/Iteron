//! Client-side observations and explicit host controls; no discovery or provider constructor.
use super::{
    App, ModelSelection, ProviderCatalogView, Session, block, queue_model_selection,
    transcript_effect,
};
use crate::app_server::{Control, ControlReply, ControlRequest, ProviderCatalogControl};
use iteron_protocol::client_inventory::ClientModelSelectionV1;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::{mpsc, oneshot};

pub(super) fn selection_request(
    directory: &ProviderCatalogView,
    selection: &ModelSelection,
) -> Result<ClientModelSelectionV1, String> {
    let (catalog, capabilities) = directory.selection_digests(selection);
    let request = ClientModelSelectionV1 {
        inventory_digest_sha256: directory.inventory_digest().into(),
        provider_id: selection.provider_id.clone(),
        model_id: selection.model_id.clone(),
        catalog_digest_sha256: catalog,
        capability_digest_sha256: capabilities,
    };
    request.validate().map_err(str::to_owned)?;
    Ok(request)
}

pub(super) fn first_frame(
    sender: mpsc::Sender<ControlRequest>,
) -> oneshot::Receiver<Result<(), String>> {
    let (completed, result) = oneshot::channel();
    tokio::spawn(async move {
        let (reply, receive) = oneshot::channel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            sender
                .send(ControlRequest {
                    control: Control::ProviderCatalog(ProviderCatalogControl::FirstFrame),
                    reply,
                })
                .await
                .map_err(|_| "provider host is unavailable".to_owned())?;
            match receive
                .await
                .map_err(|_| "provider host returned no first-frame receipt".to_owned())?
            {
                ControlReply::ProviderCatalog(_) => Ok(()),
                ControlReply::Refused(reason) => Err(reason),
                _ => Err("unexpected provider first-frame reply".into()),
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(
                "provider first-frame observation timed out; host discovery may still be running"
                    .into(),
            )
        });
        let _ = completed.send(result);
    });
    result
}

pub(super) fn queue_retry(
    app: &mut App,
    session: &Session,
    directory: &ProviderCatalogView,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    selection: ModelSelection,
) {
    let request = match selection_request(directory, &selection) {
        Ok(request) => request,
        Err(reason) => {
            app.note(block::NoticeLevel::Warn, reason);
            return;
        }
    };
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: Control::ProviderCatalog(ProviderCatalogControl::Retry(request)),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::ModelRetry { selection },
    };
    if effects.start(request).is_ok() {
        app.status = "requesting model retry…".into();
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "model retry not queued: another local control is pending",
        );
    }
}

/// A successful host health reset supplies the new identity before the ordinary model command.
/// The existing physical observer slot is released by Supervisor::recv before this continuation.
pub(super) fn complete_retry(
    app: &mut App,
    session: &Session,
    directory: &mut ProviderCatalogView,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    event: transcript_effect::Event,
) -> Option<transcript_effect::Event> {
    if let Some(control) = &event.control
        && let transcript_effect::ControlKind::ModelRetry { selection } = &control.kind
        && let Some(ControlReply::ProviderCatalog(view)) = &control.reply
    {
        *directory = view.as_ref().clone();
        if control.cancellation_requested {
            app.note(
                block::NoticeLevel::Info,
                "host retry marker cleared; cancelled model selection was not dispatched",
            );
        } else {
            queue_model_selection(
                app,
                session,
                directory,
                effects,
                interrupt,
                selection.clone(),
            );
        }
        return None;
    }
    Some(event)
}

#[cfg(test)]
mod tests;

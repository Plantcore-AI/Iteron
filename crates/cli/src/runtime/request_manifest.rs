//! Physical request admission and actual-wire inclusion are independent of optional diagnostics.
//! The existing effect ticket is the compact journal identity; no artifact IO gates a send.
use super::persistent_agents::LiveAgentMailbox;
use crate::artifacts::{
    ArtifactStoreError,
    request_manifest::{CapturedRequest, RequestManifestScope},
};
use iteron_ctx::ContextSegmentEvidence;
use iteron_ctx::context_provenance::{
    CapturedContextMaterial, MAX_CONTEXT_MATERIALS, MAX_CONTEXT_PROVENANCE_BYTES,
};
use iteron_kernel::effects::EffectTicket;
use iteron_protocol::Budget;
use iteron_provider::request_capture::{
    ProviderRequestObserver, ProviderWireRequest, RequestCaptureError,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
mod archive;
mod refusal;
pub(super) use archive::RequestArchive;
use archive::{Publication, Reservation, ScopedArchive};
use refusal::{Cause, Stage, refused};

#[cfg(test)]
#[path = "request_manifest_tests.rs"]
mod tests;

pub(super) struct RequestManifestFactory {
    budget: Budget,
    diagnostic: Option<DiagnosticContext>,
    inclusion: Arc<AtomicBool>,
    mailbox: Option<LiveAgentMailbox>,
}
struct DiagnosticContext {
    archive: ScopedArchive,
    sources: Vec<ContextSegmentEvidence>,
    materials: Vec<CapturedContextMaterial>,
    materials_dropped: u32,
}
impl RequestManifestFactory {
    pub(super) fn capture(budget: &Budget) -> Self {
        Self {
            budget: budget.clone(),
            diagnostic: None,
            inclusion: Arc::new(AtomicBool::new(false)),
            mailbox: None,
        }
    }
    pub(super) fn with_archive(
        mut self,
        archive: ScopedArchive,
        sources: &[ContextSegmentEvidence],
        materials: Vec<CapturedContextMaterial>,
        materials_dropped: u32,
    ) -> Self {
        let admitted = sources.len() <= iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS
            && materials.len() <= MAX_CONTEXT_MATERIALS
            && materials
                .iter()
                .try_fold(0usize, |sum, item| sum.checked_add(item.captured_bytes()))
                .is_some_and(|bytes| bytes <= MAX_CONTEXT_PROVENANCE_BYTES);
        if admitted {
            self.diagnostic = Some(DiagnosticContext {
                archive,
                sources: sources.to_vec(),
                materials,
                materials_dropped,
            });
        } else {
            archive.scope_failure(ArtifactStoreError::Capacity);
        }
        self
    }
    pub(super) fn with_mailbox(mut self, mailbox: Option<LiveAgentMailbox>) -> Self {
        self.mailbox = mailbox;
        self
    }
    pub(super) fn for_ticket(
        &self,
        ticket: &EffectTicket,
        admitted_output_tokens: u32,
    ) -> Arc<dyn ProviderRequestObserver> {
        let admission =
            RequestManifestScope::validate_ticket(ticket, &self.budget, admitted_output_tokens)
                .map_err(Cause::Artifact);
        let diagnostic = self.diagnostic.as_ref().and_then(|diagnostic| {
            match RequestManifestScope::capture(
                ticket,
                &self.budget,
                &diagnostic.sources,
                &diagnostic.materials,
                diagnostic.materials_dropped,
                admitted_output_tokens,
            ) {
                Ok(scope) => Some(DiagnosticScope {
                    archive: diagnostic.archive.clone(),
                    scope: Arc::new(scope),
                }),
                Err(error) => {
                    diagnostic.archive.scope_failure(error);
                    None
                }
            }
        });
        Arc::new(RequestManifestObserver {
            admission,
            admitted_output_tokens,
            diagnostic,
            state: Mutex::new(PublicationState::Initial),
            inclusion: self.inclusion.clone(),
            mailbox: self.mailbox.clone(),
        })
    }
    pub(super) fn context_inclusion_confirmed(&self) -> bool {
        self.inclusion.load(Ordering::Acquire)
    }
}

struct DiagnosticScope {
    archive: ScopedArchive,
    scope: Arc<RequestManifestScope>,
}
struct PreparedDiagnostic {
    capture: CapturedRequest,
    reservation: Reservation,
}
enum PublicationState {
    Initial,
    Prepared(Option<PreparedDiagnostic>),
    LocalDispatchIntent,
    Unsupported,
    Faulted,
}
struct RequestManifestObserver {
    admission: Result<(), Cause>,
    admitted_output_tokens: u32,
    diagnostic: Option<DiagnosticScope>,
    state: Mutex<PublicationState>,
    inclusion: Arc<AtomicBool>,
    mailbox: Option<LiveAgentMailbox>,
}
impl RequestManifestObserver {
    fn admission(&self) -> Result<(), RequestCaptureError> {
        self.admission
            .map_err(|cause| refused(Stage::TicketScope, cause, RequestCaptureError::Bounds))
    }
    fn publish(&self, prepared: Option<PreparedDiagnostic>, dispatched: bool) {
        if let (Some(diagnostic), Some(prepared)) = (&self.diagnostic, prepared) {
            diagnostic.archive.submit(
                Publication::Prepared {
                    scope: diagnostic.scope.clone(),
                    capture: prepared.capture,
                    dispatched,
                },
                prepared.reservation,
            );
        }
    }
}
impl Drop for RequestManifestObserver {
    fn drop(&mut self) {
        // A prepared request cancelled before dispatch is still useful diagnostic evidence.
        // No dispatch manifest is invented for it, and optional queue failure cannot affect IO.
        let previous = match self.state.get_mut() {
            Ok(state) => std::mem::replace(state, PublicationState::Faulted),
            Err(_) => return,
        };
        if let PublicationState::Prepared(prepared) = previous {
            self.publish(prepared, false);
        }
    }
}
impl ProviderRequestObserver for RequestManifestObserver {
    fn prepared(&self, wire: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError> {
        self.admission()?;
        let mut state = self.state.lock().map_err(|_| {
            refused(
                Stage::StateLock,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            )
        })?;
        if !matches!(*state, PublicationState::Initial) {
            return Err(refused(
                Stage::StateTransition,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            ));
        }
        *state = PublicationState::Faulted;
        // Admission remains mandatory even when all optional diagnostics are disabled.
        if wire.method != "POST"
            || wire.content_type != "application/json"
            || wire.body.len() > 32 * 1024 * 1024
            || wire.endpoint.len() > 16 * 1024
            || wire.serialized_output_tokens == 0
            || wire.serialized_output_tokens > self.admitted_output_tokens
            || std::str::from_utf8(wire.body).is_err()
        {
            return Err(refused(
                Stage::WireAdmission,
                Cause::Request(RequestCaptureError::Bounds),
                RequestCaptureError::Bounds,
            ));
        }
        let mailbox_proof = self
            .mailbox
            .as_ref()
            .map(|mailbox| mailbox.prepared_delivery(&wire))
            .transpose()
            .map_err(|error| refused(Stage::MailboxPreparation, Cause::Request(error), error))?;
        let context_included = super::request_inclusion::context_included(&wire);
        if let (Some(mailbox), Some(proof)) = (&self.mailbox, mailbox_proof) {
            mailbox.confirm_prepared(proof).map_err(|_| {
                refused(
                    Stage::MailboxConfirmation,
                    Cause::MailboxConfirmationRefused,
                    RequestCaptureError::ReconciliationNeeded,
                )
            })?;
        }
        let prepared = self.diagnostic.as_ref().and_then(|diagnostic| {
            let bytes = diagnostic
                .scope
                .retained_bytes()
                .and_then(|bytes| bytes.checked_add(wire.body.len()))
                .and_then(|bytes| bytes.checked_add(1024));
            let reservation = diagnostic.archive.reserve(bytes)?;
            match CapturedRequest::capture(wire) {
                Ok(capture) => Some(PreparedDiagnostic {
                    capture,
                    reservation,
                }),
                Err(error) => {
                    diagnostic.archive.scope_failure(error);
                    None
                }
            }
        });
        *state = PublicationState::Prepared(prepared);
        if context_included {
            self.inclusion.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn dispatching(&self) -> Result<(), RequestCaptureError> {
        self.admission()?;
        let mut state = self.state.lock().map_err(|_| {
            refused(
                Stage::StateLock,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            )
        })?;
        let previous = std::mem::replace(&mut *state, PublicationState::Faulted);
        let PublicationState::Prepared(prepared) = previous else {
            return Err(refused(
                Stage::StateTransition,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            ));
        };
        self.publish(prepared, true);
        *state = PublicationState::LocalDispatchIntent;
        Ok(())
    }
    fn unavailable(&self, reason: &'static str) -> Result<(), RequestCaptureError> {
        self.admission()?;
        let mut state = self.state.lock().map_err(|_| {
            refused(
                Stage::StateLock,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            )
        })?;
        if !matches!(*state, PublicationState::Initial) {
            return Err(refused(
                Stage::StateTransition,
                Cause::Request(RequestCaptureError::ReconciliationNeeded),
                RequestCaptureError::ReconciliationNeeded,
            ));
        }
        *state = PublicationState::Faulted;
        if reason != "adapter_wire_capture_unavailable" {
            return Err(refused(
                Stage::WireAdmission,
                Cause::Request(RequestCaptureError::Unavailable),
                RequestCaptureError::Unavailable,
            ));
        }
        if let Some(mailbox) = &self.mailbox {
            mailbox.refuse_unsupported_pending().map_err(|error| {
                refused(Stage::UnsupportedMailbox, Cause::Request(error), error)
            })?;
        }
        if let Some(diagnostic) = &self.diagnostic
            && let Some(reservation) = diagnostic
                .archive
                .reserve(diagnostic.scope.retained_bytes())
        {
            diagnostic.archive.submit(
                Publication::Unavailable {
                    scope: diagnostic.scope.clone(),
                    reason,
                },
                reservation,
            );
        }
        *state = PublicationState::Unsupported;
        Ok(())
    }
}

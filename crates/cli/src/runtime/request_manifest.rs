//! One immutable physical-ticket scope and one actual publication state. This observer holds
//! neither the runtime nor Rollout; streaming tool admission keeps its own exclusive journal.
use crate::artifacts::{DurableArtifactStore, request_manifest::RequestManifestScope};
use iteron_ctx::ContextSegmentEvidence;
use iteron_ctx::context_provenance::{
    CapturedContextMaterial, MAX_CONTEXT_MATERIALS, MAX_CONTEXT_PROVENANCE_BYTES,
};
use iteron_kernel::effects::EffectTicket;
use iteron_protocol::Budget;
use iteron_protocol::client_artifact::ClientArtifactDescriptorV1;
use iteron_provider::request_capture::{
    ProviderRequestObserver, ProviderWireRequest, RequestCaptureError,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(test)]
#[path = "request_manifest_tests.rs"]
mod tests;

pub(super) struct RequestManifestFactory {
    store: Option<DurableArtifactStore>,
    budget: Budget,
    sources: Vec<ContextSegmentEvidence>,
    materials: Vec<CapturedContextMaterial>,
    materials_dropped: u32,
    inclusion: Arc<AtomicBool>,
}

impl RequestManifestFactory {
    pub(super) fn capture(
        rollout: &iteron_record::Rollout,
        workspace: &std::path::Path,
        budget: &Budget,
        sources: &[ContextSegmentEvidence],
        materials: &[CapturedContextMaterial],
        materials_dropped: u32,
    ) -> Self {
        let admitted = sources.len() <= iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS
            && materials.len() <= MAX_CONTEXT_MATERIALS
            && materials
                .iter()
                .try_fold(0usize, |sum, item| sum.checked_add(item.captured_bytes()))
                .is_some_and(|bytes| bytes <= MAX_CONTEXT_PROVENANCE_BYTES);
        Self {
            store: admitted
                .then(|| DurableArtifactStore::from_rollout_writer(rollout, workspace).ok())
                .flatten(),
            budget: budget.clone(),
            materials: if admitted {
                materials.to_vec()
            } else {
                Vec::new()
            },
            materials_dropped,
            inclusion: Arc::new(AtomicBool::new(false)),
            sources: if admitted {
                sources.to_vec()
            } else {
                Vec::new()
            },
        }
    }
    pub(super) fn for_ticket(
        &self,
        ticket: &EffectTicket,
        admitted_output_tokens: u32,
    ) -> Arc<dyn ProviderRequestObserver> {
        Arc::new(RequestManifestObserver {
            store: self.store.clone(),
            scope: RequestManifestScope::capture(
                ticket,
                &self.budget,
                &self.sources,
                &self.materials,
                self.materials_dropped,
                admitted_output_tokens,
            )
            .ok(),
            state: Mutex::new(PublicationState::Initial),
            inclusion: self.inclusion.clone(),
        })
    }
    pub(super) fn context_inclusion_confirmed(&self) -> bool {
        self.inclusion.load(Ordering::Acquire)
    }
}

enum PublicationState {
    Initial,
    Prepared(ClientArtifactDescriptorV1),
    LocalDispatchIntent,
    Unsupported,
    Faulted,
}
struct RequestManifestObserver {
    store: Option<DurableArtifactStore>,
    scope: Option<RequestManifestScope>,
    state: Mutex<PublicationState>,
    inclusion: Arc<AtomicBool>,
}

impl RequestManifestObserver {
    fn scope(&self) -> Result<(&DurableArtifactStore, &RequestManifestScope), RequestCaptureError> {
        let store = self
            .store
            .as_ref()
            .ok_or(RequestCaptureError::Unavailable)?;
        let scope = self.scope.as_ref().ok_or(RequestCaptureError::Bounds)?;
        Ok((store, scope))
    }
}

impl ProviderRequestObserver for RequestManifestObserver {
    fn prepared(&self, wire: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError> {
        let (store, scope) = self.scope()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        if !matches!(*state, PublicationState::Initial) {
            return Err(RequestCaptureError::ReconciliationNeeded);
        }
        *state = PublicationState::Faulted;
        let context_included = super::request_inclusion::context_included(&wire);
        let prepared = store
            .publish_prepared_request(scope, wire)
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        *state = PublicationState::Prepared(prepared);
        if context_included {
            self.inclusion.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn dispatching(&self) -> Result<(), RequestCaptureError> {
        let (store, scope) = self.scope()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        let previous = std::mem::replace(&mut *state, PublicationState::Faulted);
        let PublicationState::Prepared(prepared) = previous else {
            return Err(RequestCaptureError::ReconciliationNeeded);
        };
        store
            .publish_request_dispatch_intent(scope, &prepared)
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        *state = PublicationState::LocalDispatchIntent;
        Ok(())
    }
    fn unavailable(&self, reason: &'static str) -> Result<(), RequestCaptureError> {
        let (store, scope) = self.scope()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        if !matches!(*state, PublicationState::Initial) {
            return Err(RequestCaptureError::ReconciliationNeeded);
        }
        *state = PublicationState::Faulted;
        store
            .publish_request_unavailable(scope, reason)
            .map_err(|_| RequestCaptureError::ReconciliationNeeded)?;
        *state = PublicationState::Unsupported;
        Ok(())
    }
}

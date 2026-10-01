//! Composition-only port factories for the independent model-turn driver. All stateful policy,
//! execution, journal and pricing behavior belongs to its concrete owners.
use super::provider_route_binding::{
    ProviderRouteBindingJournal, ProviderRouteBindingOwner, ProviderRouteBindingScope,
};
use super::provider_selection_journal::ProviderSelectionJournal;
use super::{Agent, KernelError};
use iteron_protocol::TurnId;

impl Agent {
    pub(super) fn memory_request_exposure(
        &mut self,
        turn: TurnId,
    ) -> super::memory_request_exposure::MemoryRequestExposure<'_> {
        let events = super::provider_route_events::ProviderRouteEvents {
            turn,
            lifecycle: self.lifecycle_emitter.clone(),
            hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
            activity: self.activity.clone(),
        };
        super::memory_request_exposure::MemoryRequestExposure {
            visibility: &mut self.session_memory_visibility,
            memory_traces: &self.memory_traces,
            events,
        }
    }

    pub(super) fn provider_route_binding(
        &mut self,
        turn: TurnId,
    ) -> Result<ProviderRouteBindingOwner<'_>, KernelError> {
        self.ensure_policy_evidence()?;
        let strict_controls = self.provider_extension_enabled();
        Ok(ProviderRouteBindingOwner {
            selected: &mut self.provider_selection,
            provider: &mut self.provider,
            model: &mut self.model,
            journal: ProviderRouteBindingJournal {
                selection: ProviderSelectionJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                policy: self.policy_evidence.as_mut(),
            },
            scope: ProviderRouteBindingScope {
                turn,
                router: self.compiled_policy_bundle.slots().model_router.as_ref(),
                authority: self.authority_ceiling,
                controls: self.provider_controls,
                strict_controls,
                governor: self.provider_governor.as_ref(),
            },
        })
    }
}

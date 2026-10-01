//! Feature-only adaptation of the historical dispatch lease and usage observer.
use super::plantcore::{DispatchGate, PlantcoreRuntime, PlantcoreTerminal};
use super::provider_extension::{
    ProviderDispatchExtension, ProviderDispatchGate, ProviderExtensionPermit,
    ProviderExtensionTerminal,
};
use iteron_protocol::{ProviderRouteAttemptAccounting, TurnId};
use std::sync::Arc;

#[async_trait::async_trait]
impl ProviderDispatchGate for PlantcoreRuntime {
    async fn enter_dispatch(&self) -> Result<Option<ProviderExtensionPermit>, ()> {
        self.enter_external_dispatch()
            .await
            .map(|permit| permit.map(ProviderExtensionPermit::retain))
    }
}
impl ProviderDispatchExtension for PlantcoreRuntime {
    fn terminal(&self) -> Option<ProviderExtensionTerminal> {
        self.terminal().map(|terminal| match terminal {
            PlantcoreTerminal::Budget(reason) => ProviderExtensionTerminal::Budget(reason),
            PlantcoreTerminal::UsageUnavailable => ProviderExtensionTerminal::UsageUnavailable,
        })
    }
    fn observe_physical_attempt(
        &mut self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        self.observe_provider_attempt(turn, accounting)
    }
}

struct LegacyDispatchGate(Arc<DispatchGate>);
#[async_trait::async_trait]
impl ProviderDispatchGate for LegacyDispatchGate {
    async fn enter_dispatch(&self) -> Result<Option<ProviderExtensionPermit>, ()> {
        self.0
            .enter()
            .await
            .map(|permit| Some(ProviderExtensionPermit::retain(permit)))
            .ok_or(())
    }
}
pub(super) fn owned_gate(gate: Arc<DispatchGate>) -> Arc<dyn ProviderDispatchGate> {
    Arc::new(LegacyDispatchGate(gate))
}

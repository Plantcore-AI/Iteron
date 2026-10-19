//! Trusted composition of an optional installed adapter. Standalone paths do not construct one.
use super::Agent;
use super::provider_extension::{
    ProviderDispatchGate, ProviderExtensionPermit, ProviderExtensionTerminal,
};
use iteron_protocol::{ProviderRouteAttemptAccounting, TurnId};
use std::sync::Arc;

impl Agent {
    pub(super) fn provider_extension_enabled(&self) -> bool {
        #[cfg(feature = "legacy-plantcore")]
        {
            self.plantcore_runtime_enabled()
        }
        #[cfg(not(feature = "legacy-plantcore"))]
        {
            false
        }
    }
    pub(super) fn provider_extension_terminal(&self) -> Option<ProviderExtensionTerminal> {
        #[cfg(feature = "legacy-plantcore")]
        {
            use super::provider_extension::ProviderDispatchExtension;
            ProviderDispatchExtension::terminal(&self.plantcore)
        }
        #[cfg(not(feature = "legacy-plantcore"))]
        {
            None
        }
    }
    pub(super) fn provider_dispatch_gate(&self) -> Option<Arc<dyn ProviderDispatchGate>> {
        #[cfg(feature = "legacy-plantcore")]
        {
            self.plantcore_dispatch_gate()
                .map(super::legacy_provider_extension::owned_gate)
        }
        #[cfg(not(feature = "legacy-plantcore"))]
        {
            None
        }
    }
    pub(super) async fn enter_provider_extension_dispatch(
        &self,
    ) -> Result<Option<ProviderExtensionPermit>, ()> {
        #[cfg(feature = "legacy-plantcore")]
        {
            super::provider_extension::enter_dispatch(Some(&self.plantcore)).await
        }
        #[cfg(not(feature = "legacy-plantcore"))]
        {
            Ok(None)
        }
    }
    pub(super) fn observe_provider_extension_attempt(
        &mut self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        #[cfg(feature = "legacy-plantcore")]
        {
            use super::provider_extension::ProviderDispatchExtension;
            self.plantcore.observe_physical_attempt(turn, accounting)
        }
        #[cfg(not(feature = "legacy-plantcore"))]
        {
            let _ = (turn, accounting);
            Ok(())
        }
    }
}

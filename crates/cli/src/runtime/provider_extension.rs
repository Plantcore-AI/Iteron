//! Optional dispatch observation outside the provider core. A standalone call has no extension,
//! gate, permit or allocation. Only an installed adapter can supply a real owned dispatch lease.
use iteron_protocol::{ProviderRouteAttemptAccounting, TurnId};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "legacy-plantcore"), allow(dead_code))]
pub(super) enum ProviderExtensionTerminal {
    Budget(&'static str),
    UsageUnavailable,
}

pub(super) struct ProviderExtensionPermit {
    _lease: Box<dyn Send + Sync>,
}
impl ProviderExtensionPermit {
    #[cfg(any(feature = "legacy-plantcore", test))]
    pub(super) fn retain(lease: impl Send + Sync + 'static) -> Self {
        Self {
            _lease: Box::new(lease),
        }
    }
}

#[async_trait::async_trait]
pub(super) trait ProviderDispatchGate: Send + Sync {
    async fn enter_dispatch(&self) -> Result<Option<ProviderExtensionPermit>, ()>;
}

pub(super) trait ProviderDispatchExtension: ProviderDispatchGate {
    fn terminal(&self) -> Option<ProviderExtensionTerminal>;
    fn observe_physical_attempt(
        &mut self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str>;
}

/// Borrow only the installed adapter. Reborrows cannot reconstruct a permit or widen a gate.
pub(super) struct ProviderExtensionPort<'a> {
    extension: Option<&'a mut (dyn ProviderDispatchExtension + 'static)>,
}
impl<'a> ProviderExtensionPort<'a> {
    #[cfg(not(feature = "legacy-plantcore"))]
    pub(super) fn none() -> Self {
        Self { extension: None }
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn installed(extension: &'a mut (dyn ProviderDispatchExtension + 'static)) -> Self {
        Self {
            extension: Some(extension),
        }
    }
    pub(super) fn reborrow(&mut self) -> ProviderExtensionPort<'_> {
        ProviderExtensionPort {
            extension: self.extension.as_deref_mut(),
        }
    }
    pub(super) fn as_read(&self) -> Option<&(dyn ProviderDispatchExtension + 'static)> {
        self.extension.as_deref()
    }
    pub(super) fn terminal(&self) -> Option<ProviderExtensionTerminal> {
        self.as_read().and_then(ProviderDispatchExtension::terminal)
    }
    pub(super) fn observe_physical_attempt(
        &mut self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        match self.extension.as_deref_mut() {
            Some(extension) => extension.observe_physical_attempt(turn, accounting),
            None => Ok(()),
        }
    }
}

pub(super) async fn enter_dispatch(
    extension: Option<&dyn ProviderDispatchExtension>,
) -> Result<Option<ProviderExtensionPermit>, ()> {
    match extension {
        Some(extension) => extension.enter_dispatch().await,
        None => Ok(None),
    }
}

pub(super) async fn enter_owned_gate(
    gate: Option<&Arc<dyn ProviderDispatchGate>>,
) -> Result<Option<ProviderExtensionPermit>, ()> {
    match gate {
        Some(gate) => gate.enter_dispatch().await,
        None => Ok(None),
    }
}

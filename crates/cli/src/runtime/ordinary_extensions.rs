//! Optional ordinary SDK host: native guards/routes and same-owner bounded observation ports.
//! No provider is invoked or automatically selected by registration.
use super::UiEvent;
#[cfg(test)]
use crate::providers::{ModelSelection, ProviderDirectory};
use iteron_extension_sdk::{
    EventSubscriptionV1, ExtensionDispatchPolicy, ExtensionEventBatchV1, ExtensionEventReader,
    ExtensionEventsReadPort, ExtensionReadErrorV1, ExtensionStatusReadPort, ExtensionSurfaceV1,
    HostStatusFactsV1, HostStatusReadPort, HostStatusValueV1, NativeProviderReadPort,
    NativeProviderRegistrationV1, OrdinaryExtensionsReadPort, OrdinaryExtensionsSnapshotV1,
    StatusFactV1, TextStatusReader,
};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

pub(super) struct OrdinaryExtensionHost {
    pub(super) catalog_sha256: String,
    pub(super) routes: Vec<NativeProviderRegistrationV1>,
    #[cfg(test)]
    pub(super) directory: ProviderDirectory,
    pub(super) policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
    pub(super) status: TextStatusReader,
    pub(super) facts: Arc<HostFacts>,
    pub(super) subscriptions: Vec<EventSubscriptionV1>,
    pub(super) events: Mutex<(u64, BTreeMap<String, Arc<ExtensionEventReader>>)>,
    pub(super) event_generation: AtomicU64,
}
pub(super) struct HostFacts {
    pub(super) state: Mutex<(super::operator_status::RuntimeOperatorStatusSources, String)>,
}
impl HostStatusReadPort for HostFacts {
    fn snapshot(&self) -> Result<HostStatusFactsV1, ExtensionReadErrorV1> {
        let (sources, phase) = self
            .state
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)?
            .clone();
        let actual = sources.snapshot();
        let budget = actual.settled_budget;
        let known = |value: String| HostStatusValueV1::Known { value };
        Ok(HostStatusFactsV1 {
            version: 1,
            source: "actual_host_phase_live_owners_and_last_settled_budget_boundary",
            values: BTreeMap::from([
                (StatusFactV1::Phase, known(phase)),
                (
                    StatusFactV1::ProviderAdmissionSlotsUsed,
                    known(budget.provider_attempts.to_string()),
                ),
                (
                    StatusFactV1::ProviderAdmissionSlotsRemaining,
                    known(budget.provider_attempts_remaining.to_string()),
                ),
                (
                    StatusFactV1::TokensUsed,
                    known(budget.tokens_used.to_string()),
                ),
                (
                    StatusFactV1::TokensRemaining,
                    budget
                        .tokens_remaining
                        .map(|value| known(value.to_string()))
                        .unwrap_or(HostStatusValueV1::Unavailable {
                            reason: "no_token_ceiling_configured".into(),
                        }),
                ),
                (
                    StatusFactV1::ToolCalls,
                    known(budget.tool_calls.to_string()),
                ),
                (
                    StatusFactV1::ToolErrors,
                    known(budget.tool_errors.to_string()),
                ),
                (
                    StatusFactV1::SessionSpawnsRemaining,
                    known(actual.collaboration.session_spawns_remaining.to_string()),
                ),
            ]),
        })
    }
}
impl OrdinaryExtensionHost {
    pub(super) fn bind_lifecycle(
        &self,
        bus: &iteron_obs::lifecycle::LifecycleBus,
    ) -> Result<(), ExtensionReadErrorV1> {
        let generation = self
            .event_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| ExtensionReadErrorV1::Unavailable)?
            .checked_add(1)
            .ok_or(ExtensionReadErrorV1::Unavailable)?;
        self.events
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)?
            .1
            .clear();
        let mut next = BTreeMap::new();
        for descriptor in &self.subscriptions {
            if self.policy.as_ref().is_some_and(|policy| {
                !policy.admits(ExtensionSurfaceV1::EventSubscription, &descriptor.name)
            }) {
                continue;
            }
            let reader = ExtensionEventReader::bind(bus, descriptor.clone(), self.policy.clone())?;
            next.insert(descriptor.name.clone(), Arc::new(reader));
        }
        *self
            .events
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)? = (generation, next);
        Ok(())
    }
    pub(super) fn observe(
        &self,
        sources: super::operator_status::RuntimeOperatorStatusSources,
        event: &UiEvent,
    ) {
        let phase = match event {
            UiEvent::Phase(phase) => Some(phase.label()),
            UiEvent::Done(_) => Some("idle"),
            UiEvent::TurnEnd { .. } => None,
            _ => return,
        };
        // Observation never backpressures the Main producer; contention is visible as an older
        // explicitly last-boundary snapshot rather than claiming fresh budget usage.
        if let Ok(mut state) = self.facts.state.try_lock() {
            state.0 = sources;
            if let Some(phase) = phase {
                state.1 = phase.into();
            }
        }
    }
    #[cfg(test)]
    pub(super) fn resolve_selection(
        &self,
        name: &str,
    ) -> Result<ModelSelection, ExtensionReadErrorV1> {
        let route = self.resolve(name)?;
        Ok(ModelSelection {
            provider_id: route.host_provider_id,
            model_id: route.host_model_id,
        })
    }
}
impl NativeProviderReadPort for OrdinaryExtensionHost {
    fn routes(&self) -> Result<Vec<NativeProviderRegistrationV1>, ExtensionReadErrorV1> {
        Ok(self
            .routes
            .iter()
            .filter(|route| {
                self.policy
                    .as_ref()
                    .is_none_or(|policy| policy.admits(ExtensionSurfaceV1::Provider, &route.name))
            })
            .cloned()
            .collect())
    }
    fn resolve(&self, name: &str) -> Result<NativeProviderRegistrationV1, ExtensionReadErrorV1> {
        if !iteron_extension_sdk::validate_key(name) {
            return Err(ExtensionReadErrorV1::InvalidRequest);
        }
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| !policy.admits(ExtensionSurfaceV1::Provider, name))
        {
            return Err(ExtensionReadErrorV1::Revoked);
        }
        self.routes
            .iter()
            .find(|route| route.name == name)
            .cloned()
            .ok_or(ExtensionReadErrorV1::NotBound)
    }
}
impl OrdinaryExtensionsReadPort for OrdinaryExtensionHost {
    fn snapshot(&self) -> Result<OrdinaryExtensionsSnapshotV1, ExtensionReadErrorV1> {
        let state = self
            .events
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)?;
        if state.0 != self.event_generation.load(Ordering::Acquire) {
            return Err(ExtensionReadErrorV1::Unavailable);
        }
        let event_subscriptions = state
            .1
            .keys()
            .filter(|name| {
                self.policy
                    .as_ref()
                    .is_none_or(|p| p.admits(ExtensionSurfaceV1::EventSubscription, name))
            })
            .cloned()
            .collect();
        drop(state);
        Ok(OrdinaryExtensionsSnapshotV1 {
            version: 1,
            catalog_sha256: self.catalog_sha256.clone(),
            providers: self.routes()?,
            status: self.status.snapshot()?,
            event_subscriptions,
        })
    }
    fn events(
        &self,
        name: &str,
        limit: usize,
        timeout_ms: u64,
    ) -> Result<ExtensionEventBatchV1, ExtensionReadErrorV1> {
        if !iteron_extension_sdk::validate_key(name) {
            return Err(ExtensionReadErrorV1::InvalidRequest);
        }
        let generation = self.event_generation.load(Ordering::Acquire);
        let state = self
            .events
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)?;
        if state.0 != generation {
            return Err(ExtensionReadErrorV1::Unavailable);
        }
        let reader = state
            .1
            .get(name)
            .cloned()
            .ok_or(ExtensionReadErrorV1::NotBound)?;
        drop(state);
        let batch = reader.read(limit, timeout_ms)?;
        if generation != self.event_generation.load(Ordering::Acquire) {
            return Err(ExtensionReadErrorV1::Unavailable);
        }
        Ok(batch)
    }
}
#[cfg(test)]
#[path = "ordinary_extensions_tests.rs"]
mod tests;

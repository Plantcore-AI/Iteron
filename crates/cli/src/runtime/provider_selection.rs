//! One private owner for the executable provider selection and its authenticated price binding.
//! Public provider/model fields are proposals; only a confirmed selection epoch binds authority.
use super::KernelError;
use super::provider_selection_journal::ProviderSelectionJournal;
use super::route_validation::{
    validate_pricing_route_digest, validate_route_digest, validate_route_identifier,
};
use iteron_obs::PricingPort;
use iteron_protocol::{Event, EventKind, PricingRoute, SignedRateCard, TurnId};
use iteron_provider::Provider;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SelectedRoute {
    pub(super) route: PricingRoute,
}

/// Constructed only by the verified-history projection, and unpriced on adoption. A recorded
/// selection is historical evidence; it does not prove the resident provider matches it.
pub(super) struct RecoveredProviderSelection(Option<SelectedRoute>);

#[derive(Default)]
pub(super) struct ProviderSelectionOwner {
    selected: Option<SelectedRoute>,
    provider: Option<Arc<dyn Provider>>,
    pricing_port: Option<Arc<dyn PricingPort>>,
    card: Option<SignedRateCard>,
}

impl ProviderSelectionOwner {
    pub(super) fn selected(&self) -> Option<&SelectedRoute> {
        self.selected.as_ref()
    }
    pub(super) fn pricing_port(&self) -> Option<&Arc<dyn PricingPort>> {
        self.pricing_port.as_ref()
    }
    pub(super) fn card(&self) -> Option<&SignedRateCard> {
        self.card.as_ref()
    }
    pub(super) fn set_pricing_port(&mut self, port: Arc<dyn PricingPort>) {
        self.pricing_port = Some(port);
        self.card = None;
    }
    pub(super) fn validate_selection(
        provider: &Arc<dyn Provider>,
        route: &PricingRoute,
    ) -> Result<(), KernelError> {
        validate_route_identifier("provider_id", &route.provider_id, 64, false)?;
        if let Some(actual) = provider.provider_instance_id()
            && actual != route.provider_id
        {
            return Err(KernelError::InvalidRoute(
                "provider instance identity does not match the selected provider id",
            ));
        }
        validate_route_identifier("model_id", &route.model_id, 512, true)?;
        validate_route_digest("catalog_digest", &route.catalog_digest)?;
        validate_route_digest("capability_digest", &route.capability_digest)
    }
    pub(super) fn select(
        &mut self,
        provider: Arc<dyn Provider>,
        route: PricingRoute,
        turn: TurnId,
        journal: &mut ProviderSelectionJournal<'_>,
    ) -> Result<(), KernelError> {
        Self::validate_selection(&provider, &route)?;
        journal.select(turn, &route)?;
        // A byte-identical selection still begins a fresh binding epoch. Failure above preserves
        // both the executable selection and its old card; no swap occurs before the WAL barrier.
        self.selected = Some(SelectedRoute { route });
        self.provider = Some(provider);
        self.card = None;
        Ok(())
    }
    pub(super) fn validate_live(
        &self,
        provider: &Arc<dyn Provider>,
        model: &str,
    ) -> Result<(), KernelError> {
        if let Some(selected) = &self.selected {
            if selected.route.model_id != model {
                return Err(KernelError::InvalidRoute(
                    "active model does not match the last durable ModelSelected record",
                ));
            }
            if self
                .provider
                .as_ref()
                .is_none_or(|bound| !Arc::ptr_eq(bound, provider))
            {
                return Err(KernelError::InvalidRoute(
                    "provider changed without a durable model selection",
                ));
            }
            if self.card.is_some()
                && provider.provider_instance_id() != Some(selected.route.provider_id.as_str())
            {
                return Err(KernelError::InvalidRoute(
                    "priced provider instance identity does not match the selected route",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn validate_request(
        &self,
        provider: &Arc<dyn Provider>,
        resident_model: &str,
        request_model: &str,
    ) -> Result<(), KernelError> {
        self.validate_live(provider, resident_model)?;
        if self
            .selected
            .as_ref()
            .is_some_and(|selected| selected.route.model_id != request_model)
        {
            return Err(KernelError::InvalidRoute(
                "request model changed without a durable model selection",
            ));
        }
        Ok(())
    }
    pub(super) fn bind_card(
        &mut self,
        turn: TurnId,
        now: u64,
        journal: &mut ProviderSelectionJournal<'_>,
    ) -> Result<bool, KernelError> {
        let Some(selected) = &self.selected else {
            return Err(KernelError::InvalidRouteMetadata {
                field: "rate_card_route",
                reason: "a durable provider/model selection must precede pricing",
            });
        };
        // A failed rebind must not preserve an expired or rejected artifact.
        self.card = None;
        let Some(port) = &self.pricing_port else {
            return Ok(false);
        };
        validate_pricing_route_digest("pricing_catalog_digest", &selected.route.catalog_digest)?;
        validate_pricing_route_digest(
            "pricing_capability_digest",
            &selected.route.capability_digest,
        )?;
        let Some(signed) = port.resolve_rate_card(&selected.route, now)? else {
            return Ok(false);
        };
        port.verify_rate_card(&signed)?;
        validate_route_identifier(
            "provider_id",
            &signed.rate_card.route.provider_id,
            64,
            false,
        )?;
        validate_route_identifier("model_id", &signed.rate_card.route.model_id, 512, false)?;
        validate_route_identifier(
            "pricing_provenance",
            &signed.rate_card.provenance,
            512,
            false,
        )?;
        validate_route_identifier("pricing_signer_id", &signed.signer_id, 128, false)?;
        validate_route_digest("rate_card_digest", &signed.rate_card_digest)?;
        if selected.route != signed.rate_card.route {
            return Err(KernelError::InvalidRouteMetadata {
                field: "rate_card_route",
                reason: "must exactly match the selected provider/model route",
            });
        }
        journal.bind(turn, &signed)?;
        self.card = Some(signed);
        Ok(true)
    }
    pub(super) fn recover_verified(
        events: &[Event],
    ) -> Result<RecoveredProviderSelection, KernelError> {
        let selected = events.iter().rev().find_map(|event| match &event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            } => Some(SelectedRoute {
                route: PricingRoute {
                    provider_id: provider_id.clone(),
                    model_id: model_id.clone(),
                    catalog_digest: catalog_digest.clone(),
                    capability_digest: capability_digest.clone(),
                },
            }),
            _ => None,
        });
        if let Some(selected) = &selected {
            validate_route_identifier("provider_id", &selected.route.provider_id, 64, false)?;
            validate_route_identifier("model_id", &selected.route.model_id, 512, true)?;
            validate_route_digest("catalog_digest", &selected.route.catalog_digest)?;
            validate_route_digest("capability_digest", &selected.route.capability_digest)?;
        }
        Ok(RecoveredProviderSelection(selected))
    }
    /// Assignment-only adoption consumes the verified staged projection. Pricing trust remains
    /// host-installed, while the selected route must acquire a new authenticated card epoch.
    pub(super) fn adopt_verified(
        &mut self,
        recovered: RecoveredProviderSelection,
        resident_provider: Arc<dyn Provider>,
    ) {
        self.selected = recovered.0;
        self.provider = self.selected.as_ref().map(|_| resident_provider);
        self.card = None;
    }
    #[cfg(test)]
    pub(super) fn fixture_selected_mut(&mut self) -> Option<&mut SelectedRoute> {
        self.selected.as_mut()
    }
    #[cfg(test)]
    pub(super) fn fixture_selection(
        &mut self,
        selected: Option<SelectedRoute>,
        provider: Arc<dyn Provider>,
    ) {
        self.adopt_verified(RecoveredProviderSelection(selected), provider);
    }
}

#[cfg(test)]
#[path = "provider_selection_tests.rs"]
mod tests;

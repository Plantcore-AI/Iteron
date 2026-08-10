use super::*;

impl Agent {
    /// Write-ahead record one provider/model route before the frontend commits the in-memory swap.
    /// A failed durable append is returned so the old pair can remain active.
    pub fn record_model_selection(
        &mut self,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        let provider = self.provider.clone();
        let selected = self.append_model_selection(
            &provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        )?;
        // Every successful selection append starts a fresh binding epoch, including a byte-for-
        // byte re-selection. Replay applies the same rule, so live state cannot retain a card that
        // the durable history says must be rebound.
        self.pricing = None;
        self.selected_route = Some(selected);
        self.selected_provider = Some(self.provider.clone());
        Ok(())
    }

    /// Atomically authorize and commit a newly constructed provider/model pair. The record append
    /// is the commit barrier: on failure the old public provider/model and private route binding
    /// remain unchanged; on success all four advance together.
    pub fn record_provider_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        let selected = self.append_model_selection(
            &provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        )?;
        self.provider = provider.clone();
        self.model = selected.route.model_id.clone();
        self.pricing = None;
        self.selected_route = Some(selected);
        self.selected_provider = Some(provider);
        Ok(())
    }

    pub(super) fn append_model_selection(
        &mut self,
        provider: &std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<SelectedRoute, KernelError> {
        validate_route_identifier("provider_id", &provider_id, 64, false)?;
        if let Some(actual_provider_id) = provider.provider_instance_id()
            && actual_provider_id != provider_id
        {
            return Err(KernelError::InvalidRoute(
                "provider instance identity does not match the selected provider id",
            ));
        }
        // An interactive session may start with an unavailable-provider placeholder solely so the
        // picker can open. It records `(provider, "")` but cannot execute a turn until a real model
        // is atomically selected; later switches always carry a non-empty catalog id.
        validate_route_identifier("model_id", &model_id, 512, true)?;
        validate_route_digest("catalog_digest", &catalog_digest)?;
        validate_route_digest("capability_digest", &capability_digest)?;
        let selected = SelectedRoute {
            route: PricingRoute {
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
                catalog_digest: catalog_digest.clone(),
                capability_digest: capability_digest.clone(),
            },
        };
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            },
        )?;
        Ok(selected)
    }

    /// Install an operator-trusted pricing strategy. The trait object, not the kernel, owns any
    /// HMAC material. Replacing trust invalidates the current public binding until it is resolved
    /// again for the selected route.
    pub fn set_pricing_port(&mut self, pricing: std::sync::Arc<dyn PricingPort>) {
        self.pricing_port = Some(pricing);
        self.pricing = None;
    }

    /// Ask the injected strategy to resolve and authenticate the unique currently-active card for
    /// the exact selected route, then durably bind only its public artifact. `false` means the
    /// trusted manifest has no card for this route; positive monetary ceilings remain fail-closed.
    pub fn bind_selected_rate_card(&mut self) -> Result<bool, KernelError> {
        let Some(selected) = &self.selected_route else {
            return Err(KernelError::InvalidRouteMetadata {
                field: "rate_card_route",
                reason: "a durable provider/model selection must precede pricing",
            });
        };
        // Resolution and freshness checks may fail. Clear the prior artifact first so even a
        // same-route rebind cannot retain a stale card after an error.
        self.pricing = None;
        let Some(port) = &self.pricing_port else {
            return Ok(false);
        };
        validate_pricing_route_digest("pricing_catalog_digest", &selected.route.catalog_digest)?;
        validate_pricing_route_digest(
            "pricing_capability_digest",
            &selected.route.capability_digest,
        )?;
        let Some(signed) = port.resolve_rate_card(&selected.route, self.pricing_now())? else {
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
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::RateCardBound {
                rate_card: signed.clone(),
            },
        )?;
        self.pricing = Some(signed);
        Ok(true)
    }

    pub(super) fn inherit_route_and_pricing(&self, child: &mut Agent) -> Result<(), KernelError> {
        // One injected evidence plane and one emission bound cover the whole parent/descendant
        // tree. A child must never fall back to the default null port or multiply the cap.
        child.diagnostics = self.diagnostics.clone();
        if self.usd_budget.is_some() {
            child.usd_budget = self.usd_budget.clone();
        }
        child.authority_ceiling = self.authority_ceiling;
        child.policy_capabilities = self.policy_capabilities;
        if let Some(pricing) = &self.pricing_port {
            child.set_pricing_port(pricing.clone());
        }
        if let Some(selected) = &self.selected_route {
            child.record_model_selection(
                selected.route.provider_id.clone(),
                selected.route.model_id.clone(),
                selected.route.catalog_digest.clone(),
                selected.route.capability_digest.clone(),
            )?;
        }
        if self.pricing.is_some() && !child.bind_selected_rate_card()? {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        Ok(())
    }
}

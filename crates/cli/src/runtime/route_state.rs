use super::*;

const MODEL_ROUTE_FEATURE_SCHEMA: &str = "iteron:model-route-decision-features-v1";

impl Agent {
    /// Record the composition root's already-resolved initial route as one deterministic
    /// `core/model_router` decision before the route itself becomes executable.
    pub(crate) fn record_initial_model_selection(
        &mut self,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        let provider = self.provider.clone();
        if let Err(error) = self.validate_model_selection(
            &provider,
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        ) {
            self.record_model_router_abstention(None, "initial", "invalid_route_metadata")?;
            return Err(error);
        }
        self.record_model_router_selection(
            None,
            "initial",
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        )?;
        self.record_model_selection(provider_id, model_id, catalog_digest, capability_digest)
    }

    fn record_inherited_model_selection(
        &mut self,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        let provider = self.provider.clone();
        if let Err(error) = self.validate_model_selection(
            &provider,
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        ) {
            self.record_model_router_abstention(None, "inherited_child", "invalid_route_metadata")?;
            return Err(error);
        }
        self.record_model_router_selection(
            None,
            "inherited_child",
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        )?;
        self.record_model_selection(provider_id, model_id, catalog_digest, capability_digest)
    }

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
        self.context_estimator
            .set_route(Some(&selected.route.provider_id), &selected.route.model_id);
        self.selected_route = Some(selected);
        self.selected_provider = Some(self.provider.clone());
        Ok(())
    }

    /// Atomically authorize and commit a newly constructed provider/model pair. The record append
    /// is the commit barrier: on failure the old public provider/model and private route binding
    /// remain unchanged; on success all four advance together.
    #[cfg(test)]
    pub fn record_provider_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        self.record_governed_provider_model_selection(
            provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
            None,
            "runtime",
        )
    }

    /// Apply an operator `/model` selection. The UI and App Server share this exact route, so one
    /// control request produces one durable model-router decision rather than separate frontend
    /// and runtime guesses.
    pub(crate) fn record_operator_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        self.record_governed_provider_model_selection(
            provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
            None,
            "operator",
        )
    }

    /// Re-bind the route after an in-process session adoption. This is a new top-level route
    /// opportunity even when the adopted journal last used the same bytes as the old session.
    pub(crate) fn record_adopted_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        self.record_governed_provider_model_selection(
            provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
            None,
            "adopted_session",
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one route selection is exactly this many independent facts; grouping them would hide which ones the record actually binds"
    )]
    pub(super) fn record_fallback_model_selection(
        &mut self,
        turn: TurnId,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        self.record_governed_provider_model_selection(
            provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
            Some(turn),
            reason,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one route selection is exactly this many independent facts; grouping them would hide which ones the record actually binds"
    )]
    fn record_governed_provider_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
        turn: Option<TurnId>,
        source: &'static str,
    ) -> Result<(), KernelError> {
        if let Err(error) = self.validate_model_selection(
            &provider,
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        ) {
            self.record_model_router_abstention(turn, source, "invalid_route_metadata")?;
            return Err(error);
        }
        provider
            .control_capabilities()
            .validate(&self.provider_controls)
            .map_err(|_| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: "new provider route does not attest the immutable request controls",
            })
            .or_else(|error| {
                self.record_model_router_abstention(turn, source, "unsupported_request_controls")?;
                Err(error)
            })?;
        let governor_route_id = format!("{provider_id}:{model_id}");
        let governor_route_inserted = self
            .provider_governor
            .as_ref()
            .map(|governor| governor.register_route(governor_route_id.clone()))
            .transpose()
            .map_err(|_| KernelError::InvalidRouteMetadata {
                field: "provider_governor",
                reason: "new provider route exceeds the immutable governor route bound",
            })
            .or_else(|error| {
                self.record_model_router_abstention(turn, source, "governor_route_refused")?;
                Err(error)
            })?
            .unwrap_or(false);

        if let Err(error) = self.record_model_router_selection(
            turn,
            source,
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        ) {
            if governor_route_inserted && let Some(governor) = &self.provider_governor {
                let _ = governor.unregister_idle_route(&governor_route_id);
            }
            return Err(error);
        }

        match self.commit_provider_model_selection(
            provider,
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                if governor_route_inserted && let Some(governor) = &self.provider_governor {
                    let _ = governor.unregister_idle_route(&governor_route_id);
                }
                Err(error)
            }
        }
    }

    fn commit_provider_model_selection(
        &mut self,
        provider: std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<(), KernelError> {
        provider
            .control_capabilities()
            .validate(&self.provider_controls)
            .map_err(|_| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: "new provider route does not attest the immutable request controls",
            })?;
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
        self.context_estimator
            .set_route(Some(&selected.route.provider_id), &selected.route.model_id);
        self.selected_route = Some(selected);
        self.selected_provider = Some(provider);
        Ok(())
    }

    fn validate_model_selection(
        &self,
        provider: &std::sync::Arc<dyn Provider>,
        provider_id: &str,
        model_id: &str,
        catalog_digest: &str,
        capability_digest: &str,
    ) -> Result<(), KernelError> {
        validate_route_identifier("provider_id", provider_id, 64, false)?;
        if let Some(actual_provider_id) = provider.provider_instance_id()
            && actual_provider_id != provider_id
        {
            return Err(KernelError::InvalidRoute(
                "provider instance identity does not match the selected provider id",
            ));
        }
        validate_route_identifier("model_id", model_id, 512, true)?;
        validate_route_digest("catalog_digest", catalog_digest)?;
        validate_route_digest("capability_digest", capability_digest)
    }

    pub(super) fn append_model_selection(
        &mut self,
        provider: &std::sync::Arc<dyn Provider>,
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    ) -> Result<SelectedRoute, KernelError> {
        self.validate_model_selection(
            provider,
            &provider_id,
            &model_id,
            &catalog_digest,
            &capability_digest,
        )?;
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

    fn record_model_router_selection(
        &mut self,
        turn: Option<TurnId>,
        source: &'static str,
        provider_id: &str,
        model_id: &str,
        catalog_digest: &str,
        capability_digest: &str,
    ) -> Result<(), KernelError> {
        let selected_route_identity =
            model_route_action_id(provider_id, model_id, catalog_digest, capability_digest);
        let previous_route_identity = self.selected_route.as_ref().map(|selected| {
            model_route_action_id(
                &selected.route.provider_id,
                &selected.route.model_id,
                &selected.route.catalog_digest,
                &selected.route.capability_digest,
            )
        });
        let features = (
            source,
            selected_route_identity.as_str(),
            previous_route_identity.as_deref(),
        );
        let eligible = [iteron_protocol::PolicyActionV1::ModelRouterPreAttestedRoute];

        // An interactive launch with no selectable model retains a non-executable placeholder so
        // `/model` can repair it. Say that explicitly as a fallback; never feed an empty identity
        // to a strategy or pretend it selected an executable route.
        if model_id.is_empty() {
            let draft = policy_evidence::PolicyDecisionDraft::baseline_fallback(
                policy_evidence::MODEL_ROUTER_SLOT,
                &eligible,
                MODEL_ROUTE_FEATURE_SCHEMA,
                &features,
                &"empty_model_is_a_non_executable_picker_placeholder",
            )?;
            return self.record_completed_policy_decision(
                policy_evidence::MODEL_ROUTER_SLOT,
                turn,
                draft,
            );
        }

        let observation = iteron_provider::catalog::ModelRouterObservation::single_route(
            model_id.to_owned(),
            None,
            None,
        );
        match iteron_provider::catalog::ModelRouterStrategy::route_with(
            self.model_router.as_ref(),
            &observation,
            self.authority_ceiling,
        ) {
            Ok(proposal) if proposal.model == model_id => self.record_completed_policy_decision(
                policy_evidence::MODEL_ROUTER_SLOT,
                turn,
                policy_evidence::PolicyDecisionDraft::selected(
                    policy_evidence::MODEL_ROUTER_SLOT,
                    &eligible,
                    iteron_protocol::PolicyActionV1::ModelRouterPreAttestedRoute,
                    MODEL_ROUTE_FEATURE_SCHEMA,
                    &features,
                    &"selected_route_must_be_the_single_pre_attested_candidate",
                )?,
            ),
            Ok(_) | Err(_) => {
                let draft = policy_evidence::PolicyDecisionDraft::abstained(
                    policy_evidence::MODEL_ROUTER_SLOT,
                    &eligible,
                    MODEL_ROUTE_FEATURE_SCHEMA,
                    &features,
                    &"model_router_refusal_cannot_widen_the_pre_attested_route",
                )?;
                self.record_completed_policy_decision(
                    policy_evidence::MODEL_ROUTER_SLOT,
                    turn,
                    draft,
                )?;
                Err(KernelError::InvalidRoute(
                    "model-router policy refused the selected route",
                ))
            }
        }
    }

    pub(super) fn record_model_router_abstention(
        &mut self,
        turn: Option<TurnId>,
        source: &'static str,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        let draft = policy_evidence::PolicyDecisionDraft::abstained(
            policy_evidence::MODEL_ROUTER_SLOT,
            &[iteron_protocol::PolicyActionV1::ModelRouterRouteCandidate],
            MODEL_ROUTE_FEATURE_SCHEMA,
            &(source, reason),
            &"no_unattested_or_ineligible_route_may_be_selected",
        )?;
        self.record_completed_policy_decision(policy_evidence::MODEL_ROUTER_SLOT, turn, draft)
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
            child.record_inherited_model_selection(
                selected.route.provider_id.clone(),
                selected.route.model_id.clone(),
                selected.route.catalog_digest.clone(),
                selected.route.capability_digest.clone(),
            )?;
        }
        child.set_provider_controls(self.provider_controls)?;
        let current_route_id = self.governed_route_id();
        let fallback_start = self
            .fallback_provider_routes
            .iter()
            .position(|route| route.id() == current_route_id)
            .map_or(0, |index| index.saturating_add(1));
        let remaining_fallbacks = self
            .fallback_provider_routes
            .iter()
            .skip(fallback_start)
            .filter(|route| route.id() != current_route_id)
            .cloned()
            .collect::<Vec<_>>();
        child.install_fallback_provider_routes(remaining_fallbacks.clone())?;
        if let Some(governor) = &self.provider_governor {
            // ProviderGovernor is an Arc-backed session owner. A child clone must retain the
            // parent's in-flight/quota/circuit state rather than minting an independent ceiling.
            child.install_shared_provider_governor(governor.clone())?;
        }
        if self.pricing.is_some() && !child.bind_selected_rate_card()? {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        Ok(())
    }
}

fn model_route_action_id(
    provider_id: &str,
    model_id: &str,
    catalog_digest: &str,
    capability_digest: &str,
) -> String {
    fn field(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"iteron.model-route-action.v1");
    field(&mut hasher, provider_id);
    field(&mut hasher, model_id);
    field(&mut hasher, catalog_digest);
    field(&mut hasher, capability_digest);
    let digest = hasher.finalize();
    let mut action = String::with_capacity(6 + digest.len() * 2);
    action.push_str("route.");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(action, "{byte:02x}");
    }
    action
}

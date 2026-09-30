use super::*;
use iteron_protocol::advisory_maintenance::MaintenanceKindV1;

const MODEL_ROUTE_FEATURE_SCHEMA: &str = "iteron:model-route-decision-features-v1";

/// Governor-bound verdict recorded when the route carries no governor metadata at all: absence is
/// not a grant, so the route is treated as unbound rather than pre-approved.
const GOVERNOR_ROUTE_BOUND_ABSENT: bool = false;

impl Agent {
    pub(crate) fn set_last_success_route_path(&mut self, path: Option<std::path::PathBuf>) {
        self.last_success_route_path = path;
    }

    pub(super) fn persist_last_success_route(&mut self, turn: TurnId) {
        let (Some(path), Some(selected)) = (
            self.last_success_route_path.as_deref(),
            self.provider_selection.selected(),
        ) else {
            return;
        };
        let selection = crate::providers::ModelSelection {
            provider_id: selected.route.provider_id.clone(),
            model_id: selected.route.model_id.clone(),
        };
        let snapshot = crate::providers::LastSuccessRouteSnapshot::successful(
            &selection,
            selected.route.catalog_digest.clone(),
            selected.route.capability_digest.clone(),
        );
        let queued = snapshot.maintenance_bytes().ok().is_some_and(|bytes| {
            self.advisory_maintenance_owner().is_some_and(|owner| {
                owner.enqueue(MaintenanceKindV1::LastSuccessfulRoute, turn.0, &bytes, path)
            })
        });
        if !queued {
            self.lifecycle_event(
                "model.route_failed",
                Some(turn),
                LifecyclePayload {
                    reason_code: Some("last_success_snapshot_queue_full".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }

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
        let turn = TurnId(self.seq_turn);
        let route = PricingRoute {
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        };
        let (selection, mut journal) = self.provider_selection_ports();
        selection.select(provider, route, turn, &mut journal)?;
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
        // The sealed session preference stays immutable. Optional cache breakpoints are projected
        // onto each route; unsupported semantic, pricing and authority controls still refuse.
        provider
            .control_capabilities()
            .validate(&self.provider_controls_for(provider.as_ref()))
            .map_err(|error| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: unattested_control_reason(error),
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
            .unwrap_or(iteron_tunables::param_bool(
                "cli.runtime.route_state.governor_route_bound_absent",
                GOVERNOR_ROUTE_BOUND_ABSENT,
            ));

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
            .validate(&self.provider_controls_for(provider.as_ref()))
            .map_err(|error| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: unattested_control_reason(error),
            })?;
        let turn = TurnId(self.seq_turn);
        let route = PricingRoute {
            provider_id,
            model_id,
            catalog_digest,
            capability_digest,
        };
        let model = route.model_id.clone();
        let (selection, mut journal) = self.provider_selection_ports();
        selection.select(provider.clone(), route, turn, &mut journal)?;
        self.provider = provider;
        self.model = model;
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
        super::provider_selection::ProviderSelectionOwner::validate_selection(
            provider,
            &PricingRoute {
                provider_id: provider_id.to_owned(),
                model_id: model_id.to_owned(),
                catalog_digest: catalog_digest.to_owned(),
                capability_digest: capability_digest.to_owned(),
            },
        )
    }

    fn provider_selection_ports(
        &mut self,
    ) -> (
        &mut super::provider_selection::ProviderSelectionOwner,
        super::provider_selection_journal::ProviderSelectionJournal<'_>,
    ) {
        (
            &mut self.provider_selection,
            super::provider_selection_journal::ProviderSelectionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
        )
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
        let previous_route_identity = self.provider_selection.selected().map(|selected| {
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
        self.provider_selection.set_pricing_port(pricing);
    }

    /// Authenticate and durably bind the exact selection epoch through the sole selection owner.
    pub fn bind_selected_rate_card(&mut self) -> Result<bool, KernelError> {
        let turn = TurnId(self.seq_turn);
        let now = self.pricing_now();
        let (selection, mut journal) = self.provider_selection_ports();
        selection.bind_card(turn, now, &mut journal)
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
        child.token_calibration = self.token_calibration.clone();
        if let Some(pricing) = self.provider_selection.pricing_port() {
            child.set_pricing_port(pricing.clone());
        }
        if let Some(selected) = self.provider_selection.selected() {
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
        if self.provider_selection.card().is_some() && !child.bind_selected_rate_card()? {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        Ok(())
    }
}

/// Operator-facing explanation of the one request control a candidate route cannot send.
///
/// Each arm names the control that failed and the single configuration knob that would let this
/// route in, because the controls themselves cannot be relaxed while the session is running: they
/// are part of the resolved, durably recorded settings, so the repair is always at the next launch.
fn unattested_control_reason(error: iteron_provider::ControlError) -> &'static str {
    use iteron_provider::ControlError;

    match error {
        ControlError::UnsupportedServiceTier(_) => {
            "the selected route does not offer this session's service tier; request controls are \
             fixed for the life of a session, so relaunch with provider_governor.service_tier at \
             the provider default to use this route"
        }
        ControlError::UnsupportedVerbosity(_) => {
            "the selected route does not accept this session's response verbosity; request \
             controls are fixed for the life of a session, so relaunch with \
             provider_governor.response_verbosity at the model default to use this route"
        }
        ControlError::UnsupportedCompression(_) => {
            "the selected route does not accept this session's request compression; request \
             controls are fixed for the life of a session, so relaunch with \
             provider_governor.request_compression set to none to use this route"
        }
        ControlError::UnsupportedCacheBreakpoint(_) => {
            "the selected route cannot mark prompt-cache breakpoints, which this session sends; \
             request controls are fixed for the life of a session, so relaunch with \
             provider_governor.prompt_cache.breakpoint set to none to use this route"
        }
        ControlError::UnsupportedCacheTtl(_) => {
            "the selected route does not offer this session's prompt-cache lifetime; request \
             controls are fixed for the life of a session, so relaunch with \
             provider_governor.prompt_cache.ttl_seconds set to 0 to use this route"
        }
        ControlError::UnsupportedCacheScope(_) => {
            "the selected route cannot preserve this session's prompt-cache scope; request \
             controls are fixed for the life of a session, so relaunch with a \
             provider_governor.prompt_cache.scope this route supports to use it"
        }
        ControlError::CacheToolInvalidationNotAttested => {
            "the selected route does not invalidate its prompt cache when the tool catalog \
             changes, which this session requires; request controls are fixed for the life of a \
             session, so relaunch with provider_governor.prompt_cache.invalidate_on_tool_change \
             set to false to use this route"
        }
        ControlError::IdempotencyNotAttested => {
            "the selected route does not attest duplicate-safe requests, which this session's \
             hedging requires; request controls are fixed for the life of a session, so relaunch \
             with provider_governor.hedge.enabled set to false to use this route"
        }
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

//! Executable route selection transaction over the sole selection/price owner. Public resident
//! provider/model proposals advance only after the true decision and ModelSelected barriers.
use super::KernelError;
use super::policy_evidence::{self, PolicyDecisionDraft};
use super::policy_evidence_recorder::{PolicyEvidenceRecorder, PolicyEvidenceRecorderError};
use super::provider_governor_state::GovernedProviderRoute;
use super::provider_selection::ProviderSelectionOwner;
use super::provider_selection_journal::ProviderSelectionJournal;
use iteron_kernel::diagnostics::KernelDiagnostic;
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{CapabilitySet, PolicyActionV1, PricingRoute, SlotId, TurnId};
use iteron_provider::{
    ControlError, FailoverClass, Provider, ProviderGovernor, ProviderRequestControls,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;

const MODEL_ROUTE_FEATURE_SCHEMA: &str = "iteron:model-route-decision-features-v1";

pub(super) struct ProviderRouteBindingScope<'a> {
    pub(super) turn: TurnId,
    pub(super) router: &'a dyn StrategySlot,
    pub(super) authority: CapabilitySet,
    pub(super) controls: ProviderRequestControls,
    pub(super) strict_controls: bool,
    pub(super) governor: Option<&'a ProviderGovernor>,
}

pub(super) struct ProviderRouteBindingJournal<'a> {
    pub(super) selection: ProviderSelectionJournal<'a>,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
}

pub(super) struct ProviderRouteBindingOwner<'a> {
    pub(super) selected: &'a mut ProviderSelectionOwner,
    pub(super) provider: &'a mut Arc<dyn Provider>,
    pub(super) model: &'a mut String,
    pub(super) journal: ProviderRouteBindingJournal<'a>,
    pub(super) scope: ProviderRouteBindingScope<'a>,
}

impl ProviderRouteBindingOwner<'_> {
    pub(super) fn select(
        &mut self,
        provider: Arc<dyn Provider>,
        route: PricingRoute,
        decision_turn: Option<TurnId>,
        source: &'static str,
    ) -> Result<(), KernelError> {
        if let Err(error) = ProviderSelectionOwner::validate_selection(&provider, &route) {
            self.abstain(decision_turn, source, "invalid_route_metadata")?;
            return Err(error);
        }
        let controls = self.controls_for(provider.as_ref());
        if let Err(error) = provider.control_capabilities().validate(&controls) {
            self.abstain(decision_turn, source, "unsupported_request_controls")?;
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: unattested_control_reason(error),
            });
        }
        let route_id = format!("{}:{}", route.provider_id, route.model_id);
        let inserted = match self
            .scope
            .governor
            .map(|governor| governor.register_route(route_id.clone()))
            .transpose()
        {
            Ok(inserted) => inserted.unwrap_or(iteron_tunables::param_bool(
                "cli.runtime.route_state.governor_route_bound_absent",
                false,
            )),
            Err(_) => {
                self.abstain(decision_turn, source, "governor_route_refused")?;
                return Err(KernelError::InvalidRouteMetadata {
                    field: "provider_governor",
                    reason: "new provider route exceeds the immutable governor route bound",
                });
            }
        };
        if let Err(error) = self.decision(&route, decision_turn, source) {
            self.rollback_governor(inserted, &route_id);
            return Err(error);
        }
        // Capabilities may belong to a stateful adapter. Recheck at the actual commit
        // boundary, exactly as the former resident transaction did.
        if let Err(error) = provider.control_capabilities().validate(&controls) {
            self.rollback_governor(inserted, &route_id);
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: unattested_control_reason(error),
            });
        }
        let model = route.model_id.clone();
        if let Err(error) = self.selected.select(
            provider.clone(),
            route,
            self.scope.turn,
            &mut self.journal.selection,
        ) {
            self.rollback_governor(inserted, &route_id);
            return Err(error);
        }
        *self.provider = provider;
        *self.model = model;
        Ok(())
    }

    pub(super) fn activate_fallback(
        &mut self,
        candidate: &GovernedProviderRoute,
        class: FailoverClass,
        require_pricing: bool,
        pricing_now: u64,
        context_window: &mut Option<u64>,
        max_output: &mut Option<u32>,
    ) -> Result<GovernedProviderRoute, KernelError> {
        self.select(
            candidate.provider.clone(),
            candidate.route.clone(),
            Some(self.scope.turn),
            class.label(),
        )?;
        if require_pricing
            && !self.selected.bind_card(
                self.scope.turn,
                pricing_now,
                &mut self.journal.selection,
            )?
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        *context_window = candidate.context_window_tokens;
        *max_output = Some(
            crate::runtime_tunables::core_facts::default_request_output_tokens(
                candidate.max_output_tokens,
            ),
        );
        Ok(candidate.clone())
    }

    pub(super) fn controls_for(&self, provider: &dyn Provider) -> ProviderRequestControls {
        if self.scope.strict_controls {
            self.scope.controls
        } else {
            provider
                .control_capabilities()
                .adapt_optional_cache_breakpoint(self.scope.controls)
        }
    }

    fn rollback_governor(&self, inserted: bool, route_id: &str) {
        if inserted && let Some(governor) = self.scope.governor {
            let _ = governor.unregister_idle_route(route_id);
        }
    }

    fn decision(
        &mut self,
        route: &PricingRoute,
        turn: Option<TurnId>,
        source: &'static str,
    ) -> Result<(), KernelError> {
        let identity = model_route_action_id(
            &route.provider_id,
            &route.model_id,
            &route.catalog_digest,
            &route.capability_digest,
        );
        let previous = self.selected.selected().map(|selected| {
            model_route_action_id(
                &selected.route.provider_id,
                &selected.route.model_id,
                &selected.route.catalog_digest,
                &selected.route.capability_digest,
            )
        });
        let features = (source, identity.as_str(), previous.as_deref());
        let eligible = [PolicyActionV1::ModelRouterPreAttestedRoute];
        let draft = if route.model_id.is_empty() {
            PolicyDecisionDraft::baseline_fallback(
                policy_evidence::MODEL_ROUTER_SLOT,
                &eligible,
                MODEL_ROUTE_FEATURE_SCHEMA,
                &features,
                &"empty_model_is_a_non_executable_picker_placeholder",
            )?
        } else {
            let observation = iteron_provider::catalog::ModelRouterObservation::single_route(
                route.model_id.clone(),
                None,
                None,
            );
            match iteron_provider::catalog::ModelRouterStrategy::route_with(
                self.scope.router,
                &observation,
                self.scope.authority,
            ) {
                Ok(proposal) if proposal.model == route.model_id => PolicyDecisionDraft::selected(
                    policy_evidence::MODEL_ROUTER_SLOT,
                    &eligible,
                    PolicyActionV1::ModelRouterPreAttestedRoute,
                    MODEL_ROUTE_FEATURE_SCHEMA,
                    &features,
                    &"selected_route_must_be_the_single_pre_attested_candidate",
                )?,
                Ok(_) | Err(_) => {
                    let draft = PolicyDecisionDraft::abstained(
                        policy_evidence::MODEL_ROUTER_SLOT,
                        &eligible,
                        MODEL_ROUTE_FEATURE_SCHEMA,
                        &features,
                        &"model_router_refusal_cannot_widen_the_pre_attested_route",
                    )?;
                    self.journal.decision(turn, draft)?;
                    return Err(KernelError::InvalidRoute(
                        "model-router policy refused the selected route",
                    ));
                }
            }
        };
        self.journal.decision(turn, draft)
    }

    fn abstain(
        &mut self,
        turn: Option<TurnId>,
        source: &'static str,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        let draft = PolicyDecisionDraft::abstained(
            policy_evidence::MODEL_ROUTER_SLOT,
            &[PolicyActionV1::ModelRouterRouteCandidate],
            MODEL_ROUTE_FEATURE_SCHEMA,
            &(source, reason),
            &"no_unattested_or_ineligible_route_may_be_selected",
        )?;
        self.journal.decision(turn, draft)
    }
}

impl ProviderRouteBindingJournal<'_> {
    fn decision(
        &mut self,
        turn: Option<TurnId>,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let Some(policy) = self.policy.as_mut() else {
            return Ok(());
        };
        let opportunity =
            policy.begin_opportunity(&SlotId(policy_evidence::MODEL_ROUTER_SLOT.into()), turn);
        let opportunity = opportunity.map_err(|error| self.policy_error(error))?;
        let started = Instant::now();
        let result = self
            .policy
            .as_mut()
            .expect("same retained recorder")
            .append_decision(self.selection.rollout, &opportunity, draft.into_input());
        self.selection.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result.map(|_| ()).map_err(|error| self.policy_error(error))
    }
    fn policy_error(&mut self, error: PolicyEvidenceRecorderError) -> KernelError {
        match error.into_record_error() {
            Ok(error) => {
                *self.selection.record_failed = true;
                self.selection
                    .diagnostics
                    .emit(KernelDiagnostic::RecordAppendFailed {});
                KernelError::Record(error)
            }
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
}

fn model_route_action_id(provider: &str, model: &str, catalog: &str, capability: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"iteron.model-route-action.v1");
    for field in [provider, model, catalog, capability] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("route.{}", hex::encode(hasher.finalize()))
}

pub(super) fn unattested_control_reason(error: ControlError) -> &'static str {
    match error {
        ControlError::UnsupportedServiceTier(_) => {
            "the selected route does not offer this session's service tier; request controls are fixed for the life of a session, so relaunch with provider_governor.service_tier at the provider default to use this route"
        }
        ControlError::UnsupportedVerbosity(_) => {
            "the selected route does not accept this session's response verbosity; request controls are fixed for the life of a session, so relaunch with provider_governor.response_verbosity at the model default to use this route"
        }
        ControlError::UnsupportedCompression(_) => {
            "the selected route does not accept this session's request compression; request controls are fixed for the life of a session, so relaunch with provider_governor.request_compression set to none to use this route"
        }
        ControlError::UnsupportedCacheBreakpoint(_) => {
            "the selected route cannot mark prompt-cache breakpoints, which this session sends; request controls are fixed for the life of a session, so relaunch with provider_governor.prompt_cache.breakpoint set to none to use this route"
        }
        ControlError::UnsupportedCacheTtl(_) => {
            "the selected route does not offer this session's prompt-cache lifetime; request controls are fixed for the life of a session, so relaunch with provider_governor.prompt_cache.ttl_seconds set to 0 to use this route"
        }
        ControlError::UnsupportedCacheScope(_) => {
            "the selected route cannot preserve this session's prompt-cache scope; request controls are fixed for the life of a session, so relaunch with a provider_governor.prompt_cache.scope this route supports to use it"
        }
        ControlError::CacheToolInvalidationNotAttested => {
            "the selected route does not invalidate its prompt cache when the tool catalog changes, which this session requires; request controls are fixed for the life of a session, so relaunch with provider_governor.prompt_cache.invalidate_on_tool_change set to false to use this route"
        }
        ControlError::IdempotencyNotAttested => {
            "the selected route does not attest duplicate-safe requests, which this session's hedging requires; request controls are fixed for the life of a session, so relaunch with provider_governor.hedge.enabled set to false to use this route"
        }
    }
}

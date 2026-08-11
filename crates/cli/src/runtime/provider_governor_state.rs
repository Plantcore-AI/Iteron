//! Agent-side bridge from the immutable provider policy to per-physical-attempt admission.

use super::*;
use iteron_provider::{
    AdmissionReason, AttemptPermit, CircuitTransition, ProviderAdmission as Admission,
};

#[derive(Clone)]
pub(crate) struct GovernedProviderRoute {
    pub provider: std::sync::Arc<dyn Provider>,
    pub route: PricingRoute,
    pub image_input: Option<bool>,
    pub tool_calling: Option<bool>,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
}

impl GovernedProviderRoute {
    pub(crate) fn new(
        provider: std::sync::Arc<dyn Provider>,
        route: PricingRoute,
        image_input: Option<bool>,
        tool_calling: Option<bool>,
        context_window_tokens: Option<u64>,
        max_output_tokens: Option<u32>,
    ) -> Self {
        Self {
            provider,
            route,
            image_input,
            tool_calling,
            context_window_tokens,
            max_output_tokens,
        }
    }

    pub(crate) fn id(&self) -> String {
        format!("{}:{}", self.route.provider_id, self.route.model_id)
    }

    pub(super) fn admits_request(&self, request: &TurnRequest) -> bool {
        (request.input_images.is_empty() || self.image_input == Some(true))
            && (request.tools.is_empty() || self.tool_calling != Some(false))
            && self
                .max_output_tokens
                .is_none_or(|maximum| request.max_tokens <= maximum)
    }
}

impl Agent {
    /// Install the exact immutable controls before the first provider attempt.
    pub(crate) fn set_provider_controls(
        &mut self,
        controls: iteron_provider::ProviderRequestControls,
    ) -> Result<(), KernelError> {
        if self.ledger.provider_attempts != 0 {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: "cannot replace request controls after provider admission",
            });
        }
        self.provider
            .control_capabilities()
            .validate(&controls)
            .map_err(|_| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: "selected provider does not attest one configured control",
            })?;
        self.provider_controls = controls;
        Ok(())
    }

    pub(crate) fn install_provider_governor(
        &mut self,
        policy: iteron_provider::GovernorPolicy,
        route_ids: impl IntoIterator<Item = String>,
    ) -> Result<(), KernelError> {
        if self.ledger.provider_attempts != 0 || self.provider_governor.is_some() {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor",
                reason: "governor must be installed exactly once before provider admission",
            });
        }
        if policy.hedge.enabled && !self.provider_controls.idempotent {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor.hedge",
                reason: "hedging requires adapter-attested duplicate-safe request controls",
            });
        }
        self.provider_governor = Some(
            iteron_provider::ProviderGovernor::new(policy, route_ids).map_err(|_| {
                KernelError::InvalidRouteMetadata {
                    field: "provider_governor",
                    reason: "configured governor policy or route set is invalid",
                }
            })?,
        );
        Ok(())
    }

    pub(crate) fn install_fallback_provider_routes(
        &mut self,
        routes: Vec<GovernedProviderRoute>,
    ) -> Result<(), KernelError> {
        if self.ledger.provider_attempts != 0 || !self.fallback_provider_routes.is_empty() {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_fallback_routes",
                reason: "fallback routes must be installed once before provider admission",
            });
        }
        for route in &routes {
            route
                .provider
                .control_capabilities()
                .validate(&self.provider_controls)
                .map_err(|_| KernelError::InvalidRouteMetadata {
                    field: "provider_fallback_routes",
                    reason: "a fallback route does not attest the configured request controls",
                })?;
            if route.provider.attempt_semantics() != ProviderAttemptSemantics::Single {
                return Err(KernelError::OpaqueProviderRetries);
            }
        }
        self.fallback_provider_routes = routes;
        Ok(())
    }

    pub(super) async fn admit_governed_route_attempt(
        &self,
        turn: TurnId,
        route_id: &str,
    ) -> Result<Option<AttemptPermit>, KernelError> {
        let Some(governor) = &self.provider_governor else {
            return Ok(None);
        };
        loop {
            match governor.admit(route_id, Instant::now()) {
                Admission::Admitted(permit) => {
                    self.emit_circuit_transition(turn, permit.transition);
                    return Ok(Some(permit));
                }
                Admission::Deferred { wait, reason } => {
                    // A deferred admission rejects this physical scheduling attempt without
                    // opening a provider effect. Keep it inside the canonical 192-event
                    // vocabulary and distinguish the retryable decision in the bounded reason.
                    self.lifecycle_event(
                        "model.route_rejected",
                        Some(turn),
                        LifecyclePayload {
                            duration_us: Some(u64::try_from(wait.as_micros()).unwrap_or(u64::MAX)),
                            reason_code: Some(format!(
                                "admission_deferred:{}",
                                admission_reason(reason)
                            )),
                            ..LifecyclePayload::default()
                        },
                    );
                    self.wait_provider_retry(wait).await?;
                }
                Admission::Rejected(reason) => {
                    self.lifecycle_event(
                        "model.route_rejected",
                        Some(turn),
                        LifecyclePayload {
                            reason_code: Some(admission_reason(reason).into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    return Err(KernelError::Provider(
                        iteron_provider::ProviderError::Configuration(format!(
                            "provider governor rejected route admission ({})",
                            admission_reason(reason)
                        )),
                    ));
                }
            }
        }
    }

    pub(super) fn observe_governed_route_attempt(
        &self,
        turn: TurnId,
        route_id: &str,
        result: &Result<iteron_provider::TurnResult, KernelError>,
        rate_limit: Option<iteron_provider::RateLimitSnapshot>,
    ) {
        let Some(governor) = &self.provider_governor else {
            return;
        };
        if let Some(snapshot) = rate_limit {
            governor.observe_rate_limit(route_id, snapshot, Instant::now());
        }
        let transition = match result {
            Ok(_) => governor.observe_success(route_id),
            Err(KernelError::Provider(
                iteron_provider::ProviderError::Interrupted
                | iteron_provider::ProviderError::DeadlineExceeded,
            )) => CircuitTransition::None,
            Err(KernelError::Provider(_)) => governor.observe_failure(route_id, Instant::now()),
            Err(_) => CircuitTransition::None,
        };
        self.emit_circuit_transition(turn, transition);
    }

    pub(super) fn admitted_failover(
        &self,
        error: &KernelError,
        emitted: bool,
    ) -> Option<iteron_provider::FailoverClass> {
        let governor = self.provider_governor.as_ref()?;
        let KernelError::Provider(error) = error else {
            return None;
        };
        let point = if matches!(
            error,
            iteron_provider::ProviderError::KnownModelUnavailable { .. }
                | iteron_provider::ProviderError::KnownAccountUnavailable { .. }
        ) {
            iteron_provider::FailurePoint::PreDispatch
        } else if !emitted && !super::provider_route::provider_outcome_is_unobservable(error) {
            iteron_provider::FailurePoint::ProvenTerminal
        } else {
            return None;
        };
        governor.failover_class(error, point)
    }

    /// Durably move to the next already-attested route before its provider effect intent opens.
    pub(super) fn activate_fallback_provider_route(
        &mut self,
        turn: TurnId,
        index: usize,
        class: iteron_provider::FailoverClass,
    ) -> Result<GovernedProviderRoute, KernelError> {
        let route =
            self.fallback_provider_routes
                .get(index)
                .cloned()
                .ok_or(KernelError::InvalidRoute(
                    "fallback route index is outside the admitted chain",
                ))?;
        self.record_fallback_model_selection(
            turn,
            route.provider.clone(),
            route.route.provider_id.clone(),
            route.route.model_id.clone(),
            route.route.catalog_digest.clone(),
            route.route.capability_digest.clone(),
            class.label(),
        )?;
        if self.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0)
            && !self.bind_selected_rate_card()?
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        self.model_context_window = route.context_window_tokens;
        self.model_max_output_tokens = route.max_output_tokens;
        Ok(route)
    }

    pub(super) fn governed_route_id(&self) -> String {
        self.selected_route
            .as_ref()
            .map(|selected| format!("{}:{}", selected.route.provider_id, selected.route.model_id))
            .unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    self.provider.provider_instance_id().unwrap_or("unbound"),
                    self.model
                )
            })
    }

    pub(super) fn emit_circuit_transition(&self, turn: TurnId, transition: CircuitTransition) {
        // Circuit state is retained by the governor owner and projected by `/status`. Admission
        // rejection carries the exact circuit reason, while the physical request terminal owns
        // open/close causality. Do not manufacture an unregistered lifecycle identifier here.
        let _ = (turn, transition);
    }
}

pub(super) const fn admission_reason(reason: AdmissionReason) -> &'static str {
    match reason {
        AdmissionReason::UnknownRoute => "provider_route_not_admitted",
        AdmissionReason::Ceiling => "provider_concurrency_ceiling",
        AdmissionReason::QuotaUnknown => "provider_quota_unknown",
        AdmissionReason::QuotaExhausted => "provider_quota_exhausted",
        AdmissionReason::CircuitOpen => "provider_circuit_open",
        AdmissionReason::CircuitHalfOpen => "provider_circuit_half_open",
    }
}

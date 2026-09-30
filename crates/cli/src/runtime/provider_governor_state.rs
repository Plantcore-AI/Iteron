//! Agent-side bridge from the immutable provider policy to per-physical-attempt admission.

use super::*;
use iteron_provider::AttemptPermit;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteObjectiveRank {
    score_millionths: u32,
    evidence_digest_sha256: String,
}

#[derive(Clone)]
pub(crate) struct GovernedProviderRoute {
    pub provider: std::sync::Arc<dyn Provider>,
    pub route: PricingRoute,
    pub image_input: Option<bool>,
    pub tool_calling: Option<bool>,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
    objective_scores: Option<iteron_provider::RouteObjectiveScores>,
    objective_rank: Option<RouteObjectiveRank>,
}

impl GovernedProviderRoute {
    pub(crate) fn new(
        provider: std::sync::Arc<dyn Provider>,
        route: PricingRoute,
        image_input: Option<bool>,
        tool_calling: Option<bool>,
        context_window_tokens: Option<u64>,
        max_output_tokens: Option<u32>,
        objective_scores: Option<iteron_provider::RouteObjectiveScores>,
    ) -> Self {
        Self {
            provider,
            route,
            image_input,
            tool_calling,
            context_window_tokens,
            max_output_tokens,
            objective_scores,
            objective_rank: None,
        }
    }

    pub(crate) fn id(&self) -> String {
        format!("{}:{}", self.route.provider_id, self.route.model_id)
    }

    pub(super) fn admits_request(&self, request: &TurnRequest) -> bool {
        self.objective_rank.is_some()
            && (request.input_images.is_empty() || self.image_input == Some(true))
            && (request.tools.is_empty() || self.tool_calling == Some(true))
            && self
                .max_output_tokens
                .is_some_and(|maximum| request.max_tokens <= maximum)
    }
}

impl Agent {
    /// Keep the sealed session preference intact; adapt only its optional cache wire hint for
    /// the selected physical route. Governed workers retain their exact request contract.
    pub(super) fn provider_controls_for(
        &self,
        provider: &dyn Provider,
    ) -> iteron_provider::ProviderRequestControls {
        if self.plantcore_runtime_enabled() {
            self.provider_controls
        } else {
            provider
                .control_capabilities()
                .adapt_optional_cache_breakpoint(self.provider_controls)
        }
    }

    /// Legacy provider cache bit projected from the same immutable typed breakpoint used on the
    /// wire. Keeping one helper prevents main, compaction, and coverage turns from disagreeing;
    /// notably Anthropic treats `true` plus a `None` breakpoint as an implicit Rolling request.
    pub(super) fn provider_cache_system_enabled(&self) -> bool {
        self.provider_controls_for(self.provider.as_ref())
            .prompt_cache
            .breakpoint
            != iteron_provider::CacheBreakpoint::None
    }

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
        let capabilities = self.provider.control_capabilities();
        let executable = if self.plantcore_runtime_enabled() {
            controls
        } else {
            capabilities.adapt_optional_cache_breakpoint(controls)
        };
        capabilities
            .validate(&executable)
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
        let governor = iteron_provider::ProviderGovernor::new(policy, route_ids).map_err(|_| {
            KernelError::InvalidRouteMetadata {
                field: "provider_governor",
                reason: "configured governor policy or route set is invalid",
            }
        })?;
        self.install_shared_provider_governor(governor)
    }

    /// Install the session-owned governor instance shared by a parent and every workflow child.
    /// Cloning [`iteron_provider::ProviderGovernor`] retains the same Arc-backed route state; it
    /// does not mint a fresh in-flight counter, quota snapshot, or circuit per child.
    pub(crate) fn install_shared_provider_governor(
        &mut self,
        governor: iteron_provider::ProviderGovernor,
    ) -> Result<(), KernelError> {
        if self.ledger.provider_attempts != 0 || self.provider_governor.is_some() {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor",
                reason: "governor must be installed exactly once before provider admission",
            });
        }
        let policy = governor.policy().clone();
        if policy.hedge.enabled && !self.provider_controls.idempotent {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor.hedge",
                reason: "hedging requires adapter-attested duplicate-safe request controls",
            });
        }
        self.rank_fallback_provider_routes(policy.objectives)?;
        self.provider_governor = Some(governor);
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
                .validate(&self.provider_controls_for(route.provider.as_ref()))
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

    /// Remove every preconfigured fallback that would change the immutable PlantCore engine
    /// identity. Retry and hedge attempts remain on the selected route; a future alternate
    /// transport instance may remain only when it advertises the exact same provider/model pair.
    pub(crate) fn freeze_plantcore_provider_identity(
        &mut self,
        provider_id: &str,
        model_id: &str,
    ) -> Result<(), KernelError> {
        if self.ledger.provider_attempts != 0
            || self.provider.provider_instance_id() != Some(provider_id)
            || self.model != model_id
        {
            return Err(KernelError::InvalidRouteMetadata {
                field: "plantcore_provider_identity",
                reason: "PlantCore provider identity must freeze before provider admission",
            });
        }
        let fixed_route = format!("{provider_id}:{model_id}");
        self.fallback_provider_routes
            .retain(|route| route.id() == fixed_route);
        Ok(())
    }

    /// Freeze the objective order once, before the first provider admission. Unknown objective
    /// facts sort after proven routes and remain ineligible at the request gate; they are retained
    /// only so the durable abstention can distinguish an exhausted chain from an empty one.
    fn rank_fallback_provider_routes(
        &mut self,
        weights: iteron_provider::ObjectiveWeights,
    ) -> Result<(), KernelError> {
        self.fallback_provider_routes =
            rank_provider_routes(std::mem::take(&mut self.fallback_provider_routes), weights)?;
        Ok(())
    }

    pub(super) fn objective_rank_evidence(&self, route_id: &str) -> (Option<u32>, Option<&str>) {
        self.fallback_provider_routes
            .iter()
            .find(|route| route.id() == route_id)
            .and_then(|route| route.objective_rank.as_ref())
            .map_or((None, None), |rank| {
                (
                    Some(rank.score_millionths),
                    Some(rank.evidence_digest_sha256.as_str()),
                )
            })
    }

    pub(super) async fn admit_governed_route_attempt(
        &mut self,
        turn: TurnId,
        route_id: &str,
    ) -> Result<Option<AttemptPermit>, KernelError> {
        self.provider_route_admission(turn).admit(route_id).await
    }

    pub(super) fn observe_governed_route_attempt(
        &mut self,
        turn: TurnId,
        route_id: &str,
        result: &Result<iteron_provider::TurnResult, KernelError>,
        rate_limit: Option<iteron_provider::RateLimitSnapshot>,
    ) -> Result<(), KernelError> {
        self.provider_route_admission(turn)
            .observe(route_id, result, rate_limit)
    }

    pub(super) fn admitted_failover(
        &self,
        error: &KernelError,
        semantic_output_observed: bool,
    ) -> Option<iteron_provider::FailoverClass> {
        let governor = self.provider_governor.as_ref()?;
        let KernelError::Provider(error) = error else {
            return None;
        };
        if matches!(
            error,
            iteron_provider::ProviderError::RequestCaptureRefusedBeforeDispatch
                | iteron_provider::ProviderError::RequestDeadlineBeforeDispatch
        ) {
            return None;
        }
        let point = if matches!(
            error,
            iteron_provider::ProviderError::ConnectFailed
                | iteron_provider::ProviderError::KnownModelUnavailable { .. }
                | iteron_provider::ProviderError::KnownAccountUnavailable { .. }
        ) {
            iteron_provider::FailurePoint::PreDispatch
        } else if !semantic_output_observed
            && !super::provider_route::provider_outcome_is_unobservable(error)
        {
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
        // Preserve the fallback's exact attested context capability, but install the governed
        // interactive request default rather than mistaking its physical output maximum for a
        // per-turn reservation. The route object retains that maximum as capability evidence.
        self.model_context_window = route.context_window_tokens;
        self.model_max_output_tokens = Some(
            crate::runtime_tunables::core_facts::default_request_output_tokens(
                route.max_output_tokens,
            ),
        );
        Ok(route)
    }

    pub(super) fn governed_route_id(&self) -> String {
        self.provider_selection
            .selected()
            .map(|selected| format!("{}:{}", selected.route.provider_id, selected.route.model_id))
            .unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    self.provider.provider_instance_id().unwrap_or("unbound"),
                    self.model
                )
            })
    }

    fn provider_route_admission(
        &mut self,
        turn: TurnId,
    ) -> super::provider_route_admission::ProviderRouteAdmission<'_> {
        let events = super::provider_route_events::ProviderRouteEvents {
            turn,
            lifecycle: self.lifecycle_emitter.clone(),
            hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
            activity: self.activity.clone(),
        };
        super::provider_route_admission::ProviderRouteAdmission {
            governor: self.provider_governor.clone(),
            control: &self.control,
            run_deadline: self.run_deadline,
            events,
            journal: super::provider_route_journal::ProviderRouteJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
        }
    }
}

fn objective_rank_order(
    scores: impl IntoIterator<Item = Option<iteron_provider::RouteObjectiveScores>>,
    weights: iteron_provider::ObjectiveWeights,
) -> Result<Vec<(usize, Option<u32>)>, KernelError> {
    let mut ranked = scores
        .into_iter()
        .enumerate()
        .map(|(index, scores)| {
            scores
                .map(|scores| scores.weighted_score(weights))
                .transpose()
                .map(|score| (index, score))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| KernelError::InvalidRouteMetadata {
            field: "provider_governor.objective_scores",
            reason: "route objective scores are outside the typed normalized domain",
        })?;
    ranked.sort_by(|(left_index, left_score), (right_index, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_index.cmp(right_index))
    });
    Ok(ranked)
}

fn rank_provider_routes(
    routes: Vec<GovernedProviderRoute>,
    weights: iteron_provider::ObjectiveWeights,
) -> Result<Vec<GovernedProviderRoute>, KernelError> {
    let ranked = objective_rank_order(routes.iter().map(|route| route.objective_scores), weights)?;
    let mut routes = routes.into_iter().map(Some).collect::<Vec<_>>();
    Ok(ranked
        .into_iter()
        .map(|(original_index, score)| {
            let mut route = routes[original_index]
                .take()
                .expect("objective rank order contains every route once");
            route.objective_rank = score.map(|score_millionths| RouteObjectiveRank {
                score_millionths,
                evidence_digest_sha256: objective_evidence_digest(
                    &route,
                    weights,
                    score_millionths,
                ),
            });
            route
        })
        .collect())
}

pub(super) fn next_admitted_fallback_index(
    routes: &[GovernedProviderRoute],
    start: usize,
    request: &TurnRequest,
) -> Option<usize> {
    first_admitted_index(routes, start, |route| route.admits_request(request))
}

fn first_admitted_index<T>(
    values: &[T],
    start: usize,
    mut admitted: impl FnMut(&T) -> bool,
) -> Option<usize> {
    values
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, value)| admitted(value))
        .map(|(index, _)| index)
}

fn objective_evidence_digest(
    route: &GovernedProviderRoute,
    weights: iteron_provider::ObjectiveWeights,
    score: u32,
) -> String {
    let scores = route
        .objective_scores
        .expect("a ranked route has complete objective scores");
    let mut digest = Sha256::new();
    for value in [
        "iteron-route-objective-rank-v1".to_owned(),
        route.id(),
        route.route.capability_digest.clone(),
        scores.quality_millionths.to_string(),
        scores.cost_efficiency_millionths.to_string(),
        scores.latency_millionths.to_string(),
        weights.quality_millionths.to_string(),
        weights.cost_millionths.to_string(),
        weights.latency_millionths.to_string(),
        score.to_string(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

pub(super) use super::provider_route_admission::admission_reason;

#[cfg(test)]
mod objective_rank_tests {
    use super::*;

    struct UncalledProvider;

    #[async_trait::async_trait]
    impl Provider for UncalledProvider {
        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
            unreachable!("route ranking and admission must not dispatch a provider")
        }
    }

    const QUALITY: iteron_provider::RouteObjectiveScores = iteron_provider::RouteObjectiveScores {
        quality_millionths: 900_000,
        cost_efficiency_millionths: 100_000,
        latency_millionths: 200_000,
    };
    const FAST_CHEAP: iteron_provider::RouteObjectiveScores =
        iteron_provider::RouteObjectiveScores {
            quality_millionths: 300_000,
            cost_efficiency_millionths: 900_000,
            latency_millionths: 900_000,
        };

    fn route(
        model: &str,
        scores: Option<iteron_provider::RouteObjectiveScores>,
        tool_calling: Option<bool>,
        max_output_tokens: Option<u32>,
    ) -> GovernedProviderRoute {
        GovernedProviderRoute::new(
            std::sync::Arc::new(UncalledProvider),
            PricingRoute {
                provider_id: "provider".into(),
                model_id: model.into(),
                catalog_digest: "sha256:catalog".into(),
                capability_digest: format!("sha256:{model}"),
            },
            Some(false),
            tool_calling,
            Some(128_000),
            max_output_tokens,
            scores,
        )
    }

    fn routes() -> Vec<GovernedProviderRoute> {
        vec![
            route("quality", Some(QUALITY), Some(false), Some(4096)),
            route("fast-cheap", Some(FAST_CHEAP), Some(true), Some(4096)),
            route("unknown-objectives", None, Some(true), Some(4096)),
        ]
    }

    fn request(with_tool: bool) -> TurnRequest {
        TurnRequest {
            model: "primary".into(),
            system: String::new(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: with_tool
                .then(|| iteron_protocol::ToolSpec {
                    name: "read_file".into(),
                    description: String::new(),
                    input_schema: serde_json::json!({"type": "object"}),
                    purity: Purity::Pure,
                    capability: Capability::ReadOnly,
                })
                .into_iter()
                .collect::<Vec<_>>()
                .into(),
            max_tokens: 1024,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: iteron_protocol::ReasoningEffort::Medium,
            controls: Default::default(),
        }
    }

    #[test]
    fn objective_weights_change_the_real_fallback_order_and_unknown_facts_fail_closed() {
        let quality_first = rank_provider_routes(
            routes(),
            iteron_provider::ObjectiveWeights {
                quality_millionths: 800_000,
                cost_millionths: 100_000,
                latency_millionths: 100_000,
            },
        )
        .unwrap();
        let efficiency_first = rank_provider_routes(
            routes(),
            iteron_provider::ObjectiveWeights {
                quality_millionths: 100_000,
                cost_millionths: 450_000,
                latency_millionths: 450_000,
            },
        )
        .unwrap();

        assert_eq!(quality_first[0].id(), "provider:quality");
        assert_eq!(efficiency_first[0].id(), "provider:fast-cheap");
        assert!(quality_first[2].objective_rank.is_none());
        assert!(efficiency_first[2].objective_rank.is_none());
        assert_eq!(
            next_admitted_fallback_index(&quality_first, 0, &request(false)),
            Some(0)
        );
        assert_eq!(
            next_admitted_fallback_index(&efficiency_first, 0, &request(false)),
            Some(0)
        );

        // Ranking is preference, never authority: the top-ranked candidate cannot be selected
        // when the independent request-capability gate rejects it.
        assert_eq!(
            next_admitted_fallback_index(&quality_first, 0, &request(true)),
            Some(1)
        );
        assert_eq!(
            next_admitted_fallback_index(&quality_first, 2, &request(false)),
            None,
            "a route with unknown objective evidence must never become eligible"
        );

        let unknown_tool_capability = rank_provider_routes(
            vec![route("unknown-tools", Some(QUALITY), None, Some(4096))],
            iteron_provider::ObjectiveWeights::default(),
        )
        .unwrap();
        assert_eq!(
            next_admitted_fallback_index(&unknown_tool_capability, 0, &request(true)),
            None,
            "ranking must not turn an unknown tool capability into authority"
        );

        let unknown_output_cap = rank_provider_routes(
            vec![route("unknown-output", Some(QUALITY), Some(true), None)],
            iteron_provider::ObjectiveWeights::default(),
        )
        .unwrap();
        assert_eq!(
            next_admitted_fallback_index(&unknown_output_cap, 0, &request(false)),
            None,
            "ranking must not invent an output-token ceiling"
        );
    }

    struct RaisedPhysicalCap;
    #[async_trait::async_trait]
    impl Provider for RaisedPhysicalCap {
        async fn turn(
            &self,
            _: &TurnRequest,
            _: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
            unreachable!("fallback admission must not dispatch")
        }
        fn physical_output_token_ceiling(
            &self,
            _: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
        ) -> Result<Option<u32>, iteron_provider::ProviderError> {
            Ok(Some(4096))
        }
    }

    #[test]
    fn normalized_fallback_rechecks_actual_output_and_context_before_selection() {
        let candidate = rank_provider_routes(
            vec![route("candidate", Some(QUALITY), Some(true), Some(3072))],
            iteron_provider::ObjectiveWeights::default(),
        )
        .unwrap()
        .remove(0);
        let policy_request = request(false);
        assert!(candidate.admits_request(&policy_request));
        let physical = super::super::provider_output_request::normalize(
            &RaisedPhysicalCap,
            policy_request,
            true,
        )
        .unwrap();
        assert_eq!(physical.requested_max_tokens, 1024);
        assert_eq!(physical.request.max_tokens, 4096);
        assert!(matches!(
            super::super::provider_route_turn::validate_fallback_request(
                &candidate,
                &physical.request,
                1
            ),
            Err(KernelError::InvalidRouteMetadata {
                field: "fallback_request",
                ..
            }),
        ));
        let mut candidate = rank_provider_routes(
            vec![route(
                "bounded-context",
                Some(QUALITY),
                Some(true),
                Some(8192),
            )],
            iteron_provider::ObjectiveWeights::default(),
        )
        .unwrap()
        .remove(0);
        candidate.context_window_tokens = Some(4096);
        assert!(candidate.admits_request(&physical.request));
        assert!(matches!(
            super::super::provider_route_turn::validate_fallback_request(
                &candidate,
                &physical.request,
                1
            ),
            Err(KernelError::ContextWindowExceeded {
                reserved_output_tokens: 4096,
                ..
            }),
        ));
    }
}

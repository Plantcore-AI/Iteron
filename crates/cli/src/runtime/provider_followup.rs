//! Settled-round retry waits and fallback proposals. A proposal still requires the independent
//! durable selection and fresh physical admission owners before any replacement transport.
use super::KernelError;
use super::plantcore::PlantcoreTerminal;
use super::pricing::SharedUsdBudget;
use super::provider_governor_state::GovernedProviderRoute;
use super::provider_output_request::{self, PhysicalProviderRequest};
use super::provider_round::ProviderRoundOwner;
use super::provider_route::provider_outcome_is_unobservable;
use super::provider_route_events::{ProviderRetrySchedule, ProviderRetryWait, ProviderRouteEvents};
use super::provider_route_turn::{self, ProviderRouteNext, ProviderRouteTurn};
use super::session_control::SessionControlState;
use iteron_obs::Ledger;
use iteron_provider::{FailoverClass, FailurePoint, ProviderError, ProviderGovernor, TurnResult};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct ProviderFollowupScope<'a> {
    pub(super) routes: &'a [GovernedProviderRoute],
    pub(super) governor: Option<&'a ProviderGovernor>,
    pub(super) controls: &'a SessionControlState,
    pub(super) ledger: &'a mut Ledger,
    pub(super) events: &'a ProviderRouteEvents,
    pub(super) run_deadline: Option<Instant>,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) plantcore_terminal: Option<PlantcoreTerminal>,
    pub(super) output_proof_required: bool,
    pub(super) context_tokens: u64,
}

pub(super) struct PreparedProviderFallback {
    pub(super) index: usize,
    pub(super) class: FailoverClass,
    pub(super) physical: PhysicalProviderRequest,
}

pub(super) enum ProviderFollowupDecision {
    Terminal(Result<TurnResult, KernelError>),
    ReAdmit,
    Fallback(PreparedProviderFallback),
}

/// Consumed at a settled physical safe point. The actual round and route retain their single
/// phase/counter owners; dropping a wait cannot manufacture a completed retry admission.
pub(super) struct ProviderFollowupOwner<'a> {
    pub(super) scope: ProviderFollowupScope<'a>,
}

impl ProviderFollowupOwner<'_> {
    pub(super) async fn advance(
        self,
        round: &mut ProviderRoundOwner,
        route: &mut ProviderRouteTurn,
        result: Result<TurnResult, KernelError>,
        monetary_followup_safe: bool,
    ) -> Result<ProviderFollowupDecision, KernelError> {
        let failover = result.as_ref().err().and_then(|error| {
            admitted_failover(
                self.scope.governor,
                error,
                round.observations().semantic_output_observed(),
            )
        });
        match round.next_route(route, &result, failover, self.scope.routes)? {
            ProviderRouteNext::Retry { delay } => {
                if let Err(error) = self.admit_followup(monetary_followup_safe) {
                    return Ok(ProviderFollowupDecision::Terminal(Err(error)));
                }
                round.fail_connect();
                if let Err(error) = self
                    .scope
                    .events
                    .wait_retry(
                        ProviderRetryWait {
                            controls: self.scope.controls,
                            run_deadline: self.scope.run_deadline,
                            ledger: &mut *self.scope.ledger,
                        },
                        ProviderRetrySchedule {
                            delay,
                            attempt: route.retry_index().saturating_add(1),
                            limit: route.max_attempts(),
                        },
                    )
                    .await
                {
                    return Ok(ProviderFollowupDecision::Terminal(Err(error)));
                }
                route.retry_wait_completed();
                Ok(ProviderFollowupDecision::ReAdmit)
            }
            ProviderRouteNext::RetryCeiling { hint, ceiling } => {
                if let Err(error) = self.admit_followup(monetary_followup_safe) {
                    return Ok(ProviderFollowupDecision::Terminal(Err(error)));
                }
                self.scope.events.ceiling_refused(hint);
                Ok(ProviderFollowupDecision::Terminal(Err(
                    ProviderRouteTurn::retry_ceiling_error(hint, ceiling),
                )))
            }
            ProviderRouteNext::Fallback { index, class } => {
                // Preserve the stronger fallback rule: unknown cost refuses even an unpriced
                // session. A retry may have a policy-permitted nonmonetary terminal instead.
                if !monetary_followup_safe {
                    if let Some(usd) = &self.scope.usd {
                        usd.mark_unknown();
                    }
                    return Ok(ProviderFollowupDecision::Terminal(Err(
                        KernelError::UnpricedUsdCeiling,
                    )));
                }
                if self.scope.usd.as_ref().is_some_and(|usd| usd.exhausted()) {
                    return Ok(ProviderFollowupDecision::Terminal(Err(
                        KernelError::InferenceBudgetExhausted("max_usd"),
                    )));
                }
                let candidate = self
                    .scope
                    .routes
                    .get(index)
                    .ok_or(KernelError::InvalidRoute(
                        "fallback route index is outside the admitted chain",
                    ))?;
                let mut request = route.request().clone();
                request.model = candidate.route.model_id.clone();
                request.max_tokens = route.requested_max_tokens();
                let physical = provider_output_request::normalize(
                    candidate.provider.as_ref(),
                    request,
                    self.scope.output_proof_required,
                )?;
                provider_route_turn::validate_fallback_request(
                    candidate,
                    &physical.request,
                    self.scope.context_tokens,
                )?;
                Ok(ProviderFollowupDecision::Fallback(
                    PreparedProviderFallback {
                        index,
                        class,
                        physical,
                    },
                ))
            }
            ProviderRouteNext::Terminal | ProviderRouteNext::FallbackExhausted { .. } => {
                Ok(ProviderFollowupDecision::Terminal(result))
            }
        }
    }

    fn admit_followup(&self, monetary_followup_safe: bool) -> Result<(), KernelError> {
        if let Some(terminal) = self.scope.plantcore_terminal {
            return Err(KernelError::InferenceBudgetExhausted(match terminal {
                PlantcoreTerminal::Budget(reason) => reason,
                PlantcoreTerminal::UsageUnavailable => "usage_unavailable",
            }));
        }
        if let Some(usd) = &self.scope.usd {
            if usd.requires_pricing() && !monetary_followup_safe {
                usd.mark_unknown();
                return Err(KernelError::UnpricedUsdCeiling);
            }
            if usd.exhausted() {
                return Err(KernelError::InferenceBudgetExhausted("max_usd"));
            }
        }
        Ok(())
    }
}

pub(super) fn admitted_failover(
    governor: Option<&ProviderGovernor>,
    error: &KernelError,
    semantic_output_observed: bool,
) -> Option<FailoverClass> {
    let governor = governor?;
    let KernelError::Provider(error) = error else {
        return None;
    };
    if matches!(
        error,
        ProviderError::RequestCaptureRefusedBeforeDispatch
            | ProviderError::RequestDeadlineBeforeDispatch
    ) {
        return None;
    }
    let point = if matches!(
        error,
        ProviderError::ConnectFailed
            | ProviderError::KnownModelUnavailable { .. }
            | ProviderError::KnownAccountUnavailable { .. }
    ) {
        FailurePoint::PreDispatch
    } else if !semantic_output_observed && !provider_outcome_is_unobservable(error) {
        FailurePoint::ProvenTerminal
    } else {
        return None;
    };
    governor.failover_class(error, point)
}

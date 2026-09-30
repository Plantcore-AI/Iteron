//! Actual logical provider route/retry state owner. A settled attempt yields a typed next step;
//! the physical journal, signed budget and durable route selection remain separate authorities.
use super::KernelError;
use super::plantcore::DispatchPermit;
use super::provider_governor_state::{GovernedProviderRoute, next_admitted_fallback_index};
use super::provider_route::retryable_before_semantic_output_provider_error;
use iteron_kernel::effects::EffectTicket;
use iteron_provider::{
    AttemptPermit, FailoverClass, Provider, ProviderError, ProviderRequestControls, TurnRequest,
    TurnResult,
};
use iteron_sched::BackoffPolicy;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
#[path = "provider_route_turn_tests.rs"]
mod tests;

pub(super) enum ProviderRouteNext {
    Terminal,
    Retry { delay: Duration },
    RetryCeiling { hint: Duration, ceiling: Duration },
    Fallback { index: usize, class: FailoverClass },
    FallbackExhausted { class: FailoverClass },
}

pub(super) struct ProviderRouteTurn {
    request: TurnRequest,
    requested_max_tokens: u32,
    provider: Arc<dyn Provider>,
    route_id: String,
    fallback_cursor: usize,
    retry_index: u32,
    jitter: iteron_sched::backoff::Jitter,
    policy: BackoffPolicy,
    retry_after_ceiling: Duration,
    physical_attempt: u32,
    ordinal: usize,
    transition: Option<&'static str>,
    ticket: Option<EffectTicket>,
    route_permit: Option<AttemptPermit>,
    dispatch_permit: Option<DispatchPermit>,
    active: Duration,
    first_attempt: bool,
}
impl ProviderRouteTurn {
    pub(super) fn new(
        request: TurnRequest,
        requested_max_tokens: u32,
        provider: Arc<dyn Provider>,
        route_id: String,
        routes: &[GovernedProviderRoute],
        policy: BackoffPolicy,
        retry_after_ceiling: Duration,
    ) -> Self {
        let fallback_cursor = routes
            .iter()
            .position(|route| route.id() == route_id)
            .map_or(0, |index| index.saturating_add(1));
        Self {
            request,
            requested_max_tokens,
            provider,
            route_id,
            fallback_cursor,
            retry_index: 0,
            jitter: iteron_sched::backoff::Jitter::new(),
            policy,
            retry_after_ceiling,
            physical_attempt: 0,
            ordinal: 0,
            transition: None,
            ticket: None,
            route_permit: None,
            dispatch_permit: None,
            active: Duration::ZERO,
            first_attempt: true,
        }
    }
    pub(super) fn request(&self) -> &TurnRequest {
        &self.request
    }
    pub(super) fn requested_max_tokens(&self) -> u32 {
        self.requested_max_tokens
    }
    pub(super) fn continuation_random(&mut self) -> f64 {
        self.jitter.next01()
    }
    pub(super) fn provider(&self) -> Arc<dyn Provider> {
        self.provider.clone()
    }
    pub(super) fn route_id(&self) -> &str {
        &self.route_id
    }
    pub(super) fn retry_index(&self) -> u32 {
        self.retry_index
    }
    pub(super) fn max_attempts(&self) -> u32 {
        self.policy.max_attempts
    }
    pub(super) fn physical_attempt(&self) -> u32 {
        self.physical_attempt
    }
    pub(super) fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub(super) fn transition(&self) -> Option<&'static str> {
        self.transition
    }
    pub(super) fn first_attempt(&self) -> bool {
        self.first_attempt
    }
    pub(super) fn active(&self) -> Duration {
        self.active
    }
    pub(super) fn observe_active(&mut self, elapsed: Duration) {
        self.active = self.active.saturating_add(elapsed);
    }
    /// Consume the identity minted once by the shared recovered Provider EffectAdmissions owner.
    /// This domain never allocates a billing counter from retries, route names or hedge indexes.
    pub(super) fn assign_identity(&mut self, ordinal: usize, physical: u32) {
        self.ordinal = ordinal;
        self.physical_attempt = physical;
    }
    pub(super) fn assign_ticket(&mut self, ticket: Option<EffectTicket>) {
        self.ticket = ticket;
    }
    pub(super) fn ticket(&self) -> Option<&EffectTicket> {
        self.ticket.as_ref()
    }
    pub(super) fn take_ticket(&mut self) -> Option<EffectTicket> {
        self.ticket.take()
    }
    pub(super) fn assign_route_permit(&mut self, permit: Option<AttemptPermit>) {
        self.route_permit = permit;
    }
    pub(super) fn take_route_permit(&mut self) -> Option<AttemptPermit> {
        self.route_permit.take()
    }
    pub(super) fn assign_dispatch_permit(&mut self, permit: Option<DispatchPermit>) {
        self.dispatch_permit = permit;
    }
    pub(super) fn take_dispatch_permit(&mut self) -> Option<DispatchPermit> {
        self.dispatch_permit.take()
    }
    pub(super) fn observe_hedged_identity(
        &mut self,
        identity: Option<u32>,
        scheduled: u32,
    ) -> Result<(), KernelError> {
        if (scheduled == 0) != identity.is_none()
            || identity.is_some_and(|id| id == 0 || id <= self.physical_attempt)
        {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_route_attempt",
                reason: "hedge identity did not come from a new physical provider intent",
            });
        }
        if let Some(identity) = identity {
            self.physical_attempt = identity;
        }
        Ok(())
    }

    /// Called after the actual physical effect/accounting terminals. No result is replayed here.
    pub(super) fn settled(&mut self) {
        self.first_attempt = false;
        self.transition = None;
    }
    pub(super) fn next(
        &mut self,
        result: &Result<TurnResult, KernelError>,
        semantic_output: bool,
        admitted_failover: Option<FailoverClass>,
        routes: &[GovernedProviderRoute],
    ) -> ProviderRouteNext {
        if let Some(error) =
            retryable_before_semantic_output_provider_error(result, semantic_output)
            && self.retry_index.saturating_add(1) < self.policy.max_attempts
        {
            if let Some(hint) = error.retry_after()
                && hint > self.retry_after_ceiling
            {
                return ProviderRouteNext::RetryCeiling {
                    hint,
                    ceiling: self.retry_after_ceiling,
                };
            }
            let jitter =
                iteron_sched::full_jitter(&self.policy, self.retry_index, self.jitter.next01());
            let delay = error.retry_after().map_or(jitter, |hint| hint.max(jitter));
            return ProviderRouteNext::Retry { delay };
        }
        if semantic_output || result.is_ok() {
            return ProviderRouteNext::Terminal;
        }
        if let Some(class) = admitted_failover {
            // The prior adapter may have raised its physical cap for thinking. Evaluate route
            // candidates against the original policy, then revalidate their normalized request
            // before durable selection; the old adapter's ceiling is not the new route's limit.
            let mut candidate_policy = self.request.clone();
            candidate_policy.max_tokens = self.requested_max_tokens;
            return match next_admitted_fallback_index(
                routes,
                self.fallback_cursor,
                &candidate_policy,
            ) {
                Some(index) => ProviderRouteNext::Fallback { index, class },
                None => ProviderRouteNext::FallbackExhausted { class },
            };
        }
        ProviderRouteNext::Terminal
    }
    /// A retry advances only after the real control wait completed and financial admission held.
    pub(super) fn retry_wait_completed(&mut self) {
        self.retry_index = self.retry_index.saturating_add(1);
    }

    /// Requote only at the settled retry safe point. Original policy and physical identity
    /// counters remain unchanged; the following admission still mints its sole actual intent.
    pub(super) fn rebind_followup(
        &mut self,
        physical: super::provider_output_request::PhysicalProviderRequest,
    ) -> Result<(), KernelError> {
        if self.first_attempt
            || self.ticket.is_some()
            || self.dispatch_permit.is_some()
            || self.route_permit.is_some()
            || physical.request.model != self.request.model
            || physical.requested_max_tokens != self.requested_max_tokens
            || physical.request.max_tokens == 0
        {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_followup_request",
                reason: "output funding can only rebind the same settled route and policy",
            });
        }
        self.request = physical.request;
        Ok(())
    }

    /// The caller has already committed the existing durable ModelSelection and rebound pricing.
    /// Immutable controls are minted from that same selected provider; this method grants no route.
    pub(super) fn selected_fallback(
        &mut self,
        next: GovernedProviderRoute,
        physical: super::provider_output_request::PhysicalProviderRequest,
        index: usize,
        class: FailoverClass,
        controls: ProviderRequestControls,
    ) {
        self.fallback_cursor = index.saturating_add(1);
        self.route_id = next.id();
        self.provider = next.provider;
        self.request = physical.request;
        self.requested_max_tokens = physical.requested_max_tokens;
        self.request.controls = controls;
        self.request.cache_system =
            controls.prompt_cache.breakpoint != iteron_provider::CacheBreakpoint::None;
        self.retry_index = 0;
        self.jitter = iteron_sched::backoff::Jitter::new();
        self.transition = Some(class.label());
    }
    pub(super) fn retry_ceiling_error(hint: Duration, ceiling: Duration) -> KernelError {
        ProviderError::RetryAfterTooLong {
            retry_after_ms: u64::try_from(hint.as_millis()).unwrap_or(u64::MAX),
            limit_ms: u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX),
        }
        .into()
    }
}

/// Recheck the actual normalized request before the durable fallback route selection. Old-route
/// token caps are not capability evidence for the candidate, and a selected route is never used
/// to bypass its attested input/output geometry.
pub(super) fn validate_fallback_request(
    route: &GovernedProviderRoute,
    request: &TurnRequest,
    estimated_input_tokens: u64,
) -> Result<(), KernelError> {
    if !route.admits_request(request) {
        return Err(KernelError::InvalidRouteMetadata {
            field: "fallback_request",
            reason: "normalized physical request exceeds the admitted route capabilities",
        });
    }
    if let Some(context_window_tokens) = route.context_window_tokens
        && estimated_input_tokens.saturating_add(u64::from(request.max_tokens))
            > context_window_tokens
    {
        return Err(KernelError::ContextWindowExceeded {
            estimated_input_tokens,
            reserved_output_tokens: request.max_tokens,
            context_window_tokens,
        });
    }
    Ok(())
}

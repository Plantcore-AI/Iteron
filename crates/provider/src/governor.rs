//! Bounded admission state for provider routes.
//!
//! This module owns no network transport and no retry loop.  It makes one deterministic decision
//! before a physical attempt and accepts one typed observation after it; the kernel remains the
//! owner of durable intent/terminal ordering and of sleeps/cancellation.

use crate::{
    AvailabilityTransition, ErrorScope, FailoverClass, FailoverRule, FailurePoint, GovernorPolicy,
    GovernorPolicyError, MAX_GOVERNED_ROUTES, ProviderError, ProviderGovernorSnapshot,
    RateAdmissionPolicy, RateLimitSnapshot, RetryDisposition, RouteCircuitSnapshot,
    RouteGovernorSnapshot, UnknownQuotaPolicy,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionReason {
    UnknownRoute,
    Ceiling,
    QuotaUnknown,
    QuotaExhausted,
    CircuitOpen,
    CircuitHalfOpen,
}

#[derive(Debug)]
pub enum Admission {
    Admitted(AttemptPermit),
    Deferred {
        wait: Duration,
        reason: AdmissionReason,
    },
    Rejected(AdmissionReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitTransition {
    None,
    Opened,
    HalfOpened,
    Closed,
}

#[derive(Clone)]
pub struct ProviderGovernor {
    inner: Arc<GovernorInner>,
}

#[derive(Debug)]
struct GovernorInner {
    policy: GovernorPolicy,
    routes: Mutex<BTreeMap<String, RouteState>>,
}

#[derive(Debug, Clone)]
struct ObservedRateLimit {
    snapshot: RateLimitSnapshot,
    observed_at: Instant,
}

#[derive(Debug, Clone)]
enum CircuitState {
    Closed { failures: u16 },
    Open { until: Instant },
    HalfOpen { successes: u16, probes: u16 },
}

#[derive(Debug, Clone)]
struct RouteState {
    in_flight: usize,
    rate: Option<ObservedRateLimit>,
    circuit: CircuitState,
}

impl ProviderGovernor {
    pub fn new(
        policy: GovernorPolicy,
        route_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, GovernorPolicyError> {
        let policy = policy.validate()?;
        let ids = route_ids.into_iter().collect::<Vec<_>>();
        if ids.is_empty() || ids.len() > MAX_GOVERNED_ROUTES {
            return Err(GovernorPolicyError::RouteCount);
        }
        let mut routes = BTreeMap::new();
        for id in ids {
            if id.is_empty() || id.len() > 640 || routes.contains_key(&id) {
                return Err(GovernorPolicyError::RouteIdentity);
            }
            routes.insert(
                id,
                RouteState {
                    in_flight: 0,
                    rate: None,
                    circuit: CircuitState::Closed { failures: 0 },
                },
            );
        }
        Ok(Self {
            inner: Arc::new(GovernorInner {
                policy,
                routes: Mutex::new(routes),
            }),
        })
    }

    pub fn policy(&self) -> &GovernorPolicy {
        &self.inner.policy
    }

    /// Content-free point-in-time state for status/telemetry. Reading it never changes admission
    /// state; an expired open circuit remains visibly open with zero remaining time until the next
    /// real admission performs the typed half-open transition.
    pub fn snapshot(&self, now: Instant) -> ProviderGovernorSnapshot {
        let routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ProviderGovernorSnapshot {
            max_in_flight_per_route: self.inner.policy.max_in_flight_per_route,
            minimum_remaining_requests: self.inner.policy.rate_admission.minimum_remaining_requests,
            minimum_remaining_tokens: self.inner.policy.rate_admission.minimum_remaining_tokens,
            reset_wait_max_ms: duration_ms(self.inner.policy.rate_admission.reset_wait_max),
            circuit_failure_threshold: self.inner.policy.circuit.failure_threshold,
            circuit_open_ms: duration_ms(self.inner.policy.circuit.open_for),
            circuit_half_open_probes: self.inner.policy.circuit.half_open_probes,
            circuit_success_threshold: self.inner.policy.circuit.success_threshold,
            hedge_enabled: self.inner.policy.hedge.enabled,
            hedge_delay_ms: duration_ms(self.inner.policy.hedge.delay),
            hedge_max_duplicates: self.inner.policy.hedge.max_duplicates,
            routes: routes
                .iter()
                .map(|(route_id, route)| route_snapshot(route_id, route, now))
                .collect(),
        }
    }

    /// Admit an explicit operator-selected route into this run's bounded route set. The caller
    /// owns the durable policy-transition transaction and may roll back a newly inserted route if
    /// that append fails.
    pub fn register_route(&self, route_id: String) -> Result<bool, GovernorPolicyError> {
        if route_id.is_empty() || route_id.len() > 640 || route_id.chars().any(char::is_control) {
            return Err(GovernorPolicyError::RouteIdentity);
        }
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routes.contains_key(&route_id) {
            return Ok(false);
        }
        if routes.len() >= MAX_GOVERNED_ROUTES {
            return Err(GovernorPolicyError::RouteCount);
        }
        routes.insert(
            route_id,
            RouteState {
                in_flight: 0,
                rate: None,
                circuit: CircuitState::Closed { failures: 0 },
            },
        );
        Ok(true)
    }

    /// Roll back a route inserted immediately before a failed durable selection append.
    pub fn unregister_idle_route(&self, route_id: &str) -> bool {
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if routes
            .get(route_id)
            .is_some_and(|route| route.in_flight == 0)
        {
            routes.remove(route_id);
            true
        } else {
            false
        }
    }

    pub fn admit(&self, route_id: &str, now: Instant) -> Admission {
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(route) = routes.get_mut(route_id) else {
            return Admission::Rejected(AdmissionReason::UnknownRoute);
        };
        let transition = refresh_circuit(route, now);
        let half_open = matches!(route.circuit, CircuitState::HalfOpen { .. });
        if matches!(route.circuit, CircuitState::Open { .. }) {
            return Admission::Rejected(AdmissionReason::CircuitOpen);
        }
        let mut ceiling = self.inner.policy.max_in_flight_per_route;
        if half_open {
            let CircuitState::HalfOpen { probes, .. } = &route.circuit else {
                unreachable!()
            };
            let probes = usize::from(*probes);
            ceiling = ceiling.min(usize::from(self.inner.policy.circuit.half_open_probes));
            if probes >= ceiling {
                return Admission::Rejected(AdmissionReason::CircuitHalfOpen);
            }
        }
        match quota_decision(route, &self.inner.policy.rate_admission, now, &mut ceiling) {
            Some(admission) => return admission,
            None => {}
        }
        if route.in_flight >= ceiling {
            return Admission::Rejected(AdmissionReason::Ceiling);
        }
        route.in_flight = route.in_flight.saturating_add(1);
        if let CircuitState::HalfOpen { probes, .. } = &mut route.circuit {
            *probes = probes.saturating_add(1);
        }
        Admission::Admitted(AttemptPermit {
            inner: self.inner.clone(),
            route_id: route_id.to_owned(),
            transition,
            released: false,
        })
    }

    pub fn observe_rate_limit(&self, route_id: &str, snapshot: RateLimitSnapshot, now: Instant) {
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(route) = routes.get_mut(route_id) {
            route.rate = Some(ObservedRateLimit {
                snapshot,
                observed_at: now,
            });
        }
    }

    pub fn observe_success(&self, route_id: &str) -> CircuitTransition {
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(route) = routes.get_mut(route_id) else {
            return CircuitTransition::None;
        };
        match &mut route.circuit {
            CircuitState::Closed { failures } => {
                *failures = 0;
                CircuitTransition::None
            }
            CircuitState::HalfOpen { successes, .. } => {
                *successes = successes.saturating_add(1);
                if *successes >= self.inner.policy.circuit.success_threshold {
                    route.circuit = CircuitState::Closed { failures: 0 };
                    CircuitTransition::Closed
                } else {
                    CircuitTransition::None
                }
            }
            CircuitState::Open { .. } => CircuitTransition::None,
        }
    }

    pub fn observe_failure(&self, route_id: &str, now: Instant) -> CircuitTransition {
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(route) = routes.get_mut(route_id) else {
            return CircuitTransition::None;
        };
        let failures = match route.circuit {
            CircuitState::Closed { failures } => failures.saturating_add(1),
            CircuitState::HalfOpen { .. } => self.inner.policy.circuit.failure_threshold,
            CircuitState::Open { .. } => return CircuitTransition::None,
        };
        if failures >= self.inner.policy.circuit.failure_threshold {
            route.circuit = CircuitState::Open {
                until: now + self.inner.policy.circuit.open_for,
            };
            CircuitTransition::Opened
        } else {
            route.circuit = CircuitState::Closed { failures };
            CircuitTransition::None
        }
    }

    pub fn failover_class(
        &self,
        error: &ProviderError,
        point: FailurePoint,
    ) -> Option<FailoverClass> {
        let class = classify_failure(error)?;
        self.inner
            .policy
            .failover
            .contains(&FailoverRule { class, point })
            .then_some(class)
    }
}

fn route_snapshot(route_id: &str, route: &RouteState, now: Instant) -> RouteGovernorSnapshot {
    let circuit = match route.circuit {
        CircuitState::Closed { failures } => RouteCircuitSnapshot::Closed { failures },
        CircuitState::Open { until } => RouteCircuitSnapshot::Open {
            remaining_ms: duration_ms(until.saturating_duration_since(now)),
        },
        CircuitState::HalfOpen { successes, probes } => {
            RouteCircuitSnapshot::HalfOpen { successes, probes }
        }
    };
    let (quota_observed, quota_age_ms, requests_remaining, tokens_remaining, reset_remaining_ms) =
        route
            .rate
            .as_ref()
            .map_or((false, None, None, None, None), |rate| {
                let age = now.saturating_duration_since(rate.observed_at);
                let reset = rate
                    .snapshot
                    .requests_reset
                    .into_iter()
                    .chain(rate.snapshot.tokens_reset)
                    .max()
                    .map(|reset| duration_ms(reset.saturating_sub(age)));
                (
                    true,
                    Some(duration_ms(age)),
                    rate.snapshot.requests_remaining,
                    rate.snapshot.tokens_remaining,
                    reset,
                )
            });
    RouteGovernorSnapshot {
        route_id: route_id.to_owned(),
        in_flight: route.in_flight,
        circuit,
        quota_observed,
        quota_age_ms,
        requests_remaining,
        tokens_remaining,
        reset_remaining_ms,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub struct AttemptPermit {
    inner: Arc<GovernorInner>,
    route_id: String,
    pub transition: CircuitTransition,
    released: bool,
}

impl AttemptPermit {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        let mut routes = self
            .inner
            .routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(route) = routes.get_mut(&self.route_id) {
            route.in_flight = route.in_flight.saturating_sub(1);
        }
        self.released = true;
    }
}

impl Drop for AttemptPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

fn refresh_circuit(route: &mut RouteState, now: Instant) -> CircuitTransition {
    if matches!(route.circuit, CircuitState::Open { until } if now >= until) {
        route.circuit = CircuitState::HalfOpen {
            successes: 0,
            probes: 0,
        };
        CircuitTransition::HalfOpened
    } else {
        CircuitTransition::None
    }
}

fn quota_decision(
    route: &RouteState,
    policy: &RateAdmissionPolicy,
    now: Instant,
    ceiling: &mut usize,
) -> Option<Admission> {
    let Some(rate) = &route.rate else {
        return match policy.unknown_quota {
            UnknownQuotaPolicy::Conservative => {
                *ceiling = (*ceiling).min(1);
                None
            }
            UnknownQuotaPolicy::Reject => Some(Admission::Rejected(AdmissionReason::QuotaUnknown)),
        };
    };
    let elapsed = now.saturating_duration_since(rate.observed_at);
    let advertised_reset = rate
        .snapshot
        .requests_reset
        .into_iter()
        .chain(rate.snapshot.tokens_reset)
        .max();
    // After the provider's own reset horizon the old remaining counters are stale. Admit one
    // conservative probe so a successful response can refresh them; otherwise a zero snapshot
    // would deadlock the route forever.
    if advertised_reset.is_some_and(|reset| elapsed >= reset) {
        *ceiling = (*ceiling).min(1);
        return None;
    }
    if let Some(remaining) = rate.snapshot.requests_remaining {
        *ceiling = (*ceiling).min(usize::try_from(remaining).unwrap_or(usize::MAX).max(1));
    }
    let requests_low = rate
        .snapshot
        .requests_remaining
        .is_some_and(|remaining| remaining < policy.minimum_remaining_requests);
    let tokens_low = rate
        .snapshot
        .tokens_remaining
        .is_some_and(|remaining| remaining < policy.minimum_remaining_tokens);
    if !requests_low && !tokens_low {
        return None;
    }
    let wait = advertised_reset
        .unwrap_or(Duration::ZERO)
        .saturating_sub(elapsed);
    if !wait.is_zero() && wait <= policy.reset_wait_max {
        Some(Admission::Deferred {
            wait,
            reason: AdmissionReason::QuotaExhausted,
        })
    } else {
        Some(Admission::Rejected(AdmissionReason::QuotaExhausted))
    }
}

fn classify_failure(error: &ProviderError) -> Option<FailoverClass> {
    if matches!(error, ProviderError::KnownModelUnavailable { .. }) {
        return Some(FailoverClass::ModelUnavailable);
    }
    if matches!(error, ProviderError::KnownAccountUnavailable { .. }) {
        return Some(FailoverClass::AccountUnavailable);
    }
    if matches!(error, ProviderError::Api { status: 429, .. }) {
        return Some(FailoverClass::RateLimited);
    }
    if matches!(error, ProviderError::Api { status: 529, .. }) {
        return Some(FailoverClass::Overloaded);
    }
    let normalized = error.normalized()?;
    if normalized.availability == AvailabilityTransition::ModelUnavailable {
        return Some(FailoverClass::ModelUnavailable);
    }
    if matches!(normalized.scope, ErrorScope::Account)
        && normalized.retry == RetryDisposition::Never
    {
        return Some(FailoverClass::AccountUnavailable);
    }
    match error.status() {
        Some(429) if normalized.retry == RetryDisposition::Transient => {
            Some(FailoverClass::RateLimited)
        }
        Some(529) if normalized.retry == RetryDisposition::Transient => {
            Some(FailoverClass::Overloaded)
        }
        _ => None,
    }
}

//! Immutable, validated policy for the provider governor.

use std::collections::BTreeSet;
use std::time::Duration;

/// Route-scoped, provenance-bearing objective facts used by the fallback ranker.
///
/// Every component is normalized to millionths and uses the same direction: larger is better.
/// These are facts supplied by the provider capability catalog (or an operator declaration in
/// that catalog), not values inferred from model names. A route without the complete triple is
/// therefore ineligible for objective-ranked fallback instead of receiving an optimistic default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteObjectiveScores {
    pub quality_millionths: u32,
    pub cost_efficiency_millionths: u32,
    pub latency_millionths: u32,
}

impl RouteObjectiveScores {
    pub fn validate(self) -> Result<Self, GovernorPolicyError> {
        if [
            self.quality_millionths,
            self.cost_efficiency_millionths,
            self.latency_millionths,
        ]
        .into_iter()
        .any(|score| score > 1_000_000)
        {
            return Err(GovernorPolicyError::ObjectiveScoreRange);
        }
        Ok(self)
    }

    /// Fixed-point weighted score in millionths. Validation makes the intermediate sum at most
    /// 1e12 and the returned score at most 1e6, so this is deterministic on every target.
    pub fn weighted_score(self, weights: ObjectiveWeights) -> Result<u32, GovernorPolicyError> {
        let scores = self.validate()?;
        let weights = weights.validate()?;
        let weighted = u64::from(scores.quality_millionths)
            .saturating_mul(u64::from(weights.quality_millionths))
            .saturating_add(
                u64::from(scores.cost_efficiency_millionths)
                    .saturating_mul(u64::from(weights.cost_millionths)),
            )
            .saturating_add(
                u64::from(scores.latency_millionths)
                    .saturating_mul(u64::from(weights.latency_millionths)),
            )
            / 1_000_000;
        u32::try_from(weighted).map_err(|_| GovernorPolicyError::ObjectiveScoreRange)
    }
}

/// How long a tripped circuit stays open before a half-open probe is allowed. Long enough for a
/// transient provider incident to clear, short enough that a recovered route is not stranded.
const CIRCUIT_OPEN_FOR_SECS: u64 = 30;

pub const MAX_GOVERNED_ROUTES: usize = 32;
pub const MAX_HEDGE_DUPLICATES: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailoverClass {
    ConnectFailed,
    RateLimited,
    Overloaded,
    ModelUnavailable,
    AccountUnavailable,
}

impl FailoverClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConnectFailed => "provider.connect_failed",
            Self::RateLimited => "provider.rate_limited",
            Self::Overloaded => "provider.overloaded",
            Self::ModelUnavailable => "model.unavailable",
            Self::AccountUnavailable => "account.unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailurePoint {
    PreDispatch,
    ProvenTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailoverRule {
    pub class: FailoverClass,
    pub point: FailurePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectiveWeights {
    pub quality_millionths: u32,
    pub cost_millionths: u32,
    pub latency_millionths: u32,
}

impl Default for ObjectiveWeights {
    fn default() -> Self {
        Self {
            quality_millionths: 600_000,
            cost_millionths: 200_000,
            latency_millionths: 200_000,
        }
    }
}

impl ObjectiveWeights {
    pub fn validate(self) -> Result<Self, GovernorPolicyError> {
        let sum = u64::from(self.quality_millionths)
            + u64::from(self.cost_millionths)
            + u64::from(self.latency_millionths);
        if sum != 1_000_000 {
            return Err(GovernorPolicyError::ObjectiveWeightSum);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitPolicy {
    pub failure_threshold: u16,
    pub open_for: Duration,
    pub half_open_probes: u16,
    pub success_threshold: u16,
}

impl Default for CircuitPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: iteron_tunables::param_integer(
                "provider.governor_policy.circuit_default_failure_threshold",
                3,
            ),
            open_for: Duration::from_secs(iteron_tunables::param_u64(
                "provider.governor_policy.circuit_open_for_secs",
                iteron_tunables::param_integer(
                    "provider.governor_policy.circuit_open_for_secs",
                    CIRCUIT_OPEN_FOR_SECS,
                ),
            )),
            half_open_probes: iteron_tunables::param_integer(
                "provider.governor_policy.circuit_default_half_open_probes",
                1,
            ),
            success_threshold: iteron_tunables::param_integer(
                "provider.governor_policy.circuit_default_success_threshold",
                1,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownQuotaPolicy {
    Conservative,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateAdmissionPolicy {
    pub minimum_remaining_requests: u64,
    pub minimum_remaining_tokens: u64,
    pub reset_wait_max: Duration,
    pub unknown_quota: UnknownQuotaPolicy,
}

impl Default for RateAdmissionPolicy {
    fn default() -> Self {
        let unknown_quota = match iteron_tunables::param_enum(
            "provider.governor_policy.rate_default_unknown_quota",
            "conservative",
        ) {
            "conservative" => UnknownQuotaPolicy::Conservative,
            "reject" => UnknownQuotaPolicy::Reject,
            value => panic!("unadmitted unknown-quota policy `{value}`"),
        };
        Self {
            minimum_remaining_requests: iteron_tunables::param_integer(
                "provider.governor_policy.rate_default_minimum_remaining_requests",
                0,
            ),
            minimum_remaining_tokens: iteron_tunables::param_integer(
                "provider.governor_policy.rate_default_minimum_remaining_tokens",
                0,
            ),
            reset_wait_max: Duration::ZERO,
            unknown_quota,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HedgePolicy {
    pub enabled: bool,
    pub delay: Duration,
    pub max_duplicates: u8,
    pub idempotent_only: bool,
}

impl Default for HedgePolicy {
    fn default() -> Self {
        Self {
            enabled: iteron_tunables::param_bool(
                "provider.governor_policy.hedge_default_enabled",
                false,
            ),
            delay: Duration::ZERO,
            max_duplicates: iteron_tunables::param_integer(
                "provider.governor_policy.hedge_default_max_duplicates",
                0,
            ),
            // This is the canonical fail-closed baseline even while hedging is disabled. A
            // future enabling override must never inherit a duplicate-unsafe owner default.
            idempotent_only: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GovernorPolicy {
    pub max_in_flight_per_route: usize,
    pub objectives: ObjectiveWeights,
    pub failover: BTreeSet<FailoverRule>,
    pub circuit: CircuitPolicy,
    pub rate_admission: RateAdmissionPolicy,
    pub hedge: HedgePolicy,
}

impl Default for GovernorPolicy {
    fn default() -> Self {
        Self {
            max_in_flight_per_route: iteron_tunables::param_integer(
                "provider.governor_policy.default_max_in_flight_per_route",
                4,
            ),
            objectives: ObjectiveWeights::default(),
            failover: default_failover_rules(),
            circuit: CircuitPolicy::default(),
            rate_admission: RateAdmissionPolicy::default(),
            hedge: HedgePolicy::default(),
        }
    }
}

/// Crate-owned shipped failover contract. CLI configuration may narrow or replace it, but a
/// direct library consumer no longer gets a contradictory empty policy.
pub fn default_failover_rules() -> BTreeSet<FailoverRule> {
    BTreeSet::from([
        FailoverRule {
            class: FailoverClass::ConnectFailed,
            point: FailurePoint::PreDispatch,
        },
        FailoverRule {
            class: FailoverClass::RateLimited,
            point: FailurePoint::ProvenTerminal,
        },
        FailoverRule {
            class: FailoverClass::Overloaded,
            point: FailurePoint::ProvenTerminal,
        },
        // A composition root may classify an upstream-rejected 5xx as pre-dispatch only when it
        // independently proves that the inference request was never accepted. Merely receiving a
        // 5xx response is a proven terminal and uses the sibling rule above; this row never
        // licenses an automatic retry or weakens at-most-once request effects.
        FailoverRule {
            class: FailoverClass::Overloaded,
            point: FailurePoint::PreDispatch,
        },
        FailoverRule {
            class: FailoverClass::ModelUnavailable,
            point: FailurePoint::PreDispatch,
        },
    ])
}

impl GovernorPolicy {
    pub fn validate(mut self) -> Result<Self, GovernorPolicyError> {
        if self.max_in_flight_per_route == 0 || self.max_in_flight_per_route > 1_024 {
            return Err(GovernorPolicyError::Concurrency);
        }
        self.objectives = self.objectives.validate()?;
        if self.circuit.failure_threshold == 0
            || self.circuit.open_for.is_zero()
            || self.circuit.half_open_probes == 0
            || self.circuit.success_threshold == 0
        {
            return Err(GovernorPolicyError::Circuit);
        }
        let max_hedge_duplicates = u8::try_from(iteron_tunables::param_i128(
            "provider.governor_policy.max_hedge_duplicates",
            i128::from(iteron_tunables::param_integer(
                "provider.governor_policy.max_hedge_duplicates",
                MAX_HEDGE_DUPLICATES,
            )),
        ))
        .unwrap_or(iteron_tunables::param_integer(
            "provider.governor_policy.max_hedge_duplicates",
            MAX_HEDGE_DUPLICATES,
        ));
        if self.hedge.max_duplicates > max_hedge_duplicates
            || (self.hedge.enabled
                && (!self.hedge.idempotent_only || self.hedge.max_duplicates == 0))
        {
            return Err(GovernorPolicyError::Hedge);
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum GovernorPolicyError {
    #[error("provider concurrency must be in 1..=1024")]
    Concurrency,
    #[error("quality/cost/latency weights must sum to exactly 1.0")]
    ObjectiveWeightSum,
    #[error("route quality/cost-efficiency/latency scores must each be in 0..=1.0")]
    ObjectiveScoreRange,
    #[error("circuit thresholds and open duration must be non-zero")]
    Circuit,
    #[error("hedging must be bounded, enabled with duplicates, and idempotent-only")]
    Hedge,
    #[error("provider route count exceeds the governor bound")]
    RouteCount,
    #[error("provider route identity is empty, too long, or duplicated")]
    RouteIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_round_defaults_provider_route_concurrency_is_independent() {
        assert_eq!(GovernorPolicy::default().max_in_flight_per_route, 4);
    }
}

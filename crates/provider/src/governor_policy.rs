//! Immutable, validated policy for the provider governor.

use std::collections::BTreeSet;
use std::time::Duration;

pub const MAX_GOVERNED_ROUTES: usize = 32;
pub const MAX_HEDGE_DUPLICATES: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailoverClass {
    RateLimited,
    Overloaded,
    ModelUnavailable,
    AccountUnavailable,
}

impl FailoverClass {
    pub const fn label(self) -> &'static str {
        match self {
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
            failure_threshold: 3,
            open_for: Duration::from_secs(30),
            half_open_probes: 1,
            success_threshold: 1,
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
        Self {
            minimum_remaining_requests: 0,
            minimum_remaining_tokens: 0,
            reset_wait_max: Duration::ZERO,
            unknown_quota: UnknownQuotaPolicy::Conservative,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HedgePolicy {
    pub enabled: bool,
    pub delay: Duration,
    pub max_duplicates: u8,
    pub idempotent_only: bool,
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
            max_in_flight_per_route: 1,
            objectives: ObjectiveWeights::default(),
            failover: BTreeSet::new(),
            circuit: CircuitPolicy::default(),
            rate_admission: RateAdmissionPolicy::default(),
            hedge: HedgePolicy::default(),
        }
    }
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
        if self.hedge.max_duplicates > MAX_HEDGE_DUPLICATES
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
    #[error("circuit thresholds and open duration must be non-zero")]
    Circuit,
    #[error("hedging must be bounded, enabled with duplicates, and idempotent-only")]
    Hedge,
    #[error("provider route count exceeds the governor bound")]
    RouteCount,
    #[error("provider route identity is empty, too long, or duplicated")]
    RouteIdentity,
}

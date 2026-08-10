//! Operator-trusted provider-governor configuration.

use core_provider::{
    CacheBreakpoint, CacheScope, CircuitPolicy, FailoverClass, FailoverRule, FailurePoint,
    GovernorPolicy, HedgePolicy, MAX_GOVERNED_ROUTES, ObjectiveWeights, PromptCacheControl,
    ProviderRequestControls, RateAdmissionPolicy, RequestCompression, ResponseVerbosity,
    ServiceTier, UnknownQuotaPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderGovernorConfig {
    /// Ordered, operator-admitted `provider:model` routes. The active selection is always first and
    /// need not be repeated here.
    pub fallback_routes: Vec<String>,
    pub failover: Option<Vec<FailoverRuleConfig>>,
    pub objectives: Option<ObjectiveWeightsConfig>,
    pub circuit: Option<CircuitConfig>,
    pub hedge: Option<HedgeConfig>,
    pub service_tier: Option<ServiceTierConfig>,
    pub response_verbosity: Option<ResponseVerbosityConfig>,
    pub request_compression: Option<RequestCompressionConfig>,
    pub rate_limit_admission: Option<RateAdmissionConfig>,
    pub prompt_cache: Option<PromptCacheConfig>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedProviderGovernorConfig {
    pub fallback_routes: Vec<String>,
    pub policy: GovernorPolicy,
    pub controls: ProviderRequestControls,
}

impl ProviderGovernorConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.resolve(1, false).map(|_| ())
    }

    pub(crate) fn resolve(
        &self,
        max_in_flight_per_route: usize,
        prompt_cache_enabled: bool,
    ) -> Result<ResolvedProviderGovernorConfig, String> {
        if self.fallback_routes.len() > MAX_GOVERNED_ROUTES.saturating_sub(1) {
            return Err(format!(
                "provider_governor.fallback_routes exceeds {} routes",
                MAX_GOVERNED_ROUTES.saturating_sub(1)
            ));
        }
        let mut unique = BTreeSet::new();
        for route in &self.fallback_routes {
            let valid = route.len() <= 640
                && route.split_once(':').is_some_and(|(provider, model)| {
                    !provider.is_empty()
                        && !model.is_empty()
                        && !route.chars().any(char::is_control)
                });
            if !valid || !unique.insert(route.as_str()) {
                return Err(
                    "provider_governor.fallback_routes must contain unique provider:model values"
                        .into(),
                );
            }
        }

        let failover = self
            .failover
            .as_ref()
            .map(|rules| rules.iter().map(FailoverRuleConfig::runtime).collect())
            .unwrap_or_else(|| {
                BTreeSet::from([
                    FailoverRule {
                        class: FailoverClass::RateLimited,
                        point: FailurePoint::ProvenTerminal,
                    },
                    FailoverRule {
                        class: FailoverClass::Overloaded,
                        point: FailurePoint::ProvenTerminal,
                    },
                    FailoverRule {
                        class: FailoverClass::ModelUnavailable,
                        point: FailurePoint::PreDispatch,
                    },
                ])
            });
        let objectives = self.objectives.unwrap_or_default().runtime()?;
        let circuit = self.circuit.unwrap_or_default().runtime()?;
        let hedge = self.hedge.unwrap_or_default().runtime()?;
        let rate_admission = self.rate_limit_admission.unwrap_or_default().runtime();
        let cache = self
            .prompt_cache
            .unwrap_or_else(|| PromptCacheConfig::default_for(prompt_cache_enabled));
        let controls = ProviderRequestControls {
            service_tier: self.service_tier.unwrap_or_default().runtime(),
            verbosity: self.response_verbosity.unwrap_or_default().runtime(),
            compression: self.request_compression.unwrap_or_default().runtime(),
            prompt_cache: cache.runtime()?,
            // Enabling hedging is the operator's request to duplicate a provider-only inference.
            // Composition still fails closed unless every admitted adapter independently attests
            // that such requests are duplicate-safe.
            idempotent: hedge.enabled,
        };
        let policy = GovernorPolicy {
            max_in_flight_per_route,
            objectives,
            failover,
            circuit,
            rate_admission,
            hedge,
        }
        .validate()
        .map_err(|error| format!("provider_governor: {error}"))?;
        Ok(ResolvedProviderGovernorConfig {
            fallback_routes: self.fallback_routes.clone(),
            policy,
            controls,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverRuleConfig {
    pub class: FailoverClassConfig,
    pub dispatch_state: FailurePointConfig,
}

impl FailoverRuleConfig {
    fn runtime(&self) -> FailoverRule {
        FailoverRule {
            class: self.class.runtime(),
            point: self.dispatch_state.runtime(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverClassConfig {
    RateLimited,
    Overloaded,
    ModelUnavailable,
    AccountUnavailable,
}

impl FailoverClassConfig {
    const fn runtime(self) -> FailoverClass {
        match self {
            Self::RateLimited => FailoverClass::RateLimited,
            Self::Overloaded => FailoverClass::Overloaded,
            Self::ModelUnavailable => FailoverClass::ModelUnavailable,
            Self::AccountUnavailable => FailoverClass::AccountUnavailable,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePointConfig {
    PreDispatch,
    ProvenTerminal,
}

impl FailurePointConfig {
    const fn runtime(self) -> FailurePoint {
        match self {
            Self::PreDispatch => FailurePoint::PreDispatch,
            Self::ProvenTerminal => FailurePoint::ProvenTerminal,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObjectiveWeightsConfig {
    pub quality_millionths: u32,
    pub cost_millionths: u32,
    pub latency_millionths: u32,
}

impl Default for ObjectiveWeightsConfig {
    fn default() -> Self {
        Self {
            quality_millionths: 600_000,
            cost_millionths: 200_000,
            latency_millionths: 200_000,
        }
    }
}

impl ObjectiveWeightsConfig {
    fn runtime(self) -> Result<ObjectiveWeights, String> {
        ObjectiveWeights {
            quality_millionths: self.quality_millionths,
            cost_millionths: self.cost_millionths,
            latency_millionths: self.latency_millionths,
        }
        .validate()
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CircuitConfig {
    pub failure_threshold: u16,
    pub open_seconds: u64,
    pub half_open_probes: u16,
    pub success_threshold: u16,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        let value = CircuitPolicy::default();
        Self {
            failure_threshold: value.failure_threshold,
            open_seconds: value.open_for.as_secs(),
            half_open_probes: value.half_open_probes,
            success_threshold: value.success_threshold,
        }
    }
}

impl CircuitConfig {
    fn runtime(self) -> Result<CircuitPolicy, String> {
        let policy = CircuitPolicy {
            failure_threshold: self.failure_threshold,
            open_for: Duration::from_secs(self.open_seconds),
            half_open_probes: self.half_open_probes,
            success_threshold: self.success_threshold,
        };
        GovernorPolicy {
            circuit: policy,
            ..GovernorPolicy::default()
        }
        .validate()
        .map(|_| policy)
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HedgeConfig {
    pub enabled: bool,
    pub delay_milliseconds: u64,
    pub max_duplicates: u8,
    pub idempotent_only: bool,
}

impl HedgeConfig {
    fn runtime(self) -> Result<HedgePolicy, String> {
        let policy = HedgePolicy {
            enabled: self.enabled,
            delay: Duration::from_millis(self.delay_milliseconds),
            max_duplicates: self.max_duplicates,
            idempotent_only: self.idempotent_only,
        };
        GovernorPolicy {
            hedge: policy,
            ..GovernorPolicy::default()
        }
        .validate()
        .map(|_| policy)
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTierConfig {
    #[default]
    ProviderDefault,
    Auto,
    Standard,
    Flex,
    Priority,
}

impl ServiceTierConfig {
    const fn runtime(self) -> ServiceTier {
        match self {
            Self::ProviderDefault => ServiceTier::ProviderDefault,
            Self::Auto => ServiceTier::Auto,
            Self::Standard => ServiceTier::Standard,
            Self::Flex => ServiceTier::Flex,
            Self::Priority => ServiceTier::Priority,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseVerbosityConfig {
    Concise,
    Balanced,
    Detailed,
    #[default]
    ModelDefault,
}

impl ResponseVerbosityConfig {
    const fn runtime(self) -> ResponseVerbosity {
        match self {
            Self::Concise => ResponseVerbosity::Concise,
            Self::Balanced => ResponseVerbosity::Balanced,
            Self::Detailed => ResponseVerbosity::Detailed,
            Self::ModelDefault => ResponseVerbosity::ModelDefault,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestCompressionConfig {
    #[default]
    None,
    Gzip,
    Zstd,
}

impl RequestCompressionConfig {
    const fn runtime(self) -> RequestCompression {
        match self {
            Self::None => RequestCompression::None,
            Self::Gzip => RequestCompression::Gzip,
            Self::Zstd => RequestCompression::Zstd,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownQuotaConfig {
    #[default]
    Conservative,
    Reject,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateAdmissionConfig {
    pub minimum_remaining_requests: u64,
    pub minimum_remaining_tokens: u64,
    pub reset_wait_max_seconds: u64,
    pub unknown_quota: UnknownQuotaConfig,
}

impl RateAdmissionConfig {
    fn runtime(self) -> RateAdmissionPolicy {
        RateAdmissionPolicy {
            minimum_remaining_requests: self.minimum_remaining_requests,
            minimum_remaining_tokens: self.minimum_remaining_tokens,
            reset_wait_max: Duration::from_secs(self.reset_wait_max_seconds.min(86_400)),
            unknown_quota: match self.unknown_quota {
                UnknownQuotaConfig::Conservative => UnknownQuotaPolicy::Conservative,
                UnknownQuotaConfig::Reject => UnknownQuotaPolicy::Reject,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PromptCacheConfig {
    pub ttl_seconds: u32,
    pub breakpoint: CacheBreakpointConfig,
    pub invalidate_on_tool_change: bool,
    pub scope: CacheScopeConfig,
}

impl PromptCacheConfig {
    fn default_for(enabled: bool) -> Self {
        Self {
            ttl_seconds: 0,
            breakpoint: if enabled {
                CacheBreakpointConfig::Rolling
            } else {
                CacheBreakpointConfig::None
            },
            invalidate_on_tool_change: true,
            scope: CacheScopeConfig::Session,
        }
    }

    fn runtime(self) -> Result<PromptCacheControl, String> {
        if self.ttl_seconds > 86_400 {
            return Err("provider_governor.prompt_cache.ttl_seconds exceeds 86400".into());
        }
        if self.ttl_seconds != 0 && matches!(self.breakpoint, CacheBreakpointConfig::None) {
            return Err(
                "provider_governor.prompt_cache.ttl_seconds requires an active breakpoint".into(),
            );
        }
        Ok(PromptCacheControl {
            ttl_seconds: self.ttl_seconds,
            breakpoint: self.breakpoint.runtime(),
            invalidate_on_tool_change: self.invalidate_on_tool_change,
            scope: self.scope.runtime(),
        })
    }
}

impl Default for PromptCacheConfig {
    fn default() -> Self {
        Self::default_for(false)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheBreakpointConfig {
    #[default]
    None,
    Rolling,
    Explicit,
}

impl CacheBreakpointConfig {
    const fn runtime(self) -> CacheBreakpoint {
        match self {
            Self::None => CacheBreakpoint::None,
            Self::Rolling => CacheBreakpoint::Rolling,
            Self::Explicit => CacheBreakpoint::Explicit,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheScopeConfig {
    Request,
    #[default]
    Session,
    Tenant,
}

impl CacheScopeConfig {
    const fn runtime(self) -> CacheScope {
        match self {
            Self::Request => CacheScope::Request,
            Self::Session => CacheScope::Session,
            Self::Tenant => CacheScope::Tenant,
        }
    }
}

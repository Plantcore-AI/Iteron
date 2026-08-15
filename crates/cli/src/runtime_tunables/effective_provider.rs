//! Decode the immutable provider-governor projection used by both fresh and resumed runs.

use super::effective_core::EffectiveCoreError;
use super::effective_view::EffectiveTunablesView;
use crate::config::ResolvedProviderGovernorConfig;
use iteron_provider::{
    CacheBreakpoint, CacheScope, CircuitPolicy, FailoverClass, FailoverRule, FailurePoint,
    GovernorPolicy, HedgePolicy, ObjectiveWeights, PromptCacheControl, ProviderRequestControls,
    RateAdmissionPolicy, RequestCompression, ResponseVerbosity, ServiceTier, UnknownQuotaPolicy,
};
use iteron_tunables::{DecimalValue, ResolutionValue, RuntimeGetterId};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub(super) fn decode(
    view: &EffectiveTunablesView,
) -> Result<ResolvedProviderGovernorConfig, EffectiveCoreError> {
    view.with_getter(RuntimeGetterId::EffectiveProvider, || decode_inner(view))
}

fn decode_inner(
    view: &EffectiveTunablesView,
) -> Result<ResolvedProviderGovernorConfig, EffectiveCoreError> {
    let fallback_routes = list_enums(view, "model_fallback_chain")?;
    // Provider request admission has its own stable physical tunable. It must not inherit the
    // workflow investigator ceiling: changing fan-out is not authority to multiply paid requests
    // on one provider route.
    let max_in_flight_per_route = GovernorPolicy::default().max_in_flight_per_route;
    let policy = GovernorPolicy {
        max_in_flight_per_route,
        objectives: decode_objectives(view)?,
        failover: decode_failover(view)?,
        circuit: decode_circuit(view)?,
        rate_admission: decode_rate_admission(view)?,
        hedge: decode_hedge(view)?,
    }
    .validate()
    .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))?;
    let controls = ProviderRequestControls {
        service_tier: parse_service_tier(view.enumeration("provider_service_tier")?)?,
        verbosity: parse_verbosity(view.enumeration("response_verbosity")?)?,
        compression: parse_compression(view.enumeration("request_compression_policy")?)?,
        prompt_cache: decode_prompt_cache(view)?,
        transport: decode_transport(view)?,
        // The immutable hedge policy is itself the request to duplicate provider-only inference;
        // adapter capability validation still independently proves the active route can do so.
        idempotent: policy.hedge.enabled,
    };
    Ok(ResolvedProviderGovernorConfig {
        fallback_routes,
        policy,
        controls,
    })
}

fn decode_transport(
    view: &EffectiveTunablesView,
) -> Result<iteron_provider::ProviderTransportTimeoutPolicy, EffectiveCoreError> {
    let pool_family = "http_pool_keepalive_idle_policy";
    let pool = view.object(pool_family)?;
    iteron_provider::ProviderTransportTimeoutPolicy {
        connect_tls: Duration::from_secs(u64v(
            view.integer("provider_connect_tls_timeout")?,
            "provider_connect_tls_timeout",
        )?),
        request_total: Duration::from_millis(u64v(
            view.integer("provider_request_total_deadline")?,
            "provider_request_total_deadline",
        )?),
        stream_idle: Duration::from_millis(u64v(
            view.integer("stream_idle_watchdog")?,
            "stream_idle_watchdog",
        )?),
        pool_idle: Duration::from_secs(u64v(
            integer(pool, pool_family, "pool_idle_seconds")?,
            pool_family,
        )?),
        tcp_keepalive: Duration::from_secs(u64v(
            integer(pool, pool_family, "tcp_keepalive_seconds")?,
            pool_family,
        )?),
        connection_reuse: boolean(pool, pool_family, "connection_reuse")?,
    }
    .validate()
    .map_err(|error| EffectiveCoreError::InvalidBudget(error.to_string()))
}

fn decode_objectives(view: &EffectiveTunablesView) -> Result<ObjectiveWeights, EffectiveCoreError> {
    let values = view.map("route_quality_cost_latency_objective_weights")?;
    Ok(ObjectiveWeights {
        quality_millionths: decimal_entry(values, "quality")?,
        cost_millionths: decimal_entry(values, "cost")?,
        latency_millionths: decimal_entry(values, "latency")?,
    })
}

fn decode_failover(
    view: &EffectiveTunablesView,
) -> Result<BTreeSet<FailoverRule>, EffectiveCoreError> {
    let family = "failover_eligible_error_taxonomy";
    let ResolutionValue::List { items } = view.value(family)? else {
        return Err(wrong(family, "list"));
    };
    let mut rules = BTreeSet::new();
    for item in items {
        let ResolutionValue::Object { fields } = item else {
            return Err(wrong(family, "list<object>"));
        };
        if !boolean(fields, family, "eligible")? {
            continue;
        }
        let class = match text(fields, family, "error_class")? {
            "provider.rate_limited" => FailoverClass::RateLimited,
            "provider.overloaded" => FailoverClass::Overloaded,
            "model.unavailable" => FailoverClass::ModelUnavailable,
            "account.unavailable" => FailoverClass::AccountUnavailable,
            value => return Err(unknown(family, value)),
        };
        let point = match enumeration(fields, family, "dispatch_state")? {
            "pre_dispatch" => FailurePoint::PreDispatch,
            "post_dispatch" => FailurePoint::ProvenTerminal,
            value => return Err(unknown(family, value)),
        };
        rules.insert(FailoverRule { class, point });
    }
    Ok(rules)
}

fn decode_circuit(view: &EffectiveTunablesView) -> Result<CircuitPolicy, EffectiveCoreError> {
    let family = "provider_health_circuit_breaker_state_policy";
    let fields = view.object(family)?;
    Ok(CircuitPolicy {
        failure_threshold: u16v(integer(fields, family, "failure_threshold")?, family)?,
        open_for: Duration::from_secs(u64v(integer(fields, family, "open_seconds")?, family)?),
        half_open_probes: u16v(integer(fields, family, "half_open_probes")?, family)?,
        success_threshold: u16v(integer(fields, family, "success_threshold")?, family)?,
    })
}

fn decode_hedge(view: &EffectiveTunablesView) -> Result<HedgePolicy, EffectiveCoreError> {
    let family = "hedged_request_policy";
    let fields = view.object(family)?;
    Ok(HedgePolicy {
        enabled: boolean(fields, family, "enabled")?,
        delay: Duration::from_millis(u64v(
            integer(fields, family, "delay_milliseconds")?,
            family,
        )?),
        max_duplicates: u8v(integer(fields, family, "max_duplicates")?, family)?,
        idempotent_only: boolean(fields, family, "idempotent_only")?,
    })
}

fn decode_rate_admission(
    view: &EffectiveTunablesView,
) -> Result<RateAdmissionPolicy, EffectiveCoreError> {
    let family = "rate_limit_aware_admission";
    let fields = view.object(family)?;
    Ok(RateAdmissionPolicy {
        minimum_remaining_requests: u64v(
            integer(fields, family, "minimum_remaining_requests")?,
            family,
        )?,
        minimum_remaining_tokens: u64v(
            integer(fields, family, "minimum_remaining_tokens")?,
            family,
        )?,
        reset_wait_max: Duration::from_secs(u64v(
            integer(fields, family, "reset_wait_max_seconds")?,
            family,
        )?),
        unknown_quota: match enumeration(fields, family, "unknown_quota")? {
            "conservative" => UnknownQuotaPolicy::Conservative,
            "reject" => UnknownQuotaPolicy::Reject,
            value => return Err(unknown(family, value)),
        },
    })
}

fn decode_prompt_cache(
    view: &EffectiveTunablesView,
) -> Result<PromptCacheControl, EffectiveCoreError> {
    let family = "prompt_cache_ttl_breakpoint_strategy";
    let fields = view.object(family)?;
    Ok(PromptCacheControl {
        ttl_seconds: u32v(integer(fields, family, "ttl_seconds")?, family)?,
        breakpoint: match enumeration(fields, family, "breakpoint")? {
            "none" => CacheBreakpoint::None,
            "rolling" => CacheBreakpoint::Rolling,
            "explicit" => CacheBreakpoint::Explicit,
            value => return Err(unknown(family, value)),
        },
        invalidate_on_tool_change: boolean(fields, family, "invalidate_on_tool_change")?,
        scope: match enumeration(fields, family, "scope")? {
            "request" => CacheScope::Request,
            "session" => CacheScope::Session,
            "tenant" => CacheScope::Tenant,
            value => return Err(unknown(family, value)),
        },
    })
}

fn parse_service_tier(value: &str) -> Result<ServiceTier, EffectiveCoreError> {
    match value {
        "provider_default" => Ok(ServiceTier::ProviderDefault),
        "auto" => Ok(ServiceTier::Auto),
        "standard" => Ok(ServiceTier::Standard),
        "flex" => Ok(ServiceTier::Flex),
        "priority" => Ok(ServiceTier::Priority),
        value => Err(unknown("provider_service_tier", value)),
    }
}

fn parse_verbosity(value: &str) -> Result<ResponseVerbosity, EffectiveCoreError> {
    match value {
        "model_default" => Ok(ResponseVerbosity::ModelDefault),
        "concise" => Ok(ResponseVerbosity::Concise),
        "balanced" => Ok(ResponseVerbosity::Balanced),
        "detailed" => Ok(ResponseVerbosity::Detailed),
        value => Err(unknown("response_verbosity", value)),
    }
}

fn parse_compression(value: &str) -> Result<RequestCompression, EffectiveCoreError> {
    match value {
        "none" => Ok(RequestCompression::None),
        "gzip" => Ok(RequestCompression::Gzip),
        "zstd" => Ok(RequestCompression::Zstd),
        value => Err(unknown("request_compression_policy", value)),
    }
}

fn list_enums(
    view: &EffectiveTunablesView,
    family: &'static str,
) -> Result<Vec<String>, EffectiveCoreError> {
    let ResolutionValue::List { items } = view.value(family)? else {
        return Err(wrong(family, "list<enum>"));
    };
    items
        .iter()
        .map(|item| match item {
            ResolutionValue::Enum { value } => Ok(value.clone()),
            _ => Err(wrong(family, "list<enum>")),
        })
        .collect()
}

fn decimal_entry(
    entries: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<u32, EffectiveCoreError> {
    let family = "route_quality_cost_latency_objective_weights";
    let ResolutionValue::Decimal { value } = entries
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    else {
        return Err(EffectiveCoreError::WrongFieldType { family, field });
    };
    decimal_ppm(*value, family)
}

fn integer(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Integer { value } => Ok(*value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn boolean(
    fields: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<bool, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Boolean { value } => Ok(*value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn text<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Text { value } => Ok(value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn enumeration<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveCoreError> {
    match fields
        .get(field)
        .ok_or(EffectiveCoreError::MissingField { family, field })?
    {
        ResolutionValue::Enum { value } => Ok(value),
        _ => Err(EffectiveCoreError::WrongFieldType { family, field }),
    }
}

fn decimal_ppm(value: DecimalValue, family: &'static str) -> Result<u32, EffectiveCoreError> {
    let denominator = 10_i128.pow(u32::from(value.scale));
    let numerator = i128::from(value.coefficient)
        .checked_mul(1_000_000)
        .ok_or(EffectiveCoreError::Range { family })?;
    if numerator % denominator != 0 {
        return Err(EffectiveCoreError::Range { family });
    }
    u32::try_from(numerator / denominator).map_err(|_| EffectiveCoreError::Range { family })
}

fn wrong(family: &'static str, expected: &'static str) -> EffectiveCoreError {
    super::effective_view::EffectiveViewError::WrongType {
        family: family.to_owned(),
        expected,
    }
    .into()
}

fn unknown(family: &'static str, value: &str) -> EffectiveCoreError {
    EffectiveCoreError::UnknownValue {
        family,
        value: value.to_owned(),
    }
}

fn u8v(value: i64, family: &'static str) -> Result<u8, EffectiveCoreError> {
    u8::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn u16v(value: i64, family: &'static str) -> Result<u16, EffectiveCoreError> {
    u16::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn u32v(value: i64, family: &'static str) -> Result<u32, EffectiveCoreError> {
    u32::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

fn u64v(value: i64, family: &'static str) -> Result<u64, EffectiveCoreError> {
    u64::try_from(value).map_err(|_| EffectiveCoreError::Range { family })
}

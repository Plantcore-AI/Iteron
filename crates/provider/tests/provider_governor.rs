use iteron_provider::{
    AdmissionReason, CacheBreakpoint, CacheScope, CircuitPolicy, CircuitTransition, FailoverClass,
    FailoverRule, FailurePoint, GovernorPolicy, ProviderAdmission, ProviderControlCapabilities,
    ProviderError, ProviderGovernor, ProviderRequestControls, RateAdmissionPolicy,
    RateLimitSnapshot, ResponseVerbosity, UnknownQuotaPolicy,
};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

fn governor(policy: GovernorPolicy) -> ProviderGovernor {
    ProviderGovernor::new(policy, ["provider:model".to_owned()]).unwrap()
}

#[test]
fn unknown_quota_conservatively_reduces_concurrency() {
    let policy = GovernorPolicy {
        max_in_flight_per_route: 8,
        ..Default::default()
    };
    let governor = governor(policy);
    let now = Instant::now();
    let first = match governor.admit("provider:model", now) {
        ProviderAdmission::Admitted(permit) => permit,
        other => panic!("first attempt was not admitted: {other:?}"),
    };
    assert!(matches!(
        governor.admit("provider:model", now),
        ProviderAdmission::Rejected(AdmissionReason::Ceiling)
    ));
    drop(first);
    assert!(matches!(
        governor.admit("provider:model", now),
        ProviderAdmission::Admitted(_)
    ));
}

#[test]
fn exhausted_quota_defers_only_to_the_resolved_wait_bound() {
    let policy = GovernorPolicy {
        rate_admission: RateAdmissionPolicy {
            minimum_remaining_requests: 1,
            minimum_remaining_tokens: 10,
            reset_wait_max: Duration::from_secs(30),
            unknown_quota: UnknownQuotaPolicy::Reject,
        },
        ..Default::default()
    };
    let governor = governor(policy);
    let now = Instant::now();
    governor.observe_rate_limit(
        "provider:model",
        RateLimitSnapshot {
            requests_remaining: Some(0),
            tokens_remaining: Some(0),
            requests_reset: Some(Duration::from_secs(20)),
            tokens_reset: Some(Duration::from_secs(10)),
        },
        now,
    );
    assert!(matches!(
        governor.admit("provider:model", now),
        ProviderAdmission::Deferred {
            wait,
            reason: AdmissionReason::QuotaExhausted
        } if wait == Duration::from_secs(20)
    ));
    assert!(matches!(
        governor.admit("provider:model", now + Duration::from_secs(21)),
        ProviderAdmission::Admitted(_)
    ));
}

#[test]
fn circuit_opens_half_opens_and_closes_without_raising_the_ceiling() {
    let policy = GovernorPolicy {
        circuit: CircuitPolicy {
            failure_threshold: 2,
            open_for: Duration::from_secs(5),
            half_open_probes: 1,
            success_threshold: 1,
        },
        ..Default::default()
    };
    let governor = governor(policy);
    let now = Instant::now();
    assert_eq!(
        governor.observe_failure("provider:model", now),
        CircuitTransition::None
    );
    assert_eq!(
        governor.observe_failure("provider:model", now),
        CircuitTransition::Opened
    );
    assert!(matches!(
        governor.admit("provider:model", now),
        ProviderAdmission::Rejected(AdmissionReason::CircuitOpen)
    ));
    let permit = match governor.admit("provider:model", now + Duration::from_secs(5)) {
        ProviderAdmission::Admitted(permit) => permit,
        other => panic!("half-open probe was not admitted: {other:?}"),
    };
    assert_eq!(permit.transition, CircuitTransition::HalfOpened);
    assert_eq!(
        governor.observe_success("provider:model"),
        CircuitTransition::Closed
    );
}

#[test]
fn failover_requires_both_typed_class_and_dispatch_state() {
    let policy = GovernorPolicy {
        failover: BTreeSet::from([FailoverRule {
            class: FailoverClass::RateLimited,
            point: FailurePoint::ProvenTerminal,
        }]),
        ..Default::default()
    };
    let governor = governor(policy);
    let error = ProviderError::Api {
        status: 429,
        body: "not retained".into(),
    };
    assert_eq!(
        governor.failover_class(&error, FailurePoint::ProvenTerminal),
        Some(FailoverClass::RateLimited)
    );
    assert_eq!(
        governor.failover_class(&error, FailurePoint::PreDispatch),
        None
    );
}

#[test]
fn route_controls_fail_closed_when_adapter_does_not_attest_them() {
    let capabilities = ProviderControlCapabilities::default();
    let mut controls = ProviderRequestControls {
        verbosity: ResponseVerbosity::Detailed,
        ..Default::default()
    };
    assert!(capabilities.validate(&controls).is_err());
    controls.verbosity = ResponseVerbosity::ModelDefault;
    controls.prompt_cache.breakpoint = CacheBreakpoint::Rolling;
    controls.prompt_cache.invalidate_on_tool_change = true;
    assert!(capabilities.validate(&controls).is_err());

    let mut capabilities = ProviderControlCapabilities::default();
    capabilities
        .cache_breakpoints
        .insert(CacheBreakpoint::Rolling);
    capabilities.cache_scopes.insert(CacheScope::Session);
    assert!(capabilities.validate(&controls).is_err());
    capabilities.cache_invalidates_on_tool_change = true;
    assert!(capabilities.validate(&controls).is_ok());
    controls.prompt_cache.scope = CacheScope::Tenant;
    assert!(capabilities.validate(&controls).is_err());
}

#[test]
fn explicit_route_registration_is_bounded_and_rollbackable() {
    let governor = governor(GovernorPolicy::default());
    assert!(matches!(
        governor.admit("other:model", Instant::now()),
        ProviderAdmission::Rejected(AdmissionReason::UnknownRoute)
    ));
    assert!(governor.register_route("other:model".into()).unwrap());
    assert!(!governor.register_route("other:model".into()).unwrap());
    let snapshot = governor.snapshot(Instant::now());
    assert_eq!(snapshot.routes.len(), 2);
    assert!(snapshot.routes.iter().all(|route| route.in_flight == 0));
    assert!(matches!(
        governor.admit("other:model", Instant::now()),
        ProviderAdmission::Admitted(_)
    ));
    // The permit above was temporary and has dropped, so a failed durable transaction can remove
    // the just-added route without racing in-flight work.
    assert!(governor.unregister_idle_route("other:model"));
    assert!(matches!(
        governor.admit("other:model", Instant::now()),
        ProviderAdmission::Rejected(AdmissionReason::UnknownRoute)
    ));
}

use super::ProviderRouteAdmission;
use crate::runtime::provider_route_events::ProviderRouteEvents;
use crate::runtime::provider_route_journal::ProviderRouteJournal;
use crate::runtime::session_control::{InboundControl, SessionControlState};
use crate::runtime::turn_activity::ActivitySink;
use crate::runtime::{DurableAppendFault, KernelError};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::{Ledger, lifecycle::LifecycleCorrelation};
use iteron_protocol::{RunId, TenantId, TurnId};
use iteron_provider::{
    GovernorPolicy, ProviderAdmission, ProviderError, ProviderGovernor, RateLimitSnapshot,
};
use iteron_record::Rollout;
use std::path::PathBuf;
use std::time::Instant;

fn directory() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "iteron-route-admission-{}-{next}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn events() -> ProviderRouteEvents {
    ProviderRouteEvents {
        turn: TurnId(1),
        lifecycle: None,
        hooks: None,
        correlation: LifecycleCorrelation::default(),
        activity: ActivitySink::default(),
    }
}

#[tokio::test]
async fn actual_shared_permit_queue_cancels_before_any_physical_intent() {
    let workspace = directory();
    let mut rollout =
        Rollout::open(&workspace, &RunId("queue".into()), TenantId::default()).unwrap();
    let governor = ProviderGovernor::new(
        GovernorPolicy {
            max_in_flight_per_route: 1,
            ..GovernorPolicy::default()
        },
        vec!["route".into()],
    )
    .unwrap();
    let ProviderAdmission::Admitted(held) = governor.admit("route", Instant::now()) else {
        panic!("actual probe permit must be available");
    };
    let mut control = SessionControlState::default();
    control.request(InboundControl::Interrupt);
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    let result = ProviderRouteAdmission {
        governor: Some(governor.clone()),
        control: &control,
        run_deadline: None,
        events: events(),
        journal: ProviderRouteJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        },
    }
    .admit("route")
    .await;
    assert!(matches!(
        result,
        Err(KernelError::Provider(ProviderError::Interrupted))
    ));
    assert!(!failed);
    assert!(iteron_record::replay(rollout.path()).unwrap().is_empty());
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 1);
    drop(held);
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 0);
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn queued_agent_deadline_has_one_budget_terminal_without_dispatch_or_permit_leak() {
    use crate::runtime::Agent;
    use iteron_protocol::{
        ActivityDetailCode, ActivityKind, ActivityOwner, ActivityState, Budget, EventKind, Outcome,
    };
    use iteron_provider::{Provider, StreamItem, TurnRequest, TurnResult};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct CountingProvider(AtomicUsize);
    #[async_trait::async_trait]
    impl Provider for CountingProvider {
        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ProviderError::Decode(
                "queued deadline fixture must never dispatch".into(),
            ))
        }
    }

    let workspace = directory();
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("queued-deadline".into()),
        TenantId::default(),
    )
    .unwrap();
    let provider = Arc::new(CountingProvider::default());
    let mut agent = Agent::new(
        provider.clone(),
        iteron_tools::Registry::read_only(&workspace).unwrap(),
        rollout,
        "queued-model".into(),
        "fixture".into(),
        Budget {
            max_turns: 2,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 30,
            max_consecutive_tool_errors: 2,
        },
    );
    agent.workspace = workspace.clone();
    let route = agent.governed_route_id();
    let governor = ProviderGovernor::new(
        GovernorPolicy {
            max_in_flight_per_route: 1,
            ..GovernorPolicy::default()
        },
        vec![route.clone()],
    )
    .unwrap();
    agent
        .install_shared_provider_governor(governor.clone())
        .unwrap();
    let ProviderAdmission::Admitted(held) = governor.admit(&route, Instant::now()) else {
        panic!("the real competing route permit must be admitted");
    };
    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel(256);
    agent.set_activity(activity_tx);
    let lifecycle = iteron_obs::lifecycle::LifecycleBus::default();
    agent.set_lifecycle_emitter(iteron_obs::lifecycle::LifecycleEmitter::new(
        lifecycle.clone(),
    ));
    // Occupy the actual shared permit for the entire invocation. Unlike a stalled transport,
    // this forces an admission wait; its typed queue activity below proves it was reached.
    agent
        .run_deadline
        .bind_external(Some(Instant::now() + Duration::from_secs(2)));
    let expected = Outcome::BudgetExhausted("max_wall_secs");
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        agent.run("finish only after the shared route admits the request"),
    )
    .await
    .expect("the inherited deadline must terminate the occupied permit wait")
    .unwrap();
    assert_eq!(outcome, expected);
    assert!(lifecycle.snapshot().events.iter().any(|event| {
        event.event_id.as_str() == "model.route_rejected"
            && event.payload.reason_code.as_deref()
                == Some("admission_deferred.provider_concurrency_ceiling")
    }));
    // Observe the real queue owner's typed events, not a best-effort lifecycle reason string.
    // Both the live queue and its failed terminal must be observed for the same identity.
    let mut activities = Vec::new();
    for _ in 0..256 {
        let Ok(event) = activity_rx.try_recv() else {
            break;
        };
        activities.push(event);
    }
    let queued = activities
        .iter()
        .find(|event| {
            event.id.ends_with(":queued_for_provider")
                && event.owner == ActivityOwner::Provider
                && event.kind == ActivityKind::ModelRequest
                && event.state == ActivityState::Running
                && event.detail_code == Some(ActivityDetailCode::RoutePermit)
                && event
                    .progress
                    .as_ref()
                    .is_some_and(|progress| progress.completed == 0 && progress.total == 1)
        })
        .expect("the invocation must actually wait for the occupied shared route permit");
    assert!(queued.validate().is_ok());
    assert!(activities.iter().any(|event| {
        event.id == queued.id
            && event.state == ActivityState::Failed
            && event.detail_code == Some(ActivityDetailCode::RoutePermit)
            && event.updated_at_unix_ms > queued.updated_at_unix_ms
    }));
    assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    assert_eq!(agent.ledger.provider_attempts, 0);
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    let terminals: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::Done { outcome } => Some(outcome.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(terminals, vec![format!("{expected:?}")]);
    assert!(!events.iter().any(|event| {
        matches!(&event.kind, EventKind::TurnStart)
            || matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")
    }));
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 1);
    drop(held);
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 0);
    let ProviderAdmission::Admitted(next) = governor.admit(&route, Instant::now()) else {
        panic!("deadline refusal must not strand a route permit");
    };
    drop(next);
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 0);
    agent.finish_advisory_maintenance_for_test().await.unwrap();
    drop(agent);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn deferred_admission_reasons_are_valid_bounded_lifecycle_codes() {
    use iteron_protocol::LifecyclePayload;
    use iteron_provider::AdmissionReason;

    for reason in [
        AdmissionReason::UnknownRoute,
        AdmissionReason::Ceiling,
        AdmissionReason::QuotaUnknown,
        AdmissionReason::QuotaExhausted,
        AdmissionReason::CircuitOpen,
        AdmissionReason::CircuitHalfOpen,
    ] {
        let code = super::admission_reason(reason);
        let payload = LifecyclePayload {
            reason_code: Some(format!("admission_deferred.{code}")),
            ..LifecyclePayload::default()
        };
        assert!(payload.validate().is_ok());
        let invalid_separator = LifecyclePayload {
            reason_code: Some(format!("admission_deferred:{code}")),
            ..LifecyclePayload::default()
        };
        assert!(invalid_separator.validate().is_err());
    }
}

#[test]
fn actual_quota_observation_cannot_claim_a_durable_projection_after_notice_fault() {
    let workspace = directory();
    let mut rollout =
        Rollout::open(&workspace, &RunId("quota".into()), TenantId::default()).unwrap();
    let governor = ProviderGovernor::new(GovernorPolicy::default(), vec!["route".into()]).unwrap();
    let control = SessionControlState::default();
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = Some(DurableAppendFault::Notice);
    let result = ProviderRouteAdmission {
        governor: Some(governor.clone()),
        control: &control,
        run_deadline: None,
        events: events(),
        journal: ProviderRouteJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        },
    }
    .observe(
        "route",
        &Err(KernelError::Provider(
            ProviderError::RequestCaptureRefusedBeforeDispatch,
        )),
        Some(RateLimitSnapshot {
            requests_remaining: Some(7),
            ..RateLimitSnapshot::default()
        }),
    );
    assert!(matches!(result, Err(KernelError::Record(_))));
    assert!(failed);
    assert!(iteron_record::replay(rollout.path()).unwrap().is_empty());
    assert!(governor.snapshot(Instant::now()).routes[0].quota_observed);
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn actual_unknown_route_refusal_keeps_typed_cause_without_intent_or_permit() {
    let workspace = directory();
    let mut rollout =
        Rollout::open(&workspace, &RunId("refused".into()), TenantId::default()).unwrap();
    let governor =
        ProviderGovernor::new(GovernorPolicy::default(), vec!["registered-route".into()]).unwrap();
    let control = SessionControlState::default();
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    let result = ProviderRouteAdmission {
        governor: Some(governor.clone()),
        control: &control,
        run_deadline: None,
        events: events(),
        journal: ProviderRouteJournal {
            rollout: &mut rollout,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            fault: &mut fault,
        },
    }
    .admit("unregistered-route")
    .await;
    assert!(matches!(
        &result,
        Err(KernelError::ProviderAdmission(
            iteron_provider::AdmissionReason::UnknownRoute
        ))
    ));
    assert_eq!(
        result.unwrap_err().refusal_reason(),
        iteron_protocol::refusal::RefusalReasonV1::InvalidRequest
    );
    assert!(!failed);
    assert!(iteron_record::replay(rollout.path()).unwrap().is_empty());
    assert_eq!(governor.snapshot(Instant::now()).routes[0].in_flight, 0);
    drop(rollout);
    std::fs::remove_dir_all(workspace).unwrap();
}

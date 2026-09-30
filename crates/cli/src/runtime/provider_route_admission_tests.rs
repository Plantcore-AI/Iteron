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

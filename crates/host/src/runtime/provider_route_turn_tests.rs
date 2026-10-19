use super::{ProviderRouteNext, ProviderRouteTurn};
use crate::runtime::KernelError;
use crate::runtime::provider_route_events::{
    ProviderRetrySchedule, ProviderRetryWait, ProviderRouteEvents,
};
use crate::runtime::session_control::InboundControl;
use crate::runtime::session_control::SessionControlState;
use crate::runtime::turn_activity::ActivitySink;
use iteron_obs::Ledger;
use iteron_obs::lifecycle::LifecycleCorrelation;
use iteron_protocol::{ReasoningEffort, TurnId};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_sched::BackoffPolicy;
use std::sync::Arc;
use std::time::Duration;

struct UncalledProvider;
#[async_trait::async_trait]
impl Provider for UncalledProvider {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        unreachable!("route state and waits never have dispatch authority")
    }
}
fn owner() -> ProviderRouteTurn {
    ProviderRouteTurn::new(
        TurnRequest {
            model: "fixture".into(),
            system: String::new(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new().into(),
            max_tokens: 4096,
            cache_system: false,
            thinking_budget: 2048,
            reasoning_effort: ReasoningEffort::Medium,
            controls: Default::default(),
        },
        1024,
        Arc::new(UncalledProvider),
        "provider:fixture".into(),
        &[],
        BackoffPolicy {
            base_ms: 0,
            cap_ms: 0,
            max_attempts: 2,
        },
        Duration::from_secs(30),
    )
}

#[test]
fn restored_physical_identity_and_original_policy_survive_logical_retry() {
    let mut state = owner();
    state.assign_identity(40, 41);
    state.settled();
    let connect = Err(KernelError::Provider(ProviderError::ConnectFailed));
    assert!(matches!(
        state.next(&connect, false, None, &[]),
        ProviderRouteNext::Retry { .. }
    ));
    assert_eq!(state.retry_index(), 0);
    state.retry_wait_completed();
    assert!(matches!(
        state.next(&connect, false, None, &[]),
        ProviderRouteNext::Terminal
    ));
    assert_eq!(state.physical_attempt(), 41);
    assert_eq!(state.ordinal(), 40);
    assert_eq!(state.requested_max_tokens(), 1024);
    assert_eq!(state.request().max_tokens, 4096);
    assert!(!state.first_attempt());
    state.observe_hedged_identity(Some(43), 2).unwrap();
    assert_eq!(state.physical_attempt(), 43);
    assert!(state.observe_hedged_identity(Some(43), 1).is_err());
    assert!(state.observe_hedged_identity(None, 1).is_err());
}

#[test]
fn semantic_output_and_local_capture_refusal_do_not_start_retry() {
    let mut state = owner();
    let connect = Err(KernelError::Provider(ProviderError::ConnectFailed));
    assert!(matches!(
        state.next(&connect, true, None, &[]),
        ProviderRouteNext::Terminal
    ));
    let capture = Err(KernelError::Provider(
        ProviderError::RequestCaptureRefusedBeforeDispatch,
    ));
    assert!(matches!(
        state.next(&capture, false, None, &[]),
        ProviderRouteNext::Terminal
    ));
    assert_eq!(state.retry_index(), 0);
    assert_eq!(state.physical_attempt(), 0);
}

#[tokio::test]
async fn real_control_wait_cancel_does_not_create_completed_retry_evidence() {
    let events = ProviderRouteEvents {
        turn: TurnId(9),
        lifecycle: None,
        hooks: None,
        correlation: LifecycleCorrelation::default(),
        activity: ActivitySink::default(),
    };
    let mut controls = SessionControlState::default();
    controls.request(InboundControl::Interrupt);
    let mut ledger = Ledger::new();
    let mut state = owner();
    assert!(
        events
            .wait_retry(
                ProviderRetryWait {
                    controls: &controls,
                    run_deadline: None,
                    ledger: &mut ledger
                },
                ProviderRetrySchedule {
                    delay: Duration::from_secs(1),
                    attempt: 1,
                    limit: 2
                },
            )
            .await
            .is_err()
    );
    assert_eq!(state.retry_index(), 0);
    assert_eq!(ledger.provider_retries, 0);
    controls.clear_interrupt_after_terminal();
    events
        .wait_retry(
            ProviderRetryWait {
                controls: &controls,
                run_deadline: None,
                ledger: &mut ledger,
            },
            ProviderRetrySchedule {
                delay: Duration::ZERO,
                attempt: 1,
                limit: 2,
            },
        )
        .await
        .unwrap();
    state.retry_wait_completed();
    assert_eq!(state.retry_index(), 1);
    assert_eq!(ledger.provider_retries, 1);
}

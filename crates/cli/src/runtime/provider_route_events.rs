//! Concrete immutable provider lifecycle/activity ports and actual bounded retry wait. This
//! adapter cannot admit requests, select routes, settle effects or change monetary ownership.
use super::KernelError;
use super::PROVIDER_INTERRUPT_POLL_INTERVAL;
use super::lifecycle_hooks::LifecycleHookDispatcher;
use super::provider_accounting::elapsed_us;
use super::session_control::SessionControlState;
use super::turn_activity::{ActivitySink, ActivitySpan, ActivityStage};
use iteron_obs::Ledger;
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{LifecyclePayload, TurnId};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(super) struct ProviderRouteEvents {
    pub(super) turn: TurnId,
    pub(super) lifecycle: Option<LifecycleEmitter>,
    pub(super) hooks: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
    pub(super) activity: ActivitySink,
}
pub(super) struct ProviderRetryWait<'a> {
    pub(super) controls: &'a SessionControlState,
    pub(super) run_deadline: Option<Instant>,
    pub(super) ledger: &'a mut Ledger,
}
pub(super) struct ProviderRetrySchedule {
    pub(super) delay: Duration,
    pub(super) attempt: u32,
    pub(super) limit: u32,
}
impl ProviderRouteEvents {
    pub(super) fn emit(&self, id: &str, payload: LifecyclePayload) {
        let Some(emitter) = &self.lifecycle else {
            return;
        };
        if let Ok(event) = emitter.emit(id, self.correlation.clone(), payload)
            && let Some(hooks) = &self.hooks
        {
            hooks.dispatch(event);
        }
    }
    pub(super) fn failover(&self) -> ActivitySpan {
        self.activity.span(ActivityStage::Failover, Some(self.turn))
    }
    pub(super) fn ceiling_refused(&self, hint: Duration) {
        self.emit(
            "model.retry_cancelled",
            LifecyclePayload {
                duration_us: Some(u64::try_from(hint.as_micros()).unwrap_or(u64::MAX)),
                reason_code: Some("retry_after_exceeds_interactive_ceiling".into()),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) fn request_sent(&self, retry: u32) {
        self.emit(
            "model.request_sent",
            LifecyclePayload {
                count: Some(u64::from(retry.saturating_add(1))),
                reason_code: Some("retry".into()),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) fn physical_stream_terminal(&self, items: u32) {
        self.emit(
            "model.stream_item",
            LifecyclePayload {
                count: Some(u64::from(items)),
                reason_code: Some("physical_attempt_terminal_aggregate".into()),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) async fn wait_retry(
        &self,
        wait: ProviderRetryWait<'_>,
        schedule: ProviderRetrySchedule,
    ) -> Result<(), KernelError> {
        self.emit(
            "model.retry_scheduled",
            LifecyclePayload {
                count: Some(u64::from(schedule.attempt)),
                duration_us: Some(u64::try_from(schedule.delay.as_micros()).unwrap_or(u64::MAX)),
                reason_code: Some("typed_transient_pre_stream_failure".into()),
                ..LifecyclePayload::default()
            },
        );
        self.activity
            .retry(self.turn, schedule.attempt, schedule.limit, schedule.delay);
        let started = Instant::now();
        let result = wait
            .controls
            .wait_retry(
                schedule.delay,
                wait.run_deadline,
                iteron_tunables::param_duration(
                    "cli.runtime.provider_interrupt_poll_interval",
                    PROVIDER_INTERRUPT_POLL_INTERVAL,
                ),
            )
            .await;
        if result.is_err() {
            self.emit(
                "model.retry_cancelled",
                LifecyclePayload {
                    count: Some(u64::from(schedule.attempt)),
                    duration_us: Some(elapsed_us(started)),
                    reason_code: Some("run_cancelled_during_backoff".into()),
                    ..LifecyclePayload::default()
                },
            );
        } else {
            wait.ledger.record_provider_retries(
                1,
                u64::try_from(schedule.delay.as_millis().max(1)).unwrap_or(u64::MAX),
            );
        }
        result
    }
}

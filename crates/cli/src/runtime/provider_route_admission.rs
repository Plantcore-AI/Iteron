//! Actual governor permit queue and physical outcome adapter. The governor retains its one Arc
//! state owner; this coordinator owns queue activity/wait state and only receives concrete ports.
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_journal::ProviderRouteJournal;
use super::session_control::SessionControlState;
use super::turn_activity::{ActivitySpan, ActivityStage};
use super::{KernelError, PROVIDER_INTERRUPT_POLL_INTERVAL};
use iteron_protocol::ActivityDetailCode;
use iteron_protocol::LifecyclePayload;
use iteron_provider::{
    AdmissionReason, AttemptPermit, CircuitTransition, ProviderAdmission, ProviderError,
    ProviderGovernor, RateLimitSnapshot, TurnResult,
};
use std::time::Instant;

pub(super) struct ProviderRouteAdmission<'a> {
    pub(super) governor: Option<ProviderGovernor>,
    pub(super) control: &'a SessionControlState,
    pub(super) run_deadline: Option<Instant>,
    pub(super) events: ProviderRouteEvents,
    pub(super) journal: ProviderRouteJournal<'a>,
}

#[cfg(test)]
#[path = "provider_route_admission_tests.rs"]
mod tests;

impl ProviderRouteAdmission<'_> {
    pub(super) async fn admit(
        &mut self,
        route_id: &str,
    ) -> Result<Option<AttemptPermit>, KernelError> {
        let Some(governor) = &self.governor else {
            return Ok(None);
        };
        let started = Instant::now();
        let total = u64::try_from(governor.policy().max_in_flight_per_route)
            .unwrap_or(iteron_protocol::MAX_ACTIVITY_PROGRESS_UNITS)
            .min(iteron_protocol::MAX_ACTIVITY_PROGRESS_UNITS);
        let mut queued: Option<ActivitySpan> = None;
        loop {
            match governor.admit(route_id, Instant::now()) {
                ProviderAdmission::Admitted(permit) => {
                    let available = available(governor, route_id);
                    if let Some(mut activity) = queued.take() {
                        activity.progress(u64::try_from(available).unwrap_or(u64::MAX), total);
                        activity.complete();
                    }
                    self.events.emit(
                        "model.route_selected",
                        LifecyclePayload {
                            count: Some(u64::try_from(available).unwrap_or(u64::MAX)),
                            duration_us: Some(
                                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                            ),
                            reason_code: Some("provider_permit_admitted".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    self.journal
                        .observe(self.events.turn, route_id, permit.transition, None)?;
                    return Ok(Some(permit));
                }
                ProviderAdmission::Deferred { wait, reason } => {
                    if queued.is_none() {
                        let mut activity = self
                            .events
                            .activity
                            .span(ActivityStage::QueuedForProvider, Some(self.events.turn));
                        activity.progress(
                            u64::try_from(available(governor, route_id)).unwrap_or(u64::MAX),
                            total,
                        );
                        queued = Some(activity);
                    }
                    self.events.emit(
                        "model.route_rejected",
                        LifecyclePayload {
                            duration_us: Some(u64::try_from(wait.as_micros()).unwrap_or(u64::MAX)),
                            reason_code: Some(format!(
                                "admission_deferred:{}",
                                admission_reason(reason)
                            )),
                            ..LifecyclePayload::default()
                        },
                    );
                    if let Err(error) = self
                        .control
                        .wait_retry(
                            wait,
                            self.run_deadline,
                            iteron_tunables::param_duration(
                                "cli.runtime.provider_interrupt_poll_interval",
                                PROVIDER_INTERRUPT_POLL_INTERVAL,
                            ),
                        )
                        .await
                    {
                        if let Some(activity) = queued.take() {
                            activity.fail(ActivityDetailCode::RoutePermit);
                        }
                        return Err(error);
                    }
                }
                ProviderAdmission::Rejected(reason) => {
                    self.events.emit(
                        "model.route_rejected",
                        LifecyclePayload {
                            reason_code: Some(admission_reason(reason).into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    return Err(ProviderError::Configuration(format!(
                        "provider governor rejected route admission ({})",
                        admission_reason(reason)
                    ))
                    .into());
                }
            }
        }
    }

    pub(super) fn observe(
        &mut self,
        route_id: &str,
        result: &Result<TurnResult, KernelError>,
        quota: Option<RateLimitSnapshot>,
    ) -> Result<(), KernelError> {
        let Some(governor) = &self.governor else {
            return Ok(());
        };
        if let Some(snapshot) = quota {
            governor.observe_rate_limit(route_id, snapshot, Instant::now());
        }
        let transition = match result {
            Ok(_) => governor.observe_success(route_id),
            Err(KernelError::Provider(
                ProviderError::Interrupted
                | ProviderError::DeadlineExceeded
                | ProviderError::RequestCaptureRefusedBeforeDispatch
                | ProviderError::RequestDeadlineBeforeDispatch,
            )) => CircuitTransition::None,
            Err(KernelError::Provider(_)) => governor.observe_failure(route_id, Instant::now()),
            Err(_) => CircuitTransition::None,
        };
        self.journal
            .observe(self.events.turn, route_id, transition, quota)
    }
}

fn available(governor: &ProviderGovernor, route: &str) -> usize {
    let snapshot = governor.snapshot(Instant::now());
    let in_flight = snapshot
        .routes
        .iter()
        .find(|row| row.route_id == route)
        .map_or(0, |row| row.in_flight);
    governor
        .policy()
        .max_in_flight_per_route
        .saturating_sub(in_flight)
}

pub(super) const fn admission_reason(reason: AdmissionReason) -> &'static str {
    match reason {
        AdmissionReason::UnknownRoute => "provider_route_not_admitted",
        AdmissionReason::Ceiling => "provider_concurrency_ceiling",
        AdmissionReason::QuotaUnknown => "provider_quota_unknown",
        AdmissionReason::QuotaExhausted => "provider_quota_exhausted",
        AdmissionReason::CircuitOpen => "provider_circuit_open",
        AdmissionReason::CircuitHalfOpen => "provider_circuit_half_open",
    }
}

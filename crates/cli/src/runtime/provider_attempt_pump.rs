//! One actual physical attempt's execution/terminal composition. Private observed state can only
//! come from the real stream pump; terminal sync, controller settlement and USD charge follow in
//! order through concrete domain ports. Host inclusion observation is between these two phases.
use super::KernelError;
use super::plantcore::PlantcoreRuntime;
use super::provider_attempt_journal::{
    ProviderAttemptJournal, ProviderLogicalUsageEvidence, ProviderObservedAttempt,
};
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_turn::ProviderRouteTurn;
use super::provider_stream_attempt::{ProviderAttemptScope, ProviderStreamAttempt};
use super::provider_transport_attempt::ProviderCancellation;
use iteron_provider::request_capture::ProviderRequestObserver;
use iteron_provider::{RateLimitSnapshot, TurnResult};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct ProviderAttemptTransport {
    pub(super) deadline: Instant,
    pub(super) cancellation: ProviderCancellation,
    pub(super) observer: Option<Arc<dyn ProviderRequestObserver>>,
    pub(super) started: Instant,
}

pub(super) struct ProviderAttemptPump {
    result: Result<TurnResult, KernelError>,
    quota: Option<RateLimitSnapshot>,
    hedged: bool,
    monetary_followup_safe: bool,
    observed_items: u32,
}

pub(super) struct ProviderAttemptCompletion {
    pub(super) result: Result<TurnResult, KernelError>,
    pub(super) quota: Option<RateLimitSnapshot>,
    pub(super) hedged: bool,
    pub(super) monetary_followup_safe: bool,
    pub(super) single_dispatched: bool,
    pub(super) usage_evidence: ProviderLogicalUsageEvidence,
}

impl ProviderAttemptPump {
    pub(super) async fn run(
        route: &mut ProviderRouteTurn,
        stream: ProviderStreamAttempt<'_>,
        transport: ProviderAttemptTransport,
        hedged: Option<HedgedProviderDispatch>,
        refusal: Option<KernelError>,
    ) -> Result<Self, KernelError> {
        if let Some(dispatch) = &hedged {
            route.observe_hedged_identity(
                dispatch.last_physical_attempt,
                dispatch.scheduled_attempts,
            )?;
        }
        let monetary_followup_safe = hedged
            .as_ref()
            .is_none_or(|dispatch| dispatch.monetary_followup_safe);
        let hedged_this_attempt = hedged.is_some();
        let before = stream.observer.stream_items();
        // Keep the same observation owner after the stream consumes its tool admission port.
        let ProviderStreamAttempt { observer, tools } = stream;
        let receipt = ProviderStreamAttempt {
            observer: &mut *observer,
            tools,
        }
        .run(
            ProviderAttemptScope {
                provider: route.provider(),
                request: route.request(),
                deadline: transport.deadline,
                cancellation: transport.cancellation,
                request_observer: transport.observer,
            },
            hedged,
            refusal,
        )
        .await;
        route.observe_active(transport.started.elapsed());
        Ok(Self {
            result: receipt.result,
            quota: receipt.quota,
            hedged: hedged_this_attempt,
            monetary_followup_safe,
            observed_items: observer.stream_items().saturating_sub(before),
        })
    }

    pub(super) fn settle(
        self,
        route: &mut ProviderRouteTurn,
        mut journal: ProviderAttemptJournal<'_>,
        events: &ProviderRouteEvents,
        plantcore: &mut PlantcoreRuntime,
    ) -> Result<ProviderAttemptCompletion, KernelError> {
        let turn = events.turn;
        let single_dispatched = route.ticket().is_some();
        if single_dispatched || self.hedged {
            events.physical_stream_terminal(self.observed_items);
        }
        let mut monetary_followup_safe = self.monetary_followup_safe;
        let mut usage_evidence = if self.hedged {
            ProviderLogicalUsageEvidence::HedgedAggregate
        } else {
            ProviderLogicalUsageEvidence::Unproven
        };
        if let Some(ticket) = route.take_ticket() {
            let started = Instant::now();
            let (accounting, safe, receipt) = journal.settle_observed(
                ticket,
                ProviderObservedAttempt {
                    route_id: route.route_id(),
                    result: &self.result,
                },
            )?;
            monetary_followup_safe = safe;
            plantcore
                .observe_provider_attempt(turn, &accounting)
                .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
            journal.commit_usd(turn, &accounting)?;
            journal.measure_broker(started);
            usage_evidence = ProviderLogicalUsageEvidence::Single(receipt);
        }
        Ok(ProviderAttemptCompletion {
            result: self.result,
            quota: self.quota,
            hedged: self.hedged,
            monetary_followup_safe,
            single_dispatched,
            usage_evidence,
        })
    }
}

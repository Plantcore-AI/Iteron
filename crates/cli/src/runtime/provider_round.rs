//! Actual streamed response/declaration and physical pump lifetime for one model round. Route
//! strategy, finance, controller and WAL owners cross this coordinator only through typed ports.
use super::KernelError;
use super::provider_attempt_journal::ProviderAttemptJournal;
use super::provider_attempt_pump::{
    ProviderAttemptCompletion, ProviderAttemptPump, ProviderAttemptTransport,
};
use super::provider_extension::ProviderExtensionPort;
use super::provider_governor_state::GovernedProviderRoute;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_turn::{ProviderRouteNext, ProviderRouteTurn};
use super::provider_stream_attempt::ProviderStreamAttempt;
use super::provider_stream_observer::{ProviderStreamObserver, ProviderStreamScope};
use super::stream_tool_admission::{StreamToolAdmission, StreamToolScope};
use super::stream_tool_journal::StreamToolJournal;
use super::tool_turn::{EarlyToolInFlight, ToolTurnOwner, ToolTurnWork};
use iteron_protocol::{ActivityDetailCode, Block, LifecyclePayload, ToolUse};
use iteron_provider::{FailoverClass, RateLimitSnapshot, TurnResult};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundPhase {
    Ready,
    PendingTerminal,
    TerminalObserved,
    AwaitingDecision,
    NeedsAdmission,
    CanClose,
    Closed,
    Failed,
}

pub(super) struct ProviderRoundOwner {
    phase: RoundPhase,
    pending: Option<ProviderAttemptPump>,
    tools: ToolTurnOwner,
    observations: ProviderStreamObserver,
    stream_started: Instant,
}

impl ProviderRoundOwner {
    pub(super) fn new(scope: ProviderStreamScope) -> Self {
        let stream_started = scope.started;
        Self {
            phase: RoundPhase::Ready,
            pending: None,
            tools: ToolTurnOwner::default(),
            observations: ProviderStreamObserver::new(scope),
            stream_started,
        }
    }
    /// The pump remains owned until an actual physical settlement consumes it. A second
    /// dispatch while the prior result lacks a terminal cannot enter this coordinator.
    pub(super) async fn run_attempt(
        &mut self,
        route: &mut ProviderRouteTurn,
        journal: StreamToolJournal<'_>,
        scope: StreamToolScope<'_>,
        transport: ProviderAttemptTransport,
        hedged: Option<HedgedProviderDispatch>,
        refusal: Option<KernelError>,
    ) -> Result<(), KernelError> {
        self.require(RoundPhase::Ready)?;
        // Dropping this future after IO cannot rearm the same round with an unobserved result.
        self.phase = RoundPhase::Failed;
        let admission = StreamToolAdmission::new(&mut self.tools, journal, scope);
        let attempt = ProviderAttemptPump::run(
            route,
            ProviderStreamAttempt {
                observer: &mut self.observations,
                tools: admission,
            },
            transport,
            hedged,
            refusal,
        )
        .await;
        match attempt {
            Ok(attempt) => {
                self.pending = Some(attempt);
                self.phase = RoundPhase::PendingTerminal;
                Ok(())
            }
            Err(error) => {
                self.phase = RoundPhase::Failed;
                Err(error)
            }
        }
    }
    pub(super) fn settle_attempt(
        &mut self,
        route: &mut ProviderRouteTurn,
        journal: ProviderAttemptJournal<'_>,
        events: &ProviderRouteEvents,
        extension: ProviderExtensionPort<'_>,
    ) -> Result<ProviderAttemptCompletion, KernelError> {
        self.require(RoundPhase::PendingTerminal)?;
        let attempt = self.pending.take().expect("owned pending physical pump");
        // Failure remains terminally closed. This owner cannot dispatch a replacement for an
        // unavailable WAL/controller settlement or reconstruct the consumed ticket.
        self.phase = RoundPhase::Failed;
        let observed = attempt.settle(route, journal, events, extension)?;
        self.phase = RoundPhase::TerminalObserved;
        Ok(observed)
    }
    pub(super) fn release_attempt(
        &mut self,
        route: &mut ProviderRouteTurn,
    ) -> Result<(), KernelError> {
        self.require(RoundPhase::TerminalObserved)?;
        drop(route.take_route_permit());
        drop(route.take_dispatch_permit());
        route.settled();
        self.phase = RoundPhase::AwaitingDecision;
        Ok(())
    }
    pub(super) fn next_route(
        &mut self,
        route: &mut ProviderRouteTurn,
        result: &Result<TurnResult, KernelError>,
        failover: Option<FailoverClass>,
        routes: &[GovernedProviderRoute],
    ) -> Result<ProviderRouteNext, KernelError> {
        self.require(RoundPhase::AwaitingDecision)?;
        let next = route.next(
            result,
            self.observations.semantic_output_observed(),
            failover,
            routes,
        );
        self.phase = match &next {
            ProviderRouteNext::Retry { .. } | ProviderRouteNext::Fallback { .. } => {
                RoundPhase::NeedsAdmission
            }
            _ => RoundPhase::CanClose,
        };
        Ok(next)
    }
    pub(super) fn restart_connect(&mut self) -> Result<(), KernelError> {
        self.require(RoundPhase::NeedsAdmission)?;
        self.phase = RoundPhase::Ready;
        self.stream_started = Instant::now();
        self.observations.restart_connect(self.stream_started);
        Ok(())
    }
    pub(super) fn close(
        &mut self,
        result: &Result<TurnResult, KernelError>,
        events: &ProviderRouteEvents,
    ) -> Result<(), KernelError> {
        if !matches!(
            self.phase,
            RoundPhase::AwaitingDecision | RoundPhase::NeedsAdmission | RoundPhase::CanClose
        ) {
            return Err(KernelError::EffectBoundary(
                "provider round closed before its physical terminal".into(),
            ));
        }
        self.phase = RoundPhase::Closed;
        match result {
            Ok(_) => {
                self.observations.complete_stream();
                events.emit(
                    "model.stream_completed",
                    LifecyclePayload {
                        count: Some(u64::from(self.observations.stream_items())),
                        duration_us: Some(super::provider_accounting::elapsed_us(
                            self.stream_started,
                        )),
                        ..LifecyclePayload::default()
                    },
                );
            }
            Err(error) => {
                self.observations.fail_stream(
                    if matches!(
                        error,
                        KernelError::Provider(iteron_provider::ProviderError::DeadlineExceeded)
                    ) {
                        ActivityDetailCode::WaitingFirstToken
                    } else {
                        ActivityDetailCode::TransportConnect
                    },
                );
                events.emit(
                    "model.request_failed",
                    LifecyclePayload {
                        reason_code: Some(
                            super::provider_route::provider_failure_stage(error).into(),
                        ),
                        duration_us: Some(super::provider_accounting::elapsed_us(
                            self.stream_started,
                        )),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
        Ok(())
    }
    /// Complete declaration identity, including argument order/content, must agree at the stream
    /// and transcript boundaries. Successful physical billing remains unaffected by a refusal.
    pub(super) fn validated_tools(&self, result: &TurnResult) -> Result<Vec<ToolUse>, KernelError> {
        self.require(RoundPhase::Closed)?;
        let declared = self.declared_calls();
        let returned = result
            .blocks
            .iter()
            .filter_map(|block| match block {
                Block::ToolUse(call) => Some(call.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if declared != returned {
            return Err(iteron_provider::ProviderError::Decode(
                "provider stream/tool transcript projections disagree".into(),
            )
            .into());
        }
        Ok(returned)
    }
    pub(super) fn declared_calls(&self) -> Vec<ToolUse> {
        let mut calls = self
            .tools
            .early()
            .iter()
            .map(|(index, call, ..)| (*index, call.clone()))
            .chain(
                self.tools
                    .deferred()
                    .iter()
                    .map(|(index, call, _)| (*index, call.clone())),
            )
            .collect::<Vec<_>>();
        calls.sort_by_key(|(index, _)| *index);
        calls.into_iter().map(|(_, call)| call).collect()
    }
    pub(super) fn tools(&self) -> &ToolTurnOwner {
        &self.tools
    }
    pub(super) fn take_record_error(&mut self) -> Option<KernelError> {
        self.tools.take_record_error()
    }
    pub(super) fn take_contract_error(
        &mut self,
    ) -> Option<iteron_kernel::effects::ToolCallContractError> {
        self.tools.take_contract_error()
    }
    pub(super) fn take_early_for_cleanup(&mut self) -> Vec<EarlyToolInFlight> {
        self.tools.take_early_for_cleanup()
    }
    pub(super) fn into_tool_work(self) -> Result<ToolTurnWork, KernelError> {
        self.require(RoundPhase::Closed)?;
        Ok(self.tools.into_work())
    }
    pub(super) fn stream_started(&self) -> Instant {
        self.stream_started
    }
    pub(super) fn observations(&self) -> &ProviderStreamObserver {
        &self.observations
    }
    pub(super) fn fail_connect(&mut self) {
        self.observations.fail_connect();
    }
    pub(super) fn take_quota(&mut self) -> Option<RateLimitSnapshot> {
        self.observations.take_quota()
    }
    fn require(&self, phase: RoundPhase) -> Result<(), KernelError> {
        if self.phase != phase {
            return Err(KernelError::EffectBoundary(
                "provider round phase refused".into(),
            ));
        }
        Ok(())
    }
}

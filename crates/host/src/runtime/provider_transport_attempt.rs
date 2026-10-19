//! Actual already-admitted provider transport owner. The caller supplies immutable route and
//! control evidence; admission, money, physical effect receipts and retries are separate owners.
use super::{KernelError, PROVIDER_INTERRUPT_POLL_INTERVAL};
use iteron_provider::request_capture::ProviderRequestObserver;
use iteron_provider::{Provider, ProviderAttemptSemantics, StreamItem, TurnRequest};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub(super) struct ProviderCancellation {
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
    pub(super) attempt: Option<Arc<AtomicBool>>,
    pub(super) allow_in_flight_past_deadline: bool,
}

pub(super) async fn execute_admitted_provider_turn_observed(
    provider: std::sync::Arc<dyn Provider>,
    deadline: Instant,
    cancellation: ProviderCancellation,
    request: &TurnRequest,
    on_item: &mut (dyn FnMut(StreamItem) + Send),
    observer: Option<&dyn ProviderRequestObserver>,
) -> Result<iteron_provider::TurnResult, KernelError> {
    if provider.attempt_semantics() != ProviderAttemptSemantics::Single {
        return Err(KernelError::OpaqueProviderRetries);
    }
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(iteron_provider::ProviderError::DeadlineExceeded.into());
    }
    // This is shared by ordinary, auxiliary and hedged physical calls. A fallback/hedge can use a
    // different adapter than the request's original route; never forward its unsupported hint or
    // leave the legacy bit true (which some adapters interpret as an implicit rolling hint).
    let controls = provider
        .control_capabilities()
        .adapt_optional_cache_breakpoint(request.controls);
    let projected;
    let request = if controls != request.controls {
        projected = TurnRequest {
            controls,
            cache_system: controls.prompt_cache.breakpoint
                != iteron_provider::CacheBreakpoint::None,
            ..request.clone()
        };
        &projected
    } else {
        request
    };
    let mut cancels = vec![
        cancellation.force_cancel.as_ref(),
        cancellation.drain.as_ref(),
    ];
    if let Some(interrupt) = cancellation.interrupt.as_deref() {
        cancels.push(interrupt);
    }
    if let Some(attempt_cancel) = cancellation.attempt.as_deref() {
        cancels.push(attempt_cancel);
    }
    let poll = iteron_tunables::param_duration(
        "cli.runtime.provider_interrupt_poll_interval",
        PROVIDER_INTERRUPT_POLL_INTERVAL,
    );
    let turn = async {
        if let Some(observer) = observer {
            iteron_provider::turn_cancellable_any_observed(
                provider.as_ref(),
                request,
                on_item,
                observer,
                &cancels,
                poll,
            )
            .await
        } else {
            // Legacy API has no extra capture work or synthetic prepared/dispatched evidence.
            iteron_provider::turn_cancellable_any(
                provider.as_ref(),
                request,
                on_item,
                &cancels,
                poll,
            )
            .await
        }
    };
    if cancellation.allow_in_flight_past_deadline {
        turn.await.map_err(KernelError::Provider)
    } else {
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(remaining, turn)
            .await
            .map_err(|_| KernelError::Provider(iteron_provider::ProviderError::DeadlineExceeded))?
            .map_err(KernelError::Provider)
    }
}

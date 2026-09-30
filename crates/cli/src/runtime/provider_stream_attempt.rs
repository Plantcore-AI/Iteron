//! One physical provider attempt's actual stream pump. Provider observations and tool admission
//! retain their own mutable owners; this coordinator routes real items and never receives Agent.
use super::KernelError;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_stream_observer::{ObservedStreamItem, ProviderStreamObserver};
use super::provider_transport_attempt::{
    ProviderCancellation, execute_admitted_provider_turn_observed,
};
use super::stream_tool_admission::StreamToolAdmission;
use iteron_provider::request_capture::ProviderRequestObserver;
use iteron_provider::{Provider, RateLimitSnapshot, StreamItem, TurnRequest, TurnResult};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct ProviderStreamAttempt<'a> {
    pub(super) observer: &'a mut ProviderStreamObserver,
    pub(super) tools: StreamToolAdmission<'a>,
}

pub(super) struct ProviderAttemptScope<'a> {
    pub(super) provider: Arc<dyn Provider>,
    pub(super) request: &'a TurnRequest,
    pub(super) deadline: Instant,
    pub(super) cancellation: ProviderCancellation,
    pub(super) request_observer: Option<Arc<dyn ProviderRequestObserver>>,
}

pub(super) struct ProviderAttemptReceipt {
    pub(super) result: Result<TurnResult, KernelError>,
    pub(super) quota: Option<RateLimitSnapshot>,
}

impl ProviderStreamAttempt<'_> {
    pub(super) async fn run(
        mut self,
        scope: ProviderAttemptScope<'_>,
        hedged: Option<HedgedProviderDispatch>,
        refusal: Option<KernelError>,
    ) -> ProviderAttemptReceipt {
        let mut quota = None;
        let already_forwarded = hedged
            .as_ref()
            .is_some_and(|dispatch| dispatch.ui_deltas_forwarded);
        let mut on_item = |item: StreamItem| match self.observer.observe(item, already_forwarded) {
            ObservedStreamItem::Quota(snapshot) => quota = Some(snapshot),
            ObservedStreamItem::Tool(call) => self.tools.declare(call),
            ObservedStreamItem::Presented => {}
        };
        let result = if let Some(dispatch) = hedged {
            // Hedge physical journals and monetary receipts are already settled by their true
            // owner. Replaying its actual retained items only folds semantic/tool observations.
            for item in dispatch.items {
                on_item(item);
            }
            dispatch.result
        } else if let Some(error) = refusal {
            Err(error)
        } else {
            execute_admitted_provider_turn_observed(
                scope.provider,
                scope.deadline,
                scope.cancellation,
                scope.request,
                &mut on_item,
                scope.request_observer.as_deref(),
            )
            .await
        };
        ProviderAttemptReceipt { result, quota }
    }
}

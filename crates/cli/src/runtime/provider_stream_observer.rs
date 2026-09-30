//! Actual provider-item presentation and activity owner. This owner observes transport truth;
//! dispatch, monetary admission, tool WAL admission and response settlement remain separate ports.
use super::frontend::FrontendChannelHealth;
use super::frontend_events::{RuntimeFrontendEvent, UiEvent};
use super::lifecycle_hooks::LifecycleHookDispatcher;
use super::provider_turn_evidence::ProviderTurnEvidence;
use super::stream_progress::StreamTiming;
use super::turn_activity::{ActivitySink, ActivitySpan, ActivityStage};
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{ActivityDetailCode, LifecyclePayload, ToolUse, TurnId};
use iteron_provider::{RateLimitSnapshot, StreamItem};
use std::time::Instant;
use tokio::sync::mpsc::Sender;

pub(super) struct ProviderStreamScope {
    pub(super) turn: TurnId,
    pub(super) started: Instant,
    pub(super) prefix_limit: usize,
    pub(super) activity: ActivitySink,
    pub(super) running: Option<ActivitySpan>,
    pub(super) connect: Option<ActivitySpan>,
    pub(super) frontend: FrontendChannelHealth,
    pub(super) resident_ui: Option<Sender<RuntimeFrontendEvent>>,
    pub(super) ui: Option<Sender<UiEvent>>,
    pub(super) lifecycle: Option<LifecycleEmitter>,
    pub(super) lifecycle_hooks: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
}

pub(super) enum ObservedStreamItem {
    Tool(ToolUse),
    Quota(RateLimitSnapshot),
    CompatibilityNotice,
    Presented,
}

pub(super) struct ProviderStreamObserver {
    evidence: ProviderTurnEvidence,
    scope: ProviderStreamScope,
    awaiting_token: Option<ActivitySpan>,
    decode: Option<ActivitySpan>,
}
impl ProviderStreamObserver {
    pub(super) fn new(scope: ProviderStreamScope) -> Self {
        Self {
            evidence: ProviderTurnEvidence::new(scope.prefix_limit),
            scope,
            awaiting_token: None,
            decode: None,
        }
    }

    pub(super) fn observe(
        &mut self,
        item: StreamItem,
        already_forwarded: bool,
    ) -> ObservedStreamItem {
        match item {
            StreamItem::Accepted => {
                if self.evidence.mark_first_byte() {
                    self.enter_awaiting_token();
                    self.emit("model.accepted", self.timing_payload());
                }
                return ObservedStreamItem::Presented;
            }
            StreamItem::CompatibilityNotice(message) => {
                self.present(UiEvent::Notice(message.to_string()));
                return ObservedStreamItem::CompatibilityNotice;
            }
            StreamItem::RateLimit(snapshot) => {
                if self.evidence.mark_first_byte() {
                    self.enter_awaiting_token();
                    self.emit("model.first_byte", self.timing_payload());
                }
                self.emit("model.rate_limit_observed", LifecyclePayload::default());
                self.evidence.observe_quota(snapshot);
                return ObservedStreamItem::Quota(snapshot);
            }
            _ => {}
        }
        if self.evidence.observe_payload(&item) {
            self.enter_awaiting_token();
            if let Some(span) = self.awaiting_token.take() {
                span.complete();
            }
            self.decode = Some(
                self.scope
                    .activity
                    .span(ActivityStage::Decode, Some(self.scope.turn)),
            );
            if self.evidence.mark_first_byte() {
                self.emit("model.first_byte", self.timing_payload());
            }
            self.emit("model.first_token", self.timing_payload());
        }
        match item {
            StreamItem::TextDelta(delta) => {
                self.evidence.append_text(&delta);
                if !already_forwarded {
                    self.present(UiEvent::Text(iteron_record::redact::scrub(&delta)));
                }
                ObservedStreamItem::Presented
            }
            StreamItem::ThinkingDelta(delta) => {
                self.evidence.append_thinking(&delta);
                if !already_forwarded {
                    self.present(UiEvent::Thinking(iteron_record::redact::scrub(&delta)));
                }
                ObservedStreamItem::Presented
            }
            StreamItem::ToolUseComplete(tool) => ObservedStreamItem::Tool(tool),
            StreamItem::Accepted
            | StreamItem::CompatibilityNotice(_)
            | StreamItem::RateLimit(_)
            | StreamItem::TurnComplete { .. } => ObservedStreamItem::Presented,
        }
    }

    pub(super) fn fail_connect(&mut self) {
        if let Some(span) = self.scope.connect.take() {
            span.fail(ActivityDetailCode::TransportConnect);
        }
    }
    pub(super) fn restart_connect(&mut self, started: Instant) {
        self.scope.started = started;
        self.scope.connect = Some(
            self.scope
                .activity
                .span(ActivityStage::Connect, Some(self.scope.turn)),
        );
    }
    pub(super) fn complete_stream(&mut self) {
        for span in [
            self.scope.running.take(),
            self.scope.connect.take(),
            self.awaiting_token.take(),
            self.decode.take(),
        ]
        .into_iter()
        .flatten()
        {
            span.complete();
        }
    }
    pub(super) fn fail_stream(&mut self, detail: ActivityDetailCode) {
        for span in [
            self.scope.running.take(),
            self.scope.connect.take(),
            self.awaiting_token.take(),
            self.decode.take(),
        ]
        .into_iter()
        .flatten()
        {
            span.fail(detail);
        }
    }
    pub(super) fn stream_items(&self) -> u32 {
        self.evidence.stream_items()
    }
    pub(super) fn semantic_output_observed(&self) -> bool {
        self.evidence.semantic_output_observed()
    }
    pub(super) fn take_quota(&mut self) -> Option<RateLimitSnapshot> {
        self.evidence.take_quota()
    }
    pub(super) fn text(&self) -> &str {
        self.evidence.text()
    }
    pub(super) fn thinking(&self) -> &str {
        self.evidence.thinking()
    }
    pub(super) fn timing(&self, started: Instant) -> StreamTiming {
        self.evidence.timing(started)
    }

    fn enter_awaiting_token(&mut self) {
        if let Some(span) = self.scope.connect.take() {
            span.complete();
        }
        if self.awaiting_token.is_none() {
            self.awaiting_token = Some(
                self.scope
                    .activity
                    .span(ActivityStage::AwaitingFirstToken, Some(self.scope.turn)),
            );
        }
    }
    fn timing_payload(&self) -> LifecyclePayload {
        LifecyclePayload {
            duration_us: Some(
                u64::try_from(self.scope.started.elapsed().as_micros()).unwrap_or(u64::MAX),
            ),
            ..LifecyclePayload::default()
        }
    }
    fn emit(&self, event_id: &str, payload: LifecyclePayload) {
        if let Some(emitter) = &self.scope.lifecycle
            && let Ok(event) = emitter.emit(event_id, self.scope.correlation.clone(), payload)
            && let Some(dispatcher) = &self.scope.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }
    fn present(&self, event: UiEvent) {
        let _ = self.scope.frontend.try_send_frontend(
            self.scope.resident_ui.as_ref(),
            self.scope.ui.as_ref(),
            event,
        );
    }
}

//! Prepared semantic request evidence published only after actual context and control gates.
//! Exact native serialized capture remains the separate provider manifest owner.
use super::context_preparation_events::ContextPreparationEvents;
use super::request_context_evidence::{
    ContextRequestObservation, RequestContextEvidenceOwner, RequestContextScope,
};
use iteron_ctx::ContextLedgerStore;
use iteron_protocol::{LifecyclePayload, TurnId};
const CONTEXT_HIGH_WATERMARK_DIVISOR: u64 = 10;

pub(super) struct RequestContextPublication<'a> {
    pub(super) sources: &'a RequestContextEvidenceOwner,
    pub(super) scope: RequestContextScope<'a>,
    pub(super) ledgers: ContextLedgerStore,
    pub(super) events: ContextPreparationEvents,
}
impl RequestContextPublication<'_> {
    pub(super) fn events(&self) -> &ContextPreparationEvents {
        &self.events
    }
    pub(super) fn publish(&self, turn: TurnId, observation: ContextRequestObservation<'_>) {
        let estimate = observation.estimate;
        let output_reserved_tokens = observation.output_reserved_tokens;
        let elapsed_us = observation.elapsed_us;
        let messages = observation.messages;
        let tools = observation.tools;
        let execution_window = self.scope.execution_window;
        let request = self.sources.build_request(
            turn,
            super::request_context_evidence::RequestContextScope {
                execution_window,
                request_trust: self.scope.request_trust,
                estimator: self.scope.estimator,
                file: self.scope.file,
                image: self.scope.image,
            },
            observation,
        );
        let ledger = request.ledger;
        for (event_id, payload) in request.observations {
            self.events.emit(turn, event_id, payload);
        }
        let segment_count = u64::try_from(ledger.segments.len()).unwrap_or(u64::MAX);
        let stable_prefix_tokens = ledger.cache.stable_prefix_tokens;
        let headroom = ledger.headroom_tokens();
        self.ledgers.publish(ledger);
        for event_id in ["context.segment.created", "context.segment.ordered"] {
            self.events.emit(
                turn,
                event_id,
                LifecyclePayload {
                    count: Some(segment_count),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.events.emit(
            turn,
            "context.segment.budget_granted",
            LifecyclePayload {
                magnitude: Some(u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        if let Some(window) = execution_window {
            self.events.emit(
                turn,
                "context.window.capacity_resolved",
                LifecyclePayload {
                    magnitude: Some(window),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.events.emit(
            turn,
            "context.window.output_reserved",
            LifecyclePayload {
                magnitude: Some(u64::from(output_reserved_tokens)),
                ..LifecyclePayload::default()
            },
        );
        if let Some(headroom) = headroom {
            self.events.emit(
                turn,
                "context.window.headroom_updated",
                LifecyclePayload {
                    magnitude: Some(headroom),
                    ..LifecyclePayload::default()
                },
            );
            if execution_window.is_some_and(|window| {
                headroom.saturating_mul(iteron_tunables::param_integer(
                    "cli.runtime.decision_observability.context_high_watermark_divisor",
                    CONTEXT_HIGH_WATERMARK_DIVISOR,
                )) < window
            }) {
                self.events.emit(
                    turn,
                    "context.window.high_watermark",
                    LifecyclePayload {
                        magnitude: Some(headroom),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
        self.events.emit(
            turn,
            "context.tool_schema.admitted",
            LifecyclePayload {
                count: Some(u64::try_from(tools.len()).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.events.emit(
            turn,
            "context.stable_prefix.computed",
            LifecyclePayload {
                magnitude: Some(stable_prefix_tokens),
                ..LifecyclePayload::default()
            },
        );
        self.events.emit(
            turn,
            "context.cache_region.classified",
            LifecyclePayload {
                magnitude: Some(stable_prefix_tokens),
                reason_code: Some("cache_candidate".into()),
                ..LifecyclePayload::default()
            },
        );
        self.events.emit(
            turn,
            "context.request.serialized",
            LifecyclePayload {
                count: Some(u64::try_from(messages.len()).unwrap_or(u64::MAX)),
                duration_us: Some(elapsed_us),
                magnitude: Some(u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
    }
}

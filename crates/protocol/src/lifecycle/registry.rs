use crate::lifecycle::{
    CardinalityClass, DurabilityClass, ExportPolicy, HookCapability, LifecycleAvailability,
    LifecycleDomain, LifecycleEventId, LifecycleEventSpec, LifecyclePhase, LifecycleReservation,
    PrivacyClass,
};

pub const EVENT_COUNT: usize = 192;

/// Stable lifecycle/Hook identifiers. Order is catalog order and must only grow by a versioned
/// migration; runtime sequence is carried by the envelope's `ordinal`, never by this index.
pub const EVENTS: [&str; EVENT_COUNT] = [
    "context.assembly.started",
    "context.source.discovered",
    "context.source.classified",
    "context.source.rejected",
    "context.source.selected",
    "context.source.deduplicated",
    "context.source.truncated",
    "context.source.serialized",
    "context.segment.created",
    "context.segment.updated",
    "context.segment.removed",
    "context.segment.ordered",
    "context.segment.budget_requested",
    "context.segment.budget_granted",
    "context.segment.budget_denied",
    "context.tokenizer.estimate_started",
    "context.tokenizer.estimate_completed",
    "context.tokenizer.actual_observed",
    "context.tokenizer.error_calculated",
    "context.window.capacity_resolved",
    "context.window.output_reserved",
    "context.window.headroom_updated",
    "context.window.high_watermark",
    "context.window.overflow_predicted",
    "context.tool_catalog.discovered",
    "context.tool_catalog.filtered",
    "context.tool_catalog.lazy_route",
    "context.tool_schema.admitted",
    "context.tool_schema.rejected",
    "context.stable_prefix.computed",
    "context.cache_region.classified",
    "context.request.serialized",
    "context.request.submitted",
    "context.request.usage_reconciled",
    "context.compaction.considered",
    "context.compaction.started",
    "context.compaction.completed",
    "context.compaction.failed",
    "context.obligation.preserved",
    "context.obligation.lost",
    "memory.query.created",
    "memory.query.rewritten",
    "memory.scope.resolved",
    "memory.store.opened",
    "memory.store.scanned",
    "memory.store.failed",
    "memory.candidate.discovered",
    "memory.candidate.scored",
    "memory.candidate.ranked",
    "memory.candidate.filtered",
    "memory.candidate.deduplicated",
    "memory.candidate.contradiction",
    "memory.candidate.superseded",
    "memory.candidate.expired",
    "memory.budget.requested",
    "memory.budget.granted",
    "memory.budget.denied",
    "memory.recall.selected",
    "memory.recall.rejected",
    "memory.recall.serialized",
    "memory.recall.injected",
    "memory.recall.used",
    "memory.recall.unused",
    "memory.fact.add_requested",
    "memory.fact.added",
    "memory.fact.add_failed",
    "memory.fact.update_requested",
    "memory.fact.updated",
    "memory.fact.delete_requested",
    "memory.fact.deleted",
    "memory.fact.superseded",
    "memory.visibility.scheduled",
    "memory.visibility.activated",
    "memory.contamination.check_started",
    "memory.contamination.check_passed",
    "memory.contamination.check_failed",
    "memory.benchmark.scope_created",
    "memory.benchmark.scope_destroyed",
    "memory.attribution.recorded",
    "memory.policy.decision",
    "submission.created",
    "submission.enqueued",
    "submission.received",
    "submission.admitted",
    "submission.applied",
    "submission.requeued",
    "submission.rejected",
    "submission.deduplicated",
    "submission.expired",
    "queue.capacity_resolved",
    "queue.overflow",
    "queue.depth_changed",
    "steer.requested",
    "steer.admitted",
    "steer.rejected",
    "cancel.requested",
    "cancel.received",
    "cancel.cooperative",
    "cancel.forced",
    "cancel.completed",
    "cancel.failed",
    "drain.requested",
    "drain.settled",
    "control.stale_rejected",
    "tool.call_proposed",
    "tool.policy_evaluated",
    "tool.call_admitted",
    "tool.call_started",
    "tool.output_chunk",
    "tool.call_completed",
    "tool.call_failed",
    "tool.call_unknown",
    "tool.call_cancelled",
    "process.spawn_requested",
    "process.spawned",
    "process.term_sent",
    "process.kill_sent",
    "process.reaped",
    "process.reap_failed",
    "background.detached",
    "background.attached",
    "background.input_written",
    "background.stopped",
    "background.orphan_detected",
    "model.route_requested",
    "model.route_selected",
    "model.route_rejected",
    "model.request_prepared",
    "model.request_sent",
    "model.first_byte",
    "model.first_token",
    "model.stream_item",
    "model.stream_completed",
    "model.request_failed",
    "model.retry_scheduled",
    "model.retry_cancelled",
    "model.usage_reported",
    "model.usage_reconciled",
    "model.rate_limit_observed",
    "model.quota_updated",
    "workflow.planning_started",
    "workflow.planning_delta",
    "workflow.planning_completed",
    "workflow.planning_failed",
    "workflow.run_started",
    "workflow.phase_started",
    "workflow.phase_completed",
    "workflow.child_proposed",
    "workflow.child_started",
    "workflow.child_progress",
    "workflow.child_completed",
    "workflow.child_failed",
    "workflow.reduction_started",
    "workflow.reduction_completed",
    "workflow.run_cancelled",
    "workflow.run_completed",
    "session.created",
    "session.title_selected",
    "session.started",
    "session.resumed",
    "session.configured",
    "session.profile_bound",
    "session.record_opened",
    "session.idle",
    "session.stopping",
    "session.stopped",
    "session.failed",
    "session.deleted",
    "verification.planned",
    "verification.check_started",
    "verification.check_completed",
    "verification.check_failed",
    "verification.repair_started",
    "verification.repair_completed",
    "verification.repair_exhausted",
    "checkpoint.requested",
    "checkpoint.created",
    "checkpoint.failed",
    "replay.started",
    "replay.completed",
    "hook.registered",
    "hook.matched",
    "hook.started",
    "hook.completed",
    "hook.blocked",
    "hook.failed",
    "hook.timed_out",
    "hook.circuit_opened",
    "exporter.started",
    "exporter.batch_flushed",
    "exporter.batch_dropped",
    "exporter.failed",
];

/// Vocabulary retained for compatibility whose producing capability is not implemented. Keeping
/// this list explicit prevents catalog size from being misreported as production trigger coverage.
pub const RESERVED_EVENTS: [&str; 0] = [];

const GATE_EVENTS: [&str; 12] = [
    "submission.created",
    "steer.requested",
    "context.source.discovered",
    "context.segment.budget_requested",
    "context.compaction.considered",
    "memory.query.created",
    "memory.budget.requested",
    "memory.fact.add_requested",
    "memory.fact.update_requested",
    "memory.fact.delete_requested",
    "tool.call_proposed",
    "workflow.child_proposed",
];

const AUGMENT_EVENTS: [&str; 20] = [
    "context.assembly.started",
    "context.source.classified",
    "context.segment.created",
    "context.tokenizer.estimate_started",
    "context.window.capacity_resolved",
    "context.tool_catalog.discovered",
    "context.stable_prefix.computed",
    "context.compaction.started",
    "memory.scope.resolved",
    "memory.store.opened",
    "memory.candidate.discovered",
    "memory.candidate.scored",
    "memory.recall.serialized",
    "memory.visibility.scheduled",
    "model.route_requested",
    "model.request_prepared",
    "workflow.planning_started",
    "verification.planned",
    "session.created",
    "session.title_selected",
];

pub fn is_registered(id: &str) -> bool {
    EVENTS.binary_search(&id).is_ok() || EVENTS.contains(&id)
}

pub fn registered_event_id(id: &str) -> Option<LifecycleEventId> {
    is_registered(id).then(|| LifecycleEventId::new(id).expect("catalog ids are valid"))
}

pub fn events() -> impl ExactSizeIterator<Item = LifecycleEventSpec> {
    EVENTS.into_iter().map(spec_for_registered)
}

pub fn event_spec(id: &str) -> Option<LifecycleEventSpec> {
    is_registered(id).then(|| {
        spec_for_registered(
            EVENTS
                .iter()
                .copied()
                .find(|row| *row == id)
                .expect("registered id exists"),
        )
    })
}

fn spec_for_registered(id: &'static str) -> LifecycleEventSpec {
    let high_frequency = id.ends_with(".planning_delta")
        || id.ends_with(".output_chunk")
        || id.ends_with(".stream_item")
        || id.ends_with(".child_progress")
        || id.ends_with(".depth_changed");
    LifecycleEventSpec {
        id,
        schema_version: 1,
        domain: domain(id),
        phase: phase(id),
        durability: if high_frequency {
            DurabilityClass::FlightRecorderOnly
        } else if is_terminal_or_decision(id) {
            DurabilityClass::Required
        } else {
            DurabilityClass::Summary
        },
        hook_capability: if GATE_EVENTS.contains(&id) {
            HookCapability::Gate
        } else if AUGMENT_EVENTS.contains(&id) {
            HookCapability::Augment
        } else {
            HookCapability::Observe
        },
        privacy: PrivacyClass::ContentFree,
        cardinality: CardinalityClass::TraceOnly,
        default_export: if high_frequency {
            ExportPolicy::Sampled
        } else if id.ends_with(".failed") || id.ends_with(".lost") || id.ends_with(".overflow") {
            ExportPolicy::Always
        } else {
            ExportPolicy::ErrorsAndBenchmarks
        },
        availability: availability(id),
    }
}

fn availability(id: &str) -> LifecycleAvailability {
    if !RESERVED_EVENTS.contains(&id) {
        return LifecycleAvailability::Active;
    }
    let reservation = if id.starts_with("context.") {
        LifecycleReservation::ContextCapability
    } else if id.starts_with("memory.benchmark.") {
        LifecycleReservation::EvaluationCapability
    } else if id.starts_with("memory.") {
        LifecycleReservation::MemoryCapability
    } else if id.starts_with("model.retry") {
        LifecycleReservation::ProviderRetryCapability
    } else {
        LifecycleReservation::SessionFailureCapability
    };
    LifecycleAvailability::Reserved(reservation)
}

fn domain(id: &str) -> LifecycleDomain {
    match id
        .split('.')
        .next()
        .expect("registered ids contain a domain")
    {
        "context" => LifecycleDomain::Context,
        "memory" => LifecycleDomain::Memory,
        "submission" | "queue" | "steer" | "cancel" | "drain" | "control" => {
            LifecycleDomain::Control
        }
        "tool" | "process" | "background" => LifecycleDomain::ToolProcess,
        "model" => LifecycleDomain::ModelProvider,
        "workflow" => LifecycleDomain::Workflow,
        "session" => LifecycleDomain::Session,
        "verification" | "checkpoint" | "replay" => LifecycleDomain::Verification,
        "hook" | "exporter" => LifecycleDomain::HookExporter,
        _ => unreachable!("catalog domains are exhaustive"),
    }
}

fn phase(id: &str) -> LifecyclePhase {
    if id.ends_with("requested") || id.ends_with("proposed") || id.ends_with("considered") {
        LifecyclePhase::Requested
    } else if id.ends_with("started") || id.ends_with("created") || id.ends_with("opened") {
        LifecyclePhase::Started
    } else if is_terminal_or_decision(id) {
        LifecyclePhase::Terminal
    } else if id.ends_with("selected")
        || id.ends_with("admitted")
        || id.ends_with("granted")
        || id.ends_with("denied")
        || id.ends_with("decision")
        || id.ends_with("evaluated")
    {
        LifecyclePhase::Decision
    } else {
        LifecyclePhase::Progress
    }
}

fn is_terminal_or_decision(id: &str) -> bool {
    [
        ".completed",
        ".failed",
        ".cancelled",
        ".rejected",
        ".applied",
        ".requeued",
        ".deduplicated",
        ".expired",
        ".forced",
        ".settled",
        ".unknown",
        ".reaped",
        ".stopped",
        ".deleted",
        ".added",
        ".updated",
        ".passed",
        ".lost",
        ".blocked",
        ".timed_out",
        ".batch_dropped",
        ".batch_flushed",
    ]
    .iter()
    .any(|suffix| id.ends_with(suffix))
}

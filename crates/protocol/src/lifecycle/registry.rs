use crate::lifecycle::{
    CardinalityClass, DurabilityClass, ExportPolicy, HookCapability, LifecycleAvailability,
    LifecycleDomain, LifecycleEventId, LifecycleEventSpec, LifecyclePhase, LifecycleReservation,
    PrivacyClass,
};

pub const EVENT_COUNT: usize = 195;

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
    "model.route_failed",
    "model.request_prepared",
    "model.request_sent",
    "model.accepted",
    "model.first_byte",
    "model.first_token",
    "model.stream_item",
    "model.stream_completed",
    "model.compatibility_notice",
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
pub const RESERVED_EVENTS: [&str; 2] = ["replay.started", "replay.completed"];

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

/// O(1) closed-catalog lookup. A large string match compiles to rustc's length-bucketed
/// decision tree and keeps `EVENTS` in its human-reviewed migration order. Returning the compact
/// index also lets a validated `LifecycleEventId` cache four bytes rather than a full spec.
pub(crate) fn event_index(id: &str) -> Option<u16> {
    match id {
        "context.assembly.started" => Some(0),
        "context.source.discovered" => Some(1),
        "context.source.classified" => Some(2),
        "context.source.rejected" => Some(3),
        "context.source.selected" => Some(4),
        "context.source.deduplicated" => Some(5),
        "context.source.truncated" => Some(6),
        "context.source.serialized" => Some(7),
        "context.segment.created" => Some(8),
        "context.segment.updated" => Some(9),
        "context.segment.removed" => Some(10),
        "context.segment.ordered" => Some(11),
        "context.segment.budget_requested" => Some(12),
        "context.segment.budget_granted" => Some(13),
        "context.segment.budget_denied" => Some(14),
        "context.tokenizer.estimate_started" => Some(15),
        "context.tokenizer.estimate_completed" => Some(16),
        "context.tokenizer.actual_observed" => Some(17),
        "context.tokenizer.error_calculated" => Some(18),
        "context.window.capacity_resolved" => Some(19),
        "context.window.output_reserved" => Some(20),
        "context.window.headroom_updated" => Some(21),
        "context.window.high_watermark" => Some(22),
        "context.window.overflow_predicted" => Some(23),
        "context.tool_catalog.discovered" => Some(24),
        "context.tool_catalog.filtered" => Some(25),
        "context.tool_catalog.lazy_route" => Some(26),
        "context.tool_schema.admitted" => Some(27),
        "context.tool_schema.rejected" => Some(28),
        "context.stable_prefix.computed" => Some(29),
        "context.cache_region.classified" => Some(30),
        "context.request.serialized" => Some(31),
        "context.request.submitted" => Some(32),
        "context.request.usage_reconciled" => Some(33),
        "context.compaction.considered" => Some(34),
        "context.compaction.started" => Some(35),
        "context.compaction.completed" => Some(36),
        "context.compaction.failed" => Some(37),
        "context.obligation.preserved" => Some(38),
        "context.obligation.lost" => Some(39),
        "memory.query.created" => Some(40),
        "memory.query.rewritten" => Some(41),
        "memory.scope.resolved" => Some(42),
        "memory.store.opened" => Some(43),
        "memory.store.scanned" => Some(44),
        "memory.store.failed" => Some(45),
        "memory.candidate.discovered" => Some(46),
        "memory.candidate.scored" => Some(47),
        "memory.candidate.ranked" => Some(48),
        "memory.candidate.filtered" => Some(49),
        "memory.candidate.deduplicated" => Some(50),
        "memory.candidate.contradiction" => Some(51),
        "memory.candidate.superseded" => Some(52),
        "memory.candidate.expired" => Some(53),
        "memory.budget.requested" => Some(54),
        "memory.budget.granted" => Some(55),
        "memory.budget.denied" => Some(56),
        "memory.recall.selected" => Some(57),
        "memory.recall.rejected" => Some(58),
        "memory.recall.serialized" => Some(59),
        "memory.recall.injected" => Some(60),
        "memory.recall.used" => Some(61),
        "memory.recall.unused" => Some(62),
        "memory.fact.add_requested" => Some(63),
        "memory.fact.added" => Some(64),
        "memory.fact.add_failed" => Some(65),
        "memory.fact.update_requested" => Some(66),
        "memory.fact.updated" => Some(67),
        "memory.fact.delete_requested" => Some(68),
        "memory.fact.deleted" => Some(69),
        "memory.fact.superseded" => Some(70),
        "memory.visibility.scheduled" => Some(71),
        "memory.visibility.activated" => Some(72),
        "memory.contamination.check_started" => Some(73),
        "memory.contamination.check_passed" => Some(74),
        "memory.contamination.check_failed" => Some(75),
        "memory.benchmark.scope_created" => Some(76),
        "memory.benchmark.scope_destroyed" => Some(77),
        "memory.attribution.recorded" => Some(78),
        "memory.policy.decision" => Some(79),
        "submission.created" => Some(80),
        "submission.enqueued" => Some(81),
        "submission.received" => Some(82),
        "submission.admitted" => Some(83),
        "submission.applied" => Some(84),
        "submission.requeued" => Some(85),
        "submission.rejected" => Some(86),
        "submission.deduplicated" => Some(87),
        "submission.expired" => Some(88),
        "queue.capacity_resolved" => Some(89),
        "queue.overflow" => Some(90),
        "queue.depth_changed" => Some(91),
        "steer.requested" => Some(92),
        "steer.admitted" => Some(93),
        "steer.rejected" => Some(94),
        "cancel.requested" => Some(95),
        "cancel.received" => Some(96),
        "cancel.cooperative" => Some(97),
        "cancel.forced" => Some(98),
        "cancel.completed" => Some(99),
        "cancel.failed" => Some(100),
        "drain.requested" => Some(101),
        "drain.settled" => Some(102),
        "control.stale_rejected" => Some(103),
        "tool.call_proposed" => Some(104),
        "tool.policy_evaluated" => Some(105),
        "tool.call_admitted" => Some(106),
        "tool.call_started" => Some(107),
        "tool.output_chunk" => Some(108),
        "tool.call_completed" => Some(109),
        "tool.call_failed" => Some(110),
        "tool.call_unknown" => Some(111),
        "tool.call_cancelled" => Some(112),
        "process.spawn_requested" => Some(113),
        "process.spawned" => Some(114),
        "process.term_sent" => Some(115),
        "process.kill_sent" => Some(116),
        "process.reaped" => Some(117),
        "process.reap_failed" => Some(118),
        "background.detached" => Some(119),
        "background.attached" => Some(120),
        "background.input_written" => Some(121),
        "background.stopped" => Some(122),
        "background.orphan_detected" => Some(123),
        "model.route_requested" => Some(124),
        "model.route_selected" => Some(125),
        "model.route_rejected" => Some(126),
        "model.route_failed" => Some(127),
        "model.request_prepared" => Some(128),
        "model.request_sent" => Some(129),
        "model.accepted" => Some(130),
        "model.first_byte" => Some(131),
        "model.first_token" => Some(132),
        "model.stream_item" => Some(133),
        "model.stream_completed" => Some(134),
        "model.compatibility_notice" => Some(135),
        "model.request_failed" => Some(136),
        "model.retry_scheduled" => Some(137),
        "model.retry_cancelled" => Some(138),
        "model.usage_reported" => Some(139),
        "model.usage_reconciled" => Some(140),
        "model.rate_limit_observed" => Some(141),
        "model.quota_updated" => Some(142),
        "workflow.planning_started" => Some(143),
        "workflow.planning_delta" => Some(144),
        "workflow.planning_completed" => Some(145),
        "workflow.planning_failed" => Some(146),
        "workflow.run_started" => Some(147),
        "workflow.phase_started" => Some(148),
        "workflow.phase_completed" => Some(149),
        "workflow.child_proposed" => Some(150),
        "workflow.child_started" => Some(151),
        "workflow.child_progress" => Some(152),
        "workflow.child_completed" => Some(153),
        "workflow.child_failed" => Some(154),
        "workflow.reduction_started" => Some(155),
        "workflow.reduction_completed" => Some(156),
        "workflow.run_cancelled" => Some(157),
        "workflow.run_completed" => Some(158),
        "session.created" => Some(159),
        "session.title_selected" => Some(160),
        "session.started" => Some(161),
        "session.resumed" => Some(162),
        "session.configured" => Some(163),
        "session.profile_bound" => Some(164),
        "session.record_opened" => Some(165),
        "session.idle" => Some(166),
        "session.stopping" => Some(167),
        "session.stopped" => Some(168),
        "session.failed" => Some(169),
        "session.deleted" => Some(170),
        "verification.planned" => Some(171),
        "verification.check_started" => Some(172),
        "verification.check_completed" => Some(173),
        "verification.check_failed" => Some(174),
        "verification.repair_started" => Some(175),
        "verification.repair_completed" => Some(176),
        "verification.repair_exhausted" => Some(177),
        "checkpoint.requested" => Some(178),
        "checkpoint.created" => Some(179),
        "checkpoint.failed" => Some(180),
        "replay.started" => Some(181),
        "replay.completed" => Some(182),
        "hook.registered" => Some(183),
        "hook.matched" => Some(184),
        "hook.started" => Some(185),
        "hook.completed" => Some(186),
        "hook.blocked" => Some(187),
        "hook.failed" => Some(188),
        "hook.timed_out" => Some(189),
        "hook.circuit_opened" => Some(190),
        "exporter.started" => Some(191),
        "exporter.batch_flushed" => Some(192),
        "exporter.batch_dropped" => Some(193),
        "exporter.failed" => Some(194),
        _ => None,
    }
}

pub fn is_registered(id: &str) -> bool {
    event_index(id).is_some()
}

pub fn registered_event_id(id: &str) -> Option<LifecycleEventId> {
    is_registered(id).then(|| LifecycleEventId::new(id).expect("catalog ids are valid"))
}

pub fn events() -> impl ExactSizeIterator<Item = LifecycleEventSpec> {
    EVENTS.into_iter().map(spec_for_registered)
}

pub fn event_spec(id: &str) -> Option<LifecycleEventSpec> {
    event_index(id).map(event_spec_by_index)
}

pub(crate) fn event_spec_by_index(index: u16) -> LifecycleEventSpec {
    spec_for_registered(EVENTS[usize::from(index)])
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
    } else if id.starts_with("replay.") {
        LifecycleReservation::ReplayCapability
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

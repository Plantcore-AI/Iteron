//! Bounded live projection of canonical lifecycle events into OTel-shaped logs, metrics and spans.
//!
//! The projector runs behind a bounded lifecycle subscriber. It never executes on the agent turn
//! and never exports content; correlation identities are trace/log attributes only, never metric
//! labels.

use super::catalog::{self, InstrumentKind};
use iteron_protocol::{LifecycleEventEnvelope, LifecyclePhase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

pub const MAX_LIVE_LOGS: usize = 4096;
pub const MAX_LIVE_SPANS: usize = 4096;
pub const MAX_OPEN_SPANS: usize = 1024;
const SUBSCRIBER_CAPACITY: usize = 2048;
/// Bounds how long the projection worker blocks on an idle channel before rechecking that the
/// `Weak` handle is still alive, so a dropped projection retires the thread within that window
/// instead of waiting for the next event that may never arrive.
const PROJECT_LOOP_IDLE_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleLogRecord {
    pub schema: String,
    pub schema_version: u16,
    pub ordinal: u64,
    pub occurred_at_mono_ns: u64,
    pub traceparent: String,
    pub outcome_code: Option<String>,
    pub reason_code: Option<String>,
    pub count: Option<u64>,
    pub duration_us: Option<u64>,
    pub magnitude: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleMetricValue {
    pub name: String,
    pub kind: String,
    pub unit: String,
    /// Counter value, histogram sum, or latest gauge observation.
    pub value: u64,
    #[serde(default)]
    pub observations: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSpanRecord {
    pub template: String,
    pub traceparent: String,
    pub start_mono_ns: u64,
    pub end_mono_ns: u64,
    pub duration_us: u64,
    pub outcome_code: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTelemetrySnapshot {
    pub logs: Vec<LifecycleLogRecord>,
    pub metrics: Vec<LifecycleMetricValue>,
    pub spans: Vec<LifecycleSpanRecord>,
    pub open_spans: usize,
    pub dropped_logs: u64,
    pub dropped_spans: u64,
    pub dropped_open_spans: u64,
}

#[derive(Debug)]
struct OpenSpan {
    template: &'static str,
    traceparent: String,
    started_at: u64,
    session_id: Option<String>,
    run_id: Option<String>,
    turn_id: Option<u64>,
}

#[derive(Debug)]
struct Projection {
    logs: VecDeque<LifecycleLogRecord>,
    metrics: BTreeMap<String, LifecycleMetricValue>,
    spans: VecDeque<LifecycleSpanRecord>,
    open: HashMap<String, OpenSpan>,
    dropped_logs: u64,
    dropped_spans: u64,
    dropped_open_spans: u64,
}

impl Default for Projection {
    fn default() -> Self {
        let metrics = catalog::metric_instruments()
            .into_iter()
            .map(|spec| {
                let kind = match spec.kind {
                    InstrumentKind::Counter => "counter",
                    InstrumentKind::Histogram => "histogram",
                    InstrumentKind::Gauge => "gauge",
                };
                (
                    spec.name.clone(),
                    LifecycleMetricValue {
                        name: spec.name,
                        kind: kind.into(),
                        unit: spec.unit.into(),
                        value: 0,
                        observations: 0,
                        min: None,
                        max: None,
                    },
                )
            })
            .collect();
        Self {
            logs: VecDeque::with_capacity(MAX_LIVE_LOGS),
            metrics,
            spans: VecDeque::with_capacity(MAX_LIVE_SPANS),
            open: HashMap::new(),
            dropped_logs: 0,
            dropped_spans: 0,
            dropped_open_spans: 0,
        }
    }
}

/// Handle to a local live OTel projection. The worker holds only a `Weak`, so dropping the last
/// handle closes it without a leaked thread; bus backpressure and loss accounting remain separate.
#[derive(Debug, Clone)]
pub struct LifecycleTelemetryRuntime {
    projection: Arc<Mutex<Projection>>,
}

impl LifecycleTelemetryRuntime {
    pub fn attach(bus: &crate::lifecycle::LifecycleBus) -> Result<Self, &'static str> {
        let receiver = bus.subscribe(SUBSCRIBER_CAPACITY)?;
        let projection = Arc::new(Mutex::new(Projection::default()));
        let weak = Arc::downgrade(&projection);
        std::thread::Builder::new()
            .name("core-lifecycle-otel".into())
            .spawn(move || project_loop(weak, receiver))
            .map_err(|_| "could not start lifecycle telemetry projector")?;
        Ok(Self { projection })
    }

    pub fn snapshot(&self) -> LifecycleTelemetrySnapshot {
        let state = self
            .projection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        LifecycleTelemetrySnapshot {
            logs: state.logs.iter().cloned().collect(),
            metrics: state.metrics.values().cloned().collect(),
            spans: state.spans.iter().cloned().collect(),
            open_spans: state.open.len(),
            dropped_logs: state.dropped_logs,
            dropped_spans: state.dropped_spans,
            dropped_open_spans: state.dropped_open_spans,
        }
    }
}

fn project_loop(
    projection: Weak<Mutex<Projection>>,
    receiver: std::sync::mpsc::Receiver<LifecycleEventEnvelope>,
) {
    loop {
        let Some(projection) = projection.upgrade() else {
            return;
        };
        match receiver.recv_timeout(PROJECT_LOOP_IDLE_POLL) {
            Ok(event) => {
                let mut state = projection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.record(event);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl Projection {
    fn record(&mut self, event: LifecycleEventEnvelope) {
        let traceparent = traceparent(&event);
        if self.logs.len() == MAX_LIVE_LOGS {
            self.logs.pop_front();
            self.dropped_logs = self.dropped_logs.saturating_add(1);
        }
        self.logs.push_back(LifecycleLogRecord {
            schema: event.event_id.as_str().into(),
            schema_version: event.event_version,
            ordinal: event.ordinal,
            occurred_at_mono_ns: event.occurred_at_mono_ns,
            traceparent: traceparent.clone(),
            outcome_code: event.payload.outcome_code.clone(),
            reason_code: event.payload.reason_code.clone(),
            count: event.payload.count,
            duration_us: event.payload.duration_us,
            magnitude: event.payload.magnitude,
        });
        self.record_metrics(&event);
        self.record_span(&event, traceparent);
    }

    fn record_metrics(&mut self, event: &LifecycleEventEnvelope) {
        let id = event.event_id.as_str();
        for family in metric_families(
            id,
            event.payload.reason_code.as_deref(),
            event.effect_id.is_some(),
        )
        .into_iter()
        .flatten()
        {
            add_metric(&mut self.metrics, &format!("{family}.calls"), 1);
            if is_failure(event) {
                add_metric(&mut self.metrics, &format!("{family}.failures"), 1);
            }
            if let Some(duration_us) = event.payload.duration_us {
                add_metric(
                    &mut self.metrics,
                    &format!("{family}.duration_ms"),
                    duration_us.saturating_add(999) / 1000,
                );
            }
            let magnitude = event.payload.magnitude.or(event.payload.count).unwrap_or(0);
            if magnitude > 0
                && let Some(name) = self
                    .metrics
                    .keys()
                    .find(|name| {
                        name.starts_with(family)
                            && !name.ends_with(".calls")
                            && !name.ends_with(".failures")
                            && !name.ends_with(".duration_ms")
                    })
                    .cloned()
            {
                add_metric(&mut self.metrics, &name, magnitude);
            }
        }
    }

    fn record_span(&mut self, event: &LifecycleEventEnvelope, traceparent: String) {
        if matches!(
            event.event_id.as_str(),
            "session.idle" | "session.stopped" | "session.failed"
        ) {
            self.flush_open_spans(event);
            return;
        }
        let Some(template) = span_template(
            event.event_id.as_str(),
            event.payload.reason_code.as_deref(),
        ) else {
            return;
        };
        let key = span_key(template, event);
        let phase = iteron_protocol::lifecycle::event_spec(event.event_id.as_str())
            .map(|spec| spec.phase)
            .unwrap_or(LifecyclePhase::Progress);
        if matches!(phase, LifecyclePhase::Requested | LifecyclePhase::Started) {
            if self.open.len() == MAX_OPEN_SPANS && !self.open.contains_key(&key) {
                self.dropped_open_spans = self.dropped_open_spans.saturating_add(1);
                return;
            }
            self.open.entry(key).or_insert(OpenSpan {
                template,
                traceparent,
                started_at: event.occurred_at_mono_ns,
                session_id: event.session_id.as_ref().map(|id| id.0.clone()),
                run_id: event.run_id.as_ref().map(|id| id.0.clone()),
                turn_id: event.turn_id.map(|id| u64::from(id.0)),
            });
            return;
        }
        // Progress observations with an explicit duration are complete one-shot operations (for
        // example attachment classification). Progress without a duration remains an event only.
        if !matches!(phase, LifecyclePhase::Decision | LifecyclePhase::Terminal)
            && event.payload.duration_us.is_none()
        {
            return;
        }
        let opened = self.open.remove(&key);
        let duration_ns = opened
            .as_ref()
            .map(|open| event.occurred_at_mono_ns.saturating_sub(open.started_at))
            .or_else(|| {
                event
                    .payload
                    .duration_us
                    .map(|value| value.saturating_mul(1000))
            });
        let Some(duration_ns) = duration_ns else {
            return;
        };
        if self.spans.len() == MAX_LIVE_SPANS {
            self.spans.pop_front();
            self.dropped_spans = self.dropped_spans.saturating_add(1);
        }
        let start = opened
            .as_ref()
            .map(|open| open.started_at)
            .unwrap_or_else(|| event.occurred_at_mono_ns.saturating_sub(duration_ns));
        self.spans.push_back(LifecycleSpanRecord {
            template: opened
                .as_ref()
                .map(|open| open.template)
                .unwrap_or(template)
                .into(),
            traceparent: opened.map(|open| open.traceparent).unwrap_or(traceparent),
            start_mono_ns: start,
            end_mono_ns: event.occurred_at_mono_ns,
            duration_us: duration_ns.saturating_add(999) / 1000,
            outcome_code: event.payload.outcome_code.clone(),
        });
    }

    fn flush_open_spans(&mut self, event: &LifecycleEventEnvelope) {
        let session_id = event.session_id.as_ref().map(|id| id.0.as_str());
        let run_id = event.run_id.as_ref().map(|id| id.0.as_str());
        let turn_id = event.turn_id.map(|id| u64::from(id.0));
        let keys = self
            .open
            .iter()
            .filter(|(_, span)| {
                span.session_id.as_deref() == session_id
                    && span.run_id.as_deref() == run_id
                    && (turn_id.is_none() || span.turn_id == turn_id)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            let Some(open) = self.open.remove(&key) else {
                continue;
            };
            if self.spans.len() == MAX_LIVE_SPANS {
                self.spans.pop_front();
                self.dropped_spans = self.dropped_spans.saturating_add(1);
            }
            self.spans.push_back(LifecycleSpanRecord {
                template: open.template.into(),
                traceparent: open.traceparent,
                start_mono_ns: open.started_at,
                end_mono_ns: event.occurred_at_mono_ns,
                duration_us: event
                    .occurred_at_mono_ns
                    .saturating_sub(open.started_at)
                    .saturating_add(999)
                    / 1000,
                outcome_code: event.payload.outcome_code.clone(),
            });
        }
    }
}

fn add_metric(metrics: &mut BTreeMap<String, LifecycleMetricValue>, name: &str, value: u64) {
    if let Some(metric) = metrics.get_mut(name) {
        metric.observations = metric.observations.saturating_add(1);
        metric.min = Some(metric.min.map_or(value, |current| current.min(value)));
        metric.max = Some(metric.max.map_or(value, |current| current.max(value)));
        if metric.kind == "gauge" {
            metric.value = value;
        } else {
            metric.value = metric.value.saturating_add(value);
        }
    }
}

fn is_failure(event: &LifecycleEventEnvelope) -> bool {
    let id = event.event_id.as_str();
    id.ends_with(".failed")
        || id.ends_with(".rejected")
        || id.ends_with(".overflow")
        || id.ends_with(".lost")
        || event
            .payload
            .outcome_code
            .as_deref()
            .is_some_and(|outcome| {
                matches!(
                    outcome,
                    "error" | "failed" | "failure" | "rejected" | "blocked" | "timed_out"
                )
            })
}

fn metric_families(
    id: &str,
    reason_code: Option<&str>,
    has_effect: bool,
) -> [Option<&'static str>; 2] {
    let primary = if id == "context.cache_region.classified" {
        match reason_code {
            Some("cache_write") => "iteron.context.cache_write",
            Some("cache_miss") => "iteron.context.cache_miss",
            Some("cache_read") => "iteron.context.cache_read",
            _ => "iteron.context.stable_prefix",
        }
    } else {
        metric_family(id)
    };
    let secondary = if id == "context.source.classified"
        && matches!(reason_code, Some("file_attachment" | "image_attachment"))
    {
        Some("iteron.context.attachment")
    } else if has_effect && id.starts_with("tool.") && primary != "iteron.tool.effect" {
        Some("iteron.tool.effect")
    } else {
        None
    };
    [Some(primary), secondary]
}

fn metric_family(id: &str) -> &'static str {
    let (domain, family) = if id.starts_with("context.") {
        ("context", context_family(id))
    } else if id.starts_with("memory.") {
        ("memory", memory_family(id))
    } else if id.starts_with("model.") {
        (
            "model",
            keyword(
                id,
                &[
                    "route",
                    "request",
                    "stream",
                    "retry",
                    "usage",
                    "quota",
                    "rate_limit",
                ],
                "cache",
            ),
        )
    } else if id.starts_with("workflow.") {
        (
            "workflow",
            if id.ends_with("run_cancelled") {
                "cancellation"
            } else {
                keyword(id, &["planning", "phase", "child", "reduction"], "run")
            },
        )
    } else if id.starts_with("tool.") || id.starts_with("process.") || id.starts_with("background.")
    {
        ("tool", tool_family(id))
    } else if id.starts_with("verification.")
        || id.starts_with("checkpoint.")
        || id.starts_with("replay.")
    {
        (
            "verification",
            if id.starts_with("verification.") {
                "checks"
            } else {
                "checkpoint_replay"
            },
        )
    } else if id.starts_with("hook.") {
        ("runtime", "hooks")
    } else if id.starts_with("exporter.") {
        ("runtime", "exporter")
    } else {
        ("control", control_family(id))
    };
    catalog_family(domain, family)
}

fn catalog_family(domain: &str, family: &str) -> &'static str {
    // All returned strings are catalog members; spelling them as complete static prefixes keeps
    // the metric map incapable of accepting a high-cardinality runtime value.
    match (domain, family) {
        ("context", "assembly") => "iteron.context.assembly",
        ("context", "source_discovery") => "iteron.context.source_discovery",
        ("context", "source_selection") => "iteron.context.source_selection",
        ("context", "source_rejection") => "iteron.context.source_rejection",
        ("context", "deduplication") => "iteron.context.deduplication",
        ("context", "truncation") => "iteron.context.truncation",
        ("context", "segment") => "iteron.context.segment",
        ("context", "budget") => "iteron.context.budget",
        ("context", "token_estimate") => "iteron.context.token_estimate",
        ("context", "tokenizer_error") => "iteron.context.tokenizer_error",
        ("context", "window_usage") => "iteron.context.window_usage",
        ("context", "window_headroom") => "iteron.context.window_headroom",
        ("context", "output_reserve") => "iteron.context.output_reserve",
        ("context", "overflow_prediction") => "iteron.context.overflow_prediction",
        ("context", "stable_prefix") => "iteron.context.stable_prefix",
        ("context", "cache_read") => "iteron.context.cache_read",
        ("context", "cache_write") => "iteron.context.cache_write",
        ("context", "cache_miss") => "iteron.context.cache_miss",
        ("context", "tool_catalog") => "iteron.context.tool_catalog",
        ("context", "tool_schema") => "iteron.context.tool_schema",
        ("context", "request_serialization") => "iteron.context.request_serialization",
        ("context", "compaction") => "iteron.context.compaction",
        ("context", "obligation_preservation") => "iteron.context.obligation_preservation",
        ("context", "attachment") => "iteron.context.attachment",
        ("memory", "query") => "iteron.memory.query",
        ("memory", "query_rewrite") => "iteron.memory.query_rewrite",
        ("memory", "scope") => "iteron.memory.scope",
        ("memory", "store_scan") => "iteron.memory.store_scan",
        ("memory", "store_failure") => "iteron.memory.store_failure",
        ("memory", "candidate") => "iteron.memory.candidate",
        ("memory", "scoring") => "iteron.memory.scoring",
        ("memory", "ranking") => "iteron.memory.ranking",
        ("memory", "filtering") => "iteron.memory.filtering",
        ("memory", "deduplication") => "iteron.memory.deduplication",
        ("memory", "contradiction") => "iteron.memory.contradiction",
        ("memory", "supersession") => "iteron.memory.supersession",
        ("memory", "expiry") => "iteron.memory.expiry",
        ("memory", "budget") => "iteron.memory.budget",
        ("memory", "recall_selection") => "iteron.memory.recall_selection",
        ("memory", "recall_injection") => "iteron.memory.recall_injection",
        ("memory", "recall_use") => "iteron.memory.recall_use",
        ("memory", "fact_add") => "iteron.memory.fact_add",
        ("memory", "fact_update") => "iteron.memory.fact_update",
        ("memory", "fact_delete") => "iteron.memory.fact_delete",
        ("memory", "visibility") => "iteron.memory.visibility",
        ("memory", "contamination") => "iteron.memory.contamination",
        ("memory", "benchmark_scope") => "iteron.memory.benchmark_scope",
        ("memory", "policy") => "iteron.memory.policy",
        ("model", "route") => "iteron.model.route",
        ("model", "request") => "iteron.model.request",
        ("model", "stream") => "iteron.model.stream",
        ("model", "retry") => "iteron.model.retry",
        ("model", "usage") => "iteron.model.usage",
        ("model", "quota") => "iteron.model.quota",
        ("model", "rate_limit") => "iteron.model.rate_limit",
        ("workflow", "planning") => "iteron.workflow.planning",
        ("workflow", "phase") => "iteron.workflow.phase",
        ("workflow", "child") => "iteron.workflow.child",
        ("workflow", "reduction") => "iteron.workflow.reduction",
        ("workflow", "cancellation") => "iteron.workflow.cancellation",
        ("tool", "policy") => "iteron.tool.policy",
        ("tool", "tool_call") => "iteron.tool.tool_call",
        ("tool", "tool_output") => "iteron.tool.tool_output",
        ("tool", "process_spawn") => "iteron.tool.process_spawn",
        ("tool", "process_termination") => "iteron.tool.process_termination",
        ("tool", "process_reap") => "iteron.tool.process_reap",
        ("tool", "background_job") => "iteron.tool.background_job",
        ("verification", "checks") => "iteron.verification.checks",
        ("verification", "checkpoint_replay") => "iteron.verification.checkpoint_replay",
        ("runtime", "hooks") => "iteron.runtime.hooks",
        ("runtime", "exporter") => "iteron.runtime.exporter",
        ("control", "queue") => "iteron.control.queue",
        ("control", "steer") => "iteron.control.steer",
        ("control", "cancel") => "iteron.control.cancel",
        ("control", "drain") => "iteron.control.drain",
        ("control", "acknowledgement") => "iteron.control.acknowledgement",
        ("control", "submission") => "iteron.control.submission",
        _ if domain == "model" => "iteron.model.cache",
        _ if domain == "workflow" => "iteron.workflow.run",
        _ if domain == "tool" => "iteron.tool.effect",
        _ => "iteron.control.submission",
    }
}

fn context_family(id: &str) -> &'static str {
    if id.contains("source.discovered") {
        "source_discovery"
    } else if id.contains("source.rejected") {
        "source_rejection"
    } else if id.contains("source.deduplicated") {
        "deduplication"
    } else if id.contains("source.truncated") {
        "truncation"
    } else if id.contains("source.") {
        "source_selection"
    } else if id.contains("segment.budget") {
        "budget"
    } else if id.contains("segment.") {
        "segment"
    } else if id.contains("tokenizer.error") {
        "tokenizer_error"
    } else if id.contains("tokenizer") {
        "token_estimate"
    } else if id.contains("window.output") {
        "output_reserve"
    } else if id.contains("window.headroom") || id.contains("high_watermark") {
        "window_headroom"
    } else if id.contains("overflow") {
        "overflow_prediction"
    } else if id.contains("window") {
        "window_usage"
    } else if id.contains("tool_catalog") {
        "tool_catalog"
    } else if id.contains("tool_schema") {
        "tool_schema"
    } else if id.contains("stable_prefix") {
        "stable_prefix"
    } else if id.contains("cache_region") {
        "cache_read"
    } else if id.contains("request.") {
        "request_serialization"
    } else if id.contains("compaction") {
        "compaction"
    } else if id.contains("obligation") {
        "obligation_preservation"
    } else if id.contains("attachment") {
        "attachment"
    } else {
        "assembly"
    }
}

fn memory_family(id: &str) -> &'static str {
    if id.contains("query.rewritten") {
        "query_rewrite"
    } else if id.contains("query") {
        "query"
    } else if id.contains("benchmark.scope") {
        "benchmark_scope"
    } else if id.contains("scope") {
        "scope"
    } else if id.contains("store.failed") {
        "store_failure"
    } else if id.contains("store") {
        "store_scan"
    } else if id.contains("candidate.scored") {
        "scoring"
    } else if id.contains("candidate.ranked") {
        "ranking"
    } else if id.contains("candidate.filtered") {
        "filtering"
    } else if id.contains("candidate.deduplicated") {
        "deduplication"
    } else if id.contains("candidate.contradiction") {
        "contradiction"
    } else if id.contains("candidate.superseded") || id.contains("fact.superseded") {
        "supersession"
    } else if id.contains("candidate.expired") {
        "expiry"
    } else if id.contains("candidate") {
        "candidate"
    } else if id.contains("budget") {
        "budget"
    } else if id.contains("recall.inject") || id.contains("recall.serialized") {
        "recall_injection"
    } else if id.contains("recall.used") || id.contains("recall.unused") {
        "recall_use"
    } else if id.contains("recall") {
        "recall_selection"
    } else if id.contains("fact.add") {
        "fact_add"
    } else if id.contains("fact.update") {
        "fact_update"
    } else if id.contains("fact.delete") {
        "fact_delete"
    } else if id.contains("visibility") {
        "visibility"
    } else if id.contains("contamination") {
        "contamination"
    } else {
        "policy"
    }
}

fn control_family(id: &str) -> &'static str {
    if id.starts_with("queue.") {
        "queue"
    } else if id.starts_with("steer.") {
        "steer"
    } else if id.starts_with("cancel.") {
        "cancel"
    } else if id.starts_with("drain.") {
        "drain"
    } else if id.starts_with("session.") || id.starts_with("control.") {
        "acknowledgement"
    } else {
        "submission"
    }
}

fn tool_family(id: &str) -> &'static str {
    if id.starts_with("process.spawn") {
        "process_spawn"
    } else if id.starts_with("process.term") || id.starts_with("process.kill") {
        "process_termination"
    } else if id.starts_with("process.reap") {
        "process_reap"
    } else if id.starts_with("background.") {
        "background_job"
    } else if id.contains("policy") {
        "policy"
    } else if id.contains("output") {
        "tool_output"
    } else {
        "tool_call"
    }
}

fn keyword<'a>(id: &str, choices: &'a [&'a str], fallback: &'a str) -> &'a str {
    choices
        .iter()
        .copied()
        .find(|choice| id.contains(choice))
        .unwrap_or(fallback)
}

fn span_template(id: &str, reason_code: Option<&str>) -> Option<&'static str> {
    let prefix = id.split('.').next()?;
    let wanted = match prefix {
        "context"
            if id == "context.source.classified"
                && matches!(reason_code, Some("file_attachment" | "image_attachment")) =>
        {
            "context.attachment"
        }
        "context" if id.contains("source") => "context.source_selection",
        "context" if id.contains("segment.budget") => "context.budget",
        "context" if id.contains("tokenizer") => "context.tokenization",
        "context" if id.contains("window") => "context.window",
        "context" if id.contains("tool_catalog") => "context.tool_catalog",
        "context" if id.contains("tool_schema") => "context.tool_schema",
        "context" if id.contains("request") => "context.serialization",
        "context" if id.contains("cache") || id.contains("stable_prefix") => "context.cache",
        "context" if id.contains("compaction") => "context.compaction",
        "context" if id.contains("obligation") => "context.obligation",
        "context" if id.contains("attachment") => "context.attachment",
        "context" => "context.assembly",
        "memory" if id.contains("query") => "memory.query",
        "memory" if id.contains("scope") => "memory.scope",
        "memory" if id.contains("store") => "memory.store_scan",
        "memory" if id.contains("candidate.scored") => "memory.candidate_score",
        "memory" if id.contains("candidate.ranked") || id.contains("candidate.filtered") => {
            "memory.rank_filter"
        }
        "memory" if id.contains("contradiction") => "memory.contradiction",
        "memory" if id.contains("budget") => "memory.budget",
        "memory" if id.contains("recall.inject") || id.contains("recall.serialized") => {
            "memory.injection"
        }
        "memory" if id.contains("visibility") => "memory.visibility",
        "memory" if id.contains("mutation") || id.contains("fact.") => "memory.mutation",
        "memory" if id.contains("contamination") => "memory.contamination",
        "memory" => "memory.recall",
        "submission" | "queue" => "control.submission",
        "steer" => "control.steer",
        "cancel" => "control.cancel",
        "drain" => "control.drain",
        "model" if id.contains("route") => "model.route",
        "model" if id.contains("stream_completed") || id.contains("request_failed") => {
            "model.request"
        }
        "model" if id.contains("stream") || id.contains("first_") => "model.stream",
        "model" if id.contains("retry") => "model.retry",
        "model" if id.contains("usage") => "model.usage",
        "model" if id.contains("quota") || id.contains("rate_limit") => "model.quota",
        "model" => "model.request",
        "tool" if id.contains("policy") => "tool.policy",
        "tool" if id.contains("output") => "tool.effect",
        "tool" => "tool.call",
        "process" if id.contains("reap") => "process.reap",
        "process" => "process.foreground",
        "background" => "process.background",
        "workflow" if id.contains("phase") => return None,
        "workflow" if id.contains("planning") => "workflow.planning",
        "workflow" if id.contains("child") => "workflow.child",
        "workflow" if id.contains("reduction") => "workflow.reduction",
        "workflow" => "workflow.run",
        "verification" => "verification.run",
        "checkpoint" | "replay" => "checkpoint.replay",
        "hook" => "hook.run",
        "exporter" => "exporter.batch",
        _ => return None,
    };
    catalog::SPAN_TEMPLATES
        .iter()
        .find(|template| template.name == wanted)
        .map(|template| template.name)
}

fn span_key(template: &str, event: &LifecycleEventEnvelope) -> String {
    format!(
        "{template}:{}:{}:{}:{}:{}:{}:{}:{}",
        event
            .session_id
            .as_ref()
            .map(|id| id.0.as_str())
            .unwrap_or("-"),
        event.run_id.as_ref().map(|id| id.0.as_str()).unwrap_or("-"),
        event.turn_id.map(|id| id.0).unwrap_or(0),
        event.submission_id.map(|id| id.0).unwrap_or(0),
        event
            .effect_id
            .as_ref()
            .map(|id| id.0.as_str())
            .unwrap_or("-"),
        event
            .workflow_id
            .as_ref()
            .map(|id| id.0.as_str())
            .unwrap_or("-"),
        event
            .subagent_id
            .as_ref()
            .map(|id| id.0.as_str())
            .unwrap_or("-"),
        event.job_id.as_ref().map(|id| id.0.as_str()).unwrap_or("-")
    )
}

fn traceparent(event: &LifecycleEventEnvelope) -> String {
    let mut trace = Sha256::new();
    trace.update(
        event
            .session_id
            .as_ref()
            .map(|id| id.0.as_bytes())
            .unwrap_or_default(),
    );
    trace.update(
        event
            .run_id
            .as_ref()
            .map(|id| id.0.as_bytes())
            .unwrap_or_default(),
    );
    trace.update(
        event
            .turn_id
            .map(|id| id.0)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    let trace = trace.finalize();
    let mut span = Sha256::new();
    span.update(&trace[..16]);
    span.update(event.event_id.as_str().as_bytes());
    span.update(event.ordinal.to_be_bytes());
    let span = span.finalize();
    format!(
        "00-{}-{}-01",
        lower_hex(&trace[..16]),
        lower_hex(&span[..8])
    )
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::EffectId;
    use iteron_protocol::lifecycle::{
        LIFECYCLE_CATALOG_VERSION, LifecycleEventId, LifecyclePayload,
    };
    use std::collections::BTreeSet;

    fn event(
        event_id: &str,
        reason_code: Option<&str>,
        has_effect: bool,
        ordinal: u64,
    ) -> LifecycleEventEnvelope {
        LifecycleEventEnvelope {
            catalog_version: LIFECYCLE_CATALOG_VERSION,
            event_id: LifecycleEventId::new(event_id).expect("test event id is valid"),
            event_version: 1,
            ordinal,
            occurred_at_mono_ns: ordinal.saturating_add(1_000),
            session_id: None,
            run_id: None,
            turn_id: None,
            submission_id: None,
            effect_id: has_effect.then(|| EffectId("effect-test".into())),
            workflow_id: None,
            subagent_id: None,
            job_id: None,
            parent_event: None,
            durable_seq: None,
            payload: LifecyclePayload {
                outcome_code: Some("failed".into()),
                reason_code: reason_code.map(str::to_owned),
                count: Some(1),
                duration_us: Some(1_000),
                magnitude: Some(1),
            },
        }
    }

    fn route_variants() -> [(&'static str, Option<&'static str>, bool); 5] {
        [
            ("context.source.classified", Some("file_attachment"), false),
            ("context.cache_region.classified", Some("cache_read"), false),
            (
                "context.cache_region.classified",
                Some("cache_write"),
                false,
            ),
            ("context.cache_region.classified", Some("cache_miss"), false),
            ("tool.call_started", None, true),
        ]
    }

    #[test]
    fn projection_registers_the_exact_metric_catalog() {
        let projection = Projection::default();
        assert_eq!(projection.metrics.len(), catalog::METRIC_INSTRUMENT_COUNT);
    }

    #[test]
    fn every_registered_metric_family_has_a_lifecycle_route() {
        let registered = catalog::metric_instruments()
            .into_iter()
            .map(|instrument| {
                instrument
                    .name
                    .rsplit_once('.')
                    .expect("catalog instruments have a terminal measure")
                    .0
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let mut routed = iteron_protocol::lifecycle::events()
            .flat_map(|event| metric_families(event.id, None, false))
            .flatten()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        for (event_id, reason_code, has_effect) in route_variants() {
            routed.extend(
                metric_families(event_id, reason_code, has_effect)
                    .into_iter()
                    .flatten()
                    .map(str::to_owned),
            );
        }
        assert_eq!(routed, registered);
    }

    #[test]
    fn every_registered_log_and_metric_instrument_is_exercised_by_a_runtime_route() {
        let mut projection = Projection::default();
        let mut ordinal = 0;
        for spec in iteron_protocol::lifecycle::events() {
            projection.record(event(spec.id, None, false, ordinal));
            ordinal = ordinal.saturating_add(1);
        }
        for (event_id, reason_code, has_effect) in route_variants() {
            projection.record(event(event_id, reason_code, has_effect, ordinal));
            ordinal = ordinal.saturating_add(1);
        }

        let projected_logs = projection
            .logs
            .iter()
            .map(|log| log.schema.as_str())
            .collect::<BTreeSet<_>>();
        let registered_logs = catalog::log_schemas()
            .into_iter()
            .map(|schema| schema.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(projected_logs, registered_logs);

        let untouched = projection
            .metrics
            .values()
            .filter(|metric| metric.observations == 0)
            .map(|metric| metric.name.as_str())
            .collect::<Vec<_>>();
        assert!(
            untouched.is_empty(),
            "unexercised instruments: {untouched:?}"
        );
    }

    #[test]
    fn every_registered_span_template_has_a_lifecycle_route() {
        let registered = catalog::SPAN_TEMPLATES
            .iter()
            .map(|template| template.name)
            .collect::<BTreeSet<_>>();
        let routed = iteron_protocol::lifecycle::events()
            .filter_map(|event| span_template(event.id, None))
            .collect::<BTreeSet<_>>();
        let routed = routed
            .into_iter()
            .chain(span_template(
                "context.source.classified",
                Some("file_attachment"),
            ))
            .collect::<BTreeSet<_>>();
        assert_eq!(routed, registered);
    }

    #[test]
    fn every_registered_span_template_can_produce_a_runtime_span() {
        let mut projection = Projection::default();
        let mut ordinal = 0;
        for spec in iteron_protocol::lifecycle::events() {
            projection.record(event(spec.id, None, false, ordinal));
            ordinal = ordinal.saturating_add(1);
        }
        projection.record(event(
            "context.source.classified",
            Some("file_attachment"),
            false,
            ordinal,
        ));
        let projected = projection
            .spans
            .iter()
            .map(|span| span.template.as_str())
            .collect::<BTreeSet<_>>();
        let registered = catalog::SPAN_TEMPLATES
            .iter()
            .map(|template| template.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(projected, registered);
    }
}

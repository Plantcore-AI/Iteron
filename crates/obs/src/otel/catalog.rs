//! Generated-shape OpenTelemetry catalog.
//!
//! Names and counts are a checked contract. Instrument handles and exporters are runtime concerns;
//! keeping this inventory pure lets local recording, OTLP and tests consume exactly the same set.

use core_protocol::lifecycle::{self, HookCapability, LifecycleDomain};

pub const METRIC_FAMILY_COUNT: usize = 80;
pub const METRIC_INSTRUMENT_COUNT: usize = 320;
pub const LOG_SCHEMA_COUNT: usize = lifecycle::EVENT_COUNT;
pub const SPAN_TEMPLATE_COUNT: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentKind {
    Counter,
    Histogram,
    Gauge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricInstrumentSpec {
    pub name: String,
    pub kind: InstrumentKind,
    pub unit: &'static str,
    /// Bounded enum/catalog dimensions only. Correlation IDs never become metric labels.
    pub allowed_labels: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogSchemaSpec {
    pub name: &'static str,
    pub domain: LifecycleDomain,
    pub hook_capability: HookCapability,
    pub schema_version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanTemplateSpec {
    pub name: &'static str,
    pub domain: LifecycleDomain,
}

const CONTEXT_FAMILIES: [&str; 24] = [
    "assembly",
    "source_discovery",
    "source_selection",
    "source_rejection",
    "deduplication",
    "truncation",
    "segment",
    "budget",
    "token_estimate",
    "tokenizer_error",
    "window_usage",
    "window_headroom",
    "output_reserve",
    "overflow_prediction",
    "stable_prefix",
    "cache_read",
    "cache_write",
    "cache_miss",
    "tool_catalog",
    "tool_schema",
    "request_serialization",
    "compaction",
    "obligation_preservation",
    "attachment",
];

const MEMORY_FAMILIES: [&str; 24] = [
    "query",
    "query_rewrite",
    "scope",
    "store_scan",
    "store_failure",
    "candidate",
    "scoring",
    "ranking",
    "filtering",
    "deduplication",
    "contradiction",
    "supersession",
    "expiry",
    "budget",
    "recall_selection",
    "recall_injection",
    "recall_use",
    "fact_add",
    "fact_update",
    "fact_delete",
    "visibility",
    "contamination",
    "benchmark_scope",
    "policy",
];

const CONTROL_FAMILIES: [&str; 6] = [
    "submission",
    "queue",
    "steer",
    "cancel",
    "drain",
    "acknowledgement",
];

const MODEL_FAMILIES: [&str; 8] = [
    "route",
    "request",
    "stream",
    "retry",
    "usage",
    "quota",
    "rate_limit",
    "cache",
];

const TOOL_FAMILIES: [&str; 8] = [
    "policy",
    "effect",
    "tool_call",
    "tool_output",
    "process_spawn",
    "process_termination",
    "process_reap",
    "background_job",
];

const WORKFLOW_FAMILIES: [&str; 6] = [
    "planning",
    "run",
    "phase",
    "child",
    "reduction",
    "cancellation",
];

const VERIFICATION_FAMILIES: [&str; 2] = ["checks", "checkpoint_replay"];
const RUNTIME_FAMILIES: [&str; 2] = ["hooks", "exporter"];

const FAMILY_GROUPS: [(&str, &[&str]); 8] = [
    ("context", &CONTEXT_FAMILIES),
    ("memory", &MEMORY_FAMILIES),
    ("control", &CONTROL_FAMILIES),
    ("model", &MODEL_FAMILIES),
    ("tool", &TOOL_FAMILIES),
    ("workflow", &WORKFLOW_FAMILIES),
    ("verification", &VERIFICATION_FAMILIES),
    ("runtime", &RUNTIME_FAMILIES),
];

const SAFE_LABELS: &[&str] = &["outcome", "reason_code", "class", "catalog_version"];

pub fn metric_instruments() -> Vec<MetricInstrumentSpec> {
    let mut instruments = Vec::with_capacity(METRIC_INSTRUMENT_COUNT);
    for (domain, families) in FAMILY_GROUPS {
        for family in families {
            let prefix = format!("core.{domain}.{family}");
            instruments.extend([
                MetricInstrumentSpec {
                    name: format!("{prefix}.calls"),
                    kind: InstrumentKind::Counter,
                    unit: "{call}",
                    allowed_labels: SAFE_LABELS,
                },
                MetricInstrumentSpec {
                    name: format!("{prefix}.failures"),
                    kind: InstrumentKind::Counter,
                    unit: "{failure}",
                    allowed_labels: SAFE_LABELS,
                },
                MetricInstrumentSpec {
                    name: format!("{prefix}.duration_ms"),
                    kind: InstrumentKind::Histogram,
                    unit: "ms",
                    allowed_labels: SAFE_LABELS,
                },
                MetricInstrumentSpec {
                    name: format!("{prefix}.{}", magnitude_name(domain, family)),
                    kind: InstrumentKind::Gauge,
                    unit: magnitude_unit(domain, family),
                    allowed_labels: SAFE_LABELS,
                },
            ]);
        }
    }
    instruments
}

pub fn log_schemas() -> Vec<LogSchemaSpec> {
    lifecycle::events()
        .map(|event| LogSchemaSpec {
            name: event.id,
            domain: event.domain,
            hook_capability: event.hook_capability,
            schema_version: event.schema_version,
        })
        .collect()
}

pub const SPAN_TEMPLATES: [SpanTemplateSpec; SPAN_TEMPLATE_COUNT] = [
    span("context.assembly", LifecycleDomain::Context),
    span("context.source_selection", LifecycleDomain::Context),
    span("context.budget", LifecycleDomain::Context),
    span("context.tokenization", LifecycleDomain::Context),
    span("context.window", LifecycleDomain::Context),
    span("context.tool_catalog", LifecycleDomain::Context),
    span("context.tool_schema", LifecycleDomain::Context),
    span("context.serialization", LifecycleDomain::Context),
    span("context.cache", LifecycleDomain::Context),
    span("context.compaction", LifecycleDomain::Context),
    span("context.obligation", LifecycleDomain::Context),
    span("context.attachment", LifecycleDomain::Context),
    span("memory.query", LifecycleDomain::Memory),
    span("memory.scope", LifecycleDomain::Memory),
    span("memory.store_scan", LifecycleDomain::Memory),
    span("memory.candidate_score", LifecycleDomain::Memory),
    span("memory.rank_filter", LifecycleDomain::Memory),
    span("memory.contradiction", LifecycleDomain::Memory),
    span("memory.budget", LifecycleDomain::Memory),
    span("memory.recall", LifecycleDomain::Memory),
    span("memory.injection", LifecycleDomain::Memory),
    span("memory.visibility", LifecycleDomain::Memory),
    span("memory.mutation", LifecycleDomain::Memory),
    span("memory.contamination", LifecycleDomain::Memory),
    span("control.submission", LifecycleDomain::Control),
    span("control.steer", LifecycleDomain::Control),
    span("control.cancel", LifecycleDomain::Control),
    span("control.drain", LifecycleDomain::Control),
    span("model.route", LifecycleDomain::ModelProvider),
    span("model.request", LifecycleDomain::ModelProvider),
    span("model.stream", LifecycleDomain::ModelProvider),
    span("model.retry", LifecycleDomain::ModelProvider),
    span("model.usage", LifecycleDomain::ModelProvider),
    span("model.quota", LifecycleDomain::ModelProvider),
    span("tool.policy", LifecycleDomain::ToolProcess),
    span("tool.effect", LifecycleDomain::ToolProcess),
    span("tool.call", LifecycleDomain::ToolProcess),
    span("process.foreground", LifecycleDomain::ToolProcess),
    span("process.background", LifecycleDomain::ToolProcess),
    span("process.reap", LifecycleDomain::ToolProcess),
    span("workflow.planning", LifecycleDomain::Workflow),
    span("workflow.run", LifecycleDomain::Workflow),
    span("workflow.child", LifecycleDomain::Workflow),
    span("workflow.reduction", LifecycleDomain::Workflow),
    span("verification.run", LifecycleDomain::Verification),
    span("checkpoint.replay", LifecycleDomain::Verification),
    span("hook.run", LifecycleDomain::HookExporter),
    span("exporter.batch", LifecycleDomain::HookExporter),
];

const fn span(name: &'static str, domain: LifecycleDomain) -> SpanTemplateSpec {
    SpanTemplateSpec { name, domain }
}

fn magnitude_name(domain: &str, family: &str) -> &'static str {
    match (domain, family) {
        ("context", "token_estimate" | "window_usage" | "window_headroom" | "output_reserve")
        | ("model", "usage") => "tokens",
        ("context", "source_discovery" | "source_selection" | "source_rejection" | "segment")
        | ("memory", "candidate" | "ranking" | "filtering" | "recall_selection")
        | ("workflow", "child") => "items",
        ("control", "queue") => "depth",
        _ => "bytes",
    }
}

fn magnitude_unit(domain: &str, family: &str) -> &'static str {
    match magnitude_name(domain, family) {
        "tokens" => "{token}",
        "items" => "{item}",
        "depth" => "{item}",
        _ => "By",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_counts_and_names_are_exact() {
        let metrics = metric_instruments();
        let logs = log_schemas();
        assert_eq!(metrics.len(), METRIC_INSTRUMENT_COUNT);
        assert_eq!(logs.len(), LOG_SCHEMA_COUNT);
        assert_eq!(SPAN_TEMPLATES.len(), SPAN_TEMPLATE_COUNT);
        assert_eq!(
            metrics
                .iter()
                .map(|metric| &metric.name)
                .collect::<BTreeSet<_>>()
                .len(),
            METRIC_INSTRUMENT_COUNT
        );
        assert_eq!(
            logs.iter()
                .map(|log| log.name)
                .collect::<BTreeSet<_>>()
                .len(),
            LOG_SCHEMA_COUNT
        );
        assert_eq!(
            SPAN_TEMPLATES
                .iter()
                .map(|template| template.name)
                .collect::<BTreeSet<_>>()
                .len(),
            SPAN_TEMPLATE_COUNT
        );
    }

    #[test]
    fn metric_labels_never_include_correlation_identity() {
        let forbidden = [
            "session_id",
            "run_id",
            "turn_id",
            "submission_id",
            "effect_id",
            "workflow_id",
            "subagent_id",
            "job_id",
        ];
        assert!(metric_instruments().iter().all(|instrument| {
            instrument
                .allowed_labels
                .iter()
                .all(|label| !forbidden.contains(label))
        }));
    }
}

//! Bounded, read-only projection of the canonical tunables registry and R2 resolver reports.
//!
//! The TUI deliberately never derives a live runtime configuration here. A registry view is only
//! metadata; a loaded request is only an explicit frozen simulation. Resolution values are exposed
//! exclusively through `core_tunables::explain_entry_json`, whose contract redacts every value.

mod format;

use self::format::{clipped, code, compact_json, constraint_summary, row};
use core_tunables::{
    Family, RESOLUTION_INPUT_MAX_BYTES, ResolutionFailureReport, ResolutionReport,
};
use serde_json::Value;
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path};

const MAX_FIELD_CHARS: usize = 768;
const MAX_REQUEST_PATH_BYTES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Detail {
    pub(crate) family_id: String,
    pub(crate) label: String,
    pub(crate) hint: String,
    pub(crate) rows: Vec<(String, String)>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Catalog {
    pub(crate) title: String,
    pub(crate) entries: Vec<Detail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadError(&'static str);

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LoadError {}

pub(crate) fn registry_catalog() -> Catalog {
    Catalog {
        title: format!(
            "tunables · catalog · {} families · simulation only",
            core_tunables::families().len()
        ),
        entries: core_tunables::families()
            .iter()
            .map(catalog_detail)
            .collect(),
    }
}

/// Load one explicit request from inside the selected workspace. Canonicalization rejects parent
/// traversal and symlinks escaping the workspace; streaming reads enforce R2's exact 1 MiB cap.
pub(crate) fn load_workspace_request(
    workspace: &Path,
    requested_path: &str,
) -> Result<Catalog, LoadError> {
    if requested_path.is_empty()
        || requested_path.len() > MAX_REQUEST_PATH_BYTES
        || requested_path.chars().any(char::is_control)
    {
        return Err(LoadError(
            "expected one bounded workspace-relative JSON request path",
        ));
    }
    let relative = Path::new(requested_path);
    if !relative.is_relative()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(LoadError("request path must stay inside the workspace"));
    }
    let workspace = workspace
        .canonicalize()
        .map_err(|_| LoadError("workspace is not available for request loading"))?;
    let request = workspace
        .join(relative)
        .canonicalize()
        .map_err(|_| LoadError("request file does not exist"))?;
    if !request.starts_with(&workspace) {
        return Err(LoadError("request path must stay inside the workspace"));
    }
    let file = File::open(&request).map_err(|_| LoadError("request file is not readable"))?;
    if !file
        .metadata()
        .map_err(|_| LoadError("request file metadata is unavailable"))?
        .is_file()
    {
        return Err(LoadError("request path must name a regular file"));
    }
    let mut bytes = Vec::with_capacity(RESOLUTION_INPUT_MAX_BYTES.min(64 * 1024));
    file.take((RESOLUTION_INPUT_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| LoadError("request file could not be read completely"))?;
    if bytes.len() > RESOLUTION_INPUT_MAX_BYTES {
        return Err(LoadError("request exceeds the resolver's 1 MiB input cap"));
    }
    catalog_from_bytes(&bytes)
}

fn catalog_from_bytes(bytes: &[u8]) -> Result<Catalog, LoadError> {
    match core_tunables::resolve_json(bytes) {
        Ok(resolved) => report_catalog(resolved.report(), "resolved", 0),
        Err(failure) => failed_report_catalog(&failure),
    }
}

fn failed_report_catalog(failure: &ResolutionFailureReport) -> Result<Catalog, LoadError> {
    let Some(report) = failure.report.as_ref() else {
        return Err(LoadError(
            "request validation failed closed; no simulation report was produced",
        ));
    };
    report_catalog(report, "active resolution failed", failure.failures.len())
}

fn report_catalog(
    report: &ResolutionReport,
    atomic_status: &str,
    failure_count: usize,
) -> Result<Catalog, LoadError> {
    let entries = core_tunables::families()
        .iter()
        .map(|family| report_detail(report, family, atomic_status))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Catalog {
        title: format!(
            "tunables · {atomic_status} · {} families · {failure_count} failures · simulation only",
            entries.len()
        ),
        entries,
    })
}

fn catalog_detail(family: &Family) -> Detail {
    let state = format!("implementation.{}", code(&family.implementation_status));
    let mut detail = metadata_detail(family, &state);
    detail.rows.splice(
        0..0,
        [
            row(
                "surface",
                "registry catalog · simulation=true · runtime_bound=false",
            ),
            row("resolution", "not loaded"),
            row("requested", "not supplied (no frozen request loaded)"),
            row("effective", "not resolved"),
            row("adjustments", "none (no resolution loaded)"),
        ],
    );
    detail.notes.push(
        "Read-only catalog: this does not edit config, bind a value to this run, authenticate evidence, train a policy, or prove benchmark impact."
            .into(),
    );
    detail
}

fn report_detail(
    report: &ResolutionReport,
    family: &Family,
    atomic_status: &str,
) -> Result<Detail, LoadError> {
    // This is the only resolution-value ingress. The R2 explain contract validates the complete
    // report and replaces values, evidence ids, routes, subjects, and input digests with previews.
    let encoded = core_tunables::explain_entry_json(report, family.id)
        .map_err(|_| LoadError("resolver explain refused the simulation report"))?;
    let document: Value = serde_json::from_str(&encoded)
        .map_err(|_| LoadError("resolver explain returned an unreadable document"))?;
    let explanation = document
        .get("entry")
        .and_then(Value::as_object)
        .ok_or(LoadError("resolver explain omitted the selected entry"))?;
    let state = string_field(explanation, "state")?;
    let reason = string_field(explanation, "reason_code")?;
    let source = string_field(explanation, "source_code")?;
    let requested = preview(explanation.get("requested"))?;
    let effective = preview(explanation.get("effective"))?;
    let adjustments = adjustment_summary(explanation.get("adjustments"))?;
    let shadowed = explanation
        .get("shadowed")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let changed = explanation
        .get("requested_effective_differ")
        .and_then(Value::as_bool)
        .ok_or(LoadError("resolver explain omitted its change marker"))?;

    let mut detail = metadata_detail(family, state);
    detail.rows.splice(
        0..0,
        [
            row(
                "surface",
                format!(
                    "frozen-request simulation · runtime_bound=false · atomic_status={atomic_status}"
                ),
            ),
            row("resolution", format!("state={state} · reason={reason}")),
            row("requested", requested),
            row("effective", effective),
            row("source", source),
            row(
                "adjustments",
                format!("{adjustments} · changed={changed} · shadowed={shadowed}"),
            ),
        ],
    );
    detail.notes.push(
        "Values are R2 redacted previews only. This simulation is not the current process state and cannot authorize or persist a runtime setting."
            .into(),
    );
    detail.hint = clipped(
        &format!(
            "{} · {state} · {reason} · key:{} · aliases:{} · default:{} · {}",
            code(&family.domain),
            family.semantic_key,
            if family.aliases.is_empty() {
                "none".into()
            } else {
                family.aliases.join(",")
            },
            code(&family.default.kind),
            family.summary
        ),
        MAX_FIELD_CHARS,
    );
    Ok(detail)
}

fn metadata_detail(family: &Family, state: &str) -> Detail {
    let sources = family
        .source
        .bindings
        .iter()
        .map(|binding| {
            format!(
                "{}/{} @ {}",
                code(&binding.kind),
                code(&binding.trust),
                binding.locator
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let capabilities = family
        .requirements
        .capabilities
        .iter()
        .map(code)
        .collect::<Vec<_>>()
        .join(", ");
    let rules = constraint_summary(family.value_schema.rules);
    let default_value = family
        .default
        .value
        .map(|value| compact_json(&value))
        .unwrap_or_else(|| "<resolver required>".into());
    let aliases = if family.aliases.is_empty() {
        "none".into()
    } else {
        family.aliases.join(", ")
    };
    let strategy_slots = family
        .strategy_slots
        .iter()
        .map(code)
        .collect::<Vec<_>>()
        .join(", ");
    let mut notes = vec![family.summary.into()];
    if family.benchmark_relevance.rationale != family.summary {
        notes.push(family.benchmark_relevance.rationale.into());
    }
    Detail {
        family_id: family.id.into(),
        label: format!("{:03}  {}  [{state}]", family.ordinal, family.id),
        hint: clipped(
            &format!(
                "{} · {state} · key:{} · aliases:{} · default:{} · {}",
                code(&family.domain),
                family.semantic_key,
                aliases,
                code(&family.default.kind),
                family.summary
            ),
            MAX_FIELD_CHARS,
        ),
        rows: vec![
            row("semantic key", family.semantic_key),
            row("aliases", aliases),
            row(
                "implementation",
                format!(
                    "{} · authority={} · risk={}",
                    code(&family.implementation_status),
                    code(&family.authority_class),
                    code(&family.risk_class)
                ),
            ),
            row(
                "default",
                format!(
                    "{} / {} · resolver={} · value={default_value}",
                    code(&family.default.kind),
                    code(&family.default.requirement),
                    compact_json(&family.default.resolver),
                ),
            ),
            row("declared sources", sources),
            row(
                "activation",
                format!(
                    "{} · inactive_reason={}",
                    compact_json(&family.activation.predicate),
                    family
                        .activation
                        .inactive_reason
                        .map(|reason| code(&reason))
                        .unwrap_or_else(|| "none".into())
                ),
            ),
            row(
                "value schema",
                format!(
                    "{} · kind={}",
                    family.value_schema.schema_id,
                    code(&family.value_schema.kind)
                ),
            ),
            row("constraints", rules),
            row(
                "requirements",
                format!(
                    "provider={} · capabilities={}",
                    code(&family.requirements.provider),
                    if capabilities.is_empty() {
                        "none"
                    } else {
                        &capabilities
                    }
                ),
            ),
            row("strategy slots", strategy_slots),
            row(
                "optimization",
                format!(
                    "class={} · phase={} · pin_reason={}",
                    code(&family.optimization.class),
                    code(&family.optimization.search_phase),
                    family.optimization.pin_reason.unwrap_or("none")
                ),
            ),
            row(
                "benchmarks",
                format!(
                    "SWE-bench Pro={} ({}) · Terminal-Bench 2.1={} ({})",
                    code(&family.benchmark_relevance.swe_bench_pro),
                    code(&family.benchmark_relevance.causal_path.swe_bench_pro),
                    code(&family.benchmark_relevance.terminal_bench_2_1),
                    code(&family.benchmark_relevance.causal_path.terminal_bench_2_1),
                ),
            ),
        ],
        notes,
    }
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, LoadError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_FIELD_CHARS && !value.chars().any(char::is_control))
        .ok_or(LoadError(
            "resolver explain contained an invalid bounded field",
        ))
}

fn preview(value: Option<&Value>) -> Result<String, LoadError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok("none".into());
    };
    let object = value.as_object().ok_or(LoadError(
        "resolver explain exposed an invalid value preview",
    ))?;
    if object.get("redacted").and_then(Value::as_bool) != Some(true) {
        return Err(LoadError("resolver explain exposed an unredacted value"));
    }
    let kind = string_field(object, "kind")?;
    let mut facts = Vec::new();
    for key in ["byte_count", "item_count", "canonical_bytes"] {
        if let Some(number) = object.get(key).and_then(Value::as_u64) {
            facts.push(format!("{key}={number}"));
        }
    }
    Ok(if facts.is_empty() {
        format!("{kind}(<redacted>)")
    } else {
        format!("{kind}(<redacted>;{})", facts.join(";"))
    })
}

fn adjustment_summary(value: Option<&Value>) -> Result<String, LoadError> {
    let adjustments = value
        .and_then(Value::as_array)
        .ok_or(LoadError("resolver explain omitted its adjustment ledger"))?;
    if adjustments.is_empty() {
        return Ok("none".into());
    }
    let mut rendered = Vec::with_capacity(adjustments.len());
    for adjustment in adjustments {
        let object = adjustment.as_object().ok_or(LoadError(
            "resolver explain contained an invalid adjustment",
        ))?;
        rendered.push(format!(
            "{} field={} ceiling={} {} -> {}",
            string_field(object, "code")?,
            string_field(object, "field")?,
            string_field(object, "ceiling")?,
            preview(object.get("requested"))?,
            preview(object.get("effective"))?,
        ));
    }
    Ok(clipped(&rendered.join("; "), MAX_FIELD_CHARS))
}

#[cfg(test)]
mod tests;

//! Bounded, read-only projection of the canonical tunables registry and R2 resolver reports.
//!
//! The TUI deliberately never derives a live runtime configuration here. A registry view is only
//! metadata; a loaded request is only an explicit frozen simulation. Resolution values are exposed
//! exclusively through `core_tunables::explain_entry_json`, whose contract redacts every value.

mod format;

use self::format::{
    MAX_DETAIL_FIELD_CHARS, bounded_detail, bounded_title, code, compact_json, constraint_summary,
    join_bounded, row,
};
#[cfg(target_os = "linux")]
use core_tunables::RESOLUTION_INPUT_MAX_BYTES;
use core_tunables::{Family, ResolutionFailureReport, ResolutionReport};
use serde_json::Value;
use std::fmt;
#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::path::{Component, Path};

const MAX_REQUEST_PATH_BYTES: usize = 4_096;
const MAX_REQUEST_COMPONENTS: usize = 128;
const SAFE_LOAD_REFUSAL: &str = "request could not be loaded safely from this workspace";

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
        title: bounded_title(&format!(
            "tunables · catalog · {} families · simulation only",
            core_tunables::families().len()
        )),
        entries: core_tunables::families()
            .iter()
            .map(catalog_detail)
            .collect(),
    }
}

/// Load one explicit request from inside the selected workspace. Linux retains directory and leaf
/// capabilities, rejects symlinks and non-regular leaves, and rebinds the complete pathname before
/// delivering exactly 1 MiB + 1 byte at most to R2. Other platforms fail closed.
pub(crate) fn load_workspace_request(
    workspace: &Path,
    requested_path: &str,
) -> Result<Catalog, LoadError> {
    let bytes = read_workspace_request(workspace, requested_path)?;
    catalog_from_bytes(&bytes)
}

fn parse_request_path(requested_path: &str) -> Result<(Vec<String>, String), LoadError> {
    if requested_path.is_empty()
        || requested_path.len() > MAX_REQUEST_PATH_BYTES
        || requested_path.chars().any(char::is_control)
    {
        return Err(LoadError(
            "expected one bounded workspace-relative JSON request path",
        ));
    }
    let relative = Path::new(requested_path);
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(LoadError("request path must stay inside the workspace"));
        };
        let component = component
            .to_str()
            .ok_or(LoadError("request path must be valid UTF-8"))?;
        components.push(component.to_owned());
        if components.len() > MAX_REQUEST_COMPONENTS {
            return Err(LoadError("request path contains too many components"));
        }
    }
    let leaf = components
        .pop()
        .ok_or(LoadError("request path must name a file"))?;
    Ok((components, leaf))
}

#[cfg(target_os = "linux")]
fn read_workspace_request(workspace: &Path, requested_path: &str) -> Result<Vec<u8>, LoadError> {
    read_workspace_request_with_hook(workspace, requested_path, || {})
}

#[cfg(target_os = "linux")]
fn read_workspace_request_with_hook(
    workspace: &Path,
    requested_path: &str,
    acquired: impl FnOnce(),
) -> Result<Vec<u8>, LoadError> {
    use super::capability_fs;

    let (parents, leaf) = parse_request_path(requested_path)?;
    let binding =
        capability_fs::RootBinding::open(workspace).map_err(|_| LoadError(SAFE_LOAD_REFUSAL))?;
    let parent = capability_fs::traverse(binding.root(), &parents)
        .map_err(|_| LoadError(SAFE_LOAD_REFUSAL))?;
    let mut file = capability_fs::open_regular_nonblocking(&parent, &leaf)
        .map_err(|_| LoadError(SAFE_LOAD_REFUSAL))?;
    acquired();

    let mut bytes = Vec::with_capacity(RESOLUTION_INPUT_MAX_BYTES.min(64 * 1024));
    (&mut file)
        .take((RESOLUTION_INPUT_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| LoadError(SAFE_LOAD_REFUSAL))?;
    if bytes.len() > RESOLUTION_INPUT_MAX_BYTES {
        return Err(LoadError("request exceeds the resolver's 1 MiB input cap"));
    }

    // Reopen the complete root/parent/leaf path after the read. Both the retained parent and the
    // retained leaf must still name the same inodes at the operator-visible workspace path before
    // these bytes can cross the resolver boundary.
    let rebound = binding.still_bound()
        && capability_fs::traverse(binding.root(), &parents)
            .and_then(|current_parent| {
                if !capability_fs::same_file(&parent, &current_parent)? {
                    return Ok(false);
                }
                let current_leaf = capability_fs::open_regular_nonblocking(&current_parent, &leaf)?;
                capability_fs::same_file(&file, &current_leaf)
            })
            .unwrap_or(false)
        && binding.still_bound();
    if !rebound {
        return Err(LoadError(SAFE_LOAD_REFUSAL));
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_workspace_request(_workspace: &Path, requested_path: &str) -> Result<Vec<u8>, LoadError> {
    let _ = parse_request_path(requested_path)?;
    Err(LoadError(SAFE_LOAD_REFUSAL))
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
        title: bounded_title(&format!(
            "tunables · {atomic_status} · {} families · {failure_count} failures · simulation only",
            entries.len()
        )),
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
    bounded_detail(detail)
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
    detail.hint = self::format::bounded_hint(&format!(
        "{} · {state} · {reason} · key:{} · aliases:{} · default:{} · {}",
        code(&family.domain),
        family.semantic_key,
        if family.aliases.is_empty() {
            "none".into()
        } else {
            join_bounded(family.aliases.iter().copied(), ",")
        },
        code(&family.default.kind),
        family.summary
    ));
    Ok(bounded_detail(detail))
}

fn metadata_detail(family: &Family, state: &str) -> Detail {
    let sources = join_bounded(
        family.source.bindings.iter().map(|binding| {
            format!(
                "{}/{} @ {}",
                code(&binding.kind),
                code(&binding.trust),
                binding.locator
            )
        }),
        "; ",
    );
    let capabilities = join_bounded(family.requirements.capabilities.iter().map(code), ", ");
    let rules = constraint_summary(family.value_schema.rules);
    let default_value = family
        .default
        .value
        .map(|value| compact_json(&value))
        .unwrap_or_else(|| "<resolver required>".into());
    let aliases = if family.aliases.is_empty() {
        "none".into()
    } else {
        join_bounded(family.aliases.iter().copied(), ", ")
    };
    let strategy_slots = join_bounded(family.strategy_slots.iter().map(code), ", ");
    let mut notes = vec![family.summary.into()];
    if family.benchmark_relevance.rationale != family.summary {
        notes.push(family.benchmark_relevance.rationale.into());
    }
    Detail {
        family_id: family.id.into(),
        label: format!("{:03}  {}  [{state}]", family.ordinal, family.id),
        hint: self::format::bounded_hint(&format!(
            "{} · {state} · key:{} · aliases:{} · default:{} · {}",
            code(&family.domain),
            family.semantic_key,
            aliases,
            code(&family.default.kind),
            family.summary
        )),
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
        .filter(|value| {
            value.len() <= self::format::MAX_DETAIL_FIELD_BYTES
                && value.chars().count() <= MAX_DETAIL_FIELD_CHARS
                && !value.chars().any(char::is_control)
        })
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
    const MAX_RENDERED_ADJUSTMENTS: usize = 64;
    let rendered = adjustments
        .iter()
        .take(MAX_RENDERED_ADJUSTMENTS)
        .map(|adjustment| {
            let object = adjustment.as_object().ok_or(LoadError(
                "resolver explain contained an invalid adjustment",
            ))?;
            Ok(format!(
                "{} field={} ceiling={} {} -> {}",
                string_field(object, "code")?,
                string_field(object, "field")?,
                string_field(object, "ceiling")?,
                preview(object.get("requested"))?,
                preview(object.get("effective"))?,
            ))
        });
    let mut checked = Vec::with_capacity(adjustments.len().min(MAX_RENDERED_ADJUSTMENTS));
    for item in rendered {
        checked.push(item?);
    }
    Ok(join_bounded(checked, "; "))
}

#[cfg(test)]
mod tests;

//! Bounded, read-only projection of the canonical tunables registry and R2 resolver reports.
//!
//! The TUI deliberately never derives a live runtime configuration here. A registry view is only
//! metadata; a loaded request is only an explicit frozen simulation. Resolution values are exposed
//! exclusively through `iteron_tunables::explain_entry_json`, whose contract redacts every value.

mod format;
mod model;

use self::format::{
    BoundedText, MAX_DETAIL_FIELD_CHARS, bounded_field, bounded_note, code, compact_json,
    constraint_summary, join_strs, row,
};
pub(super) use self::model::Detail;
use self::model::{Catalog, LoadError};
#[cfg(target_os = "linux")]
use iteron_tunables::RESOLUTION_INPUT_MAX_BYTES;
use iteron_tunables::{Family, ResolutionFailureReport, ResolutionReport};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::path::{Component, Path};

const MAX_REQUEST_PATH_BYTES: usize = 4_096;
const MAX_REQUEST_COMPONENTS: usize = 128;
const SAFE_LOAD_REFUSAL: &str = "request could not be loaded safely from this workspace";

pub(super) fn registry_catalog() -> Catalog {
    Catalog::new(
        format_args!(
            "tunables · catalog · {} families · simulation only",
            iteron_tunables::families().len()
        ),
        iteron_tunables::families()
            .iter()
            .map(catalog_detail)
            .collect(),
    )
}

/// Project the exact immutable checkpoint that drives this live runtime. Unlike `registry_catalog`
/// and loaded request files, this surface is runtime-bound and never invokes the current resolver.
pub(super) fn checkpoint_catalog(
    checkpoint: &iteron_record::TunablesCheckpoint,
) -> Result<Catalog, LoadError> {
    let iteron_record::TunablesCheckpoint::V2(snapshot) = checkpoint else {
        return Err(LoadError(
            "this historical session has an identity-only V1 tunables checkpoint",
        ));
    };
    iteron_record::validate_tunables_snapshot_v2(snapshot)
        .map_err(|_| LoadError("the immutable runtime tunables checkpoint is invalid"))?;
    let entries = snapshot
        .entries
        .iter()
        .map(checkpoint_detail)
        .collect::<Result<Vec<_>, _>>()?;
    let profile = iteron_tunables::RuntimeProfile::ALL
        .into_iter()
        .find(|profile| {
            iteron_tunables::runtime_profile_digest(*profile)
                .ok()
                .as_deref()
                == snapshot.profile_digest_sha256.as_deref()
        })
        .map(iteron_tunables::RuntimeProfile::id)
        .unwrap_or("unrecognized");
    Ok(Catalog::new(
        format_args!(
            "tunables · live runtime · {} families · profile={} · digest {}",
            entries.len(),
            profile,
            short_digest(&snapshot.effective_digest_sha256),
        ),
        entries,
    ))
}

fn checkpoint_detail(
    entry: &iteron_protocol::RunGenesisTunableEntryV2,
) -> Result<Detail, LoadError> {
    let family = iteron_tunables::families()
        .iter()
        .find(|family| family.id == entry.family_id)
        .ok_or(LoadError(
            "runtime checkpoint names a family absent from this binary",
        ))?;
    if family.ordinal != entry.ordinal || family.semantic_key != entry.semantic_key {
        return Err(LoadError(
            "runtime checkpoint family identity differs from this binary",
        ));
    }
    let state = match entry.state {
        iteron_protocol::RunGenesisTunableState::Effective => "effective",
        iteron_protocol::RunGenesisTunableState::Inactive => "inactive",
        iteron_protocol::RunGenesisTunableState::Unavailable => "unavailable",
    };
    let mut detail = metadata_detail(family, state);
    detail.prepend_rows([
        row(
            "surface",
            "live immutable runtime · simulation=false · runtime_bound=true",
        ),
        row("state", state),
        row(
            "effective",
            entry
                .effective_value
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| bounded_field("none")),
        ),
        row(
            "provenance",
            entry
                .provenance
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| bounded_field("none")),
        ),
        row("profile applied", entry.profile_applied),
        row("ceilings", compact_json(&entry.ceiling_adjustments)),
        row(
            "inactive reason",
            entry
                .inactive_reason
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| bounded_field("none")),
        ),
    ]);
    detail.push_note(
        "This is the exact V2 checkpoint used by the runtime and inherited by its children; it is not re-resolved from current defaults.",
    );
    Ok(detail)
}

fn short_digest(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

/// Load one explicit request from inside the selected workspace. Linux retains directory and leaf
/// capabilities, rejects symlinks and non-regular leaves, and rebinds the complete pathname before
/// delivering exactly 1 MiB + 1 byte at most to R2. Other platforms fail closed.
pub(super) fn load_workspace_request(
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
    match iteron_tunables::resolve_json(bytes) {
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
    let entries = iteron_tunables::families()
        .iter()
        .map(|family| report_detail(report, family, atomic_status))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Catalog::new(
        format_args!(
            "tunables · {atomic_status} · {} families · {failure_count} failures · simulation only",
            entries.len()
        ),
        entries,
    ))
}

fn catalog_detail(family: &Family) -> Detail {
    let state = bounded_field(format_args!(
        "implementation.{}",
        code(&family.implementation_status)
    ));
    let mut detail = metadata_detail(family, &state);
    detail.prepend_rows([
        row(
            "surface",
            "registry catalog · simulation=true · runtime_bound=false",
        ),
        row("resolution", "not loaded"),
        row("requested", "not supplied (no frozen request loaded)"),
        row("effective", "not resolved"),
        row("adjustments", "none (no resolution loaded)"),
    ]);
    detail.push_note(
        "Read-only catalog: this does not edit config, bind a value to this run, authenticate evidence, train a policy, or prove benchmark impact.",
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
    let encoded = iteron_tunables::explain_entry_json(report, family.id)
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
    detail.prepend_rows([
        row(
            "surface",
            format_args!(
                "frozen-request simulation · runtime_bound=false · atomic_status={atomic_status}"
            ),
        ),
        row(
            "resolution",
            format_args!("state={state} · reason={reason}"),
        ),
        row("requested", requested),
        row("effective", effective),
        row("source", source),
        row(
            "adjustments",
            format_args!("{adjustments} · changed={changed} · shadowed={shadowed}"),
        ),
    ]);
    detail.push_note(
        "Values are R2 redacted previews only. This simulation is not the current process state and cannot authorize or persist a runtime setting.",
    );
    let aliases = if family.aliases.is_empty() {
        bounded_field("none")
    } else {
        join_strs(family.aliases.iter().copied(), ",")
    };
    detail.set_hint(format_args!(
        "{} · {state} · {reason} · key:{} · aliases:{} · default:{} · {}",
        code(&family.domain),
        family.semantic_key,
        aliases,
        code(&family.default.kind),
        family.summary
    ));
    Ok(detail)
}

fn metadata_detail(family: &Family, state: &str) -> Detail {
    let mut sources = BoundedText::field();
    for binding in family.source.bindings {
        if !sources.is_empty() && !sources.push_str("; ") {
            break;
        }
        if !sources.push(format_args!(
            "{}/{} @ {}",
            code(&binding.kind),
            code(&binding.trust),
            binding.locator
        )) {
            break;
        }
    }
    let sources = sources.finish();

    let mut capabilities = BoundedText::field();
    for capability in family.requirements.capabilities {
        if !capabilities.is_empty() && !capabilities.push_str(", ") {
            break;
        }
        if !capabilities.push(code(capability)) {
            break;
        }
    }
    let capabilities = capabilities.finish();
    let rules = constraint_summary(family.value_schema.rules);
    let default_value = family
        .default
        .value
        .map(|value| compact_json(&value))
        .unwrap_or_else(|| bounded_field("<resolver required>"));
    let aliases = if family.aliases.is_empty() {
        bounded_field("none")
    } else {
        join_strs(family.aliases.iter().copied(), ", ")
    };
    let mut strategy_slots = BoundedText::field();
    for slot in family.strategy_slots {
        if !strategy_slots.is_empty() && !strategy_slots.push_str(", ") {
            break;
        }
        if !strategy_slots.push(code(slot)) {
            break;
        }
    }
    let strategy_slots = strategy_slots.finish();
    let mut notes = vec![bounded_note(family.summary)];
    if family.benchmark_relevance.rationale != family.summary {
        notes.push(bounded_note(family.benchmark_relevance.rationale));
    }
    let inactive_reason = family
        .activation
        .inactive_reason
        .map(|reason| code(&reason))
        .unwrap_or_else(|| bounded_field("none"));
    Detail::new(
        family.id,
        format_args!("{:03}  {}  [{state}]", family.ordinal, family.id),
        format_args!(
            "{} · {state} · key:{} · aliases:{} · default:{} · {}",
            code(&family.domain),
            family.semantic_key,
            aliases,
            code(&family.default.kind),
            family.summary
        ),
        vec![
            row("semantic key", family.semantic_key),
            row("aliases", aliases.as_str()),
            row(
                "implementation",
                format_args!(
                    "{} · authority={} · risk={}",
                    code(&family.implementation_status),
                    code(&family.authority_class),
                    code(&family.risk_class)
                ),
            ),
            row(
                "default",
                format_args!(
                    "{} / {} · resolver={} · value={default_value}",
                    code(&family.default.kind),
                    code(&family.default.requirement),
                    compact_json(&family.default.resolver),
                ),
            ),
            row("declared sources", sources),
            row(
                "activation",
                format_args!(
                    "{} · inactive_reason={}",
                    compact_json(&family.activation.predicate),
                    inactive_reason
                ),
            ),
            row(
                "value schema",
                format_args!(
                    "{} · kind={}",
                    family.value_schema.schema_id,
                    code(&family.value_schema.kind)
                ),
            ),
            row("constraints", rules),
            row(
                "requirements",
                format_args!(
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
                format_args!(
                    "class={} · phase={} · pin_reason={}",
                    code(&family.optimization.class),
                    code(&family.optimization.search_phase),
                    family.optimization.pin_reason.unwrap_or("none")
                ),
            ),
            row(
                "benchmarks",
                format_args!(
                    "SWE-bench Pro={} ({}) · Terminal-Bench 2.1={} ({})",
                    code(&family.benchmark_relevance.swe_bench_pro),
                    code(&family.benchmark_relevance.causal_path.swe_bench_pro),
                    code(&family.benchmark_relevance.terminal_bench_2_1),
                    code(&family.benchmark_relevance.causal_path.terminal_bench_2_1),
                ),
            ),
        ],
        notes,
    )
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
                && !value.chars().any(super::is_unsafe_display_char)
        })
        .ok_or(LoadError(
            "resolver explain contained an invalid bounded field",
        ))
}

fn preview(value: Option<&Value>) -> Result<String, LoadError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(bounded_field("none"));
    };
    let object = value.as_object().ok_or(LoadError(
        "resolver explain exposed an invalid value preview",
    ))?;
    if object.get("redacted").and_then(Value::as_bool) != Some(true) {
        return Err(LoadError("resolver explain exposed an unredacted value"));
    }
    let kind = string_field(object, "kind")?;
    let mut output = BoundedText::field();
    let _ = output.push(format_args!("{kind}(<redacted>"));
    for key in ["byte_count", "item_count", "canonical_bytes"] {
        if let Some(number) = object.get(key).and_then(Value::as_u64)
            && !output.push(format_args!(";{key}={number}"))
        {
            break;
        }
    }
    if !output.is_truncated() {
        let _ = output.push_str(")");
    }
    Ok(output.finish())
}

fn adjustment_summary(value: Option<&Value>) -> Result<String, LoadError> {
    let adjustments = value
        .and_then(Value::as_array)
        .ok_or(LoadError("resolver explain omitted its adjustment ledger"))?;
    if adjustments.is_empty() {
        return Ok(bounded_field("none"));
    }
    const MAX_RENDERED_ADJUSTMENTS: usize = 64;
    let mut output = BoundedText::field();
    for (index, adjustment) in adjustments
        .iter()
        .take(MAX_RENDERED_ADJUSTMENTS)
        .enumerate()
    {
        let object = adjustment.as_object().ok_or(LoadError(
            "resolver explain contained an invalid adjustment",
        ))?;
        let code = string_field(object, "code")?;
        let field = string_field(object, "field")?;
        let ceiling = string_field(object, "ceiling")?;
        let requested = preview(object.get("requested"))?;
        let effective = preview(object.get("effective"))?;
        if index > 0 && !output.push_str("; ") {
            break;
        }
        if !output.push(format_args!(
            "{code} field={field} ceiling={ceiling} {requested} -> {effective}"
        )) {
            break;
        }
    }
    if adjustments.len() > MAX_RENDERED_ADJUSTMENTS && !output.is_truncated() {
        output.truncate();
    }
    Ok(output.finish())
}

#[cfg(test)]
mod tests;

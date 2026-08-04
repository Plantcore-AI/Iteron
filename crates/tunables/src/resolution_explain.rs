mod validate;

use self::validate::{checked_entries, registry_family, valid_shadowed_reason};
use crate::resolution_types::{
    Adjustment, AdjustmentKind, EntryOutcome, EntryState, InactiveCause, RejectionReason,
    ResolutionReport, ResolutionSource, ResolutionValue, ResolvedEntry, ShadowedValue,
    UnresolvedReason,
};
use crate::{
    BenchmarkCausalPath, CoreStrategySlot, DefaultKind, DefaultValueRequirement,
    EXPECTED_FAMILY_COUNT, ExternalCeiling, OptimizationClass, ProviderRequirement, RelevanceLevel,
    SearchPhase, SourceKind,
};
use serde::Serialize;
use std::fmt::Write as _;
use thiserror::Error;

/// Explain output is intentionally smaller than the accepted resolver input. It never contains
/// raw values, evidence identifiers, route identities, subjects, or evidence/input digests.
pub const MAX_HUMAN_EXPLAIN_BYTES: usize = 262_144;
pub const MAX_JSON_EXPLAIN_BYTES: usize = 65_536;
pub const MAX_EXPLAIN_ENTRIES: usize = EXPECTED_FAMILY_COUNT;
const MAX_SELECTOR_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExplainError {
    #[error("the resolution report identity is invalid")]
    InvalidReportIdentity,
    #[error("the resolution report structure is invalid")]
    InvalidReportStructure,
    #[error("the resolution report exceeds explain bounds")]
    ReportBoundExceeded,
    #[error("the entry selector is invalid")]
    InvalidSelector,
    #[error("the entry selector did not match a report entry")]
    EntryNotFound,
    #[error("the entry selector is ambiguous")]
    AmbiguousSelector,
    #[error("explain serialization failed")]
    Serialization,
    #[error("explain output exceeds its byte bound")]
    OutputBoundExceeded,
}

#[derive(Serialize)]
struct JsonExplain<'a> {
    schema_version: u16,
    registry_id: &'static str,
    registry_revision: u16,
    registry_digest: &'static str,
    resolution_digest_sha256: &'a str,
    entry: EntryExplain<'a>,
}

#[derive(Serialize)]
struct EntryExplain<'a> {
    ordinal: u16,
    family_id: &'static str,
    semantic_key: &'static str,
    state: EntryState,
    reason_code: &'static str,
    source_code: String,
    requested: Option<ValuePreview>,
    effective: Option<ValuePreview>,
    requested_effective_differ: bool,
    adjustments: Vec<AdjustmentExplain<'a>>,
    shadowed: Vec<ShadowedExplain>,
    default: DefaultExplain,
    strategy_slots: &'static [CoreStrategySlot],
    optimization: OptimizationExplain,
    benchmark: BenchmarkExplain,
}

#[derive(Serialize)]
struct AdjustmentExplain<'a> {
    code: &'static str,
    field: &'a str,
    ceiling: ExternalCeiling,
    requested: ValuePreview,
    effective: ValuePreview,
}

#[derive(Serialize)]
struct ShadowedExplain {
    reason_code: &'static str,
    source_code: String,
    value: ValuePreview,
}

#[derive(Serialize)]
struct DefaultExplain {
    kind: DefaultKind,
    requirement: DefaultValueRequirement,
}

#[derive(Serialize)]
struct OptimizationExplain {
    class: OptimizationClass,
    search_phase: SearchPhase,
}

#[derive(Serialize)]
struct BenchmarkExplain {
    swe_bench_pro: RelevanceLevel,
    terminal_bench_2_1: RelevanceLevel,
    causal_path: BenchmarkCausalPath,
}

#[derive(Clone, Serialize)]
struct ValuePreview {
    kind: &'static str,
    redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_bytes: Option<u64>,
}

impl ValuePreview {
    fn of(value: &ResolutionValue) -> Self {
        let (kind, byte_count, item_count, canonical_bytes) = match value {
            ResolutionValue::Boolean { .. } => ("boolean", None, None, None),
            ResolutionValue::Integer { .. } => ("integer", None, None, None),
            ResolutionValue::Decimal { .. } => ("decimal", None, None, None),
            ResolutionValue::Text { value } => ("text", Some(value.len()), None, None),
            ResolutionValue::Enum { value } => ("enum", Some(value.len()), None, None),
            ResolutionValue::List { items } => ("list", None, Some(items.len()), None),
            ResolutionValue::Map { entries } => ("map", None, Some(entries.len()), None),
            ResolutionValue::Object { fields } => ("object", None, Some(fields.len()), None),
            ResolutionValue::CatalogRef {
                entry_count,
                canonical_bytes,
                ..
            } => (
                "catalog_ref",
                None,
                usize::try_from(*entry_count).ok(),
                Some(*canonical_bytes),
            ),
        };
        Self {
            kind,
            redacted: true,
            byte_count,
            item_count,
            canonical_bytes,
        }
    }

    fn human(&self) -> String {
        if let Some(bytes) = self.byte_count {
            format!("{}(<redacted>;bytes={bytes})", self.kind)
        } else if let Some(items) = self.item_count {
            if let Some(bytes) = self.canonical_bytes {
                format!("{}(<redacted>;items={items};bytes={bytes})", self.kind)
            } else {
                format!("{}(<redacted>;items={items})", self.kind)
            }
        } else {
            format!("{}(<redacted>)", self.kind)
        }
    }
}

/// Produce a deterministic, control-safe explanation for the entire bounded report.
pub fn explain_text(report: &ResolutionReport) -> Result<String, ExplainError> {
    let entries = checked_entries(report)?;
    let mut output = String::with_capacity(entries.len().saturating_mul(256));
    writeln!(output, "Core tunable resolution explain v1")
        .map_err(|_| ExplainError::Serialization)?;
    writeln!(
        output,
        "registry={} revision={} digest={}",
        report.registry_id, report.registry_revision, report.registry_digest
    )
    .map_err(|_| ExplainError::Serialization)?;
    writeln!(
        output,
        "resolution_digest_sha256={} entries={}",
        report.resolution_digest_sha256,
        entries.len()
    )
    .map_err(|_| ExplainError::Serialization)?;

    for entry in entries {
        let explanation = build_entry(entry)?;
        writeln!(
            output,
            "{:03} {} key={} state={} code={} source={} requested={} effective={} changed={} adjustments={} shadowed={}",
            explanation.ordinal,
            explanation.family_id,
            explanation.semantic_key,
            state_code(explanation.state),
            explanation.reason_code,
            explanation.source_code,
            human_optional(explanation.requested.as_ref()),
            human_optional(explanation.effective.as_ref()),
            explanation.requested_effective_differ,
            explanation.adjustments.len(),
            explanation.shadowed.len(),
        )
        .map_err(|_| ExplainError::Serialization)?;
        for adjustment in &explanation.adjustments {
            writeln!(
                output,
                "  adjustment code={} field={} ceiling={} requested={} effective={}",
                adjustment.code,
                adjustment.field,
                ceiling_code(adjustment.ceiling),
                adjustment.requested.human(),
                adjustment.effective.human(),
            )
            .map_err(|_| ExplainError::Serialization)?;
        }
        for shadowed in &explanation.shadowed {
            writeln!(
                output,
                "  shadowed code={} source={} value={}",
                shadowed.reason_code,
                shadowed.source_code,
                shadowed.value.human(),
            )
            .map_err(|_| ExplainError::Serialization)?;
        }
        ensure_output_bound(output.len(), MAX_HUMAN_EXPLAIN_BYTES)?;
    }
    ensure_output_bound(output.len(), MAX_HUMAN_EXPLAIN_BYTES)?;
    Ok(output)
}

/// Produce one bounded machine explanation. Selectors accept a canonical family ID, semantic key,
/// or registered alias; cross-entry matches fail closed as ambiguous.
pub fn explain_entry_json(
    report: &ResolutionReport,
    selector: &str,
) -> Result<String, ExplainError> {
    if selector.is_empty()
        || selector.len() > MAX_SELECTOR_BYTES
        || selector.chars().any(char::is_control)
    {
        return Err(ExplainError::InvalidSelector);
    }
    let entries = checked_entries(report)?;
    let mut matches = Vec::with_capacity(1);
    for entry in entries {
        let family = registry_family(entry)?;
        if family.id == selector
            || family.semantic_key == selector
            || family.aliases.contains(&selector)
        {
            matches.push(entry);
        }
    }
    let entry = match matches.as_slice() {
        [] => return Err(ExplainError::EntryNotFound),
        [entry] => *entry,
        _ => return Err(ExplainError::AmbiguousSelector),
    };
    let document = JsonExplain {
        schema_version: report.schema_version,
        registry_id: report.registry_id,
        registry_revision: report.registry_revision,
        registry_digest: report.registry_digest,
        resolution_digest_sha256: &report.resolution_digest_sha256,
        entry: build_entry(entry)?,
    };
    let output = serde_json::to_string(&document).map_err(|_| ExplainError::Serialization)?;
    ensure_output_bound(output.len(), MAX_JSON_EXPLAIN_BYTES)?;
    Ok(output)
}

fn build_entry(entry: &ResolvedEntry) -> Result<EntryExplain<'_>, ExplainError> {
    let adjustments = entry
        .adjustments
        .iter()
        .map(build_adjustment)
        .collect::<Result<Vec<_>, _>>()?;
    let shadowed = entry
        .shadowed
        .iter()
        .map(build_shadowed)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EntryExplain {
        ordinal: entry.ordinal,
        family_id: entry.family_id,
        semantic_key: entry.semantic_key,
        state: entry.outcome.state(),
        reason_code: outcome_code(&entry.outcome),
        source_code: source_code(entry.provenance.as_ref().map(|value| &value.source)),
        requested: entry.requested.as_ref().map(ValuePreview::of),
        effective: entry.effective.as_ref().map(ValuePreview::of),
        requested_effective_differ: entry.requested != entry.effective,
        adjustments,
        shadowed,
        default: DefaultExplain {
            kind: entry.default.kind,
            requirement: entry.default.requirement,
        },
        strategy_slots: entry.strategy_slots,
        optimization: OptimizationExplain {
            class: entry.optimization.class,
            search_phase: entry.optimization.search_phase,
        },
        benchmark: BenchmarkExplain {
            swe_bench_pro: entry.benchmark_relevance.swe_bench_pro,
            terminal_bench_2_1: entry.benchmark_relevance.terminal_bench_2_1,
            causal_path: entry.benchmark_relevance.causal_path,
        },
    })
}

fn build_adjustment(adjustment: &Adjustment) -> Result<AdjustmentExplain<'_>, ExplainError> {
    Ok(AdjustmentExplain {
        code: match adjustment.kind {
            AdjustmentKind::ClampMaximum => "adjustment.clamp_maximum",
            AdjustmentKind::ProviderDegrade => "adjustment.provider_degrade",
        },
        field: &adjustment.field,
        ceiling: adjustment.ceiling,
        requested: ValuePreview::of(&adjustment.requested),
        effective: ValuePreview::of(&adjustment.effective),
    })
}

fn build_shadowed(value: &ShadowedValue) -> Result<ShadowedExplain, ExplainError> {
    if !valid_shadowed_reason(value.reason_code) {
        return Err(ExplainError::InvalidReportStructure);
    }
    Ok(ShadowedExplain {
        reason_code: value.reason_code,
        source_code: source_code(Some(&value.provenance.source)),
        value: ValuePreview::of(&value.value),
    })
}

fn outcome_code(outcome: &EntryOutcome) -> &'static str {
    match outcome {
        EntryOutcome::Effective => "effective",
        EntryOutcome::Inactive { cause } => match cause {
            InactiveCause::Activation { reason } => match reason {
                crate::InactiveReason::ConfigurationAbsent => "inactive.configuration_absent",
                crate::InactiveReason::GroupedOrIncompleteSeam => {
                    "inactive.grouped_or_incomplete_seam"
                }
                crate::InactiveReason::NotImplemented => "inactive.not_implemented",
            },
            InactiveCause::RuntimeSeamMissing { .. } => "inactive.runtime_seam_missing",
            InactiveCause::RuntimeSeamInactive { .. } => "inactive.runtime_seam_inactive",
            InactiveCause::ProviderRouteMissing { requirement } => match requirement {
                ProviderRequirement::None => "inactive.provider_route_missing.none",
                ProviderRequirement::AnyAdmittedRoute => {
                    "inactive.provider_route_missing.any_admitted"
                }
                ProviderRequirement::SelectedRoute => "inactive.provider_route_missing.selected",
            },
            InactiveCause::CapabilitiesMissing { .. } => "inactive.capabilities_missing",
        },
        EntryOutcome::Unavailable => "unavailable.not_implemented",
        EntryOutcome::Unresolved { reason } => match reason {
            UnresolvedReason::ResolverEvidenceMissing { .. } => {
                "unresolved.default_evidence_missing"
            }
            UnresolvedReason::ResolverReturnedAbsent { .. } => "unresolved.default_evidence_absent",
            UnresolvedReason::ResolverUnsupported { .. } => {
                "unresolved.default_evidence_unsupported"
            }
            UnresolvedReason::ExternalConstraintMissing { .. } => {
                "unresolved.external_constraint_missing"
            }
        },
        EntryOutcome::Rejected { reason } => match reason {
            RejectionReason::ProviderRequirement { .. } => "rejected.provider_requirement",
            RejectionReason::ExternalConstraint { .. } => "rejected.external_constraint",
            RejectionReason::CrossFieldRule { .. } => "rejected.cross_field_rule",
        },
    }
}

fn source_code(source: Option<&ResolutionSource>) -> String {
    match source {
        None => "source.none".to_owned(),
        Some(ResolutionSource::Declared { kind, .. }) => {
            format!("source.declared.{}", source_kind_code(*kind))
        }
        Some(ResolutionSource::Profile { kind, .. }) => {
            format!("source.profile.{}", source_kind_code(*kind))
        }
        Some(ResolutionSource::Default { fallback: true, .. }) => {
            "source.default.fallback".to_owned()
        }
        Some(ResolutionSource::Default {
            resolver_id,
            fallback: false,
            ..
        }) if resolver_id == "core://tunables/resolvers/literal-v1" => {
            "source.default.literal".to_owned()
        }
        Some(ResolutionSource::Default { .. }) => "source.default.resolved".to_owned(),
    }
}

fn source_kind_code(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::Cli => "cli",
        SourceKind::OperatorInput => "operator_input",
        SourceKind::RustBuilder => "rust_builder",
        SourceKind::UserConfig => "user_config",
        SourceKind::ProjectConfig => "project_config",
        SourceKind::Environment => "environment",
        SourceKind::Builtin => "builtin",
        SourceKind::DerivedPolicy => "derived_policy",
        SourceKind::Catalog => "catalog",
        SourceKind::RuntimeObservation => "runtime_observation",
        SourceKind::ExternalProvider => "external_provider",
        SourceKind::GovernedBundle => "governed_bundle",
        SourceKind::Registry => "registry",
    }
}

fn state_code(state: EntryState) -> &'static str {
    match state {
        EntryState::Effective => "effective",
        EntryState::Inactive => "inactive",
        EntryState::Unavailable => "unavailable",
        EntryState::Unresolved => "unresolved",
        EntryState::Rejected => "rejected",
    }
}

fn ceiling_code(ceiling: ExternalCeiling) -> &'static str {
    match ceiling {
        ExternalCeiling::OperatorAuthority => "operator_authority",
        ExternalCeiling::ParentTurns => "parent_turns",
        ExternalCeiling::ParentTokens => "parent_tokens",
        ExternalCeiling::ParentWall => "parent_wall",
        ExternalCeiling::ParentCost => "parent_cost",
        ExternalCeiling::ProviderCapability => "provider_capability",
        ExternalCeiling::ContextWindow => "context_window",
        ExternalCeiling::ToolBudget => "tool_budget",
        ExternalCeiling::ProcessBudget => "process_budget",
        ExternalCeiling::VerificationFloor => "verification_floor",
        ExternalCeiling::TenantScope => "tenant_scope",
        ExternalCeiling::RunBudget => "run_budget",
        ExternalCeiling::BenchmarkProtocol => "benchmark_protocol",
    }
}

fn human_optional(value: Option<&ValuePreview>) -> String {
    value.map_or_else(|| "none".to_owned(), ValuePreview::human)
}

fn ensure_output_bound(actual: usize, maximum: usize) -> Result<(), ExplainError> {
    if actual > maximum {
        Err(ExplainError::OutputBoundExceeded)
    } else {
        Ok(())
    }
}

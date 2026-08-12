use crate::resolution_constraints::ConstraintResult;
use crate::resolution_prepare::{PreparedInput, default_resolver_id};
use crate::resolution_types::{
    EntryOutcome, EvidenceState, FailureCode, FamilyFailure, InactiveCause,
    RESOLUTION_INPUT_MAX_BYTES, RESOLUTION_SCHEMA_VERSION, RejectionReason,
    ResolutionFailureReport, ResolutionInput, ResolutionProvenance, ResolutionReport,
    ResolutionSource, ResolutionValue, ResolvedEntry, ResolvedTunableSet, ShadowedValue,
    UnresolvedReason,
};
use crate::{ActivationPredicate, DefaultResolver, Family, ImplementationStatus, families};
use std::collections::BTreeMap;

#[path = "resolution_route.rs"]
mod route;
#[path = "resolution/source_merge.rs"]
mod source_merge;
use source_merge::{Selected, select_explicit};

#[allow(
    clippy::result_large_err,
    reason = "the public contract returns the complete atomic failure report by value"
)]
pub fn resolve(input: ResolutionInput) -> Result<ResolvedTunableSet, ResolutionFailureReport> {
    let prepared = crate::resolution_prepare::prepare(input).map_err(invalid_input)?;
    let mut entries = families()
        .iter()
        .map(|family| resolve_family(family, &prepared))
        .collect::<Vec<_>>();
    if entries.len() != crate::EXPECTED_FAMILY_COUNT {
        return Err(invalid_input(format!(
            "resolved {} entries, registry declares {}",
            entries.len(),
            crate::EXPECTED_FAMILY_COUNT
        )));
    }
    crate::resolved_set_rules::enforce(&mut entries).map_err(invalid_input)?;
    let effective_digest_sha256 =
        crate::resolution_digest::effective_digest(&entries).map_err(invalid_input)?;
    let mut report = ResolutionReport {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        registry_id: crate::REGISTRY_ID,
        registry_revision: crate::REGISTRY_REVISION,
        registry_digest: crate::REGISTRY_DIGEST_SHA256,
        input_digest_sha256: prepared.input_digest_sha256.clone(),
        effective_digest_sha256,
        resolution_digest_sha256: String::new(),
        profile_digest_sha256: prepared.profile_digest_sha256.clone(),
        fixed_authority_attestations: Vec::new(),
        entries,
    };
    report.resolution_digest_sha256 =
        crate::resolution_digest::resolution_digest(&report).map_err(invalid_input)?;

    let failures = report
        .entries
        .iter()
        .filter_map(family_failure)
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(ResolvedTunableSet { report })
    } else {
        Err(ResolutionFailureReport {
            schema_version: RESOLUTION_SCHEMA_VERSION,
            code: FailureCode::ActiveResolutionFailed,
            detail: "active tunable resolution failed closed".into(),
            failures,
            report: Some(report),
        })
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the public contract returns the complete atomic failure report by value"
)]
pub fn resolve_json(bytes: &[u8]) -> Result<ResolvedTunableSet, ResolutionFailureReport> {
    if bytes.len() > RESOLUTION_INPUT_MAX_BYTES {
        return Err(invalid_input(format!(
            "resolution input is {} bytes, the bound is {RESOLUTION_INPUT_MAX_BYTES}",
            bytes.len()
        )));
    }
    let input = serde_json::from_slice(bytes)
        .map_err(|error| invalid_input(format!("resolution input is not valid JSON: {error}")))?;
    resolve(input)
}

fn resolve_family(family: &Family, prepared: &PreparedInput) -> ResolvedEntry {
    if family.implementation_status == ImplementationStatus::Missing {
        return entry(
            family,
            None,
            None,
            None,
            EntryOutcome::Unavailable,
            Vec::new(),
            Vec::new(),
        );
    }

    let explicit = select_explicit(family, prepared);
    if let Some(cause) = activation_cause(family, prepared) {
        let (selected, shadowed) = explicit.without_default();
        let (requested, provenance) = selected
            .map(|selected| (Some(selected.value), Some(selected.provenance)))
            .unwrap_or((None, None));
        return entry(
            family,
            requested,
            None,
            provenance,
            EntryOutcome::Inactive { cause },
            Vec::new(),
            shadowed,
        );
    }

    if !explicit.has_value()
        && let Some(outcome) = route::default_availability(family, prepared)
    {
        return entry(
            family,
            None,
            None,
            None,
            outcome,
            Vec::new(),
            explicit.shadowed,
        );
    }

    let (selected, shadowed) = match explicit.with_default(family, prepared) {
        Ok(selected) => selected,
        Err((reason, shadowed)) => {
            return entry(
                family,
                None,
                None,
                None,
                EntryOutcome::Unresolved { reason },
                Vec::new(),
                shadowed,
            );
        }
    };
    let requested = selected.value.clone();
    let provenance = selected.provenance.clone();
    if let Some(outcome) =
        route::provider_gate(family, prepared, &selected.value, selected.explicit)
    {
        return entry(
            family,
            Some(requested),
            None,
            Some(provenance),
            outcome,
            Vec::new(),
            shadowed,
        );
    }

    match crate::resolution_constraints::apply(family, prepared, &requested) {
        ConstraintResult::Effective { value, adjustments } => entry(
            family,
            Some(requested),
            Some(value),
            Some(provenance),
            EntryOutcome::Effective,
            adjustments,
            shadowed,
        ),
        ConstraintResult::Unresolved(reason) => entry(
            family,
            Some(requested),
            None,
            Some(provenance),
            EntryOutcome::Unresolved { reason },
            Vec::new(),
            shadowed,
        ),
        ConstraintResult::Rejected(reason) => entry(
            family,
            Some(requested),
            None,
            Some(provenance),
            EntryOutcome::Rejected { reason },
            Vec::new(),
            shadowed,
        ),
    }
}

fn select_default(family: &Family, prepared: &PreparedInput) -> Result<Selected, UnresolvedReason> {
    let resolver_id = default_resolver_id(family.default.resolver);
    let evidence = prepared
        .input
        .default_evidence
        .iter()
        .find(|evidence| evidence.family == family.id);
    let (mut value, digest, subject, fallback) = match evidence.map(|evidence| &evidence.state) {
        Some(EvidenceState::Present { value }) => (
            value.clone(),
            evidence.map(|evidence| evidence.evidence_digest_sha256.clone()),
            evidence.map(|evidence| evidence.subject.clone()),
            false,
        ),
        Some(EvidenceState::Absent { code }) => {
            let Some(value) = family.default.value else {
                return Err(UnresolvedReason::ResolverReturnedAbsent {
                    resolver_id,
                    code: code.clone(),
                });
            };
            (
                crate::resolution_value::owned(value),
                evidence.map(|evidence| evidence.evidence_digest_sha256.clone()),
                evidence.map(|evidence| evidence.subject.clone()),
                true,
            )
        }
        Some(EvidenceState::Unsupported { code }) => {
            let Some(value) = family.default.value else {
                return Err(UnresolvedReason::ResolverUnsupported {
                    resolver_id,
                    code: code.clone(),
                });
            };
            (
                crate::resolution_value::owned(value),
                evidence.map(|evidence| evidence.evidence_digest_sha256.clone()),
                evidence.map(|evidence| evidence.subject.clone()),
                true,
            )
        }
        None => {
            let Some(value) = family.default.value else {
                return Err(UnresolvedReason::ResolverEvidenceMissing { resolver_id });
            };
            (
                crate::resolution_value::owned(value),
                None,
                None,
                !matches!(family.default.resolver, DefaultResolver::Literal),
            )
        }
    };
    crate::resolution_value::normalize(&mut value);
    let catalogs = prepared
        .input
        .runtime
        .catalogs
        .iter()
        .map(|catalog| (catalog.catalog_id.as_str(), catalog))
        .collect::<BTreeMap<_, _>>();
    if crate::resolution_value::validate(&value, family.value_schema, &catalogs).is_err() {
        return Err(UnresolvedReason::ResolverEvidenceMissing { resolver_id });
    }
    Ok(Selected {
        value,
        provenance: ResolutionProvenance {
            source: ResolutionSource::Default {
                resolver_id,
                evidence_digest_sha256: digest,
                subject,
                fallback,
            },
        },
        explicit: false,
    })
}

fn activation_cause(family: &Family, prepared: &PreparedInput) -> Option<InactiveCause> {
    match family.activation.predicate {
        ActivationPredicate::Always => None,
        ActivationPredicate::Unavailable => Some(InactiveCause::Activation {
            reason: family
                .activation
                .inactive_reason
                .unwrap_or(crate::InactiveReason::NotImplemented),
        }),
        ActivationPredicate::Configured { sources } => {
            let configured = prepared
                .input
                .declared_values
                .iter()
                .any(|value| value.family == family.id && sources.contains(&value.source))
                || prepared.input.profile.as_ref().is_some_and(|profile| {
                    profile.values.iter().any(|value| {
                        value.family == family.id && sources.contains(&value.as_declared_source)
                    })
                });
            (!configured).then(|| InactiveCause::Activation {
                reason: family
                    .activation
                    .inactive_reason
                    .unwrap_or(crate::InactiveReason::NotImplemented),
            })
        }
        ActivationPredicate::RuntimeDerived { seam } => match prepared
            .input
            .activation_evidence
            .iter()
            .find(|evidence| evidence.family == family.id && evidence.seam == seam)
        {
            None => Some(InactiveCause::RuntimeSeamMissing { seam }),
            Some(evidence) if !evidence.active => Some(InactiveCause::RuntimeSeamInactive { seam }),
            Some(_) => None,
        },
    }
}

fn entry(
    family: &Family,
    requested: Option<ResolutionValue>,
    effective: Option<ResolutionValue>,
    provenance: Option<ResolutionProvenance>,
    outcome: EntryOutcome,
    adjustments: Vec<crate::Adjustment>,
    shadowed: Vec<ShadowedValue>,
) -> ResolvedEntry {
    ResolvedEntry {
        ordinal: family.ordinal,
        family_id: family.id,
        semantic_key: family.semantic_key,
        requested,
        effective,
        provenance,
        outcome,
        adjustments,
        shadowed,
        default: family.default,
        strategy_slots: family.strategy_slots,
        optimization: family.optimization,
        benchmark_relevance: family.benchmark_relevance,
    }
}

fn family_failure(entry: &ResolvedEntry) -> Option<FamilyFailure> {
    let reason_code = match entry.outcome {
        EntryOutcome::Unresolved {
            reason: UnresolvedReason::ResolverEvidenceMissing { .. },
        } => "resolver_evidence_missing",
        EntryOutcome::Unresolved {
            reason: UnresolvedReason::ResolverReturnedAbsent { .. },
        } => "resolver_returned_absent",
        EntryOutcome::Unresolved {
            reason: UnresolvedReason::ResolverUnsupported { .. },
        } => "resolver_unsupported",
        EntryOutcome::Unresolved {
            reason: UnresolvedReason::ExternalConstraintMissing { .. },
        } => "external_constraint_missing",
        EntryOutcome::Rejected {
            reason: RejectionReason::ProviderRequirement { .. },
        } => "provider_requirement_rejected",
        EntryOutcome::Rejected {
            reason: RejectionReason::ExternalConstraint { .. },
        } => "external_constraint_rejected",
        EntryOutcome::Rejected {
            reason: RejectionReason::CrossFieldRule { .. },
        } => "cross_field_rule_rejected",
        EntryOutcome::Effective | EntryOutcome::Inactive { .. } | EntryOutcome::Unavailable => {
            return None;
        }
    };
    Some(FamilyFailure {
        family_id: entry.family_id,
        state: entry.outcome.state(),
        reason_code,
    })
}

/// A fail-closed validation that reports nothing is undebuggable: every caller below already holds
/// the reason, so it is carried into `detail` rather than collapsed into one fixed sentence.
fn invalid_input(detail: impl Into<String>) -> ResolutionFailureReport {
    ResolutionFailureReport {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        code: FailureCode::InvalidInput,
        detail: detail.into(),
        failures: Vec::new(),
        report: None,
    }
}

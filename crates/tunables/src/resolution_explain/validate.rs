use super::{ExplainError, MAX_EXPLAIN_ENTRIES};
use crate::resolution_types::{
    Adjustment, AdjustmentKind, EntryOutcome, InactiveCause, RejectionReason, ResolutionProvenance,
    ResolutionReport, ResolutionSource, ResolvedEntry, UnresolvedReason,
};
use crate::{
    ActivationPredicate, ConstraintViolation, CrossFieldRule, DefaultResolver, ExternalCeiling,
    Family, ImplementationStatus, ProviderRequirement, REGISTRY_DIGEST_SHA256, REGISTRY_ID,
    REGISTRY_REVISION, SourceKind,
};

const MAX_ADJUSTMENTS: usize = 201;
const MAX_SHADOWED_VALUES: usize = 353;
const MAX_REASON_CODE_BYTES: usize = 96;

pub(super) fn checked_entries(
    report: &ResolutionReport,
) -> Result<Vec<&ResolvedEntry>, ExplainError> {
    if report.schema_version != crate::RESOLUTION_SCHEMA_VERSION
        || report.registry_id != REGISTRY_ID
        || report.registry_revision != REGISTRY_REVISION
        || report.registry_digest != REGISTRY_DIGEST_SHA256
        || !valid_sha256(&report.resolution_digest_sha256)
    {
        return Err(ExplainError::InvalidReportIdentity);
    }
    if report.entries.len() != MAX_EXPLAIN_ENTRIES
        || !valid_sha256(&report.input_digest_sha256)
        || !valid_sha256(&report.effective_digest_sha256)
        || report
            .profile_digest_sha256
            .as_deref()
            .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err(ExplainError::ReportBoundExceeded);
    }
    let mut adjustments = 0usize;
    let mut shadowed = 0usize;
    let entries: Vec<_> = report.entries.iter().collect();
    for (index, entry) in entries.iter().enumerate() {
        let family = registry_family(entry)?;
        if usize::from(entry.ordinal) != index + 1
            || !valid_entry(entry, family, report.profile_digest_sha256.as_deref())
        {
            return Err(ExplainError::InvalidReportStructure);
        }
        adjustments = adjustments
            .checked_add(entry.adjustments.len())
            .ok_or(ExplainError::ReportBoundExceeded)?;
        shadowed = shadowed
            .checked_add(entry.shadowed.len())
            .ok_or(ExplainError::ReportBoundExceeded)?;
        if adjustments > MAX_ADJUSTMENTS || shadowed > MAX_SHADOWED_VALUES {
            return Err(ExplainError::ReportBoundExceeded);
        }
        if entry
            .adjustments
            .iter()
            .any(|adjustment| !valid_adjustment(adjustment, family))
            || entry
                .shadowed
                .iter()
                .any(|value| !valid_shadowed_reason(value.reason_code))
        {
            return Err(ExplainError::InvalidReportStructure);
        }
    }
    Ok(entries)
}

pub(super) fn registry_family(entry: &ResolvedEntry) -> Result<&'static Family, ExplainError> {
    let family = crate::families()
        .get(usize::from(entry.ordinal).wrapping_sub(1))
        .ok_or(ExplainError::InvalidReportStructure)?;
    let ordinal_matches = family.ordinal == entry.ordinal;
    let id_matches = family.id == entry.family_id;
    let semantic_key_matches = family.semantic_key == entry.semantic_key;
    if !(ordinal_matches && id_matches && semantic_key_matches) {
        return Err(ExplainError::InvalidReportStructure);
    }
    Ok(family)
}

fn valid_entry(
    entry: &ResolvedEntry,
    family: &Family,
    profile_digest_sha256: Option<&str>,
) -> bool {
    if entry.default != family.default
        || entry.strategy_slots != family.strategy_slots
        || entry.optimization != family.optimization
        || entry.benchmark_relevance != family.benchmark_relevance
        || (entry.requested.is_some() != entry.provenance.is_some())
        || entry
            .provenance
            .as_ref()
            .is_some_and(|provenance| !valid_provenance(provenance, family, profile_digest_sha256))
        || entry
            .shadowed
            .iter()
            .any(|shadowed| !valid_provenance(&shadowed.provenance, family, profile_digest_sha256))
        || entry
            .requested
            .iter()
            .chain(&entry.effective)
            .chain(entry.shadowed.iter().map(|value| &value.value))
            .any(|value| {
                crate::resolution_value::validate_report(value, family.value_schema).is_err()
            })
    {
        return false;
    }
    let unavailable = family.implementation_status == ImplementationStatus::Missing
        && matches!(
            family.activation.predicate,
            ActivationPredicate::Unavailable
        );
    match &entry.outcome {
        EntryOutcome::Effective => {
            !unavailable
                && entry.requested.is_some()
                && entry.effective.is_some()
                && (entry.requested != entry.effective) != entry.adjustments.is_empty()
        }
        EntryOutcome::Inactive { cause } => {
            !unavailable
                && entry.effective.is_none()
                && entry.adjustments.is_empty()
                && valid_inactive_cause(cause, family)
        }
        EntryOutcome::Unavailable => {
            unavailable
                && entry.requested.is_none()
                && entry.effective.is_none()
                && entry.adjustments.is_empty()
        }
        EntryOutcome::Unresolved { reason } => {
            !unavailable
                && entry.effective.is_none()
                && entry.adjustments.is_empty()
                && match reason {
                    UnresolvedReason::ExternalConstraintMissing { .. } => entry.requested.is_some(),
                    UnresolvedReason::ResolverEvidenceMissing { .. }
                    | UnresolvedReason::ResolverReturnedAbsent { .. }
                    | UnresolvedReason::ResolverUnsupported { .. } => entry.requested.is_none(),
                }
                && valid_unresolved_reason(reason, family)
        }
        EntryOutcome::Rejected { reason } => {
            !unavailable
                && entry.effective.is_none()
                && entry.requested.is_some()
                && valid_rejection_reason(reason, family)
        }
    }
}

fn valid_provenance(
    provenance: &ResolutionProvenance,
    family: &Family,
    report_profile_digest: Option<&str>,
) -> bool {
    match &provenance.source {
        ResolutionSource::Declared {
            kind,
            trust,
            declared_locator,
            evidence_digest_sha256,
        } => {
            valid_sha256(evidence_digest_sha256)
                && family.source.bindings.iter().any(|binding| {
                    binding.kind == *kind
                        && binding.trust == *trust
                        && binding.locator == *declared_locator
                })
        }
        ResolutionSource::Profile {
            kind,
            trust,
            declared_locator,
            profile_digest_sha256,
            ..
        } => {
            matches!(kind, SourceKind::UserConfig | SourceKind::ProjectConfig)
                && report_profile_digest == Some(profile_digest_sha256)
                && family.source.bindings.iter().any(|binding| {
                    binding.kind == *kind
                        && binding.trust == *trust
                        && binding.locator == *declared_locator
                })
        }
        ResolutionSource::Default {
            resolver_id,
            evidence_digest_sha256,
            subject,
            fallback,
        } => {
            if !resolver_id_matches(family.default.resolver, resolver_id) {
                false
            } else {
                match family.default.resolver {
                    DefaultResolver::Literal => {
                        !*fallback && evidence_digest_sha256.is_none() && subject.is_none()
                    }
                    resolver if *fallback => {
                        family.default.value.is_some()
                            && match (evidence_digest_sha256.as_deref(), subject.as_ref()) {
                                (None, None) => true,
                                (Some(digest), Some(subject)) => {
                                    valid_sha256(digest) && subject_matches(resolver, subject)
                                }
                                _ => false,
                            }
                    }
                    resolver => {
                        evidence_digest_sha256.as_deref().is_some_and(valid_sha256)
                            && subject
                                .as_ref()
                                .is_some_and(|subject| subject_matches(resolver, subject))
                    }
                }
            }
        }
    }
}

fn resolver_id_matches(resolver: DefaultResolver, actual: &str) -> bool {
    match resolver {
        DefaultResolver::Literal => actual == "iteron://tunables/resolvers/literal-v1",
        DefaultResolver::Builtin { resolver_id } => actual == resolver_id,
        DefaultResolver::ModelMetadata { field } => {
            actual == format!("iteron://tunables/resolvers/model-metadata/{field}-v1")
        }
        DefaultResolver::ProviderCapability { capability } => {
            actual == format!("iteron://tunables/resolvers/provider-capability/{capability}-v1")
        }
        DefaultResolver::Transport { field } => {
            actual == format!("iteron://tunables/resolvers/transport/{field}-v1")
        }
        DefaultResolver::RuntimeObservation { field } => {
            actual == format!("iteron://tunables/resolvers/runtime-observation/{field}-v1")
        }
        DefaultResolver::GovernedCatalog { catalog_id } => actual == catalog_id,
        DefaultResolver::Operator { input_id } => actual == input_id,
    }
}

fn subject_matches(resolver: DefaultResolver, subject: &crate::EvidenceSubject) -> bool {
    match (resolver, subject) {
        (DefaultResolver::Builtin { .. }, crate::EvidenceSubject::Global) => true,
        (
            DefaultResolver::ModelMetadata { .. }
            | DefaultResolver::ProviderCapability { .. }
            | DefaultResolver::Transport { .. },
            crate::EvidenceSubject::Route { .. },
        ) => true,
        (
            DefaultResolver::RuntimeObservation { field },
            crate::EvidenceSubject::RuntimeSeam {
                seam,
                subject_digest_sha256,
            },
        ) => field == seam && valid_sha256(subject_digest_sha256),
        (
            DefaultResolver::GovernedCatalog { catalog_id },
            crate::EvidenceSubject::Catalog {
                catalog_id: actual,
                digest_sha256,
            },
        ) => catalog_id == actual && valid_sha256(digest_sha256),
        (
            DefaultResolver::Operator { .. },
            crate::EvidenceSubject::Operator {
                authority_digest_sha256,
            },
        ) => valid_sha256(authority_digest_sha256),
        _ => false,
    }
}

fn valid_inactive_cause(cause: &InactiveCause, family: &Family) -> bool {
    match cause {
        InactiveCause::Activation { reason } => family.activation.inactive_reason == Some(*reason),
        InactiveCause::RuntimeSeamMissing { seam }
        | InactiveCause::RuntimeSeamInactive { seam } => matches!(
            family.activation.predicate,
            ActivationPredicate::RuntimeDerived { seam: expected } if expected == *seam
        ),
        InactiveCause::ProviderRouteMissing { requirement } => {
            *requirement != ProviderRequirement::None
                && family.requirements.provider == *requirement
        }
        InactiveCause::CapabilitiesMissing { capabilities, .. } => {
            !capabilities.is_empty()
                && capabilities.windows(2).all(|pair| pair[0] < pair[1])
                && capabilities
                    .iter()
                    .all(|capability| family.requirements.capabilities.contains(capability))
        }
    }
}

fn valid_unresolved_reason(reason: &UnresolvedReason, family: &Family) -> bool {
    match reason {
        UnresolvedReason::ResolverEvidenceMissing { resolver_id } => {
            resolver_id_matches(family.default.resolver, resolver_id)
                && (family.default.value.is_none() || default_requires_runtime_catalog(family))
        }
        UnresolvedReason::ResolverReturnedAbsent { resolver_id, code }
        | UnresolvedReason::ResolverUnsupported { resolver_id, code } => {
            family.default.value.is_none()
                && resolver_id_matches(family.default.resolver, resolver_id)
                && safe_code(code)
        }
        UnresolvedReason::ExternalConstraintMissing { field, ceiling } => {
            external_rule(family, field, *ceiling).is_some()
        }
    }
}

fn default_requires_runtime_catalog(family: &Family) -> bool {
    let Some(default) = family.default.value else {
        return false;
    };
    let mut value = crate::resolution_value::owned(default);
    crate::resolution_value::normalize(&mut value);
    crate::resolution_value::validate(
        &value,
        family.value_schema,
        &std::collections::BTreeMap::new(),
    )
    .is_err()
}

fn valid_rejection_reason(reason: &RejectionReason, family: &Family) -> bool {
    match reason {
        RejectionReason::ProviderRequirement {
            requirement,
            route,
            missing_capabilities,
        } => {
            if *requirement == ProviderRequirement::None
                || family.requirements.provider != *requirement
            {
                return false;
            }
            if route.is_none() {
                let mut expected = family.requirements.capabilities.to_vec();
                expected.sort_unstable();
                expected.dedup();
                return missing_capabilities == &expected;
            }
            !missing_capabilities.is_empty()
                && missing_capabilities
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && missing_capabilities
                    .iter()
                    .all(|item| family.requirements.capabilities.contains(item))
        }
        RejectionReason::ExternalConstraint {
            field,
            ceiling,
            evidence_digest_sha256,
            detail_code,
        } => {
            external_rule(family, field, *ceiling).is_some()
                && valid_sha256(evidence_digest_sha256)
                && safe_code(detail_code)
        }
        RejectionReason::CrossFieldRule { detail_code } => {
            !family.value_schema.rules.is_empty() && safe_code(detail_code)
        }
    }
}

fn valid_adjustment(adjustment: &Adjustment, family: &Family) -> bool {
    let Some(violation) = external_rule(family, &adjustment.field, adjustment.ceiling) else {
        return false;
    };
    let policy_matches = match (adjustment.kind, violation) {
        (AdjustmentKind::ClampMaximum, ConstraintViolation::ClampNumeric) => {
            adjustment.policy_id == "iteron://tunables/adjustments/clamp-numeric-v1"
        }
        (AdjustmentKind::ProviderDegrade, ConstraintViolation::DegradeAttested { policy_id }) => {
            adjustment.policy_id == policy_id
        }
        _ => false,
    };
    policy_matches
        && adjustment.requested != adjustment.effective
        && valid_sha256(&adjustment.evidence_digest_sha256)
        && crate::resolution_value::validate_report_at(
            &adjustment.requested,
            family.value_schema,
            &adjustment.field,
        )
        .is_ok()
        && crate::resolution_value::validate_report_at(
            &adjustment.effective,
            family.value_schema,
            &adjustment.field,
        )
        .is_ok()
}

fn external_rule(
    family: &Family,
    field: &str,
    ceiling: ExternalCeiling,
) -> Option<ConstraintViolation> {
    family
        .value_schema
        .rules
        .iter()
        .find_map(|rule| match rule {
            CrossFieldRule::ExternalCeiling {
                field: expected,
                ceiling: expected_ceiling,
                violation,
                ..
            } if *expected == field && *expected_ceiling == ceiling => Some(*violation),
            _ => None,
        })
}

pub(super) fn valid_shadowed_reason(value: &str) -> bool {
    matches!(value, "same_source_profile_overridden" | "lower_precedence")
}

fn safe_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REASON_CODE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'$' | b'@' | b'+')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

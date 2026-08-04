use crate::resolution_prepare::{PreparedInput, canonical_family};
use crate::resolution_types::{
    Adjustment, AdjustmentKind, CatalogSnapshot, ConstraintValue, EvidenceSubject, RejectionReason,
    ResolutionInput, ResolutionValue, UnresolvedReason,
};
use crate::{
    ConstraintProjection, ConstraintRelation, ConstraintViolation, CrossFieldRule, ExternalCeiling,
    Family, ImplementationStatus,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[path = "resolution_constraints_domain.rs"]
mod domain;

pub(crate) enum ConstraintResult {
    Effective {
        value: ResolutionValue,
        adjustments: Vec<Adjustment>,
    },
    Unresolved(UnresolvedReason),
    Rejected(RejectionReason),
}

pub(crate) fn validate_evidence_set(input: &ResolutionInput) -> Result<(), String> {
    let catalogs: BTreeMap<&str, &CatalogSnapshot> = input
        .runtime
        .catalogs
        .iter()
        .map(|catalog| (catalog.catalog_id.as_str(), catalog))
        .collect();
    let mut seen = BTreeSet::new();
    for evidence in &input.constraint_evidence {
        let family = canonical_family(&evidence.family)?;
        if family.implementation_status == ImplementationStatus::Missing
            || !seen.insert((family.id, evidence.field.as_str(), evidence.ceiling))
            || !crate::resolution_value::valid_sha256(&evidence.evidence_digest_sha256)
        {
            return Err("constraint evidence is unavailable, duplicated, or unattested".into());
        }
        let Some((projection, relation, violation)) =
            external_rule(family, &evidence.field, evidence.ceiling)
        else {
            return Err("constraint evidence does not match a registry-owned rule".into());
        };
        validate_subject(evidence.ceiling, &evidence.subject, input)?;
        match (relation, &evidence.value) {
            (ConstraintRelation::UpperBound, ConstraintValue::UpperBound { value }) => {
                if !matches!(violation, ConstraintViolation::ClampNumeric) {
                    return Err("upper-bound rule has a non-clamp registry action".into());
                }
                domain::validate_upper_bound(family, &evidence.field, value)?;
            }
            (ConstraintRelation::Exact, ConstraintValue::Exact { value }) => {
                if !matches!(violation, ConstraintViolation::Reject) {
                    return Err("exact rule has a non-reject registry action".into());
                }
                domain::validate_exact(family, &evidence.field, projection, value, &catalogs)?;
            }
            (ConstraintRelation::AttestedDomain, value @ ConstraintValue::Domain { .. }) => {
                match (evidence.ceiling, violation) {
                    (
                        ExternalCeiling::ProviderCapability,
                        ConstraintViolation::DegradeAttested { .. },
                    )
                    | (_, ConstraintViolation::Reject) => {}
                    _ => return Err("attested-domain rule has an invalid registry action".into()),
                }
                domain::validate_domain(
                    family,
                    &evidence.field,
                    evidence.ceiling,
                    projection,
                    value,
                    &catalogs,
                )?;
            }
            _ => {
                return Err("constraint relation and evidence variant do not match exactly".into());
            }
        }
    }
    Ok(())
}

pub(crate) fn apply(
    family: &Family,
    prepared: &PreparedInput,
    requested: &ResolutionValue,
) -> ConstraintResult {
    let catalogs: BTreeMap<&str, &CatalogSnapshot> = prepared
        .input
        .runtime
        .catalogs
        .iter()
        .map(|catalog| (catalog.catalog_id.as_str(), catalog))
        .collect();
    let mut effective = requested.clone();
    let mut adjustments = Vec::new();
    for rule in family.value_schema.rules {
        let CrossFieldRule::ExternalCeiling {
            field,
            ceiling,
            projection,
            relation,
            violation,
        } = *rule
        else {
            continue;
        };
        let Some(current) = projected_value(&effective, field, projection).cloned() else {
            continue;
        };
        let Some(evidence) = prepared.constraint(family.id, field, ceiling) else {
            return ConstraintResult::Unresolved(UnresolvedReason::ExternalConstraintMissing {
                field: field.to_owned(),
                ceiling,
            });
        };
        let replacement = match (relation, violation, &evidence.value) {
            (
                ConstraintRelation::UpperBound,
                ConstraintViolation::ClampNumeric,
                ConstraintValue::UpperBound { value },
            ) => match crate::resolution_value::numeric_cmp(&current, value) {
                Some(Ordering::Greater) => Some((
                    value.clone(),
                    AdjustmentKind::ClampMaximum,
                    "core://tunables/adjustments/clamp-numeric-v1",
                )),
                Some(Ordering::Less | Ordering::Equal) => None,
                None => {
                    return rejected(field, ceiling, evidence, "constraint_numeric_type_mismatch");
                }
            },
            (
                ConstraintRelation::Exact,
                ConstraintViolation::Reject,
                ConstraintValue::Exact { value },
            ) if current == *value => None,
            (
                ConstraintRelation::Exact,
                ConstraintViolation::Reject,
                ConstraintValue::Exact { .. },
            ) => {
                return rejected(field, ceiling, evidence, "constraint_exact_mismatch");
            }
            (
                ConstraintRelation::AttestedDomain,
                ConstraintViolation::Reject,
                value @ ConstraintValue::Domain { .. },
            ) if domain::admits_value(family, field, projection, &current, value) => None,
            (
                ConstraintRelation::AttestedDomain,
                ConstraintViolation::Reject,
                ConstraintValue::Domain { .. },
            ) => {
                return rejected(field, ceiling, evidence, "constraint_domain_violation");
            }
            (
                ConstraintRelation::AttestedDomain,
                ConstraintViolation::DegradeAttested { .. },
                value @ ConstraintValue::Domain { .. },
            ) if domain::admits_value(family, field, projection, &current, value) => None,
            (
                ConstraintRelation::AttestedDomain,
                ConstraintViolation::DegradeAttested { policy_id },
                value @ ConstraintValue::Domain { .. },
            ) => {
                let Some(preferred) = domain::preferred(value) else {
                    return rejected(
                        field,
                        ceiling,
                        evidence,
                        "constraint_degrade_preferred_missing",
                    );
                };
                Some((
                    preferred.clone(),
                    AdjustmentKind::ProviderDegrade,
                    policy_id,
                ))
            }
            _ => {
                return rejected(
                    field,
                    ceiling,
                    evidence,
                    "constraint_registry_contract_mismatch",
                );
            }
        };
        if let Some((replacement, kind, policy_id)) = replacement {
            if projection != ConstraintProjection::WholeValue
                || crate::resolution_value::replace_at(&mut effective, field, replacement.clone())
                    .is_err()
            {
                return ConstraintResult::Rejected(RejectionReason::CrossFieldRule {
                    detail_code: "constraint_adjustment_path_invalid",
                });
            }
            adjustments.push(Adjustment {
                kind,
                field: field.to_owned(),
                requested: current,
                effective: replacement,
                ceiling,
                policy_id,
                evidence_digest_sha256: evidence.evidence_digest_sha256.clone(),
                subject: evidence.subject.clone(),
            });
        }
    }
    if crate::resolution_value::validate(&effective, family.value_schema, &catalogs).is_err() {
        return ConstraintResult::Rejected(RejectionReason::CrossFieldRule {
            detail_code: "constraint_adjustment_violates_schema",
        });
    }
    for rule in family.value_schema.rules {
        let CrossFieldRule::ExternalCeiling {
            field,
            ceiling,
            projection,
            relation,
            ..
        } = *rule
        else {
            continue;
        };
        let Some(current) = projected_value(&effective, field, projection) else {
            continue;
        };
        let Some(evidence) = prepared.constraint(family.id, field, ceiling) else {
            return ConstraintResult::Unresolved(UnresolvedReason::ExternalConstraintMissing {
                field: field.to_owned(),
                ceiling,
            });
        };
        if !constraint_satisfied(
            family,
            field,
            projection,
            relation,
            current,
            &evidence.value,
        ) {
            return rejected(field, ceiling, evidence, "constraint_adjustment_conflict");
        }
    }
    ConstraintResult::Effective {
        value: effective,
        adjustments,
    }
}

fn projected_value<'a>(
    value: &'a ResolutionValue,
    field: &str,
    projection: ConstraintProjection,
) -> Option<&'a ResolutionValue> {
    match projection {
        ConstraintProjection::WholeValue => crate::resolution_value::value_at(value, field),
        ConstraintProjection::WholeCatalog => Some(value),
    }
}

fn constraint_satisfied(
    family: &Family,
    field: &str,
    projection: ConstraintProjection,
    relation: ConstraintRelation,
    current: &ResolutionValue,
    evidence: &ConstraintValue,
) -> bool {
    match (relation, evidence) {
        (ConstraintRelation::UpperBound, ConstraintValue::UpperBound { value }) => {
            crate::resolution_value::numeric_cmp(current, value)
                .is_some_and(|ordering| ordering != Ordering::Greater)
        }
        (ConstraintRelation::Exact, ConstraintValue::Exact { value }) => current == value,
        (ConstraintRelation::AttestedDomain, value @ ConstraintValue::Domain { .. }) => {
            domain::admits_value(family, field, projection, current, value)
        }
        _ => false,
    }
}

fn rejected(
    field: &str,
    ceiling: ExternalCeiling,
    evidence: &crate::resolution_types::ConstraintEvidence,
    detail_code: &'static str,
) -> ConstraintResult {
    ConstraintResult::Rejected(RejectionReason::ExternalConstraint {
        field: field.to_owned(),
        ceiling,
        evidence_digest_sha256: evidence.evidence_digest_sha256.clone(),
        detail_code,
    })
}

fn external_rule(
    family: &Family,
    field: &str,
    ceiling: ExternalCeiling,
) -> Option<(
    ConstraintProjection,
    ConstraintRelation,
    ConstraintViolation,
)> {
    family
        .value_schema
        .rules
        .iter()
        .find_map(|rule| match *rule {
            CrossFieldRule::ExternalCeiling {
                field: actual,
                ceiling: actual_ceiling,
                projection,
                relation,
                violation,
            } if actual == field && actual_ceiling == ceiling => {
                Some((projection, relation, violation))
            }
            _ => None,
        })
}

fn validate_subject(
    ceiling: ExternalCeiling,
    subject: &EvidenceSubject,
    input: &ResolutionInput,
) -> Result<(), String> {
    let valid = match ceiling {
        ExternalCeiling::OperatorAuthority => matches!(subject, EvidenceSubject::Operator { .. }),
        ExternalCeiling::ProviderCapability | ExternalCeiling::ContextWindow => matches!(
            (subject, input.runtime.selected_route.as_ref()),
            (EvidenceSubject::Route { route }, Some(selected)) if route == selected
        ),
        _ => matches!(
            subject,
            EvidenceSubject::RuntimeSeam { seam, subject_digest_sha256 }
                if seam == constraint_seam(ceiling)
                    && crate::resolution_value::valid_sha256(subject_digest_sha256)
        ),
    };
    if valid {
        Ok(())
    } else {
        Err("constraint evidence subject does not match its registry ceiling".into())
    }
}

pub(crate) const fn constraint_seam(ceiling: ExternalCeiling) -> &'static str {
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

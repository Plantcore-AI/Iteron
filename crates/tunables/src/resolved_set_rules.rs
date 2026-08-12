use crate::{
    ActivationPredicate, CrossFieldRule, EntryOutcome, Family, ImplementationStatus, RegistryError,
    RejectionReason, ResolutionValue, ResolvedEntry, ResolvedValuePath,
};
use std::collections::BTreeSet;

const SUM_EXCEEDS_LIMIT: &str = "resolved_set_sum_exceeds_limit";
const SUM_OVERFLOW: &str = "resolved_set_sum_overflow";

pub(crate) fn validate_registry(registry: &[Family]) -> Result<(), RegistryError> {
    let mut ids = BTreeSet::new();
    for owner in registry {
        for rule in owner.value_schema.rules {
            let CrossFieldRule::ResolvedSetSumLessOrEqual {
                rule_id,
                terms,
                limit,
            } = *rule
            else {
                continue;
            };
            if !ids.insert(rule_id) {
                return Err(RegistryError::DuplicateResolvedSetRule(rule_id));
            }
            if limit.family != owner.id {
                return invalid(rule_id, "limit is not owned by the declaring family");
            }
            let unique = terms.iter().copied().collect::<BTreeSet<_>>();
            if terms.len() < 2 || unique.len() != terms.len() || terms.contains(&limit) {
                return invalid(rule_id, "terms are empty, duplicated, or include the limit");
            }
            for path in terms.iter().chain(std::iter::once(&limit)) {
                let Some(family) = registry.iter().find(|family| family.id == path.family) else {
                    return invalid(rule_id, "path names an unknown family");
                };
                if family.implementation_status == ImplementationStatus::Missing
                    || !matches!(family.activation.predicate, ActivationPredicate::Always)
                {
                    return invalid(rule_id, "path family is not always resolution-effective");
                }
                if !crate::validate::path_is_required_integer(family.value_schema.domain, path.path)
                {
                    return invalid(rule_id, "path is not a required integer value");
                }
            }
        }
    }
    Ok(())
}

fn invalid(rule_id: &'static str, reason: &'static str) -> Result<(), RegistryError> {
    Err(RegistryError::InvalidResolvedSetRule(rule_id, reason))
}

/// Apply every canonical resolved-set rule before any success digest is constructed. A rule is
/// evaluated only when all of its always-active members are effective; an earlier per-family
/// failure remains the primary atomic failure otherwise.
pub(crate) fn enforce(entries: &mut [ResolvedEntry]) -> Result<(), String> {
    let violations = violations(entries)?;
    for (owner, detail_code) in violations {
        let entry = entries
            .iter_mut()
            .find(|entry| entry.family_id == owner)
            .ok_or_else(|| format!("resolved-set rule owner `{owner}` is absent"))?;
        if !matches!(entry.outcome, EntryOutcome::Effective) {
            continue;
        }
        entry.effective = None;
        entry.adjustments.clear();
        entry.outcome = EntryOutcome::Rejected {
            reason: RejectionReason::CrossFieldRule { detail_code },
        };
    }
    Ok(())
}

/// Reject a forged or stale all-effective report whose cross-family values no longer satisfy the
/// same canonical resolver contract.
pub(crate) fn validate_report(entries: &[ResolvedEntry]) -> Result<(), String> {
    if let Some((owner, detail)) = violations(entries)?.into_iter().next() {
        return Err(format!(
            "resolved-set rule owned by `{owner}` failed with `{detail}`"
        ));
    }
    Ok(())
}

fn violations(entries: &[ResolvedEntry]) -> Result<Vec<(&'static str, &'static str)>, String> {
    let mut violations = Vec::new();
    for owner in crate::families() {
        for rule in owner.value_schema.rules {
            let CrossFieldRule::ResolvedSetSumLessOrEqual { terms, limit, .. } = *rule else {
                continue;
            };
            let Some(limit) = resolved_integer(entries, limit, false)? else {
                continue;
            };
            let mut sum = 0i128;
            let mut complete = true;
            for term in terms {
                let Some(value) = resolved_integer(entries, *term, true)? else {
                    complete = false;
                    break;
                };
                let Some(next) = sum.checked_add(value) else {
                    violations.push((owner.id, SUM_OVERFLOW));
                    complete = false;
                    break;
                };
                sum = next;
            }
            if complete && sum > limit {
                violations.push((owner.id, SUM_EXCEEDS_LIMIT));
            }
        }
    }
    Ok(violations)
}

fn resolved_integer(
    entries: &[ResolvedEntry],
    path: ResolvedValuePath,
    inactive_is_zero: bool,
) -> Result<Option<i128>, String> {
    let entry = entries
        .iter()
        .find(|entry| entry.family_id == path.family)
        .ok_or_else(|| format!("resolved-set path family `{}` is absent", path.family))?;
    match entry.outcome {
        EntryOutcome::Effective => {}
        EntryOutcome::Inactive { .. } | EntryOutcome::Unavailable if inactive_is_zero => {
            return Ok(Some(0));
        }
        EntryOutcome::Inactive { .. }
        | EntryOutcome::Unavailable
        | EntryOutcome::Unresolved { .. }
        | EntryOutcome::Rejected { .. } => return Ok(None),
    }
    let root = entry
        .effective
        .as_ref()
        .ok_or_else(|| format!("effective family `{}` has no value", path.family))?;
    match crate::resolution_value::value_at(root, path.path) {
        Some(ResolutionValue::Integer { value }) => Ok(Some(i128::from(*value))),
        Some(_) => Err(format!(
            "resolved-set path `{}:{}` is not integer-valued",
            path.family, path.path
        )),
        None => Err(format!(
            "resolved-set path `{}:{}` is absent",
            path.family, path.path
        )),
    }
}

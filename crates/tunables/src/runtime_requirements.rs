//! Bounded, read-only inventory for trusted production composition roots.
//!
//! These helpers expose registry truth without manufacturing values, authority, or evidence. A
//! caller must still observe every named runtime fact and submit it through
//! [`crate::RuntimeResolutionBuilder`].

use crate::{
    ActivationPredicate, ConstraintProjection, ConstraintRelation, ConstraintViolation,
    CrossFieldRule, DefaultResolver, ExternalCeiling, Family, ImplementationStatus,
    ResolutionValue, families,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDefaultObservation {
    pub family_id: &'static str,
    pub resolver: DefaultResolver,
    pub fallback_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConstraintRequirement {
    pub family_id: &'static str,
    pub field: &'static str,
    pub ceiling: ExternalCeiling,
    pub relation: ConstraintRelation,
    pub projection: ConstraintProjection,
    pub violation: ConstraintViolation,
}

/// One independently observed runtime activation fact.
///
/// `seam` names the production owner location; `family_id` is the semantic identity. Multiple
/// families may deliberately share a seam and must still submit distinct observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuntimeActivationRequirement {
    pub family_id: &'static str,
    pub seam: &'static str,
}

/// Resolve a canonical family identity or one of its declared aliases.
pub fn canonical_family(identity: &str) -> Option<&'static Family> {
    families()
        .iter()
        .find(|family| family.id == identity || family.aliases.contains(&identity))
}

/// Return an owned copy of the registry-embedded literal or resolver fallback, if one exists.
///
/// This does not run a resolver and does not attest that the fallback is applicable to a route.
pub fn canonical_embedded_default(identity: &str) -> Option<ResolutionValue> {
    canonical_family(identity)
        .and_then(|family| family.default.value)
        .map(crate::resolution_value::owned)
}

/// Complete runtime-derived activation inventory. There is exactly one entry per family, including
/// when several entries declare the same production seam.
pub fn runtime_activation_requirements() -> Vec<RuntimeActivationRequirement> {
    let mut requirements = families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            ActivationPredicate::RuntimeDerived { seam } => Some(RuntimeActivationRequirement {
                family_id: family.id,
                seam,
            }),
            ActivationPredicate::Always
            | ActivationPredicate::Configured { .. }
            | ActivationPredicate::Unavailable => None,
        })
        .collect::<Vec<_>>();
    requirements.sort_unstable();
    requirements
}

/// Named default observations a composition root may have to supply when no authorized declared
/// value wins. Literal defaults are omitted because their bytes are already registry-owned.
pub fn runtime_default_observations() -> Vec<RuntimeDefaultObservation> {
    families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .filter_map(|family| {
            (!matches!(family.default.resolver, DefaultResolver::Literal)).then_some(
                RuntimeDefaultObservation {
                    family_id: family.id,
                    resolver: family.default.resolver,
                    fallback_available: family.default.value.is_some(),
                },
            )
        })
        .collect()
}

/// Complete, deterministic external-constraint inventory. Whether an entry is needed for one run
/// still depends on that family's explicit activation and selected route.
pub fn runtime_constraint_requirements() -> Vec<RuntimeConstraintRequirement> {
    families()
        .iter()
        .flat_map(|family| {
            family.value_schema.rules.iter().filter_map(move |rule| {
                let CrossFieldRule::ExternalCeiling {
                    field,
                    ceiling,
                    relation,
                    projection,
                    violation,
                } = *rule
                else {
                    return None;
                };
                Some(RuntimeConstraintRequirement {
                    family_id: family.id,
                    field,
                    ceiling,
                    relation,
                    projection,
                    violation,
                })
            })
        })
        .collect()
}

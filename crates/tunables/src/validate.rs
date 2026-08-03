use crate::{
    ActivationPredicate, AuthorityClass, FAMILY_SCHEMA_VERSION, ImplementationStatus,
    OptimizationClass, SearchPhase, SourceKind, StructuredValueDomain, families,
};
use std::collections::{BTreeMap, BTreeSet};

/// Stable identities retired because they duplicate another semantic family.
const SEMANTIC_DUPLICATE_DENYLIST: &[&str] = &["delegation_depth"];

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry has {actual} families; expected exactly {expected}")]
    WrongFamilyCount { expected: usize, actual: usize },
    #[error("family ordinal {actual} is not the expected contiguous ordinal {expected}")]
    NonContiguousOrdinal { expected: u16, actual: u16 },
    #[error("family `{family}` has schema version {actual}; expected {expected}")]
    WrongFamilySchemaVersion {
        family: &'static str,
        expected: u16,
        actual: u16,
    },
    #[error("invalid stable family id or alias `{0}`")]
    InvalidFamilyId(&'static str),
    #[error("duplicate stable family id `{0}`")]
    DuplicateFamilyId(&'static str),
    #[error("alias `{alias}` on `{owner}` collides with `{existing}`")]
    AliasCollision {
        alias: &'static str,
        owner: &'static str,
        existing: &'static str,
    },
    #[error("retired semantic duplicate `{0}` is forbidden")]
    SemanticDuplicate(&'static str),
    #[error("family `{0}` has incomplete metadata")]
    IncompleteMetadata(&'static str),
    #[error("family `{0}` has an invalid structured value domain: {1}")]
    InvalidValueDomain(&'static str, &'static str),
    #[error("referenced schema catalog entry `{0}` is invalid or duplicated")]
    InvalidReferencedSchema(&'static str),
    #[error("family `{0}` has activation inconsistent with its implementation status")]
    InvalidActivation(&'static str),
    #[error("family `{0}` has no capability requirement")]
    MissingCapabilityRequirement(&'static str),
    #[error("family `{0}` must bind one or more unique core StrategySlots")]
    InvalidStrategySlots(&'static str),
    #[error("family `{0}` has source trust inconsistent with its source kind")]
    InvalidSourceTrust(&'static str),
    #[error("family `{0}` has a default resolution source inconsistent with its default kind")]
    InvalidDefaultSource(&'static str),
    #[error("family `{0}` has an inconsistent optimization class/search phase")]
    InvalidOptimization(&'static str),
    #[error("family `{0}` assigns learnable optimization to invariant authority")]
    LearnableInvariant(&'static str),
    #[error("family `{0}` claims implemented code but cites only the registry")]
    ImplementedRegistryOnly(&'static str),
    #[error("cannot encode the canonical registry: {0}")]
    CanonicalEncoding(#[source] serde_json::Error),
}

pub fn validate_registry() -> Result<(), RegistryError> {
    validate_schema_catalog()?;
    validate_families(families())
}

fn validate_schema_catalog() -> Result<(), RegistryError> {
    let mut ids = BTreeSet::new();
    for schema in crate::REFERENCED_SCHEMAS {
        if !schema.id.starts_with("core://")
            || !ids.insert(schema.id)
            || schema.max_bytes == 0
            || schema.max_nodes == 0
            || schema.max_depth == 0
        {
            return Err(RegistryError::InvalidReferencedSchema(schema.id));
        }
    }
    Ok(())
}

fn validate_families(families: &[crate::Family]) -> Result<(), RegistryError> {
    if families.len() != crate::EXPECTED_FAMILY_COUNT {
        return Err(RegistryError::WrongFamilyCount {
            expected: crate::EXPECTED_FAMILY_COUNT,
            actual: families.len(),
        });
    }

    let mut identities = BTreeMap::<&'static str, &'static str>::new();
    for (index, family) in families.iter().enumerate() {
        let expected = u16::try_from(index + 1).expect("160 ordinals fit in u16");
        if family.ordinal != expected {
            return Err(RegistryError::NonContiguousOrdinal {
                expected,
                actual: family.ordinal,
            });
        }
        if family.schema_version != FAMILY_SCHEMA_VERSION {
            return Err(RegistryError::WrongFamilySchemaVersion {
                family: family.id,
                expected: FAMILY_SCHEMA_VERSION,
                actual: family.schema_version,
            });
        }
        validate_identity(family.id)?;
        if identities.insert(family.id, family.id).is_some() {
            return Err(RegistryError::DuplicateFamilyId(family.id));
        }
        if family.summary.trim().is_empty()
            || family.default.value.trim().is_empty()
            || family.source.locator.trim().is_empty()
            || family.benchmark_relevance.rationale.trim().is_empty()
        {
            return Err(RegistryError::IncompleteMetadata(family.id));
        }
    }

    for family in families {
        for alias in family.aliases {
            validate_identity(alias)?;
            if *alias == family.id {
                return Err(RegistryError::AliasCollision {
                    alias,
                    owner: family.id,
                    existing: family.id,
                });
            }
            if let Some(existing) = identities.insert(alias, family.id) {
                return Err(RegistryError::AliasCollision {
                    alias,
                    owner: family.id,
                    existing,
                });
            }
        }
        validate_activation(family)?;
        validate_requirements_and_slots(family)?;
        validate_source(family)?;
        if family.default.resolution_source
            != crate::metadata::default_resolution_source(family.ordinal, family.default.kind)
        {
            return Err(RegistryError::InvalidDefaultSource(family.id));
        }
        validate_value_domain(family)?;
        validate_optimization(family)?;
    }
    Ok(())
}

fn validate_identity(identity: &'static str) -> Result<(), RegistryError> {
    if SEMANTIC_DUPLICATE_DENYLIST.contains(&identity) {
        return Err(RegistryError::SemanticDuplicate(identity));
    }
    if !valid_id(identity) {
        return Err(RegistryError::InvalidFamilyId(identity));
    }
    Ok(())
}

fn validate_activation(family: &crate::Family) -> Result<(), RegistryError> {
    let valid = match family.implementation_status {
        ImplementationStatus::Missing => {
            matches!(
                family.activation.predicate,
                ActivationPredicate::Unavailable
            ) && family.activation.inactive_reason.is_some()
        }
        ImplementationStatus::Partial => {
            matches!(
                family.activation.predicate,
                ActivationPredicate::RuntimeDerived { .. }
            ) && family.activation.inactive_reason.is_some()
        }
        ImplementationStatus::Full => !matches!(
            family.activation.predicate,
            ActivationPredicate::Unavailable
        ),
        ImplementationStatus::FixedHidden => {
            matches!(family.activation.predicate, ActivationPredicate::Always)
                && family.activation.inactive_reason.is_none()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RegistryError::InvalidActivation(family.id))
    }
}

fn validate_requirements_and_slots(family: &crate::Family) -> Result<(), RegistryError> {
    if family.requirements.capabilities.is_empty() {
        return Err(RegistryError::MissingCapabilityRequirement(family.id));
    }
    let unique = family
        .strategy_slots
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if family.strategy_slots.is_empty() || unique.len() != family.strategy_slots.len() {
        return Err(RegistryError::InvalidStrategySlots(family.id));
    }
    Ok(())
}

fn validate_source(family: &crate::Family) -> Result<(), RegistryError> {
    if family.source.trust != crate::metadata::source_trust(family.ordinal, family.source.kind) {
        return Err(RegistryError::InvalidSourceTrust(family.id));
    }
    if family.source.kind == SourceKind::Registry
        && family.implementation_status != ImplementationStatus::Missing
    {
        return Err(RegistryError::ImplementedRegistryOnly(family.id));
    }
    Ok(())
}

fn validate_value_domain(family: &crate::Family) -> Result<(), RegistryError> {
    let invalid = |reason| Err(RegistryError::InvalidValueDomain(family.id, reason));
    if family.value_schema.description.trim().is_empty()
        || family.value_schema.constraints.is_empty()
        || family
            .value_schema
            .constraints
            .iter()
            .any(|constraint| constraint.trim().is_empty())
    {
        return invalid("description or constraints are empty");
    }
    let kind_matches = match family.value_schema.domain {
        StructuredValueDomain::Boolean => family.value_schema.kind == crate::ValueKind::Bool,
        StructuredValueDomain::Numeric { numeric_type, .. } => match family.value_schema.kind {
            crate::ValueKind::Count | crate::ValueKind::Duration | crate::ValueKind::Bytes => {
                numeric_type == crate::NumericType::Integer
            }
            crate::ValueKind::Ratio | crate::ValueKind::Decimal => {
                numeric_type == crate::NumericType::Decimal
            }
            _ => false,
        },
        StructuredValueDomain::FiniteEnum { .. } => {
            family.value_schema.kind == crate::ValueKind::Enum
        }
        StructuredValueDomain::Text { .. } => family.value_schema.kind == crate::ValueKind::String,
        StructuredValueDomain::List { .. } => family.value_schema.kind == crate::ValueKind::List,
        StructuredValueDomain::Map { .. } => family.value_schema.kind == crate::ValueKind::Map,
        StructuredValueDomain::Composite { .. } => {
            family.value_schema.kind == crate::ValueKind::Policy
        }
        StructuredValueDomain::Catalog { .. } => {
            family.value_schema.kind == crate::ValueKind::Catalog
        }
    };
    if !kind_matches {
        return invalid("value kind and tagged domain disagree");
    }
    match family.value_schema.domain {
        StructuredValueDomain::Boolean => Ok(()),
        StructuredValueDomain::Numeric { min, max, unit, .. } => {
            if unit.trim().is_empty() {
                invalid("numeric unit is empty")
            } else if min.is_none() || max.is_none() {
                invalid("numeric domain must have finite minimum and maximum")
            } else if matches!((min, max), (Some(minimum), Some(maximum)) if minimum > maximum) {
                invalid("numeric minimum exceeds maximum")
            } else {
                Ok(())
            }
        }
        StructuredValueDomain::FiniteEnum {
            values,
            open_catalog,
            catalog_ref,
        } => {
            let unique = values.iter().copied().collect::<BTreeSet<_>>();
            if (!open_catalog && values.is_empty())
                || values.iter().any(|value| value.trim().is_empty())
                || unique.len() != values.len()
            {
                invalid("finite enum values/open-catalog declaration is invalid")
            } else if open_catalog {
                match catalog_ref {
                    Some(schema_ref) => validate_schema_ref(family.id, schema_ref),
                    None => invalid("open enum has no admitted catalog reference"),
                }
            } else if catalog_ref.is_some() {
                invalid("closed enum unexpectedly names an open catalog")
            } else {
                Ok(())
            }
        }
        StructuredValueDomain::Text {
            min_bytes,
            max_bytes,
            format,
        } => validate_bounds_and_ref(
            family.id,
            min_bytes,
            max_bytes,
            format,
            "text byte bounds or format are invalid",
            false,
        ),
        StructuredValueDomain::List {
            min_items,
            max_items,
            item_schema,
            ..
        } => validate_bounds_and_ref(
            family.id,
            min_items,
            max_items,
            item_schema,
            "list item bounds or schema are invalid",
            true,
        ),
        StructuredValueDomain::Map {
            min_entries,
            max_entries,
            key_schema,
            value_schema,
        } => {
            validate_bounds_and_ref(
                family.id,
                min_entries,
                max_entries,
                key_schema,
                "map entry bounds or key schema are invalid",
                true,
            )?;
            validate_schema_ref(family.id, value_schema)
        }
        StructuredValueDomain::Composite {
            schema_ref,
            max_bytes,
            max_nodes,
            max_depth,
        } => {
            if max_bytes == 0 || max_nodes == 0 || max_depth == 0 {
                invalid("composite structural ceilings must be positive")
            } else {
                validate_schema_ref(family.id, schema_ref)
            }
        }
        StructuredValueDomain::Catalog {
            min_entries,
            max_entries,
            entry_schema,
            ..
        } => validate_bounds_and_ref(
            family.id,
            min_entries,
            max_entries,
            entry_schema,
            "catalog entry bounds or schema are invalid",
            true,
        ),
    }
}

fn validate_bounds_and_ref(
    family: &'static str,
    minimum: u64,
    maximum: Option<u64>,
    reference: &'static str,
    reason: &'static str,
    schema_reference: bool,
) -> Result<(), RegistryError> {
    if maximum.is_none()
        || maximum.is_some_and(|maximum| minimum > maximum)
        || reference.trim().is_empty()
        || (schema_reference && !crate::schema_catalog::contains_schema(reference))
    {
        Err(RegistryError::InvalidValueDomain(family, reason))
    } else {
        Ok(())
    }
}

fn validate_schema_ref(
    family: &'static str,
    schema_ref: &'static str,
) -> Result<(), RegistryError> {
    if schema_ref.starts_with("core://") && crate::schema_catalog::contains_schema(schema_ref) {
        Ok(())
    } else {
        Err(RegistryError::InvalidValueDomain(
            family,
            "schema reference is absent from the immutable core:// schema catalog",
        ))
    }
}

fn validate_optimization(family: &crate::Family) -> Result<(), RegistryError> {
    let phase_matches = matches!(
        (family.optimization.class, family.optimization.search_phase),
        (OptimizationClass::P1, SearchPhase::P1)
            | (OptimizationClass::P2, SearchPhase::P2)
            | (
                OptimizationClass::CStructured
                    | OptimizationClass::CArtifact
                    | OptimizationClass::CComponent,
                SearchPhase::Conditional
            )
            | (OptimizationClass::Pin, SearchPhase::Pinned)
    );
    let pin_reason_matches = if family.optimization.class == OptimizationClass::Pin {
        family.optimization.pin_reason.is_some()
    } else {
        family.optimization.pin_reason.is_none()
    };
    if !phase_matches || !pin_reason_matches {
        return Err(RegistryError::InvalidOptimization(family.id));
    }
    if matches!(
        family.authority_class,
        AuthorityClass::Operator
            | AuthorityClass::RuntimeInvariant
            | AuthorityClass::KernelInvariant
    ) && family.optimization.class != OptimizationClass::Pin
    {
        return Err(RegistryError::LearnableInvariant(family.id));
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !id.ends_with('_')
        && !id.contains("__")
}

#[cfg(test)]
mod tests {
    use super::{RegistryError, valid_id, validate_families};
    use crate::{StructuredValueDomain, families};

    #[test]
    fn stable_id_grammar_is_narrow() {
        assert!(valid_id("shell_timeout_output"));
        for invalid in ["", "Shell", "a-b", "_a", "a_", "a__b"] {
            assert!(!valid_id(invalid), "accepted `{invalid}`");
        }
    }

    #[test]
    fn alias_collisions_are_rejected_against_ids() {
        let mut registry = families().to_vec();
        registry[0].aliases = &["model"];
        assert!(matches!(
            validate_families(&registry),
            Err(RegistryError::AliasCollision {
                alias: "model",
                owner: "provider",
                existing: "model"
            })
        ));
    }

    #[test]
    fn retired_semantic_duplicates_are_rejected() {
        let mut registry = families().to_vec();
        registry[66].id = "delegation_depth";
        assert!(matches!(
            validate_families(&registry),
            Err(RegistryError::SemanticDuplicate("delegation_depth"))
        ));
    }

    #[test]
    fn invalid_structured_bounds_are_rejected() {
        let mut registry = families().to_vec();
        registry[4].value_schema.domain = StructuredValueDomain::Numeric {
            numeric_type: crate::NumericType::Integer,
            min: Some(10),
            max: Some(2),
            unit: "turns",
        };
        assert!(matches!(
            validate_families(&registry),
            Err(RegistryError::InvalidValueDomain(
                "max_turns",
                "numeric minimum exceeds maximum"
            ))
        ));
    }
}

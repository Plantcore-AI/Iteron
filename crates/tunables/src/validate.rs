use crate::{
    ActivationPredicate, AuthorityClass, CrossFieldRule, DefaultKind, DefaultResolver,
    DefaultValueRequirement, ExternalCeiling, FAMILY_SCHEMA_VERSION, ImplementationStatus,
    OptimizationClass, ProviderRequirement, SearchPhase, families,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "validate/default_value.rs"]
mod default_value;
#[path = "validate/source.rs"]
mod source;
#[path = "validate/value.rs"]
mod value;

pub(crate) fn path_is_required_integer(domain: crate::StructuredValueDomain, path: &str) -> bool {
    value::path_is_required_integer(domain, path)
}

/// Stable identities retired because they duplicate another semantic family.
const SEMANTIC_DUPLICATE_DENYLIST: &[&str] = &["delegation_depth", "workflow_spawn_cap"];
const EXPECTED_EXTERNAL_CONSTRAINT_POLICIES: usize = 196;

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
    #[error("invalid runtime-control semantic key `{0}`")]
    InvalidSemanticKey(&'static str),
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
    #[error("family `{0}` has activation inconsistent with its implementation status")]
    InvalidActivation(&'static str),
    #[error("family `{0}` has invalid source provenance")]
    InvalidSource(&'static str),
    #[error("family `{0}` has an invalid default contract")]
    InvalidDefault(&'static str),
    #[error("family `{0}` has no capability requirement")]
    MissingCapabilityRequirement(&'static str),
    #[error("family `{0}` has an invalid provider requirement")]
    InvalidProviderRequirement(&'static str),
    #[error("family `{0}` must bind one or more unique iteron StrategySlots")]
    InvalidStrategySlots(&'static str),
    #[error("family `{0}` has an invalid value schema: {1}")]
    InvalidValueDomain(&'static str, &'static str),
    #[error("resolved-set rule `{0}` is invalid: {1}")]
    InvalidResolvedSetRule(&'static str, &'static str),
    #[error("resolved-set rule ID `{0}` is duplicated")]
    DuplicateResolvedSetRule(&'static str),
    #[error("registry has {actual} external constraint policies; expected exactly {expected}")]
    WrongExternalConstraintPolicyCount { expected: usize, actual: usize },
    #[error("family `{family}` repeats external constraint policy `{field}` / {ceiling:?}")]
    DuplicateExternalConstraintPolicy {
        family: &'static str,
        field: &'static str,
        ceiling: ExternalCeiling,
    },
    #[error("scalar catalog `{0}` is invalid or duplicated")]
    InvalidScalarCatalog(&'static str),
    #[error("family `{0}` has an inconsistent optimization class/search phase")]
    InvalidOptimization(&'static str),
    #[error("family `{0}` has no complete canonical runtime binding")]
    InvalidRuntimeBinding(&'static str),
    #[error("family `{0}` assigns learnable optimization to invariant authority")]
    LearnableInvariant(&'static str),
    #[error("family `{0}` claims implemented code but cites only the registry")]
    ImplementedRegistryOnly(&'static str),
    #[error("families `{first}` and `{second}` both own runtime control `{semantic_key}`")]
    DuplicateSemanticKey {
        first: &'static str,
        second: &'static str,
        semantic_key: &'static str,
    },
    #[error(
        "family declaration ordinal {ordinal} / `{actual_id}` / `{actual_key}` does not match semantic-key ledger ordinal {expected_ordinal} / `{expected_id}` / `{expected_key}`"
    )]
    SemanticKeyMappingMismatch {
        ordinal: u16,
        actual_id: &'static str,
        actual_key: &'static str,
        expected_ordinal: u16,
        expected_id: &'static str,
        expected_key: &'static str,
    },
    #[error("family `{family}` at ordinal {ordinal} has no semantic-key ledger entry")]
    MissingSemanticKeyLedgerEntry { ordinal: u16, family: &'static str },
    #[error("registry digest mismatch: expected `{expected}`, computed `{actual}`")]
    RegistryDigestMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("cannot encode the canonical registry: {0}")]
    CanonicalEncoding(#[source] serde_json::Error),
}

pub fn validate_registry() -> Result<(), RegistryError> {
    validate_scalar_catalogs()?;
    let registry = families();
    validate_families(registry)?;
    let actual = crate::canonical::registry_digest_unvalidated()?.value;
    if actual != crate::REGISTRY_DIGEST_SHA256 {
        return Err(RegistryError::RegistryDigestMismatch {
            expected: crate::REGISTRY_DIGEST_SHA256,
            actual,
        });
    }
    Ok(())
}

fn validate_scalar_catalogs() -> Result<(), RegistryError> {
    let mut ids = BTreeSet::new();
    for catalog in crate::SCALAR_CATALOGS {
        if !catalog.id.starts_with("iteron://tunables/catalogs/")
            || !catalog.id.ends_with("-v1")
            || !ids.insert(catalog.id)
            || value::validate_scalar_domain(catalog.value_domain).is_err()
        {
            return Err(RegistryError::InvalidScalarCatalog(catalog.id));
        }
    }
    Ok(())
}

fn validate_families(registry: &[crate::Family]) -> Result<(), RegistryError> {
    if registry.len() != crate::EXPECTED_FAMILY_COUNT {
        return Err(RegistryError::WrongFamilyCount {
            expected: crate::EXPECTED_FAMILY_COUNT,
            actual: registry.len(),
        });
    }
    validate_semantic_ownership(registry)?;
    for (index, family) in registry.iter().enumerate() {
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
        if family.summary.trim().is_empty()
            || family.benchmark_relevance.rationale.trim().is_empty()
        {
            return Err(RegistryError::IncompleteMetadata(family.id));
        }
    }
    for family in registry {
        validate_activation(family)?;
        source::validate(family)?;
        validate_default(family)?;
        validate_requirements_and_slots(family)?;
        validate_runtime_binding(family)?;
        value::validate_family_value(family)?;
        validate_optimization(family)?;
    }
    crate::resolved_set_rules::validate_registry(registry)?;
    validate_external_constraint_policies(registry)?;
    Ok(())
}

fn validate_runtime_binding(family: &crate::Family) -> Result<(), RegistryError> {
    use crate::{EvidenceProjectionId, RuntimeBindingSpec};

    let valid = match (family.implementation_status, family.runtime_binding) {
        (
            ImplementationStatus::Full,
            RuntimeBindingSpec::Effective {
                strategy_slot,
                evidence: EvidenceProjectionId::RunGenesisTunablesV2,
                ..
            },
        ) => family.strategy_slots.contains(&strategy_slot),
        (
            ImplementationStatus::FixedHidden,
            RuntimeBindingSpec::Fixed {
                evidence: EvidenceProjectionId::RunGenesisTunablesV2,
                ..
            },
        ) => true,
        // The published registry is complete. `Unbound` exists solely so adversarial fixtures can
        // construct an invalid family and prove this gate fails closed.
        (ImplementationStatus::Partial | ImplementationStatus::Missing, _)
        | (_, RuntimeBindingSpec::Unbound { .. })
        | (ImplementationStatus::Full, RuntimeBindingSpec::Fixed { .. })
        | (ImplementationStatus::FixedHidden, RuntimeBindingSpec::Effective { .. }) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(RegistryError::InvalidRuntimeBinding(family.id))
    }
}

fn validate_external_constraint_policies(registry: &[crate::Family]) -> Result<(), RegistryError> {
    let mut policies = BTreeSet::new();
    let mut count = 0usize;
    for family in registry {
        for rule in family.value_schema.rules {
            let CrossFieldRule::ExternalCeiling { field, ceiling, .. } = *rule else {
                continue;
            };
            count =
                count
                    .checked_add(1)
                    .ok_or(RegistryError::WrongExternalConstraintPolicyCount {
                        expected: EXPECTED_EXTERNAL_CONSTRAINT_POLICIES,
                        actual: usize::MAX,
                    })?;
            if !policies.insert((family.id, field, ceiling)) {
                return Err(RegistryError::DuplicateExternalConstraintPolicy {
                    family: family.id,
                    field,
                    ceiling,
                });
            }
        }
    }
    if count != EXPECTED_EXTERNAL_CONSTRAINT_POLICIES {
        return Err(RegistryError::WrongExternalConstraintPolicyCount {
            expected: EXPECTED_EXTERNAL_CONSTRAINT_POLICIES,
            actual: count,
        });
    }
    Ok(())
}

/// Enforce unique semantic ownership, then bind every declaration to the exact ordinal/ID/key
/// ledger association. Neither check consults family digests or the global golden digest.
pub(crate) fn validate_semantic_ownership(registry: &[crate::Family]) -> Result<(), RegistryError> {
    let mut identities = BTreeMap::<&'static str, &'static str>::new();
    let mut semantic_keys = BTreeMap::<&'static str, &'static str>::new();
    for family in registry {
        validate_identity(family.id)?;
        validate_semantic_key(family.semantic_key)?;
        if identities.insert(family.id, family.id).is_some() {
            return Err(RegistryError::DuplicateFamilyId(family.id));
        }
        if let Some(first) = semantic_keys.insert(family.semantic_key, family.id) {
            return Err(RegistryError::DuplicateSemanticKey {
                first,
                second: family.id,
                semantic_key: family.semantic_key,
            });
        }
    }
    for family in registry {
        for alias in family.aliases {
            validate_identity(alias)?;
            if let Some(existing) = identities.insert(alias, family.id) {
                return Err(RegistryError::AliasCollision {
                    alias,
                    owner: family.id,
                    existing,
                });
            }
        }
    }
    for family in registry {
        let Some(expected) = crate::semantic_keys::expected_entry(family.ordinal) else {
            return Err(RegistryError::MissingSemanticKeyLedgerEntry {
                ordinal: family.ordinal,
                family: family.id,
            });
        };
        if expected.ordinal != family.ordinal
            || expected.family_id != family.id
            || expected.semantic_key != family.semantic_key
        {
            return Err(RegistryError::SemanticKeyMappingMismatch {
                ordinal: family.ordinal,
                actual_id: family.id,
                actual_key: family.semantic_key,
                expected_ordinal: expected.ordinal,
                expected_id: expected.family_id,
                expected_key: expected.semantic_key,
            });
        }
    }
    Ok(())
}

fn validate_identity(identity: &'static str) -> Result<(), RegistryError> {
    if SEMANTIC_DUPLICATE_DENYLIST.contains(&identity) {
        return Err(RegistryError::SemanticDuplicate(identity));
    }
    if !valid_key_segment(identity) {
        return Err(RegistryError::InvalidFamilyId(identity));
    }
    Ok(())
}

fn validate_semantic_key(key: &'static str) -> Result<(), RegistryError> {
    let Some(path) = key.strip_prefix("iteron.control.") else {
        return Err(RegistryError::InvalidSemanticKey(key));
    };
    let mut segments = path.split('.');
    let Some(area) = segments.next() else {
        return Err(RegistryError::InvalidSemanticKey(key));
    };
    let Some(control) = segments.next() else {
        return Err(RegistryError::InvalidSemanticKey(key));
    };
    if !valid_key_segment(area)
        || !valid_key_segment(control)
        || segments.any(|segment| !valid_key_segment(segment))
    {
        return Err(RegistryError::InvalidSemanticKey(key));
    }
    Ok(())
}

fn valid_key_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !segment.starts_with('_')
        && !segment.ends_with('_')
}

fn validate_activation(family: &crate::Family) -> Result<(), RegistryError> {
    let valid = match family.implementation_status {
        ImplementationStatus::Missing => matches!(
            family.activation,
            crate::ActivationSpec {
                predicate: ActivationPredicate::Unavailable,
                inactive_reason: Some(crate::InactiveReason::NotImplemented),
            }
        ),
        ImplementationStatus::Partial => matches!(
            family.activation,
            crate::ActivationSpec {
                predicate: ActivationPredicate::RuntimeDerived { seam },
                inactive_reason: Some(crate::InactiveReason::GroupedOrIncompleteSeam),
            } if !seam.trim().is_empty()
        ),
        ImplementationStatus::Full | ImplementationStatus::FixedHidden => match family.activation {
            crate::ActivationSpec {
                predicate: ActivationPredicate::Always,
                inactive_reason: None,
            } => true,
            crate::ActivationSpec {
                predicate: ActivationPredicate::Configured { sources },
                inactive_reason: Some(crate::InactiveReason::ConfigurationAbsent),
            } => !sources.is_empty(),
            _ => false,
        },
    };
    valid
        .then_some(())
        .ok_or(RegistryError::InvalidActivation(family.id))
}

fn validate_default(family: &crate::Family) -> Result<(), RegistryError> {
    let default = family.default;
    let valid = match default.kind {
        DefaultKind::Literal => {
            matches!(default.resolver, DefaultResolver::Literal)
                && default.requirement == DefaultValueRequirement::Optional
                && default.value.is_some()
        }
        DefaultKind::Derived => {
            !matches!(
                default.resolver,
                DefaultResolver::Literal | DefaultResolver::Operator { .. }
            ) && default.requirement == DefaultValueRequirement::Optional
        }
        DefaultKind::Dynamic => match default.resolver {
            DefaultResolver::Literal | DefaultResolver::GovernedCatalog { .. } => false,
            DefaultResolver::Operator { input_id } => {
                default.requirement == DefaultValueRequirement::Required
                    && default.value.is_none()
                    && valid_core_id(input_id)
            }
            _ => default.requirement == DefaultValueRequirement::Optional,
        },
    } && match default.resolver {
        DefaultResolver::Literal => true,
        DefaultResolver::Builtin { resolver_id } => valid_core_id(resolver_id),
        DefaultResolver::ModelMetadata { field }
        | DefaultResolver::ProviderCapability { capability: field }
        | DefaultResolver::Transport { field }
        | DefaultResolver::RuntimeObservation { field } => !field.trim().is_empty(),
        DefaultResolver::GovernedCatalog { catalog_id } => valid_core_id(catalog_id),
        DefaultResolver::Operator { input_id } => valid_core_id(input_id),
    };
    valid
        .then_some(())
        .ok_or(RegistryError::InvalidDefault(family.id))
}

fn valid_core_id(value: &str) -> bool {
    value.starts_with("iteron://tunables/") && value.ends_with("-v1")
}

fn validate_requirements_and_slots(family: &crate::Family) -> Result<(), RegistryError> {
    if family.requirements.capabilities.is_empty() {
        return Err(RegistryError::MissingCapabilityRequirement(family.id));
    }
    let capabilities = family
        .requirements
        .capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if capabilities.len() != family.requirements.capabilities.len() {
        return Err(RegistryError::MissingCapabilityRequirement(family.id));
    }
    let slots = family
        .strategy_slots
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if family.strategy_slots.is_empty() || slots.len() != family.strategy_slots.len() {
        return Err(RegistryError::InvalidStrategySlots(family.id));
    }
    let provider_resolved = matches!(
        family.default.resolver,
        DefaultResolver::ModelMetadata { .. } | DefaultResolver::ProviderCapability { .. }
    );
    let externally_clamped = value::has_provider_ceiling(family.value_schema);
    // A provider-owned policy may remain active without a capable route when the schema requires
    // exact ProviderCapability ceiling evidence. That is how `prompt_cache=false` stays an
    // auditable runtime value on an incapable route. Dynamic provider/model lookup still needs a
    // route. A Full provider-domain family with neither a route nor an external clamp is invalid;
    // a FixedHidden family may instead be a local transport/runtime invariant whose physical
    // owner is attested by the fixed-authority binding rather than by provider capability.
    if family.requirements.provider == ProviderRequirement::None
        && (provider_resolved
            || (family.domain == crate::Domain::Provider
                && family.implementation_status != ImplementationStatus::FixedHidden
                && !externally_clamped))
    {
        return Err(RegistryError::InvalidProviderRequirement(family.id));
    }
    Ok(())
}

fn validate_optimization(family: &crate::Family) -> Result<(), RegistryError> {
    let expected_phase = match family.optimization.class {
        OptimizationClass::P1 => SearchPhase::P1,
        OptimizationClass::P2 => SearchPhase::P2,
        OptimizationClass::CStructured
        | OptimizationClass::CArtifact
        | OptimizationClass::CComponent => SearchPhase::Conditional,
        OptimizationClass::Pin => SearchPhase::Pinned,
    };
    if family.optimization.search_phase != expected_phase
        || (family.optimization.class == OptimizationClass::Pin)
            != family.optimization.pin_reason.is_some()
    {
        return Err(RegistryError::InvalidOptimization(family.id));
    }
    if matches!(
        family.authority_class,
        AuthorityClass::RuntimeInvariant | AuthorityClass::KernelInvariant
    ) && family.optimization.class != OptimizationClass::Pin
    {
        return Err(RegistryError::LearnableInvariant(family.id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RegistryError, validate_semantic_ownership};
    use crate::{DecimalValue, TunableValue, TunableValueField};

    #[test]
    fn retired_workflow_spawn_cap_identity_and_alias_are_rejected_without_a_digest() {
        let mut reintroduced = crate::families()[137];
        reintroduced.id = "workflow_spawn_cap";
        reintroduced.ordinal = 65_000;
        assert!(matches!(
            validate_semantic_ownership(&[reintroduced]),
            Err(RegistryError::SemanticDuplicate("workflow_spawn_cap"))
        ));

        let mut reintroduced_alias = crate::families()[137];
        reintroduced_alias.aliases = &["workflow_spawn_cap"];
        assert!(matches!(
            validate_semantic_ownership(&[reintroduced_alias]),
            Err(RegistryError::SemanticDuplicate("workflow_spawn_cap"))
        ));
    }

    #[test]
    fn canonical_memory_map_rules_validate_defaults_before_registry_digesting() {
        const ZERO_HYBRID: [TunableValueField; 2] = [
            TunableValueField {
                name: "lexical",
                value: TunableValue::Decimal {
                    value: DecimalValue {
                        coefficient: 0,
                        scale: 0,
                    },
                },
            },
            TunableValueField {
                name: "structural",
                value: TunableValue::Decimal {
                    value: DecimalValue {
                        coefficient: 0,
                        scale: 0,
                    },
                },
            },
        ];
        const FRACTIONAL_BM25_LIMIT: [TunableValueField; 3] = [
            TunableValueField {
                name: "k1",
                value: TunableValue::Decimal {
                    value: DecimalValue {
                        coefficient: 12,
                        scale: 1,
                    },
                },
            },
            TunableValueField {
                name: "b",
                value: TunableValue::Decimal {
                    value: DecimalValue {
                        coefficient: 75,
                        scale: 2,
                    },
                },
            },
            TunableValueField {
                name: "recall_limit",
                value: TunableValue::Decimal {
                    value: DecimalValue {
                        coefficient: 325,
                        scale: 1,
                    },
                },
            },
        ];

        let mut hybrid = *crate::families()
            .iter()
            .find(|family| family.id == "hybrid_retrieval_fusion_weights")
            .unwrap();
        assert!(super::value::validate_family_value(&hybrid).is_ok());
        hybrid.default.value = Some(TunableValue::Map {
            entries: &ZERO_HYBRID,
        });
        assert!(matches!(
            super::value::validate_family_value(&hybrid),
            Err(RegistryError::InvalidValueDomain(
                "hybrid_retrieval_fusion_weights",
                _
            ))
        ));

        let mut bm25 = *crate::families()
            .iter()
            .find(|family| family.id == "bm25")
            .unwrap();
        assert!(super::value::validate_family_value(&bm25).is_ok());
        bm25.default.value = Some(TunableValue::Map {
            entries: &FRACTIONAL_BM25_LIMIT,
        });
        assert!(matches!(
            super::value::validate_family_value(&bm25),
            Err(RegistryError::InvalidValueDomain("bm25", _))
        ));
    }
}

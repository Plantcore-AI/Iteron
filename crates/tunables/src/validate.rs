use crate::{
    ActivationPredicate, AuthorityClass, DefaultKind, DefaultResolver, DefaultValueRequirement,
    FAMILY_SCHEMA_VERSION, ImplementationStatus, OptimizationClass, ProviderRequirement,
    SearchPhase, SourceKind, SourceTrust, families,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "validate/default_value.rs"]
mod default_value;
#[path = "validate/value.rs"]
mod value;

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
    #[error("family `{0}` must bind one or more unique core StrategySlots")]
    InvalidStrategySlots(&'static str),
    #[error("family `{0}` has an invalid value schema: {1}")]
    InvalidValueDomain(&'static str, &'static str),
    #[error("scalar catalog `{0}` is invalid or duplicated")]
    InvalidScalarCatalog(&'static str),
    #[error("family `{0}` has an inconsistent optimization class/search phase")]
    InvalidOptimization(&'static str),
    #[error("family `{0}` assigns learnable optimization to invariant authority")]
    LearnableInvariant(&'static str),
    #[error("family `{0}` claims implemented code but cites only the registry")]
    ImplementedRegistryOnly(&'static str),
    #[error("families `{first}` and `{second}` have the same semantic digest `{digest}`")]
    DuplicateSemanticDigest {
        first: &'static str,
        second: &'static str,
        digest: String,
    },
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
    validate_semantic_digests(registry)?;
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
        if !catalog.id.starts_with("core://tunables/catalogs/")
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
    let mut identities = BTreeMap::<&'static str, &'static str>::new();
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
        validate_identity(family.id)?;
        if identities.insert(family.id, family.id).is_some() {
            return Err(RegistryError::DuplicateFamilyId(family.id));
        }
        if family.summary.trim().is_empty()
            || family.benchmark_relevance.rationale.trim().is_empty()
        {
            return Err(RegistryError::IncompleteMetadata(family.id));
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
        validate_activation(family)?;
        validate_source(family)?;
        validate_default(family)?;
        validate_requirements_and_slots(family)?;
        value::validate_family_value(family)?;
        validate_optimization(family)?;
    }
    Ok(())
}

fn validate_identity(identity: &'static str) -> Result<(), RegistryError> {
    if SEMANTIC_DUPLICATE_DENYLIST.contains(&identity) {
        return Err(RegistryError::SemanticDuplicate(identity));
    }
    if identity.is_empty()
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || identity.starts_with('_')
        || identity.ends_with('_')
    {
        return Err(RegistryError::InvalidFamilyId(identity));
    }
    Ok(())
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

fn expected_trust(kind: SourceKind) -> SourceTrust {
    match kind {
        SourceKind::Cli
        | SourceKind::OperatorInput
        | SourceKind::UserConfig
        | SourceKind::Environment => SourceTrust::Operator,
        SourceKind::ProjectConfig | SourceKind::Catalog => SourceTrust::Repository,
        SourceKind::Builtin | SourceKind::DerivedPolicy => SourceTrust::Builtin,
        SourceKind::RuntimeObservation => SourceTrust::RuntimeObservation,
        SourceKind::ExternalProvider => SourceTrust::ProviderAttested,
        SourceKind::GovernedBundle => SourceTrust::GovernedBundle,
        SourceKind::Registry => SourceTrust::RegistryDeclaration,
    }
}

fn validate_source(family: &crate::Family) -> Result<(), RegistryError> {
    let mut kinds = BTreeSet::new();
    let valid = !family.source.bindings.is_empty()
        && family.source.bindings.iter().all(|binding| {
            !binding.locator.trim().is_empty()
                && binding.trust == expected_trust(binding.kind)
                && kinds.insert(binding.kind)
                && (binding.kind != SourceKind::Registry
                    || family.implementation_status == ImplementationStatus::Missing)
        });
    if !valid {
        return Err(RegistryError::InvalidSource(family.id));
    }
    if family.implementation_status != ImplementationStatus::Missing
        && family
            .source
            .bindings
            .iter()
            .all(|binding| binding.kind == SourceKind::Registry)
    {
        return Err(RegistryError::ImplementedRegistryOnly(family.id));
    }
    Ok(())
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
    value.starts_with("core://tunables/") && value.ends_with("-v1")
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
    let provider_derived = family.domain == crate::Domain::Provider
        || matches!(
            family.default.resolver,
            DefaultResolver::ModelMetadata { .. } | DefaultResolver::ProviderCapability { .. }
        )
        || value::has_provider_ceiling(family.value_schema);
    if provider_derived && family.requirements.provider == ProviderRequirement::None {
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

fn validate_semantic_digests(registry: &[crate::Family]) -> Result<(), RegistryError> {
    let mut digests = BTreeMap::<String, &'static str>::new();
    for family in registry {
        let digest = crate::family_semantic_digest(family)?.value;
        if let Some(first) = digests.insert(digest.clone(), family.id) {
            return Err(RegistryError::DuplicateSemanticDigest {
                first,
                second: family.id,
                digest,
            });
        }
    }
    Ok(())
}

use super::RegistryError;
use crate::{
    ImplementationStatus, SourceKind, SourceMergePolicy, SourceTrust, StructuredValueDomain,
};
use std::collections::BTreeSet;

pub(super) fn validate(family: &crate::Family) -> Result<(), RegistryError> {
    let mut kinds = BTreeSet::new();
    let valid = !family.source.bindings.is_empty()
        && family.source.bindings.iter().all(|binding| {
            !binding.locator.trim().is_empty()
                && binding.trust == expected_trust(binding.kind)
                && kinds.insert(binding.kind)
                && (binding.kind != SourceKind::Registry
                    || family.implementation_status == ImplementationStatus::Missing)
                && valid_merge_policy(family, binding)
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

fn expected_trust(kind: SourceKind) -> SourceTrust {
    match kind {
        SourceKind::Cli
        | SourceKind::OperatorInput
        | SourceKind::RustBuilder
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

fn valid_merge_policy(family: &crate::Family, binding: &crate::SourceBinding) -> bool {
    if binding.kind != SourceKind::ProjectConfig {
        return binding.merge == SourceMergePolicy::Override;
    }
    match binding.merge {
        SourceMergePolicy::Override => false,
        SourceMergePolicy::RouteSuggestion => family.id == "model",
        SourceMergePolicy::TightenMaximum => matches!(
            family.value_schema.domain,
            StructuredValueDomain::Scalar {
                domain: crate::ScalarDomain::Integer { .. } | crate::ScalarDomain::Decimal { .. }
            }
        ),
        SourceMergePolicy::TightenBooleanGrant => matches!(
            family.value_schema.domain,
            StructuredValueDomain::Scalar {
                domain: crate::ScalarDomain::Boolean
            }
        ),
        SourceMergePolicy::IntersectAllowSet => {
            matches!(
                family.value_schema.domain,
                StructuredValueDomain::List { .. }
            )
        }
        SourceMergePolicy::RepositoryScoped => {
            family.authority_class != crate::AuthorityClass::Operator
        }
    }
}

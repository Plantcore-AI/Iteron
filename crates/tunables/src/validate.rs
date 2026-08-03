use crate::{Availability, EXPECTED_FAMILY_COUNT, families};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry has {actual} families; expected exactly {expected}")]
    WrongFamilyCount { expected: usize, actual: usize },
    #[error("family ordinal {actual} is not the expected contiguous ordinal {expected}")]
    NonContiguousOrdinal { expected: u16, actual: u16 },
    #[error("invalid stable family id `{0}`")]
    InvalidFamilyId(&'static str),
    #[error("duplicate stable family id `{0}`")]
    DuplicateFamilyId(&'static str),
    #[error("family `{0}` has incomplete metadata")]
    IncompleteMetadata(&'static str),
    #[error("family `{0}` has an incomplete typed value schema")]
    IncompleteValueSchema(&'static str),
    #[error("family `{0}` has an inactive default but is not declared-only")]
    InactiveFamilyIsActive(&'static str),
    #[error("family `{0}` is declared-only but has an active default")]
    DeclaredFamilyHasActiveDefault(&'static str),
    #[error("cannot encode the canonical registry: {0}")]
    CanonicalEncoding(#[source] serde_json::Error),
}

pub fn validate_registry() -> Result<(), RegistryError> {
    validate_families(families())
}

fn validate_families(families: &[crate::Family]) -> Result<(), RegistryError> {
    if families.len() != EXPECTED_FAMILY_COUNT {
        return Err(RegistryError::WrongFamilyCount {
            expected: EXPECTED_FAMILY_COUNT,
            actual: families.len(),
        });
    }

    let mut ids = BTreeSet::new();
    for (index, family) in families.iter().enumerate() {
        let expected = u16::try_from(index + 1).expect("160 ordinals fit in u16");
        if family.ordinal != expected {
            return Err(RegistryError::NonContiguousOrdinal {
                expected,
                actual: family.ordinal,
            });
        }
        if !valid_id(family.id) {
            return Err(RegistryError::InvalidFamilyId(family.id));
        }
        if !ids.insert(family.id) {
            return Err(RegistryError::DuplicateFamilyId(family.id));
        }
        if family.summary.trim().is_empty()
            || family.default.value.trim().is_empty()
            || family.source.locator.trim().is_empty()
            || family.benchmark.rationale.trim().is_empty()
        {
            return Err(RegistryError::IncompleteMetadata(family.id));
        }
        if family.value_schema.admissible.trim().is_empty()
            || family.value_schema.constraint.trim().is_empty()
            || family.value_schema.unit.trim().is_empty()
        {
            return Err(RegistryError::IncompleteValueSchema(family.id));
        }
        if matches!(family.default.kind, crate::DefaultKind::Inactive)
            && !matches!(family.availability, Availability::Declared)
        {
            return Err(RegistryError::InactiveFamilyIsActive(family.id));
        }
        if matches!(family.availability, Availability::Declared)
            && !matches!(family.default.kind, crate::DefaultKind::Inactive)
        {
            return Err(RegistryError::DeclaredFamilyHasActiveDefault(family.id));
        }
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
    use crate::families;

    #[test]
    fn stable_id_grammar_is_narrow() {
        assert!(valid_id("shell_timeout_output"));
        for invalid in ["", "Shell", "a-b", "_a", "a_", "a__b"] {
            assert!(!valid_id(invalid), "accepted `{invalid}`");
        }
    }

    #[test]
    fn incomplete_value_schema_is_rejected() {
        let mut registry = families().to_vec();
        registry[0].value_schema.constraint = "";
        assert!(matches!(
            validate_families(&registry),
            Err(RegistryError::IncompleteValueSchema("provider"))
        ));
    }
}

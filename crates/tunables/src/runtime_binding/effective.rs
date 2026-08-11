use crate::{DecimalValue, EntryOutcome, ResolutionValue, ResolvedTunableSet, families};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EffectiveValueError {
    #[error("unknown tunable family `{0}`")]
    UnknownFamily(String),
    #[error("tunable family `{family}` is not effective ({state})")]
    NotEffective { family: String, state: &'static str },
    #[error("effective value for `{family}` has the wrong type; expected {expected}")]
    WrongType {
        family: String,
        expected: &'static str,
    },
}

impl ResolvedTunableSet {
    pub fn effective_value(
        &self,
        family_id: &str,
    ) -> Result<&ResolutionValue, EffectiveValueError> {
        let canonical = families()
            .iter()
            .find(|family| {
                family.id == family_id
                    || family.semantic_key == family_id
                    || family.aliases.contains(&family_id)
            })
            .ok_or_else(|| EffectiveValueError::UnknownFamily(family_id.to_owned()))?;
        let entry = self
            .report()
            .entries
            .iter()
            .find(|entry| entry.family_id == canonical.id)
            .ok_or_else(|| EffectiveValueError::UnknownFamily(family_id.to_owned()))?;
        entry
            .effective
            .as_ref()
            .ok_or_else(|| EffectiveValueError::NotEffective {
                family: entry.family_id.to_owned(),
                state: outcome_label(&entry.outcome),
            })
    }

    pub fn effective_bool(&self, family: &str) -> Result<bool, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Boolean { value } => Ok(*value),
            _ => Err(wrong_type(family, "boolean")),
        }
    }

    pub fn effective_integer(&self, family: &str) -> Result<i64, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Integer { value } => Ok(*value),
            _ => Err(wrong_type(family, "integer")),
        }
    }

    pub fn effective_decimal(&self, family: &str) -> Result<DecimalValue, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Decimal { value } => Ok(*value),
            _ => Err(wrong_type(family, "decimal")),
        }
    }

    pub fn effective_text(&self, family: &str) -> Result<&str, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Text { value } => Ok(value),
            _ => Err(wrong_type(family, "text")),
        }
    }

    pub fn effective_enum(&self, family: &str) -> Result<&str, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Enum { value } => Ok(value),
            _ => Err(wrong_type(family, "enum")),
        }
    }

    pub fn effective_list(&self, family: &str) -> Result<&[ResolutionValue], EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::List { items } => Ok(items),
            _ => Err(wrong_type(family, "list")),
        }
    }

    pub fn effective_map(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Map { entries } => Ok(entries),
            _ => Err(wrong_type(family, "map")),
        }
    }

    pub fn effective_object(
        &self,
        family: &str,
    ) -> Result<&BTreeMap<String, ResolutionValue>, EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::Object { fields } => Ok(fields),
            _ => Err(wrong_type(family, "object")),
        }
    }

    pub fn effective_catalog_ref(
        &self,
        family: &str,
    ) -> Result<(&str, &str, u64, u64), EffectiveValueError> {
        match self.effective_value(family)? {
            ResolutionValue::CatalogRef {
                catalog_id,
                digest_sha256,
                entry_count,
                canonical_bytes,
            } => Ok((catalog_id, digest_sha256, *entry_count, *canonical_bytes)),
            _ => Err(wrong_type(family, "catalog_ref")),
        }
    }
}

fn wrong_type(family: &str, expected: &'static str) -> EffectiveValueError {
    EffectiveValueError::WrongType {
        family: family.to_owned(),
        expected,
    }
}

fn outcome_label(outcome: &EntryOutcome) -> &'static str {
    match outcome {
        EntryOutcome::Effective => "effective",
        EntryOutcome::Inactive { .. } => "inactive",
        EntryOutcome::Unavailable => "unavailable",
        EntryOutcome::Unresolved { .. } => "unresolved",
        EntryOutcome::Rejected { .. } => "rejected",
    }
}

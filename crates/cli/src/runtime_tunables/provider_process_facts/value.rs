use super::ProviderProcessFactError;
use core_tunables::{
    ConstraintValue, DecimalValue, ExternalCeiling, ResolutionValue, RuntimeResolutionBuilder,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub(super) fn boolv(value: bool) -> ResolutionValue {
    ResolutionValue::Boolean { value }
}

pub(super) fn int(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

pub(super) fn dec(coefficient: i64, scale: u8) -> ResolutionValue {
    ResolutionValue::Decimal {
        value: DecimalValue { coefficient, scale },
    }
}

pub(super) fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

pub(super) fn en(value: &str) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.to_owned(),
    }
}

pub(super) fn list(values: impl IntoIterator<Item = ResolutionValue>) -> ResolutionValue {
    ResolutionValue::List {
        items: values.into_iter().collect(),
    }
}

pub(super) fn map(values: impl IntoIterator<Item = (String, ResolutionValue)>) -> ResolutionValue {
    ResolutionValue::Map {
        entries: values.into_iter().collect::<BTreeMap<_, _>>(),
    }
}

pub(super) fn object<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

pub(super) fn i64u(value: u64, family: &'static str) -> Result<i64, ProviderProcessFactError> {
    i64::try_from(value).map_err(|_| ProviderProcessFactError::IntegerOverflow(family))
}

pub(super) fn upper(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ProviderProcessFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::UpperBound { value },
    )?;
    Ok(())
}

pub(super) fn domain(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    allowed: impl IntoIterator<Item = ResolutionValue>,
) -> Result<(), ProviderProcessFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(allowed.into_iter().collect::<BTreeSet<_>>()),
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn domain_max(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    maximum: ResolutionValue,
) -> Result<(), ProviderProcessFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: Some(maximum),
            allowed_values: None,
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn owner_digest(
    domain: &'static str,
    value: &impl Serialize,
) -> Result<String, ProviderProcessFactError> {
    let encoded = serde_json::to_vec(&(domain, value))
        .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

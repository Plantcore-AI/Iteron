use crate::{
    CrossFieldRule, DecimalValue, FieldDomain, RuleValue, ScalarDomain, SchemaField, StringFormat,
    StructuredValueDomain, TunableValue, TunableValueField,
};
use std::collections::BTreeSet;

pub(super) fn validate_root_value(
    value: TunableValue,
    domain: StructuredValueDomain,
) -> Result<(), &'static str> {
    match domain {
        StructuredValueDomain::Scalar { domain } => validate_scalar_value(value, domain),
        StructuredValueDomain::List {
            min_items,
            max_items,
            item,
            unique_items,
        } => validate_list(value, min_items, max_items, unique_items, |value| {
            validate_scalar_value(value, item)
        }),
        StructuredValueDomain::Map {
            min_entries,
            max_entries,
            key,
            value: value_domain,
        } => validate_map(value, min_entries, max_entries, key, |value| {
            validate_field_value(value, value_domain)
        }),
        StructuredValueDomain::Object {
            fields,
            additional_fields,
        } => validate_object(value, fields, additional_fields),
        StructuredValueDomain::Catalog {
            min_entries,
            max_entries,
            entry_fields,
            ..
        } => validate_list(value, min_entries, max_entries, true, |entry| {
            validate_object(entry, entry_fields, false)
        }),
    }
}

fn validate_field_value(value: TunableValue, domain: FieldDomain) -> Result<(), &'static str> {
    match domain {
        FieldDomain::Scalar { domain } => validate_scalar_value(value, domain),
        FieldDomain::List {
            min_items,
            max_items,
            unique_items,
            item,
        } => validate_list(value, min_items, max_items, unique_items, |value| {
            validate_scalar_value(value, item)
        }),
        FieldDomain::Map {
            min_entries,
            max_entries,
            key,
            value: value_domain,
        } => validate_map(value, min_entries, max_entries, key, |value| {
            validate_scalar_value(value, value_domain)
        }),
        FieldDomain::Object {
            fields,
            additional_fields,
        } => validate_object(value, fields, additional_fields),
    }
}

fn validate_scalar_value(value: TunableValue, domain: ScalarDomain) -> Result<(), &'static str> {
    match (value, domain) {
        (TunableValue::Boolean { .. }, ScalarDomain::Boolean) => Ok(()),
        (TunableValue::Integer { value }, ScalarDomain::Integer { min, max, .. })
            if (min..=max).contains(&value) =>
        {
            Ok(())
        }
        (
            TunableValue::Decimal { value },
            ScalarDomain::Decimal {
                min,
                max,
                max_scale,
                ..
            },
        ) if value.scale <= max_scale
            && decimal_cmp(min, value).is_some_and(|ordering| !ordering.is_gt())
            && decimal_cmp(value, max).is_some_and(|ordering| !ordering.is_gt()) =>
        {
            Ok(())
        }
        (
            TunableValue::Text { value } | TunableValue::Enum { value },
            ScalarDomain::Text {
                min_bytes,
                max_bytes,
                format,
            },
        ) if (min_bytes..=max_bytes).contains(&(value.len() as u64))
            && valid_string_format(value, format) =>
        {
            Ok(())
        }
        (
            TunableValue::Text { value } | TunableValue::Enum { value },
            ScalarDomain::Enum { values, catalog_id },
        ) => {
            if values.contains(&value) {
                return Ok(());
            }
            let Some(catalog_id) = catalog_id else {
                return Err("default enum value is outside the finite set");
            };
            let catalog = crate::SCALAR_CATALOGS
                .iter()
                .find(|catalog| catalog.id == catalog_id)
                .ok_or("default enum references an unknown scalar catalog")?;
            validate_scalar_value(TunableValue::Text { value }, catalog.value_domain)
        }
        _ => Err("typed default does not conform to the scalar schema"),
    }
}

fn validate_list(
    value: TunableValue,
    min: u64,
    max: u64,
    unique: bool,
    mut validate_item: impl FnMut(TunableValue) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let TunableValue::List { items } = value else {
        return Err("typed default is not a list");
    };
    if !(min..=max).contains(&(items.len() as u64)) {
        return Err("typed default list is outside item bounds");
    }
    if unique {
        for (index, item) in items.iter().enumerate() {
            if items[..index].contains(item) {
                return Err("typed default list violates uniqueness");
            }
        }
    }
    items.iter().copied().try_for_each(&mut validate_item)
}

fn validate_map(
    value: TunableValue,
    min: u64,
    max: u64,
    key: ScalarDomain,
    mut validate_value: impl FnMut(TunableValue) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let TunableValue::Map { entries } = value else {
        return Err("typed default is not a map");
    };
    if !(min..=max).contains(&(entries.len() as u64)) {
        return Err("typed default map is outside entry bounds");
    }
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name) {
            return Err("typed default map has duplicate keys");
        }
        validate_scalar_value(TunableValue::Text { value: entry.name }, key)?;
        validate_value(entry.value)?;
    }
    Ok(())
}

fn validate_object(
    value: TunableValue,
    schema_fields: &[SchemaField],
    additional_fields: bool,
) -> Result<(), &'static str> {
    let TunableValue::Object { fields } = value else {
        return Err("typed default is not an object");
    };
    let mut names = BTreeSet::new();
    for field in fields {
        if !names.insert(field.name) {
            return Err("typed default object has duplicate fields");
        }
        let Some(schema) = schema_fields
            .iter()
            .find(|schema| schema.name == field.name)
        else {
            if additional_fields {
                continue;
            }
            return Err("typed default object contains an unknown field");
        };
        validate_field_value(field.value, schema.domain)?;
    }
    if schema_fields
        .iter()
        .any(|schema| schema.required && !names.contains(schema.name))
    {
        return Err("typed default object omits a required field");
    }
    Ok(())
}

pub(super) fn apply_default_rules(
    value: TunableValue,
    rules: &[CrossFieldRule],
) -> Result<(), &'static str> {
    for rule in rules {
        match *rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                let (Some(left), Some(right)) =
                    (field_value(value, left), field_value(value, right))
                else {
                    continue;
                };
                if numeric_cmp(left, right).is_none_or(|ordering| ordering.is_gt()) {
                    return Err("typed default violates a less-or-equal rule");
                }
            }
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                let Some(limit) = field_value(value, limit).and_then(integer) else {
                    continue;
                };
                let mut sum = 0i128;
                for term in terms {
                    let Some(value) = field_value(value, term).and_then(integer) else {
                        return Err("sum-limit default rule is not integer-valued");
                    };
                    sum = sum
                        .checked_add(value)
                        .ok_or("sum-limit default overflowed")?;
                }
                if sum > limit {
                    return Err("typed default violates a sum-limit rule");
                }
            }
            CrossFieldRule::Requires {
                if_field,
                equals,
                then_field,
            } => {
                if field_value(value, if_field).is_some_and(|value| rule_value_eq(value, equals))
                    && field_value(value, then_field).is_none()
                {
                    return Err("typed default violates a requires rule");
                }
            }
            CrossFieldRule::MutuallyExclusive { fields } => {
                if fields
                    .iter()
                    .filter(|field| field_value(value, field).is_some())
                    .count()
                    > 1
                {
                    return Err("typed default violates a mutually-exclusive rule");
                }
            }
            CrossFieldRule::ExternalCeiling { .. } => {}
        }
    }
    Ok(())
}

fn field_value(value: TunableValue, path: &str) -> Option<TunableValue> {
    if path == "$" {
        return Some(value);
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let fields: &[TunableValueField] = match value {
        TunableValue::Object { fields } => fields,
        _ => return None,
    };
    let value = fields.iter().find(|field| field.name == head)?.value;
    if tail.is_empty() {
        Some(value)
    } else {
        field_value(value, tail)
    }
}

fn integer(value: TunableValue) -> Option<i128> {
    match value {
        TunableValue::Integer { value } => Some(i128::from(value)),
        _ => None,
    }
}

fn numeric_cmp(left: TunableValue, right: TunableValue) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (TunableValue::Integer { value: left }, TunableValue::Integer { value: right }) => {
            Some(left.cmp(&right))
        }
        (TunableValue::Decimal { value: left }, TunableValue::Decimal { value: right }) => {
            decimal_cmp(left, right)
        }
        _ => None,
    }
}

fn decimal_cmp(left: DecimalValue, right: DecimalValue) -> Option<std::cmp::Ordering> {
    let scale = left.scale.max(right.scale);
    let left = i128::from(left.coefficient)
        .checked_mul(10i128.checked_pow(u32::from(scale - left.scale))?)?;
    let right = i128::from(right.coefficient)
        .checked_mul(10i128.checked_pow(u32::from(scale - right.scale))?)?;
    Some(left.cmp(&right))
}

fn rule_value_eq(value: TunableValue, expected: RuleValue) -> bool {
    match (value, expected) {
        (TunableValue::Boolean { value }, RuleValue::Boolean { value: expected }) => {
            value == expected
        }
        (TunableValue::Integer { value }, RuleValue::Integer { value: expected }) => {
            value == expected
        }
        (TunableValue::Enum { value }, RuleValue::Enum { value: expected }) => value == expected,
        _ => false,
    }
}

fn valid_string_format(value: &str, format: StringFormat) -> bool {
    match format {
        StringFormat::Utf8 | StringFormat::Command => !value.is_empty(),
        StringFormat::Identifier => value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+')
        }),
        StringFormat::NamespacedId => value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        }),
        StringFormat::Uri => value.contains("://"),
        StringFormat::Path => !value.is_empty() && !value.contains('\0'),
        StringFormat::Regex => !value.is_empty(),
        StringFormat::Sha256 => {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        StringFormat::Semver => {
            value.split('.').take(3).count() == 3
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        }
    }
}

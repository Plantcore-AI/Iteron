use crate::resolution_types::{CatalogSnapshot, ResolutionValue};
use crate::{
    FieldDomain, ScalarDomain, SchemaField, StringFormat, StructuredValueDomain, TunableValue,
    ValueSchema,
};
use std::collections::{BTreeMap, BTreeSet};

mod report;
mod rules;
pub(crate) use report::{validate_report, validate_report_at};
use rules::decimal_cmp;
pub(crate) use rules::{numeric_cmp, replace_at, validate_rules, value_at};

pub(crate) fn owned(value: TunableValue) -> ResolutionValue {
    match value {
        TunableValue::Boolean { value } => ResolutionValue::Boolean { value },
        TunableValue::Integer { value } => ResolutionValue::Integer { value },
        TunableValue::Decimal { value } => ResolutionValue::Decimal { value },
        TunableValue::Text { value } => ResolutionValue::Text {
            value: value.to_owned(),
        },
        TunableValue::Enum { value } => ResolutionValue::Enum {
            value: value.to_owned(),
        },
        TunableValue::List { items } => ResolutionValue::List {
            items: items.iter().copied().map(owned).collect(),
        },
        TunableValue::Map { entries } => ResolutionValue::Map {
            entries: entries
                .iter()
                .map(|entry| (entry.name.to_owned(), owned(entry.value)))
                .collect(),
        },
        TunableValue::Object { fields } => ResolutionValue::Object {
            fields: fields
                .iter()
                .map(|field| (field.name.to_owned(), owned(field.value)))
                .collect(),
        },
    }
}

pub(crate) fn normalize(value: &mut ResolutionValue) {
    match value {
        ResolutionValue::Decimal { value } => {
            if value.coefficient == 0 {
                value.scale = 0;
            } else {
                while value.scale > 0 && value.coefficient % 10 == 0 {
                    value.coefficient /= 10;
                    value.scale -= 1;
                }
            }
        }
        ResolutionValue::List { items } => items.iter_mut().for_each(normalize),
        ResolutionValue::Map { entries } => entries.values_mut().for_each(normalize),
        ResolutionValue::Object { fields } => fields.values_mut().for_each(normalize),
        ResolutionValue::Boolean { .. }
        | ResolutionValue::Integer { .. }
        | ResolutionValue::Text { .. }
        | ResolutionValue::Enum { .. }
        | ResolutionValue::CatalogRef { .. } => {}
    }
}

pub(crate) fn validate(
    value: &ResolutionValue,
    schema: ValueSchema,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    validate_root(value, schema.domain, catalogs)?;
    validate_rules(value, schema.rules)
}

pub(crate) fn validate_at(
    value: &ResolutionValue,
    schema: ValueSchema,
    path: &str,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    if path == "$" {
        return validate_root(value, schema.domain, catalogs);
    }
    let domain = field_domain_at(schema.domain, path)
        .ok_or_else(|| format!("constraint path `{path}` is absent from the schema"))?;
    validate_field(value, domain, catalogs)
}

fn field_domain_at(root: StructuredValueDomain, path: &str) -> Option<FieldDomain> {
    let fields = match root {
        StructuredValueDomain::Object { fields, .. }
        | StructuredValueDomain::Catalog {
            entry_fields: fields,
            ..
        } => fields,
        _ => return None,
    };
    field_domain_in(fields, path)
}

fn field_domain_in(fields: &[SchemaField], path: &str) -> Option<FieldDomain> {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let field = fields.iter().find(|field| field.name == head)?;
    if tail.is_empty() {
        return Some(field.domain);
    }
    match field.domain {
        FieldDomain::Object { fields, .. } => field_domain_in(fields, tail),
        _ => None,
    }
}

fn validate_root(
    value: &ResolutionValue,
    domain: StructuredValueDomain,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    match domain {
        StructuredValueDomain::Scalar { domain } => validate_scalar(value, domain, catalogs),
        StructuredValueDomain::List {
            min_items,
            max_items,
            item,
            unique_items,
        } => validate_list(value, min_items, max_items, unique_items, |item_value| {
            validate_scalar(item_value, item, catalogs)
        }),
        StructuredValueDomain::Map {
            min_entries,
            max_entries,
            key,
            value: value_domain,
        } => validate_map(
            value,
            min_entries,
            max_entries,
            key,
            catalogs,
            |entry_value| validate_field(entry_value, value_domain, catalogs),
        ),
        StructuredValueDomain::Object {
            fields,
            additional_fields,
        } => validate_object(value, fields, additional_fields, catalogs),
        StructuredValueDomain::Catalog {
            catalog_id,
            min_entries,
            max_entries,
            entry_fields,
        } => match value {
            ResolutionValue::CatalogRef {
                catalog_id: actual_id,
                digest_sha256,
                entry_count,
                canonical_bytes,
            } => {
                if actual_id != catalog_id {
                    return Err("catalog reference has the wrong catalog identity".into());
                }
                if !(min_entries..=max_entries).contains(entry_count) {
                    return Err("catalog reference is outside entry bounds".into());
                }
                if *canonical_bytes > 268_435_456 {
                    return Err("catalog reference exceeds the canonical byte ceiling".into());
                }
                if !valid_sha256(digest_sha256) {
                    return Err("catalog reference has an invalid digest".into());
                }
                Ok(())
            }
            _ => validate_list(value, min_entries, max_entries, true, |entry| {
                validate_object(entry, entry_fields, false, catalogs)
            }),
        },
    }
}

fn validate_field(
    value: &ResolutionValue,
    domain: FieldDomain,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    match domain {
        FieldDomain::Scalar { domain } => validate_scalar(value, domain, catalogs),
        FieldDomain::List {
            min_items,
            max_items,
            unique_items,
            item,
        } => validate_list(value, min_items, max_items, unique_items, |item_value| {
            validate_scalar(item_value, item, catalogs)
        }),
        FieldDomain::Map {
            min_entries,
            max_entries,
            key,
            value: value_domain,
        } => validate_map(
            value,
            min_entries,
            max_entries,
            key,
            catalogs,
            |entry_value| validate_scalar(entry_value, value_domain, catalogs),
        ),
        FieldDomain::Object {
            fields,
            additional_fields,
        } => validate_object(value, fields, additional_fields, catalogs),
    }
}

fn validate_scalar(
    value: &ResolutionValue,
    domain: ScalarDomain,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    match (value, domain) {
        (ResolutionValue::Boolean { .. }, ScalarDomain::Boolean) => Ok(()),
        (ResolutionValue::Integer { value }, ScalarDomain::Integer { min, max, .. })
            if (min..=max).contains(value) =>
        {
            Ok(())
        }
        (
            ResolutionValue::Decimal { value },
            ScalarDomain::Decimal {
                min,
                max,
                max_scale,
                ..
            },
        ) if value.scale <= max_scale
            && decimal_cmp(min, *value).is_some_and(|ordering| !ordering.is_gt())
            && decimal_cmp(*value, max).is_some_and(|ordering| !ordering.is_gt()) =>
        {
            Ok(())
        }
        (
            ResolutionValue::Text { value },
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
        (ResolutionValue::Enum { value }, ScalarDomain::Enum { values, catalog_id }) => {
            if values.contains(&value.as_str()) {
                return Ok(());
            }
            let Some(catalog_id) = catalog_id else {
                return Err("value is outside the finite enum set".into());
            };
            let definition = crate::SCALAR_CATALOGS
                .iter()
                .find(|catalog| catalog.id == catalog_id)
                .ok_or_else(|| "enum references an unknown scalar catalog".to_owned())?;
            validate_scalar(
                &ResolutionValue::Text {
                    value: value.clone(),
                },
                definition.value_domain,
                catalogs,
            )?;
            let snapshot = catalogs
                .get(catalog_id)
                .ok_or_else(|| format!("catalog snapshot `{catalog_id}` is required"))?;
            if snapshot.values.contains(value) {
                Ok(())
            } else {
                Err(format!("value is absent from catalog `{catalog_id}`"))
            }
        }
        _ => Err("value does not conform to the scalar schema".into()),
    }
}

fn validate_list(
    value: &ResolutionValue,
    min: u64,
    max: u64,
    unique: bool,
    mut validate_item: impl FnMut(&ResolutionValue) -> Result<(), String>,
) -> Result<(), String> {
    let ResolutionValue::List { items } = value else {
        return Err("value is not a list".into());
    };
    if !(min..=max).contains(&(items.len() as u64)) {
        return Err("list is outside item bounds".into());
    }
    if unique && items.iter().collect::<BTreeSet<_>>().len() != items.len() {
        return Err("list violates uniqueness".into());
    }
    items.iter().try_for_each(&mut validate_item)
}

fn validate_map(
    value: &ResolutionValue,
    min: u64,
    max: u64,
    key: ScalarDomain,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
    mut validate_value: impl FnMut(&ResolutionValue) -> Result<(), String>,
) -> Result<(), String> {
    let ResolutionValue::Map { entries } = value else {
        return Err("value is not a map".into());
    };
    if !(min..=max).contains(&(entries.len() as u64)) {
        return Err("map is outside entry bounds".into());
    }
    for (entry_key, entry_value) in entries {
        let key_value = match key {
            ScalarDomain::Enum { .. } => ResolutionValue::Enum {
                value: entry_key.clone(),
            },
            _ => ResolutionValue::Text {
                value: entry_key.clone(),
            },
        };
        validate_scalar(&key_value, key, catalogs)?;
        validate_value(entry_value)?;
    }
    Ok(())
}

fn validate_object(
    value: &ResolutionValue,
    schema_fields: &[SchemaField],
    additional_fields: bool,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    let ResolutionValue::Object { fields } = value else {
        return Err("value is not an object".into());
    };
    for (name, value) in fields {
        let Some(schema) = schema_fields.iter().find(|schema| schema.name == name) else {
            if additional_fields {
                continue;
            }
            return Err(format!("object contains unknown field `{name}`"));
        };
        validate_field(value, schema.domain, catalogs)?;
    }
    if let Some(missing) = schema_fields
        .iter()
        .find(|schema| schema.required && !fields.contains_key(schema.name))
    {
        return Err(format!("object omits required field `{}`", missing.name));
    }
    Ok(())
}

fn valid_string_format(value: &str, format: StringFormat) -> bool {
    match format {
        StringFormat::Utf8 => true,
        StringFormat::Command => !value.is_empty(),
        StringFormat::Identifier => value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+')
        }),
        StringFormat::NamespacedId => value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        }),
        StringFormat::Uri => value.contains("://"),
        StringFormat::Path => !value.is_empty() && !value.contains('\0'),
        StringFormat::Regex => !value.is_empty(),
        StringFormat::Sha256 => valid_sha256(value),
        StringFormat::Semver => {
            value.split('.').take(3).count() == 3
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        }
    }
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

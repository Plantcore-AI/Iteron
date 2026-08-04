use super::{validate, validate_at};
use crate::resolution_types::{CatalogSnapshot, ResolutionValue};
use crate::{FieldDomain, ScalarDomain, SchemaField, StructuredValueDomain, ValueSchema};
use std::collections::{BTreeMap, BTreeSet};

const MAX_REPORT_DEPTH: usize = 32;

pub(crate) fn validate_report(value: &ResolutionValue, schema: ValueSchema) -> Result<(), String> {
    with_report_catalogs(value, |catalogs| {
        if !exact_root_tags(value, schema.domain) {
            return Err("report value uses a non-canonical scalar tag".into());
        }
        validate(value, schema, catalogs)
    })?
}

pub(crate) fn validate_report_at(
    value: &ResolutionValue,
    schema: ValueSchema,
    path: &str,
) -> Result<(), String> {
    with_report_catalogs(value, |catalogs| {
        if path == "$" {
            if !exact_root_tags(value, schema.domain) {
                return Err("report adjustment uses a non-canonical scalar tag".into());
            }
            return validate_at(value, schema, path, catalogs);
        }
        let domain = field_domain_at(schema.domain, path)
            .ok_or_else(|| "report adjustment names an unknown field".to_owned())?;
        if !exact_field_tags(value, domain) {
            return Err("report adjustment uses a non-canonical scalar tag".into());
        }
        validate_at(value, schema, path, catalogs)
    })?
}

fn with_report_catalogs<T>(
    value: &ResolutionValue,
    check: impl FnOnce(&BTreeMap<&str, &CatalogSnapshot>) -> T,
) -> Result<T, String> {
    let mut strings = BTreeSet::new();
    let mut bytes = 0usize;
    let mut nodes = 0usize;
    collect_strings(value, &mut strings, &mut bytes, &mut nodes, 0)?;
    let snapshots = crate::SCALAR_CATALOGS
        .iter()
        .map(|definition| CatalogSnapshot {
            catalog_id: definition.id.to_owned(),
            digest_sha256: "0".repeat(64),
            values: strings.clone(),
        })
        .collect::<Vec<_>>();
    let catalogs = snapshots
        .iter()
        .map(|snapshot| (snapshot.catalog_id.as_str(), snapshot))
        .collect();
    Ok(check(&catalogs))
}

fn collect_strings(
    value: &ResolutionValue,
    strings: &mut BTreeSet<String>,
    bytes: &mut usize,
    nodes: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_REPORT_DEPTH {
        return Err("report value exceeds its depth bound".into());
    }
    *nodes = nodes.checked_add(1).ok_or("report value node overflow")?;
    if *nodes > crate::RESOLUTION_INPUT_MAX_BYTES / 4 {
        return Err("report value exceeds its node bound".into());
    }
    match value {
        ResolutionValue::Text { value } | ResolutionValue::Enum { value } => {
            *bytes = bytes
                .checked_add(value.len())
                .ok_or("report value byte overflow")?;
            strings.insert(value.clone());
        }
        ResolutionValue::List { items } => {
            let next = depth.checked_add(1).ok_or("report value depth overflow")?;
            for value in items {
                collect_strings(value, strings, bytes, nodes, next)?;
            }
        }
        ResolutionValue::Map { entries } | ResolutionValue::Object { fields: entries } => {
            let next = depth.checked_add(1).ok_or("report value depth overflow")?;
            for (key, value) in entries {
                *bytes = bytes
                    .checked_add(key.len())
                    .ok_or("report value byte overflow")?;
                strings.insert(key.clone());
                collect_strings(value, strings, bytes, nodes, next)?;
            }
        }
        ResolutionValue::CatalogRef { catalog_id, .. } => {
            *bytes = bytes
                .checked_add(catalog_id.len())
                .ok_or("report value byte overflow")?;
        }
        ResolutionValue::Boolean { .. }
        | ResolutionValue::Integer { .. }
        | ResolutionValue::Decimal { .. } => {}
    }
    if *bytes > crate::RESOLUTION_INPUT_MAX_BYTES {
        return Err("report value exceeds its byte bound".into());
    }
    Ok(())
}

fn exact_root_tags(value: &ResolutionValue, domain: StructuredValueDomain) -> bool {
    match (value, domain) {
        (value, StructuredValueDomain::Scalar { domain }) => exact_scalar_tag(value, domain),
        (ResolutionValue::List { items }, StructuredValueDomain::List { item, .. }) => {
            items.iter().all(|value| exact_scalar_tag(value, item))
        }
        (ResolutionValue::Map { entries }, StructuredValueDomain::Map { value, .. }) => {
            entries.values().all(|entry| exact_field_tags(entry, value))
        }
        (
            ResolutionValue::Object { fields },
            StructuredValueDomain::Object {
                fields: schema,
                additional_fields,
            },
        ) => exact_object_tags(fields, schema, additional_fields),
        (ResolutionValue::CatalogRef { .. }, StructuredValueDomain::Catalog { .. }) => true,
        (ResolutionValue::List { items }, StructuredValueDomain::Catalog { entry_fields, .. }) => {
            items.iter().all(|entry| match entry {
                ResolutionValue::Object { fields } => {
                    exact_object_tags(fields, entry_fields, false)
                }
                _ => false,
            })
        }
        _ => false,
    }
}

fn exact_field_tags(value: &ResolutionValue, domain: FieldDomain) -> bool {
    match (value, domain) {
        (value, FieldDomain::Scalar { domain }) => exact_scalar_tag(value, domain),
        (ResolutionValue::List { items }, FieldDomain::List { item, .. }) => {
            items.iter().all(|value| exact_scalar_tag(value, item))
        }
        (ResolutionValue::Map { entries }, FieldDomain::Map { value: domain, .. }) => entries
            .values()
            .all(|value| exact_scalar_tag(value, domain)),
        (
            ResolutionValue::Object { fields },
            FieldDomain::Object {
                fields: schema,
                additional_fields,
            },
        ) => exact_object_tags(fields, schema, additional_fields),
        _ => false,
    }
}

fn exact_object_tags(
    values: &BTreeMap<String, ResolutionValue>,
    schema: &[SchemaField],
    additional: bool,
) -> bool {
    values.iter().all(|(name, value)| {
        schema
            .iter()
            .find(|field| field.name == name)
            .map_or(additional, |field| exact_field_tags(value, field.domain))
    })
}

fn exact_scalar_tag(value: &ResolutionValue, domain: ScalarDomain) -> bool {
    matches!(
        (value, domain),
        (ResolutionValue::Boolean { .. }, ScalarDomain::Boolean)
            | (
                ResolutionValue::Integer { .. },
                ScalarDomain::Integer { .. }
            )
            | (
                ResolutionValue::Decimal { .. },
                ScalarDomain::Decimal { .. }
            )
            | (ResolutionValue::Text { .. }, ScalarDomain::Text { .. })
            | (ResolutionValue::Enum { .. }, ScalarDomain::Enum { .. })
    )
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

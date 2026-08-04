use crate::{
    ConstraintProjection, ConstraintRelation, ConstraintViolation, CrossFieldRule, DecimalValue,
    DefaultResolver, ExternalCeiling, FieldDomain, RegistryError, ScalarDomain, SchemaField,
    StructuredValueDomain, ValueKind, ValueSchema,
};
use std::collections::BTreeSet;

pub(super) fn validate_family_value(family: &crate::Family) -> Result<(), RegistryError> {
    let invalid = |reason| Err(RegistryError::InvalidValueDomain(family.id, reason));
    let expected_schema_id = format!("core://tunables/families/{}/value-v1", family.id);
    if family.value_schema.schema_id != expected_schema_id {
        return invalid("schema ID does not match the stable family ID");
    }
    validate_schema(family.value_schema)
        .map_err(|reason| RegistryError::InvalidValueDomain(family.id, reason))?;
    if let DefaultResolver::GovernedCatalog { catalog_id } = family.default.resolver {
        let expected = format!("core://tunables/catalogs/{}-v1", family.id);
        let inline_matches = matches!(
            family.value_schema.domain,
            StructuredValueDomain::Catalog { catalog_id: schema_catalog, .. }
                if schema_catalog == catalog_id
        );
        if catalog_id != expected
            || (matches!(
                family.value_schema.domain,
                StructuredValueDomain::Catalog { .. }
            ) && !inline_matches)
        {
            return invalid("governed-catalog resolver does not name the family catalog contract");
        }
    }
    if let Some(value) = family.default.value {
        super::default_value::validate_root_value(value, family.value_schema.domain)
            .map_err(|reason| RegistryError::InvalidValueDomain(family.id, reason))?;
        super::default_value::apply_default_rules(value, family.value_schema.rules)
            .map_err(|reason| RegistryError::InvalidValueDomain(family.id, reason))?;
    }
    Ok(())
}

fn validate_schema(schema: ValueSchema) -> Result<(), &'static str> {
    if !schema.schema_id.starts_with("core://tunables/families/")
        || !schema.schema_id.ends_with("/value-v1")
    {
        return Err("invalid family schema ID");
    }
    match schema.domain {
        StructuredValueDomain::Scalar { domain } => {
            validate_scalar_domain(domain)?;
            let kind_matches = match domain {
                ScalarDomain::Boolean => schema.kind == ValueKind::Bool,
                ScalarDomain::Integer { .. } => matches!(
                    schema.kind,
                    ValueKind::Count | ValueKind::Duration | ValueKind::Bytes
                ),
                ScalarDomain::Decimal { .. } => {
                    matches!(schema.kind, ValueKind::Ratio | ValueKind::Decimal)
                }
                ScalarDomain::Text { .. } => schema.kind == ValueKind::String,
                ScalarDomain::Enum { .. } => schema.kind == ValueKind::Enum,
            };
            if !kind_matches {
                return Err("scalar domain and value kind disagree");
            }
        }
        StructuredValueDomain::List {
            min_items,
            max_items,
            item,
            ..
        } => {
            if schema.kind != ValueKind::List || min_items > max_items || max_items == 0 {
                return Err("invalid bounded list root");
            }
            validate_scalar_domain(item)?;
        }
        StructuredValueDomain::Map {
            min_entries,
            max_entries,
            key,
            value,
        } => {
            if schema.kind != ValueKind::Map || min_entries > max_entries || max_entries == 0 {
                return Err("invalid bounded map root");
            }
            validate_map_key_domain(key)?;
            validate_field_domain(value, 0)?;
        }
        StructuredValueDomain::Object {
            fields,
            additional_fields,
        } => {
            if schema.kind != ValueKind::Policy || additional_fields || fields.is_empty() {
                return Err("invalid closed object root");
            }
            validate_fields(fields, 0)?;
        }
        StructuredValueDomain::Catalog {
            catalog_id,
            min_entries,
            max_entries,
            entry_fields,
        } => {
            if schema.kind != ValueKind::Catalog
                || !catalog_id.starts_with("core://tunables/catalogs/")
                || !catalog_id.ends_with("-v1")
                || min_entries > max_entries
                || max_entries == 0
                || entry_fields.is_empty()
            {
                return Err("invalid inline catalog root");
            }
            validate_fields(entry_fields, 0)?;
        }
    }
    for rule in schema.rules {
        validate_rule(schema.domain, *rule)?;
    }
    Ok(())
}

pub(super) fn validate_scalar_domain(domain: ScalarDomain) -> Result<(), &'static str> {
    match domain {
        ScalarDomain::Boolean => Ok(()),
        ScalarDomain::Integer { min, max, unit } => {
            if min > max || unit.trim().is_empty() {
                Err("invalid integer bounds or unit")
            } else {
                Ok(())
            }
        }
        ScalarDomain::Decimal {
            min,
            max,
            max_scale,
            unit,
        } => {
            if min.scale > max_scale
                || max.scale > max_scale
                || decimal_cmp(min, max).is_none_or(|ordering| ordering.is_gt())
                || unit.trim().is_empty()
            {
                Err("invalid exact-decimal bounds, scale, or unit")
            } else {
                Ok(())
            }
        }
        ScalarDomain::Text {
            min_bytes,
            max_bytes,
            ..
        } => {
            if min_bytes > max_bytes || max_bytes == 0 {
                Err("invalid text byte bounds")
            } else {
                Ok(())
            }
        }
        ScalarDomain::Enum { values, catalog_id } => {
            let unique = values.iter().copied().collect::<BTreeSet<_>>();
            let closed = catalog_id.is_none()
                && !values.is_empty()
                && unique.len() == values.len()
                && values.iter().all(|value| !value.trim().is_empty());
            let open = values.is_empty()
                && catalog_id.is_some_and(crate::schema_catalog::contains_scalar_catalog);
            if closed || open {
                Ok(())
            } else {
                Err("enum must be concrete or name one defined scalar catalog")
            }
        }
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

fn validate_fields(fields: &[SchemaField], depth: u8) -> Result<(), &'static str> {
    if depth >= 16 {
        return Err("object nesting exceeds the static depth ceiling");
    }
    let mut names = BTreeSet::new();
    for field in fields {
        if field.name.is_empty() || !names.insert(field.name) {
            return Err("object field is empty or duplicated");
        }
        validate_field_domain(field.domain, depth + 1)?;
    }
    Ok(())
}

fn validate_field_domain(domain: FieldDomain, depth: u8) -> Result<(), &'static str> {
    match domain {
        FieldDomain::Scalar { domain } => validate_scalar_domain(domain),
        FieldDomain::List {
            min_items,
            max_items,
            item,
            ..
        } => {
            if min_items > max_items || max_items == 0 {
                return Err("invalid field list bounds");
            }
            validate_scalar_domain(item)
        }
        FieldDomain::Map {
            min_entries,
            max_entries,
            key,
            value,
        } => {
            if min_entries > max_entries || max_entries == 0 {
                return Err("invalid field map bounds");
            }
            validate_map_key_domain(key)?;
            validate_scalar_domain(value)
        }
        FieldDomain::Object {
            fields,
            additional_fields,
        } => {
            if additional_fields || fields.is_empty() {
                return Err("nested object must be non-empty and closed");
            }
            validate_fields(fields, depth)
        }
    }
}

fn validate_map_key_domain(domain: ScalarDomain) -> Result<(), &'static str> {
    if matches!(
        domain,
        ScalarDomain::Text { .. } | ScalarDomain::Enum { .. }
    ) {
        validate_scalar_domain(domain)
    } else {
        Err("map keys must use a text or enum scalar domain")
    }
}

fn validate_rule(root: StructuredValueDomain, rule: CrossFieldRule) -> Result<(), &'static str> {
    let valid_path = |path| path_exists(root, path);
    match rule {
        CrossFieldRule::LessOrEqual { left, right } => {
            if left == right || !valid_path(left) || !valid_path(right) {
                return Err("invalid or vacuous less-or-equal rule");
            }
        }
        CrossFieldRule::SumLessOrEqual { terms, limit } => {
            let unique = terms.iter().copied().collect::<BTreeSet<_>>();
            if terms.is_empty()
                || unique.len() != terms.len()
                || terms.iter().any(|term| !valid_path(term))
                || !valid_path(limit)
            {
                return Err("invalid sum-limit rule");
            }
        }
        CrossFieldRule::Requires {
            if_field,
            then_field,
            ..
        } => {
            if if_field == then_field || !valid_path(if_field) || !valid_path(then_field) {
                return Err("invalid requires rule");
            }
        }
        CrossFieldRule::MutuallyExclusive { fields } => {
            let unique = fields.iter().copied().collect::<BTreeSet<_>>();
            if fields.len() < 2
                || unique.len() != fields.len()
                || fields.iter().any(|field| !valid_path(field))
            {
                return Err("invalid mutually-exclusive rule");
            }
        }
        CrossFieldRule::ExternalCeiling {
            field,
            ceiling,
            projection,
            relation,
            violation,
        } => {
            if !valid_path(field) {
                return Err("external ceiling names an unknown field");
            }
            let numeric_target = path_is_numeric(root, field);
            let budget_authority = matches!(
                ceiling,
                ExternalCeiling::ParentTurns
                    | ExternalCeiling::ParentTokens
                    | ExternalCeiling::ParentWall
                    | ExternalCeiling::ParentCost
                    | ExternalCeiling::ContextWindow
                    | ExternalCeiling::ToolBudget
                    | ExternalCeiling::ProcessBudget
                    | ExternalCeiling::RunBudget
            );
            let whole_value_policy = projection == ConstraintProjection::WholeValue
                && match (relation, violation) {
                    (ConstraintRelation::UpperBound, ConstraintViolation::ClampNumeric) => {
                        budget_authority && numeric_target
                    }
                    (ConstraintRelation::Exact, ConstraintViolation::Reject) => {
                        ceiling == ExternalCeiling::BenchmarkProtocol
                    }
                    (
                        ConstraintRelation::AttestedDomain,
                        ConstraintViolation::DegradeAttested {
                            policy_id: "core://tunables/degrade/provider-attested-preferred-v1",
                        },
                    ) => ceiling == ExternalCeiling::ProviderCapability,
                    (ConstraintRelation::AttestedDomain, ConstraintViolation::Reject) => {
                        matches!(
                            ceiling,
                            ExternalCeiling::OperatorAuthority
                                | ExternalCeiling::VerificationFloor
                                | ExternalCeiling::TenantScope
                        ) || (budget_authority && !numeric_target)
                    }
                    _ => false,
                };
            let whole_catalog_policy = projection == ConstraintProjection::WholeCatalog
                && field != "$"
                && matches!(root, StructuredValueDomain::Catalog { .. })
                && match (relation, violation) {
                    (ConstraintRelation::Exact, ConstraintViolation::Reject) => {
                        ceiling == ExternalCeiling::BenchmarkProtocol
                    }
                    (ConstraintRelation::AttestedDomain, ConstraintViolation::Reject) => {
                        matches!(
                            ceiling,
                            ExternalCeiling::OperatorAuthority
                                | ExternalCeiling::TenantScope
                                | ExternalCeiling::ContextWindow
                                | ExternalCeiling::ParentWall
                        )
                    }
                    _ => false,
                };
            let valid_policy = whole_value_policy || whole_catalog_policy;
            if !valid_policy {
                return Err(
                    "external ceiling policy is inconsistent with its target shape or authority",
                );
            }
        }
    }
    Ok(())
}

fn path_exists(root: StructuredValueDomain, path: &str) -> bool {
    if path == "$" {
        return true;
    }
    let fields = match root {
        StructuredValueDomain::Object { fields, .. } => fields,
        StructuredValueDomain::Catalog { entry_fields, .. } => entry_fields,
        _ => return false,
    };
    field_path_exists(fields, path)
}

fn path_is_numeric(root: StructuredValueDomain, path: &str) -> bool {
    if path == "$" {
        return matches!(
            root,
            StructuredValueDomain::Scalar {
                domain: ScalarDomain::Integer { .. } | ScalarDomain::Decimal { .. }
            }
        );
    }
    let fields = match root {
        StructuredValueDomain::Object { fields, .. } => fields,
        StructuredValueDomain::Catalog { entry_fields, .. } => entry_fields,
        _ => return false,
    };
    field_path_is_numeric(fields, path)
}

fn field_path_is_numeric(fields: &[SchemaField], path: &str) -> bool {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let Some(field) = fields.iter().find(|field| field.name == head) else {
        return false;
    };
    if tail.is_empty() {
        return matches!(
            field.domain,
            FieldDomain::Scalar {
                domain: ScalarDomain::Integer { .. } | ScalarDomain::Decimal { .. }
            }
        );
    }
    match field.domain {
        FieldDomain::Object { fields, .. } => field_path_is_numeric(fields, tail),
        _ => false,
    }
}

fn field_path_exists(fields: &[SchemaField], path: &str) -> bool {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    fields.iter().any(|field| {
        if field.name != head {
            return false;
        }
        if tail.is_empty() {
            return true;
        }
        matches!(field.domain, FieldDomain::Object { fields, .. } if field_path_exists(fields, tail))
    })
}

pub(super) fn has_provider_ceiling(schema: ValueSchema) -> bool {
    schema.rules.iter().any(|rule| {
        matches!(
            rule,
            CrossFieldRule::ExternalCeiling {
                ceiling: ExternalCeiling::ProviderCapability,
                ..
            }
        )
    })
}

use crate::{
    ConstraintProjection, ConstraintRelation, ConstraintViolation, CrossFieldRule, DecimalValue,
    DefaultResolver, ExternalCeiling, FieldDomain, RegistryError, RuleValue, ScalarDomain,
    SchemaField, StringFormat, StructuredValueDomain, ValueKind, ValueSchema,
};
use std::collections::BTreeSet;

pub(super) fn validate_family_value(family: &crate::Family) -> Result<(), RegistryError> {
    let invalid = |reason| Err(RegistryError::InvalidValueDomain(family.id, reason));
    if family.value_schema.version == 0 {
        return invalid("value schema version must be positive");
    }
    let expected_schema_id = format!(
        "iteron://tunables/families/{}/value-v{}",
        family.id, family.value_schema.version
    );
    if family.value_schema.schema_id != expected_schema_id {
        return invalid("schema ID does not match the stable family ID");
    }
    validate_schema(family.value_schema)
        .map_err(|reason| RegistryError::InvalidValueDomain(family.id, reason))?;
    if let DefaultResolver::GovernedCatalog { catalog_id } = family.default.resolver {
        let expected = format!("iteron://tunables/catalogs/{}-v1", family.id);
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
    let expected_suffix = format!("/value-v{}", schema.version);
    if schema.version == 0
        || !schema.schema_id.starts_with("iteron://tunables/families/")
        || !schema.schema_id.ends_with(&expected_suffix)
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
                || !catalog_id.starts_with("iteron://tunables/catalogs/")
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
        CrossFieldRule::SumEquals { terms, total } => {
            let unique = terms.iter().copied().collect::<BTreeSet<_>>();
            if terms.len() < 2
                || unique.len() != terms.len()
                || terms
                    .iter()
                    .any(|term| !valid_path(term) || !path_is_numeric(root, term))
                || total.scale > 18
            {
                return Err("sum-equals rule requires unique numeric fields and a bounded total");
            }
        }
        CrossFieldRule::Requires {
            if_field,
            equals,
            then_field,
        } => {
            let Some(trigger_domain) = scalar_domain_at(root, if_field) else {
                return Err("requires trigger must name a scalar field");
            };
            let Some(required_domain) = scalar_domain_at(root, then_field) else {
                return Err("requires target must name a scalar field");
            };
            if if_field == then_field
                || !rule_value_conforms(equals, trigger_domain)
                || !matches!(
                    required_domain,
                    ScalarDomain::Boolean
                        | ScalarDomain::Integer { .. }
                        | ScalarDomain::Decimal { .. }
                )
            {
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
        CrossFieldRule::MapEntryDomain { key, domain } => {
            let StructuredValueDomain::Map {
                key: key_domain,
                value: FieldDomain::Scalar { domain: base },
                ..
            } = root
            else {
                return Err("map-entry domain rule requires a scalar-valued map");
            };
            if !map_key_admitted(key_domain, key)
                || validate_scalar_domain(domain).is_err()
                || !scalar_domain_is_subset(domain, base)
            {
                return Err("map-entry domain is unknown, invalid, or wider than the map domain");
            }
        }
        CrossFieldRule::AtLeastOneNonZero { fields } => {
            let unique = fields.iter().copied().collect::<BTreeSet<_>>();
            if fields.is_empty()
                || unique.len() != fields.len()
                || fields
                    .iter()
                    .any(|field| !valid_path(field) || !path_is_numeric(root, field))
            {
                return Err("non-zero rule requires unique numeric fields");
            }
        }
        CrossFieldRule::Equals { field, value } => {
            let Some(domain) = scalar_domain_at(root, field) else {
                return Err("equals rule names an unknown or non-scalar field");
            };
            if !rule_value_conforms(value, domain) {
                return Err("equals rule literal is outside the field domain");
            }
        }
        CrossFieldRule::ResolvedSetSumLessOrEqual {
            rule_id,
            terms,
            limit,
        } => {
            if !rule_id.starts_with("iteron://tunables/resolved-set-rules/")
                || !rule_id.ends_with("-v1")
                || terms.len() < 2
                || limit.family.is_empty()
                || limit.path.is_empty()
            {
                return Err("invalid resolved-set sum-limit rule identity or shape");
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
                            policy_id: "iteron://tunables/degrade/provider-attested-preferred-v1",
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
    match root {
        StructuredValueDomain::Object { fields, .. } => field_path_exists(fields, path),
        StructuredValueDomain::Catalog { entry_fields, .. } => {
            field_path_exists(entry_fields, path)
        }
        StructuredValueDomain::Map { key, .. } => {
            !path.contains('.') && map_key_admitted(key, path)
        }
        StructuredValueDomain::Scalar { .. } | StructuredValueDomain::List { .. } => false,
    }
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
    match root {
        StructuredValueDomain::Object { fields, .. } => field_path_is_numeric(fields, path),
        StructuredValueDomain::Catalog { entry_fields, .. } => {
            field_path_is_numeric(entry_fields, path)
        }
        StructuredValueDomain::Map {
            key,
            value:
                FieldDomain::Scalar {
                    domain: ScalarDomain::Integer { .. } | ScalarDomain::Decimal { .. },
                },
            ..
        } => !path.contains('.') && map_key_admitted(key, path),
        _ => false,
    }
}

pub(super) fn scalar_domain_at(root: StructuredValueDomain, path: &str) -> Option<ScalarDomain> {
    if path == "$" {
        return match root {
            StructuredValueDomain::Scalar { domain } => Some(domain),
            _ => None,
        };
    }
    match root {
        StructuredValueDomain::Map {
            key,
            value: FieldDomain::Scalar { domain },
            ..
        } if !path.contains('.') && map_key_admitted(key, path) => Some(domain),
        StructuredValueDomain::Object { fields, .. } => scalar_field_domain_in(fields, path),
        StructuredValueDomain::Catalog { entry_fields, .. } => {
            scalar_field_domain_in(entry_fields, path)
        }
        _ => None,
    }
}

pub(super) fn path_is_required_integer(root: StructuredValueDomain, path: &str) -> bool {
    if path == "$" {
        return matches!(
            root,
            StructuredValueDomain::Scalar {
                domain: ScalarDomain::Integer { .. }
            }
        );
    }
    let StructuredValueDomain::Object { fields, .. } = root else {
        return false;
    };
    required_integer_field_in(fields, path)
}

fn required_integer_field_in(fields: &[SchemaField], path: &str) -> bool {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let Some(field) = fields.iter().find(|field| field.name == head) else {
        return false;
    };
    if !field.required {
        return false;
    }
    if tail.is_empty() {
        return matches!(
            field.domain,
            FieldDomain::Scalar {
                domain: ScalarDomain::Integer { .. }
            }
        );
    }
    match field.domain {
        FieldDomain::Object { fields, .. } => required_integer_field_in(fields, tail),
        _ => false,
    }
}

fn scalar_field_domain_in(fields: &[SchemaField], path: &str) -> Option<ScalarDomain> {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let field = fields.iter().find(|field| field.name == head)?;
    if tail.is_empty() {
        return match field.domain {
            FieldDomain::Scalar { domain } => Some(domain),
            _ => None,
        };
    }
    match field.domain {
        FieldDomain::Object { fields, .. } => scalar_field_domain_in(fields, tail),
        _ => None,
    }
}

fn map_key_admitted(domain: ScalarDomain, key: &str) -> bool {
    match domain {
        ScalarDomain::Enum { values, catalog_id } => catalog_id.is_none() && values.contains(&key),
        ScalarDomain::Text {
            min_bytes,
            max_bytes,
            format,
        } => {
            (min_bytes..=max_bytes).contains(&(key.len() as u64))
                && valid_string_format(key, format)
        }
        _ => false,
    }
}

fn scalar_domain_is_subset(candidate: ScalarDomain, base: ScalarDomain) -> bool {
    match (candidate, base) {
        (ScalarDomain::Boolean, ScalarDomain::Boolean) => true,
        (
            ScalarDomain::Integer {
                min: candidate_min,
                max: candidate_max,
                ..
            },
            ScalarDomain::Integer {
                min: base_min,
                max: base_max,
                ..
            },
        ) => candidate_min >= base_min && candidate_max <= base_max,
        (
            ScalarDomain::Decimal {
                min: candidate_min,
                max: candidate_max,
                max_scale: candidate_scale,
                ..
            },
            ScalarDomain::Decimal {
                min: base_min,
                max: base_max,
                max_scale: base_scale,
                ..
            },
        ) => {
            candidate_scale <= base_scale
                && decimal_cmp(base_min, candidate_min).is_some_and(|order| !order.is_gt())
                && decimal_cmp(candidate_max, base_max).is_some_and(|order| !order.is_gt())
        }
        (
            ScalarDomain::Text {
                min_bytes: candidate_min,
                max_bytes: candidate_max,
                format: candidate_format,
            },
            ScalarDomain::Text {
                min_bytes: base_min,
                max_bytes: base_max,
                format: base_format,
            },
        ) => {
            candidate_min >= base_min
                && candidate_max <= base_max
                && candidate_format == base_format
        }
        (
            ScalarDomain::Enum {
                values: candidate,
                catalog_id: candidate_catalog,
            },
            ScalarDomain::Enum {
                values: base,
                catalog_id: base_catalog,
            },
        ) => {
            candidate_catalog == base_catalog
                && (candidate_catalog.is_some()
                    || candidate.iter().all(|value| base.contains(value)))
        }
        _ => false,
    }
}

fn rule_value_conforms(value: RuleValue, domain: ScalarDomain) -> bool {
    match (value, domain) {
        (RuleValue::Boolean { .. }, ScalarDomain::Boolean) => true,
        (RuleValue::Integer { value }, ScalarDomain::Integer { min, max, .. }) => {
            (min..=max).contains(&value)
        }
        (
            RuleValue::Decimal { value },
            ScalarDomain::Decimal {
                min,
                max,
                max_scale,
                ..
            },
        ) => {
            value.scale <= max_scale
                && decimal_cmp(min, value).is_some_and(|order| !order.is_gt())
                && decimal_cmp(value, max).is_some_and(|order| !order.is_gt())
        }
        (
            RuleValue::Enum { value },
            ScalarDomain::Enum {
                values,
                catalog_id: None,
            },
        ) => values.contains(&value),
        _ => false,
    }
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

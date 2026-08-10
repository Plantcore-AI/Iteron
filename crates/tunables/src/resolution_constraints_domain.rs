use crate::resolution_types::{CatalogSnapshot, ConstraintValue, ResolutionValue};
use crate::{
    ConstraintProjection, ExternalCeiling, Family, FieldDomain, ScalarDomain,
    StructuredValueDomain, ValueKind, ValueSchema,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
enum TargetDomain {
    Scalar(ScalarDomain),
    List(ScalarDomain),
    MapKeys(ScalarDomain),
    Whole,
}

pub(super) fn validate_upper_bound(
    family: &Family,
    field: &str,
    value: &ResolutionValue,
) -> Result<(), String> {
    let expected = target_domain(family.value_schema.domain, field)?;
    match (expected, value) {
        (TargetDomain::Scalar(ScalarDomain::Integer { .. }), ResolutionValue::Integer { .. }) => {
            Ok(())
        }
        (
            TargetDomain::Scalar(ScalarDomain::Decimal { max_scale, .. }),
            ResolutionValue::Decimal { value: decimal },
        ) if decimal.scale <= max_scale
            && crate::resolution_value::numeric_cmp(value, value).is_some() =>
        {
            Ok(())
        }
        _ => Err("upper-bound evidence is not numeric for the target field".into()),
    }
}

pub(super) fn validate_exact(
    family: &Family,
    field: &str,
    projection: ConstraintProjection,
    value: &ResolutionValue,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    let path = projection_path(family.value_schema.domain, field, projection)?;
    crate::resolution_value::validate_at(value, family.value_schema, path, catalogs)
        .map_err(|_| "exact constraint value violates the target field schema".into())
}

pub(super) fn validate_domain(
    family: &Family,
    field: &str,
    ceiling: ExternalCeiling,
    projection: ConstraintProjection,
    value: &ConstraintValue,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    let ConstraintValue::Domain {
        minimum,
        maximum,
        allowed_values,
        required_values,
        preferred,
    } = value
    else {
        return Err("attested-domain relation requires domain evidence".into());
    };
    let allowed_nonempty = allowed_values
        .as_ref()
        .is_some_and(|values| !values.is_empty());
    let required_nonempty = required_values
        .as_ref()
        .is_some_and(|values| !values.is_empty());
    if allowed_values.as_ref().is_some_and(BTreeSet::is_empty)
        || required_values.as_ref().is_some_and(BTreeSet::is_empty)
        || (minimum.is_none() && maximum.is_none() && !allowed_nonempty && !required_nonempty)
    {
        return Err("attested domain is empty or unbounded".into());
    }
    if (minimum.is_some() || maximum.is_some())
        && (allowed_values.is_some() || required_values.is_some())
    {
        return Err("attested domain cannot mix range and set constraints in schema v1".into());
    }
    let path = projection_path(family.value_schema.domain, field, projection)?;
    let raw_target = target_domain(family.value_schema.domain, path)?;
    let structured_target = !matches!(raw_target, TargetDomain::Scalar(_));
    if structured_target
        && (minimum.is_some()
            || maximum.is_some()
            || required_values.is_some()
            || !allowed_nonempty)
    {
        return Err(
            "whole structured-value authority requires exact allowed-value alternatives".into(),
        );
    }
    match ceiling {
        ExternalCeiling::ProviderCapability => {}
        ExternalCeiling::VerificationFloor
            if ((structured_target && allowed_nonempty)
                || (!structured_target && minimum.is_some()))
                && preferred.is_none() => {}
        ExternalCeiling::TenantScope
            if minimum.is_none()
                && maximum.is_none()
                && preferred.is_none()
                && (allowed_nonempty || required_nonempty) => {}
        ExternalCeiling::OperatorAuthority if preferred.is_none() => {}
        ExternalCeiling::VerificationFloor => {
            return Err("verification floor requires a minimum and forbids preferred".into());
        }
        ExternalCeiling::TenantScope => {
            return Err("tenant scope requires allow/required whole-value evidence".into());
        }
        ExternalCeiling::OperatorAuthority => {
            return Err("operator authority forbids preferred values".into());
        }
        _ if minimum.is_none()
            && maximum.is_none()
            && preferred.is_none()
            && (allowed_nonempty || required_nonempty) => {}
        _ => return Err("nonnumeric ceiling requires a bounded set domain".into()),
    }

    if ceiling == ExternalCeiling::OperatorAuthority
        && matches!(raw_target, TargetDomain::MapKeys(_) | TargetDomain::Whole)
        && (minimum.is_some() || maximum.is_some() || (!allowed_nonempty && !required_nonempty))
    {
        return Err("operator map/object authority requires exact whole-value sets".into());
    }
    if ceiling == ExternalCeiling::ProviderCapability
        && !matches!(raw_target, TargetDomain::Scalar(_))
        && !allowed_nonempty
    {
        return Err("provider collection authority requires whole-value alternatives".into());
    }
    let target = TargetDomain::Whole;
    if required_values
        .as_ref()
        .is_some_and(|values| values.len() > 1)
    {
        return Err("whole-value required domain has multiple incompatible values".into());
    }
    if let (Some(allowed), Some(required)) = (allowed_values, required_values)
        && required.iter().any(|value| !allowed.contains(value))
    {
        return Err("whole-value allowed and required domains do not intersect".into());
    }
    for bound in minimum.iter().chain(maximum) {
        validate_exact(family, field, projection, bound, catalogs)?;
    }
    if let (Some(minimum), Some(maximum)) = (minimum, maximum)
        && !meets_floor(maximum, minimum)
    {
        return Err("attested domain minimum exceeds maximum".into());
    }
    for values in [allowed_values, required_values].into_iter().flatten() {
        for member in values {
            validate_member(family, field, projection, target, member, catalogs)?;
        }
    }
    if let Some(preferred) = preferred {
        validate_exact(family, field, projection, preferred, catalogs)?;
        if !admits(target, preferred, value) {
            return Err("provider preferred value is outside its attested domain".into());
        }
    }
    Ok(())
}

pub(super) fn admits_value(
    family: &Family,
    field: &str,
    projection: ConstraintProjection,
    candidate: &ResolutionValue,
    domain: &ConstraintValue,
) -> bool {
    projection_path(family.value_schema.domain, field, projection)
        .and_then(|path| target_domain(family.value_schema.domain, path))
        .is_ok_and(|_| admits(TargetDomain::Whole, candidate, domain))
}

pub(super) fn preferred(domain: &ConstraintValue) -> Option<&ResolutionValue> {
    match domain {
        ConstraintValue::Domain { preferred, .. } => preferred.as_ref(),
        _ => None,
    }
}

fn admits(target: TargetDomain, candidate: &ResolutionValue, domain: &ConstraintValue) -> bool {
    let ConstraintValue::Domain {
        minimum,
        maximum,
        allowed_values,
        required_values,
        ..
    } = domain
    else {
        return false;
    };
    minimum
        .as_ref()
        .is_none_or(|minimum| meets_floor(candidate, minimum))
        && maximum
            .as_ref()
            .is_none_or(|maximum| meets_floor(maximum, candidate))
        && allowed_values
            .as_ref()
            .is_none_or(|allowed| is_allowed(target, candidate, allowed))
        && required_values
            .as_ref()
            .is_none_or(|required| contains_required(target, candidate, required))
}

fn is_allowed(
    target: TargetDomain,
    candidate: &ResolutionValue,
    allowed: &BTreeSet<ResolutionValue>,
) -> bool {
    match (target, candidate) {
        (TargetDomain::List(_), ResolutionValue::List { items }) => {
            items.iter().all(|item| allowed.contains(item))
        }
        (TargetDomain::MapKeys(_), ResolutionValue::Map { entries }) => entries
            .keys()
            .all(|key| allowed.contains(&ResolutionValue::Text { value: key.clone() })),
        _ => allowed.contains(candidate),
    }
}

fn contains_required(
    target: TargetDomain,
    candidate: &ResolutionValue,
    required: &BTreeSet<ResolutionValue>,
) -> bool {
    match (target, candidate) {
        (TargetDomain::List(_), ResolutionValue::List { items }) => {
            required.iter().all(|item| items.contains(item))
        }
        (TargetDomain::MapKeys(_), ResolutionValue::Map { entries }) => required.iter().all(
            |key| matches!(key, ResolutionValue::Text { value } if entries.contains_key(value)),
        ),
        _ => required.iter().all(|value| value == candidate),
    }
}

fn meets_floor(candidate: &ResolutionValue, floor: &ResolutionValue) -> bool {
    match (candidate, floor) {
        (
            ResolutionValue::Boolean { value: candidate },
            ResolutionValue::Boolean { value: floor },
        ) => *candidate || !*floor,
        (ResolutionValue::List { items }, ResolutionValue::List { items: required }) => {
            required.iter().all(|item| items.contains(item))
        }
        (ResolutionValue::Map { entries }, ResolutionValue::Map { entries: required }) => required
            .iter()
            .all(|(key, value)| entries.get(key) == Some(value)),
        (ResolutionValue::Object { fields }, ResolutionValue::Object { fields: required }) => {
            required.iter().all(|(key, value)| {
                fields
                    .get(key)
                    .is_some_and(|actual| meets_floor(actual, value))
            })
        }
        _ => {
            crate::resolution_value::numeric_cmp(candidate, floor)
                .is_some_and(|ordering| ordering != Ordering::Less)
                || candidate == floor
        }
    }
}

fn validate_member(
    family: &Family,
    field: &str,
    projection: ConstraintProjection,
    target: TargetDomain,
    member: &ResolutionValue,
    catalogs: &BTreeMap<&str, &CatalogSnapshot>,
) -> Result<(), String> {
    let scalar_member = match target {
        TargetDomain::List(domain) => Some((domain, member.clone())),
        TargetDomain::MapKeys(domain) => {
            let ResolutionValue::Text { value } = member else {
                return Err("constraint map-key member must use the text tag".into());
            };
            let canonical = match domain {
                ScalarDomain::Enum { .. } => ResolutionValue::Enum {
                    value: value.clone(),
                },
                ScalarDomain::Text { .. } => ResolutionValue::Text {
                    value: value.clone(),
                },
                _ => return Err("constraint map-key domain is not textual".into()),
            };
            Some((domain, canonical))
        }
        TargetDomain::Scalar(_) | TargetDomain::Whole => None,
    };
    if let Some((domain, canonical)) = scalar_member {
        let schema = ValueSchema {
            schema_id: "iteron://tunables/internal/constraint-member-v1",
            kind: ValueKind::String,
            domain: StructuredValueDomain::Scalar { domain },
            rules: &[],
        };
        crate::resolution_value::validate(&canonical, schema, catalogs)
            .map_err(|_| "constraint set member violates its target member schema".into())
    } else {
        validate_exact(family, field, projection, member, catalogs)
    }
}

fn projection_path(
    root: StructuredValueDomain,
    field: &str,
    projection: ConstraintProjection,
) -> Result<&str, String> {
    match projection {
        ConstraintProjection::WholeValue => Ok(field),
        ConstraintProjection::WholeCatalog => {
            if !matches!(root, StructuredValueDomain::Catalog { .. }) {
                return Err("whole-catalog projection requires a catalog schema".into());
            }
            target_domain(root, field)?;
            Ok("$")
        }
    }
}

fn target_domain(root: StructuredValueDomain, path: &str) -> Result<TargetDomain, String> {
    if path == "$" {
        return Ok(match root {
            StructuredValueDomain::Scalar { domain } => TargetDomain::Scalar(domain),
            StructuredValueDomain::List { item, .. } => TargetDomain::List(item),
            StructuredValueDomain::Map { key, .. } => TargetDomain::MapKeys(key),
            StructuredValueDomain::Object { .. } | StructuredValueDomain::Catalog { .. } => {
                TargetDomain::Whole
            }
        });
    }
    let fields = match root {
        StructuredValueDomain::Object { fields, .. }
        | StructuredValueDomain::Catalog {
            entry_fields: fields,
            ..
        } => fields,
        _ => return Err("constraint path does not address an object".into()),
    };
    field_target(fields, path)
}

fn field_target(fields: &[crate::SchemaField], path: &str) -> Result<TargetDomain, String> {
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let field = fields
        .iter()
        .find(|field| field.name == head)
        .ok_or_else(|| "constraint path is absent from the schema".to_owned())?;
    if !tail.is_empty() {
        return match field.domain {
            FieldDomain::Object { fields, .. } => field_target(fields, tail),
            _ => Err("nested constraint path does not address an object".into()),
        };
    }
    Ok(match field.domain {
        FieldDomain::Scalar { domain } => TargetDomain::Scalar(domain),
        FieldDomain::List { item, .. } => TargetDomain::List(item),
        FieldDomain::Map { key, .. } => TargetDomain::MapKeys(key),
        FieldDomain::Object { .. } => TargetDomain::Whole,
    })
}

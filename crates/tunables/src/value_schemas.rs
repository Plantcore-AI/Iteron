use crate::ValueSchema;

macro_rules! schema_id {
    ($id:literal) => {
        concat!("core://tunables/families/", $id, "/value-v1")
    };
}

macro_rules! catalog_id {
    ($id:literal) => {
        concat!("core://tunables/catalogs/", $id, "-v1")
    };
}

macro_rules! bool_domain {
    () => {
        crate::ScalarDomain::Boolean
    };
}

macro_rules! int_domain {
    ($min:expr, $max:expr, $unit:literal) => {
        crate::ScalarDomain::Integer {
            min: $min,
            max: $max,
            unit: $unit,
        }
    };
}

macro_rules! decimal_domain {
    ($min_coefficient:expr, $min_scale:expr, $max_coefficient:expr, $max_scale:expr, $scale:expr, $unit:literal) => {
        crate::ScalarDomain::Decimal {
            min: crate::DecimalValue {
                coefficient: $min_coefficient,
                scale: $min_scale,
            },
            max: crate::DecimalValue {
                coefficient: $max_coefficient,
                scale: $max_scale,
            },
            max_scale: $scale,
            unit: $unit,
        }
    };
}

macro_rules! text_domain {
    ($min:expr, $max:expr, $format:ident) => {
        crate::ScalarDomain::Text {
            min_bytes: $min,
            max_bytes: $max,
            format: crate::StringFormat::$format,
        }
    };
}

macro_rules! finite_enum_domain {
    ($($value:literal),+ $(,)?) => {
        crate::ScalarDomain::Enum {
            values: &[$($value),+],
            catalog_id: None,
        }
    };
}

macro_rules! catalog_enum_domain {
    ($id:literal) => {
        crate::ScalarDomain::Enum {
            values: &[],
            catalog_id: Some(catalog_id!($id)),
        }
    };
}

macro_rules! scalar_field {
    ($name:literal, $required:expr, $domain:expr) => {
        crate::SchemaField {
            name: $name,
            required: $required,
            domain: crate::FieldDomain::Scalar { domain: $domain },
        }
    };
}

macro_rules! list_field {
    ($name:literal, $required:expr, $min:expr, $max:expr, $unique:expr, $item:expr) => {
        crate::SchemaField {
            name: $name,
            required: $required,
            domain: crate::FieldDomain::List {
                min_items: $min,
                max_items: $max,
                unique_items: $unique,
                item: $item,
            },
        }
    };
}

macro_rules! map_field {
    ($name:literal, $required:expr, $min:expr, $max:expr, $key:expr, $value:expr) => {
        crate::SchemaField {
            name: $name,
            required: $required,
            domain: crate::FieldDomain::Map {
                min_entries: $min,
                max_entries: $max,
                key: $key,
                value: $value,
            },
        }
    };
}

macro_rules! external_rule {
    ($field:literal, $ceiling:ident) => {
        crate::CrossFieldRule::ExternalCeiling {
            field: $field,
            ceiling: crate::ExternalCeiling::$ceiling,
            projection: crate::ConstraintProjection::WholeValue,
            relation: external_relation!($ceiling),
            violation: external_violation!($ceiling),
        }
    };
}

/// A non-numeric target constrained by a budget authority uses an attested admissible domain.
/// The registry owns the reject action; request evidence cannot choose clamp/degrade behavior.
macro_rules! external_domain_rule {
    ($field:literal, $ceiling:ident) => {
        crate::CrossFieldRule::ExternalCeiling {
            field: $field,
            ceiling: crate::ExternalCeiling::$ceiling,
            projection: crate::ConstraintProjection::WholeValue,
            relation: crate::ConstraintRelation::AttestedDomain,
            violation: crate::ConstraintViolation::Reject,
        }
    };
}

/// A catalog-entry policy is executable in the pure resolver only as an attestation over the
/// complete inline catalog or its content-addressed reference. Entry materialization belongs to
/// the runtime binding layer; the resolver never silently skips the rule.
macro_rules! external_catalog_rule {
    ($field:literal, $ceiling:ident) => {
        crate::CrossFieldRule::ExternalCeiling {
            field: $field,
            ceiling: crate::ExternalCeiling::$ceiling,
            projection: crate::ConstraintProjection::WholeCatalog,
            relation: external_catalog_relation!($ceiling),
            violation: crate::ConstraintViolation::Reject,
        }
    };
}

macro_rules! external_catalog_relation {
    (BenchmarkProtocol) => {
        crate::ConstraintRelation::Exact
    };
    ($ceiling:ident) => {
        crate::ConstraintRelation::AttestedDomain
    };
}

macro_rules! external_relation {
    (ParentTurns) => {
        crate::ConstraintRelation::UpperBound
    };
    (ParentTokens) => {
        crate::ConstraintRelation::UpperBound
    };
    (ParentWall) => {
        crate::ConstraintRelation::UpperBound
    };
    (ParentCost) => {
        crate::ConstraintRelation::UpperBound
    };
    (ContextWindow) => {
        crate::ConstraintRelation::UpperBound
    };
    (ToolBudget) => {
        crate::ConstraintRelation::UpperBound
    };
    (ProcessBudget) => {
        crate::ConstraintRelation::UpperBound
    };
    (RunBudget) => {
        crate::ConstraintRelation::UpperBound
    };
    (BenchmarkProtocol) => {
        crate::ConstraintRelation::Exact
    };
    (OperatorAuthority) => {
        crate::ConstraintRelation::AttestedDomain
    };
    (ProviderCapability) => {
        crate::ConstraintRelation::AttestedDomain
    };
    (VerificationFloor) => {
        crate::ConstraintRelation::AttestedDomain
    };
    (TenantScope) => {
        crate::ConstraintRelation::AttestedDomain
    };
}

macro_rules! external_violation {
    (ParentTurns) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ParentTokens) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ParentWall) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ParentCost) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ContextWindow) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ToolBudget) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ProcessBudget) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (RunBudget) => {
        crate::ConstraintViolation::ClampNumeric
    };
    (ProviderCapability) => {
        crate::ConstraintViolation::DegradeAttested {
            policy_id: "core://tunables/degrade/provider-attested-preferred-v1",
        }
    };
    (OperatorAuthority) => {
        crate::ConstraintViolation::Reject
    };
    (VerificationFloor) => {
        crate::ConstraintViolation::Reject
    };
    (TenantScope) => {
        crate::ConstraintViolation::Reject
    };
    (BenchmarkProtocol) => {
        crate::ConstraintViolation::Reject
    };
}

macro_rules! less_equal_rule {
    ($left:literal, $right:literal) => {
        crate::CrossFieldRule::LessOrEqual {
            left: $left,
            right: $right,
        }
    };
}

macro_rules! sum_rule {
    ([$($term:literal),+ $(,)?], $limit:literal) => {
        crate::CrossFieldRule::SumLessOrEqual {
            terms: &[$($term),+],
            limit: $limit,
        }
    };
}

macro_rules! requires_bool_rule {
    ($if_field:literal, $value:expr, $then_field:literal) => {
        crate::CrossFieldRule::Requires {
            if_field: $if_field,
            equals: crate::RuleValue::Boolean { value: $value },
            then_field: $then_field,
        }
    };
}

macro_rules! scalar_schema {
    ($id:literal, $kind:ident, $domain:expr, [$($rule:expr),* $(,)?]) => {
        crate::ValueSchema {
            schema_id: schema_id!($id),
            kind: crate::ValueKind::$kind,
            domain: crate::StructuredValueDomain::Scalar { domain: $domain },
            rules: &[$($rule),*],
        }
    };
}

macro_rules! list_schema {
    ($id:literal, $min:expr, $max:expr, $unique:expr, $item:expr, [$($rule:expr),* $(,)?]) => {
        crate::ValueSchema {
            schema_id: schema_id!($id),
            kind: crate::ValueKind::List,
            domain: crate::StructuredValueDomain::List {
                min_items: $min,
                max_items: $max,
                item: $item,
                unique_items: $unique,
            },
            rules: &[$($rule),*],
        }
    };
}

macro_rules! map_schema {
    ($id:literal, $min:expr, $max:expr, $key:expr, $value:expr, [$($rule:expr),* $(,)?]) => {
        crate::ValueSchema {
            schema_id: schema_id!($id),
            kind: crate::ValueKind::Map,
            domain: crate::StructuredValueDomain::Map {
                min_entries: $min,
                max_entries: $max,
                key: $key,
                value: $value,
            },
            rules: &[$($rule),*],
        }
    };
}

macro_rules! object_schema {
    ($id:literal, [$($field:expr),+ $(,)?], [$($rule:expr),* $(,)?]) => {
        crate::ValueSchema {
            schema_id: schema_id!($id),
            kind: crate::ValueKind::Policy,
            domain: crate::StructuredValueDomain::Object {
                fields: &[$($field),+],
                additional_fields: false,
            },
            rules: &[$($rule),*],
        }
    };
}

macro_rules! catalog_schema {
    ($id:literal, $max:expr, [$($field:expr),+ $(,)?], [$($rule:expr),* $(,)?]) => {
        crate::ValueSchema {
            schema_id: schema_id!($id),
            kind: crate::ValueKind::Catalog,
            domain: crate::StructuredValueDomain::Catalog {
                catalog_id: catalog_id!($id),
                min_entries: 0,
                max_entries: $max,
                entry_fields: &[$($field),+],
            },
            rules: &[$($rule),*],
        }
    };
}

mod appendix;
mod current;

pub(crate) const fn value_schema(ordinal: u16) -> ValueSchema {
    if ordinal <= 85 {
        current::value_schema(ordinal)
    } else {
        appendix::value_schema(ordinal)
    }
}

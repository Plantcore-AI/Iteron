//! Small, fail-closed validator for the JSON Schema subset used by tool specifications.
//!
//! Tool schemas cross an authority boundary: providers may use them to constrain generation, but
//! the registry must still verify the received `ToolUse` before any executor runs. Keeping the
//! supported subset explicit prevents an externally supplied schema keyword from being silently
//! ignored and mistaken for an enforced constraint.

use crate::schema_error::ArgumentError;
use serde_json::{Map, Value};
use std::fmt;

const SUPPORTED_TYPES: &[&str] = &["object", "array", "string", "integer", "boolean"];
const MAX_SCHEMA_DEPTH: usize = 16;
const MAX_SCHEMA_NODES: usize = 1_024;
const MAX_OBJECT_FIELDS: usize = 256;
const MAX_ARRAY_ITEMS: usize = 4_096;

/// A malformed or unsupported schema. These errors are registration failures, so an external
/// tool cannot advertise constraints that this registry does not actually enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaError {
    path: String,
    detail: String,
}

impl SchemaError {
    fn new(path: &str, detail: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.detail, self.path)
    }
}

/// Check once at registration that every asserted constraint belongs to the supported subset.
pub(crate) fn validate_schema(schema: &Value) -> Result<(), SchemaError> {
    let mut remaining_nodes = MAX_SCHEMA_NODES;
    validate_schema_at(schema, "$", 0, &mut remaining_nodes)
}

fn validate_schema_at(
    schema: &Value,
    path: &str,
    depth: usize,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::new(
            path,
            format!("schema exceeds maximum depth of {MAX_SCHEMA_DEPTH}"),
        ));
    }
    let Some(next_remaining) = remaining_nodes.checked_sub(1) else {
        return Err(SchemaError::new(
            path,
            format!("schema exceeds maximum of {MAX_SCHEMA_NODES} nodes"),
        ));
    };
    *remaining_nodes = next_remaining;
    let object = schema
        .as_object()
        .ok_or_else(|| SchemaError::new(path, "schema must be an object"))?;

    // This allowlist and `validate_arguments_at` are two halves of one contract: every keyword
    // admitted here is enforced there, and each of the eight below appears in both. Do not add a
    // keyword to this list alone. `enum` in particular looks harmless because it only narrows what
    // is valid, so it cannot widen what a server may ask for; but nothing checks it at call time,
    // so admitting it would make it the first keyword advertised to the model and not enforced.
    // A constraint that is announced and unchecked is worse than one that is refused. If `enum`
    // is wanted, add the check to `validate_arguments_at` in the same change.
    for keyword in object.keys() {
        if !matches!(
            keyword.as_str(),
            "type"
                | "properties"
                | "required"
                | "items"
                | "minItems"
                | "maxItems"
                | "description"
                | "minimum"
        ) {
            return Err(SchemaError::new(
                format!("{path}.{keyword}").as_str(),
                format!("unsupported schema keyword `{keyword}`"),
            ));
        }
    }

    if let Some(description) = object.get("description")
        && !description.is_string()
    {
        return Err(SchemaError::new(
            &format!("{path}.description"),
            "`description` must be a string",
        ));
    }

    let declared_type = match object.get("type") {
        Some(Value::String(value)) if SUPPORTED_TYPES.contains(&value.as_str()) => {
            Some(value.as_str())
        }
        Some(Value::String(value)) => {
            return Err(SchemaError::new(
                &format!("{path}.type"),
                format!("unsupported schema type `{value}`"),
            ));
        }
        Some(_) => {
            return Err(SchemaError::new(
                &format!("{path}.type"),
                "`type` must be a supported string",
            ));
        }
        None => None,
    };

    if object.contains_key("properties") || object.contains_key("required") {
        if declared_type != Some("object") {
            return Err(SchemaError::new(
                path,
                "`properties` and `required` require `type: object` in the supported subset",
            ));
        }
        if let Some(properties) = object.get("properties") {
            let properties = properties.as_object().ok_or_else(|| {
                SchemaError::new(
                    &format!("{path}.properties"),
                    "`properties` must be an object",
                )
            })?;
            if properties.len() > MAX_OBJECT_FIELDS {
                return Err(SchemaError::new(
                    &format!("{path}.properties"),
                    format!("object schema exceeds maximum of {MAX_OBJECT_FIELDS} properties"),
                ));
            }
            for (name, property_schema) in properties {
                validate_schema_at(
                    property_schema,
                    &format!("{path}.properties.{name}"),
                    depth + 1,
                    remaining_nodes,
                )?;
            }
        }
        if let Some(required) = object.get("required") {
            let required = required.as_array().ok_or_else(|| {
                SchemaError::new(
                    &format!("{path}.required"),
                    "`required` must be an array of unique strings",
                )
            })?;
            if required.len() > MAX_OBJECT_FIELDS {
                return Err(SchemaError::new(
                    &format!("{path}.required"),
                    format!("object schema exceeds maximum of {MAX_OBJECT_FIELDS} required fields"),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for (index, field) in required.iter().enumerate() {
                let field = field.as_str().ok_or_else(|| {
                    SchemaError::new(
                        &format!("{path}.required[{index}]"),
                        "required field names must be strings",
                    )
                })?;
                if !seen.insert(field) {
                    return Err(SchemaError::new(
                        &format!("{path}.required[{index}]"),
                        format!("duplicate required field `{field}`"),
                    ));
                }
            }
        }
    }

    if let Some(minimum) = object.get("minimum") {
        if declared_type != Some("integer") {
            return Err(SchemaError::new(
                &format!("{path}.minimum"),
                "`minimum` requires `type: integer` in the supported subset",
            ));
        }
        if minimum.as_i64().is_none() {
            return Err(SchemaError::new(
                &format!("{path}.minimum"),
                "`minimum` must be an integer representable as i64",
            ));
        }
    }

    if (object.contains_key("items")
        || object.contains_key("minItems")
        || object.contains_key("maxItems"))
        && declared_type != Some("array")
    {
        return Err(SchemaError::new(
            path,
            "`items`, `minItems`, and `maxItems` require `type: array` in the supported subset",
        ));
    }
    if declared_type == Some("array") {
        let items = object.get("items").ok_or_else(|| {
            SchemaError::new(
                path,
                "array schemas require `items` in the supported subset",
            )
        })?;
        validate_schema_at(items, &format!("{path}.items"), depth + 1, remaining_nodes)?;
        let maximum = schema_item_count(object, "maxItems", path)?.ok_or_else(|| {
            SchemaError::new(
                path,
                "array schemas require bounded `maxItems` in the supported subset",
            )
        })?;
        if maximum > MAX_ARRAY_ITEMS {
            return Err(SchemaError::new(
                &format!("{path}.maxItems"),
                format!("`maxItems` exceeds supported maximum of {MAX_ARRAY_ITEMS}"),
            ));
        }
        if let Some(minimum) = schema_item_count(object, "minItems", path)?
            && minimum > maximum
        {
            return Err(SchemaError::new(
                path,
                "`minItems` must not exceed `maxItems`",
            ));
        }
    }

    Ok(())
}

fn schema_item_count(
    schema: &Map<String, Value>,
    keyword: &str,
    path: &str,
) -> Result<Option<usize>, SchemaError> {
    let Some(value) = schema.get(keyword) else {
        return Ok(None);
    };
    let count = value.as_u64().ok_or_else(|| {
        SchemaError::new(
            &format!("{path}.{keyword}"),
            format!("`{keyword}` must be a non-negative integer"),
        )
    })?;
    usize::try_from(count).map(Some).map_err(|_| {
        SchemaError::new(
            &format!("{path}.{keyword}"),
            format!("`{keyword}` is too large for this platform"),
        )
    })
}

/// Validate one invocation against a schema already accepted by [`validate_schema`].
pub(crate) fn validate_arguments(schema: &Value, input: &Value) -> Result<(), ArgumentError> {
    validate_arguments_at(schema, input, "$")
}

fn validate_arguments_at(schema: &Value, input: &Value, path: &str) -> Result<(), ArgumentError> {
    // Registration guarantees this shape. Treat a violated internal invariant as no constraints
    // here; callers cannot bypass registration to install a `Tool` in a `Registry`.
    let Some(schema) = schema.as_object() else {
        return Ok(());
    };
    let declared_type = schema.get("type").and_then(Value::as_str);

    if let Some(expected) = declared_type
        && !has_type(input, expected)
    {
        return Err(ArgumentError::TypeMismatch {
            field: display_path(path),
            expected: supported_type(expected),
            actual: value_type(input),
        });
    }

    if declared_type == Some("object") {
        let object = input
            .as_object()
            .expect("type was checked before object constraints");
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(ArgumentError::MissingRequired {
                        field: child_path(path, field),
                    });
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, property_schema) in properties {
                if let Some(value) = object.get(field) {
                    validate_arguments_at(property_schema, value, &child_path(path, field))?;
                }
            }
        }
    }

    if declared_type == Some("array") {
        let array = input
            .as_array()
            .expect("type was checked before array constraints");
        if let Some(minimum) = schema
            .get("minItems")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            && array.len() < minimum
        {
            return Err(ArgumentError::TooFewItems {
                field: display_path(path),
                minimum,
                actual: array.len(),
            });
        }
        if let Some(maximum) = schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            && array.len() > maximum
        {
            return Err(ArgumentError::TooManyItems {
                field: display_path(path),
                maximum,
                actual: array.len(),
            });
        }
        if let Some(items) = schema.get("items") {
            for (index, item) in array.iter().enumerate() {
                validate_arguments_at(items, item, &index_path(path, index))?;
            }
        }
    }

    if declared_type == Some("integer")
        && let Some(minimum) = schema.get("minimum").and_then(Value::as_i64)
    {
        let number = input
            .as_number()
            .expect("integer type was checked before minimum");
        let below = match (number.as_i64(), number.as_u64()) {
            (Some(actual), _) => actual < minimum,
            (None, Some(actual)) if minimum > 0 => actual < minimum as u64,
            (None, Some(_)) => false,
            (None, None) => false,
        };
        if below {
            return Err(ArgumentError::BelowMinimum {
                field: display_path(path),
                minimum,
                actual: input.clone(),
            });
        }
    }

    Ok(())
}

fn has_type(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value
            .as_number()
            .is_some_and(|number| number.as_i64().is_some() || number.as_u64().is_some()),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}

fn supported_type(value: &str) -> &'static str {
    match value {
        "object" => "object",
        "array" => "array",
        "string" => "string",
        "integer" => "integer",
        "boolean" => "boolean",
        _ => "unsupported",
    }
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            "integer"
        }
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn child_path(parent: &str, child: &str) -> String {
    if parent == "$" {
        child.into()
    } else {
        format!("{parent}.{child}")
    }
}

fn index_path(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}

fn display_path(path: &str) -> String {
    if path == "$" { "$".into() } else { path.into() }
}

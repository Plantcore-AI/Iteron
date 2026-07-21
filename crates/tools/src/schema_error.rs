//! Machine-readable model-facing errors produced by registry argument validation.

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ArgumentError {
    MissingRequired {
        field: String,
    },
    TypeMismatch {
        field: String,
        expected: &'static str,
        actual: &'static str,
    },
    BelowMinimum {
        field: String,
        minimum: i64,
        actual: Value,
    },
    TooFewItems {
        field: String,
        minimum: usize,
        actual: usize,
    },
    TooManyItems {
        field: String,
        maximum: usize,
        actual: usize,
    },
}

impl ArgumentError {
    /// JSON keeps the error machine-readable while `message` gives the model an immediately
    /// actionable correction. Field names are schema paths without the root `$` prefix.
    pub(crate) fn model_json(&self, tool: &str) -> String {
        let mut object = Map::new();
        object.insert(
            "error".into(),
            Value::String("invalid_tool_arguments".into()),
        );
        object.insert("tool".into(), Value::String(tool.into()));
        match self {
            Self::MissingRequired { field } => {
                fields(&mut object, "missing_required_field", field);
                object.insert(
                    "message".into(),
                    Value::String(format!("missing required field `{field}`")),
                );
            }
            Self::TypeMismatch {
                field,
                expected,
                actual,
            } => {
                fields(&mut object, "type_mismatch", field);
                object.insert("expected".into(), Value::String((*expected).into()));
                object.insert("actual".into(), Value::String((*actual).into()));
                object.insert(
                    "message".into(),
                    Value::String(format!(
                        "field `{field}` must be {expected}, but received {actual}"
                    )),
                );
            }
            Self::BelowMinimum {
                field,
                minimum,
                actual,
            } => {
                fields(&mut object, "below_minimum", field);
                object.insert("minimum".into(), Value::Number((*minimum).into()));
                object.insert("actual".into(), actual.clone());
                object.insert(
                    "message".into(),
                    Value::String(format!(
                        "field `{field}` must be at least {minimum}, but received {actual}"
                    )),
                );
            }
            Self::TooFewItems {
                field,
                minimum,
                actual,
            } => {
                fields(&mut object, "too_few_items", field);
                object.insert("minimum".into(), Value::Number((*minimum).into()));
                object.insert("actual".into(), Value::Number((*actual).into()));
                object.insert(
                    "message".into(),
                    Value::String(format!(
                        "field `{field}` needs at least {minimum} items, but received {actual}"
                    )),
                );
            }
            Self::TooManyItems {
                field,
                maximum,
                actual,
            } => {
                fields(&mut object, "too_many_items", field);
                object.insert("maximum".into(), Value::Number((*maximum).into()));
                object.insert("actual".into(), Value::Number((*actual).into()));
                object.insert(
                    "message".into(),
                    Value::String(format!(
                        "field `{field}` allows at most {maximum} items, but received {actual}"
                    )),
                );
            }
        }
        Value::Object(object).to_string()
    }
}

fn fields(object: &mut Map<String, Value>, kind: &str, field: &str) {
    object.insert("kind".into(), Value::String(kind.into()));
    object.insert("field".into(), Value::String(field.into()));
}

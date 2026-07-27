//! Schema-forced structured output (design §2.5): engine-side validate + retry.
//!
//! When `agent(prompt, {schema})` is called, the engine (in `bindings.rs`) parses the model's text
//! as JSON and validates it against the caller-supplied JSON Schema (draft 2020-12). On failure it
//! re-calls the spawner with the validation errors appended to the prompt, up to [`RETRY_MAX`] times;
//! on success it returns the validated JSON *object* to JS (not a string); on exhaustion it returns
//! `null`. This module owns the pure validation + the small parsing/prompt helpers; the retry loop
//! lives in `bindings.rs` where the spawner is in scope.

use serde_json::Value;

/// Retry cap for schema validation (design §2.5): 5 attempts, then degrade to `null`.
pub const RETRY_MAX: u32 = 5;

/// A compiled JSON Schema validator pinned to draft 2020-12 (design §6 commits to this dialect).
pub struct SchemaValidator {
    validator: jsonschema::Validator,
}

impl SchemaValidator {
    /// Compile a schema. `Err` carries a human message when the schema itself is malformed (the
    /// engine degrades such a call to `null` rather than looping).
    pub fn compile(schema: &Value) -> Result<Self, String> {
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(schema)
            .map_err(|error| error.to_string())?;
        Ok(SchemaValidator { validator })
    }

    /// Validate an instance. `Ok(())` = conforms; `Err(errors)` = the (non-empty) list of validation
    /// messages, which the retry loop hands back to the model.
    pub fn validate(&self, instance: &Value) -> Result<(), Vec<String>> {
        let errors: Vec<String> = self
            .validator
            .iter_errors(instance)
            .map(|error| error.to_string())
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Parse the model's text as JSON. Direct parse first; on failure, salvage the first balanced
/// `{...}` or `[...]` block (models often wrap JSON in prose or ```json fences). `Err` when neither
/// works — that becomes a validation-style error fed back on retry.
pub fn parse_json(text: &str) -> Result<Value, String> {
    let trimmed = strip_code_fence(text.trim());
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(value);
    }
    if let Some(slice) = first_json_block(trimmed) {
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            return Ok(value);
        }
    }
    Err(format!(
        "output is not valid JSON: {}",
        crate::events::truncate_preview(text, 120)
    ))
}

/// Build the retry prompt: the original task + the validation errors + a terse instruction to emit
/// only conforming JSON.
pub fn augment_prompt(original: &str, errors: &[String]) -> String {
    let mut out = String::with_capacity(original.len() + 256);
    out.push_str(original);
    out.push_str("\n\nYour previous response did not satisfy the required JSON schema.\n");
    out.push_str("Validation errors:\n");
    for error in errors.iter().take(10) {
        out.push_str("- ");
        out.push_str(error);
        out.push('\n');
    }
    out.push_str(
        "\nReturn ONLY a JSON value that satisfies the schema. No prose, no explanation, no code fences.",
    );
    out
}

/// Strip a leading/trailing markdown code fence (```json ... ``` or ``` ... ```), if present.
fn strip_code_fence(text: &str) -> &str {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("```") {
        // drop an optional language tag on the first line
        let rest = match rest.find('\n') {
            Some(nl) => &rest[nl + 1..],
            None => rest,
        };
        return rest.strip_suffix("```").unwrap_or(rest).trim();
    }
    t
}

/// Return the first balanced `{...}` or `[...]` slice, skipping string contents. Best-effort.
fn first_json_block(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let start = bytes.iter().position(|&c| c == b'{' || c == b'[')?;
    let open = bytes[start];
    let close = if open == b'{' { b'}' } else { b']' };
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(&text[start..=i]);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "required": ["answer"],
            "properties": { "answer": { "type": "number" } },
            "additionalProperties": false
        })
    }

    #[test]
    fn valid_instance_passes() {
        let v = SchemaValidator::compile(&object_schema()).expect("compile");
        assert!(v.validate(&serde_json::json!({ "answer": 42 })).is_ok());
    }

    #[test]
    fn bad_shape_is_rejected_with_errors() {
        let v = SchemaValidator::compile(&object_schema()).expect("compile");
        let errs = v
            .validate(&serde_json::json!({ "answer": "not-a-number" }))
            .expect_err("should reject");
        assert!(
            !errs.is_empty(),
            "rejection carries at least one error message"
        );
    }

    #[test]
    fn parse_salvages_fenced_json() {
        let v = parse_json("```json\n{\"answer\": 7}\n```").expect("parse");
        assert_eq!(v, serde_json::json!({ "answer": 7 }));
    }

    #[test]
    fn parse_salvages_json_embedded_in_prose() {
        let v = parse_json("Sure! Here it is: {\"answer\": 3} — done.").expect("parse");
        assert_eq!(v, serde_json::json!({ "answer": 3 }));
    }
}

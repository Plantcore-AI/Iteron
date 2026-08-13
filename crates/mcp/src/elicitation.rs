//! Bounded, user-owned form elicitation for MCP server-to-client requests.
//!
//! An MCP server does not gain an input channel merely by asking for one. The host must install a
//! handler, show the server identity and complete request to the operator, and return one of the
//! protocol's three explicit decisions. Without a handler the client does not advertise the
//! capability and inbound requests fail closed.

use crate::{McpError, McpFuture};
use serde_json::{Map, Value, json};

pub const MAX_ELICITATION_MESSAGE_BYTES: usize = 4096;
pub const MAX_ELICITATION_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_ELICITATION_CONTENT_BYTES: usize = 64 * 1024;
pub const MAX_ELICITATION_FIELDS: usize = 64;
pub const MAX_ELICITATION_FIELD_NAME_BYTES: usize = 128;

/// A validated form-mode request. URL mode is intentionally a distinct future capability: it has
/// browser-consent and anti-phishing requirements that a form handler cannot truthfully satisfy.
#[derive(Debug, Clone, PartialEq)]
pub struct ElicitationRequest {
    message: String,
    requested_schema: Value,
}

impl ElicitationRequest {
    pub(crate) fn parse(params: Value) -> Result<Self, McpError> {
        let object = params
            .as_object()
            .ok_or_else(|| protocol("elicitation params must be an object"))?;
        match object.get("mode").and_then(Value::as_str) {
            None | Some("form") => {}
            Some(_) => return Err(protocol("unsupported elicitation mode")),
        }
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("elicitation message is required"))?;
        if message.trim().is_empty()
            || message.len()
                > iteron_tunables::param_integer(
                    "mcp.elicitation.max_elicitation_message_bytes",
                    MAX_ELICITATION_MESSAGE_BYTES,
                )
            || message.chars().any(char::is_control)
        {
            return Err(protocol("elicitation message is not display-safe"));
        }
        let requested_schema = object
            .get("requestedSchema")
            .cloned()
            .ok_or_else(|| protocol("elicitation requestedSchema is required"))?;
        validate_schema(&requested_schema)?;
        Ok(Self {
            message: message.to_owned(),
            requested_schema,
        })
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn requested_schema(&self) -> &Value {
        &self.requested_schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitationAction {
    Accept,
    Decline,
    Cancel,
}

/// The operator's decision. Accepted content is revalidated against the exact server schema before
/// any byte is returned to the server; decline/cancel can never smuggle content along with them.
#[derive(Debug, Clone, PartialEq)]
pub struct ElicitationResponse {
    action: ElicitationAction,
    content: Option<Value>,
}

impl ElicitationResponse {
    pub fn accept(content: Value) -> Self {
        Self {
            action: ElicitationAction::Accept,
            content: Some(content),
        }
    }

    pub const fn decline() -> Self {
        Self {
            action: ElicitationAction::Decline,
            content: None,
        }
    }

    pub const fn cancel() -> Self {
        Self {
            action: ElicitationAction::Cancel,
            content: None,
        }
    }

    pub(crate) fn into_result(self, request: &ElicitationRequest) -> Result<Value, McpError> {
        match self.action {
            ElicitationAction::Accept => {
                let content = self
                    .content
                    .ok_or_else(|| protocol("accepted elicitation has no content"))?;
                if serde_json::to_vec(&content)?.len()
                    > iteron_tunables::param_integer(
                        "mcp.elicitation.max_elicitation_content_bytes",
                        MAX_ELICITATION_CONTENT_BYTES,
                    )
                {
                    return Err(protocol("elicitation response exceeds its byte ceiling"));
                }
                validate_content(request.requested_schema(), &content)?;
                Ok(json!({"action": "accept", "content": content}))
            }
            ElicitationAction::Decline => Ok(json!({"action": "decline"})),
            ElicitationAction::Cancel => Ok(json!({"action": "cancel"})),
        }
    }
}

/// User-interaction port. Implementations must make `server_name` visible and provide accept,
/// decline, and cancel controls; a one-shot/noninteractive frontend should install no handler.
pub trait McpElicitationHandler: Send + Sync {
    fn elicit<'a>(
        &'a self,
        server_name: &'a str,
        request: ElicitationRequest,
    ) -> McpFuture<'a, ElicitationResponse>;
}

fn validate_schema(schema: &Value) -> Result<(), McpError> {
    if serde_json::to_vec(schema)?.len()
        > iteron_tunables::param_integer(
            "mcp.elicitation.max_elicitation_schema_bytes",
            MAX_ELICITATION_SCHEMA_BYTES,
        )
    {
        return Err(protocol("elicitation schema exceeds its byte ceiling"));
    }
    let object = schema
        .as_object()
        .ok_or_else(|| protocol("elicitation schema must be an object"))?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(protocol("elicitation schema root must be an object"));
    }
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| protocol("elicitation schema properties are required"))?;
    if properties.len()
        > iteron_tunables::param_integer(
            "mcp.elicitation.max_elicitation_fields",
            MAX_ELICITATION_FIELDS,
        )
    {
        return Err(protocol("elicitation schema has too many fields"));
    }
    for (name, property) in properties {
        if !valid_field_name(name) || looks_sensitive(name) {
            return Err(protocol("elicitation field name is unsafe"));
        }
        validate_property(property)?;
    }
    if let Some(required) = object.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| protocol("elicitation required must be an array"))?;
        if required.len()
            > iteron_tunables::param_integer(
                "mcp.elicitation.max_elicitation_fields",
                MAX_ELICITATION_FIELDS,
            )
        {
            return Err(protocol("elicitation required has too many fields"));
        }
        for field in required {
            let field = field
                .as_str()
                .ok_or_else(|| protocol("elicitation required entries must be strings"))?;
            if !properties.contains_key(field) {
                return Err(protocol("elicitation required names an unknown field"));
            }
        }
    }
    Ok(())
}

fn validate_property(property: &Value) -> Result<(), McpError> {
    let object = property
        .as_object()
        .ok_or_else(|| protocol("elicitation property must be an object"))?;
    match object.get("type").and_then(Value::as_str) {
        Some("string" | "number" | "integer" | "boolean") => Ok(()),
        Some("array") => {
            let items = object
                .get("items")
                .and_then(Value::as_object)
                .ok_or_else(|| protocol("elicitation array items are required"))?;
            if items.get("type").and_then(Value::as_str) == Some("string")
                && items.get("enum").is_some_and(Value::is_array)
            {
                Ok(())
            } else {
                Err(protocol("elicitation arrays must be string enums"))
            }
        }
        _ if object.get("oneOf").is_some_and(Value::is_array) => Ok(()),
        _ => Err(protocol("elicitation property type is unsupported")),
    }
}

fn validate_content(schema: &Value, content: &Value) -> Result<(), McpError> {
    let content = content
        .as_object()
        .ok_or_else(|| protocol("elicitation content must be an object"))?;
    let schema = schema.as_object().expect("validated schema root");
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("validated schema properties");
    if content.keys().any(|name| !properties.contains_key(name)) {
        return Err(protocol("elicitation content contains an unknown field"));
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !content.contains_key(name) {
                return Err(protocol("elicitation content omits a required field"));
            }
        }
    }
    for (name, value) in content {
        validate_value(
            properties
                .get(name)
                .and_then(Value::as_object)
                .expect("validated property"),
            value,
        )?;
    }
    Ok(())
}

fn validate_value(schema: &Map<String, Value>, value: &Value) -> Result<(), McpError> {
    let valid_type = match schema.get("type").and_then(Value::as_str) {
        Some("string") => value.is_string(),
        Some("number") => value.is_number(),
        Some("integer") => value.as_i64().is_some() || value.as_u64().is_some(),
        Some("boolean") => value.is_boolean(),
        Some("array") => value.is_array(),
        None if schema.contains_key("oneOf") => value.is_string(),
        _ => false,
    };
    if !valid_type {
        return Err(protocol("elicitation content has the wrong field type"));
    }
    if let Some(choices) = schema.get("enum").and_then(Value::as_array)
        && !choices.contains(value)
    {
        return Err(protocol("elicitation content is outside the declared enum"));
    }
    if let Some(choices) = schema.get("oneOf").and_then(Value::as_array)
        && !choices
            .iter()
            .any(|choice| choice.get("const") == Some(value))
    {
        return Err(protocol(
            "elicitation content is outside the declared choices",
        ));
    }
    if let (Some(items), Some(values)) = (
        schema.get("items").and_then(Value::as_object),
        value.as_array(),
    ) && let Some(choices) = items.get("enum").and_then(Value::as_array)
        && values.iter().any(|value| !choices.contains(value))
    {
        return Err(protocol(
            "elicitation content is outside the declared multi-select",
        ));
    }
    Ok(())
}

fn valid_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len()
            <= iteron_tunables::param_integer(
                "mcp.elicitation.max_elicitation_field_name_bytes",
                MAX_ELICITATION_FIELD_NAME_BYTES,
            )
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn looks_sensitive(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    [
        "password",
        "passwd",
        "secret",
        "access_token",
        "refresh_token",
        "api_key",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
    ]
    .iter()
    .any(|needle| normalized == *needle || normalized.ends_with(&format!("_{needle}")))
}

fn protocol(message: &'static str) -> McpError {
    McpError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(schema: Value) -> ElicitationRequest {
        ElicitationRequest::parse(json!({
            "mode": "form",
            "message": "Choose a public profile name",
            "requestedSchema": schema,
        }))
        .unwrap()
    }

    #[test]
    fn form_request_and_matching_response_are_admitted() {
        let request = request(json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"]
        }));
        assert_eq!(request.message(), "Choose a public profile name");
        assert_eq!(
            ElicitationResponse::accept(json!({"name": "plantcore"}))
                .into_result(&request)
                .unwrap()["action"],
            "accept"
        );
    }

    #[test]
    fn url_nested_and_sensitive_form_requests_fail_closed() {
        let base = json!({
            "message": "input",
            "requestedSchema": {"type": "object", "properties": {}}
        });
        let mut url = base.clone();
        url["mode"] = json!("url");
        assert!(ElicitationRequest::parse(url).is_err());

        let mut nested = base.clone();
        nested["requestedSchema"]["properties"] =
            json!({"profile": {"type": "object", "properties": {}}});
        assert!(ElicitationRequest::parse(nested).is_err());

        let mut sensitive = base;
        sensitive["requestedSchema"]["properties"] = json!({"api_key": {"type": "string"}});
        assert!(ElicitationRequest::parse(sensitive).is_err());
    }

    #[test]
    fn accepted_content_cannot_widen_or_violate_the_schema() {
        let request = request(json!({
            "type": "object",
            "properties": {"choice": {"type": "string", "enum": ["a", "b"]}},
            "required": ["choice"]
        }));
        assert!(
            ElicitationResponse::accept(json!({}))
                .into_result(&request)
                .is_err()
        );
        assert!(
            ElicitationResponse::accept(json!({"choice": "c"}))
                .into_result(&request)
                .is_err()
        );
        assert!(
            ElicitationResponse::accept(json!({"choice": "a", "extra": true}))
                .into_result(&request)
                .is_err()
        );
        assert_eq!(
            ElicitationResponse::decline()
                .into_result(&request)
                .unwrap(),
            json!({"action": "decline"})
        );
    }
}

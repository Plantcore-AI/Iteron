//! Bounded, user-owned form elicitation for MCP server-to-client requests.
//!
//! An MCP server does not gain an input channel merely by asking for one. The host must install a
//! handler, show the server identity and complete request to the operator, and return one of the
//! protocol's three explicit decisions. Without a handler the client does not advertise the
//! capability and inbound requests fail closed.

use crate::{McpError, McpFuture};
use serde_json::{Map, Value, json};
use std::sync::Arc;

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

struct MrtrElicitationHandler {
    inner: Arc<dyn crate::McpMrtrHandler>,
}

impl McpElicitationHandler for MrtrElicitationHandler {
    fn elicit<'a>(
        &'a self,
        server_name: &'a str,
        request: ElicitationRequest,
    ) -> McpFuture<'a, ElicitationResponse> {
        Box::pin(async move {
            let input = crate::McpInputRequest::from_elicitation(&request);
            match self
                .inner
                .request(server_name, "elicitation/create", None, vec![input])
                .await?
            {
                crate::McpInputDecision::Approve(mut answers) => {
                    if answers.len() != 1 || answers[0].0 != "form" {
                        return Err(protocol("elicitation handler returned an invalid answer"));
                    }
                    Ok(ElicitationResponse::accept(answers.remove(0).1))
                }
                crate::McpInputDecision::Reject => Ok(ElicitationResponse::decline()),
            }
        })
    }
}

/// Adapt the session's bounded interactive-input port to the standard MCP form-elicitation port.
/// One installed frontend can therefore truthfully serve both 2026 MRTR and ordinary server
/// `elicitation/create` requests.
pub fn elicitation_handler_from_mrtr(
    handler: Arc<dyn crate::McpMrtrHandler>,
) -> Arc<dyn McpElicitationHandler> {
    Arc::new(MrtrElicitationHandler { inner: handler })
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
    reject_unsupported_keywords(
        object,
        &[
            "$schema",
            "type",
            "title",
            "description",
            "properties",
            "required",
        ],
    )?;
    validate_annotations(object, &["$schema", "title", "description"])?;
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
        Some(property_type @ ("string" | "number" | "integer" | "boolean")) => {
            reject_unsupported_keywords(
                object,
                &["type", "title", "description", "default", "enum", "oneOf"],
            )?;
            validate_annotations(object, &["title", "description"])?;
            if object.contains_key("enum") && object.contains_key("oneOf") {
                return Err(protocol("elicitation property choices are unsupported"));
            }
            if let Some(choices) = object.get("enum") {
                validate_enum(choices, property_type)?;
            }
            if let Some(choices) = object.get("oneOf") {
                if property_type != "string" {
                    return Err(protocol("elicitation property choices are unsupported"));
                }
                validate_one_of(choices)?;
            }
            if let Some(default) = object.get("default") {
                validate_value(object, default)?;
            }
            Ok(())
        }
        Some("array") => {
            reject_unsupported_keywords(
                object,
                &["type", "title", "description", "default", "items"],
            )?;
            validate_annotations(object, &["title", "description"])?;
            let items = object
                .get("items")
                .and_then(Value::as_object)
                .ok_or_else(|| protocol("elicitation array items are required"))?;
            reject_unsupported_keywords(items, &["type", "title", "description", "enum"])?;
            validate_annotations(items, &["title", "description"])?;
            if items.get("type").and_then(Value::as_str) != Some("string") {
                return Err(protocol("elicitation array items are unsupported"));
            }
            validate_enum(
                items
                    .get("enum")
                    .ok_or_else(|| protocol("elicitation array items are unsupported"))?,
                "string",
            )?;
            if let Some(default) = object.get("default") {
                validate_value(object, default)?;
            }
            Ok(())
        }
        None if object.get("oneOf").is_some() => {
            reject_unsupported_keywords(object, &["title", "description", "default", "oneOf"])?;
            validate_annotations(object, &["title", "description"])?;
            validate_one_of(&object["oneOf"])?;
            if let Some(default) = object.get("default") {
                validate_value(object, default)?;
            }
            Ok(())
        }
        _ => Err(protocol("elicitation property type is unsupported")),
    }
}

fn reject_unsupported_keywords(
    object: &Map<String, Value>,
    supported: &[&str],
) -> Result<(), McpError> {
    if object.keys().any(|key| !supported.contains(&key.as_str())) {
        return Err(protocol(
            "elicitation schema contains an unsupported keyword",
        ));
    }
    Ok(())
}

fn validate_annotations(object: &Map<String, Value>, annotations: &[&str]) -> Result<(), McpError> {
    if annotations.iter().any(|annotation| {
        object
            .get(*annotation)
            .is_some_and(|value| !value.is_string())
    }) {
        return Err(protocol("elicitation schema annotation must be a string"));
    }
    Ok(())
}

fn validate_enum(choices: &Value, property_type: &str) -> Result<(), McpError> {
    let choices = choices
        .as_array()
        .filter(|choices| !choices.is_empty())
        .ok_or_else(|| protocol("elicitation enum is unsupported"))?;
    if choices
        .iter()
        .any(|choice| !value_matches_type(choice, property_type))
    {
        return Err(protocol("elicitation enum is unsupported"));
    }
    Ok(())
}

fn validate_one_of(choices: &Value) -> Result<(), McpError> {
    let choices = choices
        .as_array()
        .filter(|choices| !choices.is_empty())
        .ok_or_else(|| protocol("elicitation choices are unsupported"))?;
    for choice in choices {
        let choice = choice
            .as_object()
            .ok_or_else(|| protocol("elicitation choices are unsupported"))?;
        reject_unsupported_keywords(choice, &["const", "title", "description"])?;
        if !choice.get("const").is_some_and(Value::is_string)
            || choice.get("title").is_some_and(|title| !title.is_string())
            || choice
                .get("description")
                .is_some_and(|description| !description.is_string())
        {
            return Err(protocol("elicitation choices are unsupported"));
        }
    }
    Ok(())
}

fn value_matches_type(value: &Value, property_type: &str) -> bool {
    match property_type {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}

pub(crate) fn validate_content(schema: &Value, content: &Value) -> Result<(), McpError> {
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

    #[test]
    fn unsupported_validation_constraints_fail_before_input_collection() {
        for property in [
            json!({"type": "string", "minLength": 8}),
            json!({"type": "string", "maxLength": 64}),
            json!({"type": "number", "minimum": 0}),
            json!({"type": "number", "maximum": 100}),
            json!({"type": "array", "items": {"type": "string", "enum": ["a"]}, "minItems": 1}),
            json!({"type": "array", "items": {"type": "string", "enum": ["a"]}, "maxItems": 1}),
            json!({"type": "string", "format": "email"}),
            json!({"type": "array", "items": {"anyOf": [{"const": "a", "title": "A"}]}}),
        ] {
            let result = ElicitationRequest::parse(json!({
                "mode": "form",
                "message": "Choose a value",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"value": property}
                }
            }));
            assert!(
                matches!(result, Err(McpError::Protocol(message)) if message.contains("unsupported")),
                "unsupported property was admitted"
            );
        }
    }

    #[test]
    fn malformed_schema_annotations_fail_before_input_collection() {
        for schema in [
            json!({"type": "object", "$schema": 7, "properties": {}}),
            json!({"type": "object", "title": false, "properties": {}}),
            json!({"type": "object", "description": [], "properties": {}}),
            json!({"type": "object", "properties": {"value": {"type": "string", "title": 7}}}),
            json!({"type": "object", "properties": {"value": {"type": "string", "description": {}}}}),
            json!({"type": "object", "properties": {"value": {"type": "array", "items": {"type": "string", "enum": ["a"], "title": []}}}}),
        ] {
            let result = ElicitationRequest::parse(json!({
                "mode": "form",
                "message": "Choose a value",
                "requestedSchema": schema,
            }));
            assert!(
                matches!(result, Err(McpError::Protocol(message)) if message.contains("annotation")),
                "malformed annotation was admitted"
            );
        }
    }
}

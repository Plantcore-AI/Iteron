//! Evidence from actual serialized native request fields. This proves actual serialized request inclusion,
//! without claiming that a socket write or a remote model consumed those bytes.
use iteron_protocol::{Block, Role};
use iteron_provider::{AdapterKind, request_capture::ProviderWireRequest};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

const MAX_TEXT_FIELDS: usize = 4096;

// deserialize_any retains serde_json's ordinary nesting, Unicode and numeric validation.
// IgnoredAny has a looser skip parser and would accept values the previous Value parse rejected.
struct DiscardValue;
impl<'de> Deserialize<'de> for DiscardValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DiscardVisitor;
        impl<'de> Visitor<'de> for DiscardVisitor {
            type Value = DiscardValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a valid JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(DiscardValue)
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                while sequence.next_element::<DiscardValue>()?.is_some() {}
                Ok(DiscardValue)
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                while map.next_key::<DiscardValue>()?.is_some() {
                    map.next_value::<DiscardValue>()?;
                }
                Ok(DiscardValue)
            }
        }
        deserializer.deserialize_any(DiscardVisitor)
    }
}

#[derive(Default)]
struct InclusionFields {
    system: Option<Value>,
    instructions: Option<Value>,
    messages: Option<Value>,
    input: Option<Value>,
}

impl<'de> Deserialize<'de> for InclusionFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;
        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = InclusionFields;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an actual provider request object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = InclusionFields::default();
                while let Some(key) = map.next_key::<String>()? {
                    let destination = match key.as_str() {
                        "system" => Some(&mut fields.system),
                        "instructions" => Some(&mut fields.instructions),
                        "messages" => Some(&mut fields.messages),
                        "input" => Some(&mut fields.input),
                        _ => None,
                    };
                    if let Some(destination) = destination {
                        // serde_json::Value keeps the last duplicate field; retain that exact
                        // rule and distinguish a present null from an absent field.
                        *destination = Some(map.next_value()?);
                    } else {
                        // Tool schemas, reasoning controls and unrelated wire fields have no
                        // inclusion authority. Validate their JSON without allocating value trees.
                        map.next_value::<DiscardValue>()?;
                    }
                }
                Ok(fields)
            }
        }
        deserializer.deserialize_map(FieldsVisitor)
    }
}

pub(super) fn context_included(wire: &ProviderWireRequest<'_>) -> bool {
    if wire.body.len() > 32 * 1024 * 1024 {
        return false;
    }
    let Ok(body) = serde_json::from_slice::<InclusionFields>(wire.body) else {
        return false;
    };
    let mut system = Vec::new();
    let mut user = Vec::new();
    let (system_value, messages) = match wire.adapter {
        AdapterKind::AnthropicMessages => (body.system.as_ref(), body.messages.as_ref()),
        AdapterKind::OpenAiResponses => (body.instructions.as_ref(), body.input.as_ref()),
        AdapterKind::OpenAiCompatibleChat => (None, body.messages.as_ref()),
    };
    if let Some(value) = system_value
        && !text_fields(value, &mut system)
    {
        return false;
    }
    let Some(messages) = messages.and_then(Value::as_array) else {
        return false;
    };
    if messages.len() > MAX_TEXT_FIELDS {
        return false;
    }
    for message in messages {
        let destination = match message.get("role").and_then(Value::as_str) {
            Some("system") if wire.adapter == AdapterKind::OpenAiCompatibleChat => &mut system,
            Some("user") => &mut user,
            _ => continue,
        };
        if let Some(content) = message.get("content")
            && !text_fields(content, destination)
        {
            return false;
        }
    }
    if !wire.request.system.is_empty() && !system.iter().any(|text| *text == wire.request.system) {
        return false;
    }
    let mut expected = 0usize;
    for message in &wire.request.messages {
        if message.role != Role::User {
            continue;
        }
        for block in &message.content {
            if let Block::Text { text } = block {
                expected += 1;
                if expected > MAX_TEXT_FIELDS
                    || !user.iter().any(|captured| captured.contains(text.as_str()))
                {
                    return false;
                }
            }
        }
    }
    true
}

fn text_fields<'a>(value: &'a Value, result: &mut Vec<&'a str>) -> bool {
    match value {
        Value::String(text) => {
            if result.len() == MAX_TEXT_FIELDS {
                return false;
            }
            result.push(text);
        }
        Value::Array(blocks) => {
            if blocks.len() > MAX_TEXT_FIELDS {
                return false;
            }
            for block in blocks {
                if matches!(
                    block.get("type").and_then(Value::as_str),
                    Some("text" | "input_text")
                ) {
                    let Some(text) = block.get("text").and_then(Value::as_str) else {
                        return false;
                    };
                    if result.len() == MAX_TEXT_FIELDS {
                        return false;
                    }
                    result.push(text);
                }
            }
        }
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Message, ReasoningEffort};
    use iteron_provider::TurnRequest;
    use serde_json::json;

    fn included(adapter: AdapterKind, body: &[u8]) -> bool {
        let request = TurnRequest {
            model: "fixture".into(),
            system: "actual system".into(),
            messages: vec![Message::user_text("actual user")],
            input_images: Vec::new(),
            tools: Vec::new().into(),
            max_tokens: 64,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: ReasoningEffort::Low,
            controls: Default::default(),
        };
        context_included(&ProviderWireRequest {
            adapter,
            method: "POST",
            endpoint: "https://fixture.invalid/v1",
            content_type: "application/json",
            body,
            serialized_output_tokens: 64,
            request: &request,
        })
    }

    #[test]
    fn projected_wire_fields_keep_adapter_roles_and_ignore_tool_text() {
        for adapter in [
            AdapterKind::OpenAiCompatibleChat,
            AdapterKind::OpenAiResponses,
            AdapterKind::AnthropicMessages,
        ] {
            let mut body = json!({"tools":[{"description":"actual user actual system","input_schema":{"role":"user","content":"actual user"}}]});
            match adapter {
                AdapterKind::OpenAiCompatibleChat => {
                    body["messages"] = json!([
                        {"role":"system","content":"actual system"},
                        {"role":"tool","content":"actual user"},
                        {"role":"user","content":"unrelated"}
                    ])
                }
                AdapterKind::OpenAiResponses => {
                    body["instructions"] = json!("actual system");
                    body["input"] = json!([
                        {"type":"function_call_output","output":"actual user"},
                        {"role":"user","content":[{"type":"input_text","text":"unrelated"}]}
                    ]);
                }
                AdapterKind::AnthropicMessages => {
                    body["system"] = json!([{"type":"text","text":"actual system"}]);
                    body["messages"] = json!([{"role":"user","content":[
                        {"type":"tool_result","content":"actual user"},
                        {"type":"text","text":"unrelated"}
                    ]}]);
                }
            }
            assert!(!included(adapter, &serde_json::to_vec(&body).unwrap()));
            let field = if adapter == AdapterKind::OpenAiResponses {
                "input"
            } else {
                "messages"
            };
            body[field]
                .as_array_mut()
                .unwrap()
                .push(json!({"role":"user","content":"actual user"}));
            assert!(included(adapter, &serde_json::to_vec(&body).unwrap()));
        }
    }

    #[test]
    fn projected_wire_duplicates_malformed_json_and_bounds_preserve_inclusion_checks() {
        let adapter = AdapterKind::OpenAiResponses;
        assert!(included(adapter, br#"{"instructions":"wrong","instructions":"actual system","input":[{"role":"user","content":"actual user"}]}"#));
        assert!(!included(adapter, br#"{"instructions":"actual system","instructions":"wrong","input":[{"role":"user","content":"actual user"}]}"#));
        for body in [
            br#"{"instructions":"actual system","input":[{"role":"user","content":"actual user"}],"tools":[1,]}"#.as_slice(),
            br#"{"instructions":null,"input":[{"role":"user","content":"actual user"}]}"#.as_slice(),
            br#"{"system":"actual system","messages":[{"role":"user","content":"actual user"}]}"#.as_slice(),
            br#"{"instructions":"actual system","input":[{"role":"user","content":"actual user"}],"tools":"\uD800"}"#.as_slice(),
            br#"{"instructions":"actual system","input":[{"role":"user","content":"actual user"}],"tools":1e999}"#.as_slice(),
        ] {
            assert!(!included(adapter, body));
        }
        let body = json!({"instructions":"actual system","input":vec![json!({"role":"user","content":"actual user"}); MAX_TEXT_FIELDS + 1]});
        assert!(!included(adapter, &serde_json::to_vec(&body).unwrap()));
        let mut nested = json!(null);
        for _ in 0..130 {
            nested = json!([nested]);
        }
        let body = json!({"instructions":"actual system","input":[{"role":"user","content":"actual user"}],"tools":nested});
        assert!(!included(adapter, &serde_json::to_vec(&body).unwrap()));
    }
}

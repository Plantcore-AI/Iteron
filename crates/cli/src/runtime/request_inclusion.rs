//! Evidence from actual serialized native request fields. This proves retained request inclusion,
//! without claiming that a socket write or a remote model consumed those bytes.
use iteron_protocol::{Block, Role};
use iteron_provider::{AdapterKind, request_capture::ProviderWireRequest};
use serde_json::Value;

const MAX_TEXT_FIELDS: usize = 4096;

pub(super) fn context_included(wire: &ProviderWireRequest<'_>) -> bool {
    if wire.body.len() > 32 * 1024 * 1024 {
        return false;
    }
    let Ok(body) = serde_json::from_slice::<Value>(wire.body) else {
        return false;
    };
    let mut system = Vec::new();
    let mut user = Vec::new();
    let (system_value, messages) = match wire.adapter {
        AdapterKind::AnthropicMessages => (body.get("system"), body.get("messages")),
        AdapterKind::OpenAiResponses => (body.get("instructions"), body.get("input")),
        AdapterKind::OpenAiCompatibleChat => (None, body.get("messages")),
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

//! Model-visible text projection before accounting and physical admission. Source receipts and
//! opaque route continuation retain their original identities; they are not display strings.
use super::KernelError;
use iteron_protocol::{Block, Message};
use iteron_provider::{PreparedToolSchemas, TurnRequest};
use serde_json::Value;

const MAX_JSON_NODES: usize = 8192;
const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy)]
pub(super) enum ProjectionRefusal {
    SensitiveStructuralField,
    Capacity,
}
impl ProjectionRefusal {
    pub(super) fn error(self) -> KernelError {
        match self {
            Self::SensitiveStructuralField => KernelError::SensitiveModelContext,
            Self::Capacity => KernelError::ModelContextProjectionLimit,
        }
    }
}

pub(super) fn text(value: &mut String) -> bool {
    let clean = iteron_record::redact::scrub(value);
    if clean == *value {
        false
    } else {
        *value = clean;
        true
    }
}

pub(super) fn messages(messages: &mut [Message]) -> Result<bool, ProjectionRefusal> {
    let mut changed = false;
    for message in messages {
        for block in &mut message.content {
            changed |= match block {
                Block::Text { text: value } | Block::Thinking { thinking: value } => text(value),
                Block::ToolResult(result) => {
                    // Physical output already has an admitted visible byte envelope. Never
                    // enlarge it by replacing a short credential with a longer marker.
                    let maximum = result.content.len();
                    let changed = text(&mut result.content);
                    if result.content.len() > maximum {
                        let mut end = maximum;
                        while !result.content.is_char_boundary(end) {
                            end -= 1;
                        }
                        result.content.truncate(end);
                    }
                    changed
                }
                Block::ToolUse(call) => {
                    if iteron_record::redact::scrub(&call.name) != call.name {
                        // Historic names may come from an unknown provider call rather than
                        // an advertised spec. Keep operation identity exact and refuse.
                        return Err(ProjectionRefusal::SensitiveStructuralField);
                    }
                    json(&mut call.input)?
                }
                // Authenticated/encrypted continuation and pixel commitments must remain exact.
                // Native adapters alone validate the route/version/state schema before replay.
                Block::ProviderState(_) | Block::ToolImage(_) => false,
            };
        }
    }
    Ok(changed)
}

pub(super) fn content(
    system: &mut String,
    messages_value: &mut [Message],
    tools: &PreparedToolSchemas,
) -> Result<bool, ProjectionRefusal> {
    // Do not rewrite constraints, defaults, tool names or capability/catalog identities. A
    // secret-bearing advertised schema must be corrected by its source owner before dispatch.
    validate_tools(tools)?;
    let changed = text(system);
    Ok(messages(messages_value)? || changed)
}

pub(super) fn request(request: &mut TurnRequest) -> Result<bool, ProjectionRefusal> {
    content(&mut request.system, &mut request.messages, &request.tools)
}

fn json(value: &mut Value) -> Result<bool, ProjectionRefusal> {
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut changed = false;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(ProjectionRefusal::Capacity);
        }
        match value {
            Value::String(value) => changed |= text(value),
            Value::Array(values) => {
                if values.len() > MAX_JSON_NODES.saturating_sub(nodes + pending.len()) {
                    return Err(ProjectionRefusal::Capacity);
                }
                pending.extend(values.iter_mut().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_JSON_NODES.saturating_sub(nodes + pending.len()) {
                    return Err(ProjectionRefusal::Capacity);
                }
                if values
                    .keys()
                    .any(|key| iteron_record::redact::scrub(key) != *key)
                {
                    // Renaming a key would reinterpret an executed operation. Refuse instead.
                    return Err(ProjectionRefusal::SensitiveStructuralField);
                }
                pending.extend(values.values_mut().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(changed)
}

fn validate_tools(tools: &PreparedToolSchemas) -> Result<(), ProjectionRefusal> {
    for tool in tools.iter() {
        if iteron_record::redact::scrub(&tool.name) != tool.name
            || iteron_record::redact::scrub(&tool.description) != tool.description
        {
            return Err(ProjectionRefusal::SensitiveStructuralField);
        }
        // Validate decoded string fields, including PEM/newlines escaped in canonical JSON.
        let mut pending = vec![(&tool.input_schema, 0usize)];
        let mut nodes = 0usize;
        while let Some((value, depth)) = pending.pop() {
            nodes += 1;
            if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
                return Err(ProjectionRefusal::Capacity);
            }
            match value {
                Value::String(value) if iteron_record::redact::scrub(value) != *value => {
                    return Err(ProjectionRefusal::SensitiveStructuralField);
                }
                Value::Array(values) => {
                    if values.len() > MAX_JSON_NODES.saturating_sub(nodes + pending.len()) {
                        return Err(ProjectionRefusal::Capacity);
                    }
                    pending.extend(values.iter().map(|value| (value, depth + 1)));
                }
                Value::Object(values) => {
                    if values.len() > MAX_JSON_NODES.saturating_sub(nodes + pending.len()) {
                        return Err(ProjectionRefusal::Capacity);
                    }
                    if values
                        .keys()
                        .any(|key| iteron_record::redact::scrub(key) != *key)
                    {
                        return Err(ProjectionRefusal::SensitiveStructuralField);
                    }
                    pending.extend(values.values().map(|value| (value, depth + 1)));
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

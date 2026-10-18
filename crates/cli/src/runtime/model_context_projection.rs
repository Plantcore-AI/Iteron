//! Model-visible text projection before accounting and physical admission. Source receipts and
//! opaque route continuation retain their original identities; they are not display strings.
use super::KernelError;
use iteron_protocol::{Block, Message};
use iteron_provider::{PreparedToolSchemas, TurnRequest};
use serde_json::Value;

const MAX_JSON_NODES: usize = 8192;
const MAX_JSON_DEPTH: usize = 64;
const MAX_CLEAN_TEXT_ENTRIES: usize = 256;
const MAX_CLEAN_TEXT_BYTES: usize = 256 * 1024;

#[derive(Default)]
struct CleanTextCache {
    values: std::collections::HashSet<String>,
    bytes: usize,
}
impl CleanTextCache {
    fn remember(&mut self, value: &str) {
        let charge = value.len().saturating_add(128);
        if charge > MAX_CLEAN_TEXT_BYTES || self.values.contains(value) {
            return;
        }
        if self.values.len() == MAX_CLEAN_TEXT_ENTRIES
            || self.bytes.saturating_add(charge) > MAX_CLEAN_TEXT_BYTES
        {
            self.values.clear();
            self.bytes = 0;
        }
        self.values.insert(value.to_owned());
        self.bytes += charge;
    }
}

std::thread_local! {
    // scrub's credential-shape policy is fixed code, with no mutable configuration. Retain only
    // actual text it left unchanged; standard HashSet equality verifies bytes after hashing.
    static CLEAN_TEXT: std::cell::RefCell<CleanTextCache> = std::cell::RefCell::new(CleanTextCache::default());
    // One retained immutable schema allocation per thread. Retention prevents address reuse;
    // distinct allocations must pass the full validation even if their supplied metadata agrees.
    static VALIDATED_TOOL_SCHEMAS: std::cell::RefCell<Option<PreparedToolSchemas>> = const {
        std::cell::RefCell::new(None)
    };
}

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
    if CLEAN_TEXT.with(|cache| cache.borrow().values.contains(value.as_str())) {
        return false;
    }
    let clean = iteron_record::redact::scrub(value);
    if clean == *value {
        CLEAN_TEXT.with(|cache| cache.borrow_mut().remember(value));
        false
    } else {
        *value = clean;
        true
    }
}

fn structural_text_is_clean(value: &str) -> bool {
    if CLEAN_TEXT.with(|cache| cache.borrow().values.contains(value)) {
        return true;
    }
    if iteron_record::redact::scrub(value) != value {
        return false;
    }
    // The same fixed scrub policy governs text and structural fields. Retain only exact bytes
    // it left unchanged; a changed name/key must be checked and can never inherit a receipt.
    CLEAN_TEXT.with(|cache| cache.borrow_mut().remember(value));
    true
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
                    if !structural_text_is_clean(&call.name) {
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
                if values.keys().any(|key| !structural_text_is_clean(key)) {
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
    let validated = VALIDATED_TOOL_SCHEMAS.with(|cached| {
        cached
            .borrow()
            .as_ref()
            .is_some_and(|previous| previous.shares_specs_with(tools))
    });
    if validated {
        return Ok(());
    }
    validate_tools_uncached(tools)?;
    VALIDATED_TOOL_SCHEMAS.with(|cached| *cached.borrow_mut() = Some(tools.clone()));
    Ok(())
}

fn validate_tools_uncached(tools: &PreparedToolSchemas) -> Result<(), ProjectionRefusal> {
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

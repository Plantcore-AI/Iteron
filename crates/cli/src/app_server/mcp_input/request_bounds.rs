//! Admission of actual input metadata before clone, recursion or escaped JSON allocation.
use super::{MAX_PROMPT_BYTES, McpInputPrompt};
use iteron_mcp::McpInputRequest;
use serde_json::Value;
const MAX_SCHEMA_NODES: usize = 8192;
const MAX_SCHEMA_DEPTH: usize = 8;

pub(super) fn requests_fit(
    server: &str,
    tool: &str,
    state: Option<&str>,
    requests: &[McpInputRequest],
) -> bool {
    bounded(
        server,
        tool,
        state,
        requests.len(),
        requests
            .iter()
            .map(|request| (request.id().len(), request.prompt(), request.schema())),
    )
}
pub(super) fn prompt_fits(prompt: &McpInputPrompt) -> bool {
    bounded(
        &prompt.server,
        &prompt.tool,
        prompt.request_state.as_deref(),
        prompt.fields.len(),
        prompt
            .fields
            .iter()
            .map(|field| (field.id.len(), field.prompt.as_str(), &field.schema)),
    )
}
pub(crate) fn prompt_view_fits(
    prompt: &iteron_protocol::client_mcp_input::McpInputPromptViewV1,
) -> bool {
    prompt.request_id != 0
        && bounded(
            &prompt.server_display,
            &prompt.tool_display,
            None,
            prompt.fields.len(),
            prompt.fields.iter().map(|field| {
                (
                    field.field_index.to_string().len(),
                    field.prompt.as_str(),
                    &field.schema,
                )
            }),
        )
}
fn bounded<'a>(
    server: &str,
    tool: &str,
    state: Option<&str>,
    field_count: usize,
    fields: impl Iterator<Item = (usize, &'a str, &'a Value)>,
) -> bool {
    if field_count > iteron_protocol::client_mcp_input::MAX_MCP_INPUT_REQUEST_FIELDS {
        return false;
    }
    let Some(mut remaining) = MAX_PROMPT_BYTES
        .checked_sub(server.len())
        .and_then(|value| value.checked_sub(tool.len()))
        .and_then(|value| value.checked_sub(state.map_or(0, str::len)))
    else {
        return false;
    };
    let mut remaining_nodes = MAX_SCHEMA_NODES;
    for (id, prompt, schema) in fields {
        let Some(value) = remaining
            .checked_sub(id)
            .and_then(|value| value.checked_sub(prompt.len()))
        else {
            return false;
        };
        remaining = value;
        let Some(bytes) = json_bytes(schema, remaining, &mut remaining_nodes) else {
            return false;
        };
        remaining -= bytes;
    }
    true
}
fn json_bytes(value: &Value, remaining: usize, nodes: &mut usize) -> Option<usize> {
    let mut stack = vec![(value, 0_usize)];
    let mut lower_bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        *nodes = nodes.checked_sub(1)?;
        if depth > MAX_SCHEMA_DEPTH {
            return None;
        }
        let bytes = match value {
            Value::String(text) => text.len().checked_add(2)?,
            Value::Array(values) => {
                if values.len().checked_add(stack.len())? > *nodes {
                    return None;
                }
                stack.extend(values.iter().map(|value| (value, depth + 1)));
                values.len().checked_add(2)?
            }
            Value::Object(fields) => {
                if fields.len().checked_add(stack.len())? > *nodes {
                    return None;
                }
                let mut bytes = 2_usize;
                for (key, value) in fields {
                    bytes = bytes.checked_add(key.len().checked_add(4)?)?;
                    if bytes > remaining {
                        return None;
                    }
                    stack.push((value, depth + 1));
                }
                bytes
            }
            Value::Number(_) => 1,
            Value::Bool(_) | Value::Null => 4,
        };
        lower_bytes = lower_bytes.checked_add(bytes)?;
        if lower_bytes > remaining {
            return None;
        }
    }
    struct Counter {
        used: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.used = self
                .used
                .checked_add(bytes.len())
                .filter(|value| *value <= self.limit)
                .ok_or_else(|| std::io::Error::other("input schema bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        used: 0,
        limit: remaining,
    };
    serde_json::to_writer(&mut counter, value).ok()?;
    Some(counter.used)
}

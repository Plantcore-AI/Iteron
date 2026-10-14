//! Scoped observations and answers for an existing host-owned MCP input callback.
//! Response values are transport data, never event, model, artifact or record content.
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MCP_INPUT_CONTRACT_VERSION: u32 = 1;
pub const MAX_MCP_INPUT_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_MCP_INPUT_RESPONSE_NODES: usize = 1024;
pub const MAX_MCP_INPUT_RESPONSE_DEPTH: usize = 8;
pub const MAX_MCP_INPUT_REQUEST_FIELDS: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputCommandV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub command: McpInputActionV1,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpInputActionV1 {
    Read {},
    Wait {
        after_revision: u64,
        timeout_ms: u32,
    },
    Respond {
        request_id: u64,
        answer: McpInputAnswerV1,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpInputAnswerV1 {
    Approve { values: Vec<McpInputValueV1> },
    Reject {},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputValueV1 {
    pub field_index: u16,
    pub content: Value,
}
impl std::fmt::Debug for McpInputCommandV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpInputCommandV1")
            .field("read_only", &self.is_read_only())
            .finish_non_exhaustive()
    }
}
impl McpInputCommandV1 {
    pub fn is_read_only(&self) -> bool {
        matches!(
            self.command,
            McpInputActionV1::Read {} | McpInputActionV1::Wait { .. }
        )
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 256
            || self.thread_id.0.chars().any(char::is_control)
        {
            return Err("invalid input thread identity");
        }
        crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
            run_id: self.run_id.clone(),
        }
        .validate()?;
        match &self.command {
            McpInputActionV1::Wait { timeout_ms, .. } if *timeout_ms > 60_000 => {
                Err("input observation wait exceeds its deadline")
            }
            McpInputActionV1::Respond { request_id, answer } => {
                if *request_id == 0 {
                    return Err("invalid input request identity");
                }
                if let McpInputAnswerV1::Approve { values } = answer {
                    if values.len() > MAX_MCP_INPUT_REQUEST_FIELDS {
                        return Err("input response has too many fields");
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    let mut remaining = MAX_MCP_INPUT_RESPONSE_BYTES;
                    for value in values {
                        if !seen.insert(value.field_index) {
                            return Err("duplicate input field handle");
                        }
                        let bytes = response_value_bytes(&value.content)?;
                        remaining = remaining
                            .checked_sub(bytes)
                            .ok_or("input response exceeds its byte ceiling")?;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Check finite actual shape/scalars before cloning, then count exact JSON bytes with a bounded
/// sink. This preserves valid UTF-8 answers without allocating an escaped response copy.
pub fn response_value_bytes(value: &Value) -> Result<usize, &'static str> {
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_MCP_INPUT_RESPONSE_NODES || depth > MAX_MCP_INPUT_RESPONSE_DEPTH {
            return Err("input response shape exceeds its bound");
        }
        let added = match value {
            Value::String(text) => text.len().saturating_add(2),
            Value::Object(fields) => {
                if fields.len() > 64 {
                    return Err("input response has too many properties");
                }
                let mut keys = 2_usize;
                for (key, value) in fields {
                    keys = keys
                        .checked_add(key.len().saturating_add(4))
                        .ok_or("input response size overflow")?;
                    stack.push((value, depth + 1));
                }
                keys
            }
            Value::Array(values) => {
                if values.len() > 64 {
                    return Err("input response array exceeds its bound");
                }
                for value in values {
                    stack.push((value, depth + 1));
                }
                values.len().saturating_add(2)
            }
            Value::Number(_) => 32,
            Value::Bool(_) | Value::Null => 5,
        };
        if stack.len().saturating_add(nodes) > MAX_MCP_INPUT_RESPONSE_NODES {
            return Err("input response shape exceeds its bound");
        }
        bytes = bytes
            .checked_add(added)
            .ok_or("input response size overflow")?;
        if bytes > MAX_MCP_INPUT_RESPONSE_BYTES {
            return Err("input response exceeds its byte ceiling");
        }
    }
    struct BoundedCount(usize);
    impl std::io::Write for BoundedCount {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|count| *count <= MAX_MCP_INPUT_RESPONSE_BYTES)
                .ok_or_else(|| std::io::Error::other("input response byte ceiling"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedCount(0);
    serde_json::to_writer(&mut output, value)
        .map_err(|_| "input response exceeds its byte ceiling")?;
    Ok(output.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpInputStateV1 {
    Answered,
    Rejected,
    Cancelled,
    TimedOut,
    Unavailable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputClosedV1 {
    pub request_id: u64,
    pub revision: u64,
    pub state: McpInputStateV1,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputFieldViewV1 {
    pub field_index: u16,
    pub prompt: String,
    pub schema: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputPromptViewV1 {
    pub request_id: u64,
    pub server_display: String,
    pub tool_display: String,
    pub fields: Vec<McpInputFieldViewV1>,
    pub prompt_complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpInputsSnapshotV1 {
    pub version: u32,
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub revision: u64,
    pub pending: Vec<McpInputPromptViewV1>,
    pub closed: Vec<McpInputClosedV1>,
    pub omitted_closed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_answer_has_no_actor_schema_path_or_state_authority() {
        let base = serde_json::json!({"thread_id":"session-run","run_id":"run","command":{"action":"read"}});
        for key in ["actor", "path", "schema", "state", "approved"] {
            let mut value = base.clone();
            value[key] = Value::Bool(true);
            assert!(serde_json::from_value::<McpInputCommandV1>(value).is_err());
        }
        let mut value = base;
        value["command"]["answer"] = serde_json::json!({"secret":"never observed"});
        assert!(serde_json::from_value::<McpInputCommandV1>(value).is_err());
    }
    #[test]
    fn answers_are_bounded_and_debug_does_not_expose_the_payload() {
        let mut command: McpInputCommandV1 = serde_json::from_value(serde_json::json!({"thread_id":"session-run","run_id":"run","command":{"action":"respond","request_id":1,"answer":{"action":"approve","values":[{"field_index":0,"content":{"name":"private-value"}}]}}})).unwrap();
        assert!(command.validate().is_ok());
        assert!(!format!("{command:?}").contains("private-value"));
        assert!(!command.is_read_only());
        command.command = McpInputActionV1::Wait {
            after_revision: 0,
            timeout_ms: 60_001,
        };
        assert!(command.validate().is_err());
        assert!(
            response_value_bytes(&Value::String("x".repeat(MAX_MCP_INPUT_RESPONSE_BYTES))).is_err()
        );
    }
}

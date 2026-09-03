//! Bounded 2026 multi-round tool-request input.

use crate::{McpError, McpFuture};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_ROUNDS: usize = 4;
const MAX_REQUESTS_PER_ROUND: usize = 16;
const MAX_TOTAL_REQUESTS: usize = 32;
const MAX_ITEM_BYTES: usize = 4096;
const MAX_TOTAL_INPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct McpInputRequest {
    id: String,
    prompt: String,
    schema: Value,
}

impl McpInputRequest {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn schema(&self) -> &Value {
        &self.schema
    }
}

pub enum McpInputDecision {
    Approve(Vec<(String, Value)>),
    Reject,
}

pub trait McpMrtrHandler: Send + Sync {
    fn request<'a>(
        &'a self,
        server_name: &'a str,
        tool_name: &'a str,
        request_state: Option<&'a str>,
        requests: Vec<McpInputRequest>,
    ) -> McpFuture<'a, McpInputDecision>;
}

/// Validate one operator answer against the exact elicitation form carried by an MRTR request.
/// Frontends can call this before closing their form; the protocol loop validates it again.
pub fn validate_mrtr_input(schema: &Value, content: &Value) -> Result<(), McpError> {
    crate::elicitation::validate_content(schema, content)
}

pub(crate) struct MrtrState {
    rounds: usize,
    total_requests: usize,
    total_input_bytes: usize,
    seen_states: BTreeSet<String>,
}

pub(crate) enum MrtrResult {
    Complete,
    InputRequired {
        request_state: Option<String>,
        requests: Vec<McpInputRequest>,
    },
}

pub(crate) struct MrtrContinuation {
    pub(crate) request_state: Option<String>,
    pub(crate) input_responses: Option<Value>,
}

impl MrtrState {
    pub(crate) fn new() -> Self {
        Self {
            rounds: 0,
            total_requests: 0,
            total_input_bytes: 0,
            seen_states: BTreeSet::new(),
        }
    }

    pub(crate) fn inspect(&mut self, result: &Value) -> Result<MrtrResult, McpError> {
        if result.get("resultType").and_then(Value::as_str) != Some("input_required") {
            return Ok(MrtrResult::Complete);
        }
        self.rounds = self.rounds.saturating_add(1);
        if self.rounds > MAX_ROUNDS {
            return Err(limit("MRTR round limit exceeded"));
        }
        let request_state = result
            .get("requestState")
            .map(|value| {
                let state = value
                    .as_str()
                    .filter(|state| !state.is_empty() && state.len() <= MAX_ITEM_BYTES)
                    .ok_or_else(|| limit("MRTR requestState is outside its bound"))?;
                if !self.seen_states.insert(state.to_owned()) {
                    return Err(limit("MRTR requestState repeated"));
                }
                Ok(state.to_owned())
            })
            .transpose()?;
        let raw = match result.get("inputRequests") {
            None => None,
            Some(Value::Object(requests)) => Some(requests),
            Some(_) => return Err(protocol("MRTR inputRequests must be an object")),
        };
        let request_count = raw.map_or(0, Map::len);
        if request_count > MAX_REQUESTS_PER_ROUND {
            return Err(limit("MRTR request count is outside its bound"));
        }
        self.total_requests = self.total_requests.saturating_add(request_count);
        if self.total_requests > MAX_TOTAL_REQUESTS {
            return Err(limit("MRTR total request limit exceeded"));
        }
        let mut requests = Vec::with_capacity(request_count);
        for (id, item) in raw.into_iter().flatten() {
            if id.is_empty() || id.len() > MAX_ITEM_BYTES || id.chars().any(char::is_control) {
                return Err(limit("MRTR request id is outside its bound"));
            }
            let object = item
                .as_object()
                .ok_or_else(|| protocol("MRTR input request must be an object"))?;
            if object.get("method").and_then(Value::as_str) != Some("elicitation/create") {
                return Err(protocol("MRTR input request method is unsupported"));
            }
            let params = object
                .get("params")
                .and_then(Value::as_object)
                .ok_or_else(|| protocol("MRTR elicitation params are required"))?;
            let elicitation =
                crate::elicitation::ElicitationRequest::parse(Value::Object(params.clone()))?;
            let prompt = elicitation.message().to_owned();
            let schema = elicitation.requested_schema().clone();
            if serde_json::to_vec(&schema)?.len() > MAX_ITEM_BYTES {
                return Err(limit("MRTR request schema exceeds its bound"));
            }
            requests.push(McpInputRequest {
                id: id.clone(),
                prompt,
                schema,
            });
        }
        if request_state.is_none() && requests.is_empty() {
            return Err(protocol("MRTR input_required result has no continuation"));
        }
        Ok(MrtrResult::InputRequired {
            request_state,
            requests,
        })
    }

    pub(crate) fn responses(
        &mut self,
        request_state: Option<String>,
        requests: &[McpInputRequest],
        decision: McpInputDecision,
    ) -> Result<MrtrContinuation, McpError> {
        let McpInputDecision::Approve(responses) = decision else {
            return Err(McpError::Cancelled {
                operation: "MCP MRTR input",
            });
        };
        let requested = requests
            .iter()
            .map(|request| request.id.as_str())
            .collect::<BTreeSet<_>>();
        if responses.len() != requested.len() {
            return Err(protocol("MRTR response count does not match the request"));
        }
        let mut content = Map::new();
        for (id, value) in responses {
            if !requested.contains(id.as_str()) || content.contains_key(&id) {
                return Err(protocol(
                    "MRTR response names an unknown or duplicate request",
                ));
            }
            let bytes = serde_json::to_vec(&value)?.len();
            if bytes > MAX_ITEM_BYTES {
                return Err(limit("MRTR response exceeds its item bound"));
            }
            self.total_input_bytes = self.total_input_bytes.saturating_add(bytes);
            if self.total_input_bytes > MAX_TOTAL_INPUT_BYTES {
                return Err(limit("MRTR total input limit exceeded"));
            }
            let request = requests
                .iter()
                .find(|request| request.id == id)
                .expect("response identities were checked above");
            validate_mrtr_input(&request.schema, &value)?;
            content.insert(id, serde_json::json!({"action":"accept", "content": value}));
        }
        Ok(MrtrContinuation {
            request_state,
            input_responses: (!content.is_empty()).then_some(Value::Object(content)),
        })
    }
}

fn protocol(message: &str) -> McpError {
    McpError::Protocol(message.to_owned())
}

fn limit(message: &str) -> McpError {
    McpError::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn approval_is_bound_to_unique_requests_and_state() {
        let mut state = MrtrState::new();
        let MrtrResult::InputRequired {
            request_state,
            requests,
        } = state
            .inspect(&json!({
                "resultType": "input_required",
                "requestState": "one",
                "inputRequests": {"name": {
                    "method":"elicitation/create",
                    "params":{"message":"Name", "requestedSchema":{
                        "type":"object", "properties":{"name":{"type":"string"}},
                        "required":["name"]
                    }}
                }}
            }))
            .unwrap()
        else {
            panic!("expected input request");
        };
        let continuation = state
            .responses(
                request_state,
                &requests,
                McpInputDecision::Approve(vec![("name".into(), json!({"name":"leaf"}))]),
            )
            .unwrap();
        assert_eq!(
            continuation.input_responses.unwrap()["name"]["content"]["name"],
            "leaf"
        );
        assert!(
            state
                .inspect(&json!({
                    "resultType":"input_required", "requestState":"one"
                }))
                .is_err()
        );
    }

    #[test]
    fn rejection_and_mismatched_responses_fail_closed() {
        let mut state = MrtrState::new();
        let MrtrResult::InputRequired {
            request_state,
            requests,
        } = state
            .inspect(&json!({
                "resultType":"input_required", "requestState":"one",
                "inputRequests":{"name": {
                    "method":"elicitation/create", "params":{
                        "message":"Name", "requestedSchema":{
                            "type":"object", "properties":{"value":{"type":"integer"}}
                        }
                    }
                }}
            }))
            .unwrap()
        else {
            panic!("expected input request");
        };
        assert!(
            state
                .responses(
                    request_state.clone(),
                    &requests,
                    McpInputDecision::Approve(vec![("other".into(), json!(1))]),
                )
                .is_err()
        );
        assert!(matches!(
            state.responses(request_state, &requests, McpInputDecision::Reject),
            Err(McpError::Cancelled { .. })
        ));
    }

    #[test]
    fn rounds_request_counts_and_total_input_bytes_are_independently_bounded() {
        let mut rounds = MrtrState::new();
        for index in 0..MAX_ROUNDS {
            assert!(
                rounds
                    .inspect(&json!({
                        "resultType":"input_required",
                        "requestState": format!("state-{index}")
                    }))
                    .is_ok()
            );
        }
        assert!(
            rounds
                .inspect(&json!({
                    "resultType":"input_required", "requestState":"one-too-many"
                }))
                .is_err()
        );

        let too_many = (0..=MAX_REQUESTS_PER_ROUND)
            .map(|index| {
                (
                    format!("request-{index}"),
                    json!({"method":"elicitation/create", "params":{
                        "message":"value", "requestedSchema":{
                            "type":"object", "properties":{"value":{"type":"string"}}
                        }
                    }}),
                )
            })
            .collect::<Map<_, _>>();
        assert!(
            MrtrState::new()
                .inspect(&json!({
                    "resultType":"input_required", "inputRequests": too_many
                }))
                .is_err()
        );

        let requests = (0..5)
            .map(|index| {
                (
                    format!("request-{index}"),
                    json!({"method":"elicitation/create", "params":{
                        "message":"value", "requestedSchema":{
                            "type":"object", "properties":{"value":{"type":"string"}}
                        }
                    }}),
                )
            })
            .collect::<Map<_, _>>();
        let mut inputs = MrtrState::new();
        let MrtrResult::InputRequired {
            request_state,
            requests,
        } = inputs
            .inspect(&json!({
                "resultType":"input_required", "inputRequests": requests
            }))
            .unwrap()
        else {
            panic!("expected input request");
        };
        let large = "x".repeat(4090);
        let responses = requests
            .iter()
            .map(|request| (request.id().to_owned(), json!({"value": large.clone()})))
            .collect();
        assert!(
            inputs
                .responses(
                    request_state,
                    &requests,
                    McpInputDecision::Approve(responses)
                )
                .is_err()
        );
    }
}

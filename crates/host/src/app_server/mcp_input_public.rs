//! Public input observations/answers bind to the actual callback owner and adoption lease.
use super::mcp_input::{McpInputAnswer, McpInputResponse, PendingInputs};
use super::product_contract::ContractReader;
use iteron_protocol::client_mcp_input::{McpInputActionV1, McpInputAnswerV1, McpInputCommandV1};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub(super) struct InputBinding {
    pub(super) owner: PendingInputs,
    pub(super) gate: Option<Arc<RwLock<()>>>,
}

pub(super) async fn execute(reader: ContractReader, command: McpInputCommandV1) -> Value {
    if command.validate().is_err() {
        return refused("invalid_request");
    }
    let Some((scope, binding)) = reader.mcp_input_binding() else {
        return refused("unavailable");
    };
    if scope.thread_id != command.thread_id || scope.run_id != command.run_id {
        return refused("scope_mismatch");
    }
    if command.is_read_only() {
        let response = match &command.command {
            McpInputActionV1::Read {} => {
                snapshot(&binding.owner, &command.thread_id, &command.run_id)
            }
            McpInputActionV1::Wait {
                after_revision,
                timeout_ms,
            } => {
                let value = binding
                    .owner
                    .wait(
                        &command.thread_id,
                        &command.run_id,
                        *after_revision,
                        *timeout_ms,
                    )
                    .await;
                json!({"type":"mcp_inputs_snapshot_v1","snapshot":value,"source":"same_input_callback_owner","delivery":"bounded_current_state_not_durable_replay"})
            }
            McpInputActionV1::Respond { .. } => unreachable!("read-only branch"),
        };
        // Observer waits hold no adoption lease and have no callback side effect.
        return if is_current(&reader, &command, &binding.owner) {
            response
        } else {
            refused("scope_changed")
        };
    }
    let Some(gate) = binding.gate else {
        return refused("unavailable");
    };
    let Ok(_lease) = gate.try_read_owned() else {
        return refused("adoption_pending");
    };
    // Admission must precede the actual response handoff. A later snapshot check cannot undo it.
    if !is_current(&reader, &command, &binding.owner) {
        return refused("scope_changed");
    }
    // The real admission lease remains held through callback handoff and reply construction.
    match command.command {
        McpInputActionV1::Read {} | McpInputActionV1::Wait { .. } => {
            unreachable!("observations handled before effect admission")
        }
        McpInputActionV1::Respond { request_id, answer } => {
            let answer = match answer {
                McpInputAnswerV1::Reject {} => McpInputAnswer::Reject,
                McpInputAnswerV1::Approve { values } => {
                    let view = binding.owner.field_identities(
                        &command.thread_id,
                        &command.run_id,
                        request_id,
                    );
                    let Some(ids) = view else {
                        return refused("request_not_pending");
                    };
                    let mut answers = Vec::with_capacity(values.len());
                    for value in values {
                        let Some(id) = ids.get(usize::from(value.field_index)) else {
                            return refused("field_mismatch");
                        };
                        answers.push((id.clone(), value.content));
                    }
                    McpInputAnswer::Approve(answers)
                }
            };
            match binding.owner.respond_scoped(
                &command.thread_id,
                &command.run_id,
                McpInputResponse { request_id, answer },
                true,
            ) {
                Ok(state) => {
                    json!({"type":"mcp_input_response_v1","thread_id":command.thread_id,"run_id":command.run_id,"request_id":request_id,"state":state,"delivery":"input_callback_handoff_not_tool_completion"})
                }
                Err(_) => refused("response_refused"),
            }
        }
    }
}
fn is_current(reader: &ContractReader, command: &McpInputCommandV1, owner: &PendingInputs) -> bool {
    reader.mcp_input_binding().is_some_and(|(scope, current)| {
        scope.thread_id == command.thread_id
            && scope.run_id == command.run_id
            && current.owner.same_owner(owner)
    })
}
fn snapshot(
    owner: &PendingInputs,
    thread: &iteron_protocol::SessionId,
    run: &iteron_protocol::RunId,
) -> Value {
    json!({"type":"mcp_inputs_snapshot_v1","snapshot":owner.snapshot(thread,run),"source":"same_input_callback_owner","delivery":"bounded_current_state_not_durable_replay"})
}
fn refused(code: &'static str) -> Value {
    json!({"type":"mcp_input_refused_v1","reason_code":code})
}

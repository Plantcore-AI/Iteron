//! JSON-safe projection of the resident App Server control plane.
//!
//! Background jobs belong to the App Server session, not to a TCP connection. An authenticated
//! client can therefore disconnect, restart, reconnect, list the same supervisor, and attach at
//! the last byte cursors it observed. Server-process restart is deliberately a different boundary:
//! this transport never turns a stale journal row into a live process capability.

use crate::app_server::{
    Control, ControlReply, ControlRequest, JobControl, MemoryControlReply, SessionSnapshot,
};
use anyhow::{Context, Result};
use iteron_protocol::product_contract::{PRODUCT_CONTRACT_VERSION, ProductControlV1, TurnStateV1};
use iteron_protocol::{Capability, Effort, PermissionMode, Verdict, task::MAX_TASK_TEXT_BYTES};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;

const MAX_JOB_ID_BYTES: usize = 128;
const MAX_JOB_INPUT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PlantcoreCommand {
    Steer {
        #[serde(deserialize_with = "deserialize_command_text")]
        text: String,
    },
    Interrupt,
    Drain,
    PauseDispatchAfterSafePoint,
    ResumeDispatch,
}

impl PlantcoreCommand {
    pub(super) fn into_op(self) -> Option<iteron_protocol::Op> {
        match self {
            Self::Steer { text } => Some(iteron_protocol::Op::Steer { text }),
            Self::Interrupt => Some(iteron_protocol::Op::Interrupt),
            Self::Drain => Some(iteron_protocol::Op::Drain),
            Self::PauseDispatchAfterSafePoint | Self::ResumeDispatch => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WireControl {
    ProductV1 {
        command: ProductControlV1,
    },
    PlantcoreRunBootstrapV1 {
        payload: Box<iteron_protocol::PlantcoreRunBootstrapV1>,
    },
    PlantcoreCommandV1 {
        #[serde(deserialize_with = "deserialize_command_id")]
        command_id: String,
        command: PlantcoreCommand,
    },
    SetEffort {
        effort: Effort,
    },
    SetPermissionMode {
        mode: PermissionMode,
    },
    SetCapabilityRule {
        capability: Capability,
        verdict: Verdict,
    },
    Compact {
        #[serde(default, deserialize_with = "deserialize_optional_focus")]
        focus: Option<String>,
    },
    TurnBudget {
        #[serde(default)]
        set: Option<u32>,
    },
    JobsList,
    JobsAttach {
        #[serde(deserialize_with = "deserialize_job_id")]
        job_id: String,
        #[serde(default)]
        stdout_cursor: u64,
        #[serde(default)]
        stderr_cursor: u64,
    },
    JobsWrite {
        #[serde(deserialize_with = "deserialize_job_id")]
        job_id: String,
        #[serde(default, deserialize_with = "deserialize_job_input")]
        input: String,
        #[serde(default)]
        eof: bool,
    },
    JobsStop {
        #[serde(deserialize_with = "deserialize_job_id")]
        job_id: String,
    },
}

fn deserialize_command_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_bounded_nonempty(deserializer, "command_id", MAX_COMMAND_ID_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(de::Error::custom(
            "command_id contains characters outside [A-Za-z0-9_.:-]",
        ));
    }
    Ok(value)
}

fn deserialize_command_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_nonempty(deserializer, "command text", MAX_TASK_TEXT_BYTES)
}

fn deserialize_optional_focus<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let focus = Option::<String>::deserialize(deserializer)?;
    if focus
        .as_ref()
        .is_some_and(|focus| focus.len() > MAX_TASK_TEXT_BYTES)
    {
        return Err(de::Error::custom(format_args!(
            "compact focus exceeds {MAX_TASK_TEXT_BYTES} bytes"
        )));
    }
    Ok(focus)
}

fn deserialize_job_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_nonempty(
        deserializer,
        "job_id",
        iteron_tunables::param_integer(
            "cli.tui.headless.control.max_job_id_bytes",
            MAX_JOB_ID_BYTES,
        ),
    )
}

fn deserialize_bounded_nonempty<'de, D>(
    deserializer: D,
    field: &str,
    max: usize,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(de::Error::custom(format_args!("{field} must not be empty")));
    }
    if value.len() > max {
        return Err(de::Error::custom(format_args!(
            "{field} exceeds {max} bytes"
        )));
    }
    Ok(value)
}

fn deserialize_job_input<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let input = String::deserialize(deserializer)?;
    if input.len()
        > iteron_tunables::param_integer(
            "cli.tui.headless.control.max_job_input_bytes",
            MAX_JOB_INPUT_BYTES,
        )
    {
        return Err(de::Error::custom(format_args!(
            "job input exceeds {MAX_JOB_INPUT_BYTES} bytes"
        )));
    }
    Ok(input)
}

impl WireControl {
    pub(super) fn into_app_server(self) -> Control {
        match self {
            Self::ProductV1 { .. } => {
                unreachable!("product controls are admitted by the versioned transport")
            }
            Self::PlantcoreRunBootstrapV1 { payload } => Control::PlantcoreRunBootstrapV1(payload),
            Self::PlantcoreCommandV1 { .. } => {
                unreachable!("PlantCore commands are admitted by the transport deduplicator")
            }
            Self::SetEffort { effort } => Control::SetEffort(effort),
            Self::SetPermissionMode { mode } => Control::SetPermissionMode(mode),
            Self::SetCapabilityRule {
                capability,
                verdict,
            } => Control::SetCapabilityRule {
                capability,
                verdict,
            },
            Self::Compact { focus } => Control::Compact { focus },
            Self::TurnBudget { set } => Control::TurnBudget { set },
            Self::JobsList => Control::Job(JobControl::Inventory),
            Self::JobsAttach {
                job_id,
                stdout_cursor,
                stderr_cursor,
            } => Control::Job(JobControl::Attach {
                job_id,
                stdout_cursor,
                stderr_cursor,
            }),
            Self::JobsWrite { job_id, input, eof } => {
                Control::Job(JobControl::Write { job_id, input, eof })
            }
            Self::JobsStop { job_id } => Control::Job(JobControl::Stop { job_id }),
        }
    }
}

/// Public control reply: a queued SQ command is only a receipt, never a permission or effect
/// result. The following lifecycle events and turn terminal remain authoritative.
pub(super) fn product_reply(
    client: &crate::app_server::AppServerClient,
    command: ProductControlV1,
) -> Value {
    let Some(snapshot) = client.thread_snapshot_v1() else {
        return product_refused("thread_unavailable");
    };
    if command.thread_id() != &snapshot.thread_id {
        return product_refused("thread_mismatch");
    }
    if matches!(&command, ProductControlV1::ThreadRead { .. }) {
        return json!({"type": "thread_snapshot_v1", "contract_version": PRODUCT_CONTRACT_VERSION, "thread": snapshot});
    }
    if let ProductControlV1::TerminalDiagnosticsRead { turn_id, .. } = &command {
        return match client.product_terminal_diagnostics_v1(*turn_id) {
            Some(diagnostics) => json!({
                "type": "terminal_diagnostics_v1",
                "contract_version": PRODUCT_CONTRACT_VERSION,
                "diagnostics": diagnostics,
            }),
            None => product_refused("terminal_diagnostics_unavailable"),
        };
    }
    if let ProductControlV1::EventsRead { after, .. } = &command {
        return match client.product_events_read_v1(*after) {
            Some(Ok(page)) => {
                json!({"type": "product_events_v1", "contract_version": PRODUCT_CONTRACT_VERSION, "page": page})
            }
            Some(Err(error)) => {
                json!({"type": "product_events_error_v1", "contract_version": PRODUCT_CONTRACT_VERSION, "error": error})
            }
            None => product_refused("thread_unavailable"),
        };
    }
    if let ProductControlV1::TurnStart { text, .. } = &command {
        if snapshot
            .turn
            .as_ref()
            .is_some_and(|turn| turn.state == TurnStateV1::Running)
        {
            return product_refused("turn_active");
        }
        if text.trim().is_empty() || text.len() > MAX_TASK_TEXT_BYTES {
            return product_refused("invalid_turn_text");
        }
        return match client.submit_identified(iteron_protocol::Op::UserInput { text: text.clone() })
        {
            Ok(id) => json!({
                "type": "control_queued_v1",
                "contract_version": PRODUCT_CONTRACT_VERSION,
                "submission_id": id,
                "thread_id": snapshot.thread_id,
                "turn_id": null,
            }),
            Err(crate::app_server::SubmitError::Busy) => product_refused("busy"),
            Err(crate::app_server::SubmitError::Disconnected) => {
                product_refused("runtime_disconnected")
            }
        };
    }
    let Some(turn) = snapshot.turn.as_ref() else {
        return product_refused("no_active_turn");
    };
    if command.turn_id() != Some(turn.turn_id) || turn.state != TurnStateV1::Running {
        return product_refused("turn_mismatch_or_terminal");
    }
    let op = match command {
        ProductControlV1::ThreadRead { .. } => unreachable!(),
        ProductControlV1::TerminalDiagnosticsRead { .. } => unreachable!(),
        ProductControlV1::EventsRead { .. } => unreachable!(),
        ProductControlV1::TurnStart { .. } => unreachable!(),
        ProductControlV1::TurnSteer { text, .. } => {
            if text.trim().is_empty() || text.len() > MAX_TASK_TEXT_BYTES {
                return product_refused("invalid_steer_text");
            }
            iteron_protocol::Op::Steer { text }
        }
        ProductControlV1::TurnInterrupt { .. } => iteron_protocol::Op::Interrupt,
        ProductControlV1::TurnDrain { .. } => iteron_protocol::Op::Drain,
        ProductControlV1::ApprovalRespond {
            approval_id,
            approved,
            remember,
            ..
        } => {
            if turn.pending_approval != Some(approval_id) {
                return product_refused("approval_mismatch");
            }
            if approved && !client.product_approval_prompt_complete_v1(approval_id) {
                return product_refused("approval_prompt_incomplete");
            }
            iteron_protocol::Op::ApprovalResponse {
                id: approval_id,
                approved,
                remember,
            }
        }
    };
    match client.submit_identified_for_turn(op, turn.turn_id) {
        Ok(id) => json!({
            "type": "control_queued_v1",
            "contract_version": PRODUCT_CONTRACT_VERSION,
            "submission_id": id,
            "thread_id": snapshot.thread_id.clone(),
            "turn_id": turn.turn_id,
        }),
        Err(crate::app_server::SubmitError::Busy) => product_refused("busy"),
        Err(crate::app_server::SubmitError::Disconnected) => {
            product_refused("runtime_disconnected")
        }
    }
}

fn product_refused(reason_code: &'static str) -> Value {
    json!({"type": "control_refused_v1", "contract_version": PRODUCT_CONTRACT_VERSION, "reason_code": reason_code})
}

pub(super) type Pending =
    Pin<Box<dyn Future<Output = Result<(u64, ControlReply)>> + Send + 'static>>;

pub(super) fn dispatch(
    sender: mpsc::Sender<ControlRequest>,
    request_id: u64,
    control: WireControl,
) -> Pending {
    Box::pin(async move {
        let (reply, receive) = tokio::sync::oneshot::channel();
        sender
            .send(ControlRequest {
                control: control.into_app_server(),
                reply,
            })
            .await
            .context("headless App Server control channel closed")?;
        let reply = receive
            .await
            .context("headless App Server dropped a control reply")?;
        Ok((request_id, reply))
    })
}

pub(super) async fn receive(pending: &mut Option<Pending>) -> Result<(u64, ControlReply)> {
    pending
        .as_mut()
        .context("headless pending control future is absent")?
        .await
}

pub(super) fn reply_value(reply: ControlReply) -> Value {
    match reply {
        ControlReply::PlantcoreBootstrapAccepted(accepted) => json!({
            "type": "plantcore_run_bootstrap_accepted_v1",
            "run_id": accepted.run_id,
            "payload_digest_sha256": accepted.payload_digest_sha256,
        }),
        ControlReply::PlantcoreProtocolError(error) => json!({
            "type": "error",
            "code": error.code,
            "message": error.message,
        }),
        ControlReply::State(snapshot) => json!({
            "type": "state",
            "state": snapshot_value(&snapshot),
        }),
        ControlReply::Refused(message) => json!({
            "type": "refused",
            "message": message,
        }),
        ControlReply::Compacted { report, snapshot } => json!({
            "type": "compacted",
            "before": report.before,
            "after": report.after,
            "state": snapshot_value(&snapshot),
        }),
        ControlReply::TurnBudget(state) => json!({
            "type": "turn_budget",
            "max_turns": state.max_turns,
            "used": state.used,
            "remaining": state.remaining(),
        }),
        ControlReply::Jobs(value) => json!({
            "type": "jobs",
            "value": value,
        }),
        ControlReply::Memory(MemoryControlReply::Added { id }) => json!({
            "type": "memory",
            "status": "added",
            "id": id,
        }),
        ControlReply::Memory(MemoryControlReply::Updated { old_id, id }) => json!({
            "type": "memory",
            "status": "updated",
            "old_id": old_id,
            "id": id,
        }),
        ControlReply::Memory(MemoryControlReply::Deleted { id }) => json!({
            "type": "memory",
            "status": "deleted",
            "id": id,
        }),
        ControlReply::Memory(MemoryControlReply::Missing { id }) => json!({
            "type": "memory",
            "status": "missing",
            "id": id,
        }),
        ControlReply::Mcp(reply) => json!({
            "type": "mcp",
            "servers": reply.servers,
            "notice": reply.notice,
        }),
        ControlReply::SideAnswer(_)
        | ControlReply::SideStatus { .. }
        | ControlReply::Adopted { .. }
        | ControlReply::Workflows(_)
        | ControlReply::OperatorStatus(_) => json!({
            "type": "refused",
            "message": "this reply type is not available on the public control transport",
        }),
    }
}

fn snapshot_value(snapshot: &SessionSnapshot) -> Value {
    json!({
        "mode": snapshot.mode,
        "effort": snapshot.effort,
        "model": snapshot.model,
        "provider_id": if snapshot.provider_id.is_empty() { None } else { Some(snapshot.provider_id.as_str()) },
        "cost": snapshot.cost,
        "last_turn_usage": snapshot.last_turn_usage,
        "unadmitted_steers": snapshot.unadmitted_steers,
        "permission_rules": snapshot.permission_rules,
        "runtime_policy": snapshot.runtime_policy,
        "ledger_summary": snapshot.ledger_summary,
        "rate_limit": snapshot.rate_limit,
        "mcp_health": snapshot.mcp_health,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_turn_start_queues_input_without_inventing_an_admitted_turn() {
        let (sender, mut submissions) = tokio::sync::mpsc::channel(2);
        let client =
            crate::app_server::AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, sender)
                .unwrap();
        let thread_id = iteron_protocol::SessionId("session-r".into());
        client
            .seed_contract_identity_for_test(thread_id.clone(), iteron_protocol::RunId("r".into()));
        let queued = product_reply(
            &client,
            ProductControlV1::TurnStart {
                thread_id,
                text: "fix the test".into(),
            },
        );
        assert_eq!(queued["type"], "control_queued_v1");
        assert!(queued["turn_id"].is_null());
        assert!(client.thread_snapshot_v1().unwrap().turn.is_none());
        assert!(matches!(
            submissions.try_recv().unwrap().op,
            iteron_protocol::Op::UserInput { text } if text == "fix the test"
        ));
    }

    #[test]
    fn product_control_reads_same_projection_and_queues_without_claiming_application() {
        let (sender, mut submissions) = tokio::sync::mpsc::channel(2);
        let client =
            crate::app_server::AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, sender)
                .unwrap();
        let thread_id = iteron_protocol::SessionId("session-r".into());
        client.seed_contract_turn_for_test(
            thread_id.clone(),
            iteron_protocol::RunId("r".into()),
            iteron_protocol::product_contract::ProductTurnId(3),
        );
        let read = product_reply(
            &client,
            ProductControlV1::ThreadRead {
                thread_id: thread_id.clone(),
            },
        );
        assert_eq!(read["type"], "thread_snapshot_v1");
        assert_eq!(read["thread"]["turn"]["state"], "running");
        assert_eq!(read["thread"]["turn"]["turn_id"], 3);
        let queued = product_reply(
            &client,
            ProductControlV1::TurnInterrupt {
                thread_id,
                turn_id: iteron_protocol::product_contract::ProductTurnId(3),
            },
        );
        assert_eq!(queued["type"], "control_queued_v1");
        assert!(queued.get("applied").is_none());
        assert!(matches!(
            submissions.try_recv().unwrap().op,
            iteron_protocol::Op::Interrupt
        ));
    }

    #[test]
    fn product_control_rejects_wrong_turn_before_sq_submission() {
        let (sender, mut submissions) = tokio::sync::mpsc::channel(2);
        let client =
            crate::app_server::AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, sender)
                .unwrap();
        client.seed_contract_turn_for_test(
            iteron_protocol::SessionId("session-r".into()),
            iteron_protocol::RunId("r".into()),
            iteron_protocol::product_contract::ProductTurnId(3),
        );
        let refused = product_reply(
            &client,
            ProductControlV1::TurnDrain {
                thread_id: iteron_protocol::SessionId("session-r".into()),
                turn_id: iteron_protocol::product_contract::ProductTurnId(2),
            },
        );
        assert_eq!(refused["reason_code"], "turn_mismatch_or_terminal");
        assert!(submissions.try_recv().is_err());
    }

    #[tokio::test]
    async fn product_events_read_reconnects_to_failed_partial_content_and_exact_terminal() {
        use crate::app_server::{ServerEvent, SessionSnapshot, TerminalAuthority, TerminalSummary};
        use crate::runtime::UiEvent;
        let (handle, mut ends) = crate::app_server::wire().unwrap();
        let client = handle.client.clone();
        let thread_id = iteron_protocol::SessionId("session-r".into());
        client.seed_contract_turn_for_test(
            thread_id.clone(),
            iteron_protocol::RunId("r".into()),
            iteron_protocol::product_contract::ProductTurnId(3),
        );
        ends.events
            .publish(ServerEvent::Ui(UiEvent::Text("partial answer ".into())))
            .await
            .unwrap();
        let first = product_reply(
            &client,
            ProductControlV1::EventsRead {
                thread_id: thread_id.clone(),
                after: 0,
            },
        );
        assert_eq!(first["type"], "product_events_v1");
        assert!(first["page"]["gap"].is_null());
        let cursor = first["page"]["next_cursor"].as_u64().unwrap();
        assert_eq!(first["page"]["events"][2]["item_id"], "item-1");
        assert_eq!(
            first["page"]["events"][2]["event"]["content"],
            "partial answer "
        );
        drop(client);

        ends.events
            .publish(ServerEvent::RunEnded {
                snapshot: Box::new(SessionSnapshot {
                    mode: iteron_protocol::PermissionMode::default(),
                    effort: iteron_protocol::Effort::default(),
                    model: "test-model".into(),
                    provider_id: "test-provider".into(),
                    cost: iteron_obs::CostState::default(),
                    last_turn_usage: None,
                    unadmitted_steers: Vec::new(),
                    unadmitted_internal_notifications: Vec::new(),
                    unadmitted_client_steers: 0,
                    unadmitted_steer_submission_ids: Vec::new(),
                    permission_rules: iteron_protocol::PermissionRules::new(),
                    runtime_policy: None,
                    ledger_summary: String::new(),
                    rate_limit: None,
                    mcp_health: Vec::new(),
                }),
                summary: Box::new(TerminalSummary {
                    terminal: TerminalAuthority::Runtime(iteron_protocol::Outcome::HarnessError),
                    assistant_text: "partial answer".into(),
                    v7_assistant_text: None,
                    run_id: "r".into(),
                    cost: iteron_obs::CostState::Zero,
                    turns: 1,
                    kernel_tax: iteron_obs::KernelTax::default(),
                    error: Some("provider disconnected".into()),
                    memo_hits: 0,
                    memo_misses: 0,
                    terminal_evidence: Some(
                        iteron_protocol::product_contract::TerminalEvidenceV1 {
                            failure_code: Some(
                                iteron_protocol::PolicyHarnessErrorCode::ProviderError,
                            ),
                            effect_state:
                                iteron_protocol::product_contract::TerminalEffectStateV1::Unknown,
                        },
                    ),
                }),
            })
            .await
            .unwrap();
        // A new authenticated connection uses the same resident App Server client and its own
        // product cursor, independent of the legacy headless EQ resume cursor.
        let reconnected = handle.client.clone();
        let page = product_reply(
            &reconnected,
            ProductControlV1::EventsRead {
                thread_id: thread_id.clone(),
                after: cursor,
            },
        );
        assert!(page["page"]["gap"].is_null());
        assert_eq!(
            page["page"]["events"][0]["event"]["channel"],
            "final_answer"
        );
        assert_eq!(
            page["page"]["events"][0]["event"]["content"],
            "partial answer"
        );
        assert_eq!(page["page"]["events"][1]["event"]["state"], "failed");
        assert_eq!(page["page"]["events"][2]["event"]["type"], "turn_ended");
        assert_eq!(
            page["page"]["events"][2]["event"]["error"],
            "provider disconnected"
        );
        assert_eq!(page["page"]["latest_terminal"]["state"], "failed");
        assert_eq!(page["page"]["latest_terminal"]["terminal_text_exact"], true);
        assert!(
            page["page"]["events"][2]["event"]
                .get("effect_state")
                .is_none()
        );
        let diagnostics = product_reply(
            &reconnected,
            ProductControlV1::TerminalDiagnosticsRead {
                thread_id: thread_id.clone(),
                turn_id: iteron_protocol::product_contract::ProductTurnId(3),
            },
        );
        assert_eq!(diagnostics["type"], "terminal_diagnostics_v1");
        assert_eq!(
            diagnostics["diagnostics"]["evidence"]["failure_code"],
            "provider_error"
        );
        assert_eq!(
            diagnostics["diagnostics"]["evidence"]["effect_state"],
            "unknown"
        );
        assert_eq!(
            diagnostics["diagnostics"]["terminal_event_seq"],
            page["page"]["latest_terminal"]["event_seq"]
        );
        assert!(!diagnostics.to_string().contains("provider disconnected"));
        let wrong_turn = product_reply(
            &reconnected,
            ProductControlV1::TerminalDiagnosticsRead {
                thread_id: thread_id.clone(),
                turn_id: iteron_protocol::product_contract::ProductTurnId(4),
            },
        );
        assert_eq!(
            wrong_turn["reason_code"],
            "terminal_diagnostics_unavailable"
        );
        let snapshot = product_reply(&reconnected, ProductControlV1::ThreadRead { thread_id });
        assert_eq!(snapshot["thread"]["turn"]["items"][0]["state"], "failed");
        assert_eq!(snapshot["thread"]["turn"]["state"], "failed");
    }

    #[tokio::test]
    async fn product_events_show_bounded_approval_prompt_and_exact_resolution() {
        use crate::app_server::ServerEvent;
        use crate::runtime::{ApprovalResolution, UiEvent};
        let (handle, mut ends) = crate::app_server::wire().unwrap();
        let client = handle.client.clone();
        let thread_id = iteron_protocol::SessionId("session-r".into());
        let turn_id = iteron_protocol::product_contract::ProductTurnId(3);
        let approval_id = iteron_protocol::SubmissionId(44);
        client.seed_contract_turn_for_test(
            thread_id.clone(),
            iteron_protocol::RunId("r".into()),
            turn_id,
        );
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        ends.events
            .publish(ServerEvent::Ui(UiEvent::ApprovalRequest {
                id: approval_id,
                tool: "shell".into(),
                capability: iteron_protocol::Capability::CodeExecuting,
                reason: "run the requested test".into(),
                arguments: json!({"command": "cargo test", "credential": secret}),
                workspace: "/workspace".into(),
            }))
            .await
            .unwrap();
        let prompt = product_reply(
            &client,
            ProductControlV1::EventsRead {
                thread_id: thread_id.clone(),
                after: 0,
            },
        );
        let encoded = serde_json::to_string(&prompt).unwrap();
        assert!(!encoded.contains(secret));
        assert_eq!(
            prompt["page"]["events"][1]["event"]["type"],
            "approval_requested"
        );
        assert_eq!(prompt["page"]["events"][1]["event"]["approval_id"], 44);
        assert_eq!(
            prompt["page"]["events"][1]["event"]["prompt_complete"],
            true
        );
        let cursor = prompt["page"]["next_cursor"].as_u64().unwrap();
        let queued = product_reply(
            &client,
            ProductControlV1::ApprovalRespond {
                thread_id: thread_id.clone(),
                turn_id,
                approval_id,
                approved: true,
                remember: false,
            },
        );
        assert_eq!(queued["type"], "control_queued_v1");
        assert!(queued.get("effect_completed").is_none());
        assert!(ends.priority_submissions.try_recv().is_ok());
        ends.events
            .publish(ServerEvent::Ui(UiEvent::ApprovalResolved {
                id: approval_id,
                resolution: ApprovalResolution::Approved,
                reason_code: "operator_approved",
                response_submission_id: Some(iteron_protocol::SubmissionId(92)),
            }))
            .await
            .unwrap();
        let reconnected = handle.client.clone();
        let resolved = product_reply(
            &reconnected,
            ProductControlV1::EventsRead {
                thread_id: thread_id.clone(),
                after: cursor,
            },
        );
        assert_eq!(
            resolved["page"]["events"][0]["event"]["type"],
            "approval_resolved"
        );
        assert_eq!(
            resolved["page"]["events"][0]["event"]["resolution"],
            "approved"
        );
        assert!(product_reply(&reconnected, ProductControlV1::ThreadRead { thread_id })
            ["thread"]["turn"]["pending_approval"].is_null());
        let second_id = iteron_protocol::SubmissionId(45);
        ends.events
            .publish(ServerEvent::Ui(UiEvent::ApprovalRequest {
                id: second_id,
                tool: "shell".into(),
                capability: iteron_protocol::Capability::CodeExecuting,
                reason: "large command".into(),
                arguments: json!({"command": "x".repeat(5000)}),
                workspace: "/workspace".into(),
            }))
            .await
            .unwrap();
        let refused = product_reply(
            &reconnected,
            ProductControlV1::ApprovalRespond {
                thread_id: iteron_protocol::SessionId("session-r".into()),
                turn_id,
                approval_id: second_id,
                approved: true,
                remember: false,
            },
        );
        assert_eq!(refused["reason_code"], "approval_prompt_incomplete");
        assert!(ends.priority_submissions.try_recv().is_err());
    }

    #[test]
    fn product_events_refuse_future_cursor_with_typed_error() {
        let (sender, _submissions) = tokio::sync::mpsc::channel(2);
        let client =
            crate::app_server::AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, sender)
                .unwrap();
        let thread_id = iteron_protocol::SessionId("session-r".into());
        client
            .seed_contract_identity_for_test(thread_id.clone(), iteron_protocol::RunId("r".into()));
        let reply = product_reply(
            &client,
            ProductControlV1::EventsRead {
                thread_id,
                after: 99,
            },
        );
        assert_eq!(reply["type"], "product_events_error_v1");
        assert_eq!(reply["error"]["type"], "cursor_ahead");
        assert_eq!(reply["error"]["latest_cursor"], 0);
    }

    #[test]
    fn job_attach_preserves_resume_cursors() {
        let wire: WireControl = serde_json::from_value(json!({
            "type": "jobs_attach",
            "job_id": "job-0123456789abcdef-00000001",
            "stdout_cursor": 17,
            "stderr_cursor": 29,
        }))
        .unwrap();
        assert!(matches!(
            wire.into_app_server(),
            Control::Job(JobControl::Attach {
                stdout_cursor: 17,
                stderr_cursor: 29,
                ..
            })
        ));
    }

    #[test]
    fn reversible_dispatch_gate_commands_are_closed_and_not_sq_operations() {
        for (wire_type, expected) in [
            (
                "pause_dispatch_after_safe_point",
                PlantcoreCommand::PauseDispatchAfterSafePoint,
            ),
            ("resume_dispatch", PlantcoreCommand::ResumeDispatch),
        ] {
            let wire: WireControl = serde_json::from_value(json!({
                "type": "plantcore_command_v1",
                "command_id": "gate-command-1",
                "command": {"type": wire_type},
            }))
            .unwrap();
            let WireControl::PlantcoreCommandV1 { command, .. } = wire else {
                panic!("gate command must retain the PlantCore envelope");
            };
            assert_eq!(command, expected);
            assert!(command.into_op().is_none());
        }

        assert!(
            serde_json::from_value::<WireControl>(json!({
                "type": "plantcore_command_v1",
                "command_id": "gate-command-1",
                "command": {"type": "pause_dispatch"},
            }))
            .is_err()
        );
    }

    #[test]
    fn job_control_payloads_are_independently_bounded() {
        let oversized = json!({
            "type": "jobs_write",
            "job_id": "job-0123456789abcdef-00000001",
            "input": "x".repeat(MAX_JOB_INPUT_BYTES + 1),
        });
        let error = serde_json::from_value::<WireControl>(oversized)
            .err()
            .expect("oversized job input must be refused");
        assert!(error.to_string().contains("job input exceeds"));
    }
}

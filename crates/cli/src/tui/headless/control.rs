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
use iteron_protocol::{Capability, Effort, PermissionMode, Verdict, task::MAX_TASK_TEXT_BYTES};
use serde::{Deserialize, Deserializer, de};
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;

const MAX_JOB_ID_BYTES: usize = 128;
const MAX_JOB_INPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WireControl {
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
    deserialize_bounded_nonempty(deserializer, "job_id", MAX_JOB_ID_BYTES)
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
    if input.len() > MAX_JOB_INPUT_BYTES {
        return Err(de::Error::custom(format_args!(
            "job input exceeds {MAX_JOB_INPUT_BYTES} bytes"
        )));
    }
    Ok(input)
}

impl WireControl {
    pub(super) fn into_app_server(self) -> Control {
        match self {
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
        "cost": snapshot.cost,
        "last_turn_usage": snapshot.last_turn_usage,
        "unadmitted_steers": snapshot.unadmitted_steers,
        "permission_rules": snapshot.permission_rules,
        "ledger_summary": snapshot.ledger_summary,
        "rate_limit": snapshot.rate_limit,
        "mcp_health": snapshot.mcp_health,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

//! Run-local recording command owner. Only this owner holds the bounded replay map and
//! the admitted SQ/dispatch-gate ports; TCP connection state cannot edit replay receipts.

use super::control::PlantcoreCommand;
use crate::app_server::AppServerClient;
use crate::runtime::{DispatchGate, ResumeActivation};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;

pub(super) struct PlantcoreCommands {
    recorded: Mutex<BTreeMap<String, RecordedCommand>>,
    client: AppServerClient,
    dispatch_gate: Option<Arc<DispatchGate>>,
    interrupt: Arc<AtomicBool>,
    drain: Arc<AtomicBool>,
}
impl PlantcoreCommands {
    pub(super) fn new(
        client: AppServerClient,
        dispatch_gate: Option<Arc<DispatchGate>>,
        interrupt: Arc<AtomicBool>,
        drain: Arc<AtomicBool>,
    ) -> Self {
        Self {
            recorded: Mutex::new(BTreeMap::new()),
            client,
            dispatch_gate,
            interrupt,
            drain,
        }
    }
    pub(super) async fn submit(
        &self,
        command_id: String,
        command: PlantcoreCommand,
    ) -> PreparedPlantcoreReply {
        const MAX_RECORDED_COMMANDS: usize = 4096;
        let pending_replay = {
            let mut recorded = self.recorded.lock().await;
            if let Some(previous) = recorded.get(&command_id) {
                if previous.command != command {
                    return PreparedPlantcoreReply {
                        value: plantcore_command_rejection(&command_id, "command_conflict"),
                        resume_activation: None,
                    };
                }
                if let Some(reply) = &previous.reply {
                    return replayed_plantcore_reply(reply.clone());
                }
                Some(previous.completed.subscribe())
            } else {
                if recorded.len() >= MAX_RECORDED_COMMANDS {
                    return PreparedPlantcoreReply {
                        value: plantcore_command_rejection(&command_id, "command_window_exhausted"),
                        resume_activation: None,
                    };
                }
                recorded.insert(
                    command_id.clone(),
                    RecordedCommand {
                        command: command.clone(),
                        reply: None,
                        completed: tokio::sync::watch::channel(false).0,
                    },
                );
                None
            }
        };
        if let Some(mut completed) = pending_replay {
            let _ = completed.wait_for(|done| *done).await;
            let recorded = self.recorded.lock().await;
            return recorded
                .get(&command_id)
                .and_then(|recorded| recorded.reply.clone())
                .map(replayed_plantcore_reply)
                .unwrap_or_else(|| PreparedPlantcoreReply {
                    value: plantcore_command_rejection(&command_id, "runtime_disconnected"),
                    resume_activation: None,
                });
        }

        let prepared = if let Some(reply) =
            dispatch_gate_command_reply(self.dispatch_gate.as_ref(), &command_id, &command).await
        {
            reply
        } else {
            let reply = submit_sq_plantcore_command(
                self.dispatch_gate.as_ref(),
                &command_id,
                &command,
                |op| self.client.submit_identified(op),
            );
            if reply["status"] == "accepted" {
                match command {
                    PlantcoreCommand::Interrupt => {
                        self.interrupt.store(true, Ordering::SeqCst);
                    }
                    PlantcoreCommand::Drain => {
                        self.drain.store(true, Ordering::SeqCst);
                    }
                    PlantcoreCommand::Steer { .. }
                    | PlantcoreCommand::PauseDispatchAfterSafePoint
                    | PlantcoreCommand::ResumeDispatch => {}
                }
            }
            PreparedPlantcoreReply {
                value: reply,
                resume_activation: None,
            }
        };
        let mut recorded = self.recorded.lock().await;
        let entry = recorded
            .get_mut(&command_id)
            .expect("the bounded command record was inserted before execution");
        if let Some(existing) = &entry.reply {
            return replayed_plantcore_reply(existing.clone());
        }
        entry.reply = Some(prepared.value.clone());
        entry.completed.send_replace(true);
        prepared
    }
}

#[derive(Clone)]
pub(super) struct RecordedCommand {
    command: PlantcoreCommand,
    reply: Option<Value>,
    completed: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone)]
pub(super) struct PreparedPlantcoreReply {
    pub(super) value: Value,
    pub(super) resume_activation: Option<ResumeActivation>,
}

pub(super) fn replayed_plantcore_reply(value: Value) -> PreparedPlantcoreReply {
    PreparedPlantcoreReply {
        value,
        resume_activation: None,
    }
}

#[cfg(test)]
pub(super) fn admit_plantcore_command(
    recorded: &mut std::collections::BTreeMap<String, RecordedCommand>,
    command_id: String,
    command: PlantcoreCommand,
    submit: impl FnOnce(
        iteron_protocol::Op,
    ) -> Result<iteron_protocol::SubmissionId, crate::app_server::SubmitError>,
) -> Value {
    const MAX_RECORDED_COMMANDS: usize = 4096;
    if let Some(previous) = recorded.get(&command_id) {
        if previous.command == command {
            return previous.reply.clone().unwrap_or_else(|| {
                json!({
                    "type": "plantcore_command_reply_v1",
                    "command_id": command_id,
                    "status": "rejected",
                    "reason": "busy",
                })
            });
        }
        return json!({
            "type": "plantcore_command_reply_v1",
            "command_id": command_id,
            "status": "rejected",
            "reason": "command_conflict",
        });
    }
    if recorded.len() >= MAX_RECORDED_COMMANDS {
        return json!({
            "type": "plantcore_command_reply_v1",
            "command_id": command_id,
            "status": "rejected",
            "reason": "command_window_exhausted",
        });
    }
    let reply = submit_sq_plantcore_command(None, &command_id, &command, submit);
    recorded.insert(
        command_id,
        RecordedCommand {
            command,
            reply: Some(reply.clone()),
            completed: tokio::sync::watch::channel(true).0,
        },
    );
    reply
}

pub(super) fn submit_sq_plantcore_command(
    dispatch_gate: Option<&Arc<DispatchGate>>,
    command_id: &str,
    command: &PlantcoreCommand,
    submit: impl FnOnce(
        iteron_protocol::Op,
    ) -> Result<iteron_protocol::SubmissionId, crate::app_server::SubmitError>,
) -> Value {
    let Some(op) = command.clone().into_op() else {
        return plantcore_command_rejection(command_id, "dispatch_gate_unavailable");
    };
    let submitted = match dispatch_gate {
        Some(gate) => {
            let submitted = if matches!(
                command,
                PlantcoreCommand::Interrupt | PlantcoreCommand::Drain
            ) {
                gate.terminalize_if_accepted(|| submit(op))
            } else {
                gate.submit_if_admitted(|| submit(op))
            };
            match submitted {
                Ok(submitted) => submitted,
                Err(reason) => return plantcore_command_rejection(command_id, reason),
            }
        }
        None => submit(op),
    };
    match submitted {
        Ok(submission_id) => json!({
            "type": "plantcore_command_reply_v1",
            "command_id": command_id,
            "status": "accepted",
            "safe_point": "kernel_submission_queue",
            "submission_id": submission_id.0,
        }),
        Err(crate::app_server::SubmitError::Busy) => json!({
            "type": "plantcore_command_reply_v1",
            "command_id": command_id,
            "status": "rejected",
            "reason": "busy",
        }),
        Err(crate::app_server::SubmitError::Disconnected) => json!({
            "type": "plantcore_command_reply_v1",
            "command_id": command_id,
            "status": "rejected",
            "reason": "runtime_disconnected",
        }),
    }
}

fn plantcore_command_rejection(command_id: &str, reason: &'static str) -> Value {
    json!({
        "type": "plantcore_command_reply_v1",
        "command_id": command_id,
        "status": "rejected",
        "reason": reason,
    })
}

pub(super) async fn dispatch_gate_command_reply(
    gate: Option<&Arc<DispatchGate>>,
    command_id: &str,
    command: &PlantcoreCommand,
) -> Option<PreparedPlantcoreReply> {
    let result = match command {
        PlantcoreCommand::PauseDispatchAfterSafePoint => match gate {
            Some(gate) => gate.pause_after_safe_point().await.map(|()| {
                (
                    json!({
                        "type": "plantcore_command_reply_v1",
                        "command_id": command_id,
                        "status": "accepted",
                        "safe_point": "dispatch_gate_active",
                    }),
                    None,
                )
            }),
            None => Err("dispatch_gate_unavailable"),
        },
        PlantcoreCommand::ResumeDispatch => match gate {
            Some(gate) => gate.prepare_resume().map(|activation| {
                (
                    json!({
                        "type": "plantcore_command_reply_v1",
                        "command_id": command_id,
                        "status": "accepted",
                        "safe_point": "dispatch_gate_open",
                    }),
                    Some(activation),
                )
            }),
            None => Err("dispatch_gate_unavailable"),
        },
        PlantcoreCommand::Steer { .. } | PlantcoreCommand::Interrupt | PlantcoreCommand::Drain => {
            return None;
        }
    };
    Some(match result {
        Ok((value, resume_activation)) => PreparedPlantcoreReply {
            value,
            resume_activation,
        },
        Err(reason) => PreparedPlantcoreReply {
            value: plantcore_command_rejection(command_id, reason),
            resume_activation: None,
        },
    })
}

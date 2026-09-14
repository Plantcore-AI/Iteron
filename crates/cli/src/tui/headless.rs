//! Bounded loopback transport for headless App Server clients.
//!
//! The runtime and its SQ/EQ semantics remain in `crate::app_server`; this module is only a framed
//! transport adapter. A client must complete the version handshake before it can submit an op or
//! make a control request.

mod auth;
mod control;
mod framing;
mod input;

use self::auth::BearerToken;
use self::control::PlantcoreCommand;
use self::framing::{
    EncodedServerFrame, ReplayRing, ServerFrame, max_in_flight_server_bytes,
    max_pinned_replay_bytes, send_encoded_frame, send_frame, send_recording_fault,
};
use self::input::{
    ClientFrame, FrameBytes, FrameReader, MAX_CLIENT_FRAME_BYTES, MAX_PENDING_CLIENT_BYTES,
};
#[cfg(test)]
use crate::app_server::TerminalSummary;
use crate::app_server::{AppServerClient, Attached, ControlRequest, ServerEvent};
use crate::output;
use crate::runtime::{PlantcoreUiEvent, UiEvent};
use anyhow::{Context, Result, bail};
use iteron_protocol::PROTOCOL_VERSION;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::task::JoinSet;

const MAX_CONNECTIONS: usize = 32;
const LIVE_CAPACITY: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHENTICATED_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const ROLLOUT_REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

fn project_v7_plantcore_event(
    assistant: &mut output::V7AssistantStream,
    event: PlantcoreUiEvent,
) -> Result<Vec<Value>> {
    let mut values = Vec::with_capacity(2);
    if matches!(event, PlantcoreUiEvent::Usage(_))
        && let Some(delta) = assistant.flush()?
    {
        values.push(delta);
    }
    values.push(output::v7_plantcore_event(event)?);
    Ok(values)
}

#[cfg(test)]
fn terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
    schema_version: u32,
) -> Result<ServerFrame> {
    Ok(ServerFrame::Result {
        protocol_version: PROTOCOL_VERSION,
        seq,
        result: summary.result_for_schema(schema_version)?,
    })
}

#[cfg(test)]
pub(super) fn capture_terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
) -> (u32, u64, Value) {
    capture_terminal_result_frame_for_schema(seq, summary, output::SCHEMA_VERSION)
}

#[cfg(test)]
pub(super) fn capture_plantcore_terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
) -> (u32, u64, Value) {
    capture_terminal_result_frame_for_schema(seq, summary, output::V7_SCHEMA_VERSION)
}

#[cfg(test)]
fn capture_terminal_result_frame_for_schema(
    seq: u64,
    summary: &TerminalSummary,
    schema_version: u32,
) -> (u32, u64, Value) {
    match terminal_result_frame(seq, summary, schema_version)
        .expect("test terminal facts must project")
    {
        ServerFrame::Result {
            protocol_version,
            seq,
            result,
        } => (protocol_version, seq, result),
        _ => unreachable!("terminal_result_frame always constructs a result frame"),
    }
}

struct Shared {
    client: AppServerClient,
    control: mpsc::WeakSender<ControlRequest>,
    auth_token: BearerToken,
    ring: Mutex<ReplayRing>,
    live: broadcast::Sender<u64>,
    outbound_budget: Arc<Semaphore>,
    frame_preparers: Arc<Semaphore>,
    fragment_encoders: Arc<Semaphore>,
    replay_retention: Arc<Semaphore>,
    rollout_replays: Arc<Semaphore>,
    cursor: AtomicU64,
    client_failures: AtomicU64,
    rollout_path: PathBuf,
    session_id: String,
    plantcore: bool,
    machine_schema_version: u32,
    plantcore_commands: Mutex<std::collections::BTreeMap<String, RecordedCommand>>,
    dispatch_gate: Option<Arc<crate::runtime::DispatchGate>>,
    interrupt: Arc<std::sync::atomic::AtomicBool>,
    drain: Arc<std::sync::atomic::AtomicBool>,
    recording_fault: Mutex<Option<crate::app_server::RecordingAppServerFault>>,
}

#[derive(Clone)]
struct RecordedCommand {
    command: PlantcoreCommand,
    reply: Option<Value>,
    completed: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone)]
struct PreparedPlantcoreReply {
    value: Value,
    resume_activation: Option<crate::runtime::ResumeActivation>,
}

fn replayed_plantcore_reply(value: Value) -> PreparedPlantcoreReply {
    PreparedPlantcoreReply {
        value,
        resume_activation: None,
    }
}

#[cfg(test)]
fn admit_plantcore_command(
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

fn submit_sq_plantcore_command(
    dispatch_gate: Option<&Arc<crate::runtime::DispatchGate>>,
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

fn submit_plantcore_initial_input<T, E>(
    dispatch_gate: Option<&Arc<crate::runtime::DispatchGate>>,
    op: iteron_protocol::Op,
    submit: impl FnOnce(iteron_protocol::Op) -> Result<T, E>,
) -> Result<Result<T, E>, &'static str> {
    if !matches!(
        op,
        iteron_protocol::Op::UserInput { .. }
            | iteron_protocol::Op::UserInputV2 { .. }
            | iteron_protocol::Op::UserInputV3 { .. }
    ) {
        return Err("plantcore_initial_input_required");
    }
    dispatch_gate
        .ok_or("dispatch_gate_unavailable")?
        .submit_if_admitted(|| submit(op))
}

impl Shared {
    async fn submit_plantcore_command(
        &self,
        command_id: String,
        command: PlantcoreCommand,
    ) -> PreparedPlantcoreReply {
        const MAX_RECORDED_COMMANDS: usize = 4096;
        let pending_replay = {
            let mut recorded = self.plantcore_commands.lock().await;
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
            let recorded = self.plantcore_commands.lock().await;
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
        let mut recorded = self.plantcore_commands.lock().await;
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

    async fn publish(
        &self,
        event: ServerEvent,
        turn: u32,
        mut assistant: output::V7AssistantStream,
    ) -> Result<(u32, output::V7AssistantStream)> {
        // `resume_from` names this transport's presentation stream, not the in-process EQ. Some EQ
        // variants intentionally have no frozen stream-json representation, so carrying their EQ
        // sequence numbers across the projection would manufacture holes that every correct client
        // must reject. The single event pump assigns a dense cursor only to frames it publishes;
        // it still validates the source EQ independently before calling this method.
        if matches!(
            event,
            ServerEvent::Submission { .. }
                | ServerEvent::WorkflowRun(_)
                | ServerEvent::Activity(_)
                | ServerEvent::McpInputRequested(_)
        ) {
            return Ok((turn, assistant));
        }
        let previous_seq = self.cursor.load(Ordering::Acquire);
        let machine_schema_version = self.machine_schema_version;
        // Projection can redact or serialize the full bounded provider result. Keep that work, and
        // the following two-pass frame preparation, off Tokio's runtime workers.
        let (frames, next_turn, assistant) = tokio::task::spawn_blocking(move || {
            let mut next_turn = turn;
            let mut logical = Vec::with_capacity(3);
            match event {
                ServerEvent::Ui(UiEvent::Text(delta))
                    if machine_schema_version == output::V7_SCHEMA_VERSION =>
                {
                    if let Some(event) = assistant.push(&delta)? {
                        logical.push((false, event));
                    }
                }
                ServerEvent::Ui(event) => logical.push((
                    false,
                    output::stream_event_for_schema(event, &mut next_turn, machine_schema_version)?,
                )),
                ServerEvent::Plantcore(event) => {
                    logical.extend(
                        project_v7_plantcore_event(&mut assistant, event)?
                            .into_iter()
                            .map(|event| (false, event)),
                    );
                }
                ServerEvent::Notice(message) => logical.push((
                    false,
                    output::stream_event_for_schema(
                        UiEvent::Notice(message),
                        &mut next_turn,
                        machine_schema_version,
                    )?,
                )),
                ServerEvent::Lagged { dropped } => logical.push((
                    false,
                    output::stream_event_for_schema(
                        UiEvent::Notice(format!(
                            "{dropped} streamed update(s) were dropped by the bounded event queue"
                        )),
                        &mut next_turn,
                        machine_schema_version,
                    )?,
                )),
                ServerEvent::RunEnded { summary, .. } => {
                    if machine_schema_version == output::V7_SCHEMA_VERSION {
                        let completes_assistant = summary.completes_assistant_stream_for_v7();
                        logical.extend(
                            assistant
                                .finish_run(
                                    completes_assistant,
                                    completes_assistant.then_some(summary.assistant_text_for_v7()),
                                )?
                                .into_iter()
                                .map(|event| (false, event)),
                        );
                    }
                    logical.push((true, summary.result_for_schema(machine_schema_version)?));
                }
                ServerEvent::Submission { .. }
                | ServerEvent::WorkflowRun(_)
                | ServerEvent::Activity(_)
                | ServerEvent::McpInputRequested(_) => {
                    unreachable!("unpublished EQ variants were filtered before projection")
                }
            }
            let frames = logical
                .into_iter()
                .enumerate()
                .map(|(index, (result, value))| {
                    let seq = previous_seq
                        .checked_add(u64::try_from(index).unwrap_or(u64::MAX))
                        .and_then(|value| value.checked_add(1))
                        .context("headless presentation cursor exhausted")?;
                    Ok(if result {
                        ServerFrame::Result {
                            protocol_version: PROTOCOL_VERSION,
                            seq,
                            result: value,
                        }
                    } else {
                        ServerFrame::Event {
                            protocol_version: PROTOCOL_VERSION,
                            seq,
                            event: value,
                        }
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok::<_, anyhow::Error>((frames, next_turn, assistant))
        })
        .await
        .context("headless live-frame projection task join")??;
        let frames = tokio::task::spawn_blocking(move || {
            frames
                .into_iter()
                .map(EncodedServerFrame::from_live)
                .collect::<Result<Vec<_>>>()
        })
        .await
        .context("headless live-frame encoder task join")??;
        if frames.is_empty() {
            return Ok((next_turn, assistant));
        }
        let sequences = frames.iter().map(|frame| frame.seq).collect::<Vec<_>>();
        let mut ring = self.ring.lock().await;
        for frame in frames {
            ring.push(Arc::new(frame));
        }
        // Publish the cursor under the same ring lock so a reconnect snapshot cannot observe a
        // cursor whose complete logical frame has not entered the ring yet.
        self.cursor.store(
            *sequences
                .last()
                .expect("a nonempty frame batch has a cursor"),
            Ordering::Release,
        );
        drop(ring);
        for seq in sequences {
            let _ = self.live.send(seq);
        }
        Ok((next_turn, assistant))
    }

    fn record_client_failure(&self) {
        let _ = self
            .client_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1))
            });
    }

    fn record_client_task_completion(
        &self,
        completed: std::result::Result<(), tokio::task::JoinError>,
    ) {
        if completed.is_err() {
            // Never format a panic payload: it can contain arbitrary application data.
            self.record_client_failure();
        }
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

async fn dispatch_gate_command_reply(
    gate: Option<&Arc<crate::runtime::DispatchGate>>,
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

fn validate_listen(listen: SocketAddr, plantcore: bool) -> Result<()> {
    let required_plantcore_listen = SocketAddr::from(([127, 0, 0, 1], 0));
    if plantcore && listen != required_plantcore_listen {
        bail!(
            "PlantCore headless App Server requires listen address {required_plantcore_listen}, got {listen}"
        );
    }
    if !listen.ip().is_loopback() {
        bail!("headless App Server requires a loopback listen address, got {listen}");
    }
    Ok(())
}

/// Run a local-only multi-client listener until interrupted.
pub(crate) async fn serve(
    attached: Attached,
    listen: SocketAddr,
    plantcore: bool,
    recording_fault: Option<crate::app_server::RecordingAppServerFault>,
) -> Result<()> {
    validate_listen(listen, plantcore)?;
    // The managing parent writes one fresh token then closes the inherited pipe. Reading to EOF
    // before `bind` makes an absent, malformed, or overlong capability fail without exposing a
    // listening socket, and `take` bounds a parent that violates the close contract.
    let auth_token = auth::read_from_stdin().await?;
    let Attached {
        handle,
        task: server_task,
        facts,
        machine_schema_version,
        dispatch_gate,
        interrupt,
        drain,
        ..
    } = attached;
    let session_id = facts.session_id.0.clone();
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind headless App Server at {listen}"))?;
    let bound = listener.local_addr().context("read bound listen address")?;
    log(json!({
        "component": "app_server",
        "event": "listening",
        "protocol_version": PROTOCOL_VERSION,
        "listen": bound.to_string(),
        "transport": "loopback_tcp_jsonl",
        "authentication": "stdin_bearer_hello",
    }));

    let (live, _) = broadcast::channel(iteron_tunables::param_integer(
        "cli.tui.headless.live_capacity",
        LIVE_CAPACITY,
    ));
    let shared = Arc::new(Shared {
        client: handle.client,
        control: handle.control.downgrade(),
        auth_token,
        ring: Mutex::new(ReplayRing::production()),
        live,
        outbound_budget: Arc::new(Semaphore::new(max_in_flight_server_bytes())),
        frame_preparers: Arc::new(Semaphore::new(1)),
        fragment_encoders: Arc::new(Semaphore::new(1)),
        replay_retention: Arc::new(Semaphore::new(max_pinned_replay_bytes())),
        rollout_replays: Arc::new(Semaphore::new(1)),
        cursor: AtomicU64::new(0),
        client_failures: AtomicU64::new(0),
        rollout_path: facts.rollout_path,
        session_id,
        plantcore,
        machine_schema_version,
        plantcore_commands: Mutex::new(std::collections::BTreeMap::new()),
        dispatch_gate,
        interrupt,
        drain,
        recording_fault: Mutex::new(recording_fault),
    });
    let mut events = handle.events;
    let pump_shared = shared.clone();
    let mut pump = tokio::spawn(async move {
        let mut turn = 0;
        let mut assistant = output::V7AssistantStream::default();
        let mut last_seq = 0;
        while let Some(envelope) = events.recv().await {
            let seq = envelope.sequence();
            if seq <= last_seq {
                log(json!({
                    "component": "app_server",
                    "event": "event_order_error",
                    "seq": seq,
                    "previous_seq": last_seq,
                }));
                break;
            }
            last_seq = seq;
            let event = match envelope.into_current() {
                Ok(event) => event,
                Err(error) => {
                    log(json!({
                        "component": "app_server",
                        "event": "protocol_error",
                        "message": error.to_string(),
                    }));
                    break;
                }
            };
            match pump_shared.publish(event, turn, assistant).await {
                Ok((next_turn, next_assistant)) => {
                    turn = next_turn;
                    assistant = next_assistant;
                }
                Err(error) => {
                    log(json!({
                        "component": "app_server",
                        "event": "protocol_error",
                        "message": iteron_record::redact::scrub(&error.to_string()),
                    }));
                    break;
                }
            };
        }
    });

    let permits = Arc::new(Semaphore::new(iteron_tunables::param_integer(
        "cli.tui.headless.max_connections",
        MAX_CONNECTIONS,
    )));
    let frame_budget = Arc::new(Semaphore::new(iteron_tunables::param_integer(
        "cli.tui.headless.input.max_pending_client_bytes",
        MAX_PENDING_CLIENT_BYTES,
    )));
    let mut connections = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut pump_stopped_early = false;
    let mut pump_was_observed = false;
    loop {
        // Deterministically reap every completed task before accepting again. The select branch
        // below handles completions while accept is idle; this pre-drain prevents a permanently
        // ready accept flood from growing completed JoinSet metadata probabilistically.
        while let Some(completed) = connections.try_join_next() {
            shared.record_client_task_completion(completed);
        }
        tokio::select! {
            biased;
            result = &mut pump => {
                pump_was_observed = true;
                pump_stopped_early = true;
                log(json!({
                    "component": "app_server",
                    "event": if result.is_err() {
                        "event_pump_failed"
                    } else {
                        "event_pump_stopped"
                    },
                }));
                break;
            }
            _ = &mut shutdown => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(completed) = completed {
                    shared.record_client_task_completion(completed);
                }
            }
            result = listener.accept() => {
                let (socket, _) = result.context("accept headless client")?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    // An untrusted connection above the admitted bound gets no task, queue slot, or
                    // write allocation. Closing it is the only response whose resource use stays
                    // independent of an arbitrary local connection flood.
                    drop(socket);
                    continue;
                };
                let shared = shared.clone();
                let frame_budget = frame_budget.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if serve_connection(socket, &shared, frame_budget).await.is_err() {
                        // Untrusted client errors never reach synchronous stderr. Record only a
                        // saturating aggregate for the fixed-size shutdown diagnostic.
                        shared.record_client_failure();
                    }
                });
            }
        }
    }

    log(json!({
        "component": "app_server",
        "event": "stopping",
        "protocol_version": PROTOCOL_VERSION,
        "client_failures": shared.client_failures.load(Ordering::Acquire),
    }));
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    drop(handle.control);
    drop(shared);
    let stopped = server_task.await.context("App Server task join")?;
    // A headless session owns background workflow runs exactly like an interactive one, and its
    // operator reads this log, not a terminal. Silence here would be the one place a run is stopped
    // without anyone being told.
    if !stopped.is_empty() {
        log(json!({
            "component": "app_server",
            "event": "workflow_runs_stopped_at_exit",
            "runs": stopped.lines,
        }));
    }
    if !pump_was_observed {
        pump.await.context("headless event pump join")?;
    }
    if pump_stopped_early {
        bail!("headless event pump stopped before transport shutdown");
    }
    Ok(())
}

fn session_identity_mismatch(
    plantcore: bool,
    resident_session_id: &str,
    requested_session_id: Option<&str>,
    resume_from: Option<u64>,
) -> bool {
    plantcore
        && (requested_session_id.is_some_and(|requested| requested != resident_session_id)
            || resume_from.is_some_and(|cursor| cursor > 0) && requested_session_id.is_none())
}

async fn serve_connection(
    socket: TcpStream,
    shared: &Shared,
    frame_budget: Arc<Semaphore>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = FrameReader::new(reader, frame_budget);
    let hello = tokio::time::timeout(
        iteron_tunables::param_duration("cli.tui.headless.handshake_timeout", HANDSHAKE_TIMEOUT),
        reader.next_frame(),
    )
    .await
    .context("headless handshake timed out")??
    .context("client disconnected before handshake")?;
    let ParsedClientFrame {
        frame: hello,
        input_guard: hello_input_guard,
    } = parse_client_frame(hello).await?;
    let (version, resume_from, requested_session_id) = match hello {
        ClientFrame::Hello {
            bearer_token,
            protocol_version,
            resume_from,
            session_id,
        } if shared.auth_token.authorizes(&bearer_token) => {
            (protocol_version, resume_from, session_id)
        }
        ClientFrame::Hello { .. } | ClientFrame::Submit { .. } | ClientFrame::Control { .. } => {
            // Do not expose even the negotiated protocol version until the capability check has
            // succeeded. Missing/malformed tokens fail during bounded parsing on the same path.
            bail!("headless client authorization failed");
        }
    };
    drop(hello_input_guard);
    if version != PROTOCOL_VERSION {
        send_frame(
            &mut writer,
            &shared.outbound_budget,
            &shared.frame_preparers,
            &shared.fragment_encoders,
            error_frame(
                "protocol_version_mismatch",
                &format!(
                    "unsupported SQ/EQ protocol version {version}; expected {PROTOCOL_VERSION}"
                ),
            ),
        )
        .await?;
        return Ok(());
    }
    if session_identity_mismatch(
        shared.plantcore,
        &shared.session_id,
        requested_session_id.as_deref(),
        resume_from,
    ) {
        send_frame(
            &mut writer,
            &shared.outbound_budget,
            &shared.frame_preparers,
            &shared.fragment_encoders,
            error_frame(
                "session_mismatch",
                "resume requires the same Run-local resident session identity",
            ),
        )
        .await?;
        return Ok(());
    }
    reader.set_max_frame_bytes(iteron_tunables::param_integer(
        "cli.tui.headless.input.max_client_frame_bytes",
        MAX_CLIENT_FRAME_BYTES,
    ));

    let mut live = shared.live.subscribe();
    let (cursor, requested, fallback, lost_result, oldest) = {
        let ring = shared.ring.lock().await;
        let cursor = shared.cursor.load(Ordering::Acquire);
        let requested = resume_from.unwrap_or(cursor);
        (
            cursor,
            requested,
            ring.rollout_required(requested, cursor),
            ring.lost_result_after(requested),
            ring.oldest_seq(),
        )
    };
    if requested > cursor {
        send_frame(
            &mut writer,
            &shared.outbound_budget,
            &shared.frame_preparers,
            &shared.fragment_encoders,
            error_frame(
                "cursor_ahead",
                &format!("resume cursor {requested} is ahead of server cursor {cursor}"),
            ),
        )
        .await?;
        return Ok(());
    }
    if lost_result {
        send_frame(
            &mut writer,
            &shared.outbound_budget,
            &shared.frame_preparers,
            &shared.fragment_encoders,
            error_frame(
                "cursor_expired",
                "the requested cursor predates an exact terminal result retained by this server",
            ),
        )
        .await?;
        return Ok(());
    }
    send_frame(
        &mut writer,
        &shared.outbound_budget,
        &shared.frame_preparers,
        &shared.fragment_encoders,
        ServerFrame::Hello {
            protocol_version: PROTOCOL_VERSION,
            session_id: shared.session_id.clone(),
            cursor,
            replay_source: if fallback { "rollout" } else { "ring" },
        },
    )
    .await?;
    if fallback {
        send_rollout(
            &mut writer,
            &shared.outbound_budget,
            &shared.frame_preparers,
            &shared.fragment_encoders,
            &shared.rollout_replays,
            &shared.rollout_path,
        )
        .await?;
    }
    let mut delivered = if fallback {
        oldest
            .context("headless replay ring is empty behind a nonzero live cursor")?
            .saturating_sub(1)
    } else {
        requested
    };
    while delivered < cursor {
        let expected = delivered
            .checked_add(1)
            .context("headless replay cursor exhausted")?;
        let frame = shared
            .ring
            .lock()
            .await
            .try_lease(expected, &shared.replay_retention);
        let Some(frame) = frame else {
            send_frame(
                &mut writer,
                &shared.outbound_budget,
                &shared.frame_preparers,
                &shared.fragment_encoders,
                error_frame(
                    "slow_client",
                    "replay sequence left the bounded ring or its aggregate retention budget; reconnect with resume_from",
                ),
            )
            .await?;
            return Ok(());
        };
        debug_assert_eq!(frame.seq(), expected);
        send_encoded_frame(
            &mut writer,
            &shared.outbound_budget,
            &shared.fragment_encoders,
            frame,
        )
        .await?;
        delivered = expected;
    }

    let mut idle_deadline = tokio::time::Instant::now()
        + iteron_tunables::param_duration(
            "cli.tui.headless.authenticated_idle_timeout",
            AUTHENTICATED_IDLE_TIMEOUT,
        );
    let mut pending_control: Option<control::Pending> = None;
    loop {
        tokio::select! {
            inbound = tokio::time::timeout_at(
                idle_deadline,
                reader.next_frame_with_partial_timeout(iteron_tunables::param_duration("cli.tui.headless.partial_frame_timeout", PARTIAL_FRAME_TIMEOUT)),
            ), if pending_control.is_none() => {
                let Some(bytes) = inbound
                    .context("authenticated headless client idle timeout")??
                else {
                    return Ok(());
                };
                idle_deadline = tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
                let ParsedClientFrame { frame, input_guard } =
                    parse_client_frame(bytes).await?;
                match frame {
                    ClientFrame::Hello { .. } => {
                        drop(input_guard);
                        send_frame(
                            &mut writer,
                            &shared.outbound_budget,
                            &shared.frame_preparers,
                            &shared.fragment_encoders,
                            error_frame(
                                "duplicate_handshake",
                                "the version handshake is already complete",
                            ),
                        )
                        .await?;
                        return Ok(());
                    }
                    ClientFrame::Submit { protocol_version, op } => {
                        if protocol_version != PROTOCOL_VERSION {
                            drop(op);
                            drop(input_guard);
                            send_frame(
                                &mut writer,
                                &shared.outbound_budget,
                                &shared.frame_preparers,
                                &shared.fragment_encoders,
                                error_frame(
                                    "protocol_version_mismatch",
                                    &format!(
                                        "submission uses protocol version {protocol_version}; expected {PROTOCOL_VERSION}"
                                    ),
                                ),
                            )
                            .await?;
                            continue;
                        }
                        if shared.plantcore {
                            let mut recording_fault = shared.recording_fault.lock().await;
                            if recording_fault.is_some() {
                                match submit_plantcore_initial_input(
                                    shared.dispatch_gate.as_ref(),
                                    op,
                                    |_| Ok::<_, std::convert::Infallible>(()),
                                ) {
                                    Ok(Ok(())) => {}
                                    Ok(Err(never)) => match never {},
                                    Err(reason) => {
                                        drop(recording_fault);
                                        drop(input_guard);
                                        send_frame(
                                            &mut writer,
                                            &shared.outbound_budget,
                                            &shared.frame_preparers,
                                            &shared.fragment_encoders,
                                            error_frame("submission_refused", reason),
                                        )
                                        .await?;
                                        continue;
                                    }
                                }
                                let fault = recording_fault
                                    .take()
                                    .expect("the recording fault was checked while locked");
                                drop(recording_fault);
                                drop(input_guard);
                                send_recording_fault(
                                    &mut writer,
                                    &shared.outbound_budget,
                                    &shared.frame_preparers,
                                    &shared.fragment_encoders,
                                    fault,
                                    delivered
                                        .checked_add(1)
                                        .context("headless recording fault cursor exhausted")?,
                                )
                                .await?;
                                return Ok(());
                            }
                            drop(recording_fault);
                        }
                        let submission = if shared.plantcore {
                            match submit_plantcore_initial_input(
                                shared.dispatch_gate.as_ref(),
                                op,
                                |op| shared.client.submit(op),
                            ) {
                                Ok(submission) => submission,
                                Err(reason) => {
                                    drop(input_guard);
                                    send_frame(
                                        &mut writer,
                                        &shared.outbound_budget,
                                        &shared.frame_preparers,
                                        &shared.fragment_encoders,
                                        error_frame("submission_refused", reason),
                                    )
                                    .await?;
                                    continue;
                                }
                            }
                        } else {
                            shared.client.submit(op)
                        };
                        // The parsed operation keeps the completed input-frame authority until the
                        // SQ has either acquired its own byte permit or refused the submission.
                        drop(input_guard);
                        if let Err(error) = submission {
                            send_frame(
                                &mut writer,
                                &shared.outbound_budget,
                                &shared.frame_preparers,
                                &shared.fragment_encoders,
                                error_frame("submission_refused", &error.to_string()),
                            ).await?;
                        }
                    }
                    ClientFrame::Control {
                        protocol_version,
                        request_id,
                        control,
                    } => {
                        if protocol_version != PROTOCOL_VERSION {
                            drop(control);
                            drop(input_guard);
                            send_frame(
                                &mut writer,
                                &shared.outbound_budget,
                                &shared.frame_preparers,
                                &shared.fragment_encoders,
                                error_frame(
                                    "protocol_version_mismatch",
                                    &format!(
                                        "control request uses protocol version {protocol_version}; expected {PROTOCOL_VERSION}"
                                    ),
                                ),
                            )
                            .await?;
                            continue;
                        }
                        drop(input_guard);
                        match control {
                            control::WireControl::PlantcoreCommandV1 {
                                command_id,
                                command,
                            } => {
                                let prepared = shared
                                    .submit_plantcore_command(command_id, command)
                                    .await;
                                let resume_activation = prepared.resume_activation;
                                send_frame(
                                    &mut writer,
                                    &shared.outbound_budget,
                                    &shared.frame_preparers,
                                    &shared.fragment_encoders,
                                    ServerFrame::ControlReply {
                                        protocol_version: PROTOCOL_VERSION,
                                        request_id,
                                        reply: prepared.value,
                                    },
                                )
                                .await?;
                                if let (Some(gate), Some(activation)) =
                                    (&shared.dispatch_gate, resume_activation)
                                {
                                    gate.activate_resume(activation)
                                        .map_err(anyhow::Error::msg)?;
                                }
                            }
                            control => {
                                let sender = shared
                                    .control
                                    .upgrade()
                                    .context("headless App Server control channel closed")?;
                                pending_control =
                                    Some(control::dispatch(sender, request_id, control));
                            }
                        }
                    }
                }
            }
            reply = control::receive(&mut pending_control), if pending_control.is_some() => {
                let (request_id, reply) = reply?;
                pending_control = None;
                send_frame(
                    &mut writer,
                    &shared.outbound_budget,
                    &shared.frame_preparers,
                    &shared.fragment_encoders,
                    ServerFrame::ControlReply {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        reply: control::reply_value(reply),
                    },
                )
                .await?;
                idle_deadline = tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
            }
            outbound = live.recv() => {
                match outbound {
                    Ok(seq) if seq <= delivered => {
                        // Subscription happens before the ring snapshot; a frame replayed from the
                        // snapshot can therefore still have an already-queued notification.
                    }
                    Ok(seq) => {
                        let frame = shared.ring.lock().await.notified_next(
                            delivered,
                            seq,
                            &shared.replay_retention,
                        );
                        let Some(frame) = frame else {
                            send_frame(
                                &mut writer,
                                &shared.outbound_budget,
                                &shared.frame_preparers,
                                &shared.fragment_encoders,
                                error_frame(
                                    "slow_client",
                                    "live sequence gapped or left the bounded replay ring; reconnect with resume_from",
                                ),
                            )
                            .await?;
                            return Ok(());
                        };
                        send_encoded_frame(
                            &mut writer,
                            &shared.outbound_budget,
                            &shared.fragment_encoders,
                            frame,
                        )
                        .await?;
                        delivered = seq;
                        idle_deadline =
                            tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        send_frame(
                            &mut writer,
                            &shared.outbound_budget,
                            &shared.frame_preparers,
                            &shared.fragment_encoders,
                            error_frame(
                                "slow_client",
                                "client fell behind the bounded live queue; reconnect with resume_from",
                            ),
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

struct ParsedClientFrame {
    frame: ClientFrame,
    input_guard: FrameBytes,
}

async fn parse_client_frame(bytes: FrameBytes) -> Result<ParsedClientFrame> {
    // Parsing a legal multimodal submission can scan tens of MiB. Moving the owned, byte-budgeted
    // frame into the blocking pool keeps its input authority attached to the parsed Op until SQ
    // admission and guarantees its zeroizing Drop runs before those permits return.
    tokio::task::spawn_blocking(move || {
        let frame = input::parse(&bytes)?;
        Ok(ParsedClientFrame {
            frame,
            input_guard: bytes,
        })
    })
    .await
    .context("headless client-frame parser task join")?
}

async fn send_rollout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    frame_preparers: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    rollout_replays: &Arc<Semaphore>,
    path: &Path,
) -> Result<()> {
    tokio::time::timeout(
        iteron_tunables::param_duration(
            "cli.tui.headless.rollout_replay_timeout",
            ROLLOUT_REPLAY_TIMEOUT,
        ),
        send_rollout_inner(
            writer,
            outbound_budget,
            frame_preparers,
            fragment_encoders,
            rollout_replays,
            path,
        ),
    )
    .await
    .context("headless Rollout replay timed out")?
}

async fn send_rollout_inner<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    frame_preparers: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    rollout_replays: &Arc<Semaphore>,
    path: &Path,
) -> Result<()> {
    let replay_permit = rollout_replays
        .clone()
        .acquire_owned()
        .await
        .context("headless Rollout replay gate closed")?;
    let path = path.to_path_buf();
    // Move the permit into the blocking task. If the outer total deadline cancels this await, a
    // detached replay still retains the sole permit until its bounded file read has actually
    // finished, so another connection cannot multiply replay memory.
    let (replay_permit, events) =
        tokio::task::spawn_blocking(move || (replay_permit, iteron_record::replay(&path)))
            .await
            .context("Rollout replay task join")?;
    let events = events.context("replay Rollout for reconnect fallback")?;
    let _replay_permit = replay_permit;
    for event in events {
        send_frame(
            writer,
            outbound_budget,
            frame_preparers,
            fragment_encoders,
            ServerFrame::Rollout {
                protocol_version: PROTOCOL_VERSION,
                rollout_seq: event.seq.0,
                event: serde_json::to_value(event).context("serialize Rollout event")?,
            },
        )
        .await?;
    }
    Ok(())
}

fn error_frame(code: &'static str, message: &str) -> ServerFrame {
    ServerFrame::Error {
        protocol_version: PROTOCOL_VERSION,
        code,
        message: iteron_record::redact::scrub(message),
    }
}

fn log(value: Value) {
    eprintln!("{}", serde_json::to_string(&value).unwrap_or_default());
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use iteron_protocol::{
        FiveClassUsage, TurnUsage, input::MAX_TOTAL_IMAGE_BASE64_BYTES, task::MAX_TASK_TEXT_BYTES,
    };
    use std::cell::Cell;

    #[test]
    fn listener_validation_preserves_ordinary_loopback_addresses() {
        assert!(validate_listen("127.0.0.1:4567".parse().unwrap(), false).is_ok());
        assert!(validate_listen("[::1]:4567".parse().unwrap(), false).is_ok());
        assert!(validate_listen("192.0.2.1:4567".parse().unwrap(), false).is_err());
    }

    #[test]
    fn plantcore_listener_requires_ephemeral_ipv4_loopback() {
        assert!(validate_listen("127.0.0.1:0".parse().unwrap(), true).is_ok());
        assert!(validate_listen("127.0.0.1:4567".parse().unwrap(), true).is_err());
        assert!(validate_listen("[::1]:0".parse().unwrap(), true).is_err());
    }

    #[test]
    fn resident_session_identity_is_required_only_for_plantcore_resume() {
        assert!(!session_identity_mismatch(false, "resident", None, Some(7)));
        assert!(session_identity_mismatch(true, "resident", None, Some(7)));
        assert!(session_identity_mismatch(
            true,
            "resident",
            Some("different"),
            Some(7)
        ));
        assert!(!session_identity_mismatch(
            true,
            "resident",
            Some("resident"),
            Some(7)
        ));
    }

    /// Kept in this orchestration module because the client-evidence boundary names this selector.
    #[test]
    fn client_frame_bound_covers_the_protocol_image_and_escaped_text_ceilings() {
        const {
            assert!(
                input::MAX_CLIENT_FRAME_BYTES
                    > MAX_TOTAL_IMAGE_BASE64_BYTES + (MAX_TASK_TEXT_BYTES * 6)
            );
            assert!(input::MAX_PENDING_CLIENT_BYTES == input::MAX_CLIENT_FRAME_BYTES * 2);
            assert!(input::MAX_HELLO_FRAME_BYTES < input::MAX_CLIENT_FRAME_BYTES);
            assert!(framing::MAX_SERVER_FRAME_BYTES == 1024 * 1024);
        }
    }

    #[test]
    fn usage_follows_every_preceding_assistant_byte() {
        let mut assistant = output::V7AssistantStream::default();
        assert!(assistant.push("answer").unwrap().is_none());
        let values = project_v7_plantcore_event(
            &mut assistant,
            PlantcoreUiEvent::Usage(TurnUsage::Complete {
                turn: 1,
                dispatched_attempt_count: 1,
                counters: FiveClassUsage::default(),
                cumulative_metering: None,
            }),
        )
        .unwrap();
        assert_eq!(values[0]["type"], "assistant_delta");
        assert_eq!(values[0]["text_utf8"], "answer");
        assert_eq!(values[1]["type"], "usage");

        let completed = assistant.finish_run(true, Some("answer")).unwrap();
        assert_eq!(completed[0]["type"], "assistant_completed");
    }

    #[test]
    fn repeated_plantcore_command_id_never_reapplies() {
        let mut recorded = std::collections::BTreeMap::new();
        let applications = Cell::new(0_u32);
        let command = PlantcoreCommand::Interrupt;
        let first =
            admit_plantcore_command(&mut recorded, "command-1".into(), command.clone(), |_| {
                applications.set(applications.get() + 1);
                Ok(iteron_protocol::SubmissionId(11))
            });
        let replay = admit_plantcore_command(&mut recorded, "command-1".into(), command, |_| {
            applications.set(applications.get() + 1);
            Ok(iteron_protocol::SubmissionId(12))
        });
        assert_eq!(applications.get(), 1);
        assert_eq!(first, replay);

        let conflict = admit_plantcore_command(
            &mut recorded,
            "command-1".into(),
            PlantcoreCommand::Drain,
            |_| panic!("a conflicting replay must not reach the SQ"),
        );
        assert_eq!(conflict["reason"], "command_conflict");
    }

    #[tokio::test]
    async fn command_completion_signal_retains_an_early_reply_notification() {
        let completed = tokio::sync::watch::channel(false).0;
        let mut replay = completed.subscribe();
        completed.send_replace(true);

        tokio::time::timeout(
            Duration::from_millis(100),
            replay.wait_for(|finished| *finished),
        )
        .await
        .expect("a concurrent replay must not lose an already-published completion")
        .unwrap();
    }

    #[tokio::test]
    async fn dispatch_gate_commands_report_only_effective_safe_points() {
        let gate = crate::runtime::DispatchGate::new();
        let second_client_gate = gate.clone();
        let second_client = tokio::spawn(async move {
            submit_sq_plantcore_command(
                Some(&second_client_gate),
                "steer-before-bootstrap",
                &PlantcoreCommand::Steer {
                    text: "early".into(),
                },
                |_| panic!("a second connection must not queue steer before bootstrap"),
            )
        });
        let early_steer = second_client.await.unwrap();
        assert_eq!(early_steer["status"], "rejected");
        assert_eq!(early_steer["reason"], "run_not_admitted");
        let before_bootstrap = dispatch_gate_command_reply(
            Some(&gate),
            "pause-before-bootstrap",
            &PlantcoreCommand::PauseDispatchAfterSafePoint,
        )
        .await
        .unwrap();
        assert_eq!(before_bootstrap.value["status"], "rejected");
        assert_eq!(before_bootstrap.value["reason"], "run_not_admitted");

        gate.admit().unwrap();
        let paused = dispatch_gate_command_reply(
            Some(&gate),
            "pause-1",
            &PlantcoreCommand::PauseDispatchAfterSafePoint,
        )
        .await
        .unwrap();
        assert_eq!(paused.value["status"], "accepted");
        assert_eq!(paused.value["safe_point"], "dispatch_gate_active");
        assert!(paused.value.get("submission_id").is_none());

        let resumed =
            dispatch_gate_command_reply(Some(&gate), "resume-1", &PlantcoreCommand::ResumeDispatch)
                .await
                .unwrap();
        assert_eq!(resumed.value["status"], "accepted");
        assert_eq!(resumed.value["safe_point"], "dispatch_gate_open");
        gate.activate_resume(resumed.resume_activation.unwrap())
            .unwrap();

        gate.terminal();
        let terminal = dispatch_gate_command_reply(
            Some(&gate),
            "resume-after-terminal",
            &PlantcoreCommand::ResumeDispatch,
        )
        .await
        .unwrap();
        assert_eq!(terminal.value["status"], "rejected");
        assert_eq!(terminal.value["reason"], "session_terminal");
        let terminal_steer = submit_sq_plantcore_command(
            Some(&gate),
            "steer-after-terminal",
            &PlantcoreCommand::Steer {
                text: "late".into(),
            },
            |_| panic!("a terminal session must not queue steer"),
        );
        assert_eq!(terminal_steer["status"], "rejected");
        assert_eq!(terminal_steer["reason"], "session_terminal");
    }

    #[tokio::test]
    async fn replayed_resume_does_not_reapply_its_activation() {
        let gate = crate::runtime::DispatchGate::new();
        gate.admit().unwrap();
        gate.pause_after_safe_point().await.unwrap();
        let first =
            dispatch_gate_command_reply(Some(&gate), "resume-1", &PlantcoreCommand::ResumeDispatch)
                .await
                .unwrap();
        let replay = replayed_plantcore_reply(first.value.clone());

        assert!(first.resume_activation.is_some());
        assert!(replay.resume_activation.is_none());
        gate.activate_resume(first.resume_activation.unwrap())
            .unwrap();
        gate.pause_after_safe_point().await.unwrap();
        assert!(gate.prepare_resume().is_ok());
    }

    #[tokio::test]
    async fn plantcore_generic_submit_accepts_only_user_input_ops() {
        let rejected = [
            iteron_protocol::Op::ApprovalResponse {
                id: iteron_protocol::SubmissionId(1),
                approved: true,
                remember: false,
            },
            iteron_protocol::Op::Steer {
                text: "bypass".into(),
            },
            iteron_protocol::Op::Interrupt,
            iteron_protocol::Op::ForceCancel,
            iteron_protocol::Op::Drain,
            iteron_protocol::Op::Unknown,
        ];
        let gate = crate::runtime::DispatchGate::new();
        assert_eq!(
            submit_plantcore_initial_input(
                Some(&gate),
                rejected[1].clone(),
                |_| -> Result<(), ()> {
                    panic!("pre-bootstrap generic control must not reach the SQ")
                }
            ),
            Err("plantcore_initial_input_required")
        );
        gate.admit().unwrap();
        gate.pause_after_safe_point().await.unwrap();
        for op in rejected {
            assert_eq!(
                submit_plantcore_initial_input(Some(&gate), op, |_| -> Result<(), ()> {
                    panic!("generic PlantCore control must not reach the SQ")
                }),
                Err("plantcore_initial_input_required")
            );
        }
        assert_eq!(
            submit_plantcore_initial_input(
                Some(&gate),
                iteron_protocol::Op::UserInput {
                    text: "initial".into(),
                },
                |_| Ok::<_, ()>(17),
            ),
            Ok(Ok(17))
        );
        assert_eq!(
            submit_plantcore_initial_input(
                Some(&gate),
                iteron_protocol::Op::UserInput {
                    text: "second connection".into(),
                },
                |_| Ok::<_, ()>(18),
            ),
            Ok(Ok(18))
        );

        let terminal = crate::runtime::DispatchGate::new();
        terminal.admit().unwrap();
        terminal.terminal();
        assert_eq!(
            submit_plantcore_initial_input(
                Some(&terminal),
                iteron_protocol::Op::UserInput {
                    text: "late".into(),
                },
                |_| -> Result<(), ()> { panic!("post-terminal input must not reach the SQ") },
            ),
            Err("session_terminal")
        );
    }
}

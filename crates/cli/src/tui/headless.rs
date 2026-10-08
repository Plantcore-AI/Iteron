//! Bounded loopback transport for headless App Server clients.
//!
//! The runtime and its SQ/EQ semantics remain in `crate::app_server`; this module is only a framed
//! transport adapter. A client must complete the version handshake before it can submit an op or
//! make a control request.

mod advisory_maintenance;
mod auth;
#[cfg(feature = "legacy-plantcore")]
mod commands;
#[cfg(not(feature = "legacy-plantcore"))]
#[path = "headless/commands_disabled.rs"]
mod commands;
mod connection;
mod control;
mod framing;
mod input;
mod provider_catalog;
mod turn_publication;

use self::auth::BearerToken;
use self::commands::PlantcoreCommands;
#[cfg(all(test, feature = "legacy-plantcore"))]
use self::commands::{
    admit_plantcore_command, dispatch_gate_command_reply, replayed_plantcore_reply,
    submit_sq_plantcore_command,
};
#[cfg(test)]
use self::connection::session_identity_mismatch;
use self::connection::{ConnectionServices, ConnectionSession};
#[cfg(all(test, feature = "legacy-plantcore"))]
use self::control::PlantcoreCommand;
#[cfg(test)]
use self::framing::send_encoded_frame;
use self::framing::{
    EncodedServerFrame, ReplayRing, ServerFrame, max_in_flight_server_bytes,
    max_pinned_replay_bytes, send_frame,
};
use self::input::MAX_PENDING_CLIENT_BYTES;
#[cfg(test)]
use crate::app_server::TerminalSummary;
use crate::app_server::{AppServerClient, Attached, ControlRequest, ServerEvent};
use crate::machine_projection as projection;
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
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::task::JoinSet;

const MAX_CONNECTIONS: usize = 32;
const LIVE_CAPACITY: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
const AUTHENTICATED_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const ROLLOUT_REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

fn project_v7_plantcore_event(
    assistant: &mut projection::V7AssistantStream,
    event: PlantcoreUiEvent,
) -> Result<Vec<Value>> {
    let mut values = Vec::with_capacity(2);
    if matches!(event, PlantcoreUiEvent::Usage(_))
        && let Some(delta) = assistant.flush()?
    {
        values.push(delta);
    }
    values.push(projection::v7_plantcore_event(event)?);
    Ok(values)
}

/// Preserve redaction state across V4/V5/V6 provider chunks and emit only complete tokens.
#[derive(Default)]
struct LegacyStreamScrubbers {
    assistant: projection::StreamingScrubber,
    reasoning: projection::StreamingScrubber,
}

impl LegacyStreamScrubbers {
    fn emit(
        logical: &mut Vec<(bool, Value)>,
        event: UiEvent,
        turn: &mut u32,
        schema: u32,
    ) -> Result<()> {
        logical.push((
            false,
            projection::stream_event_for_schema(event, turn, schema)?,
        ));
        Ok(())
    }

    fn finish(
        &mut self,
        logical: &mut Vec<(bool, Value)>,
        turn: &mut u32,
        schema: u32,
    ) -> Result<()> {
        if let Some(safe) = self.assistant.finish() {
            Self::emit(logical, UiEvent::Text(safe), turn, schema)?;
        }
        if let Some(safe) = self.reasoning.finish() {
            Self::emit(logical, UiEvent::Thinking(safe), turn, schema)?;
        }
        Ok(())
    }

    fn project(
        &mut self,
        event: UiEvent,
        logical: &mut Vec<(bool, Value)>,
        turn: &mut u32,
        schema: u32,
    ) -> Result<()> {
        match event {
            UiEvent::Text(delta) => {
                if let Some(safe) = self.reasoning.finish() {
                    Self::emit(logical, UiEvent::Thinking(safe), turn, schema)?;
                }
                if let Some(safe) = self.assistant.push(&delta) {
                    Self::emit(logical, UiEvent::Text(safe), turn, schema)?;
                }
            }
            UiEvent::Thinking(delta) => {
                if let Some(safe) = self.assistant.finish() {
                    Self::emit(logical, UiEvent::Text(safe), turn, schema)?;
                }
                if let Some(safe) = self.reasoning.push(&delta) {
                    Self::emit(logical, UiEvent::Thinking(safe), turn, schema)?;
                }
            }
            other => {
                self.finish(logical, turn, schema)?;
                Self::emit(logical, other, turn, schema)?;
            }
        }
        Ok(())
    }
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
    capture_terminal_result_frame_for_schema(seq, summary, projection::SCHEMA_VERSION)
}

#[cfg(test)]
pub(super) fn capture_plantcore_terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
) -> (u32, u64, Value) {
    capture_terminal_result_frame_for_schema(seq, summary, projection::V7_SCHEMA_VERSION)
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
    publications: broadcast::Sender<iteron_protocol::turn_publication::TurnPublicationEventV1>,
    maintenance: broadcast::Sender<crate::app_server::ServerEvent>,
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
    commands: PlantcoreCommands,
    dispatch_gate: Option<Arc<crate::runtime::DispatchGate>>,
    recording_fault: Mutex<Option<crate::app_server::RecordingAppServerFault>>,
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
    fn connection_services(&self) -> ConnectionServices<'_> {
        ConnectionServices {
            client: &self.client,
            control: &self.control,
            auth_token: &self.auth_token,
            ring: &self.ring,
            live: &self.live,
            publications: &self.publications,
            maintenance: &self.maintenance,
            outbound_budget: &self.outbound_budget,
            frame_preparers: &self.frame_preparers,
            fragment_encoders: &self.fragment_encoders,
            replay_retention: &self.replay_retention,
            rollout_replays: &self.rollout_replays,
            cursor: &self.cursor,
            rollout_path: &self.rollout_path,
            session_id: &self.session_id,
            plantcore: self.plantcore,
            commands: &self.commands,
            dispatch_gate: &self.dispatch_gate,
            recording_fault: &self.recording_fault,
        }
    }

    async fn publish(
        &self,
        event: ServerEvent,
        turn: u32,
        mut assistant: projection::V7AssistantStream,
        mut legacy: LegacyStreamScrubbers,
    ) -> Result<(u32, projection::V7AssistantStream, LegacyStreamScrubbers)> {
        // `resume_from` names this transport's presentation stream, not the in-process EQ. Some EQ
        // variants intentionally have no frozen stream-json representation, so carrying their EQ
        // sequence numbers across the projection would manufacture holes that every correct client
        // must reject. The single event pump assigns a dense cursor only to frames it publishes;
        // it still validates the source EQ independently before calling this method.
        if matches!(
            &event,
            ServerEvent::AdvisoryMaintenance(_) | ServerEvent::MaintenanceAvailability(_)
        ) {
            let _ = self.maintenance.send(event.clone());
            return Ok((turn, assistant, legacy));
        }
        if let ServerEvent::TurnPublication(publication) = &event {
            let _ = self.publications.send(publication.clone());
            return Ok((turn, assistant, legacy));
        }
        if matches!(
            event,
            ServerEvent::Submission { .. }
                | ServerEvent::WorkflowRun(_)
                | ServerEvent::Activity(_)
                | ServerEvent::McpInputRequested(_)
        ) {
            return Ok((turn, assistant, legacy));
        }
        let previous_seq = self.cursor.load(Ordering::Acquire);
        let machine_schema_version = self.machine_schema_version;
        // Projection can redact or serialize the full bounded provider result. Keep that work, and
        // the following two-pass frame preparation, off Tokio's runtime workers.
        let (frames, next_turn, assistant, legacy) = tokio::task::spawn_blocking(move || {
            let mut next_turn = turn;
            let mut logical = Vec::with_capacity(3);
            match event {
                ServerEvent::Ui(UiEvent::Text(delta))
                    if machine_schema_version == projection::V7_SCHEMA_VERSION =>
                {
                    if let Some(event) = assistant.push(&delta)? {
                        logical.push((false, event));
                    }
                }
                ServerEvent::Ui(event)
                    if machine_schema_version != projection::V7_SCHEMA_VERSION =>
                {
                    legacy.project(event, &mut logical, &mut next_turn, machine_schema_version)?;
                }
                ServerEvent::Ui(event) => logical.push((
                    false,
                    projection::stream_event_for_schema(
                        event,
                        &mut next_turn,
                        machine_schema_version,
                    )?,
                )),
                ServerEvent::Plantcore(event) => {
                    legacy.finish(&mut logical, &mut next_turn, machine_schema_version)?;
                    logical.extend(
                        project_v7_plantcore_event(&mut assistant, event)?
                            .into_iter()
                            .map(|event| (false, event)),
                    );
                }
                ServerEvent::Notice(message) => {
                    legacy.finish(&mut logical, &mut next_turn, machine_schema_version)?;
                    LegacyStreamScrubbers::emit(
                        &mut logical,
                        UiEvent::Notice(message),
                        &mut next_turn,
                        machine_schema_version,
                    )?;
                }
                ServerEvent::Lagged { dropped } => {
                    legacy.finish(&mut logical, &mut next_turn, machine_schema_version)?;
                    LegacyStreamScrubbers::emit(
                        &mut logical,
                        UiEvent::Notice(format!(
                            "{dropped} streamed update(s) were dropped by the bounded event queue"
                        )),
                        &mut next_turn,
                        machine_schema_version,
                    )?;
                }
                ServerEvent::RunEnded { summary, .. } => {
                    legacy.finish(&mut logical, &mut next_turn, machine_schema_version)?;
                    if machine_schema_version == projection::V7_SCHEMA_VERSION {
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
                | ServerEvent::TurnPublication(_)
                | ServerEvent::AdvisoryMaintenance(_)
                | ServerEvent::MaintenanceAvailability(_)
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
            Ok::<_, anyhow::Error>((frames, next_turn, assistant, legacy))
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
            return Ok((next_turn, assistant, legacy));
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
        Ok((next_turn, assistant, legacy))
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

fn validate_listen(listen: SocketAddr, plantcore: bool) -> Result<()> {
    #[cfg(not(feature = "legacy-plantcore"))]
    if plantcore {
        bail!("legacy integration is unavailable in standalone Iteron");
    }
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
    #[cfg(not(feature = "legacy-plantcore"))]
    if recording_fault.is_some() {
        bail!("legacy recording faults are unavailable in standalone Iteron");
    }
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
    // These content-free facts have their own source sequences. They cannot create holes in the
    // frozen presentation replay cursor or appear without an explicit authenticated subscription.
    let (publications, _) = broadcast::channel(64);
    let (maintenance, _) = broadcast::channel(64);
    #[cfg(feature = "legacy-plantcore")]
    let commands = PlantcoreCommands::new(
        handle.client.clone(),
        dispatch_gate.clone(),
        interrupt,
        drain,
    );
    #[cfg(not(feature = "legacy-plantcore"))]
    let commands = {
        let _ = (interrupt, drain);
        PlantcoreCommands::disabled()
    };
    let shared = Arc::new(Shared {
        client: handle.client,
        control: handle.control.downgrade(),
        auth_token,
        ring: Mutex::new(ReplayRing::production()),
        live,
        publications,
        maintenance,
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
        commands,
        dispatch_gate,
        recording_fault: Mutex::new(recording_fault),
    });
    let mut events = handle.events;
    let pump_shared = shared.clone();
    let mut pump = tokio::spawn(async move {
        let mut turn = 0;
        let mut assistant = projection::V7AssistantStream::default();
        let mut legacy = LegacyStreamScrubbers::default();
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
            match pump_shared.publish(event, turn, assistant, legacy).await {
                Ok((next_turn, next_assistant, next_legacy)) => {
                    turn = next_turn;
                    assistant = next_assistant;
                    legacy = next_legacy;
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
                    if ConnectionSession::new(socket, shared.connection_services(), frame_budget).run().await.is_err() {
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
    #[cfg(feature = "legacy-plantcore")]
    use std::cell::Cell;

    #[tokio::test]
    async fn legacy_headless_replay_frames_scrub_split_url_and_token() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        for schema in projection::SUPPORTED_SCHEMA_VERSIONS {
            let mut scrubbers = LegacyStreamScrubbers::default();
            let mut turn = 0;
            let mut logical = Vec::new();
            for delta in [
                "link https:",
                "//user:plain",
                "password@host.example/path ",
                "key sk-an",
                "t-api03-AbCdEfGhIjKlMnOpQrStUvWx ",
            ] {
                scrubbers
                    .project(UiEvent::Text(delta.into()), &mut logical, &mut turn, schema)
                    .unwrap();
                let live = serde_json::to_string(&logical).unwrap();
                assert!(!live.contains("plainpassword"), "schema {schema}: {live}");
                assert!(!live.contains("sk-ant-api03"), "schema {schema}: {live}");
            }
            for delta in ["thought sk-an", "t-api03-AbCdEfGhIjKlMnOpQrStUvWx "] {
                scrubbers
                    .project(
                        UiEvent::Thinking(delta.into()),
                        &mut logical,
                        &mut turn,
                        schema,
                    )
                    .unwrap();
                let live = serde_json::to_string(&logical).unwrap();
                assert!(!live.contains("sk-ant-api03"), "schema {schema}: {live}");
            }
            scrubbers
                .project(
                    UiEvent::Notice("boundary".into()),
                    &mut logical,
                    &mut turn,
                    schema,
                )
                .unwrap();
            let mut ring = ReplayRing::production();
            let frame_count = logical.len();
            for (index, (_, event)) in logical.into_iter().enumerate() {
                let frame = ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq: index as u64 + 1,
                    event,
                };
                ring.push(Arc::new(EncodedServerFrame::from_live(frame).unwrap()));
            }
            let retention = Arc::new(Semaphore::new(max_pinned_replay_bytes()));
            let outbound = Arc::new(Semaphore::new(max_in_flight_server_bytes()));
            let encoders = Arc::new(Semaphore::new(1));
            let (mut writer, mut reader) = tokio::io::duplex(16 * 1024);
            for seq in 1..=frame_count as u64 {
                let frame = ring
                    .try_lease(seq, &retention)
                    .expect("retained replay frame");
                send_encoded_frame(&mut writer, &outbound, &encoders, frame)
                    .await
                    .unwrap();
            }
            writer.shutdown().await.unwrap();
            let mut replay = String::new();
            reader.read_to_string(&mut replay).await.unwrap();
            assert!(replay.contains("REDACTED"), "schema {schema}: {replay}");
            assert!(
                !replay.contains("plainpassword"),
                "schema {schema}: {replay}"
            );
            assert!(
                !replay.contains("sk-ant-api03"),
                "schema {schema}: {replay}"
            );
        }
    }

    #[test]
    fn listener_validation_preserves_ordinary_loopback_addresses() {
        assert!(validate_listen("127.0.0.1:4567".parse().unwrap(), false).is_ok());
        assert!(validate_listen("[::1]:4567".parse().unwrap(), false).is_ok());
        assert!(validate_listen("192.0.2.1:4567".parse().unwrap(), false).is_err());
    }

    #[test]
    #[cfg(feature = "legacy-plantcore")]
    fn plantcore_listener_requires_ephemeral_ipv4_loopback() {
        assert!(validate_listen("127.0.0.1:0".parse().unwrap(), true).is_ok());
        assert!(validate_listen("127.0.0.1:4567".parse().unwrap(), true).is_err());
        assert!(validate_listen("[::1]:0".parse().unwrap(), true).is_err());
    }

    #[cfg(not(feature = "legacy-plantcore"))]
    #[test]
    fn standalone_listener_refuses_legacy_mode_before_binding_or_reading_auth() {
        assert!(validate_listen(SocketAddr::from(([127, 0, 0, 1], 0)), true).is_err());
        assert!(validate_listen(SocketAddr::from(([127, 0, 0, 1], 0)), false).is_ok());
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
        let mut assistant = projection::V7AssistantStream::default();
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
    #[cfg(feature = "legacy-plantcore")]
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
    #[cfg(feature = "legacy-plantcore")]
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
    #[cfg(feature = "legacy-plantcore")]
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
    #[cfg(feature = "legacy-plantcore")]
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

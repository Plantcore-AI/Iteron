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
use self::framing::{
    EncodedServerFrame, MAX_IN_FLIGHT_SERVER_BYTES, MAX_PINNED_REPLAY_BYTES, ReplayRing,
    ServerFrame, send_encoded_frame, send_frame,
};
use self::input::{
    ClientFrame, FrameBytes, FrameReader, MAX_CLIENT_FRAME_BYTES, MAX_PENDING_CLIENT_BYTES,
};
use crate::app_server::{AppServerClient, Attached, ControlRequest, ServerEvent, TerminalSummary};
use crate::output;
use crate::runtime::UiEvent;
use anyhow::{Context, Result, bail};
use core_protocol::PROTOCOL_VERSION;
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

fn terminal_result_frame(seq: u64, summary: &TerminalSummary) -> ServerFrame {
    ServerFrame::Result {
        protocol_version: PROTOCOL_VERSION,
        seq,
        result: summary.result_v5(),
    }
}

#[cfg(test)]
pub(super) fn capture_terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
) -> (u32, u64, Value) {
    match terminal_result_frame(seq, summary) {
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
}

impl Shared {
    async fn publish(&self, event: ServerEvent, turn: u32) -> Result<u32> {
        // `resume_from` names this transport's presentation stream, not the in-process EQ. Some EQ
        // variants intentionally have no frozen stream-json representation, so carrying their EQ
        // sequence numbers across the projection would manufacture holes that every correct client
        // must reject. The single event pump assigns a dense cursor only to frames it publishes;
        // it still validates the source EQ independently before calling this method.
        if matches!(
            event,
            ServerEvent::Submission { .. } | ServerEvent::WorkflowRun(_)
        ) {
            return Ok(turn);
        }
        let seq = self
            .cursor
            .load(Ordering::Acquire)
            .checked_add(1)
            .context("headless presentation cursor exhausted")?;
        // Projection can redact or serialize the full bounded provider result. Keep that work, and
        // the following two-pass frame preparation, off Tokio's runtime workers.
        let (frame, next_turn) = tokio::task::spawn_blocking(move || {
            let mut next_turn = turn;
            let frame = match event {
                ServerEvent::Ui(event) => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(event, &mut next_turn),
                },
                ServerEvent::Notice(message) => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(UiEvent::Notice(message), &mut next_turn),
                },
                ServerEvent::Lagged { dropped } => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(
                        UiEvent::Notice(format!(
                            "{dropped} streamed update(s) were dropped by the bounded event queue"
                        )),
                        &mut next_turn,
                    ),
                },
                ServerEvent::RunEnded { summary, .. } => terminal_result_frame(seq, &summary),
                ServerEvent::Submission { .. } | ServerEvent::WorkflowRun(_) => {
                    unreachable!("unpublished EQ variants were filtered before projection")
                }
            };
            Ok::<_, anyhow::Error>((Some(frame), next_turn))
        })
        .await
        .context("headless live-frame projection task join")??;
        let Some(frame) = frame else {
            return Ok(next_turn);
        };
        let frame = Arc::new(
            tokio::task::spawn_blocking(move || EncodedServerFrame::from_live(frame))
                .await
                .context("headless live-frame encoder task join")??,
        );
        let seq = frame.seq;
        let mut ring = self.ring.lock().await;
        ring.push(frame.clone());
        // Publish the cursor under the same ring lock so a reconnect snapshot cannot observe a
        // cursor whose complete logical frame has not entered the ring yet.
        self.cursor.store(seq, Ordering::Release);
        drop(ring);
        let _ = self.live.send(seq);
        Ok(next_turn)
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

/// Run a local-only multi-client listener until interrupted.
pub(crate) async fn serve(attached: Attached, listen: SocketAddr) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("headless App Server refuses non-loopback listen address {listen}");
    }
    // The managing parent writes one fresh token then closes the inherited pipe. Reading to EOF
    // before `bind` makes an absent, malformed, or overlong capability fail without exposing a
    // listening socket, and `take` bounds a parent that violates the close contract.
    let auth_token = auth::read_from_stdin().await?;
    let Attached {
        handle,
        task: server_task,
        facts,
        ..
    } = attached;
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

    let (live, _) = broadcast::channel(LIVE_CAPACITY);
    let shared = Arc::new(Shared {
        client: handle.client,
        control: handle.control.downgrade(),
        auth_token,
        ring: Mutex::new(ReplayRing::production()),
        live,
        outbound_budget: Arc::new(Semaphore::new(MAX_IN_FLIGHT_SERVER_BYTES)),
        frame_preparers: Arc::new(Semaphore::new(1)),
        fragment_encoders: Arc::new(Semaphore::new(1)),
        replay_retention: Arc::new(Semaphore::new(MAX_PINNED_REPLAY_BYTES)),
        rollout_replays: Arc::new(Semaphore::new(1)),
        cursor: AtomicU64::new(0),
        client_failures: AtomicU64::new(0),
        rollout_path: facts.rollout_path,
    });
    let mut events = handle.events;
    let pump_shared = shared.clone();
    let mut pump = tokio::spawn(async move {
        let mut turn = 0;
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
            match pump_shared.publish(event, turn).await {
                Ok(next_turn) => turn = next_turn,
                Err(error) => {
                    log(json!({
                        "component": "app_server",
                        "event": "protocol_error",
                        "message": core_record::redact::scrub(&error.to_string()),
                    }));
                    break;
                }
            };
        }
    });

    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let frame_budget = Arc::new(Semaphore::new(MAX_PENDING_CLIENT_BYTES));
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

async fn serve_connection(
    socket: TcpStream,
    shared: &Shared,
    frame_budget: Arc<Semaphore>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = FrameReader::new(reader, frame_budget);
    let hello = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.next_frame())
        .await
        .context("headless handshake timed out")??
        .context("client disconnected before handshake")?;
    let ParsedClientFrame {
        frame: hello,
        input_guard: hello_input_guard,
    } = parse_client_frame(hello).await?;
    let (version, resume_from) = match hello {
        ClientFrame::Hello {
            bearer_token,
            protocol_version,
            resume_from,
        } if shared.auth_token.authorizes(&bearer_token) => (protocol_version, resume_from),
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
    reader.set_max_frame_bytes(MAX_CLIENT_FRAME_BYTES);

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

    let mut idle_deadline = tokio::time::Instant::now() + AUTHENTICATED_IDLE_TIMEOUT;
    let mut pending_control: Option<control::Pending> = None;
    loop {
        tokio::select! {
            inbound = tokio::time::timeout_at(
                idle_deadline,
                reader.next_frame_with_partial_timeout(PARTIAL_FRAME_TIMEOUT),
            ), if pending_control.is_none() => {
                let Some(bytes) = inbound
                    .context("authenticated headless client idle timeout")??
                else {
                    return Ok(());
                };
                idle_deadline = tokio::time::Instant::now() + AUTHENTICATED_IDLE_TIMEOUT;
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
                        let submission = shared.client.submit(op);
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
                        let sender = shared
                            .control
                            .upgrade()
                            .context("headless App Server control channel closed")?;
                        pending_control = Some(control::dispatch(sender, request_id, control));
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
                idle_deadline = tokio::time::Instant::now() + AUTHENTICATED_IDLE_TIMEOUT;
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
                            tokio::time::Instant::now() + AUTHENTICATED_IDLE_TIMEOUT;
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
        ROLLOUT_REPLAY_TIMEOUT,
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
        tokio::task::spawn_blocking(move || (replay_permit, core_record::replay(&path)))
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
        message: core_record::redact::scrub(message),
    }
}

fn log(value: Value) {
    eprintln!("{}", serde_json::to_string(&value).unwrap_or_default());
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use core_protocol::{input::MAX_TOTAL_IMAGE_BASE64_BYTES, task::MAX_TASK_TEXT_BYTES};

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
}

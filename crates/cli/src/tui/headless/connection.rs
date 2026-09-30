//! One authenticated TCP client. This owner holds the physical socket, immutable negotiated
//! authority, exact replay cursor and independent observation subscriptions. Its source ports
//! are borrowed from the listener; it has no Agent, runtime state or authority-bearing locator.

use super::auth::BearerToken;
use super::commands::PlantcoreCommands;
use super::framing::{
    ReplayRing, ServerFrame, send_encoded_frame, send_frame, send_recording_fault,
};
use super::input::{self, ClientFrame, FrameBytes, FrameReader, MAX_CLIENT_FRAME_BYTES};
use super::{
    AUTHENTICATED_IDLE_TIMEOUT, HANDSHAKE_TIMEOUT, PARTIAL_FRAME_TIMEOUT, advisory_maintenance,
    control, error_frame, send_rollout, submit_plantcore_initial_input, turn_publication,
};
use crate::app_server::{AppServerClient, ControlRequest, RecordingAppServerFault, ServerEvent};
use crate::runtime::DispatchGate;
use anyhow::{Context, Result, bail};
use iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION;
use iteron_protocol::turn_publication::TurnPublicationEventV1;
use iteron_protocol::{PROTOCOL_VERSION, client_negotiation::NegotiatedClientV1};
use serde_json::json;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};

/// Disjoint real source/read/write ports. No mutable listener/runtime aggregate is accepted.
pub(super) struct ConnectionServices<'a> {
    pub(super) client: &'a AppServerClient,
    pub(super) control: &'a mpsc::WeakSender<ControlRequest>,
    pub(super) auth_token: &'a BearerToken,
    pub(super) ring: &'a Mutex<ReplayRing>,
    pub(super) live: &'a broadcast::Sender<u64>,
    pub(super) publications: &'a broadcast::Sender<TurnPublicationEventV1>,
    pub(super) maintenance: &'a broadcast::Sender<ServerEvent>,
    pub(super) outbound_budget: &'a Arc<Semaphore>,
    pub(super) frame_preparers: &'a Arc<Semaphore>,
    pub(super) fragment_encoders: &'a Arc<Semaphore>,
    pub(super) replay_retention: &'a Arc<Semaphore>,
    pub(super) rollout_replays: &'a Arc<Semaphore>,
    pub(super) cursor: &'a AtomicU64,
    pub(super) rollout_path: &'a Path,
    pub(super) session_id: &'a str,
    pub(super) plantcore: bool,
    pub(super) commands: &'a PlantcoreCommands,
    pub(super) dispatch_gate: &'a Option<Arc<DispatchGate>>,
    pub(super) recording_fault: &'a Mutex<Option<RecordingAppServerFault>>,
}

struct Admission {
    negotiated: NegotiatedClientV1,
    resume_from: Option<u64>,
    product_contract_version: Option<u32>,
    observation_only: bool,
}
struct Observations {
    publications: broadcast::Receiver<TurnPublicationEventV1>,
    publications_enabled: bool,
    maintenance: broadcast::Receiver<ServerEvent>,
    maintenance_enabled: bool,
    maintenance_last: Option<(String, u64)>,
    maintenance_gap_tick: tokio::time::Interval,
    maintenance_gap_seen: (String, u64),
}
pub(super) struct ConnectionSession<'a> {
    reader: FrameReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    services: ConnectionServices<'a>,
    live: broadcast::Receiver<u64>,
    observations: Observations,
    delivered: u64,
    idle_deadline: tokio::time::Instant,
    pending_control: Option<control::Pending>,
}
impl<'a> ConnectionSession<'a> {
    pub(super) fn new(
        socket: TcpStream,
        services: ConnectionServices<'a>,
        frame_budget: Arc<Semaphore>,
    ) -> Self {
        let (reader, writer) = socket.into_split();
        let mut gap_tick = tokio::time::interval(Duration::from_secs(1));
        gap_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            reader: FrameReader::new(reader, frame_budget),
            writer,
            live: services.live.subscribe(),
            observations: Observations {
                publications: services.publications.subscribe(),
                publications_enabled: false,
                maintenance: services.maintenance.subscribe(),
                maintenance_enabled: false,
                maintenance_last: None,
                maintenance_gap_tick: gap_tick,
                maintenance_gap_seen: (String::new(), 0),
            },
            services,
            delivered: 0,
            pending_control: None,
            idle_deadline: tokio::time::Instant::now()
                + iteron_tunables::param_duration(
                    "cli.tui.headless.authenticated_idle_timeout",
                    AUTHENTICATED_IDLE_TIMEOUT,
                ),
        }
    }
    pub(super) async fn run(mut self) -> Result<()> {
        let Some(admission) = self.authenticate().await? else {
            return Ok(());
        };
        if !self.replay(&admission).await? {
            return Ok(());
        }
        self.idle_deadline = tokio::time::Instant::now()
            + iteron_tunables::param_duration(
                "cli.tui.headless.authenticated_idle_timeout",
                AUTHENTICATED_IDLE_TIMEOUT,
            );
        self.pump(admission).await
    }
    async fn authenticate(&mut self) -> Result<Option<Admission>> {
        let shared = &self.services;
        let hello = tokio::time::timeout(
            iteron_tunables::param_duration(
                "cli.tui.headless.handshake_timeout",
                HANDSHAKE_TIMEOUT,
            ),
            self.reader.next_frame(),
        )
        .await
        .context("headless handshake timed out")??
        .context("client disconnected before handshake")?;
        let ParsedClientFrame {
            frame: hello,
            input_guard: hello_input_guard,
        } = parse_client_frame(hello).await?;
        let (
            version,
            resume_from,
            requested_session_id,
            product_contract_version,
            observation_only,
        ) = match hello {
            ClientFrame::Hello {
                bearer_token,
                protocol_version,
                resume_from,
                session_id,
                product_contract_version,
                observation_only,
            } if shared.auth_token.authorizes(&bearer_token) => (
                protocol_version,
                resume_from,
                session_id,
                product_contract_version,
                observation_only,
            ),
            ClientFrame::Hello { .. }
            | ClientFrame::Submit { .. }
            | ClientFrame::Control { .. } => {
                // Do not expose even the negotiated protocol version until the capability check has
                // succeeded. Missing/malformed tokens fail during bounded parsing on the same path.
                bail!("headless client authorization failed");
            }
        };
        drop(hello_input_guard);
        let negotiated =
            iteron_protocol::client_negotiation::negotiate_client_v1(version, observation_only);
        if negotiated.is_err() {
            send_frame(
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                error_frame(
                    "protocol_version_mismatch",
                    &format!(
                        "unsupported SQ/EQ protocol version {version}; expected {PROTOCOL_VERSION}"
                    ),
                ),
            )
            .await?;
            return Ok(None);
        }
        let negotiated = negotiated.expect("negotiation refusal returned before client access");
        if product_contract_version.is_some_and(|version| version != PRODUCT_CONTRACT_VERSION) {
            send_frame(
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                error_frame(
                    "product_contract_version_mismatch",
                    "unsupported product contract version; expected 1",
                ),
            )
            .await?;
            return Ok(None);
        }
        if session_identity_mismatch(
            shared.plantcore,
            shared.session_id,
            requested_session_id.as_deref(),
            resume_from,
        ) {
            send_frame(
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                error_frame(
                    "session_mismatch",
                    "resume requires the same Run-local resident session identity",
                ),
            )
            .await?;
            return Ok(None);
        }
        self.reader
            .set_max_frame_bytes(iteron_tunables::param_integer(
                "cli.tui.headless.input.max_client_frame_bytes",
                MAX_CLIENT_FRAME_BYTES,
            ));

        Ok(Some(Admission {
            negotiated,
            resume_from,
            product_contract_version,
            observation_only,
        }))
    }
    async fn replay(&mut self, admission: &Admission) -> Result<bool> {
        let shared = &self.services;
        let resume_from = admission.resume_from;
        let product_contract_version = admission.product_contract_version;
        let observation_only = admission.observation_only;
        let negotiated = admission.negotiated;
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
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                error_frame(
                    "cursor_ahead",
                    &format!("resume cursor {requested} is ahead of server cursor {cursor}"),
                ),
            )
            .await?;
            return Ok(false);
        }
        if lost_result {
            send_frame(
            &mut self.writer,
            shared.outbound_budget,
            shared.frame_preparers,
            shared.fragment_encoders,
            error_frame(
                "cursor_expired",
                "the requested cursor predates an exact terminal result retained by this server",
            ),
        )
        .await?;
            return Ok(false);
        }
        send_frame(
            &mut self.writer,
            shared.outbound_budget,
            shared.frame_preparers,
            shared.fragment_encoders,
            ServerFrame::Hello {
                protocol_version: PROTOCOL_VERSION,
                session_id: shared.session_id.to_owned(),
                cursor,
                replay_source: if fallback { "rollout" } else { "ring" },
                product_contract_version,
                client_access: observation_only.then_some(negotiated.access),
            },
        )
        .await?;
        if fallback {
            send_rollout(
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                shared.rollout_replays,
                shared.rollout_path,
            )
            .await?;
        }
        self.delivered = if fallback {
            oldest
                .context("headless replay ring is empty behind a nonzero live cursor")?
                .saturating_sub(1)
        } else {
            requested
        };
        while self.delivered < cursor {
            let expected = self
                .delivered
                .checked_add(1)
                .context("headless replay cursor exhausted")?;
            let frame = shared
                .ring
                .lock()
                .await
                .try_lease(expected, shared.replay_retention);
            let Some(frame) = frame else {
                send_frame(
                &mut self.writer,
                shared.outbound_budget,
                shared.frame_preparers,
                shared.fragment_encoders,
                error_frame(
                    "slow_client",
                    "replay sequence left the bounded ring or its aggregate retention budget; reconnect with resume_from",
                ),
            )
            .await?;
                return Ok(false);
            };
            debug_assert_eq!(frame.seq(), expected);
            send_encoded_frame(
                &mut self.writer,
                shared.outbound_budget,
                shared.fragment_encoders,
                frame,
            )
            .await?;
            self.delivered = expected;
        }

        Ok(true)
    }
    async fn pump(&mut self, admission: Admission) -> Result<()> {
        let shared = &self.services;
        let Admission {
            negotiated,
            product_contract_version,
            observation_only,
            ..
        } = admission;
        loop {
            tokio::select! {
                inbound = tokio::time::timeout_at(
                    self.idle_deadline,
                    self.reader.next_frame_with_partial_timeout(iteron_tunables::param_duration("cli.tui.headless.partial_frame_timeout", PARTIAL_FRAME_TIMEOUT)),
                ), if self.pending_control.is_none() => {
                    let Some(bytes) = inbound
                        .context("authenticated headless client idle timeout")??
                    else {
                        return Ok(());
                    };
                    self.idle_deadline = tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
                    let ParsedClientFrame { frame, input_guard } =
                        parse_client_frame(bytes).await?;
                    match frame {
                        ClientFrame::Hello { .. } => {
                            drop(input_guard);
                            send_frame(
                                &mut self.writer,
                                shared.outbound_budget,
                                shared.frame_preparers,
                                shared.fragment_encoders,
                                error_frame(
                                    "duplicate_handshake",
                                    "the version handshake is already complete",
                                ),
                            )
                            .await?;
                            return Ok(());
                        }
                        ClientFrame::Submit { protocol_version, op } => {
                            if !negotiated.accepts_submission(protocol_version) {
                                drop(op);
                                drop(input_guard);
                                send_frame(
                                    &mut self.writer,
                                    shared.outbound_budget,
                                    shared.frame_preparers,
                                    shared.fragment_encoders,
                                    error_frame(
                                        if observation_only { "observer_authority" } else { "protocol_version_mismatch" },
                                        if observation_only {
                                            "this connection negotiated observation authority; submissions are unavailable"
                                        } else {
                                            "submission protocol version does not match the server"
                                        },
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
                                                &mut self.writer,
                                                shared.outbound_budget,
                                                shared.frame_preparers,
                                                shared.fragment_encoders,
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
                                        &mut self.writer,
                                        shared.outbound_budget,
                                        shared.frame_preparers,
                                        shared.fragment_encoders,
                                        fault,
                                        self.delivered
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
                                            &mut self.writer,
                                            shared.outbound_budget,
                                            shared.frame_preparers,
                                            shared.fragment_encoders,
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
                                    &mut self.writer,
                                    shared.outbound_budget,
                                    shared.frame_preparers,
                                    shared.fragment_encoders,
                                    error_frame("submission_refused", &error.to_string()),
                                ).await?;
                            }
                        }
                        ClientFrame::Control {
                            protocol_version,
                            request_id,
                            control,
                        } => {
                            if !negotiated.accepts_control(protocol_version, control.is_read_only()) {
                                drop(control);
                                drop(input_guard);
                                send_frame(
                                    &mut self.writer,
                                    shared.outbound_budget,
                                    shared.frame_preparers,
                                    shared.fragment_encoders,
                                    error_frame(
                                        if observation_only { "observer_authority" } else { "protocol_version_mismatch" },
                                        if observation_only {
                                            "this connection accepts only read controls stamped with its negotiated client version"
                                        } else {
                                            "control request protocol version does not match the server"
                                        },
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            drop(input_guard);
                            match control {
                                control::WireControl::MaintenanceV1 { command } => {
                                    let subscribe = matches!(&command, iteron_protocol::advisory_maintenance_control::MaintenanceReadV1::Subscribe { .. });
                                    if subscribe { self.observations.maintenance = shared.maintenance.subscribe(); }
                                    let reply = shared.client.maintenance_v1(command);
                                    if subscribe && matches!(reply["type"].as_str(), Some("maintenance_snapshot_v1" | "maintenance_unavailable_v1")) {
                                        self.observations.maintenance_enabled = true;
                                        self.observations.maintenance_last = reply["event"]["run_id"].as_str().zip(reply["event"]["observation"]["journal_revision"].as_u64()).map(|(run, revision)| (run.to_owned(), revision));
                                    }
                                    send_frame(&mut self.writer, shared.outbound_budget, shared.frame_preparers, shared.fragment_encoders,
                                        ServerFrame::ControlReply { protocol_version, request_id, reply }).await?;
                                }
                                control::WireControl::TurnPublicationsV1 { command } => {
                                    let subscribe = matches!(&command, iteron_protocol::turn_publication::TurnPublicationReadV1::Subscribe { .. });
                                    if subscribe {
                                        // Subscribe before the snapshot read. Any overlap is explicit
                                        // and deduplicated by the actual current-run source sequence.
                                        self.observations.publications = shared.publications.subscribe();
                                    }
                                    let reply = shared.client.turn_publications_v1(command);
                                    if subscribe && reply["type"] == "turn_publications_v1" {
                                        self.observations.publications_enabled = true;
                                    }
                                    send_frame(
                                        &mut self.writer, shared.outbound_budget, shared.frame_preparers,
                                        shared.fragment_encoders,
                                        ServerFrame::ControlReply { protocol_version: PROTOCOL_VERSION, request_id, reply },
                                    ).await?;
                                }
                                control::WireControl::ArtifactsV1 { command } => {
                                    send_frame(
                                        &mut self.writer,
                                        shared.outbound_budget,
                                        shared.frame_preparers,
                                        shared.fragment_encoders,
                                        ServerFrame::ControlReply {
                                            protocol_version: PROTOCOL_VERSION,
                                            request_id,
                                            reply: shared.client.artifacts_v1(command),
                                        },
                                    ).await?;
                                }
                                control::WireControl::ProductV1 { command } => {
                                    let reply = if product_contract_version.is_none() {
                                        json!({
                                            "type": "control_refused_v1",
                                            "contract_version": PRODUCT_CONTRACT_VERSION,
                                            "reason_code": "contract_not_negotiated",
                                        })
                                    } else if shared.plantcore {
                                        json!({
                                            "type": "control_refused_v1",
                                            "contract_version": PRODUCT_CONTRACT_VERSION,
                                            "reason_code": "mode_unavailable",
                                        })
                                    } else {
                                        control::product_reply(shared.client, command)
                                    };
                                    send_frame(
                                        &mut self.writer,
                                        shared.outbound_budget,
                                        shared.frame_preparers,
                                        shared.fragment_encoders,
                                        ServerFrame::ControlReply {
                                            protocol_version: PROTOCOL_VERSION,
                                            request_id,
                                            reply,
                                        },
                                    )
                                    .await?;
                                }
                                control::WireControl::PlantcoreCommandV1 {
                                    command_id,
                                    command,
                                } => {
                                    let prepared = shared.commands
                                        .submit(command_id, command)
                                        .await;
                                    let resume_activation = prepared.resume_activation;
                                    send_frame(
                                        &mut self.writer,
                                        shared.outbound_budget,
                                        shared.frame_preparers,
                                        shared.fragment_encoders,
                                        ServerFrame::ControlReply {
                                            protocol_version: PROTOCOL_VERSION,
                                            request_id,
                                            reply: prepared.value,
                                        },
                                    )
                                    .await?;
                                    if let (Some(gate), Some(activation)) =
                                        (shared.dispatch_gate, resume_activation)
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
                                    self.pending_control =
                                        Some(control::dispatch(sender, request_id, control));
                                }
                            }
                        }
                    }
                }
                reply = control::receive(&mut self.pending_control), if self.pending_control.is_some() => {
                    let (request_id, reply) = reply?;
                    self.pending_control = None;
                    send_frame(
                        &mut self.writer,
                        shared.outbound_budget,
                        shared.frame_preparers,
                        shared.fragment_encoders,
                        ServerFrame::ControlReply {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            reply: control::reply_value(reply),
                        },
                    )
                    .await?;
                    self.idle_deadline = tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
                }
                _ = self.observations.maintenance_gap_tick.tick(), if self.observations.maintenance_enabled => {
                    let gap = shared.client.maintenance_gaps();
                    let run = gap["run_id"].as_str().unwrap_or_default();
                    let count = gap["presentation_gaps"].as_u64().unwrap_or(0);
                    if self.observations.maintenance_gap_seen.0 != run { self.observations.maintenance_gap_seen = (run.to_owned(), 0); }
                    if count > self.observations.maintenance_gap_seen.1 {
                        self.observations.maintenance_gap_seen.1 = count;
                        send_frame(&mut self.writer, shared.outbound_budget, shared.frame_preparers, shared.fragment_encoders,
                            error_frame("maintenance_gap", "optional observations exceeded the bounded session presentation queue; read maintenance_v1 for actual current journal state")).await?;
                    }
                }
                event = self.observations.maintenance.recv(), if self.observations.maintenance_enabled => {
                    match event {
                        Ok(event) => advisory_maintenance::send(&mut self.writer, shared.client, shared.outbound_budget,
                            shared.frame_preparers, shared.fragment_encoders, &mut self.observations.maintenance_last, event).await?,
                        Err(broadcast::error::RecvError::Lagged(_)) => send_frame(&mut self.writer,
                            shared.outbound_budget, shared.frame_preparers, shared.fragment_encoders,
                            error_frame("maintenance_gap", "maintenance snapshots exceeded the bounded queue; read maintenance_v1 to reconcile current journal state")).await?,
                        Err(broadcast::error::RecvError::Closed) => self.observations.maintenance_enabled = false,
                    }
                }
                publication = self.observations.publications.recv(), if self.observations.publications_enabled => {
                    match publication {
                        Ok(publication) => {
                            turn_publication::send(
                                &mut self.writer, shared.client, shared.outbound_budget,
                                shared.frame_preparers, shared.fragment_encoders, publication,
                            ).await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            send_frame(
                                &mut self.writer, shared.outbound_budget, shared.frame_preparers,
                                shared.fragment_encoders,
                                error_frame("turn_publication_gap", "publication updates exceeded the bounded queue; read turn_publications_v1 to reconcile durable facts"),
                            ).await?;
                        }
                        Err(broadcast::error::RecvError::Closed) => self.observations.publications_enabled = false,
                    }
                }
                outbound = self.live.recv() => {
                    if self.observations.publications_enabled {
                        // The publication source is enqueued before its corresponding legacy
                        // terminal. Drain at most one bounded channel window before that terminal,
                        // while keeping the outer select fair to input and other output.
                        for _ in 0..64 {
                            match self.observations.publications.try_recv() {
                                Ok(publication) => turn_publication::send(
                                    &mut self.writer, shared.client, shared.outbound_budget,
                                    shared.frame_preparers, shared.fragment_encoders, publication,
                                ).await?,
                                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                                    send_frame(
                                        &mut self.writer, shared.outbound_budget, shared.frame_preparers,
                                        shared.fragment_encoders,
                                        error_frame("turn_publication_gap", "publication updates exceeded the bounded queue; read turn_publications_v1 to reconcile durable facts"),
                                    ).await?;
                                }
                                Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed) => break,
                            }
                        }
                    }
                    match outbound {
                        Ok(seq) if seq <= self.delivered => {
                            // Subscription happens before the ring snapshot; a frame replayed from the
                            // snapshot can therefore still have an already-queued notification.
                        }
                        Ok(seq) => {
                            let frame = shared.ring.lock().await.notified_next(
                                self.delivered,
                                seq,
                                shared.replay_retention,
                            );
                            let Some(frame) = frame else {
                                send_frame(
                                    &mut self.writer,
                                    shared.outbound_budget,
                                    shared.frame_preparers,
                                    shared.fragment_encoders,
                                    error_frame(
                                        "slow_client",
                                        "live sequence gapped or left the bounded replay ring; reconnect with resume_from",
                                    ),
                                )
                                .await?;
                                return Ok(());
                            };
                            send_encoded_frame(
                                &mut self.writer,
                                shared.outbound_budget,
                                shared.fragment_encoders,
                                frame,
                            )
                            .await?;
                            self.delivered = seq;
                            self.idle_deadline =
                                tokio::time::Instant::now() + iteron_tunables::param_duration("cli.tui.headless.authenticated_idle_timeout", AUTHENTICATED_IDLE_TIMEOUT);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            send_frame(
                                &mut self.writer,
                                shared.outbound_budget,
                                shared.frame_preparers,
                                shared.fragment_encoders,
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
}

pub(super) fn session_identity_mismatch(
    plantcore: bool,
    resident_session_id: &str,
    requested_session_id: Option<&str>,
    resume_from: Option<u64>,
) -> bool {
    plantcore
        && (requested_session_id.is_some_and(|requested| requested != resident_session_id)
            || resume_from.is_some_and(|cursor| cursor > 0) && requested_session_id.is_none())
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

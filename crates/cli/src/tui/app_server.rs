//! The App Server: the runtime lives here, reachable only through a versioned SQ/EQ wire.
//!
//! # What this replaces
//!
//! The interactive frontend used to *co-compose the runtime*. It held the kernel [`Agent`] in an
//! `Option<Agent>`, moved it into a `tokio::spawn` for each turn, and got it back through the
//! `JoinHandle` — so "is a run in flight" was encoded as "is the slot empty", and every
//! configuration path (`/model`, `/effort`, `/mode`, `/compact`) was reachable only because the
//! borrow checker made it so. Task start and follow-up never touched the submission queue at all;
//! only `Interrupt`, `ApprovalResponse`, `Drain` and `Steer` did. A frontend that starts work by
//! moving the runtime into a task it owns is not a client of a server.
//!
//! Here the runtime is resident. One long-lived task owns the `Agent`, drains the SQ, and publishes
//! the EQ. The frontend holds queue endpoints and a negotiated protocol version, nothing else.
//!
//! # Why the EQ does not carry `core_protocol::Event`
//!
//! This is the one design decision in this module that is not obvious, so it is recorded rather
//! than left to be rediscovered.
//!
//! `core_protocol::EqEnvelope` carries `core_protocol::Event`, and translating the kernel's
//! [`UiEvent`] into `EventKind` is **lossy in four places the frontend actually renders**:
//!
//! - `UiEvent::TurnEnd` carries seven fields; `EventKind::TurnEnd` carries one (`usage`). The cost
//!   state, context estimate, model window, reserved output tokens, compaction trigger and effort
//!   application have no durable counterpart — and the status bar renders all of them.
//! - `UiEvent::SteerApplied { count }` has no `EventKind` counterpart at all.
//! - `UiEvent::ToolEnd.diff` has no `EventKind` home; the durable record is deliberately terse.
//! - `UiEvent::ApprovalRequest.reason` — the operator-facing justification — has no field to go in.
//!
//! Closing those would mean adding variants and fields to `core_protocol`, and this issue's
//! acceptance criteria forbid changing the frozen wire types: WS1 owns them, this lane only
//! consumes them. Carrying `UiEvent` in a versioned envelope of our own satisfies both — the wire
//! is version-negotiated in both directions, and no frozen type moves.
//!
//! The SQ is different: it carries `core_protocol::SqEnvelope` unchanged, because `Op` expresses
//! everything the frontend submits.
//!
//! # Backpressure
//!
//! Both queues are bounded. The policies are deliberately asymmetric, because the two directions
//! fail differently:
//!
//! - **SQ**: submissions never block the UI thread. A full queue returns
//!   [`SubmitError::Busy`] so the frontend can tell the operator their keystroke did not land,
//!   rather than freezing the render loop behind an unbounded queue that grows until the process
//!   dies.
//! - **EQ**: a slow reader must never cost the operator the *authoritative* answer. Cosmetic
//!   deltas — streamed text and thinking — are dropped oldest-first under pressure and the loss is
//!   reported. Everything else, and `Done` above all, is delivered even if that means waiting for
//!   the reader.

use core_kernel::{Agent, UiEvent};
use core_protocol::{Op, Outcome, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc;

/// Submission-queue depth.
///
/// Sized for the burst a human can produce with a held key or a paste, not for a backlog: past this
/// the honest answer is "busy", not a longer queue.
pub(crate) const SQ_CAPACITY: usize = 256;

/// Event-queue depth.
///
/// Streamed text arrives far faster than a terminal repaints, so this is the elastic that absorbs a
/// burst between frames. It is a bound, not a buffer to be filled: see the drop policy above.
pub(crate) const EQ_CAPACITY: usize = 1024;

/// How a run ended, as the server reports it.
///
/// The frontend used to learn this by `await`ing a `JoinHandle` it owned. With a resident runtime
/// there is no join, so the terminal state has to arrive as an event like everything else.
#[derive(Debug)]
pub(crate) enum RunEnded {
    Outcome(Outcome),
    Error(String),
}

/// The runtime state the frontend mirrors in its status line.
///
/// The frontend used to read these six values straight off the `Agent` at the instant it reclaimed
/// it from the `JoinHandle` — that join was the ONLY refresh point in the whole loop. A resident
/// runtime never comes back, so the snapshot travels on the EQ with the terminal event instead.
///
/// `unadmitted_steers` is here for the same reason. Steering submitted after the kernel's last safe
/// point sits in its inbound queue; the frontend has to move those exact raw texts back into its own
/// submission order or they are lost, duplicated, or reordered across the turn boundary.
#[derive(Debug, Clone)]
pub(crate) struct SessionSnapshot {
    pub(crate) mode: core_protocol::PermissionMode,
    pub(crate) effort: core_protocol::Effort,
    pub(crate) model: String,
    pub(crate) cost: core_obs::CostState,
    pub(crate) last_turn_usage: Option<core_protocol::Usage>,
    pub(crate) unadmitted_steers: Vec<String>,
    /// The capability rules in force. Dynamic: `/permissions` changes them, and the frontend
    /// renders them, so they cannot be a session-invariant fact.
    pub(crate) permission_rules: core_protocol::PermissionRules,
    /// The ledger line the status panel prints.
    pub(crate) ledger_summary: String,
}

/// The EQ payload.
#[derive(Debug)]
pub(crate) enum ServerEvent {
    /// A kernel UI event, verbatim.
    Ui(UiEvent),
    /// A run reached a terminal state, with the runtime state the frontend mirrors.
    ///
    /// **Never dropped under backpressure** — this is the authoritative answer to "what happened",
    /// and it is also the only refresh point for the status line.
    RunEnded {
        completion: RunEnded,
        snapshot: Box<SessionSnapshot>,
    },
    /// The server declined to act on something and is telling the operator so.
    ///
    /// This is where an unknown `Op` surfaces. A submission the server does not understand is
    /// never replayed and never guessed at: it becomes a visible notice and stops.
    Notice(String),
    /// Cosmetic deltas were dropped to keep the queue bounded.
    ///
    /// Reported rather than hidden: a transcript with a silent hole in it is worse than one that
    /// says where the hole is.
    Lagged { dropped: usize },
}

impl ServerEvent {
    /// Is this event authoritative — must it be delivered even under backpressure?
    ///
    /// The acceptance criterion is "a saturated EQ still delivers every `Done` event, 0
    /// authoritative drops". Streamed text and thinking are the only two things a reader can miss
    /// without being lied to; everything else changes what the operator believes happened.
    pub(crate) fn is_authoritative(&self) -> bool {
        !matches!(self, Self::Ui(UiEvent::Text(_) | UiEvent::Thinking(_)))
    }
}

/// A control-plane request the frontend makes of the resident runtime.
///
/// # Why this is not on the SQ
///
/// It should be. `core_protocol::Op` has six variants — `UserInput`, `Steer`, `Interrupt`,
/// `Drain`, `ApprovalResponse`, `Unknown` — and **none of them can express `/model`, `/effort`,
/// `/mode`, `/permissions` or `/compact`**. Adding one is a change to the frozen wire types, which
/// WS1 owns and this issue's acceptance criteria explicitly forbid: "zero changes to
/// `core_protocol`; this issue only consumes them."
///
/// So the runtime is owned by the server — the frontend holds no `Agent` — and the operations the
/// wire cannot yet carry travel on a typed in-process channel beside it. That is a smaller lie than
/// either alternative: leaving the `Agent` in the frontend (which is the co-composition this issue
/// exists to remove) or quietly widening a frozen protocol.
///
/// **Folding these into the SQ is a WS1 protocol change, not a WS6 one.** When `Op` grows the
/// variants, each arm here becomes a `route()` case and this enum shrinks to nothing.
pub(crate) enum Control {
    /// `/effort`
    SetEffort(core_protocol::Effort),
    /// `/mode`
    SetPermissionMode(core_protocol::PermissionMode),
    /// `/permissions <capability> <verdict>`
    SetCapabilityRule {
        capability: core_protocol::Capability,
        verdict: core_protocol::Verdict,
    },
    /// `/model` — one transaction: durable audit append, capability fields, rate-card rebind.
    SelectModel(Box<ModelSelection>),
    /// `/compact`
    Compact { focus: Option<String> },
}

/// The `/model` transaction's inputs, kept together because the kernel applies them as one.
///
/// No `Debug`: `Arc<dyn Provider>` has none, and a hand-written one that printed the identifiers
/// while eliding the handle would put a provider id and a catalog digest into whatever logged it.
pub(crate) struct ModelSelection {
    pub(crate) provider: std::sync::Arc<dyn core_provider::Provider>,
    pub(crate) provider_id: String,
    pub(crate) model_id: String,
    pub(crate) catalog_digest: String,
    pub(crate) capability_digest: String,
    pub(crate) context_window_tokens: Option<u64>,
    pub(crate) max_output_tokens: Option<u32>,
}

/// What a control request answers with.
#[derive(Debug)]
pub(crate) enum ControlReply {
    /// The current runtime state. Answers `Snapshot` and every successful mutation.
    State(Box<SessionSnapshot>),
    /// The runtime refused, with the operator-facing reason.
    Refused(String),
    /// `/compact` finished.
    Compacted {
        report: Box<core_kernel::CompactionReport>,
        snapshot: Box<SessionSnapshot>,
    },
}

/// One control request and the channel its answer comes back on.
pub(crate) struct ControlRequest {
    pub(crate) control: Control,
    pub(crate) reply: tokio::sync::oneshot::Sender<ControlReply>,
}

/// A versioned EQ envelope.
///
/// Deliberately not `core_protocol::EqEnvelope` — see the module docs for the four losses that
/// would force.
#[derive(Debug)]
pub(crate) struct EventEnvelope {
    pub(crate) protocol_version: u32,
    pub(crate) event: ServerEvent,
}

impl EventEnvelope {
    /// Unwrap an event the frontend's negotiated protocol can render. Mirrors
    /// `SqEnvelope::into_current`: the version travels with the payload, so a server that started
    /// emitting a newer shape mid-session is caught at the point of use rather than assumed away by
    /// the connect-time handshake.
    pub(crate) fn into_current(self) -> Result<ServerEvent, ProtocolVersionError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        Ok(self.event)
    }
}

/// Why a submission did not reach the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubmitError {
    /// The server is gone: the run task that owned the receiver has ended.
    Disconnected,
    /// The queue is full. The operation was NOT accepted and must not be assumed applied.
    Busy,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str(
                "the App Server submission queue is closed; the runtime is no longer reachable",
            ),
            Self::Busy => formatter.write_str(
                "the App Server submission queue is full; the runtime has not accepted this operation",
            ),
        }
    }
}

impl std::error::Error for SubmitError {}

/// A version-negotiated client of the runtime App Server.
///
/// The client cannot be constructed without a completed handshake, so a version-skewed frontend can
/// never obtain a handle it would use to push envelopes the server rejects.
#[derive(Debug, Clone)]
pub(crate) struct AppServerClient {
    submissions: mpsc::Sender<SqEnvelope>,
    negotiated_version: u32,
}

impl AppServerClient {
    /// Complete a versioned handshake with a server advertising `server_version`.
    ///
    /// This is the ONLY constructor. An earlier version also offered `current()`, which stamped
    /// `PROTOCOL_VERSION` without checking anything on the ground that the in-process runtime
    /// "speaks the frontend's own version by construction" — true only for as long as the runtime
    /// stays in-process, which is precisely what this module ends. Skew is refused up front, not
    /// discovered one rejected submission at a time.
    pub(crate) fn connect(
        server_version: u32,
        submissions: mpsc::Sender<SqEnvelope>,
    ) -> Result<Self, ProtocolVersionError> {
        if server_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: server_version,
            });
        }
        Ok(Self {
            submissions,
            negotiated_version: server_version,
        })
    }

    /// The protocol version agreed during the handshake and stamped on every submission.
    pub(crate) fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Submit one operation, stamped with the negotiated protocol version.
    ///
    /// Never blocks: a full queue is reported as [`SubmitError::Busy`] so the render loop keeps
    /// running and the operator learns their input did not land.
    pub(crate) fn submit(&self, op: Op) -> Result<(), SubmitError> {
        use mpsc::error::TrySendError;
        self.submissions
            .try_send(SqEnvelope::with_version(self.negotiated_version, op))
            .map_err(|error| match error {
                TrySendError::Full(_) => SubmitError::Busy,
                TrySendError::Closed(_) => SubmitError::Disconnected,
            })
    }
}

/// The frontend's end of the wire: a client to submit through and a queue to read.
/// A registered tool, reduced to the three fields a client renders. `core_tools::ToolSpec` is not
/// public, so this is what crosses the attach boundary instead of the spec.
pub(crate) struct ToolFact {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) capability: core_protocol::Capability,
}

/// What a client is handed once, at attach time, and may read for the life of the session.
///
/// These are the shapes a co-composing frontend used to read straight off an idle `Agent`. They are
/// invariants — nothing here changes while the session runs — which is exactly why they can be
/// copied across the boundary instead of being asked for on every keystroke.
pub(crate) struct SessionFacts {
    pub(crate) workspace: std::path::PathBuf,
    pub(crate) memory_workspace: Option<std::path::PathBuf>,
    pub(crate) rollout_path: std::path::PathBuf,
    pub(crate) compaction_trigger_tokens: usize,
    /// The window of the model selected at startup. Only an initial value: `/model` replaces it,
    /// and the client tracks the current one itself.
    pub(crate) initial_model_context_window: Option<u64>,
    pub(crate) registry_tools: Vec<ToolFact>,
}

/// Everything a client needs to talk to a running App Server, and nothing more.
pub(crate) struct Attached {
    pub(crate) handle: AppServerHandle,
    /// The server task. Awaiting it after dropping the client is how a client waits for the
    /// runtime's own shutdown — the final rollout flush happens in there.
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) facts: SessionFacts,
    pub(crate) initial_state: SessionSnapshot,
    /// Ctrl-C: cancel the in-flight provider turn at the next safe point.
    pub(crate) interrupt: Arc<AtomicBool>,
    /// Ctrl-D: stop after checkpointing the workspace.
    pub(crate) drain: Arc<AtomicBool>,
}

/// **The composition root.** The one place an `Agent` is handed to an App Server, and the one place
/// the wire's version, capacities and ownership are decided.
///
/// The interactive TUI attaches here today; the one-shot path and the headless `core serve` (#44)
/// attach to this same function rather than building a second wire of their own. That is the point
/// of it being a function: a client that constructs its own transport is a client that can drift
/// from the protocol the server speaks, which is the failure this lane exists to remove.
///
/// It is a function here rather than statements in `main.rs` because the schema-compatibility
/// authority freezes `main` and `run_cli` token-for-token, along with `main.rs`'s module list
/// (`xtask/src/schema_compat_rust_semantics_functions.rs`). Single-sourcing the wire does not
/// require the call to be written in the composition root's file; it requires there to be exactly
/// one of it, which is what this is.
pub(crate) fn attach(mut agent: Agent) -> Result<Attached, ProtocolVersionError> {
    let (handle, ends) = wire()?;

    let interrupt = Arc::new(AtomicBool::new(false));
    agent.set_interrupt(interrupt.clone());
    let drain = Arc::new(AtomicBool::new(false));
    agent.set_drain(drain.clone());

    let facts = SessionFacts {
        workspace: agent.workspace.clone(),
        memory_workspace: agent.memory_workspace.clone(),
        rollout_path: agent.rollout.path().to_path_buf(),
        compaction_trigger_tokens: agent.compaction.trigger_tokens,
        initial_model_context_window: agent.model_context_window,
        registry_tools: agent
            .registry
            .specs()
            .into_iter()
            .map(|spec| ToolFact {
                name: spec.name,
                description: spec.description,
                capability: spec.capability,
            })
            .collect(),
    };
    let initial_state = snapshot_of(&mut agent);

    // The `Agent` moves in here and never comes back. "A run is in flight" becomes the server's
    // fact to report, not a slot a client can inspect.
    let task = tokio::spawn(AppServer::new(agent, ends).serve());

    Ok(Attached {
        handle,
        task,
        facts,
        initial_state,
        interrupt,
        drain,
    })
}

pub(crate) struct AppServerHandle {
    pub(crate) client: AppServerClient,
    pub(crate) events: mpsc::Receiver<EventEnvelope>,
    /// The control plane. See [`Control`] for why it is not the SQ.
    pub(crate) control: mpsc::Sender<ControlRequest>,
}

/// The EQ publisher, held by the server side.
///
/// Owns the drop policy so no call site can bypass it.
pub(crate) struct EventPublisher {
    events: mpsc::Sender<EventEnvelope>,
    dropped: usize,
}

impl EventPublisher {
    fn new(events: mpsc::Sender<EventEnvelope>) -> Self {
        Self { events, dropped: 0 }
    }

    /// Publish one event, applying the bounded-queue policy.
    ///
    /// Authoritative events wait for room. Cosmetic deltas are dropped when there is none, and the
    /// count is flushed as a `Lagged` notice as soon as the queue drains — so the transcript says
    /// where it is incomplete instead of quietly being wrong.
    pub(crate) async fn publish(&mut self, event: ServerEvent) -> Result<(), ()> {
        let authoritative = event.is_authoritative();
        if !authoritative && self.events.capacity() == 0 {
            self.dropped += 1;
            return Ok(());
        }
        // Report the gap immediately before the event that follows it. A cosmetic event only gets
        // to report when there is spare room — reporting a drop must never itself block the stream.
        // An authoritative event already waits for room, so the notice waits with it, and that is
        // what guarantees a run cannot end with an unreported gap: while the queue stays saturated
        // `capacity() > 1` is never true, so a policy that waited for slack alone would carry the
        // count silently past `RunEnded` and lose it.
        if self.dropped > 0 && (authoritative || self.events.capacity() > 1) {
            let dropped = std::mem::take(&mut self.dropped);
            self.events
                .send(EventEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    event: ServerEvent::Lagged { dropped },
                })
                .await
                .map_err(|_| ())?;
        }
        self.events
            .send(EventEnvelope {
                protocol_version: PROTOCOL_VERSION,
                event,
            })
            .await
            .map_err(|_| ())
    }
}

/// Build the wire and hand back both ends.
///
/// The frontend gets [`AppServerHandle`]; the server side gets the SQ receiver and the EQ
/// publisher. Both sides are constructed here so the capacities and the negotiated version have a
/// single source.
pub(crate) struct ServerEnds {
    pub(crate) submissions: mpsc::Receiver<SqEnvelope>,
    pub(crate) control: mpsc::Receiver<ControlRequest>,
    pub(crate) events: EventPublisher,
}

/// The protocol version the in-process runtime advertises to a connecting frontend.
///
/// Overridable only so a process-level test can point the frontend at a server that does not speak
/// its protocol. `core-cli` is a managed binary-only package — the boundary authority forbids it a
/// library target — so a skewed server cannot be injected any other way, and the refusal path would
/// otherwise be unreachable in every test that can actually run the frontend. A user who sets it
/// gets a refusal to attach and a diagnostic; there is nothing else behind the door.
pub(crate) fn advertised_version() -> u32 {
    std::env::var("CORE_APP_SERVER_PROTOCOL_VERSION")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(PROTOCOL_VERSION)
}

pub(crate) fn wire() -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    let (sq_tx, sq_rx) = mpsc::channel::<SqEnvelope>(SQ_CAPACITY);
    let (eq_tx, eq_rx) = mpsc::channel::<EventEnvelope>(EQ_CAPACITY);
    // The control plane is deliberately shallow: these are operator commands, one at a time, and a
    // backlog of them would mean the frontend is issuing config changes faster than a human can.
    let (control_tx, control_rx) = mpsc::channel::<ControlRequest>(8);
    let client = AppServerClient::connect(advertised_version(), sq_tx)?;
    Ok((
        AppServerHandle {
            client,
            events: eq_rx,
            control: control_tx,
        },
        ServerEnds {
            submissions: sq_rx,
            control: control_rx,
            events: EventPublisher::new(eq_tx),
        },
    ))
}

/// Where a submission goes once the server has classified it.
///
/// Split out so the routing is testable without a live `Agent`: the classification is the part that
/// decides whether an operation reaches the kernel at all, and it is the part an unknown `Op` must
/// not slip through.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Routed {
    /// Start a turn. The server owns "is a run in flight", not the frontend.
    StartTurn(String),
    /// Hand to the kernel's inbound queue: it consumes these at its own safe points.
    ToKernel,
    /// Refuse, and tell the operator why.
    ///
    /// An `Op` this build does not understand degrades here via `#[serde(other)]`. It is never
    /// replayed, never guessed at, and never auto-acted.
    Refuse(&'static str),
}

/// Classify one submission.
pub(crate) fn route(op: &Op) -> Routed {
    match op {
        Op::UserInput { text } => Routed::StartTurn(text.clone()),
        Op::Steer { .. } | Op::Interrupt | Op::Drain | Op::ApprovalResponse { .. } => {
            Routed::ToKernel
        }
        Op::Unknown => Routed::Refuse(
            "the runtime received a submission this build does not understand; it was discarded \
             rather than guessed at. Check that the client and server are the same version.",
        ),
    }
}

/// Everything the server needs to own a session.
pub(crate) struct AppServer {
    agent: Agent,
    submissions: mpsc::Receiver<SqEnvelope>,
    control: mpsc::Receiver<ControlRequest>,
    events: EventPublisher,
    /// Forwarded to the kernel's inbound queue. The kernel drains it at its own safe points; the
    /// server never reaches into a running turn.
    to_kernel: mpsc::UnboundedSender<SqEnvelope>,
}

impl AppServer {
    /// Take ownership of the runtime.
    ///
    /// `set_approvals` installs the kernel's inbound receiver here rather than in the frontend, so
    /// the queue outlives every turn. That is what removes `take_unadmitted_steers`: the reconcile
    /// path existed only because the receiver used to travel with the `Agent` in and out of a task
    /// the frontend owned.
    pub(crate) fn new(mut agent: Agent, ends: ServerEnds) -> Self {
        let (to_kernel, kernel_rx) = mpsc::unbounded_channel::<SqEnvelope>();
        agent.set_approvals(kernel_rx);
        Self {
            agent,
            submissions: ends.submissions,
            control: ends.control,
            events: ends.events,
            to_kernel,
        }
    }

    /// Run the session until every client hangs up.
    ///
    /// # Why this is one task and not a task per turn
    ///
    /// The frontend used to spawn a task per turn, move the `Agent` into it, and take it back
    /// through the `JoinHandle`. That made "a run is in flight" the same fact as "the slot is
    /// empty", which is why every configuration path was reachable only while idle — the borrow
    /// checker, not the design, was enforcing the ordering.
    ///
    /// Here the runtime is resident and the concurrency is explicit. The one borrow that matters is
    /// `agent`, held by the in-flight turn; the submission queue, the kernel's inbound sender and
    /// the event publisher are disjoint locals, so the `select!` below can keep draining the SQ and
    /// republishing the EQ *while* a turn runs. Destructuring `self` is what makes that legal, and
    /// it is the whole trick.
    pub(crate) async fn serve(self) {
        let Self {
            mut agent,
            mut submissions,
            mut control,
            mut events,
            to_kernel,
        } = self;

        // The kernel's UI stream stays unbounded: it is already backpressured downstream by the
        // bounded EQ, and a bound here would make the kernel block on a frontend that stopped
        // reading — the opposite of what the EQ policy is for.
        let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiEvent>();
        agent.set_ui(ui_tx);

        // `run` versus `follow_up` was a caller-side boolean the frontend chose. With a resident
        // runtime it is session state and belongs here: the first admitted turn starts the session,
        // every later one continues it.
        let mut started = false;

        loop {
            let envelope = tokio::select! {
                request = control.recv() => {
                    match request {
                        Some(request) => { apply_control(&mut agent, &mut events, request).await; continue }
                        None => break,
                    }
                }
                envelope = submissions.recv() => {
                    match envelope { Some(envelope) => envelope, None => break }
                }
            };
            let version = envelope.protocol_version;
            let Ok(op) = envelope.into_current() else {
                let _ = events
                    .publish(ServerEvent::Notice(format!(
                        "a submission arrived stamped protocol v{version}; this runtime speaks v{PROTOCOL_VERSION} and discarded it"
                    )))
                    .await;
                continue;
            };
            match route(&op) {
                Routed::Refuse(why) => {
                    let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                }
                Routed::ToKernel => {
                    if to_kernel
                        .send(SqEnvelope::with_version(version, op))
                        .is_err()
                    {
                        break;
                    }
                }
                Routed::StartTurn(task) => {
                    // Control requests that arrive mid-turn wait here; see the `select!` arm below.
                    let mut deferred: Vec<ControlRequest> = Vec::new();
                    let completion = {
                        let running = async {
                            if started {
                                agent.follow_up(&task).await
                            } else {
                                agent.run(&task).await
                            }
                        };
                        tokio::pin!(running);
                        loop {
                            tokio::select! {
                                // Biased so the event stream is served before the turn is polled
                                // again: a burst of deltas must reach the frontend while the turn
                                // is still producing, not in one lump at the end.
                                biased;
                                Some(ui) = ui_rx.recv() => {
                                    if events.publish(ServerEvent::Ui(ui)).await.is_err() {
                                        // The frontend is gone. Keep the turn running to its own
                                        // safe point rather than dropping the future mid-effect.
                                    }
                                }
                                Some(request) = control.recv() => {
                                    // Configuration DURING a turn is DEFERRED, not applied.
                                    //
                                    // The borrow checker says so and it is right: the turn holds
                                    // `&mut agent` for its whole duration, so there is no instant
                                    // at which a mutation could be applied without interleaving it
                                    // into the turn's own state. The old design got this ordering
                                    // for free — the frontend's `Option<Agent>` was empty while
                                    // running, so `/model` and `/effort` were structurally
                                    // unreachable — and lost the reason along with the `Option`.
                                    //
                                    // Deferring makes the same guarantee an explicit decision:
                                    // requests are applied at the turn boundary, in arrival order,
                                    // and the operator's answer arrives when it is true rather
                                    // than when it was asked.
                                    deferred.push(request);
                                }
                                Some(envelope) = submissions.recv() => {
                                    let version = envelope.protocol_version;
                                    if let Ok(op) = envelope.into_current() {
                                        match route(&op) {
                                            // A second turn cannot start while one is running; the
                                            // frontend queues it. Saying so is better than
                                            // silently dropping it.
                                            Routed::StartTurn(_) => {
                                                let _ = events.publish(ServerEvent::Notice(
                                                    "a turn is already running; this submission was not admitted".into(),
                                                )).await;
                                            }
                                            Routed::ToKernel => {
                                                let _ = to_kernel.send(SqEnvelope::with_version(version, op));
                                            }
                                            Routed::Refuse(why) => {
                                                let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                                            }
                                        }
                                    }
                                }
                                outcome = &mut running => break outcome,
                            }
                        }
                    };
                    started = true;

                    // The tail. The turn's completion is the synchronisation barrier for the kernel's
                    // sender, so deltas emitted between the last `select!` poll and the return are
                    // still queued here. Draining before the terminal event is what keeps the
                    // transcript ordered.
                    while let Ok(ui) = ui_rx.try_recv() {
                        let _ = events.publish(ServerEvent::Ui(ui)).await;
                    }

                    // The turn's borrow has ended, so the deferred control plane can run — in
                    // arrival order, before the snapshot, so the state the frontend receives
                    // already reflects everything it asked for during the turn.
                    for request in deferred {
                        apply_control(&mut agent, &mut events, request).await;
                    }

                    let snapshot = snapshot_of(&mut agent);
                    let completion = match completion {
                        Ok(outcome) => RunEnded::Outcome(outcome),
                        Err(error) => RunEnded::Error(error.public_summary()),
                    };
                    if events
                        .publish(ServerEvent::RunEnded {
                            completion,
                            snapshot: Box::new(snapshot),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    }
}

/// Apply one control request against the resident runtime.
///
/// Free function rather than a method so it can be called from inside `serve`'s `select!`, where
/// `self` has been destructured and only `agent` is borrowable.
///
/// Every arm answers. A control request that got no reply would hang the frontend's render loop,
/// which is the one failure a control plane must not have.
async fn apply_control(agent: &mut Agent, events: &mut EventPublisher, request: ControlRequest) {
    let reply = match request.control {
        Control::SetEffort(next) => {
            match agent.transition_effort(next, core_protocol::RuntimePolicySource::Operator) {
                Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                Err(error) => ControlReply::Refused(error.public_summary()),
            }
        }
        Control::SetPermissionMode(next) => {
            match agent
                .transition_permission_mode(next, core_protocol::RuntimePolicySource::Operator)
            {
                Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                Err(error) => ControlReply::Refused(error.public_summary()),
            }
        }
        Control::SetCapabilityRule {
            capability,
            verdict,
        } => match agent.transition_permission_capability_rule(
            capability,
            verdict,
            core_protocol::RuntimePolicySource::Operator,
        ) {
            Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
            Err(error) => ControlReply::Refused(error.public_summary()),
        },
        Control::SelectModel(selection) => {
            // One transaction, in the kernel's required order: the durable audit append happens
            // FIRST, so a failure leaves the old selection in force rather than a half-applied one.
            let ModelSelection {
                provider,
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
                context_window_tokens,
                max_output_tokens,
            } = *selection;
            let changed = agent.model != model_id;
            match agent.record_provider_model_selection(
                provider,
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            ) {
                Ok(()) => {
                    agent.model_context_window = context_window_tokens;
                    agent.model_max_output_tokens = max_output_tokens;
                    if changed {
                        // Last-turn usage belongs to the model that produced it. Carrying it across
                        // a switch would print the old model's token counts under the new one's
                        // name; the frontend used to clear this itself, back when it held the
                        // ledger.
                        agent.ledger.last_turn_usage = None;
                    }
                    match agent.bind_selected_rate_card() {
                        Ok(bound) => {
                            if !bound && agent.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) {
                                // Advisory, not a refusal: the route is recorded and in force. The
                                // operator needs to know the ceiling will stop provider calls, so it
                                // goes out on the EQ where every other runtime advisory goes.
                                let _ = events
                                    .publish(ServerEvent::Notice(
                                        "selected route has no active verified rate card; the USD \
                                         ceiling will block provider calls"
                                            .into(),
                                    ))
                                    .await;
                            }
                            ControlReply::State(Box::new(snapshot_of(agent)))
                        }
                        Err(error) => ControlReply::Refused(error.public_summary()),
                    }
                }
                Err(error) => ControlReply::Refused(format!(
                    "cannot record model switch; old selection retained: {error}"
                )),
            }
        }
        Control::Compact { focus } => match agent.compact_now(focus).await {
            Ok(report) => ControlReply::Compacted {
                report: Box::new(report),
                snapshot: Box::new(snapshot_of(agent)),
            },
            Err(error) => ControlReply::Refused(error.public_summary()),
        },
    };
    // A frontend that dropped the receiver has moved on; that is not the server's problem.
    let _ = request.reply.send(reply);
}

/// Read the runtime state the frontend mirrors.
fn snapshot_of(agent: &mut Agent) -> SessionSnapshot {
    SessionSnapshot {
        mode: agent.permission_mode(),
        effort: agent.effort(),
        model: agent.model.clone(),
        cost: agent.ledger.cost_state(),
        last_turn_usage: agent.ledger.last_turn_usage,
        unadmitted_steers: agent.take_unadmitted_steers(),
        permission_rules: agent.permission_rules().clone(),
        ledger_summary: agent.ledger.summary(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(op: Op) -> SqEnvelope {
        SqEnvelope::with_version(PROTOCOL_VERSION, op)
    }

    fn snapshot() -> Box<SessionSnapshot> {
        Box::new(SessionSnapshot {
            mode: core_protocol::PermissionMode::default(),
            effort: core_protocol::Effort::default(),
            model: "test-model".into(),
            cost: core_obs::CostState::default(),
            last_turn_usage: None,
            unadmitted_steers: Vec::new(),
            permission_rules: core_protocol::PermissionRules::new(),
            ledger_summary: String::new(),
        })
    }

    #[test]
    fn matching_version_connects_and_stamps_every_submission() {
        let (tx, mut rx) = mpsc::channel::<SqEnvelope>(4);
        let client = AppServerClient::connect(PROTOCOL_VERSION, tx)
            .expect("the current server version accepts the handshake");
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);

        client
            .submit(Op::Interrupt)
            .expect("submit reaches the queue");
        let envelope = rx.try_recv().expect("submission is queued");
        assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
        assert!(matches!(envelope.into_current(), Ok(Op::Interrupt)));
    }

    #[test]
    fn version_skew_is_refused_up_front() {
        let (tx, mut rx) = mpsc::channel::<SqEnvelope>(4);
        let err = AppServerClient::connect(PROTOCOL_VERSION + 1, tx.clone())
            .expect_err("a peer on a different version must be refused");
        assert_eq!(err.expected, PROTOCOL_VERSION);
        assert_eq!(err.actual, PROTOCOL_VERSION + 1);
        assert!(rx.try_recv().is_err(), "a refused handshake queues nothing");
        assert!(AppServerClient::connect(PROTOCOL_VERSION - 1, tx).is_err());
    }

    #[test]
    fn a_closed_queue_and_a_full_queue_are_different_answers() {
        // The frontend must be able to tell "the runtime is gone" from "try again": one is fatal,
        // the other is a keystroke that did not land.
        let (tx, rx) = mpsc::channel::<SqEnvelope>(1);
        let client = AppServerClient::connect(PROTOCOL_VERSION, tx).expect("handshake");
        client.submit(Op::Interrupt).expect("first fits");
        assert_eq!(client.submit(Op::Drain), Err(SubmitError::Busy));
        drop(rx);
        assert_eq!(client.submit(Op::Drain), Err(SubmitError::Disconnected));
    }

    #[test]
    fn a_saturated_sq_applies_backpressure_within_a_fixed_bound() {
        // The bound is the point: an unbounded queue answers every submission and grows until the
        // process dies. This one refuses, and the refusal is what the operator sees.
        let (tx, _rx) = mpsc::channel::<SqEnvelope>(SQ_CAPACITY);
        let client = AppServerClient::connect(PROTOCOL_VERSION, tx).expect("handshake");
        let mut accepted = 0usize;
        for _ in 0..(SQ_CAPACITY * 4) {
            match client.submit(Op::Interrupt) {
                Ok(()) => accepted += 1,
                Err(SubmitError::Busy) => break,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(accepted, SQ_CAPACITY, "the queue accepted past its bound");
        assert_eq!(client.submit(Op::Interrupt), Err(SubmitError::Busy));
    }

    #[tokio::test]
    async fn a_saturated_eq_drops_only_cosmetic_deltas_and_never_the_terminal_event() {
        // The acceptance criterion: 0 authoritative drops. A reader that never reads must still be
        // able to learn how the run ended once it starts reading.
        let (tx, mut rx) = mpsc::channel::<EventEnvelope>(8);
        let mut publisher = EventPublisher::new(tx);
        for i in 0..64 {
            publisher
                .publish(ServerEvent::Ui(UiEvent::Text(format!("chunk {i}"))))
                .await
                .expect("cosmetic deltas never fail");
        }
        // Terminal event, with the queue already saturated: it waits rather than being dropped.
        let publish = tokio::spawn(async move {
            publisher
                .publish(ServerEvent::RunEnded {
                    completion: RunEnded::Error("done".into()),
                    snapshot: snapshot(),
                })
                .await
        });
        let mut saw_terminal = false;
        let mut saw_lag_notice = false;
        while let Some(envelope) = rx.recv().await {
            assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
            match envelope.event {
                ServerEvent::RunEnded { .. } => {
                    saw_terminal = true;
                    break;
                }
                ServerEvent::Lagged { dropped } => {
                    assert!(dropped > 0);
                    saw_lag_notice = true;
                }
                ServerEvent::Ui(_) | ServerEvent::Notice(_) => {}
            }
        }
        publish.await.expect("publisher task").expect("delivered");
        assert!(saw_terminal, "the terminal event was dropped");
        assert!(saw_lag_notice, "dropped deltas were not reported");
    }

    #[tokio::test]
    async fn a_flooded_eq_delivers_every_authoritative_event_and_only_drops_deltas() {
        // The criterion is "0 authoritative drops", not "the last one arrives". A slow reader and a
        // long flood is where a drop-oldest policy loses events in the middle, so the oracle counts
        // every authoritative event and checks their order, not just the terminal one.
        const CAPACITY: usize = 8;
        const ROUNDS: usize = 256;
        const AUTHORITATIVE_EVERY: usize = 4;
        let (tx, mut rx) = mpsc::channel::<EventEnvelope>(CAPACITY);
        let mut publisher = EventPublisher::new(tx);

        let flood = tokio::spawn(async move {
            for i in 0..ROUNDS {
                publisher
                    .publish(ServerEvent::Ui(UiEvent::Text(format!("delta {i}"))))
                    .await
                    .expect("cosmetic deltas are never a transport failure");
                if i % AUTHORITATIVE_EVERY == 0 {
                    publisher
                        .publish(ServerEvent::Notice(format!("authoritative {i}")))
                        .await
                        .expect("authoritative events wait for room, they do not fail");
                }
            }
            publisher
                .publish(ServerEvent::RunEnded {
                    completion: RunEnded::Error("done".into()),
                    snapshot: snapshot(),
                })
                .await
                .expect("the terminal event is delivered")
        });

        let expected: Vec<String> = (0..ROUNDS)
            .filter(|i| i % AUTHORITATIVE_EVERY == 0)
            .map(|i| format!("authoritative {i}"))
            .collect();
        let mut seen: Vec<String> = Vec::new();
        let mut deltas = 0usize;
        let mut dropped = 0usize;
        let mut saw_terminal = false;
        while let Some(envelope) = rx.recv().await {
            // A reader slow enough that the queue stays saturated for the whole flood.
            tokio::task::yield_now().await;
            assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
            match envelope.event {
                ServerEvent::Notice(text) => seen.push(text),
                ServerEvent::Ui(_) => deltas += 1,
                ServerEvent::Lagged { dropped: count } => dropped += count,
                ServerEvent::RunEnded { .. } => {
                    saw_terminal = true;
                    break;
                }
            }
        }
        flood.await.expect("publisher task");

        assert!(saw_terminal, "the terminal event was dropped");
        assert_eq!(
            seen, expected,
            "every authoritative event must arrive, in order and exactly once"
        );
        // The other half of "bounded": deltas really were shed rather than buffered. Without this
        // the test would also pass against an unbounded queue, which is the bug being fixed.
        assert!(
            dropped > 0 && deltas < ROUNDS,
            "a saturated queue must shed cosmetic deltas and report how many ({deltas} delivered, {dropped} reported dropped)"
        );
    }

    #[test]
    fn an_event_from_a_newer_server_is_refused_at_the_point_of_use() {
        // The connect-time handshake covers the session's start. The version travels with each
        // event so a server that begins emitting a newer shape mid-session is caught too, rather
        // than being rendered as if it were the shape this build knows.
        let envelope = EventEnvelope {
            protocol_version: PROTOCOL_VERSION + 1,
            event: ServerEvent::Notice("from the future".into()),
        };
        assert_eq!(
            envelope.into_current().unwrap_err(),
            ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: PROTOCOL_VERSION + 1,
            }
        );
        let current = EventEnvelope {
            protocol_version: PROTOCOL_VERSION,
            event: ServerEvent::Notice("now".into()),
        };
        assert!(matches!(current.into_current(), Ok(ServerEvent::Notice(_))));
    }

    #[test]
    fn every_op_is_classified_and_an_unknown_one_is_refused() {
        assert_eq!(
            route(&Op::UserInput { text: "hi".into() }),
            Routed::StartTurn("hi".into())
        );
        for op in [
            Op::Steer { text: "x".into() },
            Op::Interrupt,
            Op::Drain,
            Op::ApprovalResponse {
                id: core_protocol::SubmissionId(1),
                approved: true,
                remember: false,
            },
        ] {
            assert_eq!(route(&op), Routed::ToKernel, "{op:?}");
        }
        // The degradation path: an `Op` this build does not know is refused with a notice, never
        // replayed and never auto-acted.
        assert!(matches!(route(&Op::Unknown), Routed::Refuse(_)));
    }

    #[test]
    fn an_unknown_op_arriving_on_the_wire_degrades_rather_than_failing_the_decode() {
        // `#[serde(other)]` on `Op::Unknown` is what makes a newer client's submission readable at
        // all; the routing above is what stops it being acted on.
        let decoded: Op = serde_json::from_value(serde_json::json!({
            "op": "some_future_op",
            "payload": {"secret": "must not be replayed"}
        }))
        .expect("an unknown tag degrades instead of failing the decode");
        assert!(matches!(decoded, Op::Unknown));
        assert!(matches!(route(&decoded), Routed::Refuse(_)));
    }

    #[test]
    fn the_wire_hands_back_both_ends_at_one_capacity() {
        let (handle, ends) = wire().expect("the in-process handshake succeeds");
        assert_eq!(handle.client.negotiated_version(), PROTOCOL_VERSION);
        assert_eq!(ends.submissions.capacity(), SQ_CAPACITY);
        // The control plane exists and is separate from the SQ. It is separate because `Op` cannot
        // express `/model`, `/effort`, `/mode` or `/compact` and this lane may not widen it.
        assert!(!handle.control.is_closed());
        let _ = envelope(Op::Interrupt);
    }
}

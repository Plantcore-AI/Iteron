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

mod control;

use self::control::{apply_control, apply_immediate_control, is_immediate_control, snapshot_of};
#[cfg(test)]
use self::control::{apply_immediate_workflow_control, apply_side};
use crate::runtime::{Agent, UiEvent};
use core_protocol::{
    ContentSegments, Op, Outcome, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope,
};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// Submission-queue depth.
///
/// Sized for the burst a human can produce with a held key or a paste, not for a backlog: past this
/// the honest answer is "busy", not a longer queue.
pub(crate) const SQ_CAPACITY: usize = 256;

/// Conservative heap charge for the envelope, enum/segment storage, channel node and allocator
/// bookkeeping of one submission, before counting its variable-length strings.
///
/// Small control operations use only this charge. Keeping a full queue's worth in reserve means
/// the byte budget never reduces the existing 256-item control burst bound.
const SQ_ENTRY_OVERHEAD_BYTES: usize = 1024;

/// Bytes reserved for a full [`SQ_CAPACITY`] burst of small control operations.
const SQ_CONTROL_RESERVE_BYTES: usize = SQ_CAPACITY * SQ_ENTRY_OVERHEAD_BYTES;

/// Total heap budget for submissions waiting on the in-process SQ.
///
/// This admits one maximum legal multimodal submission (1 MiB text plus 32 MiB of encoded image
/// data), with a full control-queue reserve beside it. The item bound still applies, so a maximum
/// payload plus controls can occupy at most 256 queue slots. Charging the actual text and encoded
/// image lengths prevents 256 maximum payloads from multiplying into a multi-GiB queue.
pub(crate) const SQ_BYTE_CAPACITY: usize = SQ_ENTRY_OVERHEAD_BYTES
    + core_protocol::task::MAX_TASK_TEXT_BYTES
    + core_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
    + SQ_CONTROL_RESERVE_BYTES;

/// Event-queue depth.
///
/// Streamed text arrives far faster than a terminal repaints, so this is the elastic that absorbs a
/// burst between frames. It is a bound, not a buffer to be filled: see the drop policy above.
pub(crate) const EQ_CAPACITY: usize = 1024;

/// The authoritative terminal facts needed by every non-interactive client.
///
/// Keeping this projection on the server side is what lets one-shot and headless clients remain
/// clients: neither needs to reclaim the [`Agent`] or parse `UiEvent::Done`'s debug string. The
/// stable result-v5 object is still constructed by `output::final_result` at the client boundary.
#[derive(Debug, Clone)]
pub(crate) struct TerminalSummary {
    pub(crate) outcome: Outcome,
    pub(crate) assistant_text: String,
    pub(crate) run_id: String,
    pub(crate) cost: core_obs::CostState,
    pub(crate) turns: u32,
    pub(crate) kernel_tax: core_obs::KernelTax,
    pub(crate) error: Option<String>,
    pub(crate) memo_hits: u64,
    pub(crate) memo_misses: u64,
}

impl TerminalSummary {
    /// Project the one terminal authority into the versioned object consumed by every sibling
    /// client. Presentation remains client-owned; outcome, exit status, and result fields do not.
    pub(crate) fn result_v5(&self) -> serde_json::Value {
        crate::output::final_result(
            &self.outcome,
            &self.assistant_text,
            &self.run_id,
            &self.cost,
            self.turns,
            self.kernel_tax,
            self.error.as_deref(),
        )
    }
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
    /// One line of provider quota, read from the response headers of the last request. `None`
    /// when the route publishes none — a row of dashes reads like an exhausted budget (I-53).
    pub(crate) rate_limit: Option<String>,
}

/// The EQ payload.
#[derive(Debug, Clone)]
pub(crate) enum ServerEvent {
    /// A kernel UI event, verbatim.
    Ui(UiEvent),
    /// A run reached a terminal state, with the runtime state the frontend mirrors.
    ///
    /// **Never dropped under backpressure** — this is the authoritative answer to "what happened",
    /// and it is also the only refresh point for the status line.
    RunEnded {
        snapshot: Box<SessionSnapshot>,
        summary: Box<TerminalSummary>,
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
    /// One live update for a QuickJS workflow-script run (ADR-0001 step 1).
    ///
    /// A second payload rather than a `UiEvent` variant, because `UiEvent` is the frozen, published
    /// stream/event-queue vocabulary and `ProgressEvent` is the engine's unfrozen in-process one;
    /// see `crate::runtime::Agent::workflow_progress_tx`. Both arrive on the same EQ, so the card
    /// still lands in transcript order relative to the assistant text around it.
    WorkflowRun(crate::workflow::WorkflowRunUiEvent),
}

impl ServerEvent {
    /// Is this event authoritative — must it be delivered even under backpressure?
    ///
    /// The acceptance criterion is "a saturated EQ still delivers every `Done` event, 0
    /// authoritative drops". Streamed text and thinking are the only two things a reader can miss
    /// without being lied to; everything else changes what the operator believes happened.
    ///
    /// A workflow row's `AgentActivity` tick joins them: it restates a running row's climbing
    /// token/tool counters, so a reader that misses one sees a slightly stale line and nothing
    /// else. Every other workflow update — the queued fan, a phase boundary, a narrator line, a
    /// terminal row, the run settling — changes what the operator believes happened, so those wait
    /// for room like any other authoritative event. Dropping an `AgentFinished` would leave a row
    /// spinning as `Running` for the rest of the session.
    pub(crate) fn is_authoritative(&self) -> bool {
        !matches!(
            self,
            Self::Ui(UiEvent::Text(_) | UiEvent::Thinking(_))
                | Self::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Progress {
                    event: core_workflow::events::ProgressEvent::AgentActivity { .. },
                    ..
                })
        )
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
    /// `/budget` — read the turn ceiling, or (with `set`) move it for this session.
    TurnBudget { set: Option<u32> },
    /// `/side` — the operator's side conversation.
    Side(SideRequest),
    /// `/resume <run>` — adopt another recorded run into this live session.
    AdoptRun(Box<AdoptRun>),
    /// `/workflows` fullscreen operator controls. Inventory and cancellation are owned by the
    /// session-scoped workflow supervisor; resume also asks the resident agent to reconstruct the
    /// persisted run under the current route and authority.
    Workflow(WorkflowControl),
    /// `/jobs` controls the exact supervisor backing the model-facing `process_*` tools.
    Job(JobControl),
}

pub(crate) enum JobControl {
    Inventory,
    Attach {
        job_id: String,
        stdout_cursor: u64,
        stderr_cursor: u64,
    },
    Write {
        job_id: String,
        input: String,
        eof: bool,
    },
    Stop {
        job_id: String,
    },
}

/// One operator action from the interactive workflow panel.
pub(crate) enum WorkflowControl {
    Inventory,
    Cancel { run_id: String },
    Resume { run_id: String },
}

/// The complete workflow-panel control reply. Returning inventory with every action lets the
/// frontend render the state the owner actually reached instead of optimistically changing a row.
#[derive(Debug, Clone)]
pub(crate) struct WorkflowControlReply {
    pub(crate) runs: Vec<crate::workflow::SupervisedRunInfo>,
    pub(crate) notice: Option<String>,
}

/// The inputs of one in-process session adoption, kept together because the runtime applies them as
/// one: a session that adopted a transcript but not a route would refuse its own next turn.
///
/// The `Rollout` is opened by the CLIENT, before the request is sent. That is deliberate: opening it
/// is what takes the target run's exclusive writer lock, and it is the failure an operator is most
/// likely to hit (another process is on that run). Taking it client-side means that refusal never
/// reaches the resident runtime, so the live session cannot be disturbed by an adoption that was
/// never possible.
pub(crate) struct AdoptRun {
    pub(crate) rollout: core_record::Rollout,
    /// Empty operator-created run: record a new genesis and dispatch its first prompt as a fresh
    /// turn instead of treating it as a resumed transcript.
    pub(crate) fresh: bool,
    /// The route the adopted session will actually dispatch on — the record's own route when the
    /// client could resolve a provider for it, otherwise the route this process is already using.
    /// Recorded into the adopted journal, so what the session runs on is what its record says.
    pub(crate) route: Box<ModelSelection>,
}

/// What the operator wants of the side conversation.
///
/// The conversation itself is server state, exactly like the `Agent`, and for the same reason: it
/// holds a live runtime with an open journal, so a frontend that owned it could be restarted, lose
/// it, and leave a half-written record with nobody to close it.
pub(crate) enum SideRequest {
    /// Ask a question, opening the conversation if this is the first one.
    Ask(String),
    /// Report identity and books without asking anything (and without opening one).
    Status,
    /// End it. The next `Ask` starts a new conversation with a new record.
    Close,
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
        report: Box<crate::runtime::CompactionReport>,
        snapshot: Box<SessionSnapshot>,
    },
    /// `/budget` — the ceiling actually in force and the attempts charged against it.
    TurnBudget(crate::runtime::TurnBudgetState),
    /// `/side <question>` — the side conversation's answer plus its own books.
    SideAnswer(Box<crate::runtime::SideAnswer>),
    /// `/side status` and `/side close` — the side conversation's own books, or `None` when there
    /// is no open one. `closed` distinguishes "here is what it cost" from "here is what it cost,
    /// and it is now over".
    SideStatus {
        status: Option<Box<crate::runtime::SideStatus>>,
        closed: bool,
    },
    /// The session is now on another run. The identity is what the runtime reached, so a frontend
    /// that renders it cannot show a run the next turn will not continue.
    ///
    /// `blocked` is the honest half. The journal swap and the route rebind are two durable steps,
    /// and the second one can fail after the first has taken effect. When it does, the session IS on
    /// the adopted run — that is why this is not a `Refused` — but it cannot dispatch, because the
    /// kernel refuses every provider request whose route its record does not carry. The frontend
    /// must show the adopted identity AND this reason: a screen still showing the previous run would
    /// be the one thing worse than the failure.
    Adopted {
        adopted: Box<crate::runtime::AdoptedRun>,
        snapshot: Box<SessionSnapshot>,
        blocked: Option<String>,
    },
    /// `/workflows` inventory or action result.
    Workflows(Box<WorkflowControlReply>),
    /// `/jobs` inventory, attached output page, write receipt, or terminal stop snapshot.
    Jobs(serde_json::Value),
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
#[derive(Debug, Clone)]
pub(crate) struct EventEnvelope {
    /// Monotonic live-delivery cursor. This is deliberately not `core_protocol::Seq`, which names
    /// the durable hash-chained Rollout order. Reconnect code must never conflate the two.
    pub(crate) seq: u64,
    pub(crate) protocol_version: u32,
    pub(crate) event: ServerEvent,
}

impl EventEnvelope {
    /// The live-delivery cursor used to reject duplicate or reordered EQ frames.
    pub(crate) fn sequence(&self) -> u64 {
        self.seq
    }

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
    submissions: SubmissionSender,
    negotiated_version: u32,
}

#[derive(Debug, Clone)]
enum SubmissionSender {
    /// Test-only bare wires keep the existing constructor usable by frontend submission tests.
    #[cfg(test)]
    Bare(mpsc::Sender<SqEnvelope>),
    /// Production wires charge every queued submission against the shared heap budget.
    Weighted {
        sender: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
    },
}

/// One weighted SQ entry. The permit is released when the server dequeues or drops the item.
#[derive(Debug)]
pub(crate) struct QueuedSubmission {
    envelope: SqEnvelope,
    _memory: OwnedSemaphorePermit,
}

impl QueuedSubmission {
    fn into_envelope(self) -> SqEnvelope {
        self.envelope
    }
}

impl AppServerClient {
    /// Complete a versioned handshake with a server advertising `server_version`.
    ///
    /// This is the ONLY constructor. An earlier version also offered `current()`, which stamped
    /// `PROTOCOL_VERSION` without checking anything on the ground that the in-process runtime
    /// "speaks the frontend's own version by construction" — true only for as long as the runtime
    /// stays in-process, which is precisely what this module ends. Skew is refused up front, not
    /// discovered one rejected submission at a time.
    #[cfg(test)]
    pub(crate) fn connect(
        server_version: u32,
        submissions: mpsc::Sender<SqEnvelope>,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_to(server_version, SubmissionSender::Bare(submissions))
    }

    fn connect_weighted(
        server_version: u32,
        submissions: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_to(
            server_version,
            SubmissionSender::Weighted {
                sender: submissions,
                budget,
            },
        )
    }

    fn connect_to(
        server_version: u32,
        submissions: SubmissionSender,
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
        let envelope = SqEnvelope::with_version(self.negotiated_version, op);
        match &self.submissions {
            #[cfg(test)]
            SubmissionSender::Bare(submissions) => {
                submissions.try_send(envelope).map_err(|error| match error {
                    TrySendError::Full(_) => SubmitError::Busy,
                    TrySendError::Closed(_) => SubmitError::Disconnected,
                })
            }
            SubmissionSender::Weighted { sender, budget } => {
                if sender.is_closed() {
                    return Err(SubmitError::Disconnected);
                }
                let weight = u32::try_from(submission_weight(&envelope.op))
                    .map_err(|_| SubmitError::Busy)?;
                let permit = budget
                    .clone()
                    .try_acquire_many_owned(weight)
                    .map_err(|_| SubmitError::Busy)?;
                sender
                    .try_send(QueuedSubmission {
                        envelope,
                        _memory: permit,
                    })
                    .map_err(|error| match error {
                        TrySendError::Full(_) => SubmitError::Busy,
                        TrySendError::Closed(_) => SubmitError::Disconnected,
                    })
            }
        }
    }
}

/// Heap bytes charged to a queued operation.
///
/// The fixed charge covers bounded container/allocation overhead. Every variable-size text and
/// encoded-image allocation visible through `Op` is then charged at its actual byte length.
fn submission_weight(op: &Op) -> usize {
    let variable_bytes = match op {
        Op::UserInput { text } | Op::Steer { text } => text.len(),
        Op::UserInputV2 { segments } => {
            segments
                .as_slice()
                .iter()
                .fold(0usize, |bytes, segment| match segment {
                    core_protocol::ContentSegment::Text { text } => {
                        bytes.saturating_add(text.len())
                    }
                    core_protocol::ContentSegment::Image { image } => {
                        bytes.saturating_add(image.data.encoded_len())
                    }
                    core_protocol::ContentSegment::Unknown => bytes,
                })
        }
        // Same rule as the segment list above: every variable-size allocation `Op` exposes is
        // charged at its actual byte length, so a queue full of file chips is bounded in bytes and
        // not merely in entries.
        Op::UserInputV3 {
            text,
            images,
            files,
        } => images
            .iter()
            .fold(text.len(), |bytes, image| {
                bytes.saturating_add(image.data.encoded_len())
            })
            .saturating_add(files.iter().fold(0usize, |bytes, file| {
                bytes
                    .saturating_add(file.path.len())
                    .saturating_add(file.text.len())
            })),
        Op::ApprovalResponse { .. } | Op::Interrupt | Op::Drain | Op::Unknown => 0,
    };
    SQ_ENTRY_OVERHEAD_BYTES.saturating_add(variable_bytes)
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
    pub(crate) memory_strategy: Arc<dyn core_protocol::slot::StrategySlot>,
    pub(crate) rollout_path: std::path::PathBuf,
    pub(crate) compaction_trigger_tokens: usize,
    /// The window of the model selected at startup. Only an initial value: `/model` replaces it,
    /// and the client tracks the current one itself.
    pub(crate) initial_model_context_window: Option<u64>,
    /// Whether the capability gate is replaced by blanket auto-approval for this session. A
    /// startup fact, not runtime state: nothing changes it after `wire`. It is carried here so the
    /// permission surfaces can say so — a `/permissions` screen listing "ask every time" rows while
    /// nothing asks would be a lie, and one this project's own truth overlay exists to prevent.
    pub(crate) bypass_permissions: bool,
    pub(crate) registry_tools: Vec<ToolFact>,
    /// Exact verified dependency skill roots pinned into the runtime at composition time.
    pub(crate) dependency_skill_dirs: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    /// The exact immutable `Arc` the runtime resolves child definitions against. Keeping object
    /// identity across the attach boundary prevents `/agents` from presenting filesystem drift as
    /// executable state while the resident runtime continues using its pinned catalog.
    pub(crate) agent_catalog: Arc<core_agents::AgentCatalog>,
}

/// Everything a client needs to talk to a running App Server, and nothing more.
pub(crate) struct Attached {
    pub(crate) handle: AppServerHandle,
    /// The server task. Awaiting it after dropping the client is how a client waits for the
    /// runtime's own shutdown — the final rollout flush happens in there, and so does cancelling
    /// and recording any workflow run the session still owned. It yields what it did with those
    /// runs; a client that renders to a terminal prints it after restoring the terminal, because
    /// the event queue's reader is gone by the time this resolves.
    pub(crate) task: tokio::task::JoinHandle<crate::workflow::ShutdownReport>,
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
pub(crate) fn attach(
    mut agent: Agent,
    interactive_approvals: bool,
    lossless_events: bool,
) -> Result<Attached, ProtocolVersionError> {
    let (handle, ends) = wire_with_policy(lossless_events)?;

    let interrupt = Arc::new(AtomicBool::new(false));
    agent.set_interrupt(interrupt.clone());
    let drain = Arc::new(AtomicBool::new(false));
    agent.set_drain(drain.clone());

    let facts = SessionFacts {
        workspace: agent.workspace.clone(),
        memory_workspace: agent.memory_workspace.clone(),
        memory_strategy: agent.memory_strategy(),
        rollout_path: agent.rollout.path().to_path_buf(),
        compaction_trigger_tokens: agent.compaction.trigger_tokens,
        initial_model_context_window: agent.model_context_window,
        bypass_permissions: agent.bypass_permissions,
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
        dependency_skill_dirs: agent.dependency_skill_dirs().to_vec(),
        agent_catalog: agent.agent_catalog_snapshot(),
    };
    let initial_state = snapshot_of(&mut agent);

    // The `Agent` moves in here and never comes back. "A run is in flight" becomes the server's
    // fact to report, not a slot a client can inspect.
    let task = tokio::spawn(AppServer::new(agent, ends, interactive_approvals).serve());

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
    next_seq: u64,
    lossless: bool,
}

impl EventPublisher {
    fn new(events: mpsc::Sender<EventEnvelope>, lossless: bool) -> Self {
        Self {
            events,
            dropped: 0,
            next_seq: 1,
            lossless,
        }
    }

    async fn send(&mut self, event: ServerEvent) -> Result<(), ()> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(())?;
        self.events
            .send(EventEnvelope {
                seq,
                protocol_version: PROTOCOL_VERSION,
                event,
            })
            .await
            .map_err(|_| ())
    }

    /// Publish one event, applying the bounded-queue policy.
    ///
    /// Authoritative events wait for room. Cosmetic deltas are dropped when there is none, and the
    /// count is flushed as a `Lagged` notice as soon as the queue drains — so the transcript says
    /// where it is incomplete instead of quietly being wrong.
    pub(crate) async fn publish(&mut self, event: ServerEvent) -> Result<(), ()> {
        let authoritative = event.is_authoritative();
        if !self.lossless && !authoritative && self.events.capacity() == 0 {
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
            self.send(ServerEvent::Lagged { dropped }).await?;
        }
        self.send(event).await
    }
}

/// Build the wire and hand back both ends.
///
/// The frontend gets [`AppServerHandle`]; the server side gets the SQ receiver and the EQ
/// publisher. Both sides are constructed here so the capacities and the negotiated version have a
/// single source.
pub(crate) struct ServerEnds {
    pub(crate) submissions: mpsc::Receiver<QueuedSubmission>,
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

#[cfg(test)]
pub(crate) fn wire() -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    wire_with_policy(false)
}

fn wire_with_policy(
    lossless_events: bool,
) -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    let (sq_tx, sq_rx) = mpsc::channel::<QueuedSubmission>(SQ_CAPACITY);
    let sq_budget = Arc::new(Semaphore::new(SQ_BYTE_CAPACITY));
    let (eq_tx, eq_rx) = mpsc::channel::<EventEnvelope>(EQ_CAPACITY);
    // The control plane is deliberately shallow: these are operator commands, one at a time, and a
    // backlog of them would mean the frontend is issuing config changes faster than a human can.
    let (control_tx, control_rx) = mpsc::channel::<ControlRequest>(8);
    let client = AppServerClient::connect_weighted(advertised_version(), sq_tx, sq_budget)?;
    Ok((
        AppServerHandle {
            client,
            events: eq_rx,
            control: control_tx,
        },
        ServerEnds {
            submissions: sq_rx,
            control: control_rx,
            events: EventPublisher::new(eq_tx, lossless_events),
        },
    ))
}

/// Where a submission goes once the server has classified it.
///
/// Split out so the routing is testable without a live `Agent`: the classification is the part that
/// decides whether an operation reaches the kernel at all, and it is the part an unknown `Op` must
/// not slip through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunInput {
    Text(String),
    Content(ContentSegments),
    /// One text prompt plus first-class file references, and optionally images beside them.
    /// Carried untouched from the operation so the kernel, not the router, decides admission.
    Files {
        text: String,
        images: Vec<core_protocol::ImageContent>,
        files: Vec<core_protocol::FileContent>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Routed {
    /// Start a turn. The server owns "is a run in flight", not the frontend.
    StartTurn(RunInput),
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
        Op::UserInput { text } => Routed::StartTurn(RunInput::Text(text.clone())),
        Op::UserInputV2 { segments } => Routed::StartTurn(RunInput::Content(segments.clone())),
        Op::UserInputV3 {
            text,
            images,
            files,
        } => Routed::StartTurn(RunInput::Files {
            text: text.clone(),
            images: images.clone(),
            files: files.clone(),
        }),
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
    submissions: mpsc::Receiver<QueuedSubmission>,
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
    pub(crate) fn new(mut agent: Agent, ends: ServerEnds, interactive_approvals: bool) -> Self {
        let (to_kernel, kernel_rx) = mpsc::unbounded_channel::<SqEnvelope>();
        if interactive_approvals {
            agent.set_approvals(kernel_rx);
        }
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
    ///
    /// # The workflow run owner
    ///
    /// [`crate::workflow::WorkflowSupervisor`] is installed here for exactly the same reason. A
    /// `Workflow` run could not outlive its turn because the only thing holding it was a local
    /// binding inside a method that borrows `&mut agent`; the supervisor is an `Arc` reachable from
    /// both sides of that borrow, so a detached run has an owner while the turn that started it
    /// returns. Its settled-run channel is selected on in BOTH loops below, which is what makes a
    /// background run finishing while the operator sits idle still reach the screen.
    ///
    /// Returns what the session did with the runs it still owned when it ended: by that point the
    /// EQ's reader is already gone (the session ends *because* the frontend hung up), so the client
    /// prints it after restoring the terminal rather than receiving it as an event.
    pub(crate) async fn serve(self) -> crate::workflow::ShutdownReport {
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

        // The workflow-script progress seam, unbounded for the same reason: `ProgressSink::emit` is
        // called from the engine's single JS-driver thread and must not block. Installing it here
        // is what makes a `Workflow` tool call render a live tree instead of a silent minutes-long
        // turn; the one-shot `--output-format` paths install no such sink and are unaffected.
        let (workflow_tx, mut workflow_rx) =
            mpsc::unbounded_channel::<crate::workflow::WorkflowRunUiEvent>();
        agent.set_workflow_progress(workflow_tx);

        // The session-scoped owner for `Workflow({background: true})` runs. Installed OUTSIDE the
        // turn's borrow — that placement is the whole point, not an implementation detail: it is
        // what lets a run be held while the turn that started it returns. Its channel is unbounded
        // for the same reason the two above are: a reaper task must never block on the frontend.
        let (settled_tx, mut settled_rx) = mpsc::unbounded_channel::<crate::workflow::RunSettled>();
        let workflows = crate::workflow::WorkflowSupervisor::new(settled_tx);
        agent.set_workflow_launcher(workflows.clone());
        // Clone the job control port before a turn borrows `&mut agent`. It owns no second job
        // table: every operation reaches the supervisor captured by this registry's process tools.
        let processes = agent.registry.process_control();

        // `run` versus `follow_up` was a caller-side boolean the frontend chose. With a resident
        // runtime it is session state and belongs here: the first admitted turn starts the session,
        // every later one continues it.
        let mut started = false;

        // The operator's side conversation, if they have opened one. It is server state for the
        // same reason the `Agent` is: it owns a live runtime with an open journal.
        let mut side: Option<crate::runtime::SideConversation> = None;
        let mut pending_runtime = std::collections::VecDeque::<String>::new();

        enum TurnTrigger {
            Submission(QueuedSubmission),
            Runtime(String),
        }

        loop {
            let trigger = if let Some(notification) = pending_runtime.pop_front() {
                TurnTrigger::Runtime(notification)
            } else {
                tokio::select! {
                    request = control.recv() => {
                        match request {
                            Some(request) => { apply_control(&mut agent, &workflows, processes.as_ref(), &mut side, &mut started, &mut events, request).await; continue }
                            None => break,
                        }
                    }
                    // A detached run keeps emitting between turns. Without this arm its tree froze on
                    // the frame the turn ended on and only resumed when the operator typed again —
                    // "the run is invisible while it is the only thing happening", which is precisely
                    // the state detaching would otherwise create.
                    Some(progress) = workflow_rx.recv() => {
                        let _ = events.publish(ServerEvent::WorkflowRun(progress)).await;
                        continue
                    }
                    Some(settled) = settled_rx.recv() => {
                        TurnTrigger::Runtime(publish_settled(&mut events, settled).await)
                    }
                    queued = submissions.recv() => {
                        match queued { Some(queued) => TurnTrigger::Submission(queued), None => break }
                    }
                }
            };
            let (input, runtime_follow_up) = match trigger {
                TurnTrigger::Runtime(notification) => (RunInput::Text(notification), true),
                TurnTrigger::Submission(queued) => {
                    let envelope = queued.into_envelope();
                    let version = envelope.protocol_version;
                    let Ok(op) = envelope.into_current() else {
                        let _ = events.publish(ServerEvent::Notice(format!(
                            "a submission arrived stamped protocol v{version}; this runtime speaks v{PROTOCOL_VERSION} and discarded it"
                        ))).await;
                        continue;
                    };
                    match route(&op) {
                        Routed::Refuse(why) => {
                            let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                            continue;
                        }
                        Routed::ToKernel => {
                            if to_kernel
                                .send(SqEnvelope::with_version(version, op))
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        Routed::StartTurn(input) => (input, false),
                    }
                }
            };
            // Control requests that arrive mid-turn wait here; see the `select!` arm below.
            let mut deferred: Vec<ControlRequest> = Vec::new();
            let completion = {
                let running = async {
                    if runtime_follow_up {
                        match &input {
                            RunInput::Text(notification) => {
                                agent.follow_up_runtime_notification(notification).await
                            }
                            _ => unreachable!("runtime notifications are text"),
                        }
                    } else {
                        match (&input, started) {
                            (RunInput::Text(task), false) => agent.run(task).await,
                            (RunInput::Text(task), true) => agent.follow_up(task).await,
                            (RunInput::Content(segments), false) => {
                                agent.run_content(segments).await
                            }
                            (RunInput::Content(segments), true) => {
                                agent.follow_up_content(segments).await
                            }
                            (
                                RunInput::Files {
                                    text,
                                    images,
                                    files,
                                },
                                false,
                            ) => agent.run_files(text, images, files).await,
                            (
                                RunInput::Files {
                                    text,
                                    images,
                                    files,
                                },
                                true,
                            ) => agent.follow_up_files(text, images, files).await,
                        }
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
                        Some(progress) = workflow_rx.recv() => {
                            // Same policy as the UI stream: a frontend that hung up never
                            // aborts a run that is already executing.
                            let _ = events.publish(ServerEvent::WorkflowRun(progress)).await;
                        }
                        Some(settled) = settled_rx.recv() => {
                            // A run detached by an EARLIER turn can settle during this one.
                            // Its terminal row belongs in the transcript at the moment it
                            // happened, not at the end of whatever turn is running.
                            let notification = publish_settled(&mut events, settled).await;
                            let _ = to_kernel.send(SqEnvelope::current(Op::Steer { text: notification }));
                        }
                        Some(request) = control.recv() => {
                            if is_immediate_control(&request.control) {
                                apply_immediate_control(&workflows, processes.as_ref(), request).await;
                                continue;
                            }
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
                        Some(queued) = submissions.recv() => {
                            let envelope = queued.into_envelope();
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
            // The workflow seam drains with it: an in-turn run settles inside the turn, so
            // its terminal rows and its `Finished` are queued here exactly like the last
            // text deltas, and a tail that skipped them would leave the tree spinning.
            while let Ok(progress) = workflow_rx.try_recv() {
                let _ = events.publish(ServerEvent::WorkflowRun(progress)).await;
            }
            while let Ok(settled) = settled_rx.try_recv() {
                pending_runtime.push_back(publish_settled(&mut events, settled).await);
            }

            // The turn's borrow has ended, so the deferred control plane can run — in
            // arrival order, before the snapshot, so the state the frontend receives
            // already reflects everything it asked for during the turn.
            for request in deferred {
                apply_control(
                    &mut agent,
                    &workflows,
                    processes.as_ref(),
                    &mut side,
                    &mut started,
                    &mut events,
                    request,
                )
                .await;
            }

            let mut snapshot = snapshot_of(&mut agent);
            snapshot.unadmitted_steers.retain(|text| {
                if text.starts_with(crate::runtime::RUNTIME_NOTIFICATION_PREFIX) {
                    pending_runtime.push_back(text.clone());
                    false
                } else {
                    true
                }
            });
            let (outcome, error) = match completion {
                Ok(outcome) => (outcome, None),
                Err(error) => {
                    let error = error.public_summary();
                    (Outcome::HarnessError, Some(error))
                }
            };
            let (memo_hits, memo_misses) = agent.registry.memo_stats();
            let kernel_tax = agent
                .ledger
                .kernel_tax()
                .with_failed_run(!matches!(outcome, Outcome::Done | Outcome::Drained));
            let summary = TerminalSummary {
                outcome,
                assistant_text: agent.last_assistant_text().to_owned(),
                run_id: agent.rollout.run_id().to_string(),
                cost: agent.ledger.cost_state(),
                turns: agent.ledger.turns,
                kernel_tax,
                error,
                memo_hits,
                memo_misses,
            };
            if events
                .publish(ServerEvent::RunEnded {
                    snapshot: Box::new(snapshot),
                    summary: Box::new(summary),
                })
                .await
                .is_err()
            {
                break;
            }
        }

        // SESSION EXIT WITH A RUN STILL LIVE.
        //
        // The three candidate policies were: refuse to exit, kill, or let it finish alone. The
        // third is not available and saying otherwise would be a lie — a workflow run is an OS
        // thread inside THIS process, so "detached" has never meant "survives the process". The
        // first turns one wedged script into an unquittable session. So: cancel, wait a bounded
        // grace for the engine's own safe point, and write the terminal record either way, so no
        // run is left listing as `running` forever. The operator is told twice — the receipt the
        // model got stated this exact rule up front, and the report below names every run that was
        // stopped together with the `core workflow resume` that continues it.
        //
        // This runs on EVERY exit from the loop above, which is what makes "the session cannot end
        // with a run it does not account for" a property of the type rather than of a call site.
        workflows
            .shutdown(&mut settled_rx, crate::workflow::SHUTDOWN_GRACE)
            .await
    }
}

/// Publish one settled background run: settle its card, then say what happened.
///
/// Both events, always. The card settles on every terminal state for the same reason the in-turn
/// path settles it on both exits — a run whose tree spins forever is a transcript that is wrong —
/// and the notice is the operator's copy of an outcome that otherwise only the model can read.
async fn publish_settled(
    events: &mut EventPublisher,
    settled: crate::workflow::RunSettled,
) -> String {
    let run_id = settled.run_id.clone();
    let notification = format!(
        "{}\n{}",
        crate::runtime::RUNTIME_NOTIFICATION_PREFIX,
        settled.notification,
    );
    let _ = events
        .publish(ServerEvent::WorkflowRun(
            crate::workflow::WorkflowRunUiEvent::Finished { run_id },
        ))
        .await;
    let _ = events.publish(ServerEvent::Notice(settled.notice)).await;
    notification
}

/// The heaviest admissible submission still fits the queue.
///
/// Admission caps text plus framed files at `MAX_TASK_TEXT_BYTES`, which is exactly what the
/// capacity reserves. A `const` assertion rather than a runtime one: every term is a compile-time
/// constant, so `assert!` over them is optimised out and would pass even if the relation broke.
const _: () = assert!(
    SQ_ENTRY_OVERHEAD_BYTES
        + core_protocol::task::MAX_TASK_TEXT_BYTES
        + core_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
        <= SQ_BYTE_CAPACITY
);

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(op: Op) -> SqEnvelope {
        SqEnvelope::with_version(PROTOCOL_VERSION, op)
    }

    #[tokio::test]
    async fn a_settled_background_run_returns_one_task_notification_without_polling() {
        let (eq_tx, mut eq_rx) = mpsc::channel(4);
        let mut events = EventPublisher::new(eq_tx, true);
        let notification = publish_settled(
            &mut events,
            crate::workflow::RunSettled {
                run_id: "wf_done".into(),
                notice: "workflow `wf_done` finished".into(),
                notification: "<task-notification>done</task-notification>".into(),
            },
        )
        .await;

        assert!(notification.starts_with(crate::runtime::RUNTIME_NOTIFICATION_PREFIX));
        assert!(notification.contains("<task-notification>done</task-notification>"));

        assert!(matches!(
            eq_rx.recv().await.unwrap().into_current().unwrap(),
            ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Finished { run_id })
                if run_id == "wf_done"
        ));
        assert!(matches!(
            eq_rx.recv().await.unwrap().into_current().unwrap(),
            ServerEvent::Notice(notice) if notice.contains("finished")
        ));
    }

    #[test]
    fn only_a_workflow_activity_tick_is_droppable_under_backpressure() {
        use core_workflow::events::{ProgressEvent, WorkflowState};
        let progress = |event| {
            ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Progress {
                run_id: "wf_1".into(),
                event,
            })
        };

        // A tick only restates a running row's climbing counters: missing one shows a stale line.
        assert!(
            !progress(ProgressEvent::AgentActivity {
                index: 0,
                tokens: 10,
                tool_calls: 1,
                last_tool_summary: None,
            })
            .is_authoritative()
        );

        // Everything else changes what the operator believes happened. A dropped `AgentFinished`
        // in particular would leave the row spinning as `Running` for the rest of the session.
        for authoritative in [
            progress(ProgressEvent::AgentFinished {
                index: 0,
                label: "row".into(),
                state: WorkflowState::Done,
                tokens: 10,
                tool_calls: 1,
                duration_ms: 5,
                result_preview: None,
                last_tool_summary: None,
                error: None,
            }),
            progress(ProgressEvent::Log {
                message: "narrating".into(),
            }),
            progress(ProgressEvent::Phase {
                index: 1,
                title: "Explore".into(),
            }),
            progress(ProgressEvent::AgentQueued {
                index: 1,
                label: "queued".into(),
                phase: None,
                model: None,
            }),
            progress(ProgressEvent::AgentStarted {
                index: 1,
                label: "queued".into(),
                phase: None,
                model: None,
            }),
            ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Started {
                run_id: "wf_1".into(),
                name: "audit".into(),
                phases: Vec::new(),
            }),
            ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Finished {
                run_id: "wf_1".into(),
            }),
        ] {
            assert!(
                authoritative.is_authoritative(),
                "{authoritative:?} must wait for room rather than vanish"
            );
        }
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
            rate_limit: None,
        })
    }

    fn terminal_summary() -> Box<TerminalSummary> {
        Box::new(TerminalSummary {
            outcome: Outcome::HarnessError,
            assistant_text: String::new(),
            run_id: "test-run".into(),
            cost: core_obs::CostState::Zero,
            turns: 0,
            kernel_tax: core_obs::KernelTax::default(),
            error: Some("done".into()),
            memo_hits: 0,
            memo_misses: 0,
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
    fn parity_transcript_done_capture_matches_terminal_summary_projection() {
        let summary = TerminalSummary {
            outcome: Outcome::Done,
            assistant_text: "parity reply".into(),
            run_id: "run-client-parity".into(),
            cost: core_obs::CostState::default(),
            turns: 1,
            kernel_tax: core_obs::KernelTax::default(),
            error: None,
            memo_hits: 0,
            memo_misses: 0,
        };
        let authoritative = summary.result_v5();
        let transcript: serde_json::Value = serde_json::from_str(include_str!(
            "../../../governance/client-conformance/client-parity-v5.json"
        ))
        .unwrap();
        let captures = transcript["clients"].as_array().unwrap();
        assert_eq!(captures.len(), 3);
        for capture in captures {
            assert_eq!(
                capture["result"], authoritative,
                "{} changed terminal authority rather than presentation",
                capture["client"]
            );
        }
        assert_eq!(authoritative["outcome"], "done");
        assert_eq!(authoritative["exit_code"], 0);
        assert_eq!(authoritative["type"], "result");
        assert_eq!(authoritative["schema_version"], 5);
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
        let (tx, _rx) = mpsc::channel::<QueuedSubmission>(SQ_CAPACITY);
        let client = AppServerClient::connect_weighted(
            PROTOCOL_VERSION,
            tx,
            Arc::new(Semaphore::new(SQ_BYTE_CAPACITY)),
        )
        .expect("handshake");
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

    #[test]
    fn sq_weight_counts_actual_text_and_encoded_image_bytes() {
        let segments = core_protocol::ContentSegments::new(vec![
            core_protocol::ContentSegment::Text {
                text: "describe".into(),
            },
            core_protocol::ContentSegment::Image {
                image: core_protocol::ImageContent::new(
                    core_protocol::ImageMediaType::Png,
                    "iVBORw0KGgo=",
                )
                .unwrap(),
            },
        ])
        .unwrap();
        let op = Op::UserInputV2 { segments };
        assert_eq!(
            submission_weight(&op),
            SQ_ENTRY_OVERHEAD_BYTES + "describe".len() + "iVBORw0KGgo=".len()
        );
        assert_eq!(
            SQ_BYTE_CAPACITY,
            SQ_ENTRY_OVERHEAD_BYTES
                + core_protocol::task::MAX_TASK_TEXT_BYTES
                + core_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
                + SQ_CONTROL_RESERVE_BYTES
        );
        assert!(
            SQ_BYTE_CAPACITY <= u32::MAX as usize,
            "tokio's weighted semaphore acquisition accepts a u32 permit count"
        );

        // File chips are charged the same way, path included, so a queue full of them is bounded
        // in bytes and not merely in entries.
        let file = core_protocol::FileContent::new("src/main.rs", "fn main() {}").unwrap();
        let with_files = Op::UserInputV3 {
            text: "review".into(),
            images: vec![
                core_protocol::ImageContent::new(
                    core_protocol::ImageMediaType::Png,
                    "iVBORw0KGgo=",
                )
                .unwrap(),
            ],
            files: vec![file.clone()],
        };
        assert_eq!(
            submission_weight(&with_files),
            SQ_ENTRY_OVERHEAD_BYTES
                + "review".len()
                + "iVBORw0KGgo=".len()
                + file.path.len()
                + file.text.len()
        );
    }

    #[test]
    fn sq_byte_budget_refuses_a_second_large_item_and_releases_on_dequeue() {
        let op = Op::UserInput {
            text: "x".repeat(4096),
        };
        let weight = submission_weight(&op);
        let budget = Arc::new(Semaphore::new(weight));
        let (tx, mut rx) = mpsc::channel::<QueuedSubmission>(4);
        let client =
            AppServerClient::connect_weighted(PROTOCOL_VERSION, tx, budget.clone()).unwrap();

        client
            .submit(op.clone())
            .expect("first item consumes budget");
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(
            client.submit(op.clone()),
            Err(SubmitError::Busy),
            "the byte bound, not the four-item channel bound, refuses the second item"
        );

        let queued = rx.try_recv().expect("first item is queued");
        let envelope = queued.into_envelope();
        assert_eq!(
            budget.available_permits(),
            weight,
            "dequeue releases the queue's memory charge"
        );
        assert!(matches!(envelope.op, Op::UserInput { .. }));

        client
            .submit(op)
            .expect("released byte permits admit a later item");
    }

    #[tokio::test]
    async fn a_saturated_eq_drops_only_cosmetic_deltas_and_never_the_terminal_event() {
        // The acceptance criterion: 0 authoritative drops. A reader that never reads must still be
        // able to learn how the run ended once it starts reading.
        let (tx, mut rx) = mpsc::channel::<EventEnvelope>(8);
        let mut publisher = EventPublisher::new(tx, false);
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
                    snapshot: snapshot(),
                    summary: terminal_summary(),
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
                ServerEvent::Ui(_) | ServerEvent::Notice(_) | ServerEvent::WorkflowRun(_) => {}
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
        let mut publisher = EventPublisher::new(tx, false);

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
                    snapshot: snapshot(),
                    summary: terminal_summary(),
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
        let mut last_seq = 0;
        while let Some(envelope) = rx.recv().await {
            // A reader slow enough that the queue stays saturated for the whole flood.
            tokio::task::yield_now().await;
            assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
            assert_eq!(
                envelope.seq,
                last_seq + 1,
                "live EQ cursors must be contiguous and never duplicate"
            );
            last_seq = envelope.seq;
            match envelope.event {
                ServerEvent::Notice(text) => seen.push(text),
                ServerEvent::Ui(_) | ServerEvent::WorkflowRun(_) => deltas += 1,
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

    #[tokio::test]
    async fn a_lossless_client_backpressures_instead_of_dropping_cosmetic_events() {
        let (tx, mut rx) = mpsc::channel::<EventEnvelope>(1);
        let mut publisher = EventPublisher::new(tx, true);
        let publish = tokio::spawn(async move {
            publisher
                .publish(ServerEvent::Ui(UiEvent::Text("first".into())))
                .await
                .unwrap();
            publisher
                .publish(ServerEvent::Ui(UiEvent::Text("second".into())))
                .await
                .unwrap();
        });

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        publish.await.unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
        assert!(matches!(
            first.event,
            ServerEvent::Ui(UiEvent::Text(ref text)) if text == "first"
        ));
        assert!(matches!(
            second.event,
            ServerEvent::Ui(UiEvent::Text(ref text)) if text == "second"
        ));
        assert!(
            rx.try_recv().is_err(),
            "lossless delivery must not synthesize a lag notice"
        );
    }

    #[test]
    fn an_event_from_a_newer_server_is_refused_at_the_point_of_use() {
        // The connect-time handshake covers the session's start. The version travels with each
        // event so a server that begins emitting a newer shape mid-session is caught too, rather
        // than being rendered as if it were the shape this build knows.
        let envelope = EventEnvelope {
            seq: 1,
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
            seq: 1,
            protocol_version: PROTOCOL_VERSION,
            event: ServerEvent::Notice("now".into()),
        };
        assert!(matches!(current.into_current(), Ok(ServerEvent::Notice(_))));
    }

    #[test]
    fn every_op_is_classified_and_an_unknown_one_is_refused() {
        assert_eq!(
            route(&Op::UserInput { text: "hi".into() }),
            Routed::StartTurn(RunInput::Text("hi".into()))
        );
        let multimodal = core_protocol::ContentSegments::new(vec![
            core_protocol::ContentSegment::Text {
                text: "describe".into(),
            },
            core_protocol::ContentSegment::Image {
                image: core_protocol::ImageContent::new(
                    core_protocol::ImageMediaType::Png,
                    "iVBORw0KGgo=",
                )
                .unwrap(),
            },
        ])
        .unwrap();
        assert_eq!(
            route(&Op::UserInputV2 {
                segments: multimodal.clone(),
            }),
            Routed::StartTurn(RunInput::Content(multimodal))
        );
        let files = vec![core_protocol::FileContent::new("src/main.rs", "fn main() {}").unwrap()];
        assert_eq!(
            route(&Op::UserInputV3 {
                text: "review".into(),
                images: Vec::new(),
                files: files.clone(),
            }),
            Routed::StartTurn(RunInput::Files {
                text: "review".into(),
                images: Vec::new(),
                files,
            }),
            "a file submission starts a turn; it is not steering and not a control op"
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

    /// A minimal provider so the control-plane test can own a real `Agent` without a network.
    #[derive(Default)]
    struct StubProvider;

    #[async_trait::async_trait]
    impl core_provider::Provider for StubProvider {
        async fn turn(
            &self,
            _request: &core_provider::TurnRequest,
            _on_item: &mut (dyn FnMut(core_provider::StreamItem) + Send),
        ) -> Result<core_provider::TurnResult, core_provider::ProviderError> {
            Ok(core_provider::TurnResult {
                blocks: vec![core_protocol::Block::Text {
                    text: "side reply".into(),
                }],
                stop_reason: core_protocol::StopReason::EndTurn,
                usage: core_provider::UsageReport::complete(core_protocol::Usage::default()),
            })
        }
    }

    #[derive(Default)]
    struct BackgroundPlanningProvider {
        planner_started: tokio::sync::Notify,
        release_planner: tokio::sync::Notify,
        planner_released: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl core_provider::Provider for BackgroundPlanningProvider {
        fn provider_instance_id(&self) -> Option<&str> {
            Some("provider-a")
        }

        async fn turn(
            &self,
            request: &core_provider::TurnRequest,
            _on_item: &mut (dyn FnMut(core_provider::StreamItem) + Send),
        ) -> Result<core_provider::TurnResult, core_provider::ProviderError> {
            let text = if request.system.starts_with("You plan a READ-ONLY") {
                self.planner_started.notify_one();
                self.release_planner.notified().await;
                self.planner_released
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                "Inspect workflow ownership and completion events"
            } else if request.system.contains("read-only investigation subagent") {
                "Finding: the supervisor owns the detached engine run."
            } else {
                "The main thread is available while the background investigation continues."
            };
            Ok(core_provider::TurnResult {
                blocks: vec![core_protocol::Block::Text { text: text.into() }],
                stop_reason: core_protocol::StopReason::EndTurn,
                usage: core_provider::UsageReport::complete(core_protocol::Usage::default()),
            })
        }
    }

    fn agent_in(workspace: &std::path::Path) -> Agent {
        let rollout = core_record::Rollout::open(
            &workspace.join(".core/runs"),
            &core_protocol::RunId("control-plane".into()),
            core_protocol::TenantId::default(),
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(StubProvider),
            core_tools::Registry::coding_agent(workspace).unwrap(),
            rollout,
            "m".into(),
            "system".into(),
            core_protocol::Budget {
                max_turns: 4,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: 30,
                max_consecutive_tool_errors: 3,
            },
        );
        agent.workspace = workspace.to_path_buf();
        agent
    }

    fn temp_workspace(tag: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "core-side-control-{tag}-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// UX-3 control plane: the side conversation is SERVER state. Every request answers, an
    /// unopened conversation says so instead of inventing zeroes, and the conversation survives
    /// between control requests so a second ask continues the first.
    #[tokio::test]
    async fn the_side_conversation_is_server_state_that_survives_between_control_requests() {
        let workspace = temp_workspace("survives");
        let mut agent = agent_in(&workspace);
        let mut side: Option<crate::runtime::SideConversation> = None;

        // Nothing is open, and nothing is invented.
        match apply_side(&mut agent, &mut side, SideRequest::Status).await {
            ControlReply::SideStatus { status, closed } => {
                assert!(
                    status.is_none(),
                    "an unopened side conversation has no books"
                );
                assert!(!closed);
            }
            other => panic!("unexpected reply: {other:?}"),
        }
        assert!(side.is_none(), "asking for status must not open one");

        let first = match apply_side(
            &mut agent,
            &mut side,
            SideRequest::Ask("first question".into()),
        )
        .await
        {
            ControlReply::SideAnswer(answer) => *answer,
            other => panic!("unexpected reply: {other:?}"),
        };
        assert_eq!(first.status.asks, 1);
        assert!(side.is_some(), "the first ask opens the conversation");

        let second = match apply_side(
            &mut agent,
            &mut side,
            SideRequest::Ask("second question".into()),
        )
        .await
        {
            ControlReply::SideAnswer(answer) => *answer,
            other => panic!("unexpected reply: {other:?}"),
        };
        assert_eq!(
            second.status.run_id, first.status.run_id,
            "a second ask continues the SAME side conversation, not a new one"
        );
        assert_eq!(second.status.asks, 2);

        // Closing reports the books it is closing, then really is closed.
        match apply_side(&mut agent, &mut side, SideRequest::Close).await {
            ControlReply::SideStatus { status, closed } => {
                assert!(closed);
                let status = status.expect("closing an open conversation reports its books");
                assert_eq!(status.run_id, first.status.run_id);
                assert_eq!(status.asks, 2);
            }
            other => panic!("unexpected reply: {other:?}"),
        }
        assert!(side.is_none());

        // The session itself never ran a turn because of any of this.
        assert_eq!(
            agent.ledger.turns, 0,
            "side conversation traffic is not the session's traffic"
        );

        drop(agent);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[tokio::test]
    async fn closing_a_side_conversation_that_was_never_opened_is_answered_not_ignored() {
        let workspace = temp_workspace("close-none");
        let mut agent = agent_in(&workspace);
        let mut side: Option<crate::runtime::SideConversation> = None;
        match apply_side(&mut agent, &mut side, SideRequest::Close).await {
            ControlReply::SideStatus { status, closed } => {
                assert!(status.is_none());
                assert!(closed, "the operator asked to close; the answer says so");
            }
            other => panic!("unexpected reply: {other:?}"),
        }
        drop(agent);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[tokio::test]
    async fn workflow_inventory_and_kill_bypass_the_agent_borrow_but_resume_does_not() {
        assert!(is_immediate_control(&Control::Workflow(
            WorkflowControl::Inventory
        )));
        assert!(is_immediate_control(&Control::Workflow(
            WorkflowControl::Cancel {
                run_id: "wf-live".into()
            }
        )));
        assert!(!is_immediate_control(&Control::Workflow(
            WorkflowControl::Resume {
                run_id: "wf-stopped".into()
            }
        )));
        assert!(is_immediate_control(&Control::Job(JobControl::Inventory)));

        let (settled_tx, _settled_rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = crate::workflow::WorkflowSupervisor::new(settled_tx);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        apply_immediate_workflow_control(
            &owner,
            ControlRequest {
                control: Control::Workflow(WorkflowControl::Inventory),
                reply: reply_tx,
            },
        );
        let ControlReply::Workflows(reply) = reply_rx.await.expect("every control answers") else {
            panic!("inventory has a typed workflow reply")
        };
        assert!(reply.runs.is_empty());
        assert!(reply.notice.is_none());
    }

    #[tokio::test]
    async fn panel_resume_launches_the_persisted_run_and_orders_started_before_finished() {
        let workspace = temp_workspace("workflow-panel-resume");
        let mut agent = agent_in(&workspace);
        agent
            .record_model_selection(
                "provider-a".into(),
                "m".into(),
                String::new(),
                String::new(),
            )
            .unwrap();
        let workflows_dir = workspace.join(".core/runs/subagents/workflows");
        let run_id = "wf-panel-resume";
        let script =
            "export const meta = { name: 'panel resume', phases: ['restore'] }; return 42;";
        crate::workflow::persist_inputs(
            &workflows_dir,
            &crate::workflow::RunManifest {
                run_id: run_id.into(),
                name: "panel resume".into(),
                args: serde_json::Value::Null,
                provider_id: "provider-a".into(),
                model: "m".into(),
                created_at: 1,
            },
            script,
        )
        .unwrap();

        let Attached {
            handle,
            task,
            facts: _,
            initial_state: _,
            interrupt: _,
            drain: _,
        } = attach(agent, true, true).unwrap();
        let AppServerHandle {
            client,
            mut events,
            control,
        } = handle;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        control
            .send(ControlRequest {
                control: Control::Workflow(WorkflowControl::Resume {
                    run_id: run_id.into(),
                }),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let ControlReply::Workflows(reply) = reply_rx.await.unwrap() else {
            panic!("resume answers through the typed workflow surface")
        };
        assert!(
            reply
                .notice
                .as_deref()
                .is_some_and(|notice| notice.contains("resumed workflow"))
        );

        let mut lifecycle = Vec::new();
        while lifecycle.last().copied() != Some("finished") {
            let envelope = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv())
                .await
                .expect("the resumed run settles")
                .expect("the event channel stays open");
            match envelope.into_current().unwrap() {
                ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Started {
                    run_id: id,
                    ..
                }) if id == run_id => lifecycle.push("started"),
                ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Finished {
                    run_id: id,
                }) if id == run_id => lifecycle.push("finished"),
                _ => {}
            }
        }
        assert_eq!(lifecycle, vec!["started", "finished"]);
        assert_eq!(
            crate::workflow::load_result(&workflows_dir, run_id)
                .expect("the supervisor persists the resumed result")
                .value,
            serde_json::json!(42)
        );

        drop(control);
        drop(client);
        drop(events);
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("the server stops after its clients close")
            .unwrap();
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[tokio::test]
    async fn ultracode_planning_renders_in_one_detached_run_while_the_main_thread_returns() {
        let workspace = temp_workspace("ultracode-detached-planning");
        let rollout = core_record::Rollout::open(
            &workspace.join(".core/runs"),
            &core_protocol::RunId("ultracode-detached".into()),
            core_protocol::TenantId::default(),
        )
        .unwrap();
        let provider = Arc::new(BackgroundPlanningProvider::default());
        let mut agent = Agent::new(
            provider.clone(),
            core_tools::Registry::coding_agent(&workspace).unwrap(),
            rollout,
            "model-a".into(),
            "system".into(),
            core_protocol::Budget {
                max_turns: 20,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: 30,
                max_consecutive_tool_errors: 3,
            },
        );
        agent.workspace = workspace.clone();
        agent
            .configure_initial_runtime_policy(
                core_protocol::Effort::Ultracode,
                core_protocol::PermissionMode::default(),
                core_protocol::PermissionRules::new(),
            )
            .unwrap();
        agent
            .record_model_selection(
                "provider-a".into(),
                "model-a".into(),
                String::new(),
                String::new(),
            )
            .unwrap();

        let Attached {
            handle,
            task,
            facts: _,
            initial_state: _,
            interrupt: _,
            drain: _,
        } = attach(agent, true, true).unwrap();
        let AppServerHandle {
            client,
            mut events,
            control,
        } = handle;
        client
            .submit(Op::UserInput {
                text: "audit workflow ownership across every module".into(),
            })
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            provider.planner_started.notified(),
        )
        .await
        .expect("the workflow planning child starts");

        let mut declared_planning = false;
        let mut rendered_planner = false;
        loop {
            let event = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv())
                .await
                .expect("the main turn returns while planning is parked")
                .expect("the event stream stays open")
                .into_current()
                .unwrap();
            match event {
                ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Started {
                    phases,
                    ..
                }) => declared_planning |= phases.iter().any(|phase| phase == "planning"),
                ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Progress {
                    event:
                        core_workflow::ProgressEvent::AgentStarted {
                            phase: Some(phase), ..
                        },
                    ..
                }) if phase == "planning" => rendered_planner = true,
                ServerEvent::RunEnded { .. } => break,
                _ => {}
            }
        }
        assert!(
            declared_planning,
            "planning exists on the first workflow frame"
        );
        assert!(
            rendered_planner,
            "the planning agent is a live rendered row"
        );
        assert!(
            !provider
                .planner_released
                .load(std::sync::atomic::Ordering::SeqCst),
            "the main writer returns to idle without waiting for planning"
        );

        provider.release_planner.notify_one();
        let mut workflow_finished = false;
        let mut notification_turn_finished = false;
        loop {
            let event = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv())
                .await
                .expect("the detached run settles after planning is released")
                .expect("the event stream stays open")
                .into_current()
                .unwrap();
            match event {
                ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Finished {
                    ..
                }) => {
                    workflow_finished = true;
                }
                ServerEvent::RunEnded { summary, .. } if workflow_finished => {
                    assert!(
                        summary.assistant_text.contains("main thread is available"),
                        "the idle main thread consumes the task notification"
                    );
                    notification_turn_finished = true;
                }
                _ => {}
            }
            if workflow_finished && notification_turn_finished {
                break;
            }
        }

        drop(control);
        drop(client);
        drop(events);
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("the server stops after its clients close")
            .unwrap();
        let _ = std::fs::remove_dir_all(&workspace);
    }
}

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
//! # Why the EQ does not carry `iteron_protocol::Event`
//!
//! This is the one design decision in this module that is not obvious, so it is recorded rather
//! than left to be rediscovered.
//!
//! `iteron_protocol::EqEnvelope` carries `iteron_protocol::Event`, and translating the kernel's
//! [`UiEvent`] into `EventKind` is **lossy in four places the frontend actually renders**:
//!
//! - `UiEvent::TurnEnd` carries seven fields; `EventKind::TurnEnd` carries one (`usage`). The cost
//!   state, context estimate, model window, reserved output tokens, compaction trigger and effort
//!   application have no durable counterpart — and the status bar renders all of them.
//! - `UiEvent::SteerApplied { count }` has no `EventKind` counterpart at all.
//! - `UiEvent::ToolEnd.diff` has no `EventKind` home; the durable record is deliberately terse.
//! - `UiEvent::ApprovalRequest.reason` — the operator-facing justification — has no field to go in.
//!
//! Closing those would mean adding variants and fields to `iteron_protocol`, and this issue's
//! acceptance criteria forbid changing the frozen wire types: WS1 owns them, this lane only
//! consumes them. Carrying `UiEvent` in a versioned envelope of our own satisfies both — the wire
//! is version-negotiated in both directions, and no frozen type moves.
//!
//! The SQ is different: it carries `iteron_protocol::SqEnvelope` unchanged, because `Op` expresses
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

#[path = "app_server/backpressure.rs"]
mod backpressure;
mod control;
mod mcp_control;
mod operator_status;

pub(crate) use backpressure::{AppServerQueuePolicy, AuthoritativeOverflow, CosmeticOverflow};

use self::control::{apply_control, apply_immediate_control, is_immediate_control, snapshot_of};
#[cfg(test)]
use self::control::{apply_immediate_workflow_control, apply_side};
use self::mcp_control::apply_mcp_control;
use self::operator_status::OperatorStatusSources;
pub(crate) use self::operator_status::{
    LanguageServerStatus, OperatorStatusSnapshot, WorkflowHealth,
};
use crate::runtime::{Agent, UiEvent};
use iteron_protocol::{
    Capability, ContentSegments, LifecyclePayload, LifecycleState, Op, Outcome, PROTOCOL_VERSION,
    ProtocolVersionError, RunId, RunLifecycleState, SessionId, SessionLifecycleState, SqEnvelope,
    SubmissionId, SubmissionLifecycleState, TurnId, TurnLifecycleState,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// Submission-queue depth.
///
/// Sized for the burst a human can produce with a held key or a paste, not for a backlog: past this
/// the honest answer is "busy", not a longer queue.
pub(crate) const SQ_CAPACITY: usize = 256;

/// Entries reserved for in-turn control. A paste or a burst of future turns may consume every
/// data slot, but can never prevent an interrupt, force-cancel, drain, steer, or approval receipt
/// from reaching the resident actor.
const SQ_PRIORITY_CAPACITY: usize = 16;
#[cfg(test)]
const SQ_DATA_CAPACITY: usize = SQ_CAPACITY - SQ_PRIORITY_CAPACITY;

/// Conservative heap charge for the envelope, enum/segment storage, channel node and allocator
/// bookkeeping of one submission, before counting its variable-length strings.
///
/// Small control operations use only this charge. Keeping a full queue's worth in reserve means
/// the byte budget never reduces the existing 256-item control burst bound.
const SQ_ENTRY_OVERHEAD_BYTES: usize = 1024;

/// Bytes reserved for a full [`SQ_CAPACITY`] burst of small control operations.
const SQ_CONTROL_RESERVE_BYTES: usize = SQ_CAPACITY * SQ_ENTRY_OVERHEAD_BYTES;

fn sq_control_reserve_bytes() -> usize {
    iteron_tunables::param_integer(
        "cli.app_server.sq_control_reserve_bytes",
        SQ_CONTROL_RESERVE_BYTES,
    )
}

/// Total heap budget for submissions waiting on the in-process SQ.
///
/// This admits one maximum legal multimodal submission (1 MiB text plus 32 MiB of encoded image
/// data), with a full control-queue reserve beside it. The item bound still applies, so a maximum
/// payload plus controls can occupy at most 256 queue slots. Charging the actual text and encoded
/// image lengths prevents 256 maximum payloads from multiplying into a multi-GiB queue.
pub(crate) const SQ_BYTE_CAPACITY: usize = SQ_ENTRY_OVERHEAD_BYTES
    + iteron_protocol::task::MAX_TASK_TEXT_BYTES
    + iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
    + SQ_CONTROL_RESERVE_BYTES;

fn sq_byte_capacity() -> usize {
    let derived = iteron_tunables::param_integer(
        "cli.app_server.sq_entry_overhead_bytes",
        SQ_ENTRY_OVERHEAD_BYTES,
    )
    .saturating_add(iteron_protocol::task::MAX_TASK_TEXT_BYTES)
    .saturating_add(iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES)
    .saturating_add(sq_control_reserve_bytes());
    iteron_tunables::param_integer("cli.app_server.sq_byte_capacity", derived)
}

/// Event-queue depth.
///
/// Streamed text arrives far faster than a terminal repaints, so this is the elastic that absorbs a
/// burst between frames. It is a bound, not a buffer to be filled: see the drop policy above.
pub(crate) const EQ_CAPACITY: usize = 1024;

/// How long session teardown waits for the lifecycle-hook task to drain after the last event is
/// published. Bounded, because a hook that never returns must not hold the session open; past it
/// the task is aborted.
const LIFECYCLE_HOOK_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

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
    pub(crate) cost: iteron_obs::CostState,
    pub(crate) turns: u32,
    pub(crate) kernel_tax: iteron_obs::KernelTax,
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
    pub(crate) mode: iteron_protocol::PermissionMode,
    pub(crate) effort: iteron_protocol::Effort,
    pub(crate) model: String,
    pub(crate) cost: iteron_obs::CostState,
    pub(crate) last_turn_usage: Option<iteron_protocol::Usage>,
    pub(crate) unadmitted_steers: Vec<String>,
    /// The capability rules in force. Dynamic: `/permissions` changes them, and the frontend
    /// renders them, so they cannot be a session-invariant fact.
    pub(crate) permission_rules: iteron_protocol::PermissionRules,
    /// Ordered live runtime-policy overlay joined to the durable transition that made each value
    /// effective. `None` is reserved for an unsealed legacy/test agent and must never be rendered
    /// as though the immutable genesis values were still live.
    pub(crate) runtime_policy: Option<crate::runtime::RuntimePolicyOverlaySnapshot>,
    /// The ledger line the status panel prints.
    pub(crate) ledger_summary: String,
    /// One line of provider quota, read from the response headers of the last request. `None`
    /// when the route publishes none — a row of dashes reads like an exhausted budget (I-53).
    pub(crate) rate_limit: Option<String>,
    /// Non-blocking projections from the exact session-owned MCP supervisors. A busy server is
    /// reported as busy rather than blocking the App Server snapshot path behind external I/O.
    pub(crate) mcp_health: Vec<crate::mcp::McpServerHealth>,
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
    /// Ordered receipt/admission/application evidence for one client-minted submission.
    Submission {
        id: SubmissionId,
        state: SubmissionLifecycleState,
        reason_code: Option<&'static str>,
    },
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
                    event: iteron_workflow::events::ProgressEvent::AgentActivity { .. },
                    ..
                })
        )
    }
}

/// A control-plane request the frontend makes of the resident runtime.
///
/// # Why this is not on the SQ
///
/// It should be. `iteron_protocol::Op` has six variants — `UserInput`, `Steer`, `Interrupt`,
/// `Drain`, `ApprovalResponse`, `Unknown` — and **none of them can express `/model`, `/effort`,
/// `/mode`, `/permissions` or `/compact`**. Adding one is a change to the frozen wire types, which
/// WS1 owns and this issue's acceptance criteria explicitly forbid: "zero changes to
/// `iteron_protocol`; this issue only consumes them."
///
/// So the runtime is owned by the server — the frontend holds no `Agent` — and the operations the
/// wire cannot yet carry travel on a typed in-process channel beside it. That is a smaller lie than
/// either alternative: leaving the `Agent` in the frontend (which is the co-composition this issue
/// exists to remove) or quietly widening a frozen protocol.
///
/// **Folding these into the SQ is a WS1 protocol change, not a WS6 one.** When `Op` grows the
/// variants, each arm here becomes a `route()` case and this enum shrinks to nothing.
pub(crate) enum Control {
    /// `/status` — one content-free snapshot from the exact runtime-owned authorities.
    OperatorStatus,
    /// `/effort`
    SetEffort(iteron_protocol::Effort),
    /// `/mode`
    SetPermissionMode(iteron_protocol::PermissionMode),
    /// `/permissions <capability> <verdict>`
    SetCapabilityRule {
        capability: iteron_protocol::Capability,
        verdict: iteron_protocol::Verdict,
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
    /// Operator memory mutations run in the resident runtime so canonical Gate Hooks and durable
    /// effect evidence execute before the filesystem mutation.
    Memory(MemoryControl),
    /// `/mcp` addresses the exact lazy supervisors captured by this session. These controls are
    /// immediate even mid-turn: cancellation and stop must be able to release a blocked MCP call.
    Mcp(McpControl),
}

pub(crate) enum McpControl {
    Status,
    Cancel { server: String },
    Restart { server: String },
    Stop { server: String },
}

#[derive(Debug, Clone)]
pub(crate) struct McpControlReply {
    pub(crate) servers: Vec<crate::mcp::McpServerHealth>,
    pub(crate) notice: Option<String>,
}

pub(crate) enum MemoryControl {
    Add(String),
    Update { id: String, text: String },
    Delete(String),
}

#[derive(Debug)]
pub(crate) enum MemoryControlReply {
    Added { id: String },
    Updated { old_id: String, id: String },
    Deleted { id: String },
    Missing { id: String },
}

pub(crate) enum JobControl {
    Inventory,
    Clean,
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
    pub(crate) rollout: iteron_record::Rollout,
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
    pub(crate) provider: std::sync::Arc<dyn iteron_provider::Provider>,
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
    /// `/status` — runtime policy identity plus live bounded owner health.
    OperatorStatus(Box<OperatorStatusSnapshot>),
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
        /// Exact immutable tunables identity of the run now owned by the resident runtime. This
        /// is dynamic run state: keeping the attach-time checkpoint after an in-process resume
        /// would make `/tunables` and `/config` describe the run that was left.
        tunables_checkpoint: Box<iteron_record::TunablesCheckpoint>,
        /// Run-local compaction trigger decoded from the same checkpoint. The frontend's context
        /// surface reads this value directly, so it must move with an adopted run as one reply.
        compaction_trigger_tokens: usize,
        blocked: Option<String>,
    },
    /// `/workflows` inventory or action result.
    Workflows(Box<WorkflowControlReply>),
    /// `/jobs` inventory, attached output page, write receipt, or terminal stop snapshot.
    Jobs(serde_json::Value),
    /// `/memory add|forget` mutation result from the resident authority owner.
    Memory(MemoryControlReply),
    /// `/mcp` inventory or lifecycle action result.
    Mcp(Box<McpControlReply>),
}

/// One control request and the channel its answer comes back on.
pub(crate) struct ControlRequest {
    pub(crate) control: Control,
    pub(crate) reply: tokio::sync::oneshot::Sender<ControlReply>,
}

/// A versioned EQ envelope.
///
/// Deliberately not `iteron_protocol::EqEnvelope` — see the module docs for the four losses that
/// would force.
#[derive(Debug, Clone)]
pub(crate) struct EventEnvelope {
    /// Monotonic live-delivery cursor. This is deliberately not `iteron_protocol::Seq`, which names
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
    next_submission_id: Arc<AtomicU64>,
    lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
}

#[derive(Debug, Clone)]
enum SubmissionSender {
    /// Test-only bare wires keep the existing constructor usable by frontend submission tests.
    #[cfg(test)]
    Bare(mpsc::Sender<SqEnvelope>),
    /// Production wires charge every queued submission against the shared heap budget.
    Weighted {
        sender: mpsc::Sender<QueuedSubmission>,
        priority_sender: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        data_slots: Arc<Semaphore>,
        priority_slots: Arc<Semaphore>,
    },
}

/// One weighted SQ entry. Permits are released only when the server consumes or drops the item;
/// moving it into the safe-point queue retains both bounds.
#[derive(Debug)]
pub(crate) struct QueuedSubmission {
    envelope: SqEnvelope,
    _memory: OwnedSemaphorePermit,
    /// Retained across server-side requeue. Channel capacity alone is not a bound once an item has
    /// been dequeued, so this permit keeps data and priority populations independently bounded.
    _slot: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelSubmissionKind {
    Steer,
    Interrupt,
    Drain,
    Approval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingKernelSubmission {
    id: SubmissionId,
    kind: KernelSubmissionKind,
}

const SUBMISSION_DEDUP_WINDOW: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionIdentityAdmission {
    Fresh,
    Duplicate,
    Stale,
}

/// Bounded replay protection for the SQ. Client clones may allocate IDs concurrently and enqueue
/// them out of numeric order, so a simple high-water mark would reject valid work. The live window
/// accepts that reordering; once its smallest IDs retire, replay at or below that floor is stale.
#[derive(Debug, Default)]
struct SubmissionDeduplicator {
    live: std::collections::BTreeSet<u64>,
    retired_through: u64,
}

impl SubmissionDeduplicator {
    fn admit(&mut self, id: SubmissionId) -> SubmissionIdentityAdmission {
        if id.0 == 0 || id.0 <= self.retired_through {
            return SubmissionIdentityAdmission::Stale;
        }
        if !self.live.insert(id.0) {
            return SubmissionIdentityAdmission::Duplicate;
        }
        if self.live.len()
            > iteron_tunables::param_integer(
                "cli.app_server.submission_dedup_window",
                SUBMISSION_DEDUP_WINDOW,
            )
            && let Some(oldest) = self.live.pop_first()
        {
            self.retired_through = self.retired_through.max(oldest);
        }
        SubmissionIdentityAdmission::Fresh
    }
}

fn kernel_submission_kind(op: &Op) -> Option<KernelSubmissionKind> {
    match op {
        Op::Steer { .. } => Some(KernelSubmissionKind::Steer),
        Op::Interrupt | Op::ForceCancel => Some(KernelSubmissionKind::Interrupt),
        Op::Drain => Some(KernelSubmissionKind::Drain),
        Op::ApprovalResponse { .. } => Some(KernelSubmissionKind::Approval),
        Op::UserInput { .. } | Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
            None
        }
    }
}

fn is_priority_submission(op: &Op) -> bool {
    matches!(
        op,
        Op::Steer { .. }
            | Op::Interrupt
            | Op::ForceCancel
            | Op::Drain
            | Op::ApprovalResponse { .. }
    )
}

impl QueuedSubmission {
    fn into_envelope(self) -> SqEnvelope {
        self.envelope
    }
}

impl AppServerClient {
    /// Record a frontend-owned local boundary (for example an explicit memory mutation). The
    /// event is content-free and shares the same bounded stream as runtime events.
    pub(crate) fn record_lifecycle(&self, event_name: &str, payload: LifecyclePayload) {
        let _ = self.lifecycle.emit(
            event_name,
            iteron_obs::lifecycle::LifecycleCorrelation::default(),
            payload,
        );
    }

    fn queue_depth(&self) -> usize {
        match &self.submissions {
            #[cfg(test)]
            SubmissionSender::Bare(sender) => {
                sender.max_capacity().saturating_sub(sender.capacity())
            }
            SubmissionSender::Weighted {
                sender,
                priority_sender,
                ..
            } => sender
                .max_capacity()
                .saturating_sub(sender.capacity())
                .saturating_add(
                    priority_sender
                        .max_capacity()
                        .saturating_sub(priority_sender.capacity()),
                ),
        }
    }

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
        Self::connect_to(
            server_version,
            SubmissionSender::Bare(submissions),
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        )
    }

    #[cfg(test)]
    fn connect_weighted(
        server_version: u32,
        submissions: mpsc::Sender<QueuedSubmission>,
        priority_submissions: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_weighted_with_policy(
            server_version,
            submissions,
            priority_submissions,
            budget,
            lifecycle,
            AppServerQueuePolicy::owner(),
        )
    }

    fn connect_weighted_with_policy(
        server_version: u32,
        submissions: mpsc::Sender<QueuedSubmission>,
        priority_submissions: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        queue_policy: AppServerQueuePolicy,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_to(
            server_version,
            SubmissionSender::Weighted {
                sender: submissions,
                priority_sender: priority_submissions,
                budget,
                data_slots: Arc::new(Semaphore::new(queue_policy.data_entries())),
                priority_slots: Arc::new(Semaphore::new(queue_policy.priority_entries())),
            },
            lifecycle,
        )
    }

    fn connect_to(
        server_version: u32,
        submissions: SubmissionSender,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
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
            next_submission_id: Arc::new(AtomicU64::new(1)),
            lifecycle,
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
        self.submit_identified(op).map(|_| ())
    }

    /// Submit and return the identity that every receipt/application event will carry.
    pub(crate) fn submit_identified(&self, op: Op) -> Result<SubmissionId, SubmitError> {
        use mpsc::error::TrySendError;
        let id = SubmissionId(
            self.next_submission_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| SubmitError::Busy)?,
        );
        let requested_event = match &op {
            Op::Steer { .. } => Some("steer.requested"),
            Op::Interrupt | Op::ForceCancel => Some("cancel.requested"),
            Op::Drain => Some("drain.requested"),
            _ => None,
        };
        let envelope = SqEnvelope::with_version_and_id(self.negotiated_version, id, op);
        let correlation = iteron_obs::lifecycle::LifecycleCorrelation {
            submission_id: Some(id),
            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
        };
        let _ = self.lifecycle.emit(
            "submission.created",
            correlation.clone(),
            LifecyclePayload::default(),
        );
        if let Some(event_id) = requested_event {
            let _ = self
                .lifecycle
                .emit(event_id, correlation.clone(), LifecyclePayload::default());
        }
        let result = match &self.submissions {
            #[cfg(test)]
            SubmissionSender::Bare(submissions) => {
                submissions.try_send(envelope).map_err(|error| match error {
                    TrySendError::Full(_) => SubmitError::Busy,
                    TrySendError::Closed(_) => SubmitError::Disconnected,
                })
            }
            SubmissionSender::Weighted {
                sender,
                priority_sender,
                budget,
                data_slots,
                priority_slots,
            } => (|| {
                let priority = is_priority_submission(&envelope.op);
                let selected = if priority { priority_sender } else { sender };
                let slots = if priority { priority_slots } else { data_slots };
                if selected.is_closed() {
                    return Err(SubmitError::Disconnected);
                }
                let weight = u32::try_from(submission_weight(&envelope.op))
                    .map_err(|_| SubmitError::Busy)?;
                let slot = slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| SubmitError::Busy)?;
                let permit = budget
                    .clone()
                    .try_acquire_many_owned(weight)
                    .map_err(|_| SubmitError::Busy)?;
                selected
                    .try_send(QueuedSubmission {
                        envelope,
                        _memory: permit,
                        _slot: slot,
                    })
                    .map_err(|error| match error {
                        TrySendError::Full(_) => SubmitError::Busy,
                        TrySendError::Closed(_) => SubmitError::Disconnected,
                    })
            })(),
        };
        match result {
            Ok(()) => {
                let _ = self.lifecycle.emit(
                    "submission.enqueued",
                    correlation.clone(),
                    LifecyclePayload::default(),
                );
                let _ = self.lifecycle.emit(
                    "queue.depth_changed",
                    correlation,
                    LifecyclePayload {
                        count: Some(u64::try_from(self.queue_depth()).unwrap_or(u64::MAX)),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(id)
            }
            Err(error) => {
                let reason = match &error {
                    SubmitError::Busy => "queue_full",
                    SubmitError::Disconnected => "runtime_disconnected",
                };
                let _ = self.lifecycle.emit(
                    "submission.rejected",
                    correlation,
                    LifecyclePayload {
                        reason_code: Some(reason.into()),
                        ..LifecyclePayload::default()
                    },
                );
                if matches!(&error, SubmitError::Busy) {
                    let _ = self.lifecycle.emit(
                        "queue.overflow",
                        iteron_obs::lifecycle::LifecycleCorrelation {
                            submission_id: Some(id),
                            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
                        },
                        LifecyclePayload {
                            count: Some(u64::try_from(self.queue_depth()).unwrap_or(u64::MAX)),
                            ..LifecyclePayload::default()
                        },
                    );
                }
                Err(error)
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
                    iteron_protocol::ContentSegment::Text { text } => {
                        bytes.saturating_add(text.len())
                    }
                    iteron_protocol::ContentSegment::Image { image } => {
                        bytes.saturating_add(image.data.encoded_len())
                    }
                    iteron_protocol::ContentSegment::Unknown => bytes,
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
        Op::ApprovalResponse { .. } | Op::Interrupt | Op::ForceCancel | Op::Drain | Op::Unknown => {
            0
        }
    };
    iteron_tunables::param_integer(
        "cli.app_server.sq_entry_overhead_bytes",
        SQ_ENTRY_OVERHEAD_BYTES,
    )
    .saturating_add(variable_bytes)
}

/// The frontend's end of the wire: a client to submit through and a queue to read.
/// A registered tool, reduced to the three fields a client renders. `iteron_tools::ToolSpec` is not
/// public, so this is what crosses the attach boundary instead of the spec.
pub(crate) struct ToolFact {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) capability: iteron_protocol::Capability,
}

/// What a client is handed once, at attach time, and may read for the life of the session.
///
/// These are the shapes a co-composing frontend used to read straight off an idle `Agent`. They are
/// invariants — nothing here changes while the session runs — which is exactly why they can be
/// copied across the boundary instead of being asked for on every keystroke.
pub(crate) struct SessionFacts {
    pub(crate) session_id: SessionId,
    pub(crate) context_ledgers: iteron_ctx::ContextLedgerStore,
    pub(crate) memory_traces: iteron_ctx::MemoryTraceStore,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
    pub(crate) telemetry_health: Option<crate::runtime::telemetry::TelemetryHealth>,
    pub(crate) workspace: std::path::PathBuf,
    pub(crate) memory_workspace: Option<std::path::PathBuf>,
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
    pub(crate) agent_catalog: Arc<iteron_agents::AgentCatalog>,
    /// Exact immutable runtime checkpoint. Production composition always supplies V2; Option is
    /// retained only for narrow wire tests that construct an unbound Agent.
    pub(crate) tunables_checkpoint: Option<iteron_record::TunablesCheckpoint>,
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
    /// Ctrl-D: quiesce active work and settle the session record.
    pub(crate) drain: Arc<AtomicBool>,
}

/// **The composition root.** The one place an `Agent` is handed to an App Server, and the one place
/// the wire's version, capacities and ownership are decided.
///
/// The interactive TUI attaches here today; the one-shot path and the headless `iteron serve` (#44)
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
    let queue_policy = agent.app_server_queue_policy();
    let (handle, ends) = wire_with_queue_policy(lossless_events, queue_policy)?;

    let interrupt = Arc::new(AtomicBool::new(false));
    agent.set_interrupt(interrupt.clone());
    let drain = Arc::new(AtomicBool::new(false));
    agent.set_drain(drain.clone());

    let facts = SessionFacts {
        session_id: SessionId(format!("session-{}", agent.rollout.run_id().0)),
        context_ledgers: agent.context_ledgers.clone(),
        memory_traces: agent.memory_traces.clone(),
        hook_health: handle.hook_health.clone(),
        telemetry_health: agent.telemetry.as_ref().map(|sink| sink.health()),
        workspace: agent.workspace.clone(),
        memory_workspace: agent.memory_workspace.clone(),
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
        tunables_checkpoint: agent.tunables_checkpoint().ok().cloned(),
    };
    let initial_state = snapshot_of(&mut agent);
    if let Some(telemetry) = handle.lifecycle_otel.clone() {
        agent.set_lifecycle_telemetry(telemetry);
    }

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
    /// Content-free, bounded local lifecycle evidence. Reading it never asks the runtime actor or
    /// an exporter to stop what it is doing.
    pub(crate) lifecycle: iteron_obs::lifecycle::LifecycleBus,
    pub(crate) lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
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
    lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    lifecycle_hooks: Option<crate::runtime::lifecycle_hooks::LifecycleHookDispatcher>,
    session_id: Option<SessionId>,
    run_id: Option<RunId>,
    workflow_phases: std::collections::BTreeMap<String, String>,
    queue_policy: AppServerQueuePolicy,
    pending_cosmetic: Option<ServerEvent>,
}

const MAX_TRACKED_WORKFLOW_PHASES: usize = 256;

impl EventPublisher {
    #[cfg(test)]
    fn new(
        events: mpsc::Sender<EventEnvelope>,
        lossless: bool,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    ) -> Self {
        Self::new_with_policy(events, lossless, lifecycle, AppServerQueuePolicy::owner())
    }

    fn new_with_policy(
        events: mpsc::Sender<EventEnvelope>,
        lossless: bool,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        queue_policy: AppServerQueuePolicy,
    ) -> Self {
        Self {
            events,
            dropped: 0,
            next_seq: 1,
            lossless,
            lifecycle,
            lifecycle_hooks: None,
            session_id: None,
            run_id: None,
            workflow_phases: std::collections::BTreeMap::new(),
            queue_policy,
            pending_cosmetic: None,
        }
    }

    fn bind_lifecycle_identity(&mut self, session_id: SessionId, run_id: RunId) {
        self.session_id = Some(session_id);
        self.run_id = Some(run_id);
    }

    fn bind_lifecycle_hooks(
        &mut self,
        dispatcher: crate::runtime::lifecycle_hooks::LifecycleHookDispatcher,
    ) {
        self.lifecycle_hooks = Some(dispatcher);
    }

    fn lifecycle_emitter(&self) -> iteron_obs::lifecycle::LifecycleEmitter {
        self.lifecycle.clone()
    }

    fn lifecycle_correlation(
        &self,
        turn_id: Option<TurnId>,
        submission_id: Option<SubmissionId>,
    ) -> iteron_obs::lifecycle::LifecycleCorrelation {
        iteron_obs::lifecycle::LifecycleCorrelation {
            session_id: self.session_id.clone(),
            run_id: self.run_id.clone(),
            turn_id,
            submission_id,
            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
        }
    }

    fn record_lifecycle(
        &self,
        event_name: &str,
        turn_id: Option<TurnId>,
        submission_id: Option<SubmissionId>,
        payload: LifecyclePayload,
    ) {
        if let Ok(event) = self.lifecycle.emit(
            event_name,
            self.lifecycle_correlation(turn_id, submission_id),
            payload,
        ) && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    fn record_workflow_lifecycle(
        &self,
        event_name: &str,
        workflow_id: Option<&str>,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.workflow_id = workflow_id.map(|id| iteron_protocol::WorkflowId(id.to_owned()));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    fn record_job_lifecycle(&self, event_name: &str, job_id: &str, payload: LifecyclePayload) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.job_id = Some(iteron_protocol::JobId(job_id.to_owned()));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    fn record_workflow_child_lifecycle(
        &self,
        event_name: &str,
        workflow_id: &str,
        index: usize,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.workflow_id = Some(iteron_protocol::WorkflowId(workflow_id.to_owned()));
        correlation.subagent_id = Some(iteron_protocol::SubagentId(format!(
            "{workflow_id}:agent-{index}"
        )));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    fn transition_workflow_phase(&mut self, workflow_id: &str, next: &str) {
        let previous = self.workflow_phases.get(workflow_id).cloned();
        if previous.as_deref() == Some(next) {
            return;
        }
        if let Some(previous) = previous {
            self.record_workflow_lifecycle(
                if previous == "planning" {
                    "workflow.planning_completed"
                } else if previous == "reducing" {
                    "workflow.reduction_completed"
                } else {
                    "workflow.phase_completed"
                },
                Some(workflow_id),
                LifecyclePayload::default(),
            );
        }
        if self.workflow_phases.len()
            < iteron_tunables::param_integer(
                "cli.app_server.max_tracked_workflow_phases",
                MAX_TRACKED_WORKFLOW_PHASES,
            )
            || self.workflow_phases.contains_key(workflow_id)
        {
            self.workflow_phases
                .insert(workflow_id.to_owned(), next.to_owned());
        }
        self.record_workflow_lifecycle(
            if next == "planning" {
                "workflow.planning_started"
            } else if next == "reducing" {
                "workflow.reduction_started"
            } else {
                "workflow.phase_started"
            },
            Some(workflow_id),
            LifecyclePayload::default(),
        );
    }

    fn finish_workflow_phase(
        &mut self,
        workflow_id: &str,
        terminal: crate::workflow::WorkflowRunTerminal,
    ) {
        let Some(previous) = self.workflow_phases.remove(workflow_id) else {
            return;
        };
        let event_id = if previous == "planning"
            && matches!(terminal, crate::workflow::WorkflowRunTerminal::Failed)
        {
            "workflow.planning_failed"
        } else if previous == "planning" {
            "workflow.planning_completed"
        } else if previous == "reducing" {
            "workflow.reduction_completed"
        } else {
            "workflow.phase_completed"
        };
        self.record_workflow_lifecycle(event_id, Some(workflow_id), LifecyclePayload::default());
    }

    fn record_submission_lifecycle(
        &self,
        id: SubmissionId,
        state: SubmissionLifecycleState,
        reason_code: Option<&'static str>,
    ) {
        let event_name = match state {
            SubmissionLifecycleState::Created => "submission.created",
            SubmissionLifecycleState::Enqueued => "submission.enqueued",
            SubmissionLifecycleState::Received => "submission.received",
            SubmissionLifecycleState::Admitted => "submission.admitted",
            SubmissionLifecycleState::Applied => "submission.applied",
            SubmissionLifecycleState::Requeued => "submission.requeued",
            SubmissionLifecycleState::Rejected => "submission.rejected",
            SubmissionLifecycleState::Expired => "submission.expired",
        };
        self.record_lifecycle(
            event_name,
            None,
            Some(id),
            LifecyclePayload {
                reason_code: reason_code.map(str::to_owned),
                ..LifecyclePayload::default()
            },
        );
    }

    async fn send(&mut self, event: ServerEvent) -> Result<(), ()> {
        let reject_authoritative = !self.lossless
            && event.is_authoritative()
            && self.queue_policy.authoritative_overflow() == AuthoritativeOverflow::Reject;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(())?;
        let envelope = EventEnvelope {
            seq,
            protocol_version: PROTOCOL_VERSION,
            event,
        };
        if reject_authoritative {
            self.events.try_send(envelope).map_err(|_| ())
        } else {
            self.events.send(envelope).await.map_err(|_| ())
        }
    }

    /// Publish one event, applying the bounded-queue policy.
    ///
    /// Authoritative events wait for room. Cosmetic deltas are dropped when there is none, and the
    /// count is flushed as a `Lagged` notice as soon as the queue drains — so the transcript says
    /// where it is incomplete instead of quietly being wrong.
    pub(crate) async fn publish(&mut self, event: ServerEvent) -> Result<(), ()> {
        let authoritative = event.is_authoritative();
        if !self.lossless && !authoritative && self.events.capacity() == 0 {
            match self.queue_policy.cosmetic_overflow() {
                CosmeticOverflow::Drop => self.dropped += 1,
                CosmeticOverflow::Coalesce => {
                    if self.pending_cosmetic.replace(event).is_some() {
                        self.dropped += 1;
                    }
                }
            }
            return Ok(());
        }
        if !self.lossless
            && !authoritative
            && self.pending_cosmetic.is_some()
            && self.events.capacity() <= 1
        {
            self.pending_cosmetic = Some(event);
            self.dropped += 1;
            return Ok(());
        }
        if self.pending_cosmetic.is_some() && (authoritative || self.events.capacity() > 1) {
            if self.dropped > 0 {
                let dropped = std::mem::take(&mut self.dropped);
                self.send(ServerEvent::Lagged { dropped }).await?;
            }
            if let Some(pending) = self.pending_cosmetic.take() {
                self.send(pending).await?;
            }
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
    pub(crate) priority_submissions: mpsc::Receiver<QueuedSubmission>,
    pub(crate) control: mpsc::Receiver<ControlRequest>,
    pub(crate) events: EventPublisher,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
}

/// The protocol version the in-process runtime advertises to a connecting frontend.
///
/// Overridable only so a process-level test can point the frontend at a server that does not speak
/// its protocol. `iteron-cli` is a managed binary-only package — the boundary authority forbids it a
/// library target — so a skewed server cannot be injected any other way, and the refusal path would
/// otherwise be unreachable in every test that can actually run the frontend. A user who sets it
/// gets a refusal to attach and a diagnostic; there is nothing else behind the door.
pub(crate) fn advertised_version() -> u32 {
    std::env::var("ITERON_APP_SERVER_PROTOCOL_VERSION")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(PROTOCOL_VERSION)
}

#[cfg(test)]
pub(crate) fn wire() -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    wire_with_policy(false)
}

#[cfg(test)]
fn wire_with_policy(
    lossless_events: bool,
) -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    wire_with_queue_policy(lossless_events, AppServerQueuePolicy::owner())
}

fn wire_with_queue_policy(
    lossless_events: bool,
    queue_policy: AppServerQueuePolicy,
) -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    let (sq_tx, sq_rx) = mpsc::channel::<QueuedSubmission>(queue_policy.data_entries());
    let (priority_sq_tx, priority_sq_rx) =
        mpsc::channel::<QueuedSubmission>(queue_policy.priority_entries());
    let sq_budget = Arc::new(Semaphore::new(queue_policy.submission_bytes()));
    let (eq_tx, eq_rx) = mpsc::channel::<EventEnvelope>(queue_policy.event_entries());
    // The control plane is deliberately shallow: these are operator commands, one at a time, and a
    // backlog of them would mean the frontend is issuing config changes faster than a human can.
    let (control_tx, control_rx) = mpsc::channel::<ControlRequest>(8);
    let lifecycle = iteron_obs::lifecycle::LifecycleBus::default();
    let lifecycle_emitter = iteron_obs::lifecycle::LifecycleEmitter::new(lifecycle.clone());
    let _ = lifecycle_emitter.emit(
        "queue.capacity_resolved",
        iteron_obs::lifecycle::LifecycleCorrelation::default(),
        LifecyclePayload {
            count: Some(u64::try_from(queue_policy.submission_entries()).unwrap_or(u64::MAX)),
            magnitude: Some(u64::try_from(queue_policy.submission_bytes()).unwrap_or(u64::MAX)),
            ..LifecyclePayload::default()
        },
    );
    let lifecycle_otel =
        iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime::attach(&lifecycle).ok();
    let hook_health = crate::runtime::lifecycle_hooks::LifecycleHookHealth::default();
    let client = AppServerClient::connect_weighted_with_policy(
        advertised_version(),
        sq_tx,
        priority_sq_tx,
        sq_budget,
        lifecycle_emitter.clone(),
        queue_policy,
    )?;
    Ok((
        AppServerHandle {
            client,
            events: eq_rx,
            lifecycle,
            lifecycle_otel,
            hook_health: hook_health.clone(),
            control: control_tx,
        },
        ServerEnds {
            submissions: sq_rx,
            priority_submissions: priority_sq_rx,
            control: control_rx,
            events: EventPublisher::new_with_policy(
                eq_tx,
                lossless_events,
                lifecycle_emitter,
                queue_policy,
            ),
            hook_health,
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
        images: Vec<iteron_protocol::ImageContent>,
        files: Vec<iteron_protocol::FileContent>,
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
        Op::Steer { .. }
        | Op::Interrupt
        | Op::ForceCancel
        | Op::Drain
        | Op::ApprovalResponse { .. } => Routed::ToKernel,
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
    priority_submissions: mpsc::Receiver<QueuedSubmission>,
    control: mpsc::Receiver<ControlRequest>,
    events: EventPublisher,
    hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
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
        let mut ends = ends;
        let run_id = agent.rollout.run_id().clone();
        ends.events
            .bind_lifecycle_identity(SessionId(format!("session-{}", run_id.0)), run_id);
        let (to_kernel, kernel_rx) = mpsc::unbounded_channel::<SqEnvelope>();
        if interactive_approvals {
            agent.set_approvals(kernel_rx);
        }
        Self {
            agent,
            submissions: ends.submissions,
            priority_submissions: ends.priority_submissions,
            control: ends.control,
            events: ends.events,
            hook_health: ends.hook_health,
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
            mut priority_submissions,
            mut control,
            mut events,
            hook_health,
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
        // Runtime and frontend project the same canonical lifecycle stream. Installing this before
        // any session-owned worker starts prevents model/tool/context events from becoming an
        // uncorrelated second telemetry island.
        agent.set_lifecycle_emitter(events.lifecycle_emitter());

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
        // MCP cancellation/restart/stop must remain reachable while the turn is blocked in an MCP
        // request. This clone addresses the same session-owned actors as the registry proxies.
        let mcp_runtime = agent.mcp_runtime_control();
        // The same ownership rule applies to language servers: drain/exit must address the exact
        // bounded pool that served this session, never reconstruct a best-effort client list.
        let language_servers = agent.registry.lsp_control();
        let mut operator_status = OperatorStatusSources::capture(
            &agent,
            processes.clone(),
            language_servers.clone(),
            mcp_runtime.clone(),
            workflows.clone(),
        );
        let hook_cancel = agent.interrupt_handle();
        let drain_signal = agent.drain_handle();

        // Canonical Hook observation is bounded and off the turn path. Gate hooks remain at their
        // owning admission sites below; the dispatcher deliberately skips the fixed Gate set.
        let lifecycle_gate_hooks = agent.hooks.clone();
        let hook_journal = if lifecycle_gate_hooks.is_empty() {
            None
        } else {
            match crate::runtime::hooks::journal::HookEffectJournal::open(
                &agent.rollout.path().with_extension("hooks.jsonl"),
            ) {
                Ok(journal) => {
                    let recovered_unknown = journal.recovered_unknown();
                    if recovered_unknown > 0 {
                        events.record_lifecycle(
                            "hook.failed",
                            None,
                            None,
                            LifecyclePayload {
                                count: Some(recovered_unknown),
                                reason_code: Some("recovered_unknown_effect".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                    }
                    Some(journal)
                }
                Err(_) => {
                    events.record_lifecycle(
                        "hook.failed",
                        None,
                        None,
                        LifecyclePayload {
                            reason_code: Some("durable_journal_unavailable".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    None
                }
            }
        };
        agent.set_hook_effect_journal(hook_journal.clone());
        let (lifecycle_hooks, mut lifecycle_hook_task) =
            crate::runtime::lifecycle_hooks::LifecycleHookDispatcher::start(
                agent.hooks.clone(),
                events.lifecycle_emitter(),
                events.lifecycle_correlation(None, None),
                hook_journal.clone(),
                drain_signal.clone(),
                hook_health,
            );
        events.bind_lifecycle_hooks(lifecycle_hooks.clone());
        agent.set_lifecycle_hooks(lifecycle_hooks);
        if let Some(processes) = &processes {
            let emitter = events.lifecycle_emitter();
            let base_correlation = events.lifecycle_correlation(None, None);
            let dispatcher = events.lifecycle_hooks.clone();
            processes.bind_lifecycle_observer(std::sync::Arc::new(move |notice| {
                let outcome = match notice.kind {
                    iteron_tools::ProcessLifecycleKind::Spawned => "spawned",
                    iteron_tools::ProcessLifecycleKind::Exited => "exited",
                    iteron_tools::ProcessLifecycleKind::Stopped => "stopped",
                    iteron_tools::ProcessLifecycleKind::TimedOut => "timed_out",
                    iteron_tools::ProcessLifecycleKind::IdleStalled => "idle_stalled",
                    iteron_tools::ProcessLifecycleKind::OutputLimitExceeded => "output_limit",
                    iteron_tools::ProcessLifecycleKind::IoFailed => "io_failed",
                    iteron_tools::ProcessLifecycleKind::CleanupUnknown => "cleanup_unknown",
                };
                let event_ids: &[&str] = match notice.kind {
                    iteron_tools::ProcessLifecycleKind::Spawned => {
                        &["process.spawned", "background.detached"]
                    }
                    iteron_tools::ProcessLifecycleKind::Exited => {
                        &["process.kill_sent", "process.reaped", "background.stopped"]
                    }
                    iteron_tools::ProcessLifecycleKind::CleanupUnknown => &[
                        "process.kill_sent",
                        "process.reap_failed",
                        "background.orphan_detected",
                    ],
                    iteron_tools::ProcessLifecycleKind::Stopped
                    | iteron_tools::ProcessLifecycleKind::TimedOut
                    | iteron_tools::ProcessLifecycleKind::IdleStalled
                    | iteron_tools::ProcessLifecycleKind::OutputLimitExceeded
                    | iteron_tools::ProcessLifecycleKind::IoFailed => &[
                        "process.term_sent",
                        "process.kill_sent",
                        "process.reaped",
                        "background.stopped",
                    ],
                };
                for event_id in event_ids {
                    let mut correlation = base_correlation.clone();
                    correlation.job_id = Some(iteron_protocol::JobId(notice.job_id.clone()));
                    if let Ok(event) = emitter.emit(
                        event_id,
                        correlation,
                        LifecyclePayload {
                            outcome_code: Some(outcome.to_owned()),
                            ..LifecyclePayload::default()
                        },
                    ) && let Some(dispatcher) = &dispatcher
                    {
                        dispatcher.dispatch(event);
                    }
                }
            }));
        }
        let mut session_lifecycle = SessionLifecycleState::Created;
        events.record_lifecycle("session.created", None, None, LifecyclePayload::default());
        events.record_lifecycle(
            "session.record_opened",
            None,
            None,
            LifecyclePayload::default(),
        );
        events.record_lifecycle(
            "session.profile_bound",
            None,
            None,
            LifecyclePayload::default(),
        );
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Configured)
            .expect("new sessions configure before serving");
        events.record_lifecycle(
            "session.configured",
            None,
            None,
            LifecyclePayload::default(),
        );
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Idle)
            .expect("configured sessions become idle");
        run_legacy_hook(
            HookExecution {
                hooks: &lifecycle_gate_hooks,
                journal: hook_journal.as_ref(),
                events: &events,
                cancel: hook_cancel.as_deref(),
                drain: Some(drain_signal.as_ref()),
            },
            crate::runtime::hooks::HookEvent::SessionStart,
            None,
            None,
            serde_json::json!({
                "event": "SessionStart",
                "session_id": format!("session-{}", agent.rollout.run_id().0),
            })
            .to_string(),
        )
        .await;
        events.record_lifecycle("session.started", None, None, LifecyclePayload::default());
        events.record_lifecycle("session.idle", None, None, LifecyclePayload::default());

        // `run` versus `follow_up` was a caller-side boolean the frontend chose. With a resident
        // runtime it is session state and belongs here: the first admitted turn starts the session,
        // every later one continues it.
        let mut started = false;

        // The operator's side conversation, if they have opened one. It is server state for the
        // same reason the `Agent` is: it owns a live runtime with an open journal.
        let mut side: Option<crate::runtime::SideConversation> = None;
        let mut pending_runtime = std::collections::VecDeque::<String>::new();
        let mut pending_turns = std::collections::VecDeque::<QueuedSubmission>::new();
        let mut pending_kernel_submissions =
            std::collections::VecDeque::<PendingKernelSubmission>::new();
        let mut submission_identities = SubmissionDeduplicator::default();

        enum TurnTrigger {
            Submission {
                queued: QueuedSubmission,
                preprocessed: bool,
            },
            Runtime(String),
        }

        loop {
            let trigger = if let Ok(queued) = priority_submissions.try_recv() {
                events.record_lifecycle(
                    "queue.depth_changed",
                    None,
                    None,
                    LifecyclePayload {
                        count: Some(queue_population(
                            &submissions,
                            &priority_submissions,
                            pending_turns.len(),
                        )),
                        ..LifecyclePayload::default()
                    },
                );
                TurnTrigger::Submission {
                    queued,
                    preprocessed: false,
                }
            } else if let Some(queued) = pending_turns.pop_front() {
                TurnTrigger::Submission {
                    queued,
                    preprocessed: true,
                }
            } else if let Some(notification) = pending_runtime.pop_front() {
                TurnTrigger::Runtime(notification)
            } else {
                tokio::select! {
                    biased;
                    Some(queued) = priority_submissions.recv() => {
                        events.record_lifecycle(
                            "queue.depth_changed",
                            None,
                            None,
                            LifecyclePayload {
                                count: Some(queue_population(
                                    &submissions,
                                    &priority_submissions,
                                    pending_turns.len(),
                                )),
                                ..LifecyclePayload::default()
                            },
                        );
                        TurnTrigger::Submission { queued, preprocessed: false }
                    }
                    request = control.recv() => {
                        match request {
                            Some(request) => {
                                apply_control(
                                    &mut agent,
                                    &workflows,
                                    processes.as_ref(),
                                    &operator_status,
                                    &mut side,
                                    &mut started,
                                    &mut events,
                                    request,
                                ).await;
                                operator_status.refresh_runtime(&agent);
                                continue
                            }
                            None => break,
                        }
                    }
                    // A detached run keeps emitting between turns. Without this arm its tree froze on
                    // the frame the turn ended on and only resumed when the operator typed again —
                    // "the run is invisible while it is the only thing happening", which is precisely
                    // the state detaching would otherwise create.
                    Some(progress) = workflow_rx.recv() => {
                        publish_workflow_progress(&mut events, progress).await;
                        continue
                    }
                    Some(settled) = settled_rx.recv() => {
                        TurnTrigger::Runtime(publish_settled(&mut events, settled).await)
                    }
                    queued = submissions.recv() => {
                        match queued {
                            Some(queued) => {
                                events.record_lifecycle(
                                    "queue.depth_changed",
                                    None,
                                    None,
                                    LifecyclePayload {
                                        count: Some(queue_population(
                                            &submissions,
                                            &priority_submissions,
                                            pending_turns.len(),
                                        )),
                                        ..LifecyclePayload::default()
                                    },
                                );
                                TurnTrigger::Submission { queued, preprocessed: false }
                            }
                            None => break,
                        }
                    }
                }
            };
            let (input, runtime_follow_up, turn_submission_id) = match trigger {
                TurnTrigger::Runtime(notification) => (RunInput::Text(notification), true, None),
                TurnTrigger::Submission {
                    queued,
                    preprocessed,
                } => {
                    let envelope = queued.into_envelope();
                    let version = envelope.protocol_version;
                    let submission_id = envelope.submission_id;
                    let Ok((_, op)) = envelope.into_current_identified() else {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("protocol_version_mismatch"),
                        )
                        .await;
                        let _ = events.publish(ServerEvent::Notice(format!(
                            "a submission arrived stamped protocol v{version}; this runtime speaks v{PROTOCOL_VERSION} and discarded it"
                        ))).await;
                        continue;
                    };
                    if !preprocessed
                        && reject_replayed_submission(
                            &mut events,
                            &mut submission_identities,
                            submission_id,
                            None,
                        )
                        .await
                    {
                        continue;
                    }
                    publish_submission(
                        &mut events,
                        submission_id,
                        SubmissionLifecycleState::Received,
                        None,
                    )
                    .await;
                    if !preprocessed
                        && let Some(context) = legacy_user_prompt_context(&op, submission_id)
                    {
                        run_legacy_hook(
                            HookExecution {
                                hooks: &lifecycle_gate_hooks,
                                journal: hook_journal.as_ref(),
                                events: &events,
                                cancel: hook_cancel.as_deref(),
                                drain: Some(drain_signal.as_ref()),
                            },
                            crate::runtime::hooks::HookEvent::UserPromptSubmit,
                            Some(submission_id),
                            None,
                            context,
                        )
                        .await;
                    }
                    let gate_event = match &op {
                        Op::Steer { .. } => Some("steer.requested"),
                        Op::UserInput { .. } | Op::UserInputV2 { .. } | Op::UserInputV3 { .. } => {
                            Some("submission.created")
                        }
                        Op::ApprovalResponse { .. }
                        | Op::Interrupt
                        | Op::ForceCancel
                        | Op::Drain
                        | Op::Unknown => None,
                    };
                    if !preprocessed
                        && let Some(gate_event) = gate_event
                        && let Err(reason) = run_lifecycle_gate(
                            HookExecution {
                                hooks: &lifecycle_gate_hooks,
                                journal: hook_journal.as_ref(),
                                events: &events,
                                cancel: hook_cancel.as_deref(),
                                drain: Some(drain_signal.as_ref()),
                            },
                            gate_event,
                            submission_id,
                            None,
                        )
                        .await
                    {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("hook_blocked"),
                        )
                        .await;
                        let _ = events.publish(ServerEvent::Notice(reason)).await;
                        continue;
                    }
                    if matches!(op, Op::Interrupt | Op::ForceCancel) {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("no_active_turn"),
                        )
                        .await;
                        continue;
                    }
                    match route(&op) {
                        Routed::Refuse(why) => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Rejected,
                                Some("unsupported_operation"),
                            )
                            .await;
                            let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                            continue;
                        }
                        Routed::ToKernel => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Rejected,
                                Some("no_active_turn"),
                            )
                            .await;
                            continue;
                        }
                        Routed::StartTurn(input) => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Admitted,
                                None,
                            )
                            .await;
                            (input, false, Some(submission_id))
                        }
                    }
                }
            };
            if let Some(submission_id) = turn_submission_id {
                publish_submission(
                    &mut events,
                    submission_id,
                    SubmissionLifecycleState::Applied,
                    None,
                )
                .await;
            }
            if !started && !runtime_follow_up {
                let title = first_prompt_title(&input);
                if !title.is_empty() {
                    events.record_lifecycle(
                        "session.title_selected",
                        None,
                        turn_submission_id,
                        LifecyclePayload {
                            count: Some(u64::try_from(title.chars().count()).unwrap_or(u64::MAX)),
                            magnitude: Some(u64::try_from(title.len()).unwrap_or(u64::MAX)),
                            ..LifecyclePayload::default()
                        },
                    );
                }
            }
            session_lifecycle = session_lifecycle
                .transition(SessionLifecycleState::Running)
                .expect("only an idle session admits a turn");
            let live_turn_id = agent.current_turn_id();
            let mut run_lifecycle = RunLifecycleState::Created;
            run_lifecycle = run_lifecycle
                .transition(RunLifecycleState::Admitted)
                .expect("a created run is admitted before activation");
            run_lifecycle = run_lifecycle
                .transition(RunLifecycleState::Active)
                .expect("an admitted run starts exactly once");
            let mut turn_lifecycle = TurnLifecycleState::Received;
            turn_lifecycle = turn_lifecycle
                .transition(TurnLifecycleState::Admitted)
                .expect("a received turn is admitted before it runs");
            turn_lifecycle = turn_lifecycle
                .transition(TurnLifecycleState::Running)
                .expect("an admitted turn starts exactly once");
            let mut cancel_forwarded = false;
            let mut cancel_submission_id = None;
            let mut drain_submission_id = None;
            let mut drain_admission_closed = false;
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
                            settle_kernel_submission_events(
                                &mut events,
                                &mut pending_kernel_submissions,
                                &ui,
                            ).await;
                            if events.publish(ServerEvent::Ui(ui)).await.is_err() {
                                // The frontend is gone. Keep the turn running to its own
                                // safe point rather than dropping the future mid-effect.
                            }
                        }
                        Some(progress) = workflow_rx.recv() => {
                            // Same policy as the UI stream: a frontend that hung up never
                            // aborts a run that is already executing.
                            publish_workflow_progress(&mut events, progress).await;
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
                                apply_immediate_control(
                                    &workflows,
                                    processes.as_ref(),
                                    mcp_runtime.as_ref(),
                                    &operator_status,
                                    &events,
                                    request,
                                ).await;
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
                        Some(queued) = receive_next_submission(
                            &mut priority_submissions,
                            &mut submissions,
                        ) => {
                            events.record_lifecycle(
                                "queue.depth_changed",
                                Some(live_turn_id),
                                None,
                                LifecyclePayload {
                                    count: Some(queue_population(
                                        &submissions,
                                        &priority_submissions,
                                        pending_turns.len(),
                                    )),
                                    ..LifecyclePayload::default()
                                },
                            );
                            let version = queued.envelope.protocol_version;
                            let submission_id = queued.envelope.submission_id;
                            if version != PROTOCOL_VERSION {
                                publish_submission(
                                    &mut events,
                                    submission_id,
                                    SubmissionLifecycleState::Rejected,
                                    Some("protocol_version_mismatch"),
                                ).await;
                                continue;
                            }
                                if reject_replayed_submission(
                                    &mut events,
                                    &mut submission_identities,
                                    submission_id,
                                    Some(live_turn_id),
                                ).await {
                                    continue;
                                }
                                publish_submission(
                                    &mut events,
                                    submission_id,
                                    SubmissionLifecycleState::Received,
                                    None,
                                ).await;
                                let op = &queued.envelope.op;
                                if drain_admission_closed
                                    && matches!(
                                        op,
                                        Op::UserInput { .. }
                                            | Op::UserInputV2 { .. }
                                            | Op::UserInputV3 { .. }
                                    )
                                {
                                    publish_submission(
                                        &mut events,
                                        submission_id,
                                        SubmissionLifecycleState::Expired,
                                        Some("drain_requested"),
                                    )
                                    .await;
                                    continue;
                                }
                                if let Some(context) = legacy_user_prompt_context(op, submission_id) {
                                    run_legacy_hook(
                                        HookExecution {
                                            hooks: &lifecycle_gate_hooks,
                                            journal: hook_journal.as_ref(),
                                            events: &events,
                                            cancel: hook_cancel.as_deref(),
                                            drain: Some(drain_signal.as_ref()),
                                        },
                                        crate::runtime::hooks::HookEvent::UserPromptSubmit,
                                        Some(submission_id),
                                        Some(live_turn_id),
                                        context,
                                    ).await;
                                }
                                let gate_event = match &op {
                                    Op::Steer { .. } => Some("steer.requested"),
                                    Op::UserInput { .. }
                                    | Op::UserInputV2 { .. }
                                    | Op::UserInputV3 { .. } => Some("submission.created"),
                                    Op::ApprovalResponse { .. }
                                    | Op::Interrupt
                                    | Op::ForceCancel
                                    | Op::Drain
                                    | Op::Unknown => None,
                                };
                                if let Some(gate_event) = gate_event
                                    && let Err(reason) = run_lifecycle_gate(
                                        HookExecution {
                                            hooks: &lifecycle_gate_hooks,
                                            journal: hook_journal.as_ref(),
                                            events: &events,
                                            cancel: hook_cancel.as_deref(),
                                            drain: Some(drain_signal.as_ref()),
                                        },
                                        gate_event,
                                        submission_id,
                                        Some(live_turn_id),
                                    ).await
                                {
                                        publish_submission(
                                            &mut events,
                                            submission_id,
                                            SubmissionLifecycleState::Rejected,
                                            Some("hook_blocked"),
                                        ).await;
                                        if matches!(op, Op::Steer { .. }) {
                                            events.record_lifecycle(
                                                "steer.rejected",
                                                Some(live_turn_id),
                                                Some(submission_id),
                                                LifecyclePayload {
                                                    reason_code: Some("hook_blocked".into()),
                                                    ..LifecyclePayload::default()
                                                },
                                            );
                                        }
                                        let _ = events.publish(ServerEvent::Notice(reason)).await;
                                        continue;
                                }
                                match &op {
                                    Op::Interrupt => events.record_lifecycle(
                                        "cancel.received",
                                        Some(live_turn_id),
                                        Some(submission_id),
                                        LifecyclePayload::default(),
                                    ),
                                    Op::ForceCancel => events.record_lifecycle(
                                        "cancel.forced",
                                        Some(live_turn_id),
                                        Some(submission_id),
                                        LifecyclePayload::default(),
                                    ),
                                    Op::Drain => {
                                        drain_admission_closed = true;
                                        drain_signal.store(true, Ordering::SeqCst);
                                        events.record_lifecycle(
                                            "drain.requested",
                                            Some(live_turn_id),
                                            Some(submission_id),
                                            LifecyclePayload::default(),
                                        );
                                    }
                                    _ => {}
                                }
                                match route(op) {
                                    Routed::StartTurn(_) => {
                                        publish_submission(
                                            &mut events,
                                            submission_id,
                                            SubmissionLifecycleState::Requeued,
                                            Some("turn_safe_point"),
                                        ).await;
                                        publish_submission(
                                            &mut events,
                                            submission_id,
                                            SubmissionLifecycleState::Enqueued,
                                            None,
                                        ).await;
                                        pending_turns.push_back(queued);
                                    }
                                    Routed::ToKernel => {
                                        let envelope = queued.into_envelope();
                                        let (_, op) = envelope
                                            .into_current_identified()
                                            .expect("the protocol version was checked above");
                                        publish_submission(
                                            &mut events,
                                            submission_id,
                                            SubmissionLifecycleState::Admitted,
                                            None,
                                        ).await;
                                        let kind = kernel_submission_kind(&op);
                                        let forced = matches!(op, Op::ForceCancel);
                                        if to_kernel.send(SqEnvelope::with_version_and_id(version, submission_id, op)).is_err() {
                                            publish_submission(
                                                &mut events,
                                                submission_id,
                                                SubmissionLifecycleState::Rejected,
                                                Some("runtime_disconnected"),
                                            ).await;
                                            match kind {
                                                Some(KernelSubmissionKind::Steer) => events.record_lifecycle(
                                                    "steer.rejected",
                                                    Some(live_turn_id),
                                                    Some(submission_id),
                                                    LifecyclePayload {
                                                        reason_code: Some("runtime_disconnected".into()),
                                                        ..LifecyclePayload::default()
                                                    },
                                                ),
                                                Some(KernelSubmissionKind::Interrupt) => events.record_lifecycle(
                                                    "cancel.failed",
                                                    Some(live_turn_id),
                                                    Some(submission_id),
                                                    LifecyclePayload {
                                                        reason_code: Some("runtime_disconnected".into()),
                                                        ..LifecyclePayload::default()
                                                    },
                                                ),
                                                _ => {}
                                            }
                                        } else if let Some(kind) = kind {
                                            // The ordered SQ receipt is the typed cancellation
                                            // authority, but the kernel cannot drain that queue
                                            // while it is awaiting provider I/O. Raise the exact
                                            // session-owned signal only after the receipt reaches
                                            // the kernel queue so headless clients get the same
                                            // bounded wake-up as the TUI's eager keyboard path.
                                            if matches!(kind, KernelSubmissionKind::Interrupt)
                                                && let Some(interrupt) = &hook_cancel
                                            {
                                                interrupt.store(true, Ordering::SeqCst);
                                            }
                                            match kind {
                                                KernelSubmissionKind::Steer => events.record_lifecycle(
                                                    "steer.admitted",
                                                    Some(live_turn_id),
                                                    Some(submission_id),
                                                    LifecyclePayload::default(),
                                                ),
                                                KernelSubmissionKind::Interrupt => {
                                                    cancel_forwarded = true;
                                                    cancel_submission_id = Some(submission_id);
                                                    if !forced {
                                                        events.record_lifecycle(
                                                            "cancel.cooperative",
                                                            Some(live_turn_id),
                                                            Some(submission_id),
                                                            LifecyclePayload::default(),
                                                        );
                                                    }
                                                }
                                                KernelSubmissionKind::Drain => {
                                                    drain_submission_id = Some(submission_id);
                                                }
                                                KernelSubmissionKind::Approval => {}
                                            }
                                            pending_kernel_submissions.push_back(PendingKernelSubmission { id: submission_id, kind });
                                            if matches!(kind, KernelSubmissionKind::Drain) {
                                                expire_pending_turns(
                                                    &mut events,
                                                    &mut pending_turns,
                                                    "drain_requested",
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                    Routed::Refuse(why) => {
                                        publish_submission(
                                            &mut events,
                                            submission_id,
                                            SubmissionLifecycleState::Rejected,
                                            Some("unsupported_operation"),
                                        ).await;
                                        let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
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
                settle_kernel_submission_events(&mut events, &mut pending_kernel_submissions, &ui)
                    .await;
                let _ = events.publish(ServerEvent::Ui(ui)).await;
            }
            // The workflow seam drains with it: an in-turn run settles inside the turn, so
            // its terminal rows and its `Finished` are queued here exactly like the last
            // text deltas, and a tail that skipped them would leave the tree spinning.
            while let Ok(progress) = workflow_rx.try_recv() {
                publish_workflow_progress(&mut events, progress).await;
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
                    &operator_status,
                    &mut side,
                    &mut started,
                    &mut events,
                    request,
                )
                .await;
            }
            operator_status.refresh_runtime(&agent);

            let mut snapshot = snapshot_of(&mut agent);
            settle_kernel_submissions_at_turn_end(
                &mut events,
                &mut pending_kernel_submissions,
                snapshot.unadmitted_steers.len(),
            )
            .await;
            snapshot.unadmitted_steers.retain(|text| {
                if text.starts_with(crate::runtime::RUNTIME_NOTIFICATION_PREFIX) {
                    pending_runtime.push_back(text.clone());
                    false
                } else {
                    true
                }
            });
            let (outcome, mut error) = match completion {
                Ok(outcome) => (outcome, None),
                Err(error) => {
                    let error = error.public_summary();
                    (Outcome::HarnessError, Some(error))
                }
            };
            let drain_cleanup_failures = if matches!(outcome, Outcome::Drained) {
                clean_session_owned_tools(processes.as_ref(), language_servers.as_ref()).await
            } else {
                Vec::new()
            };
            if !drain_cleanup_failures.is_empty() {
                let detail = drain_cleanup_failures.join("; ");
                error = Some(match error {
                    Some(existing) => format!("{existing}; {detail}"),
                    None => detail,
                });
            }
            if matches!(outcome, Outcome::Drained) {
                expire_pending_turns(&mut events, &mut pending_turns, "drain_settled").await;
                expire_queued_after_drain(&mut events, &mut submissions, &mut priority_submissions)
                    .await;
            }
            turn_lifecycle = match &outcome {
                Outcome::Done => {
                    if cancel_forwarded {
                        events.record_lifecycle(
                            "cancel.failed",
                            Some(live_turn_id),
                            cancel_submission_id,
                            LifecyclePayload {
                                reason_code: Some("turn_completed_first".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                    }
                    turn_lifecycle
                        .transition(TurnLifecycleState::Completed)
                        .expect("running turn completes once")
                }
                Outcome::Interrupted => {
                    session_lifecycle = session_lifecycle
                        .transition(SessionLifecycleState::Cancelling)
                        .expect("an interrupted running session enters cancelling");
                    events.record_lifecycle(
                        "cancel.completed",
                        Some(live_turn_id),
                        cancel_submission_id,
                        LifecyclePayload::default(),
                    );
                    turn_lifecycle
                        .transition(TurnLifecycleState::Cancelling)
                        .and_then(|state| state.transition(TurnLifecycleState::Interrupted))
                        .expect("a running turn cancels exactly once")
                }
                Outcome::Drained => {
                    session_lifecycle = session_lifecycle
                        .transition(SessionLifecycleState::Draining)
                        .expect("a drained running session enters draining");
                    events.record_lifecycle(
                        "drain.settled",
                        Some(live_turn_id),
                        drain_submission_id,
                        LifecyclePayload {
                            count: (!drain_cleanup_failures.is_empty())
                                .then_some(drain_cleanup_failures.len() as u64),
                            reason_code: (!drain_cleanup_failures.is_empty())
                                .then(|| "owned_tool_cleanup_unknown".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    turn_lifecycle
                        .transition(TurnLifecycleState::Cancelling)
                        .and_then(|state| state.transition(TurnLifecycleState::Interrupted))
                        .expect("a drained turn interrupts exactly once")
                }
                Outcome::Stuck | Outcome::BudgetExhausted(_) | Outcome::HarnessError => {
                    if cancel_forwarded {
                        events.record_lifecycle(
                            "cancel.failed",
                            Some(live_turn_id),
                            cancel_submission_id,
                            LifecyclePayload {
                                reason_code: Some("turn_failed".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                        turn_lifecycle = turn_lifecycle
                            .transition(TurnLifecycleState::Cancelling)
                            .expect("a cancellation was forwarded before failure");
                    }
                    turn_lifecycle
                        .transition(TurnLifecycleState::Failed)
                        .expect("running turn fails once")
                }
            };
            run_lifecycle = match &outcome {
                Outcome::Done => run_lifecycle
                    .transition(RunLifecycleState::Completed)
                    .expect("active run completes once"),
                Outcome::Interrupted | Outcome::Drained => run_lifecycle
                    .transition(RunLifecycleState::Cancelling)
                    .and_then(|state| state.transition(RunLifecycleState::Interrupted))
                    .expect("active run interrupts once"),
                Outcome::Stuck | Outcome::BudgetExhausted(_) | Outcome::HarnessError => {
                    if cancel_forwarded {
                        run_lifecycle = run_lifecycle
                            .transition(RunLifecycleState::Cancelling)
                            .expect("a cancellation was forwarded before run failure");
                    }
                    run_lifecycle
                        .transition(RunLifecycleState::Failed)
                        .expect("active run fails once")
                }
            };
            debug_assert!(turn_lifecycle.is_terminal());
            debug_assert!(run_lifecycle.is_terminal());
            session_lifecycle = session_lifecycle
                .transition(SessionLifecycleState::Idle)
                .expect("a terminal turn returns its session to idle");
            events.record_lifecycle(
                "session.idle",
                Some(live_turn_id),
                turn_submission_id,
                LifecyclePayload {
                    outcome_code: Some(outcome_name(&outcome).into()),
                    ..LifecyclePayload::default()
                },
            );
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
                events.record_lifecycle(
                    "session.failed",
                    Some(live_turn_id),
                    turn_submission_id,
                    LifecyclePayload {
                        reason_code: Some("terminal_event_delivery_closed".into()),
                        ..LifecyclePayload::default()
                    },
                );
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
        // stopped together with the `iteron workflow resume` that continues it.
        //
        // This runs on EVERY exit from the loop above, which is what makes "the session cannot end
        // with a run it does not account for" a property of the type rather than of a call site.
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Stopping)
            .unwrap_or(SessionLifecycleState::Stopping);
        events.record_lifecycle("session.stopping", None, None, LifecyclePayload::default());
        let mut report = workflows
            .shutdown(
                &mut settled_rx,
                iteron_tunables::param_duration(
                    "cli.workflow.shutdown_grace",
                    crate::workflow::SHUTDOWN_GRACE,
                ),
            )
            .await;
        report
            .lines
            .extend(clean_session_owned_tools(processes.as_ref(), language_servers.as_ref()).await);
        if let Some(mut side) = side.take()
            && let Err(error) = side.finalize_policy_run()
        {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("side_policy_run_terminal_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report.lines.push(error.public_summary());
        }
        if let Err(error) = agent.finalize_policy_run() {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("policy_run_terminal_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report.lines.push(error.public_summary());
        }
        if agent.has_memory_benchmark_scope() {
            events.record_lifecycle(
                "memory.benchmark.scope_destroyed",
                None,
                None,
                LifecyclePayload::default(),
            );
        }
        if agent
            .cleanup_mcp_spills(iteron_mcp::McpSpillCleanup::SessionEnd)
            .await
            .is_err()
        {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("mcp_private_spill_cleanup_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report
                .lines
                .push("private MCP spill cleanup failed at session end".into());
        }
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Stopped)
            .expect("a stopping session publishes one terminal");
        debug_assert!(session_lifecycle.is_terminal());
        events.record_lifecycle("session.stopped", None, None, LifecyclePayload::default());
        drop(events.lifecycle_hooks.take());
        if tokio::time::timeout(
            iteron_tunables::param_duration(
                "cli.app_server.lifecycle_hook_drain_grace",
                LIFECYCLE_HOOK_DRAIN_GRACE,
            ),
            &mut lifecycle_hook_task,
        )
        .await
        .is_err()
        {
            lifecycle_hook_task.abort();
            let _ = lifecycle_hook_task.await;
        }
        report
    }
}

/// Settle every persistent tool owner captured from this session's registry.
///
/// Success is intentionally silent. Returned lines are bounded, content-free failure summaries
/// suitable for the terminal shutdown report; process commands and LSP workspace paths never
/// cross this seam.
async fn clean_session_owned_tools(
    processes: Option<&iteron_tools::ProcessControl>,
    language_servers: Option<&iteron_tools::LspControl>,
) -> Vec<String> {
    let mut failures = Vec::with_capacity(2);
    if let Some(processes) = processes
        && let Err(error) = processes.clean().await
    {
        failures.push(if error.unknown {
            "persistent process cleanup outcome is unknown".to_owned()
        } else {
            "persistent process cleanup failed before full reconciliation".to_owned()
        });
    }
    if let Some(language_servers) = language_servers {
        let unconfirmed = language_servers
            .clean()
            .await
            .into_iter()
            .filter(|(_, confirmed)| !confirmed)
            .count();
        if unconfirmed > 0 {
            failures.push(format!(
                "{unconfirmed} language-server cleanup outcome(s) are unknown"
            ));
        }
    }
    failures
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Done => "done",
        Outcome::Drained => "drained",
        Outcome::Interrupted => "interrupted",
        Outcome::Stuck => "stuck",
        Outcome::BudgetExhausted(_) => "budget_exhausted",
        Outcome::HarnessError => "harness_error",
    }
}

fn first_prompt_title(input: &RunInput) -> String {
    let text = match input {
        RunInput::Text(text) | RunInput::Files { text, .. } => text.as_str(),
        RunInput::Content(segments) => segments.text(),
    };
    iteron_record::session::title_from_text(text)
}

async fn settle_kernel_submission_events(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<PendingKernelSubmission>,
    event: &UiEvent,
) {
    let UiEvent::SteerApplied { count } = event else {
        return;
    };
    for _ in 0..*count {
        let Some(index) = pending
            .iter()
            .position(|entry| entry.kind == KernelSubmissionKind::Steer)
        else {
            break;
        };
        let entry = pending
            .remove(index)
            .expect("position came from this queue");
        publish_submission(events, entry.id, SubmissionLifecycleState::Applied, None).await;
    }
}

async fn settle_kernel_submissions_at_turn_end(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<PendingKernelSubmission>,
    mut unadmitted_steers: usize,
) {
    while let Some(entry) = pending.pop_front() {
        let (state, reason) = match entry.kind {
            KernelSubmissionKind::Steer if unadmitted_steers > 0 => {
                unadmitted_steers -= 1;
                (
                    SubmissionLifecycleState::Requeued,
                    Some("safe_point_missed"),
                )
            }
            KernelSubmissionKind::Steer => (
                SubmissionLifecycleState::Rejected,
                Some("application_unconfirmed"),
            ),
            KernelSubmissionKind::Interrupt
            | KernelSubmissionKind::Drain
            | KernelSubmissionKind::Approval => (SubmissionLifecycleState::Applied, None),
        };
        publish_submission(events, entry.id, state, reason).await;
    }
}

async fn publish_submission(
    events: &mut EventPublisher,
    id: SubmissionId,
    state: SubmissionLifecycleState,
    reason_code: Option<&'static str>,
) {
    events.record_submission_lifecycle(id, state, reason_code);
    let _ = events
        .publish(ServerEvent::Submission {
            id,
            state,
            reason_code,
        })
        .await;
}

async fn receive_next_submission(
    priority: &mut mpsc::Receiver<QueuedSubmission>,
    data: &mut mpsc::Receiver<QueuedSubmission>,
) -> Option<QueuedSubmission> {
    loop {
        let priority_done = priority.is_closed() && priority.is_empty();
        let data_done = data.is_closed() && data.is_empty();
        if priority_done && data_done {
            return None;
        }
        tokio::select! {
            biased;
            queued = priority.recv(), if !priority_done => {
                if queued.is_some() {
                    return queued;
                }
            }
            queued = data.recv(), if !data_done => {
                if queued.is_some() {
                    return queued;
                }
            }
        }
    }
}

fn queue_population(
    data: &mpsc::Receiver<QueuedSubmission>,
    priority: &mpsc::Receiver<QueuedSubmission>,
    pending_turns: usize,
) -> u64 {
    u64::try_from(
        data.len()
            .saturating_add(priority.len())
            .saturating_add(pending_turns),
    )
    .unwrap_or(u64::MAX)
}

async fn expire_pending_turns(
    events: &mut EventPublisher,
    pending: &mut std::collections::VecDeque<QueuedSubmission>,
    reason: &'static str,
) {
    while let Some(queued) = pending.pop_front() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some(reason),
        )
        .await;
    }
}

async fn expire_queued_after_drain(
    events: &mut EventPublisher,
    data: &mut mpsc::Receiver<QueuedSubmission>,
    priority: &mut mpsc::Receiver<QueuedSubmission>,
) {
    while let Ok(queued) = priority.try_recv() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some("drain_settled"),
        )
        .await;
    }
    while let Ok(queued) = data.try_recv() {
        publish_submission(
            events,
            queued.envelope.submission_id,
            SubmissionLifecycleState::Expired,
            Some("drain_settled"),
        )
        .await;
    }
}

async fn reject_replayed_submission(
    events: &mut EventPublisher,
    identities: &mut SubmissionDeduplicator,
    id: SubmissionId,
    turn_id: Option<TurnId>,
) -> bool {
    let admission = identities.admit(id);
    let (event_id, reason) = match admission {
        SubmissionIdentityAdmission::Fresh => return false,
        SubmissionIdentityAdmission::Duplicate => ("submission.deduplicated", "duplicate_id"),
        SubmissionIdentityAdmission::Stale => ("control.stale_rejected", "stale_id"),
    };
    events.record_lifecycle(
        event_id,
        turn_id,
        Some(id),
        LifecyclePayload {
            reason_code: Some(reason.into()),
            ..LifecyclePayload::default()
        },
    );
    publish_submission(events, id, SubmissionLifecycleState::Rejected, Some(reason)).await;
    true
}

#[derive(Clone, Copy)]
struct HookExecution<'a> {
    hooks: &'a crate::runtime::hooks::Hooks,
    journal: Option<&'a crate::runtime::hooks::journal::HookEffectJournal>,
    events: &'a EventPublisher,
    cancel: Option<&'a AtomicBool>,
    drain: Option<&'a AtomicBool>,
}

async fn run_lifecycle_gate(
    execution: HookExecution<'_>,
    event_id: &'static str,
    submission_id: SubmissionId,
    turn_id: Option<TurnId>,
) -> Result<(), String> {
    let HookExecution {
        hooks,
        journal,
        events,
        cancel,
        drain,
    } = execution;
    if hooks.is_empty_for_lifecycle(event_id) {
        return Ok(());
    }
    let journal = journal.ok_or_else(|| {
        "hook gate failed closed because its durable journal is unavailable".to_string()
    })?;
    let context = serde_json::json!({
        "catalog_version": iteron_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION.0,
        "event_id": event_id,
        "submission_id": submission_id.0,
        "turn_id": turn_id.map(|turn| turn.0),
    })
    .to_string();
    let report = hooks
        .run_lifecycle_cancellable_journaled(event_id, &context, cancel, drain, journal)
        .await
        .map_err(str::to_owned)?;
    events.record_lifecycle(
        "hook.matched",
        turn_id,
        Some(submission_id),
        LifecyclePayload {
            count: Some(u64::from(report.matched)),
            ..LifecyclePayload::default()
        },
    );
    events.record_lifecycle(
        "hook.started",
        turn_id,
        Some(submission_id),
        LifecyclePayload::default(),
    );
    if report.timed_out > 0 {
        events.record_lifecycle(
            "hook.timed_out",
            turn_id,
            Some(submission_id),
            LifecyclePayload {
                count: Some(u64::from(report.timed_out)),
                ..LifecyclePayload::default()
            },
        );
    }
    if report.failed > 0 {
        events.record_lifecycle(
            "hook.failed",
            turn_id,
            Some(submission_id),
            LifecyclePayload {
                count: Some(u64::from(report.failed)),
                ..LifecyclePayload::default()
            },
        );
    }
    match report.decision {
        crate::runtime::hooks::HookDecision::Allow => {
            events.record_lifecycle(
                "hook.completed",
                turn_id,
                Some(submission_id),
                LifecyclePayload {
                    count: Some(u64::from(report.completed)),
                    ..LifecyclePayload::default()
                },
            );
            Ok(())
        }
        crate::runtime::hooks::HookDecision::Deny(reason) => {
            events.record_lifecycle(
                "hook.blocked",
                turn_id,
                Some(submission_id),
                LifecyclePayload::default(),
            );
            Err(reason)
        }
    }
}

/// Run a compatibility hook once, outside the canonical lifecycle dispatcher. These names remain
/// supported for existing operator configuration, but never alias into canonical subscriptions:
/// doing both here is what previously double-ran `session.idle` and `tool.call_completed` hooks.
async fn run_legacy_hook(
    execution: HookExecution<'_>,
    event: crate::runtime::hooks::HookEvent,
    submission_id: Option<SubmissionId>,
    turn_id: Option<TurnId>,
    context: String,
) {
    let HookExecution {
        hooks,
        journal,
        events,
        cancel,
        drain,
    } = execution;
    if hooks.is_empty_for(event) {
        return;
    }
    let Some(journal) = journal else {
        events.record_lifecycle(
            "hook.failed",
            turn_id,
            submission_id,
            LifecyclePayload {
                reason_code: Some("durable_journal_unavailable".into()),
                ..LifecyclePayload::default()
            },
        );
        return;
    };
    events.record_lifecycle(
        "hook.matched",
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
    events.record_lifecycle(
        "hook.started",
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
    let decision = hooks
        .run_cancellable_journaled(event, &context, cancel, drain, journal)
        .await;
    let outcome = if matches!(decision, crate::runtime::hooks::HookDecision::Deny(_)) {
        "blocked"
    } else {
        "completed"
    };
    events.record_lifecycle(
        if outcome == "blocked" {
            "hook.blocked"
        } else {
            "hook.completed"
        },
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
}

/// Preserve the text compatibility hooks historically received without copying encoded image
/// payloads or file contents into a command's stdin. Attachment counts are sufficient context for
/// the old hook surface; canonical hooks use the structured lifecycle envelope.
fn legacy_user_prompt_context(op: &Op, submission_id: SubmissionId) -> Option<String> {
    let (prompt, image_count, file_count) = match op {
        Op::UserInput { text } => (text.as_str(), 0usize, 0usize),
        Op::UserInputV2 { segments } => {
            let prompt = segments
                .as_slice()
                .iter()
                .find_map(|segment| match segment {
                    iteron_protocol::ContentSegment::Text { text } => Some(text.as_str()),
                    iteron_protocol::ContentSegment::Image { .. }
                    | iteron_protocol::ContentSegment::Unknown => None,
                })?;
            let images = segments
                .as_slice()
                .iter()
                .filter(|segment| matches!(segment, iteron_protocol::ContentSegment::Image { .. }))
                .count();
            (prompt, images, 0)
        }
        Op::UserInputV3 {
            text,
            images,
            files,
        } => (text.as_str(), images.len(), files.len()),
        Op::ApprovalResponse { .. }
        | Op::Steer { .. }
        | Op::Interrupt
        | Op::ForceCancel
        | Op::Drain
        | Op::Unknown => return None,
    };
    Some(
        serde_json::json!({
            "event": "UserPromptSubmit",
            "submission_id": submission_id.0,
            "prompt": prompt,
            "image_count": image_count,
            "file_count": file_count,
        })
        .to_string(),
    )
}

/// Project workflow-engine milestones into the same canonical lifecycle stream before they reach
/// the frontend. The engine event is authoritative; this observer is bounded and cannot delay it.
async fn publish_workflow_progress(
    events: &mut EventPublisher,
    progress: crate::workflow::WorkflowRunUiEvent,
) {
    use iteron_workflow::events::{ProgressEvent, WorkflowState};

    match &progress {
        crate::workflow::WorkflowRunUiEvent::KernelActivity { kind, .. } => match kind {
            crate::workflow::KernelActivityKind::Planning => events.record_workflow_lifecycle(
                "workflow.planning_delta",
                None,
                LifecyclePayload::default(),
            ),
            crate::workflow::KernelActivityKind::Compaction => events.record_lifecycle(
                "context.compaction.started",
                None,
                None,
                LifecyclePayload::default(),
            ),
        },
        crate::workflow::WorkflowRunUiEvent::Started { run_id, .. } => {
            events.record_workflow_lifecycle(
                "workflow.run_started",
                Some(run_id),
                LifecyclePayload::default(),
            );
        }
        crate::workflow::WorkflowRunUiEvent::Progress { run_id, event } => match event {
            ProgressEvent::Phase { title, .. } => events.transition_workflow_phase(run_id, title),
            ProgressEvent::Log { .. } => events.record_workflow_lifecycle(
                "workflow.planning_delta",
                Some(run_id),
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentQueued { index, .. } => events.record_workflow_child_lifecycle(
                "workflow.child_proposed",
                run_id,
                *index,
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentStarted { index, .. } => events.record_workflow_child_lifecycle(
                "workflow.child_started",
                run_id,
                *index,
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentActivity {
                index,
                tokens,
                tool_calls,
                ..
            } => events.record_workflow_child_lifecycle(
                "workflow.child_progress",
                run_id,
                *index,
                LifecyclePayload {
                    count: Some(*tool_calls),
                    magnitude: Some(*tokens),
                    ..LifecyclePayload::default()
                },
            ),
            ProgressEvent::AgentFinished {
                index,
                state,
                tokens,
                tool_calls,
                duration_ms,
                ..
            } => events.record_workflow_child_lifecycle(
                if matches!(state, WorkflowState::Done | WorkflowState::Skipped) {
                    "workflow.child_completed"
                } else {
                    "workflow.child_failed"
                },
                run_id,
                *index,
                LifecyclePayload {
                    outcome_code: Some(
                        match state {
                            WorkflowState::Queued => "queued",
                            WorkflowState::Running => "running",
                            WorkflowState::Done => "done",
                            WorkflowState::Error => "error",
                            WorkflowState::Skipped => "skipped",
                        }
                        .into(),
                    ),
                    count: Some(*tool_calls),
                    duration_us: Some(duration_ms.saturating_mul(1_000)),
                    magnitude: Some(*tokens),
                    ..LifecyclePayload::default()
                },
            ),
        },
        crate::workflow::WorkflowRunUiEvent::Finished { run_id, terminal } => {
            events.finish_workflow_phase(run_id, *terminal);
            events.record_workflow_lifecycle(
                match terminal {
                    crate::workflow::WorkflowRunTerminal::Completed => "workflow.run_completed",
                    crate::workflow::WorkflowRunTerminal::Cancelled => "workflow.run_cancelled",
                    // The frozen catalog's resolved terminal is `run_completed`; the outcome code
                    // preserves failure without inventing a 193rd event or misclassifying it as an
                    // operator cancellation.
                    crate::workflow::WorkflowRunTerminal::Failed => "workflow.run_completed",
                },
                Some(run_id),
                LifecyclePayload {
                    outcome_code: Some(
                        match terminal {
                            crate::workflow::WorkflowRunTerminal::Completed => "completed",
                            crate::workflow::WorkflowRunTerminal::Cancelled => "cancelled",
                            crate::workflow::WorkflowRunTerminal::Failed => "failed",
                        }
                        .into(),
                    ),
                    ..LifecyclePayload::default()
                },
            );
        }
    }
    let _ = events.publish(ServerEvent::WorkflowRun(progress)).await;
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
    publish_workflow_progress(
        events,
        crate::workflow::WorkflowRunUiEvent::Finished {
            run_id,
            terminal: settled.terminal,
        },
    )
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
        + iteron_protocol::task::MAX_TASK_TEXT_BYTES
        + iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
        <= SQ_BYTE_CAPACITY
);

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(op: Op) -> SqEnvelope {
        SqEnvelope::with_version(PROTOCOL_VERSION, op)
    }

    #[test]
    fn immutable_queue_policy_changes_the_actual_wire_capacities() {
        let policy = AppServerQueuePolicy::new(
            SQ_PRIORITY_CAPACITY + 3,
            1_000_000,
            7,
            CosmeticOverflow::Drop,
            AuthoritativeOverflow::Reject,
        )
        .unwrap();
        let (handle, ends) = wire_with_queue_policy(false, policy).expect("wire");

        assert_eq!(ends.submissions.max_capacity(), 3);
        assert_eq!(
            ends.priority_submissions.max_capacity(),
            SQ_PRIORITY_CAPACITY
        );
        assert_eq!(handle.events.max_capacity(), 7);
        assert_eq!(ends.events.queue_policy, policy);
        match &handle.client.submissions {
            SubmissionSender::Weighted { budget, .. } => {
                assert_eq!(budget.available_permits(), 1_000_000)
            }
            SubmissionSender::Bare(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn immutable_overflow_policy_coalesces_cosmetic_and_rejects_authoritative() {
        let policy = AppServerQueuePolicy::new(
            SQ_PRIORITY_CAPACITY + 1,
            1_000_000,
            1,
            CosmeticOverflow::Coalesce,
            AuthoritativeOverflow::Wait,
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let mut publisher = EventPublisher::new_with_policy(
            tx,
            false,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
            policy,
        );
        publisher
            .publish(ServerEvent::Ui(UiEvent::Text("first".into())))
            .await
            .unwrap();
        publisher
            .publish(ServerEvent::Ui(UiEvent::Text("second".into())))
            .await
            .unwrap();
        publisher
            .publish(ServerEvent::Ui(UiEvent::Text("third".into())))
            .await
            .unwrap();
        let flush = tokio::spawn(async move {
            publisher
                .publish(ServerEvent::Notice("authoritative".into()))
                .await
        });
        assert!(
            matches!(rx.recv().await.unwrap().event, ServerEvent::Ui(UiEvent::Text(text)) if text == "first")
        );
        assert!(matches!(
            rx.recv().await.unwrap().event,
            ServerEvent::Lagged { dropped: 1 }
        ));
        assert!(
            matches!(rx.recv().await.unwrap().event, ServerEvent::Ui(UiEvent::Text(text)) if text == "third")
        );
        assert!(
            matches!(rx.recv().await.unwrap().event, ServerEvent::Notice(text) if text == "authoritative")
        );
        flush.await.unwrap().unwrap();

        let reject = AppServerQueuePolicy::new(
            SQ_PRIORITY_CAPACITY + 1,
            1_000_000,
            1,
            CosmeticOverflow::Drop,
            AuthoritativeOverflow::Reject,
        )
        .unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let mut publisher = EventPublisher::new_with_policy(
            tx,
            false,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
            reject,
        );
        publisher
            .publish(ServerEvent::Notice("first".into()))
            .await
            .unwrap();
        assert!(
            publisher
                .publish(ServerEvent::Notice("refused".into()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_settled_background_run_returns_one_task_notification_without_polling() {
        let (eq_tx, mut eq_rx) = mpsc::channel(4);
        let mut events = EventPublisher::new(
            eq_tx,
            true,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );
        let notification = publish_settled(
            &mut events,
            crate::workflow::RunSettled {
                run_id: "wf_done".into(),
                terminal: crate::workflow::WorkflowRunTerminal::Completed,
                notice: "workflow `wf_done` finished".into(),
                notification: "<task-notification>done</task-notification>".into(),
            },
        )
        .await;

        assert!(notification.starts_with(crate::runtime::RUNTIME_NOTIFICATION_PREFIX));
        assert!(notification.contains("<task-notification>done</task-notification>"));

        assert!(matches!(
            eq_rx.recv().await.unwrap().into_current().unwrap(),
            ServerEvent::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Finished { run_id, .. })
                if run_id == "wf_done"
        ));
        assert!(matches!(
            eq_rx.recv().await.unwrap().into_current().unwrap(),
            ServerEvent::Notice(notice) if notice.contains("finished")
        ));
    }

    #[test]
    fn only_a_workflow_activity_tick_is_droppable_under_backpressure() {
        use iteron_workflow::events::{ProgressEvent, WorkflowState};
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
                terminal: crate::workflow::WorkflowRunTerminal::Completed,
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
            mode: iteron_protocol::PermissionMode::default(),
            effort: iteron_protocol::Effort::default(),
            model: "test-model".into(),
            cost: iteron_obs::CostState::default(),
            last_turn_usage: None,
            unadmitted_steers: Vec::new(),
            permission_rules: iteron_protocol::PermissionRules::new(),
            runtime_policy: None,
            ledger_summary: String::new(),
            rate_limit: None,
            mcp_health: Vec::new(),
        })
    }

    fn terminal_summary() -> Box<TerminalSummary> {
        Box::new(TerminalSummary {
            outcome: Outcome::HarnessError,
            assistant_text: String::new(),
            run_id: "test-run".into(),
            cost: iteron_obs::CostState::Zero,
            turns: 0,
            kernel_tax: iteron_obs::KernelTax::default(),
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
            cost: iteron_obs::CostState::default(),
            turns: 1,
            kernel_tax: iteron_obs::KernelTax::default(),
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
        let (tx, _rx) = mpsc::channel::<QueuedSubmission>(SQ_DATA_CAPACITY);
        let (priority_tx, _priority_rx) = mpsc::channel::<QueuedSubmission>(SQ_PRIORITY_CAPACITY);
        let client = AppServerClient::connect_weighted(
            PROTOCOL_VERSION,
            tx,
            priority_tx,
            Arc::new(Semaphore::new(SQ_BYTE_CAPACITY)),
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        )
        .expect("handshake");
        let mut accepted = 0usize;
        for _ in 0..(SQ_CAPACITY * 4) {
            match client.submit(Op::UserInput {
                text: "next".into(),
            }) {
                Ok(()) => accepted += 1,
                Err(SubmitError::Busy) => break,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(
            accepted, SQ_DATA_CAPACITY,
            "the data lane accepted past its bound"
        );
        assert!(
            client.submit(Op::Interrupt).is_ok(),
            "control retains reserved capacity"
        );
    }

    #[test]
    fn sq_weight_counts_actual_text_and_encoded_image_bytes() {
        let segments = iteron_protocol::ContentSegments::new(vec![
            iteron_protocol::ContentSegment::Text {
                text: "describe".into(),
            },
            iteron_protocol::ContentSegment::Image {
                image: iteron_protocol::ImageContent::new(
                    iteron_protocol::ImageMediaType::Png,
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
                + iteron_protocol::task::MAX_TASK_TEXT_BYTES
                + iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
                + SQ_CONTROL_RESERVE_BYTES
        );
        assert!(
            SQ_BYTE_CAPACITY <= u32::MAX as usize,
            "tokio's weighted semaphore acquisition accepts a u32 permit count"
        );

        // File chips are charged the same way, path included, so a queue full of them is bounded
        // in bytes and not merely in entries.
        let file = iteron_protocol::FileContent::new("src/main.rs", "fn main() {}").unwrap();
        let with_files = Op::UserInputV3 {
            text: "review".into(),
            images: vec![
                iteron_protocol::ImageContent::new(
                    iteron_protocol::ImageMediaType::Png,
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
        let (priority_tx, _priority_rx) = mpsc::channel::<QueuedSubmission>(1);
        let client = AppServerClient::connect_weighted(
            PROTOCOL_VERSION,
            tx,
            priority_tx,
            budget.clone(),
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        )
        .unwrap();

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
        let mut publisher = EventPublisher::new(
            tx,
            false,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );
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
                ServerEvent::Ui(_)
                | ServerEvent::Notice(_)
                | ServerEvent::Submission { .. }
                | ServerEvent::WorkflowRun(_) => {}
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
        let mut publisher = EventPublisher::new(
            tx,
            false,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );

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
                ServerEvent::Ui(_)
                | ServerEvent::Submission { .. }
                | ServerEvent::WorkflowRun(_) => deltas += 1,
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
        let mut publisher = EventPublisher::new(
            tx,
            true,
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
        );
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
        let multimodal = iteron_protocol::ContentSegments::new(vec![
            iteron_protocol::ContentSegment::Text {
                text: "describe".into(),
            },
            iteron_protocol::ContentSegment::Image {
                image: iteron_protocol::ImageContent::new(
                    iteron_protocol::ImageMediaType::Png,
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
        let files = vec![iteron_protocol::FileContent::new("src/main.rs", "fn main() {}").unwrap()];
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
                id: iteron_protocol::SubmissionId(1),
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
        assert_eq!(ends.submissions.capacity(), SQ_DATA_CAPACITY);
        assert_eq!(ends.priority_submissions.capacity(), SQ_PRIORITY_CAPACITY);
        assert_eq!(
            ends.submissions.capacity() + ends.priority_submissions.capacity(),
            SQ_CAPACITY
        );
        // The control plane exists and is separate from the SQ. It is separate because `Op` cannot
        // express `/model`, `/effort`, `/mode` or `/compact` and this lane may not widen it.
        assert!(!handle.control.is_closed());
        let _ = envelope(Op::Interrupt);
    }

    /// A minimal provider so the control-plane test can own a real `Agent` without a network.
    #[derive(Default)]
    struct StubProvider;

    #[async_trait::async_trait]
    impl iteron_provider::Provider for StubProvider {
        async fn turn(
            &self,
            _request: &iteron_provider::TurnRequest,
            _on_item: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
        ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
            Ok(iteron_provider::TurnResult {
                blocks: vec![iteron_protocol::Block::Text {
                    text: "side reply".into(),
                }],
                stop_reason: iteron_protocol::StopReason::EndTurn,
                usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
            })
        }
    }

    fn pin_test_tunables(agent: &mut Agent, orchestrated: bool, provider_id: &str, model_id: &str) {
        const FIXED_ARTIFACT_FAMILIES: &[&str] = &[
            "hooks_map",
            "operator_prompt_stream",
            "instruction_bundle",
            "memory_corpus",
            "skill_catalog",
            "provider_model_capability_catalog",
            "mcp_topology_tool_catalog",
            "mcp_transport_selection",
            "oauth_auth_lifecycle_policy",
            "web_search_backend_catalog",
        ];
        let mut input = iteron_record::resolved_fixture::input();
        input
            .declared_values
            .retain(|value| !FIXED_ARTIFACT_FAMILIES.contains(&value.family.as_str()));
        input
            .constraint_evidence
            .retain(|value| !FIXED_ARTIFACT_FAMILIES.contains(&value.family.as_str()));

        let context_window = iteron_tunables::ResolutionValue::Integer { value: 120_000 };
        let window = input
            .declared_values
            .iter_mut()
            .find(|value| value.family == "context_window_override_reserve")
            .expect("context-window fixture value");
        let iteron_tunables::ResolutionValue::Object { fields } = &mut window.value else {
            panic!("context-window fixture stopped being an object")
        };
        fields.insert("model_window_tokens".into(), context_window.clone());
        fields.insert(
            "tool_schema_budget_tokens".into(),
            iteron_tunables::ResolutionValue::Integer { value: 20_000 },
        );
        let ceiling = input
            .constraint_evidence
            .iter_mut()
            .find(|evidence| {
                evidence.family == "context_window_override_reserve"
                    && evidence.field == "model_window_tokens"
                    && evidence.ceiling == iteron_tunables::ExternalCeiling::ProviderCapability
            })
            .expect("context-window provider ceiling");
        ceiling.value = iteron_tunables::ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(
                [context_window.clone()]
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            required_values: None,
            preferred: Some(context_window),
        };

        let graph = iteron_workflow::workflow_graph_runtime_identity();
        let workflow_graph = iteron_tunables::ResolutionValue::CatalogRef {
            catalog_id: "iteron://tunables/catalogs/workflow_graph-v1".into(),
            digest_sha256: graph.digest_sha256,
            entry_count: u64::try_from(graph.entry_count).unwrap(),
            canonical_bytes: u64::try_from(graph.canonical_bytes).unwrap(),
        };
        let environment = iteron_protocol::EnvironmentSnapshotIdentity::from_optional(None);
        let environment_value = iteron_tunables::ResolutionValue::Object {
            fields: [
                (
                    "present".into(),
                    iteron_tunables::ResolutionValue::Boolean {
                        value: environment.present,
                    },
                ),
                (
                    "digest_sha256".into(),
                    iteron_tunables::ResolutionValue::Text {
                        value: environment.digest_sha256,
                    },
                ),
                (
                    "canonical_bytes".into(),
                    iteron_tunables::ResolutionValue::Integer {
                        value: i64::try_from(environment.canonical_bytes).unwrap(),
                    },
                ),
                (
                    "trust".into(),
                    iteron_tunables::ResolutionValue::Enum {
                        value: "trusted".into(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let live_catalog = agent.agent_catalog_snapshot();
        let catalog = live_catalog.runtime_identity();
        let agent_catalog = iteron_tunables::ResolutionValue::CatalogRef {
            catalog_id: "iteron://tunables/catalogs/agent_catalog-v1".into(),
            digest_sha256: catalog.digest_sha256,
            entry_count: u64::try_from(catalog.entry_count).unwrap(),
            canonical_bytes: u64::try_from(catalog.canonical_bytes).unwrap(),
        };
        for (family, value) in [
            ("workflow_graph", workflow_graph),
            ("environment_snapshot", environment_value),
            ("agent_catalog", agent_catalog),
        ] {
            input
                .declared_values
                .iter_mut()
                .find(|candidate| candidate.family == family)
                .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
                .value = value.clone();
            for evidence in input
                .constraint_evidence
                .iter_mut()
                .filter(|evidence| evidence.family == family)
            {
                if let iteron_tunables::ConstraintValue::Domain { allowed_values, .. } =
                    &mut evidence.value
                {
                    *allowed_values = Some([value.clone()].into_iter().collect());
                }
            }
        }
        let admitted_role_routes =
            crate::runtime_tunables::execution_policy::admitted_role_model_routes(
                live_catalog.as_ref(),
                provider_id,
                model_id,
            )
            .expect("the live test catalog must resolve role-specific routes");
        let selected_route = format!("{provider_id}:{model_id}");
        let role_specific_models = iteron_tunables::ResolutionValue::Map {
            entries: admitted_role_routes
                .iter()
                .map(|(role, route)| {
                    (
                        role.clone(),
                        iteron_tunables::ResolutionValue::Enum {
                            value: route.clone(),
                        },
                    )
                })
                .collect(),
        };
        for (catalog_id, values) in [
            (
                "iteron://tunables/catalogs/agent-roles-v1",
                live_catalog
                    .defs()
                    .iter()
                    .map(|definition| definition.name.clone())
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            (
                "iteron://tunables/catalogs/model-routes-v1",
                admitted_role_routes
                    .values()
                    .cloned()
                    .chain(std::iter::once(selected_route.clone()))
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
        ] {
            let snapshot = iteron_tunables::runtime_catalog_snapshot(catalog_id, values)
                .expect("test catalog owner must publish bounded route values");
            *input
                .runtime
                .catalogs
                .iter_mut()
                .find(|catalog| catalog.catalog_id == catalog_id)
                .unwrap_or_else(|| panic!("resolved fixture omitted {catalog_id}")) = snapshot;
        }
        for (family, value) in [
            ("role_specific_model_map", role_specific_models.clone()),
            (
                "per_agent_model",
                iteron_tunables::ResolutionValue::Enum {
                    value: selected_route.clone(),
                },
            ),
        ] {
            input
                .declared_values
                .iter_mut()
                .find(|declared| declared.family == family)
                .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
                .value = value;
        }
        for evidence in &mut input.constraint_evidence {
            match evidence.family.as_str() {
                "role_specific_model_map" => {
                    let iteron_tunables::ConstraintValue::Domain { allowed_values, .. } =
                        &mut evidence.value
                    else {
                        panic!("role-specific model ceiling stopped being a domain")
                    };
                    *allowed_values = Some([role_specific_models.clone()].into_iter().collect());
                }
                "per_agent_model" => {
                    let iteron_tunables::ConstraintValue::Domain {
                        allowed_values,
                        preferred,
                        ..
                    } = &mut evidence.value
                    else {
                        panic!("per-agent model ceiling stopped being a domain")
                    };
                    let selected = iteron_tunables::ResolutionValue::Enum {
                        value: selected_route.clone(),
                    };
                    *allowed_values = Some([selected.clone()].into_iter().collect());
                    if evidence.ceiling == iteron_tunables::ExternalCeiling::ProviderCapability {
                        *preferred = Some(selected);
                    }
                }
                _ => {}
            }
        }
        if orchestrated {
            let route_topology = iteron_tunables::ResolutionValue::Enum {
                value: "orchestrated".into(),
            };
            input
                .declared_values
                .iter_mut()
                .find(|declared| declared.family == "route_topology")
                .expect("route-topology fixture value")
                .value = route_topology.clone();
            for evidence in input
                .constraint_evidence
                .iter_mut()
                .filter(|evidence| evidence.family == "route_topology")
            {
                match &mut evidence.value {
                    iteron_tunables::ConstraintValue::Domain {
                        allowed_values,
                        preferred,
                        ..
                    } => {
                        *allowed_values = Some([route_topology.clone()].into_iter().collect());
                        if preferred.is_some() {
                            *preferred = Some(route_topology.clone());
                        }
                    }
                    iteron_tunables::ConstraintValue::Exact { value } => {
                        *value = route_topology.clone();
                    }
                    iteron_tunables::ConstraintValue::UpperBound { .. } => {
                        panic!("route topology cannot have an upper-bound constraint")
                    }
                }
            }
        }
        let resolved = iteron_tunables::resolve(input)
            .expect("the production-compatible app-server fixture must resolve");
        let resolved =
            iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
                .expect("the resolver-only fixture must bind every effective fixed authority");
        agent
            .pin_resolved_tunables(Arc::new(resolved))
            .expect("the canonical resolved fixture must install before app-server execution");
        let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
            agent.tunables_checkpoint().unwrap(),
            None,
        )
        .expect("the canonical checkpoint must have an executable runtime projection")
        .core;
        agent.model_context_window = effective.model_context_window;
        agent.model_max_output_tokens = effective.request_output_cap;
        if orchestrated {
            agent
                .set_provider_controls(effective.provider_governor.controls)
                .expect("the fixture provider must attest the checkpoint-derived controls");
            agent
                .install_provider_governor(
                    effective.provider_governor.policy,
                    [format!("{provider_id}:{model_id}")],
                )
                .expect("the fixture must install one provider-governor owner before execution");
        }
    }

    fn agent_in(workspace: &std::path::Path) -> Agent {
        let rollout = iteron_record::Rollout::open(
            &workspace.join(".iteron/runs"),
            &iteron_protocol::RunId("control-plane".into()),
            iteron_protocol::TenantId::default(),
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::new(StubProvider),
            iteron_tools::Registry::coding_agent(workspace).unwrap(),
            rollout,
            "m".into(),
            "system".into(),
            iteron_protocol::Budget {
                max_turns: 4,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: 30,
                max_consecutive_tool_errors: 3,
            },
        );
        agent.workspace = workspace.to_path_buf();
        pin_test_tunables(&mut agent, false, "provider-a", "m");
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

    #[test]
    fn session_snapshot_exposes_the_exact_ordered_runtime_policy_overlay() {
        let workspace = temp_workspace("runtime-policy-overlay");
        let mut agent = agent_in(&workspace);
        agent
            .configure_initial_runtime_policy(
                iteron_protocol::Effort::Low,
                iteron_protocol::PermissionMode::Default,
                iteron_protocol::PermissionRules::new(),
            )
            .unwrap();
        agent
            .record_genesis(workspace.display().to_string(), 1, String::new(), None)
            .unwrap();
        let stale_frontend_snapshot = control::snapshot_of(&mut agent);
        let live_operator_sources = agent.operator_status_sources();
        agent
            .transition_effort(
                iteron_protocol::Effort::High,
                iteron_protocol::RuntimePolicySource::Operator,
            )
            .unwrap();
        agent.set_turn_ceiling(17).unwrap();
        let mut rules = iteron_protocol::PermissionRules::new();
        rules
            .try_set_cap(
                iteron_protocol::Capability::CodeExecuting,
                iteron_protocol::Verdict::Deny,
            )
            .unwrap();
        agent
            .transition_permission_policy(
                iteron_protocol::PermissionMode::Plan,
                rules,
                iteron_protocol::RuntimePolicySource::Operator,
            )
            .unwrap();

        let snapshot = control::snapshot_of(&mut agent);
        let overlay = snapshot
            .runtime_policy
            .expect("sealed production state has a complete overlay");
        assert_eq!(snapshot.effort, overlay.effort.value);
        assert_eq!(snapshot.mode, overlay.permission_mode.value);
        assert_eq!(overlay.max_turns.value, 17);
        assert_eq!(overlay.permission_rule_count, 1);
        assert_eq!(
            overlay.effort.observed_via,
            crate::runtime::RuntimePolicyObservation::LiveCommit
        );
        assert!(
            overlay.effort.sequence < overlay.max_turns.sequence
                && overlay.max_turns.sequence < overlay.permission_mode.sequence,
            "the overlay must preserve durable transition order"
        );
        let stale_overlay = stale_frontend_snapshot
            .runtime_policy
            .expect("genesis overlay");
        assert_eq!(stale_overlay.effort.value, iteron_protocol::Effort::Low);
        assert_eq!(stale_overlay.max_turns.value, 4);
        let live_overlay = live_operator_sources
            .snapshot()
            .runtime_policy
            .expect("captured operator source advances without the frontend cache");
        assert_eq!(live_overlay.effort.value, iteron_protocol::Effort::High);
        assert_eq!(live_overlay.max_turns.value, 17);
        assert_eq!(
            live_overlay.permission_mode.value,
            iteron_protocol::PermissionMode::Plan
        );
        let _ = std::fs::remove_dir_all(workspace);
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
        assert!(is_immediate_control(&Control::OperatorStatus));
        assert!(is_immediate_control(&Control::Mcp(McpControl::Status)));
        assert!(is_immediate_control(&Control::Mcp(McpControl::Cancel {
            server: "docs".into(),
        })));

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
        let workflows_dir = workspace.join(".iteron/runs/subagents/workflows");
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
            lifecycle: _,
            lifecycle_otel: _,
            hook_health: _,
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
                    ..
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
}

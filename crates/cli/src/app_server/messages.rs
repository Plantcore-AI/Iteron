//! Typed session observations, terminal authority and operator control contracts.

use super::{
    AssistantTextSpill, McpInputPrompt, ModelSelection, OperatorStatusSnapshot, Outcome,
    OwnedSemaphorePermit, PROTOCOL_VERSION, ProtocolVersionError, SubmissionId,
    SubmissionLifecycleState, UiEvent, plantcore,
};

/// The authoritative terminal facts needed by every non-interactive client.
///
/// Keeping this projection on the server side is what lets one-shot and headless clients remain
/// clients: neither needs to reclaim the [`Agent`] or parse `UiEvent::Done`'s debug string. The
/// current versioned result object is still constructed by `machine_projection::final_result` at the client
/// boundary.
#[derive(Debug, Clone)]
pub(crate) struct TerminalSummary {
    pub(crate) terminal: TerminalAuthority,
    /// Content-free classification supplied by the runtime. `None` is projected as unavailable,
    /// never as proof that no external effect was dispatched.
    pub(crate) terminal_evidence: Option<iteron_protocol::product_contract::TerminalEvidenceV1>,
    /// Most recent assistant turn, retained for the frozen v4-v6 projections.
    pub(crate) assistant_text: String,
    /// Run-wide schema-v7 assistant message when it differs from the final turn.
    pub(crate) v7_assistant_text: Option<String>,
    pub(crate) run_id: String,
    pub(crate) cost: iteron_obs::CostState,
    pub(crate) turns: u32,
    pub(crate) kernel_tax: iteron_obs::KernelTax,
    pub(crate) error: Option<String>,
    pub(crate) memo_hits: u64,
    pub(crate) memo_misses: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum TerminalAuthority {
    Runtime(Outcome),
    Plantcore(iteron_protocol::PlantcoreTerminalOutcome),
}

impl TerminalAuthority {
    pub(crate) fn outcome(&self) -> Outcome {
        match self {
            Self::Runtime(outcome) => outcome.clone(),
            Self::Plantcore(terminal) => terminal.outcome(),
        }
    }
}

impl TerminalSummary {
    pub(crate) fn assistant_text_for_v7(&self) -> &str {
        self.v7_assistant_text
            .as_deref()
            .unwrap_or(&self.assistant_text)
    }

    pub(crate) fn completes_assistant_stream_for_v7(&self) -> bool {
        match &self.terminal {
            TerminalAuthority::Plantcore(iteron_protocol::PlantcoreTerminalOutcome::Done(
                iteron_protocol::ProductResult::Completed { .. },
            )) => true,
            TerminalAuthority::Plantcore(_) => false,
            TerminalAuthority::Runtime(outcome) => matches!(outcome, Outcome::Done),
        }
    }

    /// Project the one terminal authority into the versioned object consumed by every sibling
    /// client. Presentation remains client-owned; outcome, exit status, and result fields do not.
    pub(crate) fn current_result(&self) -> serde_json::Value {
        let outcome = self.terminal.outcome();
        crate::machine_projection::final_result(
            &outcome,
            &self.assistant_text,
            &self.run_id,
            &self.cost,
            self.turns,
            self.kernel_tax,
            self.error.as_deref(),
        )
    }

    pub(crate) fn v7_result(&self) -> anyhow::Result<serde_json::Value> {
        match &self.terminal {
            TerminalAuthority::Plantcore(terminal) => {
                Ok(crate::machine_projection::v7_result(terminal)?)
            }
            TerminalAuthority::Runtime(outcome) => {
                let product_result = matches!(outcome, Outcome::Done).then(|| {
                    iteron_protocol::ProductResult::Completed {
                        assistant_text: self.assistant_text_for_v7().to_owned(),
                        artifacts: Vec::new(),
                    }
                });
                let terminal = match outcome {
                    Outcome::BudgetExhausted("verify_attempts") => {
                        iteron_protocol::PlantcoreTerminalOutcome::Stuck
                    }
                    _ => iteron_protocol::PlantcoreTerminalOutcome::from_runtime(
                        outcome.clone(),
                        product_result,
                    )
                    .map_err(anyhow::Error::msg)?,
                };
                Ok(crate::machine_projection::v7_result(&terminal)?)
            }
        }
    }

    pub(crate) fn result_for_schema(
        &self,
        schema_version: u32,
    ) -> anyhow::Result<serde_json::Value> {
        if schema_version == crate::machine_projection::V7_SCHEMA_VERSION {
            return self.v7_result();
        }
        let assistant_text = iteron_record::redact::scrub(&self.assistant_text);
        let error = self.error.as_deref().map(iteron_record::redact::scrub);
        let outcome = self.terminal.outcome();
        Ok(crate::machine_projection::final_result(
            &outcome,
            &assistant_text,
            &self.run_id,
            &self.cost,
            self.turns,
            self.kernel_tax,
            error.as_deref(),
        ))
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
    /// The provider half of the live route. `model` alone cannot identify a route, so a runtime
    /// failover that moved the turn to another provider was invisible to the status line: it kept
    /// rendering the route selected at init (or by the last `/model`) forever. Empty means the
    /// route is unbound and the frontend must keep whatever it already resolved.
    pub(crate) provider_id: String,
    pub(crate) cost: iteron_obs::CostState,
    pub(crate) last_turn_usage: Option<iteron_protocol::Usage>,
    pub(crate) unadmitted_steers: Vec<String>,
    /// Runtime-origin notifications reclaimed alongside user steering, kept separate so a user
    /// message with the same text prefix never acquires internal authority.
    pub(crate) unadmitted_internal_notifications: Vec<String>,
    /// Only user submissions still awaiting a safe point. Internal runtime notifications can be
    /// present in `unadmitted_steers` but must never consume a user's SQ receipt.
    pub(crate) unadmitted_client_steers: usize,
    /// Identified App Server steers among the reclaimed texts. Turn-end receipt settlement uses
    /// these exact IDs; legacy/unidentified steering never consumes an identified receipt.
    /// Positions match `unadmitted_steers`; `None` is an unidentified legacy steer.
    pub(crate) unadmitted_steer_submission_ids: Vec<Option<SubmissionId>>,
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
    /// A PlantCore resident fact kept outside the frozen CLI UI vocabulary.
    Plantcore(crate::runtime::PlantcoreUiEvent),
    /// Content-free observations from the exact committed answer/Done source, separate from
    /// runtime ownership release and advisory maintenance.
    TurnPublication(iteron_protocol::turn_publication::TurnPublicationEventV1),
    AdvisoryMaintenance(iteron_protocol::advisory_maintenance_control::MaintenanceEventV1),
    MaintenanceAvailability(
        iteron_protocol::advisory_maintenance_control::MaintenanceAvailabilityV1,
    ),
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
    /// Cosmetic updates were dropped only when a checkpoint explicitly selects the legacy Drop
    /// policy. The owner policy coalesces semantic stream bytes losslessly.
    ///
    /// Reported rather than hidden: a transcript with a silent hole in it is worse than one that
    /// says where the hole is.
    Lagged {
        dropped: usize,
    },
    /// One live update for a QuickJS workflow-script run (ADR-0001 step 1).
    ///
    /// A second payload rather than a `UiEvent` variant, because `UiEvent` is the frozen, published
    /// stream/event-queue vocabulary and `ProgressEvent` is the engine's unfrozen in-process one;
    /// see `crate::runtime::Agent::workflow_progress_tx`. Both arrive on the same EQ, so the card
    /// still lands in transcript order relative to the assistant text around it.
    WorkflowRun(crate::workflow::WorkflowRunUiEvent),
    /// Content-free live work projection. Durable `Phase` remains the replay authority.
    Activity(iteron_protocol::ActivityEvent),
    /// A 2026 server paused one tool call for bounded operator-owned input. This is not model prose
    /// and not a permission decision; only the dedicated correlated response port can answer it.
    McpInputRequested(McpInputPrompt),
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
        match self {
            Self::Ui(UiEvent::Text(_) | UiEvent::Thinking(_)) => false,
            Self::Activity(activity) => activity.state.is_terminal(),
            Self::AdvisoryMaintenance(_) | Self::MaintenanceAvailability(_) => false,
            Self::WorkflowRun(crate::workflow::WorkflowRunUiEvent::Progress {
                event: iteron_workflow::events::ProgressEvent::AgentActivity { .. },
                ..
            }) => false,
            _ => true,
        }
    }
}

/// Fixed conservative heap-accounting term. Its distinct type keeps the byte-bound proof outside
/// the learned plane while still exposing the value as a read-only census row.
pub(super) struct EnvelopeAccountingBytes(pub(super) usize);
const ENVELOPE: EnvelopeAccountingBytes = EnvelopeAccountingBytes(512);

pub(super) fn event_heap_bytes(event: &ServerEvent) -> usize {
    ENVELOPE.0.saturating_add(match event {
        ServerEvent::Ui(UiEvent::Text(text) | UiEvent::Thinking(text) | UiEvent::Notice(text)) => {
            text.len()
        }
        ServerEvent::Ui(UiEvent::ToolStart { id, name, args }) => id
            .len()
            .saturating_add(name.len())
            .saturating_add(serde_json::to_vec(args).map_or(0, |bytes| bytes.len())),
        ServerEvent::Ui(UiEvent::ToolEnd {
            id, output, diff, ..
        }) => id
            .len()
            .saturating_add(output.len())
            .saturating_add(serde_json::to_vec(diff).map_or(0, |bytes| bytes.len())),
        ServerEvent::Ui(_) => 4 * 1024,
        ServerEvent::Plantcore(_) => 64 * 1024,
        ServerEvent::RunEnded { snapshot, summary } => summary
            .assistant_text
            .len()
            .saturating_add(summary.v7_assistant_text.as_ref().map_or(0, String::len))
            .saturating_add(summary.error.as_ref().map_or(0, String::len))
            .saturating_add(snapshot.model.len())
            .saturating_add(snapshot.ledger_summary.len())
            .saturating_add(
                snapshot
                    .unadmitted_steers
                    .iter()
                    .map(String::len)
                    .sum::<usize>(),
            )
            .saturating_add(
                snapshot
                    .unadmitted_internal_notifications
                    .iter()
                    .map(String::len)
                    .sum::<usize>(),
            ),
        ServerEvent::Notice(text) => text.len(),
        ServerEvent::Submission { .. } | ServerEvent::Lagged { .. } => 128,
        ServerEvent::TurnPublication(_) => 512,
        ServerEvent::AdvisoryMaintenance(_) => 32 * 1024,
        ServerEvent::MaintenanceAvailability(_) => 1024,
        ServerEvent::WorkflowRun(_) => 64 * 1024,
        ServerEvent::Activity(_) => 512,
        ServerEvent::McpInputRequested(prompt) => prompt
            .server
            .len()
            .saturating_add(prompt.tool.len())
            .saturating_add(prompt.request_state.as_ref().map_or(0, String::len))
            .saturating_add(
                prompt
                    .fields
                    .iter()
                    .map(|field| {
                        field
                            .id
                            .len()
                            .saturating_add(field.prompt.len())
                            .saturating_add(
                                serde_json::to_vec(&field.schema).map_or(0, |bytes| bytes.len()),
                            )
                    })
                    .sum::<usize>(),
            ),
    })
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
pub(crate) enum ProviderCatalogControl {
    FirstFrame,
    Refresh,
    Retry(iteron_protocol::client_inventory::ClientModelSelectionV1),
}

pub(crate) enum Control {
    WorkspaceRewind {
        command: iteron_protocol::workspace_rewind::WorkspaceRewindCommandV1,
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    },
    SessionNavigate {
        command: iteron_protocol::session_navigation::SessionNavigationV1,
        /// Host-minted local observer cancellation. The public wire can never supply a signal.
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    },
    OrdinaryExtensions(iteron_protocol::ordinary_extension_control::OrdinaryExtensionReadV1),
    PluginManagement(iteron_protocol::plugin_control::PluginControlV1),
    ActivityCenter(iteron_protocol::activity_control::ActivityControlV1),
    /// One-time immutable PlantCore Run admission on the existing versioned control channel.
    PlantcoreRunBootstrapV1(Box<iteron_protocol::PlantcoreRunBootstrapV1>),
    /// `/status` — one content-free snapshot from the exact runtime-owned authorities.
    OperatorStatus,
    ThreadLifecycle(iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1),
    PersistentAgents(iteron_protocol::client_agent_control::ClientAgentControlV1),
    LiveWorkflow(crate::workflow::live_session::LiveWorkflowCommandV1),
    Inventory(iteron_protocol::client_inventory::ClientInventoryQueryV1),
    ProviderCatalog(ProviderCatalogControl),
    TranscriptExport(Box<super::TranscriptExportV1>),
    SelectModelV1(iteron_protocol::client_inventory::ClientModelSelectionV1),
    /// `/effort`
    SetEffort(iteron_protocol::Effort),
    /// `/mode`
    SetPermissionMode(iteron_protocol::PermissionMode),
    /// `/permissions <capability> <verdict>`
    SetCapabilityRule {
        capability: iteron_protocol::Capability,
        verdict: iteron_protocol::Verdict,
    },
    SetToolRule {
        tool: String,
        verdict: iteron_protocol::Verdict,
    },
    /// `/model` — one transaction: durable audit append, capability fields, rate-card rebind.
    SelectModel(Box<ModelSelection>),
    /// `/compact`
    Compact {
        focus: Option<String>,
    },
    /// `/budget` — read the turn ceiling, or (with `set`) move it for this session.
    TurnBudget {
        set: Option<u32>,
    },
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
    pub(crate) created_at: Option<u64>,
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

/// What a control request answers with.
#[derive(Debug)]
pub(crate) enum ControlReply {
    WorkspaceRewound(Box<WorkspaceRewound>),
    SessionNavigated(Box<NavigatedSession>),
    OrdinaryExtensions(serde_json::Value),
    PluginManagement(serde_json::Value),
    ActivityCenter(serde_json::Value),
    PlantcoreBootstrapAccepted(plantcore::PlantcoreBootstrapAccepted),
    PlantcoreProtocolError(plantcore::PlantcoreProtocolError),
    /// The current runtime state. Answers `Snapshot` and every successful mutation.
    State(Box<SessionSnapshot>),
    ThreadLifecycle(serde_json::Value),
    PersistentAgents(serde_json::Value),
    LiveWorkflow(Box<crate::workflow::live_session::LiveWorkflowReplyV1>),
    Inventory(serde_json::Value),
    ProviderCatalog(Box<crate::providers::ProviderCatalogView>),
    TranscriptExport(serde_json::Value),
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
#[derive(Debug)]
pub(crate) struct EventEnvelope {
    /// Monotonic live-delivery cursor. This is deliberately not `iteron_protocol::Seq`, which names
    /// the durable hash-chained Rollout order. Reconnect code must never conflate the two.
    pub(crate) seq: u64,
    pub(crate) protocol_version: u32,
    pub(crate) event: ServerEvent,
    pub(super) assistant_text_spill: Option<AssistantTextSpill>,
    /// Releases this envelope's EQ byte charge when every consumer is finished with it.
    pub(super) _byte_permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EventEnvelopeError {
    #[error(transparent)]
    Protocol(#[from] ProtocolVersionError),
    #[error("the bounded EQ terminal-text spool could not be read: {0}")]
    Spill(#[from] std::io::Error),
}

impl PartialEq<ProtocolVersionError> for EventEnvelopeError {
    fn eq(&self, other: &ProtocolVersionError) -> bool {
        matches!(self, Self::Protocol(error) if error == other)
    }
}

impl EventEnvelope {
    /// The live-delivery cursor used to reject duplicate or reordered EQ frames.
    pub(crate) fn sequence(&self) -> u64 {
        self.seq
    }

    /// Unwrap an event the frontend's negotiated protocol can render. Mirrors
    /// `TurnSubmission::into_current`: the version travels with the payload, so a server that started
    /// emitting a newer shape mid-session is caught at the point of use rather than assumed away by
    /// the connect-time handshake.
    pub(crate) fn into_current(mut self) -> Result<ServerEvent, EventEnvelopeError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            }
            .into());
        }
        if let Some(spill) = self.assistant_text_spill.take() {
            let ServerEvent::RunEnded { summary, .. } = &mut self.event else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "terminal-text spool was attached to a non-terminal EQ event",
                )
                .into());
            };
            let text = spill.read_to_string(&summary.run_id)?;
            summary.assistant_text = text;
        }
        Ok(self.event)
    }
}

/// Actual adopted state and bounded public presentation. Native leases and provider constructors
/// are retained by the host and cannot be supplied or recovered through this reply.
#[derive(Debug)]
pub(crate) struct NavigatedSession {
    pub(crate) presentation: iteron_protocol::session_navigation::SessionNavigationReplyV1,
    pub(crate) adopted: crate::runtime::AdoptedRun,
    pub(crate) snapshot: SessionSnapshot,
    pub(crate) tunables_checkpoint: iteron_record::TunablesCheckpoint,
    pub(crate) compaction_trigger_tokens: usize,
}

/// Workspace execution facts and, only when the actual host adoption succeeded, selected state.
#[derive(Debug)]
pub(crate) struct WorkspaceRewound {
    pub(crate) presentation: iteron_protocol::workspace_rewind::WorkspaceRewindReplyV1,
    pub(crate) navigation: Option<Box<NavigatedSession>>,
}

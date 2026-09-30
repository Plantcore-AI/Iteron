//! Immutable runtime/frontend contracts. These values carry observations and never grant authority.

use iteron_ctx::ContextEstimate;
use iteron_obs::CostState;
use iteron_protocol::{Capability, Phase, SubmissionId};

/// A permission decision, not evidence that the proposed tool effect ran or succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResolution {
    Approved,
    Denied,
    Cancelled,
    TimedOut,
}

/// An identified control command that the runtime actually admitted. This is not a claim that a
/// tool or external effect succeeded; it only records the cooperative control-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlSubmissionKind {
    Interrupt,
    ForceCancel,
    Drain,
}

impl ControlSubmissionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::ForceCancel => "force_cancel",
            Self::Drain => "drain",
        }
    }
}

/// Events a UI (the TUI) renders. The kernel sends these to an optional channel so a front-end
/// can display the run live without the kernel writing to stdout.
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Streamed assistant text.
    Text(String),
    /// Streamed reasoning (extended thinking).
    Thinking(String),
    /// A tool is about to run: a stable id (to correlate with `ToolEnd`), its name, and its
    /// (secret-scrubbed) args as structured JSON so the TUI can humanize them into a card
    /// (ADR-015). `args` is scrubbed before it crosses this seam (R1).
    ToolStart {
        id: String,
        name: String,
        args: serde_json::Value,
    },
    /// A tool finished: correlated to its `ToolStart` by `id`. Carries the full (scrubbed, bounded)
    /// output so the TUI can render a collapsible result card, and an optional parsed `FileDiff`
    /// for edit tools (populated in P1; `None` at P0). ADR-015 R1/R5/R7.
    ToolEnd {
        id: String,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<iteron_protocol::FileDiff>,
    },
    /// Phase transition.
    Phase(Phase),
    /// End of one provider turn. `usage` is provider-reported for this turn only; input excludes
    /// cache classes per the protocol contract. `context` is the labelled preflight estimate for
    /// the request that just ran. The model window remains `None` until catalog metadata proves it;
    /// the compaction trigger is a policy threshold and must never be rendered as that window.
    TurnEnd {
        cost: CostState,
        usage: iteron_protocol::Usage,
        context: ContextEstimate,
        model_context_window: Option<u64>,
        /// Exact output allowance reserved by the admission check for this request.
        reserved_output_tokens: u32,
        compaction_trigger_tokens: usize,
        effort: iteron_provider::EffortApplication,
    },
    /// A structured workflow lifecycle update. Frontends project these id-correlated events into
    /// one live card/tree instead of printing a line per worker (the Claude Code/Codex interaction
    /// model). Task labels are scrubbed and bounded before crossing this seam.
    #[allow(dead_code)]
    Workflow(WorkflowUiEvent),
    /// Legacy/unidentified steering messages admitted at a turn boundary. This count is never
    /// authoritative for an identified client's submission receipt.
    SteerApplied { count: usize },
    /// An exact identified steer was durably appended to the run record. App Server settles only
    /// this submission ID as Applied; queue admission by itself is not successful execution.
    SteerSubmissionApplied { id: SubmissionId },
    /// Exact rejection of a product-turn-scoped command that arrived after its user-facing turn
    /// ceased to own the kernel queue. The reason is a closed, non-secret code.
    SubmissionRejected {
        id: SubmissionId,
        reason_code: &'static str,
    },
    /// Exact identified interrupt/drain command applied to runtime control state. A terminal
    /// event alone does not prove this happened, so the App Server must not infer it by FIFO.
    ControlSubmissionApplied {
        id: SubmissionId,
        kind: ControlSubmissionKind,
    },
    /// A harness notice (compaction, verify gate, interrupt, ...).
    Notice(String),
    /// A capability gate needs the operator's answer (mode = default/plan/... produced `Ask`). The
    /// TUI renders a prompt and answers on the approvals channel (`Op::ApprovalResponse`).
    ApprovalRequest {
        id: SubmissionId,
        tool: String,
        capability: Capability,
        reason: String,
        /// Secret-scrubbed exact tool arguments. Frontends must keep the decision actions visible
        /// even on short screens; this is presentation evidence, not a capability grant.
        arguments: serde_json::Value,
        /// Bounded workspace provenance for the effect target.
        workspace: String,
    },
    /// Authoritative resolution of the same approval id after its durable decision boundary.
    /// `Approved` permits the later tool admission; it never claims the tool was executed.
    ApprovalResolved {
        id: SubmissionId,
        resolution: ApprovalResolution,
        reason_code: &'static str,
        /// Exact client response submission accepted for this durable decision. Missing on
        /// timeout, cancellation, one-shot denial, or a response never matched to this request.
        response_submission_id: Option<SubmissionId>,
    },
    /// The run ended.
    Done(String),
}

/// PlantCore-only runtime facts carried beside the frozen CLI `UiEvent` vocabulary.
#[derive(Debug, Clone)]
pub(crate) enum PlantcoreUiEvent {
    Usage(iteron_protocol::TurnUsage),
    RunAdmitted {
        profile_digest_sha256: iteron_protocol::HexSha256,
    },
}

/// Ordered ingress from the resident runtime into App Server presentation.
#[derive(Debug, Clone)]
pub(crate) enum RuntimeFrontendEvent {
    Ui(UiEvent),
    Plantcore(PlantcoreUiEvent),
    TurnPublication(iteron_protocol::turn_publication::TurnPublicationEventV1),
}

/// A bounded, presentation-safe task declared by a workflow plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WorkflowTaskUi {
    pub id: usize,
    pub label: String,
}

/// Actual execution posture. Keeping this explicit prevents the fan from being mislabeled: `Direct`
/// is the single-writer path, `Concurrent` is the bounded-concurrent read-only investigation fan
/// (owned tasks under a `Governor` permit cap). `Sequential` is retained for older frontends/tests
/// that still describe the pre-concurrency executor; the kernel no longer emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Frozen frontend vocabulary includes legacy states this runtime does not emit.
pub enum WorkflowExecutionModeUi {
    Direct,
    Sequential,
    Concurrent,
}

/// Replay-compatible user-visible workflow phases for the frozen frontend projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Frozen machine/frontend projection; the engine tree is the live renderer.
pub enum WorkflowPhaseUi {
    Planning,
    Exploring,
    Synthesizing,
    Writing,
    Direct,
}

/// Terminal state of one workflow worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Frozen frontend vocabulary includes a replay-only pre-start state.
pub enum WorkflowAgentOutcomeUi {
    Done,
    Failed,
    Interrupted,
    SkippedBudget,
    NotStarted,
}

/// Terminal state of the workflow as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Frozen machine/frontend projection; the engine tree is the live renderer.
pub enum WorkflowRunOutcomeUi {
    Done,
    Degraded,
    BudgetExhausted,
    Stuck,
    Failed,
    Stopped,
}

/// Id-correlated workflow lifecycle. The event names intentionally mirror the stable workflow
/// projection used by production coding agents: run -> plan -> phase -> agent -> terminal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[allow(dead_code)] // Replay compatibility; production emits WorkflowRunUiEvent from the engine.
pub enum WorkflowUiEvent {
    RunStarted {
        run_id: String,
        name: String,
        class: String,
    },
    PlanReady {
        run_id: String,
        tasks: Vec<WorkflowTaskUi>,
        dropped: usize,
        duplicates_removed: usize,
        invalid_removed: usize,
        execution_mode: WorkflowExecutionModeUi,
        fan_turn_budget: u32,
        writer_turn_reserve: u32,
        fan_wall_secs: u64,
        writer_wall_reserve_secs: u64,
    },
    PhaseChanged {
        run_id: String,
        phase: WorkflowPhaseUi,
    },
    AgentStarted {
        run_id: String,
        agent_id: usize,
        sub_run: String,
        turn_budget: u32,
    },
    AgentActivity {
        run_id: String,
        agent_id: usize,
        activity: String,
    },
    AgentFinished {
        run_id: String,
        agent_id: usize,
        outcome: WorkflowAgentOutcomeUi,
        turns: u32,
        tokens: u64,
        tool_calls: u64,
        elapsed_ms: u64,
        summary_preview: Option<String>,
        error_preview: Option<String>,
    },
    RunFinished {
        run_id: String,
        outcome: WorkflowRunOutcomeUi,
        reason: Option<String>,
        elapsed_ms: u64,
        provider_attempts: u32,
        turns: u32,
        tokens: u64,
        tool_calls: u64,
        failed_tasks: u32,
        skipped_tasks: u32,
    },
}

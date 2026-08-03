//! Events on the EQ. Every phase transition, token class, and tool latency is emitted here
//! (invariant #4, observable). The phase is the point: the harness is the only layer that
//! knows what phase it is in (the phase-oracle thesis).

use crate::artifact::ArtifactRef;
use crate::ids::{EffectId, Seq, SubmissionId, TurnId};
use crate::message::{Message, Usage};
use crate::permission::Verdict;
use crate::pricing::{CostProjection, SignedRateCard};
use crate::tool::{Capability, ToolResult, ToolUse};
use serde::{Deserialize, Serialize};

/// Schema version for durable runtime-policy snapshots. This is an enum rather than an open
/// integer so writers cannot accidentally emit an unreviewed wire format under a familiar event
/// kind. A future format gets a new variant and an explicit replay migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePolicyEventVersion {
    V1,
}

/// Auditable origin of a runtime-policy transition. Sources are deliberately protocol vocabulary,
/// not frontend-controlled strings: a model or plugin cannot forge an arbitrary provenance label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePolicySource {
    /// Effective configuration captured when a fresh run is created.
    Startup,
    /// An explicit live operator action (command, picker, or embedding API).
    Operator,
    /// The operator selected a session-scoped "remember" action while approving one operation.
    ApprovalRemember,
    /// A bounded harness-owned policy choice, such as a constrained child agent.
    Harness,
    /// A child journal materialized the effective state at its exact fork point.
    Fork,
}

/// Versioned durable vocabulary for harness-owned workflows. The workflow journal is deliberately
/// separate from free-form notices: resume, session projection, and frontends must be able to
/// reconstruct child attribution without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowEventVersion {
    V1,
    /// Adds the distinct `drained` child and workflow terminals. Writers pair this with the
    /// top-level `workflow_v2` event tag so V1 readers skip the whole event through their existing
    /// unknown-kind fallback instead of failing inside a known `workflow` payload.
    V2,
}

/// The execution topology that was actually admitted, not the topology a planner merely proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowExecutionMode {
    Direct,
    /// Legacy: fan workers executed one at a time. Retained so historical durable records still
    /// deserialize; the kernel no longer emits it.
    SequentialFan,
    /// Fan workers run bounded-concurrent (owned tasks under a `Governor` permit cap). This is the
    /// mode the kernel emits for every read-only investigation fan.
    ConcurrentFan,
}

/// Durable workflow phases. `Writing` is distinct from `Reducing`: deterministic bundle assembly
/// is harness work, while writing admits model/tool effects through the ordinary controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowPhase {
    Planning,
    Exploring,
    Reducing,
    Writing,
    Direct,
}

/// Authoritative terminal disposition for one declared workflow task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowChildOutcome {
    Done,
    Failed,
    Interrupted,
    Drained,
    SkippedBudget,
    NotStarted,
}

/// Authoritative terminal disposition for the workflow as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowOutcome {
    Done,
    Degraded,
    Interrupted,
    Drained,
    BudgetExhausted,
    Stuck,
    HarnessError,
    Failed,
}

/// Content-minimal evidence for a declared task. The full delegation remains in the child rollout;
/// the parent stores only a bounded display label and a digest for correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowTaskEvidence {
    pub task_id: u32,
    pub label: String,
    pub prompt_digest: String,
}

/// Additive metrics for exactly one child, or a terminal snapshot for the whole workflow. A
/// `Finished` snapshot is informational; projections add only `ChildFinished` metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowMetrics {
    pub provider_attempts: u32,
    pub completed_turns: u32,
    pub usage: Usage,
    pub tool_calls: u64,
    pub tool_errors: u64,
    /// Process-local child timing. `None` is an explicit unknown, used when a resumed ledger lacks
    /// complete historical phase timing; legacy numeric JSON values remain wire-compatible.
    #[serde(default)]
    pub model_ms: Option<u64>,
    #[serde(default)]
    pub tools_ms: Option<u64>,
    /// Aggregate monetary evidence from the child's own signed per-turn projections. `None` means
    /// either no completed provider turn or at least one turn was not verifiably priced.
    #[serde(default)]
    pub cost: Option<WorkflowCostEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowCostEvidence {
    pub amount_microusd: u64,
    pub rate_card_digest: String,
    /// Signed per-turn projections from the child rollout. A parent replay verifies every HMAC and
    /// usage total before treating the aggregate as priced; the aggregate fields alone are never a
    /// monetary authority.
    #[serde(
        default,
        deserialize_with = "crate::pricing::deserialize_cost_projections"
    )]
    pub projections: Vec<CostProjection>,
}

/// Typed workflow journal carried by [`EventKind::Workflow`] and [`EventKind::WorkflowV2`].
/// Activity chatter is intentionally absent: the durable boundary records decisions, budgets,
/// attribution, adoption, and terminals; high-frequency current-tool updates remain a coalescible
/// frontend projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WorkflowEvent {
    Started {
        name: String,
        class: String,
    },
    Planned {
        mode: WorkflowExecutionMode,
        tasks: Vec<WorkflowTaskEvidence>,
        dropped: u32,
        duplicates_removed: u32,
        invalid_removed: u32,
        fan_turn_budget: u32,
        writer_turn_reserve: u32,
        fan_wall_secs: u64,
        writer_wall_reserve_secs: u64,
    },
    PhaseChanged {
        phase: WorkflowPhase,
    },
    ChildStarted {
        task_id: u32,
        sub_run: String,
        spawn_seq: Seq,
        budget: crate::Budget,
    },
    ChildFinished {
        task_id: u32,
        sub_run: Option<String>,
        outcome: WorkflowChildOutcome,
        metrics: WorkflowMetrics,
        error_code: Option<String>,
        error_detail: Option<String>,
        summary_digest: Option<String>,
        evidence_bytes: u32,
    },
    Reduced {
        evidence_message_seq: Option<Seq>,
        done: u32,
        failed: u32,
        skipped: u32,
        elapsed_ms: u64,
    },
    Finished {
        outcome: WorkflowOutcome,
        metrics: WorkflowMetrics,
        elapsed_ms: u64,
        error_code: Option<String>,
        error_detail: Option<String>,
    },
}

/// Canonical pure projection of runtime policy from a logical rollout. Keeping this reducer beside
/// the wire vocabulary gives the kernel, session index, and fork code one interpretation of legacy
/// genesis events and v1 snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyState {
    pub effort: crate::Effort,
    pub permission_mode: crate::PermissionMode,
    pub permission_rules: crate::PermissionRules,
}

impl Default for RuntimePolicyState {
    fn default() -> Self {
        Self {
            effort: crate::Effort::default(),
            permission_mode: crate::PermissionMode::default(),
            permission_rules: crate::PermissionRules::new(),
        }
    }
}

impl RuntimePolicyState {
    /// Apply one event to the projection. Legacy records get effort from `RunStart` and the safest
    /// default permission policy; newer full snapshots then replace the relevant state atomically.
    pub fn apply(&mut self, kind: &EventKind) {
        match kind {
            EventKind::RunStart { effort, .. } => self.effort = *effort,
            EventKind::EffortChanged {
                version: RuntimePolicyEventVersion::V1,
                effort,
                ..
            } => self.effort = *effort,
            EventKind::PolicyChanged {
                version: RuntimePolicyEventVersion::V1,
                mode,
                rules,
                ..
            } => {
                self.permission_mode = *mode;
                self.permission_rules = rules.clone();
            }
            _ => {}
        }
    }

    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a Event>) -> Self {
        let mut state = Self::default();
        for event in events {
            state.apply(&event.kind);
        }
        state
    }
}

/// The phase a turn is in. The harness *declares* this; nothing else in the stack can.
/// (ADR-002: this is what makes the run observable, attributable, and priceable.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Assembling the context projection c(s_t) for the model.
    Context,
    /// Waiting on / streaming the model response (prefill + decode).
    Model,
    /// Executing tool calls.
    Tools,
    /// Verifying / selecting (the crown; a separate phase so its cost is attributable).
    Verify,
    /// Idle between turns.
    Idle,
}

impl Phase {
    /// A human status word for the TUI status line (never the raw Debug variant — TUI v3 §7).
    pub fn label(self) -> &'static str {
        match self {
            Phase::Context => "reading context",
            Phase::Model => "thinking",
            Phase::Tools => "running tools",
            Phase::Verify => "verifying",
            Phase::Idle => "idle",
        }
    }
}

/// An event with its place in the run's total order. `seq` is per-run (ADR-008).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: Seq,
    pub turn: TurnId,
    pub kind: EventKind,
}

/// Maximum serialized frontend environment prefix admitted into one durable context snapshot.
/// This is intentionally independent of the instruction and memory/skills bounds: each source is
/// admitted at its owning boundary before the kernel combines their already-bounded bytes.
pub const MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES: usize = 4 * 1024;

/// Maximum UTF-8 bytes in immutable operator-defined run grouping metadata.
pub const MAX_AGENT_DEFINITION_TAG_BYTES: usize = 128;

/// Exact frontend-observed environment facts captured for a fresh run. The text is data, not an
/// instruction source, and keeps its own provenance so combining it cannot silently raise trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableEnvironmentContext {
    pub text: String,
    pub trust: crate::Trust,
}

/// Exact strategy-admitted frontend prefix carried beside the legacy memory/skills context.
/// Keeping it as an optional typed field lets older readers ignore the additive evidence while a
/// current reader can distinguish a complete durable context from a pre-instruction legacy event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableInstructionContext {
    pub text: String,
    pub trust: crate::Trust,
    /// Fresh-start environment snapshot. `None` preserves the historical wire shape exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<DurableEnvironmentContext>,
}

/// Machine-readable reason for refusing an SQ submission before it can affect session state.
/// This vocabulary intentionally has no free-text or opaque-payload variant: unsupported client
/// data must be observable without becoming a secret-bearing record field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionRejectionReason {
    UnsupportedOperation,
    ProtocolVersionMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A phase transition. The load-bearing telemetry.
    Phase { phase: Phase },
    /// A turn began.
    TurnStart,
    /// A full transcript message was committed (append-only). Recording these makes the rollout
    /// a complete, resumable record of the conversation (ADR-006 (a)+(b): the decisions and the
    /// recorded outputs replay) and completes the audit trail (every message is on the record).
    Message { message: Message },
    /// Compaction rewrote the working message set (a rare "cache bomb"). Recorded as a full
    /// snapshot so resume reconstructs the in-memory compacted state exactly rather than the
    /// pre-compaction history (code review: without this, resume diverges from what ran).
    Compaction { messages: Vec<Message> },
    /// The model produced streamed text (surfaced incrementally to the operator).
    Text { delta: String },
    /// The model's reasoning delta (extended thinking).
    Thinking { delta: String },
    /// A tool_use block completed mid-stream — the dispatch point for pure tools (ADR-004).
    ToolReady { tool: ToolUse, purity_pure: bool },
    /// A tool finished. `latency_ms` is measured tau_wall contribution.
    ///
    /// # Why the completion names its own tool
    ///
    /// The payload used to be exactly `{result, effect_id}`, and `ToolResult` carries only the
    /// provider's opaque `tool_use_id`, so a completion did not say *what had run*. Answering
    /// "which tools did this run use" required joining every terminal back to the assistant
    /// message that emitted its `tool_use` block — and a record whose message was compacted away
    /// (`EventKind::Compaction` rewrites the working set) could not answer it at all. `None` is
    /// reserved for records written before this field existed: an empty string would be a claim
    /// about a tool that never had that name.
    ///
    /// # Why a successful terminal always carries an effect id
    ///
    /// `effect_id` is the harness-minted id of this call's preceding `EffectIntent`. Every
    /// dispatch path that can *succeed* crosses the effect boundary, including the ADR-004 pure
    /// reads that used to commit their terminal locally, so a proven-successful completion always
    /// names its admission. `None` survives for a refused or failed call — which never reached an
    /// executor, so there was nothing to admit — and for records written before the boundary went
    /// universal. `core_record` enforces exactly that split at the durable append boundary; it is
    /// deliberately not a parse-time rule, because records already on disk must stay readable.
    ///
    /// Both fields are additive `Option`s (abi.md §4.3(b)3), so a `None` serializes to the exact
    /// bytes a historical record holds and `PROTOCOL_VERSION` MUST NOT bump for them.
    ToolDone {
        result: ToolResult,
        #[serde(default)]
        effect_id: Option<EffectId>,
        /// The registry tool name this completion belongs to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<String>,
    },
    /// Write-ahead admission for one effecting tool call. This event must be fsynced before the
    /// registry executor is entered. `(turn, id)` is the correlation key; arguments/workspace are
    /// a scrubbed audit projection, not an ambient capability handle.
    EffectIntent {
        id: EffectId,
        /// Provider/model correlation metadata. Empty only for the first experimental WAL format,
        /// where `id` itself contained the model-controlled tool-use id.
        #[serde(default)]
        tool_use_id: String,
        tool: String,
        capability: Capability,
        arguments: serde_json::Value,
        workspace: String,
    },
    /// Runtime dispatch or recovery could not prove a terminal outcome for an admitted intent.
    /// It is never retried automatically. A future authenticated broker reconciliation may append
    /// a distinct reconciliation event; an ordinary `ToolDone` cannot erase this state.
    EffectUnknown {
        id: EffectId,
        tool: String,
        reason: String,
    },
    /// Proven successful terminal for a brokered effect that is **not** a registry tool call:
    /// provider requests, lifecycle hooks, subagent spawns, verifier oracle runs, workspace
    /// checkpoints and in-turn workflow launches.
    ///
    /// # Why these do not reuse `ToolDone`
    ///
    /// `ToolDone` is not merely a terminal marker; it is a transcript and accounting record.
    /// `core_obs::pricing::replay` folds every `ToolDone` into `ledger.replay_tool`, and the
    /// kernel reconstructs pending tool results from it. Minting a synthetic `ToolResult` for a
    /// provider request or a checkpoint would inflate the tool counters and put rows that were
    /// never tool calls into the transcript projection. A distinct tag keeps one WAL ordering for
    /// every effect class without corrupting the meaning of the class that already had one.
    ///
    /// This is a purely additive top-level tag (abi.md §4.3(b)2): every byte already on disk
    /// decodes unchanged, so `PROTOCOL_VERSION` MUST NOT bump for it.
    ///
    /// `duration_ms` is the boundary's own measurement of `open_effect` -> `settle_effect`: the
    /// whole admitted lifetime of this effect, stamped by [`crate`]'s broker rather than by the
    /// executor, so every one of the effect classes is measured by the same clock at the same two
    /// points. It is `Option` because a record written before this field existed has no honest
    /// value, and a plausible-looking `0` would be a lie about a completed effect.
    EffectDone {
        id: EffectId,
        tool: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
    /// Proven **failed** terminal for a brokered effect. The distinction from
    /// [`EventKind::EffectUnknown`] is the whole point of the boundary: `EffectFailed` means the
    /// executor observed an authoritative negative outcome, so the effect is closed and recovery
    /// owes it nothing; `EffectUnknown` means no terminal could be observed at all, so recovery
    /// must never replay it. Collapsing the two would make every honest failure look unrecoverable
    /// and every unrecoverable dispatch look like an honest failure.
    ///
    /// A proven failure has a real duration and hiding it would make every failure look
    /// instantaneous, so this carries the same measurement as `EffectDone`. `EffectUnknown`
    /// deliberately does **not**: no terminal was observed, so no honest duration exists.
    EffectFailed {
        id: EffectId,
        tool: String,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
    /// The model turn completed, with usage by cache class.
    ///
    /// The three timing fields split what `phase_model_ms` folds into one scalar. `ttft_ms` is
    /// measured to the FIRST stream item of the attempt whichever variant it is — a `ThinkingDelta`
    /// counts, because extended thinking is the model producing tokens and a TTFT that ignored it
    /// would report a reasoning turn as pathologically slow. `decode_ms` runs from that first item
    /// to the turn's completion, and `stream_items` is the raw count so inter-token time is
    /// derivable by a reader rather than pre-averaged here.
    ///
    /// All three are `Option` and that is load-bearing: a non-streaming adapter, a replayed turn,
    /// or an attempt that failed before its first byte has no TTFT at all, and `0` would claim an
    /// instantaneous first token. They are **not** a partition of `phase_model_ms`, which remains
    /// the outer bound: pure tools overlap the stream by design.
    TurnEnd {
        usage: Usage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttft_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decode_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stream_items: Option<u32>,
    },
    /// A run declaring a product: "I produced this", with a content-addressed handle.
    ///
    /// `ArtifactRef` is deliberately a handle rather than inline content, because the evolution
    /// registry has to be able to verify what it holds. Everything the stream vocabulary needs is
    /// already on it or on the enclosing event: the ref and its hash, the kind (`schema`), the
    /// producing turn (`Event::turn`), and the tool or effect that made it (`producer`). Adding
    /// fields beside it would create a second, drifting copy of what the handle already says.
    ///
    /// Before this existed, a product built on top of a run could only be discovered by parsing
    /// the assistant's prose, so every consumer invented its own convention and none of them could
    /// be verified.
    ///
    /// This is a purely additive top-level tag (abi.md §4.3(b)2), exactly like
    /// [`EventKind::EffectDone`]: every byte already on disk decodes unchanged, so
    /// `PROTOCOL_VERSION` MUST NOT bump for it.
    ArtifactProduced { artifact: ArtifactRef },
    /// A message for the operator (not part of the transcript).
    Notice { text: String },
    /// A submission was decoded safely but is not understood by this build. The record contains
    /// only a closed typed reason; the unknown tag and payload are discarded by `Op::Unknown`.
    SubmissionRejected { reason: SubmissionRejectionReason },
    /// A capability-gate decision (ADR-007 §3): the request (`verdict: Ask`) and then the
    /// resolution (`Auto` = approved, `Deny` = refused). Recording both makes the approval the
    /// replay decision-log — a deterministic replay reads the recorded verdict and does not
    /// re-prompt (the operator is not in the replay; ADR-006 boundary).
    Approval {
        id: SubmissionId,
        /// Correlates the human decision with one concrete model invocation, not merely a tool
        /// class. Empty only when replaying a legacy record written before this field existed.
        #[serde(default)]
        tool_use_id: String,
        tool: String,
        capability: Capability,
        /// Secret-scrubbed, bounded operation projection shown to the operator. This is audit
        /// evidence; future opaque secret handles must be bound separately by the effect broker.
        #[serde(default)]
        arguments: serde_json::Value,
        /// Workspace/resource provenance at the decision boundary.
        #[serde(default)]
        workspace: String,
        verdict: Verdict,
    },
    /// The session genesis header (seq-0). Carries the wall-clock `created_at` ONCE, crossing the
    /// nondeterminism boundary (ADR-006 rule 1) so it is read from the record on replay, never
    /// re-read at list time. `parent_*` set on a fork/rewind child; `parent_hash_at_seq` is the
    /// parent chain's hash at the fork point (ADR-008 §4 tamper-evidence — R5-review Risk 3).
    RunStart {
        cwd: String,
        model: String,
        effort: crate::Effort,
        created_at: u64,
        /// Fresh-run environment facts are duplicated in genesis so a crash before the first
        /// ContextInjection can resume without consulting a newer live clock or Git state.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        environment: Option<DurableEnvironmentContext>,
        parent_run: Option<String>,
        forked_at: Option<u64>,
        parent_hash_at_seq: Option<String>,
        config_digest: String,
        /// Bounded operator-defined grouping metadata. It is immutable for a run, inherited by a
        /// fork, and absent on legacy records.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_definition_tag: Option<String>,
        /// Invocation-independent monetary ceiling. Missing on legacy records. Forks copy the
        /// effective value into their own genesis so rewinding cannot silently remove it.
        #[serde(default)]
        max_usd: Option<f64>,
    },
    /// The exact provider/model routing pair selected for subsequent turns. Provider identity is
    /// separate from model identity because the same model id can exist behind several accounts or
    /// gateways. Digests pin the catalog/capability evidence used at selection time; empty means
    /// the frontend had no stronger provenance and must not invent one during replay.
    ModelSelected {
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    },
    /// Verified, versioned rate card bound to the exact selected provider/model route. The
    /// strategy-layer signature and content digest are durable provenance; no price lookup occurs
    /// in the kernel or during replay.
    RateCardBound { rate_card: SignedRateCard },
    /// Signed fixed-point cost for the immediately preceding completed provider turn. Replay binds
    /// its usage to `TurnEnd` and reconstructs monetary state directly from this evidence.
    CostProjected { projection: CostProjection },
    /// Monotone fixed-point monetary policy. Writers append this before establishing or tightening
    /// a live ceiling; replay and forks take the minimum across the logical history. Absence is the
    /// legacy format, whose optional `RunStart.max_usd` remains authoritative.
    UsdCeilingChanged {
        version: RuntimePolicyEventVersion,
        source: RuntimePolicySource,
        max_microusd: u64,
    },
    /// Full snapshot of the effective reasoning/orchestration policy. The rollout is write-ahead:
    /// the kernel fsyncs this event before changing the in-memory value. Full snapshots avoid
    /// replay depending on frontend-specific commands such as "cycle to next effort".
    EffortChanged {
        version: RuntimePolicyEventVersion,
        source: RuntimePolicySource,
        effort: crate::Effort,
    },
    /// Full snapshot of the capability gate policy. Both mode and rules travel together so replay,
    /// resume, and fork reconstruct exactly one coherent gate state rather than a partial update.
    PolicyChanged {
        version: RuntimePolicyEventVersion,
        source: RuntimePolicySource,
        mode: crate::PermissionMode,
        rules: crate::PermissionRules,
    },
    /// The exact context (environment + instructions + memory/skills) injected into the stable
    /// prefix this run
    /// (REC-INJECT, R5-review item 1). Replay re-materializes context FROM this record, never from
    /// disk, so a mid-run on-disk edit cannot alter a replay and post-compaction facts do not drop.
    /// Stored protocol-native (the rendered text + its trust) to avoid a dep on the ctx crate.
    ContextInjection {
        text: String,
        trust: crate::Trust,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instructions: Option<DurableInstructionContext>,
    },
    /// A workspace checkpoint (files) keyed to a record `Seq` — the snapshot ledger in the rollout.
    Checkpoint { at: Seq, tree_ref: String },
    /// A read-only subagent was spawned; links its child rollout to the parent (single-writer
    /// fan-out, ADR-001) for the `/sessions` tree view.
    SubagentSpawned { sub_run: String, agent: String },
    /// Terminal attribution for a directly-dispatched read-only child. Ultracode children use the
    /// richer correlated `Workflow::ChildFinished` event instead; projections add exactly one of
    /// these terminal forms per spawned child.
    SubagentFinished {
        sub_run: String,
        outcome: WorkflowChildOutcome,
        metrics: WorkflowMetrics,
        error_code: Option<String>,
        error_detail: Option<String>,
        summary_digest: Option<String>,
        evidence_bytes: u32,
    },
    /// Current directly-dispatched child terminal. Like `workflow_v2`, the distinct top-level tag
    /// lets V1 readers skip a terminal carrying the new `drained` outcome instead of failing while
    /// decoding the already-known `subagent_finished` shape.
    SubagentFinishedV2 {
        version: WorkflowEventVersion,
        sub_run: String,
        outcome: WorkflowChildOutcome,
        metrics: WorkflowMetrics,
        error_code: Option<String>,
        error_detail: Option<String>,
        summary_digest: Option<String>,
        evidence_bytes: u32,
    },
    /// Versioned, typed workflow lifecycle. This is the parent WAL source of truth for child
    /// attribution and terminal reconstruction; `SubagentSpawned` remains for legacy tree views.
    Workflow {
        version: WorkflowEventVersion,
        workflow_id: String,
        event: WorkflowEvent,
    },
    /// Current workflow lifecycle envelope. A distinct top-level tag is intentional: readers that
    /// only know `workflow` V1 deserialize this as `Unknown` instead of rejecting the rollout when
    /// V2 introduces the `drained` terminal vocabulary.
    WorkflowV2 {
        version: WorkflowEventVersion,
        workflow_id: String,
        event: WorkflowEvent,
    },
    /// The run ended.
    Done { outcome: String },
    /// Forward-compatibility: an event kind this build does not recognize (written by a newer
    /// version). Deserializes here instead of failing the whole replay (R5-review Risk 6).
    #[serde(other)]
    Unknown,
}

impl EventKind {
    /// Enforce the public tag/version contract before an event reaches durable storage. V2 uses a
    /// new top-level tag because an already-released serde reader can skip an unknown tag, but it
    /// cannot recover from a new enum value or `null` timing nested inside a known V1 tag.
    pub fn validate_compatibility_tag(&self) -> Result<(), &'static str> {
        match self {
            Self::Workflow {
                version: WorkflowEventVersion::V1,
                event,
                ..
            } if workflow_event_is_v1_compatible(event) => Ok(()),
            Self::Workflow { .. } => Err("workflow V1 tag contains V2-only fields or version"),
            Self::WorkflowV2 {
                version: WorkflowEventVersion::V2,
                ..
            } => Ok(()),
            Self::WorkflowV2 { .. } => Err("workflow_v2 tag must carry version v2"),
            Self::SubagentFinished {
                outcome, metrics, ..
            } if *outcome != WorkflowChildOutcome::Drained
                && metrics_are_v1_compatible(metrics) =>
            {
                Ok(())
            }
            Self::SubagentFinished { .. } => {
                Err("subagent_finished V1 tag contains V2-only fields")
            }
            Self::SubagentFinishedV2 {
                version: WorkflowEventVersion::V2,
                ..
            } => Ok(()),
            Self::SubagentFinishedV2 { .. } => {
                Err("subagent_finished_v2 tag must carry version v2")
            }
            _ => Ok(()),
        }
    }
}

fn metrics_are_v1_compatible(metrics: &WorkflowMetrics) -> bool {
    metrics.model_ms.is_some() && metrics.tools_ms.is_some()
}

fn workflow_event_is_v1_compatible(event: &WorkflowEvent) -> bool {
    match event {
        WorkflowEvent::ChildFinished {
            outcome, metrics, ..
        } => *outcome != WorkflowChildOutcome::Drained && metrics_are_v1_compatible(metrics),
        WorkflowEvent::Finished {
            outcome, metrics, ..
        } => *outcome != WorkflowOutcome::Drained && metrics_are_v1_compatible(metrics),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #103's whole honesty claim, at the wire. A turn that produced no stream item must be
    /// distinguishable from one whose first token arrived instantly, and `0` cannot carry that
    /// distinction. Absent means "never observed"; present means "measured, and this is the value".
    #[test]
    fn turn_end_timing_distinguishes_unmeasured_from_measured_zero() {
        let usage = Usage::default();
        let unmeasured = serde_json::to_value(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        })
        .unwrap();
        for field in ["ttft_ms", "decode_ms", "stream_items"] {
            assert!(
                unmeasured.get(field).is_none(),
                "unmeasured `{field}` must be absent, not null: {unmeasured}"
            );
        }

        let measured = serde_json::to_value(EventKind::TurnEnd {
            usage,
            ttft_ms: Some(0),
            decode_ms: Some(0),
            stream_items: Some(0),
        })
        .unwrap();
        assert_eq!(measured["ttft_ms"], 0);
        assert_eq!(measured["decode_ms"], 0);
        assert_eq!(measured["stream_items"], 0);
    }

    /// A `turn_end` written before #103 existed must still decode, and must decode as "unknown"
    /// rather than as a fabricated zero. This is the retained-fixture guarantee expressed as a
    /// unit test so it fails at the type, not three layers away in the corpus gate.
    #[test]
    fn a_pre_timing_turn_end_decodes_as_unknown_not_zero() {
        let event: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "turn_end",
            "usage": {"input": 1, "output": 1, "cache_creation": 0, "cache_read": 0, "thinking": 0}
        }))
        .unwrap();
        assert!(matches!(
            event,
            EventKind::TurnEnd {
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
                ..
            }
        ));
    }

    #[test]
    fn pre_route_run_start_event_remains_readable() {
        // Exact shape written before `model_selected` existed. Adding a new tagged variant must
        // not require a provider field in legacy genesis records.
        let event: Event = serde_json::from_value(serde_json::json!({
            "seq": 0,
            "turn": 0,
            "kind": {
                "kind": "run_start",
                "cwd": "/repo/legacy",
                "model": "claude-legacy",
                "effort": "medium",
                "created_at": 1,
                "parent_run": null,
                "forked_at": null,
                "parent_hash_at_seq": null,
                "config_digest": ""
            }
        }))
        .unwrap();
        assert!(matches!(
            event.kind,
            EventKind::RunStart { model, .. } if model == "claude-legacy"
        ));
    }

    #[test]
    fn model_selection_schema_contains_identity_and_digests_not_credentials() {
        let value = serde_json::to_value(EventKind::ModelSelected {
            provider_id: "openai-work".into(),
            model_id: "gpt-5-codex".into(),
            catalog_digest: "sha256:catalog".into(),
            capability_digest: "sha256:capability".into(),
        })
        .unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.get("kind").and_then(|value| value.as_str()),
            Some("model_selected")
        );
        for forbidden in ["api_key", "credential", "key_env", "api_root"] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn runtime_policy_events_are_versioned_full_snapshots_with_fixed_sources() {
        let effort = serde_json::to_value(EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Operator,
            effort: crate::Effort::High,
        })
        .unwrap();
        assert_eq!(effort["kind"], "effort_changed");
        assert_eq!(effort["version"], "v1");
        assert_eq!(effort["source"], "operator");
        assert_eq!(effort["effort"], "high");

        let mut rules = crate::PermissionRules::new();
        rules.set_cap(crate::Capability::CodeExecuting, Verdict::Deny);
        let policy = serde_json::to_value(EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::ApprovalRemember,
            mode: crate::PermissionMode::AcceptEdits,
            rules,
        })
        .unwrap();
        assert_eq!(policy["kind"], "policy_changed");
        assert_eq!(policy["version"], "v1");
        assert_eq!(policy["source"], "approval_remember");
        assert_eq!(policy["mode"], "acceptEdits");
        assert_eq!(policy["rules"]["by_cap"]["code_executing"], "deny");
    }

    #[test]
    fn runtime_policy_projection_uses_last_full_snapshot() {
        let mut denied = crate::PermissionRules::new();
        denied.set_cap(crate::Capability::CodeExecuting, Verdict::Deny);
        let events = vec![
            Event {
                seq: Seq(0),
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: "/repo".into(),
                    model: "model".into(),
                    effort: crate::Effort::Medium,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            },
            Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    effort: crate::Effort::Max,
                },
            },
            Event {
                seq: Seq(2),
                turn: TurnId(0),
                kind: EventKind::PolicyChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    mode: crate::PermissionMode::Plan,
                    rules: denied.clone(),
                },
            },
        ];
        let projected = RuntimePolicyState::from_events(&events);
        assert_eq!(projected.effort, crate::Effort::Max);
        assert_eq!(projected.permission_mode, crate::PermissionMode::Plan);
        assert_eq!(projected.permission_rules, denied);
    }

    #[test]
    fn legacy_capability_only_approval_remains_readable() {
        let event: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "approval",
            "id": 7,
            "tool": "edit",
            "capability": "reversible_local",
            "verdict": "ask"
        }))
        .unwrap();
        assert!(matches!(
            event,
            EventKind::Approval {
                tool_use_id,
                arguments: serde_json::Value::Null,
                workspace,
                ..
            } if tool_use_id.is_empty() && workspace.is_empty()
        ));
    }

    #[test]
    fn approval_record_binds_one_operation_and_workspace() {
        let value = serde_json::to_value(EventKind::Approval {
            id: SubmissionId(9),
            tool_use_id: "call-42".into(),
            tool: "bash".into(),
            capability: Capability::CodeExecuting,
            arguments: serde_json::json!({"command": "cargo test"}),
            workspace: "/repo".into(),
            verdict: Verdict::Ask,
        })
        .unwrap();
        assert_eq!(value["tool_use_id"], "call-42");
        assert_eq!(value["arguments"]["command"], "cargo test");
        assert_eq!(value["workspace"], "/repo");
    }

    #[test]
    fn legacy_effect_events_remain_readable_without_new_correlation_fields() {
        let intent: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "effect_intent",
            "id": "legacy-model-call",
            "tool": "edit",
            "capability": "reversible_local",
            "arguments": {"path":"f"},
            "workspace": "/repo"
        }))
        .unwrap();
        assert!(matches!(
            intent,
            EventKind::EffectIntent { id, tool_use_id, .. }
                if id.0 == "legacy-model-call" && tool_use_id.is_empty()
        ));

        let terminal: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "tool_done",
            "result": {
                "tool_use_id": "legacy-model-call",
                "content": "ok",
                "is_error": false,
                "trust": "workspace",
                "latency_ms": 1
            }
        }))
        .unwrap();
        assert!(matches!(
            terminal,
            EventKind::ToolDone {
                effect_id: None,
                tool: None,
                ..
            }
        ));
    }

    /// I-42: across 71 audited journals the `tool_done` payload keys were exactly `kind`, `result`
    /// and `effect_id`, so no completion identified the tool that produced it. The name is additive
    /// and absent-when-unknown, so a record written before it existed still re-serializes to the
    /// exact bytes it holds — which is what keeps the rollout hash chain verifiable across the
    /// change.
    #[test]
    fn a_tool_completion_names_its_tool_without_disturbing_the_legacy_bytes() {
        let result = ToolResult {
            tool_use_id: "call-1".into(),
            content: "ok".into(),
            is_error: false,
            trust: crate::Trust::Workspace,
            latency_ms: 3,
        };
        let named = serde_json::to_value(EventKind::ToolDone {
            result: result.clone(),
            effect_id: Some(EffectId("fx1-00000001-0000".into())),
            tool: Some("edit".into()),
        })
        .unwrap();
        assert_eq!(named["tool"], "edit");
        let decoded: EventKind = serde_json::from_value(named).unwrap();
        assert!(matches!(
            decoded,
            EventKind::ToolDone { tool: Some(name), .. } if name == "edit"
        ));

        let unnamed = serde_json::to_value(EventKind::ToolDone {
            result,
            effect_id: None,
            tool: None,
        })
        .unwrap();
        assert!(
            unnamed.get("tool").is_none(),
            "an unknown tool name must not reach the wire as an empty string: {unnamed}"
        );
    }

    #[test]
    fn workflow_child_terminal_round_trips_with_additive_metrics() {
        let kind = EventKind::Workflow {
            version: WorkflowEventVersion::V1,
            workflow_id: "workflow-7".into(),
            event: WorkflowEvent::ChildFinished {
                task_id: 2,
                sub_run: Some("fan-parent-t00000001-n0002".into()),
                outcome: WorkflowChildOutcome::Failed,
                metrics: WorkflowMetrics {
                    provider_attempts: 3,
                    completed_turns: 2,
                    usage: Usage {
                        input: 100,
                        output: 20,
                        cache_creation: 4,
                        cache_read: 80,
                        thinking: 5,
                    },
                    tool_calls: 4,
                    tool_errors: 1,
                    model_ms: Some(90),
                    tools_ms: Some(12),
                    cost: None,
                },
                error_code: Some("child_budget_exhausted".into()),
                error_detail: Some("bounded child stopped".into()),
                summary_digest: Some("a".repeat(64)),
                evidence_bytes: 128,
            },
        };
        let encoded = serde_json::to_value(&kind).unwrap();
        let decoded: EventKind = serde_json::from_value(encoded).unwrap();
        assert!(matches!(
            decoded,
            EventKind::Workflow {
                version: WorkflowEventVersion::V1,
                workflow_id,
                event: WorkflowEvent::ChildFinished {
                    task_id: 2,
                    outcome: WorkflowChildOutcome::Failed,
                    metrics: WorkflowMetrics {
                        provider_attempts: 3,
                        tool_calls: 4,
                        ..
                    },
                    ..
                },
            } if workflow_id == "workflow-7"
        ));
    }

    #[test]
    fn durable_instruction_context_is_additive_and_legacy_absence_is_explicit() {
        #[derive(Debug, Deserialize)]
        struct LegacyDurableInstructionContext {
            text: String,
            trust: crate::Trust,
        }

        #[derive(Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum LegacyEventKind {
            ContextInjection {
                text: String,
                trust: crate::Trust,
                instructions: Option<LegacyDurableInstructionContext>,
            },
            #[serde(other)]
            Unknown,
        }

        let current = EventKind::ContextInjection {
            text: "legacy memory".into(),
            trust: crate::Trust::Workspace,
            instructions: Some(DurableInstructionContext {
                text: "framed instructions".into(),
                trust: crate::Trust::Untrusted,
                environment: Some(DurableEnvironmentContext {
                    text: "framed environment facts".into(),
                    trust: crate::Trust::Workspace,
                }),
            }),
        };
        let encoded = serde_json::to_value(&current).unwrap();
        assert_eq!(encoded["instructions"]["text"], "framed instructions");
        assert_eq!(
            encoded["instructions"]["environment"]["text"],
            "framed environment facts"
        );
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(encoded).unwrap(),
            LegacyEventKind::ContextInjection { text, trust, instructions: Some(instructions) }
                if text == "legacy memory"
                    && trust == crate::Trust::Workspace
                    && instructions.text == "framed instructions"
                    && instructions.trust == crate::Trust::Untrusted
        ));

        let legacy: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "context_injection",
            "text": "legacy memory",
            "trust": "workspace"
        }))
        .unwrap();
        assert!(matches!(
            &legacy,
            EventKind::ContextInjection {
                instructions: None,
                ..
            }
        ));
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("instructions")
                .is_none(),
            "None keeps the historical wire shape byte-compatible"
        );

        let without_environment = EventKind::ContextInjection {
            text: String::new(),
            trust: crate::Trust::Trusted,
            instructions: Some(DurableInstructionContext {
                text: "instructions only".into(),
                trust: crate::Trust::Untrusted,
                environment: None,
            }),
        };
        assert!(
            serde_json::to_value(without_environment).unwrap()["instructions"]
                .get("environment")
                .is_none(),
            "None keeps pre-environment instruction records byte-shape compatible"
        );
    }

    #[test]
    fn durable_genesis_environment_is_additive_and_none_preserves_the_legacy_shape() {
        #[derive(Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum LegacyEventKind {
            RunStart {
                cwd: String,
                created_at: u64,
            },
            #[serde(other)]
            Unknown,
        }

        let current = EventKind::RunStart {
            cwd: "/repo".into(),
            model: "model".into(),
            effort: crate::Effort::Medium,
            created_at: 7,
            environment: Some(DurableEnvironmentContext {
                text: "environment snapshot".into(),
                trust: crate::Trust::Workspace,
            }),
            parent_run: None,
            forked_at: None,
            parent_hash_at_seq: None,
            config_digest: String::new(),
            agent_definition_tag: None,
            max_usd: None,
        };
        let encoded = serde_json::to_value(current).unwrap();
        assert_eq!(encoded["environment"]["text"], "environment snapshot");
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(encoded).unwrap(),
            LegacyEventKind::RunStart { cwd, created_at }
                if cwd == "/repo" && created_at == 7
        ));

        let legacy: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "run_start",
            "cwd": "/repo",
            "model": "model",
            "effort": "medium",
            "created_at": 7,
            "parent_run": null,
            "forked_at": null,
            "parent_hash_at_seq": null,
            "config_digest": "",
            "max_usd": null
        }))
        .unwrap();
        assert!(matches!(
            &legacy,
            EventKind::RunStart {
                environment: None,
                ..
            }
        ));
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("environment")
                .is_none(),
            "None keeps the historical RunStart wire shape byte-compatible"
        );
    }

    #[test]
    fn workflow_v2_drain_is_skippable_by_a_v1_reader() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum LegacyWorkflowVersion {
            V1,
        }

        #[derive(Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum LegacyEventKind {
            Workflow {
                version: LegacyWorkflowVersion,
            },
            #[serde(other)]
            Unknown,
        }

        let current = EventKind::WorkflowV2 {
            version: WorkflowEventVersion::V2,
            workflow_id: "workflow-drained".into(),
            event: WorkflowEvent::Finished {
                outcome: WorkflowOutcome::Drained,
                metrics: WorkflowMetrics::default(),
                elapsed_ms: 7,
                error_code: Some("operator_drain".into()),
                error_detail: None,
            },
        };
        let encoded = serde_json::to_value(&current).unwrap();
        assert_eq!(encoded["kind"], "workflow_v2");
        assert_eq!(encoded["version"], "v2");
        assert_eq!(encoded["event"]["outcome"], "drained");
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(encoded).unwrap(),
            LegacyEventKind::Unknown
        ));
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(serde_json::json!({
                "kind": "workflow",
                "version": "v1"
            }))
            .unwrap(),
            LegacyEventKind::Workflow {
                version: LegacyWorkflowVersion::V1
            }
        ));
    }

    #[test]
    fn direct_child_v2_drain_is_skippable_by_a_v1_reader() {
        #[derive(Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum LegacyEventKind {
            SubagentFinished {
                outcome: LegacyChildOutcome,
            },
            #[serde(other)]
            Unknown,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum LegacyChildOutcome {
            Done,
            Failed,
            Interrupted,
            SkippedBudget,
            NotStarted,
        }

        let current = EventKind::SubagentFinishedV2 {
            version: WorkflowEventVersion::V2,
            sub_run: "direct-drained".into(),
            outcome: WorkflowChildOutcome::Drained,
            metrics: WorkflowMetrics::default(),
            error_code: Some("operator_drain".into()),
            error_detail: None,
            summary_digest: None,
            evidence_bytes: 0,
        };
        let encoded = serde_json::to_value(&current).unwrap();
        assert_eq!(encoded["kind"], "subagent_finished_v2");
        assert_eq!(encoded["version"], "v2");
        assert_eq!(encoded["outcome"], "drained");
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(encoded).unwrap(),
            LegacyEventKind::Unknown
        ));
        assert!(matches!(
            serde_json::from_value::<LegacyEventKind>(serde_json::json!({
                "kind": "subagent_finished",
                "outcome": "done"
            }))
            .unwrap(),
            LegacyEventKind::SubagentFinished {
                outcome: LegacyChildOutcome::Done
            }
        ));
    }

    #[test]
    fn workflow_projection_collection_is_bounded_during_deserialization() {
        let projection = CostProjection {
            version: crate::PricingVersion::V1,
            identity: None,
            route: crate::PricingRoute {
                provider_id: "p".into(),
                model_id: "m".into(),
                catalog_digest: "sha256:a".into(),
                capability_digest: "sha256:b".into(),
            },
            usage: Usage::default(),
            amount_microusd: 0,
            projected_at_unix_secs: 1,
            rate_card_digest: "sha256:card".into(),
            signer_id: "signer".into(),
            projection_digest: "sha256:projection".into(),
            signature: "hmac-sha256:signature".into(),
        };
        let oversized = WorkflowCostEvidence {
            amount_microusd: 0,
            rate_card_digest: "sha256:card".into(),
            projections: vec![projection; crate::MAX_WORKFLOW_COST_PROJECTIONS + 1],
        };
        let encoded = serde_json::to_value(oversized).unwrap();
        let error = serde_json::from_value::<WorkflowCostEvidence>(encoded).unwrap_err();
        assert!(error.to_string().contains("invalid length"));
    }
}

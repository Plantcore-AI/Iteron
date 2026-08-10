//! The published, versioned wire form of the event queue.
//!
//! `app_server.rs` records the decision this module exists to serve: the EQ deliberately does not
//! carry `iteron_protocol::Event`, because projecting `UiEvent` onto `EventKind` loses four things a
//! frontend renders. So the queue carries a Rust enum with no wire form, and a client in another
//! process cannot consume it at all.
//!
//! #44 is scoped to a transport and a reconnect protocol. It cannot invent the payload vocabulary
//! as a side effect — if it did, which of the four losses stands would be decided by whoever wrote
//! the socket code rather than by the people who own the contract. This module owns the payload.
//!
//! # The four losses, each resolved rather than repeated
//!
//! Every one is **published** here. None is silently dropped:
//!
//! - `TurnEnd`'s seven fields collapsed to one on `EventKind`. All seven are carried.
//! - `SteerApplied` had no counterpart at all. It is [`ClientEvent::SteerApplied`], with `count`.
//! - `ToolEnd.diff` had no home. It is carried as `iteron_protocol::FileDiff`, whole.
//! - `ApprovalRequest.reason`, the operator-facing justification, had no field to go in. It is
//!   carried, alongside `capability`, `arguments` and `workspace`.
//!
//! # Why some types are mirrored and others are reused
//!
//! `UiEvent` and the six workflow types are frozen: `xtask/src/schema_compat_rust_semantics_*`
//! compares their token fingerprints against the trusted base, and adding a `Deserialize` derive
//! changes that fingerprint. Deriving in place would either break the freeze or force it to be
//! re-blessed for a serde change to a type whose *shape* never moved. Those are mirrored.
//!
//! `Phase`, `Capability`, `Usage`, `ReasoningEffort` and `FileDiff` already round-trip, so they are
//! reused verbatim. Mirroring them would create a second definition of a shape the protocol already
//! owns, which is the drift this module is meant to prevent, not cause.
//!
//! The conversion is a total match, so **adding a `UiEvent` variant without a wire form fails to
//! compile.** That is the exhaustiveness check; it cannot be forgotten into passing.
//!
//! # Relationship to the frozen `stream-json` result contract
//!
//! `output.rs` owns the *result* of a run: one terminal document, versioned by
//! `SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS`, consumed by eval. This module owns the *progress* of a
//! run: many frames, consumed by a frontend as they arrive. They describe the same run and are
//! deliberately not the same contract.
//!
//! Neither is derived from the other, so the rule that stops them becoming two truths is narrow and
//! stated here: **the terminal `stream-json` result stays authoritative for outcome, usage and
//! cost.** A client rendering [`ClientEvent::TurnEnd`] is reading a projection of the same
//! accounting, not a second opinion on it; where they could disagree, the result wins.

use crate::runtime::{
    UiEvent, WorkflowAgentOutcomeUi, WorkflowExecutionModeUi, WorkflowPhaseUi,
    WorkflowRunOutcomeUi, WorkflowTaskUi, WorkflowUiEvent,
};
use iteron_protocol::wire::{PROTOCOL_VERSION, ProtocolVersionError};
use iteron_protocol::{Capability, FileDiff, Phase, ReasoningEffort, Usage};
use serde::{Deserialize, Serialize};

/// One item on the published event queue.
///
/// Versioned in both directions like `SqEnvelope` and `EqEnvelope`, with the same exact-match
/// refusal: a skewed version is a typed error *before* decoding, never a decode failure a caller
/// has to interpret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientEventEnvelope {
    pub protocol_version: u32,
    pub event: ClientEvent,
}

impl ClientEventEnvelope {
    pub fn current(event: ClientEvent) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            event,
        }
    }

    pub fn with_version(protocol_version: u32, event: ClientEvent) -> Self {
        Self {
            protocol_version,
            event,
        }
    }

    pub fn into_current(self) -> Result<ClientEvent, ProtocolVersionError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        Ok(self.event)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientEvent {
    Text {
        text: String,
    },
    Thinking {
        text: String,
    },
    ToolStart {
        id: String,
        name: String,
        args: serde_json::Value,
    },
    ToolEnd {
        id: String,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        /// Third documented loss: `EventKind` had no home for a parsed diff.
        diff: Option<FileDiff>,
    },
    Phase {
        phase: Phase,
    },
    /// First documented loss: seven fields, all of them, not one.
    TurnEnd {
        cost: ClientCost,
        usage: Usage,
        context: ClientContextEstimate,
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
        compaction_trigger_tokens: usize,
        effort: ClientEffortApplication,
    },
    Workflow {
        event: ClientWorkflowEvent,
    },
    /// Second documented loss: `EventKind` had no counterpart at all.
    SteerApplied {
        count: usize,
    },
    Notice {
        text: String,
    },
    ApprovalRequest {
        id: u64,
        tool: String,
        capability: Capability,
        /// Fourth documented loss: the operator-facing justification.
        reason: String,
        arguments: serde_json::Value,
        workspace: String,
    },
    Done {
        outcome: String,
    },
    /// A run declaring a product.
    ///
    /// Unlike every other variant this one has no `UiEvent` source, because it is not a rendering
    /// of the conversation: it is the run saying "I produced this". It is minted beside the
    /// durable `EventKind::ArtifactProduced`, from the same handle, so a socket client and the
    /// record cannot disagree about what was produced.
    ArtifactProduced {
        artifact: iteron_protocol::artifact::ArtifactRef,
    },
}

/// Cost as evidence-backed state, not a bare number.
///
/// `Unknown` is a first-class answer: a completed turn without matching durable pricing evidence is
/// honestly unpriced, and a client that renders `0.0` for it is lying about the run. `Zero` is kept
/// distinct from both for the same reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ClientCost {
    Zero,
    Known { usd: f64 },
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientContextEstimate {
    pub system_tokens: usize,
    pub tool_tokens: usize,
    pub transcript_tokens: usize,
    pub framing_tokens: usize,
    pub total_tokens: usize,
    /// How the estimate was produced. Published so a client can say "estimated", not "measured".
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "application", rename_all = "snake_case")]
pub enum ClientEffortApplication {
    Exact {
        requested: ReasoningEffort,
    },
    Mapped {
        requested: ReasoningEffort,
        sent: ReasoningEffort,
    },
    BudgetBased {
        requested: ReasoningEffort,
        budget_tokens: u32,
    },
    ToggleOnly {
        requested: ReasoningEffort,
        enabled: bool,
    },
    Unsupported {
        requested: ReasoningEffort,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientWorkflowTask {
    pub id: usize,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientWorkflowExecutionMode {
    Direct,
    Sequential,
    Concurrent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientWorkflowPhase {
    Planning,
    Exploring,
    Synthesizing,
    Writing,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientWorkflowAgentOutcome {
    Done,
    Failed,
    Interrupted,
    SkippedBudget,
    NotStarted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientWorkflowRunOutcome {
    Done,
    Degraded,
    BudgetExhausted,
    Stuck,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientWorkflowEvent {
    RunStarted {
        run_id: String,
        name: String,
        class: String,
    },
    PlanReady {
        run_id: String,
        tasks: Vec<ClientWorkflowTask>,
        dropped: usize,
        duplicates_removed: usize,
        invalid_removed: usize,
        execution_mode: ClientWorkflowExecutionMode,
        fan_turn_budget: u32,
        writer_turn_reserve: u32,
        fan_wall_secs: u64,
        writer_wall_reserve_secs: u64,
    },
    PhaseChanged {
        run_id: String,
        phase: ClientWorkflowPhase,
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
        outcome: ClientWorkflowAgentOutcome,
        turns: u32,
        tokens: u64,
        tool_calls: u64,
        elapsed_ms: u64,
        summary_preview: Option<String>,
        error_preview: Option<String>,
    },
    RunFinished {
        run_id: String,
        outcome: ClientWorkflowRunOutcome,
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

impl From<&iteron_protocol::artifact::ArtifactRef> for ClientEvent {
    fn from(artifact: &iteron_protocol::artifact::ArtifactRef) -> Self {
        Self::ArtifactProduced {
            artifact: artifact.clone(),
        }
    }
}

impl From<&iteron_obs::CostState> for ClientCost {
    fn from(cost: &iteron_obs::CostState) -> Self {
        match cost {
            iteron_obs::CostState::Zero => Self::Zero,
            iteron_obs::CostState::Known { .. } => Self::Known {
                // `usd()` is the frozen accessor; recomputing from microusd here would be a second
                // implementation of the same conversion, free to drift from the authoritative one.
                usd: cost.usd().unwrap_or_default(),
            },
            iteron_obs::CostState::Unknown { reason } => Self::Unknown {
                reason: reason.code().to_owned(),
            },
        }
    }
}

impl From<&iteron_ctx::ContextEstimate> for ClientContextEstimate {
    fn from(estimate: &iteron_ctx::ContextEstimate) -> Self {
        Self {
            system_tokens: estimate.system_tokens,
            tool_tokens: estimate.tool_tokens,
            transcript_tokens: estimate.transcript_tokens,
            framing_tokens: estimate.framing_tokens,
            total_tokens: estimate.total_tokens,
            provenance: format!("{:?}", estimate.provenance),
        }
    }
}

impl From<&iteron_provider::EffortApplication> for ClientEffortApplication {
    fn from(effort: &iteron_provider::EffortApplication) -> Self {
        use iteron_provider::EffortApplication as E;
        match effort {
            E::Exact { requested } => Self::Exact {
                requested: *requested,
            },
            E::Mapped { requested, sent } => Self::Mapped {
                requested: *requested,
                sent: *sent,
            },
            E::BudgetBased {
                requested,
                budget_tokens,
            } => Self::BudgetBased {
                requested: *requested,
                budget_tokens: *budget_tokens,
            },
            E::ToggleOnly { requested, enabled } => Self::ToggleOnly {
                requested: *requested,
                enabled: *enabled,
            },
            E::Unsupported { requested } => Self::Unsupported {
                requested: *requested,
            },
        }
    }
}

impl From<&WorkflowTaskUi> for ClientWorkflowTask {
    fn from(task: &WorkflowTaskUi) -> Self {
        Self {
            id: task.id,
            label: task.label.clone(),
        }
    }
}

impl From<&WorkflowExecutionModeUi> for ClientWorkflowExecutionMode {
    fn from(mode: &WorkflowExecutionModeUi) -> Self {
        match mode {
            WorkflowExecutionModeUi::Direct => Self::Direct,
            WorkflowExecutionModeUi::Sequential => Self::Sequential,
            WorkflowExecutionModeUi::Concurrent => Self::Concurrent,
        }
    }
}

impl From<&WorkflowPhaseUi> for ClientWorkflowPhase {
    fn from(phase: &WorkflowPhaseUi) -> Self {
        match phase {
            WorkflowPhaseUi::Planning => Self::Planning,
            WorkflowPhaseUi::Exploring => Self::Exploring,
            WorkflowPhaseUi::Synthesizing => Self::Synthesizing,
            WorkflowPhaseUi::Writing => Self::Writing,
            WorkflowPhaseUi::Direct => Self::Direct,
        }
    }
}

impl From<&WorkflowAgentOutcomeUi> for ClientWorkflowAgentOutcome {
    fn from(outcome: &WorkflowAgentOutcomeUi) -> Self {
        match outcome {
            WorkflowAgentOutcomeUi::Done => Self::Done,
            WorkflowAgentOutcomeUi::Failed => Self::Failed,
            WorkflowAgentOutcomeUi::Interrupted => Self::Interrupted,
            WorkflowAgentOutcomeUi::SkippedBudget => Self::SkippedBudget,
            WorkflowAgentOutcomeUi::NotStarted => Self::NotStarted,
        }
    }
}

impl From<&WorkflowRunOutcomeUi> for ClientWorkflowRunOutcome {
    fn from(outcome: &WorkflowRunOutcomeUi) -> Self {
        match outcome {
            WorkflowRunOutcomeUi::Done => Self::Done,
            WorkflowRunOutcomeUi::Degraded => Self::Degraded,
            WorkflowRunOutcomeUi::BudgetExhausted => Self::BudgetExhausted,
            WorkflowRunOutcomeUi::Stuck => Self::Stuck,
            WorkflowRunOutcomeUi::Failed => Self::Failed,
            WorkflowRunOutcomeUi::Stopped => Self::Stopped,
        }
    }
}

impl From<&WorkflowUiEvent> for ClientWorkflowEvent {
    fn from(event: &WorkflowUiEvent) -> Self {
        match event {
            WorkflowUiEvent::RunStarted {
                run_id,
                name,
                class,
            } => Self::RunStarted {
                run_id: run_id.clone(),
                name: name.clone(),
                class: class.clone(),
            },
            WorkflowUiEvent::PlanReady {
                run_id,
                tasks,
                dropped,
                duplicates_removed,
                invalid_removed,
                execution_mode,
                fan_turn_budget,
                writer_turn_reserve,
                fan_wall_secs,
                writer_wall_reserve_secs,
            } => Self::PlanReady {
                run_id: run_id.clone(),
                tasks: tasks.iter().map(ClientWorkflowTask::from).collect(),
                dropped: *dropped,
                duplicates_removed: *duplicates_removed,
                invalid_removed: *invalid_removed,
                execution_mode: execution_mode.into(),
                fan_turn_budget: *fan_turn_budget,
                writer_turn_reserve: *writer_turn_reserve,
                fan_wall_secs: *fan_wall_secs,
                writer_wall_reserve_secs: *writer_wall_reserve_secs,
            },
            WorkflowUiEvent::PhaseChanged { run_id, phase } => Self::PhaseChanged {
                run_id: run_id.clone(),
                phase: phase.into(),
            },
            WorkflowUiEvent::AgentStarted {
                run_id,
                agent_id,
                sub_run,
                turn_budget,
            } => Self::AgentStarted {
                run_id: run_id.clone(),
                agent_id: *agent_id,
                sub_run: sub_run.clone(),
                turn_budget: *turn_budget,
            },
            WorkflowUiEvent::AgentActivity {
                run_id,
                agent_id,
                activity,
            } => Self::AgentActivity {
                run_id: run_id.clone(),
                agent_id: *agent_id,
                activity: activity.clone(),
            },
            WorkflowUiEvent::AgentFinished {
                run_id,
                agent_id,
                outcome,
                turns,
                tokens,
                tool_calls,
                elapsed_ms,
                summary_preview,
                error_preview,
            } => Self::AgentFinished {
                run_id: run_id.clone(),
                agent_id: *agent_id,
                outcome: outcome.into(),
                turns: *turns,
                tokens: *tokens,
                tool_calls: *tool_calls,
                elapsed_ms: *elapsed_ms,
                summary_preview: summary_preview.clone(),
                error_preview: error_preview.clone(),
            },
            WorkflowUiEvent::RunFinished {
                run_id,
                outcome,
                reason,
                elapsed_ms,
                provider_attempts,
                turns,
                tokens,
                tool_calls,
                failed_tasks,
                skipped_tasks,
            } => Self::RunFinished {
                run_id: run_id.clone(),
                outcome: outcome.into(),
                reason: reason.clone(),
                elapsed_ms: *elapsed_ms,
                provider_attempts: *provider_attempts,
                turns: *turns,
                tokens: *tokens,
                tool_calls: *tool_calls,
                failed_tasks: *failed_tasks,
                skipped_tasks: *skipped_tasks,
            },
        }
    }
}

/// The exhaustiveness check.
///
/// A total match: adding a `UiEvent` variant without giving it a wire form does not compile, so the
/// vocabulary cannot silently fall behind the thing it publishes.
impl From<&UiEvent> for ClientEvent {
    fn from(event: &UiEvent) -> Self {
        match event {
            UiEvent::Text(text) => Self::Text { text: text.clone() },
            UiEvent::Thinking(text) => Self::Thinking { text: text.clone() },
            UiEvent::ToolStart { id, name, args } => Self::ToolStart {
                id: id.clone(),
                name: name.clone(),
                args: args.clone(),
            },
            UiEvent::ToolEnd {
                id,
                ok,
                exit_code,
                output,
                diff,
            } => Self::ToolEnd {
                id: id.clone(),
                ok: *ok,
                exit_code: *exit_code,
                output: output.clone(),
                diff: diff.clone(),
            },
            UiEvent::Phase(phase) => Self::Phase { phase: *phase },
            UiEvent::TurnEnd {
                cost,
                usage,
                context,
                model_context_window,
                reserved_output_tokens,
                compaction_trigger_tokens,
                effort,
            } => Self::TurnEnd {
                cost: cost.into(),
                usage: *usage,
                context: context.into(),
                model_context_window: *model_context_window,
                reserved_output_tokens: *reserved_output_tokens,
                compaction_trigger_tokens: *compaction_trigger_tokens,
                effort: effort.into(),
            },
            UiEvent::Workflow(event) => Self::Workflow {
                event: event.into(),
            },
            UiEvent::SteerApplied { count } => Self::SteerApplied { count: *count },
            UiEvent::Notice(text) => Self::Notice { text: text.clone() },
            UiEvent::ApprovalRequest {
                id,
                tool,
                capability,
                reason,
                arguments,
                workspace,
            } => Self::ApprovalRequest {
                id: id.0,
                tool: tool.clone(),
                capability: *capability,
                reason: reason.clone(),
                arguments: arguments.clone(),
                workspace: workspace.clone(),
            },
            UiEvent::Done(outcome) => Self::Done {
                outcome: outcome.clone(),
            },
        }
    }
}

#[cfg(test)]
#[path = "client_event_tests.rs"]
mod tests;

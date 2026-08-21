//! Parser for the stable one-shot Core CLI result object.

use crate::strict_json::parse_json_no_duplicates;
use crate::types::CostStatus;
#[cfg(test)]
use crate::types::RunStatus;
use serde::Deserialize;
use serde_json::Value;

/// Versions of the frozen `iteron --output-format json` contract this consumer can read.
///
/// Keep the current version last. The schema-compatibility corpus test below binds this list to
/// every retained machine-output fixture, so a producer bump cannot silently strand evaluation.
pub const SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS: &[u32] = &[3, 4, 5, 6];
/// Version currently emitted by `iteron --output-format json`.
pub const ITERON_CLI_SCHEMA_VERSION: u32 = 6;
const MAX_CLI_INPUT_ATTACHMENTS: u8 = 8;
const MAX_CLI_IMAGE_BASE64_BYTES: u64 = 8 * 1024 * 1024;
/// Exact machine-record/version pairs admitted by the real evaluation consumer.
pub const SUPPORTED_ITERON_CLI_TYPE_VERSIONS: &[(&str, u32)] = &[
    ("approval_request", 4),
    ("approval_request", 5),
    ("approval_request", 6),
    ("assistant_text", 3),
    ("assistant_text", 4),
    ("assistant_text", 5),
    ("assistant_text", 6),
    ("input_attachment", 5),
    ("input_attachment", 6),
    ("notice", 4),
    ("notice", 5),
    ("notice", 6),
    ("phase", 3),
    ("phase", 4),
    ("phase", 5),
    ("phase", 6),
    ("result", 3),
    ("result", 4),
    ("result", 5),
    ("result", 6),
    ("run_done", 3),
    ("run_done", 4),
    ("run_done", 5),
    ("run_done", 6),
    ("steer_applied", 4),
    ("steer_applied", 5),
    ("steer_applied", 6),
    ("thinking", 4),
    ("thinking", 5),
    ("thinking", 6),
    ("tool_end", 4),
    ("tool_end", 5),
    ("tool_end", 6),
    ("tool_start", 4),
    ("tool_start", 5),
    ("tool_start", 6),
    ("turn_end", 3),
    ("turn_end", 4),
    ("turn_end", 5),
    ("turn_end", 6),
    ("workflow_agent_activity", 4),
    ("workflow_agent_activity", 5),
    ("workflow_agent_activity", 6),
    ("workflow_agent_end", 4),
    ("workflow_agent_end", 5),
    ("workflow_agent_end", 6),
    ("workflow_agent_start", 4),
    ("workflow_agent_start", 5),
    ("workflow_agent_start", 6),
    ("workflow_end", 4),
    ("workflow_end", 5),
    ("workflow_end", 6),
    ("workflow_phase", 4),
    ("workflow_phase", 5),
    ("workflow_phase", 6),
    ("workflow_plan", 4),
    ("workflow_plan", 5),
    ("workflow_plan", 6),
    ("workflow_start", 4),
    ("workflow_start", 5),
    ("workflow_start", 6),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliKernelTax {
    pub admission_latency_us: u64,
    pub broker_latency_us: u64,
    pub record_fsync_latency_us: u64,
    pub estimated_tokens: u64,
    pub failed_runs: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliFinalResult {
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub success: bool,
    pub assistant_text: String,
    pub run_id: String,
    pub cost_usd: Option<f64>,
    pub cost_status: String,
    pub cost_reason: Option<String>,
    pub turns: u32,
    #[serde(default)]
    pub kernel_tax: Option<CliKernelTax>,
    pub exit_code: i32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliMachineEventKind {
    AssistantText,
    InputAttachment,
    Thinking,
    ToolStart,
    ToolEnd,
    Phase,
    TurnEnd,
    WorkflowStart,
    WorkflowPlan,
    WorkflowPhase,
    WorkflowAgentStart,
    WorkflowAgentActivity,
    WorkflowAgentEnd,
    WorkflowEnd,
    SteerApplied,
    Notice,
    ApprovalRequest,
    RunDone,
}

impl CliMachineEventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AssistantText => "assistant_text",
            Self::InputAttachment => "input_attachment",
            Self::Thinking => "thinking",
            Self::ToolStart => "tool_start",
            Self::ToolEnd => "tool_end",
            Self::Phase => "phase",
            Self::TurnEnd => "turn_end",
            Self::WorkflowStart => "workflow_start",
            Self::WorkflowPlan => "workflow_plan",
            Self::WorkflowPhase => "workflow_phase",
            Self::WorkflowAgentStart => "workflow_agent_start",
            Self::WorkflowAgentActivity => "workflow_agent_activity",
            Self::WorkflowAgentEnd => "workflow_agent_end",
            Self::WorkflowEnd => "workflow_end",
            Self::SteerApplied => "steer_applied",
            Self::Notice => "notice",
            Self::ApprovalRequest => "approval_request",
            Self::RunDone => "run_done",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
// Keep the parsed terminal result inline: boxing this public contract would add
// allocation and change the API solely to optimize a short-lived parser enum.
#[allow(clippy::large_enum_variant)]
pub enum CliMachineRecord {
    Event {
        schema_version: u32,
        kind: CliMachineEventKind,
    },
    Result(CliFinalResult),
}

#[derive(Debug)]
// Like the public projection above, the terminal result is intentionally kept inline. This
// private form retains the fully decoded event so stream consumers do not parse each line twice.
#[allow(clippy::large_enum_variant)]
enum ParsedCliMachineRecord {
    Event(CliStreamEvent),
    Result(CliFinalResult),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CliRunOutput {
    pub(crate) result: CliFinalResult,
    /// Sum of every admitted `turn_end` usage sample. `None` means the selected output surface did
    /// not carry usage; it is never rewritten to a misleading measured zero.
    pub(crate) usage: Option<iteron_protocol::Usage>,
    /// Content-free tool/context behavior from typed stream events. A final-result-only surface has
    /// no such evidence and remains `None`.
    pub(crate) optimization: Option<crate::types::OptimizationMetrics>,
}

#[derive(Debug, Default)]
struct OptimizationAccumulator {
    metrics: crate::types::OptimizationMetrics,
    open_tools: std::collections::BTreeSet<String>,
    prior_transcript_tokens: Option<u64>,
    component_samples: u64,
    cumulative_components: crate::types::ContextComponentTokens,
    peak_components: crate::types::ContextComponentTokens,
    final_components: crate::types::ContextComponentTokens,
    observed: bool,
}

impl OptimizationAccumulator {
    fn observe(&mut self, event: &CliStreamEvent) -> Result<(), ContractError> {
        match event {
            CliStreamEvent::ToolStart { tool_use_id, .. } => {
                self.observed = true;
                self.metrics.tool_calls_started =
                    checked_increment(self.metrics.tool_calls_started, "tool_calls_started")?;
                self.open_tools.insert(tool_use_id.clone());
                self.metrics.peak_tool_concurrency = self.metrics.peak_tool_concurrency.max(
                    u64::try_from(self.open_tools.len())
                        .map_err(|_| ContractError::OptimizationOverflow("open_tools"))?,
                );
            }
            CliStreamEvent::ToolEnd {
                tool_use_id, ok, ..
            } => {
                self.observed = true;
                self.metrics.tool_calls_completed =
                    checked_increment(self.metrics.tool_calls_completed, "tool_calls_completed")?;
                if !ok {
                    self.metrics.tool_errors =
                        checked_increment(self.metrics.tool_errors, "tool_errors")?;
                }
                self.open_tools.remove(tool_use_id);
            }
            CliStreamEvent::TurnEnd { context, .. } => {
                self.observed = true;
                self.metrics.context_samples =
                    checked_increment(self.metrics.context_samples, "context_samples")?;
                self.metrics.cumulative_context_tokens = self
                    .metrics
                    .cumulative_context_tokens
                    .checked_add(context.input_tokens)
                    .ok_or(ContractError::OptimizationOverflow(
                        "cumulative_context_tokens",
                    ))?;
                self.metrics.peak_context_tokens =
                    self.metrics.peak_context_tokens.max(context.input_tokens);
                self.metrics.final_context_tokens = Some(context.input_tokens);
                self.metrics.peak_system_tokens =
                    self.metrics.peak_system_tokens.max(context.system_tokens);
                self.metrics.peak_tool_schema_tokens = self
                    .metrics
                    .peak_tool_schema_tokens
                    .max(context.tool_tokens);
                self.metrics.peak_transcript_tokens = self
                    .metrics
                    .peak_transcript_tokens
                    .max(context.transcript_tokens);
                if let Some(prior) = self.prior_transcript_tokens
                    && context.transcript_tokens < prior
                {
                    self.metrics.transcript_shrink_events = checked_increment(
                        self.metrics.transcript_shrink_events,
                        "transcript_shrink_events",
                    )?;
                    self.metrics.transcript_tokens_reclaimed = self
                        .metrics
                        .transcript_tokens_reclaimed
                        .checked_add(prior - context.transcript_tokens)
                        .ok_or(ContractError::OptimizationOverflow(
                            "transcript_tokens_reclaimed",
                        ))?;
                }
                self.prior_transcript_tokens = Some(context.transcript_tokens);
                if let Some(components) = context.components {
                    self.component_samples =
                        checked_increment(self.component_samples, "context_component_samples")?;
                    let components = components.into_tokens();
                    self.cumulative_components =
                        self.cumulative_components.checked_add(components).ok_or(
                            ContractError::OptimizationOverflow("cumulative_context_components"),
                        )?;
                    self.peak_components = self.peak_components.component_max(components);
                    self.final_components = components;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn finish(mut self) -> Option<crate::types::OptimizationMetrics> {
        if self.component_samples > 0 && self.component_samples == self.metrics.context_samples {
            self.metrics.context_components = Some(crate::types::ContextComponentMetrics {
                cumulative: self.cumulative_components,
                peak: self.peak_components,
                final_turn: self.final_components,
            });
        }
        self.observed.then_some(self.metrics)
    }
}

fn checked_increment(value: u64, field: &'static str) -> Result<u64, ContractError> {
    value
        .checked_add(1)
        .ok_or(ContractError::OptimizationOverflow(field))
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum CliStreamEvent {
    AssistantText {
        schema_version: u32,
        delta: String,
    },
    InputAttachment {
        schema_version: u32,
        ordinal: CliInputAttachmentOrdinal,
        media_type: CliImageMediaType,
        encoded_bytes: CliImageEncodedBytes,
    },
    Thinking {
        schema_version: u32,
        delta: String,
    },
    ToolStart {
        schema_version: u32,
        tool_use_id: String,
        name: String,
        args: Value,
    },
    ToolEnd {
        schema_version: u32,
        tool_use_id: String,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<CliFileDiff>,
    },
    Phase {
        schema_version: u32,
        phase: String,
    },
    TurnEnd {
        schema_version: u32,
        turn: u32,
        cost_usd: Option<f64>,
        cumulative_cost_usd: Option<f64>,
        cost_status: String,
        cost_reason: Option<String>,
        usage: CliUsage,
        cache_hit: f64,
        context: Box<CliContextEstimate>,
        effort: CliEffortApplication,
    },
    WorkflowStart {
        schema_version: u32,
        workflow_run_id: String,
        name: String,
        class: String,
    },
    WorkflowPlan {
        schema_version: u32,
        workflow_run_id: String,
        tasks: Vec<CliWorkflowTask>,
        dropped: usize,
        duplicates_removed: usize,
        invalid_removed: usize,
        execution_mode: String,
        budget: CliWorkflowBudget,
    },
    WorkflowPhase {
        schema_version: u32,
        workflow_run_id: String,
        phase: String,
    },
    WorkflowAgentStart {
        schema_version: u32,
        workflow_run_id: String,
        agent_id: usize,
        sub_run_id: String,
        turn_budget: u32,
    },
    WorkflowAgentActivity {
        schema_version: u32,
        workflow_run_id: String,
        agent_id: usize,
        activity: String,
    },
    WorkflowAgentEnd {
        schema_version: u32,
        workflow_run_id: String,
        agent_id: usize,
        outcome: String,
        turns: u32,
        tokens: u64,
        tool_calls: u64,
        elapsed_ms: u64,
        summary_preview: Option<String>,
        error_preview: Option<String>,
    },
    WorkflowEnd {
        schema_version: u32,
        workflow_run_id: String,
        outcome: String,
        reason: Option<String>,
        elapsed_ms: u64,
        provider_attempts: u32,
        turns: u32,
        tokens: u64,
        tool_calls: u64,
        failed_tasks: u32,
        skipped_tasks: u32,
    },
    SteerApplied {
        schema_version: u32,
        count: usize,
    },
    Notice {
        schema_version: u32,
        message: String,
    },
    ApprovalRequest {
        schema_version: u32,
        submission_id: u64,
        tool: String,
        capability: String,
        reason: String,
        arguments: Value,
        workspace: String,
    },
    RunDone {
        schema_version: u32,
    },
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliFileDiff {
    path: String,
    adds: u32,
    dels: u32,
    hunks: Vec<CliDiffHunk>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliDiffHunk {
    header: String,
    lines: Vec<CliDiffLine>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliDiffLine {
    tag: CliDiffTag,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
enum CliDiffTag {
    Add,
    Del,
    Ctx,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum CliImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/gif")]
    Gif,
    #[serde(rename = "image/webp")]
    Webp,
}

impl CliStreamEvent {
    fn schema_and_kind(&self) -> (u32, CliMachineEventKind) {
        match self {
            Self::AssistantText { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::AssistantText)
            }
            Self::InputAttachment { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::InputAttachment)
            }
            Self::Thinking { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::Thinking)
            }
            Self::ToolStart { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::ToolStart)
            }
            Self::ToolEnd { schema_version, .. } => (*schema_version, CliMachineEventKind::ToolEnd),
            Self::Phase { schema_version, .. } => (*schema_version, CliMachineEventKind::Phase),
            Self::TurnEnd { schema_version, .. } => (*schema_version, CliMachineEventKind::TurnEnd),
            Self::WorkflowStart { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowStart)
            }
            Self::WorkflowPlan { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowPlan)
            }
            Self::WorkflowPhase { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowPhase)
            }
            Self::WorkflowAgentStart { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowAgentStart)
            }
            Self::WorkflowAgentActivity { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowAgentActivity)
            }
            Self::WorkflowAgentEnd { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowAgentEnd)
            }
            Self::WorkflowEnd { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::WorkflowEnd)
            }
            Self::SteerApplied { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::SteerApplied)
            }
            Self::Notice { schema_version, .. } => (*schema_version, CliMachineEventKind::Notice),
            Self::ApprovalRequest { schema_version, .. } => {
                (*schema_version, CliMachineEventKind::ApprovalRequest)
            }
            Self::RunDone { schema_version } => (*schema_version, CliMachineEventKind::RunDone),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct CliInputAttachmentOrdinal(u8);

impl<'de> Deserialize<'de> for CliInputAttachmentOrdinal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ordinal = u8::deserialize(deserializer)?;
        if ordinal == 0
            || ordinal
                > iteron_tunables::param_integer(
                    "eval.contract.max_cli_input_attachments",
                    MAX_CLI_INPUT_ATTACHMENTS,
                )
        {
            return Err(<D::Error as serde::de::Error>::custom(
                "input attachment ordinal exceeds its frozen bound",
            ));
        }
        Ok(Self(ordinal))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct CliImageEncodedBytes(u64);

impl<'de> Deserialize<'de> for CliImageEncodedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded_bytes = u64::deserialize(deserializer)?;
        if encoded_bytes == 0
            || encoded_bytes
                > iteron_tunables::param_integer(
                    "eval.contract.max_cli_image_base64_bytes",
                    MAX_CLI_IMAGE_BASE64_BYTES,
                )
            || !encoded_bytes.is_multiple_of(4)
        {
            return Err(<D::Error as serde::de::Error>::custom(
                "input attachment encoded size exceeds its frozen bound",
            ));
        }
        Ok(Self(encoded_bytes))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliUsage {
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
    thinking: u64,
}

impl CliUsage {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            input: self.input.checked_add(other.input)?,
            output: self.output.checked_add(other.output)?,
            cache_creation: self.cache_creation.checked_add(other.cache_creation)?,
            cache_read: self.cache_read.checked_add(other.cache_read)?,
            thinking: self.thinking.checked_add(other.thinking)?,
        })
    }

    const fn into_usage(self) -> iteron_protocol::Usage {
        iteron_protocol::Usage {
            input: self.input,
            output: self.output,
            cache_creation: self.cache_creation,
            cache_read: self.cache_read,
            thinking: self.thinking,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliContextEstimate {
    kind: String,
    input_tokens: u64,
    system_tokens: u64,
    tool_tokens: u64,
    transcript_tokens: u64,
    framing_tokens: u64,
    #[serde(default)]
    components: Option<CliContextComponents>,
    estimator: String,
    model_context_window: Option<u64>,
    reserved_output_tokens: u64,
    compaction_trigger_tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliContextComponents {
    stable_prefix_tokens: u64,
    instruction_tokens: u64,
    task_context_tokens: u64,
    memory_tokens: u64,
    transcript_tokens: u64,
    attachment_tokens: u64,
    tool_schema_tokens: u64,
    tool_result_tokens: u64,
    lsp_result_tokens: u64,
}

impl CliContextComponents {
    const fn into_tokens(self) -> crate::types::ContextComponentTokens {
        crate::types::ContextComponentTokens {
            stable_prefix: self.stable_prefix_tokens,
            instructions: self.instruction_tokens,
            task_context: self.task_context_tokens,
            memory: self.memory_tokens,
            transcript: self.transcript_tokens,
            attachments: self.attachment_tokens,
            tool_schemas: self.tool_schema_tokens,
            tool_results: self.tool_result_tokens,
            lsp_results: self.lsp_result_tokens,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "enforcement", rename_all = "snake_case", deny_unknown_fields)]
enum CliEffortApplication {
    Exact {
        meaning: String,
        capability_proven_by_catalog: bool,
        requested: String,
        sent: String,
    },
    Mapped {
        capability_proven_by_catalog: bool,
        requested: String,
        sent: String,
    },
    BudgetBased {
        capability_proven_by_catalog: bool,
        requested: String,
        budget_tokens: u32,
    },
    ToggleOnly {
        capability_proven_by_catalog: bool,
        requested: String,
        enabled: bool,
    },
    Unsupported {
        capability_proven_by_catalog: bool,
        requested: String,
    },
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliWorkflowTask {
    id: usize,
    label: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliWorkflowBudget {
    fan_turns: u32,
    writer_turns_reserved: u32,
    fan_wall_secs: u64,
    writer_wall_secs_reserved: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("iteron stdout is not one valid final-result JSON object: {0}")]
    MalformedJson(String),
    #[error(
        "unsupported iteron CLI schema_version {actual}; expected an admitted frozen version through {expected}"
    )]
    SchemaVersion { actual: u32, expected: u32 },
    #[error("iteron CLI machine record `{kind}` has no frozen schema_version {actual} contract")]
    TypeVersion { kind: String, actual: u32 },
    #[error("iteron JSON object has type `{0}`, expected `result`")]
    WrongType(String),
    #[error("iteron process exit {process} disagrees with result exit_code {result}")]
    ExitMismatch { process: i32, result: i32 },
    #[error("iteron result success/outcome fields are inconsistent")]
    OutcomeMismatch,
    #[error("known cost is missing cost_usd")]
    KnownCostMissing,
    #[error("known cost is negative or non-finite")]
    InvalidKnownCost,
    #[error("unknown cost_status `{0}`")]
    UnknownCostStatus(String),
    #[error("iteron stream does not contain exactly one terminal result")]
    TerminalResultCardinality,
    #[error("iteron stream contains a machine event after its terminal result")]
    EventAfterResult,
    #[error("iteron stream token usage overflowed its u64 accounting bound")]
    UsageOverflow,
    #[error("iteron stream optimization metric `{0}` overflowed its u64 accounting bound")]
    OptimizationOverflow(&'static str),
}

fn admit_type_version(kind: &str, actual: u32) -> Result<(), ContractError> {
    if !SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS.contains(&actual) {
        return Err(ContractError::SchemaVersion {
            actual,
            expected: ITERON_CLI_SCHEMA_VERSION,
        });
    }
    if !SUPPORTED_ITERON_CLI_TYPE_VERSIONS.contains(&(kind, actual)) {
        return Err(ContractError::TypeVersion {
            kind: kind.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// Parse one strict JSON/JSONL record from either machine-output surface.
///
/// This is intentionally version-aware and type-aware rather than a generic `serde_json::Value`
/// check. Additive producer changes therefore require both a new frozen fixture and an updated
/// consumer before the schema version can be admitted.
pub fn parse_machine_record(bytes: &[u8]) -> Result<CliMachineRecord, ContractError> {
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::MalformedJson("missing string field `type`".into()))?;
    if kind == "result" {
        let result: CliFinalResult = serde_json::from_value(value)
            .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
        admit_type_version("result", result.schema_version)?;
        return Ok(CliMachineRecord::Result(result));
    }

    let event: CliStreamEvent = serde_json::from_value(value)
        .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
    let (schema_version, kind) = event.schema_and_kind();
    admit_type_version(kind.as_str(), schema_version)?;
    Ok(CliMachineRecord::Event {
        schema_version,
        kind,
    })
}

fn parse_machine_record_payload(bytes: &[u8]) -> Result<ParsedCliMachineRecord, ContractError> {
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::MalformedJson("missing string field `type`".into()))?;
    if kind == "result" {
        let result: CliFinalResult = serde_json::from_value(value)
            .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
        admit_type_version("result", result.schema_version)?;
        return Ok(ParsedCliMachineRecord::Result(result));
    }

    let event: CliStreamEvent = serde_json::from_value(value)
        .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
    let (schema_version, kind) = event.schema_and_kind();
    admit_type_version(kind.as_str(), schema_version)?;
    if let CliStreamEvent::TurnEnd { context, .. } = &event {
        match (schema_version >= 6, context.components.is_some()) {
            (true, false) => {
                return Err(ContractError::MalformedJson(
                    "schema v6 turn_end lacks `context.components`".into(),
                ));
            }
            (false, true) => {
                return Err(ContractError::MalformedJson(
                    "pre-v6 turn_end unexpectedly carries `context.components`".into(),
                ));
            }
            (true, true) | (false, false) => {}
        }
    }
    Ok(ParsedCliMachineRecord::Event(event))
}

pub fn parse_final_result(
    stdout: &[u8],
    process_exit: i32,
) -> Result<CliFinalResult, ContractError> {
    let result = match parse_machine_record(stdout)? {
        CliMachineRecord::Result(result) => result,
        CliMachineRecord::Event { kind, .. } => {
            return Err(ContractError::WrongType(kind.as_str().into()));
        }
    };
    if result.schema_version >= 5 && result.kernel_tax.is_none() {
        return Err(ContractError::MalformedJson(
            "schema v5 result lacks `kernel_tax`".into(),
        ));
    }
    if result.exit_code != process_exit {
        return Err(ContractError::ExitMismatch {
            process: process_exit,
            result: result.exit_code,
        });
    }
    if result.success != matches!(result.outcome.as_str(), "done" | "drained") {
        return Err(ContractError::OutcomeMismatch);
    }
    // Validate cost truth eagerly; a malformed cost must classify the cell as a harness error.
    let _ = result.cost()?;
    Ok(result)
}

/// Parse the bounded stdout of either the one-object `json` surface or the multi-record
/// `stream-json` surface. The latter is required for exact per-turn token accounting.
pub(crate) fn parse_run_output(
    stdout: &[u8],
    process_exit: i32,
) -> Result<CliRunOutput, ContractError> {
    let mut result = None;
    let mut usage = None::<CliUsage>;
    let mut optimization = OptimizationAccumulator::default();
    for line in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
    {
        match parse_machine_record_payload(line)? {
            ParsedCliMachineRecord::Event(event) => {
                if result.is_some() {
                    return Err(ContractError::EventAfterResult);
                }
                if let CliStreamEvent::TurnEnd { usage: sample, .. } = &event {
                    usage = Some(match usage {
                        Some(total) => total
                            .checked_add(*sample)
                            .ok_or(ContractError::UsageOverflow)?,
                        None => *sample,
                    });
                }
                optimization.observe(&event)?;
            }
            ParsedCliMachineRecord::Result(observed) => {
                if result.replace(observed).is_some() {
                    return Err(ContractError::TerminalResultCardinality);
                }
            }
        }
    }
    let result = result.ok_or(ContractError::TerminalResultCardinality)?;
    Ok(CliRunOutput {
        result: validate_final_result(result, process_exit)?,
        usage: usage.map(CliUsage::into_usage),
        optimization: optimization.finish(),
    })
}

fn validate_final_result(
    result: CliFinalResult,
    process_exit: i32,
) -> Result<CliFinalResult, ContractError> {
    if result.schema_version >= 5 && result.kernel_tax.is_none() {
        return Err(ContractError::MalformedJson(
            "schema v5 result lacks `kernel_tax`".into(),
        ));
    }
    if result.exit_code != process_exit {
        return Err(ContractError::ExitMismatch {
            process: process_exit,
            result: result.exit_code,
        });
    }
    if result.success != matches!(result.outcome.as_str(), "done" | "drained") {
        return Err(ContractError::OutcomeMismatch);
    }
    // Validate cost truth eagerly; a malformed cost must classify the cell as a harness error.
    let _ = result.cost()?;
    Ok(result)
}

pub fn cost_status(result: &CliFinalResult) -> Result<CostStatus, ContractError> {
    Ok(result.cost()?.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn result_json(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"run-contract","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":2,"exit_code":0,"error":null{extra}}}"#
        )
        .into_bytes()
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root exists")
    }

    fn compatibility_contract(root: &Path) -> Value {
        serde_json::from_slice(
            &std::fs::read(root.join("governance/schema-compatibility.json"))
                .expect("compatibility contract is readable"),
        )
        .expect("compatibility contract is JSON")
    }

    #[test]
    fn multiple_human_turn_counts_on_stderr_cannot_change_machine_json() {
        let stdout = result_json("");
        let stderr_variants = [
            b"session turns=1\nledger turns=400\nsummary turns=999999\n".as_slice(),
            b"turns=0\nturns=7 cost=$0.00\nturns=4294967295\n".as_slice(),
        ];
        assert!(
            stderr_variants.iter().all(|stderr| stderr
                .windows(b"turns=".len())
                .filter(|window| *window == b"turns=")
                .count()
                > 1),
            "each human-only fixture must contain multiple conflicting turns= fields"
        );

        let parsed: Vec<_> = stderr_variants
            .iter()
            .map(|stderr| {
                let output = crate::process::ProcessOutput {
                    exit_code: 0,
                    stdout: stdout.clone(),
                    stderr: stderr.to_vec(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                };
                // This is the production seam used by runner.rs: only the versioned stdout object
                // and OS exit code enter the contract parser. Human stderr is retained solely as
                // diagnostic evidence and cannot be scraped into `turns`.
                parse_final_result(&output.stdout, output.exit_code).unwrap()
            })
            .collect();

        assert_eq!(parsed[0], parsed[1]);
        assert_eq!(parsed[0].turns, 2);
        assert_eq!(parsed[0].run_status(), RunStatus::Completed);
        assert_eq!(parsed[0].cost().unwrap().status, CostStatus::Unknown);
    }

    #[test]
    fn schema_mismatch_and_absent_result_fail_loudly() {
        let wrong = String::from_utf8(result_json(""))
            .unwrap()
            .replace("\"schema_version\":4", "\"schema_version\":999");
        assert!(matches!(
            parse_final_result(wrong.as_bytes(), 0),
            Err(ContractError::SchemaVersion { .. })
        ));
        assert!(matches!(
            parse_final_result(b"turns=9 cost=$0.00", 0),
            Err(ContractError::MalformedJson(_))
        ));
    }

    #[test]
    fn machine_admission_is_scoped_to_the_exact_type_version_pair() {
        assert!(matches!(
            parse_machine_record(br#"{"schema_version":3,"type":"thinking","delta":"old"}"#),
            Err(ContractError::TypeVersion { kind, actual })
                if kind == "thinking" && actual == 3
        ));
        assert!(matches!(
            parse_machine_record(br#"{"schema_version":3,"type":"assistant_text","delta":"old"}"#),
            Ok(CliMachineRecord::Event {
                schema_version: 3,
                kind: CliMachineEventKind::AssistantText,
                ..
            })
        ));
        assert!(matches!(
            parse_machine_record(
                br#"{"encoded_bytes":12,"media_type":"image/png","ordinal":1,"schema_version":5,"type":"input_attachment"}"#
            ),
            Ok(CliMachineRecord::Event {
                schema_version: 5,
                kind: CliMachineEventKind::InputAttachment,
                ..
            })
        ));
        for malformed in [
            br#"{"encoded_bytes":12,"media_type":"image/png","ordinal":0,"schema_version":5,"type":"input_attachment"}"#.as_slice(),
            br#"{"encoded_bytes":3,"media_type":"image/png","ordinal":1,"schema_version":5,"type":"input_attachment"}"#.as_slice(),
            br#"{"encoded_bytes":12,"media_type":"image/svg+xml","ordinal":1,"schema_version":5,"type":"input_attachment"}"#.as_slice(),
        ] {
            assert!(
                parse_machine_record(malformed).is_err(),
                "invalid attachment metadata must fail closed"
            );
        }
    }

    #[test]
    fn machine_parser_rejects_duplicate_keys_at_every_depth() {
        for malformed in [
            br#"{"schema_version":4,"type":"thinking","delta":"first","delta":"second"}"#.as_slice(),
            br#"{"schema_version":4,"type":"tool_start","tool_use_id":"tool-1","name":"read_file","args":{"path":"a","path":"b"}}"#.as_slice(),
        ] {
            let error = parse_machine_record(malformed)
                .expect_err("duplicate machine-output keys must fail closed");
            assert!(
                matches!(&error, ContractError::MalformedJson(message) if message.contains("duplicate JSON object key")),
                "unexpected duplicate-key error: {error}"
            );
        }
    }

    #[test]
    fn terminal_outcome_and_process_exit_drive_classification() {
        let budget = br#"{"schema_version":4,"type":"result","outcome":"budget_exhausted","reason":"max_turns","success":false,"assistant_text":"","run_id":"run-budget","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":4,"exit_code":3,"error":null}"#;
        let parsed = parse_final_result(budget, 3).unwrap();
        assert_eq!(parsed.run_status(), RunStatus::Censored);
        assert!(matches!(
            parse_final_result(budget, 2),
            Err(ContractError::ExitMismatch { .. })
        ));
    }

    #[test]
    fn unknown_cost_never_becomes_numeric_zero() {
        let cost = parse_final_result(&result_json(""), 0)
            .unwrap()
            .cost()
            .unwrap();
        assert_eq!(cost.status, CostStatus::Unknown);
        assert_eq!(cost.usd, None);
        assert_eq!(cost.reason.as_deref(), Some("no_verified_rate_card"));
    }

    #[test]
    fn d13_14_every_frozen_machine_output_is_accepted_by_the_real_eval_consumer() {
        let root = repository_root();
        let contract = compatibility_contract(&root);
        let surfaces = contract["surfaces"]
            .as_array()
            .expect("surfaces is an array");
        let mut observed_versions = BTreeSet::new();
        let mut observed_types = BTreeSet::new();
        let mut observed_type_versions = BTreeSet::new();
        let mut observed_diff_tags_by_version = BTreeMap::<u32, BTreeSet<CliDiffTag>>::new();
        let mut observed_diff_lines_by_version = BTreeMap::<u32, usize>::new();

        for surface in surfaces.iter().filter(|surface| {
            surface["id"] == "cli.machine-result"
                || surface["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("cli.machine-stream."))
        }) {
            let surface_id = surface["id"].as_str().expect("surface id is a string");
            assert_eq!(
                surface["current_version"], ITERON_CLI_SCHEMA_VERSION,
                "the eval consumer must track the current {surface_id} producer"
            );
            let selector = surface["selector"].as_object().expect("CLI selector");
            let selector_field = selector["field"].as_str().expect("selector field");
            let selector_value = selector["value"].as_str().expect("selector value");
            observed_types.insert(selector_value.to_owned());

            for fixture in surface["fixtures"]
                .as_array()
                .expect("fixtures is an array")
            {
                let relative = fixture["path"].as_str().expect("fixture path is a string");
                let expected_version = fixture["schema_version"]
                    .as_u64()
                    .and_then(|version| u32::try_from(version).ok())
                    .expect("fixture schema version fits u32");
                assert!(
                    SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS.contains(&expected_version),
                    "frozen fixture {relative} has no real eval consumer"
                );
                assert!(
                    SUPPORTED_ITERON_CLI_TYPE_VERSIONS
                        .contains(&(selector_value, expected_version)),
                    "frozen fixture {relative} has no `{selector_value}` schema {expected_version} consumer"
                );
                observed_versions.insert(expected_version);
                observed_type_versions.insert((selector_value.to_owned(), expected_version));

                let bytes = std::fs::read(root.join(relative)).expect("fixture is readable");
                let records = if fixture["format"] == "json" {
                    vec![parse_json_no_duplicates(&bytes).expect("fixture is duplicate-free JSON")]
                } else {
                    std::str::from_utf8(&bytes)
                        .expect("JSONL fixture is UTF-8")
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| {
                            parse_json_no_duplicates(line.as_bytes())
                                .expect("fixture is duplicate-free JSONL")
                        })
                        .collect::<Vec<_>>()
                };
                let selected = records
                    .iter()
                    .filter(|record| record[selector_field] == selector_value)
                    .collect::<Vec<_>>();
                assert!(
                    !selected.is_empty(),
                    "{surface_id} does not occur in {relative}"
                );
                for record in selected {
                    assert_eq!(
                        record["schema_version"], expected_version,
                        "{relative} mixes schema versions"
                    );
                    if selector_value == "tool_end" {
                        let event: CliStreamEvent = serde_json::from_value((*record).clone())
                            .expect("tool_end has the typed eval shape");
                        let CliStreamEvent::ToolEnd {
                            diff: Some(diff), ..
                        } = event
                        else {
                            panic!("{relative} must freeze a non-null typed FileDiff")
                        };
                        for hunk in diff.hunks {
                            *observed_diff_lines_by_version
                                .entry(expected_version)
                                .or_default() += hunk.lines.len();
                            observed_diff_tags_by_version
                                .entry(expected_version)
                                .or_default()
                                .extend(hunk.lines.into_iter().map(|line| line.tag));
                        }
                    }
                    let encoded = serde_json::to_vec(record).expect("machine fixture encodes");
                    match parse_machine_record(&encoded)
                        .unwrap_or_else(|error| panic!("eval rejected {relative}: {error}"))
                    {
                        CliMachineRecord::Event {
                            schema_version,
                            kind,
                            ..
                        } => {
                            assert_ne!(selector_value, "result", "{surface_id}");
                            assert_eq!(schema_version, expected_version, "{relative}");
                            assert_eq!(kind.as_str(), selector_value, "{relative}");
                        }
                        CliMachineRecord::Result(result) => {
                            assert_eq!(selector_value, "result", "{surface_id}");
                            assert_eq!(result.schema_version, expected_version, "{relative}");
                            let parsed = parse_final_result(&encoded, result.exit_code)
                                .unwrap_or_else(|error| {
                                    panic!("eval rejected {relative}: {error}")
                                });
                            if parsed.outcome == "drained" {
                                assert_eq!(parsed.run_status(), RunStatus::Completed);
                            }
                        }
                    }
                }
            }
        }

        let supported_versions = SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_versions, supported_versions,
            "the consumer set and all retained fixture versions must agree"
        );
        let supported_type_versions = SUPPORTED_ITERON_CLI_TYPE_VERSIONS
            .iter()
            .map(|(kind, version)| ((*kind).to_owned(), *version))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            supported_type_versions.len(),
            SUPPORTED_ITERON_CLI_TYPE_VERSIONS.len(),
            "the admitted `(type, schema_version)` matrix cannot contain duplicates"
        );
        assert!(
            SUPPORTED_ITERON_CLI_TYPE_VERSIONS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "the admitted `(type, schema_version)` matrix must remain strictly sorted"
        );
        assert_eq!(
            observed_type_versions, supported_type_versions,
            "eval admission must equal the exact frozen `(type, schema_version)` matrix"
        );
        let supported_diff_versions = SUPPORTED_ITERON_CLI_TYPE_VERSIONS
            .iter()
            .filter_map(|(kind, version)| (*kind == "tool_end").then_some(*version))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_diff_tags_by_version
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            supported_diff_versions,
            "every admitted tool_end version must freeze a typed diff corpus"
        );
        for version in supported_diff_versions {
            let tags = &observed_diff_tags_by_version[&version];
            assert_eq!(
                tags,
                &BTreeSet::from([CliDiffTag::Add, CliDiffTag::Ctx, CliDiffTag::Del]),
                "the schema-v{version} eval consumer must decode every frozen DiffTag"
            );
            assert_eq!(
                observed_diff_lines_by_version[&version],
                tags.len(),
                "the schema-v{version} eval corpus must carry each DiffTag exactly once"
            );
        }
        assert_eq!(
            SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS.last(),
            Some(&ITERON_CLI_SCHEMA_VERSION),
            "the current producer must be the newest admitted consumer version"
        );
        assert_eq!(
            observed_types.len(),
            19,
            "every stream/result type is decoded"
        );
    }

    #[test]
    fn stream_output_sums_disjoint_turn_usage_and_requires_one_terminal_result() {
        let parsed = parse_run_output(
            include_bytes!("../../cli/tests/golden/one_shot_stream_json_success_v5.jsonl"),
            0,
        )
        .expect("frozen stream output parses");
        assert_eq!(parsed.result.outcome, "done");
        assert_eq!(
            parsed.usage,
            Some(iteron_protocol::Usage {
                input: 11,
                output: 2,
                cache_creation: 0,
                cache_read: 0,
                thinking: 0,
            })
        );

        let duplicate = [result_json(""), result_json("")].concat();
        assert!(matches!(
            parse_run_output(&duplicate, 0),
            Err(ContractError::MalformedJson(_) | ContractError::TerminalResultCardinality)
        ));
        assert!(matches!(
            parse_run_output(b"{\"schema_version\":5,\"type\":\"run_done\"}\n", 0),
            Err(ContractError::TerminalResultCardinality)
        ));
    }

    #[test]
    fn stream_output_preserves_generic_tool_and_context_optimization_evidence() {
        fn turn(turn: u32, input: u64, system: u64, tools: u64, transcript: u64) -> Value {
            serde_json::json!({
                "schema_version": 5,
                "type": "turn_end",
                "turn": turn,
                "cost_usd": null,
                "cumulative_cost_usd": null,
                "cost_status": "unknown",
                "cost_reason": "fixture",
                "usage": {
                    "input": input,
                    "output": 1,
                    "cache_creation": 0,
                    "cache_read": 0,
                    "thinking": 0
                },
                "cache_hit": 0.0,
                "context": {
                    "kind": "estimate",
                    "input_tokens": input,
                    "system_tokens": system,
                    "tool_tokens": tools,
                    "transcript_tokens": transcript,
                    "framing_tokens": 200,
                    "estimator": "fixture",
                    "model_context_window": 10000,
                    "reserved_output_tokens": 1000,
                    "compaction_trigger_tokens": 8000
                },
                "effort": {
                    "enforcement": "unsupported",
                    "capability_proven_by_catalog": false,
                    "requested": "medium"
                }
            })
        }

        let records = vec![
            serde_json::json!({
                "schema_version": 5,
                "type": "tool_start",
                "tool_use_id": "call-a",
                "name": "read_file",
                "args": {}
            }),
            serde_json::json!({
                "schema_version": 5,
                "type": "tool_start",
                "tool_use_id": "call-b",
                "name": "grep",
                "args": {}
            }),
            serde_json::json!({
                "schema_version": 5,
                "type": "tool_end",
                "tool_use_id": "call-a",
                "ok": true,
                "exit_code": null,
                "output": "",
                "diff": null
            }),
            turn(1, 1500, 100, 200, 1000),
            serde_json::json!({
                "schema_version": 5,
                "type": "tool_end",
                "tool_use_id": "call-b",
                "ok": false,
                "exit_code": 1,
                "output": "",
                "diff": null
            }),
            turn(2, 900, 110, 250, 400),
            serde_json::json!({
                "schema_version": 5,
                "type": "result",
                "outcome": "done",
                "reason": null,
                "success": true,
                "assistant_text": "done",
                "run_id": "optimization-fixture",
                "cost_usd": null,
                "cost_status": "unknown",
                "cost_reason": "fixture",
                "turns": 2,
                "kernel_tax": {
                    "admission_latency_us": 0,
                    "broker_latency_us": 0,
                    "record_fsync_latency_us": 0,
                    "estimated_tokens": 0,
                    "failed_runs": 0
                },
                "exit_code": 0,
                "error": null
            }),
        ];
        let stream = records
            .into_iter()
            .map(|record| serde_json::to_string(&record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse_run_output(stream.as_bytes(), 0).expect("typed stream parses");
        assert_eq!(
            parsed.optimization,
            Some(crate::types::OptimizationMetrics {
                tool_calls_started: 2,
                tool_calls_completed: 2,
                tool_errors: 1,
                peak_tool_concurrency: 2,
                context_samples: 2,
                cumulative_context_tokens: 2400,
                peak_context_tokens: 1500,
                final_context_tokens: Some(900),
                peak_system_tokens: 110,
                peak_tool_schema_tokens: 250,
                peak_transcript_tokens: 1000,
                transcript_shrink_events: 1,
                transcript_tokens_reclaimed: 600,
                context_components: None,
            })
        );
    }

    #[test]
    fn v6_turns_aggregate_every_non_overlapping_context_source() {
        let components = |base: u64| {
            serde_json::json!({
                "stable_prefix_tokens": base,
                "instruction_tokens": base + 1,
                "task_context_tokens": base + 2,
                "memory_tokens": base + 3,
                "transcript_tokens": base + 4,
                "attachment_tokens": base + 5,
                "tool_schema_tokens": base + 6,
                "tool_result_tokens": base + 7,
                "lsp_result_tokens": base + 8
            })
        };
        let turn = |ordinal: u32, base: u64| {
            serde_json::json!({
                "schema_version": 6,
                "type": "turn_end",
                "turn": ordinal,
                "cost_usd": null,
                "cumulative_cost_usd": null,
                "cost_status": "unknown",
                "cost_reason": "fixture",
                "usage": {"input": 100, "output": 1, "cache_creation": 0, "cache_read": 0, "thinking": 0},
                "cache_hit": 0.0,
                "context": {
                    "kind": "estimate",
                    "input_tokens": 100,
                    "system_tokens": 20,
                    "tool_tokens": 10,
                    "transcript_tokens": 60,
                    "framing_tokens": 10,
                    "components": components(base),
                    "estimator": "fixture",
                    "model_context_window": 10000,
                    "reserved_output_tokens": 1000,
                    "compaction_trigger_tokens": 8000
                },
                "effort": {"enforcement": "unsupported", "capability_proven_by_catalog": false, "requested": "medium"}
            })
        };
        let records = [
            turn(1, 10),
            turn(2, 20),
            serde_json::json!({
                "schema_version": 6,
                "type": "result",
                "outcome": "done",
                "reason": null,
                "success": true,
                "assistant_text": "done",
                "run_id": "component-fixture",
                "cost_usd": null,
                "cost_status": "unknown",
                "cost_reason": "fixture",
                "turns": 2,
                "kernel_tax": {"admission_latency_us": 0, "broker_latency_us": 0, "record_fsync_latency_us": 0, "estimated_tokens": 0, "failed_runs": 0},
                "exit_code": 0,
                "error": null
            }),
        ];
        let stream = records
            .into_iter()
            .map(|record| serde_json::to_string(&record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let observed = parse_run_output(stream.as_bytes(), 0)
            .unwrap()
            .optimization
            .unwrap()
            .context_components
            .unwrap();
        assert_eq!(observed.cumulative.stable_prefix, 30);
        assert_eq!(observed.cumulative.memory, 36);
        assert_eq!(observed.cumulative.tool_results, 44);
        assert_eq!(observed.cumulative.lsp_results, 46);
        assert_eq!(observed.peak.memory, 23);
        assert_eq!(observed.final_turn.transcript, 24);
    }

    #[test]
    fn context_component_shape_is_bound_to_cli_schema_v6() {
        let mut v6: Value = serde_json::from_str(
            include_str!("../../cli/tests/golden/one_shot_stream_json_success_v6.jsonl")
                .lines()
                .find(|line| line.contains("\"type\":\"turn_end\""))
                .unwrap(),
        )
        .unwrap();
        v6["context"].as_object_mut().unwrap().remove("components");
        assert!(matches!(
            parse_machine_record_payload(&serde_json::to_vec(&v6).unwrap()),
            Err(ContractError::MalformedJson(_))
        ));

        let mut v5 = v6;
        v5["schema_version"] = Value::from(5);
        v5["context"].as_object_mut().unwrap().insert(
            "components".into(),
            serde_json::json!({
                "stable_prefix_tokens": 0,
                "instruction_tokens": 0,
                "task_context_tokens": 0,
                "memory_tokens": 0,
                "transcript_tokens": 0,
                "attachment_tokens": 0,
                "tool_schema_tokens": 0,
                "tool_result_tokens": 0,
                "lsp_result_tokens": 0
            }),
        );
        assert!(matches!(
            parse_machine_record_payload(&serde_json::to_vec(&v5).unwrap()),
            Err(ContractError::MalformedJson(_))
        ));
    }
}

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
pub const SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS: &[u32] = &[3, 4, 5];
/// Version currently emitted by `iteron --output-format json`.
pub const ITERON_CLI_SCHEMA_VERSION: u32 = 5;
const MAX_CLI_INPUT_ATTACHMENTS: u8 = 8;
const MAX_CLI_IMAGE_BASE64_BYTES: u64 = 8 * 1024 * 1024;
/// Exact machine-record/version pairs admitted by the real evaluation consumer.
pub const SUPPORTED_ITERON_CLI_TYPE_VERSIONS: &[(&str, u32)] = &[
    ("approval_request", 4),
    ("approval_request", 5),
    ("assistant_text", 3),
    ("assistant_text", 4),
    ("assistant_text", 5),
    ("input_attachment", 5),
    ("notice", 4),
    ("notice", 5),
    ("phase", 3),
    ("phase", 4),
    ("phase", 5),
    ("result", 3),
    ("result", 4),
    ("result", 5),
    ("run_done", 3),
    ("run_done", 4),
    ("run_done", 5),
    ("steer_applied", 4),
    ("steer_applied", 5),
    ("thinking", 4),
    ("thinking", 5),
    ("tool_end", 4),
    ("tool_end", 5),
    ("tool_start", 4),
    ("tool_start", 5),
    ("turn_end", 3),
    ("turn_end", 4),
    ("turn_end", 5),
    ("workflow_agent_activity", 4),
    ("workflow_agent_activity", 5),
    ("workflow_agent_end", 4),
    ("workflow_agent_end", 5),
    ("workflow_agent_start", 4),
    ("workflow_agent_start", 5),
    ("workflow_end", 4),
    ("workflow_end", 5),
    ("workflow_phase", 4),
    ("workflow_phase", 5),
    ("workflow_plan", 4),
    ("workflow_plan", 5),
    ("workflow_start", 4),
    ("workflow_start", 5),
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
        context: CliContextEstimate,
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
        if ordinal == 0 || ordinal > MAX_CLI_INPUT_ATTACHMENTS {
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
            || encoded_bytes > MAX_CLI_IMAGE_BASE64_BYTES
            || !encoded_bytes.is_multiple_of(4)
        {
            return Err(<D::Error as serde::de::Error>::custom(
                "input attachment encoded size exceeds its frozen bound",
            ));
        }
        Ok(Self(encoded_bytes))
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliUsage {
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
    thinking: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliContextEstimate {
    kind: String,
    input_tokens: usize,
    system_tokens: usize,
    tool_tokens: usize,
    transcript_tokens: usize,
    framing_tokens: usize,
    estimator: String,
    model_context_window: Option<usize>,
    reserved_output_tokens: usize,
    compaction_trigger_tokens: usize,
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
            })
        ));
        assert!(matches!(
            parse_machine_record(
                br#"{"encoded_bytes":12,"media_type":"image/png","ordinal":1,"schema_version":5,"type":"input_attachment"}"#
            ),
            Ok(CliMachineRecord::Event {
                schema_version: 5,
                kind: CliMachineEventKind::InputAttachment,
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
}

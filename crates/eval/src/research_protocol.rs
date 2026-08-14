//! Strict benchmark-neutral `iteron-research/1` request/response protocol.

use crate::adapter_registry::{AdapterOperation, AdapterPin, AdapterRegistryEntry};
use crate::strict_json::parse_json_no_duplicates;
use crate::terminal_bench::{AdapterCommand, ArtifactReference, TerminalBenchRequest};
use crate::tuner::{
    CandidateAddress, CandidateGraphIdentity, CandidateNodeClass, CandidatePatch,
    CandidateProductionPlan, TunerCandidate,
};
use serde::{Deserialize, Serialize};

pub const RESEARCH_PROTOCOL: &str = "iteron-research/1";
pub const EXTERNAL_NATIVE_ADAPTER_PROTOCOL: &str = "iteron-native-adapter/2";
pub const NATIVE_MATERIALIZATION_SCHEMA: &str = "iteron-candidate-materialization/2";
pub const NATIVE_CONSUMPTION_SCHEMA: &str = "iteron-candidate-materialization-consumption/2";
pub const EXTERNAL_NATIVE_RESULT_SCHEMA: &str = "iteron-native-adapter-result/1";
pub const MAX_NATIVE_MATERIALIZATION_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_NATIVE_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROTOCOL_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PROTOCOL_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_ID_BYTES: usize = 256;
pub(crate) const MAX_PATH_BYTES: usize = 4096;
pub(crate) const MAX_PROMPT_BYTES: usize = 256 * 1024;
pub(crate) const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub(crate) const MAX_WALL_SECS: u64 = 86_400;
pub(crate) const MAX_TURNS: u32 = 1_000_000;
pub(crate) const CREDENTIAL_NAMES: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "FIREWORKS_API_KEY",
    "GLM_API_KEY",
    "MINIMAX_API_KEY",
    "OPENAI_API_KEY",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchRequestEnvelope {
    pub protocol: String,
    pub request_id: String,
    pub payload: ResearchRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
// CandidateValidate owns the bounded candidate so deserialization remains a single closed object;
// boxing it would force broad source-level churn without changing the bounded wire contract.
#[allow(clippy::large_enum_variant)]
pub enum ResearchRequest {
    Surface {
        adapter: AdapterPin,
    },
    CandidateValidate {
        adapter: AdapterPin,
        candidate_sha256: String,
        candidate: TunerCandidate,
        /// Required, absolute create-new destination when the candidate carries implementations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_candidate_path: Option<String>,
        /// Required create-new destination for a v3 graph carrying native patches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        native_materialization_path: Option<String>,
    },
    Run {
        adapter: AdapterPin,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        run_id: String,
        run: Box<RunSpec>,
    },
    Cancel {
        adapter: AdapterPin,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        run_id: String,
    },
    Result {
        adapter: AdapterPin,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        run_id: String,
    },
    Evidence {
        adapter: AdapterPin,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        run_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunSpec {
    IteronCli {
        spec: CliRunSpec,
    },
    TerminalBench21 {
        request: TerminalBenchRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        implementation_candidate: Option<ImplementationCandidateRef>,
    },
    ExternalNative {
        spec: ExternalNativeRunSpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMaterializationDocument {
    pub schema_id: String,
    pub candidate_sha256: String,
    pub candidate_graph_identity: CandidateGraphIdentity,
    pub implementation_activation_sha256: Option<String>,
    /// Full value-bearing production graph. A digest without this plan is never executable.
    pub production_plan: CandidateProductionPlan,
    pub direct_config_patches: Vec<CandidatePatch>,
    pub caller_input_patches: Vec<CandidatePatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePatchConsumption {
    pub address: CandidateAddress,
    pub input_value_sha256: String,
    pub observed_value_sha256: String,
    pub loaded: bool,
    pub applied: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNodeConsumption {
    pub ordinal: u32,
    pub address: CandidateAddress,
    pub class: CandidateNodeClass,
    pub input_node_sha256: String,
    pub observed_node_sha256: String,
    pub dependencies_loaded: bool,
    pub conditions_satisfied: bool,
    pub loaded: bool,
    pub applied: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeImplementationConsumption {
    pub module: iteron_tunables::ModuleId,
    pub implementation_id: String,
    pub input_binding_sha256: String,
    pub observed_binding_sha256: String,
    pub loaded: bool,
    pub applied: bool,
    pub observed: bool,
    pub started: bool,
    pub terminal: bool,
    pub stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConsumptionReceipt {
    pub schema_id: String,
    pub candidate_sha256: String,
    pub materialization_sha256: String,
    pub experiment_sha256: String,
    pub topology_sha256: String,
    pub native_materialization_sha256: String,
    pub implementation_activation_sha256: Option<String>,
    pub run_id: String,
    pub nodes: Vec<NativeNodeConsumption>,
    pub implementations: Vec<NativeImplementationConsumption>,
    pub patches: Vec<NativePatchConsumption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNativeResult {
    pub schema_id: String,
    pub run_id: String,
    pub outcome: String,
    pub success: bool,
    pub exit_code: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_micros: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNativeRunSpec {
    pub binary_path: String,
    pub workspace_path: String,
    pub profile_path: String,
    pub effective_profile_path: String,
    pub native_materialization_path: String,
    pub native_materialization_sha256: String,
    pub consumption_receipt_path: String,
    pub result_path: String,
    pub stdout_path: String,
    pub runs_dir: String,
    pub profile_sha256: String,
    pub candidate_sha256: String,
    pub candidate_graph_identity: CandidateGraphIdentity,
    pub run_id: String,
    #[serde(default)]
    pub task_arguments: Vec<String>,
    #[serde(default)]
    pub credential_env_names: Vec<String>,
    pub max_wall_secs: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationCandidateRef {
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliRunSpec {
    pub binary_path: String,
    pub workspace_path: String,
    pub profile_path: String,
    pub effective_profile_path: String,
    pub result_path: String,
    pub runs_dir: String,
    pub profile_sha256: String,
    pub registry_sha256: String,
    pub param_registry_sha256: String,
    pub iteron_revision: String,
    pub task_prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_candidate_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_candidate_digest: Option<String>,
    #[serde(default)]
    pub credential_env_names: Vec<String>,
    pub max_wall_secs: u64,
    pub max_turns: u32,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_memory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRunState {
    Planned,
    Running,
    AwaitingResult,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    StdoutLimit,
    StderrLimit,
    EvidenceLimit,
}

impl ResearchRunState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Planned | Self::Running | Self::AwaitingResult)
    }
}

/// Source-compatible name retained for callers that only consume dry-run plans.
pub type DryRunState = ResearchRunState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchTerminalResult {
    pub schema_id: String,
    pub run_id: String,
    pub outcome: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub score_micros: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchResponseEnvelope {
    pub protocol: String,
    pub request_id: String,
    pub payload: ResearchResponse,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResearchResponse {
    Surface {
        registry_digest_sha256: String,
        adapters: Vec<AdapterRegistryEntry>,
        candidate_schemas: Vec<String>,
        candidate_capabilities: Vec<String>,
        surface: serde_json::Value,
    },
    CandidateValidate {
        candidate_id: String,
        candidate_schema_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        rendered_bytes: u64,
        implementation_count: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        implementation_activation_bytes: u64,
        native_patch_count: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        native_materialization_sha256: Option<String>,
        native_materialization_bytes: u64,
    },
    Run {
        execution_mode: String,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        implementation_count: u64,
        run_id: String,
        state: ResearchRunState,
        command: AdapterCommand,
        #[serde(skip_serializing_if = "Option::is_none")]
        adapter_result_path: Option<String>,
    },
    Cancel {
        execution_mode: String,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        implementation_count: u64,
        run_id: String,
        state: ResearchRunState,
    },
    Result {
        execution_mode: String,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        implementation_count: u64,
        run_id: String,
        state: ResearchRunState,
        terminal_result_available: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        terminal_result: Option<ResearchTerminalResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    Evidence {
        execution_mode: String,
        candidate_id: String,
        candidate_sha256: String,
        profile_sha256: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        implementation_activation_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate_graph_identity: Option<CandidateGraphIdentity>,
        implementation_count: u64,
        run_id: String,
        state: ResearchRunState,
        evidence_available: bool,
        artifacts: Vec<ArtifactReference>,
    },
    Error {
        failed_operation: AdapterOperation,
        code: String,
        message: String,
    },
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ResearchProtocolError {
    #[error("protocol JSON exceeds its byte bound")]
    TooLarge,
    #[error("invalid protocol JSON: {0}")]
    Json(String),
    #[error("protocol must be exactly iteron-research/1")]
    Protocol,
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("unknown or unpinned benchmark adapter")]
    UnknownAdapter,
    #[error("operation is not supported by this adapter")]
    UnsupportedOperation,
    #[error("run spec does not match the pinned adapter")]
    RunSpecAdapterMismatch,
    #[error("adapter does not support the candidate implementation activation protocol")]
    UnsupportedImplementationActivation,
    #[error("request/response correlation mismatch")]
    Correlation,
    #[error("run id already exists")]
    DuplicateRun,
    #[error("candidate id has not been validated")]
    UnknownCandidate,
    #[error("candidate identity does not match its validated content or run profile")]
    CandidateIdentity,
    #[error("run id is unknown")]
    UnknownRun,
    #[error("run adapter identity mismatch")]
    RunIdentity,
    #[error("execute mode has no operator-pinned executable for this adapter")]
    UnpinnedExecutable,
    #[error("adapter executable does not match the registry-owned identity")]
    ExecutableIdentity,
    #[error("adapter cannot consume direct-config or caller-input candidate patches")]
    UnsupportedCandidateMaterialization,
}

pub fn parse_research_request(
    bytes: &[u8],
) -> Result<ResearchRequestEnvelope, ResearchProtocolError> {
    if bytes.len() > MAX_PROTOCOL_REQUEST_BYTES {
        return Err(ResearchProtocolError::TooLarge);
    }
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| ResearchProtocolError::Json(error.to_string()))?;
    let request: ResearchRequestEnvelope = serde_json::from_value(value)
        .map_err(|error| ResearchProtocolError::Json(error.to_string()))?;
    request.validate_shape()?;
    Ok(request)
}

pub fn parse_research_response(
    bytes: &[u8],
    request: &ResearchRequestEnvelope,
) -> Result<ResearchResponseEnvelope, ResearchProtocolError> {
    if bytes.len() > MAX_PROTOCOL_RESPONSE_BYTES {
        return Err(ResearchProtocolError::TooLarge);
    }
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| ResearchProtocolError::Json(error.to_string()))?;
    let response: ResearchResponseEnvelope = serde_json::from_value(value)
        .map_err(|error| ResearchProtocolError::Json(error.to_string()))?;
    response.validate_against(request)?;
    Ok(response)
}

pub(crate) use crate::research_execution::protocol_validation::{
    ValidatedCandidate, validated_candidate,
};

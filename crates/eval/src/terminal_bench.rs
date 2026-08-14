//! Harness-independent Terminal-Bench 2.1 adapter; it has no selection or promotion authority.

use crate::strict_json::parse_json_no_duplicates;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path};

pub const EXTERNAL_HARNESS_SCHEMA_VERSION: u32 = 1;
pub const TERMINAL_BENCH_ID: &str = "terminal-bench";
pub const TERMINAL_BENCH_VERSION: &str = "2.1";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TASK_PROMPT_BYTES: usize = 256 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_WALL_SECS: u64 = 86_400;
const MAX_TURNS: u32 = 1_000_000;
const ALLOWED_CREDENTIAL_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "FIREWORKS_API_KEY",
    "GLM_API_KEY",
    "MINIMAX_API_KEY",
    "OPENAI_API_KEY",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkPin {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIdentity {
    pub task_id: String,
    pub trial_id: String,
    pub dataset_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileIdentity {
    pub profile_sha256: String,
    pub registry_sha256: String,
    pub param_registry_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBounds {
    pub max_wall_secs: u64,
    pub max_turns: u32,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalBenchRequest {
    pub schema_version: u32,
    pub benchmark: BenchmarkPin,
    pub task: TaskIdentity,
    pub profile: ProfileIdentity,
    pub iteron_revision: String,
    pub binary_path: String,
    pub workspace_path: String,
    pub profile_path: String,
    pub effective_profile_path: String,
    pub result_path: String,
    pub runs_dir: String,
    pub task_prompt: String,
    /// Names only; credential values never enter the serialized contract.
    #[serde(default)]
    pub credential_env_names: Vec<String>,
    pub resources: ResourceBounds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCommand {
    pub program: String,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    /// Credential names that the launcher may inherit directly without materializing their values.
    pub inherit_environment: Vec<String>,
    pub clear_environment: bool,
    pub cwd: String,
    pub stdout_path: String,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Completed,
    TimedOut,
    Errored,
    Censored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvidence {
    pub effective_profile: ArtifactReference,
    pub iteron_result: ArtifactReference,
    pub run_record: ArtifactReference,
    pub score_evidence: Option<ArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingEvidence {
    pub started_unix_ms: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub evidence_bytes: u64,
    pub peak_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalHarnessResult {
    pub schema_version: u32,
    pub benchmark: BenchmarkPin,
    pub task: TaskIdentity,
    pub profile: ProfileIdentity,
    pub iteron_revision: String,
    pub run_id: String,
    pub outcome: TerminalOutcome,
    pub success: bool,
    pub exit_code: Option<i32>,
    /// Harness score in millionths. `None` means the external verifier produced no score.
    pub score_micros: Option<u32>,
    pub evidence: RunEvidence,
    pub timing: TimingEvidence,
    pub resources: ResourceUsage,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TerminalBenchAdapterError {
    #[error("external-harness JSON exceeds its byte bound")]
    TooLarge,
    #[error("invalid external-harness JSON: {0}")]
    Json(String),
    #[error("unsupported external-harness schema_version {0}")]
    Schema(u32),
    #[error("benchmark must be exactly terminal-bench/2.1")]
    BenchmarkPin,
    #[error("invalid external-harness field: {0}")]
    Field(&'static str),
    #[error("external-harness result identity does not match its request")]
    IdentityMismatch,
}

pub fn parse_terminal_bench_request(
    bytes: &[u8],
) -> Result<TerminalBenchRequest, TerminalBenchAdapterError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(TerminalBenchAdapterError::TooLarge);
    }
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| TerminalBenchAdapterError::Json(error.to_string()))?;
    let request: TerminalBenchRequest = serde_json::from_value(value)
        .map_err(|error| TerminalBenchAdapterError::Json(error.to_string()))?;
    request.validate()?;
    Ok(request)
}

pub fn parse_external_harness_result(
    bytes: &[u8],
    request: &TerminalBenchRequest,
) -> Result<ExternalHarnessResult, TerminalBenchAdapterError> {
    if bytes.len() > MAX_RESULT_BYTES {
        return Err(TerminalBenchAdapterError::TooLarge);
    }
    let value = parse_json_no_duplicates(bytes)
        .map_err(|error| TerminalBenchAdapterError::Json(error.to_string()))?;
    let result: ExternalHarnessResult = serde_json::from_value(value)
        .map_err(|error| TerminalBenchAdapterError::Json(error.to_string()))?;
    result.validate_against(request)?;
    Ok(result)
}

impl TerminalBenchRequest {
    pub fn validate(&self) -> Result<(), TerminalBenchAdapterError> {
        validate_schema_and_benchmark(self.schema_version, &self.benchmark)?;
        validate_task(&self.task)?;
        validate_profile(&self.profile)?;
        validate_revision(&self.iteron_revision)?;
        for path in [
            &self.binary_path,
            &self.workspace_path,
            &self.profile_path,
            &self.effective_profile_path,
            &self.result_path,
            &self.runs_dir,
        ] {
            validate_absolute_path(path)?;
        }
        if self.task_prompt.is_empty()
            || self.task_prompt.len() > MAX_TASK_PROMPT_BYTES
            || self.task_prompt.contains('\0')
        {
            return Err(TerminalBenchAdapterError::Field("task_prompt"));
        }
        if self.profile_path == self.effective_profile_path
            || self.result_path == self.effective_profile_path
            || self.result_path == self.profile_path
        {
            return Err(TerminalBenchAdapterError::Field("artifact_paths"));
        }
        validate_environment_names(&self.credential_env_names)?;
        self.resources.validate()
    }

    /// Construct the complete ordinary CLI invocation. The caller remains responsible for
    /// bounded process execution and direct, value-free inheritance of the named credentials.
    pub fn command(&self) -> Result<AdapterCommand, TerminalBenchAdapterError> {
        self.validate()?;
        let attempt = format!(
            "{}/{}/{}/{}",
            TERMINAL_BENCH_ID, TERMINAL_BENCH_VERSION, self.task.task_id, self.task.trial_id
        );
        let argv = vec![
            "--print".into(),
            "--output-format".into(),
            "json".into(),
            "--output-schema-version".into(),
            "5".into(),
            "--repo".into(),
            self.workspace_path.clone(),
            "--tunables-profile".into(),
            self.profile_path.clone(),
            "--tunables-profile-digest".into(),
            self.profile.profile_sha256.clone(),
            "--emit-tunables-profile".into(),
            self.effective_profile_path.clone(),
            "--runs-dir".into(),
            self.runs_dir.clone(),
            "--harness-profile".into(),
            "benchmark".into(),
            "--benchmark-attempt-scope".into(),
            attempt,
            "--max-turns".into(),
            self.resources.max_turns.to_string(),
            "--max-wall-secs".into(),
            self.resources.max_wall_secs.to_string(),
            "--allow-code".into(),
            "--dangerously-bypass-permissions".into(),
            "--".into(),
            self.task_prompt.clone(),
        ];
        Ok(AdapterCommand {
            program: self.binary_path.clone(),
            argv,
            environment: BTreeMap::from([
                ("LANG".into(), "C.UTF-8".into()),
                ("LC_ALL".into(), "C.UTF-8".into()),
                ("NO_COLOR".into(), "1".into()),
                ("TZ".into(), "UTC".into()),
            ]),
            inherit_environment: self.credential_env_names.clone(),
            clear_environment: true,
            cwd: self.workspace_path.clone(),
            stdout_path: self.result_path.clone(),
            stdout_limit_bytes: self.resources.max_stdout_bytes,
            stderr_limit_bytes: self.resources.max_stderr_bytes,
        })
    }
}

impl ResourceBounds {
    fn validate(&self) -> Result<(), TerminalBenchAdapterError> {
        if !(1..=MAX_WALL_SECS).contains(&self.max_wall_secs)
            || !(1..=MAX_TURNS).contains(&self.max_turns)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stdout_bytes)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stderr_bytes)
            || !(1..=MAX_EVIDENCE_BYTES).contains(&self.max_evidence_bytes)
            || !(1..=MAX_MEMORY_BYTES).contains(&self.max_memory_bytes)
        {
            return Err(TerminalBenchAdapterError::Field("resources"));
        }
        Ok(())
    }
}

impl ExternalHarnessResult {
    pub fn validate_against(
        &self,
        request: &TerminalBenchRequest,
    ) -> Result<(), TerminalBenchAdapterError> {
        request.validate()?;
        validate_schema_and_benchmark(self.schema_version, &self.benchmark)?;
        validate_task(&self.task)?;
        validate_profile(&self.profile)?;
        validate_revision(&self.iteron_revision)?;
        validate_text(&self.run_id, "run_id")?;
        if self.benchmark != request.benchmark
            || self.task != request.task
            || self.profile != request.profile
            || self.iteron_revision != request.iteron_revision
        {
            return Err(TerminalBenchAdapterError::IdentityMismatch);
        }
        if self.score_micros.is_some_and(|score| score > 1_000_000)
            || self.score_micros.is_some() != self.evidence.score_evidence.is_some()
            || (self.outcome == TerminalOutcome::Completed && self.exit_code.is_none())
            || (self.success && self.outcome != TerminalOutcome::Completed)
            || self.timing.started_unix_ms == 0
            || self.timing.elapsed_ms > request.resources.max_wall_secs.saturating_mul(1_000)
            || self.resources.stdout_bytes > request.resources.max_stdout_bytes
            || self.resources.stderr_bytes > request.resources.max_stderr_bytes
            || self.resources.evidence_bytes > request.resources.max_evidence_bytes
            || self.resources.stdout_bytes != self.evidence.iteron_result.bytes
            || self
                .resources
                .peak_memory_bytes
                .is_some_and(|bytes| bytes > request.resources.max_memory_bytes)
        {
            return Err(TerminalBenchAdapterError::Field(
                "result_outcome_or_resources",
            ));
        }
        validate_artifact(
            &self.evidence.effective_profile,
            request.resources.max_evidence_bytes,
        )?;
        validate_artifact(
            &self.evidence.iteron_result,
            request.resources.max_stdout_bytes,
        )?;
        validate_artifact(
            &self.evidence.run_record,
            request.resources.max_evidence_bytes,
        )?;
        if let Some(score) = &self.evidence.score_evidence {
            validate_artifact(score, request.resources.max_evidence_bytes)?;
        }
        let referenced_bytes = [
            Some(self.evidence.effective_profile.bytes),
            Some(self.evidence.iteron_result.bytes),
            Some(self.evidence.run_record.bytes),
            self.evidence
                .score_evidence
                .as_ref()
                .map(|score| score.bytes),
        ]
        .into_iter()
        .flatten()
        .try_fold(0_u64, u64::checked_add)
        .ok_or(TerminalBenchAdapterError::Field("evidence_bytes"))?;
        if self.evidence.effective_profile.path != request.effective_profile_path
            || self.evidence.iteron_result.path != request.result_path
            || !Path::new(&self.evidence.run_record.path).starts_with(&request.runs_dir)
            || self.resources.evidence_bytes != referenced_bytes
        {
            return Err(TerminalBenchAdapterError::IdentityMismatch);
        }
        Ok(())
    }
}

fn validate_schema_and_benchmark(
    schema: u32,
    benchmark: &BenchmarkPin,
) -> Result<(), TerminalBenchAdapterError> {
    if schema != EXTERNAL_HARNESS_SCHEMA_VERSION {
        return Err(TerminalBenchAdapterError::Schema(schema));
    }
    if benchmark.id != TERMINAL_BENCH_ID || benchmark.version != TERMINAL_BENCH_VERSION {
        return Err(TerminalBenchAdapterError::BenchmarkPin);
    }
    Ok(())
}

fn validate_task(task: &TaskIdentity) -> Result<(), TerminalBenchAdapterError> {
    validate_identity_component(&task.task_id, "task_id")?;
    validate_identity_component(&task.trial_id, "trial_id")?;
    validate_identity_component(&task.dataset_revision, "dataset_revision")
}

fn validate_profile(profile: &ProfileIdentity) -> Result<(), TerminalBenchAdapterError> {
    validate_sha256(&profile.profile_sha256, "profile_sha256")?;
    validate_sha256(&profile.registry_sha256, "registry_sha256")?;
    validate_sha256(&profile.param_registry_sha256, "param_registry_sha256")
}

fn validate_revision(revision: &str) -> Result<(), TerminalBenchAdapterError> {
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TerminalBenchAdapterError::Field("iteron_revision"));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), TerminalBenchAdapterError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TerminalBenchAdapterError::Field(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), TerminalBenchAdapterError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .chars()
            .any(|character| ['\0', '\n', '\r'].contains(&character))
    {
        return Err(TerminalBenchAdapterError::Field(field));
    }
    Ok(())
}

fn validate_identity_component(
    value: &str,
    field: &'static str,
) -> Result<(), TerminalBenchAdapterError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
    }) {
        return Err(TerminalBenchAdapterError::Field(field));
    }
    Ok(())
}

fn validate_absolute_path(value: &str) -> Result<(), TerminalBenchAdapterError> {
    let path = Path::new(value);
    if value.len() > MAX_TEXT_BYTES
        || value.contains('\0')
        || !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(TerminalBenchAdapterError::Field("path"));
    }
    Ok(())
}

fn validate_environment_names(names: &[String]) -> Result<(), TerminalBenchAdapterError> {
    if names.len() > ALLOWED_CREDENTIAL_ENV.len()
        || !names.windows(2).all(|pair| pair[0] < pair[1])
        || names.iter().any(|name| {
            ALLOWED_CREDENTIAL_ENV
                .binary_search(&name.as_str())
                .is_err()
        })
    {
        return Err(TerminalBenchAdapterError::Field("credential_env_names"));
    }
    Ok(())
}

fn validate_artifact(
    artifact: &ArtifactReference,
    limit: u64,
) -> Result<(), TerminalBenchAdapterError> {
    validate_absolute_path(&artifact.path)?;
    validate_sha256(&artifact.sha256, "artifact_sha256")?;
    if artifact.bytes == 0 || artifact.bytes > limit {
        return Err(TerminalBenchAdapterError::Field("artifact_bytes"));
    }
    Ok(())
}

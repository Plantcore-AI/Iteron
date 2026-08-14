//! Closed benchmark-adapter registry and shell-free command construction.

use crate::research_protocol::{
    CliRunSpec, EXTERNAL_NATIVE_ADAPTER_PROTOCOL, ExternalNativeRunSpec, ResearchProtocolError,
    RunSpec,
};
use crate::terminal_bench::{AdapterCommand, TERMINAL_BENCH_ID, TERMINAL_BENCH_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const ITERON_CLI_ID: &str = "iteron-cli";
pub const ITERON_CLI_VERSION: &str = "1";
pub const EXTERNAL_NATIVE_ID: &str = "iteron-native-adapter";
pub const EXTERNAL_NATIVE_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPin {
    pub benchmark_id: String,
    pub benchmark_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOperation {
    Surface,
    CandidateValidate,
    Run,
    Cancel,
    Result,
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRegistryEntry {
    pub benchmark_id: String,
    pub benchmark_version: String,
    pub request_schema_id: String,
    pub result_schema_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_protocol: Option<String>,
    pub supported_operations: Vec<AdapterOperation>,
    pub adapter_digest_sha256: String,
}

#[derive(Debug, Clone)]
pub struct BenchmarkAdapterRegistry {
    entries: BTreeMap<(String, String), AdapterRegistryEntry>,
    iteron_cli_executable: Option<ExecutableIdentity>,
    external_native_executable: Option<ExecutableIdentity>,
}

const MAX_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

/// Operator-owned executable identity captured outside the request protocol. Requests can select
/// only this exact path/content pair; they cannot mint trust by repeating a digest themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutableIdentity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
}

impl ExecutableIdentity {
    fn observe(path: &Path) -> Result<Self, ResearchProtocolError> {
        let path = path
            .canonicalize()
            .map_err(|_| ResearchProtocolError::ExecutableIdentity)?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| ResearchProtocolError::ExecutableIdentity)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err(ResearchProtocolError::ExecutableIdentity);
        }
        let sha256 = hash_executable(&path, metadata.len())?;
        Ok(Self {
            path,
            sha256,
            bytes: metadata.len(),
        })
    }

    fn command_path(&self, requested: &str) -> Result<String, ResearchProtocolError> {
        let requested = Path::new(requested)
            .canonicalize()
            .map_err(|_| ResearchProtocolError::ExecutableIdentity)?;
        if requested != self.path {
            return Err(ResearchProtocolError::ExecutableIdentity);
        }
        self.verify()?;
        self.path
            .to_str()
            .map(str::to_owned)
            .ok_or(ResearchProtocolError::ExecutableIdentity)
    }

    pub(crate) fn verify(&self) -> Result<(), ResearchProtocolError> {
        let observed = Self::observe(&self.path)?;
        (observed == *self)
            .then_some(())
            .ok_or(ResearchProtocolError::ExecutableIdentity)
    }
}

fn hash_executable(path: &Path, expected_bytes: u64) -> Result<String, ResearchProtocolError> {
    let mut file = File::open(path).map_err(|_| ResearchProtocolError::ExecutableIdentity)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ResearchProtocolError::ExecutableIdentity)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ResearchProtocolError::ExecutableIdentity)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(ResearchProtocolError::ExecutableIdentity);
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_bytes {
        return Err(ResearchProtocolError::ExecutableIdentity);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResearchExecutionMode {
    DryRun,
    Execute,
}

impl ResearchExecutionMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Execute => "execute",
        }
    }
}

impl BenchmarkAdapterRegistry {
    pub fn builtin() -> Self {
        let operations = vec![
            AdapterOperation::Surface,
            AdapterOperation::CandidateValidate,
            AdapterOperation::Run,
            AdapterOperation::Cancel,
            AdapterOperation::Result,
            AdapterOperation::Evidence,
        ];
        let entries = [
            entry(
                ITERON_CLI_ID,
                ITERON_CLI_VERSION,
                "iteron-research/1#iteron-cli-run-request",
                "iteron-research/1#run-response",
                Some(crate::tuner::IMPLEMENTATION_PROTOCOL),
                None,
                operations.clone(),
            ),
            entry(
                TERMINAL_BENCH_ID,
                TERMINAL_BENCH_VERSION,
                "iteron-eval/terminal-bench-request/1",
                "iteron-eval/terminal-bench-result/1",
                None,
                None,
                operations.clone(),
            ),
            entry(
                EXTERNAL_NATIVE_ID,
                EXTERNAL_NATIVE_VERSION,
                "iteron-research/1#external-native-run-request",
                "iteron-native-adapter-result/1",
                None,
                Some(EXTERNAL_NATIVE_ADAPTER_PROTOCOL),
                operations,
            ),
        ];
        Self {
            entries: entries
                .into_iter()
                .map(|entry| {
                    (
                        (entry.benchmark_id.clone(), entry.benchmark_version.clone()),
                        entry,
                    )
                })
                .collect(),
            iteron_cli_executable: None,
            external_native_executable: None,
        }
    }

    pub(crate) fn with_iteron_cli_executable(path: &Path) -> Result<Self, ResearchProtocolError> {
        let mut registry = Self::builtin();
        registry.iteron_cli_executable = Some(ExecutableIdentity::observe(path)?);
        Ok(registry)
    }

    pub(crate) fn with_external_native_executable(
        path: &Path,
    ) -> Result<Self, ResearchProtocolError> {
        let mut registry = Self::builtin();
        registry.external_native_executable = Some(ExecutableIdentity::observe(path)?);
        Ok(registry)
    }

    pub fn entries(&self) -> Vec<AdapterRegistryEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn resolve(
        &self,
        pin: &AdapterPin,
        operation: AdapterOperation,
    ) -> Result<&AdapterRegistryEntry, ResearchProtocolError> {
        validate_pin(pin)?;
        let entry = self
            .entries
            .get(&(pin.benchmark_id.clone(), pin.benchmark_version.clone()))
            .ok_or(ResearchProtocolError::UnknownAdapter)?;
        if !entry.supported_operations.contains(&operation) {
            return Err(ResearchProtocolError::UnsupportedOperation);
        }
        Ok(entry)
    }

    pub fn digest_sha256(&self) -> String {
        let bytes = serde_json::to_vec(&self.entries()).expect("registry entries serialize");
        hex::encode(Sha256::digest(bytes))
    }

    pub fn command(
        &self,
        pin: &AdapterPin,
        run: &RunSpec,
    ) -> Result<AdapterCommand, ResearchProtocolError> {
        let entry = self.resolve(pin, AdapterOperation::Run)?;
        if run.implementation_candidate_digest().is_some()
            && entry.implementation_protocol.as_deref()
                != Some(crate::tuner::IMPLEMENTATION_PROTOCOL)
        {
            return Err(ResearchProtocolError::UnsupportedImplementationActivation);
        }
        if run.native_materialization_digest().is_some()
            && entry.materialization_protocol.as_deref() != Some(EXTERNAL_NATIVE_ADAPTER_PROTOCOL)
        {
            return Err(ResearchProtocolError::UnsupportedCandidateMaterialization);
        }
        match (
            pin.benchmark_id.as_str(),
            pin.benchmark_version.as_str(),
            run,
        ) {
            (ITERON_CLI_ID, ITERON_CLI_VERSION, RunSpec::IteronCli { spec }) => {
                iteron_cli_command(spec)
            }
            (
                TERMINAL_BENCH_ID,
                TERMINAL_BENCH_VERSION,
                RunSpec::TerminalBench21 {
                    request,
                    implementation_candidate,
                },
            ) => {
                let mut command = request
                    .command()
                    .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
                if let Some(reference) = implementation_candidate {
                    insert_activation_argv(&mut command.argv, &reference.path, &reference.digest)?;
                }
                Ok(command)
            }
            (EXTERNAL_NATIVE_ID, EXTERNAL_NATIVE_VERSION, RunSpec::ExternalNative { spec }) => {
                external_native_command(spec)
            }
            _ => Err(ResearchProtocolError::RunSpecAdapterMismatch),
        }
    }

    pub(crate) fn execution_command(
        &self,
        pin: &AdapterPin,
        run: &RunSpec,
    ) -> Result<(AdapterCommand, Option<ExecutableIdentity>), ResearchProtocolError> {
        let mut command = self.command(pin, run)?;
        if matches!(run, RunSpec::IteronCli { .. }) {
            let executable = self
                .iteron_cli_executable
                .as_ref()
                .ok_or(ResearchProtocolError::UnpinnedExecutable)?;
            command.program = executable.command_path(&command.program)?;
            return Ok((command, Some(executable.clone())));
        }
        if matches!(run, RunSpec::ExternalNative { .. }) {
            let executable = self
                .external_native_executable
                .as_ref()
                .ok_or(ResearchProtocolError::UnpinnedExecutable)?;
            command.program = executable.command_path(&command.program)?;
            return Ok((command, Some(executable.clone())));
        }
        Ok((command, None))
    }
}

pub use crate::research_execution::session::ResearchSession;
fn entry(
    benchmark_id: &str,
    benchmark_version: &str,
    request_schema_id: &str,
    result_schema_id: &str,
    implementation_protocol: Option<&str>,
    materialization_protocol: Option<&str>,
    supported_operations: Vec<AdapterOperation>,
) -> AdapterRegistryEntry {
    #[derive(Serialize)]
    struct Identity<'a> {
        benchmark_id: &'a str,
        benchmark_version: &'a str,
        request_schema_id: &'a str,
        result_schema_id: &'a str,
        implementation_protocol: Option<&'a str>,
        materialization_protocol: Option<&'a str>,
        supported_operations: &'a [AdapterOperation],
    }
    let identity = Identity {
        benchmark_id,
        benchmark_version,
        request_schema_id,
        result_schema_id,
        implementation_protocol,
        materialization_protocol,
        supported_operations: &supported_operations,
    };
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&identity).expect("adapter identity serializes"),
    ));
    AdapterRegistryEntry {
        benchmark_id: benchmark_id.into(),
        benchmark_version: benchmark_version.into(),
        request_schema_id: request_schema_id.into(),
        result_schema_id: result_schema_id.into(),
        implementation_protocol: implementation_protocol.map(str::to_owned),
        materialization_protocol: materialization_protocol.map(str::to_owned),
        supported_operations,
        adapter_digest_sha256: digest,
    }
}

fn external_native_command(
    spec: &ExternalNativeRunSpec,
) -> Result<AdapterCommand, ResearchProtocolError> {
    spec.validate()?;
    let mut argv = vec![
        "--protocol".into(),
        EXTERNAL_NATIVE_ADAPTER_PROTOCOL.into(),
        "--candidate-profile".into(),
        spec.profile_path.clone(),
        "--candidate-profile-sha256".into(),
        spec.profile_sha256.clone(),
        "--effective-profile".into(),
        spec.effective_profile_path.clone(),
        "--native-materialization".into(),
        spec.native_materialization_path.clone(),
        "--native-materialization-sha256".into(),
        spec.native_materialization_sha256.clone(),
        "--consumption-receipt".into(),
        spec.consumption_receipt_path.clone(),
        "--result".into(),
        spec.result_path.clone(),
        "--run-id".into(),
        spec.run_id.clone(),
        "--candidate-sha256".into(),
        spec.candidate_sha256.clone(),
        "--materialization-sha256".into(),
        spec.candidate_graph_identity.materialization_sha256.clone(),
        "--experiment-sha256".into(),
        spec.candidate_graph_identity.experiment_sha256.clone(),
        "--topology-sha256".into(),
        spec.candidate_graph_identity.topology_sha256.clone(),
    ];
    if !spec.task_arguments.is_empty() {
        argv.push("--".into());
        argv.extend(spec.task_arguments.clone());
    }
    Ok(AdapterCommand {
        program: spec.binary_path.clone(),
        argv,
        environment: BTreeMap::from([
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("NO_COLOR".into(), "1".into()),
            ("TZ".into(), "UTC".into()),
        ]),
        inherit_environment: spec.credential_env_names.clone(),
        clear_environment: true,
        cwd: spec.workspace_path.clone(),
        stdout_path: spec.stdout_path.clone(),
        stdout_limit_bytes: spec.max_stdout_bytes,
        stderr_limit_bytes: spec.max_stderr_bytes,
    })
}

fn validate_pin(pin: &AdapterPin) -> Result<(), ResearchProtocolError> {
    if pin.benchmark_id.is_empty()
        || pin.benchmark_version.is_empty()
        || pin.benchmark_id.len() > 128
        || pin.benchmark_version.len() > 64
        || !pin.benchmark_id.bytes().all(is_id_byte)
        || !pin.benchmark_version.bytes().all(is_id_byte)
    {
        return Err(ResearchProtocolError::InvalidField("adapter pin".into()));
    }
    Ok(())
}

fn is_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn iteron_cli_command(spec: &CliRunSpec) -> Result<AdapterCommand, ResearchProtocolError> {
    spec.validate()?;
    let mut argv = vec![
        "--print".into(),
        "--output-format".into(),
        "json".into(),
        "--output-schema-version".into(),
        "5".into(),
        "--repo".into(),
        spec.workspace_path.clone(),
        "--tunables-profile".into(),
        spec.profile_path.clone(),
        "--tunables-profile-digest".into(),
        spec.profile_sha256.clone(),
        "--emit-tunables-profile".into(),
        spec.effective_profile_path.clone(),
        "--runs-dir".into(),
        spec.runs_dir.clone(),
        "--max-turns".into(),
        spec.max_turns.to_string(),
        "--max-wall-secs".into(),
        spec.max_wall_secs.to_string(),
        "--allow-code".into(),
        "--dangerously-bypass-permissions".into(),
    ];
    if let (Some(path), Some(digest)) = (
        &spec.implementation_candidate_path,
        &spec.implementation_candidate_digest,
    ) {
        argv.extend([
            "--harness-profile".into(),
            "research".into(),
            "--implementation-candidate".into(),
            path.clone(),
            "--implementation-candidate-digest".into(),
            digest.clone(),
        ]);
    }
    argv.extend(["--".into(), spec.task_prompt.clone()]);
    Ok(AdapterCommand {
        program: spec.binary_path.clone(),
        argv,
        environment: BTreeMap::from([
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("NO_COLOR".into(), "1".into()),
            ("TZ".into(), "UTC".into()),
        ]),
        inherit_environment: spec.credential_env_names.clone(),
        clear_environment: true,
        cwd: spec.workspace_path.clone(),
        stdout_path: spec.result_path.clone(),
        stdout_limit_bytes: spec.max_stdout_bytes,
        stderr_limit_bytes: spec.max_stderr_bytes,
    })
}

fn insert_activation_argv(
    argv: &mut Vec<String>,
    path: &str,
    digest: &str,
) -> Result<(), ResearchProtocolError> {
    let Some(separator) = argv.iter().position(|argument| argument == "--") else {
        return Err(ResearchProtocolError::InvalidField(
            "adapter command separator".into(),
        ));
    };
    argv.splice(
        separator..separator,
        [
            "--implementation-candidate".into(),
            path.into(),
            "--implementation-candidate-digest".into(),
            digest.into(),
        ],
    );
    Ok(())
}

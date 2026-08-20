//! Bounded process owner for explicitly operator-enabled research runs.

mod implementation;
pub(crate) mod native_materialization;
mod process;
pub(crate) mod protocol_validation;
pub(crate) mod response_validation;
pub(crate) mod session;

use crate::adapter_registry::ExecutableIdentity;
#[cfg(unix)]
use crate::research_protocol::CliRunSpec;
use crate::research_protocol::{ResearchRunState, ResearchTerminalResult, RunSpec};
use crate::terminal_bench::{
    AdapterCommand, ArtifactReference, ExternalHarnessResult, MAX_RESULT_BYTES,
    parse_external_harness_result,
};
use implementation::require_consumption;
#[cfg(unix)]
use native_materialization::require_native_consumption;
#[cfg(unix)]
use process::CaptureSummary;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(unix)]
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone)]
pub(crate) struct ExecutionSnapshot {
    pub(crate) state: ResearchRunState,
    pub(crate) terminal_result: Option<ResearchTerminalResult>,
    pub(crate) artifacts: Vec<ArtifactReference>,
    pub(crate) detail: Option<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
}

impl ExecutionSnapshot {
    pub(crate) fn new(state: ResearchRunState) -> Self {
        Self {
            state,
            terminal_result: None,
            artifacts: Vec::new(),
            detail: None,
            exit_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExecutionControl {
    cancel: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ExecutionControl {
    pub(crate) fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.join.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub(crate) fn join(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn result_sidecar_path(run: &RunSpec) -> Option<String> {
    match run {
        RunSpec::TerminalBench21 { request, .. } => Some(
            Path::new(&request.runs_dir)
                .join(format!(
                    ".iteron-research-{}-{}-result.json",
                    request.task.task_id, request.task.trial_id
                ))
                .to_string_lossy()
                .into_owned(),
        ),
        RunSpec::ExternalNative { spec } => Some(spec.result_path.clone()),
        RunSpec::IteronCli { .. } => None,
    }
}

pub(crate) fn materialize_candidate_profile(
    path: &str,
    rendered: &str,
    expected_sha256: &str,
) -> Result<(), ()> {
    if hex::encode(Sha256::digest(rendered.as_bytes())) != expected_sha256 {
        return Err(());
    }
    let path = Path::new(path);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(());
            }
            let existing = read_file_bounded(path, iteron_tunables::MAX_PROFILE_BYTES as u64)
                .map_err(|_| ())?;
            (existing == rendered.as_bytes()).then_some(()).ok_or(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(path).map_err(|_| ())?;
            file.write_all(rendered.as_bytes()).map_err(|_| ())?;
            file.sync_all().map_err(|_| ())
        }
        Err(_) => Err(()),
    }
}

pub(crate) fn spawn_execution(
    command: AdapterCommand,
    executable: Option<ExecutableIdentity>,
    run: RunSpec,
    sidecar_path: Option<String>,
    snapshot: Arc<Mutex<ExecutionSnapshot>>,
) -> ExecutionControl {
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let join = thread::Builder::new()
        .name("iteron-research-run".into())
        .spawn(move || {
            let finished = process::execute_command(
                &command,
                executable.as_ref(),
                &run,
                sidecar_path.as_deref(),
                &worker_cancel,
            );
            *snapshot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = finished;
        })
        .expect("research supervisor thread creation is infallible at process scale");
    ExecutionControl {
        cancel,
        join: Some(join),
    }
}

pub(crate) fn refresh_terminal_bench_result(
    run: &RunSpec,
    path: &str,
    current: &ExecutionSnapshot,
) -> Result<Option<ExecutionSnapshot>, ()> {
    let (RunSpec::TerminalBench21 { request, .. }, Some(exit_code)) = (run, current.exit_code)
    else {
        return Ok(None);
    };
    let Some(parsed) = load_terminal_bench_result(
        Path::new(path),
        request,
        exit_code,
        current.stdout_bytes,
        current.stderr_bytes,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(require_consumption(
        run,
        ExecutionSnapshot {
            state: ResearchRunState::Completed,
            terminal_result: Some(parsed.terminal_result),
            artifacts: parsed.artifacts,
            detail: None,
            ..current.clone()
        },
    )))
}

#[cfg(unix)]
fn finish_natural_run(
    status: ExitStatus,
    stdout: CaptureSummary,
    stderr: CaptureSummary,
    run: &RunSpec,
    sidecar_path: Option<&str>,
) -> ExecutionSnapshot {
    if stdout.io_failed || stderr.io_failed {
        return terminal_snapshot(ResearchRunState::Failed, "bounded output capture failed");
    }
    if stdout.bytes > stdout_limit(run) {
        return terminal_snapshot(ResearchRunState::StdoutLimit, "stdout byte bound reached");
    }
    if stderr.bytes > stderr_limit(run) {
        return terminal_snapshot(ResearchRunState::StderrLimit, "stderr byte bound reached");
    }
    if process::evidence_usage(run, result_path(run), sidecar_path).is_err() {
        return terminal_snapshot(
            ResearchRunState::EvidenceLimit,
            "evidence byte bound reached",
        );
    }
    let exit_code = status.code().unwrap_or(-1);
    let snapshot = match run {
        RunSpec::IteronCli { spec } => finish_cli(spec, exit_code, stdout.bytes, stderr.bytes),
        RunSpec::TerminalBench21 { request, .. } => {
            let Some(path) = sidecar_path else {
                return terminal_snapshot(
                    ResearchRunState::Failed,
                    "terminal-bench adapter result path is unavailable",
                );
            };
            match load_terminal_bench_result(
                Path::new(path),
                request,
                exit_code,
                stdout.bytes,
                stderr.bytes,
            ) {
                Ok(Some(parsed)) => ExecutionSnapshot {
                    state: ResearchRunState::Completed,
                    terminal_result: Some(parsed.terminal_result),
                    artifacts: parsed.artifacts,
                    detail: None,
                    exit_code: Some(exit_code),
                    stdout_bytes: stdout.bytes,
                    stderr_bytes: stderr.bytes,
                },
                Ok(None) => ExecutionSnapshot {
                    detail: Some(
                        "awaiting externally produced Terminal-Bench 2.1 result sidecar".into(),
                    ),
                    exit_code: Some(exit_code),
                    stdout_bytes: stdout.bytes,
                    stderr_bytes: stderr.bytes,
                    ..ExecutionSnapshot::new(ResearchRunState::AwaitingResult)
                },
                Err(()) => terminal_snapshot(
                    ResearchRunState::Failed,
                    "Terminal-Bench 2.1 result or evidence failed exact validation",
                ),
            }
        }
        RunSpec::ExternalNative { spec } => {
            finish_external_native(spec, exit_code, stdout.bytes, stderr.bytes)
        }
    };
    if snapshot.state == ResearchRunState::Completed {
        require_native_consumption(run, require_consumption(run, snapshot))
    } else {
        snapshot
    }
}

#[cfg(unix)]
fn finish_external_native(
    spec: &crate::research_protocol::ExternalNativeRunSpec,
    exit_code: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> ExecutionSnapshot {
    let bytes = match read_file_bounded(Path::new(&spec.result_path), spec.max_evidence_bytes) {
        Ok(bytes) => bytes,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "native adapter result could not be read within bounds",
            );
        }
    };
    let value = match crate::strict_json::parse_json_no_duplicates(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "native adapter result is not strict JSON",
            );
        }
    };
    let result: crate::research_protocol::ExternalNativeResult = match serde_json::from_value(value)
    {
        Ok(result) => result,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "native adapter result has the wrong schema",
            );
        }
    };
    if result.schema_id != crate::research_protocol::EXTERNAL_NATIVE_RESULT_SCHEMA
        || result.run_id != spec.run_id
        || result.exit_code != exit_code
        || result.success != (exit_code == 0 && result.outcome == "completed")
        || !matches!(result.outcome.as_str(), "completed" | "failed")
        || result.score_micros.is_some_and(|score| score > 1_000_000)
    {
        return terminal_snapshot(
            ResearchRunState::Failed,
            "native adapter result failed exact correlation",
        );
    }
    let artifact = match artifact_reference(Path::new(&spec.result_path), spec.max_evidence_bytes) {
        Ok(artifact) => artifact,
        Err(()) => {
            return terminal_snapshot(
                ResearchRunState::EvidenceLimit,
                "native adapter result evidence is invalid",
            );
        }
    };
    let state = if result.success {
        ResearchRunState::Completed
    } else {
        ResearchRunState::Failed
    };
    ExecutionSnapshot {
        state,
        terminal_result: result.success.then_some(ResearchTerminalResult {
            schema_id: result.schema_id,
            run_id: result.run_id,
            outcome: result.outcome,
            success: result.success,
            exit_code: Some(result.exit_code),
            score_micros: result.score_micros,
        }),
        artifacts: vec![artifact],
        detail: (!result.success).then_some("native adapter reported failure".into()),
        exit_code: Some(exit_code),
        stdout_bytes,
        stderr_bytes,
    }
}

#[cfg(unix)]
fn finish_cli(
    spec: &CliRunSpec,
    exit_code: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> ExecutionSnapshot {
    let bytes = match read_file_bounded(Path::new(&spec.result_path), spec.max_stdout_bytes) {
        Ok(bytes) => bytes,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "terminal result artifact could not be read within bounds",
            );
        }
    };
    let parsed = match crate::parse_final_result(&bytes, exit_code) {
        Ok(parsed) => parsed,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::Failed,
                "terminal result failed the Iteron CLI schema contract",
            );
        }
    };
    let artifacts = match collect_generic_artifacts(spec) {
        Ok(artifacts) => artifacts,
        Err(_) => {
            return terminal_snapshot(
                ResearchRunState::EvidenceLimit,
                "result evidence failed its byte, digest, or path contract",
            );
        }
    };
    ExecutionSnapshot {
        state: ResearchRunState::Completed,
        terminal_result: Some(ResearchTerminalResult {
            schema_id: format!("iteron-cli/result/{}", parsed.schema_version),
            run_id: parsed.run_id,
            outcome: parsed.outcome,
            success: parsed.success,
            exit_code: Some(parsed.exit_code),
            score_micros: None,
        }),
        artifacts,
        detail: None,
        exit_code: Some(exit_code),
        stdout_bytes,
        stderr_bytes,
    }
}

struct ParsedTerminalBench {
    terminal_result: ResearchTerminalResult,
    artifacts: Vec<ArtifactReference>,
}

fn load_terminal_bench_result(
    path: &Path,
    request: &crate::terminal_bench::TerminalBenchRequest,
    process_exit: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> Result<Option<ParsedTerminalBench>, ()> {
    if !path.try_exists().map_err(|_| ())? {
        return Ok(None);
    }
    let bytes = read_file_bounded(path, MAX_RESULT_BYTES as u64).map_err(|_| ())?;
    let result = parse_external_harness_result(&bytes, request).map_err(|_| ())?;
    if result.exit_code != Some(process_exit)
        || result.resources.stdout_bytes != stdout_bytes
        || result.resources.stderr_bytes != stderr_bytes
    {
        return Err(());
    }
    let artifacts = terminal_bench_artifacts(&result, request.resources.max_evidence_bytes)?;
    let outcome = match result.outcome {
        crate::terminal_bench::TerminalOutcome::Completed => "completed",
        crate::terminal_bench::TerminalOutcome::TimedOut => "timed_out",
        crate::terminal_bench::TerminalOutcome::Errored => "errored",
        crate::terminal_bench::TerminalOutcome::Censored => "censored",
    };
    Ok(Some(ParsedTerminalBench {
        terminal_result: ResearchTerminalResult {
            schema_id: "iteron-eval/terminal-bench-result/1".into(),
            run_id: result.run_id,
            outcome: outcome.into(),
            success: result.success,
            exit_code: result.exit_code,
            score_micros: result.score_micros,
        },
        artifacts,
    }))
}

fn terminal_bench_artifacts(
    result: &ExternalHarnessResult,
    limit: u64,
) -> Result<Vec<ArtifactReference>, ()> {
    let mut artifacts = vec![
        result.evidence.effective_profile.clone(),
        result.evidence.iteron_result.clone(),
        result.evidence.run_record.clone(),
    ];
    artifacts.extend(result.evidence.score_evidence.clone());
    let mut total = 0_u64;
    for artifact in &artifacts {
        verify_artifact(artifact)?;
        total = total.checked_add(artifact.bytes).ok_or(())?;
    }
    (total <= limit && total == result.resources.evidence_bytes)
        .then_some(artifacts)
        .ok_or(())
}

#[cfg(unix)]
fn collect_generic_artifacts(spec: &CliRunSpec) -> Result<Vec<ArtifactReference>, ()> {
    let mut files = BTreeMap::<String, ArtifactReference>::new();
    for path in [&spec.result_path, &spec.effective_profile_path] {
        let artifact = artifact_reference(Path::new(path), spec.max_evidence_bytes)?;
        files.insert(artifact.path.clone(), artifact);
    }
    collect_directory_artifacts(
        Path::new(&spec.runs_dir),
        spec.max_evidence_bytes,
        &mut files,
    )?;
    let total = files
        .values()
        .try_fold(0_u64, |total, artifact| total.checked_add(artifact.bytes))
        .ok_or(())?;
    (total <= spec.max_evidence_bytes)
        .then_some(files.into_values().collect())
        .ok_or(())
}

#[cfg(unix)]
fn collect_directory_artifacts(
    path: &Path,
    limit: u64,
    artifacts: &mut BTreeMap<String, ArtifactReference>,
) -> Result<(), ()> {
    if !path.try_exists().map_err(|_| ())? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() {
        return Err(());
    }
    if metadata.is_file() {
        let artifact = artifact_reference(path, limit)?;
        artifacts.insert(artifact.path.clone(), artifact);
        return Ok(());
    }
    if !metadata.is_dir() || artifacts.len() > 1024 {
        return Err(());
    }
    for entry in fs::read_dir(path).map_err(|_| ())? {
        collect_directory_artifacts(&entry.map_err(|_| ())?.path(), limit, artifacts)?;
        if artifacts.len() > 1024 {
            return Err(());
        }
    }
    Ok(())
}

fn terminal_snapshot(state: ResearchRunState, detail: &str) -> ExecutionSnapshot {
    let mut snapshot = ExecutionSnapshot::new(state);
    snapshot.detail = Some(detail.into());
    snapshot
}

#[cfg(unix)]
fn result_path(run: &RunSpec) -> &str {
    match run {
        RunSpec::IteronCli { spec } => &spec.result_path,
        RunSpec::TerminalBench21 { request, .. } => &request.result_path,
        RunSpec::ExternalNative { spec } => &spec.result_path,
    }
}

#[cfg(unix)]
fn stdout_limit(run: &RunSpec) -> u64 {
    match run {
        RunSpec::IteronCli { spec } => spec.max_stdout_bytes,
        RunSpec::TerminalBench21 { request, .. } => request.resources.max_stdout_bytes,
        RunSpec::ExternalNative { spec } => spec.max_stdout_bytes,
    }
}

#[cfg(unix)]
fn stderr_limit(run: &RunSpec) -> u64 {
    match run {
        RunSpec::IteronCli { spec } => spec.max_stderr_bytes,
        RunSpec::TerminalBench21 { request, .. } => request.resources.max_stderr_bytes,
        RunSpec::ExternalNative { spec } => spec.max_stderr_bytes,
    }
}

fn read_file_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::other("artifact is outside its file bound"));
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(64 * 1024) as usize);
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    (bytes.len() as u64 <= limit)
        .then_some(bytes)
        .ok_or_else(|| std::io::Error::other("artifact exceeds its byte bound"))
}

fn artifact_reference(path: &Path, limit: u64) -> Result<ArtifactReference, ()> {
    let bytes = read_file_bounded(path, limit).map_err(|_| ())?;
    if bytes.is_empty() {
        return Err(());
    }
    Ok(ArtifactReference {
        path: path.to_string_lossy().into_owned(),
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

fn verify_artifact(expected: &ArtifactReference) -> Result<(), ()> {
    (&artifact_reference(Path::new(&expected.path), expected.bytes)? == expected)
        .then_some(())
        .ok_or(())
}

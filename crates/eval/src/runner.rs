//! Real-repository, fixed-model evaluation runner.

use crate::attempts::{
    AttemptEvent, AttemptKey, AttemptLedger, AttemptLedgerError, MAX_PHYSICAL_ATTEMPTS,
};
use crate::contract::parse_run_output;
use crate::corpus::{CorpusManifest, CorpusTask};
use crate::process::{ProcessOutput, ProcessSpec, find_core, run_process};
use crate::report::{aggregate, compare, selection_summaries};
use crate::types::{
    AgentMetrics, CellKey, CellResult, EVAL_SCHEMA_VERSION, EvaluationManifest, EvaluationPurpose,
    KernelTaxObservation, OracleStatus, RunStatus, SamplingControl,
};
use iteron_sandbox::Confinement;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod hermetic;
#[cfg(test)]
mod hermetic_tests;

// `stream-json` includes bounded tool events as well as the terminal result. Keep the evaluator's
// capture ceiling aligned with the public harness output bound so exact usage collection does not
// turn an otherwise valid tool-heavy run into a 1 MiB harness failure.
const PROCESS_OUTPUT_LIMIT: usize = crate::research_protocol::MAX_OUTPUT_BYTES as usize;
const ORACLE_OUTPUT_LIMIT: usize = 128 * 1024;
const MAX_CANDIDATE_DIFF_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVAL_CELLS: usize = 1_000_000;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const ITERON_PROCESS_MIN_GRACE_SECS: u64 = 1;
const ITERON_PROCESS_MAX_GRACE_SECS: u64 = 30;
const ITERON_PROCESS_GRACE_DIVISOR: u64 = 20;
const DEFAULT_PARALLEL_EVAL_WORKERS: usize = 50;
// These are operational limits, not integer-storage limits. Keeping every evaluator deadline at
// or below one day makes the corresponding std/Tokio Instant additions portable and auditable.
const MAX_ITERON_AGENT_WALL_SECS: u64 = 24 * 60 * 60;
const MAX_CHECKOUT_TIMEOUT_SECS: u64 = 24 * 60 * 60;
const MAX_ORACLE_TIMEOUT_SECS: u64 = 24 * 60 * 60;
const BUILTIN_CREDENTIAL_ENVS: [&str; 6] = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "GLM_API_KEY",
    "MINIMAX_API_KEY",
    "FIREWORKS_API_KEY",
];

fn is_builtin_credential_env(name: &str) -> bool {
    BUILTIN_CREDENTIAL_ENVS.contains(&name)
}

/// The sole credential environment name permitted to cross into Core, named by
/// `ITERON_EVAL_CREDENTIAL_ENV`.
///
/// It is read from the environment rather than taken as a flag because the credential *value*
/// already has to be in the evaluator's environment for this to do anything: keeping the name
/// beside it puts the whole credential surface in one place instead of splitting it across argv,
/// where a process listing would carry half of it. An empty setting is the same as unset, so an
/// exported-but-blank variable cannot select the empty credential name and reach the check below
/// as `Some("")`. The name is validated against the built-in list before use; values are never
/// read or recorded by the evaluator.
fn credential_env_from_environment() -> Option<String> {
    normalize_credential_env(std::env::var("ITERON_EVAL_CREDENTIAL_ENV").ok())
}

/// Split from the lookup so the empty-is-unset rule is testable without mutating the process
/// environment, which every other test in this binary shares.
fn normalize_credential_env(raw: Option<String>) -> Option<String> {
    raw.filter(|name| !name.is_empty())
}

#[derive(Debug, Clone)]
pub struct EvalOptions {
    pub corpus_path: PathBuf,
    pub output_path: PathBuf,
    pub work_root: PathBuf,
    pub core_bin: Option<PathBuf>,
    /// Explicit opt-in for `file://` corpus repositories. It is false in the CLI by default so an
    /// untrusted manifest cannot make the evaluator clone arbitrary local source trees.
    pub allow_local_repositories: bool,
    pub model: String,
    pub provider: Option<String>,
    pub purpose: EvaluationPurpose,
    pub seeds: u64,
    pub minimum_seeds: u64,
    /// Wall-clock budget passed into Core itself. The evaluator gives the child a separate,
    /// bounded startup/finalization grace before enforcing its outer process ceiling.
    pub run_timeout: Duration,
    pub checkout_timeout: Duration,
    pub oracle_timeout: Duration,
    pub max_turns: u32,
    /// Maximum fresh physical executions of one logical task/config/seed cell. Only harness
    /// errors and timeouts are retryable; model outcomes are never retried into a better score.
    pub max_attempts: u8,
}

/// Versioned WS4 execution controls layered behind the frozen `EvalOptions`/CLI seam.
///
/// The legacy options remain source-compatible with the schema-authority `main` function while
/// this surface carries the bounded-worker, bundle, and explicit-uncapped controls.
#[derive(Debug, Clone)]
pub struct ParallelEvalOptions {
    pub corpus_path: PathBuf,
    pub output_path: PathBuf,
    pub work_root: PathBuf,
    pub core_bin: Option<PathBuf>,
    pub allow_local_repositories: bool,
    pub model: String,
    pub provider: Option<String>,
    pub credential_env: Option<String>,
    pub bundle_path: Option<PathBuf>,
    pub purpose: EvaluationPurpose,
    pub seeds: u64,
    pub minimum_seeds: u64,
    /// Wall-clock budget passed into Core itself. This is not the outer process ceiling.
    pub run_timeout: Duration,
    pub checkout_timeout: Duration,
    pub oracle_timeout: Duration,
    pub workers: usize,
    pub max_turns: u32,
    /// Explicitly omit the CLI turn ceiling. `max_turns` remains populated for capped runs and for
    /// stable CLI defaults, but is ignored when this flag is set.
    pub uncapped: bool,
    pub max_attempts: u8,
}

impl From<&EvalOptions> for ParallelEvalOptions {
    fn from(options: &EvalOptions) -> Self {
        Self {
            corpus_path: options.corpus_path.clone(),
            output_path: options.output_path.clone(),
            work_root: options.work_root.clone(),
            core_bin: options.core_bin.clone(),
            allow_local_repositories: options.allow_local_repositories,
            model: options.model.clone(),
            provider: options.provider.clone(),
            credential_env: credential_env_from_environment(),
            bundle_path: None,
            purpose: options.purpose,
            seeds: options.seeds,
            minimum_seeds: options.minimum_seeds,
            run_timeout: options.run_timeout,
            checkout_timeout: options.checkout_timeout,
            oracle_timeout: options.oracle_timeout,
            workers: iteron_tunables::param_usize(
                "eval.runner.default_parallel_eval_workers",
                iteron_tunables::param_integer(
                    "eval.runner.default_parallel_eval_workers",
                    DEFAULT_PARALLEL_EVAL_WORKERS,
                ),
            )
            .clamp(1, 100),
            max_turns: options.max_turns,
            uncapped: options.max_turns == 0,
            max_attempts: options.max_attempts,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HarnessConfig {
    name: &'static str,
    verify_gate: bool,
}

const CONFIGS: [HarnessConfig; 2] = [
    HarnessConfig {
        name: "verify_OFF",
        verify_gate: false,
    },
    HarnessConfig {
        name: "verify_ON",
        verify_gate: true,
    },
];

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error(transparent)]
    Corpus(#[from] crate::corpus::CorpusError),
    #[error(transparent)]
    FindCore(#[from] crate::process::FindCoreError),
    #[error("invalid evaluation option: {0}")]
    InvalidOption(String),
    #[error("cannot create evaluation path `{path}`: {source}")]
    CreatePath {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot canonicalize evaluation path `{path}`: {source}")]
    CanonicalizePath {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot encode evaluation artifact: {0}")]
    Encode(serde_json::Error),
    #[error("cannot write evaluation artifact `{path}`: {source}")]
    WriteArtifact {
        path: String,
        source: std::io::Error,
    },
    #[error("evaluation worker failed to join: {0}")]
    WorkerJoin(String),
    #[error(transparent)]
    AttemptLedger(#[from] AttemptLedgerError),
    #[error(transparent)]
    Attestation(#[from] crate::attestation::AttestationError),
    #[error(transparent)]
    Activity(#[from] iteron_evolve::ActivityError),
    #[error("evaluation cancelled by operator")]
    Cancelled,
}

pub async fn run_evaluation(options: &EvalOptions) -> Result<EvaluationManifest, RunnerError> {
    run_evaluation_parallel(&ParallelEvalOptions::from(options)).await
}

fn append_attempt(
    ledger: &std::sync::Mutex<AttemptLedger>,
    event: AttemptEvent,
) -> Result<(), AttemptLedgerError> {
    ledger
        .lock()
        .map_err(|_| AttemptLedgerError::Poisoned)?
        .append(event)
}

struct PhysicalAttempt<'a> {
    core: &'a Path,
    cell_root: &'a Path,
    oracle_root: &'a Path,
    run_root: &'a Path,
    task: &'a CorpusTask,
    config: HarnessConfig,
    seed: u64,
    legacy_options: &'a EvalOptions,
    options: &'a ParallelEvalOptions,
}

impl PhysicalAttempt<'_> {
    async fn execute(self) -> CellResult {
        let checkout = match authorize_repository(self.task, self.options.allow_local_repositories)
        {
            Ok(()) => {
                materialize_repository(self.task, self.cell_root, self.options.checkout_timeout)
                    .await
            }
            Err(error) => Err(error),
        };
        match checkout {
            Ok(()) => match canonical_cell_workspace(self.cell_root, self.run_root) {
                Ok(workspace) => {
                    let cell = run_cell(
                        self.core,
                        &workspace,
                        self.task,
                        self.config,
                        self.seed,
                        self.legacy_options,
                    )
                    .await;
                    attach_two_sided_verdict(cell, self.oracle_root, self.task, self.options).await
                }
                Err(error) => errored_cell(
                    self.task,
                    self.config,
                    self.seed,
                    "checkout_identity",
                    error,
                ),
            },
            Err(error) => errored_cell(self.task, self.config, self.seed, "checkout", error),
        }
    }
}

pub async fn run_evaluation_parallel(
    options: &ParallelEvalOptions,
) -> Result<EvaluationManifest, RunnerError> {
    run_evaluation_parallel_with_activity(options, None).await
}

/// The normal evaluator with an optional bounded publisher for the same ActivityEvent contract
/// used by interactive runs. This path stays entirely offline and is never called at startup.
pub async fn run_evaluation_parallel_with_activity(
    options: &ParallelEvalOptions,
    activity: Option<&iteron_evolve::ActivityPublisher>,
) -> Result<EvaluationManifest, RunnerError> {
    validate_parallel_options(options)?;
    let corpus = CorpusManifest::load(&options.corpus_path)?;
    let tasks = corpus.tasks_for(options.purpose)?;
    let core = find_core(options.core_bin.as_deref())?;
    std::fs::create_dir_all(&options.work_root).map_err(|source| RunnerError::CreatePath {
        path: options.work_root.display().to_string(),
        source,
    })?;
    // Resolve a relative operator-supplied root exactly once, before any child changes cwd. Every
    // descendant passed across a process boundary is derived from this canonical absolute root.
    let work_root = std::fs::canonicalize(&options.work_root).map_err(|source| {
        RunnerError::CanonicalizePath {
            path: options.work_root.display().to_string(),
            source,
        }
    })?;
    let run_id = new_run_id();
    let run_root = work_root.join(&run_id);
    std::fs::create_dir(&run_root).map_err(|source| RunnerError::CreatePath {
        path: run_root.display().to_string(),
        source,
    })?;
    let run_root =
        std::fs::canonicalize(&run_root).map_err(|source| RunnerError::CanonicalizePath {
            path: run_root.display().to_string(),
            source,
        })?;
    let mut runtime_options = options.clone();
    runtime_options.work_root = work_root;
    let bundle_digest = match options.bundle_path.as_deref() {
        Some(source) => {
            let snapshot = run_root.join("policy.bundle");
            let digest = snapshot_bundle(source, &snapshot)?;
            runtime_options.bundle_path = Some(snapshot);
            Some(digest)
        }
        None => None,
    };
    let legacy_options = EvalOptions {
        corpus_path: runtime_options.corpus_path.clone(),
        output_path: runtime_options.output_path.clone(),
        work_root: runtime_options.work_root.clone(),
        core_bin: runtime_options.core_bin.clone(),
        allow_local_repositories: runtime_options.allow_local_repositories,
        model: runtime_options.model.clone(),
        provider: runtime_options.provider.clone(),
        purpose: runtime_options.purpose,
        seeds: runtime_options.seeds,
        minimum_seeds: runtime_options.minimum_seeds,
        run_timeout: runtime_options.run_timeout,
        checkout_timeout: runtime_options.checkout_timeout,
        oracle_timeout: runtime_options.oracle_timeout,
        max_turns: if runtime_options.uncapped {
            0
        } else {
            runtime_options.max_turns
        },
        max_attempts: runtime_options.max_attempts,
    };

    let seeds = usize::try_from(options.seeds)
        .map_err(|_| RunnerError::InvalidOption("seeds do not fit this platform".into()))?;
    let total_cells = tasks
        .len()
        .checked_mul(CONFIGS.len())
        .and_then(|count| count.checked_mul(seeds))
        .ok_or_else(|| RunnerError::InvalidOption("evaluation cell count overflow".into()))?;
    if total_cells > iteron_tunables::param_integer("eval.runner.max_eval_cells", MAX_EVAL_CELLS) {
        return Err(RunnerError::InvalidOption(format!(
            "evaluation expands to {total_cells} cells; maximum is {MAX_EVAL_CELLS}"
        )));
    }
    if let Some(activity) = activity {
        let _ = activity.stage(
            "eval.run",
            iteron_evolve::ActivityState::Running,
            Some(iteron_evolve::ActivityProgress {
                completed: 0,
                total: total_cells as u64,
            }),
            iteron_evolve::ActivityDetailCode::Verification,
        );
    }

    let mut pending = std::collections::VecDeque::with_capacity(total_cells);
    for task in tasks {
        for config in CONFIGS {
            for seed in 0..options.seeds {
                pending.push_back((task.clone(), config, seed));
            }
        }
    }

    let options = std::sync::Arc::new(runtime_options);
    let legacy_options = std::sync::Arc::new(legacy_options);
    let attempt_ledger = std::sync::Arc::new(std::sync::Mutex::new(AttemptLedger::create(
        &crate::attempts::sidecar_path(&options.output_path),
    )?));
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(options.workers));
    let process_cancellation = crate::process::ProcessCancellation::default();
    let mut running = tokio::task::JoinSet::new();
    let mut cells = Vec::with_capacity(total_cells);
    while !pending.is_empty() || !running.is_empty() {
        if activity.is_some_and(|activity| activity.cancellation().is_cancelled()) {
            // Wake every active `run_process` first. Each child owns the process group and proves
            // terminate+reap before its worker returns; task abort is only a bounded fallback for
            // code that is not currently inside a physical process boundary.
            process_cancellation.cancel();
            let cleanup = async { while running.join_next().await.is_some() {} };
            if tokio::time::timeout(Duration::from_secs(5), cleanup)
                .await
                .is_err()
            {
                running.abort_all();
                while running.join_next().await.is_some() {}
            }
            if let Some(activity) = activity {
                let _ = activity.stage(
                    "eval.run",
                    iteron_evolve::ActivityState::Cancelled,
                    None,
                    iteron_evolve::ActivityDetailCode::Verification,
                );
            }
            return Err(RunnerError::Cancelled);
        }
        while running.len() < options.workers {
            let Some((task, config, seed)) = pending.pop_front() else {
                break;
            };
            let core = core.clone();
            let run_root = run_root.clone();
            let options = std::sync::Arc::clone(&options);
            let legacy_options = std::sync::Arc::clone(&legacy_options);
            let semaphore = std::sync::Arc::clone(&semaphore);
            let attempt_ledger = std::sync::Arc::clone(&attempt_ledger);
            let worker_cancellation = process_cancellation.clone();
            running.spawn(crate::process::scope_process_cancellation(
                worker_cancellation,
                async move {
                    let _permit = semaphore
                        .acquire_owned()
                        .await
                        .expect("evaluation semaphore is owned until all workers join");
                    let directory = cell_directory(&task, config, seed);
                    let mut final_cell = None;
                    for attempt in 1..=options.max_attempts {
                        let key = AttemptKey {
                            task: task.id.clone(),
                            config: config.name.into(),
                            seed,
                            attempt,
                        };
                        append_attempt(
                            &attempt_ledger,
                            AttemptEvent::Planned { key: key.clone() },
                        )?;
                        append_attempt(
                            &attempt_ledger,
                            AttemptEvent::Started { key: key.clone() },
                        )?;
                        let attempt_directory = format!("{directory}-attempt-{attempt}");
                        let cell_root = run_root.join(&attempt_directory);
                        let oracle_root = run_root.join(format!("{attempt_directory}-oracle"));
                        let mut cell = PhysicalAttempt {
                            core: &core,
                            cell_root: &cell_root,
                            oracle_root: &oracle_root,
                            run_root: &run_root,
                            task: &task,
                            config,
                            seed,
                            legacy_options: &legacy_options,
                            options: &options,
                        }
                        .execute()
                        .await;
                        cell.benchmark = benchmark_reference(&task);
                        append_attempt(
                            &attempt_ledger,
                            AttemptEvent::Finished {
                                key,
                                run_status: cell.run_status,
                                failure_phase: cell.failure_phase.clone(),
                            },
                        )?;
                        let retryable =
                            matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut);
                        final_cell = Some(cell);
                        if !retryable {
                            break;
                        }
                    }
                    Ok::<CellResult, RunnerError>(
                        final_cell.expect("validated max_attempts always executes at least once"),
                    )
                },
            ));
        }
        let joined = tokio::select! {
            joined = running.join_next() => joined,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)),
                if activity.is_some() => continue,
        };
        if let Some(joined) = joined {
            cells.push(joined.map_err(|error| RunnerError::WorkerJoin(error.to_string()))??);
            if let Some(activity) = activity {
                let _ = activity.stage(
                    "eval.run",
                    iteron_evolve::ActivityState::Running,
                    Some(iteron_evolve::ActivityProgress {
                        completed: cells.len() as u64,
                        total: total_cells as u64,
                    }),
                    iteron_evolve::ActivityDetailCode::Verification,
                );
            }
        }
    }
    cells.sort_by(|left, right| {
        (
            &left.task,
            &left.config,
            left.seed,
            &left.repo_url,
            &left.commit,
        )
            .cmp(&(
                &right.task,
                &right.config,
                right.seed,
                &right.repo_url,
                &right.commit,
            ))
    });

    let summary = aggregate(&cells, options.minimum_seeds);
    let comparison = compare(&summary, "verify_OFF", "verify_ON");
    let selections = selection_summaries(&cells);
    let kernel_tax = aggregate_kernel_tax(&cells);
    let core_timing = core_process_timing(options.run_timeout)
        .expect("validated Core wall budget has a representable outer process ceiling");
    let manifest = EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id,
        corpus_version: corpus.corpus_version.clone(),
        dataset_digest: corpus.dataset_digest.clone(),
        model: options.model.clone(),
        provider: options.provider.clone(),
        bundle_digest,
        purpose: options.purpose,
        seeds: options.seeds,
        minimum_seeds: options.minimum_seeds,
        workers: options.workers as u16,
        max_turns: (!options.uncapped).then_some(options.max_turns),
        core_agent_wall_secs: core_timing.agent_wall.as_secs(),
        core_process_grace_secs: core_timing.grace.as_secs(),
        core_process_timeout_secs: core_timing.process_ceiling.as_secs(),
        result_path: options.output_path.clone(),
        cells,
        aggregate: summary,
        comparison,
        selections,
        kernel_tax,
    };
    write_artifact_atomic(&manifest, &options.output_path)?;
    let attempt_path = crate::attempts::sidecar_path(&options.output_path);
    let (attempt_head, attempt_record_count) = {
        let ledger = attempt_ledger
            .lock()
            .map_err(|_| AttemptLedgerError::Poisoned)?;
        (ledger.head_hash().to_owned(), ledger.record_count())
    };
    let reopened = AttemptLedger::open(&attempt_path)?;
    if reopened.head_hash() != attempt_head || reopened.record_count() != attempt_record_count {
        return Err(AttemptLedgerError::Corrupt(attempt_record_count.saturating_add(1)).into());
    }
    let attestation =
        crate::attestation::RunAttestation::build(crate::attestation::RunAttestationInput {
            run_id: &manifest.run_id,
            corpus: &corpus,
            core_path: &core,
            corpus_path: &options.corpus_path,
            result_path: &options.output_path,
            attempt_ledger_path: &attempt_path,
            attempt_ledger_head: &attempt_head,
            attempt_record_count,
            model: &options.model,
            provider: options.provider.as_deref(),
            bundle_digest: manifest.bundle_digest.as_deref(),
            purpose: options.purpose,
            limits: crate::attestation::ExecutionLimits {
                seeds: options.seeds,
                minimum_seeds: options.minimum_seeds,
                workers: options.workers as u16,
                max_attempts: options.max_attempts,
                max_turns: (!options.uncapped).then_some(options.max_turns),
                run_timeout_secs: options.run_timeout.as_secs(),
                checkout_timeout_secs: options.checkout_timeout.as_secs(),
                oracle_timeout_secs: options.oracle_timeout.as_secs(),
            },
        })?;
    attestation.verify_artifacts(
        &core,
        &options.corpus_path,
        &options.output_path,
        &attempt_path,
    )?;
    crate::attestation::write_atomic(
        &attestation,
        &crate::attestation::sidecar_path(&options.output_path),
    )?;
    if let Some(activity) = activity {
        let _ = activity.evidence("eval.run", &manifest.run_id);
        let _ = activity.stage(
            "eval.run",
            iteron_evolve::ActivityState::Succeeded,
            Some(iteron_evolve::ActivityProgress {
                completed: total_cells as u64,
                total: total_cells as u64,
            }),
            iteron_evolve::ActivityDetailCode::Verification,
        );
    }
    Ok(manifest)
}

fn validate_parallel_options(options: &ParallelEvalOptions) -> Result<(), RunnerError> {
    if options.model.trim().is_empty() {
        return Err(RunnerError::InvalidOption("model must be explicit".into()));
    }
    if let Some(name) = options.credential_env.as_deref() {
        if !is_builtin_credential_env(name) {
            return Err(RunnerError::InvalidOption(
                "credential_env must be an exact built-in Core provider credential name".into(),
            ));
        }
        if std::env::var_os(name).is_none_or(|value| value.is_empty()) {
            return Err(RunnerError::InvalidOption(
                "credential_env is not present in the evaluator environment".into(),
            ));
        }
    }
    if options.seeds == 0 {
        return Err(RunnerError::InvalidOption(
            "seeds must be at least 1".into(),
        ));
    }
    if options.minimum_seeds == 0 {
        return Err(RunnerError::InvalidOption(
            "minimum_seeds must be at least 1".into(),
        ));
    }
    if !(1..=100).contains(&options.workers) {
        return Err(RunnerError::InvalidOption(
            "workers must be in 1..=100".into(),
        ));
    }
    if !(1..=MAX_PHYSICAL_ATTEMPTS).contains(&options.max_attempts) {
        return Err(RunnerError::InvalidOption(format!(
            "max_attempts must be in 1..={MAX_PHYSICAL_ATTEMPTS}"
        )));
    }
    for (name, duration, maximum_secs) in [
        (
            "run_timeout",
            options.run_timeout,
            iteron_tunables::param_integer(
                "eval.runner.max_iteron_agent_wall_secs",
                MAX_ITERON_AGENT_WALL_SECS,
            ),
        ),
        (
            "checkout_timeout",
            options.checkout_timeout,
            iteron_tunables::param_integer(
                "eval.runner.max_checkout_timeout_secs",
                MAX_CHECKOUT_TIMEOUT_SECS,
            ),
        ),
        (
            "oracle_timeout",
            options.oracle_timeout,
            iteron_tunables::param_integer(
                "eval.runner.max_oracle_timeout_secs",
                MAX_ORACLE_TIMEOUT_SECS,
            ),
        ),
    ] {
        validate_whole_second_duration(name, duration, maximum_secs)?;
    }
    core_process_timing(options.run_timeout).ok_or_else(|| {
        RunnerError::InvalidOption(
            "run_timeout is too large to add the bounded Core process grace".into(),
        )
    })?;
    if !options.uncapped && options.max_turns == 0 {
        return Err(RunnerError::InvalidOption(
            "max_turns must be at least 1 for a capped run".into(),
        ));
    }
    if options
        .bundle_path
        .as_ref()
        .is_some_and(|path| !path.is_file())
    {
        return Err(RunnerError::InvalidOption(
            "bundle_path must name an existing regular file".into(),
        ));
    }
    if options.bundle_path.is_some() {
        return Err(RunnerError::InvalidOption(
            "the production Core CLI has no policy-bundle input; refusing a simulated trained arm"
                .into(),
        ));
    }
    Ok(())
}

fn validate_whole_second_duration(
    name: &str,
    duration: Duration,
    maximum_secs: u64,
) -> Result<(), RunnerError> {
    if duration.is_zero() || duration.subsec_nanos() != 0 {
        return Err(RunnerError::InvalidOption(format!(
            "{name} must be a positive whole number of seconds"
        )));
    }
    if duration.as_secs() > maximum_secs {
        return Err(RunnerError::InvalidOption(format!(
            "{name} exceeds the operational maximum of {maximum_secs} seconds"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreProcessTiming {
    agent_wall: Duration,
    grace: Duration,
    process_ceiling: Duration,
}

/// Keep Core's semantic agent budget distinct from the harness kill switch. The proportional
/// grace is intentionally small for short tests and capped for production-length evaluations.
fn core_process_timing(agent_wall: Duration) -> Option<CoreProcessTiming> {
    if agent_wall.is_zero()
        || agent_wall.subsec_nanos() != 0
        || agent_wall.as_secs()
            > iteron_tunables::param_integer(
                "eval.runner.max_iteron_agent_wall_secs",
                MAX_ITERON_AGENT_WALL_SECS,
            )
    {
        return None;
    }
    let grace_secs = (agent_wall.as_secs()
        / iteron_tunables::param_integer(
            "eval.runner.iteron_process_grace_divisor",
            ITERON_PROCESS_GRACE_DIVISOR,
        ))
    .clamp(
        iteron_tunables::param_integer(
            "eval.runner.iteron_process_min_grace_secs",
            ITERON_PROCESS_MIN_GRACE_SECS,
        ),
        iteron_tunables::param_integer(
            "eval.runner.iteron_process_max_grace_secs",
            ITERON_PROCESS_MAX_GRACE_SECS,
        ),
    );
    let grace = Duration::from_secs(grace_secs);
    let process_ceiling = agent_wall.checked_add(grace)?;
    Some(CoreProcessTiming {
        agent_wall,
        grace,
        process_ceiling,
    })
}

fn canonical_cell_workspace(path: &Path, run_root: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize materialized checkout: {error}"))?;
    if !canonical.is_dir() || !canonical.starts_with(run_root) {
        return Err("materialized checkout escaped the canonical evaluation run root".into());
    }
    Ok(canonical)
}

fn snapshot_bundle(source: &Path, destination: &Path) -> Result<String, RunnerError> {
    let input = std::fs::File::open(source).map_err(|error| {
        RunnerError::InvalidOption(format!(
            "cannot open bundle `{}`: {error}",
            source.display()
        ))
    })?;
    let metadata = input.metadata().map_err(|error| {
        RunnerError::InvalidOption(format!(
            "cannot inspect bundle `{}`: {error}",
            source.display()
        ))
    })?;
    if !metadata.is_file()
        || metadata.len()
            > iteron_tunables::param_integer("eval.runner.max_bundle_bytes", MAX_BUNDLE_BYTES)
    {
        return Err(RunnerError::InvalidOption(format!(
            "bundle `{}` must be a regular file no larger than {MAX_BUNDLE_BYTES} bytes",
            source.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded_input = std::io::Read::take(
        input,
        iteron_tunables::param_integer("eval.runner.max_bundle_bytes", MAX_BUNDLE_BYTES) + 1,
    );
    std::io::Read::read_to_end(&mut bounded_input, &mut bytes).map_err(|error| {
        RunnerError::InvalidOption(format!(
            "cannot read bundle `{}`: {error}",
            source.display()
        ))
    })?;
    if bytes.len() as u64
        > iteron_tunables::param_integer("eval.runner.max_bundle_bytes", MAX_BUNDLE_BYTES)
    {
        return Err(RunnerError::InvalidOption(format!(
            "bundle `{}` grew beyond the {MAX_BUNDLE_BYTES}-byte bound while reading",
            source.display()
        )));
    }
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| RunnerError::CreatePath {
            path: destination.display().to_string(),
            source: error,
        })?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| RunnerError::WriteArtifact {
            path: destination.display().to_string(),
            source: error,
        })?;
    let mut permissions = output
        .metadata()
        .map_err(|error| RunnerError::WriteArtifact {
            path: destination.display().to_string(),
            source: error,
        })?
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(destination, permissions).map_err(|error| {
        RunnerError::WriteArtifact {
            path: destination.display().to_string(),
            source: error,
        }
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

async fn run_cell(
    core: &Path,
    workspace: &Path,
    task: &CorpusTask,
    config: HarnessConfig,
    seed: u64,
    options: &EvalOptions,
) -> CellResult {
    let started = Instant::now();
    let output = match run_core(core, workspace, task, config, options).await {
        Ok(output) => output,
        Err(error) => {
            let mut cell = errored_cell(task, config, seed, "iteron_spawn", error);
            let agent_elapsed_ms = millis(started.elapsed());
            cell.agent_metrics = Some(AgentMetrics {
                elapsed_ms: agent_elapsed_ms,
                usage: None,
                optimization: None,
            });
            cell.elapsed_ms = agent_elapsed_ms;
            return cell;
        }
    };
    let agent_elapsed_ms = millis(started.elapsed());
    if output.timed_out {
        return timeout_cell(task, config, seed, agent_elapsed_ms);
    }
    if output.stdout_truncated {
        let mut cell = errored_cell(
            task,
            config,
            seed,
            "iteron_contract",
            "iteron stdout exceeded the bounded JSON contract limit",
        );
        cell.exit_code = Some(output.exit_code);
        cell.agent_metrics = Some(AgentMetrics {
            elapsed_ms: agent_elapsed_ms,
            usage: None,
            optimization: None,
        });
        cell.elapsed_ms = agent_elapsed_ms;
        return cell;
    }

    let parsed_output = match parse_run_output(&output.stdout, output.exit_code) {
        Ok(result) => result,
        Err(error) => {
            let mut cell = errored_cell(task, config, seed, "iteron_contract", error.to_string());
            cell.exit_code = Some(output.exit_code);
            cell.agent_metrics = Some(AgentMetrics {
                elapsed_ms: agent_elapsed_ms,
                usage: None,
                optimization: None,
            });
            cell.elapsed_ms = agent_elapsed_ms;
            return cell;
        }
    };
    let final_result = parsed_output.result;
    let cost = final_result
        .cost()
        .expect("parse_final_result validates cost");
    let mut cell = CellResult {
        task: task.id.clone(),
        config: config.name.into(),
        seed,
        partition: task.partition,
        repo_url: task.repo_url.clone(),
        commit: task.commit.clone(),
        benchmark: benchmark_reference(task),
        resolved: None,
        run_status: final_result.run_status(),
        failure_phase: None,
        exit_code: Some(output.exit_code),
        terminal_outcome: Some(final_result.outcome.clone()),
        cost_status: cost.status,
        cost_usd: cost.usd,
        cost_reason: cost.reason,
        turns: Some(final_result.turns),
        kernel_tax: final_result.kernel_tax.map(|tax| KernelTaxObservation {
            admission_latency_us: tax.admission_latency_us,
            broker_latency_us: tax.broker_latency_us,
            record_fsync_latency_us: tax.record_fsync_latency_us,
            estimated_tokens: tax.estimated_tokens,
            failed_runs: tax.failed_runs,
        }),
        oracle_status: OracleStatus::NotRun,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "uncontrolled".into(),
            reason: Some(
                "the selected Core/provider route exposes no sampling-seed contract".into(),
            ),
        },
        agent_metrics: Some(AgentMetrics {
            elapsed_ms: agent_elapsed_ms,
            usage: parsed_output.usage,
            optimization: parsed_output.optimization,
        }),
        elapsed_ms: agent_elapsed_ms,
        error: final_result.error.clone(),
        candidate_diff: None,
    };

    if cell.run_status != RunStatus::Completed {
        cell.failure_phase = Some("iteron".into());
        return cell;
    }

    cell.candidate_diff = collect_candidate_diff(workspace, options.checkout_timeout).await;
    if config.verify_gate {
        let observation =
            evaluate_command(workspace, &task.verify_command, options.oracle_timeout).await;
        cell.oracle_status = observation.status;
        cell.oracle_detail = Some(format!("verify: {}", observation.detail));
    }
    if let Err(error) = apply_benchmark_test_patch(task, workspace, options.checkout_timeout).await
    {
        cell.run_status = RunStatus::Errored;
        cell.failure_phase = Some("ground_truth_setup".into());
        cell.oracle_status = OracleStatus::InfrastructureFailed;
        cell.error = Some(error.clone());
        cell.oracle_detail = Some(match cell.oracle_detail.take() {
            Some(verify) => format!("{verify}\nground_truth_setup: {error}"),
            None => format!("ground_truth_setup: {error}"),
        });
        cell.elapsed_ms = millis(started.elapsed());
        return cell;
    }
    let ground_truth = evaluate_command(
        workspace,
        &task.ground_truth_command,
        options.oracle_timeout,
    )
    .await;
    let ground_detail = format!("ground_truth: {}", ground_truth.detail);
    cell.oracle_detail = Some(match cell.oracle_detail.take() {
        Some(verify) => format!("{verify}\n{ground_detail}"),
        None => ground_detail,
    });
    match ground_truth.status {
        OracleStatus::Passed => cell.resolved = Some(true),
        OracleStatus::TestFailed => cell.resolved = Some(false),
        OracleStatus::TimedOut => {
            cell.run_status = RunStatus::TimedOut;
            cell.failure_phase = Some("ground_truth".into());
            cell.error = Some("ground-truth oracle timed out".into());
        }
        OracleStatus::InfrastructureFailed | OracleStatus::NotRun => {
            cell.run_status = RunStatus::Errored;
            cell.failure_phase = Some("ground_truth".into());
            cell.error = Some("ground-truth oracle could not run under confinement".into());
        }
    }
    cell.elapsed_ms = millis(started.elapsed());
    cell
}

async fn attach_two_sided_verdict(
    mut cell: CellResult,
    oracle_workspace: &Path,
    task: &CorpusTask,
    options: &ParallelEvalOptions,
) -> CellResult {
    let started = Instant::now();
    let Some(candidate_diff) = cell.candidate_diff.as_deref() else {
        if matches!(
            cell.failure_phase.as_deref(),
            Some("iteron" | "iteron_spawn" | "iteron_contract" | "iteron_timeout")
        ) {
            return cell;
        }
        cell.run_status = RunStatus::Errored;
        cell.failure_phase = Some("candidate_diff".into());
        cell.oracle_status = OracleStatus::InfrastructureFailed;
        cell.error = Some("candidate diff could not be captured".into());
        cell.elapsed_ms = cell.elapsed_ms.saturating_add(millis(started.elapsed()));
        return cell;
    };
    // `candidate_diff` is written only after the frozen cell has decoded a completed Core result.
    // Its legacy oracle result is intentionally superseded by this fresh two-sided Pro oracle.
    cell.run_status = RunStatus::Completed;
    cell.failure_phase = None;
    cell.resolved = None;
    cell.oracle_status = OracleStatus::NotRun;
    cell.oracle_detail = None;
    cell.error = None;
    let receipt = match score_candidate_diff(
        task,
        candidate_diff,
        oracle_workspace,
        options.checkout_timeout,
        options.oracle_timeout,
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            cell.run_status = RunStatus::Errored;
            cell.failure_phase = Some("oracle_setup".into());
            cell.oracle_status = OracleStatus::InfrastructureFailed;
            cell.error = Some(error.clone());
            cell.oracle_detail = Some(format!("two-sided oracle setup failed: {error}"));
            cell.elapsed_ms = cell.elapsed_ms.saturating_add(millis(started.elapsed()));
            return cell;
        }
    };
    let status = two_sided_status(&receipt);
    cell.oracle_status = status;
    cell.oracle_detail = serde_json::to_string(&receipt).ok();
    match status {
        OracleStatus::Passed | OracleStatus::TestFailed => {
            cell.resolved = Some(receipt.resolved);
        }
        OracleStatus::TimedOut => {
            cell.run_status = RunStatus::TimedOut;
            cell.failure_phase = Some("two_sided_oracle".into());
            cell.error = Some("F2P/P2P oracle timed out".into());
        }
        OracleStatus::InfrastructureFailed | OracleStatus::NotRun => {
            cell.run_status = RunStatus::Errored;
            cell.failure_phase = Some("two_sided_oracle".into());
            cell.error = Some("F2P/P2P oracle could not run under confinement".into());
        }
    }
    cell.elapsed_ms = cell.elapsed_ms.saturating_add(millis(started.elapsed()));
    cell
}

fn aggregate_kernel_tax(cells: &[CellResult]) -> KernelTaxObservation {
    let mut total = KernelTaxObservation::default();
    for cell in cells {
        if let Some(observation) = cell.kernel_tax {
            total.add(observation);
        } else if matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut) {
            total.failed_runs = total.failed_runs.saturating_add(1);
        }
    }
    total
}

fn benchmark_reference(task: &CorpusTask) -> Option<crate::types::BenchmarkReference> {
    task.benchmark
        .as_ref()
        .map(|binding| binding.reference.clone())
}

fn authorize_repository(task: &CorpusTask, allow_local: bool) -> Result<(), String> {
    let scheme = url::Url::parse(&task.repo_url)
        .map_err(|error| format!("invalid repository URL after corpus validation: {error}"))?
        .scheme()
        .to_owned();
    if scheme == "file" && !allow_local {
        return Err("file:// corpus repositories require explicit local-repository opt-in".into());
    }
    Ok(())
}

async fn apply_benchmark_test_patch(
    task: &CorpusTask,
    workspace: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let Some(binding) = &task.benchmark else {
        return Ok(());
    };
    let patch_path = workspace.join(".iteron-eval-hidden-test.patch");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&patch_path)
        .map_err(|error| format!("create hidden benchmark test patch: {error}"))?;
    if let Err(error) = file
        .write_all(binding.test_patch.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&patch_path);
        return Err(format!("write hidden benchmark test patch: {error}"));
    }
    drop(file);
    let output = run_git(
        vec![
            "apply".into(),
            "--whitespace=nowarn".into(),
            "--".into(),
            patch_path.as_os_str().to_owned(),
        ],
        Some(workspace),
        timeout,
    )
    .await;
    let cleanup = std::fs::remove_file(&patch_path);
    let output = output?;
    cleanup.map_err(|error| format!("remove hidden benchmark test patch: {error}"))?;
    if !output.success() {
        return Err(format!(
            "git apply of benchmark test patch failed (exit={}, timed_out={})",
            output.exit_code, output.timed_out
        ));
    }
    Ok(())
}

/// Score an externally produced candidate with Core's own hidden F2P/P2P oracle.
///
/// Reference harnesses deliberately enter through this function. Their self-reported pass/fail
/// value is not an input, so both Core and third-party candidates use the identical evaluator.
pub async fn score_candidate_diff(
    task: &CorpusTask,
    candidate_diff: &str,
    workspace: &Path,
    checkout_timeout: Duration,
    oracle_timeout: Duration,
) -> Result<crate::types::TwoSidedOracleReceipt, String> {
    materialize_repository(task, workspace, checkout_timeout).await?;
    // Hidden tests exist only in the oracle checkout. The model-facing checkout never receives
    // them, so a candidate cannot read its held-out oracle before producing the diff.
    apply_benchmark_test_patch(task, workspace, checkout_timeout).await?;

    let provisioner = crate::provisioner::Provisioner::default();
    let fail_to_pass_before = provisioner
        .run_test_set(
            task,
            workspace,
            crate::provisioner::TestSet::FailToPass,
            oracle_timeout,
        )
        .await;
    let pass_to_pass_before = provisioner
        .run_test_set(
            task,
            workspace,
            crate::provisioner::TestSet::PassToPass,
            oracle_timeout,
        )
        .await;

    apply_candidate_diff(candidate_diff, workspace, checkout_timeout).await?;
    let fail_to_pass_after = provisioner
        .run_test_set(
            task,
            workspace,
            crate::provisioner::TestSet::FailToPass,
            oracle_timeout,
        )
        .await;
    let pass_to_pass_after = provisioner
        .run_test_set(
            task,
            workspace,
            crate::provisioner::TestSet::PassToPass,
            oracle_timeout,
        )
        .await;

    let resolved = fail_to_pass_before.status == OracleStatus::TestFailed
        && pass_to_pass_before.status == OracleStatus::Passed
        && fail_to_pass_after.status == OracleStatus::Passed
        && pass_to_pass_after.status == OracleStatus::Passed;
    Ok(crate::types::TwoSidedOracleReceipt {
        fail_to_pass_before,
        pass_to_pass_before,
        fail_to_pass_after,
        pass_to_pass_after,
        resolved,
    })
}

fn two_sided_status(receipt: &crate::types::TwoSidedOracleReceipt) -> OracleStatus {
    let statuses = [
        receipt.fail_to_pass_before.status,
        receipt.pass_to_pass_before.status,
        receipt.fail_to_pass_after.status,
        receipt.pass_to_pass_after.status,
    ];
    if statuses.contains(&OracleStatus::InfrastructureFailed) {
        OracleStatus::InfrastructureFailed
    } else if statuses.contains(&OracleStatus::TimedOut) {
        OracleStatus::TimedOut
    } else if statuses.contains(&OracleStatus::NotRun) {
        OracleStatus::NotRun
    } else if receipt.resolved {
        OracleStatus::Passed
    } else {
        OracleStatus::TestFailed
    }
}

async fn apply_candidate_diff(
    candidate_diff: &str,
    workspace: &Path,
    timeout: Duration,
) -> Result<(), String> {
    if candidate_diff.is_empty() {
        return Ok(());
    }
    if candidate_diff.len()
        > iteron_tunables::param_integer(
            "eval.runner.max_candidate_diff_bytes",
            MAX_CANDIDATE_DIFF_BYTES,
        )
    {
        return Err(format!(
            "candidate diff exceeds the {MAX_CANDIDATE_DIFF_BYTES}-byte bound"
        ));
    }
    let patch_path = workspace.join(".iteron-eval-candidate.patch");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&patch_path)
        .map_err(|error| format!("create candidate patch: {error}"))?;
    if let Err(error) = file
        .write_all(candidate_diff.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&patch_path);
        return Err(format!("write candidate patch: {error}"));
    }
    drop(file);
    let output = run_git(
        vec![
            "apply".into(),
            "--binary".into(),
            "--whitespace=nowarn".into(),
            "--".into(),
            patch_path.as_os_str().to_owned(),
        ],
        Some(workspace),
        timeout,
    )
    .await;
    let cleanup = std::fs::remove_file(&patch_path);
    let output = output?;
    cleanup.map_err(|error| format!("remove candidate patch: {error}"))?;
    if !output.success() {
        return Err(format!(
            "git apply of candidate diff failed (exit={}, timed_out={}): {}",
            output.exit_code,
            output.timed_out,
            bounded_text(&output.stderr_lossy(), 2_048)
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CoreRuntimePaths {
    home: PathBuf,
    config: PathBuf,
    temporary: PathBuf,
    runs: PathBuf,
}

fn create_isolated_runtime_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|error| format!("create private Core runtime directory: {error}"))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
            .map_err(|error| format!("create isolated Core runtime directory: {error}"))
    }
}

fn create_core_runtime(workspace: &Path) -> Result<CoreRuntimePaths, String> {
    if !workspace.is_absolute() {
        return Err("benchmark workspace must be canonical and absolute".into());
    }
    let canonical_workspace = std::fs::canonicalize(workspace)
        .map_err(|error| format!("canonicalize benchmark workspace: {error}"))?;
    if canonical_workspace != workspace {
        return Err("benchmark workspace must be canonical and absolute".into());
    }
    match std::fs::symlink_metadata(workspace.join(".iteron")) {
        Ok(_) => {
            return Err(
                "benchmark workspace contains .iteron project state; refusing a confounded arm"
                    .into(),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect benchmark project state: {error}")),
    }
    let parent = workspace
        .parent()
        .ok_or_else(|| "benchmark workspace has no runtime parent".to_owned())?;
    let name = workspace
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "benchmark workspace name is not UTF-8".to_owned())?;
    let root = parent.join(format!("{name}.core-runtime"));
    create_isolated_runtime_dir(&root)?;
    let root = std::fs::canonicalize(&root)
        .map_err(|error| format!("canonicalize isolated Core runtime root: {error}"))?;
    let mut children = [
        root.join("home"),
        root.join("config"),
        root.join("tmp"),
        root.join("runs"),
    ];
    for path in &children {
        create_isolated_runtime_dir(path)?;
    }
    for path in &mut children {
        *path = std::fs::canonicalize(&*path)
            .map_err(|error| format!("canonicalize isolated Core runtime directory: {error}"))?;
        if !path.starts_with(&root) {
            return Err("isolated Core runtime directory escaped its canonical root".into());
        }
    }
    let [home, config, temporary, runs] = children;
    Ok(CoreRuntimePaths {
        home,
        config,
        temporary,
        runs,
    })
}

async fn run_core(
    core: &Path,
    workspace: &Path,
    task: &CorpusTask,
    config: HarnessConfig,
    options: &EvalOptions,
) -> Result<ProcessOutput, String> {
    let spec = core_process_spec(core, workspace, task, config, options)?;
    run_process(&spec).await.map_err(|error| error.to_string())
}

fn core_process_spec(
    core: &Path,
    workspace: &Path,
    task: &CorpusTask,
    config: HarnessConfig,
    options: &EvalOptions,
) -> Result<ProcessSpec, String> {
    let runtime = create_core_runtime(workspace)?;
    let timing = core_process_timing(options.run_timeout)
        .ok_or_else(|| "Core agent wall budget cannot form an outer process ceiling".to_owned())?;
    let mut args: Vec<OsString> = vec![
        "-p".into(),
        "-C".into(),
        ".".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--output-schema-version".into(),
        crate::contract::ITERON_CLI_SCHEMA_VERSION
            .to_string()
            .into(),
        "--model".into(),
        options.model.clone().into(),
        "--max-wall-secs".into(),
        timing.agent_wall.as_secs().to_string().into(),
        "--allow-code".into(),
        "--dangerously-bypass-permissions".into(),
        "--runs-dir".into(),
        runtime.runs.as_os_str().to_owned(),
        "--benchmark-attempt-scope".into(),
        task.id.clone().into(),
    ];
    if options.max_turns != 0 {
        args.push("--max-turns".into());
        args.push(options.max_turns.to_string().into());
    }
    if let Some(provider) = &options.provider {
        args.push("--provider".into());
        args.push(provider.into());
    }
    if config.verify_gate {
        args.push("--verify".into());
        args.push(task.verify_command.clone().into());
    }
    args.push(task.prompt.clone().into());
    let mut inherit_env = vec![OsString::from("PATH")];
    if let Some(name) = credential_env_from_environment() {
        inherit_env.push(name.into());
    }
    let mut env = vec![
        (OsString::from("HOME"), runtime.home.as_os_str().to_owned()),
        (
            OsString::from("ITERON_CONFIG_HOME"),
            runtime.config.as_os_str().to_owned(),
        ),
        (
            OsString::from("TMPDIR"),
            runtime.temporary.as_os_str().to_owned(),
        ),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (OsString::from("LC_ALL"), OsString::from("C.UTF-8")),
        (OsString::from("NO_COLOR"), OsString::from("1")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
    ];
    if cfg!(windows) {
        env.extend([
            (
                OsString::from("USERPROFILE"),
                runtime.home.as_os_str().to_owned(),
            ),
            (
                OsString::from("TEMP"),
                runtime.temporary.as_os_str().to_owned(),
            ),
            (
                OsString::from("TMP"),
                runtime.temporary.as_os_str().to_owned(),
            ),
        ]);
        inherit_env.extend(["SYSTEMROOT".into(), "COMSPEC".into(), "PATHEXT".into()]);
    }
    Ok(ProcessSpec {
        program: core.to_owned(),
        args,
        cwd: Some(workspace.to_owned()),
        clear_env: true,
        inherit_env,
        env,
        timeout: timing.process_ceiling,
        max_output_bytes: PROCESS_OUTPUT_LIMIT,
    })
}

pub(crate) async fn materialize_repository(
    task: &CorpusTask,
    destination: &Path,
    timeout: Duration,
) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "refusing to reuse non-fresh checkout `{}`",
            destination.display()
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "checkout has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| format!("create checkout parent: {error}"))?;
    let clone = run_git(
        vec![
            "clone".into(),
            "--quiet".into(),
            "--no-checkout".into(),
            "--no-tags".into(),
            "--".into(),
            task.repo_url.clone().into(),
            destination.as_os_str().to_owned(),
        ],
        None,
        timeout,
    )
    .await?;
    if !clone.success() {
        return Err(format!(
            "git clone failed (exit={}, timed_out={})",
            clone.exit_code, clone.timed_out
        ));
    }
    let checkout = run_git(
        vec![
            "checkout".into(),
            "--quiet".into(),
            "--detach".into(),
            task.commit.clone().into(),
        ],
        Some(destination),
        timeout,
    )
    .await?;
    if !checkout.success() {
        return Err(format!(
            "git checkout of pinned commit failed (exit={}, timed_out={})",
            checkout.exit_code, checkout.timed_out
        ));
    }
    let head = run_git(
        vec!["rev-parse".into(), "HEAD".into()],
        Some(destination),
        timeout,
    )
    .await?;
    if !head.success() || String::from_utf8_lossy(&head.stdout).trim() != task.commit {
        return Err("materialized checkout HEAD does not equal the pinned commit".into());
    }
    let marker = base_commit_marker(destination)
        .ok_or_else(|| "checkout cannot derive its external base marker".to_owned())?;
    let mut marker_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)
        .map_err(|error| format!("create external checkout base marker: {error}"))?;
    marker_file
        .write_all(task.commit.as_bytes())
        .and_then(|()| marker_file.sync_all())
        .map_err(|error| format!("write external checkout base marker: {error}"))?;
    let mut permissions = marker_file
        .metadata()
        .map_err(|error| format!("inspect external checkout base marker: {error}"))?
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&marker, permissions)
        .map_err(|error| format!("seal external checkout base marker: {error}"))?;
    Ok(())
}

async fn run_git(
    args: Vec<OsString>,
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    run_git_with_output_limit(args, cwd, timeout, 64 * 1024).await
}

async fn run_git_with_output_limit(
    args: Vec<OsString>,
    cwd: Option<&Path>,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ProcessOutput, String> {
    run_process(&ProcessSpec {
        program: PathBuf::from("git"),
        args,
        cwd: cwd.map(Path::to_owned),
        clear_env: false,
        inherit_env: Vec::new(),
        env: vec![
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            (
                "GIT_CONFIG_GLOBAL".into(),
                if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
            ),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_LFS_SKIP_SMUDGE".into(), "1".into()),
        ],
        timeout,
        max_output_bytes,
    })
    .await
    .map_err(|error| error.to_string())
}

struct OracleObservation {
    status: OracleStatus,
    detail: String,
}

async fn evaluate_command(workspace: &Path, command: &str, timeout: Duration) -> OracleObservation {
    let mut confinement = Confinement::egress_off(workspace);
    confinement.timeout_secs = timeout.as_secs().max(1);
    confinement.max_output_bytes =
        iteron_tunables::param_integer("eval.runner.oracle_output_limit", ORACLE_OUTPUT_LIMIT);
    match iteron_sandbox::platform_sandbox()
        .run(command, &confinement)
        .await
    {
        Ok(output) if output.timed_out => OracleObservation {
            status: OracleStatus::TimedOut,
            detail: "timed out inside the egress-off sandbox".into(),
        },
        Ok(output) => {
            let status = if output.exit_code == 0 {
                OracleStatus::Passed
            } else {
                OracleStatus::TestFailed
            };
            let truncation = if output.stdout_truncated || output.stderr_truncated {
                format!(
                    " [bounded output truncated: stdout={}, stderr={}]",
                    output.stdout_truncated, output.stderr_truncated
                )
            } else {
                String::new()
            };
            OracleObservation {
                status,
                detail: format!(
                    "sandbox exit={}{}; {}",
                    output.exit_code,
                    truncation,
                    bounded_text(&format!("{}\n{}", output.stdout, output.stderr), 4_096)
                ),
            }
        }
        Err(error) => OracleObservation {
            status: OracleStatus::InfrastructureFailed,
            detail: format!("sandbox refused or failed: {error}"),
        },
    }
}

async fn collect_candidate_diff(workspace: &Path, timeout: Duration) -> Option<String> {
    let marker = base_commit_marker(workspace)?;
    if std::fs::metadata(&marker).ok()?.len() > 64 {
        return None;
    }
    let base_commit = std::fs::read_to_string(marker).ok()?;
    let base_commit = base_commit.trim();
    if base_commit.len() != 40 || !base_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    // Intent-to-add makes untracked source files appear in `git diff` without staging their
    // contents or mutating the caller's real repository (this checkout is cell-private).
    let intent = run_git(
        vec!["add".into(), "-N".into(), "--".into(), ".".into()],
        Some(workspace),
        timeout,
    )
    .await
    .ok()?;
    if !intent.success() {
        return None;
    }
    let output = run_git_with_output_limit(
        vec![
            "diff".into(),
            "--binary".into(),
            "--no-ext-diff".into(),
            base_commit.into(),
        ],
        Some(workspace),
        timeout,
        iteron_tunables::param_integer(
            "eval.runner.max_candidate_diff_bytes",
            MAX_CANDIDATE_DIFF_BYTES,
        ),
    )
    .await
    .ok()?;
    if !output.success() || output.stdout_truncated {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn base_commit_marker(workspace: &Path) -> Option<PathBuf> {
    let parent = workspace.parent()?;
    let name = workspace.file_name()?.to_str()?;
    Some(parent.join(format!(".{name}.base-commit")))
}

fn timeout_cell(
    task: &CorpusTask,
    config: HarnessConfig,
    seed: u64,
    elapsed_ms: u64,
) -> CellResult {
    let mut cell = errored_cell(
        task,
        config,
        seed,
        "iteron_timeout",
        "iteron process exceeded the configured wall-clock timeout",
    );
    cell.run_status = RunStatus::TimedOut;
    cell.agent_metrics = Some(AgentMetrics {
        elapsed_ms,
        usage: None,
        optimization: None,
    });
    cell.elapsed_ms = elapsed_ms;
    cell
}

fn errored_cell(
    task: &CorpusTask,
    config: HarnessConfig,
    seed: u64,
    phase: &str,
    error: impl Into<String>,
) -> CellResult {
    CellResult::errored(
        CellKey {
            task: &task.id,
            config: config.name,
            seed,
            partition: task.partition,
            repo_url: &task.repo_url,
            commit: &task.commit,
        },
        phase,
        error,
    )
}

fn cell_directory(task: &CorpusTask, config: HarnessConfig, seed: u64) -> String {
    let digest = Sha256::digest(format!("{}\0{}\0{seed}", task.id, config.name).as_bytes());
    format!("cell-{}", &hex::encode(digest)[..24])
}

fn new_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("eval-{nanos:x}-{:x}", std::process::id())
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn bounded_text(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        text.to_owned()
    } else {
        format!(
            "…{}",
            text.chars().skip(count - max_chars).collect::<String>()
        )
    }
}

fn write_artifact_atomic(manifest: &EvaluationManifest, path: &Path) -> Result<(), RunnerError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| RunnerError::CreatePath {
        path: parent.display().to_string(),
        source,
    })?;
    let temporary = parent.join(format!(".iteron-eval-{}.tmp", manifest.run_id));
    let bytes = serde_json::to_vec_pretty(manifest).map_err(RunnerError::Encode)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| RunnerError::WriteArtifact {
            path: temporary.display().to_string(),
            source,
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|source| RunnerError::WriteArtifact {
            path: temporary.display().to_string(),
            source,
        })?;
    std::fs::rename(&temporary, path).map_err(|source| RunnerError::WriteArtifact {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{BenchmarkBinding, CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
    use crate::types::{BenchmarkReference, Partition};
    use std::process::Command;

    /// A path no other caller in this process can also produce.
    ///
    /// The pid and the clock are not enough. Six tests reach here through `fixture_repo`, all
    /// with the same label, all in one test binary, and `SystemTime` does not actually resolve
    /// to nanoseconds on macOS. Two threads that read it in the same tick built the same path,
    /// `create_dir_all` succeeded for both because it is idempotent, and then both ran `git
    /// init` in one directory -- where the loser fails copying a template hook that the winner
    /// has already written:
    ///
    /// ```text
    /// fatal: cannot copy '.../templates/hooks/push-to-checkout.sample'
    ///   to '.../.git/hooks/push-to-checkout.sample': File exists
    /// ```
    ///
    /// It only shows up under `cargo test --workspace`, which is why it read as a Windows or a
    /// CI problem rather than as this. The counter makes the name unique by construction.
    fn unique_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "iteron-eval-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn fixture_repo() -> (PathBuf, String, String) {
        let repo = unique_dir("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        std::fs::write(repo.join("status.txt"), "bad\n").unwrap();
        git(&repo, &["add", "status.txt"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=eval",
                "-c",
                "user.email=eval@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        );
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let url = url::Url::from_file_path(&repo).unwrap().to_string();
        (repo, url, commit)
    }

    fn task(url: String, commit: String) -> CorpusTask {
        CorpusTask {
            id: "fixture-task".into(),
            repo_url: url,
            commit,
            prompt: "make status.txt contain good".into(),
            verify_command: "test \"$(cat status.txt)\" = good".into(),
            ground_truth_command: "test \"$(cat status.txt)\" = good".into(),
            dockerhub_tag: None,
            fail_to_pass: vec!["fixture::status".into()],
            pass_to_pass: Vec::new(),
            test_cmd: std::collections::BTreeMap::from([(
                "legacy".into(),
                "test \"$(cat status.txt)\" = good".into(),
            )]),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "local-git-golden".into(),
                task_id: "fixture-task".into(),
                license: None,
            },
            benchmark: None,
        }
    }

    fn timeout_validation_options(root: &Path) -> ParallelEvalOptions {
        ParallelEvalOptions {
            corpus_path: root.join("missing-corpus.json"),
            output_path: root.join("result.json"),
            work_root: root.join("work"),
            core_bin: Some(root.join("missing-core")),
            allow_local_repositories: false,
            model: "timeout-validation-model".into(),
            provider: None,
            credential_env: None,
            bundle_path: None,
            purpose: EvaluationPurpose::Score,
            seeds: 1,
            minimum_seeds: 1,
            run_timeout: Duration::from_secs(1),
            checkout_timeout: Duration::from_secs(1),
            oracle_timeout: Duration::from_secs(1),
            workers: 1,
            max_turns: 1,
            uncapped: false,
            max_attempts: 1,
        }
    }

    #[test]
    fn core_runtime_is_private_outside_the_checkout_and_refuses_project_state() {
        let parent = unique_dir("core-runtime");
        let workspace = parent.join("cell");
        std::fs::create_dir_all(&workspace).unwrap();
        let workspace = workspace.canonicalize().unwrap();
        let runtime = create_core_runtime(&workspace).unwrap();
        for path in [
            &runtime.home,
            &runtime.config,
            &runtime.temporary,
            &runtime.runs,
        ] {
            assert!(path.is_dir());
            assert!(path.is_absolute());
            assert_eq!(*path, path.canonicalize().unwrap());
            assert!(!path.starts_with(&workspace));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o700);
            }
        }

        let contaminated = parent.join("contaminated");
        std::fs::create_dir_all(contaminated.join(".iteron")).unwrap();
        let contaminated = contaminated.canonicalize().unwrap();
        assert!(
            create_core_runtime(&contaminated)
                .unwrap_err()
                .contains("refusing a confounded arm")
        );
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn core_process_timing_has_bounded_grace_and_checked_deadline_edges() {
        let one = core_process_timing(Duration::from_secs(1)).unwrap();
        assert_eq!(one.agent_wall, Duration::from_secs(1));
        assert_eq!(one.grace, Duration::from_secs(1));
        assert_eq!(one.process_ceiling, Duration::from_secs(2));

        let proportional = core_process_timing(Duration::from_secs(40)).unwrap();
        assert_eq!(proportional.grace, Duration::from_secs(2));
        assert_eq!(proportional.process_ceiling, Duration::from_secs(42));

        let capped = core_process_timing(Duration::from_secs(1_800)).unwrap();
        assert_eq!(capped.grace, Duration::from_secs(30));
        assert_eq!(capped.process_ceiling, Duration::from_secs(1_830));

        let maximum = core_process_timing(Duration::from_secs(MAX_ITERON_AGENT_WALL_SECS)).unwrap();
        assert_eq!(maximum.grace, Duration::from_secs(30));
        assert_eq!(
            maximum.process_ceiling,
            Duration::from_secs(MAX_ITERON_AGENT_WALL_SECS + 30)
        );

        assert!(core_process_timing(Duration::ZERO).is_none());
        assert!(core_process_timing(Duration::from_millis(1_500)).is_none());
        assert!(core_process_timing(Duration::from_secs(MAX_ITERON_AGENT_WALL_SECS + 1)).is_none());
        assert!(core_process_timing(Duration::from_secs(u64::MAX)).is_none());
    }

    #[test]
    fn evaluation_durations_reject_zero_and_nonzero_subsecond_values_consistently() {
        for name in ["run_timeout", "checkout_timeout", "oracle_timeout"] {
            for invalid in [
                Duration::ZERO,
                Duration::from_nanos(1),
                Duration::from_millis(999),
                Duration::from_millis(1_500),
            ] {
                let error =
                    validate_whole_second_duration(name, invalid, 24 * 60 * 60).unwrap_err();
                assert!(error.to_string().contains(name));
                assert!(
                    error
                        .to_string()
                        .contains("positive whole number of seconds")
                );
            }
            validate_whole_second_duration(name, Duration::from_secs(1), 24 * 60 * 60).unwrap();
        }
    }

    #[tokio::test]
    async fn timeout_operational_maxima_accept_boundary_reject_next_and_do_not_mutate() {
        let root = unique_dir("timeout-operational-maxima");
        let mut exact = timeout_validation_options(&root);
        exact.run_timeout = Duration::from_secs(MAX_ITERON_AGENT_WALL_SECS);
        exact.checkout_timeout = Duration::from_secs(MAX_CHECKOUT_TIMEOUT_SECS);
        exact.oracle_timeout = Duration::from_secs(MAX_ORACLE_TIMEOUT_SECS);
        validate_parallel_options(&exact).expect("all exact timeout maxima are admitted");
        assert!(!root.exists(), "pure preflight validation must not mutate");

        for (name, ordinal) in [
            ("run_timeout", 0_u8),
            ("checkout_timeout", 1_u8),
            ("oracle_timeout", 2_u8),
        ] {
            let mut rejected = timeout_validation_options(&root);
            match ordinal {
                0 => {
                    rejected.run_timeout = Duration::from_secs(MAX_ITERON_AGENT_WALL_SECS + 1);
                }
                1 => {
                    rejected.checkout_timeout = Duration::from_secs(MAX_CHECKOUT_TIMEOUT_SECS + 1);
                }
                2 => {
                    rejected.oracle_timeout = Duration::from_secs(MAX_ORACLE_TIMEOUT_SECS + 1);
                }
                _ => unreachable!(),
            }
            let error = run_evaluation_parallel(&rejected)
                .await
                .expect_err("the first second above each maximum is rejected");
            assert!(
                error.to_string().contains(name),
                "unexpected error: {error}"
            );
            assert!(
                error.to_string().contains("operational maximum"),
                "unexpected error: {error}"
            );
            assert!(
                !root.exists(),
                "invalid {name} must fail before filesystem mutation"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn core_spec_uses_canonical_cwd_absolute_runtime_and_separate_outer_ceiling() {
        use std::os::unix::fs::PermissionsExt;

        let parent = unique_dir("core-process-spec");
        let workspace = parent.join("cell");
        std::fs::create_dir_all(&workspace).unwrap();
        let workspace = workspace.canonicalize().unwrap();
        let core = parent.join("fake-core");
        std::fs::write(
            &core,
            "#!/bin/sh\nprintf '%s\\n' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"budget_exhausted\",\"reason\":\"max_wall_secs\",\"success\":false,\"assistant_text\":\"\",\"run_id\":\"deadline-edge\",\"cost_usd\":null,\"cost_status\":\"unknown\",\"cost_reason\":\"fixture\",\"turns\":1,\"exit_code\":3,\"error\":null}'\nexit 3\n",
        )
        .unwrap();
        let mut permissions = core.metadata().unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&core, permissions).unwrap();
        let fixture_task = task("https://example.invalid/repo.git".into(), "0".repeat(40));
        let options = EvalOptions {
            corpus_path: parent.join("corpus.json"),
            output_path: parent.join("result.json"),
            work_root: parent.join("work"),
            core_bin: Some(core.clone()),
            allow_local_repositories: false,
            model: "deadline-model".into(),
            provider: None,
            purpose: EvaluationPurpose::Score,
            seeds: 1,
            minimum_seeds: 1,
            run_timeout: Duration::from_secs(1),
            checkout_timeout: Duration::from_secs(1),
            oracle_timeout: Duration::from_secs(1),
            max_turns: 1,
            max_attempts: 1,
        };
        let spec = core_process_spec(&core, &workspace, &fixture_task, CONFIGS[0], &options)
            .expect("build isolated Core process specification");
        assert_eq!(spec.cwd.as_deref(), Some(workspace.as_path()));
        assert_eq!(spec.timeout, Duration::from_secs(2));
        let arg_after = |flag: &str| {
            spec.args
                .windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].clone())
                .unwrap_or_else(|| panic!("missing {flag}"))
        };
        assert_eq!(arg_after("-C"), ".");
        assert_eq!(arg_after("--output-format"), "stream-json");
        assert_eq!(arg_after("--max-wall-secs"), "1");
        assert_eq!(
            arg_after("--benchmark-attempt-scope"),
            fixture_task.id.as_str()
        );
        let runs = PathBuf::from(arg_after("--runs-dir"));
        assert!(runs.is_absolute());
        assert_eq!(runs, runs.canonicalize().unwrap());
        for key in ["HOME", "ITERON_CONFIG_HOME", "TMPDIR"] {
            let value = spec
                .env
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| PathBuf::from(value))
                .unwrap_or_else(|| panic!("missing {key}"));
            assert!(value.is_absolute());
            assert_eq!(value, value.canonicalize().unwrap());
        }

        let output = run_process(&spec).await.unwrap();
        assert!(!output.timed_out);
        let result = crate::contract::parse_final_result(&output.stdout, output.exit_code).unwrap();
        assert_eq!(result.outcome, "budget_exhausted");
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn evaluator_credential_boundary_allows_only_builtin_provider_keys() {
        for allowed in BUILTIN_CREDENTIAL_ENVS {
            assert!(is_builtin_credential_env(allowed));
        }
        for rejected in [
            "BASH_ENV",
            "ENV",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "HOME",
            "ITERON_CONFIG_HOME",
            "HTTPS_PROXY",
            "RUSTC_WRAPPER",
            "BASH_ENV_API_KEY",
            "HARBOR_ITERON_GATEWAY_API_KEY",
        ] {
            assert!(!is_builtin_credential_env(rejected), "{rejected}");
        }
    }

    #[test]
    fn an_exported_but_blank_credential_name_is_unset_rather_than_the_empty_name() {
        assert_eq!(normalize_credential_env(None), None);
        assert_eq!(normalize_credential_env(Some(String::new())), None);
        assert_eq!(
            normalize_credential_env(Some("ANTHROPIC_API_KEY".into())),
            Some("ANTHROPIC_API_KEY".into())
        );
    }

    #[tokio::test]
    async fn pinned_checkout_reproduces_exact_commit_and_bad_ref_is_harness_error() {
        let (repo, url, commit) = fixture_repo();
        let task = task(url, commit.clone());
        let checkout = unique_dir("checkout");
        materialize_repository(&task, &checkout, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), commit);
        assert_eq!(
            std::fs::read_to_string(checkout.join("status.txt")).unwrap(),
            "bad\n"
        );

        let mut broken = task;
        broken.commit = "f".repeat(40);
        assert!(
            materialize_repository(
                &broken,
                &unique_dir("broken-checkout"),
                Duration::from_secs(10)
            )
            .await
            .is_err()
        );
        let _ = std::fs::remove_dir_all(repo);
        let _ = std::fs::remove_dir_all(checkout);
    }

    #[tokio::test]
    async fn candidate_diff_is_anchored_to_base_even_after_agent_commit() {
        let (repo, url, commit) = fixture_repo();
        let task = task(url, commit.clone());
        let checkout = unique_dir("committed-candidate");
        materialize_repository(&task, &checkout, Duration::from_secs(10))
            .await
            .unwrap();
        std::fs::write(checkout.join("status.txt"), "good\n").unwrap();
        git(&checkout, &["add", "status.txt"]);
        git(
            &checkout,
            &[
                "-c",
                "user.name=eval",
                "-c",
                "user.email=eval@example.invalid",
                "commit",
                "-q",
                "-m",
                "agent candidate",
            ],
        );
        std::fs::write(checkout.join("new.txt"), "untracked\n").unwrap();
        let diff = collect_candidate_diff(&checkout, Duration::from_secs(10))
            .await
            .expect("candidate diff");
        assert!(diff.contains("-bad"));
        assert!(diff.contains("+good"));
        assert!(diff.contains("new.txt"));
        let _ = std::fs::remove_dir_all(repo);
        let _ = std::fs::remove_dir_all(checkout);
    }

    #[tokio::test]
    async fn benchmark_test_patch_is_integrity_checked_then_applied_after_checkout() {
        let (repo, url, commit) = fixture_repo();
        let mut task = task(url, commit);
        let patch = "diff --git a/regression.txt b/regression.txt\nnew file mode 100644\n--- /dev/null\n+++ b/regression.txt\n@@ -0,0 +1 @@\n+hidden regression\n";
        task.benchmark = Some(BenchmarkBinding {
            reference: BenchmarkReference {
                name: "fixture-benchmark".into(),
                instance_id: "fixture-1".into(),
                dataset_revision: "dataset-revision".into(),
                environment_setup_commit: "1".repeat(40),
                environment_image: None,
                test_patch_sha256: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(patch.as_bytes()))
                ),
            },
            test_patch: patch.into(),
        });
        let checkout = unique_dir("benchmark-patch-checkout");
        materialize_repository(&task, &checkout, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!checkout.join("regression.txt").exists());
        apply_benchmark_test_patch(&task, &checkout, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(checkout.join("regression.txt")).unwrap(),
            "hidden regression\n"
        );
        assert!(!checkout.join(".iteron-eval-hidden-test.patch").exists());
        let _ = std::fs::remove_dir_all(repo);
        let _ = std::fs::remove_dir_all(checkout);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn golden_ground_truth_distinguishes_wrong_and_correct_tree_in_sandbox() {
        let (repo, url, commit) = fixture_repo();
        let task = task(url, commit);
        let checkout = unique_dir("oracle-checkout");
        materialize_repository(&task, &checkout, Duration::from_secs(10))
            .await
            .unwrap();
        let wrong = evaluate_command(
            &checkout,
            &task.ground_truth_command,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(wrong.status, OracleStatus::TestFailed);
        std::fs::write(checkout.join("status.txt"), "good\n").unwrap();
        let correct = evaluate_command(
            &checkout,
            &task.ground_truth_command,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(correct.status, OracleStatus::Passed);
        let _ = std::fs::remove_dir_all(repo);
        let _ = std::fs::remove_dir_all(checkout);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn hostile_corpus_command_cannot_write_outside_workspace() {
        let workspace = unique_dir("hostile-workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        // The sandbox intentionally grants the OS temp root, so use the invoking repository as a
        // genuinely ungranted location while the confined workspace remains under temp.
        let marker = std::env::current_dir().unwrap().join(format!(
            ".iteron-eval-hostile-marker-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!("printf escaped > '{}'", marker.display());
        let observation = evaluate_command(&workspace, &command, Duration::from_secs(5)).await;
        assert_ne!(observation.status, OracleStatus::Passed);
        assert!(!marker.exists());
        assert!(!observation.detail.is_empty());
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn manifest_artifact_round_trip_keeps_model_corpus_and_seed() {
        let commit = "0".repeat(40);
        let mut cell = CellResult::errored(
            CellKey {
                task: "task",
                config: "verify_OFF",
                seed: 7,
                partition: Partition::HeldOut,
                repo_url: "https://example.invalid/repo.git",
                commit: &commit,
            },
            "fixture",
            "expected",
        );
        cell.benchmark = Some(crate::types::BenchmarkReference {
            name: "benchmark".into(),
            instance_id: "benchmark-task".into(),
            dataset_revision: "revision".into(),
            environment_setup_commit: "1".repeat(40),
            environment_image: None,
            test_patch_sha256: format!("sha256:{}", "2".repeat(64)),
        });
        let aggregate = aggregate(std::slice::from_ref(&cell), 3);
        let manifest = EvaluationManifest {
            schema_version: EVAL_SCHEMA_VERSION,
            run_id: "run-fixture".into(),
            corpus_version: "corpus-v7".into(),
            dataset_digest: "sha256:fixture".into(),
            model: "provider/model-fixed".into(),
            provider: Some("provider".into()),
            bundle_digest: None,
            purpose: EvaluationPurpose::Score,
            seeds: 8,
            minimum_seeds: 3,
            workers: 1,
            max_turns: Some(20),
            core_agent_wall_secs: 60,
            core_process_grace_secs: 3,
            core_process_timeout_secs: 63,
            result_path: PathBuf::from("result.json"),
            comparison: compare(&aggregate, "verify_OFF", "verify_ON"),
            aggregate,
            selections: Vec::new(),
            kernel_tax: KernelTaxObservation::default(),
            cells: vec![cell],
        };
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: EvaluationManifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.model, "provider/model-fixed");
        assert_eq!(decoded.corpus_version, "corpus-v7");
        assert_eq!(decoded.cells[0].seed, 7);
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn corpus_fixture_helper_builds_a_valid_external_manifest() {
        let (repo, url, commit) = fixture_repo();
        let tasks = vec![task(url, commit)];
        let corpus = CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            corpus_version: "fixture-v1".into(),
            dataset_digest: digest_tasks(&tasks).unwrap(),
            tasks,
        };
        corpus.validate().unwrap();
        let _ = std::fs::remove_dir_all(repo);
    }

    #[test]
    fn local_repository_requires_explicit_operator_opt_in() {
        let (repo, url, commit) = fixture_repo();
        let task = task(url, commit);
        assert!(authorize_repository(&task, true).is_ok());
        assert!(
            authorize_repository(&task, false)
                .unwrap_err()
                .contains("explicit local-repository opt-in")
        );
        let _ = std::fs::remove_dir_all(repo);
    }
}

//! Real-repository, fixed-model evaluation runner.

use crate::contract::parse_final_result;
use crate::corpus::{CorpusManifest, CorpusTask};
use crate::process::{ProcessOutput, ProcessSpec, find_core, run_process};
use crate::report::{aggregate, compare, selection_summaries};
use crate::types::{
    CellKey, CellResult, EVAL_SCHEMA_VERSION, EvaluationManifest, EvaluationPurpose, OracleStatus,
    RunStatus, SamplingControl,
};
use core_sandbox::Confinement;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROCESS_OUTPUT_LIMIT: usize = 1024 * 1024;
const ORACLE_OUTPUT_LIMIT: usize = 128 * 1024;

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
    pub run_timeout: Duration,
    pub checkout_timeout: Duration,
    pub oracle_timeout: Duration,
    pub max_turns: u32,
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
    #[error("cannot encode evaluation artifact: {0}")]
    Encode(serde_json::Error),
    #[error("cannot write evaluation artifact `{path}`: {source}")]
    WriteArtifact {
        path: String,
        source: std::io::Error,
    },
}

pub async fn run_evaluation(options: &EvalOptions) -> Result<EvaluationManifest, RunnerError> {
    validate_options(options)?;
    let corpus = CorpusManifest::load(&options.corpus_path)?;
    let tasks = corpus.tasks_for(options.purpose)?;
    let core = find_core(options.core_bin.as_deref())?;
    std::fs::create_dir_all(&options.work_root).map_err(|source| RunnerError::CreatePath {
        path: options.work_root.display().to_string(),
        source,
    })?;
    let run_id = new_run_id();
    let run_root = options.work_root.join(&run_id);
    std::fs::create_dir(&run_root).map_err(|source| RunnerError::CreatePath {
        path: run_root.display().to_string(),
        source,
    })?;

    let mut cells = Vec::new();
    for task in tasks {
        for config in CONFIGS {
            for seed in 0..options.seeds {
                let cell_root = run_root.join(cell_directory(task, config, seed));
                let checkout = match authorize_repository(task, options.allow_local_repositories) {
                    Ok(()) => {
                        materialize_repository(task, &cell_root, options.checkout_timeout).await
                    }
                    Err(error) => Err(error),
                };
                let mut cell = match checkout {
                    Ok(()) => run_cell(&core, &cell_root, task, config, seed, options).await,
                    Err(error) => errored_cell(task, config, seed, "checkout", error),
                };
                cell.benchmark = benchmark_reference(task);
                cells.push(cell);
            }
        }
    }

    let summary = aggregate(&cells, options.minimum_seeds);
    let comparison = compare(&summary, "verify_OFF", "verify_ON");
    let selections = selection_summaries(&cells);
    let manifest = EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id,
        corpus_version: corpus.corpus_version,
        dataset_digest: corpus.dataset_digest,
        model: options.model.clone(),
        provider: options.provider.clone(),
        purpose: options.purpose,
        seeds: options.seeds,
        minimum_seeds: options.minimum_seeds,
        run_timeout_secs: options.run_timeout.as_secs(),
        result_path: options.output_path.clone(),
        cells,
        aggregate: summary,
        comparison,
        selections,
    };
    write_artifact_atomic(&manifest, &options.output_path)?;
    Ok(manifest)
}

fn validate_options(options: &EvalOptions) -> Result<(), RunnerError> {
    if options.model.trim().is_empty() {
        return Err(RunnerError::InvalidOption("model must be explicit".into()));
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
    for (name, duration) in [
        ("run_timeout", options.run_timeout),
        ("checkout_timeout", options.checkout_timeout),
        ("oracle_timeout", options.oracle_timeout),
    ] {
        if duration.is_zero() {
            return Err(RunnerError::InvalidOption(format!(
                "{name} must be greater than zero"
            )));
        }
    }
    if options.max_turns == 0 {
        return Err(RunnerError::InvalidOption(
            "max_turns must be at least 1".into(),
        ));
    }
    Ok(())
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
            let mut cell = errored_cell(task, config, seed, "core_spawn", error);
            cell.elapsed_ms = millis(started.elapsed());
            return cell;
        }
    };
    if output.timed_out {
        return timeout_cell(task, config, seed, started.elapsed());
    }
    if output.stdout_truncated {
        let mut cell = errored_cell(
            task,
            config,
            seed,
            "core_contract",
            "core stdout exceeded the bounded JSON contract limit",
        );
        cell.exit_code = Some(output.exit_code);
        cell.elapsed_ms = millis(started.elapsed());
        return cell;
    }

    // The versioned machine JSON on stdout and the OS exit code are the sole authorities for every
    // terminal metric; the CLI's human ledger/diagnostics on stderr are never parsed into a metric.
    // On a contract failure the stderr is retained only as debugging evidence on the errored cell.
    let final_result = match parse_final_result(&output.stdout, output.exit_code) {
        Ok(result) => result,
        Err(error) => {
            let detail = crate::contract::contract_failure_detail(&error, &output.stderr);
            let mut cell = errored_cell(task, config, seed, "core_contract", detail);
            cell.exit_code = Some(output.exit_code);
            cell.elapsed_ms = millis(started.elapsed());
            return cell;
        }
    };
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
        oracle_status: OracleStatus::NotRun,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "uncontrolled".into(),
            reason: Some(
                "the selected Core/provider route exposes no sampling-seed contract".into(),
            ),
        },
        elapsed_ms: millis(started.elapsed()),
        error: final_result.error.clone(),
        candidate_diff: None,
    };

    if cell.run_status != RunStatus::Completed {
        cell.failure_phase = Some("core".into());
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
    let patch_path = workspace.join(".core-eval-hidden-test.patch");
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

async fn run_core(
    core: &Path,
    workspace: &Path,
    task: &CorpusTask,
    config: HarnessConfig,
    options: &EvalOptions,
) -> Result<ProcessOutput, String> {
    let mut args: Vec<OsString> = vec![
        "-p".into(),
        "-C".into(),
        workspace.as_os_str().to_owned(),
        "--output-format".into(),
        "json".into(),
        "--model".into(),
        options.model.clone().into(),
        "--allow-code".into(),
        "--max-turns".into(),
        options.max_turns.to_string().into(),
    ];
    if let Some(provider) = &options.provider {
        args.push("--provider".into());
        args.push(provider.into());
    }
    if config.verify_gate {
        args.push("--verify".into());
        args.push(task.verify_command.clone().into());
    }
    args.push(task.prompt.clone().into());
    run_process(&ProcessSpec {
        program: core.to_owned(),
        args,
        cwd: None,
        env: Vec::new(),
        timeout: options.run_timeout,
        max_output_bytes: PROCESS_OUTPUT_LIMIT,
    })
    .await
    .map_err(|error| error.to_string())
}

async fn materialize_repository(
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
    Ok(())
}

async fn run_git(
    args: Vec<OsString>,
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    run_process(&ProcessSpec {
        program: PathBuf::from("git"),
        args,
        cwd: cwd.map(Path::to_owned),
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
        max_output_bytes: 64 * 1024,
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
    confinement.max_output_bytes = ORACLE_OUTPUT_LIMIT;
    match core_sandbox::platform_sandbox()
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
    let output = run_git(
        vec![
            "diff".into(),
            "--binary".into(),
            "--no-ext-diff".into(),
            "HEAD".into(),
        ],
        Some(workspace),
        timeout,
    )
    .await
    .ok()?;
    if !output.success() || output.stdout_truncated {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn timeout_cell(
    task: &CorpusTask,
    config: HarnessConfig,
    seed: u64,
    elapsed: Duration,
) -> CellResult {
    let mut cell = errored_cell(
        task,
        config,
        seed,
        "core_timeout",
        "core process exceeded the configured wall-clock timeout",
    );
    cell.run_status = RunStatus::TimedOut;
    cell.elapsed_ms = millis(elapsed);
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
    let temporary = parent.join(format!(".core-eval-{}.tmp", manifest.run_id));
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

    fn unique_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "core-eval-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "local-git-golden".into(),
                task_id: "fixture-task".into(),
                license: None,
            },
            benchmark: None,
        }
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
        assert!(!checkout.join(".core-eval-hidden-test.patch").exists());
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
            ".core-eval-hostile-marker-{}-{}",
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
            purpose: EvaluationPurpose::Score,
            seeds: 8,
            minimum_seeds: 3,
            run_timeout_secs: 60,
            result_path: PathBuf::from("result.json"),
            comparison: compare(&aggregate, "verify_OFF", "verify_ON"),
            aggregate,
            selections: Vec::new(),
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

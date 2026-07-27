//! D12-02 oracle: `core-eval` accounts for failed runs in its exit status.
//!
//! The gap under closure is "Eval discards subprocess exit status and run outcome — no failed-run
//! accounting": the evaluation binary returned an unconditional success whenever a manifest was
//! produced, so a run in which every subprocess crashed, produced a malformed contract, failed its
//! checkout, or exceeded the wall-clock timeout reported the exact same exit status as a clean run.
//!
//! These tests pin the run-outcome accounting that closes the gap:
//!   * [`EvaluationManifest::failed_runs`] counts errored + timed-out cells (harness failures) and
//!     deliberately excludes censored cells (budget / interrupt / stuck — legitimate model
//!     outcomes);
//!   * [`EvaluationManifest::exit_code`] maps a manifest carrying any failed run to a distinct
//!     non-zero code, and a clean manifest to success.
//!
//! Both are absent on the base branch, so this whole test target does not exist there (RED); with
//! the fix in place every assertion below holds (GREEN).

use core_eval::types::{EVAL_EXIT_RUN_FAILURES, EVAL_EXIT_SUCCESS, EVAL_SCHEMA_VERSION};
use core_eval::{
    CellResult, CostStatus, EvaluationManifest, EvaluationPurpose, OracleStatus, Partition,
    RunStatus, SamplingControl, aggregate, compare, selection_summaries,
};
use std::path::PathBuf;

fn cell(config: &str, seed: u64, status: RunStatus) -> CellResult {
    CellResult {
        task: "task".into(),
        config: config.into(),
        seed,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: (status == RunStatus::Completed).then_some(true),
        run_status: status,
        failure_phase: (status != RunStatus::Completed).then(|| "core".into()),
        exit_code: Some(1),
        terminal_outcome: None,
        cost_status: CostStatus::Zero,
        cost_usd: None,
        cost_reason: None,
        turns: Some(1),
        oracle_status: OracleStatus::NotRun,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "fixed".into(),
            reason: None,
        },
        elapsed_ms: 1,
        error: None,
        candidate_diff: None,
    }
}

fn manifest_of(cells: Vec<CellResult>) -> EvaluationManifest {
    let aggregate = aggregate(&cells, 1);
    let comparison = compare(&aggregate, "verify_OFF", "verify_ON");
    let selections = selection_summaries(&cells);
    EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id: "run-d12-02".into(),
        corpus_version: "d12-02".into(),
        dataset_digest: "sha256:fixture".into(),
        model: "fixture/model".into(),
        provider: None,
        purpose: EvaluationPurpose::Score,
        seeds: 1,
        minimum_seeds: 1,
        run_timeout_secs: 60,
        result_path: PathBuf::from("result.json"),
        cells,
        aggregate,
        comparison,
        selections,
    }
}

#[test]
fn exit_codes_are_stable_and_distinct() {
    // The whole point of the gap: failure and success must not collapse onto one status.
    assert_eq!(EVAL_EXIT_SUCCESS, 0);
    assert_ne!(EVAL_EXIT_RUN_FAILURES, EVAL_EXIT_SUCCESS);
}

#[test]
fn a_clean_run_accounts_for_no_failures_and_exits_success() {
    let manifest = manifest_of(vec![
        cell("verify_OFF", 0, RunStatus::Completed),
        cell("verify_ON", 0, RunStatus::Completed),
    ]);
    assert_eq!(manifest.failed_runs(), 0);
    assert_eq!(manifest.exit_code(), EVAL_EXIT_SUCCESS);
}

#[test]
fn errored_and_timed_out_runs_are_counted_and_flip_the_exit_status() {
    // A subprocess spawn / JSON-contract / checkout failure is Errored; a wall-clock overrun is
    // TimedOut. Both are harness failures the exit status must not discard.
    let errored = manifest_of(vec![cell("verify_OFF", 0, RunStatus::Errored)]);
    assert_eq!(errored.failed_runs(), 1);
    assert_eq!(errored.exit_code(), EVAL_EXIT_RUN_FAILURES);
    assert_ne!(errored.exit_code(), EVAL_EXIT_SUCCESS);

    let timed_out = manifest_of(vec![cell("verify_OFF", 0, RunStatus::TimedOut)]);
    assert_eq!(timed_out.failed_runs(), 1);
    assert_eq!(timed_out.exit_code(), EVAL_EXIT_RUN_FAILURES);
}

#[test]
fn censored_runs_are_not_harness_failures() {
    // budget_exhausted / interrupted / stuck map to Censored: legitimate model outcomes, not a
    // broken harness, so they must NOT flip the exit status even when nothing completed.
    let manifest = manifest_of(vec![
        cell("verify_OFF", 0, RunStatus::Censored),
        cell("verify_ON", 0, RunStatus::Censored),
    ]);
    assert_eq!(manifest.failed_runs(), 0);
    assert_eq!(manifest.exit_code(), EVAL_EXIT_SUCCESS);
}

#[test]
fn one_failure_among_completed_cells_still_flips_the_exit_status() {
    let manifest = manifest_of(vec![
        cell("verify_OFF", 0, RunStatus::Completed),
        cell("verify_OFF", 1, RunStatus::Completed),
        cell("verify_ON", 0, RunStatus::Completed),
        cell("verify_ON", 1, RunStatus::Errored),
    ]);
    assert_eq!(manifest.failed_runs(), 1);
    assert_eq!(manifest.exit_code(), EVAL_EXIT_RUN_FAILURES);
}

/// End-to-end proof through the real runner: a corpus whose every cell reaches a Core process that
/// emits a malformed (truncated) JSON contract makes each cell fail the contract, so the persisted
/// manifest records only failed runs — and its exit code is the non-zero failed-run status rather
/// than the unconditional success the gap used to return.
#[cfg(unix)]
mod pipeline {
    use super::*;
    use core_eval::corpus::{
        CORPUS_SCHEMA_VERSION, CorpusManifest, CorpusTask, Provenance, digest_tasks,
    };
    use core_eval::{EvalOptions, run_evaluation};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("core-eval-d12-02-{}-{nonce:x}", std::process::id()));
            std::fs::create_dir(&path).expect("create isolated D12-02 root");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("spawn git fixture command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output is UTF-8")
            .trim()
            .to_owned()
    }

    fn real_repository(root: &TempRoot) -> (String, String) {
        let repo = root.join("source-repo");
        std::fs::create_dir(&repo).expect("create source repository");
        git(&repo, &["init", "--quiet"]);
        std::fs::write(repo.join("README.md"), "fixture\n").expect("write fixture state");
        git(&repo, &["add", "README.md"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=core-eval",
                "-c",
                "user.email=core-eval@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        );
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let canonical = repo.canonicalize().expect("canonical source repository");
        let url = url::Url::from_file_path(canonical)
            .expect("file URL")
            .to_string();
        (url, commit)
    }

    /// A stand-in Core CLI that always emits a truncated final-result JSON object, so every cell
    /// that reaches the core-invocation phase fails the contract (RunStatus::Errored) without ever
    /// entering the egress-off oracle.
    fn fake_core(root: &TempRoot) -> PathBuf {
        let path = root.join("fake-core");
        std::fs::write(&path, "#!/bin/sh\nprintf '%s' '{\"schema_version\":4'\n")
            .expect("write fake core");
        let mut permissions = std::fs::metadata(&path).expect("stat fake core").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make fake core executable");
        path
    }

    fn task(id: &str, repo_url: &str, commit: &str) -> CorpusTask {
        CorpusTask {
            id: id.to_owned(),
            repo_url: repo_url.to_owned(),
            commit: commit.to_owned(),
            prompt: format!("resolve {id}"),
            verify_command: "true".into(),
            ground_truth_command: "true".into(),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "d12-02-failed-run-accounting".into(),
                task_id: id.to_owned(),
                license: Some("test-fixture-only".into()),
            },
            benchmark: None,
        }
    }

    #[tokio::test]
    async fn a_run_of_only_failed_cells_exits_non_zero_not_success() {
        let root = TempRoot::new();
        let (repo_url, commit) = real_repository(&root);
        let tasks = vec![task("t", &repo_url, &commit)];
        let corpus = CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            corpus_version: "d12-02-v1".into(),
            dataset_digest: digest_tasks(&tasks).expect("digest tasks"),
            tasks,
        };
        corpus.validate().expect("corpus is valid");
        let corpus_path = root.join("corpus.json");
        std::fs::write(
            &corpus_path,
            serde_json::to_vec_pretty(&corpus).expect("encode corpus"),
        )
        .expect("write corpus");

        let options = EvalOptions {
            corpus_path,
            output_path: root.join("out/evaluation.json"),
            work_root: root.join("work"),
            core_bin: Some(fake_core(&root)),
            allow_local_repositories: true,
            model: "fixture/model".into(),
            provider: None,
            purpose: EvaluationPurpose::Score,
            seeds: 1,
            minimum_seeds: 1,
            run_timeout: Duration::from_secs(30),
            checkout_timeout: Duration::from_secs(60),
            oracle_timeout: Duration::from_secs(5),
            max_turns: 4,
        };

        let manifest = tokio::time::timeout(Duration::from_secs(120), run_evaluation(&options))
            .await
            .expect("evaluation stays bounded")
            .expect("per-cell faults belong in the artifact, not the top-level error");

        // 1 task x 2 configs x 1 seed, and every cell failed the JSON contract.
        assert_eq!(manifest.cells.len(), 2);
        assert!(
            manifest
                .cells
                .iter()
                .all(|cell| cell.run_status == RunStatus::Errored)
        );
        assert_eq!(manifest.failed_runs(), manifest.cells.len() as u64);
        assert_eq!(manifest.exit_code(), EVAL_EXIT_RUN_FAILURES);
        assert_ne!(manifest.exit_code(), EVAL_EXIT_SUCCESS);
    }
}

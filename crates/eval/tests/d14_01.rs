#![cfg(unix)]
//! D14-01 oracle: `core-eval` performs REAL-repository evaluation, not fabricated synthetic
//! 2-file micro-repos.
//!
//! The gap under closure is "no real-repository evaluation — eval fabricates synthetic 2-file
//! micro-repos". The original harness wrote a fixed, hard-coded pair of files (e.g. `calc.py` +
//! `test_calc.py`) into a scratch directory for every task, ignoring any repository URL or commit.
//! A genuine real-repository evaluator instead clones the corpus task's actual Git repository and
//! checks out the *exact* pinned commit before invoking Core.
//!
//! This test proves the real path with two contrasts a synthetic template generator cannot exhibit:
//!
//!   1. EXACT non-tip commit materialization. One repository has a real two-commit history; the
//!      corpus pins its task to the *first* (non-tip) commit. The runner verifies `HEAD` equals the
//!      pinned SHA after checkout, so reaching the core-invocation phase (rather than failing at
//!      `checkout`) can only happen if the runner genuinely cloned the repository and detached HEAD
//!      onto that precise historical commit — not the tip, and not a hard-coded synthetic tree.
//!
//!   2. Multiple distinct real repositories. A second, genuinely different repository is bound to a
//!      second task, and each cell records its own task's real repository URL and pinned commit. A
//!      synthetic 2-file generator produces identical, repo-agnostic content and could never bind
//!      cells to two different real repository URLs.
//!
//! A third task pins the first repository to a valid-shaped but nonexistent SHA and must fail
//! *precisely* at the real Git `checkout` phase — the boundary between a valid and a bogus pinned
//! commit only exists when a real repository is materialized.
//!
//! The fixture is network-free (`file://` repositories) and sandbox-free (no cell completes, so the
//! egress-off oracle is never entered), so it runs deterministically on the Linux merge gate.

use core_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use core_eval::{
    CellResult, CorpusManifest, CorpusTask, EvalOptions, EvaluationManifest, EvaluationPurpose,
    Partition, RunStatus, run_evaluation,
};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "core-eval-d14-01-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated D14-01 root");
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
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn local git fixture command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git fixture output must be UTF-8")
        .trim()
        .to_owned()
}

fn commit(repo: &Path, message: &str) -> String {
    git(
        repo,
        &[
            "-c",
            "user.name=core-eval",
            "-c",
            "user.email=core-eval@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
    );
    git(repo, &["rev-parse", "HEAD"])
}

fn file_url(repo: &Path) -> String {
    let canonical = repo.canonicalize().expect("canonical source repository");
    url::Url::from_file_path(canonical)
        .expect("source repository must convert to a file URL")
        .to_string()
}

/// A repository with a genuine two-commit history. Returns its `file://` URL, the first (non-tip)
/// commit, and the tip commit — deliberately distinct so pinning to the first commit exercises an
/// exact historical checkout.
fn create_two_commit_repository(root: &TempRoot) -> (String, String, String) {
    let repo = root.join("repo-alpha");
    std::fs::create_dir(&repo).expect("create alpha repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("alpha.txt"), "first alpha state\n").expect("write first commit file");
    git(&repo, &["add", "alpha.txt"]);
    let first = commit(&repo, "first alpha commit");
    std::fs::write(repo.join("gamma.txt"), "second-commit addition\n")
        .expect("write second commit file");
    git(&repo, &["add", "gamma.txt"]);
    let tip = commit(&repo, "second alpha commit");
    assert_ne!(first, tip, "the fixture must have a non-trivial history");
    (file_url(&repo), first, tip)
}

/// A genuinely different single-commit repository whose distinctive file cannot appear in a
/// synthetic template that ignores the repository entirely.
fn create_other_repository(root: &TempRoot) -> (String, String) {
    let repo = root.join("repo-beta");
    std::fs::create_dir(&repo).expect("create beta repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("beta.txt"), "distinct beta repository\n").expect("write beta file");
    git(&repo, &["add", "beta.txt"]);
    let head = commit(&repo, "beta commit");
    (file_url(&repo), head)
}

/// A stand-in Core CLI that always emits a truncated (malformed) final-result JSON object. Any cell
/// that reaches the core-invocation phase therefore fails the JSON contract instead of completing —
/// which keeps the egress-off oracle (and the platform sandbox) untouched, so the test exercises
/// only the real Git materialization path and stays deterministic on the Linux gate.
fn create_fake_core(root: &TempRoot) -> PathBuf {
    let path = root.join("fake-core");
    std::fs::write(&path, "#!/bin/sh\nprintf '%s' '{\"schema_version\":4'\n")
        .expect("write executable fake core");
    let mut permissions = std::fs::metadata(&path)
        .expect("stat fake core")
        .permissions();
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
        // Never executed: no cell completes, so the verify / ground-truth oracle is not entered.
        verify_command: "true".into(),
        ground_truth_command: "true".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["legacy::true".into()],
        pass_to_pass: Vec::new(),
        test_cmd: std::collections::BTreeMap::from([("legacy".into(), "true".into())]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "d14-01-real-repository-oracle".into(),
            task_id: id.to_owned(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    }
}

fn write_corpus(root: &TempRoot, tasks: Vec<CorpusTask>) -> PathBuf {
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "d14-01-real-repository-v1".into(),
        dataset_digest: digest_tasks(&tasks).expect("digest external corpus tasks"),
        tasks,
    };
    manifest.validate().expect("external corpus must be valid");
    let path = root.join("corpus.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).expect("encode external corpus"),
    )
    .expect("write external corpus");
    path
}

fn cells_for<'a>(manifest: &'a EvaluationManifest, task: &str) -> Vec<&'a CellResult> {
    let cells: Vec<_> = manifest
        .cells
        .iter()
        .filter(|cell| cell.task == task)
        .collect();
    assert_eq!(
        cells.len(),
        2,
        "task {task} must execute both verify_OFF and verify_ON"
    );
    cells
}

#[tokio::test]
async fn evaluates_real_repositories_at_exact_pinned_commits_not_synthetic_micro_repos() {
    let root = TempRoot::new("real-repos");
    let (alpha_url, alpha_first, alpha_tip) = create_two_commit_repository(&root);
    let (beta_url, beta_commit) = create_other_repository(&root);
    assert!(
        alpha_url.starts_with("file://") && beta_url.starts_with("file://"),
        "the fixtures must be network-free"
    );
    assert_ne!(
        alpha_url, beta_url,
        "the corpus must reference two genuinely distinct repositories"
    );

    let fake_core = create_fake_core(&root);
    let corpus_path = write_corpus(
        &root,
        vec![
            // A real repository pinned to a NON-TIP historical commit.
            task("alpha-historical", &alpha_url, &alpha_first),
            // A second, genuinely different real repository.
            task("beta", &beta_url, &beta_commit),
            // The first repository pinned to a valid-shaped but nonexistent commit.
            task("alpha-bogus", &alpha_url, &"f".repeat(40)),
        ],
    );
    let artifact = root.join("out/evaluation.json");

    let options = EvalOptions {
        corpus_path,
        output_path: artifact.clone(),
        work_root: root.join("work"),
        core_bin: Some(fake_core),
        allow_local_repositories: true,
        model: "fixture/fixed-model".into(),
        provider: None,
        purpose: EvaluationPurpose::Score,
        seeds: 1,
        minimum_seeds: 1,
        run_timeout: Duration::from_secs(30),
        checkout_timeout: Duration::from_secs(60),
        oracle_timeout: Duration::from_secs(5),
        max_turns: 4,
        max_attempts: 1,
    };

    let manifest = tokio::time::timeout(Duration::from_secs(120), run_evaluation(&options))
        .await
        .expect("real-repository evaluation must remain bounded")
        .expect("per-cell faults belong in the artifact, not the top-level error");

    // 3 tasks x 2 configs x 1 seed: a real-repository matrix, not a single synthetic template.
    assert_eq!(manifest.cells.len(), 6, "3 tasks x 2 configs x 1 seed");

    // Every cell binds to its own task's real repository URL — a synthetic 2-file generator would
    // bind them all to the same hard-coded scratch tree regardless of task.
    let distinct_urls: BTreeSet<&str> = manifest
        .cells
        .iter()
        .map(|cell| cell.repo_url.as_str())
        .collect();
    assert_eq!(
        distinct_urls,
        BTreeSet::from([alpha_url.as_str(), beta_url.as_str()]),
        "cells must bind to exactly the two distinct real repositories"
    );

    // (1) EXACT non-tip commit materialization. The task pinned to the FIRST (non-tip) commit is
    // cloned and checked out at precisely that SHA — the runner verifies HEAD == pinned commit — so
    // it reaches the core phase and never fails at `checkout`. Only a real Git checkout of an exact
    // historical commit can do this; a synthetic tree could not.
    for cell in cells_for(&manifest, "alpha-historical") {
        assert_eq!(cell.repo_url, alpha_url);
        assert_eq!(
            cell.commit, alpha_first,
            "the pinned historical commit must be recorded verbatim"
        );
        assert_ne!(
            cell.commit, alpha_tip,
            "the pinned commit is deliberately NOT the repository tip"
        );
        assert_eq!(cell.run_status, RunStatus::Errored);
        let phase = cell
            .failure_phase
            .as_deref()
            .expect("a failed cell records its phase");
        assert_ne!(
            phase, "checkout",
            "an exact historical commit must materialize, not fail at checkout"
        );
        assert!(
            phase.starts_with("core"),
            "materialization at the pinned commit must reach the core phase, got `{phase}`"
        );
    }

    // (2) A second, genuinely different real repository is materialized at its own pinned commit.
    for cell in cells_for(&manifest, "beta") {
        assert_eq!(cell.repo_url, beta_url);
        assert_eq!(cell.commit, beta_commit);
        assert_eq!(cell.run_status, RunStatus::Errored);
        let phase = cell
            .failure_phase
            .as_deref()
            .expect("a failed cell records its phase");
        assert_ne!(phase, "checkout");
        assert!(
            phase.starts_with("core"),
            "the second real repository must also materialize and reach the core phase, got `{phase}`"
        );
    }

    // (3) A valid-shaped but nonexistent pinned commit fails PRECISELY at the real Git checkout,
    // naming the pinned commit — the valid/bogus boundary only exists for a materialized repository.
    for cell in cells_for(&manifest, "alpha-bogus") {
        assert_eq!(cell.repo_url, alpha_url);
        assert_eq!(cell.commit, "f".repeat(40));
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("checkout"));
        assert_eq!(
            cell.exit_code, None,
            "no core process runs when checkout of the pinned commit fails"
        );
        assert!(
            cell.error
                .as_deref()
                .is_some_and(|error| error.contains("pinned commit")),
            "the checkout failure must name the pinned commit, got {:?}",
            cell.error
        );
    }

    // The valid historical commit and the bogus commit diverge at different phases — the signature
    // of real materialization rather than a repo-agnostic synthetic path.
    let historical_phase = cells_for(&manifest, "alpha-historical")[0]
        .failure_phase
        .clone();
    let bogus_phase = cells_for(&manifest, "alpha-bogus")[0].failure_phase.clone();
    assert_ne!(
        historical_phase, bogus_phase,
        "a real vs. nonexistent pinned commit must fail at different phases"
    );

    // The versioned real-repository run is persisted to a machine-readable artifact.
    assert_eq!(manifest.result_path, artifact);
    assert!(manifest.dataset_digest.starts_with("sha256:"));
    let bytes = std::fs::read(&artifact).expect("artifact must be persisted to disk");
    let decoded: EvaluationManifest =
        serde_json::from_slice(&bytes).expect("artifact must round-trip through its schema");
    assert_eq!(decoded.cells, manifest.cells);
    assert_eq!(decoded.corpus_version, "d14-01-real-repository-v1");
}

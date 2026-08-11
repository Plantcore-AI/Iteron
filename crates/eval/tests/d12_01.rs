#![cfg(unix)]
//! D12-01 oracle: `iteron-eval` performs REAL-repository evaluation.
//!
//! The gap under closure is "eval runs only synthetic micro-repos; no real-repository
//! evaluation". This test drives the public [`run_evaluation`] pipeline end to end against a
//! versioned external corpus whose tasks point at an actual Git repository, and proves the runner
//! genuinely clones that repository and checks out an exact pinned commit — behaviour that a
//! synthetic / in-process micro-repo path cannot exhibit.
//!
//! The proof is a contrast that is impossible without real Git materialization: a task pinned to a
//! commit that truly exists in the repository is cloned + checked out and reaches the
//! core-invocation phase, while an otherwise-identical task pinned to a nonexistent SHA fails
//! *precisely* at the `checkout` phase with an error naming the pinned commit. Every cell is bound
//! to the real repository URL and pinned commit, and the run is persisted to a versioned artifact.
//!
//! The test is network-free (a `file://` fixture repository) and sandbox-free (no cell completes,
//! so the egress-off oracle is never entered), so it runs deterministically on the Linux merge
//! gate rather than only on a developer's macOS box.

use iteron_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use iteron_eval::{
    CellResult, CorpusManifest, CorpusTask, EvalOptions, EvaluationManifest, EvaluationPurpose,
    Partition, RunStatus, run_evaluation,
};
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
            "iteron-eval-d12-01-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated D12-01 root");
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

/// Build a genuine local Git repository and return its `file://` URL plus a real pinned commit.
fn create_real_repository(root: &TempRoot) -> (String, String) {
    let repo = root.join("source-repo");
    std::fs::create_dir(&repo).expect("create source repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("README.md"), "pinned evaluation fixture\n")
        .expect("write committed fixture state");
    git(&repo, &["add", "README.md"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=iteron-eval",
            "-c",
            "user.email=iteron-eval@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "pinned evaluation fixture",
        ],
    );
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    let canonical = repo.canonicalize().expect("canonical source repository");
    let url = url::Url::from_file_path(canonical)
        .expect("source repository must convert to a file URL")
        .to_string();
    (url, commit)
}

/// A stand-in Core CLI that always emits a truncated (malformed) final-result JSON object. Any
/// cell that reaches the core-invocation phase therefore fails the JSON contract instead of
/// completing — which keeps the egress-off oracle (and thus the platform sandbox) untouched, so
/// this test exercises only the real Git materialization path.
fn create_fake_core(root: &TempRoot) -> PathBuf {
    let path = root.join("fake-core");
    std::fs::write(&path, "#!/bin/sh\nprintf '%s' '{\"schema_version\":4'\n")
        .expect("write executable fake iteron");
    let mut permissions = std::fs::metadata(&path)
        .expect("stat fake iteron")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make fake iteron executable");
    path
}

fn task(id: &str, repo_url: &str, commit: &str) -> CorpusTask {
    CorpusTask {
        id: id.to_owned(),
        repo_url: repo_url.to_owned(),
        commit: commit.to_owned(),
        prompt: format!("resolve {id}"),
        // Never executed: no cell completes, so the verify/ground-truth oracle is not entered.
        verify_command: "true".into(),
        ground_truth_command: "true".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["legacy::true".into()],
        pass_to_pass: Vec::new(),
        test_cmd: std::collections::BTreeMap::from([("legacy".into(), "true".into())]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "d12-01-real-repository-oracle".into(),
            task_id: id.to_owned(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    }
}

fn write_corpus(root: &TempRoot, real_url: &str, real_commit: &str) -> PathBuf {
    let tasks = vec![
        task("real-pinned", real_url, real_commit),
        task("nonexistent-pinned", real_url, &"f".repeat(40)),
    ];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "d12-01-real-repository-v1".into(),
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
async fn evaluates_a_real_pinned_repository_not_a_synthetic_micro_repo() {
    let root = TempRoot::new("real-repo");
    let (repo_url, commit) = create_real_repository(&root);
    assert!(
        repo_url.starts_with("file://"),
        "the fixture must be network-free"
    );
    assert_eq!(commit.len(), 40, "a real pinned commit is a full Git SHA");

    let fake_core = create_fake_core(&root);
    let corpus_path = write_corpus(&root, &repo_url, &commit);
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

    // Two corpus tasks, each run under verify_OFF and verify_ON: a real-repository matrix.
    assert_eq!(manifest.cells.len(), 4, "2 tasks x 2 configs x 1 seed");
    assert!(
        manifest.cells.iter().all(|cell| cell.repo_url == repo_url),
        "every cell must be bound to the real repository URL, not a synthetic in-process repo"
    );

    // The task pinned to a commit that genuinely exists is materialized (cloned + checked out) and
    // proceeds to the core-invocation phase — it never fails at `checkout`. This is only possible
    // if the runner actually clones the real repository and checks out the exact pinned commit.
    for cell in cells_for(&manifest, "real-pinned") {
        assert_eq!(
            cell.commit, commit,
            "the real pinned commit must be recorded verbatim"
        );
        assert_eq!(cell.run_status, RunStatus::Errored);
        let phase = cell
            .failure_phase
            .as_deref()
            .expect("a failed cell records its phase");
        assert!(
            phase.starts_with("iteron"),
            "a real pinned commit must materialize and reach the iteron phase, got `{phase}`"
        );
        assert_ne!(
            phase, "checkout",
            "the pinned commit exists, so materialization must not fail at checkout"
        );
    }

    // An otherwise-identical task pinned to a commit that does NOT exist fails precisely at the
    // real Git checkout of the pinned SHA — a synthetic micro-repo path could never distinguish a
    // valid pinned commit from a bogus one.
    for cell in cells_for(&manifest, "nonexistent-pinned") {
        assert_eq!(cell.commit, "f".repeat(40));
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("checkout"));
        assert_eq!(
            cell.exit_code, None,
            "no iteron process runs when checkout of the pinned commit fails"
        );
        assert!(
            cell.error
                .as_deref()
                .is_some_and(|error| error.contains("pinned commit")),
            "the checkout failure must name the pinned commit, got {:?}",
            cell.error
        );
    }

    // The contrast is load-bearing: a real vs. bogus pinned commit diverge at the materialization
    // boundary, which is the definition of real-repository (not synthetic) evaluation.
    let real_phase = cells_for(&manifest, "real-pinned")[0].failure_phase.clone();
    let bogus_phase = cells_for(&manifest, "nonexistent-pinned")[0]
        .failure_phase
        .clone();
    assert_ne!(
        real_phase, bogus_phase,
        "the valid and the nonexistent pinned commit must fail at different phases"
    );

    // The versioned real-repository run is persisted to a machine-readable artifact.
    assert_eq!(manifest.result_path, artifact);
    assert!(manifest.dataset_digest.starts_with("sha256:"));
    let bytes = std::fs::read(&artifact).expect("artifact must be persisted to disk");
    let decoded: EvaluationManifest =
        serde_json::from_slice(&bytes).expect("artifact must round-trip through its schema");
    assert_eq!(decoded.cells, manifest.cells);
    assert_eq!(decoded.corpus_version, "d12-01-real-repository-v1");
}

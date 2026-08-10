#![cfg(unix)]
//! D14-05 oracle: the `iteron-eval` measurement machinery in `crates/eval/src/main.rs` has
//! black-box coverage of its two load-bearing behaviors — the process exit-code contract and the
//! human-readable summary — driven through the ACTUAL compiled binary rather than only its library
//! internals.
//!
//! The gap under closure is "zero tests on the measurement machinery": `src/main.rs` owns the CLI
//! wiring, the `print_summary` report, and — critically — the finalization of the run outcome into
//! the process exit status (`std::process::exit(i32::from(manifest.exit_code()))`). None of that
//! was exercised end-to-end. A frozen exit-code contract is exactly the kind of surface a silent
//! regression (e.g. reverting to an unconditional `ExitCode::SUCCESS`) would slip through, so it is
//! pinned here against the real binary.
//!
//! Two contrasts, both deterministic and network-free on the Linux merge gate:
//!
//!   1. HARNESS ERROR -> exit 2. A missing corpus makes `run_evaluation` return `Err`, so the
//!      binary reports the tool-level failure and exits with the dedicated harness code. No manifest
//!      is produced.
//!
//!   2. RECORDED RUN FAILURES -> exit 1 (NOT a clean success). A `file://` corpus + a stand-in Core
//!      that emits truncated JSON drives every cell to a typed `errored` run status. The evaluation
//!      artifact is still written, but the binary must finalize the failed-run accounting into a
//!      non-zero exit and print the summary that names it — a completed-with-failures run and a
//!      clean run cannot both report success.
//!
//! No cell reaches a terminal model outcome, so the egress-off sandbox / ground-truth oracle is
//! never entered; the test stays deterministic and sandbox-free on the gate (mirroring d14_01).

use iteron_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use iteron_eval::{CorpusManifest, CorpusTask, EvaluationManifest, Partition, RunStatus};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The compiled `iteron-eval` binary under test. Cargo builds it and exports this path before running
/// this integration target, so the measurement machinery is exercised exactly as an operator runs it.
const ITERON_EVAL_BIN: &str = env!("CARGO_BIN_EXE_iteron-eval");

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-eval-d14-05-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated D14-05 root");
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
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git fixture output must be UTF-8")
        .trim()
        .to_owned()
}

/// A single-commit `file://` repository. Returns its URL and pinned commit — network-free so the
/// runner materializes it without egress on the gate.
fn create_repository(root: &TempRoot) -> (String, String) {
    let repo = root.join("repo");
    std::fs::create_dir(&repo).expect("create fixture repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("state.txt"), "unresolved\n").expect("write fixture file");
    git(&repo, &["add", "state.txt"]);
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
            "fixture commit",
        ],
    );
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    let canonical = repo.canonicalize().expect("canonical fixture repository");
    let url = url::Url::from_file_path(canonical)
        .expect("fixture repository must convert to a file URL")
        .to_string();
    (url, commit)
}

/// A stand-in Core CLI that always emits a truncated (malformed) final-result object. Any cell that
/// reaches the core-invocation phase therefore fails the JSON contract and is recorded as a typed
/// `errored` run — never completing, so the sandbox / oracle path is never entered.
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

fn write_corpus(root: &TempRoot, repo_url: &str, commit: &str) -> PathBuf {
    let tasks = vec![CorpusTask {
        id: "measurement-task".into(),
        repo_url: repo_url.to_owned(),
        commit: commit.to_owned(),
        prompt: "resolve measurement-task".into(),
        // Never executed: no cell completes, so the verify / ground-truth oracle is not entered.
        verify_command: "true".into(),
        ground_truth_command: "true".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["legacy::true".into()],
        pass_to_pass: Vec::new(),
        test_cmd: std::collections::BTreeMap::from([("legacy".into(), "true".into())]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "d14-05-measurement-oracle".into(),
            task_id: "measurement-task".into(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    }];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "d14-05-measurement-v1".into(),
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

#[test]
fn missing_corpus_is_a_harness_error_that_exits_two_and_names_the_tool() {
    let root = TempRoot::new("harness-error");
    let artifact = root.join("out/evaluation.json");
    let output = Command::new(ITERON_EVAL_BIN)
        .arg("--corpus")
        .arg(root.join("does-not-exist.json"))
        .arg("--model")
        .arg("fixture/fixed-model")
        .arg("--work-root")
        .arg(root.join("work"))
        .arg("--output")
        .arg(&artifact)
        .output()
        .expect("run iteron-eval binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a harness-level failure (unreadable corpus) must exit with the dedicated harness code, \
         not a success or a run-failure code; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("iteron-eval:"),
        "the harness error must be reported on stderr under the tool name, got: {stderr:?}"
    );
    // A harness error produces no artifact — the run never reached aggregation.
    assert!(
        !artifact.exists(),
        "no evaluation artifact may be written when the harness fails before aggregation"
    );
}

#[test]
fn recorded_run_failures_finalize_a_nonzero_exit_and_print_the_summary() {
    let root = TempRoot::new("run-failures");
    let (repo_url, commit) = create_repository(&root);
    assert!(
        repo_url.starts_with("file://"),
        "the fixture must be network-free"
    );
    let fake_core = create_fake_core(&root);
    let corpus_path = write_corpus(&root, &repo_url, &commit);
    let artifact = root.join("out/evaluation.json");

    let output = Command::new(ITERON_EVAL_BIN)
        .arg("--corpus")
        .arg(&corpus_path)
        .arg("--model")
        .arg("fixture/fixed-model")
        .arg("--core-bin")
        .arg(&fake_core)
        .arg("--allow-local-repositories")
        .arg("--seeds")
        .arg("1")
        .arg("--minimum-seeds")
        .arg("1")
        .arg("--work-root")
        .arg(root.join("work"))
        .arg("--output")
        .arg(&artifact)
        .output()
        .expect("run iteron-eval binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // (1) The exit-code CONTRACT: a run that RECORDED failed cells must finalize into a non-zero
    // exit. An unconditional `ExitCode::SUCCESS` (the regression this pins) would return 0 here.
    assert_eq!(
        output.status.code(),
        Some(1),
        "a run with recorded errored cells must exit non-zero (run-failure code), not clean; \
         stdout: {stdout}\nstderr: {stderr}"
    );

    // (2) The summary REPORT names the finalized outcome. One task x two configs x one seed = two
    // cells, and the stand-in Core drives both to the typed `errored` run status.
    assert!(
        stdout.contains("| cells=2"),
        "the summary header must report the full 1x2x1 cell matrix, got: {stdout}"
    );
    assert!(
        stdout.contains("failed_runs=2 (errored+timed_out); exit_code=1"),
        "the summary must reconcile the failed-run accounting with the finalized exit code, \
         got: {stdout}"
    );
    assert!(
        stdout.contains("errored=1"),
        "each config's summary line must surface its errored-cell count, got: {stdout}"
    );
    assert!(
        stdout.contains("artifact="),
        "the summary must point at the persisted evaluation artifact, got: {stdout}"
    );

    // (3) The artifact is still persisted despite the non-zero exit, and every cell is a typed
    // `errored` run — the harness censored the failures rather than scoring them as wrong patches.
    let bytes =
        std::fs::read(&artifact).expect("the evaluation artifact must be persisted to disk");
    let manifest: EvaluationManifest =
        serde_json::from_slice(&bytes).expect("artifact must round-trip through its schema");
    assert_eq!(manifest.cells.len(), 2, "1 task x 2 configs x 1 seed");
    assert!(
        manifest
            .cells
            .iter()
            .all(|cell| cell.run_status == RunStatus::Errored),
        "every cell must be recorded as a typed errored run under the stand-in Core"
    );
    assert_eq!(
        manifest.failed_runs(),
        2,
        "the manifest's own failed-run accounting must match the printed summary"
    );
    assert_eq!(
        manifest.exit_code(),
        1,
        "the manifest exit code and the binary's process exit status must agree"
    );
}

#![cfg(unix)]
//! D14-03 oracle: `core-eval` classifies every cell from the CLI's versioned JSON *evidence
//! contract* on stdout plus the OS exit code — NEVER from the CLI's human-readable stderr chrome.
//!
//! The gap under closure is "eval consumes the CLI's human stderr chrome, not the versioned JSON
//! evidence contract". The Core CLI, under `--output-format json`, prints exactly one versioned
//! `result` object on stdout (`schema_version` + typed `outcome`/`success`/`exit_code`/`turns`/
//! `cost_status`, `crates/cli/src/output.rs`) while its human operator chrome — the
//! `core · repo=… · model=… · run=…` banner, the `outcome: …` line, the ledger `turns=…`/`cost=$…`
//! summary — streams to stderr (`crates/cli/src/main.rs`). Only the stdout object is a contract;
//! the stderr text is diagnostic prose that a future build may reword freely. A harness that scraped
//! that prose for the run's outcome, turn count, or cost would silently mismeasure the model.
//!
//! This oracle drives the ACTUAL compiled `core-eval` binary against a `file://` corpus with a
//! stand-in Core whose two streams tell DELIBERATELY CONTRADICTORY stories, and pins that the
//! recorded cells follow the stdout contract, not the stderr chrome. Both contrasts stop at a
//! non-`Completed` run status, so no cell reaches the egress-off sandbox / ground-truth oracle — the
//! test stays deterministic and sandbox-free on the Linux merge gate (mirroring d14_01 / d14_05).
//!
//!   1. AUTHORITATIVE STDOUT. stdout carries a truthful *censored* terminal outcome
//!      (`budget_exhausted`, exit 3, 4 turns, unknown cost); stderr shouts a conflicting clean
//!      success (`outcome: Done`, `turns=999`, `cost=$0`), including a whole valid-looking `result`
//!      object placed on the WRONG stream. The recorded cell must be the stdout truth
//!      (censored / 4 turns / unknown cost), and none of the stderr fictions may leak in.
//!
//!   2. NO STDERR FALLBACK. The versioned `result` object is emitted only on stderr while stdout
//!      carries nothing but human chrome. A harness that fell back to scraping stderr would score a
//!      clean completed run; the honest classification is a hard JSON-contract error, so the cell is
//!      a typed `errored` harness failure with no terminal outcome, turns, or resolution scavenged
//!      from the stderr text.

use core_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use core_eval::{
    CorpusManifest, CorpusTask, CostStatus, EvaluationManifest, Partition, RunStatus,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The compiled `core-eval` binary under test — the exact measurement machinery an operator runs.
const CORE_EVAL_BIN: &str = env!("CARGO_BIN_EXE_core-eval");

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "core-eval-d14-03-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated D14-03 root");
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

/// A single-commit `file://` repository — network-free so the runner materializes it without egress.
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
            "user.name=core-eval",
            "-c",
            "user.email=core-eval@example.invalid",
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

/// Write an executable stand-in Core CLI from an exact shell body.
fn write_fake_core(root: &TempRoot, script: &str) -> PathBuf {
    let path = root.join("fake-core");
    std::fs::write(&path, script).expect("write executable fake core");
    let mut permissions = std::fs::metadata(&path)
        .expect("stat fake core")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make fake core executable");
    path
}

fn write_corpus(root: &TempRoot, repo_url: &str, commit: &str) -> PathBuf {
    let tasks = vec![CorpusTask {
        id: "evidence-task".into(),
        repo_url: repo_url.to_owned(),
        commit: commit.to_owned(),
        prompt: "resolve evidence-task".into(),
        // Never executed: no cell completes, so the verify / ground-truth oracle is not entered.
        verify_command: "true".into(),
        ground_truth_command: "true".into(),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "d14-03-evidence-oracle".into(),
            task_id: "evidence-task".into(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    }];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "d14-03-evidence-v1".into(),
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

/// Run the compiled binary against a `file://` corpus + stand-in Core, then decode the persisted
/// artifact. One task x two configs (verify_OFF / verify_ON) x one seed = two cells.
fn run_eval(root: &TempRoot, fake_core: &Path) -> (std::process::Output, EvaluationManifest) {
    let (repo_url, commit) = create_repository(root);
    assert!(
        repo_url.starts_with("file://"),
        "the fixture must be network-free"
    );
    let corpus_path = write_corpus(root, &repo_url, &commit);
    let artifact = root.join("out/evaluation.json");
    let output = Command::new(CORE_EVAL_BIN)
        .arg("--corpus")
        .arg(&corpus_path)
        .arg("--model")
        .arg("fixture/fixed-model")
        .arg("--core-bin")
        .arg(fake_core)
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
        .expect("run core-eval binary");
    let bytes = std::fs::read(&artifact).expect("the evaluation artifact must be persisted to disk");
    let manifest: EvaluationManifest =
        serde_json::from_slice(&bytes).expect("artifact must round-trip through its schema");
    (output, manifest)
}

#[test]
fn versioned_stdout_result_overrides_a_contradictory_human_stderr_chrome() {
    let root = TempRoot::new("stdout-authoritative");
    // stderr = adversarial HUMAN chrome telling the OPPOSITE story from the stdout contract: a
    // clean "done" run, 999 turns, $0 cost, a different model — and even a whole valid-looking
    // `result` object, but on the WRONG stream. If eval scraped any of this, the recorded cell
    // would flip to a completed / priced / high-turn run.
    //
    // stdout = the ONE versioned evidence contract: a truthful CENSORED terminal outcome.
    let fake_core = write_fake_core(
        &root,
        concat!(
            "#!/bin/sh\n",
            "{\n",
            "  echo 'core · repo=/decoy · model=EVIL-DIFFERENT-MODEL · run=run-fake'\n",
            "  echo 'outcome: Done'\n",
            "  echo 'success=true resolved turns=999 cost=$0.000000'\n",
            "  echo 'ledger: turns=999 tool_wall=0ms cost=$0.00'\n",
            "  printf '%s\\n' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"done\",\"reason\":null,\"success\":true,\"assistant_text\":\"faked\",\"run_id\":\"run-fake\",\"cost_usd\":0.0,\"cost_status\":\"zero\",\"cost_reason\":null,\"turns\":999,\"exit_code\":0,\"error\":null}'\n",
            "} 1>&2\n",
            "printf '%s' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"budget_exhausted\",\"reason\":\"max_turns\",\"success\":false,\"assistant_text\":\"\",\"run_id\":\"run-real\",\"cost_usd\":null,\"cost_status\":\"unknown\",\"cost_reason\":\"no_verified_rate_card\",\"turns\":4,\"exit_code\":3,\"error\":null}'\n",
            "exit 3\n",
        ),
    );

    let (output, manifest) = run_eval(&root, &fake_core);

    assert_eq!(manifest.cells.len(), 2, "1 task x 2 configs x 1 seed");
    for cell in &manifest.cells {
        // The stdout contract governs the run status, terminal outcome, exit code, turns and cost —
        // NONE of the stderr fictions (done / 999 / $0 / a different model) may appear.
        assert_eq!(
            cell.run_status,
            RunStatus::Censored,
            "the versioned stdout `budget_exhausted` outcome must classify the cell as censored, \
             not the stderr `outcome: Done` chrome"
        );
        assert_eq!(
            cell.terminal_outcome.as_deref(),
            Some("budget_exhausted"),
            "the recorded terminal outcome must be the stdout contract, not stderr's `done`"
        );
        assert_eq!(
            cell.exit_code,
            Some(3),
            "the OS exit code (3), reconciled with the stdout contract, is authoritative"
        );
        assert_eq!(
            cell.turns,
            Some(4),
            "the turn count must be the contract's 4, never the stderr chrome's 999"
        );
        assert_eq!(
            cell.cost_status,
            CostStatus::Unknown,
            "an unknown cost from the contract must not be overwritten by stderr's `cost=$0`"
        );
        assert_eq!(
            cell.cost_usd, None,
            "an unknown cost is never scavenged into a numeric $0 from the stderr chrome"
        );
        // A censored run is a real terminal model outcome, not a resolved patch.
        assert_eq!(
            cell.resolved, None,
            "a censored run resolves nothing; stderr's `resolved` token must not leak in"
        );
        assert_eq!(cell.failure_phase.as_deref(), Some("core"));
    }

    // A censored terminal outcome is NOT a harness failure, so the run finalizes as a clean success
    // even though the loud stderr chrome would (if believed) have implied otherwise.
    assert_eq!(
        manifest.failed_runs(),
        0,
        "censored terminal outcomes from the contract are not harness failures"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a fully-censored run exits clean; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_valid_result_on_stderr_is_not_scraped_and_leaves_a_hard_contract_error() {
    let root = TempRoot::new("no-stderr-fallback");
    // The versioned `result` object exists — but on stderr, alongside human chrome. stdout carries
    // ONLY human prose. Scraping stderr would score a clean completed run; the honest reading is
    // that the machine contract is absent from stdout, i.e. a hard JSON-contract error.
    let fake_core = write_fake_core(
        &root,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"done\",\"reason\":null,\"success\":true,\"assistant_text\":\"stderr-only\",\"run_id\":\"run-stderr\",\"cost_usd\":null,\"cost_status\":\"unknown\",\"cost_reason\":\"no_verified_rate_card\",\"turns\":2,\"exit_code\":0,\"error\":null}' 1>&2\n",
            "echo 'core · repo=/decoy · model=whatever · run=run-x' \n",
            "echo 'outcome: Done'\n",
            "exit 0\n",
        ),
    );

    let (output, manifest) = run_eval(&root, &fake_core);

    assert_eq!(manifest.cells.len(), 2, "1 task x 2 configs x 1 seed");
    for cell in &manifest.cells {
        assert_eq!(
            cell.run_status,
            RunStatus::Errored,
            "a valid `result` on stderr must NOT be scraped; the absent stdout contract is a \
             typed harness error, not a completed run"
        );
        assert_eq!(
            cell.failure_phase.as_deref(),
            Some("core_contract"),
            "the failure must be attributed to the missing stdout JSON contract"
        );
        assert_eq!(
            cell.terminal_outcome, None,
            "no terminal outcome may be scavenged from the stderr `result` object"
        );
        assert_eq!(
            cell.turns, None,
            "no turn count may be scavenged from the stderr chrome"
        );
        assert_eq!(
            cell.resolved, None,
            "a contract error resolves nothing"
        );
    }

    // Errored cells ARE harness failures, so the run finalizes non-zero — the exact opposite of the
    // clean success a stderr-scraping harness would have reported.
    assert_eq!(
        manifest.failed_runs(),
        2,
        "both cells are harness failures because the stdout contract was absent"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "recorded run failures finalize into a non-zero exit; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

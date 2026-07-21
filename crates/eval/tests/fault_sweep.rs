#![cfg(target_os = "macos")]

use core_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use core_eval::{
    CellResult, CostStatus, EvalOptions, EvaluationManifest, EvaluationPurpose, OracleStatus,
    Partition, RunStatus, run_evaluation,
};
use core_eval::{CorpusManifest, CorpusTask};
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
            "core-eval-integration-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated integration-test root");
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

fn create_real_repository(root: &TempRoot) -> (String, String) {
    let repo = root.join("source-repo");
    std::fs::create_dir(&repo).expect("create source repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("status.txt"), "bad\n").expect("write committed fixture state");
    git(&repo, &["add", "status.txt"]);
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
            "pinned evaluation fixture",
        ],
    );
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    let canonical = repo.canonicalize().expect("canonical source repository");
    let url = url::Url::from_file_path(canonical)
        .expect("source repository must convert to file URL")
        .to_string();
    (url, commit)
}

fn create_fake_core(root: &TempRoot) -> PathBuf {
    let path = root.join("fake-core");
    let script = r##"#!/bin/sh
set -eu

workspace=
prompt=
verify_enabled=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -C)
            shift
            workspace=$1
            ;;
        --output-format|--model|--max-turns|--provider)
            shift
            ;;
        --verify)
            verify_enabled=1
            shift
            ;;
        -p|--allow-code)
            ;;
        *)
            prompt=$1
            ;;
    esac
    shift
done

if [ -z "$workspace" ] || [ -z "$prompt" ]; then
    printf '%s\n' 'fake core did not receive workspace and prompt' >&2
    exit 64
fi

done_result() {
    printf '%s\n' '{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"fixture done","run_id":"run-fixture","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture_has_no_rate_card","turns":1,"exit_code":0,"error":null}'
}

case "$prompt" in
    pass-before|pass-after)
        printf 'good\n' > "$workspace/status.txt"
        done_result
        ;;
    malformed)
        printf '%s' '{"schema_version":4'
        ;;
    crashed)
        printf '%s\n' 'injected fake-core crash' >&2
        exit 70
        ;;
    budget)
        printf '%s\n' '{"schema_version":4,"type":"result","outcome":"budget_exhausted","reason":"max_turns","success":false,"assistant_text":"","run_id":"run-fixture","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture_has_no_rate_card","turns":4,"exit_code":3,"error":null}'
        exit 3
        ;;
    harness-error)
        printf '%s\n' '{"schema_version":4,"type":"result","outcome":"harness_error","reason":"injected_fixture","success":false,"assistant_text":"","run_id":"run-fixture","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture_has_no_rate_card","turns":1,"exit_code":2,"error":"injected harness error"}'
        exit 2
        ;;
    interrupted)
        printf '%s\n' '{"schema_version":4,"type":"result","outcome":"interrupted","reason":"sigint","success":false,"assistant_text":"","run_id":"run-fixture","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture_has_no_rate_card","turns":1,"exit_code":130,"error":null}'
        exit 130
        ;;
    stuck)
        printf '%s\n' '{"schema_version":4,"type":"result","outcome":"stuck","reason":"repeated_tool_failure","success":false,"assistant_text":"","run_id":"run-fixture","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture_has_no_rate_card","turns":3,"exit_code":4,"error":null}'
        exit 4
        ;;
    stalled)
        printf '%s\n' 'injected fake-core stall' >&2
        sleep 10
        ;;
    wrong-fix)
        printf 'wrong\n' > "$workspace/status.txt"
        done_result
        ;;
    selection-gap)
        if [ "$verify_enabled" -eq 1 ]; then
            printf 'good\n' > "$workspace/status.txt"
        else
            printf 'wrong\n' > "$workspace/status.txt"
        fi
        done_result
        ;;
    *)
        printf 'unknown fixture prompt: %s\n' "$prompt" >&2
        exit 64
        ;;
esac
"##;
    std::fs::write(&path, script).expect("write executable fake core");
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
        // The fake CLI intentionally dispatches on this external task input. No behavior is
        // selected through a production-only hook in core-eval.
        prompt: id.to_owned(),
        verify_command: "test \"$(cat status.txt)\" = good".into(),
        ground_truth_command: "test \"$(cat status.txt)\" = good".into(),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "local-fault-sweep-v1".into(),
            task_id: id.to_owned(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    }
}

fn write_external_corpus(root: &TempRoot, repo_url: &str, commit: &str) -> PathBuf {
    // Ordering is load-bearing: every injected failure occurs before `pass-after`, proving the
    // public runner continues the sweep instead of returning on a malformed/crashed/stalled cell.
    let mut tasks = [
        "pass-before",
        "malformed",
        "crashed",
        "budget",
        "harness-error",
        "interrupted",
        "stuck",
        "stalled",
        "wrong-fix",
        "selection-gap",
        "bad-checkout",
        "pass-after",
    ]
    .into_iter()
    .map(|id| task(id, repo_url, commit))
    .collect::<Vec<_>>();
    tasks
        .iter_mut()
        .find(|task| task.id == "selection-gap")
        .expect("selection-gap task")
        .verify_command = "false".into();
    tasks
        .iter_mut()
        .find(|task| task.id == "bad-checkout")
        .expect("bad-checkout task")
        .commit = "f".repeat(40);
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "local-fault-sweep-v1".into(),
        dataset_digest: digest_tasks(&tasks).expect("digest external corpus tasks"),
        tasks,
    };
    manifest.validate().expect("external corpus must be valid");
    let path = root.join("external-corpus.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).expect("encode external corpus"),
    )
    .expect("write external corpus");
    path
}

fn cells_for<'a>(manifest: &'a EvaluationManifest, task: &str) -> Vec<&'a CellResult> {
    let cells = manifest
        .cells
        .iter()
        .filter(|cell| cell.task == task)
        .collect::<Vec<_>>();
    assert_eq!(
        cells.len(),
        2,
        "each task must execute both verify_OFF and verify_ON"
    );
    cells
}

#[tokio::test]
async fn public_runner_continues_fault_sweep_and_persists_typed_artifact() {
    let root = TempRoot::new("fault-sweep");
    let (repo_url, commit) = create_real_repository(&root);
    assert!(
        repo_url.starts_with("file://"),
        "the fixture must not use network"
    );
    let fake_core = create_fake_core(&root);
    let corpus_path = write_external_corpus(&root, &repo_url, &commit);
    let artifact_path = root.join("artifacts/evaluation.json");
    let options = EvalOptions {
        corpus_path,
        output_path: artifact_path.clone(),
        work_root: root.join("work"),
        core_bin: Some(fake_core),
        allow_local_repositories: true,
        model: "fixture/fixed-model".into(),
        provider: None,
        purpose: EvaluationPurpose::Score,
        seeds: 1,
        minimum_seeds: 1,
        run_timeout: Duration::from_secs(1),
        checkout_timeout: Duration::from_secs(5),
        oracle_timeout: Duration::from_secs(2),
        max_turns: 4,
    };

    let manifest = tokio::time::timeout(Duration::from_secs(20), run_evaluation(&options))
        .await
        .expect("the complete fault sweep must remain bounded")
        .expect("cell failures belong in the artifact, not the top-level result");

    assert_eq!(manifest.cells.len(), 24, "no fault may truncate the matrix");
    assert!(manifest.cells.iter().all(|cell| cell.repo_url == repo_url));
    assert!(
        manifest
            .cells
            .iter()
            .filter(|cell| cell.task != "bad-checkout")
            .all(|cell| cell.commit == commit)
    );

    for cell in cells_for(&manifest, "malformed") {
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("core_contract"));
        assert_eq!(cell.exit_code, Some(0));
        assert_eq!(cell.resolved, None);
        assert!(
            cell.error
                .as_deref()
                .is_some_and(|error| { error.contains("one valid final-result JSON object") })
        );
    }
    let crashed = cells_for(&manifest, "crashed");
    for cell in &crashed {
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("core_contract"));
        assert_eq!(cell.exit_code, Some(70));
        assert_eq!(cell.resolved, None);
        assert_eq!(cell.candidate_diff, None);
    }

    for cell in cells_for(&manifest, "budget") {
        assert_eq!(cell.run_status, RunStatus::Censored);
        assert_eq!(cell.failure_phase.as_deref(), Some("core"));
        assert_eq!(cell.terminal_outcome.as_deref(), Some("budget_exhausted"));
        assert_eq!(cell.exit_code, Some(3));
        assert_eq!(cell.resolved, None);
        assert_eq!(cell.cost_status, CostStatus::Unknown);
        assert_eq!(cell.oracle_status, OracleStatus::NotRun);
    }

    for cell in cells_for(&manifest, "harness-error") {
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("core"));
        assert_eq!(cell.terminal_outcome.as_deref(), Some("harness_error"));
        assert_eq!(cell.exit_code, Some(2));
        assert_eq!(cell.resolved, None);
    }

    for (task, outcome, exit_code) in [("interrupted", "interrupted", 130), ("stuck", "stuck", 4)] {
        for cell in cells_for(&manifest, task) {
            assert_eq!(cell.run_status, RunStatus::Censored);
            assert_eq!(cell.failure_phase.as_deref(), Some("core"));
            assert_eq!(cell.terminal_outcome.as_deref(), Some(outcome));
            assert_eq!(cell.exit_code, Some(exit_code));
            assert_eq!(cell.resolved, None);
            assert_eq!(cell.oracle_status, OracleStatus::NotRun);
        }
    }

    let stalled = cells_for(&manifest, "stalled");
    for cell in stalled {
        assert_eq!(cell.run_status, RunStatus::TimedOut);
        assert_eq!(cell.failure_phase.as_deref(), Some("core_timeout"));
        assert_eq!(cell.resolved, None);
        assert!(
            cell.error
                .as_deref()
                .is_some_and(|error| { error.contains("wall-clock timeout") })
        );
    }

    let wrong = cells_for(&manifest, "wrong-fix");
    for cell in &wrong {
        assert_eq!(cell.run_status, RunStatus::Completed);
        assert_eq!(cell.resolved, Some(false));
        assert_eq!(cell.exit_code, Some(0));
        assert!(
            cell.candidate_diff
                .as_deref()
                .is_some_and(|diff| diff.contains("+wrong")),
            "a wrong candidate must retain its diff evidence"
        );
    }
    assert_eq!(
        wrong
            .iter()
            .find(|cell| cell.config == "verify_ON")
            .expect("verify_ON wrong-fix cell")
            .oracle_status,
        OracleStatus::TestFailed
    );
    assert_ne!(
        wrong[0].run_status, crashed[0].run_status,
        "wrong fixes are completed-but-unresolved; crashed runs are harness errors"
    );
    assert_ne!(wrong[0].resolved, crashed[0].resolved);

    let selection_gap_cells = cells_for(&manifest, "selection-gap");
    let selection_gap_off = selection_gap_cells
        .iter()
        .find(|cell| cell.config == "verify_OFF")
        .expect("verify_OFF selection-gap cell");
    assert_eq!(selection_gap_off.resolved, Some(false));
    assert_eq!(selection_gap_off.oracle_status, OracleStatus::NotRun);
    let selection_gap_on = selection_gap_cells
        .iter()
        .find(|cell| cell.config == "verify_ON")
        .expect("verify_ON selection-gap cell");
    assert_eq!(selection_gap_on.resolved, Some(true));
    assert_eq!(selection_gap_on.oracle_status, OracleStatus::TestFailed);
    let selection = manifest
        .selections
        .iter()
        .find(|selection| selection.task == "selection-gap")
        .expect("public runner must persist a selection summary");
    assert_eq!(selection.candidates, 2);
    assert_eq!(selection.chosen, Some(0));
    assert!(selection.ceiling);
    assert!(!selection.resolved);
    assert!(selection.resolve_vs_ceiling_gap);

    for cell in cells_for(&manifest, "bad-checkout") {
        assert_eq!(cell.commit, "f".repeat(40));
        assert_eq!(cell.run_status, RunStatus::Errored);
        assert_eq!(cell.failure_phase.as_deref(), Some("checkout"));
        assert_eq!(cell.exit_code, None);
        assert_eq!(cell.resolved, None);
        assert!(
            cell.error
                .as_deref()
                .is_some_and(|error| error.contains("pinned commit failed"))
        );
    }

    let pass_after = cells_for(&manifest, "pass-after");
    for cell in pass_after {
        assert_eq!(cell.run_status, RunStatus::Completed);
        assert_eq!(cell.resolved, Some(true));
    }
    let pass_after_index = manifest
        .cells
        .iter()
        .position(|cell| cell.task == "pass-after")
        .expect("post-fault cell must execute");
    for fault in [
        "malformed",
        "crashed",
        "budget",
        "harness-error",
        "interrupted",
        "stuck",
        "stalled",
        "bad-checkout",
    ] {
        let fault_index = manifest
            .cells
            .iter()
            .position(|cell| cell.task == fault)
            .expect("fault cell must exist");
        assert!(
            fault_index < pass_after_index,
            "{fault} must occur before the successful post-fault cell"
        );
    }

    assert_eq!(manifest.result_path, artifact_path);
    let artifact_bytes = std::fs::read(&artifact_path).expect("artifact must be on disk");
    assert!(artifact_bytes.ends_with(b"\n"));
    let mut canonical_bytes =
        serde_json::to_vec_pretty(&manifest).expect("encode returned manifest canonically");
    canonical_bytes.push(b'\n');
    assert_eq!(
        artifact_bytes, canonical_bytes,
        "the atomic artifact must contain the exact returned manifest"
    );
    let round_tripped: EvaluationManifest = serde_json::from_slice(&artifact_bytes)
        .expect("artifact must round-trip through its schema");
    assert_eq!(round_tripped.schema_version, manifest.schema_version);
    assert_eq!(round_tripped.run_id, manifest.run_id);
    assert_eq!(round_tripped.dataset_digest, manifest.dataset_digest);
    assert_eq!(round_tripped.result_path, manifest.result_path);
    assert_eq!(round_tripped.cells, manifest.cells);
    assert_eq!(round_tripped.selections, manifest.selections);
    assert_eq!(
        round_tripped.aggregate.total_cells,
        manifest.aggregate.total_cells
    );
    assert!(
        (round_tripped.comparison.resolved_rate_delta - manifest.comparison.resolved_rate_delta)
            .abs()
            <= f64::EPSILON,
        "JSON float decoding may differ by at most one machine epsilon"
    );
}

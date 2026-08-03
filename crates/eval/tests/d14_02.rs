//! D14-02 oracle: failed-run accounting — a subprocess/harness failure and a wall-clock timeout
//! must be folded into a non-zero process exit code, while a genuine *terminal model outcome*
//! (a censored budget-exhausted / interrupted run) is NOT discarded into the harness-failure
//! bucket and does not, on its own, mark the evaluation as broken.
//!
//! The gap under closure is "no failed-run accounting — subprocess status and terminal Outcome
//! discarded": the harness always persisted the artifact but reported a clean success regardless of
//! how many cells failed to run, so CI could never tell a completed-with-failures run from a clean
//! one. The accounting lives in [`EvaluationManifest::failed_runs`] /
//! [`EvaluationManifest::exit_code`], which `crates/eval/src/main.rs` finalizes into the process
//! exit status.
//!
//! This test pins the *classification boundary* directly at the library level (the sibling D14-05
//! oracle only exercises an all-errored corpus through the compiled binary, and never proves that a
//! censored terminal outcome is excluded):
//!
//!   1. `Errored` (subprocess spawn / JSON-contract / infrastructure failure) and `TimedOut`
//!      (wall-clock timeout) are the ONLY statuses counted as failed runs, and any such failure
//!      drives the whole evaluation to a non-zero exit ([`EVAL_EXIT_RUN_FAILURES`]).
//!   2. `Censored` (a budget-exhausted / interrupted terminal model outcome) and `Completed` are
//!      NOT failures — a run consisting only of those must finalize as a clean success
//!      ([`EVAL_EXIT_SUCCESS`]); the terminal outcome is accounted, not dropped.
//!   3. The accounting survives the artifact schema round-trip: an operator/CI reading the persisted
//!      manifest recomputes the same failed-run count and exit code the binary used.
//!
//! The test is pure (no filesystem, network, or subprocess), so it is deterministic on the gate.

use core_eval::types::{EVAL_EXIT_RUN_FAILURES, EVAL_EXIT_SUCCESS, EVAL_SCHEMA_VERSION};
use core_eval::{
    CellResult, CostStatus, EvaluationManifest, EvaluationPurpose, OracleStatus, Partition,
    RunStatus, SamplingControl,
};
use std::path::PathBuf;

fn cell(config: &str, status: RunStatus, terminal: Option<&str>, exit: Option<i32>) -> CellResult {
    CellResult {
        task: "task-1".into(),
        config: config.into(),
        seed: 0,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: None,
        run_status: status,
        failure_phase: None,
        exit_code: exit,
        terminal_outcome: terminal.map(str::to_owned),
        cost_status: CostStatus::Unknown,
        cost_usd: None,
        cost_reason: None,
        turns: None,
        kernel_tax: None,
        oracle_status: OracleStatus::NotRun,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: 0,
            enforcement: "uncontrolled".into(),
            reason: None,
        },
        elapsed_ms: 1,
        error: None,
        candidate_diff: None,
    }
}

/// Assemble a schema-valid manifest around `cells`. `failed_runs`/`exit_code` read only
/// `self.cells`, so the aggregate/comparison/selection blocks are built with the production
/// reducers purely to keep the artifact well-formed.
fn manifest(cells: Vec<CellResult>) -> EvaluationManifest {
    let aggregate = core_eval::aggregate(&cells, 3);
    let comparison = core_eval::compare(&aggregate, "verify_OFF", "verify_ON");
    let selections = core_eval::selection_summaries(&cells);
    EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id: "run-d14-02".into(),
        corpus_version: "v1".into(),
        dataset_digest: "sha256:test".into(),
        model: "fixed-model".into(),
        provider: None,
        bundle_digest: None,
        purpose: EvaluationPurpose::Score,
        seeds: 3,
        minimum_seeds: 3,
        workers: 1,
        max_turns: Some(20),
        core_agent_wall_secs: 1_800,
        core_process_grace_secs: 30,
        core_process_timeout_secs: 1_830,
        result_path: PathBuf::from("core-eval-result.json"),
        cells,
        aggregate,
        comparison,
        selections,
        kernel_tax: core_eval::types::KernelTaxObservation::default(),
    }
}

#[test]
fn d14_02_subprocess_failures_and_timeouts_drive_a_non_zero_exit() {
    let m = manifest(vec![
        cell("verify_OFF", RunStatus::Errored, None, Some(2)),
        cell("verify_ON", RunStatus::TimedOut, None, None),
        // A censored budget-exhausted terminal outcome is a legitimate model result, not a harness
        // failure — it must NOT be discarded into the failed-run bucket.
        cell(
            "verify_OFF",
            RunStatus::Censored,
            Some("budget_exhausted"),
            Some(3),
        ),
        cell("verify_ON", RunStatus::Completed, Some("done"), Some(0)),
    ]);

    assert_eq!(
        m.failed_runs(),
        2,
        "only the errored subprocess and the wall-clock timeout are failed runs; \
         the censored terminal outcome and the completed cell are not"
    );
    assert_eq!(
        m.exit_code(),
        EVAL_EXIT_RUN_FAILURES,
        "any failed run must finalize as a non-zero exit, not a clean success"
    );
    assert_ne!(m.exit_code(), EVAL_EXIT_SUCCESS);
}

#[test]
fn d14_02_a_completed_or_only_censored_run_is_a_clean_success() {
    let m = manifest(vec![
        cell("verify_OFF", RunStatus::Completed, Some("done"), Some(0)),
        cell(
            "verify_ON",
            RunStatus::Censored,
            Some("budget_exhausted"),
            Some(3),
        ),
    ]);

    assert_eq!(
        m.failed_runs(),
        0,
        "a censored budget-exhausted run is a terminal model outcome, not a harness failure"
    );
    assert_eq!(
        m.exit_code(),
        EVAL_EXIT_SUCCESS,
        "with no failed runs the evaluation must report a clean success"
    );
}

#[test]
fn d14_02_the_failure_accounting_survives_the_artifact_schema_round_trip() {
    let m = manifest(vec![
        cell("verify_OFF", RunStatus::Errored, None, Some(2)),
        cell("verify_ON", RunStatus::Completed, Some("done"), Some(0)),
    ]);
    assert_eq!(m.failed_runs(), 1);
    assert_eq!(m.exit_code(), EVAL_EXIT_RUN_FAILURES);

    let bytes = serde_json::to_vec(&m).expect("manifest encodes to its schema");
    let restored: EvaluationManifest =
        serde_json::from_slice(&bytes).expect("manifest round-trips through its schema");

    assert_eq!(
        restored.failed_runs(),
        1,
        "the persisted artifact preserves the failed-run count an operator recomputes"
    );
    assert_eq!(restored.exit_code(), EVAL_EXIT_RUN_FAILURES);
}

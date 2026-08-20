use iteron_eval::types::EVAL_SCHEMA_VERSION;
use iteron_eval::{
    AgentMetrics, CellResult, CostStatus, EvaluationManifest, EvaluationPurpose,
    KernelTaxObservation, MeasurementError, OracleStatus, Partition, PerformanceDecision,
    PerformanceThresholds, RunStatus, SamplingControl, aggregate, compare,
    compare_performance_manifests, selection_summaries,
};
use iteron_protocol::Usage;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn cell(task: &str, resolved: bool, elapsed_ms: u64, usage: Option<Usage>) -> CellResult {
    CellResult {
        task: task.into(),
        config: "harness".into(),
        seed: 0,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "a".repeat(40),
        benchmark: None,
        resolved: Some(resolved),
        run_status: RunStatus::Completed,
        failure_phase: None,
        exit_code: Some(0),
        terminal_outcome: Some("done".into()),
        cost_status: CostStatus::Unknown,
        cost_usd: None,
        cost_reason: Some("unpriced_fixture".into()),
        turns: Some(1),
        kernel_tax: None,
        oracle_status: if resolved {
            OracleStatus::Passed
        } else {
            OracleStatus::TestFailed
        },
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: 0,
            enforcement: "fixed_fixture".into(),
            reason: None,
        },
        agent_metrics: Some(AgentMetrics { elapsed_ms, usage }),
        elapsed_ms: elapsed_ms.saturating_add(10_000),
        error: None,
        candidate_diff: Some(format!("diff-{task}")),
    }
}

fn manifest(run_id: &str, cells: Vec<CellResult>) -> EvaluationManifest {
    let aggregate = aggregate(&cells, 1);
    EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id: run_id.into(),
        corpus_version: "held-out-v1".into(),
        dataset_digest: format!("sha256:{}", "b".repeat(64)),
        model: "fixed-model".into(),
        provider: Some("fixed-route".into()),
        bundle_digest: None,
        purpose: EvaluationPurpose::Score,
        seeds: 1,
        minimum_seeds: 1,
        workers: 1,
        max_turns: Some(64),
        core_agent_wall_secs: 60,
        core_process_grace_secs: 3,
        core_process_timeout_secs: 63,
        result_path: PathBuf::from(format!("{run_id}.json")),
        comparison: compare(&aggregate, "missing-a", "missing-b"),
        selections: selection_summaries(&cells),
        cells,
        aggregate,
        kernel_tax: KernelTaxObservation::default(),
    }
}

fn usage(input: u64, cache_read: u64, output: u64, thinking: u64) -> Usage {
    Usage {
        input,
        output,
        cache_creation: 0,
        cache_read,
        thinking,
    }
}

fn thresholds() -> PerformanceThresholds {
    PerformanceThresholds {
        minimum_pairs: 4,
        resolution_noninferiority_margin: 0.0,
        minimum_latency_reduction_ratio: 0.2,
        minimum_token_reduction_ratio: 0.2,
    }
}

#[test]
fn matched_complete_evidence_can_prove_harness_outperformance() {
    let baseline = manifest(
        "baseline",
        (0..4)
            .map(|index| {
                cell(
                    &format!("task-{index}"),
                    true,
                    100,
                    Some(usage(800, 100, 100, 20)),
                )
            })
            .collect(),
    );
    let treatment = manifest(
        "treatment",
        (0..4)
            .map(|index| {
                cell(
                    &format!("task-{index}"),
                    true,
                    50,
                    Some(usage(400, 50, 50, 10)),
                )
            })
            .collect(),
    );
    let report =
        compare_performance_manifests(&baseline, "harness", &treatment, "harness", thresholds())
            .unwrap();
    assert_eq!(report.decision, PerformanceDecision::Outperforms);
    assert!(report.outperforms);
    assert_eq!(report.latency_ms.unwrap().reduction_ratio, 0.5);
    assert_eq!(report.total_tokens.unwrap().reduction_ratio, 0.5);
}

#[test]
fn failed_fast_or_missing_usage_can_never_claim_outperformance() {
    let baseline = manifest(
        "baseline",
        (0..4)
            .map(|index| {
                cell(
                    &format!("task-{index}"),
                    true,
                    100,
                    Some(usage(80, 10, 10, 2)),
                )
            })
            .collect(),
    );
    let failed_fast = manifest(
        "failed-fast",
        (0..4)
            .map(|index| cell(&format!("task-{index}"), false, 1, Some(usage(1, 0, 0, 0))))
            .collect(),
    );
    let report =
        compare_performance_manifests(&baseline, "harness", &failed_fast, "harness", thresholds())
            .unwrap();
    assert_eq!(report.decision, PerformanceDecision::CompletionRegressed);
    assert!(!report.outperforms);

    let missing_usage = manifest(
        "missing-usage",
        (0..4)
            .map(|index| cell(&format!("task-{index}"), true, 1, None))
            .collect(),
    );
    let report = compare_performance_manifests(
        &baseline,
        "harness",
        &missing_usage,
        "harness",
        thresholds(),
    )
    .unwrap();
    assert_eq!(report.decision, PerformanceDecision::MissingMetrics);
    assert!(!report.outperforms);
}

#[test]
fn comparison_rejects_unpaired_cells_and_invalid_token_attribution() {
    let baseline = manifest(
        "baseline",
        vec![cell("task-a", true, 100, Some(usage(10, 0, 5, 6)))],
    );
    assert_eq!(
        baseline.cells[0]
            .agent_metrics
            .expect("fixture metrics")
            .total_tokens(),
        None,
        "thinking is an output subset and cannot exceed output"
    );
    let treatment = manifest(
        "treatment",
        vec![cell("task-b", true, 50, Some(usage(5, 0, 2, 1)))],
    );
    assert!(matches!(
        compare_performance_manifests(
            &baseline,
            "harness",
            &treatment,
            "harness",
            PerformanceThresholds {
                minimum_pairs: 1,
                ..thresholds()
            },
        ),
        Err(MeasurementError::PairingMismatch)
    ));
}

#[test]
fn generic_cli_compares_two_standard_manifests_without_harness_specific_branches() {
    let baseline = manifest(
        "baseline-cli",
        (0..4)
            .map(|index| {
                cell(
                    &format!("task-{index}"),
                    true,
                    100,
                    Some(usage(800, 100, 100, 20)),
                )
            })
            .collect(),
    );
    let treatment = manifest(
        "treatment-cli",
        (0..4)
            .map(|index| {
                cell(
                    &format!("task-{index}"),
                    true,
                    50,
                    Some(usage(400, 50, 50, 10)),
                )
            })
            .collect(),
    );
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "iteron-performance-cli-{}-{nonce:x}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let baseline_path = root.join("baseline.json");
    let treatment_path = root.join("treatment.json");
    std::fs::write(&baseline_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    std::fs::write(&treatment_path, serde_json::to_vec(&treatment).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iteron-harness"))
        .args([
            "compare-performance",
            baseline_path.to_str().unwrap(),
            "harness",
            treatment_path.to_str().unwrap(),
            "harness",
            "4",
            "0",
            "0.2",
            "0.2",
        ])
        .env_clear()
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["report_type"], "matched_harness_performance");
    assert_eq!(report["decision"], "outperforms");
    assert_eq!(report["outperforms"], true);
}

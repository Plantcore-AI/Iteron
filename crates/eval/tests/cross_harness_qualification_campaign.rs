#![cfg(unix)]

use iteron_eval::process::{ProcessOutput, ProcessSpec, run_process};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

async fn run_campaign(args: &[&str], timeout: Duration) -> ProcessOutput {
    let output = run_process(&ProcessSpec {
        program: PathBuf::from(env!("CARGO_BIN_EXE_iteron-harness")),
        args: args.iter().map(|arg| (*arg).into()).collect(),
        cwd: None,
        clear_env: true,
        inherit_env: Vec::new(),
        env: Vec::new(),
        timeout,
        max_output_bytes: iteron_eval::MAX_PROTOCOL_REQUEST_BYTES,
    })
    .await
    .expect("run credential-free campaign with its owned process watchdog");
    assert!(
        !output.timed_out,
        "campaign exceeded its real outer process deadline"
    );
    assert!(!output.stdout_truncated && !output.stderr_truncated);
    output
}

#[tokio::test]
async fn campaign_observes_local_runtime_coverage_and_refuses_missing_tb21() {
    // The outer bound covers 56 existing five-second runtime/one-second cleanup cells plus a
    // five-second initial-attestation allowance. No implementation's admitted budget changes.
    let output = run_campaign(
        &["campaign", "--qualification-id", "fixture-campaign"],
        Duration::from_secs(56 * (5 + 1) + 5),
    )
    .await;
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.is_empty());
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("strict JSON receipt");
    assert_eq!(
        receipt["schema_id"],
        "iteron-cross-harness-campaign-receipt/1"
    );
    assert_eq!(receipt["qualification_id"], "fixture-campaign");
    assert_eq!(receipt["status"], "refused");
    assert_eq!(receipt["score_superiority_claimed"], false);
    assert_eq!(
        receipt["implemented_executable_coverage"]["module_matrix"]["cases"],
        56
    );
    assert_eq!(
        receipt["implemented_executable_coverage"]["module_matrix"]["correlated_terminal_observations"],
        56
    );
    assert_eq!(
        receipt["implemented_executable_coverage"]["optimizer_negotiation"]["families"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_eq!(
        receipt["implemented_executable_coverage"]["stateful_hotswap"]["fault_phases"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    assert_eq!(receipt["manifest_path"], Value::Null);
    let prerequisites = receipt["missing_prerequisites"]
        .as_array()
        .expect("prerequisites are a list");
    assert!(
        prerequisites
            .iter()
            .any(|row| { row["code"] == "terminal_bench_campaign_not_run" })
    );
}

#[tokio::test]
async fn campaign_refuses_unknown_or_malformed_arguments_without_running_coverage() {
    let malformed = [
        vec!["campaign", "--unknown"],
        vec!["campaign", "--qualification-id"],
        vec!["campaign", "--qualification-id", "invalid id"],
        vec!["campaign", "--qualification-id", "valid", "extra"],
    ];
    for args in malformed {
        let output = run_campaign(&args, Duration::from_secs(5)).await;
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.is_empty());
        let receipt: Value = serde_json::from_slice(&output.stdout).expect("strict JSON receipt");
        assert_eq!(receipt["status"], "refused");
        assert_eq!(
            receipt["missing_prerequisites"][0]["code"],
            "invalid_campaign_arguments"
        );
        assert_eq!(
            receipt["implemented_executable_coverage"]["module_matrix"]["cases"],
            0
        );
        assert_eq!(
            receipt["implemented_executable_coverage"]["optimizer_negotiation"]["families"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            receipt["implemented_executable_coverage"]["stateful_hotswap"]["committed_records"],
            0
        );
    }
}

#![cfg(unix)]

use serde_json::Value;
use std::process::Command;

#[test]
fn campaign_observes_local_runtime_coverage_and_refuses_missing_tb21() {
    let output = Command::new(env!("CARGO_BIN_EXE_iteron-harness"))
        .args(["campaign", "--qualification-id", "fixture-campaign"])
        .env_clear()
        .output()
        .expect("run campaign command");
    assert_eq!(output.status.code(), Some(2));
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

#[test]
fn campaign_refuses_unknown_or_malformed_arguments_without_running_coverage() {
    let malformed = [
        vec!["campaign", "--unknown"],
        vec!["campaign", "--qualification-id"],
        vec!["campaign", "--qualification-id", "invalid id"],
        vec!["campaign", "--qualification-id", "valid", "extra"],
    ];
    for args in malformed {
        let output = Command::new(env!("CARGO_BIN_EXE_iteron-harness"))
            .args(args)
            .env_clear()
            .output()
            .expect("run malformed campaign command");
        assert_eq!(output.status.code(), Some(2));
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

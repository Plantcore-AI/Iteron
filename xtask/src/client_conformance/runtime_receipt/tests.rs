use super::*;
use serde_json::{Value, json};

fn platform(
    name: &str,
    target: &str,
    runner: &str,
    job_id: u64,
    runner_id: u64,
    version_independence: &str,
) -> Value {
    json!({
        "platform": name,
        "target": target,
        "runner": runner,
        "job": {
            "id": job_id,
            "runner_id": runner_id,
            "runner_name": format!("GitHub Actions {runner_id}"),
            "runner_group_id": 0,
            "runner_group_name": "GitHub Actions",
            "labels": [runner],
            "conclusion": "success"
        },
        "steps": {
            "target_tests": "success",
            "binary_build": "success",
            "binary_identity": "success",
            "native_client_smoke": "success",
            "version_independence": version_independence
        }
    })
}

fn valid_receipt_value() -> Value {
    let commit = "a".repeat(40);
    json!({
        "schema_version": 1,
        "type": "client_runtime_receipt",
        "repository": {
            "name": "Plantcore-AI/core",
            "id": 1
        },
        "tested_commit": commit,
        "tested_tree": "b".repeat(40),
        "builder_workflow": {
            "path": ".github/workflows/runtime-receipt.yml",
            "commit": "c".repeat(40)
        },
        "run": {
            "id": 42,
            "attempt": 3,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": "a".repeat(40),
            "workflow_path": ".github/workflows/release.yml",
            "url": "https://github.com/Plantcore-AI/core/actions/runs/42"
        },
        "platforms": [
            platform(
                "macos-arm64",
                "aarch64-apple-darwin",
                "macos-15",
                101,
                201,
                "skipped",
            ),
            platform(
                "macos-x86_64",
                "x86_64-apple-darwin",
                "macos-15-intel",
                102,
                202,
                "skipped",
            ),
            platform(
                "linux-arm64",
                "aarch64-unknown-linux-musl",
                "ubuntu-24.04-arm",
                103,
                203,
                "skipped",
            ),
            platform(
                "linux-x86_64",
                "x86_64-unknown-linux-musl",
                "ubuntu-24.04",
                104,
                204,
                "success",
            ),
            platform(
                "windows-x86_64",
                "x86_64-pc-windows-msvc",
                "windows-2022",
                105,
                205,
                "success",
            )
        ],
        "version_independence": [
            {
                "operating_system": "unix",
                "platform": "linux-x86_64",
                "job_id": 104,
                "clients": ["headless", "one-shot", "tui"],
                "conclusion": "success"
            },
            {
                "operating_system": "windows-msvc",
                "platform": "windows-x86_64",
                "job_id": 105,
                "clients": ["headless", "one-shot", "tui"],
                "conclusion": "success"
            }
        ]
    })
}

fn parse_valid_receipt() -> RuntimeReceipt {
    parse_receipt(&serde_json::to_vec(&valid_receipt_value()).unwrap()).unwrap()
}

fn valid_builder() -> BuilderRef {
    BuilderRef {
        path: BUILDER_WORKFLOW.into(),
        commit: "c".repeat(40),
    }
}

#[test]
fn canonical_paths_bind_run_id_and_attempt_without_aliases() {
    let digest = "a".repeat(64);
    let reference = ReceiptRef {
        path: format!("{RECEIPT_PREFIX}42-attempt-3.json"),
        sha256: digest.clone(),
        attestation_path: format!("{RECEIPT_PREFIX}42-attempt-3.sigstore.json"),
        attestation_sha256: digest,
    };
    assert_eq!(validate_reference_shape(&reference).unwrap(), (42, 3));

    let noncanonical = ReceiptRef {
        path: format!("{RECEIPT_PREFIX}042-attempt-3.json"),
        ..reference
    };
    assert!(validate_reference_shape(&noncanonical).is_err());
}

#[test]
fn runtime_builder_must_pin_the_exact_reusable_workflow() {
    validate_builder_reference(&valid_builder()).unwrap();

    let mut builder = valid_builder();
    builder.path = ".github/workflows/release.yml".into();
    assert!(validate_builder_reference(&builder).is_err());

    let mut builder = valid_builder();
    builder.commit = "C".repeat(40);
    assert!(validate_builder_reference(&builder).is_err());
}

#[test]
fn duplicate_and_unknown_receipt_fields_fail_closed() {
    let encoded = serde_json::to_string(&valid_receipt_value()).unwrap();
    let duplicate = format!("{{\"schema_version\":1,{}", &encoded[1..]);
    assert!(parse_receipt(duplicate.as_bytes()).is_err());

    let mut unknown = valid_receipt_value();
    unknown["unexpected"] = json!(true);
    assert!(parse_receipt(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn spoofed_runner_identity_and_partial_client_coverage_are_rejected() {
    let mut receipt = parse_valid_receipt();
    receipt.platforms[0].job.runner_name = "macos-15".into();
    assert!(validate_receipt(&receipt, &valid_builder()).is_err());

    let mut receipt = parse_valid_receipt();
    receipt.version_independence[0].clients.pop();
    assert!(validate_receipt(&receipt, &valid_builder()).is_err());
}

#[test]
fn receipt_row_order_must_match_the_canonical_collector_schema() {
    let mut receipt = parse_valid_receipt();
    receipt.platforms.swap(0, 1);
    assert!(validate_receipt(&receipt, &valid_builder()).is_err());

    let mut receipt = parse_valid_receipt();
    receipt.version_independence.swap(0, 1);
    assert!(validate_receipt(&receipt, &valid_builder()).is_err());
}

#[test]
fn uppercase_or_noncanonical_hashes_are_rejected() {
    assert!(validate_sha(&"A".repeat(64), 64, "digest").is_err());
    assert!(validate_sha(&"a".repeat(63), 64, "digest").is_err());
}

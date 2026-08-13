use super::super::BUILDER_WORKFLOW;
use super::*;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RECEIPT_PATH: &str =
    "governance/client-conformance/runtime/runtime-receipt-42-attempt-3.json";
const BUNDLE_PATH: &str =
    "governance/client-conformance/runtime/runtime-receipt-42-attempt-3.sigstore.json";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TempRepository {
    root: PathBuf,
}

impl TempRepository {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow the Unix epoch")
            .as_nanos();
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-runtime-receipt-test-{}-{nonce}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        command(&root, &["init", "--quiet"]);
        command(&root, &["config", "user.name", "runtime-receipt-test"]);
        command(
            &root,
            &["config", "user.email", "runtime-receipt@example.invalid"],
        );
        Self { root }
    }
}

impl Drop for TempRepository {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Promotion {
    _repository: TempRepository,
    builder: String,
    base: String,
    base_tree: String,
    matrix: Matrix,
    reference: ReceiptRef,
}

fn promotion(extra_path: bool, executable_receipt: bool, semantic_drift: bool) -> Promotion {
    let repository = TempRepository::new();
    let root = &repository.root;
    let builder_path = root.join(BUILDER_WORKFLOW);
    std::fs::create_dir_all(builder_path.parent().unwrap()).unwrap();
    std::fs::write(&builder_path, b"name: trusted runtime builder\n").unwrap();
    command(root, &["add", BUILDER_WORKFLOW]);
    command(root, &["commit", "--quiet", "-m", "runtime builder policy"]);
    let builder = command(root, &["rev-parse", "HEAD"]);

    let matrix_path = root.join(MATRIX_PATH);
    std::fs::create_dir_all(matrix_path.parent().unwrap()).unwrap();
    let mut value = base_matrix();
    write_json(&matrix_path, &value);
    command(root, &["add", MATRIX_PATH]);
    command(root, &["commit", "--quiet", "-m", "base policy"]);
    let base = command(root, &["rev-parse", "HEAD"]);
    let base_tree = command(root, &["rev-parse", "HEAD^{tree}"]);

    let reference = ReceiptRef {
        path: RECEIPT_PATH.into(),
        sha256: "a".repeat(64),
        attestation_path: BUNDLE_PATH.into(),
        attestation_sha256: "b".repeat(64),
    };
    value["runtime_receipt"] = json!({
        "path": reference.path,
        "sha256": reference.sha256,
        "attestation_path": reference.attestation_path,
        "attestation_sha256": reference.attestation_sha256
    });
    value["version_independence"]["status"] = json!("green");
    for row in value["platform_smoke"].as_array_mut().unwrap() {
        row["status"] = json!("green");
    }
    if semantic_drift {
        value["placement_reference"] = json!("silently-broadened");
    }
    write_json(&matrix_path, &value);
    let receipt_path = root.join(RECEIPT_PATH);
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"{}\n").unwrap();
    std::fs::write(root.join(BUNDLE_PATH), b"{}\n").unwrap();
    if extra_path {
        let extra = root.join(".github/workflows/extra.yml");
        std::fs::create_dir_all(extra.parent().unwrap()).unwrap();
        std::fs::write(extra, b"name: forbidden\n").unwrap();
    }
    command(root, &["add", "."]);
    if executable_receipt {
        command(root, &["update-index", "--chmod=+x", RECEIPT_PATH]);
    }
    command(root, &["commit", "--quiet", "-m", "promote evidence"]);
    let source = std::fs::read(matrix_path).unwrap();
    let matrix = parse_matrix(&source, "test candidate matrix").unwrap();
    Promotion {
        _repository: repository,
        builder,
        base,
        base_tree,
        matrix,
        reference,
    }
}

fn base_matrix() -> Value {
    let platform = |name: &str, target: &str, runner: &str| {
        json!({
            "platform": name,
            "target": target,
            "runner": runner,
            "status": "pending",
            "native": true,
            "workflow": {
                "kind": "workflow",
                "path": ".github/workflows/release.yml",
                "selector": target
            }
        })
    };
    json!({
        "schema_version": 2,
        "placement_reference": "placement",
        "runtime_builder": null,
        "runtime_receipt": null,
        "rows": [],
        "client_parity": {
            "status": "green",
            "clients": [],
            "transcript": "transcript",
            "test": {"kind": "test", "path": "test", "selector": "test"}
        },
        "version_independence": {
            "status": "pending",
            "clients": [],
            "operating_systems": [],
            "evidence": []
        },
        "platform_smoke": [
            platform("macos-arm64", "aarch64-apple-darwin", "macos-15"),
            platform("macos-x86_64", "x86_64-apple-darwin", "macos-15-intel"),
            platform(
                "linux-arm64",
                "aarch64-unknown-linux-musl",
                "ubuntu-24.04-arm",
            ),
            platform(
                "linux-x86_64",
                "x86_64-unknown-linux-musl",
                "ubuntu-24.04",
            )
        ]
    })
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn command(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
fn exact_clean_evidence_only_promotion_passes_every_history_guard() {
    let fixture = promotion(false, false, false);
    let root = &fixture._repository.root;
    require_clean_evidence_paths(root, &fixture.reference).unwrap();
    require_commit_and_tree(root, &fixture.base, &fixture.base_tree).unwrap();
    require_builder_ancestor(root, &fixture.builder, &fixture.base).unwrap();
    let builder = BuilderRef {
        path: BUILDER_WORKFLOW.into(),
        commit: fixture.builder.clone(),
    };
    validate_builder_configuration(root, &builder).unwrap();
    require_evidence_only_delta(root, &fixture.base, &fixture.reference).unwrap();
    require_semantically_unchanged_matrix(root, &fixture.matrix, &fixture.base).unwrap();
}

#[test]
fn extra_workflow_path_and_executable_receipt_are_rejected() {
    let extra = promotion(true, false, false);
    assert!(
        require_evidence_only_delta(&extra._repository.root, &extra.base, &extra.reference)
            .is_err()
    );

    let executable = promotion(false, true, false);
    assert!(
        require_evidence_only_delta(
            &executable._repository.root,
            &executable.base,
            &executable.reference,
        )
        .is_err()
    );
}

#[test]
fn wrong_tree_and_non_ancestor_commit_are_rejected() {
    let fixture = promotion(false, false, false);
    let root = &fixture._repository.root;
    assert!(require_commit_and_tree(root, &fixture.base, &"0".repeat(40)).is_err());

    let candidate_tree = command(root, &["rev-parse", "HEAD^{tree}"]);
    let side = command(
        root,
        &[
            "commit-tree",
            &candidate_tree,
            "-p",
            &fixture.base,
            "-m",
            "side evidence",
        ],
    );
    assert!(require_commit_and_tree(root, &side, &candidate_tree).is_err());
    assert!(require_builder_ancestor(root, &fixture.base, &fixture.base).is_err());
    assert!(require_builder_ancestor(root, &side, &fixture.base).is_err());
}

#[test]
fn broader_matrix_change_is_rejected_after_status_normalization() {
    let fixture = promotion(false, false, true);
    assert!(
        require_semantically_unchanged_matrix(
            &fixture._repository.root,
            &fixture.matrix,
            &fixture.base,
        )
        .is_err()
    );
}

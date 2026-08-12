use iteron_protocol::{
    Effort, ErasureAuthorityId, ErasureContentDigest, ErasureFailureCode, ErasureOperationId,
    ErasureRequest, ErasureScopeId, ErasureState, ErasureTarget, ErasureTargetId,
    ErasureVerification, Event, EventKind, RunId, Seq, TenantId, TurnId,
};
use iteron_record::erasure::{execute_erasure, read_erasure_receipt};
use iteron_record::{ErasureError, Rollout};
use std::path::{Path, PathBuf};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn tmpdir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "core-erasure-integration-{tag}-{}-{}",
        std::process::id(),
        now_ms()
    ))
}

fn scope() -> ErasureScopeId {
    ErasureScopeId::new("default").unwrap()
}

fn request(operation: &str, target: ErasureTarget) -> ErasureRequest {
    ErasureRequest {
        operation_id: ErasureOperationId::new(operation).unwrap(),
        authority_id: ErasureAuthorityId::new("operator.owner").unwrap(),
        requested_at_unix_ms: now_ms(),
        target,
    }
}

fn exact(operation: &str, run: &str) -> ErasureRequest {
    request(
        operation,
        ErasureTarget::ExactSession {
            scope_id: scope(),
            run_id: ErasureTargetId::new(run).unwrap(),
        },
    )
}

fn run_start() -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::RunStart {
            cwd: "/workspace".into(),
            model: "model-a".into(),
            effort: Effort::Medium,
            created_at: 1,
            environment: None,
            parent_run: None,
            forked_at: None,
            parent_hash_at_seq: None,
            config_digest: "cfg".into(),
            agent_definition_tag: None,
            max_usd: None,
        },
    }
}

fn create_run(runs_dir: &Path, run: &str) {
    let mut rollout = Rollout::open(runs_dir, &RunId(run.to_owned()), TenantId::default()).unwrap();
    rollout.append(&run_start()).unwrap();
}

#[test]
fn exact_delete_has_a_durable_idempotent_terminal_receipt() {
    let dir = tmpdir("exact");
    create_run(&dir, "run-1");
    let request = exact("erase-exact", "run-1");
    let first = execute_erasure(&dir, request.clone()).unwrap();

    assert_eq!(first.state(), ErasureState::Verified);
    assert_eq!(
        first.verification(),
        Some(&ErasureVerification::ExactSessionAbsent)
    );
    assert!(!dir.join("run-1.jsonl").exists());
    let mut retry = request;
    retry.requested_at_unix_ms = retry.requested_at_unix_ms.saturating_add(1);
    assert_eq!(execute_erasure(&dir, retry).unwrap(), first);
    assert_eq!(
        read_erasure_receipt(&dir, &ErasureOperationId::new("erase-exact").unwrap())
            .unwrap()
            .unwrap(),
        first
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn active_writer_is_excluded_and_the_failure_is_idempotent() {
    let dir = tmpdir("active");
    let mut rollout =
        Rollout::open(&dir, &RunId("run-active".into()), TenantId::default()).unwrap();
    rollout.append(&run_start()).unwrap();
    let request = exact("erase-active", "run-active");

    let receipt = execute_erasure(&dir, request.clone()).unwrap();
    assert_eq!(receipt.state(), ErasureState::Failed);
    assert_eq!(receipt.failure(), Some(ErasureFailureCode::ActiveWriter));
    assert!(dir.join("run-active.jsonl").exists());
    assert_eq!(execute_erasure(&dir, request).unwrap(), receipt);
    drop(rollout);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retention_is_separate_from_exact_delete_and_verifies_its_scope() {
    let dir = tmpdir("retention");
    create_run(&dir, "run-a");
    create_run(&dir, "run-b");
    let receipt = execute_erasure(
        &dir,
        request(
            "erase-retention",
            ErasureTarget::RetentionPrune {
                scope_id: scope(),
                max_age_secs: None,
                keep_last: Some(0),
            },
        ),
    )
    .unwrap();

    assert_eq!(receipt.state(), ErasureState::Verified);
    assert_eq!(
        receipt.verification(),
        Some(&ErasureVerification::RetentionApplied {
            retained_sessions: 0,
            active_sessions: 0,
            ancestor_sessions: 0,
        })
    );
    assert!(!dir.join("run-a.jsonl").exists());
    assert!(!dir.join("run-b.jsonl").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retention_does_not_call_a_selected_active_session_erased() {
    let dir = tmpdir("retention-active");
    let mut rollout = Rollout::open(
        &dir,
        &RunId("run-retention-active".into()),
        TenantId::default(),
    )
    .unwrap();
    rollout.append(&run_start()).unwrap();
    let receipt = execute_erasure(
        &dir,
        request(
            "erase-retention-active",
            ErasureTarget::RetentionPrune {
                scope_id: scope(),
                max_age_secs: None,
                keep_last: Some(0),
            },
        ),
    )
    .unwrap();

    assert_eq!(receipt.state(), ErasureState::Failed);
    assert_eq!(receipt.failure(), Some(ErasureFailureCode::ActiveWriter));
    assert!(dir.join("run-retention-active.jsonl").exists());
    drop(rollout);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn missing_content_revocation_fails_closed_and_operation_ids_cannot_be_rebound() {
    let dir = tmpdir("content");
    let content = request(
        "erase-content",
        ErasureTarget::ContentRevocation {
            scope_id: scope(),
            content_digest: ErasureContentDigest::new(format!("sha256:{}", "b".repeat(64)))
                .unwrap(),
        },
    );
    let receipt = execute_erasure(&dir, content.clone()).unwrap();
    assert_eq!(receipt.state(), ErasureState::Failed);
    assert_eq!(receipt.failure(), Some(ErasureFailureCode::TargetNotFound));
    assert_eq!(execute_erasure(&dir, content).unwrap(), receipt);

    let first = exact("same-operation", "missing-a");
    assert_eq!(
        execute_erasure(&dir, first).unwrap().failure(),
        Some(ErasureFailureCode::TargetNotFound)
    );
    assert!(matches!(
        execute_erasure(&dir, exact("same-operation", "missing-b")),
        Err(ErasureError::ReceiptConflict { .. })
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

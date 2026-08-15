use super::*;
use iteron_protocol::{
    Block, Effort, ErasureAuthorityId, Event, EventKind, Message, Role, Seq, TurnId,
};

fn tmpdir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("core-erasure-{tag}-{}-{nonce}", std::process::id()))
}

fn scope() -> ErasureScopeId {
    ErasureScopeId::new("default").unwrap()
}

/// The request as `execute_erasure` would durably have recorded it.
///
/// Authorization is proven locally, not accepted from the wire: `execute_erasure` overwrites
/// `authority_id` with the effective OS principal before it evaluates request identity, so that a
/// caller cannot mint destructive authority by choosing a string. A crash-boundary fixture that
/// persists the wire value therefore models a receipt the product can never write, and recovery
/// correctly refuses it as a `ReceiptConflict`.
fn as_persisted(runs_dir: &Path, mut request: ErasureRequest) -> ErasureRequest {
    request.authority_id = authorize_local_erasure(runs_dir).unwrap().id;
    request
}

fn request(operation: &str, target: ErasureTarget) -> ErasureRequest {
    ErasureRequest {
        operation_id: ErasureOperationId::new(operation).unwrap(),
        authority_id: ErasureAuthorityId::new("operator.owner").unwrap(),
        requested_at_unix_ms: now_unix_ms(),
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

fn create_run(runs_dir: &Path, run: &str) {
    let mut rollout =
        crate::Rollout::open(runs_dir, &RunId(run.to_owned()), TenantId::default()).unwrap();
    rollout
        .append(&Event {
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
        })
        .unwrap();
}

fn text_digest(value: &str) -> iteron_protocol::ErasureContentDigest {
    crate::content_store::private_content_digest(value.as_bytes())
}

#[test]
fn exact_session_erasure_is_durable_and_idempotent() {
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
    assert!(matches!(
        crate::content_store::guard_private_content(
            &dir,
            &TenantId::default(),
            &text_digest("/workspace")
        ),
        Err(crate::ContentStoreError::Unresolved { .. })
    ));

    let mut retried = request;
    retried.requested_at_unix_ms = retried.requested_at_unix_ms.saturating_add(1);
    let repeated = execute_erasure(&dir, retried).unwrap();
    assert_eq!(repeated, first, "terminal receipt must be byte-stable");
    assert_eq!(
        read_erasure_receipt(&dir, &ErasureOperationId::new("erase-exact").unwrap())
            .unwrap()
            .unwrap(),
        first
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn exact_session_recovery_resumes_after_unlink_before_tombstone_receipt() {
    let dir = tmpdir("recover");
    create_run(&dir, "run-recover");
    session::reindex(&dir).unwrap();
    let request = exact("erase-recover", "run-recover");
    ensure_layout(&dir).unwrap();

    let mut interrupted =
        ErasureReceipt::requested(as_persisted(&dir, request.clone()), now_unix_ms()).unwrap();
    interrupted
        .advance(ErasureState::Quiescing, now_unix_ms())
        .unwrap();
    persist_receipt(&dir, &interrupted).unwrap();
    // Model the exact crash boundary: journal unlink is durable, sidecar/index cleanup and the
    // Tombstoned receipt replacement have not happened yet.
    assert!(dir.join("run-recover.meta.json").exists());
    std::fs::remove_file(dir.join("run-recover.jsonl")).unwrap();

    let recovered = execute_erasure(&dir, request).unwrap();
    assert_eq!(recovered.state(), ErasureState::Verified);
    assert_eq!(recovered.transition_count(), 3);
    assert!(!dir.join("run-recover.meta.json").exists());
    assert!(matches!(
        crate::content_store::guard_private_content(
            &dir,
            &TenantId::default(),
            &text_digest("/workspace")
        ),
        Err(crate::ContentStoreError::Unresolved { .. })
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn active_writer_exclusion_becomes_an_idempotent_failed_receipt() {
    let dir = tmpdir("active");
    let mut rollout =
        crate::Rollout::open(&dir, &RunId("run-active".into()), TenantId::default()).unwrap();
    rollout
        .append(&Event {
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
        })
        .unwrap();
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
fn retention_prune_is_distinct_and_verifies_the_remaining_scope() {
    let dir = tmpdir("retention");
    create_run(&dir, "run-a");
    create_run(&dir, "run-b");
    let request = request(
        "erase-retention",
        ErasureTarget::RetentionPrune {
            scope_id: scope(),
            max_age_secs: None,
            keep_last: Some(0),
        },
    );

    let receipt = execute_erasure(&dir, request).unwrap();
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
fn retention_recovery_removes_a_stale_index_after_the_last_unlink() {
    let dir = tmpdir("retention-recover");
    create_run(&dir, "run-stale");
    session::reindex(&dir).unwrap();
    let request = request(
        "erase-retention-recover",
        ErasureTarget::RetentionPrune {
            scope_id: scope(),
            max_age_secs: None,
            keep_last: Some(0),
        },
    );
    ensure_layout(&dir).unwrap();
    let mut interrupted =
        ErasureReceipt::requested(as_persisted(&dir, request.clone()), now_unix_ms()).unwrap();
    interrupted
        .advance(ErasureState::Quiescing, now_unix_ms())
        .unwrap();
    persist_receipt(&dir, &interrupted).unwrap();

    std::fs::remove_file(dir.join("run-stale.meta.json")).unwrap();
    std::fs::remove_file(dir.join("run-stale.jsonl")).unwrap();
    assert!(
        std::fs::read_to_string(dir.join("sessions.index"))
            .unwrap()
            .contains("run-stale")
    );

    let recovered = execute_erasure(&dir, request).unwrap();
    assert_eq!(recovered.state(), ErasureState::Verified);
    assert!(
        !std::fs::read_to_string(dir.join("sessions.index"))
            .unwrap()
            .contains("run-stale")
    );
    assert!(matches!(
        crate::content_store::guard_private_content(
            &dir,
            &TenantId::default(),
            &text_digest("/workspace")
        ),
        Err(crate::ContentStoreError::Unresolved { .. })
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn exact_erasure_preserves_shared_material_until_its_last_session_is_removed() {
    let dir = tmpdir("shared-content");
    create_run(&dir, "run-shared-a");
    create_run(&dir, "run-shared-b");
    let digest = text_digest("/workspace");
    crate::content_store::guard_private_content(&dir, &TenantId::default(), &digest).unwrap();

    assert_eq!(
        execute_erasure(&dir, exact("erase-shared-a", "run-shared-a"))
            .unwrap()
            .state(),
        ErasureState::Verified
    );
    crate::content_store::guard_private_content(&dir, &TenantId::default(), &digest).unwrap();

    assert_eq!(
        execute_erasure(&dir, exact("erase-shared-b", "run-shared-b"))
            .unwrap()
            .state(),
        ErasureState::Verified
    );
    assert!(matches!(
        crate::content_store::guard_private_content(&dir, &TenantId::default(), &digest),
        Err(crate::ContentStoreError::Unresolved { .. })
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn content_revocation_shreds_material_and_blocks_replay_and_fork() {
    let dir = tmpdir("content");
    create_run(&dir, "run-content");
    let secret = "private payload only the vault may hold";
    let mut rollout =
        crate::Rollout::open_existing(&dir, &RunId("run-content".into()), TenantId::default())
            .unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Message {
                message: Message {
                    role: Role::User,
                    content: vec![Block::Text {
                        text: secret.into(),
                    }],
                },
            },
        })
        .unwrap();
    drop(rollout);
    session::reindex(&dir).unwrap();
    let sidecar_manifest = std::fs::read(dir.join("run-content.meta.json")).unwrap();
    let index = std::fs::read(dir.join("sessions.index")).unwrap();
    let mut index_lines = index.split(|byte| *byte == b'\n');
    assert_eq!(
        index_lines.next(),
        Some(br#"{"version":2,"order":"updated_desc"}"#.as_slice())
    );
    let index_manifest = index_lines
        .find(|line| !line.is_empty())
        .expect("V2 index must contain the run's private manifest after its public header")
        .to_vec();
    assert!(
        !String::from_utf8_lossy(&sidecar_manifest).contains(secret)
            && !String::from_utf8_lossy(&index_manifest).contains(secret),
        "session cache files must publish handles, never content-bearing metadata"
    );
    assert_eq!(
        session::private_cache::read_sidecar(&dir, &sidecar_manifest)
            .unwrap()
            .title,
        secret
    );
    assert_eq!(
        session::private_cache::read_index_line(&dir, &index_manifest)
            .unwrap()
            .title,
        secret
    );
    let raw = std::fs::read_to_string(dir.join("run-content.jsonl")).unwrap();
    assert!(!raw.contains(secret));
    assert!(matches!(
        &crate::replay(&dir.join("run-content.jsonl")).unwrap()[1].kind,
        EventKind::Message { message }
            if matches!(&message.content[0], Block::Text { text } if text == secret)
    ));
    let digest = crate::content_store::private_content_digest(secret.as_bytes());
    let request = request(
        "erase-content",
        ErasureTarget::ContentRevocation {
            scope_id: scope(),
            content_digest: digest,
        },
    );

    let receipt = execute_erasure(&dir, request.clone()).unwrap();
    assert_eq!(receipt.state(), ErasureState::Verified);
    let Some(ErasureVerification::ContentRevoked {
        reference_count,
        affected_sessions,
        ..
    }) = receipt.verification()
    else {
        panic!("content revocation must produce typed verification");
    };
    // The source record plus the independently gated sidecar and index derivatives.
    assert_eq!(*reference_count, 3);
    assert_eq!(*affected_sessions, 1);
    let Some(ErasureVerification::ContentRevoked { coverage, .. }) = receipt.verification() else {
        panic!("verified content revocation must carry propagation coverage");
    };
    assert!(
        coverage.session_projections
            && coverage.indexes
            && coverage.prompt_history
            && coverage.attachments
            && coverage.tool_artifacts
            && coverage.checkpoints
            && coverage.memory_context
            && coverage.exports
            && coverage.telemetry_debug
            && coverage.trajectories
            && coverage.datasets
            && coverage.evaluator_inputs
            && coverage.candidate_stores,
        "a verified receipt may claim complete coverage only while all 13 production gates exist"
    );
    assert!(
        !dir.join("run-content.meta.json").exists() && !dir.join("sessions.index").exists(),
        "propagation must invalidate private caches without recursively acquiring the content lock"
    );
    assert!(
        session::list(&dir, &TenantId::default()).is_empty(),
        "lazy cache rebuild must skip a rollout whose source handle is revoked"
    );
    let cold_page = session::page(&dir, &TenantId::default(), None, None, Some(1));
    assert!(
        !cold_page.index_ready && cold_page.rebuild_recommended,
        "latency-sensitive reads must request an off-foreground rebuild after invalidation"
    );
    assert_eq!(session::reindex(&dir).unwrap(), 0);
    assert!(
        dir.join("sessions.index").exists(),
        "explicit maintenance must rebuild the bounded V2 index manifest"
    );
    assert!(matches!(
        crate::replay(&dir.join("run-content.jsonl")),
        Err(crate::RecordError::PrivateContent(
            crate::ContentStoreError::Revoked { .. }
        ))
    ));
    assert!(
        session::private_cache::read_sidecar(&dir, &sidecar_manifest).is_err(),
        "a copied pre-revocation projection manifest must not hydrate after source revocation"
    );
    assert!(
        session::private_cache::read_index_line(&dir, &index_manifest).is_err(),
        "a copied pre-revocation index manifest must not hydrate after source revocation"
    );
    assert!(
        crate::fork(
            &dir,
            &RunId("run-content".into()),
            Seq(1),
            &TenantId::default()
        )
        .is_err()
    );
    assert_eq!(execute_erasure(&dir, request).unwrap(), receipt);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn content_revocation_transitively_shreds_record_trajectory_dataset_and_candidate() {
    let dir = tmpdir("transitive-content");
    create_run(&dir, "run-transitive");
    let secret = "source content with transformed descendants";
    let mut rollout =
        crate::Rollout::open_existing(&dir, &RunId("run-transitive".into()), TenantId::default())
            .unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Message {
                message: Message::user_text(secret),
            },
        })
        .unwrap();
    drop(rollout);

    let tenant = TenantId::default();
    let source_run = RunId("run-transitive".into());
    let trajectory_store = crate::PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        source_run.clone(),
        crate::ContentReferenceSurface::Trajectory,
        crate::PrivateContentClass::Trajectory,
        crate::PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let trajectory = trajectory_store
        .put_derived_from_run(Seq(20), b"trajectory projection", &source_run)
        .unwrap();
    let dataset_owner = RunId("dataset-transitive".into());
    let dataset_store = crate::PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        dataset_owner.clone(),
        crate::ContentReferenceSurface::Dataset,
        crate::PrivateContentClass::Dataset,
        crate::PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let dataset = dataset_store
        .put_derived(
            Seq(21),
            b"governed dataset",
            &[crate::content_store::PrivateContentSource {
                owner: source_run.clone(),
                digest: trajectory.digest.clone(),
            }],
        )
        .unwrap();
    let candidate_owner = RunId("candidate-transitive".into());
    let candidate_store = crate::PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        candidate_owner.clone(),
        crate::ContentReferenceSurface::CandidateStore,
        crate::PrivateContentClass::Candidate,
        crate::PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let candidate = candidate_store
        .put_derived(
            Seq(22),
            b"candidate artifact",
            &[crate::content_store::PrivateContentSource {
                owner: dataset_owner.clone(),
                digest: dataset.digest.clone(),
            }],
        )
        .unwrap();
    drop(candidate_store);
    drop(dataset_store);
    drop(trajectory_store);

    let receipt = execute_erasure(
        &dir,
        request(
            "erase-transitive",
            ErasureTarget::ContentRevocation {
                scope_id: scope(),
                content_digest: crate::content_store::private_content_digest(secret.as_bytes()),
            },
        ),
    )
    .unwrap();
    assert_eq!(receipt.state(), ErasureState::Verified);
    assert!(matches!(
        receipt.verification(),
        Some(ErasureVerification::ContentRevoked {
            reference_count: 5,
            affected_sessions: 1,
            ..
        })
    ));

    for (owner, surface, class, seq, handle) in [
        (
            source_run,
            crate::ContentReferenceSurface::Trajectory,
            crate::PrivateContentClass::Trajectory,
            Seq(20),
            trajectory,
        ),
        (
            dataset_owner,
            crate::ContentReferenceSurface::Dataset,
            crate::PrivateContentClass::Dataset,
            Seq(21),
            dataset,
        ),
        (
            candidate_owner,
            crate::ContentReferenceSurface::CandidateStore,
            crate::PrivateContentClass::Candidate,
            Seq(22),
            candidate,
        ),
    ] {
        let reopened = crate::PrivateContentDerivativeStore::open(
            &dir,
            tenant.clone(),
            owner,
            surface,
            class,
            crate::PrivateContentRetention::ExplicitRevocation,
            1024,
        )
        .unwrap();
        assert!(matches!(
            reopened.read_at(seq, &handle),
            Err(crate::ContentStoreError::Revoked { .. })
        ));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn checkpoint_projection_is_lineaged_to_prior_record_content_and_replay_fails_closed() {
    let dir = tmpdir("checkpoint-lineage");
    let tenant = TenantId::default();
    let run = RunId("checkpoint-lineage".into());
    let mut rollout = crate::Rollout::open(&dir, &run, tenant.clone()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Notice {
                text: "checkpoint source content".into(),
            },
        })
        .unwrap();
    let source = crate::content_store::private_content_sources_for_run(&dir, &tenant, &run)
        .unwrap()
        .into_iter()
        .next()
        .expect("notice is a private record field");
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Checkpoint {
                at: Seq(1),
                tree_ref: "0123456789abcdef0123456789abcdef01234567".into(),
            },
        })
        .unwrap();
    let path = rollout.path().to_path_buf();
    assert_eq!(crate::replay(&path).unwrap().len(), 2);
    drop(rollout);

    let receipt = execute_erasure(
        &dir,
        request(
            "revoke-checkpoint-source",
            ErasureTarget::ContentRevocation {
                scope_id: scope(),
                content_digest: source.digest,
            },
        ),
    )
    .unwrap();
    assert_eq!(receipt.state(), ErasureState::Verified);
    assert!(matches!(
        crate::replay(&path),
        Err(crate::RecordError::PrivateContent(
            crate::ContentStoreError::Revoked { .. } | crate::ContentStoreError::Unresolved { .. }
        ))
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn operation_id_cannot_be_rebound_to_another_target() {
    let dir = tmpdir("conflict");
    let first = exact("same-operation", "missing-a");
    assert_eq!(
        execute_erasure(&dir, first).unwrap().failure(),
        Some(ErasureFailureCode::TargetNotFound)
    );
    let conflict = execute_erasure(&dir, exact("same-operation", "missing-b")).unwrap_err();
    assert!(matches!(conflict, ErasureError::ReceiptConflict { .. }));
    std::fs::remove_dir_all(&dir).unwrap();
}

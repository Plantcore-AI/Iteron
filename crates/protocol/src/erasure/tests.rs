use super::*;

fn request(target: ErasureTarget) -> ErasureRequest {
    ErasureRequest {
        operation_id: ErasureOperationId::new("erase-001").unwrap(),
        authority_id: ErasureAuthorityId::new("operator.jamal").unwrap(),
        requested_at_unix_ms: 10,
        target,
    }
}

fn scope() -> ErasureScopeId {
    ErasureScopeId::new("tenant.default").unwrap()
}

#[test]
fn erasure_identifiers_and_content_addresses_are_bounded() {
    assert!(ErasureOperationId::new("../../escape").is_err());
    assert!(ErasureAuthorityId::new("x".repeat(MAX_ERASURE_AUTHORITY_ID_BYTES + 1)).is_err());
    assert!(ErasureTargetId::new("run-safe_1.2").is_ok());
    assert!(ErasureContentDigest::new(format!("sha256:{}", "a".repeat(64))).is_ok());
    assert!(ErasureContentDigest::new(format!("sha256:{}", "A".repeat(64))).is_err());
    for invalid in ["CON", "COM1.log", "run."] {
        let request = request(ErasureTarget::ExactSession {
            scope_id: scope(),
            run_id: ErasureTargetId::new(invalid).unwrap(),
        });
        assert_eq!(request.validate(), Err(ErasureValidationError::TargetId));
    }
}

#[test]
fn retention_requires_a_bounded_selection_rule() {
    let empty = request(ErasureTarget::RetentionPrune {
        scope_id: scope(),
        max_age_secs: None,
        keep_last: None,
    });
    assert_eq!(
        empty.validate(),
        Err(ErasureValidationError::RetentionPolicy)
    );
    let unbounded = request(ErasureTarget::RetentionPrune {
        scope_id: scope(),
        max_age_secs: None,
        keep_last: Some(MAX_RETENTION_KEEP_LAST + 1),
    });
    assert_eq!(
        unbounded.validate(),
        Err(ErasureValidationError::RetentionPolicy)
    );
}

#[test]
fn receipt_state_machine_is_typed_and_terminal_is_immutable() {
    let mut receipt = ErasureReceipt::requested(
        request(ErasureTarget::ExactSession {
            scope_id: scope(),
            run_id: ErasureTargetId::new("run-1").unwrap(),
        }),
        11,
    )
    .unwrap();
    assert_eq!(
        receipt.advance(ErasureState::Tombstoned, 12),
        Err(ErasureValidationError::Transition)
    );
    receipt.advance(ErasureState::Quiescing, 12).unwrap();
    receipt.advance(ErasureState::Tombstoned, 13).unwrap();
    receipt
        .mark_verified(ErasureVerification::ExactSessionAbsent, 14)
        .unwrap();
    receipt.validate().unwrap();
    assert_eq!(receipt.state(), ErasureState::Verified);
    assert_eq!(
        receipt.mark_failed(ErasureFailureCode::StorageFailure, 15),
        Err(ErasureValidationError::TerminalReceipt)
    );
    let encoded = serde_json::to_vec(&receipt).unwrap();
    assert!(encoded.len() < iteron_tunables::param_integer("protocol.erasure.max_erasure_receipt_bytes", MAX_ERASURE_RECEIPT_BYTES));
    assert_eq!(
        serde_json::from_slice::<ErasureReceipt>(&encoded).unwrap(),
        receipt
    );
}

fn complete_coverage() -> ErasurePropagationCoverage {
    ErasurePropagationCoverage {
        session_projections: true,
        indexes: true,
        prompt_history: true,
        attachments: true,
        tool_artifacts: true,
        checkpoints: true,
        memory_context: true,
        exports: true,
        telemetry_debug: true,
        trajectories: true,
        datasets: true,
        evaluator_inputs: true,
        candidate_stores: true,
    }
}

#[test]
fn content_revocation_requires_complete_propagation_verification() {
    let mut receipt = ErasureReceipt::requested(
        request(ErasureTarget::ContentRevocation {
            scope_id: scope(),
            content_digest: ErasureContentDigest::new(format!("sha256:{}", "c".repeat(64)))
                .unwrap(),
        }),
        11,
    )
    .unwrap();
    receipt.advance(ErasureState::Quiescing, 12).unwrap();
    receipt.advance(ErasureState::Tombstoned, 13).unwrap();
    receipt.advance(ErasureState::Shredded, 14).unwrap();
    receipt.advance(ErasureState::Propagating, 15).unwrap();
    receipt
        .mark_verified(
            ErasureVerification::ContentRevoked {
                reference_count: 1,
                affected_sessions: 1,
                revocation_generation: 2,
                coverage: complete_coverage(),
            },
            16,
        )
        .unwrap();
    receipt.validate().unwrap();

    let mut incomplete = receipt.clone();
    let Some(ErasureVerification::ContentRevoked { coverage, .. }) =
        incomplete.verification.as_mut()
    else {
        unreachable!("the fixture is a content-revocation receipt")
    };
    coverage.prompt_history = false;
    assert_eq!(
        incomplete.validate(),
        Err(ErasureValidationError::Receipt),
        "a missing namespace gate must make a Verified receipt unpersistable"
    );

    let mut wrong = ErasureReceipt::requested(
        request(ErasureTarget::ContentRevocation {
            scope_id: scope(),
            content_digest: ErasureContentDigest::new(format!("sha256:{}", "d".repeat(64)))
                .unwrap(),
        }),
        20,
    )
    .unwrap();
    wrong.advance(ErasureState::Quiescing, 21).unwrap();
    wrong.advance(ErasureState::Tombstoned, 22).unwrap();
    assert_eq!(
        wrong.mark_verified(ErasureVerification::ExactSessionAbsent, 23),
        Err(ErasureValidationError::Transition),
        "content revocation cannot skip shred and propagation or borrow exact-delete proof"
    );
}

use crate::verifier_crypto::sha256_hex;
use crate::{
    ArtifactKind, AttestationKey, ConsentAwareDatasetRegistry, DataClass, DataGovernance,
    DatasetAuditKind, DatasetRegistryError, EVOLUTION_SCHEMA_VERSION, EvaluationSuite,
    EvaluationTask, EvidenceRecordError, EvidenceRecorder, EvolutionMethod, EvolutionVerifier,
    PolicyBundle, PolicyManifest, PolicyRef, ProducerTrustAnchor, ProtocolRange,
    RetentionTrainingUse, RewardVector, SignedTrajectory, StrategyDecision, StrategySlot,
    TrainingAdmissionPolicy, TrainingConsent, TrainingEligibilityError, TrajectoryEnvelope,
    VerifierError,
};
use core_protocol::{RunId, TenantId};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn key(byte: u8) -> AttestationKey {
    AttestationKey::new(vec![byte; 32]).unwrap()
}

fn admission() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn verifier() -> EvolutionVerifier {
    EvolutionVerifier::new(
        vec![ProducerTrustAnchor::new("producer-a", TenantId::default(), key(0x11)).unwrap()],
        admission(),
    )
    .unwrap()
}

fn trajectory(task_id: &str, tenant: TenantId, action: serde_json::Value) -> TrajectoryEnvelope {
    let policy = PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "router-a".into(),
        version: "1.0.0".into(),
        digest: D.into(),
    };
    let mut envelope = TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId(format!("run-{task_id}")),
        tenant_id: tenant,
        task_id: task_id.into(),
        domain: "coding".into(),
        environment_digest: D.into(),
        bundle: PolicyBundle {
            bundle_id: "bundle-a".into(),
            digest: D.into(),
            policies: vec![policy.clone()],
            rollback_to: None,
        },
        decisions: Vec::new(),
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.01,
            wall_time_ms: 10,
            human_acceptance: None,
            domain: BTreeMap::new(),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        },
    };
    EvidenceRecorder::new()
        .record_decision(
            &mut envelope,
            StrategyDecision {
                decision_id: "decision-0".into(),
                ordinal: 0,
                policy,
                observation_digest: D.into(),
                candidate_set_digest: D.into(),
                action,
                action_digest: D.into(),
                propensity: Some(1.0),
            },
        )
        .unwrap();
    envelope
}

fn signed(task_id: &str, action: serde_json::Value) -> SignedTrajectory {
    SignedTrajectory::sign(
        "producer-a",
        trajectory(task_id, TenantId::default(), action),
        &key(0x11),
    )
    .unwrap()
}

fn evaluation(task_id: &str) -> EvaluationSuite {
    EvaluationSuite::new(
        "independent-eval-owner",
        "suite-v1",
        vec![EvaluationTask {
            task_id: task_id.into(),
            fixture_digest: D.into(),
        }],
    )
    .unwrap()
}

fn manifest(artifact: &[u8], training_digest: &str, evaluation_digest: &str) -> PolicyManifest {
    PolicyManifest {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        policy: PolicyRef {
            slot: StrategySlot::router(),
            policy_id: "candidate-a".into(),
            version: "2.0.0".into(),
            digest: sha256_hex(artifact),
        },
        artifact_kind: ArtifactKind::Rules,
        base_model: crate::BaseModelId::unspecified(),
        artifact_locator: "registry://candidate-a@2.0.0".into(),
        parent: None,
        method: EvolutionMethod::Search,
        protocol: ProtocolRange { min: 1, max: 1 },
        required_capabilities: BTreeSet::new(),
        training_dataset_digest: Some(training_digest.into()),
        evaluation_suite_digest: evaluation_digest.into(),
    }
}

#[test]
fn d14_09_g1_recomputes_artifact_dataset_and_evaluation_digests() {
    let verifier = verifier();
    let signed = vec![signed("train-1", json!({"route":"safe"}))];
    let dataset = verifier.build_training_dataset(&signed).unwrap();
    let evaluation = evaluation("held-out-1");
    let artifact = br#"{"rule":"bounded"}"#;
    let valid = manifest(artifact, dataset.digest(), evaluation.digest());

    let verified = verifier
        .verify_candidate_inputs(&valid, artifact, Some(&dataset), &evaluation)
        .unwrap();
    assert_eq!(verified.artifact_digest, sha256_hex(artifact));
    assert_eq!(
        verified.training_dataset_digest.as_deref(),
        Some(dataset.digest())
    );
    assert_eq!(verified.evaluation_suite_digest, evaluation.digest());

    assert!(matches!(
        verifier.verify_candidate_inputs(&valid, b"tampered", Some(&dataset), &evaluation),
        Err(VerifierError::ArtifactDigestMismatch)
    ));
    let mut wrong_dataset = valid.clone();
    wrong_dataset.training_dataset_digest = Some(D.into());
    assert!(matches!(
        verifier.verify_candidate_inputs(&wrong_dataset, artifact, Some(&dataset), &evaluation),
        Err(VerifierError::TrainingDatasetDigestMismatch)
    ));
    let mut wrong_eval = valid.clone();
    wrong_eval.evaluation_suite_digest = D.into();
    assert!(matches!(
        verifier.verify_candidate_inputs(&wrong_eval, artifact, Some(&dataset), &evaluation),
        Err(VerifierError::EvaluationDigestMismatch)
    ));
    assert!(matches!(
        verifier.verify_candidate_inputs(&valid, artifact, None, &evaluation),
        Err(VerifierError::TrainingDatasetNotRegistered)
    ));
}

#[test]
fn d14_09_g2_authenticates_producer_tenant_governance_and_secret_scan() {
    let verifier = verifier();
    let valid = signed("clean", json!({"route":"safe"}));
    let proof = verifier.verify_trajectory(&valid).unwrap();
    assert_eq!(proof.producer_id(), "producer-a");
    assert_eq!(proof.envelope().task_id, "clean");

    let forged_tenant = SignedTrajectory::sign(
        "producer-a",
        trajectory(
            "forged-tenant",
            TenantId("another-tenant".into()),
            json!({"route":"safe"}),
        ),
        &key(0x11),
    )
    .unwrap();
    assert!(matches!(
        verifier.verify_trajectory(&forged_tenant),
        Err(VerifierError::UntrustedProducerTenant { .. })
    ));

    let wrong_key = SignedTrajectory::sign(
        "producer-a",
        trajectory("wrong-key", TenantId::default(), json!({"route":"safe"})),
        &key(0x22),
    )
    .unwrap();
    assert!(matches!(
        verifier.verify_trajectory(&wrong_key),
        Err(VerifierError::InvalidProducerAttestation)
    ));

    let secret = signed(
        "secret",
        json!({"authorization":"sk-test-secret-material-not-for-training"}),
    );
    assert!(!secret.envelope().governance.contains_secret_material);
    assert!(matches!(
        verifier.verify_trajectory(&secret),
        Err(VerifierError::SecretMaterialDetected)
    ));

    let mut tampered = trajectory("action-tamper", TenantId::default(), json!({"tool":"read"}));
    tampered.decisions[0].action = json!({"tool":"write"});
    let signed_tampered = SignedTrajectory::sign("producer-a", tampered, &key(0x11)).unwrap();
    assert!(matches!(
        verifier.verify_trajectory(&signed_tampered),
        Err(VerifierError::InvalidActionEvidence(
            EvidenceRecordError::ActionDigestMismatch { .. }
        ))
    ));

    assert_eq!(format!("{:?}", key(0x11)), "AttestationKey([REDACTED])");
    assert!(!format!("{secret:?}").contains("secret-material"));
}

#[test]
fn d14_09_g3_detects_membership_overlap_instead_of_trusting_a_boolean() {
    let verifier = verifier();
    let signed = vec![signed("shared-task", json!({"route":"safe"}))];
    let dataset = verifier.build_training_dataset(&signed).unwrap();
    let evaluation = evaluation("shared-task");
    let artifact = b"candidate";
    let manifest = manifest(artifact, dataset.digest(), evaluation.digest());

    assert!(matches!(
        verifier.verify_candidate_inputs(&manifest, artifact, Some(&dataset), &evaluation),
        Err(VerifierError::DetectedTrainEvalOverlap(task)) if task == "shared-task"
    ));
}

#[test]
fn verifier_construction_and_all_canonical_inputs_are_fixed_bounded() {
    assert!(matches!(
        AttestationKey::new(vec![0; 15]),
        Err(VerifierError::InvalidAttestationKeyLength { .. })
    ));
    let duplicate_eval = EvaluationSuite::new(
        "owner",
        "v1",
        vec![
            EvaluationTask {
                task_id: "same".into(),
                fixture_digest: D.into(),
            },
            EvaluationTask {
                task_id: "same".into(),
                fixture_digest: D.into(),
            },
        ],
    );
    assert!(matches!(
        duplicate_eval,
        Err(VerifierError::DuplicateEvaluationTask(task)) if task == "same"
    ));
}

#[test]
fn d14_12_g1_builder_refuses_every_unverified_or_ineligible_governance_class() {
    let verifier = verifier();

    let mut evaluation_only = trajectory(
        "evaluation-only",
        TenantId::default(),
        json!({"route":"safe"}),
    );
    evaluation_only.governance.consent = TrainingConsent::EvaluationOnly;
    let evaluation_only =
        SignedTrajectory::sign("producer-a", evaluation_only, &key(0x11)).unwrap();

    let mut denied = trajectory("denied", TenantId::default(), json!({"route":"safe"}));
    denied.governance.consent = TrainingConsent::Denied;
    let denied = SignedTrajectory::sign("producer-a", denied, &key(0x11)).unwrap();

    let mut flagged_secret = trajectory(
        "flagged-secret",
        TenantId::default(),
        json!({"route":"safe"}),
    );
    flagged_secret.governance.contains_secret_material = true;
    let flagged_secret = SignedTrajectory::sign("producer-a", flagged_secret, &key(0x11)).unwrap();

    let mut unlicensed = trajectory("unlicensed", TenantId::default(), json!({"route":"safe"}));
    unlicensed.governance.content_license = Some("proprietary".into());
    let unlicensed = SignedTrajectory::sign("producer-a", unlicensed, &key(0x11)).unwrap();

    for (candidate, expected) in [
        (evaluation_only, "consent"),
        (denied, "consent"),
        (flagged_secret, "secret"),
        (unlicensed, "license"),
    ] {
        let mut registry = ConsentAwareDatasetRegistry::new();
        let error = registry
            .build_and_register(&verifier, &[candidate])
            .unwrap_err();
        match (expected, error) {
            (
                "consent",
                DatasetRegistryError::Verification(VerifierError::IneligibleTraining(
                    TrainingEligibilityError::ConsentNotAllowed(_),
                )),
            )
            | (
                "secret",
                DatasetRegistryError::Verification(VerifierError::IneligibleTraining(
                    TrainingEligibilityError::ContainsSecretMaterial,
                )),
            )
            | (
                "license",
                DatasetRegistryError::Verification(VerifierError::IneligibleTraining(
                    TrainingEligibilityError::LicenseNotAllowed { .. },
                )),
            ) => {}
            (_, other) => panic!("unexpected eligibility result: {other}"),
        }
    }

    let first = signed("stable-a", json!({"route":"a"}));
    let second = signed("stable-b", json!({"route":"b"}));
    let mut registry_a = ConsentAwareDatasetRegistry::new();
    let members_a = [first.clone(), second.clone()];
    let dataset_a = registry_a
        .build_and_register(&verifier, &members_a)
        .unwrap();
    let mut registry_b = ConsentAwareDatasetRegistry::new();
    let members_b = [second, first];
    let dataset_b = registry_b
        .build_and_register(&verifier, &members_b)
        .unwrap();
    assert_eq!(dataset_a.digest(), dataset_b.digest());
}

#[test]
fn d14_12_g2_manifest_digest_must_resolve_to_exact_registered_members() {
    let verifier = verifier();
    let members = vec![signed("train-registry", json!({"route":"safe"}))];
    let evaluation = evaluation("held-out-registry");
    let artifact = b"candidate-registry";
    let preview = verifier.build_training_dataset(&members).unwrap();
    let manifest = manifest(artifact, preview.digest(), evaluation.digest());

    let mut registry = ConsentAwareDatasetRegistry::new();
    assert!(matches!(
        registry.require_manifest_dataset(&manifest),
        Err(DatasetRegistryError::UnregisteredManifestDataset(digest))
            if digest == preview.digest()
    ));

    let dataset = registry.build_and_register(&verifier, &members).unwrap();
    let resolved = registry
        .require_manifest_dataset(&manifest)
        .unwrap()
        .unwrap();
    assert_eq!(resolved.digest, dataset.digest());
    assert_eq!(resolved.members.len(), 1);
    assert_eq!(resolved.members[0].tenant_id, "default");
    assert_eq!(resolved.members[0].run_id, "run-train-registry");
    assert_eq!(resolved.members[0].task_id, "train-registry");
    assert_eq!(resolved.members[0].producer_id, "producer-a");
    assert_eq!(
        resolved.members[0].envelope_digest,
        members[0].envelope_digest()
    );
}

#[test]
fn d14_12_g3_revocation_excludes_future_membership_and_is_auditable() {
    let verifier = verifier();
    let members = vec![
        signed("revoked", json!({"route":"old"})),
        signed("retained", json!({"route":"current"})),
    ];
    let mut registry = ConsentAwareDatasetRegistry::new();
    let before = registry
        .build_and_register(&verifier, &members)
        .unwrap()
        .digest()
        .to_owned();
    let before_evaluation = evaluation("held-out-revocation");
    let before_manifest = manifest(b"before", &before, before_evaluation.digest());

    registry
        .revoke_run(
            "default",
            "run-revoked",
            "operator withdrew training consent",
        )
        .unwrap();
    let after = registry.build_and_register(&verifier, &members).unwrap();
    assert_ne!(after.digest(), before);
    assert_eq!(after.members().len(), 1);
    assert_eq!(after.members()[0].envelope().task_id, "retained");
    assert!(registry.is_revoked("default", "run-revoked"));
    assert!(matches!(
        registry.require_manifest_dataset(&before_manifest),
        Err(DatasetRegistryError::RegisteredDatasetContainsRevokedRun {
            tenant_id,
            run_id
        }) if tenant_id == "default" && run_id == "run-revoked"
    ));
    assert!(registry.audit().iter().any(|event| matches!(
        &event.kind,
        DatasetAuditKind::ConsentRevoked { tenant_id, run_id, .. }
            if tenant_id == "default" && run_id == "run-revoked"
    )));
    assert!(registry.audit().iter().any(|event| matches!(
        event.kind,
        DatasetAuditKind::DatasetRegistered {
            revoked_excluded: 1,
            member_count: 1,
            ..
        }
    )));
}

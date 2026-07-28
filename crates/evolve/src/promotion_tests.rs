use super::*;
use crate::verifier_crypto::sha256_hex;
use core_protocol::{RunId, TenantId};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

const SECURITY_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DURABILITY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FIXTURE_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "core-evolve-promotion-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn key(byte: u8) -> PromotionAuthorityKey {
    PromotionAuthorityKey::new(vec![byte; 32]).unwrap()
}

fn all_roles() -> BTreeSet<PromotionRole> {
    [
        PromotionRole::Bootstrap,
        PromotionRole::AdmitCandidate,
        PromotionRole::AdvanceStage,
        PromotionRole::Rollback,
    ]
    .into()
}

fn control_policy() -> PromotionControlPolicy {
    PromotionControlPolicy::new(
        PromotionGate::default(),
        StageLimits::new(20, 2, 5_000, 0, 2_000).unwrap(),
        StageLimits::new(10, 1, 2_000, 500, 1_000).unwrap(),
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
    )
    .unwrap()
}

fn promotion_anchor() -> PromotionTrustAnchor {
    PromotionTrustAnchor::new("release-owner", all_roles(), key(0x11)).unwrap()
}

fn evaluator_anchor() -> EvaluatorTrustAnchor {
    EvaluatorTrustAnchor::new("independent-evaluator", "held-out-owner", key(0x22)).unwrap()
}

fn open_authority(root: &Path, policy: &PromotionControlPolicy) -> PromotionAuthority {
    PromotionAuthority::open(
        root,
        "release-registry-a",
        policy.clone(),
        vec![promotion_anchor()],
        vec![evaluator_anchor()],
    )
    .unwrap()
}

fn authorizer(policy: &PromotionControlPolicy) -> PromotionAuthorizer {
    PromotionAuthorizer::new(
        "release-registry-a",
        policy.digest().unwrap(),
        "release-owner",
        key(0x11),
    )
    .unwrap()
}

fn evaluator() -> IndependentEvaluator {
    IndependentEvaluator::new("independent-evaluator", key(0x22)).unwrap()
}

fn policy_ref(id: &str, artifact: &[u8]) -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::router(),
        policy_id: id.into(),
        version: "1.0.0".into(),
        digest: sha256_hex(artifact),
    }
}

fn deployment(
    bundle_id: &str,
    policy: PolicyRef,
    rollback_to: Option<&str>,
    exact_bytes: Vec<u8>,
) -> DeploymentBundle {
    DeploymentBundle::new(
        PolicyBundle {
            bundle_id: bundle_id.into(),
            digest: sha256_hex(&exact_bytes),
            policies: vec![policy],
            rollback_to: rollback_to.map(str::to_owned),
        },
        exact_bytes,
    )
    .unwrap()
}

fn bootstrap(
    authority: &mut PromotionAuthority,
    authorizer: &PromotionAuthorizer,
    baseline: DeploymentBundle,
) {
    let request = PromotionRequest::bootstrap("auth-bootstrap", &baseline.bundle().digest).unwrap();
    let token = authorizer.authorize(&request).unwrap();
    authority.bootstrap(&request, &token, baseline).unwrap();
}

fn training_admission() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn evolution_verifier() -> EvolutionVerifier {
    let key = AttestationKey::new(vec![0x44; 32]).unwrap();
    EvolutionVerifier::new(
        vec![ProducerTrustAnchor::new("producer-a", TenantId::default(), key).unwrap()],
        training_admission(),
    )
    .unwrap()
}

fn training_trajectory(task_id: &str) -> SignedTrajectory {
    let key = AttestationKey::new(vec![0x44; 32]).unwrap();
    let artifact = b"training-policy";
    let policy = policy_ref("training-router", artifact);
    let mut envelope = TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId(format!("run-{task_id}")),
        tenant_id: TenantId::default(),
        task_id: task_id.into(),
        domain: "coding".into(),
        environment_digest: FIXTURE_DIGEST.into(),
        bundle: PolicyBundle {
            bundle_id: "training-bundle".into(),
            digest: FIXTURE_DIGEST.into(),
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
                observation_digest: FIXTURE_DIGEST.into(),
                candidate_set_digest: FIXTURE_DIGEST.into(),
                action: json!({"route":"safe"}),
                action_digest: FIXTURE_DIGEST.into(),
                propensity: Some(1.0),
            },
        )
        .unwrap();
    SignedTrajectory::sign("producer-a", envelope, &key).unwrap()
}

fn evaluation(task_id: &str) -> EvaluationSuite {
    EvaluationSuite::new(
        "held-out-owner",
        "suite-v1",
        vec![EvaluationTask {
            task_id: task_id.into(),
            fixture_digest: FIXTURE_DIGEST.into(),
        }],
    )
    .unwrap()
}

fn manifest(
    candidate: PolicyRef,
    training_digest: &str,
    evaluation_digest: &str,
    baseline_policy: &PolicyRef,
) -> PolicyManifest {
    PolicyManifest {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        policy: candidate,
        artifact_kind: ArtifactKind::Rules,
        artifact_locator: "registry://candidate-router@1.0.0".into(),
        parent: Some(baseline_policy.clone()),
        method: EvolutionMethod::Search,
        protocol: ProtocolRange { min: 1, max: 1 },
        required_capabilities: BTreeSet::new(),
        training_dataset_digest: Some(training_digest.into()),
        evaluation_suite_digest: evaluation_digest.into(),
        base_model: crate::BaseModelId {
            model_family: "anthropic/claude".into(),
            model_id: "claude-opus-5".into(),
            model_digest: "b".repeat(64),
        },
    }
}

/// The base model every fixture in this file is measured against.
fn candidate_base_model() -> crate::BaseModelId {
    crate::BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-5".into(),
        model_digest: "b".repeat(64),
    }
}

fn evidence(
    baseline: &PolicyRef,
    candidate: &PolicyRef,
    all_invariants_pass: bool,
) -> PromotionEvidence {
    PromotionEvidence {
        base_model: candidate_base_model(),
        baseline: baseline.clone(),
        candidate: candidate.clone(),
        paired_tasks: 100,
        task_score_delta: Interval {
            estimate: 0.1,
            lower: 0.05,
            upper: 0.2,
        },
        cost_delta_usd: Interval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        },
        latency_delta_ms: Interval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        },
        candidate_safety_violations: 0,
        candidate_policy_violations: 0,
        train_eval_overlap: false,
        replay_equivalence_passed: true,
        sandbox_suite_passed: true,
        invariant_suites: [
            ("runtime".into(), true),
            ("security".into(), all_invariants_pass),
            ("durability".into(), true),
        ]
        .into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_clean<'a>(
    authority: &mut PromotionAuthority,
    authorizer: &PromotionAuthorizer,
    verifier: &EvolutionVerifier,
    datasets: &ConsentAwareDatasetRegistry,
    dataset: &VerifiedTrainingDataset<'a>,
    suite: &EvaluationSuite,
    manifest: &PolicyManifest,
    artifact: &[u8],
    baseline_policy: &PolicyRef,
    deployment: DeploymentBundle,
    authorization_id: &str,
) {
    let verified = verifier
        .verify_candidate_inputs(manifest, artifact, Some(dataset), suite)
        .unwrap();
    let report = HeldOutEvaluation::new(
        manifest.policy.clone(),
        &verified,
        evidence(baseline_policy, &manifest.policy, true),
    )
    .unwrap();
    let signed = evaluator().sign_held_out(report).unwrap();
    let request =
        PromotionRequest::admit_candidate(authorization_id, &deployment.bundle().digest).unwrap();
    let token = authorizer.authorize(&request).unwrap();
    authority
        .admit_candidate(
            &request,
            &token,
            verifier,
            datasets,
            manifest,
            artifact,
            Some(dataset),
            suite,
            signed,
            deployment,
        )
        .unwrap();
}

fn signed_stage(
    permit: &StagePermit,
    baseline: &PolicyRef,
    candidate: &PolicyRef,
    invariants_pass: bool,
) -> SignedStageObservation {
    let traffic = match permit.stage() {
        DeploymentStage::Shadow => 0,
        DeploymentStage::Canary => 100,
        _ => unreachable!(),
    };
    let observation = StageObservation::new(
        permit,
        2,
        1,
        100,
        traffic,
        100,
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
        evidence(baseline, candidate, invariants_pass),
    )
    .unwrap();
    evaluator().sign_stage(observation).unwrap()
}

struct TestStageExecutor {
    baseline: PolicyRef,
    candidate: PolicyRef,
    invariants_pass: bool,
    calls: usize,
}

impl BoundedStageExecutor for TestStageExecutor {
    fn execute(
        &mut self,
        permit: &StagePermit,
        suite: &EvaluationSuite,
    ) -> Result<SignedStageObservation, PromotionAuthorityError> {
        assert_eq!(suite.owner_id(), "held-out-owner");
        self.calls += 1;
        Ok(signed_stage(
            permit,
            &self.baseline,
            &self.candidate,
            self.invariants_pass,
        ))
    }
}

struct CandidateFixture<'a> {
    baseline: DeploymentBundle,
    baseline_policy: PolicyRef,
    candidate: DeploymentBundle,
    manifest: PolicyManifest,
    artifact: &'a [u8],
}

fn candidate_fixture<'a>(dataset_digest: &str, suite: &EvaluationSuite) -> CandidateFixture<'a> {
    let baseline_policy = policy_ref("baseline-router", b"baseline-policy");
    let baseline = deployment(
        "baseline-bundle",
        baseline_policy.clone(),
        None,
        vec![0, 255, 7, 9, 0, 42],
    );
    let artifact: &'a [u8] = b"candidate-policy-v1";
    let candidate_policy = policy_ref("candidate-router", artifact);
    let candidate = deployment(
        "candidate-bundle",
        candidate_policy.clone(),
        Some("baseline-bundle"),
        b"candidate-deployment-exact-bytes".to_vec(),
    );
    let manifest = manifest(
        candidate_policy,
        dataset_digest,
        suite.digest(),
        &baseline_policy,
    );
    CandidateFixture {
        baseline,
        baseline_policy,
        candidate,
        manifest,
        artifact,
    }
}

#[test]
fn held_out_evidence_gathered_against_another_base_model_is_refused() {
    // The base model lives inside the signed report and is bound to the identity the authority
    // built from the verified manifest. Without that binding a signature would attest a score while
    // leaving the weights it was measured on free to differ, so a genuine evaluation of this
    // candidate under a convenient base model could be replayed as evidence under the real one.
    //
    // Everything below is honestly signed by a registered evaluator. The ONLY thing wrong is the
    // base model, which is what makes this a test of the binding rather than of the signature.
    let root = scratch("held-out-base-model");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let verifier = evolution_verifier();
    let signed_training = vec![training_trajectory("task-a")];
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let dataset = datasets
        .build_and_register(&verifier, &signed_training)
        .unwrap();
    let suite = evaluation("task-b");
    let fixture = candidate_fixture(dataset.digest(), &suite);
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, fixture.baseline.clone());

    // The attack, stated precisely: the evaluator honestly evaluated this candidate against base
    // model X and signs a fully self-consistent report saying so. It then submits that report for a
    // candidate whose manifest names base model Y. Nothing about the signature is forged, and
    // `HeldOutEvaluation::new` has nothing to object to, because the report agrees with itself. Only
    // the authority holds Y — read off the validated manifest by the verifier — and only the
    // verification-path binding can catch the mismatch.
    let honest_but_wrong_model = BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-4".into(),
        model_digest: "c".repeat(64),
    };
    assert_ne!(honest_but_wrong_model, fixture.manifest.base_model);
    let verified = VerifiedCandidateInputs {
        artifact_digest: sha256_hex(fixture.artifact),
        training_dataset_digest: Some(dataset.digest().into()),
        evaluation_suite_digest: suite.digest().into(),
        base_model: honest_but_wrong_model.clone(),
    };
    let mut consistent_evidence =
        evidence(&fixture.baseline_policy, &fixture.manifest.policy, false);
    consistent_evidence.base_model = honest_but_wrong_model.clone();

    let report = HeldOutEvaluation::new(
        fixture.manifest.policy.clone(),
        &verified,
        consistent_evidence,
    )
    .expect("the report is internally consistent; only the authority disagrees with it");
    assert_eq!(report.base_model(), &honest_but_wrong_model);
    let signed_report = evaluator().sign_held_out(report).unwrap();

    let request =
        PromotionRequest::admit_candidate("auth-base-model", &fixture.candidate.bundle().digest)
            .unwrap();
    let token = authorizer.authorize(&request).unwrap();
    assert!(
        matches!(
            authority.admit_candidate(
                &request,
                &token,
                &verifier,
                &datasets,
                &fixture.manifest,
                fixture.artifact,
                Some(&dataset),
                &suite,
                signed_report,
                fixture.candidate.clone(),
            ),
            Err(PromotionAuthorityError::IndependentEvaluationRequired)
        ),
        "a validly signed report naming a different base model must still be refused"
    );
}

#[test]
fn a_held_out_report_cannot_be_built_on_the_migration_sentinel() {
    // The other half: a manifest migrated from schema 2 records no base model at all. The verifier
    // refuses it before this point, so this asserts the report type is independently fail-closed
    // rather than relying on a check upstream of it.
    let suite = evaluation("task-b");
    let fixture = candidate_fixture(&"d".repeat(64), &suite);
    let unusable = VerifiedCandidateInputs {
        artifact_digest: sha256_hex(fixture.artifact),
        training_dataset_digest: None,
        evaluation_suite_digest: suite.digest().into(),
        base_model: BaseModelId::unspecified(),
    };
    assert!(
        HeldOutEvaluation::new(
            fixture.manifest.policy.clone(),
            &unusable,
            evidence(&fixture.baseline_policy, &fixture.manifest.policy, false),
        )
        .is_err(),
        "a held-out evaluation cannot attest anything about weights nobody recorded"
    );
}

#[test]
fn d14_13_g1_contaminated_candidate_is_blocked_before_shadow() {
    let root = scratch("held-out-overlap");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let verifier = evolution_verifier();
    let signed_training = vec![training_trajectory("same-task")];
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let dataset = datasets
        .build_and_register(&verifier, &signed_training)
        .unwrap();
    let suite = evaluation("same-task");
    let fixture = candidate_fixture(dataset.digest(), &suite);
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, fixture.baseline.clone());

    // A candidate can claim clean inputs and obtain an evaluator signature, but the authority
    // reruns the verifier against authenticated dataset membership before it appends admission.
    let forged_proof = VerifiedCandidateInputs {
        artifact_digest: sha256_hex(fixture.artifact),
        training_dataset_digest: Some(dataset.digest().into()),
        evaluation_suite_digest: suite.digest().into(),
        // The forgery under test is the contaminated dataset, not the base model, so this names the
        // honest identity. A mismatched one would be refused earlier, by a different check.
        base_model: fixture.manifest.base_model.clone(),
    };
    let report = HeldOutEvaluation::new(
        fixture.manifest.policy.clone(),
        &forged_proof,
        evidence(&fixture.baseline_policy, &fixture.manifest.policy, true),
    )
    .unwrap();
    let signed_report = evaluator().sign_held_out(report).unwrap();
    let request =
        PromotionRequest::admit_candidate("auth-contaminated", &fixture.candidate.bundle().digest)
            .unwrap();
    let token = authorizer.authorize(&request).unwrap();
    assert!(matches!(
        authority.admit_candidate(
            &request,
            &token,
            &verifier,
            &datasets,
            &fixture.manifest,
            fixture.artifact,
            Some(&dataset),
            &suite,
            signed_report,
            fixture.candidate.clone(),
        ),
        Err(PromotionAuthorityError::Verifier(
            VerifierError::DetectedTrainEvalOverlap(task)
        )) if task == "same-task"
    ));
    assert_eq!(
        authority
            .candidate_stage(&fixture.candidate.bundle().digest)
            .unwrap(),
        None
    );
    let shadow =
        PromotionRequest::enter_shadow("auth-no-shadow", &fixture.candidate.bundle().digest)
            .unwrap();
    assert!(matches!(
        authority.enter_shadow(&shadow, &authorizer.authorize(&shadow).unwrap()),
        Err(PromotionAuthorityError::CandidateNotFound)
    ));
    assert_eq!(authority.audit().unwrap().len(), 1);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn d14_13_g2_bounded_shadow_canary_and_failed_invariant_are_enforced_and_audited() {
    let root = scratch("bounded-stages");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let verifier = evolution_verifier();
    let signed_training = vec![training_trajectory("train-task")];
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let dataset = datasets
        .build_and_register(&verifier, &signed_training)
        .unwrap();
    let suite = evaluation("held-out-task");
    let fixture = candidate_fixture(dataset.digest(), &suite);
    let candidate_digest = fixture.candidate.bundle().digest.clone();
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, fixture.baseline.clone());
    admit_clean(
        &mut authority,
        &authorizer,
        &verifier,
        &datasets,
        &dataset,
        &suite,
        &fixture.manifest,
        fixture.artifact,
        &fixture.baseline_policy,
        fixture.candidate.clone(),
        "auth-admit",
    );

    let shadow_request = PromotionRequest::enter_shadow("auth-shadow", &candidate_digest).unwrap();
    let shadow = authority
        .enter_shadow(
            &shadow_request,
            &authorizer.authorize(&shadow_request).unwrap(),
        )
        .unwrap();
    assert_eq!(shadow.stage(), DeploymentStage::Shadow);
    assert_eq!(shadow.limits().max_traffic_basis_points(), 0);
    assert_eq!(shadow.limits().max_work_units(), 20);

    let canary_request =
        PromotionRequest::complete_shadow("auth-canary", &candidate_digest).unwrap();
    let mut shadow_executor = TestStageExecutor {
        baseline: fixture.baseline_policy.clone(),
        candidate: fixture.manifest.policy.clone(),
        invariants_pass: true,
        calls: 0,
    };
    let canary = authority
        .execute_shadow(
            &canary_request,
            &authorizer.authorize(&canary_request).unwrap(),
            &suite,
            &mut shadow_executor,
        )
        .unwrap();
    assert_eq!(shadow_executor.calls, 1);
    assert_eq!(canary.stage(), DeploymentStage::Canary);
    assert!(canary.limits().max_traffic_basis_points() <= 1_000);
    assert_eq!(canary.limits().max_concurrency(), 1);

    let fail_request =
        PromotionRequest::complete_canary("auth-fail-invariant", &candidate_digest).unwrap();
    let mut failing_canary_executor = TestStageExecutor {
        baseline: fixture.baseline_policy.clone(),
        candidate: fixture.manifest.policy.clone(),
        invariants_pass: false,
        calls: 0,
    };
    assert!(matches!(
        authority.execute_canary(
            &fail_request,
            &authorizer.authorize(&fail_request).unwrap(),
            &suite,
            &mut failing_canary_executor,
        ),
        Err(PromotionAuthorityError::StageRefused)
    ));
    assert_eq!(failing_canary_executor.calls, 1);
    assert_eq!(
        authority.candidate_stage(&candidate_digest).unwrap(),
        Some(DeploymentStage::Canary)
    );
    assert_eq!(
        authority.active_bundle().unwrap().unwrap().bytes(),
        fixture.baseline.bytes()
    );
    let audit = authority.audit().unwrap();
    let refused = audit.last().unwrap();
    assert_eq!(refused.authorizing_party, "release-owner");
    assert_eq!(
        refused.lineage.as_ref().unwrap().baseline_bundle_digest,
        fixture.baseline.bundle().digest
    );
    assert!(matches!(
        &refused.kind,
        PromotionAuditKind::StageRefused { refusal_codes, .. }
            if refusal_codes.contains(&"invariant_suite".to_owned())
    ));

    let pass_request =
        PromotionRequest::complete_canary("auth-promote", &candidate_digest).unwrap();
    let mut passing_canary_executor = TestStageExecutor {
        baseline: fixture.baseline_policy.clone(),
        candidate: fixture.manifest.policy.clone(),
        invariants_pass: true,
        calls: 0,
    };
    let active = authority
        .execute_canary(
            &pass_request,
            &authorizer.authorize(&pass_request).unwrap(),
            &suite,
            &mut passing_canary_executor,
        )
        .unwrap();
    assert_eq!(passing_canary_executor.calls, 1);
    assert_eq!(active.bytes(), fixture.candidate.bytes());
    assert_eq!(
        authority.candidate_stage(&candidate_digest).unwrap(),
        Some(DeploymentStage::Active)
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn d14_13_g3_rollback_and_reopen_restore_exact_prior_bundle_bytes_and_identity() {
    let root = scratch("rollback-recovery");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let verifier = evolution_verifier();
    let signed_training = vec![training_trajectory("train-task")];
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let dataset = datasets
        .build_and_register(&verifier, &signed_training)
        .unwrap();
    let suite = evaluation("held-out-task");
    let fixture = candidate_fixture(dataset.digest(), &suite);
    let candidate_digest = fixture.candidate.bundle().digest.clone();
    let baseline_bytes = fixture.baseline.bytes().to_vec();
    let baseline_identity = fixture.baseline.bundle().clone();
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, fixture.baseline.clone());
    admit_clean(
        &mut authority,
        &authorizer,
        &verifier,
        &datasets,
        &dataset,
        &suite,
        &fixture.manifest,
        fixture.artifact,
        &fixture.baseline_policy,
        fixture.candidate.clone(),
        "auth-admit-g3",
    );
    let shadow_request =
        PromotionRequest::enter_shadow("auth-shadow-g3", &candidate_digest).unwrap();
    let shadow = authority
        .enter_shadow(
            &shadow_request,
            &authorizer.authorize(&shadow_request).unwrap(),
        )
        .unwrap();
    let canary_request =
        PromotionRequest::complete_shadow("auth-canary-g3", &candidate_digest).unwrap();
    let canary = authority
        .complete_shadow(
            &canary_request,
            &authorizer.authorize(&canary_request).unwrap(),
            signed_stage(
                &shadow,
                &fixture.baseline_policy,
                &fixture.manifest.policy,
                true,
            ),
        )
        .unwrap();
    let active_request =
        PromotionRequest::complete_canary("auth-active-g3", &candidate_digest).unwrap();
    authority
        .complete_canary(
            &active_request,
            &authorizer.authorize(&active_request).unwrap(),
            signed_stage(
                &canary,
                &fixture.baseline_policy,
                &fixture.manifest.policy,
                true,
            ),
        )
        .unwrap();

    let rollback_request = PromotionRequest::rollback(
        "auth-rollback-g3",
        &candidate_digest,
        DeploymentStage::Active,
    )
    .unwrap();
    let restored = authority
        .rollback(
            &rollback_request,
            &authorizer.authorize(&rollback_request).unwrap(),
        )
        .unwrap();
    assert_eq!(restored.bytes(), baseline_bytes);
    assert_eq!(restored.bundle(), &baseline_identity);
    let journal_path = authority.journal_path().to_owned();
    drop(authority);

    let verified_length = std::fs::metadata(&journal_path).unwrap().len();
    let mut torn = std::fs::OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .unwrap();
    torn.write_all(br#"{"torn_rollback_record":"#).unwrap();
    torn.sync_all().unwrap();
    drop(torn);

    let mut reopened = open_authority(&root, &policy);
    assert_eq!(
        std::fs::metadata(&journal_path).unwrap().len(),
        verified_length,
        "reopen must discard only the unterminated tail and retain the authenticated rollback"
    );
    let recovered = reopened.active_bundle().unwrap().unwrap();
    assert_eq!(recovered.bytes(), baseline_bytes);
    assert_eq!(recovered.bundle(), &baseline_identity);
    assert_eq!(
        reopened.candidate_stage(&candidate_digest).unwrap(),
        Some(DeploymentStage::RolledBack)
    );
    assert!(matches!(
        reopened.audit().unwrap().last().unwrap().kind,
        PromotionAuditKind::RolledBack { .. }
    ));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn d14_13_g4_candidate_cannot_self_authorize_change_policy_or_relax_safety_budgets() {
    let root = scratch("candidate-denied");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let verifier = evolution_verifier();
    let signed_training = vec![training_trajectory("train-task")];
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let dataset = datasets
        .build_and_register(&verifier, &signed_training)
        .unwrap();
    let suite = evaluation("held-out-task");
    let fixture = candidate_fixture(dataset.digest(), &suite);
    let candidate_digest = fixture.candidate.bundle().digest.clone();
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, fixture.baseline.clone());
    admit_clean(
        &mut authority,
        &authorizer,
        &verifier,
        &datasets,
        &dataset,
        &suite,
        &fixture.manifest,
        fixture.artifact,
        &fixture.baseline_policy,
        fixture.candidate.clone(),
        "auth-admit-g4",
    );

    let shadow_request =
        PromotionRequest::enter_shadow("auth-self-promote", &candidate_digest).unwrap();
    let candidate_signer = PromotionAuthorizer::new(
        "release-registry-a",
        policy.digest().unwrap(),
        "candidate-router",
        key(0x99),
    )
    .unwrap();
    assert!(matches!(
        authority.enter_shadow(
            &shadow_request,
            &candidate_signer.authorize(&shadow_request).unwrap(),
        ),
        Err(PromotionAuthorityError::Unauthorized)
    ));

    let relaxed_gate = PromotionGate {
        min_paired_tasks: 1,
        ..PromotionGate::default()
    };
    let relaxed = PromotionControlPolicy::new(
        relaxed_gate,
        StageLimits::new(20, 2, 5_000, 0, 99_000).unwrap(),
        StageLimits::new(10, 1, 2_000, 1_000, 99_000).unwrap(),
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
    )
    .unwrap();
    let wrong_policy_signer = PromotionAuthorizer::new(
        "release-registry-a",
        relaxed.digest().unwrap(),
        "release-owner",
        key(0x11),
    )
    .unwrap();
    assert!(matches!(
        authority.enter_shadow(
            &shadow_request,
            &wrong_policy_signer.authorize(&shadow_request).unwrap(),
        ),
        Err(PromotionAuthorityError::Unauthorized)
    ));

    let shadow_token = authorizer.authorize(&shadow_request).unwrap();
    let shadow = authority
        .enter_shadow(&shadow_request, &shadow_token)
        .unwrap();
    assert!(matches!(
        authority.enter_shadow(&shadow_request, &shadow_token),
        Err(PromotionAuthorityError::AuthorizationReplay)
    ));

    let candidate_observation = StageObservation::new(
        &shadow,
        1,
        1,
        10,
        0,
        1,
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
        evidence(&fixture.baseline_policy, &fixture.manifest.policy, true),
    )
    .unwrap();
    let candidate_evaluator = IndependentEvaluator::new("candidate-router", key(0x99)).unwrap();
    let candidate_scored = candidate_evaluator
        .sign_stage(candidate_observation)
        .unwrap();
    let candidate_score_request =
        PromotionRequest::complete_shadow("auth-candidate-score", &candidate_digest).unwrap();
    assert!(matches!(
        authority.complete_shadow(
            &candidate_score_request,
            &authorizer.authorize(&candidate_score_request).unwrap(),
            candidate_scored,
        ),
        Err(PromotionAuthorityError::IndependentEvaluationRequired)
    ));
    assert_eq!(
        authority.candidate_stage(&candidate_digest).unwrap(),
        Some(DeploymentStage::Shadow)
    );

    let unsafe_observation = StageObservation::new(
        &shadow,
        1,
        1,
        10,
        0,
        shadow.limits().max_cost_microusd() + 1,
        FIXTURE_DIGEST,
        FIXTURE_DIGEST,
        evidence(&fixture.baseline_policy, &fixture.manifest.policy, true),
    )
    .unwrap();
    let unsafe_signed = evaluator().sign_stage(unsafe_observation).unwrap();
    let unsafe_request =
        PromotionRequest::complete_shadow("auth-unsafe-stage", &candidate_digest).unwrap();
    assert!(matches!(
        authority.complete_shadow(
            &unsafe_request,
            &authorizer.authorize(&unsafe_request).unwrap(),
            unsafe_signed,
        ),
        Err(PromotionAuthorityError::StageRefused)
    ));
    let audit = authority.audit().unwrap();
    assert!(matches!(
        &audit.last().unwrap().kind,
        PromotionAuditKind::StageRefused { refusal_codes, .. }
            if refusal_codes.contains(&"budget_policy".to_owned())
                && refusal_codes.contains(&"security_policy".to_owned())
                && refusal_codes.contains(&"durability_policy".to_owned())
    ));

    let rollback_request = PromotionRequest::rollback(
        "auth-self-rollback",
        &candidate_digest,
        DeploymentStage::Shadow,
    )
    .unwrap();
    assert!(matches!(
        authority.rollback(
            &rollback_request,
            &candidate_signer.authorize(&rollback_request).unwrap(),
        ),
        Err(PromotionAuthorityError::Unauthorized)
    ));
    assert_eq!(
        authority.candidate_stage(&candidate_digest).unwrap(),
        Some(DeploymentStage::Shadow)
    );
    assert!(format!("{:?}", key(0x11)).contains("REDACTED"));
    assert!(format!("{shadow_token:?}").contains("REDACTED"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn promotion_audit_hash_chain_detects_authorizing_party_tampering() {
    let root = scratch("audit-tamper");
    let policy = control_policy();
    let authorizer = authorizer(&policy);
    let baseline = deployment(
        "baseline-bundle",
        policy_ref("baseline-router", b"baseline-policy"),
        None,
        b"baseline-bytes".to_vec(),
    );
    let mut authority = open_authority(&root, &policy);
    bootstrap(&mut authority, &authorizer, baseline);
    let path = authority.journal_path().to_owned();
    let mut bytes = std::fs::read(&path).unwrap();
    let original = b"release-owner";
    let replacement = b"release-0wner";
    let offset = bytes
        .windows(original.len())
        .position(|window| window == original)
        .unwrap();
    bytes[offset..offset + original.len()].copy_from_slice(replacement);
    std::fs::write(path, bytes).unwrap();
    assert!(matches!(
        authority.audit(),
        Err(PromotionAuthorityError::CorruptJournal { sequence: 0 })
    ));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn promotion_authority_rejects_unbounded_contracts_and_a_second_writer() {
    assert!(matches!(
        StageLimits::new(100_001, 1, 1, 0, 1),
        Err(PromotionAuthorityError::InvalidStageLimits)
    ));
    let invalid_bundle = PolicyBundle {
        bundle_id: "too-large".into(),
        digest: sha256_hex(&vec![7; MAX_DEPLOYMENT_BUNDLE_BYTES + 1]),
        policies: vec![policy_ref("bounded", b"bounded")],
        rollback_to: None,
    };
    assert!(matches!(
        DeploymentBundle::new(invalid_bundle, vec![7; MAX_DEPLOYMENT_BUNDLE_BYTES + 1]),
        Err(PromotionAuthorityError::InvalidBundleBytes { .. })
    ));

    let root = scratch("writer-bound");
    let policy = control_policy();
    let first = open_authority(&root, &policy);
    assert!(matches!(
        PromotionAuthority::open(
            &root,
            "release-registry-a",
            policy,
            vec![promotion_anchor()],
            vec![evaluator_anchor()],
        ),
        Err(PromotionAuthorityError::WriterBusy { .. })
    ));
    drop(first);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn a_stage_observation_can_say_which_base_model_it_was_measured_on() {
    // The half of #26's "thread base_model into HeldOutEvaluation and PromotionEvidence" that an
    // adversarial review found unmet. A stage observation is signed under its own domain and is what
    // a third party actually holds; before the identity moved onto `PromotionEvidence` it could be
    // attributed only transitively, through a `pub(crate)` `CandidateIdentity` that nothing outside
    // this crate can reach. A separately-signed artefact that cannot say what it measured is not
    // evidence about any particular model.
    let baseline = policy_ref("baseline-a", b"baseline-artifact");
    let candidate = policy_ref("candidate-a", b"candidate-artifact");
    let evidence = evidence(&baseline, &candidate, true);
    assert_eq!(evidence.base_model, candidate_base_model());

    // And the same identity is reachable through both carriers, because there is only one field.
    let verified = VerifiedCandidateInputs {
        artifact_digest: "a".repeat(64),
        training_dataset_digest: None,
        evaluation_suite_digest: "c".repeat(64),
        base_model: candidate_base_model(),
    };
    let report = HeldOutEvaluation::new(candidate, &verified, evidence).unwrap();
    assert_eq!(report.base_model(), &candidate_base_model());
    assert_eq!(report.evidence().base_model, candidate_base_model());
}

#[test]
fn evidence_naming_a_different_base_model_than_the_verifier_read_is_refused() {
    // The evidence carries the identity, so an evaluator could try to name a convenient one. The
    // verifier read the real one off the validated manifest; the two must agree before anything is
    // signed, or the signature would faithfully attest whatever the evaluator felt like.
    let baseline = policy_ref("baseline-a", b"baseline-artifact");
    let candidate = policy_ref("candidate-a", b"candidate-artifact");
    let mut evidence = evidence(&baseline, &candidate, true);
    evidence.base_model = crate::BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-4".into(),
        model_digest: "c".repeat(64),
    };
    let verified = VerifiedCandidateInputs {
        artifact_digest: "a".repeat(64),
        training_dataset_digest: None,
        evaluation_suite_digest: "c".repeat(64),
        base_model: candidate_base_model(),
    };
    assert!(HeldOutEvaluation::new(candidate, &verified, evidence).is_err());
}

#[test]
fn evidence_resting_on_the_migration_sentinel_is_refused_by_both_carriers() {
    let baseline = policy_ref("baseline-a", b"baseline-artifact");
    let candidate = policy_ref("candidate-a", b"candidate-artifact");
    let mut sentinel_evidence = evidence(&baseline, &candidate, true);
    sentinel_evidence.base_model = crate::BaseModelId::unspecified();
    assert!(
        sentinel_evidence.validate_contract().is_err(),
        "a document that never recorded its base model attests nothing about one"
    );
}

use super::*;
use crate::{
    ArtifactKind, AuthenticatedHeldOutEvaluation, BaseModelId, DeploymentStage, EvolutionMethod,
    HeldOutEvaluation, IndependentEvaluator, PromotionAssessment, PromotionAuthorityKey,
    PromotionGate, ProtocolRange, TransferMetric, VerifiedCandidateInputs, transfer,
};

const BASELINE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CANDIDATE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const EVALUATION_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn model(seed: char) -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: format!("claude-{seed}"),
        model_digest: seed.to_string().repeat(64),
    }
}

fn policy(slot: StrategySlot, id: &str, digest: &str) -> PolicyRef {
    PolicyRef {
        slot,
        policy_id: id.into(),
        version: "1.0.0".into(),
        digest: digest.into(),
    }
}

fn manifest(
    policy: PolicyRef,
    base_model: BaseModelId,
    required_capabilities: BTreeSet<Capability>,
) -> PolicyManifest {
    PolicyManifest {
        schema_version: crate::EVOLUTION_SCHEMA_VERSION,
        artifact_kind: ArtifactKind::Rules,
        artifact_locator: format!("inert:sha256:{}", policy.digest),
        parent: None,
        method: EvolutionMethod::HandAuthored,
        protocol: ProtocolRange { min: 1, max: 1 },
        required_capabilities,
        training_dataset_digest: None,
        evaluation_suite_digest: EVALUATION_DIGEST.into(),
        base_model,
        policy,
    }
}

fn checkpoint(
    id: &str,
    rollback_to: Option<&str>,
    manifests: impl IntoIterator<Item = PolicyManifest>,
) -> PolicyCheckpoint {
    PolicyCheckpoint::build(
        id,
        rollback_to.map(str::to_owned),
        manifests
            .into_iter()
            .map(|manifest| (manifest.policy.slot.clone(), manifest))
            .collect(),
    )
    .unwrap()
}

fn admission(
    slots: impl IntoIterator<Item = (StrategySlot, BTreeSet<Capability>)>,
) -> BTreeMap<StrategySlot, ManifestAdmissionPolicy> {
    slots
        .into_iter()
        .map(|(slot, allowed)| (slot.clone(), ManifestAdmissionPolicy::new(slot, allowed)))
        .collect()
}

fn evidence(
    baseline: PolicyRef,
    candidate: PolicyRef,
    base_model: BaseModelId,
    delta: f64,
) -> PromotionEvidence {
    PromotionEvidence {
        baseline,
        candidate,
        base_model,
        paired_tasks: 100,
        task_score_delta: Interval {
            estimate: delta,
            lower: delta,
            upper: delta,
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
            ("security".into(), true),
            ("durability".into(), true),
        ]
        .into(),
    }
}

fn authenticated(evidence: PromotionEvidence) -> AuthenticatedHeldOutEvaluation {
    authenticated_with_inputs(evidence, CANDIDATE_DIGEST, None, EVALUATION_DIGEST)
}

fn authenticated_with_inputs(
    evidence: PromotionEvidence,
    artifact_digest: &str,
    training_dataset_digest: Option<&str>,
    evaluation_suite_digest: &str,
) -> AuthenticatedHeldOutEvaluation {
    let verified = VerifiedCandidateInputs {
        artifact_digest: artifact_digest.into(),
        training_dataset_digest: training_dataset_digest.map(str::to_owned),
        evaluation_suite_digest: evaluation_suite_digest.into(),
        base_model: evidence.base_model.clone(),
    };
    let report = HeldOutEvaluation::new(evidence.candidate.clone(), &verified, evidence).unwrap();
    let signed = IndependentEvaluator::new(
        "independent-evaluator",
        PromotionAuthorityKey::new(vec![0x22; 32]).unwrap(),
    )
    .unwrap()
    .sign_held_out(report)
    .unwrap();
    AuthenticatedHeldOutEvaluation::new(signed)
}

fn evaluation_set(
    slot: StrategySlot,
    evaluation: AuthenticatedHeldOutEvaluation,
) -> BTreeMap<StrategySlot, AuthenticatedHeldOutEvaluation> {
    [(slot, evaluation)].into()
}

#[test]
fn diff_is_slot_level_and_attributes_delta() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let before = checkpoint(
        "before",
        None,
        [manifest(baseline.clone(), model('a'), BTreeSet::new())],
    );
    let after = checkpoint(
        "after",
        Some("before"),
        [manifest(candidate.clone(), model('a'), BTreeSet::new())],
    );
    let attribution = evidence(baseline, candidate, model('a'), 0.25);
    let result = diff(&before, &after, &[(slot.clone(), attribution)].into()).unwrap();
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].slot, slot);
    assert!(result.changed[0].before.is_some());
    assert!(result.changed[0].after.is_some());
    assert_eq!(
        result.changed[0]
            .held_out_delta
            .expect("replacement has comparable evidence")
            .estimate,
        0.25
    );
}

#[test]
fn diff_reports_added_and_removed_slots_without_fabricating_delta() {
    let router = StrategySlot::router();
    let planner = StrategySlot::planner();
    let router_candidate = policy(router.clone(), "router-candidate", CANDIDATE_DIGEST);
    let planner_policy = policy(
        planner.clone(),
        "planner",
        "4444444444444444444444444444444444444444444444444444444444444444",
    );
    let planner_manifest = manifest(planner_policy, model('a'), BTreeSet::new());
    let without_router = checkpoint("without", None, [planner_manifest.clone()]);
    let with_router = checkpoint(
        "with",
        Some("without"),
        [
            planner_manifest,
            manifest(router_candidate.clone(), model('a'), BTreeSet::new()),
        ],
    );

    let added = diff(&without_router, &with_router, &BTreeMap::new()).unwrap();
    assert_eq!(added.changed.len(), 1);
    assert_eq!(added.changed[0].before, None);
    assert_eq!(added.changed[0].after, Some(router_candidate.clone()));
    assert_eq!(added.changed[0].held_out_delta, None);

    let removed = diff(&with_router, &without_router, &BTreeMap::new()).unwrap();
    assert_eq!(removed.changed.len(), 1);
    assert_eq!(removed.changed[0].before, Some(router_candidate));
    assert_eq!(removed.changed[0].after, None);
    assert_eq!(removed.changed[0].held_out_delta, None);
}

#[test]
fn merge_rejects_duplicate_slot_and_reruns_admission() {
    let slot = StrategySlot::router();
    let source = checkpoint(
        "source",
        None,
        [manifest(
            policy(slot.clone(), "candidate", CANDIDATE_DIGEST),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(
        slot.clone(),
        [Capability::ReadOnly, Capability::CodeExecuting].into(),
    )]);
    assert!(matches!(
        merge(
            "merged",
            None,
            &[source.clone(), source.clone()],
            &admissions
        ),
        Err(CheckpointAlgebraError::DuplicateSlot(_))
    ));

    let refusing = admission([(slot, BTreeSet::new())]);
    assert!(matches!(
        merge("merged", None, &[source], &refusing),
        Err(CheckpointAlgebraError::Admission(
            CapabilityAdmissionError::ExceedsSlotCeiling { .. }
        ))
    ));
}

#[test]
fn restrict_is_monotone_cannot_widen() {
    let slot = StrategySlot::router();
    let source = checkpoint(
        "source",
        None,
        [manifest(
            policy(slot.clone(), "candidate", CANDIDATE_DIGEST),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(
        slot.clone(),
        [Capability::ReadOnly, Capability::CodeExecuting].into(),
    )]);
    assert!(matches!(
        restrict(
            &source,
            "widened",
            &slot,
            [Capability::ReadOnly, Capability::CodeExecuting].into(),
            &admissions,
        ),
        Err(CheckpointAlgebraError::CapabilityWidening { .. })
    ));
    let restricted = restrict(&source, "restricted", &slot, BTreeSet::new(), &admissions).unwrap();
    assert!(
        restricted
            .checkpoint
            .manifest_for(&slot)
            .unwrap()
            .required_capabilities
            .is_empty()
    );
    assert!(restricted.checkpoint.validate().is_ok());
}

#[test]
fn retire_drops_slot_to_baseline_as_event() {
    let slot = StrategySlot::router();
    let baseline_policy = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate_policy = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let baseline = checkpoint(
        "baseline",
        None,
        [manifest(
            baseline_policy.clone(),
            model('a'),
            BTreeSet::new(),
        )],
    );
    let source = checkpoint(
        "candidate",
        Some("baseline"),
        [manifest(
            candidate_policy.clone(),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(slot.clone(), [Capability::ReadOnly].into())]);
    let retired = retire(&source, &baseline, "retired", &slot, &admissions).unwrap();
    assert_eq!(
        retired.checkpoint.bundle().rollback_to.as_deref(),
        Some("baseline")
    );
    assert_eq!(
        retired.checkpoint.bundle().policy_for(&slot),
        Some(&baseline_policy)
    );
    assert!(matches!(
        &retired.events[0],
        CheckpointEvent::Retired {
            retired,
            restored,
            ..
        } if retired == &candidate_policy && restored == &baseline_policy
    ));
    assert!(retired.checkpoint.validate().is_ok());
}

#[test]
fn transfer_reports_portable_fraction_without_offsetting_gate() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "model-a",
        Some("baseline"),
        [manifest(
            candidate.clone(),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(slot.clone(), [Capability::ReadOnly].into())]);
    let eval_a = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('a'),
        0.4,
    ));
    let eval_b = authenticated(evidence(baseline, candidate, model('b'), 0.2));
    let result = transfer(
        &source,
        &model('a'),
        &model('b'),
        &evaluation_set(slot.clone(), eval_a),
        &evaluation_set(slot.clone(), eval_b),
        &admissions,
        &PromotionGate::default(),
    )
    .unwrap();
    assert_eq!(result.metric.portable_fraction, 0.5);
    assert_eq!(
        result.target_assessment,
        PromotionAssessment::EligibleForReleaseReview {
            suggested_next: DeploymentStage::Shadow,
        }
    );
    assert_eq!(
        result
            .output
            .checkpoint
            .manifest_for(&slot)
            .unwrap()
            .base_model,
        model('b')
    );
    assert!(!result.output.fresh_held_out_required);
    assert_eq!(result.output.checkpoint.bundle().bundle_id, "model-a");
    assert!(result.output.checkpoint.validate().is_ok());
    assert!(result.output.checkpoint.deployment_bundle().is_ok());
}

#[test]
fn transfer_requires_matching_from_and_to_base_models() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "model-a",
        Some("baseline"),
        [manifest(
            candidate.clone(),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(slot.clone(), [Capability::ReadOnly].into())]);
    let eval_a = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('a'),
        0.4,
    ));
    let eval_b = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('b'),
        0.2,
    ));
    assert!(matches!(
        transfer(
            &source,
            &model('a'),
            &model('a'),
            &evaluation_set(StrategySlot::router(), eval_a.clone(),),
            &evaluation_set(StrategySlot::router(), eval_b,),
            &admissions,
            &PromotionGate::default(),
        ),
        Err(CheckpointAlgebraError::SameBaseModel)
    ));

    let wrong_target = authenticated(evidence(baseline, candidate, model('c'), 0.2));
    assert!(matches!(
        transfer(
            &source,
            &model('a'),
            &model('b'),
            &evaluation_set(StrategySlot::router(), eval_a,),
            &evaluation_set(StrategySlot::router(), wrong_target,),
            &admissions,
            &PromotionGate::default(),
        ),
        Err(CheckpointAlgebraError::EvaluationBaseModelMismatch)
    ));
}

#[test]
fn target_model_must_pass_gate_on_its_own_evidence() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "model-a",
        Some("baseline"),
        [manifest(
            candidate.clone(),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([(slot.clone(), [Capability::ReadOnly].into())]);
    let eval_a = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('a'),
        0.4,
    ));
    let mut unsafe_target = evidence(baseline, candidate, model('b'), 0.2);
    unsafe_target.candidate_safety_violations = 1;
    let refusal = transfer(
        &source,
        &model('a'),
        &model('b'),
        &evaluation_set(slot.clone(), eval_a),
        &evaluation_set(slot.clone(), authenticated(unsafe_target)),
        &admissions,
        &PromotionGate::default(),
    );
    assert!(matches!(
        refusal,
        Err(CheckpointAlgebraError::TargetGateRejected {
            slot: ref refused_slot,
            metric: TransferMetric {
                portable_fraction: 0.5,
                ..
            },
            ref reasons,
        })
            if refused_slot == &slot
                && reasons.iter().any(|reason| reason.contains("safety"))
    ));
}

#[test]
fn portable_fraction_is_reported_not_offsetting() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "model-a",
        Some("baseline"),
        [manifest(candidate.clone(), model('a'), BTreeSet::new())],
    );
    let result = transfer(
        &source,
        &model('a'),
        &model('b'),
        &evaluation_set(
            slot.clone(),
            authenticated(evidence(
                baseline.clone(),
                candidate.clone(),
                model('a'),
                0.8,
            )),
        ),
        &evaluation_set(
            slot.clone(),
            authenticated(evidence(baseline, candidate, model('b'), 0.2)),
        ),
        &admission([(slot, BTreeSet::new())]),
        &PromotionGate::default(),
    )
    .unwrap();
    assert_eq!(result.metric.portable_fraction, 0.25);
    assert_eq!(
        result.target_assessment,
        PromotionAssessment::EligibleForReleaseReview {
            suggested_next: DeploymentStage::Shadow,
        }
    );
}

#[test]
fn every_operator_output_validates_as_policy_bundle() {
    let router = StrategySlot::router();
    let planner = StrategySlot::planner();
    let router_baseline = policy(router.clone(), "router-base", BASELINE_DIGEST);
    let router_candidate = policy(router.clone(), "router-next", CANDIDATE_DIGEST);
    let planner_policy = policy(
        planner.clone(),
        "planner",
        "4444444444444444444444444444444444444444444444444444444444444444",
    );
    let baseline = checkpoint(
        "baseline",
        None,
        [
            manifest(router_baseline.clone(), model('a'), BTreeSet::new()),
            manifest(planner_policy.clone(), model('a'), BTreeSet::new()),
        ],
    );
    let router_checkpoint = checkpoint(
        "router",
        Some("baseline"),
        [manifest(
            router_candidate.clone(),
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let planner_checkpoint = checkpoint(
        "planner",
        Some("baseline"),
        [manifest(
            planner_policy,
            model('a'),
            [Capability::ReadOnly].into(),
        )],
    );
    let admissions = admission([
        (router.clone(), [Capability::ReadOnly].into()),
        (planner, [Capability::ReadOnly].into()),
    ]);
    let merged = merge(
        "merged",
        Some("baseline".into()),
        &[router_checkpoint.clone(), planner_checkpoint],
        &admissions,
    )
    .unwrap();
    let restricted = restrict(
        &router_checkpoint,
        "restricted",
        &router,
        BTreeSet::new(),
        &admissions,
    )
    .unwrap();
    let retired = retire(
        &restricted.checkpoint,
        &baseline,
        "retired",
        &router,
        &admissions,
    )
    .unwrap();
    let transferred = transfer(
        &router_checkpoint,
        &model('a'),
        &model('b'),
        &evaluation_set(
            router.clone(),
            authenticated(evidence(
                router_baseline.clone(),
                router_candidate.clone(),
                model('a'),
                0.4,
            )),
        ),
        &evaluation_set(
            router.clone(),
            authenticated(evidence(router_baseline, router_candidate, model('b'), 0.2)),
        ),
        &admissions,
        &PromotionGate::default(),
    )
    .unwrap();
    for output in [
        &merged.checkpoint,
        &restricted.checkpoint,
        &retired.checkpoint,
        &transferred.output.checkpoint,
    ] {
        output.validate().unwrap();
        output.bundle().validate().unwrap();
        let slots: BTreeSet<_> = output
            .bundle()
            .policies
            .iter()
            .map(|policy| &policy.slot)
            .collect();
        assert_eq!(slots.len(), output.bundle().policies.len());
    }
    for pending in [
        &merged.checkpoint,
        &restricted.checkpoint,
        &retired.checkpoint,
    ] {
        assert!(matches!(
            pending.deployment_bundle(),
            Err(PromotionAuthorityError::FreshHeldOutRequired)
        ));
    }
    transferred.output.checkpoint.deployment_bundle().unwrap();
}

#[test]
fn transfer_rebinds_every_slot_with_independent_evidence() {
    let router = StrategySlot::router();
    let planner = StrategySlot::planner();
    let router_baseline = policy(router.clone(), "router-baseline", BASELINE_DIGEST);
    let router_candidate = policy(router.clone(), "router-candidate", CANDIDATE_DIGEST);
    let planner_baseline = policy(
        planner.clone(),
        "planner-baseline",
        "4444444444444444444444444444444444444444444444444444444444444444",
    );
    let planner_candidate = policy(
        planner.clone(),
        "planner-candidate",
        "5555555555555555555555555555555555555555555555555555555555555555",
    );
    let source = checkpoint(
        "multi-slot",
        Some("baseline"),
        [
            manifest(router_candidate.clone(), model('a'), BTreeSet::new()),
            manifest(planner_candidate.clone(), model('a'), BTreeSet::new()),
        ],
    );
    let evaluations_a = [
        (
            router.clone(),
            authenticated_with_inputs(
                evidence(router_baseline, router_candidate, model('a'), 0.4),
                CANDIDATE_DIGEST,
                None,
                EVALUATION_DIGEST,
            ),
        ),
        (
            planner.clone(),
            authenticated_with_inputs(
                evidence(
                    planner_baseline.clone(),
                    planner_candidate.clone(),
                    model('a'),
                    0.6,
                ),
                &planner_candidate.digest,
                None,
                EVALUATION_DIGEST,
            ),
        ),
    ]
    .into();
    let evaluations_b = [
        (
            router.clone(),
            authenticated_with_inputs(
                evidence(
                    policy(router.clone(), "router-baseline", BASELINE_DIGEST),
                    policy(router.clone(), "router-candidate", CANDIDATE_DIGEST),
                    model('b'),
                    0.2,
                ),
                CANDIDATE_DIGEST,
                None,
                EVALUATION_DIGEST,
            ),
        ),
        (
            planner.clone(),
            authenticated_with_inputs(
                evidence(planner_baseline, planner_candidate.clone(), model('b'), 0.3),
                &planner_candidate.digest,
                None,
                EVALUATION_DIGEST,
            ),
        ),
    ]
    .into();
    let result = transfer(
        &source,
        &model('a'),
        &model('b'),
        &evaluations_a,
        &evaluations_b,
        &admission([
            (router.clone(), BTreeSet::new()),
            (planner.clone(), BTreeSet::new()),
        ]),
        &PromotionGate::default(),
    )
    .unwrap();
    assert_eq!(result.metric.slots.len(), 2);
    assert_eq!(result.metric.portable_fraction, 0.5);
    assert_eq!(result.output.checkpoint.bundle().bundle_id, "multi-slot");
    assert!(
        result
            .output
            .checkpoint
            .manifests()
            .values()
            .all(|manifest| manifest.base_model == model('b'))
    );
}

#[test]
fn transfer_rejects_non_finite_multi_slot_aggregate() {
    let router = StrategySlot::router();
    let planner = StrategySlot::planner();
    let router_candidate = policy(router.clone(), "router-candidate", CANDIDATE_DIGEST);
    let planner_digest = "5555555555555555555555555555555555555555555555555555555555555555";
    let planner_candidate = policy(planner.clone(), "planner-candidate", planner_digest);
    let source = checkpoint(
        "overflow",
        Some("baseline"),
        [
            manifest(router_candidate.clone(), model('a'), BTreeSet::new()),
            manifest(planner_candidate.clone(), model('a'), BTreeSet::new()),
        ],
    );
    let router_baseline = policy(router.clone(), "router-baseline", BASELINE_DIGEST);
    let planner_baseline = policy(
        planner.clone(),
        "planner-baseline",
        "4444444444444444444444444444444444444444444444444444444444444444",
    );
    let evaluations_a = [
        (
            router.clone(),
            authenticated_with_inputs(
                evidence(
                    router_baseline.clone(),
                    router_candidate.clone(),
                    model('a'),
                    f64::MAX,
                ),
                CANDIDATE_DIGEST,
                None,
                EVALUATION_DIGEST,
            ),
        ),
        (
            planner.clone(),
            authenticated_with_inputs(
                evidence(
                    planner_baseline.clone(),
                    planner_candidate.clone(),
                    model('a'),
                    f64::MAX,
                ),
                planner_digest,
                None,
                EVALUATION_DIGEST,
            ),
        ),
    ]
    .into();
    let evaluations_b = [
        (
            router.clone(),
            authenticated_with_inputs(
                evidence(router_baseline, router_candidate, model('b'), 1.0),
                CANDIDATE_DIGEST,
                None,
                EVALUATION_DIGEST,
            ),
        ),
        (
            planner.clone(),
            authenticated_with_inputs(
                evidence(planner_baseline, planner_candidate, model('b'), 1.0),
                planner_digest,
                None,
                EVALUATION_DIGEST,
            ),
        ),
    ]
    .into();

    assert!(matches!(
        transfer(
            &source,
            &model('a'),
            &model('b'),
            &evaluations_a,
            &evaluations_b,
            &admission([(router, BTreeSet::new()), (planner, BTreeSet::new()),]),
            &PromotionGate::default(),
        ),
        Err(CheckpointAlgebraError::InvalidTransferDelta)
    ));
}

#[test]
fn transfer_checks_source_model_before_reporting_a_target_refusal() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "wrong-source-model",
        Some("baseline"),
        [manifest(candidate.clone(), model('b'), BTreeSet::new())],
    );
    let evaluation_a = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('a'),
        0.4,
    ));
    let mut unsafe_target = evidence(baseline, candidate, model('b'), 0.2);
    unsafe_target.candidate_safety_violations = 1;

    assert!(matches!(
        transfer(
            &source,
            &model('a'),
            &model('b'),
            &evaluation_set(slot.clone(), evaluation_a),
            &evaluation_set(slot.clone(), authenticated(unsafe_target)),
            &admission([(slot.clone(), BTreeSet::new())]),
            &PromotionGate::default(),
        ),
        Err(CheckpointAlgebraError::ManifestBaseModelMismatch(
            ref mismatched
        )) if mismatched == &slot
    ));
}

#[test]
fn transfer_binds_artifact_dataset_and_suite_to_the_source_manifest() {
    let slot = StrategySlot::router();
    let baseline = policy(slot.clone(), "baseline", BASELINE_DIGEST);
    let candidate = policy(slot.clone(), "candidate", CANDIDATE_DIGEST);
    let source = checkpoint(
        "model-a",
        Some("baseline"),
        [manifest(candidate.clone(), model('a'), BTreeSet::new())],
    );
    let good_a = authenticated(evidence(
        baseline.clone(),
        candidate.clone(),
        model('a'),
        0.4,
    ));
    let target_evidence = evidence(baseline, candidate, model('b'), 0.2);
    for bad_b in [
        authenticated_with_inputs(
            target_evidence.clone(),
            "5555555555555555555555555555555555555555555555555555555555555555",
            None,
            EVALUATION_DIGEST,
        ),
        authenticated_with_inputs(
            target_evidence.clone(),
            CANDIDATE_DIGEST,
            Some("6666666666666666666666666666666666666666666666666666666666666666"),
            EVALUATION_DIGEST,
        ),
        authenticated_with_inputs(
            target_evidence.clone(),
            CANDIDATE_DIGEST,
            None,
            "7777777777777777777777777777777777777777777777777777777777777777",
        ),
    ] {
        assert!(matches!(
            transfer(
                &source,
                &model('a'),
                &model('b'),
                &evaluation_set(slot.clone(), good_a.clone()),
                &evaluation_set(slot.clone(), bad_b),
                &admission([(slot.clone(), BTreeSet::new())]),
                &PromotionGate::default(),
            ),
            Err(CheckpointAlgebraError::TransferIdentityMismatch)
        ));
    }
}

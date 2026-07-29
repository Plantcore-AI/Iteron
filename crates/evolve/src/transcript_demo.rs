//! One-button composition of the offline evolution path.
//!
//! This module owns no runtime handle. "Active" means only the authenticated pointer in the
//! promotion journal; every candidate is rolled back to the exact baseline before the run returns.

use crate::transcript::{
    OfflineTranscriptConfig, OfflineTranscriptResult, TranscriptEvent, TranscriptRunError,
    write_transcript,
};
use crate::transcript_demo_support as demo;
use crate::{
    ConsentAwareDatasetRegistry, DeploymentStage, HeldOutEvalReport, HeldOutEvidenceBridge,
    HeldOutEvidenceStore, HeldOutTrainingCorpus, ManifestAdmissionPolicy, PolicyManifest,
    ProducedPolicyCandidate, PromotionAuthority, PromotionAuthorityError, PromotionRequest,
    RecordedRunFixture, RecordedRunProjector, SignedHeldOutEvaluation, SignedTrajectory,
    StrategySlot, TrajectoryProjection, TrajectoryRegistry, VerifiedTrainingDataset,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const RECORDED_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/recorded-run-clean-v1.json");
const ROLLOUT_DIGEST: &str = "0722b7c0b2b2f35b340557421165459ab748e6bfa1355d30e398ebc9270439f9";

pub(crate) fn run(
    root: &Path,
    config: &OfflineTranscriptConfig,
) -> Result<OfflineTranscriptResult, TranscriptRunError> {
    if std::fs::symlink_metadata(root).is_ok() {
        return Err(TranscriptRunError::OutputAlreadyExists(root.to_path_buf()));
    }
    std::fs::create_dir(root)?;

    let mut events = Vec::new();
    let training_policy = demo::training_policy();
    let fixture = RecordedRunFixture::from_json(RECORDED_FIXTURE)?;
    let projector = RecordedRunProjector::new(vec![fixture], training_policy.clone())?;
    let envelope = projector
        .project(ROLLOUT_DIGEST)?
        .ok_or(TranscriptRunError::Invariant(
            "the admitted recorded-run fixture did not project",
        ))?;
    let projected_run_id = envelope.run_id.clone();
    let mut trajectory_registry = TrajectoryRegistry::open(&root.join("trajectory"))?;
    trajectory_registry.ingest(&envelope)?;
    let trajectory_registry_path = trajectory_registry.path().to_path_buf();
    let registered =
        trajectory_registry
            .get_by_run(&projected_run_id)?
            .ok_or(TranscriptRunError::Invariant(
                "the ingested trajectory was not readable from the verified registry",
            ))?;
    events.push(TranscriptEvent::TrajectoryProjected {
        rollout_digest: ROLLOUT_DIGEST.into(),
        run_id: registered.envelope.run_id.0.clone(),
        registry_address: registered.address.to_string(),
    });
    // From this point onward the projected value is intentionally shadowed by the envelope loaded
    // through `get_by_run`, whose scan re-verifies the registry chain and evidence bindings.
    let envelope = registered.envelope;
    let signed_trajectories = vec![SignedTrajectory::sign(
        demo::PRODUCER_ID,
        envelope,
        &demo::attestation_key(),
    )?];
    let verifier = demo::verifier();
    let mut datasets = ConsentAwareDatasetRegistry::new();
    let verified_dataset = datasets.build_and_register(&verifier, &signed_trajectories)?;
    let eligible = training_policy.admit(signed_trajectories[0].envelope())?;
    let governed_dataset = crate::GovernedTrainingDataset::new(&[eligible])?;
    if verified_dataset.digest() != governed_dataset.digest() {
        return Err(TranscriptRunError::Invariant(
            "verified and governed dataset views disagree",
        ));
    }
    events.push(TranscriptEvent::DatasetRegistered {
        digest: verified_dataset.digest().into(),
        members: verified_dataset.members().len(),
    });

    let suite = demo::evaluation_suite();
    let (baseline_policy, baseline) = demo::baseline()?;
    let control_policy = demo::control_policy();
    let authorizer = demo::authorizer(&control_policy)?;
    let authority_root = root.join("promotion");
    let mut authority = PromotionAuthority::open(
        &authority_root,
        demo::AUTHORITY_ID,
        control_policy.clone(),
        vec![demo::promotion_anchor()],
        vec![demo::evaluator_anchor()],
    )?;
    let bootstrap = PromotionRequest::bootstrap("baseline-bootstrap", &baseline.bundle().digest)?;
    authority.bootstrap(
        &bootstrap,
        &authorizer.authorize(&bootstrap)?,
        baseline.clone(),
    )?;
    // Model-specific deployment histories are independent authority domains. Reusing one journal
    // would correctly reject the transferred checkpoint because a bundle ID is unique for the
    // lifetime of that journal, even after rollback. The checkpoint keeps one logical bundle ID
    // across both models while each deployment is audited under its own authority ID.
    let target_control_policy = demo::control_policy();
    let target_authorizer = demo::target_authorizer(&target_control_policy)?;
    let target_authority_root = root.join("promotion-target");
    let mut target_authority = PromotionAuthority::open(
        &target_authority_root,
        demo::TARGET_AUTHORITY_ID,
        target_control_policy,
        vec![demo::promotion_anchor()],
        vec![demo::evaluator_anchor()],
    )?;
    let target_bootstrap =
        PromotionRequest::bootstrap("target-baseline-bootstrap", &baseline.bundle().digest)?;
    target_authority.bootstrap(
        &target_bootstrap,
        &target_authorizer.authorize(&target_bootstrap)?,
        baseline.clone(),
    )?;
    events.push(TranscriptEvent::BaselineBootstrapped {
        bundle_digest: baseline.bundle().digest.clone(),
    });

    let admission = demo::admission(&baseline_policy);
    let promotion_parties = BTreeSet::from([demo::PROMOTION_PARTY.to_owned()]);
    let corpus = HeldOutTrainingCorpus::from_verified(&verified_dataset);
    let mut evidence_store = HeldOutEvidenceStore::new();
    let source_model = config.source_base_model().clone();
    let target_model = config.target_base_model().clone();
    let primary_kind = config.primary_producer();
    let secondary_kind = config.secondary_producer();
    let primary_source_label = format!("{}-{}", primary_kind.as_str(), source_model.model_id);
    let primary_target_label = format!("{}-{}", primary_kind.as_str(), target_model.model_id);
    let transfer_label = format!("{primary_source_label}-to-{}", target_model.model_id);
    let secondary_source_label = format!("{}-{}", secondary_kind.as_str(), source_model.model_id);

    let primary = demo::produce_candidate(
        primary_kind,
        &governed_dataset,
        &admission,
        &suite,
        &baseline_policy,
        source_model.clone(),
        primary_kind.as_str(),
    )?;
    push_produced(&primary_source_label, &primary, &mut events);
    let primary_checkpoint = demo::checkpoint(
        &format!("{primary_source_label}-bundle"),
        primary.manifest(),
    )?;
    let signed_a = register_evidence(
        &mut evidence_store,
        &primary,
        primary.manifest(),
        primary.artifact_bytes(),
        &verifier,
        &verified_dataset,
        &corpus,
        &suite,
        demo::held_out_report(
            &suite,
            &baseline_policy,
            &primary.manifest().policy,
            0.125,
            0,
        ),
        &promotion_parties,
    )?;
    demo::promote_and_rollback(
        &primary_source_label,
        &mut authority,
        &authorizer,
        &verifier,
        &datasets,
        &verified_dataset,
        &suite,
        primary.manifest(),
        primary.artifact_bytes(),
        &signed_a,
        primary_checkpoint.deployment_bundle()?,
        &mut events,
    )?;

    let mut rebound_manifest = primary.manifest().clone();
    rebound_manifest.base_model = target_model.clone();
    let target_report =
        crate::transcript_target_fixture::load(&suite, &baseline_policy, &rebound_manifest.policy)?;
    let signed_b = register_evidence(
        &mut evidence_store,
        &primary,
        &rebound_manifest,
        primary.artifact_bytes(),
        &verifier,
        &verified_dataset,
        &corpus,
        &suite,
        target_report,
        &promotion_parties,
    )?;
    let admissions: BTreeMap<StrategySlot, ManifestAdmissionPolicy> =
        [(StrategySlot::router(), admission.clone())].into();
    let authenticated_a = authority.authenticate_held_out(&suite, signed_a.clone())?;
    let authenticated_b = target_authority.authenticate_held_out(&suite, signed_b.clone())?;
    let transfer_slot = StrategySlot::router();
    let evaluations_a = [(transfer_slot.clone(), authenticated_a.clone())].into();
    let evaluations_b = [(transfer_slot.clone(), authenticated_b)].into();
    let transferred = crate::transfer(
        &primary_checkpoint,
        &source_model,
        &target_model,
        &evaluations_a,
        &evaluations_b,
        &admissions,
        &crate::PromotionGate::default(),
    )?;
    if !(0.0..=1.0).contains(&transferred.metric.portable_fraction)
        || !matches!(
            transferred.target_assessment,
            crate::PromotionAssessment::EligibleForReleaseReview {
                suggested_next: DeploymentStage::Shadow
            }
        )
        || transferred.output.checkpoint.bundle().bundle_id != primary_checkpoint.bundle().bundle_id
    {
        return Err(TranscriptRunError::Invariant(
            "target-model transfer did not preserve identity with a separately eligible gain",
        ));
    }
    events.push(TranscriptEvent::TransferReported {
        label: transfer_label.clone(),
        bundle_id: primary_checkpoint.bundle().bundle_id.clone(),
        source_bundle_digest: primary_checkpoint.bundle().digest.clone(),
        target_bundle_digest: transferred.output.checkpoint.bundle().digest.clone(),
        from_model: Box::new(source_model.clone()),
        to_model: Box::new(target_model.clone()),
        source_delta: transferred.metric.source_delta,
        target_delta: transferred.metric.target_delta,
        retained_delta: transferred.metric.retained_delta,
        portable_fraction: transferred.metric.portable_fraction,
        target_gate_eligible: true,
        target_evaluation_fixture: crate::transcript_target_fixture::TARGET_OBSERVATION_ID.into(),
    });
    let transferred_manifest = transferred
        .output
        .checkpoint
        .manifest_for(&StrategySlot::router())
        .ok_or(TranscriptRunError::Invariant(
            "transferred checkpoint lost the router manifest",
        ))?
        .clone();
    demo::promote_and_rollback(
        &primary_target_label,
        &mut target_authority,
        &target_authorizer,
        &verifier,
        &datasets,
        &verified_dataset,
        &suite,
        &transferred_manifest,
        primary.artifact_bytes(),
        &signed_b,
        transferred.output.checkpoint.deployment_bundle()?,
        &mut events,
    )?;

    let unsafe_target_report = crate::transcript_target_fixture::load_unsafe(
        &suite,
        &baseline_policy,
        &rebound_manifest.policy,
    )?;
    let mut unsafe_evidence_store = HeldOutEvidenceStore::new();
    let unsafe_target = register_evidence(
        &mut unsafe_evidence_store,
        &primary,
        &rebound_manifest,
        primary.artifact_bytes(),
        &verifier,
        &verified_dataset,
        &corpus,
        &suite,
        unsafe_target_report,
        &promotion_parties,
    )?;
    let unsafe_target_label = format!("{primary_target_label}-unsafe");
    let unsafe_target_bundle_id = format!("{unsafe_target_label}-bundle");
    let unsafe_target_checkpoint = demo::checkpoint(&unsafe_target_bundle_id, &rebound_manifest)?;
    let unsafe_target_deployment = unsafe_target_checkpoint.deployment_bundle()?;
    let unsafe_target_request = PromotionRequest::admit_candidate(
        format!("{unsafe_target_label}-admit"),
        &unsafe_target_deployment.bundle().digest,
    )?;
    match target_authority.admit_candidate(
        &unsafe_target_request,
        &target_authorizer.authorize(&unsafe_target_request)?,
        &verifier,
        &datasets,
        &rebound_manifest,
        primary.artifact_bytes(),
        Some(&verified_dataset),
        &suite,
        unsafe_target.clone(),
        unsafe_target_deployment,
    ) {
        Err(PromotionAuthorityError::PromotionRefused { .. }) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(TranscriptRunError::Invariant(
                "promotion authority admitted unsafe target-model evidence",
            ));
        }
    }
    let authenticated_unsafe_target =
        target_authority.authenticate_held_out(&suite, unsafe_target)?;
    let unsafe_evaluations_b = [(transfer_slot, authenticated_unsafe_target)].into();
    match crate::transfer(
        &primary_checkpoint,
        &source_model,
        &target_model,
        &evaluations_a,
        &unsafe_evaluations_b,
        &admissions,
        &crate::PromotionGate::default(),
    ) {
        Err(crate::CheckpointAlgebraError::TargetGateRejected { metric, .. }) => {
            events.push(TranscriptEvent::TransferReported {
                label: format!("{transfer_label}-unsafe"),
                bundle_id: primary_checkpoint.bundle().bundle_id.clone(),
                source_bundle_digest: primary_checkpoint.bundle().digest.clone(),
                target_bundle_digest: transferred.output.checkpoint.bundle().digest.clone(),
                from_model: Box::new(source_model.clone()),
                to_model: Box::new(target_model.clone()),
                source_delta: metric.source_delta,
                target_delta: metric.target_delta,
                retained_delta: metric.retained_delta,
                portable_fraction: metric.portable_fraction,
                target_gate_eligible: false,
                target_evaluation_fixture:
                    crate::transcript_target_fixture::TARGET_UNSAFE_OBSERVATION_ID.into(),
            });
            events.push(TranscriptEvent::CandidateRefused {
                label: unsafe_target_label,
                reason: "target_model_safety_violation".into(),
            });
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(TranscriptRunError::Invariant(
                "unsafe target-model evidence produced a transferable checkpoint",
            ));
        }
    }

    crate::transcript_safety::exercise_safety_refusal(
        &governed_dataset,
        &admission,
        &suite,
        &baseline_policy,
        source_model.clone(),
        &verifier,
        &datasets,
        &verified_dataset,
        &corpus,
        &promotion_parties,
        &mut evidence_store,
        &mut authority,
        &authorizer,
        &mut events,
    )?;

    let secondary = demo::produce_candidate(
        secondary_kind,
        &governed_dataset,
        &admission,
        &suite,
        &baseline_policy,
        source_model,
        secondary_kind.as_str(),
    )?;
    push_produced(&secondary_source_label, &secondary, &mut events);
    let secondary_checkpoint = demo::checkpoint(
        &format!("{secondary_source_label}-bundle"),
        secondary.manifest(),
    )?;
    let secondary_signed = register_evidence(
        &mut evidence_store,
        &secondary,
        secondary.manifest(),
        secondary.artifact_bytes(),
        &verifier,
        &verified_dataset,
        &corpus,
        &suite,
        demo::held_out_report(
            &suite,
            &baseline_policy,
            &secondary.manifest().policy,
            0.125,
            0,
        ),
        &promotion_parties,
    )?;
    demo::promote_and_rollback(
        &secondary_source_label,
        &mut authority,
        &authorizer,
        &verifier,
        &datasets,
        &verified_dataset,
        &suite,
        secondary.manifest(),
        secondary.artifact_bytes(),
        &secondary_signed,
        secondary_checkpoint.deployment_bundle()?,
        &mut events,
    )?;
    let source_audit = authority.audit()?;
    events.push(crate::transcript_method_proof::prove(
        &primary,
        &secondary,
        signed_a.report().evidence(),
        secondary_signed.report().evidence(),
        &source_audit,
        &primary_checkpoint.bundle().bundle_id,
        &secondary_checkpoint.bundle().bundle_id,
    )?);

    let final_active = demo::require_restored_baseline(&mut authority, &baseline)?;
    let promotion_journal_path = authority.journal_path().to_path_buf();
    demo::require_restored_baseline(&mut target_authority, &baseline)?;
    let target_promotion_journal_path = target_authority.journal_path().to_path_buf();
    events.push(TranscriptEvent::Completed {
        promotion_journal: "promotion/promotion-authority.jsonl".into(),
        target_promotion_journal: "promotion-target/promotion-authority.jsonl".into(),
        final_active_bundle_digest: final_active.bundle().digest.clone(),
    });

    let transcript_path = root.join("offline-transcript.jsonl");
    write_transcript(&transcript_path, &events)?;
    Ok(OfflineTranscriptResult {
        transcript_path,
        promotion_journal_path,
        target_promotion_journal_path,
        trajectory_registry_path,
        event_count: events.len(),
        final_active_bundle_digest: final_active.bundle().digest.clone(),
    })
}

pub(super) fn push_produced(
    label: &str,
    candidate: &ProducedPolicyCandidate,
    events: &mut Vec<TranscriptEvent>,
) {
    let (method, artifact_kind) = demo::method_and_kind(candidate);
    events.push(TranscriptEvent::CandidateProduced {
        label: label.into(),
        policy_digest: candidate.candidate_digest().into(),
        method,
        artifact_kind,
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn register_evidence<'a>(
    store: &mut HeldOutEvidenceStore,
    carrier: &ProducedPolicyCandidate,
    manifest: &PolicyManifest,
    artifact: &[u8],
    verifier: &crate::EvolutionVerifier,
    dataset: &VerifiedTrainingDataset<'a>,
    corpus: &HeldOutTrainingCorpus,
    suite: &crate::EvaluationSuite,
    report: HeldOutEvalReport,
    promotion_parties: &BTreeSet<String>,
) -> Result<SignedHeldOutEvaluation, TranscriptRunError> {
    if manifest.policy != carrier.manifest().policy {
        return Err(TranscriptRunError::Invariant(
            "candidate carrier and rebound manifest disagree on policy identity",
        ));
    }
    let verified = verifier.verify_candidate_inputs(manifest, artifact, Some(dataset), suite)?;
    store.register(
        report,
        &manifest.policy,
        &verified,
        Some(corpus),
        suite,
        &demo::evaluator(),
        promotion_parties,
    )?;
    store
        .evidence_for(&manifest.policy.digest, &manifest.base_model)?
        .ok_or(TranscriptRunError::Invariant(
            "registered held-out evidence was not discoverable",
        ))
}

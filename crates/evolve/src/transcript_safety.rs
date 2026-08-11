//! Deliberate refusal cases exercised by the offline transcript demonstration.

use crate::transcript::{TranscriptEvent, TranscriptRunError};
use crate::transcript_demo::{push_produced, register_evidence};
use crate::transcript_demo_support as demo;
use crate::{
    ConsentAwareDatasetRegistry, GovernedTrainingDataset, HeldOutBridgeError, HeldOutEvidenceStore,
    HeldOutTrainingCorpus, IndependentEvaluator, ManifestAdmissionPolicy, PolicyRef,
    PromotionAuthority, PromotionAuthorityError, PromotionAuthorizer, PromotionRequest,
    VerifiedTrainingDataset,
};
use std::collections::BTreeSet;

#[allow(clippy::too_many_arguments)]
pub(super) fn exercise_safety_refusal<'a>(
    governed_dataset: &GovernedTrainingDataset<'_>,
    admission: &ManifestAdmissionPolicy,
    suite: &crate::EvaluationSuite,
    baseline_policy: &PolicyRef,
    base_model: crate::BaseModelId,
    verifier: &crate::EvolutionVerifier,
    datasets: &ConsentAwareDatasetRegistry,
    dataset: &VerifiedTrainingDataset<'a>,
    corpus: &HeldOutTrainingCorpus,
    promotion_parties: &BTreeSet<String>,
    store: &mut HeldOutEvidenceStore,
    authority: &mut PromotionAuthority,
    authorizer: &PromotionAuthorizer,
    events: &mut Vec<TranscriptEvent>,
) -> Result<(), TranscriptRunError> {
    let candidate = demo::rule_candidate(
        governed_dataset,
        admission,
        suite,
        baseline_policy,
        base_model,
        "unsafe",
    )?;
    datasets.persist_candidate(&candidate)?;
    push_produced("unsafe-rule", &candidate, events);
    let verified = verifier.verify_candidate_inputs(
        candidate.manifest(),
        candidate.artifact_bytes(),
        Some(dataset),
        suite,
    )?;
    let promotion_signer = IndependentEvaluator::new(demo::PROMOTION_PARTY, demo::key(0x11))?;
    match store.register(
        demo::held_out_report(
            suite,
            baseline_policy,
            &candidate.manifest().policy,
            0.125,
            1,
        ),
        &candidate.manifest().policy,
        &verified,
        Some(corpus),
        suite,
        &promotion_signer,
        promotion_parties,
    ) {
        Err(HeldOutBridgeError::EvaluatorIsPromotionParty(_)) => {
            events.push(TranscriptEvent::CandidateRefused {
                label: "promotion-party-held-out-signer".into(),
                reason: "independent_evaluator_required".into(),
            });
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(TranscriptRunError::Invariant(
                "promotion party signed held-out evidence",
            ));
        }
    }

    let held_out = register_evidence(
        store,
        &candidate,
        candidate.manifest(),
        candidate.artifact_bytes(),
        verifier,
        dataset,
        corpus,
        suite,
        demo::held_out_report(
            suite,
            baseline_policy,
            &candidate.manifest().policy,
            0.125,
            1,
        ),
        promotion_parties,
    )?;
    let checkpoint = demo::checkpoint("unsafe-rule-bundle", candidate.manifest())?;
    let deployment = checkpoint.deployment_bundle()?;
    let producer_signed = IndependentEvaluator::new(demo::PRODUCER_ID, demo::key(0x44))?
        .sign_held_out(held_out.report().clone())?;
    let producer_request = PromotionRequest::admit_candidate(
        "unsafe-rule-producer-signer",
        &deployment.bundle().digest,
    )?;
    match authority.admit_candidate(
        &producer_request,
        &authorizer.authorize(&producer_request)?,
        verifier,
        datasets,
        candidate.manifest(),
        candidate.artifact_bytes(),
        Some(dataset),
        suite,
        producer_signed,
        deployment.clone(),
    ) {
        Err(PromotionAuthorityError::IndependentEvaluationRequired) => {
            events.push(TranscriptEvent::CandidateRefused {
                label: "producer-anchor-held-out-signer".into(),
                reason: "independent_evaluator_required_by_authority".into(),
            });
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(TranscriptRunError::Invariant(
                "promotion authority accepted held-out evidence signed with the producer key",
            ));
        }
    }

    let request =
        PromotionRequest::admit_candidate("unsafe-rule-admit", &deployment.bundle().digest)?;
    match authority.admit_candidate(
        &request,
        &authorizer.authorize(&request)?,
        verifier,
        datasets,
        candidate.manifest(),
        candidate.artifact_bytes(),
        Some(dataset),
        suite,
        held_out,
        deployment,
    ) {
        Err(PromotionAuthorityError::PromotionRefused { .. }) => {
            events.push(TranscriptEvent::CandidateRefused {
                label: "unsafe-rule".into(),
                reason: "candidate_safety_violation".into(),
            });
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(TranscriptRunError::Invariant(
            "candidate with a safety violation was admitted",
        )),
    }
}

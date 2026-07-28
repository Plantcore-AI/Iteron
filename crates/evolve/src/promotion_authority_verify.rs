//! Deny-by-default executing authority for the offline promotion journal.
//!
//! This is not connected to the runtime kernel and has no policy loader.  Its "activation" is an
//! audited offline active-bundle pointer whose exact bytes can be handed to a separate human-owned
//! release process.

use crate::promotion::{EvaluatorTrustAnchor, PromotionAuthorityError};
use crate::promotion_auth::{
    PromotionAuthorization, PromotionOperation, PromotionRequest, authorization_signature,
};
use crate::promotion_evaluation::{
    SignedHeldOutEvaluation, SignedStageObservation, StagePermit, evaluation_signature,
    held_out_domain, stage_result_domain,
};
use crate::promotion_journal::{CandidateIdentity, JournalContent, JournalEvent, RefusalCode};
use crate::promotion_state::AuthorityState;
use crate::verifier_crypto::constant_time_eq;
use crate::{DeploymentBundle, DeploymentStage, EvaluationSuite, PromotionAssessment};
use std::collections::BTreeSet;

use crate::promotion_authority::PromotionAuthority;

impl PromotionAuthority {
    pub(crate) fn refresh(&mut self) -> Result<(), PromotionAuthorityError> {
        let records = self.journal.records()?;
        let mut state = AuthorityState::default();
        for record in records {
            self.verify_record_authorization(&record.content)?;
            match &record.content.event {
                JournalEvent::CandidateAdmitted {
                    identity,
                    held_out_attestation,
                    ..
                } => {
                    let active_digest = state
                        .active_bundle_digest
                        .as_ref()
                        .ok_or(PromotionAuthorityError::MissingBaseline)?;
                    let active = state
                        .bundles
                        .get(active_digest)
                        .ok_or(PromotionAuthorityError::MissingBaseline)?;
                    let baseline_policy = active
                        .bundle()
                        .policy_for(&identity.candidate_policy.slot)
                        .ok_or(PromotionAuthorityError::LineageMismatch)?;
                    self.verify_held_out_without_suite(
                        identity,
                        baseline_policy,
                        held_out_attestation,
                    )?;
                }
                JournalEvent::StageTransition {
                    candidate_bundle_digest,
                    from,
                    to,
                    stage_attestation: Some(observation),
                    ..
                } => {
                    let candidate = state
                        .candidates
                        .get(candidate_bundle_digest)
                        .ok_or(PromotionAuthorityError::CandidateNotFound)?;
                    let permit = candidate
                        .permit
                        .as_ref()
                        .ok_or(PromotionAuthorityError::StageMismatch)?;
                    if candidate.stage != *from
                        || !self
                            .stage_refusal_codes(&state, candidate, permit, *to, observation)?
                            .is_empty()
                    {
                        return Err(PromotionAuthorityError::CorruptJournal {
                            sequence: record.sequence,
                        });
                    }
                }
                JournalEvent::StageRefused {
                    candidate_bundle_digest,
                    stage,
                    codes,
                    stage_attestation,
                } => {
                    let candidate = state
                        .candidates
                        .get(candidate_bundle_digest)
                        .ok_or(PromotionAuthorityError::CandidateNotFound)?;
                    let permit = candidate
                        .permit
                        .as_ref()
                        .ok_or(PromotionAuthorityError::StageMismatch)?;
                    let target = match stage {
                        DeploymentStage::Shadow => DeploymentStage::Canary,
                        DeploymentStage::Canary => DeploymentStage::Active,
                        _ => return Err(PromotionAuthorityError::StageMismatch),
                    };
                    if &self.stage_refusal_codes(
                        &state,
                        candidate,
                        permit,
                        target,
                        stage_attestation,
                    )? != codes
                    {
                        return Err(PromotionAuthorityError::CorruptJournal {
                            sequence: record.sequence,
                        });
                    }
                }
                _ => {}
            }
            state.apply(&record)?;
        }
        self.state = state;
        Ok(())
    }

    pub(crate) fn verify_record_authorization(
        &self,
        content: &JournalContent,
    ) -> Result<(), PromotionAuthorityError> {
        if content.authority_id != self.authority_id || content.policy_digest != self.policy_digest
        {
            return Err(PromotionAuthorityError::Unauthorized);
        }
        let authorization = PromotionAuthorization {
            party_id: content.authorizing_party.clone(),
            signature: content.authorization_signature.clone(),
        };
        self.verify_authorization(&content.request, &authorization)
    }

    pub(crate) fn prepare_authorized(
        &self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        operation: PromotionOperation,
    ) -> Result<(), PromotionAuthorityError> {
        if request.operation() != operation {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        if self
            .state
            .used_authorizations
            .contains(request.authorization_id())
        {
            return Err(PromotionAuthorityError::AuthorizationReplay);
        }
        self.verify_authorization(request, authorization)
    }

    pub(crate) fn verify_authorization(
        &self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
    ) -> Result<(), PromotionAuthorityError> {
        request.validate()?;
        let anchor = self
            .promotion_anchors
            .get(&authorization.party_id)
            .ok_or(PromotionAuthorityError::Unauthorized)?;
        if !anchor.roles.contains(&request.operation().required_role()) {
            return Err(PromotionAuthorityError::Unauthorized);
        }
        let expected =
            authorization_signature(anchor, &self.authority_id, &self.policy_digest, request)?;
        if !constant_time_eq(expected.as_bytes(), authorization.signature.as_bytes()) {
            return Err(PromotionAuthorityError::Unauthorized);
        }
        Ok(())
    }

    pub(crate) fn verify_held_out(
        &self,
        identity: &CandidateIdentity,
        baseline_policy: &crate::PolicyRef,
        suite: &EvaluationSuite,
        signed: &SignedHeldOutEvaluation,
    ) -> Result<(), PromotionAuthorityError> {
        if suite.owner_id() != identity.evaluation_owner_id
            || suite.digest() != identity.evaluation_suite_digest
        {
            return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
        }
        self.verify_held_out_without_suite(identity, baseline_policy, signed)
    }

    pub(crate) fn verify_held_out_without_suite(
        &self,
        identity: &CandidateIdentity,
        baseline_policy: &crate::PolicyRef,
        signed: &SignedHeldOutEvaluation,
    ) -> Result<(), PromotionAuthorityError> {
        let anchor = self.require_evaluator(&signed.evaluator_id, &identity.evaluation_owner_id)?;
        let expected = evaluation_signature(anchor, held_out_domain(), &signed.report)?;
        if signed.evaluator_id == identity.candidate_policy.policy_id
            || signed.evaluator_id == identity.bundle_id
            || !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes())
            || signed.report.candidate != identity.candidate_policy
            || signed.report.artifact_digest != identity.artifact_digest
            || signed.report.training_dataset_digest != identity.training_dataset_digest
            || signed.report.evaluation_suite_digest != identity.evaluation_suite_digest
            // Evidence gathered against one set of weights says nothing about another, so the base
            // model inside the signed report must be the one the verifier read off the manifest.
            // Without this the signature would attest a number while leaving the weights it was
            // measured on free to differ, and a genuine evaluation of the candidate under a
            // convenient base model could be replayed as evidence under the real one.
            || signed.report.base_model() != &identity.base_model
            || signed.report.evidence.baseline != *baseline_policy
            || signed.report.evidence.candidate != identity.candidate_policy
        {
            return Err(PromotionAuthorityError::IndependentEvaluationRequired);
        }
        match self
            .policy
            .gate()
            .assess(DeploymentStage::Candidate, &signed.report.evidence)
        {
            PromotionAssessment::EligibleForReleaseReview {
                suggested_next: DeploymentStage::Shadow,
            } => Ok(()),
            PromotionAssessment::Reject { reasons } => {
                Err(PromotionAuthorityError::PromotionRefused { reasons })
            }
            _ => Err(PromotionAuthorityError::PromotionRefused {
                reasons: vec!["assessor did not return the authorized next stage".into()],
            }),
        }
    }

    pub(crate) fn stage_refusal_codes(
        &self,
        state: &AuthorityState,
        candidate: &crate::promotion_state::CandidateState,
        permit: &StagePermit,
        target: DeploymentStage,
        signed: &SignedStageObservation,
    ) -> Result<Vec<RefusalCode>, PromotionAuthorityError> {
        let anchor = self.require_evaluator(
            &signed.evaluator_id,
            &candidate.identity.evaluation_owner_id,
        )?;
        let expected = evaluation_signature(anchor, stage_result_domain(), &signed.observation)?;
        // The same self-evaluation refusal the held-out path performs, which this path did not.
        // `PromotionAuthority::open` refuses an evaluator id that collides with a PROMOTION party
        // id, never one that collides with a candidate, and nothing requires the stage signer to be
        // the evaluator that admitted the candidate — so an anchor registered under the candidate's
        // own policy id or bundle id could sign both of its stage observations. A review drove
        // exactly that all the way to `Active`: the candidate signed its own promotion.
        //
        // docs/spec/evolution.md §6.7 states "producer 不能伪造自己的晋升" as a property of promotion
        // as a whole, not of one of its two paths.
        if signed.evaluator_id == candidate.identity.candidate_policy.policy_id
            || signed.evaluator_id == candidate.identity.bundle_id
            || !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes())
        {
            return Err(PromotionAuthorityError::IndependentEvaluationRequired);
        }
        let observation = &signed.observation;
        let mut codes = BTreeSet::new();
        let stage_traffic_invalid = match permit.stage {
            DeploymentStage::Shadow => observation.traffic_basis_points != 0,
            DeploymentStage::Canary => observation.traffic_basis_points == 0,
            _ => true,
        };
        if observation.permit_digest != permit.digest
            || observation.candidate_bundle_digest != permit.candidate_bundle_digest
            || observation.stage != permit.stage
            || observation.executed_work_units == 0
            || observation.executed_work_units > permit.limits.max_work_units()
            || observation.peak_concurrency == 0
            || observation.peak_concurrency > permit.limits.max_concurrency()
            || observation.duration_ms == 0
            || observation.duration_ms > permit.limits.max_duration_ms()
            || observation.traffic_basis_points > permit.limits.max_traffic_basis_points()
            || stage_traffic_invalid
        {
            codes.insert(RefusalCode::StageBounds);
        }
        if observation.cost_microusd > permit.limits.max_cost_microusd() {
            codes.insert(RefusalCode::BudgetPolicy);
        }
        if observation.applied_security_policy_digest != permit.security_policy_digest {
            codes.insert(RefusalCode::SecurityPolicy);
        }
        if observation.applied_durability_policy_digest != permit.durability_policy_digest {
            codes.insert(RefusalCode::DurabilityPolicy);
        }
        let evidence = &observation.evidence;
        if evidence.baseline != self.baseline_policy_for(state, &candidate.identity)?
            || evidence.candidate != candidate.identity.candidate_policy
            // The same binding the held-out path performs eight functions up, and for the same
            // reason. Without it the stage path accepts an observation measured on a DIFFERENT base
            // model and advances the candidate — a review reproduced exactly that, all the way to
            // Canary. `StageObservation::new` only calls `validate_contract`, which asks whether the
            // identity is well-formed and admissible, never whether it is the RIGHT one. The
            // signature is honest either way; only the authority holds what the verifier read off
            // the validated manifest.
            || evidence.base_model != candidate.identity.base_model
        {
            codes.insert(RefusalCode::InvariantSuite);
        }
        match self.policy.gate().assess(candidate.stage, evidence) {
            PromotionAssessment::EligibleForReleaseReview { suggested_next }
                if suggested_next == target => {}
            PromotionAssessment::Reject { .. } => {
                let invariant_failed = evidence.candidate_safety_violations > 0
                    || evidence.candidate_policy_violations > 0
                    || evidence.train_eval_overlap
                    || (self.policy.gate().require_replay_equivalence
                        && !evidence.replay_equivalence_passed)
                    || (self.policy.gate().require_sandbox_suite && !evidence.sandbox_suite_passed)
                    || self
                        .policy
                        .gate()
                        .required_invariant_suites
                        .iter()
                        .any(|suite| evidence.invariant_suites.get(suite) != Some(&true));
                codes.insert(if invariant_failed {
                    RefusalCode::InvariantSuite
                } else {
                    RefusalCode::PromotionThreshold
                });
            }
            _ => {
                codes.insert(RefusalCode::PromotionThreshold);
            }
        }
        Ok(codes.into_iter().collect())
    }

    pub(crate) fn require_evaluator(
        &self,
        evaluator_id: &str,
        owner_id: &str,
    ) -> Result<&EvaluatorTrustAnchor, PromotionAuthorityError> {
        let anchor = self
            .evaluator_anchors
            .get(evaluator_id)
            .ok_or(PromotionAuthorityError::IndependentEvaluationRequired)?;
        if anchor.suite_owner_id != owner_id {
            return Err(PromotionAuthorityError::IndependentEvaluationRequired);
        }
        Ok(anchor)
    }

    pub(crate) fn baseline_policy_for(
        &self,
        state: &AuthorityState,
        identity: &CandidateIdentity,
    ) -> Result<crate::PolicyRef, PromotionAuthorityError> {
        state
            .bundles
            .get(&identity.baseline_bundle_digest)
            .and_then(|bundle| bundle.bundle().policy_for(&identity.candidate_policy.slot))
            .cloned()
            .ok_or(PromotionAuthorityError::LineageMismatch)
    }

    pub(crate) fn require_stage(
        &self,
        digest: &str,
        stage: DeploymentStage,
    ) -> Result<&crate::promotion_state::CandidateState, PromotionAuthorityError> {
        let candidate = self
            .state
            .candidates
            .get(digest)
            .ok_or(PromotionAuthorityError::CandidateNotFound)?;
        if candidate.stage != stage {
            return Err(PromotionAuthorityError::StageMismatch);
        }
        if matches!(
            stage,
            DeploymentStage::Candidate | DeploymentStage::Shadow | DeploymentStage::Canary
        ) && self.state.active_bundle_digest.as_deref()
            != Some(candidate.identity.baseline_bundle_digest.as_str())
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        Ok(candidate)
    }

    pub(crate) fn active_bundle_ref(&self) -> Result<&DeploymentBundle, PromotionAuthorityError> {
        self.state
            .active_bundle_digest
            .as_ref()
            .and_then(|digest| self.state.bundles.get(digest))
            .ok_or(PromotionAuthorityError::MissingBaseline)
    }

    pub(crate) fn append(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        event: JournalEvent,
    ) -> Result<(), PromotionAuthorityError> {
        self.journal.append(JournalContent {
            authority_id: self.authority_id.clone(),
            policy_digest: self.policy_digest.clone(),
            request: request.clone(),
            authorizing_party: authorization.party_id.clone(),
            authorization_signature: authorization.signature.clone(),
            event,
        })?;
        self.refresh()
    }
}

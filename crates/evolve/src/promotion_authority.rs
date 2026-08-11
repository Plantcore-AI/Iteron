//! Deny-by-default executing authority for the offline promotion journal.
//!
//! This is not connected to the runtime kernel and has no policy loader.  Its "activation" is an
//! audited offline active-bundle pointer whose exact bytes can be handed to a separate human-owned
//! release process.

use crate::private_derivatives::{EvolutionDerivativeKind, EvolutionPrivateContent};
use crate::promotion::{
    EvaluatorTrustAnchor, PromotionAuthorityError, PromotionControlPolicy, PromotionTrustAnchor,
};
use crate::promotion_auth::{PromotionAuthorization, PromotionOperation, PromotionRequest};
use crate::promotion_evaluation::{
    BoundedStageExecutor, SignedCheckpointEvaluation, SignedHeldOutEvaluation,
    SignedStageObservation, StagePermit,
};
use crate::promotion_journal::{
    CandidateIdentity, CheckpointEvaluationIdentity, JournalEvent, PromotionJournal,
};
use crate::promotion_state::{
    AuthorityState, CheckpointEvaluationRef, PromotionAuditEvent, PromotionLineage,
    changed_deployment_slots, changed_policy_slots, checkpoint_evaluators_are_independent,
};
use crate::verifier_crypto::constant_time_eq;
use crate::{
    ConsentAwareDatasetRegistry, DeploymentBundle, DeploymentStage, EvaluationSuite,
    EvolutionVerifier, MAX_EVALUATOR_TRUST_ANCHORS, MAX_PROMOTION_TRUST_ANCHORS,
    ManifestAdmissionPolicy, PolicyCheckpoint, PolicyManifest, StrategySlot,
    VerifiedTrainingDataset,
};
use std::collections::BTreeMap;
use std::path::Path;

/// One changed checkpoint slot and the trusted inputs required to admit it.
///
/// The map key passed to [`PromotionAuthority::admit_checkpoint_candidate`] is the slot identity;
/// the manifest itself comes from the checkpoint, so a caller cannot present one manifest for
/// evaluation while deploying another.
pub struct CheckpointCandidateAdmission<'a> {
    admission_policy: &'a ManifestAdmissionPolicy,
    artifact_bytes: &'a [u8],
    training_dataset: Option<&'a VerifiedTrainingDataset<'a>>,
    evaluation_suite: &'a EvaluationSuite,
    held_out: SignedCheckpointEvaluation,
}

impl<'a> CheckpointCandidateAdmission<'a> {
    pub fn new(
        admission_policy: &'a ManifestAdmissionPolicy,
        artifact_bytes: &'a [u8],
        training_dataset: Option<&'a VerifiedTrainingDataset<'a>>,
        evaluation_suite: &'a EvaluationSuite,
        held_out: SignedCheckpointEvaluation,
    ) -> Self {
        Self {
            admission_policy,
            artifact_bytes,
            training_dataset,
            evaluation_suite,
            held_out,
        }
    }
}

pub struct PromotionAuthority {
    pub(crate) authority_id: String,
    pub(crate) policy: PromotionControlPolicy,
    pub(crate) policy_digest: String,
    pub(crate) promotion_anchors: BTreeMap<String, PromotionTrustAnchor>,
    pub(crate) evaluator_anchors: BTreeMap<String, EvaluatorTrustAnchor>,
    pub(crate) journal: PromotionJournal,
    pub(crate) state: AuthorityState,
    private_content: Option<EvolutionPrivateContent>,
}

impl PromotionAuthority {
    pub fn open(
        directory: &Path,
        authority_id: impl Into<String>,
        policy: PromotionControlPolicy,
        promotion_anchors: Vec<PromotionTrustAnchor>,
        evaluator_anchors: Vec<EvaluatorTrustAnchor>,
    ) -> Result<Self, PromotionAuthorityError> {
        policy.validate()?;
        let authority_id = authority_id.into();
        crate::validate_nonempty_string(
            "promotion.authority_id",
            &authority_id,
            crate::MAX_SHORT_STRING_BYTES,
        )?;
        if authority_id.chars().any(char::is_control)
            || promotion_anchors.is_empty()
            || promotion_anchors.len() > MAX_PROMOTION_TRUST_ANCHORS
            || evaluator_anchors.is_empty()
            || evaluator_anchors.len() > MAX_EVALUATOR_TRUST_ANCHORS
        {
            return Err(PromotionAuthorityError::InvalidTrustConfiguration);
        }
        let mut promotions = BTreeMap::new();
        for anchor in promotion_anchors {
            if promotions.insert(anchor.party_id.clone(), anchor).is_some() {
                return Err(PromotionAuthorityError::InvalidTrustConfiguration);
            }
        }
        let mut evaluators = BTreeMap::new();
        for anchor in evaluator_anchors {
            if promotions.contains_key(&anchor.evaluator_id)
                || promotions
                    .values()
                    .any(|promotion| constant_time_eq(promotion.key.bytes(), anchor.key.bytes()))
                || evaluators
                    .insert(anchor.evaluator_id.clone(), anchor)
                    .is_some()
            {
                return Err(PromotionAuthorityError::InvalidTrustConfiguration);
            }
        }
        let policy_digest = policy.digest()?;
        let journal = PromotionJournal::open(directory)?;
        let mut authority = Self {
            authority_id,
            policy,
            policy_digest,
            promotion_anchors: promotions,
            evaluator_anchors: evaluators,
            journal,
            state: AuthorityState::default(),
            private_content: None,
        };
        authority.refresh()?;
        Ok(authority)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_record_backed(
        directory: &Path,
        authority_id: impl Into<String>,
        policy: PromotionControlPolicy,
        promotion_anchors: Vec<PromotionTrustAnchor>,
        evaluator_anchors: Vec<EvaluatorTrustAnchor>,
        manifest_root: &Path,
        content_runs_dir: &Path,
        tenant_id: iteron_protocol::TenantId,
    ) -> Result<Self, PromotionAuthorityError> {
        let mut authority = Self::open(
            directory,
            authority_id,
            policy,
            promotion_anchors,
            evaluator_anchors,
        )?;
        authority.private_content = Some(EvolutionPrivateContent::open(
            manifest_root,
            content_runs_dir,
            tenant_id,
        )?);
        Ok(authority)
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    pub fn bootstrap(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        baseline: DeploymentBundle,
    ) -> Result<(), PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, PromotionOperation::Bootstrap)?;
        baseline.validate()?;
        if request.candidate_bundle_digest() != baseline.bundle().digest {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        if self.state.active_bundle_digest.is_some() {
            return Err(PromotionAuthorityError::AlreadyBootstrapped);
        }
        self.append(
            request,
            authorization,
            JournalEvent::Bootstrapped { bundle: baseline },
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_candidate<'a>(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        verifier: &EvolutionVerifier,
        datasets: &ConsentAwareDatasetRegistry,
        manifest: &PolicyManifest,
        artifact_bytes: &[u8],
        training_dataset: Option<&VerifiedTrainingDataset<'a>>,
        evaluation_suite: &EvaluationSuite,
        held_out: SignedHeldOutEvaluation,
        deployment: DeploymentBundle,
    ) -> Result<PromotionLineage, PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, PromotionOperation::AdmitCandidate)?;
        let active = self.active_bundle_ref()?.clone();
        deployment.validate()?;
        manifest.validate()?;
        if request.candidate_bundle_digest() != deployment.bundle().digest
            || deployment.bundle().policy_for(&manifest.policy.slot) != Some(&manifest.policy)
            || deployment.bundle().rollback_to.as_deref()
                != Some(active.bundle().bundle_id.as_str())
            || changed_deployment_slots(&active, &deployment)?
                != [manifest.policy.slot.clone()].into()
            || changed_policy_slots(active.bundle(), deployment.bundle())
                != [manifest.policy.slot.clone()].into()
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        let registered = datasets.require_manifest_dataset(manifest)?;
        match (registered, training_dataset) {
            (Some(registered), Some(dataset)) if registered.digest == dataset.digest() => {}
            (None, None) => {}
            _ => return Err(PromotionAuthorityError::LineageMismatch),
        }
        let hydrated_artifact;
        let artifact_bytes = if let Some(private) = &self.private_content {
            hydrated_artifact =
                private.read(EvolutionDerivativeKind::Candidate, &manifest.policy.digest)?;
            if hydrated_artifact.as_slice() != artifact_bytes {
                return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
            }
            hydrated_artifact.as_slice()
        } else {
            artifact_bytes
        };
        let verified = verifier.verify_candidate_inputs(
            manifest,
            artifact_bytes,
            training_dataset,
            evaluation_suite,
        )?;
        let baseline_policy = active
            .bundle()
            .policy_for(&manifest.policy.slot)
            .ok_or(PromotionAuthorityError::LineageMismatch)?;
        if manifest.parent.as_ref() != Some(baseline_policy) {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        let identity = CandidateIdentity {
            bundle_id: deployment.bundle().bundle_id.clone(),
            bundle_digest: deployment.bundle().digest.clone(),
            rollback_bundle_id: active.bundle().bundle_id.clone(),
            baseline_bundle_digest: active.bundle().digest.clone(),
            candidate_policy: manifest.policy.clone(),
            parent_policy: manifest.parent.clone(),
            artifact_digest: verified.artifact_digest.clone(),
            training_dataset_digest: verified.training_dataset_digest.clone(),
            evaluation_suite_digest: verified.evaluation_suite_digest.clone(),
            base_model: verified.base_model.clone(),
            evaluation_owner_id: evaluation_suite.owner_id().to_owned(),
            evaluator_id: held_out.evaluator_id.clone(),
            additional_evaluations: Vec::new(),
        };
        self.verify_held_out(&identity, baseline_policy, evaluation_suite, &held_out)?;
        let lineage = PromotionLineage::from(&identity);
        self.append(
            request,
            authorization,
            JournalEvent::CandidateAdmitted {
                bundle: deployment,
                identity: Box::new(identity),
                held_out_attestation: Box::new(held_out),
            },
        )?;
        Ok(lineage)
    }

    /// Admit an algebra checkpoint only after every marked slot has a fresh, checkpoint-bound
    /// held-out attestation and a re-run of its trusted manifest admission policy.
    ///
    /// This is intentionally a separate path from [`Self::admit_candidate`]. The latter admits
    /// exactly one changed `PolicyRef`; it rejects a deployment carrying any additional change.
    /// Checkpoint operations such as `merge` and `restrict` can be atomic only through this method.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_checkpoint_candidate<'a>(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        verifier: &EvolutionVerifier,
        datasets: &ConsentAwareDatasetRegistry,
        checkpoint: &PolicyCheckpoint,
        admissions: BTreeMap<StrategySlot, CheckpointCandidateAdmission<'a>>,
    ) -> Result<PromotionLineage, PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, PromotionOperation::AdmitCandidate)?;
        checkpoint
            .validate()
            .map_err(|_| PromotionAuthorityError::LineageMismatch)?;
        let active = self.active_bundle_ref()?.clone();
        let deployment = checkpoint.deployment_bundle_unchecked()?;
        let active_checkpoint = PolicyCheckpoint::from_deployment(&active)
            .map_err(|_| PromotionAuthorityError::LineageMismatch)?;
        let required = checkpoint.fresh_held_out_slots();
        let supplied: std::collections::BTreeSet<_> = admissions.keys().cloned().collect();
        let changed = active_checkpoint.changed_slots(checkpoint);
        if required.is_empty()
            || changed.is_empty()
            || supplied != *required
            || !changed.is_subset(required)
            || request.candidate_bundle_digest() != deployment.bundle().digest
            || deployment.bundle().rollback_to.as_deref()
                != Some(active.bundle().bundle_id.as_str())
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }

        let mut identities = Vec::with_capacity(admissions.len());
        let mut admission_policies = BTreeMap::new();
        let mut attestations = Vec::with_capacity(admissions.len());
        for (slot, admission) in admissions {
            let manifest = checkpoint
                .manifest_for(&slot)
                .ok_or(PromotionAuthorityError::LineageMismatch)?;
            admission.admission_policy.assess(manifest)?;
            let registered = datasets.require_manifest_dataset(manifest)?;
            match (registered, admission.training_dataset) {
                (Some(registered), Some(dataset)) if registered.digest == dataset.digest() => {}
                (None, None) => {}
                _ => return Err(PromotionAuthorityError::LineageMismatch),
            }
            let hydrated_artifact;
            let artifact_bytes = if let Some(private) = &self.private_content {
                hydrated_artifact =
                    private.read(EvolutionDerivativeKind::Candidate, &manifest.policy.digest)?;
                if hydrated_artifact.as_slice() != admission.artifact_bytes {
                    return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
                }
                hydrated_artifact.as_slice()
            } else {
                admission.artifact_bytes
            };
            let verified = verifier.verify_candidate_inputs(
                manifest,
                artifact_bytes,
                admission.training_dataset,
                admission.evaluation_suite,
            )?;
            let baseline_policy = active
                .bundle()
                .policy_for(&slot)
                .ok_or(PromotionAuthorityError::LineageMismatch)?;
            let identity = CheckpointEvaluationIdentity {
                candidate_policy: manifest.policy.clone(),
                // Checkpoint transition lineage is relative to the active deployment. The
                // manifest's own artifact lineage is assessed separately by its exact admission
                // policy and may legitimately name an older source (merge) or no parent (retire).
                parent_policy: Some(baseline_policy.clone()),
                artifact_digest: verified.artifact_digest.clone(),
                training_dataset_digest: verified.training_dataset_digest.clone(),
                evaluation_suite_digest: verified.evaluation_suite_digest.clone(),
                base_model: verified.base_model.clone(),
                evaluation_owner_id: admission.evaluation_suite.owner_id().to_owned(),
                evaluator_id: admission.held_out.evaluator_id.clone(),
            };
            self.verify_checkpoint_held_out(
                deployment.bundle(),
                required,
                CheckpointEvaluationRef {
                    candidate_policy: &identity.candidate_policy,
                    parent_policy: &identity.parent_policy,
                    artifact_digest: &identity.artifact_digest,
                    training_dataset_digest: &identity.training_dataset_digest,
                    evaluation_suite_digest: &identity.evaluation_suite_digest,
                    base_model: &identity.base_model,
                    evaluation_owner_id: &identity.evaluation_owner_id,
                    evaluator_id: &identity.evaluator_id,
                },
                baseline_policy,
                manifest,
                admission.admission_policy,
                Some(admission.evaluation_suite),
                &admission.held_out,
            )?;
            identities.push(identity);
            admission_policies.insert(slot, admission.admission_policy.clone());
            attestations.push(admission.held_out);
        }

        identities.sort_by(|left, right| {
            let left_changed = changed.contains(&left.candidate_policy.slot);
            let right_changed = changed.contains(&right.candidate_policy.slot);
            right_changed
                .cmp(&left_changed)
                .then_with(|| left.candidate_policy.slot.cmp(&right.candidate_policy.slot))
        });
        let mut identities = identities.into_iter();
        let primary = identities
            .next()
            .ok_or(PromotionAuthorityError::FreshHeldOutRequired)?;
        let identity = CandidateIdentity {
            bundle_id: deployment.bundle().bundle_id.clone(),
            bundle_digest: deployment.bundle().digest.clone(),
            rollback_bundle_id: active.bundle().bundle_id.clone(),
            baseline_bundle_digest: active.bundle().digest.clone(),
            candidate_policy: primary.candidate_policy,
            parent_policy: primary.parent_policy,
            artifact_digest: primary.artifact_digest,
            training_dataset_digest: primary.training_dataset_digest,
            evaluation_suite_digest: primary.evaluation_suite_digest,
            base_model: primary.base_model,
            evaluation_owner_id: primary.evaluation_owner_id,
            evaluator_id: primary.evaluator_id,
            additional_evaluations: identities.collect(),
        };
        if !checkpoint_evaluators_are_independent(&identity, deployment.bundle()) {
            return Err(PromotionAuthorityError::IndependentEvaluationRequired);
        }
        let lineage = PromotionLineage::from(&identity);
        self.append(
            request,
            authorization,
            JournalEvent::CheckpointCandidateAdmitted {
                checkpoint: Box::new(checkpoint.clone()),
                identity: Box::new(identity),
                admission_policies,
                attestations,
            },
        )?;
        Ok(lineage)
    }

    pub fn enter_shadow(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
    ) -> Result<StagePermit, PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, PromotionOperation::EnterShadow)?;
        self.require_stage(
            request.candidate_bundle_digest(),
            DeploymentStage::Candidate,
        )?;
        let permit = StagePermit::issue(
            &self.authority_id,
            &self.policy_digest,
            request.candidate_bundle_digest(),
            DeploymentStage::Shadow,
            &self.policy,
        )?;
        self.append(
            request,
            authorization,
            JournalEvent::StageTransition {
                candidate_bundle_digest: request.candidate_bundle_digest().to_owned(),
                from: DeploymentStage::Candidate,
                to: DeploymentStage::Shadow,
                permit: Some(permit.clone()),
                stage_attestation: None,
            },
        )?;
        Ok(permit)
    }

    pub fn complete_shadow(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        observation: SignedStageObservation,
    ) -> Result<StagePermit, PromotionAuthorityError> {
        self.complete_bounded_stage(
            request,
            authorization,
            observation,
            DeploymentStage::Shadow,
            DeploymentStage::Canary,
            PromotionOperation::CompleteShadow,
        )?;
        self.state
            .candidates
            .get(request.candidate_bundle_digest())
            .and_then(|candidate| candidate.permit.clone())
            .ok_or(PromotionAuthorityError::StageMismatch)
    }

    pub fn complete_canary(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        observation: SignedStageObservation,
    ) -> Result<DeploymentBundle, PromotionAuthorityError> {
        self.complete_bounded_stage(
            request,
            authorization,
            observation,
            DeploymentStage::Canary,
            DeploymentStage::Active,
            PromotionOperation::CompleteCanary,
        )?;
        self.active_bundle_ref().cloned()
    }

    pub fn execute_shadow(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        suite: &EvaluationSuite,
        executor: &mut impl BoundedStageExecutor,
    ) -> Result<StagePermit, PromotionAuthorityError> {
        let observation = self.execute_bounded_stage(
            request,
            authorization,
            suite,
            executor,
            PromotionOperation::CompleteShadow,
            DeploymentStage::Shadow,
        )?;
        self.complete_shadow(request, authorization, observation)
    }

    pub fn execute_canary(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        suite: &EvaluationSuite,
        executor: &mut impl BoundedStageExecutor,
    ) -> Result<DeploymentBundle, PromotionAuthorityError> {
        let observation = self.execute_bounded_stage(
            request,
            authorization,
            suite,
            executor,
            PromotionOperation::CompleteCanary,
            DeploymentStage::Canary,
        )?;
        self.complete_canary(request, authorization, observation)
    }

    pub fn rollback(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
    ) -> Result<DeploymentBundle, PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, PromotionOperation::Rollback)?;
        let from = request
            .expected_from()
            .ok_or(PromotionAuthorityError::InvalidRequestTransition)?;
        let candidate = self
            .state
            .candidates
            .get(request.candidate_bundle_digest())
            .ok_or(PromotionAuthorityError::CandidateNotFound)?;
        if candidate.stage != from {
            return Err(PromotionAuthorityError::StageMismatch);
        }
        let expected_active = if from == DeploymentStage::Active {
            request.candidate_bundle_digest()
        } else {
            candidate.identity.baseline_bundle_digest.as_str()
        };
        if self.state.active_bundle_digest.as_deref() != Some(expected_active) {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        let restored = self
            .state
            .bundles
            .get(&candidate.identity.baseline_bundle_digest)
            .ok_or(PromotionAuthorityError::LineageMismatch)?
            .clone();
        self.append(
            request,
            authorization,
            JournalEvent::RolledBack {
                candidate_bundle_digest: request.candidate_bundle_digest().to_owned(),
                from,
                restored_bundle_id: restored.bundle().bundle_id.clone(),
                restored_bundle_digest: restored.bundle().digest.clone(),
            },
        )?;
        self.active_bundle_ref().cloned()
    }

    pub fn active_bundle(&mut self) -> Result<Option<DeploymentBundle>, PromotionAuthorityError> {
        self.refresh()?;
        Ok(self.active_bundle_ref().ok().cloned())
    }

    pub fn candidate_stage(
        &mut self,
        candidate_bundle_digest: &str,
    ) -> Result<Option<DeploymentStage>, PromotionAuthorityError> {
        self.refresh()?;
        Ok(self
            .state
            .candidates
            .get(candidate_bundle_digest)
            .map(|candidate| candidate.stage))
    }

    pub fn audit(&mut self) -> Result<Vec<PromotionAuditEvent>, PromotionAuthorityError> {
        self.refresh()?;
        Ok(self.state.audit.clone())
    }

    fn execute_bounded_stage(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        suite: &EvaluationSuite,
        executor: &mut impl BoundedStageExecutor,
        operation: PromotionOperation,
        stage: DeploymentStage,
    ) -> Result<SignedStageObservation, PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, operation)?;
        let candidate = self.require_stage(request.candidate_bundle_digest(), stage)?;
        if candidate.identity.evaluation_suite_digest != suite.digest()
            || candidate.identity.evaluation_owner_id != suite.owner_id()
        {
            return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
        }
        let journalled = candidate
            .permit
            .as_ref()
            .ok_or(PromotionAuthorityError::StageMismatch)?;
        // The permit handed to the executor is re-derived from THIS authority's policy, never the
        // one replay installed. `stage_refusal_codes` already re-derives the permit it READS, which
        // closed the advance-the-candidate consequence; a review then measured the other one — a
        // rewritten journal still set the bounds the executor was given, and it ran 5,000 work units
        // against a real limit of 20 before the refusal fired. Bounding the work is the entire
        // purpose of a permit, so a permit that only bounds the verdict is not one.
        //
        // `refresh()` cannot catch it upstream: it re-verifies a `StageTransition` only when one
        // carries a stage attestation, and the Candidate -> Shadow record carries none, so it falls
        // through untouched. `apply_transition` compares the journalled permit's candidate digest
        // and stage and nothing else.
        let permit = StagePermit::issue(
            &self.authority_id,
            &self.policy_digest,
            request.candidate_bundle_digest(),
            journalled.stage,
            &self.policy,
        )?;
        if permit.digest != journalled.digest {
            return Err(PromotionAuthorityError::IndependentEvaluationRequired);
        }
        executor.execute(&permit, suite)
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_bounded_stage(
        &mut self,
        request: &PromotionRequest,
        authorization: &PromotionAuthorization,
        observation: SignedStageObservation,
        from: DeploymentStage,
        to: DeploymentStage,
        operation: PromotionOperation,
    ) -> Result<(), PromotionAuthorityError> {
        self.refresh()?;
        self.prepare_authorized(request, authorization, operation)?;
        let candidate = self.require_stage(request.candidate_bundle_digest(), from)?;
        let permit = candidate
            .permit
            .as_ref()
            .ok_or(PromotionAuthorityError::StageMismatch)?;
        let codes = self.stage_refusal_codes(&self.state, candidate, permit, to, &observation)?;
        if !codes.is_empty() {
            self.append(
                request,
                authorization,
                JournalEvent::StageRefused {
                    candidate_bundle_digest: request.candidate_bundle_digest().to_owned(),
                    stage: from,
                    codes,
                    stage_attestation: Box::new(observation),
                },
            )?;
            return Err(PromotionAuthorityError::StageRefused);
        }
        let next_permit = if to == DeploymentStage::Active {
            None
        } else {
            Some(StagePermit::issue(
                &self.authority_id,
                &self.policy_digest,
                request.candidate_bundle_digest(),
                to,
                &self.policy,
            )?)
        };
        self.append(
            request,
            authorization,
            JournalEvent::StageTransition {
                candidate_bundle_digest: request.candidate_bundle_digest().to_owned(),
                from,
                to,
                permit: next_permit,
                stage_attestation: Some(Box::new(observation)),
            },
        )?;
        Ok(())
    }
}

//! Deterministic replay reducer for the authenticated promotion journal.

use crate::DeploymentStage;
use crate::promotion::{DeploymentBundle, MAX_PROMOTION_CANDIDATES, PromotionAuthorityError};
use crate::promotion_auth::{PromotionOperation, PromotionRequest};
use crate::promotion_evaluation::StagePermit;
use crate::promotion_journal::{
    CandidateIdentity, CheckpointEvaluationIdentity, JournalEvent, JournalRecord, RefusalCode,
};
use crate::{BaseModelId, PolicyBundle, StrategySlot};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionLineage {
    pub bundle_id: String,
    pub bundle_digest: String,
    pub rollback_bundle_id: String,
    pub baseline_bundle_digest: String,
    pub candidate_policy_id: String,
    pub candidate_policy_digest: String,
    pub parent_policy_id: Option<String>,
    pub artifact_digest: String,
    pub training_dataset_digest: Option<String>,
    pub evaluation_suite_digest: String,
    pub base_model: BaseModelId,
    pub evaluation_owner_id: String,
    pub evaluator_id: String,
    pub additional_evaluations: Vec<PromotionEvaluationLineage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvaluationLineage {
    pub slot: StrategySlot,
    pub candidate_policy_id: String,
    pub candidate_policy_digest: String,
    pub parent_policy_id: Option<String>,
    pub artifact_digest: String,
    pub training_dataset_digest: Option<String>,
    pub evaluation_suite_digest: String,
    pub base_model: BaseModelId,
    pub evaluation_owner_id: String,
    pub evaluator_id: String,
}

impl From<&CandidateIdentity> for PromotionLineage {
    fn from(identity: &CandidateIdentity) -> Self {
        Self {
            bundle_id: identity.bundle_id.clone(),
            bundle_digest: identity.bundle_digest.clone(),
            rollback_bundle_id: identity.rollback_bundle_id.clone(),
            baseline_bundle_digest: identity.baseline_bundle_digest.clone(),
            candidate_policy_id: identity.candidate_policy.policy_id.clone(),
            candidate_policy_digest: identity.candidate_policy.digest.clone(),
            parent_policy_id: identity
                .parent_policy
                .as_ref()
                .map(|parent| parent.policy_id.clone()),
            artifact_digest: identity.artifact_digest.clone(),
            training_dataset_digest: identity.training_dataset_digest.clone(),
            evaluation_suite_digest: identity.evaluation_suite_digest.clone(),
            base_model: identity.base_model.clone(),
            evaluation_owner_id: identity.evaluation_owner_id.clone(),
            evaluator_id: identity.evaluator_id.clone(),
            additional_evaluations: identity
                .additional_evaluations
                .iter()
                .map(PromotionEvaluationLineage::from)
                .collect(),
        }
    }
}

impl From<&CheckpointEvaluationIdentity> for PromotionEvaluationLineage {
    fn from(identity: &CheckpointEvaluationIdentity) -> Self {
        Self {
            slot: identity.candidate_policy.slot.clone(),
            candidate_policy_id: identity.candidate_policy.policy_id.clone(),
            candidate_policy_digest: identity.candidate_policy.digest.clone(),
            parent_policy_id: identity
                .parent_policy
                .as_ref()
                .map(|parent| parent.policy_id.clone()),
            artifact_digest: identity.artifact_digest.clone(),
            training_dataset_digest: identity.training_dataset_digest.clone(),
            evaluation_suite_digest: identity.evaluation_suite_digest.clone(),
            base_model: identity.base_model.clone(),
            evaluation_owner_id: identity.evaluation_owner_id.clone(),
            evaluator_id: identity.evaluator_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PromotionAuditKind {
    Bootstrapped {
        active_bundle_digest: String,
    },
    CandidateAdmitted,
    StageTransition {
        from: DeploymentStage,
        to: DeploymentStage,
        permit_digest: Option<String>,
    },
    StageRefused {
        stage: DeploymentStage,
        refusal_codes: Vec<String>,
    },
    RolledBack {
        from: DeploymentStage,
        restored_bundle_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionAuditEvent {
    pub sequence: u64,
    pub record_hash: String,
    pub authorization_id: String,
    pub authorizing_party: String,
    pub kind: PromotionAuditKind,
    pub lineage: Option<PromotionLineage>,
}

#[derive(Debug, Clone)]
pub(crate) struct CandidateState {
    pub(crate) identity: CandidateIdentity,
    pub(crate) stage: DeploymentStage,
    pub(crate) permit: Option<StagePermit>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AuthorityState {
    pub(crate) active_bundle_digest: Option<String>,
    pub(crate) bundles: BTreeMap<String, DeploymentBundle>,
    pub(crate) candidates: BTreeMap<String, CandidateState>,
    pub(crate) used_authorizations: BTreeSet<String>,
    pub(crate) audit: Vec<PromotionAuditEvent>,
}

impl AuthorityState {
    pub(crate) fn apply(&mut self, record: &JournalRecord) -> Result<(), PromotionAuthorityError> {
        let request = &record.content.request;
        request.validate()?;
        if !self
            .used_authorizations
            .insert(request.authorization_id().to_owned())
        {
            return Err(PromotionAuthorityError::AuthorizationReplay);
        }

        let (kind, lineage) = match &record.content.event {
            JournalEvent::Bootstrapped { bundle } => {
                self.apply_bootstrap(request, bundle)?;
                (
                    PromotionAuditKind::Bootstrapped {
                        active_bundle_digest: bundle.bundle().digest.clone(),
                    },
                    None,
                )
            }
            JournalEvent::CandidateAdmitted {
                bundle,
                identity,
                held_out_attestation,
            } => {
                self.apply_candidate(request, bundle, identity)?;
                if held_out_attestation.report.candidate != identity.candidate_policy
                    || held_out_attestation.report.artifact_digest != identity.artifact_digest
                    || held_out_attestation.report.training_dataset_digest
                        != identity.training_dataset_digest
                    || held_out_attestation.report.evaluation_suite_digest
                        != identity.evaluation_suite_digest
                    || held_out_attestation.evaluator_id != identity.evaluator_id
                    // Added when `base_model` joined `CandidateIdentity`. Not a live hole before —
                    // `refresh` calls `verify_held_out_without_suite`, which checks it, in the same
                    // loop just above this — but this is a parallel copy of the identity check, and
                    // the next reader will reasonably take the list for the whole of it. An
                    // incomplete copy of a list that grew is how a check quietly stops covering what
                    // its name says.
                    || held_out_attestation.report.base_model() != &identity.base_model
                {
                    return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
                }
                (
                    PromotionAuditKind::CandidateAdmitted,
                    Some(PromotionLineage::from(identity.as_ref())),
                )
            }
            JournalEvent::CheckpointCandidateAdmitted {
                checkpoint,
                identity,
                admission_policies,
                attestations,
            } => {
                self.apply_checkpoint_candidate(
                    request,
                    checkpoint,
                    identity,
                    admission_policies,
                    attestations,
                )?;
                (
                    PromotionAuditKind::CandidateAdmitted,
                    Some(PromotionLineage::from(identity.as_ref())),
                )
            }
            JournalEvent::StageTransition {
                candidate_bundle_digest,
                from,
                to,
                permit,
                stage_attestation,
            } => {
                let identity = self.apply_transition(
                    request,
                    candidate_bundle_digest,
                    *from,
                    *to,
                    permit,
                    stage_attestation.is_some(),
                )?;
                (
                    PromotionAuditKind::StageTransition {
                        from: *from,
                        to: *to,
                        permit_digest: permit.as_ref().map(|permit| permit.digest.clone()),
                    },
                    Some(PromotionLineage::from(&identity)),
                )
            }
            JournalEvent::StageRefused {
                candidate_bundle_digest,
                stage,
                codes,
                stage_attestation,
            } => {
                let identity = self.apply_refusal(
                    request,
                    candidate_bundle_digest,
                    *stage,
                    codes,
                    &stage_attestation.observation.candidate_bundle_digest,
                )?;
                (
                    PromotionAuditKind::StageRefused {
                        stage: *stage,
                        refusal_codes: codes.iter().map(refusal_code_name).collect(),
                    },
                    Some(PromotionLineage::from(&identity)),
                )
            }
            JournalEvent::RolledBack {
                candidate_bundle_digest,
                from,
                restored_bundle_id,
                restored_bundle_digest,
            } => {
                let identity = self.apply_rollback(
                    request,
                    candidate_bundle_digest,
                    *from,
                    restored_bundle_id,
                    restored_bundle_digest,
                )?;
                (
                    PromotionAuditKind::RolledBack {
                        from: *from,
                        restored_bundle_digest: restored_bundle_digest.clone(),
                    },
                    Some(PromotionLineage::from(&identity)),
                )
            }
        };
        self.audit.push(PromotionAuditEvent {
            sequence: record.sequence,
            record_hash: record.record_hash.clone(),
            authorization_id: request.authorization_id().to_owned(),
            authorizing_party: record.content.authorizing_party.clone(),
            kind,
            lineage,
        });
        Ok(())
    }

    fn apply_bootstrap(
        &mut self,
        request: &PromotionRequest,
        bundle: &DeploymentBundle,
    ) -> Result<(), PromotionAuthorityError> {
        if request.operation() != PromotionOperation::Bootstrap
            || request.candidate_bundle_digest() != bundle.bundle().digest
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        if self.active_bundle_digest.is_some() || !self.bundles.is_empty() {
            return Err(PromotionAuthorityError::AlreadyBootstrapped);
        }
        bundle.validate()?;
        self.active_bundle_digest = Some(bundle.bundle().digest.clone());
        self.bundles
            .insert(bundle.bundle().digest.clone(), bundle.clone());
        Ok(())
    }

    fn apply_candidate(
        &mut self,
        request: &PromotionRequest,
        bundle: &DeploymentBundle,
        identity: &CandidateIdentity,
    ) -> Result<(), PromotionAuthorityError> {
        if request.operation() != PromotionOperation::AdmitCandidate
            || request.candidate_bundle_digest() != bundle.bundle().digest
            || identity.bundle_digest != bundle.bundle().digest
            || identity.bundle_id != bundle.bundle().bundle_id
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        bundle.validate()?;
        if self.candidates.len()
            >= iteron_tunables::param_integer(
                "evolve.promotion.max_promotion_candidates",
                MAX_PROMOTION_CANDIDATES,
            )
        {
            return Err(PromotionAuthorityError::CandidateLimit {
                max: iteron_tunables::param_integer(
                    "evolve.promotion.max_promotion_candidates",
                    MAX_PROMOTION_CANDIDATES,
                ),
            });
        }
        if self.candidates.contains_key(&identity.bundle_digest)
            || self.bundles.contains_key(&identity.bundle_digest)
            || self
                .bundles
                .values()
                .any(|stored| stored.bundle().bundle_id == identity.bundle_id)
        {
            return Err(PromotionAuthorityError::CandidateConflict);
        }
        let active_digest = self
            .active_bundle_digest
            .as_ref()
            .ok_or(PromotionAuthorityError::MissingBaseline)?;
        let active = self
            .bundles
            .get(active_digest)
            .ok_or(PromotionAuthorityError::MissingBaseline)?;
        let changed_slots = changed_deployment_slots(active, bundle)?;
        if !identity.additional_evaluations.is_empty()
            || changed_slots != [identity.candidate_policy.slot.clone()].into()
            || changed_policy_slots(active.bundle(), bundle.bundle())
                != [identity.candidate_policy.slot.clone()].into()
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        if identity.baseline_bundle_digest != *active_digest
            || identity.rollback_bundle_id != active.bundle().bundle_id
            || bundle.bundle().rollback_to.as_deref() != Some(identity.rollback_bundle_id.as_str())
            || bundle.bundle().policy_for(&identity.candidate_policy.slot)
                != Some(&identity.candidate_policy)
            || identity.parent_policy.as_ref()
                != active.bundle().policy_for(&identity.candidate_policy.slot)
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        self.bundles
            .insert(identity.bundle_digest.clone(), bundle.clone());
        self.candidates.insert(
            identity.bundle_digest.clone(),
            CandidateState {
                identity: identity.clone(),
                stage: DeploymentStage::Candidate,
                permit: None,
            },
        );
        Ok(())
    }

    fn apply_checkpoint_candidate(
        &mut self,
        request: &PromotionRequest,
        checkpoint: &crate::PolicyCheckpoint,
        identity: &CandidateIdentity,
        admission_policies: &BTreeMap<StrategySlot, crate::ManifestAdmissionPolicy>,
        attestations: &[crate::SignedCheckpointEvaluation],
    ) -> Result<(), PromotionAuthorityError> {
        checkpoint
            .validate()
            .map_err(|_| PromotionAuthorityError::LineageMismatch)?;
        let bundle = checkpoint.deployment_bundle_unchecked()?;
        if request.operation() != PromotionOperation::AdmitCandidate
            || request.candidate_bundle_digest() != bundle.bundle().digest
            || identity.bundle_digest != bundle.bundle().digest
            || identity.bundle_id != bundle.bundle().bundle_id
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        if self.candidates.len()
            >= iteron_tunables::param_integer(
                "evolve.promotion.max_promotion_candidates",
                MAX_PROMOTION_CANDIDATES,
            )
        {
            return Err(PromotionAuthorityError::CandidateLimit {
                max: iteron_tunables::param_integer(
                    "evolve.promotion.max_promotion_candidates",
                    MAX_PROMOTION_CANDIDATES,
                ),
            });
        }
        if self.candidates.contains_key(&identity.bundle_digest)
            || self.bundles.contains_key(&identity.bundle_digest)
            || self
                .bundles
                .values()
                .any(|stored| stored.bundle().bundle_id == identity.bundle_id)
        {
            return Err(PromotionAuthorityError::CandidateConflict);
        }
        let active_digest = self
            .active_bundle_digest
            .as_ref()
            .ok_or(PromotionAuthorityError::MissingBaseline)?;
        let active = self
            .bundles
            .get(active_digest)
            .ok_or(PromotionAuthorityError::MissingBaseline)?;
        let required = checkpoint.fresh_held_out_slots();
        let evaluated = evaluated_slots(identity)?;
        let attested: BTreeSet<_> = attestations
            .iter()
            .map(|attestation| attestation.report().candidate.slot.clone())
            .collect();
        let active_checkpoint = crate::PolicyCheckpoint::from_deployment(active)
            .map_err(|_| PromotionAuthorityError::LineageMismatch)?;
        let changed = active_checkpoint.changed_slots(checkpoint);
        if required.is_empty()
            || changed.is_empty()
            || &evaluated != required
            || !checkpoint_evaluations_are_canonical(identity, &changed, required)
            || !checkpoint_evaluators_are_independent(identity, checkpoint.bundle())
            || &attested != required
            || admission_policies.keys().cloned().collect::<BTreeSet<_>>() != *required
            || !changed.is_subset(required)
            || identity.baseline_bundle_digest != *active_digest
            || identity.rollback_bundle_id != active.bundle().bundle_id
            || bundle.bundle().rollback_to.as_deref() != Some(identity.rollback_bundle_id.as_str())
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        for evaluation in checkpoint_evaluations(identity) {
            let slot = &evaluation.candidate_policy.slot;
            if bundle.bundle().policy_for(slot) != Some(evaluation.candidate_policy)
                || evaluation.parent_policy.as_ref() != active.bundle().policy_for(slot)
                || checkpoint
                    .manifest_for(slot)
                    .map(|manifest| &manifest.policy)
                    != Some(evaluation.candidate_policy)
            {
                return Err(PromotionAuthorityError::LineageMismatch);
            }
        }
        self.bundles.insert(identity.bundle_digest.clone(), bundle);
        self.candidates.insert(
            identity.bundle_digest.clone(),
            CandidateState {
                identity: identity.clone(),
                stage: DeploymentStage::Candidate,
                permit: None,
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_transition(
        &mut self,
        request: &PromotionRequest,
        candidate_digest: &str,
        from: DeploymentStage,
        to: DeploymentStage,
        permit: &Option<StagePermit>,
        has_stage_attestation: bool,
    ) -> Result<CandidateIdentity, PromotionAuthorityError> {
        let expected_operation = match (from, to) {
            (DeploymentStage::Candidate, DeploymentStage::Shadow) => {
                PromotionOperation::EnterShadow
            }
            (DeploymentStage::Shadow, DeploymentStage::Canary) => {
                PromotionOperation::CompleteShadow
            }
            (DeploymentStage::Canary, DeploymentStage::Active) => {
                PromotionOperation::CompleteCanary
            }
            _ => return Err(PromotionAuthorityError::InvalidRequestTransition),
        };
        if request.operation() != expected_operation
            || request.candidate_bundle_digest() != candidate_digest
            || request.expected_from() != Some(from)
            || request.target() != to
            || has_stage_attestation != (from != DeploymentStage::Candidate)
            || permit.is_some() != (to != DeploymentStage::Active)
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        let candidate = self
            .candidates
            .get_mut(candidate_digest)
            .ok_or(PromotionAuthorityError::CandidateNotFound)?;
        if candidate.stage != from {
            return Err(PromotionAuthorityError::StageMismatch);
        }
        if self.active_bundle_digest.as_deref()
            != Some(candidate.identity.baseline_bundle_digest.as_str())
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        if let Some(permit) = permit
            && (permit.candidate_bundle_digest != candidate_digest || permit.stage != to)
        {
            return Err(PromotionAuthorityError::StageMismatch);
        }
        candidate.stage = to;
        candidate.permit.clone_from(permit);
        if to == DeploymentStage::Active {
            self.active_bundle_digest = Some(candidate_digest.to_owned());
        }
        Ok(candidate.identity.clone())
    }

    fn apply_refusal(
        &self,
        request: &PromotionRequest,
        candidate_digest: &str,
        stage: DeploymentStage,
        codes: &[RefusalCode],
        attested_candidate_digest: &str,
    ) -> Result<CandidateIdentity, PromotionAuthorityError> {
        if request.candidate_bundle_digest() != candidate_digest
            || request.expected_from() != Some(stage)
            || request.operation()
                != match stage {
                    DeploymentStage::Shadow => PromotionOperation::CompleteShadow,
                    DeploymentStage::Canary => PromotionOperation::CompleteCanary,
                    _ => return Err(PromotionAuthorityError::InvalidRequestTransition),
                }
            || codes.is_empty()
            || codes.len() > 6
            || candidate_digest != attested_candidate_digest
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        let candidate = self
            .candidates
            .get(candidate_digest)
            .ok_or(PromotionAuthorityError::CandidateNotFound)?;
        if candidate.stage != stage {
            return Err(PromotionAuthorityError::StageMismatch);
        }
        Ok(candidate.identity.clone())
    }

    fn apply_rollback(
        &mut self,
        request: &PromotionRequest,
        candidate_digest: &str,
        from: DeploymentStage,
        restored_bundle_id: &str,
        restored_bundle_digest: &str,
    ) -> Result<CandidateIdentity, PromotionAuthorityError> {
        if request.operation() != PromotionOperation::Rollback
            || request.candidate_bundle_digest() != candidate_digest
            || request.expected_from() != Some(from)
            || request.target() != DeploymentStage::RolledBack
        {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        let candidate = self
            .candidates
            .get_mut(candidate_digest)
            .ok_or(PromotionAuthorityError::CandidateNotFound)?;
        if candidate.stage != from
            || candidate.identity.rollback_bundle_id != restored_bundle_id
            || candidate.identity.baseline_bundle_digest != restored_bundle_digest
        {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        let expected_active = if from == DeploymentStage::Active {
            candidate_digest
        } else {
            restored_bundle_digest
        };
        if self.active_bundle_digest.as_deref() != Some(expected_active) {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        let restored = self
            .bundles
            .get(restored_bundle_digest)
            .ok_or(PromotionAuthorityError::LineageMismatch)?;
        if restored.bundle().bundle_id != restored_bundle_id {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
        candidate.stage = DeploymentStage::RolledBack;
        candidate.permit = None;
        self.active_bundle_digest = Some(restored_bundle_digest.to_owned());
        Ok(candidate.identity.clone())
    }
}

pub(crate) fn changed_policy_slots(
    before: &PolicyBundle,
    after: &PolicyBundle,
) -> BTreeSet<StrategySlot> {
    before
        .policies
        .iter()
        .map(|policy| policy.slot.clone())
        .chain(after.policies.iter().map(|policy| policy.slot.clone()))
        .filter(|slot| before.policy_for(slot) != after.policy_for(slot))
        .collect()
}

pub(crate) fn changed_deployment_slots(
    before: &DeploymentBundle,
    after: &DeploymentBundle,
) -> Result<BTreeSet<StrategySlot>, PromotionAuthorityError> {
    match (
        crate::PolicyCheckpoint::from_deployment(before),
        crate::PolicyCheckpoint::from_deployment(after),
    ) {
        (Ok(before_checkpoint), Ok(after_checkpoint)) => {
            Ok(before_checkpoint.changed_slots(&after_checkpoint))
        }
        _ => Ok(changed_policy_slots(before.bundle(), after.bundle())),
    }
}

pub(crate) fn evaluated_slots(
    identity: &CandidateIdentity,
) -> Result<BTreeSet<StrategySlot>, PromotionAuthorityError> {
    let mut slots = BTreeSet::new();
    if !slots.insert(identity.candidate_policy.slot.clone()) {
        return Err(PromotionAuthorityError::LineageMismatch);
    }
    for evaluation in &identity.additional_evaluations {
        if !slots.insert(evaluation.candidate_policy.slot.clone()) {
            return Err(PromotionAuthorityError::LineageMismatch);
        }
    }
    Ok(slots)
}

pub(crate) fn checkpoint_evaluations_are_canonical(
    identity: &CandidateIdentity,
    changed: &BTreeSet<StrategySlot>,
    required: &BTreeSet<StrategySlot>,
) -> bool {
    checkpoint_evaluations(identity)
        .map(|evaluation| &evaluation.candidate_policy.slot)
        .eq(changed.iter().chain(required.difference(changed)))
}

pub(crate) fn checkpoint_evaluators_are_independent(
    identity: &CandidateIdentity,
    bundle: &PolicyBundle,
) -> bool {
    let policy_ids: BTreeSet<_> = bundle
        .policies
        .iter()
        .map(|policy| policy.policy_id.as_str())
        .collect();
    checkpoint_evaluations(identity).all(|evaluation| {
        evaluation.evaluator_id != &identity.bundle_id
            && !policy_ids.contains(evaluation.evaluator_id.as_str())
    })
}

pub(crate) fn checkpoint_evaluations(
    identity: &CandidateIdentity,
) -> impl Iterator<Item = CheckpointEvaluationRef<'_>> {
    std::iter::once(CheckpointEvaluationRef {
        candidate_policy: &identity.candidate_policy,
        parent_policy: &identity.parent_policy,
        artifact_digest: &identity.artifact_digest,
        training_dataset_digest: &identity.training_dataset_digest,
        evaluation_suite_digest: &identity.evaluation_suite_digest,
        base_model: &identity.base_model,
        evaluation_owner_id: &identity.evaluation_owner_id,
        evaluator_id: &identity.evaluator_id,
    })
    .chain(
        identity
            .additional_evaluations
            .iter()
            .map(|evaluation| CheckpointEvaluationRef {
                candidate_policy: &evaluation.candidate_policy,
                parent_policy: &evaluation.parent_policy,
                artifact_digest: &evaluation.artifact_digest,
                training_dataset_digest: &evaluation.training_dataset_digest,
                evaluation_suite_digest: &evaluation.evaluation_suite_digest,
                base_model: &evaluation.base_model,
                evaluation_owner_id: &evaluation.evaluation_owner_id,
                evaluator_id: &evaluation.evaluator_id,
            }),
    )
}

pub(crate) fn checkpoint_evaluation_for<'a>(
    identity: &'a CandidateIdentity,
    slot: &StrategySlot,
) -> Option<CheckpointEvaluationRef<'a>> {
    checkpoint_evaluations(identity).find(|evaluation| &evaluation.candidate_policy.slot == slot)
}

pub(crate) struct CheckpointEvaluationRef<'a> {
    pub(crate) candidate_policy: &'a crate::PolicyRef,
    pub(crate) parent_policy: &'a Option<crate::PolicyRef>,
    pub(crate) artifact_digest: &'a String,
    pub(crate) training_dataset_digest: &'a Option<String>,
    pub(crate) evaluation_suite_digest: &'a String,
    pub(crate) base_model: &'a crate::BaseModelId,
    pub(crate) evaluation_owner_id: &'a String,
    pub(crate) evaluator_id: &'a String,
}

fn refusal_code_name(code: &RefusalCode) -> String {
    match code {
        RefusalCode::StageBounds => "stage_bounds",
        RefusalCode::InvariantSuite => "invariant_suite",
        RefusalCode::BudgetPolicy => "budget_policy",
        RefusalCode::SecurityPolicy => "security_policy",
        RefusalCode::DurabilityPolicy => "durability_policy",
        RefusalCode::PromotionThreshold => "promotion_threshold",
    }
    .to_owned()
}

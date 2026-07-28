//! Deterministic replay reducer for the authenticated promotion journal.

use crate::DeploymentStage;
use crate::promotion::{DeploymentBundle, MAX_PROMOTION_CANDIDATES, PromotionAuthorityError};
use crate::promotion_auth::{PromotionOperation, PromotionRequest};
use crate::promotion_evaluation::StagePermit;
use crate::promotion_journal::{CandidateIdentity, JournalEvent, JournalRecord, RefusalCode};
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
        if self.candidates.len() >= MAX_PROMOTION_CANDIDATES {
            return Err(PromotionAuthorityError::CandidateLimit {
                max: MAX_PROMOTION_CANDIDATES,
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

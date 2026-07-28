//! Independently signed held-out and bounded-stage observations.

use crate::promotion::{
    EvaluatorTrustAnchor, MAX_PROMOTION_AUTH_BYTES, PromotionAuthorityError, PromotionAuthorityKey,
    PromotionControlPolicy, StageLimits, checked_identity,
};
use crate::verifier_crypto::{digest_serialized, hmac_serialized};
use crate::{
    BaseModelId, ContractError, DeploymentStage, PolicyRef, PromotionEvidence,
    VerifiedCandidateInputs, validate_digest,
};
use serde::{Deserialize, Serialize};

const EVALUATION_DOMAIN: &str = "core-evolve/independent-evaluation/v1";
const STAGE_RESULT_DOMAIN: &str = "core-evolve/stage-result/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeldOutEvaluation {
    pub(crate) candidate: PolicyRef,
    pub(crate) artifact_digest: String,
    pub(crate) training_dataset_digest: Option<String>,
    pub(crate) evaluation_suite_digest: String,
    /// The base model this score was gathered against.
    ///
    /// A held-out number means nothing without the weights it was measured on: the same candidate
    /// scored against two base models yields two incomparable results, and the transfer operator
    /// exists precisely to compare evaluations that differ only in this field. It lives inside the
    /// signed report, so the base model is **attested** rather than asserted alongside it, and
    /// `verify_held_out_without_suite` binds it to the candidate identity the authority holds.
    ///
    /// It is populated from [`VerifiedCandidateInputs`], which copies it off the validated
    /// manifest, so an evaluator cannot name a base model of its own choosing.
    pub(crate) base_model: BaseModelId,
    pub(crate) evidence: PromotionEvidence,
}

impl HeldOutEvaluation {
    pub fn new(
        candidate: PolicyRef,
        verified: &VerifiedCandidateInputs,
        evidence: PromotionEvidence,
    ) -> Result<Self, PromotionAuthorityError> {
        let report = Self {
            candidate,
            artifact_digest: verified.artifact_digest.clone(),
            training_dataset_digest: verified.training_dataset_digest.clone(),
            evaluation_suite_digest: verified.evaluation_suite_digest.clone(),
            base_model: verified.base_model.clone(),
            evidence,
        };
        report.validate()?;
        Ok(report)
    }

    /// The base model this evaluation attests to.
    pub fn base_model(&self) -> &BaseModelId {
        &self.base_model
    }

    fn validate(&self) -> Result<(), PromotionAuthorityError> {
        self.candidate.validate()?;
        validate_digest(&self.artifact_digest)?;
        if let Some(digest) = &self.training_dataset_digest {
            validate_digest(digest)?;
        }
        validate_digest(&self.evaluation_suite_digest)?;
        self.base_model.validate()?;
        // The two live checks the deleted, unsigned `HeldOutEvidence::validate` used to perform are
        // inherited here, where they now sit inside the signed payload rather than beside it. A
        // document that never recorded its base model cannot attest anything about one, so the
        // migration sentinel is refused rather than treated as a wildcard.
        if !self.base_model.is_admissible() {
            return Err(ContractError::InvalidBaseModel(
                "a held-out evaluation cannot rest on an inadmissible base model identity",
            )
            .into());
        }
        self.evidence.validate_contract()?;
        if self.evidence.candidate != self.candidate {
            return Err(PromotionAuthorityError::EvaluationIdentityMismatch);
        }
        Ok(())
    }

    pub fn evidence(&self) -> &PromotionEvidence {
        &self.evidence
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedHeldOutEvaluation {
    pub(crate) evaluator_id: String,
    pub(crate) report: HeldOutEvaluation,
    pub(crate) signature: String,
}

impl std::fmt::Debug for SignedHeldOutEvaluation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedHeldOutEvaluation")
            .field("evaluator_id", &self.evaluator_id)
            .field("report", &self.report)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageObservation {
    pub(crate) permit_digest: String,
    pub(crate) candidate_bundle_digest: String,
    pub(crate) stage: DeploymentStage,
    pub(crate) executed_work_units: u32,
    pub(crate) peak_concurrency: u16,
    pub(crate) duration_ms: u64,
    pub(crate) traffic_basis_points: u16,
    pub(crate) cost_microusd: u64,
    pub(crate) applied_security_policy_digest: String,
    pub(crate) applied_durability_policy_digest: String,
    pub(crate) evidence: PromotionEvidence,
}

impl StageObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        permit: &StagePermit,
        executed_work_units: u32,
        peak_concurrency: u16,
        duration_ms: u64,
        traffic_basis_points: u16,
        cost_microusd: u64,
        applied_security_policy_digest: impl Into<String>,
        applied_durability_policy_digest: impl Into<String>,
        evidence: PromotionEvidence,
    ) -> Result<Self, PromotionAuthorityError> {
        evidence.validate_contract()?;
        let observation = Self {
            permit_digest: permit.digest.clone(),
            candidate_bundle_digest: permit.candidate_bundle_digest.clone(),
            stage: permit.stage,
            executed_work_units,
            peak_concurrency,
            duration_ms,
            traffic_basis_points,
            cost_microusd,
            applied_security_policy_digest: applied_security_policy_digest.into(),
            applied_durability_policy_digest: applied_durability_policy_digest.into(),
            evidence,
        };
        validate_digest(&observation.applied_security_policy_digest)?;
        validate_digest(&observation.applied_durability_policy_digest)?;
        Ok(observation)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedStageObservation {
    pub(crate) evaluator_id: String,
    pub(crate) observation: StageObservation,
    pub(crate) signature: String,
}

impl std::fmt::Debug for SignedStageObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedStageObservation")
            .field("evaluator_id", &self.evaluator_id)
            .field("observation", &self.observation)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct IndependentEvaluator {
    evaluator_id: String,
    key: PromotionAuthorityKey,
}

impl IndependentEvaluator {
    pub fn new(
        evaluator_id: impl Into<String>,
        key: PromotionAuthorityKey,
    ) -> Result<Self, PromotionAuthorityError> {
        Ok(Self {
            evaluator_id: checked_identity("evaluator.evaluator_id", evaluator_id.into())?,
            key,
        })
    }

    pub fn sign_held_out(
        &self,
        report: HeldOutEvaluation,
    ) -> Result<SignedHeldOutEvaluation, PromotionAuthorityError> {
        report.validate()?;
        let signature = evaluator_hmac(
            self.key.bytes(),
            EVALUATION_DOMAIN,
            &self.evaluator_id,
            &report,
        )?;
        Ok(SignedHeldOutEvaluation {
            evaluator_id: self.evaluator_id.clone(),
            report,
            signature,
        })
    }

    pub fn sign_stage(
        &self,
        observation: StageObservation,
    ) -> Result<SignedStageObservation, PromotionAuthorityError> {
        let signature = evaluator_hmac(
            self.key.bytes(),
            STAGE_RESULT_DOMAIN,
            &self.evaluator_id,
            &observation,
        )?;
        Ok(SignedStageObservation {
            evaluator_id: self.evaluator_id.clone(),
            observation,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagePermit {
    pub(crate) digest: String,
    pub(crate) authority_id: String,
    pub(crate) policy_digest: String,
    pub(crate) candidate_bundle_digest: String,
    pub(crate) stage: DeploymentStage,
    pub(crate) limits: StageLimits,
    pub(crate) security_policy_digest: String,
    pub(crate) durability_policy_digest: String,
}

/// Offline executor boundary. The authority supplies an immutable permit and re-verifies the
/// independently signed result before changing stage; this trait has no runtime-kernel handle.
pub trait BoundedStageExecutor {
    fn execute(
        &mut self,
        permit: &StagePermit,
        suite: &crate::EvaluationSuite,
    ) -> Result<SignedStageObservation, PromotionAuthorityError>;
}

impl StagePermit {
    pub(crate) fn issue(
        authority_id: &str,
        policy_digest: &str,
        candidate_bundle_digest: &str,
        stage: DeploymentStage,
        policy: &PromotionControlPolicy,
    ) -> Result<Self, PromotionAuthorityError> {
        let limits = policy
            .limits(stage)
            .ok_or(PromotionAuthorityError::InvalidRequestTransition)?;
        #[derive(Serialize)]
        struct Content<'a> {
            authority_id: &'a str,
            policy_digest: &'a str,
            candidate_bundle_digest: &'a str,
            stage: DeploymentStage,
            limits: StageLimits,
            security_policy_digest: &'a str,
            durability_policy_digest: &'a str,
        }
        let content = Content {
            authority_id,
            policy_digest,
            candidate_bundle_digest,
            stage,
            limits,
            security_policy_digest: policy.security_policy_digest(),
            durability_policy_digest: policy.durability_policy_digest(),
        };
        let digest = digest_serialized(&content, MAX_PROMOTION_AUTH_BYTES)?;
        Ok(Self {
            digest,
            authority_id: authority_id.to_owned(),
            policy_digest: policy_digest.to_owned(),
            candidate_bundle_digest: candidate_bundle_digest.to_owned(),
            stage,
            limits,
            security_policy_digest: policy.security_policy_digest().to_owned(),
            durability_policy_digest: policy.durability_policy_digest().to_owned(),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn stage(&self) -> DeploymentStage {
        self.stage
    }

    pub fn limits(&self) -> StageLimits {
        self.limits
    }
}

pub(crate) fn evaluation_signature(
    anchor: &EvaluatorTrustAnchor,
    domain: &'static str,
    value: &impl Serialize,
) -> Result<String, PromotionAuthorityError> {
    evaluator_hmac(anchor.key.bytes(), domain, &anchor.evaluator_id, value)
}

pub(crate) fn held_out_domain() -> &'static str {
    EVALUATION_DOMAIN
}

pub(crate) fn stage_result_domain() -> &'static str {
    STAGE_RESULT_DOMAIN
}

fn evaluator_hmac(
    key: &[u8],
    domain: &'static str,
    evaluator_id: &str,
    value: &impl Serialize,
) -> Result<String, PromotionAuthorityError> {
    #[derive(Serialize)]
    struct Payload<'a, T> {
        domain: &'static str,
        evaluator_id: &'a str,
        value: &'a T,
    }
    Ok(hmac_serialized(
        key,
        &Payload {
            domain,
            evaluator_id,
            value,
        },
        MAX_PROMOTION_AUTH_BYTES,
    )?)
}

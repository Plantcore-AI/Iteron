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
            evidence,
        };
        // The identity the caller put on the evidence must be the one the VERIFIER read off the
        // validated manifest. Refusing the mismatch here is what stops an evaluator naming a base
        // model of its own choosing: the field is inside the signed payload either way, so without
        // this check the signature would faithfully attest whatever the evaluator felt like.
        if report.evidence.base_model != verified.base_model {
            return Err(ContractError::InvalidBaseModel(
                "held-out evidence names a different base model than the verified candidate inputs",
            )
            .into());
        }
        report.validate()?;
        Ok(report)
    }

    /// The base model this evaluation attests to.
    ///
    /// Read through to the evidence rather than duplicated onto this type. Two fields naming the
    /// same thing is two fields that can disagree, and a signed attestation that disagrees with
    /// itself is worse than one that says less.
    pub fn base_model(&self) -> &BaseModelId {
        &self.evidence.base_model
    }

    fn validate(&self) -> Result<(), PromotionAuthorityError> {
        self.candidate.validate()?;
        validate_digest(&self.artifact_digest)?;
        if let Some(digest) = &self.training_dataset_digest {
            validate_digest(digest)?;
        }
        validate_digest(&self.evaluation_suite_digest)?;
        // `validate_contract` carries the base-model checks now: it refuses a malformed identity and
        // refuses the migration sentinel, because evidence gathered against weights nobody recorded
        // attests nothing. Those are the two live checks the deleted, unsigned `HeldOutEvidence`
        // used to perform, and they now sit on the type BOTH carriers share.
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

impl SignedHeldOutEvaluation {
    /// Who signed this attestation.
    ///
    /// Readable, and deliberately so: an implementor of the eval -> evolve seam has to be able to
    /// say which evaluator produced what it is handing back. Reading it proves nothing about
    /// authenticity — only `PromotionAuthority` can, by resolving this id against its configured
    /// anchors and recomputing the HMAC.
    pub fn evaluator_id(&self) -> &str {
        &self.evaluator_id
    }

    /// The attested report.
    ///
    /// These two accessors exist because an adversarial review proved the type was completely opaque
    /// outside this crate — `pub(crate)` fields, no accessor of any kind — while
    /// [`crate::HeldOutEvidenceBridge`]'s own doc told an implementor that the `base_model` argument
    /// was "checkable against the returned report". It was not: a probe crate holding only
    /// `core-evolve` got `E0616: field report is private`. And out-of-crate is the *only* place an
    /// implementor may live, because `core-xtask boundaries check` forbids implementing that seam
    /// inside this crate outside a test target. A doc that states a property only the one forbidden
    /// crate can use is the same defect this seam was already corrected for once.
    ///
    /// **The barrier is the key, not the field visibility.** `pub(crate)` stops a struct literal
    /// from outside and nothing more: this type derives `Deserialize`, and serde's generated impl
    /// lives inside this crate, so `serde_json::from_value` reconstitutes one from a crate holding
    /// only `core-evolve` — a review did exactly that, with an attacker-chosen evaluator id and
    /// signature, and mutated the contents on the way through. What that forgery cannot do is make
    /// the HMAC verify against an anchor the authority configured, which is the whole guarantee and
    /// the only one worth stating.
    pub fn report(&self) -> &HeldOutEvaluation {
        &self.report
    }
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
    /// The base model this stage was observed against.
    ///
    /// A stage observation is signed separately from the held-out evaluation and is what a third
    /// party actually holds, so it has to be able to say what it was measured on. Before the base
    /// model moved onto `PromotionEvidence` it could not: attribution existed only transitively,
    /// through a `pub(crate)` `CandidateIdentity` reachable from inside this crate alone.
    pub fn base_model(&self) -> &BaseModelId {
        &self.evidence.base_model
    }

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

impl SignedStageObservation {
    /// Who signed this observation.
    pub fn evaluator_id(&self) -> &str {
        &self.evaluator_id
    }

    /// The attested observation.
    ///
    /// `complete_shadow` and `complete_canary` take one of these by value from a public caller, so
    /// an outside orchestrator holds one — and until this existed it could inspect nothing on it, not
    /// even which evaluator signed it. `StageObservation::base_model` was public and unreachable
    /// through the wrapper, which made its own doc comment ("what a third party actually holds, so it
    /// has to be able to say what it was measured on") describe something no third party could do.
    /// The sibling type was given the same pair of accessors one commit earlier for the same reason;
    /// this one was missed.
    ///
    /// As with the held-out attestation, `pub(crate)` blocks a struct literal and nothing else — the
    /// derived `Deserialize` is generated inside this crate, so one can be reconstituted and altered
    /// from outside. The guarantee lives in `stage_refusal_codes`, which resolves the evaluator id
    /// against the configured anchors, recomputes the HMAC, and refuses an id equal to the
    /// candidate's own policy id or bundle id.
    pub fn observation(&self) -> &StageObservation {
        &self.observation
    }
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

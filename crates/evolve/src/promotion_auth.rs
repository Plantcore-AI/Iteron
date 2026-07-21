//! Narrow action authorization for the offline promotion state machine.

use crate::promotion::{
    MAX_PROMOTION_AUTH_BYTES, PromotionAuthorityError, PromotionAuthorityKey, PromotionRole,
    PromotionTrustAnchor, checked_identity,
};
use crate::verifier_crypto::hmac_serialized;
use crate::{DeploymentStage, validate_digest};
use serde::{Deserialize, Serialize};

const AUTHORIZATION_DOMAIN: &str = "core-evolve/promotion-authorization/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionOperation {
    Bootstrap,
    AdmitCandidate,
    EnterShadow,
    CompleteShadow,
    CompleteCanary,
    Rollback,
}

impl PromotionOperation {
    pub(crate) fn required_role(self) -> PromotionRole {
        match self {
            Self::Bootstrap => PromotionRole::Bootstrap,
            Self::AdmitCandidate => PromotionRole::AdmitCandidate,
            Self::EnterShadow | Self::CompleteShadow | Self::CompleteCanary => {
                PromotionRole::AdvanceStage
            }
            Self::Rollback => PromotionRole::Rollback,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionRequest {
    authorization_id: String,
    operation: PromotionOperation,
    candidate_bundle_digest: String,
    expected_from: Option<DeploymentStage>,
    target: DeploymentStage,
}

impl PromotionRequest {
    fn new(
        authorization_id: impl Into<String>,
        operation: PromotionOperation,
        candidate_bundle_digest: impl Into<String>,
        expected_from: Option<DeploymentStage>,
        target: DeploymentStage,
    ) -> Result<Self, PromotionAuthorityError> {
        let request = Self {
            authorization_id: checked_identity(
                "promotion.authorization_id",
                authorization_id.into(),
            )?,
            operation,
            candidate_bundle_digest: candidate_bundle_digest.into(),
            expected_from,
            target,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn bootstrap(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::Bootstrap,
            bundle_digest,
            None,
            DeploymentStage::Active,
        )
    }

    pub fn admit_candidate(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::AdmitCandidate,
            bundle_digest,
            None,
            DeploymentStage::Candidate,
        )
    }

    pub fn enter_shadow(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::EnterShadow,
            bundle_digest,
            Some(DeploymentStage::Candidate),
            DeploymentStage::Shadow,
        )
    }

    pub fn complete_shadow(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::CompleteShadow,
            bundle_digest,
            Some(DeploymentStage::Shadow),
            DeploymentStage::Canary,
        )
    }

    pub fn complete_canary(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::CompleteCanary,
            bundle_digest,
            Some(DeploymentStage::Canary),
            DeploymentStage::Active,
        )
    }

    pub fn rollback(
        authorization_id: impl Into<String>,
        bundle_digest: impl Into<String>,
        from: DeploymentStage,
    ) -> Result<Self, PromotionAuthorityError> {
        Self::new(
            authorization_id,
            PromotionOperation::Rollback,
            bundle_digest,
            Some(from),
            DeploymentStage::RolledBack,
        )
    }

    pub(crate) fn validate(&self) -> Result<(), PromotionAuthorityError> {
        checked_identity("promotion.authorization_id", self.authorization_id.clone())?;
        validate_digest(&self.candidate_bundle_digest)?;
        let valid = matches!(
            (self.operation, self.expected_from, self.target),
            (PromotionOperation::Bootstrap, None, DeploymentStage::Active)
                | (
                    PromotionOperation::AdmitCandidate,
                    None,
                    DeploymentStage::Candidate
                )
                | (
                    PromotionOperation::EnterShadow,
                    Some(DeploymentStage::Candidate),
                    DeploymentStage::Shadow
                )
                | (
                    PromotionOperation::CompleteShadow,
                    Some(DeploymentStage::Shadow),
                    DeploymentStage::Canary
                )
                | (
                    PromotionOperation::CompleteCanary,
                    Some(DeploymentStage::Canary),
                    DeploymentStage::Active
                )
                | (
                    PromotionOperation::Rollback,
                    Some(
                        DeploymentStage::Shadow | DeploymentStage::Canary | DeploymentStage::Active
                    ),
                    DeploymentStage::RolledBack
                )
        );
        if !valid {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
        Ok(())
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    pub fn operation(&self) -> PromotionOperation {
        self.operation
    }

    pub fn candidate_bundle_digest(&self) -> &str {
        &self.candidate_bundle_digest
    }

    pub fn expected_from(&self) -> Option<DeploymentStage> {
        self.expected_from
    }

    pub fn target(&self) -> DeploymentStage {
        self.target
    }
}

#[derive(Serialize)]
struct AuthorizationPayload<'a> {
    domain: &'static str,
    authority_id: &'a str,
    policy_digest: &'a str,
    party_id: &'a str,
    request: &'a PromotionRequest,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PromotionAuthorization {
    pub(crate) party_id: String,
    pub(crate) signature: String,
}

impl std::fmt::Debug for PromotionAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PromotionAuthorization")
            .field("party_id", &self.party_id)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct PromotionAuthorizer {
    authority_id: String,
    policy_digest: String,
    party_id: String,
    key: PromotionAuthorityKey,
}

impl PromotionAuthorizer {
    pub fn new(
        authority_id: impl Into<String>,
        policy_digest: impl Into<String>,
        party_id: impl Into<String>,
        key: PromotionAuthorityKey,
    ) -> Result<Self, PromotionAuthorityError> {
        let policy_digest = policy_digest.into();
        validate_digest(&policy_digest)?;
        Ok(Self {
            authority_id: checked_identity("promotion.authority_id", authority_id.into())?,
            policy_digest,
            party_id: checked_identity("promotion.party_id", party_id.into())?,
            key,
        })
    }

    pub fn authorize(
        &self,
        request: &PromotionRequest,
    ) -> Result<PromotionAuthorization, PromotionAuthorityError> {
        request.validate()?;
        let signature = authorization_hmac(
            self.key.bytes(),
            &self.authority_id,
            &self.policy_digest,
            &self.party_id,
            request,
        )?;
        Ok(PromotionAuthorization {
            party_id: self.party_id.clone(),
            signature,
        })
    }
}

pub(crate) fn authorization_signature(
    anchor: &PromotionTrustAnchor,
    authority_id: &str,
    policy_digest: &str,
    request: &PromotionRequest,
) -> Result<String, PromotionAuthorityError> {
    authorization_hmac(
        anchor.key.bytes(),
        authority_id,
        policy_digest,
        &anchor.party_id,
        request,
    )
}

fn authorization_hmac(
    key: &[u8],
    authority_id: &str,
    policy_digest: &str,
    party_id: &str,
    request: &PromotionRequest,
) -> Result<String, PromotionAuthorityError> {
    Ok(hmac_serialized(
        key,
        &AuthorizationPayload {
            domain: AUTHORIZATION_DOMAIN,
            authority_id,
            policy_digest,
            party_id,
            request,
        },
        MAX_PROMOTION_AUTH_BYTES,
    )?)
}

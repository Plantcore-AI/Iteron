//! Fixed policy, trust anchors, and exact deployment bytes for governed promotion.

use crate::verifier_crypto::{digest_serialized, sha256_hex};
use crate::{
    ContractError, DeploymentStage, MAX_SHORT_STRING_BYTES, PolicyBundle, PromotionGate,
    VerifierError, validate_digest, validate_nonempty_string,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_PROMOTION_KEY_BYTES: usize = 64;
pub const MAX_PROMOTION_TRUST_ANCHORS: usize = 32;
pub const MAX_EVALUATOR_TRUST_ANCHORS: usize = 32;
pub const MAX_DEPLOYMENT_BUNDLE_BYTES: usize = 256 * 1024;
pub const MAX_PROMOTION_CANDIDATES: usize = 256;
pub const MAX_PROMOTION_AUDIT_EVENTS: usize = 8_192;
pub const MAX_PROMOTION_AUTH_BYTES: usize = 256 * 1024;

const MIN_PROMOTION_KEY_BYTES: usize = 16;

#[derive(Clone, PartialEq, Eq)]
pub struct PromotionAuthorityKey(Vec<u8>);

impl PromotionAuthorityKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, PromotionAuthorityError> {
        let bytes = bytes.into();
        if !(MIN_PROMOTION_KEY_BYTES..=MAX_PROMOTION_KEY_BYTES).contains(&bytes.len()) {
            return Err(PromotionAuthorityError::InvalidKeyLength {
                min: MIN_PROMOTION_KEY_BYTES,
                max: MAX_PROMOTION_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for PromotionAuthorityKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PromotionAuthorityKey([REDACTED])")
    }
}

impl Drop for PromotionAuthorityKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionRole {
    Bootstrap,
    AdmitCandidate,
    AdvanceStage,
    Rollback,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PromotionTrustAnchor {
    pub(crate) party_id: String,
    pub(crate) roles: BTreeSet<PromotionRole>,
    pub(crate) key: PromotionAuthorityKey,
}

impl PromotionTrustAnchor {
    pub fn new(
        party_id: impl Into<String>,
        roles: BTreeSet<PromotionRole>,
        key: PromotionAuthorityKey,
    ) -> Result<Self, PromotionAuthorityError> {
        let party_id = checked_identity("promotion.party_id", party_id.into())?;
        if roles.is_empty() || roles.len() > 4 {
            return Err(PromotionAuthorityError::InvalidRoles);
        }
        Ok(Self {
            party_id,
            roles,
            key,
        })
    }
}

impl std::fmt::Debug for PromotionTrustAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PromotionTrustAnchor")
            .field("party_id", &self.party_id)
            .field("roles", &self.roles)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EvaluatorTrustAnchor {
    pub(crate) evaluator_id: String,
    pub(crate) suite_owner_id: String,
    pub(crate) key: PromotionAuthorityKey,
}

impl EvaluatorTrustAnchor {
    pub fn new(
        evaluator_id: impl Into<String>,
        suite_owner_id: impl Into<String>,
        key: PromotionAuthorityKey,
    ) -> Result<Self, PromotionAuthorityError> {
        Ok(Self {
            evaluator_id: checked_identity("evaluator.evaluator_id", evaluator_id.into())?,
            suite_owner_id: checked_identity("evaluator.suite_owner_id", suite_owner_id.into())?,
            key,
        })
    }
}

impl std::fmt::Debug for EvaluatorTrustAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvaluatorTrustAnchor")
            .field("evaluator_id", &self.evaluator_id)
            .field("suite_owner_id", &self.suite_owner_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLimits {
    max_work_units: u32,
    max_concurrency: u16,
    max_duration_ms: u64,
    max_traffic_basis_points: u16,
    max_cost_microusd: u64,
}

impl StageLimits {
    pub fn new(
        max_work_units: u32,
        max_concurrency: u16,
        max_duration_ms: u64,
        max_traffic_basis_points: u16,
        max_cost_microusd: u64,
    ) -> Result<Self, PromotionAuthorityError> {
        let limits = Self {
            max_work_units,
            max_concurrency,
            max_duration_ms,
            max_traffic_basis_points,
            max_cost_microusd,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), PromotionAuthorityError> {
        if self.max_work_units == 0
            || self.max_work_units > 100_000
            || self.max_concurrency == 0
            || self.max_concurrency > 64
            || self.max_duration_ms == 0
            || self.max_duration_ms > 7 * 24 * 60 * 60 * 1_000
            || self.max_traffic_basis_points > 10_000
            || self.max_cost_microusd == 0
        {
            return Err(PromotionAuthorityError::InvalidStageLimits);
        }
        Ok(())
    }

    pub fn max_work_units(self) -> u32 {
        self.max_work_units
    }

    pub fn max_concurrency(self) -> u16 {
        self.max_concurrency
    }

    pub fn max_duration_ms(self) -> u64 {
        self.max_duration_ms
    }

    pub fn max_traffic_basis_points(self) -> u16 {
        self.max_traffic_basis_points
    }

    pub fn max_cost_microusd(self) -> u64 {
        self.max_cost_microusd
    }
}

/// Immutable safety and blast-radius policy. There is deliberately no mutation API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionControlPolicy {
    gate: PromotionGate,
    shadow: StageLimits,
    canary: StageLimits,
    security_policy_digest: String,
    durability_policy_digest: String,
}

impl PromotionControlPolicy {
    pub fn new(
        gate: PromotionGate,
        shadow: StageLimits,
        canary: StageLimits,
        security_policy_digest: impl Into<String>,
        durability_policy_digest: impl Into<String>,
    ) -> Result<Self, PromotionAuthorityError> {
        let policy = Self {
            gate,
            shadow,
            canary,
            security_policy_digest: security_policy_digest.into(),
            durability_policy_digest: durability_policy_digest.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PromotionAuthorityError> {
        self.gate.validate()?;
        self.shadow.validate()?;
        self.canary.validate()?;
        let mandatory: BTreeSet<String> =
            ["runtime".into(), "security".into(), "durability".into()].into();
        if !self.gate.require_replay_equivalence
            || !self.gate.require_sandbox_suite
            || !mandatory.is_subset(&self.gate.required_invariant_suites)
        {
            return Err(PromotionAuthorityError::InvalidMandatoryInvariants);
        }
        if self.shadow.max_traffic_basis_points != 0
            || self.canary.max_traffic_basis_points == 0
            || self.canary.max_traffic_basis_points > 1_000
        {
            return Err(PromotionAuthorityError::InvalidBlastRadius);
        }
        validate_digest(&self.security_policy_digest)?;
        validate_digest(&self.durability_policy_digest)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, PromotionAuthorityError> {
        Ok(digest_serialized(self, MAX_PROMOTION_AUTH_BYTES)?)
    }

    pub(crate) fn gate(&self) -> &PromotionGate {
        &self.gate
    }

    pub(crate) fn limits(&self, stage: DeploymentStage) -> Option<StageLimits> {
        match stage {
            DeploymentStage::Shadow => Some(self.shadow),
            DeploymentStage::Canary => Some(self.canary),
            _ => None,
        }
    }

    pub fn security_policy_digest(&self) -> &str {
        &self.security_policy_digest
    }

    pub fn durability_policy_digest(&self) -> &str {
        &self.durability_policy_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentBundle {
    bundle: PolicyBundle,
    bytes: Vec<u8>,
}

impl DeploymentBundle {
    pub fn new(bundle: PolicyBundle, bytes: Vec<u8>) -> Result<Self, PromotionAuthorityError> {
        bundle.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_DEPLOYMENT_BUNDLE_BYTES {
            return Err(PromotionAuthorityError::InvalidBundleBytes {
                max: MAX_DEPLOYMENT_BUNDLE_BYTES,
                actual: bytes.len(),
            });
        }
        if sha256_hex(&bytes) != bundle.digest {
            return Err(PromotionAuthorityError::BundleDigestMismatch);
        }
        Ok(Self { bundle, bytes })
    }

    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn validate(&self) -> Result<(), PromotionAuthorityError> {
        Self::new(self.bundle.clone(), self.bytes.clone()).map(|_| ())
    }
}

impl std::fmt::Debug for DeploymentBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentBundle")
            .field("bundle", &self.bundle)
            .field("bytes", &format_args!("[{} bytes]", self.bytes.len()))
            .finish()
    }
}

pub(crate) fn checked_identity(
    field: &'static str,
    value: String,
) -> Result<String, PromotionAuthorityError> {
    validate_nonempty_string(field, &value, MAX_SHORT_STRING_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(PromotionAuthorityError::InvalidIdentity);
    }
    Ok(value)
}

#[derive(Debug, thiserror::Error)]
pub enum PromotionAuthorityError {
    #[error("promotion authority I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("promotion authority JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evolution contract is invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("candidate verification failed: {0}")]
    Verifier(#[from] VerifierError),
    #[error("checkpoint manifest admission failed: {0}")]
    CheckpointAdmission(#[from] crate::CapabilityAdmissionError),
    #[error("dataset registry rejected the candidate: {0}")]
    Dataset(#[from] crate::DatasetRegistryError),
    #[error("private candidate storage failed: {0}")]
    PrivateContent(#[from] crate::EvolutionPrivateContentError),
    #[error("authority key length is {actual}; expected {min}..={max} bytes")]
    InvalidKeyLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("promotion authority identity is invalid")]
    InvalidIdentity,
    #[error("promotion trust anchor must grant one or more known roles")]
    InvalidRoles,
    #[error("promotion stage limits exceed the fixed contract")]
    InvalidStageLimits,
    #[error("shadow must receive zero traffic and canary traffic must be in 1..=1000 basis points")]
    InvalidBlastRadius,
    #[error(
        "promotion policy must retain replay, sandbox, runtime, security, and durability invariants"
    )]
    InvalidMandatoryInvariants,
    #[error("deployment bundle byte count is {actual}; expected 1..={max}")]
    InvalidBundleBytes { max: usize, actual: usize },
    #[error("deployment bundle digest does not match its exact bytes")]
    BundleDigestMismatch,
    #[error("promotion request encodes an invalid stage transition")]
    InvalidRequestTransition,
    #[error("promotion/evaluator trust anchor count is invalid or contains duplicates")]
    InvalidTrustConfiguration,
    #[error("evaluation identity or content is not bound to the candidate proof")]
    EvaluationIdentityMismatch,
    #[error("evaluation was not signed by the configured independent evaluator")]
    IndependentEvaluationRequired,
    #[error("promotion authorization is invalid or not trusted for this operation")]
    Unauthorized,
    #[error("promotion authorization id was already consumed")]
    AuthorizationReplay,
    #[error("authority is already bootstrapped")]
    AlreadyBootstrapped,
    #[error("authority has no active baseline")]
    MissingBaseline,
    #[error("candidate count reached the fixed limit of {max}")]
    CandidateLimit { max: usize },
    #[error("candidate bundle is already registered or conflicts with immutable identity")]
    CandidateConflict,
    #[error("candidate bundle or rollback lineage does not match the active baseline")]
    LineageMismatch,
    #[error("checkpoint requires fresh held-out evidence before it can become a deployment bundle")]
    FreshHeldOutRequired,
    #[error("candidate is not registered")]
    CandidateNotFound,
    #[error("candidate stage does not match the authorized transition")]
    StageMismatch,
    #[error("stage result exceeded its permit or relaxed an invariant policy")]
    StageRefused,
    #[error("promotion assessor refused authenticated evidence: {reasons:?}")]
    PromotionRefused { reasons: Vec<String> },
    #[error("journal path is a symlink or unexpected file kind: {path}")]
    InvalidJournalPath { path: std::path::PathBuf },
    #[error("promotion journal already has an active writer: {path}")]
    WriterBusy { path: std::path::PathBuf },
    #[error("promotion journal writer is poisoned; reopen it before retrying")]
    WriterPoisoned,
    #[error("promotion journal record is {actual} bytes; limit is {max}")]
    RecordTooLarge { max: usize, actual: usize },
    #[error("promotion journal is {actual} bytes; limit is {max}")]
    JournalTooLarge { max: u64, actual: u64 },
    #[error("promotion journal reached the fixed {max}-record limit")]
    AuditLimit { max: usize },
    #[error("promotion journal hash chain or sequence is corrupt at record {sequence}")]
    CorruptJournal { sequence: u64 },
    #[error("promotion journal schema {found} is unsupported at record {sequence}")]
    UnsupportedJournalSchema { sequence: u64, found: u16 },
}

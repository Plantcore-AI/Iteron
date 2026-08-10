//! Authenticated, content-recomputing verifier for the offline evolution plane.
//!
//! This is a separate evolution TCB. It authenticates evidence and emits immutable proofs; it has
//! no dependency on the runtime kernel and exposes no policy activation, capability grant, or
//! deployment-stage mutation operation.

use crate::verifier_crypto::{constant_time_eq, digest_serialized, hmac_serialized, sha256_hex};
use crate::verifier_eval::EvaluationSuite;
use crate::{
    BaseModelId, ContractError, EvidenceRecordError, EvidenceRecorder, MAX_GOVERNED_DATASET_BYTES,
    MAX_GOVERNED_DATASET_TRAJECTORIES, MAX_SHORT_STRING_BYTES, MAX_TRAJECTORY_JSON_BYTES,
    PolicyManifest, TrainingAdmissionPolicy, TrainingEligibilityError, TrajectoryEnvelope,
    validate_nonempty_string,
};
use iteron_protocol::TenantId;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_TRUSTED_PRODUCERS: usize = 128;
pub const MAX_ATTESTATION_KEY_BYTES: usize = 64;
pub const MAX_VERIFIED_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MIN_ATTESTATION_KEY_BYTES: usize = 16;
const ATTESTATION_DOMAIN: &str = "core-evolution-trajectory-attestation-v1";

#[derive(Clone, PartialEq, Eq)]
pub struct AttestationKey(Vec<u8>);

impl AttestationKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, VerifierError> {
        let bytes = bytes.into();
        if !(MIN_ATTESTATION_KEY_BYTES..=MAX_ATTESTATION_KEY_BYTES).contains(&bytes.len()) {
            return Err(VerifierError::InvalidAttestationKeyLength {
                min: MIN_ATTESTATION_KEY_BYTES,
                max: MAX_ATTESTATION_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AttestationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttestationKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProducerTrustAnchor {
    producer_id: String,
    tenant_id: TenantId,
    key: AttestationKey,
}

impl ProducerTrustAnchor {
    pub fn new(
        producer_id: impl Into<String>,
        tenant_id: TenantId,
        key: AttestationKey,
    ) -> Result<Self, VerifierError> {
        let producer_id = producer_id.into();
        validate_nonempty_string(
            "producer_trust.producer_id",
            &producer_id,
            MAX_SHORT_STRING_BYTES,
        )
        .map_err(VerifierError::InvalidContract)?;
        validate_nonempty_string(
            "producer_trust.tenant_id",
            &tenant_id.0,
            MAX_SHORT_STRING_BYTES,
        )
        .map_err(VerifierError::InvalidContract)?;
        Ok(Self {
            producer_id,
            tenant_id,
            key,
        })
    }
}

impl std::fmt::Debug for ProducerTrustAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProducerTrustAnchor")
            .field("producer_id", &self.producer_id)
            .field("tenant_id", &self.tenant_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct AttestationPayload<'a> {
    domain: &'static str,
    producer_id: &'a str,
    envelope_digest: &'a str,
    envelope: &'a TrajectoryEnvelope,
}

#[derive(Clone, PartialEq)]
pub struct SignedTrajectory {
    producer_id: String,
    envelope_digest: String,
    envelope: TrajectoryEnvelope,
    signature: String,
}

impl std::fmt::Debug for SignedTrajectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedTrajectory")
            .field("producer_id", &self.producer_id)
            .field("tenant_id", &self.envelope.tenant_id)
            .field("run_id", &self.envelope.run_id)
            .field("task_id", &self.envelope.task_id)
            .field("envelope_digest", &self.envelope_digest)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl SignedTrajectory {
    pub fn sign(
        producer_id: impl Into<String>,
        envelope: TrajectoryEnvelope,
        key: &AttestationKey,
    ) -> Result<Self, VerifierError> {
        let producer_id = producer_id.into();
        validate_nonempty_string(
            "signed_trajectory.producer_id",
            &producer_id,
            MAX_SHORT_STRING_BYTES,
        )
        .map_err(VerifierError::InvalidContract)?;
        envelope
            .validate()
            .map_err(VerifierError::InvalidContract)?;
        let envelope_digest = digest_serialized(&envelope, MAX_TRAJECTORY_JSON_BYTES)?;
        let payload = AttestationPayload {
            domain: ATTESTATION_DOMAIN,
            producer_id: &producer_id,
            envelope_digest: &envelope_digest,
            envelope: &envelope,
        };
        let signature = hmac_serialized(key.bytes(), &payload, MAX_TRAJECTORY_JSON_BYTES)?;
        Ok(Self {
            producer_id,
            envelope_digest,
            envelope,
            signature,
        })
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub fn envelope(&self) -> &TrajectoryEnvelope {
        &self.envelope
    }

    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

#[derive(Clone, Copy)]
pub struct VerifiedTrajectory<'a> {
    envelope: &'a TrajectoryEnvelope,
    producer_id: &'a str,
    envelope_digest: &'a str,
}

impl std::fmt::Debug for VerifiedTrajectory<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedTrajectory")
            .field("producer_id", &self.producer_id)
            .field("tenant_id", &self.envelope.tenant_id)
            .field("run_id", &self.envelope.run_id)
            .field("task_id", &self.envelope.task_id)
            .field("envelope_digest", &self.envelope_digest)
            .finish()
    }
}

impl<'a> VerifiedTrajectory<'a> {
    pub fn envelope(self) -> &'a TrajectoryEnvelope {
        self.envelope
    }

    pub fn producer_id(self) -> &'a str {
        self.producer_id
    }

    pub fn envelope_digest(self) -> &'a str {
        self.envelope_digest
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedTrainingDataset<'a> {
    members: Vec<VerifiedTrajectory<'a>>,
    digest: String,
}

impl<'a> VerifiedTrainingDataset<'a> {
    pub(crate) fn from_members(
        mut members: Vec<VerifiedTrajectory<'a>>,
    ) -> Result<Self, VerifierError> {
        if members.is_empty() || members.len() > MAX_GOVERNED_DATASET_TRAJECTORIES {
            return Err(VerifierError::InvalidDatasetMemberCount {
                max: MAX_GOVERNED_DATASET_TRAJECTORIES,
                actual: members.len(),
            });
        }
        members.sort_by(|left, right| trajectory_identity(left).cmp(&trajectory_identity(right)));
        if members
            .windows(2)
            .any(|pair| trajectory_identity(&pair[0]) == trajectory_identity(&pair[1]))
        {
            return Err(VerifierError::DuplicateTrajectoryIdentity);
        }
        let envelopes: Vec<_> = members.iter().map(|member| member.envelope).collect();
        let digest = digest_serialized(&envelopes, MAX_GOVERNED_DATASET_BYTES)?;
        Ok(Self { members, digest })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn members(&self) -> &[VerifiedTrajectory<'a>] {
        &self.members
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCandidateInputs {
    pub artifact_digest: String,
    pub training_dataset_digest: Option<String>,
    pub evaluation_suite_digest: String,
    /// The base model these inputs were verified against, copied off the validated manifest.
    ///
    /// It is here rather than asserted downstream so that whatever ends up inside a signed
    /// attestation is the identity **the verifier read**, not one the evaluator supplied. An
    /// evaluation is only meaningful against one set of weights, and an evaluator that could name
    /// the weights itself could name convenient ones.
    ///
    /// `verify_candidate_inputs` already refuses an inadmissible identity above, so anything
    /// reaching this field is admissible.
    pub base_model: BaseModelId,
}

#[derive(Debug, Clone)]
pub struct EvolutionVerifier {
    anchors: BTreeMap<(String, String), AttestationKey>,
    admission: TrainingAdmissionPolicy,
}

impl EvolutionVerifier {
    pub fn new(
        anchors: Vec<ProducerTrustAnchor>,
        admission: TrainingAdmissionPolicy,
    ) -> Result<Self, VerifierError> {
        admission
            .validate()
            .map_err(VerifierError::InvalidContract)?;
        if anchors.is_empty() || anchors.len() > MAX_TRUSTED_PRODUCERS {
            return Err(VerifierError::InvalidTrustedProducerCount {
                max: MAX_TRUSTED_PRODUCERS,
                actual: anchors.len(),
            });
        }
        let mut trusted = BTreeMap::new();
        for anchor in anchors {
            let identity = (anchor.producer_id, anchor.tenant_id.0);
            if trusted.insert(identity.clone(), anchor.key).is_some() {
                return Err(VerifierError::DuplicateTrustAnchor {
                    producer_id: identity.0,
                    tenant_id: identity.1,
                });
            }
        }
        Ok(Self {
            anchors: trusted,
            admission,
        })
    }

    pub fn verify_trajectory<'a>(
        &self,
        signed: &'a SignedTrajectory,
    ) -> Result<VerifiedTrajectory<'a>, VerifierError> {
        let envelope = &signed.envelope;
        envelope
            .validate()
            .map_err(VerifierError::InvalidContract)?;
        let identity = (signed.producer_id.clone(), envelope.tenant_id.0.clone());
        let key = self
            .anchors
            .get(&identity)
            .ok_or(VerifierError::UntrustedProducerTenant {
                producer_id: identity.0,
                tenant_id: identity.1,
            })?;
        let envelope_digest = digest_serialized(envelope, MAX_TRAJECTORY_JSON_BYTES)?;
        if !constant_time_eq(
            envelope_digest.as_bytes(),
            signed.envelope_digest.as_bytes(),
        ) {
            return Err(VerifierError::EnvelopeDigestMismatch);
        }
        let payload = AttestationPayload {
            domain: ATTESTATION_DOMAIN,
            producer_id: &signed.producer_id,
            envelope_digest: &envelope_digest,
            envelope,
        };
        let expected_signature = hmac_serialized(key.bytes(), &payload, MAX_TRAJECTORY_JSON_BYTES)?;
        if !constant_time_eq(expected_signature.as_bytes(), signed.signature.as_bytes()) {
            return Err(VerifierError::InvalidProducerAttestation);
        }
        EvidenceRecorder::new().verify_trajectory(envelope)?;
        if envelope
            .decisions
            .iter()
            .any(|decision| action_contains_secret(&decision.action))
        {
            return Err(VerifierError::SecretMaterialDetected);
        }
        self.admission.admit(envelope)?;
        Ok(VerifiedTrajectory {
            envelope,
            producer_id: &signed.producer_id,
            envelope_digest: &signed.envelope_digest,
        })
    }

    pub fn build_training_dataset<'a>(
        &self,
        signed: &'a [SignedTrajectory],
    ) -> Result<VerifiedTrainingDataset<'a>, VerifierError> {
        if signed.is_empty() || signed.len() > MAX_GOVERNED_DATASET_TRAJECTORIES {
            return Err(VerifierError::InvalidDatasetMemberCount {
                max: MAX_GOVERNED_DATASET_TRAJECTORIES,
                actual: signed.len(),
            });
        }
        let members = signed
            .iter()
            .map(|trajectory| self.verify_trajectory(trajectory))
            .collect::<Result<Vec<_>, _>>()?;
        VerifiedTrainingDataset::from_members(members)
    }

    pub fn verify_candidate_inputs(
        &self,
        manifest: &PolicyManifest,
        artifact_bytes: &[u8],
        dataset: Option<&VerifiedTrainingDataset<'_>>,
        evaluation: &EvaluationSuite,
    ) -> Result<VerifiedCandidateInputs, VerifierError> {
        manifest
            .validate()
            .map_err(VerifierError::InvalidContract)?;
        // `validate` answers "is this well-formed", and a document migrated from schema 2 is
        // well-formed while carrying the inadmissible base-model sentinel - that is deliberate, so
        // old documents still load. This is the second predicate, and it belongs here: every
        // candidate crosses this function before it can be promoted, so this is where "no
        // authority decision may rest on an unknown base model" stops being a comment.
        if !manifest.base_model.is_admissible() {
            return Err(VerifierError::InadmissibleBaseModel);
        }
        if artifact_bytes.len() > MAX_VERIFIED_ARTIFACT_BYTES {
            return Err(VerifierError::ArtifactTooLarge {
                max: MAX_VERIFIED_ARTIFACT_BYTES,
                actual: artifact_bytes.len(),
            });
        }
        let artifact_digest = sha256_hex(artifact_bytes);
        if !constant_time_eq(
            artifact_digest.as_bytes(),
            manifest.policy.digest.as_bytes(),
        ) {
            return Err(VerifierError::ArtifactDigestMismatch);
        }
        if !constant_time_eq(
            evaluation.digest.as_bytes(),
            manifest.evaluation_suite_digest.as_bytes(),
        ) {
            return Err(VerifierError::EvaluationDigestMismatch);
        }

        let training_dataset_digest = match (&manifest.training_dataset_digest, dataset) {
            (Some(_), None) => return Err(VerifierError::TrainingDatasetNotRegistered),
            (Some(claimed), Some(dataset)) => {
                if !constant_time_eq(claimed.as_bytes(), dataset.digest.as_bytes()) {
                    return Err(VerifierError::TrainingDatasetDigestMismatch);
                }
                let eval_tasks: BTreeSet<_> = evaluation
                    .tasks
                    .iter()
                    .map(|task| task.task_id.as_str())
                    .collect();
                if let Some(overlap) = dataset
                    .members
                    .iter()
                    .map(|member| member.envelope.task_id.as_str())
                    .find(|task_id| eval_tasks.contains(task_id))
                {
                    return Err(VerifierError::DetectedTrainEvalOverlap(overlap.to_owned()));
                }
                Some(dataset.digest.clone())
            }
            (None, Some(_)) => return Err(VerifierError::UnexpectedTrainingDataset),
            (None, None) => None,
        };
        Ok(VerifiedCandidateInputs {
            artifact_digest,
            training_dataset_digest,
            evaluation_suite_digest: evaluation.digest.clone(),
            base_model: manifest.base_model.clone(),
        })
    }
}

fn trajectory_identity<'a>(member: &VerifiedTrajectory<'a>) -> (&'a str, &'a str, &'a str) {
    (
        &member.envelope.tenant_id.0,
        &member.envelope.run_id.0,
        &member.envelope.task_id,
    )
}

fn action_contains_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => {
            let upper = value.to_ascii_uppercase();
            value.starts_with("sk-")
                || value.starts_with("ghp_")
                || value.starts_with("xoxb-")
                || (upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----"))
        }
        serde_json::Value::Array(values) => values.iter().any(action_contains_secret),
        serde_json::Value::Object(values) => values.values().any(action_contains_secret),
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("evolution contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error(
        "candidate names no admissible base model, so no promotion decision can rest on it; a          document migrated from schema 2 carries the reserved sentinel and must be re-produced          against known weights rather than promoted"
    )]
    InadmissibleBaseModel,
    #[error("evolution action evidence is invalid: {0}")]
    InvalidActionEvidence(#[from] EvidenceRecordError),
    #[error("trajectory is not eligible for governed training: {0}")]
    IneligibleTraining(#[from] TrainingEligibilityError),
    #[error("attestation key length is {actual}; expected {min}..={max} bytes")]
    InvalidAttestationKeyLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("trusted producer count is {actual}; expected 1..={max}")]
    InvalidTrustedProducerCount { max: usize, actual: usize },
    #[error("duplicate trust anchor for producer `{producer_id}` and tenant `{tenant_id}`")]
    DuplicateTrustAnchor {
        producer_id: String,
        tenant_id: String,
    },
    #[error("producer `{producer_id}` is not trusted for tenant `{tenant_id}`")]
    UntrustedProducerTenant {
        producer_id: String,
        tenant_id: String,
    },
    #[error("trajectory envelope digest does not match recomputed canonical content")]
    EnvelopeDigestMismatch,
    #[error("producer attestation does not authenticate the canonical trajectory")]
    InvalidProducerAttestation,
    #[error("verified trajectory content contains secret-shaped material")]
    SecretMaterialDetected,
    #[error("dataset member count is {actual}; expected 1..={max}")]
    InvalidDatasetMemberCount { max: usize, actual: usize },
    #[error("verified dataset contains a duplicate tenant/run/task identity")]
    DuplicateTrajectoryIdentity,
    #[error("evaluation task count is {actual}; expected 1..={max}")]
    InvalidEvaluationTaskCount { max: usize, actual: usize },
    #[error("evaluation suite contains duplicate task `{0}`")]
    DuplicateEvaluationTask(String),
    #[error("artifact is {actual} bytes; limit is {max}")]
    ArtifactTooLarge { max: usize, actual: usize },
    #[error("artifact digest does not match recomputed bytes")]
    ArtifactDigestMismatch,
    #[error("training dataset digest does not match recomputed verified membership")]
    TrainingDatasetDigestMismatch,
    #[error("manifest pins a training dataset that is not registered with the verifier")]
    TrainingDatasetNotRegistered,
    #[error("a dataset was supplied for a manifest that declares no training dataset")]
    UnexpectedTrainingDataset,
    #[error("evaluation suite digest does not match recomputed fixtures")]
    EvaluationDigestMismatch,
    #[error("verified training/evaluation membership overlaps on task `{0}`")]
    DetectedTrainEvalOverlap(String),
    #[error("canonical evidence exceeds its {max}-byte bound")]
    CanonicalTooLarge { max: usize },
    #[error("canonical evidence encoding failed: {0}")]
    CanonicalEncoding(String),
}

//! Consent-aware registry for datasets assembled only from authenticated trajectories.

use crate::private_derivatives::{
    EvolutionDerivativeKind, EvolutionPrivateContent, EvolutionPrivateContentError,
    source_for_trajectory,
};
use crate::{
    EvolutionVerifier, MAX_SHORT_STRING_BYTES, PolicyManifest, ProducedPolicyCandidate,
    SignedTrajectory, TrajectoryEnvelope, VerifiedTrainingDataset, VerifiedTrajectory,
    VerifierError, validate_nonempty_string,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAX_REGISTERED_DATASETS: usize = 1_024;
pub const MAX_DATASET_REVOCATIONS: usize = 4_096;
pub const MAX_DATASET_AUDIT_EVENTS: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DatasetMemberIdentity {
    pub tenant_id: String,
    pub run_id: String,
    pub task_id: String,
    pub producer_id: String,
    pub envelope_digest: String,
}

impl DatasetMemberIdentity {
    fn from_verified(verified: VerifiedTrajectory<'_>) -> Self {
        let envelope = verified.envelope();
        Self {
            tenant_id: envelope.tenant_id.0.clone(),
            run_id: envelope.run_id.0.clone(),
            task_id: envelope.task_id.clone(),
            producer_id: verified.producer_id().to_owned(),
            envelope_digest: verified.envelope_digest().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetRegistration {
    pub digest: String,
    pub members: Vec<DatasetMemberIdentity>,
    pub audit_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetAuditKind {
    ConsentRevoked {
        tenant_id: String,
        run_id: String,
        reason: String,
    },
    DatasetRegistered {
        digest: String,
        member_count: usize,
        revoked_excluded: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetAuditEvent {
    pub seq: u64,
    pub kind: DatasetAuditKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Revocation {
    reason: String,
    audit_seq: u64,
}

/// Fixed-bounded offline registry. It records only authenticated identities and derived digests;
/// it stores no trajectory content and has no runtime activation operation.
#[derive(Debug, Default, Clone)]
pub struct ConsentAwareDatasetRegistry {
    datasets: BTreeMap<String, DatasetRegistration>,
    revocations: BTreeMap<(String, String), Revocation>,
    audit: Vec<DatasetAuditEvent>,
    next_seq: u64,
    private_content: Option<EvolutionPrivateContent>,
}

impl ConsentAwareDatasetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the production registry with dataset/candidate bytes behind the record erasure gate.
    pub fn open_record_backed(
        manifest_root: &Path,
        content_runs_dir: &Path,
        tenant_id: iteron_protocol::TenantId,
    ) -> Result<Self, EvolutionPrivateContentError> {
        Ok(Self {
            private_content: Some(EvolutionPrivateContent::open(
                manifest_root,
                content_runs_dir,
                tenant_id,
            )?),
            ..Self::default()
        })
    }

    pub fn revoke_run(
        &mut self,
        tenant_id: impl Into<String>,
        run_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<u64, DatasetRegistryError> {
        let tenant_id = tenant_id.into();
        let run_id = run_id.into();
        let reason = reason.into();
        validate_nonempty_string(
            "dataset_revocation.tenant_id",
            &tenant_id,
            MAX_SHORT_STRING_BYTES,
        )?;
        validate_nonempty_string("dataset_revocation.run_id", &run_id, MAX_SHORT_STRING_BYTES)?;
        validate_nonempty_string("dataset_revocation.reason", &reason, MAX_SHORT_STRING_BYTES)?;
        if reason.chars().any(char::is_control) {
            return Err(DatasetRegistryError::InvalidRevocationReason);
        }
        let key = (tenant_id.clone(), run_id.clone());
        if let Some(existing) = self.revocations.get(&key) {
            return if existing.reason == reason {
                Ok(existing.audit_seq)
            } else {
                Err(DatasetRegistryError::RunAlreadyRevoked)
            };
        }
        if self.revocations.len()
            >= iteron_tunables::param_integer(
                "evolve.dataset_registry.max_dataset_revocations",
                MAX_DATASET_REVOCATIONS,
            )
        {
            return Err(DatasetRegistryError::RevocationLimit {
                max: iteron_tunables::param_integer(
                    "evolve.dataset_registry.max_dataset_revocations",
                    MAX_DATASET_REVOCATIONS,
                ),
            });
        }
        let seq = self.append_audit(DatasetAuditKind::ConsentRevoked {
            tenant_id: tenant_id.clone(),
            run_id: run_id.clone(),
            reason: reason.clone(),
        })?;
        self.revocations.insert(
            key,
            Revocation {
                reason,
                audit_seq: seq,
            },
        );
        Ok(seq)
    }

    pub fn build_and_register<'a>(
        &mut self,
        verifier: &EvolutionVerifier,
        signed: &'a [SignedTrajectory],
    ) -> Result<VerifiedTrainingDataset<'a>, DatasetRegistryError> {
        let mut excluded = 0usize;
        let mut members = Vec::with_capacity(signed.len());
        for trajectory in signed {
            // Authenticate before consulting caller-visible identity fields. A forged tenant/run
            // must not impersonate a revoked record and become a seemingly valid exclusion.
            let verified = verifier.verify_trajectory(trajectory)?;
            let envelope = verified.envelope();
            if self
                .revocations
                .contains_key(&(envelope.tenant_id.0.clone(), envelope.run_id.0.clone()))
            {
                excluded = excluded.saturating_add(1);
                continue;
            }
            members.push(verified);
        }
        let dataset = VerifiedTrainingDataset::from_members(members)?;
        self.register(&dataset, excluded)?;
        Ok(dataset)
    }

    pub fn resolve(&self, digest: &str) -> Option<&DatasetRegistration> {
        self.datasets.get(digest)
    }

    pub fn require_manifest_dataset(
        &self,
        manifest: &PolicyManifest,
    ) -> Result<Option<&DatasetRegistration>, DatasetRegistryError> {
        manifest.validate()?;
        match &manifest.training_dataset_digest {
            Some(digest) => {
                let dataset = self.datasets.get(digest).ok_or_else(|| {
                    DatasetRegistryError::UnregisteredManifestDataset(digest.clone())
                })?;
                if let Some(private) = &self.private_content {
                    let bytes = private.read(EvolutionDerivativeKind::Dataset, digest)?;
                    let envelopes: Vec<TrajectoryEnvelope> = serde_json::from_slice(&bytes)
                        .map_err(EvolutionPrivateContentError::from)?;
                    if envelopes.len() != dataset.members.len()
                        || envelopes
                            .iter()
                            .zip(&dataset.members)
                            .any(|(envelope, member)| {
                                envelope.tenant_id.0 != member.tenant_id
                                    || envelope.run_id.0 != member.run_id
                                    || envelope.task_id != member.task_id
                            })
                    {
                        return Err(DatasetRegistryError::PrivateContent(
                            EvolutionPrivateContentError::ContentDigestMismatch,
                        ));
                    }
                }
                if let Some(member) = dataset.members.iter().find(|member| {
                    self.revocations
                        .contains_key(&(member.tenant_id.clone(), member.run_id.clone()))
                }) {
                    return Err(DatasetRegistryError::RegisteredDatasetContainsRevokedRun {
                        tenant_id: member.tenant_id.clone(),
                        run_id: member.run_id.clone(),
                    });
                }
                Ok(Some(dataset))
            }
            None => Ok(None),
        }
    }

    pub fn audit(&self) -> &[DatasetAuditEvent] {
        &self.audit
    }

    pub fn is_revoked(&self, tenant_id: &str, run_id: &str) -> bool {
        self.revocations
            .contains_key(&(tenant_id.to_owned(), run_id.to_owned()))
    }

    /// Publish an inert candidate artifact as a derivative of its registered training dataset.
    /// A record-backed promotion authority will refuse the candidate unless this handoff exists.
    pub fn persist_candidate(
        &self,
        candidate: &ProducedPolicyCandidate,
    ) -> Result<(), DatasetRegistryError> {
        let Some(private) = &self.private_content else {
            return Ok(());
        };
        let digest = candidate
            .manifest()
            .training_dataset_digest
            .as_ref()
            .ok_or(DatasetRegistryError::CandidateMissingTrainingDataset)?;
        if !self.datasets.contains_key(digest) {
            return Err(DatasetRegistryError::UnregisteredManifestDataset(
                digest.clone(),
            ));
        }
        let source = private.source(EvolutionDerivativeKind::Dataset, digest)?;
        private.store(
            EvolutionDerivativeKind::Candidate,
            candidate.candidate_digest(),
            candidate.artifact_bytes(),
            &[source],
        )?;
        let hydrated = private.read(
            EvolutionDerivativeKind::Candidate,
            candidate.candidate_digest(),
        )?;
        if hydrated != candidate.artifact_bytes() {
            return Err(DatasetRegistryError::PrivateContent(
                EvolutionPrivateContentError::ContentDigestMismatch,
            ));
        }
        Ok(())
    }

    fn register(
        &mut self,
        dataset: &VerifiedTrainingDataset<'_>,
        revoked_excluded: usize,
    ) -> Result<(), DatasetRegistryError> {
        let members: Vec<_> = dataset
            .members()
            .iter()
            .copied()
            .map(DatasetMemberIdentity::from_verified)
            .collect();
        if let Some(private) = &self.private_content {
            if dataset
                .members()
                .iter()
                .any(|member| member.envelope().tenant_id != *private.tenant_id())
            {
                return Err(DatasetRegistryError::PrivateContent(
                    EvolutionPrivateContentError::TenantMismatch,
                ));
            }
            let envelopes: Vec<_> = dataset
                .members()
                .iter()
                .map(|member| member.envelope())
                .collect();
            let bytes =
                serde_json::to_vec(&envelopes).map_err(EvolutionPrivateContentError::from)?;
            if crate::verifier_crypto::sha256_hex(&bytes) != dataset.digest() {
                return Err(DatasetRegistryError::PrivateContent(
                    EvolutionPrivateContentError::ContentDigestMismatch,
                ));
            }
            let sources = dataset
                .members()
                .iter()
                .map(|member| {
                    source_for_trajectory(
                        private.tenant_id(),
                        &member.envelope().run_id.0,
                        member.envelope_digest(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            private.store(
                EvolutionDerivativeKind::Dataset,
                dataset.digest(),
                &bytes,
                &sources,
            )?;
        }
        if let Some(existing) = self.datasets.get(dataset.digest()) {
            return if existing.members == members {
                Ok(())
            } else {
                Err(DatasetRegistryError::DigestIdentityConflict)
            };
        }
        if self.datasets.len()
            >= iteron_tunables::param_integer(
                "evolve.dataset_registry.max_registered_datasets",
                MAX_REGISTERED_DATASETS,
            )
        {
            return Err(DatasetRegistryError::DatasetLimit {
                max: iteron_tunables::param_integer(
                    "evolve.dataset_registry.max_registered_datasets",
                    MAX_REGISTERED_DATASETS,
                ),
            });
        }
        let seq = self.append_audit(DatasetAuditKind::DatasetRegistered {
            digest: dataset.digest().to_owned(),
            member_count: members.len(),
            revoked_excluded,
        })?;
        self.datasets.insert(
            dataset.digest().to_owned(),
            DatasetRegistration {
                digest: dataset.digest().to_owned(),
                members,
                audit_seq: seq,
            },
        );
        Ok(())
    }

    fn append_audit(&mut self, kind: DatasetAuditKind) -> Result<u64, DatasetRegistryError> {
        if self.audit.len()
            >= iteron_tunables::param_integer(
                "evolve.dataset_registry.max_dataset_audit_events",
                MAX_DATASET_AUDIT_EVENTS,
            )
        {
            return Err(DatasetRegistryError::AuditLimit {
                max: iteron_tunables::param_integer(
                    "evolve.dataset_registry.max_dataset_audit_events",
                    MAX_DATASET_AUDIT_EVENTS,
                ),
            });
        }
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(DatasetRegistryError::AuditSequenceExhausted)?;
        self.audit.push(DatasetAuditEvent { seq, kind });
        Ok(seq)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DatasetRegistryError {
    #[error("dataset contract is invalid: {0}")]
    InvalidContract(#[from] crate::ContractError),
    #[error("trajectory verification failed: {0}")]
    Verification(#[from] VerifierError),
    #[error("private dataset/candidate storage failed: {0}")]
    PrivateContent(#[from] EvolutionPrivateContentError),
    #[error("revocation reason contains a control character")]
    InvalidRevocationReason,
    #[error("run is already revoked with a different reason")]
    RunAlreadyRevoked,
    #[error("dataset registry reached its {max}-dataset limit")]
    DatasetLimit { max: usize },
    #[error("dataset registry reached its {max}-revocation limit")]
    RevocationLimit { max: usize },
    #[error("dataset registry reached its {max}-event audit limit")]
    AuditLimit { max: usize },
    #[error("dataset audit sequence is exhausted")]
    AuditSequenceExhausted,
    #[error("one digest resolved to a conflicting member identity set")]
    DigestIdentityConflict,
    #[error("manifest pins unregistered training dataset `{0}`")]
    UnregisteredManifestDataset(String),
    #[error("registered dataset contains revoked run `{tenant_id}/{run_id}`")]
    RegisteredDatasetContainsRevokedRun { tenant_id: String, run_id: String },
    #[error("a persisted candidate must name one registered training dataset")]
    CandidateMissingTrainingDataset,
}

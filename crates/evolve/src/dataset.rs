//! Governed, bounded source-of-truth for offline producer inputs.

use crate::{TrainingEligibleTrajectory, TrajectoryEnvelope};
use sha2::{Digest, Sha256};
use std::io::Write;

pub const MAX_GOVERNED_DATASET_TRAJECTORIES: usize = 1_024;
pub const MAX_GOVERNED_DATASET_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Debug, thiserror::Error)]
pub enum GovernedDatasetError {
    #[error("governed training dataset must contain at least one admitted trajectory")]
    Empty,
    #[error("governed training dataset contains {actual} trajectories; limit is {limit}")]
    TooManyTrajectories { limit: usize, actual: usize },
    #[error("governed training dataset contains a duplicate tenant/run/task identity")]
    DuplicateTrajectoryIdentity,
    #[error("canonical governed training dataset exceeds {limit} bytes")]
    DatasetTooLarge { limit: usize },
    #[error("canonical governed training dataset could not be encoded: {0}")]
    Encoding(#[source] serde_json::Error),
}

/// A deterministic view over trajectories already admitted by [`crate::TrainingAdmissionPolicy`].
///
/// The dataset source-of-truth is the compact JSON array of complete trajectory envelopes sorted
/// by `(tenant_id, run_id, task_id)`. `digest` is SHA-256 of those exact bytes. Duplicate
/// identities are rejected so caller order can never break determinism.
#[derive(Debug, Clone)]
pub struct GovernedTrainingDataset<'a> {
    trajectories: Vec<&'a TrajectoryEnvelope>,
    digest: String,
    canonical_bytes: usize,
}

impl<'a> GovernedTrainingDataset<'a> {
    pub fn new(proofs: &[TrainingEligibleTrajectory<'a>]) -> Result<Self, GovernedDatasetError> {
        if proofs.is_empty() {
            return Err(GovernedDatasetError::Empty);
        }
        if proofs.len() > MAX_GOVERNED_DATASET_TRAJECTORIES {
            return Err(GovernedDatasetError::TooManyTrajectories {
                limit: MAX_GOVERNED_DATASET_TRAJECTORIES,
                actual: proofs.len(),
            });
        }

        let mut trajectories: Vec<_> = proofs.iter().map(|proof| (*proof).envelope()).collect();
        trajectories
            .sort_by(|left, right| trajectory_identity(left).cmp(&trajectory_identity(right)));
        if trajectories
            .windows(2)
            .any(|pair| trajectory_identity(pair[0]) == trajectory_identity(pair[1]))
        {
            return Err(GovernedDatasetError::DuplicateTrajectoryIdentity);
        }

        let (digest, canonical_bytes) = digest_trajectories(&trajectories)?;
        Ok(Self {
            trajectories,
            digest,
            canonical_bytes,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    pub fn trajectories(&self) -> &[&'a TrajectoryEnvelope] {
        &self.trajectories
    }
}

fn trajectory_identity(envelope: &TrajectoryEnvelope) -> (&str, &str, &str) {
    (
        envelope.tenant_id.0.as_str(),
        envelope.run_id.0.as_str(),
        envelope.task_id.as_str(),
    )
}

fn digest_trajectories(
    trajectories: &[&TrajectoryEnvelope],
) -> Result<(String, usize), GovernedDatasetError> {
    let mut writer = BoundedDigestWriter::new(MAX_GOVERNED_DATASET_BYTES);
    write_bytes(&mut writer, b"[")?;
    for (index, trajectory) in trajectories.iter().enumerate() {
        if index != 0 {
            write_bytes(&mut writer, b",")?;
        }
        if let Err(source) = serde_json::to_writer(&mut writer, trajectory) {
            return if writer.exceeded {
                Err(GovernedDatasetError::DatasetTooLarge {
                    limit: MAX_GOVERNED_DATASET_BYTES,
                })
            } else {
                Err(GovernedDatasetError::Encoding(source))
            };
        }
    }
    write_bytes(&mut writer, b"]")?;
    Ok(writer.finish())
}

fn write_bytes(writer: &mut BoundedDigestWriter, bytes: &[u8]) -> Result<(), GovernedDatasetError> {
    writer
        .write_all(bytes)
        .map_err(|_| GovernedDatasetError::DatasetTooLarge {
            limit: MAX_GOVERNED_DATASET_BYTES,
        })
}

struct BoundedDigestWriter {
    hasher: Sha256,
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl BoundedDigestWriter {
    fn new(limit: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            written: 0,
            limit,
            exceeded: false,
        }
    }

    fn finish(self) -> (String, usize) {
        (hex_lower(self.hasher.finalize()), self.written)
    }
}

impl Write for BoundedDigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "governed dataset byte limit exceeded",
            ));
        }
        self.hasher.update(bytes);
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes))
}

fn hex_lower(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest.as_ref();
    let mut encoded = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

//! Deterministic, hash-chained and signed transcript for the fully offline evolution demo.
//!
//! The transcript signature uses a fixed, public **demo key** so repeated fixture runs are
//! byte-identical. It proves deterministic content binding, not external identity. The promotion
//! journal it references carries the real independently keyed evaluator and promotion
//! authorizations used by the demo pipeline.

use crate::verifier_crypto::{constant_time_eq, hmac_serialized, sha256_hex};
use crate::{
    ArtifactKind, BaseModelId, CheckpointAlgebraError, ContractError, DatasetRegistryError,
    DeploymentStage, EvolutionMethod, GovernedDatasetError, HeldOutBridgeError,
    OfflineProducerError, PromotionAuthorityError, PromptPreferenceError,
    RecordedRunProjectorError, TrainingEligibilityError, VerifierError,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const TRANSCRIPT_DOMAIN: &str = "iteron-evolve/offline-transcript/v1";
const TRANSCRIPT_SCHEMA_VERSION: u16 = 1;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_TRANSCRIPT_RECORDS: usize = 256;
const MAX_TRANSCRIPT_LINE_BYTES: usize = 256 * 1024;
const MAX_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;
const DEMO_TRANSCRIPT_KEY: &[u8] = b"iteron-evolve-public-demo-key-v1";
const DEFAULT_PRIMARY_PRODUCER: &str = "rule";
const DEFAULT_SECONDARY_PRODUCER: &str = "prompt";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TranscriptEvent {
    TrajectoryProjected {
        rollout_digest: String,
        run_id: String,
        registry_address: String,
    },
    DatasetRegistered {
        digest: String,
        members: usize,
    },
    BaselineBootstrapped {
        bundle_digest: String,
    },
    CandidateProduced {
        label: String,
        policy_digest: String,
        method: EvolutionMethod,
        artifact_kind: ArtifactKind,
    },
    CandidateAdmitted {
        label: String,
        bundle_digest: String,
    },
    StageReached {
        label: String,
        stage: DeploymentStage,
    },
    RolledBack {
        label: String,
        restored_bundle_digest: String,
    },
    TransferReported {
        label: String,
        bundle_id: String,
        source_bundle_digest: String,
        target_bundle_digest: String,
        from_model: Box<BaseModelId>,
        to_model: Box<BaseModelId>,
        source_delta: f64,
        target_delta: f64,
        retained_delta: f64,
        portable_fraction: f64,
        target_gate_eligible: bool,
        target_evaluation_fixture: String,
    },
    MethodAgnostic {
        first_method: EvolutionMethod,
        first_artifact_kind: ArtifactKind,
        second_method: EvolutionMethod,
        second_artifact_kind: ArtifactKind,
        matched_gate_input_digest: String,
        first_pipeline_path: Vec<String>,
        second_pipeline_path: Vec<String>,
        first_gate_refusal_reasons: Vec<String>,
        second_gate_refusal_reasons: Vec<String>,
        identical_gate_decision: bool,
        byte_identical_gate_reasons: bool,
    },
    CandidateRefused {
        label: String,
        reason: String,
    },
    Completed {
        promotion_journal: String,
        target_promotion_journal: String,
        final_active_bundle_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRecord {
    pub schema_version: u16,
    pub sequence: u64,
    pub previous_hash: String,
    pub event_hash: String,
    pub signature: String,
    pub event: TranscriptEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineTranscriptResult {
    pub transcript_path: PathBuf,
    pub promotion_journal_path: PathBuf,
    pub target_promotion_journal_path: PathBuf,
    pub trajectory_registry_path: PathBuf,
    pub event_count: usize,
    pub final_active_bundle_digest: String,
}

/// The two independently implemented producers exercised by the offline transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptProducerKind {
    RuleSearch,
    PromptPreference,
}

impl TranscriptProducerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuleSearch => "rule",
            Self::PromptPreference => "prompt",
        }
    }

    fn from_profile(value: &str, fallback: Self) -> Self {
        match value {
            "rule" => Self::RuleSearch,
            "prompt" => Self::PromptPreference,
            _ => fallback,
        }
    }
}

/// Frozen models and producer order for one deterministic transcript run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineTranscriptConfig {
    source_base_model: BaseModelId,
    target_base_model: BaseModelId,
    primary_producer: TranscriptProducerKind,
    secondary_producer: TranscriptProducerKind,
}

impl OfflineTranscriptConfig {
    pub fn new(
        source_base_model: BaseModelId,
        target_base_model: BaseModelId,
        primary_producer: TranscriptProducerKind,
        secondary_producer: TranscriptProducerKind,
    ) -> Result<Self, TranscriptRunError> {
        if !source_base_model.is_admissible() || !target_base_model.is_admissible() {
            return Err(TranscriptRunError::InvalidConfiguration(
                "both transcript base models must be admissible frozen identities",
            ));
        }
        if source_base_model == target_base_model {
            return Err(TranscriptRunError::InvalidConfiguration(
                "source and target base models must be distinct",
            ));
        }
        if primary_producer == secondary_producer {
            return Err(TranscriptRunError::InvalidConfiguration(
                "the transcript requires two distinct producer kinds",
            ));
        }
        Ok(Self {
            source_base_model,
            target_base_model,
            primary_producer,
            secondary_producer,
        })
    }

    pub fn source_base_model(&self) -> &BaseModelId {
        &self.source_base_model
    }

    pub fn target_base_model(&self) -> &BaseModelId {
        &self.target_base_model
    }

    pub fn primary_producer(&self) -> TranscriptProducerKind {
        self.primary_producer
    }

    pub fn secondary_producer(&self) -> TranscriptProducerKind {
        self.secondary_producer
    }
}

impl Default for OfflineTranscriptConfig {
    fn default() -> Self {
        let primary = TranscriptProducerKind::from_profile(
            iteron_tunables::param_str(
                "evolve.transcript.default_primary_producer",
                DEFAULT_PRIMARY_PRODUCER,
            ),
            TranscriptProducerKind::RuleSearch,
        );
        let secondary = TranscriptProducerKind::from_profile(
            iteron_tunables::param_str(
                "evolve.transcript.default_secondary_producer",
                DEFAULT_SECONDARY_PRODUCER,
            ),
            TranscriptProducerKind::PromptPreference,
        );
        let (primary, secondary) = if primary == secondary {
            (
                TranscriptProducerKind::RuleSearch,
                TranscriptProducerKind::PromptPreference,
            )
        } else {
            (primary, secondary)
        };
        Self::new(
            crate::transcript_demo_support::model_a(),
            crate::transcript_demo_support::model_b(),
            primary,
            secondary,
        )
        .expect("the fixed transcript configuration is valid")
    }
}

pub fn run_offline_transcript(root: &Path) -> Result<OfflineTranscriptResult, TranscriptRunError> {
    run_offline_transcript_with_config(root, &OfflineTranscriptConfig::default())
}

pub fn run_offline_transcript_with_config(
    root: &Path,
    config: &OfflineTranscriptConfig,
) -> Result<OfflineTranscriptResult, TranscriptRunError> {
    crate::transcript_demo::run(root, config)
}

pub fn verify_offline_transcript(path: &Path) -> Result<usize, TranscriptRunError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TranscriptRunError::InvalidPath(path.to_path_buf()));
    }
    if metadata.len()
        > iteron_tunables::param_integer(
            "evolve.transcript.max_transcript_bytes",
            MAX_TRANSCRIPT_BYTES,
        )
    {
        return Err(TranscriptRunError::TranscriptTooLarge {
            max: iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_bytes",
                MAX_TRANSCRIPT_BYTES,
            ),
            actual: metadata.len(),
        });
    }
    let mut previous =
        iteron_tunables::param_str("evolve.transcript.zero_hash", ZERO_HASH).to_owned();
    let mut expected_sequence = 0_u64;
    let reader = BufReader::new(File::open(path)?);
    for line in reader.lines() {
        let line = line?;
        if line.len()
            > iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_line_bytes",
                MAX_TRANSCRIPT_LINE_BYTES,
            )
        {
            return Err(TranscriptRunError::RecordTooLarge {
                max: iteron_tunables::param_integer(
                    "evolve.transcript.max_transcript_line_bytes",
                    MAX_TRANSCRIPT_LINE_BYTES,
                ),
                actual: line.len(),
            });
        }
        if expected_sequence as usize
            >= iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_records",
                MAX_TRANSCRIPT_RECORDS,
            )
        {
            return Err(TranscriptRunError::TooManyRecords {
                max: iteron_tunables::param_integer(
                    "evolve.transcript.max_transcript_records",
                    MAX_TRANSCRIPT_RECORDS,
                ),
            });
        }
        let record: TranscriptRecord = serde_json::from_str(&line)?;
        if record.schema_version != TRANSCRIPT_SCHEMA_VERSION
            || record.sequence != expected_sequence
            || record.previous_hash != previous
        {
            return Err(TranscriptRunError::InvalidChain(expected_sequence));
        }
        let event_hash = event_hash(record.sequence, &record.previous_hash, &record.event)?;
        if !constant_time_eq(event_hash.as_bytes(), record.event_hash.as_bytes()) {
            return Err(TranscriptRunError::InvalidChain(expected_sequence));
        }
        let signature = event_signature(record.sequence, &record.previous_hash, &event_hash)?;
        if !constant_time_eq(signature.as_bytes(), record.signature.as_bytes()) {
            return Err(TranscriptRunError::InvalidSignature(expected_sequence));
        }
        previous = record.event_hash;
        expected_sequence = expected_sequence.saturating_add(1);
    }
    if expected_sequence == 0 {
        return Err(TranscriptRunError::EmptyTranscript);
    }
    Ok(expected_sequence as usize)
}

pub(crate) fn write_transcript(
    path: &Path,
    events: &[TranscriptEvent],
) -> Result<(), TranscriptRunError> {
    if events.is_empty() {
        return Err(TranscriptRunError::EmptyTranscript);
    }
    if events.len()
        > iteron_tunables::param_integer(
            "evolve.transcript.max_transcript_records",
            MAX_TRANSCRIPT_RECORDS,
        )
    {
        return Err(TranscriptRunError::TooManyRecords {
            max: iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_records",
                MAX_TRANSCRIPT_RECORDS,
            ),
        });
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(TranscriptRunError::OutputAlreadyExists(path.to_path_buf()));
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    let mut previous =
        iteron_tunables::param_str("evolve.transcript.zero_hash", ZERO_HASH).to_owned();
    let mut total = 0_u64;
    for (index, event) in events.iter().enumerate() {
        let sequence = index as u64;
        let event_hash = event_hash(sequence, &previous, event)?;
        let signature = event_signature(sequence, &previous, &event_hash)?;
        let record = TranscriptRecord {
            schema_version: TRANSCRIPT_SCHEMA_VERSION,
            sequence,
            previous_hash: previous,
            event_hash: event_hash.clone(),
            signature,
            event: event.clone(),
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        if line.len()
            > iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_line_bytes",
                MAX_TRANSCRIPT_LINE_BYTES,
            )
        {
            return Err(TranscriptRunError::RecordTooLarge {
                max: iteron_tunables::param_integer(
                    "evolve.transcript.max_transcript_line_bytes",
                    MAX_TRANSCRIPT_LINE_BYTES,
                ),
                actual: line.len(),
            });
        }
        total =
            total
                .checked_add(line.len() as u64)
                .ok_or(TranscriptRunError::TranscriptTooLarge {
                    max: iteron_tunables::param_integer(
                        "evolve.transcript.max_transcript_bytes",
                        MAX_TRANSCRIPT_BYTES,
                    ),
                    actual: u64::MAX,
                })?;
        if total
            > iteron_tunables::param_integer(
                "evolve.transcript.max_transcript_bytes",
                MAX_TRANSCRIPT_BYTES,
            )
        {
            return Err(TranscriptRunError::TranscriptTooLarge {
                max: iteron_tunables::param_integer(
                    "evolve.transcript.max_transcript_bytes",
                    MAX_TRANSCRIPT_BYTES,
                ),
                actual: total,
            });
        }
        file.write_all(&line)?;
        previous = event_hash;
    }
    file.sync_all()?;
    Ok(())
}

fn event_hash(
    sequence: u64,
    previous_hash: &str,
    event: &TranscriptEvent,
) -> Result<String, TranscriptRunError> {
    #[derive(Serialize)]
    struct Content<'a> {
        domain: &'static str,
        sequence: u64,
        previous_hash: &'a str,
        event: &'a TranscriptEvent,
    }
    Ok(sha256_hex(&serde_json::to_vec(&Content {
        domain: TRANSCRIPT_DOMAIN,
        sequence,
        previous_hash,
        event,
    })?))
}

fn event_signature(
    sequence: u64,
    previous_hash: &str,
    event_hash: &str,
) -> Result<String, TranscriptRunError> {
    #[derive(Serialize)]
    struct SignatureContent<'a> {
        domain: &'static str,
        sequence: u64,
        previous_hash: &'a str,
        event_hash: &'a str,
    }
    Ok(hmac_serialized(
        DEMO_TRANSCRIPT_KEY,
        &SignatureContent {
            domain: TRANSCRIPT_DOMAIN,
            sequence,
            previous_hash,
            event_hash,
        },
        iteron_tunables::param_integer(
            "evolve.transcript.max_transcript_line_bytes",
            MAX_TRANSCRIPT_LINE_BYTES,
        ),
    )?)
}

#[derive(Debug, thiserror::Error)]
pub enum TranscriptRunError {
    #[error("offline transcript I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("offline transcript JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("offline transcript contract is invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("offline transcript verifier failed: {0}")]
    Verifier(#[from] VerifierError),
    #[error("offline transcript promotion failed: {0}")]
    Promotion(#[from] PromotionAuthorityError),
    #[error("offline transcript dataset registry failed: {0}")]
    DatasetRegistry(#[from] DatasetRegistryError),
    #[error("offline transcript trajectory registry failed: {0}")]
    TrajectoryRegistry(#[from] crate::TrajectoryRegistryError),
    #[error("offline transcript governed dataset failed: {0}")]
    GovernedDataset(#[from] GovernedDatasetError),
    #[error("offline transcript training admission failed: {0}")]
    Training(#[from] TrainingEligibilityError),
    #[error("offline transcript rule producer failed: {0}")]
    RuleProducer(#[from] OfflineProducerError),
    #[error("offline transcript prompt producer failed: {0}")]
    PromptProducer(#[from] PromptPreferenceError),
    #[error("offline transcript held-out bridge failed: {0}")]
    HeldOut(#[from] HeldOutBridgeError),
    #[error("offline transcript private evolution storage failed: {0}")]
    PrivateContent(#[from] crate::EvolutionPrivateContentError),
    #[error("offline transcript projection setup failed: {0}")]
    ProjectionSetup(#[from] RecordedRunProjectorError),
    #[error("offline transcript checkpoint algebra failed: {0}")]
    Algebra(#[from] CheckpointAlgebraError),
    #[error("offline transcript path is not a regular file: {0}")]
    InvalidPath(PathBuf),
    #[error("offline transcript output already exists: {0}")]
    OutputAlreadyExists(PathBuf),
    #[error("offline transcript record is {actual} bytes; limit is {max}")]
    RecordTooLarge { max: usize, actual: usize },
    #[error("offline transcript is {actual} bytes; limit is {max}")]
    TranscriptTooLarge { max: u64, actual: u64 },
    #[error("offline transcript exceeds the {max}-record limit")]
    TooManyRecords { max: usize },
    #[error("offline transcript hash chain is invalid at sequence {0}")]
    InvalidChain(u64),
    #[error("offline transcript signature is invalid at sequence {0}")]
    InvalidSignature(u64),
    #[error("offline transcript contains no records")]
    EmptyTranscript,
    #[error("offline transcript invariant failed: {0}")]
    Invariant(&'static str),
    #[error("offline transcript configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
}

#[cfg(test)]
#[path = "transcript_tests.rs"]
mod tests;

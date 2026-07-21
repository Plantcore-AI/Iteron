//! Durable, non-authoritative storage for validated trajectory envelopes.
//!
//! The registry is one append-only, hash-chained JSONL file. Every record embeds its envelope,
//! pins the envelope's SHA-256 content address, and links to the preceding record. It can retain
//! evidence and answer provenance queries; it has no policy-resolution or activation operation.

use crate::{
    EvidenceRecordError, EvidenceRecorder, MAX_POLICIES_PER_BUNDLE, MAX_TRAJECTORY_JSON_BYTES,
    PolicyRef, TrajectoryEnvelope,
};
use core_protocol::RunId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[path = "registry_io.rs"]
mod registry_io;
use registry_io::*;

const REGISTRY_SCHEMA_VERSION: u16 = 1;
const REGISTRY_FILE_NAME: &str = "trajectory-registry.jsonl";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Bound the serialized envelope independently of in-memory construction.
pub const MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES: usize = MAX_TRAJECTORY_JSON_BYTES;
/// One physical line includes the bounded envelope plus fixed chain metadata.
pub const MAX_TRAJECTORY_REGISTRY_RECORD_BYTES: usize =
    MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES + 64 * 1024;
/// A registry is deliberately finite even when every individual record is small.
pub const MAX_TRAJECTORY_REGISTRY_BYTES: u64 = 256 * 1024 * 1024;
/// A second cardinality ceiling avoids an unbounded scan of tiny records.
pub const MAX_TRAJECTORY_REGISTRY_RECORDS: usize = 16_384;
/// A lineage result can contain no more policies than its already-validated source bundle.
pub const MAX_TRAJECTORY_LINEAGE_POLICIES: usize = MAX_POLICIES_PER_BUNDLE;

#[derive(Debug, thiserror::Error)]
pub enum TrajectoryRegistryError {
    #[error("trajectory registry I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("trajectory registry JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("trajectory envelope is not verified evidence: {0}")]
    InvalidEnvelope(#[source] EvidenceRecordError),
    #[error("stored trajectory at sequence {sequence} is not verified evidence: {source}")]
    InvalidStoredEnvelope {
        sequence: u64,
        #[source]
        source: EvidenceRecordError,
    },
    #[error("registry root or journal symlink is refused: {path}")]
    SymlinkRefused { path: PathBuf },
    #[error("registry path is not the expected directory or regular file: {path}")]
    InvalidPathKind { path: PathBuf },
    #[error("trajectory registry already has an active writer: {path}")]
    WriterBusy { path: PathBuf },
    #[error("trajectory registry writer is poisoned; close and reopen it to recover")]
    WriterPoisoned,
    #[error("trajectory envelope is larger than the {limit}-byte registry limit")]
    EnvelopeTooLarge { limit: usize },
    #[error("trajectory registry record is {bytes} bytes; limit is {limit}")]
    RecordTooLarge { bytes: usize, limit: usize },
    #[error("trajectory registry is {bytes} bytes; limit is {limit}")]
    RegistryTooLarge { bytes: u64, limit: u64 },
    #[error("trajectory registry exceeds the {limit}-record limit")]
    TooManyRecords { limit: usize },
    #[error("unsupported trajectory registry record schema {found} at sequence {sequence}")]
    UnsupportedRecordSchema { sequence: u64, found: u16 },
    #[error("trajectory registry expected sequence {expected}, found {found}")]
    SequenceMismatch { expected: u64, found: u64 },
    #[error("trajectory registry previous hash mismatch at sequence {sequence}")]
    PreviousHashMismatch { sequence: u64 },
    #[error("trajectory content digest mismatch at sequence {sequence}")]
    ContentDigestMismatch { sequence: u64 },
    #[error("trajectory registry hash mismatch at sequence {sequence}")]
    RecordHashMismatch { sequence: u64 },
    #[error("trajectory run `{run_id}` occurs more than once in the append-only registry")]
    DuplicateStoredRun { run_id: String },
    #[error("trajectory run `{run_id}` is already bound to {stored_digest}, not {incoming_digest}")]
    RunConflict {
        run_id: String,
        stored_digest: String,
        incoming_digest: String,
    },
    #[error("invalid trajectory content address; expected 64 lowercase hexadecimal characters")]
    InvalidAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrajectoryAddress(String);

impl TrajectoryAddress {
    pub fn parse(value: impl Into<String>) -> Result<Self, TrajectoryRegistryError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(TrajectoryRegistryError::InvalidAddress)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrajectoryAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredTrajectory {
    pub address: TrajectoryAddress,
    pub envelope: TrajectoryEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLineage {
    pub bundle_id: String,
    pub bundle_digest: String,
    pub parent_bundle_id: Option<String>,
}

/// The immutable bundle and policies whose decisions produced one trajectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryLineage {
    pub address: TrajectoryAddress,
    pub run_id: RunId,
    pub source_bundle: BundleLineage,
    pub source_policies: Vec<PolicyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrajectoryIngest {
    Stored(TrajectoryAddress),
    AlreadyPresent(TrajectoryAddress),
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryRecord {
    registry_schema_version: u16,
    sequence: u64,
    previous_hash: String,
    record_hash: String,
    content_digest: String,
    envelope: TrajectoryEnvelope,
}

struct ScanSummary {
    next_sequence: u64,
    last_hash: String,
    verified_bytes: u64,
    run_digests: BTreeMap<String, String>,
}

/// One exclusively-owned append writer. Every read re-verifies the on-disk chain.
pub struct TrajectoryRegistry {
    directory: PathBuf,
    path: PathBuf,
    file: File,
    #[cfg(unix)]
    identity: FileIdentity,
    poisoned: bool,
}

impl TrajectoryRegistry {
    pub fn open(directory: &Path) -> Result<Self, TrajectoryRegistryError> {
        let directory = prepare_directory(directory)?;
        let path = directory.join(REGISTRY_FILE_NAME);
        reject_existing_symlink(&path)?;
        let was_missing = std::fs::symlink_metadata(&path).is_err();

        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(TrajectoryRegistryError::InvalidPathKind { path });
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(TrajectoryRegistryError::WriterBusy { path });
            }
            Err(TryLockError::Error(source)) => return Err(source.into()),
        }

        #[cfg(unix)]
        let identity = file_identity(&metadata);
        let mut registry = Self {
            directory,
            path,
            file,
            #[cfg(unix)]
            identity,
            poisoned: false,
        };
        if was_missing {
            registry.file.sync_all()?;
            sync_directory(&registry.directory)?;
        }
        registry.scan(|_| Ok(()))?;
        Ok(registry)
    }

    pub fn ingest(
        &mut self,
        envelope: &TrajectoryEnvelope,
    ) -> Result<TrajectoryIngest, TrajectoryRegistryError> {
        if self.poisoned {
            return Err(TrajectoryRegistryError::WriterPoisoned);
        }
        EvidenceRecorder::new()
            .verify_trajectory(envelope)
            .map_err(TrajectoryRegistryError::InvalidEnvelope)?;
        let envelope_bytes = encode_envelope(envelope)?;
        let content_digest = digest_bytes(&envelope_bytes);
        let summary = self.scan(|_| Ok(()))?;
        if let Some(stored_digest) = summary.run_digests.get(&envelope.run_id.0) {
            let address = TrajectoryAddress::parse(stored_digest.clone())?;
            return if stored_digest == &content_digest {
                Ok(TrajectoryIngest::AlreadyPresent(address))
            } else {
                Err(TrajectoryRegistryError::RunConflict {
                    run_id: envelope.run_id.0.clone(),
                    stored_digest: stored_digest.clone(),
                    incoming_digest: content_digest,
                })
            };
        }
        if summary.run_digests.len() >= MAX_TRAJECTORY_REGISTRY_RECORDS {
            return Err(TrajectoryRegistryError::TooManyRecords {
                limit: MAX_TRAJECTORY_REGISTRY_RECORDS,
            });
        }

        let record_hash = hash_record(&summary.last_hash, summary.next_sequence, &content_digest);
        let record = RegistryRecord {
            registry_schema_version: REGISTRY_SCHEMA_VERSION,
            sequence: summary.next_sequence,
            previous_hash: summary.last_hash,
            record_hash,
            content_digest: content_digest.clone(),
            envelope: envelope.clone(),
        };
        let mut line = encode_record(&record)?;
        line.push(b'\n');
        let next_bytes = summary
            .verified_bytes
            .checked_add(line.len() as u64)
            .ok_or(TrajectoryRegistryError::RegistryTooLarge {
                bytes: u64::MAX,
                limit: MAX_TRAJECTORY_REGISTRY_BYTES,
            })?;
        ensure_registry_size(next_bytes)?;

        self.poisoned = true;
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.poisoned = false;
        Ok(TrajectoryIngest::Stored(TrajectoryAddress(content_digest)))
    }

    pub fn get_by_run(
        &mut self,
        run_id: &RunId,
    ) -> Result<Option<RegisteredTrajectory>, TrajectoryRegistryError> {
        let mut found = None;
        self.scan(|record| {
            if &record.envelope.run_id == run_id {
                found = Some(registered(record)?);
            }
            Ok(())
        })?;
        Ok(found)
    }

    pub fn get(
        &mut self,
        address: &TrajectoryAddress,
    ) -> Result<Option<RegisteredTrajectory>, TrajectoryRegistryError> {
        let mut found = None;
        self.scan(|record| {
            if record.content_digest == address.0 {
                found = Some(registered(record)?);
            }
            Ok(())
        })?;
        Ok(found)
    }

    pub fn lineage_for_run(
        &mut self,
        run_id: &RunId,
    ) -> Result<Option<TrajectoryLineage>, TrajectoryRegistryError> {
        let mut found = None;
        self.scan(|record| {
            if &record.envelope.run_id == run_id {
                found = Some(TrajectoryLineage {
                    address: TrajectoryAddress::parse(record.content_digest.clone())?,
                    run_id: record.envelope.run_id.clone(),
                    source_bundle: BundleLineage {
                        bundle_id: record.envelope.bundle.bundle_id.clone(),
                        bundle_digest: record.envelope.bundle.digest.clone(),
                        parent_bundle_id: record.envelope.bundle.rollback_to.clone(),
                    },
                    source_policies: record.envelope.bundle.policies.clone(),
                });
            }
            Ok(())
        })?;
        Ok(found)
    }

    pub fn len(&mut self) -> Result<usize, TrajectoryRegistryError> {
        Ok(self.scan(|_| Ok(()))?.run_digests.len())
    }

    pub fn is_empty(&mut self) -> Result<bool, TrajectoryRegistryError> {
        self.len().map(|length| length == 0)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn scan(
        &mut self,
        mut visitor: impl FnMut(&RegistryRecord) -> Result<(), TrajectoryRegistryError>,
    ) -> Result<ScanSummary, TrajectoryRegistryError> {
        self.ensure_file_identity()?;
        self.file.seek(SeekFrom::Start(0))?;
        let original_len = self.file.metadata()?.len();
        ensure_registry_size(original_len)?;
        let mut reader = BufReader::new(&mut self.file);
        let mut sequence = 0u64;
        let mut last_hash = ZERO_HASH.to_string();
        let mut verified_bytes = 0u64;
        let mut run_digests = BTreeMap::new();

        while let Some((bytes, terminated, consumed)) = read_bounded_line(&mut reader)? {
            if !terminated {
                break;
            }
            if sequence as usize >= MAX_TRAJECTORY_REGISTRY_RECORDS {
                return Err(TrajectoryRegistryError::TooManyRecords {
                    limit: MAX_TRAJECTORY_REGISTRY_RECORDS,
                });
            }
            let record: RegistryRecord = serde_json::from_slice(&bytes)?;
            verify_record(&record, sequence, &last_hash)?;
            if run_digests
                .insert(
                    record.envelope.run_id.0.clone(),
                    record.content_digest.clone(),
                )
                .is_some()
            {
                return Err(TrajectoryRegistryError::DuplicateStoredRun {
                    run_id: record.envelope.run_id.0.clone(),
                });
            }
            visitor(&record)?;
            sequence = sequence.saturating_add(1);
            last_hash = record.record_hash;
            verified_bytes = verified_bytes.checked_add(consumed as u64).ok_or(
                TrajectoryRegistryError::RegistryTooLarge {
                    bytes: u64::MAX,
                    limit: MAX_TRAJECTORY_REGISTRY_BYTES,
                },
            )?;
        }
        drop(reader);

        if verified_bytes < original_len {
            self.file.set_len(verified_bytes)?;
            self.file.sync_all()?;
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(ScanSummary {
            next_sequence: sequence,
            last_hash,
            verified_bytes,
            run_digests,
        })
    }

    fn ensure_file_identity(&self) -> Result<(), TrajectoryRegistryError> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink() {
            return Err(TrajectoryRegistryError::SymlinkRefused {
                path: self.path.clone(),
            });
        }
        if !metadata.is_file() {
            return Err(TrajectoryRegistryError::InvalidPathKind {
                path: self.path.clone(),
            });
        }
        #[cfg(unix)]
        if file_identity(&metadata).device != self.identity.device
            || file_identity(&metadata).inode != self.identity.inode
        {
            return Err(TrajectoryRegistryError::InvalidPathKind {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}

impl Drop for TrajectoryRegistry {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn verify_record(
    record: &RegistryRecord,
    expected_sequence: u64,
    expected_previous: &str,
) -> Result<(), TrajectoryRegistryError> {
    if record.registry_schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(TrajectoryRegistryError::UnsupportedRecordSchema {
            sequence: expected_sequence,
            found: record.registry_schema_version,
        });
    }
    if record.sequence != expected_sequence {
        return Err(TrajectoryRegistryError::SequenceMismatch {
            expected: expected_sequence,
            found: record.sequence,
        });
    }
    if record.previous_hash != expected_previous {
        return Err(TrajectoryRegistryError::PreviousHashMismatch {
            sequence: record.sequence,
        });
    }
    EvidenceRecorder::new()
        .verify_trajectory(&record.envelope)
        .map_err(|source| TrajectoryRegistryError::InvalidStoredEnvelope {
            sequence: record.sequence,
            source,
        })?;
    let envelope_bytes = encode_envelope(&record.envelope)?;
    if digest_bytes(&envelope_bytes) != record.content_digest {
        return Err(TrajectoryRegistryError::ContentDigestMismatch {
            sequence: record.sequence,
        });
    }
    let computed = hash_record(
        &record.previous_hash,
        record.sequence,
        &record.content_digest,
    );
    if computed != record.record_hash {
        return Err(TrajectoryRegistryError::RecordHashMismatch {
            sequence: record.sequence,
        });
    }
    Ok(())
}

fn registered(record: &RegistryRecord) -> Result<RegisteredTrajectory, TrajectoryRegistryError> {
    Ok(RegisteredTrajectory {
        address: TrajectoryAddress::parse(record.content_digest.clone())?,
        envelope: record.envelope.clone(),
    })
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;

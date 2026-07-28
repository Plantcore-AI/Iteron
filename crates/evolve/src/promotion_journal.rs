//! Fixed-bounded append-only journal for promotion decisions and exact deployment bytes.

use crate::promotion::{DeploymentBundle, MAX_PROMOTION_AUDIT_EVENTS, PromotionAuthorityError};
use crate::promotion_auth::PromotionRequest;
use crate::promotion_evaluation::{SignedHeldOutEvaluation, SignedStageObservation, StagePermit};
use crate::verifier_crypto::sha256_hex;
use crate::{BaseModelId, DeploymentStage, PolicyRef};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const MAX_PROMOTION_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_PROMOTION_JOURNAL_RECORD_BYTES: usize = 2 * 1024 * 1024;
/// Bumped 1 -> 2 when `base_model` was threaded into `CandidateIdentity` and into the signed
/// `HeldOutEvaluation` payload.
///
/// This is a hard break rather than a migration, and deliberately so. The new field is inside the
/// HMAC preimage, so every held-out signature written under schema 1 recomputes to a different value
/// and would be reported as forged rather than as old. A journal that cannot distinguish "this
/// attestation predates a field" from "this attestation was tampered with" must refuse to read the
/// old one, and the existing check below already does exactly that. There are no shipped journals,
/// so the cost of breaking now is zero; after the first real promotion it would be a migration of
/// hash-chained, signed records.
const JOURNAL_SCHEMA_VERSION: u16 = 2;
const JOURNAL_FILE_NAME: &str = "promotion-authority.jsonl";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CandidateIdentity {
    pub(crate) bundle_id: String,
    pub(crate) bundle_digest: String,
    pub(crate) rollback_bundle_id: String,
    pub(crate) baseline_bundle_digest: String,
    pub(crate) candidate_policy: PolicyRef,
    pub(crate) parent_policy: Option<PolicyRef>,
    pub(crate) artifact_digest: String,
    pub(crate) training_dataset_digest: Option<String>,
    pub(crate) evaluation_suite_digest: String,
    /// Copied off the verified inputs, so the authority holds the base model the *verifier* read.
    /// `verify_held_out_without_suite` refuses an attestation whose signed report names a different
    /// one, which is what stops evidence gathered on one set of weights being replayed for another.
    pub(crate) base_model: BaseModelId,
    pub(crate) evaluation_owner_id: String,
    pub(crate) evaluator_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefusalCode {
    StageBounds,
    InvariantSuite,
    BudgetPolicy,
    SecurityPolicy,
    DurabilityPolicy,
    PromotionThreshold,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum JournalEvent {
    Bootstrapped {
        bundle: DeploymentBundle,
    },
    CandidateAdmitted {
        bundle: DeploymentBundle,
        identity: Box<CandidateIdentity>,
        held_out_attestation: Box<SignedHeldOutEvaluation>,
    },
    StageTransition {
        candidate_bundle_digest: String,
        from: DeploymentStage,
        to: DeploymentStage,
        permit: Option<StagePermit>,
        stage_attestation: Option<Box<SignedStageObservation>>,
    },
    StageRefused {
        candidate_bundle_digest: String,
        stage: DeploymentStage,
        codes: Vec<RefusalCode>,
        stage_attestation: Box<SignedStageObservation>,
    },
    RolledBack {
        candidate_bundle_digest: String,
        from: DeploymentStage,
        restored_bundle_id: String,
        restored_bundle_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JournalContent {
    pub(crate) authority_id: String,
    pub(crate) policy_digest: String,
    pub(crate) request: PromotionRequest,
    pub(crate) authorizing_party: String,
    pub(crate) authorization_signature: String,
    pub(crate) event: JournalEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JournalRecord {
    journal_schema_version: u16,
    pub(crate) sequence: u64,
    previous_hash: String,
    pub(crate) record_hash: String,
    content_digest: String,
    pub(crate) content: JournalContent,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

pub(crate) struct PromotionJournal {
    directory: PathBuf,
    path: PathBuf,
    file: File,
    #[cfg(unix)]
    identity: FileIdentity,
    poisoned: bool,
}

impl PromotionJournal {
    pub(crate) fn open(directory: &Path) -> Result<Self, PromotionAuthorityError> {
        let directory = prepare_directory(directory)?;
        let path = directory.join(JOURNAL_FILE_NAME);
        reject_symlink_or_special(&path, true)?;
        let was_missing = std::fs::symlink_metadata(&path).is_err();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(PromotionAuthorityError::InvalidJournalPath { path });
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(PromotionAuthorityError::WriterBusy { path });
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        #[cfg(unix)]
        let identity = file_identity(&file.metadata()?);
        let mut journal = Self {
            directory,
            path,
            file,
            #[cfg(unix)]
            identity,
            poisoned: false,
        };
        if was_missing {
            journal.file.sync_all()?;
            sync_directory(&journal.directory)?;
        }
        journal.records()?;
        Ok(journal)
    }

    pub(crate) fn records(&mut self) -> Result<Vec<JournalRecord>, PromotionAuthorityError> {
        self.ensure_identity()?;
        self.file.seek(SeekFrom::Start(0))?;
        let original_len = self.file.metadata()?.len();
        ensure_size(original_len)?;
        let mut reader = BufReader::new(&mut self.file);
        let mut records = Vec::new();
        let mut expected_sequence = 0u64;
        let mut previous_hash = ZERO_HASH.to_owned();
        let mut verified_bytes = 0u64;

        while let Some((bytes, terminated, consumed)) = read_bounded_line(&mut reader)? {
            if !terminated {
                break;
            }
            if records.len() >= MAX_PROMOTION_AUDIT_EVENTS {
                return Err(PromotionAuthorityError::AuditLimit {
                    max: MAX_PROMOTION_AUDIT_EVENTS,
                });
            }
            let record: JournalRecord = serde_json::from_slice(&bytes)?;
            verify_record(&record, expected_sequence, &previous_hash)?;
            expected_sequence =
                expected_sequence
                    .checked_add(1)
                    .ok_or(PromotionAuthorityError::AuditLimit {
                        max: MAX_PROMOTION_AUDIT_EVENTS,
                    })?;
            previous_hash.clone_from(&record.record_hash);
            verified_bytes = verified_bytes.checked_add(consumed as u64).ok_or(
                PromotionAuthorityError::JournalTooLarge {
                    max: MAX_PROMOTION_JOURNAL_BYTES,
                    actual: u64::MAX,
                },
            )?;
            records.push(record);
        }
        drop(reader);
        if verified_bytes < original_len {
            self.file.set_len(verified_bytes)?;
            self.file.sync_all()?;
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(records)
    }

    pub(crate) fn append(
        &mut self,
        content: JournalContent,
    ) -> Result<JournalRecord, PromotionAuthorityError> {
        if self.poisoned {
            return Err(PromotionAuthorityError::WriterPoisoned);
        }
        let records = self.records()?;
        if records.len() >= MAX_PROMOTION_AUDIT_EVENTS {
            return Err(PromotionAuthorityError::AuditLimit {
                max: MAX_PROMOTION_AUDIT_EVENTS,
            });
        }
        let sequence = records.len() as u64;
        let previous_hash = records
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |record| record.record_hash.clone());
        let content_bytes = bounded_json(&content, MAX_PROMOTION_JOURNAL_RECORD_BYTES)?;
        let content_digest = sha256_hex(&content_bytes);
        let record_hash = chained_hash(&previous_hash, sequence, &content_digest);
        let record = JournalRecord {
            journal_schema_version: JOURNAL_SCHEMA_VERSION,
            sequence,
            previous_hash,
            record_hash,
            content_digest,
            content,
        };
        let mut bytes = bounded_json(&record, MAX_PROMOTION_JOURNAL_RECORD_BYTES - 1)?;
        bytes.push(b'\n');
        let next_size = self
            .file
            .metadata()?
            .len()
            .checked_add(bytes.len() as u64)
            .ok_or(PromotionAuthorityError::JournalTooLarge {
                max: MAX_PROMOTION_JOURNAL_BYTES,
                actual: u64::MAX,
            })?;
        ensure_size(next_size)?;
        self.poisoned = true;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        self.poisoned = false;
        Ok(record)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_identity(&self) -> Result<(), PromotionAuthorityError> {
        reject_symlink_or_special(&self.path, false)?;
        #[cfg(unix)]
        {
            let current = file_identity(&std::fs::metadata(&self.path)?);
            if current.device != self.identity.device || current.inode != self.identity.inode {
                return Err(PromotionAuthorityError::InvalidJournalPath {
                    path: self.path.clone(),
                });
            }
        }
        Ok(())
    }
}

impl Drop for PromotionJournal {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn verify_record(
    record: &JournalRecord,
    expected_sequence: u64,
    expected_previous: &str,
) -> Result<(), PromotionAuthorityError> {
    if record.journal_schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(PromotionAuthorityError::UnsupportedJournalSchema {
            sequence: expected_sequence,
            found: record.journal_schema_version,
        });
    }
    let content_bytes = bounded_json(&record.content, MAX_PROMOTION_JOURNAL_RECORD_BYTES)?;
    let valid = record.sequence == expected_sequence
        && record.previous_hash == expected_previous
        && sha256_hex(&content_bytes) == record.content_digest
        && chained_hash(
            &record.previous_hash,
            record.sequence,
            &record.content_digest,
        ) == record.record_hash;
    if !valid {
        return Err(PromotionAuthorityError::CorruptJournal {
            sequence: expected_sequence,
        });
    }
    Ok(())
}

fn chained_hash(previous_hash: &str, sequence: u64, content_digest: &str) -> String {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(b"core-evolve/promotion-journal/v1\0");
    bytes.extend_from_slice(previous_hash.as_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(content_digest.as_bytes());
    sha256_hex(&bytes)
}

fn prepare_directory(directory: &Path) -> Result<PathBuf, PromotionAuthorityError> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(PromotionAuthorityError::InvalidJournalPath {
                path: directory.to_path_buf(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    reject_symlink_or_special(directory, false)?;
    Ok(std::fs::canonicalize(directory)?)
}

fn reject_symlink_or_special(
    path: &Path,
    missing_allowed: bool,
) -> Result<(), PromotionAuthorityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(PromotionAuthorityError::InvalidJournalPath {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if !metadata.is_file() && !metadata.is_dir() => {
            Err(PromotionAuthorityError::InvalidJournalPath {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if missing_allowed && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
) -> Result<Option<(Vec<u8>, bool, usize)>, PromotionAuthorityError> {
    let mut bytes = Vec::new();
    let consumed = reader
        .take((MAX_PROMOTION_JOURNAL_RECORD_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if consumed == 0 {
        return Ok(None);
    }
    if consumed > MAX_PROMOTION_JOURNAL_RECORD_BYTES {
        return Err(PromotionAuthorityError::RecordTooLarge {
            max: MAX_PROMOTION_JOURNAL_RECORD_BYTES,
            actual: consumed,
        });
    }
    let terminated = bytes.last() == Some(&b'\n');
    if terminated {
        bytes.pop();
    }
    Ok(Some((bytes, terminated, consumed)))
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("promotion JSON bound exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, PromotionAuthorityError> {
    let mut writer = CappedWriter {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(PromotionAuthorityError::RecordTooLarge {
            max: limit,
            actual: limit.saturating_add(1),
        });
    }
    result?;
    Ok(writer.bytes)
}

fn ensure_size(actual: u64) -> Result<(), PromotionAuthorityError> {
    if actual > MAX_PROMOTION_JOURNAL_BYTES {
        Err(PromotionAuthorityError::JournalTooLarge {
            max: MAX_PROMOTION_JOURNAL_BYTES,
            actual,
        })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

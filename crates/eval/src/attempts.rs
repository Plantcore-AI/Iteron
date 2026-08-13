//! Hash-chained physical-attempt ledger for benchmark retries.
//!
//! A logical cell remains one task/config/seed result, but every physical execution is recorded
//! before it starts and after it settles. Retry accounting therefore survives a harness crash and
//! can never be reconstructed from only the winning attempt.

use crate::types::RunStatus;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"iteron-eval/attempt-ledger/v1\0";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_PHYSICAL_ATTEMPTS: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptKey {
    pub task: String,
    pub config: String,
    pub seed: u64,
    pub attempt: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttemptEvent {
    Planned {
        key: AttemptKey,
    },
    Started {
        key: AttemptKey,
    },
    Finished {
        key: AttemptKey,
        run_status: RunStatus,
        failure_phase: Option<String>,
    },
}

impl AttemptEvent {
    fn key(&self) -> &AttemptKey {
        match self {
            Self::Planned { key } | Self::Started { key } | Self::Finished { key, .. } => key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecord {
    schema_version: u8,
    sequence: u64,
    previous_hash: String,
    event: AttemptEvent,
    hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptPhase {
    Planned,
    Started,
    Finished,
}

#[derive(Debug, thiserror::Error)]
pub enum AttemptLedgerError {
    #[error("attempt ledger I/O at `{path}`: {reason}")]
    Io { path: String, reason: String },
    #[error("attempt ledger is corrupt at sequence {0}")]
    Corrupt(u64),
    #[error("attempt ledger exceeds the fixed {MAX_LEDGER_BYTES}-byte limit")]
    TooLarge,
    #[error("attempt transition for `{0}` is invalid")]
    InvalidTransition(String),
    #[error("attempt ledger JSON is invalid: {0}")]
    Json(String),
    #[error("attempt ledger lock was poisoned by a failed writer")]
    Poisoned,
}

pub struct AttemptLedger {
    path: PathBuf,
    file: std::fs::File,
    next_sequence: u64,
    previous_hash: String,
    phases: BTreeMap<AttemptKey, AttemptPhase>,
}

impl AttemptLedger {
    pub fn create(path: &Path) -> Result<Self, AttemptLedgerError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| io(path, error))?;
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path)
            .map_err(|error| io(path, error))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_sequence: 1,
            previous_hash: "0".repeat(64),
            phases: BTreeMap::new(),
        })
    }

    pub fn open(path: &Path) -> Result<Self, AttemptLedgerError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(AttemptLedgerError::Io {
                path: path.display().to_string(),
                reason: "ledger must be a regular non-symlink file".into(),
            });
        }
        if metadata.len()
            > iteron_tunables::param_integer("eval.attempts.max_ledger_bytes", MAX_LEDGER_BYTES)
        {
            return Err(AttemptLedgerError::TooLarge);
        }
        let reader =
            std::io::BufReader::new(std::fs::File::open(path).map_err(|error| io(path, error))?);
        let mut next_sequence = 1_u64;
        let mut previous_hash = "0".repeat(64);
        let mut phases = BTreeMap::new();
        for line in reader.split(b'\n') {
            let line = line.map_err(|error| io(path, error))?;
            if line.is_empty() {
                continue;
            }
            if line.len()
                > iteron_tunables::param_integer("eval.attempts.max_record_bytes", MAX_RECORD_BYTES)
            {
                return Err(AttemptLedgerError::Corrupt(next_sequence));
            }
            let record: LedgerRecord = serde_json::from_slice(&line)
                .map_err(|error| AttemptLedgerError::Json(error.to_string()))?;
            if record.schema_version != 1
                || record.sequence != next_sequence
                || record.previous_hash != previous_hash
                || record.hash
                    != record_hash(record.sequence, &record.previous_hash, &record.event)?
            {
                return Err(AttemptLedgerError::Corrupt(next_sequence));
            }
            apply_phase(&mut phases, &record.event)?;
            previous_hash = record.hash;
            next_sequence = next_sequence
                .checked_add(1)
                .ok_or(AttemptLedgerError::Corrupt(record.sequence))?;
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| io(path, error))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_sequence,
            previous_hash,
            phases,
        })
    }

    pub fn append(&mut self, event: AttemptEvent) -> Result<(), AttemptLedgerError> {
        // Validate against a copy so an I/O failure cannot advance the in-memory state past the
        // durable journal. Callers may safely retry the append or reopen the ledger.
        let mut next_phases = self.phases.clone();
        apply_phase(&mut next_phases, &event)?;
        let hash = record_hash(self.next_sequence, &self.previous_hash, &event)?;
        let record = LedgerRecord {
            schema_version: 1,
            sequence: self.next_sequence,
            previous_hash: self.previous_hash.clone(),
            event,
            hash: hash.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| AttemptLedgerError::Json(error.to_string()))?;
        if bytes.len()
            > iteron_tunables::param_integer("eval.attempts.max_record_bytes", MAX_RECORD_BYTES)
        {
            return Err(AttemptLedgerError::TooLarge);
        }
        let projected = self
            .file
            .metadata()
            .map_err(|error| io(&self.path, error))?
            .len()
            .saturating_add(bytes.len() as u64 + 1);
        if projected
            > iteron_tunables::param_integer("eval.attempts.max_ledger_bytes", MAX_LEDGER_BYTES)
        {
            return Err(AttemptLedgerError::TooLarge);
        }
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.sync_data())
            .map_err(|error| io(&self.path, error))?;
        self.phases = next_phases;
        self.previous_hash = hash;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AttemptLedgerError::Corrupt(record.sequence))?;
        Ok(())
    }

    pub fn head_hash(&self) -> &str {
        &self.previous_hash
    }

    pub fn record_count(&self) -> u64 {
        self.next_sequence.saturating_sub(1)
    }
}

fn apply_phase(
    phases: &mut BTreeMap<AttemptKey, AttemptPhase>,
    event: &AttemptEvent,
) -> Result<(), AttemptLedgerError> {
    let key = event.key().clone();
    if key.attempt == 0
        || key.attempt
            > iteron_tunables::param_integer(
                "eval.attempts.max_physical_attempts",
                MAX_PHYSICAL_ATTEMPTS,
            )
        || key.task.is_empty()
        || key.config.is_empty()
        || key.task.len() > 512
        || key.config.len() > 128
    {
        return Err(AttemptLedgerError::InvalidTransition(format!(
            "{}/{}/{}/{}",
            key.task, key.config, key.seed, key.attempt
        )));
    }
    let prior_finished = key.attempt == 1 || {
        let mut prior = key.clone();
        prior.attempt -= 1;
        phases.get(&prior) == Some(&AttemptPhase::Finished)
    };
    let valid = match (phases.get(&key), event) {
        (None, AttemptEvent::Planned { .. }) if prior_finished => Some(AttemptPhase::Planned),
        (Some(AttemptPhase::Planned), AttemptEvent::Started { .. }) => Some(AttemptPhase::Started),
        (Some(AttemptPhase::Started), AttemptEvent::Finished { .. }) => {
            Some(AttemptPhase::Finished)
        }
        _ => None,
    };
    let Some(next) = valid else {
        return Err(AttemptLedgerError::InvalidTransition(format!(
            "{}/{}/{}/{}",
            key.task, key.config, key.seed, key.attempt
        )));
    };
    phases.insert(key, next);
    Ok(())
}

fn record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &AttemptEvent,
) -> Result<String, AttemptLedgerError> {
    let event =
        serde_json::to_vec(event).map_err(|error| AttemptLedgerError::Json(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(sequence.to_le_bytes());
    digest.update(previous_hash.as_bytes());
    digest.update(event);
    Ok(hex::encode(digest.finalize()))
}

fn io(path: &Path, error: std::io::Error) -> AttemptLedgerError {
    AttemptLedgerError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

pub fn sidecar_path(output: &Path) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("iteron-eval-result.json");
    output.with_file_name(format!("{name}.attempts.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(attempt: u8) -> AttemptKey {
        AttemptKey {
            task: "task".into(),
            config: "arm".into(),
            seed: 7,
            attempt,
        }
    }

    #[test]
    fn ledger_reopens_and_rejects_a_duplicate_terminal_transition() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-eval-attempt-ledger-{}-{nonce:x}.jsonl",
            std::process::id(),
        ));
        let _ = std::fs::remove_file(&path);
        let mut ledger = AttemptLedger::create(&path).unwrap();
        ledger
            .append(AttemptEvent::Planned { key: key(1) })
            .unwrap();
        ledger
            .append(AttemptEvent::Started { key: key(1) })
            .unwrap();
        ledger
            .append(AttemptEvent::Finished {
                key: key(1),
                run_status: RunStatus::Completed,
                failure_phase: None,
            })
            .unwrap();
        let head = ledger.head_hash().to_owned();
        drop(ledger);
        let mut reopened = AttemptLedger::open(&path).unwrap();
        assert_eq!(reopened.head_hash(), head);
        assert!(
            reopened
                .append(AttemptEvent::Finished {
                    key: key(1),
                    run_status: RunStatus::Completed,
                    failure_phase: None,
                })
                .is_err()
        );
        let _ = std::fs::remove_file(path);
    }
}

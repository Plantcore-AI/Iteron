use super::{TunerError, TunerEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"iteron-eval/offline-tuner-journal/v1\0";
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u8,
    sequence: u64,
    previous_hash: String,
    event: TunerEvent,
    hash: String,
}

pub(super) struct TunerJournal {
    path: PathBuf,
    file: std::fs::File,
    next_sequence: u64,
    previous_hash: String,
}

impl TunerJournal {
    pub(super) fn create(path: &Path) -> Result<Self, TunerError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| io(path, error))?;
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path)
            .map_err(|error| io(path, error))?;
        Ok(Self {
            path: path.into(),
            file,
            next_sequence: 1,
            previous_hash: "0".repeat(64),
        })
    }

    pub(super) fn open(path: &Path) -> Result<(Self, Vec<TunerEvent>), TunerError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len()
                > iteron_tunables::param_integer(
                    "eval.tuner.journal.max_journal_bytes",
                    MAX_JOURNAL_BYTES,
                )
        {
            return Err(TunerError::Journal(
                "journal must be a bounded regular file".into(),
            ));
        }
        let reader =
            std::io::BufReader::new(std::fs::File::open(path).map_err(|error| io(path, error))?);
        let mut sequence = 1_u64;
        let mut previous_hash = "0".repeat(64);
        let mut events = Vec::new();
        for line in reader.split(b'\n') {
            let line = line.map_err(|error| io(path, error))?;
            if line.is_empty() {
                continue;
            }
            if line.len()
                > iteron_tunables::param_integer(
                    "eval.tuner.journal.max_record_bytes",
                    MAX_RECORD_BYTES,
                )
            {
                return Err(TunerError::Journal(
                    "journal record exceeds its limit".into(),
                ));
            }
            let record: Record = serde_json::from_slice(&line)
                .map_err(|error| TunerError::Journal(error.to_string()))?;
            if record.schema_version != 1
                || record.sequence != sequence
                || record.previous_hash != previous_hash
                || record.hash != record_hash(sequence, &previous_hash, &record.event)?
            {
                return Err(TunerError::Journal(format!(
                    "hash-chain mismatch at sequence {sequence}"
                )));
            }
            previous_hash = record.hash;
            events.push(record.event);
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| TunerError::Journal("journal sequence overflow".into()))?;
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| io(path, error))?;
        Ok((
            Self {
                path: path.into(),
                file,
                next_sequence: sequence,
                previous_hash,
            },
            events,
        ))
    }

    pub(super) fn append(&mut self, event: &TunerEvent) -> Result<(), TunerError> {
        let hash = record_hash(self.next_sequence, &self.previous_hash, event)?;
        let record = Record {
            schema_version: 1,
            sequence: self.next_sequence,
            previous_hash: self.previous_hash.clone(),
            event: event.clone(),
            hash: hash.clone(),
        };
        let bytes =
            serde_json::to_vec(&record).map_err(|error| TunerError::Journal(error.to_string()))?;
        let projected = self
            .file
            .metadata()
            .map_err(|error| io(&self.path, error))?
            .len()
            .saturating_add(bytes.len() as u64 + 1);
        if bytes.len()
            > iteron_tunables::param_integer(
                "eval.tuner.journal.max_record_bytes",
                MAX_RECORD_BYTES,
            )
            || projected
                > iteron_tunables::param_integer(
                    "eval.tuner.journal.max_journal_bytes",
                    MAX_JOURNAL_BYTES,
                )
        {
            return Err(TunerError::Journal("journal size limit reached".into()));
        }
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.sync_data())
            .map_err(|error| io(&self.path, error))?;
        self.previous_hash = hash;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| TunerError::Journal("journal sequence overflow".into()))?;
        Ok(())
    }

    pub(super) fn head_hash(&self) -> &str {
        &self.previous_hash
    }
}

fn record_hash(sequence: u64, previous: &str, event: &TunerEvent) -> Result<String, TunerError> {
    let bytes =
        serde_json::to_vec(event).map_err(|error| TunerError::Journal(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(sequence.to_le_bytes());
    digest.update(previous.as_bytes());
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

fn io(path: &Path, error: std::io::Error) -> TunerError {
    TunerError::Journal(format!("{}: {error}", path.display()))
}

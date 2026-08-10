//! Durable content-free journal for Hook commands executed outside the resident Agent borrow.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

const VERSION: u8 = 1;
const MAX_ENTRIES: u64 = 131_072;

#[derive(Debug, Clone)]
pub(crate) struct HookEffectJournal {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    file: File,
    next_sequence: u64,
    previous_hash: String,
    recovered_unknown: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HookEffectTicket {
    invocation: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    version: u8,
    sequence: u64,
    invocation: u64,
    event_id: String,
    phase: Phase,
    outcome: Option<String>,
    previous_hash: String,
    hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    Terminal,
}

#[derive(Debug, Serialize)]
struct HashBody<'a> {
    version: u8,
    sequence: u64,
    invocation: u64,
    event_id: &'a str,
    phase: Phase,
    outcome: Option<&'a str>,
    previous_hash: &'a str,
}

impl HookEffectJournal {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let (next_sequence, previous_hash, recovered_unknown) = replay(path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create hook journal directory: {error}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("cannot open hook journal: {error}"))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                file,
                next_sequence,
                previous_hash,
                recovered_unknown,
            })),
        })
    }

    pub(crate) fn recovered_unknown(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| inner.recovered_unknown)
            .unwrap_or(u64::MAX)
    }

    /// Persist and fsync intent before the arbitrary operator command can start.
    pub(crate) fn begin(&self, event_id: &str) -> Result<HookEffectTicket, String> {
        let mut inner = self.inner.lock().map_err(|_| "hook journal poisoned")?;
        let invocation = inner.next_sequence;
        append(&mut inner, invocation, event_id, Phase::Intent, None)?;
        Ok(HookEffectTicket { invocation })
    }

    /// Persist one terminal after the command chain settles. Unknown outcomes deliberately remain
    /// as unmatched intents when the process crashes between these two calls.
    pub(crate) fn finish(
        &self,
        ticket: HookEffectTicket,
        event_id: &str,
        outcome: &'static str,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| "hook journal poisoned")?;
        append(
            &mut inner,
            ticket.invocation,
            event_id,
            Phase::Terminal,
            Some(outcome),
        )
    }
}

fn append(
    inner: &mut Inner,
    invocation: u64,
    event_id: &str,
    phase: Phase,
    outcome: Option<&'static str>,
) -> Result<(), String> {
    let sequence = inner.next_sequence;
    if sequence >= MAX_ENTRIES {
        return Err("hook journal reached its fixed entry ceiling".into());
    }
    let body = HashBody {
        version: VERSION,
        sequence,
        invocation,
        event_id,
        phase,
        outcome,
        previous_hash: &inner.previous_hash,
    };
    let canonical = serde_json::to_vec(&body)
        .map_err(|error| format!("cannot encode hook journal hash body: {error}"))?;
    let hash = format!("{:x}", Sha256::digest(canonical));
    let entry = Entry {
        version: VERSION,
        sequence,
        invocation,
        event_id: event_id.to_owned(),
        phase,
        outcome: outcome.map(str::to_owned),
        previous_hash: inner.previous_hash.clone(),
        hash: hash.clone(),
    };
    serde_json::to_writer(&mut inner.file, &entry)
        .map_err(|error| format!("cannot append hook journal: {error}"))?;
    inner
        .file
        .write_all(b"\n")
        .and_then(|_| inner.file.sync_data())
        .map_err(|error| format!("cannot fsync hook journal: {error}"))?;
    inner.previous_hash = hash;
    inner.next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| "hook journal sequence exhausted".to_string())?;
    Ok(())
}

fn replay(path: &Path) -> Result<(u64, String, u64), String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, String::new(), 0));
        }
        Err(error) => return Err(format!("cannot read hook journal: {error}")),
    };
    let mut expected_sequence = 0u64;
    let mut previous_hash = String::new();
    let mut pending = std::collections::BTreeMap::<u64, String>::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| format!("cannot read hook journal entry: {error}"))?;
        let entry: Entry = serde_json::from_str(&line)
            .map_err(|error| format!("invalid hook journal entry: {error}"))?;
        if entry.version != VERSION
            || entry.sequence != expected_sequence
            || entry.previous_hash != previous_hash
        {
            return Err("hook journal chain or sequence mismatch".into());
        }
        let canonical = serde_json::to_vec(&HashBody {
            version: entry.version,
            sequence: entry.sequence,
            invocation: entry.invocation,
            event_id: &entry.event_id,
            phase: entry.phase,
            outcome: entry.outcome.as_deref(),
            previous_hash: &entry.previous_hash,
        })
        .map_err(|error| format!("cannot verify hook journal: {error}"))?;
        if format!("{:x}", Sha256::digest(canonical)) != entry.hash {
            return Err("hook journal hash mismatch".into());
        }
        match entry.phase {
            Phase::Intent => {
                if pending
                    .insert(entry.invocation, entry.event_id.clone())
                    .is_some()
                {
                    return Err("hook journal repeated an invocation intent".into());
                }
            }
            Phase::Terminal => {
                let Some(intent_event) = pending.remove(&entry.invocation) else {
                    return Err("hook journal terminal has no matching intent".into());
                };
                if intent_event != entry.event_id || entry.outcome.is_none() {
                    return Err("hook journal terminal does not match its intent".into());
                }
            }
        }
        previous_hash = entry.hash;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| "hook journal sequence exhausted".to_string())?;
    }
    if expected_sequence > MAX_ENTRIES {
        return Err("hook journal exceeds its fixed entry ceiling".into());
    }
    Ok((
        expected_sequence,
        previous_hash,
        u64::try_from(pending.len()).unwrap_or(u64::MAX),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_and_terminal_replay_as_one_hash_chain() {
        let path = std::env::temp_dir().join(format!(
            "core-hook-journal-{}-{}.jsonl",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let journal = HookEffectJournal::open(&path).unwrap();
        let ticket = journal.begin("session.started").unwrap();
        journal
            .finish(ticket, "session.started", "completed")
            .unwrap();
        drop(journal);
        let reopened = HookEffectJournal::open(&path).unwrap();
        let _ = reopened.begin("session.idle").unwrap();
        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 3);
        let _ = std::fs::remove_file(path);
    }
}

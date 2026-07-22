//! The append-only outcome journal + content-hash resume cache (design §2.7 + review B2).
//!
//! One flat `journal.jsonl` per run, one `result` line per completed `agent()` call, keyed by the
//! `v2:` content hash. The load-bearing invariant (B2): the journal stores the OUTCOME —
//! `Structured | Text | Null` — and `__agent` short-circuits on a journal hit BEFORE the Governor,
//! budget, or lifetime cap. Negative outcomes (null/error/skipped) are journaled and replayed so
//! that `parallel(...).filter(Boolean)` stays deterministic across a resume: a call that returned
//! `null` live is replayed as `null`, never re-run (which could non-deterministically succeed and
//! cascade a cache miss through every downstream prompt).
//!
//! This is a deliberately lightweight writer, NOT the hash-chained `core-record` rollout — resume is
//! keyed by content hash, not `Seq`, so the heavier format buys nothing here (design §6). It does
//! reuse the rollout's exclusive-append discipline via a single `Mutex<File>` opened in append mode.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The replayable outcome of one `agent()` call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Outcome {
    /// A schema-validated JSON object (schema-forced structured output).
    Structured { value: Value },
    /// Plain model text (the no-schema path).
    Text { text: String },
    /// A degraded/terminal-negative outcome, replayed as JS `null`. Carries the reason so the
    /// progress row and resume both see why.
    Null { reason: Option<String> },
}

/// A journaled agent result: its outcome plus the metrics that repaint the progress row on replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub outcome: Outcome,
    #[serde(default)]
    pub tokens: u64,
    #[serde(default)]
    pub tool_calls: u64,
    #[serde(default)]
    pub last_tool_summary: Option<String>,
}

impl Record {
    pub fn structured(value: Value, tokens: u64, tool_calls: u64) -> Self {
        Record {
            outcome: Outcome::Structured { value },
            tokens,
            tool_calls,
            last_tool_summary: None,
        }
    }
    pub fn text(text: String, tokens: u64, tool_calls: u64, last_tool_summary: Option<String>) -> Self {
        Record {
            outcome: Outcome::Text { text },
            tokens,
            tool_calls,
            last_tool_summary,
        }
    }
    pub fn null(reason: Option<String>) -> Self {
        Record {
            outcome: Outcome::Null { reason },
            tokens: 0,
            tool_calls: 0,
            last_tool_summary: None,
        }
    }
}

/// One line in `journal.jsonl`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Line {
    /// Written when live execution begins (mirrors Claude Code's `started` line; informational).
    Started { key: String, agent_id: String },
    /// The replayable result.
    Result {
        key: String,
        agent_id: String,
        record: Record,
    },
}

/// The per-run journal: a shared content-hash cache (prior run's records pre-loaded on resume, plus
/// this run's, so intra-run content-hash dedup also hits) and an optional append-only file sink.
pub struct Journal {
    /// key -> record. Seeded from the resume journal, extended as this run records outcomes.
    cache: Mutex<HashMap<String, Record>>,
    /// Append sink for this run's `journal.jsonl`. `None` = in-memory only (no persistence).
    file: Mutex<Option<File>>,
    hits: AtomicUsize,
    misses: AtomicUsize,
}

impl Journal {
    /// A journal with no persistence and no prior records — every probe misses. Used by the blocking
    /// `WorkflowEngine::run` compat path and by tests that only want the return value.
    pub fn in_memory() -> Self {
        Journal {
            cache: Mutex::new(HashMap::new()),
            file: Mutex::new(None),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        }
    }

    /// Open a journal. `path` (if set) is this run's `journal.jsonl`, created (with parents) and
    /// opened for append. `resume` (if set) is a prior run's `journal.jsonl` whose records are loaded
    /// as the cache — the resume replay source. A missing/short resume file loads as empty (fresh).
    pub fn open(path: Option<PathBuf>, resume: Option<PathBuf>) -> io::Result<Self> {
        let mut cache = HashMap::new();
        if let Some(resume_path) = resume {
            load_records(&resume_path, &mut cache)?;
        }
        let file = match path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent)?;
                }
                Some(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&p)?,
                )
            }
            None => None,
        };
        Ok(Journal {
            cache: Mutex::new(cache),
            file: Mutex::new(file),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        })
    }

    /// Probe the cache. `Some(record)` = journal HIT (replay, counts a hit); `None` = MISS (run
    /// live, counts a miss). This is the B2 short-circuit point — call it FIRST in `__agent`.
    pub fn get(&self, key: &str) -> Option<Record> {
        let hit = self.cache.lock().unwrap().get(key).cloned();
        match &hit {
            Some(_) => self.hits.fetch_add(1, Ordering::Relaxed),
            None => self.misses.fetch_add(1, Ordering::Relaxed),
        };
        hit
    }

    /// Record a live outcome: insert into the cache (so an identical later call in THIS run hits) and
    /// append a `started` + `result` line to `journal.jsonl`. Positive AND negative outcomes are
    /// recorded — that is the B2 invariant.
    pub fn record(&self, key: &str, agent_id: &str, record: Record) {
        self.cache
            .lock()
            .unwrap()
            .insert(key.to_string(), record.clone());
        let mut guard = self.file.lock().unwrap();
        if let Some(file) = guard.as_mut() {
            let started = Line::Started {
                key: key.to_string(),
                agent_id: agent_id.to_string(),
            };
            let result = Line::Result {
                key: key.to_string(),
                agent_id: agent_id.to_string(),
                record,
            };
            let _ = write_line(file, &started);
            let _ = write_line(file, &result);
        }
    }

    /// Flush the append sink to disk (called once at run end so a resume can read it).
    pub fn flush(&self) {
        if let Some(file) = self.file.lock().unwrap().as_mut() {
            let _ = file.flush();
            let _ = file.sync_all();
        }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
    pub fn misses(&self) -> usize {
        self.misses.load(Ordering::Relaxed)
    }
}

fn write_line(file: &mut File, line: &Line) -> io::Result<()> {
    let mut s = serde_json::to_string(line).map_err(io::Error::other)?;
    s.push('\n');
    file.write_all(s.as_bytes())
}

/// Load the last `result` record per key from a prior `journal.jsonl`. Malformed lines are skipped.
fn load_records(path: &Path, out: &mut HashMap<String, Record>) -> io::Result<()> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(Line::Result { key, record, .. }) = serde_json::from_str::<Line>(&line) {
            out.insert(key, record);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_outcomes_through_a_file_and_replays_null() {
        let dir = std::env::temp_dir().join(format!(
            "core-workflow-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("journal.jsonl");

        {
            let j = Journal::open(Some(path.clone()), None).expect("open");
            j.record(
                "v2:aaa",
                "aaa",
                Record::text("hello".into(), 3, 0, None),
            );
            j.record("v2:bbb", "bbb", Record::null(Some("makenull".into())));
            j.flush();
        }

        // Resume: a fresh journal loading the prior file replays both, null included.
        let resumed = Journal::open(None, Some(path.clone())).expect("resume");
        assert_eq!(
            resumed.get("v2:aaa").unwrap().outcome,
            Outcome::Text { text: "hello".into() }
        );
        assert_eq!(
            resumed.get("v2:bbb").unwrap().outcome,
            Outcome::Null {
                reason: Some("makenull".into())
            },
            "null outcomes replay as null (B2)"
        );
        assert_eq!(resumed.hits(), 2);
        assert_eq!(resumed.misses(), 0);
        assert!(resumed.get("v2:missing").is_none());
        assert_eq!(resumed.misses(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}

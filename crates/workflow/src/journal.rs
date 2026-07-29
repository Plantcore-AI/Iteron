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

/// Append format version. Old lines without this field deserialize as v1.
pub const JOURNAL_FORMAT_VERSION: u32 = 1;

const fn journal_format_version() -> u32 {
    JOURNAL_FORMAT_VERSION
}

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
    Null {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A newer writer's outcome vocabulary. Older engines keep it as an honest null-equivalent
    /// cache hit and never re-run a child merely because they cannot interpret its result.
    #[serde(other)]
    Unknown,
}

/// A journaled agent result: its outcome plus the metrics that repaint the progress row on replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub outcome: Outcome,
    #[serde(default)]
    pub tokens: u64,
    #[serde(default)]
    pub tool_calls: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub fn text(
        text: String,
        tokens: u64,
        tool_calls: u64,
        last_tool_summary: Option<String>,
    ) -> Self {
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
    Started {
        #[serde(default = "journal_format_version")]
        version: u32,
        key: String,
        agent_id: String,
    },
    /// The replayable result.
    Result {
        #[serde(default = "journal_format_version")]
        version: u32,
        key: String,
        agent_id: String,
        record: Record,
    },
    /// Forward-compatible sentinel for a newer informational line. It carries no authority and is
    /// ignored by the v1 cache projection.
    #[serde(other)]
    Unknown,
}

/// The per-run journal: a shared content-hash cache (prior run's records pre-loaded on resume, plus
/// this run's, so intra-run content-hash dedup also hits) and an optional append-only file sink.
pub struct Journal {
    /// key -> record. Seeded from the resume journal, extended as this run records outcomes.
    cache: Mutex<HashMap<String, Record>>,
    /// Append sink for this run's `journal.jsonl`. `None` = in-memory only (no persistence).
    file: Mutex<Option<File>>,
    /// First durability failure. Once set, no later write may claim success.
    failure: Mutex<Option<String>>,
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
            failure: Mutex::new(None),
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
                Some(OpenOptions::new().create(true).append(true).open(&p)?)
            }
            None => None,
        };
        Ok(Journal {
            cache: Mutex::new(cache),
            file: Mutex::new(file),
            failure: Mutex::new(None),
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
    pub fn record(&self, key: &str, agent_id: &str, record: Record) -> io::Result<()> {
        if let Some(message) = self.failure.lock().unwrap().clone() {
            return Err(io::Error::other(message));
        }
        let mut guard = self.file.lock().unwrap();
        if let Some(file) = guard.as_mut() {
            let started = Line::Started {
                version: JOURNAL_FORMAT_VERSION,
                key: key.to_string(),
                agent_id: agent_id.to_string(),
            };
            let result = Line::Result {
                version: JOURNAL_FORMAT_VERSION,
                key: key.to_string(),
                agent_id: agent_id.to_string(),
                record: record.clone(),
            };
            let write = write_line(file, &started)
                .and_then(|()| write_line(file, &result))
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_data());
            if let Err(error) = write {
                *self.failure.lock().unwrap() = Some(error.to_string());
                return Err(error);
            }
        }
        self.cache.lock().unwrap().insert(key.to_string(), record);
        Ok(())
    }

    /// Flush the append sink to disk (called once at run end so a resume can read it). Failure is
    /// load-bearing: a run never reports success when its replay evidence is uncertain.
    pub fn flush(&self) -> io::Result<()> {
        if let Some(message) = self.failure.lock().unwrap().clone() {
            return Err(io::Error::other(message));
        }
        if let Some(file) = self.file.lock().unwrap().as_mut() {
            file.flush()?;
            file.sync_all()?;
        }
        Ok(())
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
        if let Ok(Line::Result {
            version,
            key,
            record,
            ..
        }) = serde_json::from_str::<Line>(&line)
            && version == JOURNAL_FORMAT_VERSION
        {
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
            j.record("v2:aaa", "aaa", Record::text("hello".into(), 3, 0, None))
                .unwrap();
            j.record("v2:bbb", "bbb", Record::null(Some("makenull".into())))
                .unwrap();
            j.flush().unwrap();
        }

        // Resume: a fresh journal loading the prior file replays both, null included.
        let resumed = Journal::open(None, Some(path.clone())).expect("resume");
        assert_eq!(
            resumed.get("v2:aaa").unwrap().outcome,
            Outcome::Text {
                text: "hello".into()
            }
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

    #[test]
    fn a_failed_durable_append_never_enters_the_replay_cache() {
        let dir = std::env::temp_dir().join(format!(
            "core-workflow-journal-failure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("read-only.jsonl");
        fs::write(&path, b"").unwrap();
        let read_only = File::open(&path).unwrap();
        let journal = Journal {
            cache: Mutex::new(HashMap::new()),
            file: Mutex::new(Some(read_only)),
            failure: Mutex::new(None),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        };

        assert!(
            journal
                .record(
                    "v2:never",
                    "never",
                    Record::text("unsafe".into(), 1, 0, None)
                )
                .is_err()
        );
        assert!(journal.get("v2:never").is_none());
        assert!(journal.flush().is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_future_outcome_is_a_cache_hit_and_never_becomes_a_reexecution() {
        let dir = std::env::temp_dir().join(format!(
            "core-workflow-journal-future-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("journal.jsonl");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &path,
            concat!(
                "{\"type\":\"future_info\",\"opaque\":true}\n",
                "{\"type\":\"result\",\"version\":1,\"key\":\"v2:future\",",
                "\"agent_id\":\"future\",\"record\":{\"outcome\":{\"t\":\"future_outcome\"},",
                "\"tokens\":0,\"tool_calls\":0}}\n"
            ),
        )
        .unwrap();

        let resumed = Journal::open(None, Some(path)).unwrap();
        assert_eq!(resumed.get("v2:future").unwrap().outcome, Outcome::Unknown);
        assert_eq!(resumed.hits(), 1);
        assert_eq!(resumed.misses(), 0);
        let _ = fs::remove_dir_all(&dir);
    }
}

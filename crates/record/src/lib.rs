//! core-record — the nondeterminism boundary.
//!
//! Every reproducible system quarantines nondeterminism behind a recorded boundary and
//! makes the code above it a pure function of the record (ADR-006). This crate is that
//! boundary. It promises:
//!   (a) replay of the harness's own decisions from the record, and
//!   (b) replay of recorded model outputs,
//! and never (c) re-derivation of a model output.
//!
//! The rollout is an append-only, per-run **hash-chained** JSONL log (ADR-008): each line
//! carries the hash of the previous line, so the chain is tamper-evident. The chain is
//! immutable; the *content* it references is separately erasable (ADR-008 redaction-at-rest)
//! — that reconciliation ("immutable + hash-chained" does not mean "unpurgeable") is the
//! whole point.
//!
//! What is implemented here (vertical slice): the append-only hash-chained rollout with
//! write-ahead durability (intent before effect), replay of the event stream, and the
//! chain-verify. What is stubbed with a pointer: content-addressed tombstonable blobs for
//! GDPR crypto-shred (ADR-008 §1) — the interface is present, the blob store is a TODO.

pub mod checkpoint;
pub mod redact;
pub mod session;

pub use checkpoint::{Snapshot, checkpoint, rewind_workspace};
pub use session::{
    Provenance, SessionMeta, fork, list, load_forked, meta, most_recent, reindex, write_meta,
};

use core_protocol::{Event, RunId, Seq, TenantId};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const MAX_RUN_ID_BYTES: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Another live writer already owns this run's journal. Retrying the same run concurrently
    /// would fork the in-memory hash-chain heads and irreversibly interleave the append stream, so
    /// the second writer is rejected before it scans or mutates the file.
    #[error(
        "rollout already has an active writer at {path}; close the other Core process or choose a different run id"
    )]
    WriterBusy { path: PathBuf },
    /// The platform could not attempt the advisory file lock for a reason other than contention.
    #[error("cannot acquire the exclusive rollout writer lock at {path}: {source}")]
    WriterLock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Run ids are persisted as filenames. Reject anything that is not one portable path
    /// component before touching the filesystem, so a caller-controlled id cannot escape the
    /// configured runs directory (or alias a Windows device when records are moved across hosts).
    #[error("invalid run id: {reason}")]
    InvalidRunId { reason: &'static str },
    /// Once an append has reached file I/O, an error leaves durability ambiguous: the line may be
    /// absent, partial, or complete-but-not-confirmed. Continuing from the old in-memory head could
    /// fork the chain, so the writer fails closed until it is dropped and reopened/recovered.
    #[error("rollout writer is poisoned after an append I/O failure; close and reopen the run")]
    WriterPoisoned,
    /// A physical rollout and every edge in a fork chain are single-tenant boundaries. Tenant is
    /// retained outside the legacy line hash for on-disk compatibility, so it is checked
    /// explicitly on every read/open boundary.
    #[error("tenant mismatch at seq {seq}: expected {expected}, found {found}")]
    TenantMismatch {
        seq: u64,
        expected: String,
        found: String,
    },
    #[error("chain broken at seq {seq}: stored prev {stored} != computed {computed}")]
    ChainBroken {
        seq: u64,
        stored: String,
        computed: String,
    },
    /// A fork child's pinned parent hash (`parent_hash_at_seq`, ADR-008 §4) does not match the
    /// parent chain's actual hash at the fork point: the parent prefix was altered after the fork.
    /// Detected by `session::load_forked` (R5-review Risk 3, tamper-evidence).
    #[error("fork parent tampered: {parent} hash at seq {forked_at} is {actual}, pinned {pinned}")]
    ForkParentMismatch {
        parent: String,
        forked_at: u64,
        pinned: String,
        actual: String,
    },
}

/// One line of the rollout. `prev` chains to the previous line's `hash`; `hash` covers
/// (`prev`, `seq`, `payload`). The genesis line has `prev` = the zero hash.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChainLine {
    seq: u64,
    tenant: String,
    prev: String,
    hash: String,
    /// The recorded payload. For the vertical slice this is an `Event`; the schema is
    /// tagged so intent-records and tool-result-blobs can share the chain later.
    payload: serde_json::Value,
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Validate the identifier before it is interpolated into any rollout or sidecar filename.
///
/// We intentionally allow ordinary Unicode and interior spaces so existing human-named records
/// remain readable. Separators, platform-reserved characters, control bytes, dot components, and
/// names that exceed the portable filename budget are rejected. The explicit cross-platform
/// checks matter when a record directory is copied between Unix and Windows.
pub(crate) fn validate_run_id(run: &RunId) -> Result<(), RecordError> {
    let id = run.0.as_str();
    if id.is_empty() {
        return Err(RecordError::InvalidRunId {
            reason: "must not be empty",
        });
    }
    if id.len() > MAX_RUN_ID_BYTES {
        return Err(RecordError::InvalidRunId {
            reason: "is too long",
        });
    }
    if id.chars().any(char::is_control) {
        return Err(RecordError::InvalidRunId {
            reason: "must not contain control characters",
        });
    }
    if id
        .chars()
        .any(|c| matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err(RecordError::InvalidRunId {
            reason: "must be one portable filename component",
        });
    }
    if id.ends_with('.') || id.ends_with(' ') {
        return Err(RecordError::InvalidRunId {
            reason: "must not end in a dot or space",
        });
    }

    let mut components = Path::new(id).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(RecordError::InvalidRunId {
            reason: "must be one normal path component",
        });
    }

    // Windows treats these basenames as devices even when an extension is appended. Reject them
    // on every platform so a portable record never aliases a device after being copied.
    let device_stem = id.split('.').next().unwrap_or(id).to_ascii_uppercase();
    let reserved_device = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || device_stem
            .strip_prefix("COM")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
        || device_stem
            .strip_prefix("LPT")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"));
    if reserved_device {
        return Err(RecordError::InvalidRunId {
            reason: "is a reserved device name",
        });
    }
    Ok(())
}

pub(crate) fn validated_run_path(
    dir: &Path,
    run: &RunId,
    suffix: &str,
) -> Result<PathBuf, RecordError> {
    validate_run_id(run)?;
    Ok(dir.join(format!("{}{suffix}", run.0)))
}

pub(crate) fn ensure_tenant(expected: &TenantId, found: &str, seq: u64) -> Result<(), RecordError> {
    if expected.0 == found {
        Ok(())
    } else {
        Err(RecordError::TenantMismatch {
            seq,
            expected: expected.0.clone(),
            found: found.to_string(),
        })
    }
}

fn hash_line(prev: &str, seq: u64, payload: &serde_json::Value) -> String {
    // Deterministic: serde_json serializes maps in insertion order for Value::Object, and
    // our payloads are structs with fixed field order, so this is stable across runs on the
    // same input (ADR-006: no map-iteration-order dependence in the recorded bytes).
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(seq.to_le_bytes());
    h.update(payload.to_string().as_bytes());
    hex::encode(h.finalize())
}

/// The append-only, hash-chained rollout for one run. Per-run chain (ADR-008): no global
/// lock, so 100%-coverage append is not a bottleneck across concurrent runs. The open file holds
/// an OS-level exclusive lock for this object's full lifetime: one run has exactly one writer,
/// while different run files remain independently writable.
pub struct Rollout {
    path: PathBuf,
    file: File,
    run: RunId,
    tenant: TenantId,
    seq: Seq,
    last_hash: String,
    poisoned: bool,
}

impl Rollout {
    /// True only before the first durable event has been appended. Frontends use this narrow
    /// predicate to configure a fresh agent's genesis policy; runtime policy changes must use the
    /// kernel's write-ahead transition APIs instead.
    pub fn is_empty(&self) -> bool {
        self.seq == Seq::ZERO && self.last_hash == ZERO_HASH
    }

    /// Open (creating) the rollout for a run under `dir`. If the file exists, resume the
    /// chain from its tail (recoverable, invariant #2). The exclusive writer lock is acquired
    /// before tail recovery, so a second process can neither race the scan nor interleave appends.
    pub fn open(dir: &Path, run: &RunId, tenant: TenantId) -> Result<Self, RecordError> {
        let path = validated_run_path(dir, run, ".jsonl")?;
        std::fs::create_dir_all(dir)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(RecordError::WriterBusy { path });
            }
            Err(TryLockError::Error(source)) => {
                return Err(RecordError::WriterLock { path, source });
            }
        }
        let (seq, last_hash) = match Self::scan_tail(&mut file, &tenant) {
            Ok(tail) => tail,
            Err(error) => {
                // Make the early-return release explicit. Dropping `file` also releases an OS file
                // lock, but this keeps the RAII ownership transition obvious at the error edge.
                let _ = file.unlock();
                return Err(error);
            }
        };
        Ok(Rollout {
            path,
            file,
            run: run.clone(),
            tenant,
            seq,
            last_hash,
            poisoned: false,
        })
    }

    /// Scan to the tail, tolerating a single **torn trailing line** from a crash mid-append
    /// (code review: a partial last line must not make the whole run unresumable). Every
    /// newline-terminated line is chain-verified (tampering still fails); only an unterminated or
    /// unparseable FINAL line is treated as torn — the file is truncated back to before it.
    fn scan_tail(file: &mut File, tenant: &TenantId) -> Result<(Seq, String), RecordError> {
        file.seek(SeekFrom::Start(0))?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        let mut seq = Seq::ZERO;
        let mut last = ZERO_HASH.to_string();
        let mut saw_line = false;
        let mut good_len: usize = 0; // byte length of the verified, newline-terminated prefix
        let mut pos = 0usize;
        while pos < content.len() {
            // find the next newline
            let nl = content[pos..].iter().position(|&b| b == b'\n');
            let Some(rel) = nl else {
                // no trailing newline -> the last line is torn; drop it.
                break;
            };
            let line_end = pos + rel;
            let line = &content[pos..line_end];
            let text = std::str::from_utf8(line).map_err(|e| {
                RecordError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            if text.trim().is_empty() {
                pos = line_end + 1;
                good_len = pos;
                continue;
            }
            match serde_json::from_str::<ChainLine>(text) {
                Ok(cl) => {
                    ensure_tenant(tenant, &cl.tenant, cl.seq)?;
                    // verify the chain link
                    let computed = hash_line(&cl.prev, cl.seq, &cl.payload);
                    if computed != cl.hash || cl.prev != last {
                        return Err(RecordError::ChainBroken {
                            seq: cl.seq,
                            stored: cl.hash,
                            computed,
                        });
                    }
                    seq = Seq(cl.seq);
                    last = cl.hash;
                    saw_line = true;
                    pos = line_end + 1;
                    good_len = pos;
                }
                // A newline-terminated line that fails to parse in the MIDDLE is corruption, not
                // a torn tail; surface it. (Only an unterminated final line is "torn".)
                Err(e) => return Err(RecordError::Json(e)),
            }
        }
        // Truncate any torn trailing bytes so the next append starts clean.
        if good_len < content.len() {
            file.set_len(good_len as u64)?;
            file.sync_all()?;
        }
        // `append` ignores the cursor on supported platforms, but restoring it to the verified end
        // makes the intended state explicit and keeps the descriptor ready for any future non-
        // append write implementation.
        file.seek(SeekFrom::End(0))?;
        Ok((if saw_line { seq.next() } else { Seq::ZERO }, last))
    }

    /// Append an event. Durably `fsync`s before returning (ADR-008 write-ahead durability), and
    /// **only advances the in-memory chain state after durability succeeds** (code review: a
    /// failed write must not leave `last_hash`/`seq` pointing past a line that was never written,
    /// which would silently fork the chain). Once file I/O begins the writer is pessimistically
    /// poisoned; only a successful durability barrier clears it. An I/O error therefore requires
    /// close + reopen, where tail recovery establishes the authoritative chain head.
    pub fn append(&mut self, event: &Event) -> Result<Seq, RecordError> {
        if self.poisoned {
            return Err(RecordError::WriterPoisoned);
        }
        // Scrub known-secret shapes from tool output before it enters the durable record
        // (ADR-008 §1). The caller's live copy (the model context) is untouched.
        let mut event = redact::redact_event(event);
        // Stamp the authoritative seq into the payload before hashing so the on-disk record is
        // self-consistent going forward (the caller emits a placeholder seq; see `replay`). The
        // hash then covers the true seq. `replay` still overwrites from the chain line, so legacy
        // rollouts written before this fix remain correct.
        event.seq = self.seq;
        let event = &event;
        let payload = serde_json::to_value(event)?;
        let seq = self.seq;
        let hash = hash_line(&self.last_hash, seq.0, &payload);
        let cl = ChainLine {
            seq: seq.0,
            tenant: self.tenant.0.clone(),
            prev: self.last_hash.clone(),
            hash: hash.clone(),
            payload,
        };
        let mut line = serde_json::to_string(&cl)?;
        line.push('\n');
        // After this point an error is ambiguous: write(2) may have committed any prefix and an
        // fsync error may still follow a complete line. Fail-stop until a fresh scan recovers the
        // descriptor and chain head.
        self.poisoned = true;
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?; // durable BEFORE we advance state
        // Only now, after the line is on disk, advance the chain.
        self.last_hash = hash;
        self.seq = seq.next();
        self.poisoned = false;
        Ok(seq)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn run_id(&self) -> &RunId {
        &self.run
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl Drop for Rollout {
    fn drop(&mut self) {
        // OS locks are also released when `File` is dropped. Unlock explicitly so the ownership
        // rule is visible and testable as RAII, while still relying on descriptor close if this
        // best-effort call itself fails during teardown.
        let _ = self.file.unlock();
    }
}

/// Replay: read a rollout back as its event stream, verifying the hash chain as it goes.
/// This is promise (a)+(b): the recorded decisions and outputs replay exactly. A broken
/// chain is an error, not a warning — the record is the audit.
pub fn replay(path: &Path) -> Result<Vec<Event>, RecordError> {
    let content = std::fs::read_to_string(path)?;
    let mut events = Vec::new();
    let mut prev = ZERO_HASH.to_string();
    let mut tenant: Option<TenantId> = None;
    // A crash mid-append can leave a partial FINAL line (no trailing newline). Tolerate it — drop a
    // torn tail — so a crashed run stays replayable/resumable (code review: the strict read path
    // otherwise defeats the torn-tail tolerance scan_tail was hardened for on the append path).
    let mut lines: Vec<&str> = content.lines().collect();
    if !content.is_empty() && !content.ends_with('\n') {
        lines.pop();
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cl: ChainLine = serde_json::from_str(line)?;
        if let Some(expected) = &tenant {
            ensure_tenant(expected, &cl.tenant, cl.seq)?;
        } else {
            tenant = Some(TenantId(cl.tenant.clone()));
        }
        let computed = hash_line(&prev, cl.seq, &cl.payload);
        if computed != cl.hash {
            return Err(RecordError::ChainBroken {
                seq: cl.seq,
                stored: cl.hash,
                computed,
            });
        }
        if cl.prev != prev {
            return Err(RecordError::ChainBroken {
                seq: cl.seq,
                stored: cl.prev,
                computed: prev,
            });
        }
        prev = cl.hash;
        // The payload's own `seq` is a WRITE-TIME PLACEHOLDER — the kernel emits every event with
        // `Seq::ZERO` and `append` stamps the assigned seq only onto the chain line, not the embedded
        // payload. The authoritative total order is the chain-line seq (`cl.seq`), so overwrite the
        // deserialized event's seq with it. Without this, every replay consumer (`--fork`, `/fork`,
        // `/rewind`) saw seq 0 and branched at genesis, silently discarding the entire parent
        // transcript (review CRITICAL/HIGH). Handles legacy rollouts (payload seq 0) too.
        let mut event: Event = serde_json::from_value(cl.payload)?;
        event.seq = Seq(cl.seq);
        events.push(event);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{EventKind, Phase, TurnId};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "core-rec-{tag}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn ev(seq: u64) -> Event {
        Event {
            seq: Seq(seq),
            turn: TurnId(0),
            kind: EventKind::Phase {
                phase: Phase::Model,
            },
        }
    }

    #[test]
    fn append_then_replay_roundtrips_and_chain_verifies() {
        let dir = std::env::temp_dir().join(format!("core-rec-{}", std::process::id()));
        let run = RunId("t1".into());
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(0)).unwrap();
            r.append(&ev(1)).unwrap();
            r.append(&ev(2)).unwrap();
        }
        let path = dir.join("t1.jsonl");
        let back = replay(&path).unwrap();
        assert_eq!(back.len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hostile_run_ids_are_rejected_before_any_filesystem_mutation() {
        let root = test_dir("run-id-traversal");
        let runs = root.join("runs");
        let too_long = "x".repeat(MAX_RUN_ID_BYTES + 1);
        for id in [
            "",
            ".",
            "..",
            "../escape",
            "nested/escape",
            r"nested\escape",
            "/absolute",
            "C:\\escape",
            "line\nbreak",
            "CON",
            &too_long,
        ] {
            let error = Rollout::open(&runs, &RunId(id.into()), TenantId::default())
                .err()
                .expect("an unsafe run id must be rejected");
            assert!(
                matches!(error, RecordError::InvalidRunId { .. }),
                "{id:?} produced the wrong error: {error}"
            );
        }

        assert!(
            !runs.exists(),
            "validation must happen before create_dir_all"
        );
        assert!(
            !root.join("escape.jsonl").exists(),
            "a traversal id must never create a file outside runs_dir"
        );
    }

    #[test]
    fn existing_portable_unicode_run_names_remain_compatible() {
        let dir = test_dir("unicode-run-id");
        let run = RunId("legacy run-中文".into());
        {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            rollout.append(&ev(0)).unwrap();
        }
        assert_eq!(replay(&dir.join("legacy run-中文.jsonl")).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopening_an_existing_rollout_with_another_tenant_fails_closed() {
        let dir = test_dir("tenant-reopen");
        let run = RunId("tenant-boundary".into());
        let acme = TenantId("acme".into());
        {
            let mut rollout = Rollout::open(&dir, &run, acme.clone()).unwrap();
            rollout.append(&ev(0)).unwrap();
        }

        let error = Rollout::open(&dir, &run, TenantId("globex".into()))
            .err()
            .expect("a different tenant must not take over an existing run");
        assert!(matches!(
            error,
            RecordError::TenantMismatch {
                seq: 0,
                ref expected,
                ref found,
            } if expected == "globex" && found == "acme"
        ));

        // A failed cross-tenant open releases its lock and does not mutate the valid journal.
        {
            let mut reopened = Rollout::open(&dir, &run, acme).unwrap();
            assert_eq!(reopened.append(&ev(0)).unwrap(), Seq(1));
        }
        assert_eq!(replay(&dir.join("tenant-boundary.jsonl")).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_mixed_tenant_physical_chain_is_rejected_even_when_legacy_hashes_still_match() {
        let dir = test_dir("tenant-line-tamper");
        let run = RunId("mixed-tenant".into());
        {
            let mut rollout = Rollout::open(&dir, &run, TenantId("acme".into())).unwrap();
            rollout.append(&ev(0)).unwrap();
            rollout.append(&ev(0)).unwrap();
        }
        let path = dir.join("mixed-tenant.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<ChainLine> = raw
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        lines[1].tenant = "globex".into();
        let mut tampered = lines
            .iter()
            .map(|line| serde_json::to_string(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        tampered.push('\n');
        std::fs::write(&path, tampered).unwrap();

        let replay_error = replay(&path).expect_err("replay must reject a mixed-tenant chain");
        assert!(matches!(
            replay_error,
            RecordError::TenantMismatch { seq: 1, .. }
        ));
        let reopen_error = Rollout::open(&dir, &run, TenantId("acme".into()))
            .err()
            .expect("resume must reject a mixed-tenant chain");
        assert!(matches!(
            reopen_error,
            RecordError::TenantMismatch { seq: 1, .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_io_failure_poisons_writer_and_reopen_recovers() {
        let dir = test_dir("poison-recovery");
        let run = RunId("poisoned".into());
        let tenant = TenantId::default();
        let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
        rollout.append(&ev(0)).unwrap();
        let path = rollout.path().to_path_buf();

        // Inject a deterministic write failure without a production-only fault-injection seam:
        // replace the private descriptor with a read-only one. The first append reaches I/O and
        // poisons the object.
        rollout.file = File::open(&path).unwrap();
        let first_error = rollout
            .append(&ev(0))
            .expect_err("writing through a read-only descriptor must fail");
        assert!(matches!(first_error, RecordError::Io(_)));

        // Give the object a writable descriptor. It must still fail-stop instead of trusting its
        // pre-error in-memory hash head and continuing the journal.
        rollout.file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            rollout.append(&ev(0)),
            Err(RecordError::WriterPoisoned)
        ));
        drop(rollout);

        // Reopen scans the durable tail, clears the poison by constructing a fresh writer, and
        // resumes at the authoritative next sequence.
        {
            let mut recovered = Rollout::open(&dir, &run, tenant).unwrap();
            assert_eq!(recovered.append(&ev(0)).unwrap(), Seq(1));
        }
        assert_eq!(replay(&path).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Helper invoked as a separately spawned test process by
    /// `a_second_process_cannot_write_the_same_rollout`. In an ordinary test-suite invocation the
    /// environment variable is absent and this is a no-op.
    #[test]
    fn child_process_holds_rollout_writer_lock() {
        let Ok(dir) = std::env::var("CORE_RECORD_LOCK_TEST_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let run = RunId("locked-run".into());
        let _rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        std::fs::write(dir.join("child.ready"), b"ready").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !dir.join("child.release").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            dir.join("child.release").exists(),
            "parent did not release the child lock holder before the deadline"
        );
    }

    #[test]
    fn a_second_process_cannot_write_the_same_rollout_and_raii_releases_the_lock() {
        let dir = test_dir("process-lock");
        std::fs::create_dir_all(&dir).unwrap();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::child_process_holds_rollout_writer_lock")
            .arg("--nocapture")
            .env("CORE_RECORD_LOCK_TEST_DIR", &dir)
            .spawn()
            .unwrap();

        let ready = dir.join("child.ready");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("lock-holder child exited before acquiring the lock: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "lock-holder child did not become ready");

        let run = RunId("locked-run".into());
        let error = Rollout::open(&dir, &run, TenantId::default())
            .err()
            .expect("a concurrent writer must be rejected");
        assert!(
            matches!(
                error,
                RecordError::WriterBusy { ref path }
                    if path == &dir.join("locked-run.jsonl")
            ),
            "lock contention must be a typed, actionable WriterBusy error: {error}"
        );

        std::fs::write(dir.join("child.release"), b"release").unwrap();
        assert!(child.wait().unwrap().success());

        // The child-owned Rollout has been dropped. Its OS lock must be gone without any cleanup
        // API, and the next owner must resume the still-empty journal at seq zero.
        {
            let mut reopened = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            assert_eq!(reopened.append(&ev(0)).unwrap(), Seq::ZERO);
        }
        assert_eq!(replay(&dir.join("locked-run.jsonl")).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn different_rollouts_do_not_share_a_writer_lock() {
        let dir = test_dir("independent-locks");
        let mut first = Rollout::open(&dir, &RunId("first".into()), TenantId::default()).unwrap();
        let mut second = Rollout::open(&dir, &RunId("second".into()), TenantId::default()).unwrap();

        assert_eq!(first.append(&ev(0)).unwrap(), Seq::ZERO);
        assert_eq!(second.append(&ev(0)).unwrap(), Seq::ZERO);
        drop((first, second));
        assert_eq!(replay(&dir.join("first.jsonl")).unwrap().len(), 1);
        assert_eq!(replay(&dir.join("second.jsonl")).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_stamps_authoritative_chain_seq_not_the_payload_placeholder() {
        // Regression for the CRITICAL/HIGH fork+rewind bug: the KERNEL emits every event with a
        // placeholder payload seq (Seq::ZERO), relying on `append` to assign the real total order.
        // `replay` must return the AUTHORITATIVE chain seq, not the placeholder — else `--fork` /
        // `/rewind` (which read `events.last().seq`) branch at genesis and discard the parent
        // transcript. The old tests missed this because they passed distinct payload seqs; here we
        // emit kernel-style (all Seq::ZERO) so the placeholder can't accidentally look correct.
        let dir = std::env::temp_dir().join(format!("core-rec-seq-{}", std::process::id()));
        let run = RunId("tseq".into());
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(0)).unwrap(); // payload seq 0 (placeholder), chain seq 0
            r.append(&ev(0)).unwrap(); // payload seq 0 (placeholder), chain seq 1
            r.append(&ev(0)).unwrap(); // payload seq 0 (placeholder), chain seq 2
        }
        let path = dir.join("tseq.jsonl");
        let back = replay(&path).unwrap();
        let seqs: Vec<u64> = back.iter().map(|e| e.seq.0).collect();
        assert_eq!(
            seqs,
            vec![0, 1, 2],
            "replay must expose the true chain order, not [0,0,0]"
        );
        // The exact value `--fork` / `/rewind` consume: the tail seq must be the LAST line, not 0.
        assert_eq!(back.last().unwrap().seq, Seq(2));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secrets_in_tool_output_are_scrubbed_in_the_record() {
        use core_protocol::{Block, EventKind, Message, Role, ToolResult, Trust};
        let dir = std::env::temp_dir().join(format!("core-rec-redact-{}", std::process::id()));
        let run = RunId("t5".into());
        let leaked = "found key sk-\
ant-api03-SuperSecretTokenValue12345 in config";
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            let msg = Message {
                role: Role::User,
                content: vec![Block::ToolResult(ToolResult {
                    tool_use_id: "t".into(),
                    content: leaked.into(),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 0,
                })],
            };
            r.append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message { message: msg },
            })
            .unwrap();
        }
        let path = dir.join("t5.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("SuperSecretTokenValue"),
            "the secret must not be in the durable record"
        );
        assert!(raw.contains("[REDACTED"), "the secret must be masked");
        // and the chain still verifies (replay works over the redacted content)
        assert_eq!(replay(&path).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secrets_in_route_metadata_are_absent_from_the_durable_record() {
        let dir = test_dir("route-redact");
        let run = RunId("route-redact".into());
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::ModelSelected {
                        provider_id: "sk-\
ant-api03-SuperSecretProviderToken12345"
                            .into(),
                        model_id: "ghp_\
AbCdEf1234567890AbCdEf1234567890"
                            .into(),
                        catalog_digest: digest.into(),
                        capability_digest: "xoxb-SuperSecretCapabilityToken123456".into(),
                    },
                })
                .unwrap();
        }
        let path = dir.join("route-redact.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        for secret in [
            "SuperSecretProviderToken",
            "ghp_AbCdEf1234567890",
            "SuperSecretCapabilityToken",
        ] {
            assert!(!raw.contains(secret), "route record leaked {secret}");
        }
        assert!(raw.contains("[REDACTED"));
        assert!(raw.contains(digest), "valid provenance digest must survive");
        assert!(matches!(
            &replay(&path).unwrap()[0].kind,
            EventKind::ModelSelected { catalog_digest, .. } if catalog_digest == digest
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let dir = std::env::temp_dir().join(format!("core-rec-tamper-{}", std::process::id()));
        let run = RunId("t2".into());
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(0)).unwrap();
            r.append(&ev(1)).unwrap();
        }
        let path = dir.join("t2.jsonl");
        // Flip a byte in the middle line's payload.
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("model", "tools", 1);
        std::fs::write(&path, tampered).unwrap();
        assert!(matches!(
            replay(&path),
            Err(RecordError::ChainBroken { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_trailing_line_is_tolerated_on_resume() {
        // A crash mid-append leaves a partial final line (no newline). Resume must truncate it
        // and continue, not fail the whole run (code review).
        let dir = std::env::temp_dir().join(format!("core-rec-torn-{}", std::process::id()));
        let run = RunId("t4".into());
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(0)).unwrap();
            r.append(&ev(1)).unwrap();
        }
        let path = dir.join("t4.jsonl");
        // simulate a torn append: a partial line with no trailing newline
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(br#"{"seq":2,"tenant":"default","prev":"deadbeef","hash":"tor"#)
                .unwrap();
        }
        // reopen: must tolerate the torn tail, truncate it, and resume from seq 2
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(2)).unwrap();
        }
        // and the chain must now verify cleanly (torn line gone, new seq-2 line valid)
        assert_eq!(replay(&path).unwrap().len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resume_continues_the_chain() {
        let dir = std::env::temp_dir().join(format!("core-rec-resume-{}", std::process::id()));
        let run = RunId("t3".into());
        {
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(0)).unwrap();
        }
        {
            // reopen: should resume, not restart, the chain
            let mut r = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            r.append(&ev(1)).unwrap();
        }
        let path = dir.join("t3.jsonl");
        assert_eq!(replay(&path).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}

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

mod cache_io;

pub use checkpoint::{
    Snapshot, checkpoint, checkpoint_excluding_runtime_state, checkpoint_supported,
    rewind_workspace,
};
pub use session::{
    Provenance, ScopedEvent, SessionAncestryReceipt, SessionMeta, fork, list, load_forked,
    load_forked_scoped, meta, meta_with_pricing, most_recent, reindex, replay_run_timed,
};

/// Explicit policy for admitting records created before immutable tunables snapshots.
pub type LegacyTunablesPolicy = session::tunables::LegacyTunablesPolicy;
/// Result of comparing a record's immutable genesis identity with the current resolved set.
pub type TunablesCompatibility = session::tunables::TunablesCompatibility;
/// Typed fail-closed snapshot/placement/compatibility error.
pub type TunablesSnapshotError = session::tunables::TunablesSnapshotError;

/// Project an atomically accepted resolver result into its bounded durable identity.
pub fn snapshot_from_resolved(
    resolved: &core_tunables::ResolvedTunableSet,
) -> Result<core_protocol::RunGenesisTunablesSnapshot, TunablesSnapshotError> {
    session::tunables::snapshot_from_resolved(resolved)
}

/// Validate bounds, state invariants, and the recomputed canonical self-digest.
pub fn validate_tunables_snapshot(
    snapshot: &core_protocol::RunGenesisTunablesSnapshot,
) -> Result<(), TunablesSnapshotError> {
    session::tunables::validate_tunables_snapshot(snapshot)
}

/// Checked fork convenience retained at the crate root.
pub fn fork_with_tunables_snapshot(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    expected: &core_protocol::RunGenesisTunablesSnapshot,
    legacy: LegacyTunablesPolicy,
) -> Result<(RunId, TunablesCompatibility), RecordError> {
    session::fork_with_tunables_snapshot(runs_dir, parent, at, tenant, expected, legacy)
}

/// Resolver-typed convenience wrapper for [`fork_with_tunables_snapshot`].
pub fn fork_with_resolved_tunables(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    resolved: &core_tunables::ResolvedTunableSet,
    legacy: LegacyTunablesPolicy,
) -> Result<(RunId, TunablesCompatibility), RecordError> {
    session::fork_with_resolved_tunables(runs_dir, parent, at, tenant, resolved, legacy)
}

use core_protocol::{
    Event, EventKind, MAX_AGENT_DEFINITION_TAG_BYTES, MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES, RunId,
    Seq, TenantId,
};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const MAX_RUN_ID_BYTES: usize = 200;
pub(crate) const MAX_RECORD_LINE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_ROLLOUT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_ROLLOUT_EVENTS: usize = 100_000;
pub(crate) const MAX_ROLLOUT_PHYSICAL_LINES: usize = MAX_ROLLOUT_EVENTS + 1_024;

#[cfg(test)]
std::thread_local! {
    static AFTER_VISIT_METADATA_PREFLIGHT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// How hard one append pushes its line toward the platter.
///
/// `File::sync_data` is `fcntl(F_FULLFSYNC)` on Apple platforms — it asks the *device* to flush its
/// own volatile write cache, and profiling measured it at p50 4.09 ms against tens of microseconds
/// for a plain `fsync(2)` in the same directory. A turn appends 15 to 20 events, so paying the full
/// barrier on every one of them spends two orders of magnitude more than the turn boundary needs.
///
/// What the tiering does NOT change: a *process* crash (panic, SIGKILL, an OOM kill mid-turn) never
/// loses an appended line under either tier, because `write(2)` already handed the bytes to the
/// kernel's page cache and the kernel outlives the process. `Barrier::Line` additionally forces
/// them out to the device, so an OS panic does not lose them either.
///
/// What it DOES change, precisely: sudden power loss (or a device that lies about its cache) can
/// now lose the events appended since the last `Barrier::Turn`. That is the only weakened mode, and
/// the chain already tolerates it by construction — `scan_tail` truncates a torn trailing line and
/// resumes, and every surviving line is still chain-verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Barrier {
    /// Per-event: a plain `fsync(2)`. Kernel and device hold the bytes; the device's write cache
    /// may still be volatile.
    Line,
    /// Turn boundary: the platform's strongest flush (`F_FULLFSYNC` on Apple), which is what
    /// survives power loss.
    Turn,
}

/// Turn boundaries carry the full barrier. `TurnEnd` closes one turn's accounting and `Done` closes
/// the run; those are the points an operator can observe as "the turn happened", so those are the
/// points that must survive power loss, not every intermediate phase/tool line inside them.
fn barrier_for(kind: &EventKind) -> Barrier {
    match kind {
        EventKind::TurnEnd { .. } | EventKind::Done { .. } => Barrier::Turn,
        _ => Barrier::Line,
    }
}

/// A plain `fsync(2)`. std has no API for this on Apple platforms: both `sync_all` and `sync_data`
/// route through `F_FULLFSYNC` there, so the cheap tier has to call libc directly.
#[cfg(unix)]
fn sync_line(file: &File) -> std::io::Result<()> {
    // Fully qualified rather than a `use`: this file is a managed schema source whose import
    // fingerprint is pinned, and a platform fd accessor is not a schema change.
    let fd = <File as std::os::unix::io::AsRawFd>::as_raw_fd(file);
    loop {
        // SAFETY: `fd` is borrowed from `file`, which is alive for the whole call, and `fsync`
        // neither takes ownership of it nor reads caller memory.
        if unsafe { libc::fsync(fd) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(not(unix))]
fn sync_line(file: &File) -> std::io::Result<()> {
    file.sync_data()
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pricing evidence: {0}")]
    Pricing(#[from] core_obs::PricingError),
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
    /// Public protocol versions are enforced at the one durable append boundary. This prevents an
    /// embedder from pairing a V2-only nested value with a V1 top-level tag and producing a record
    /// that an older reader recognizes but cannot deserialize.
    #[error("invalid public event schema: {reason}")]
    InvalidEventSchema { reason: &'static str },
    /// Bound every physical JSONL record before parsing its nested payload. Typed protocol fields
    /// have their own cardinality caps; this outer bound prevents a hostile line from forcing an
    /// unbounded `serde_json::Value` allocation first.
    #[error("record line is {bytes} bytes, exceeding the {max}-byte limit")]
    RecordLineTooLarge { bytes: usize, max: usize },
    #[error("durable environment context is {bytes} bytes, exceeding the {max}-byte limit")]
    EnvironmentContextTooLarge { bytes: usize, max: usize },
    #[error("rollout is {bytes} bytes, exceeding the {max}-byte replay limit")]
    RolloutTooLarge { bytes: u64, max: u64 },
    #[error("rollout exceeds the {max}-event replay limit")]
    TooManyEvents { max: usize },
    #[error("rollout exceeds the {max}-physical-line scan limit")]
    TooManyRecordLines { max: usize },
    /// Sequence numbers are part of the durable total order, not caller-provided labels. A reader
    /// must reject gaps, duplicates, and wraparound before using a line as the next chain head.
    #[error("record sequence is not contiguous: expected {expected}, found {found}")]
    SequenceBroken { expected: u64, found: u64 },
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
    #[error(transparent)]
    TunablesSnapshot(#[from] TunablesSnapshotError),
}

/// One line of the rollout. `prev` chains to the previous line's `hash`; `hash` covers
/// (`prev`, `seq`, `payload`). The genesis line has `prev` = the zero hash.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChainLine {
    seq: u64,
    tenant: String,
    prev: String,
    hash: String,
    /// Microseconds since THIS writer opened the rollout (#102).
    ///
    /// # Why the line and not the payload
    ///
    /// `hash_line` covers `(prev, seq, payload)` and nothing else, so a sibling of `tenant` is
    /// outside the hash by construction: every byte of every already-written chain still verifies,
    /// and no migration re-hashes anything. It also keeps the determinism contract exactly where it
    /// was — live and replay still produce identical `payload` bytes; only the line as a whole is
    /// no longer byte-reproducible, which it never needed to be.
    ///
    /// # Why relative and monotonic
    ///
    /// Monotonic, so a stepped operator clock cannot make a duration go backwards. Relative to the
    /// writer, so this never becomes a second, disagreeing absolute authority beside
    /// `run_start.created_at`, which stays the one wall-clock anchor.
    ///
    /// # Reading it across a resume
    ///
    /// A resumed run opens a new writer, so its origin restarts and `ts_us` DROPS at the seam.
    /// That discontinuity is the segment marker and needs no extra field: a reader splits on it,
    /// times exactly within each segment, and reports the join between segments as unknown rather
    /// than inventing a number. `#[serde(default)]` means a pre-#102 rollout reads as segment
    /// origin zero, which `TimingSnapshot`-style consumers must treat as unknown, not as instant.
    ///
    /// `Option`, skipped when absent, for the same reason the #101/#103 fields are: a line written
    /// before this existed has no honest value, `0` already means "at the segment origin" and must
    /// stay distinguishable from "never measured", and an absent key keeps every frozen rollout
    /// re-serialising byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_us: Option<u64>,
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

/// Enforce the environment field's protocol bound at every durable read and write boundary.
/// Frontend setters are not sufficient: records can be produced by embedders, copied between
/// versions, or be independently hash-valid while carrying a hostile nested field.
pub(crate) fn validate_event_bounds(event: &Event) -> Result<(), RecordError> {
    let environment = match &event.kind {
        EventKind::RunStart { environment, .. } => environment.as_ref(),
        EventKind::ContextInjection { instructions, .. } => instructions
            .as_ref()
            .and_then(|instructions| instructions.environment.as_ref()),
        _ => None,
    };
    if let Some(environment) = environment {
        let bytes = environment.text.len();
        if bytes > MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES {
            return Err(RecordError::EnvironmentContextTooLarge {
                bytes,
                max: MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES,
            });
        }
    }
    if let EventKind::RunStart {
        agent_definition_tag: Some(tag),
        ..
    } = &event.kind
        && (tag.trim().is_empty()
            || tag.len() > MAX_AGENT_DEFINITION_TAG_BYTES
            || tag.chars().any(char::is_control)
            || crate::redact::scrub_route_identifier(tag) != *tag)
    {
        return Err(RecordError::InvalidEventSchema {
            reason: "agent_definition_tag must be bounded, non-blank, control-free, and credential-free",
        });
    }
    if let EventKind::TunablesSnapshot { snapshot, .. } = &event.kind {
        validate_tunables_snapshot(snapshot)?;
    }
    Ok(())
}

/// A tool completion MUST identify itself, and a successful one MUST name its admission (I-42).
///
/// The audit that produced this gate read 71 journals: 81 of 198 `tool_done` records carried no
/// `effect_id`, and 77 of those were *successful* executions — work that ran with no admission
/// event to correlate it to. The same payload carried no tool name either, so nothing in the
/// record said what had run. Both holes are closed at the dispatch sites; this is what keeps them
/// closed, because a silent reappearance of either is indistinguishable, from the record alone,
/// from a run that simply used no tools.
///
/// A missing `effect_id` stays legal for an error result and only for an error result: a refused,
/// gate-denied, deduplicated or deadline-cancelled call never reached an executor, so there was no
/// effect to admit and a synthesized identity would be a lie about an admission that never
/// happened.
///
/// This is deliberately a **write-only** gate, applied in [`Rollout::append`] rather than in
/// `validate_event_bounds`. Records already on disk predate the rule and must stay replayable;
/// rejecting them at read time would destroy exactly the evidence the audit was built from.
fn validate_terminal_identity(kind: &EventKind) -> Result<(), &'static str> {
    let EventKind::ToolDone {
        result,
        effect_id,
        tool,
    } = kind
    else {
        return Ok(());
    };
    if !tool.iter().any(|name| !name.is_empty()) {
        return Err("a tool_done must name the tool that produced it");
    }
    if effect_id.is_none() && !result.is_error {
        return Err(
            "a successful tool_done must carry the effect id of its admission event; only a call \
             that failed or was refused before dispatch may omit it",
        );
    }
    Ok(())
}

pub(crate) fn ensure_record_line_size(bytes: usize) -> Result<(), RecordError> {
    if bytes > MAX_RECORD_LINE_BYTES {
        Err(RecordError::RecordLineTooLarge {
            bytes,
            max: MAX_RECORD_LINE_BYTES,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_rollout_size(bytes: u64) -> Result<(), RecordError> {
    if bytes > MAX_ROLLOUT_BYTES {
        Err(RecordError::RolloutTooLarge {
            bytes,
            max: MAX_ROLLOUT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn admit_stream_bytes(total: &mut u64, bytes: usize) -> Result<(), RecordError> {
    *total = total
        .checked_add(bytes as u64)
        .ok_or(RecordError::RolloutTooLarge {
            bytes: u64::MAX,
            max: MAX_ROLLOUT_BYTES,
        })?;
    ensure_rollout_size(*total)
}

/// Read at most one physical JSONL line without ever allocating past the global line bound.
/// The boolean reports whether a newline terminated the bytes; an unterminated final line is a
/// tolerated torn append and is never passed to a parser.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
) -> Result<Option<(Vec<u8>, bool, usize)>, RecordError> {
    let mut bytes = Vec::new();
    let mut bounded = (&mut *reader).take((MAX_RECORD_LINE_BYTES + 1) as u64);
    let consumed = bounded.read_until(b'\n', &mut bytes)?;
    if consumed == 0 {
        return Ok(None);
    }
    ensure_record_line_size(consumed)?;
    let terminated = bytes.last() == Some(&b'\n');
    if terminated {
        bytes.pop();
    }
    Ok(Some((bytes, terminated, consumed)))
}

fn visit_record_lines_with_budget(
    path: &Path,
    total_bytes: &mut u64,
    total_physical_lines: &mut usize,
    mut visitor: impl FnMut(&str) -> Result<(), RecordError>,
) -> Result<(), RecordError> {
    let file = File::open(path)?;
    let declared_total =
        total_bytes
            .checked_add(file.metadata()?.len())
            .ok_or(RecordError::RolloutTooLarge {
                bytes: u64::MAX,
                max: MAX_ROLLOUT_BYTES,
            })?;
    ensure_rollout_size(declared_total)?;
    #[cfg(test)]
    AFTER_VISIT_METADATA_PREFLIGHT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
    let mut reader = BufReader::new(file);
    let mut events = 0usize;
    while let Some((bytes, terminated, consumed)) = read_bounded_line(&mut reader)? {
        // File length is only a preflight snapshot. Charge the bytes actually consumed as well so
        // a concurrent append cannot expand one replay from 64 MiB to 100k nearly-8-MiB lines.
        admit_stream_bytes(total_bytes, consumed)?;
        if !terminated {
            break;
        }
        *total_physical_lines = total_physical_lines.saturating_add(1);
        if *total_physical_lines > MAX_ROLLOUT_PHYSICAL_LINES {
            return Err(RecordError::TooManyRecordLines {
                max: MAX_ROLLOUT_PHYSICAL_LINES,
            });
        }
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            RecordError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        if !text.trim().is_empty() {
            events = events.saturating_add(1);
            if events > MAX_ROLLOUT_EVENTS {
                return Err(RecordError::TooManyEvents {
                    max: MAX_ROLLOUT_EVENTS,
                });
            }
        }
        visitor(text)?;
    }
    Ok(())
}

pub(crate) fn visit_record_lines(
    path: &Path,
    visitor: impl FnMut(&str) -> Result<(), RecordError>,
) -> Result<(), RecordError> {
    let mut total_bytes = 0;
    let mut total_physical_lines = 0;
    visit_record_lines_with_budget(path, &mut total_bytes, &mut total_physical_lines, visitor)
}

pub(crate) fn visit_record_lines_charged(
    path: &Path,
    total_bytes: &mut u64,
    total_physical_lines: &mut usize,
    visitor: impl FnMut(&str) -> Result<(), RecordError>,
) -> Result<(), RecordError> {
    visit_record_lines_with_budget(path, total_bytes, total_physical_lines, visitor)
}

/// The `<repo>/.core` state root a runs directory lives under, if any. A runs dir configured
/// somewhere else entirely (an absolute `--runs-dir` outside the project) has no state root here
/// and is left alone: this only ever speaks for Core's own per-repository directory.
fn state_root_of(runs_dir: &Path) -> Option<PathBuf> {
    let mut walked = PathBuf::new();
    let mut root = None;
    for component in runs_dir.components() {
        walked.push(component);
        if root.is_none()
            && let Component::Normal(name) = component
            && name.to_str().is_some_and(core_protocol::home::is_home_dir)
        {
            // The OUTERMOST `.core` is the one sitting in the repository, which is the directory
            // git would otherwise stage.
            root = Some(walked.clone());
        }
    }
    root
}

/// `create_dir_all` for a runs directory, claiming the git exclusion the first time Core's
/// per-repository state root comes into existence.
///
/// Everything Core keeps per repository — run journals, memory, skills — lands under `<repo>/.core`.
/// Nothing used to exclude it, so the first `git add -A` after a run committed the session
/// transcript into the user's own history. This is the one place that knows the directory is new,
/// so it is the one place that can claim the exclusion exactly once.
///
/// Every path that can bring the state directory into being goes through here — a run opening its
/// rollout, a `reindex`, and the session-index lock — because whichever of them happens to run
/// first in a fresh repository is the one that has to make the claim.
pub(crate) fn create_state_dir(dir: &Path) -> std::io::Result<()> {
    let state_root = state_root_of(dir);
    let unclaimed = state_root.as_deref().is_some_and(|root| !root.exists());
    std::fs::create_dir_all(dir)?;
    if let Some(root) = state_root.filter(|_| unclaimed) {
        exclude_state_dir_from_git(&root);
    }
    Ok(())
}

/// Exclude the per-repository state directory in `.git/info/exclude` for the repository that owns
/// `state_root`.
///
/// `.git/info/exclude` and not `.gitignore`: the ignore file is the user's, it is tracked, and a
/// tool that edits it puts its own housekeeping into someone else's commit. `info/exclude` is
/// per-clone, untracked, and exactly the place for "this working copy has a tool directory in it".
///
/// The pattern is two lines, and the second one is load-bearing:
///
/// ```text
/// /.core/**
/// !/.core/**/
/// ```
///
/// The obvious `/.core/` would ignore the same files, but it also makes `.core` — and under
/// `/.core/**` alone, `.core/runs` — an *ignored directory entry*. `git add` treats a pathspec that
/// names an ignored entry as a fatal error, not a no-op, and the checkpoint stages with
/// `add -A -- . :(top,literal,exclude)<runtime state dir>`, which names it exactly. Either
/// directory form would therefore have turned every checkpoint in the repository into a hard
/// failure. Re-including the directories leaves them ordinary and empty in git's eyes while every
/// file beneath them stays ignored, which is the whole of what this needs to do.
///
/// Entirely best effort. A repository we cannot write to is not a reason to fail a run — the worst
/// case is the status quo, where the directory shows up as untracked.
fn exclude_state_dir_from_git(state_root: &Path) {
    let Some(repo_root) = state_root.parent() else {
        return;
    };
    let git_dir = repo_root.join(".git");
    // Only a real `.git` DIRECTORY is claimed. A `.git` FILE is a worktree or submodule pointer
    // whose exclude file lives behind an indirection; guessing at it would mean writing into
    // metadata we did not resolve.
    if !git_dir.is_dir() {
        return;
    }
    let home = core_protocol::home::HOME_DIR;
    let files = format!("/{home}/**");
    let keep_dirs = format!("!/{home}/**/");
    let already_excluded = |text: &str| {
        text.lines().any(|line| {
            let line = line.trim();
            line == files
                || line == home
                || line == format!("{home}/")
                || line == format!("/{home}/")
                || line == format!("{home}/**")
        })
    };
    // A project that already ignores the directory (this one does) needs no second declaration —
    // and could not be helped by one anyway, since `.gitignore` outranks `info/exclude`.
    if std::fs::read_to_string(repo_root.join(".gitignore"))
        .is_ok_and(|text| already_excluded(&text))
    {
        return;
    }
    let info_dir = git_dir.join("info");
    let exclude = info_dir.join("exclude");
    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    if already_excluded(&existing) {
        return;
    }
    if std::fs::create_dir_all(&info_dir).is_err() {
        return;
    }
    let mut addition = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        addition.push('\n');
    }
    addition.push_str("# Core Code per-repository state (run records, memory, skills).\n");
    addition.push_str(&files);
    addition.push('\n');
    addition.push_str(&keep_dirs);
    addition.push('\n');
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&exclude)
        .and_then(|mut file| file.write_all(addition.as_bytes()));
}

enum SessionProjectionState {
    /// No projection has been loaded for this writer. The first durable `TurnStart` (or an
    /// explicit refresh) performs the one bounded replay needed to initialize it.
    Uninitialized,
    /// Exact projection of every durable event through this writer's current tail receipt.
    Ready(Box<session::SessionProjection>),
    /// Initialization or observation failed. Do not retry a full replay on every later turn;
    /// closing and reopening the rollout gives a fresh writer one bounded recovery attempt.
    Disabled,
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
    event_count: usize,
    physical_line_count: usize,
    /// Exact newline-terminated bytes verified at open or durably written by this descriptor.
    /// Cache coverage is pinned to this cursor, never promoted from a later metadata() sample.
    durable_bytes: u64,
    last_hash: String,
    poisoned: bool,
    /// Record-owned so every public append path observes the actual redacted, stamped event only
    /// after fsync. A caller cannot bypass the session projection by appending directly.
    session_projection: SessionProjectionState,
    /// This writer's monotonic origin, set when the descriptor opened. Every `ts_us` is measured
    /// from here, which is what makes a segment internally exact without claiming to be joinable
    /// to a previous process's segment.
    opened_at: std::time::Instant,
    /// Barrier tiers this descriptor actually took, counted per tier. The tiering is a *cost*
    /// property, and timing a disk is not a test, so the counter is how a regression test pins it.
    #[cfg(test)]
    barriers_taken: (u64, u64),
}

impl Rollout {
    /// True only before the first durable event has been appended. Frontends use this narrow
    /// predicate to configure a fresh agent's genesis policy; runtime policy changes must use the
    /// kernel's write-ahead transition APIs instead.
    pub fn is_empty(&self) -> bool {
        self.seq == Seq::ZERO && self.last_hash == ZERO_HASH
    }

    /// Sequence that will be assigned to the next durable event. Checkpoint producers bind a
    /// workspace snapshot to this exact position before appending its `Checkpoint` event.
    pub fn next_sequence(&self) -> Seq {
        self.seq
    }

    /// Open (creating) the rollout for a run under `dir`. If the file exists, resume the
    /// chain from its tail (recoverable, invariant #2). The exclusive writer lock is acquired
    /// before tail recovery, so a second process can neither race the scan nor interleave appends.
    pub fn open(dir: &Path, run: &RunId, tenant: TenantId) -> Result<Self, RecordError> {
        Self::open_with_create(dir, run, tenant, true)
    }

    /// Open an existing rollout without creating an empty record when the requested run is absent.
    /// Resume frontends use this before replay so the writer lock covers route/message recovery as
    /// well as every later append, closing the read-before-lock race with another process.
    /// This legacy-compatible entry point validates any recorded snapshot internally but does not
    /// compare it with a current resolver result. A frontend that will execute resumed work must
    /// use [`Self::open_existing_with_resolved_tunables`] (or the explicitly snapshot-checked form).
    pub fn open_existing(dir: &Path, run: &RunId, tenant: TenantId) -> Result<Self, RecordError> {
        Self::open_with_create(dir, run, tenant, false)
    }

    /// Open an existing rollout and prove that its immutable genesis snapshot is exactly the
    /// supplied atomic resolver result. Legacy admission is never implicit: the caller must choose
    /// a [`LegacyTunablesPolicy`] and receives the weaker result as a distinct compatibility state.
    pub fn open_existing_with_tunables_snapshot(
        dir: &Path,
        run: &RunId,
        tenant: TenantId,
        expected: &core_protocol::RunGenesisTunablesSnapshot,
        legacy: LegacyTunablesPolicy,
    ) -> Result<(Self, TunablesCompatibility), RecordError> {
        let rollout = Self::open_existing(dir, run, tenant)?;
        // `open_existing` already performed the mandatory bounded tail scan while acquiring the
        // writer lock. Its schema-frozen return shape cannot expose a new genesis projection, so
        // compare through one bounded replay under that same lock rather than duplicating the
        // durability scanner and letting the two implementations drift.
        let events = replay(rollout.path())?;
        let recorded = session::tunables::snapshot_from_events(&events)?;
        let compatibility =
            session::tunables::check_compatibility(recorded.as_ref(), expected, legacy)?;
        Ok((rollout, compatibility))
    }

    /// Resolver-typed convenience wrapper for [`Self::open_existing_with_tunables_snapshot`].
    pub fn open_existing_with_resolved_tunables(
        dir: &Path,
        run: &RunId,
        tenant: TenantId,
        resolved: &core_tunables::ResolvedTunableSet,
        legacy: LegacyTunablesPolicy,
    ) -> Result<(Self, TunablesCompatibility), RecordError> {
        let expected = snapshot_from_resolved(resolved)?;
        Self::open_existing_with_tunables_snapshot(dir, run, tenant, &expected, legacy)
    }

    /// Durably append a fresh root `RunStart` and its immutable resolved-set companion without an
    /// opportunity for another event to interleave. Success means both lines passed their fsync
    /// barriers. A crash or I/O error between them leaves an unpinned record that every checked
    /// operation rejects under [`LegacyTunablesPolicy::RejectUnpinned`]; no migration is invented.
    pub fn append_fresh_genesis_with_tunables(
        &mut self,
        run_start: &Event,
        resolved: &core_tunables::ResolvedTunableSet,
    ) -> Result<(Seq, Seq), RecordError> {
        if !matches!(
            &run_start.kind,
            EventKind::RunStart {
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                ..
            }
        ) {
            return Err(TunablesSnapshotError::GenesisOrder {
                reason: "fresh tunables genesis requires a root run_start",
            }
            .into());
        }
        let snapshot = snapshot_from_resolved(resolved)?;
        self.append_genesis_snapshot(run_start, snapshot, None)
    }

    pub(crate) fn append_genesis_snapshot(
        &mut self,
        run_start: &Event,
        snapshot: core_protocol::RunGenesisTunablesSnapshot,
        inherited_from: Option<core_protocol::RunGenesisTunablesInheritance>,
    ) -> Result<(Seq, Seq), RecordError> {
        if !self.is_empty() || !matches!(&run_start.kind, EventKind::RunStart { .. }) {
            return Err(TunablesSnapshotError::GenesisOrder {
                reason: "genesis append requires an empty rollout and run_start",
            }
            .into());
        }
        validate_tunables_snapshot(&snapshot)?;
        let snapshot_event = Event {
            // `append` owns the authoritative physical sequence and stamps this placeholder.
            seq: Seq::ZERO,
            turn: run_start.turn,
            kind: EventKind::TunablesSnapshot {
                version: core_protocol::RunGenesisTunablesVersion::V1,
                snapshot,
                inherited_from,
            },
        };
        let mut genesis = session::tunables::GenesisTunablesState::default();
        genesis.observe(0, &run_start.kind)?;
        genesis.observe(1, &snapshot_event.kind)?;
        let start_seq = self.append(run_start)?;
        let snapshot_seq = self.append(&snapshot_event)?;
        Ok((start_seq, snapshot_seq))
    }

    fn open_with_create(
        dir: &Path,
        run: &RunId,
        tenant: TenantId,
        create: bool,
    ) -> Result<Self, RecordError> {
        let _ = validated_run_path(dir, run, ".jsonl")?;
        if create {
            create_state_dir(dir)?;
        }
        let dir = dir.canonicalize()?;
        let path = validated_run_path(&dir, run, ".jsonl")?;
        let mut file = OpenOptions::new()
            .create(create)
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
        let (seq, event_count, physical_line_count, last_hash) =
            match Self::scan_tail(&mut file, &tenant) {
                Ok(tail) => tail,
                Err(error) => {
                    // Make the early-return release explicit. Dropping `file` also releases an OS file
                    // lock, but this keeps the RAII ownership transition obvious at the error edge.
                    let _ = file.unlock();
                    return Err(error);
                }
            };
        let durable_bytes = file.metadata()?.len();
        Ok(Rollout {
            path,
            file,
            run: run.clone(),
            tenant,
            seq,
            event_count,
            physical_line_count,
            durable_bytes,
            last_hash,
            poisoned: false,
            session_projection: SessionProjectionState::Uninitialized,
            // The segment origin. A resumed run reaches here again in a new process, which is
            // precisely why `ts_us` restarts and why the reader treats that drop as a seam.
            opened_at: std::time::Instant::now(),
            #[cfg(test)]
            barriers_taken: (0, 0),
        })
    }

    /// Scan to the tail, tolerating a single **torn trailing line** from a crash mid-append
    /// (code review: a partial last line must not make the whole run unresumable). Every
    /// newline-terminated line is chain-verified (tampering still fails); only an unterminated
    /// FINAL line is treated as torn — the file is truncated back to before it.
    fn scan_tail(
        file: &mut File,
        tenant: &TenantId,
    ) -> Result<(Seq, usize, usize, String), RecordError> {
        file.seek(SeekFrom::Start(0))?;
        let mut next_seq = Seq::ZERO;
        let mut last = ZERO_HASH.to_string();
        let mut event_count = 0usize;
        let mut physical_line_count = 0usize;
        let mut good_len = 0u64; // byte length of the verified, newline-terminated prefix
        let mut total_bytes = 0u64;
        let original_len = file.metadata()?.len();
        ensure_rollout_size(original_len)?;
        let mut reader = BufReader::new(&mut *file);
        while let Some((line, terminated, consumed)) = read_bounded_line(&mut reader)? {
            admit_stream_bytes(&mut total_bytes, consumed)?;
            if !terminated {
                break;
            }
            physical_line_count = physical_line_count.saturating_add(1);
            if physical_line_count > MAX_ROLLOUT_PHYSICAL_LINES {
                return Err(RecordError::TooManyRecordLines {
                    max: MAX_ROLLOUT_PHYSICAL_LINES,
                });
            }
            let text = std::str::from_utf8(&line).map_err(|error| {
                RecordError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?;
            if text.trim().is_empty() {
                good_len = good_len.saturating_add(consumed as u64);
                continue;
            }
            event_count = event_count.saturating_add(1);
            if event_count > MAX_ROLLOUT_EVENTS {
                return Err(RecordError::TooManyEvents {
                    max: MAX_ROLLOUT_EVENTS,
                });
            }
            match serde_json::from_str::<ChainLine>(text) {
                Ok(cl) => {
                    if cl.seq != next_seq.0 {
                        return Err(RecordError::SequenceBroken {
                            expected: next_seq.0,
                            found: cl.seq,
                        });
                    }
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
                    let event: Event = serde_json::from_value(cl.payload)?;
                    validate_event_bounds(&event)?;
                    last = cl.hash;
                    next_seq = next_seq.next();
                    good_len = good_len.saturating_add(consumed as u64);
                }
                // A newline-terminated line that fails to parse in the MIDDLE is corruption, not
                // a torn tail; surface it. (Only an unterminated final line is "torn".)
                Err(e) => return Err(RecordError::Json(e)),
            }
        }
        drop(reader);
        // Truncate any torn trailing bytes so the next append starts clean.
        let current_len = file.metadata()?.len();
        ensure_rollout_size(current_len)?;
        if good_len < current_len {
            file.set_len(good_len)?;
            file.sync_all()?;
        }
        // `append` ignores the cursor on supported platforms, but restoring it to the verified end
        // makes the intended state explicit and keeps the descriptor ready for any future non-
        // append write implementation.
        file.seek(SeekFrom::End(0))?;
        Ok((next_seq, event_count, physical_line_count, last))
    }

    /// Append an event. Durably `fsync`s before returning (ADR-008 write-ahead durability) at the
    /// tier [`barrier_for`] assigns — a plain `fsync(2)` inside a turn, the platform's full barrier
    /// at the turn boundary — and
    /// **only advances the in-memory chain state after durability succeeds** (code review: a
    /// failed write must not leave `last_hash`/`seq` pointing past a line that was never written,
    /// which would silently fork the chain). Once file I/O begins the writer is pessimistically
    /// poisoned; only a successful durability barrier clears it. An I/O error therefore requires
    /// close + reopen, where tail recovery establishes the authoritative chain head.
    pub fn append(&mut self, event: &Event) -> Result<Seq, RecordError> {
        if self.poisoned {
            return Err(RecordError::WriterPoisoned);
        }
        if self.event_count >= MAX_ROLLOUT_EVENTS {
            return Err(RecordError::TooManyEvents {
                max: MAX_ROLLOUT_EVENTS,
            });
        }
        if self.physical_line_count >= MAX_ROLLOUT_PHYSICAL_LINES {
            return Err(RecordError::TooManyRecordLines {
                max: MAX_ROLLOUT_PHYSICAL_LINES,
            });
        }
        event
            .kind
            .validate_compatibility_tag()
            .map_err(|reason| RecordError::InvalidEventSchema { reason })?;
        validate_terminal_identity(&event.kind)
            .map_err(|reason| RecordError::InvalidEventSchema { reason })?;
        validate_event_bounds(event)?;
        // Scrub known-secret shapes from tool output before it enters the durable record
        // (ADR-008 §1). The caller's live copy (the model context) is untouched.
        let mut event = redact::redact_event(event);
        validate_event_bounds(&event)?;
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
            // Read AFTER hashing and BEFORE the write, so the stamp is as close to the durable
            // write as the sequence allows without being inside it. It is deliberately not part of
            // `hash`: see `ChainLine::ts_us`.
            ts_us: Some(u64::try_from(self.opened_at.elapsed().as_micros()).unwrap_or(u64::MAX)),
            payload,
        };
        let mut line = serde_json::to_string(&cl)?;
        line.push('\n');
        ensure_record_line_size(line.len())?;
        let current_bytes = self.file.metadata()?.len();
        if current_bytes != self.durable_bytes {
            self.poisoned = true;
            return Err(RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "rollout length changed outside the active writer",
            )));
        }
        let next_bytes =
            current_bytes
                .checked_add(line.len() as u64)
                .ok_or(RecordError::RolloutTooLarge {
                    bytes: u64::MAX,
                    max: MAX_ROLLOUT_BYTES,
                })?;
        ensure_rollout_size(next_bytes)?;
        // After this point an error is ambiguous: write(2) may have committed any prefix and an
        // fsync error may still follow a complete line. Fail-stop until a fresh scan recovers the
        // descriptor and chain head.
        self.poisoned = true;
        self.file.write_all(line.as_bytes())?;
        // Durable BEFORE we advance state, at the tier this event's position earns (see `Barrier`).
        let barrier = barrier_for(&event.kind);
        match barrier {
            Barrier::Line => sync_line(&self.file)?,
            Barrier::Turn => self.file.sync_data()?,
        }
        #[cfg(test)]
        self.observe_barrier(barrier);
        // Only now, after the line is on disk, advance the chain.
        self.last_hash = hash.clone();
        self.seq = seq.next();
        self.event_count = self.event_count.saturating_add(1);
        self.physical_line_count = self.physical_line_count.saturating_add(1);
        self.durable_bytes = next_bytes;
        self.poisoned = false;
        if let SessionProjectionState::Ready(projection) = &mut self.session_projection
            && projection.observe_committed(event, seq, &hash).is_err()
        {
            self.session_projection = SessionProjectionState::Disabled;
        }
        if matches!(&event.kind, EventKind::TurnStart) {
            // Loading after this append means the initial replay already contains this exact
            // redacted, seq-stamped line. Do not observe it a second time.
            let _ = self.ensure_session_projection();
        }
        if matches!(
            &event.kind,
            EventKind::TurnEnd { .. } | EventKind::Done { .. }
        ) {
            // Cache writes are rebuildable and must never turn a successful authoritative append
            // into a reported failure. Explicit refresh callers can inspect the error if needed.
            let _ = self.refresh_session_cache();
        }
        Ok(seq)
    }

    /// Refresh the rebuildable session sidecars from the record-owned incremental projection.
    /// The first call performs one bounded verified replay; later calls are O(1) in rollout age.
    pub fn refresh_session_cache(&mut self) -> Result<bool, RecordError> {
        if !self.ensure_session_projection()? {
            return Ok(false);
        }
        let SessionProjectionState::Ready(projection) = &mut self.session_projection else {
            unreachable!("a successful projection initialization must be ready");
        };
        projection.persist_at(self.durable_bytes)
    }

    fn ensure_session_projection(&mut self) -> Result<bool, RecordError> {
        match self.session_projection {
            SessionProjectionState::Ready(_) => return Ok(true),
            SessionProjectionState::Disabled => return Ok(false),
            SessionProjectionState::Uninitialized => {}
        }
        let runs_dir = self.path.parent().ok_or_else(|| {
            RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rollout path has no runs directory",
            ))
        })?;
        match session::SessionProjection::load(runs_dir, &self.run) {
            Ok(projection) => {
                self.session_projection = SessionProjectionState::Ready(Box::new(projection));
                Ok(true)
            }
            Err(error) => {
                self.session_projection = SessionProjectionState::Disabled;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn observe_barrier(&mut self, barrier: Barrier) {
        match barrier {
            Barrier::Line => self.barriers_taken.0 = self.barriers_taken.0.saturating_add(1),
            Barrier::Turn => self.barriers_taken.1 = self.barriers_taken.1.saturating_add(1),
        }
    }

    /// `(cheap fsync appends, full F_FULLFSYNC barriers)` taken by this descriptor.
    #[cfg(test)]
    pub(crate) fn barriers_taken(&self) -> (u64, u64) {
        self.barriers_taken
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
/// Snapshot self-integrity is validated, but authoritative physical placement and current resolved
/// values are checked only by [`replay_with_resolved_tunables`].
/// One replayed event together with the segment offset its chain line carried (#102).
///
/// `ts_us` is `None` for a line written before the field existed. A consumer MUST treat that as
/// unknown rather than as the segment origin; the whole point of the `Option` is that a timeline
/// reader cannot silently turn a missing measurement into an instantaneous one.
#[derive(Debug, Clone)]
pub struct TimedEvent {
    pub ts_us: Option<u64>,
    pub event: Event,
}

/// Replay, keeping each line's segment offset.
///
/// Identical verification to [`replay`] -- same chain check, same tenant check, same torn-tail
/// tolerance, same authoritative-seq overwrite -- so a timeline can never be read from bytes the
/// audit path would have rejected. It is a separate entry point rather than a change to `replay`
/// because every existing caller wants the event stream alone and should not be made to thread a
/// timing concern it does not use.
pub fn replay_timed(path: &Path) -> Result<Vec<TimedEvent>, RecordError> {
    let mut events = Vec::new();
    let mut prev = ZERO_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut tenant: Option<TenantId> = None;
    visit_record_lines(path, |line| {
        if line.trim().is_empty() {
            return Ok(());
        }
        let cl: ChainLine = serde_json::from_str(line)?;
        if cl.seq != expected_seq {
            return Err(RecordError::SequenceBroken {
                expected: expected_seq,
                found: cl.seq,
            });
        }
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
                computed: prev.clone(),
            });
        }
        prev = cl.hash;
        expected_seq = expected_seq.saturating_add(1);
        let ts_us = cl.ts_us;
        let mut event: Event = serde_json::from_value(cl.payload)?;
        validate_event_bounds(&event)?;
        event.seq = Seq(cl.seq);
        events.push(TimedEvent { ts_us, event });
        Ok(())
    })?;
    Ok(events)
}

pub fn replay(path: &Path) -> Result<Vec<Event>, RecordError> {
    let mut events = Vec::new();
    let mut prev = ZERO_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut tenant: Option<TenantId> = None;
    // A crash mid-append can leave a partial FINAL line (no trailing newline). Tolerate it — drop a
    // torn tail — so a crashed run stays replayable/resumable (code review: the strict read path
    // otherwise defeats the torn-tail tolerance scan_tail was hardened for on the append path).
    visit_record_lines(path, |line| {
        if line.trim().is_empty() {
            return Ok(());
        }
        let cl: ChainLine = serde_json::from_str(line)?;
        if cl.seq != expected_seq {
            return Err(RecordError::SequenceBroken {
                expected: expected_seq,
                found: cl.seq,
            });
        }
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
                computed: prev.clone(),
            });
        }
        prev = cl.hash;
        expected_seq = expected_seq.saturating_add(1);
        // The payload's own `seq` is a WRITE-TIME PLACEHOLDER — the kernel emits every event with
        // `Seq::ZERO` and `append` stamps the assigned seq only onto the chain line, not the embedded
        // payload. The authoritative total order is the chain-line seq (`cl.seq`), so overwrite the
        // deserialized event's seq with it. Without this, every replay consumer (`--fork`, `/fork`,
        // `/rewind`) saw seq 0 and branched at genesis, silently discarding the entire parent
        // transcript (review CRITICAL/HIGH). Handles legacy rollouts (payload seq 0) too.
        let mut event: Event = serde_json::from_value(cl.payload)?;
        validate_event_bounds(&event)?;
        event.seq = Seq(cl.seq);
        events.push(event);
        Ok(())
    })?;
    Ok(events)
}

/// Hash-verified replay plus an exact immutable tunables compatibility check.
///
/// This deliberately has a distinct name from [`replay`]; callers that need parameter identity
/// must opt into the checked contract and cannot accidentally treat ordinary legacy replay as an
/// exact match.
pub fn replay_with_tunables_snapshot(
    path: &Path,
    expected: &core_protocol::RunGenesisTunablesSnapshot,
    legacy: LegacyTunablesPolicy,
) -> Result<(Vec<Event>, TunablesCompatibility), RecordError> {
    let events = replay(path)?;
    let recorded = session::tunables::snapshot_from_events(&events)?;
    let compatibility =
        session::tunables::check_compatibility(recorded.as_ref(), expected, legacy)?;
    Ok((events, compatibility))
}

/// Resolver-typed convenience wrapper for [`replay_with_tunables_snapshot`].
pub fn replay_with_resolved_tunables(
    path: &Path,
    resolved: &core_tunables::ResolvedTunableSet,
    legacy: LegacyTunablesPolicy,
) -> Result<(Vec<Event>, TunablesCompatibility), RecordError> {
    let expected = snapshot_from_resolved(resolved)?;
    replay_with_tunables_snapshot(path, &expected, legacy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{
        Block, DurableEnvironmentContext, DurableInstructionContext, Effort, EventKind, Message,
        Phase, ProviderState, ProviderStateFormat, Role, Trust, TurnId,
    };
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
    fn durable_environment_bound_is_enforced_on_append_replay_open_and_fork() {
        fn run_start_environment(text: String) -> Event {
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: "/workspace".into(),
                    model: "model-a".into(),
                    effort: Effort::Medium,
                    created_at: 1,
                    environment: Some(DurableEnvironmentContext {
                        text,
                        trust: Trust::Workspace,
                    }),
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            }
        }

        fn injection_environment(text: String) -> Event {
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::ContextInjection {
                    text: String::new(),
                    trust: Trust::Trusted,
                    instructions: Some(DurableInstructionContext {
                        text: String::new(),
                        trust: Trust::Trusted,
                        environment: Some(DurableEnvironmentContext {
                            text,
                            trust: Trust::Workspace,
                        }),
                    }),
                },
            }
        }

        fn write_hash_valid(path: &Path, events: Vec<Event>) {
            let mut previous = ZERO_HASH.to_owned();
            let mut physical = String::new();
            for (index, mut event) in events.into_iter().enumerate() {
                event.seq = Seq(index as u64);
                let payload = serde_json::to_value(event).unwrap();
                let hash = hash_line(&previous, index as u64, &payload);
                let line = ChainLine {
                    seq: index as u64,
                    tenant: TenantId::default().0,
                    prev: previous,
                    hash: hash.clone(),
                    payload,
                    // Hand-built test line: no writer, so no segment origin to measure from.
                    ts_us: None,
                };
                physical.push_str(&serde_json::to_string(&line).unwrap());
                physical.push('\n');
                previous = hash;
            }
            std::fs::write(path, physical).unwrap();
        }

        let exact_dir = test_dir("environment-exact-bound");
        let exact_run = RunId("environment-exact-bound".into());
        let mut rollout = Rollout::open(&exact_dir, &exact_run, TenantId::default()).unwrap();
        rollout
            .append(&run_start_environment(
                "x".repeat(MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES),
            ))
            .unwrap();
        let exact_path = rollout.path().to_path_buf();
        let bytes_before_rejection = std::fs::metadata(&exact_path).unwrap().len();
        let oversized =
            injection_environment("y".repeat(MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES + 1));
        assert!(matches!(
            rollout.append(&oversized),
            Err(RecordError::EnvironmentContextTooLarge { bytes, max })
                if bytes == MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES + 1
                    && max == MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES
        ));
        assert_eq!(
            std::fs::metadata(&exact_path).unwrap().len(),
            bytes_before_rejection,
            "oversized nested context must fail before record mutation"
        );
        rollout.append(&ev(0)).unwrap();
        drop(rollout);
        assert_eq!(replay(&exact_path).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(exact_dir);

        for (label, events, at) in [
            (
                "oversized-genesis",
                vec![run_start_environment(
                    "g".repeat(MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES + 1),
                )],
                Seq::ZERO,
            ),
            (
                "oversized-injection",
                vec![
                    ev(0),
                    injection_environment("i".repeat(MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES + 1)),
                ],
                Seq(1),
            ),
        ] {
            let dir = test_dir(label);
            std::fs::create_dir_all(&dir).unwrap();
            let run = RunId(label.into());
            let path = dir.join(format!("{run}.jsonl"));
            write_hash_valid(&path, events);

            assert!(matches!(
                replay(&path),
                Err(RecordError::EnvironmentContextTooLarge { .. })
            ));
            assert!(matches!(
                Rollout::open(&dir, &run, TenantId::default()),
                Err(RecordError::EnvironmentContextTooLarge { .. })
            ));
            assert!(matches!(
                fork(&dir, &run, at, &TenantId::default()),
                Err(RecordError::EnvironmentContextTooLarge { .. })
            ));
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn oversized_complete_record_line_is_rejected_before_payload_parsing() {
        let dir = test_dir("oversized-line");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.jsonl");
        let mut bytes = vec![b'x'; MAX_RECORD_LINE_BYTES + 1];
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            replay(&path),
            Err(RecordError::RecordLineTooLarge { .. })
        ));
        assert!(matches!(
            Rollout::open(&dir, &RunId("oversized".into()), TenantId::default()),
            Err(RecordError::RecordLineTooLarge { .. })
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_11_g1_oversized_rollout_is_rejected_before_any_line_parsing() {
        let dir = test_dir("oversized-rollout");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.jsonl");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_ROLLOUT_BYTES + 1).unwrap();

        assert!(matches!(
            replay(&path),
            Err(RecordError::RolloutTooLarge {
                bytes,
                max: MAX_ROLLOUT_BYTES,
            }) if bytes == MAX_ROLLOUT_BYTES + 1
        ));
        assert!(matches!(
            Rollout::open(&dir, &RunId("oversized".into()), TenantId::default()),
            Err(RecordError::RolloutTooLarge {
                bytes,
                max: MAX_ROLLOUT_BYTES,
            }) if bytes == MAX_ROLLOUT_BYTES + 1
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_g1_blank_lines_do_not_let_append_create_an_unreplayable_rollout() {
        let dir = test_dir("blank-line-boundary");
        std::fs::create_dir_all(&dir).unwrap();
        let run = RunId("blank-line-boundary".into());
        let path = dir.join("blank-line-boundary.jsonl");
        std::fs::write(&path, vec![b'\n'; MAX_ROLLOUT_EVENTS]).unwrap();

        {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            assert_eq!(rollout.event_count, 0);
            rollout.append(&ev(0)).unwrap();
            assert_eq!(rollout.event_count, 1);
        }
        assert_eq!(replay(&path).unwrap().len(), 1);
        let reopened = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        assert_eq!(reopened.event_count, 1);

        drop(reopened);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_blank_line_cpu_work_has_a_physical_scan_ceiling() {
        let dir = test_dir("blank-line-scan-ceiling");
        std::fs::create_dir_all(&dir).unwrap();
        let run = RunId("blank-line-scan-ceiling".into());
        let path = dir.join("blank-line-scan-ceiling.jsonl");
        std::fs::write(&path, vec![b'\n'; MAX_ROLLOUT_PHYSICAL_LINES + 1]).unwrap();

        assert!(matches!(
            replay(&path),
            Err(RecordError::TooManyRecordLines {
                max: MAX_ROLLOUT_PHYSICAL_LINES,
            })
        ));
        assert!(matches!(
            Rollout::open(&dir, &run, TenantId::default()),
            Err(RecordError::TooManyRecordLines {
                max: MAX_ROLLOUT_PHYSICAL_LINES,
            })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_append_at_exact_physical_line_cap_fails_without_mutating_rollout() {
        let dir = test_dir("blank-line-exact-cap");
        std::fs::create_dir_all(&dir).unwrap();
        let run = RunId("blank-line-exact-cap".into());
        let path = dir.join("blank-line-exact-cap.jsonl");
        std::fs::write(&path, vec![b'\n'; MAX_ROLLOUT_PHYSICAL_LINES]).unwrap();
        let original_len = std::fs::metadata(&path).unwrap().len();

        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        assert!(matches!(
            rollout.append(&ev(0)),
            Err(RecordError::TooManyRecordLines {
                max: MAX_ROLLOUT_PHYSICAL_LINES,
            })
        ));
        drop(rollout);

        assert_eq!(std::fs::metadata(&path).unwrap().len(), original_len);
        assert!(replay(&path).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_g1_non_contiguous_and_wrapping_sequences_fail_closed() {
        for found in [1, u64::MAX] {
            let dir = test_dir("broken-sequence");
            std::fs::create_dir_all(&dir).unwrap();
            let run = RunId(format!("broken-sequence-{found}"));
            let path = dir.join(format!("{}.jsonl", run.0));
            let payload = serde_json::to_value(ev(0)).unwrap();
            let line = ChainLine {
                seq: found,
                tenant: TenantId::default().0,
                prev: ZERO_HASH.to_string(),
                hash: hash_line(ZERO_HASH, found, &payload),
                payload,
                // Hand-built test line: no writer, so no segment origin to measure from.
                ts_us: None,
            };
            std::fs::write(
                &path,
                format!("{}\n", serde_json::to_string(&line).unwrap()),
            )
            .unwrap();

            assert!(matches!(
                replay(&path),
                Err(RecordError::SequenceBroken {
                    expected: 0,
                    found: actual,
                }) if actual == found
            ));
            assert!(matches!(
                Rollout::open(&dir, &run, TenantId::default()),
                Err(RecordError::SequenceBroken {
                    expected: 0,
                    found: actual,
                }) if actual == found
            ));
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn d9_11_g1_writer_event_ceiling_refuses_before_mutation() {
        let dir = test_dir("event-ceiling");
        let run = RunId("event-ceiling".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        rollout.event_count = MAX_ROLLOUT_EVENTS;
        let before_len = rollout.file.metadata().unwrap().len();
        let before_seq = rollout.seq;

        assert!(matches!(
            rollout.append(&ev(0)),
            Err(RecordError::TooManyEvents {
                max: MAX_ROLLOUT_EVENTS,
            })
        ));
        assert_eq!(rollout.file.metadata().unwrap().len(), before_len);
        assert_eq!(rollout.seq, before_seq);
        drop(rollout);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_g2_actual_stream_bytes_cannot_grow_past_the_ceiling() {
        let mut consumed = MAX_ROLLOUT_BYTES - 1;
        assert!(matches!(
            admit_stream_bytes(&mut consumed, 2),
            Err(RecordError::RolloutTooLarge {
                bytes,
                max: MAX_ROLLOUT_BYTES,
            }) if bytes == MAX_ROLLOUT_BYTES + 1
        ));
    }

    #[test]
    fn d9_11_g2_growth_after_metadata_preflight_is_charged_by_the_real_visitor() {
        let dir = test_dir("growth-after-preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("growth-after-preflight.jsonl");
        File::create(&path).unwrap();

        let growing_path = path.clone();
        AFTER_VISIT_METADATA_PREFLIGHT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let mut file = OpenOptions::new().write(true).open(&growing_path).unwrap();
                file.set_len(MAX_ROLLOUT_BYTES + 1).unwrap();
                for line in 1..=MAX_ROLLOUT_BYTES / MAX_RECORD_LINE_BYTES as u64 {
                    file.seek(SeekFrom::Start(line * MAX_RECORD_LINE_BYTES as u64 - 1))
                        .unwrap();
                    file.write_all(b"\n").unwrap();
                }
                file.sync_all().unwrap();
            }));
        });

        assert!(matches!(
            visit_record_lines(&path, |_| Ok(())),
            Err(RecordError::RolloutTooLarge {
                bytes,
                max: MAX_ROLLOUT_BYTES,
            }) if bytes == MAX_ROLLOUT_BYTES + 1
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn i16_only_the_turn_boundary_pays_the_full_barrier() {
        let dir = test_dir("durability-tiering");
        let run = RunId("durability-tiering".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();

        // One turn as the profile measured it: 16 intra-turn phase/tool lines, then the boundary.
        // Before the fix every one of these was an `F_FULLFSYNC` at p50 4.09 ms.
        for _ in 0..16 {
            rollout.append(&ev(0)).unwrap();
        }
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: core_protocol::Usage::default(),
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        assert_eq!(
            rollout.barriers_taken(),
            (16, 1),
            "only TurnEnd may pay F_FULLFSYNC; the 16 intra-turn appends take a plain fsync"
        );

        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "Completed".into(),
                },
            })
            .unwrap();
        assert_eq!(
            rollout.barriers_taken(),
            (16, 2),
            "the run terminal is a boundary too"
        );

        // The cheap tier is a durability tier, not a correctness shortcut: the chain still verifies
        // and replays byte-for-byte, and a reopened writer still recovers the same head.
        drop(rollout);
        let path = dir.join("durability-tiering.jsonl");
        assert_eq!(replay(&path).unwrap().len(), 18);
        let reopened = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        assert_eq!(reopened.next_sequence(), Seq(18));
        drop(reopened);
        let _ = std::fs::remove_dir_all(dir);
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
    fn append_rejects_v2_payloads_under_v1_public_tags_without_mutation() {
        let dir = test_dir("schema-tag-validation");
        let run = RunId("schema-tag-validation".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        let v1_metrics = core_protocol::WorkflowMetrics {
            model_ms: Some(0),
            tools_ms: Some(0),
            ..core_protocol::WorkflowMetrics::default()
        };
        let invalid = [
            EventKind::Workflow {
                version: core_protocol::WorkflowEventVersion::V1,
                workflow_id: "w".into(),
                event: core_protocol::WorkflowEvent::Finished {
                    outcome: core_protocol::WorkflowOutcome::Drained,
                    metrics: v1_metrics.clone(),
                    elapsed_ms: 0,
                    error_code: None,
                    error_detail: None,
                },
            },
            EventKind::Workflow {
                version: core_protocol::WorkflowEventVersion::V1,
                workflow_id: "w".into(),
                event: core_protocol::WorkflowEvent::Finished {
                    outcome: core_protocol::WorkflowOutcome::Done,
                    metrics: core_protocol::WorkflowMetrics::default(),
                    elapsed_ms: 0,
                    error_code: None,
                    error_detail: None,
                },
            },
            EventKind::WorkflowV2 {
                version: core_protocol::WorkflowEventVersion::V1,
                workflow_id: "w".into(),
                event: core_protocol::WorkflowEvent::Started {
                    name: "w".into(),
                    class: "direct".into(),
                },
            },
            EventKind::SubagentFinished {
                sub_run: "child".into(),
                outcome: core_protocol::WorkflowChildOutcome::Drained,
                metrics: v1_metrics.clone(),
                error_code: None,
                error_detail: None,
                summary_digest: None,
                evidence_bytes: 0,
            },
            EventKind::SubagentFinished {
                sub_run: "child".into(),
                outcome: core_protocol::WorkflowChildOutcome::Done,
                metrics: core_protocol::WorkflowMetrics::default(),
                error_code: None,
                error_detail: None,
                summary_digest: None,
                evidence_bytes: 0,
            },
            EventKind::SubagentFinishedV2 {
                version: core_protocol::WorkflowEventVersion::V1,
                sub_run: "child".into(),
                outcome: core_protocol::WorkflowChildOutcome::Done,
                metrics: core_protocol::WorkflowMetrics::default(),
                error_code: None,
                error_detail: None,
                summary_digest: None,
                evidence_bytes: 0,
            },
        ];
        for kind in invalid {
            let error = rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind,
                })
                .unwrap_err();
            assert!(matches!(error, RecordError::InvalidEventSchema { .. }));
            assert_eq!(rollout.next_sequence(), Seq::ZERO);
        }
        assert!(replay(rollout.path()).unwrap().is_empty());

        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Workflow {
                    version: core_protocol::WorkflowEventVersion::V1,
                    workflow_id: "legacy-compatible".into(),
                    event: core_protocol::WorkflowEvent::Finished {
                        outcome: core_protocol::WorkflowOutcome::Done,
                        metrics: v1_metrics,
                        elapsed_ms: 0,
                        error_code: None,
                        error_detail: None,
                    },
                },
            })
            .unwrap();
        assert_eq!(replay(rollout.path()).unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    /// I-42: 81 of 198 audited `tool_done` records had no `effect_id` and 77 of those were
    /// successful, so successful work was landing in the record with nothing that admitted it and
    /// nothing that named it. The gate has to sit at the append boundary rather than in a caller,
    /// because the whole point is that no caller can quietly regrow the hole.
    #[test]
    fn append_refuses_a_tool_terminal_that_names_neither_its_tool_nor_its_admission() {
        let dir = test_dir("tool-terminal-identity");
        let run = RunId("tool-terminal-identity".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        let result = |is_error: bool| core_protocol::ToolResult {
            tool_use_id: "call-1".into(),
            content: "ok".into(),
            is_error,
            trust: Trust::Workspace,
            latency_ms: 3,
        };

        for kind in [
            // Successful, admitted, but anonymous: the audited shape.
            EventKind::ToolDone {
                result: result(false),
                effect_id: Some(core_protocol::EffectId("fx1-00000000-0000".into())),
                tool: None,
            },
            // Named but empty is the same defect wearing a value.
            EventKind::ToolDone {
                result: result(false),
                effect_id: Some(core_protocol::EffectId("fx1-00000000-0000".into())),
                tool: Some(String::new()),
            },
            // Successful with no admission event: 77 of the 81.
            EventKind::ToolDone {
                result: result(false),
                effect_id: None,
                tool: Some("read_file".into()),
            },
        ] {
            let error = rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind,
                })
                .unwrap_err();
            assert!(matches!(error, RecordError::InvalidEventSchema { .. }));
            assert_eq!(rollout.next_sequence(), Seq::ZERO);
        }

        // A call that never reached an executor has no admission to name, and refusing it would
        // leave the transcript with a dangling tool_use the provider rejects on the next turn.
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::ToolDone {
                    result: result(true),
                    effect_id: None,
                    tool: Some("bash".into()),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::ToolDone {
                    result: result(false),
                    effect_id: Some(core_protocol::EffectId("fx1-00000000-0001".into())),
                    tool: Some("edit".into()),
                },
            })
            .unwrap();
        assert_eq!(replay(rollout.path()).unwrap().len(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// The gate is write-only. Every rollout the audit read is full of anonymous terminals, and a
    /// read-time rule would turn the evidence into an unreplayable file.
    #[test]
    fn replay_still_reads_the_anonymous_terminals_already_on_disk() {
        let dir = test_dir("legacy-tool-terminal");
        std::fs::create_dir_all(&dir).unwrap();
        let run = RunId("legacy-tool-terminal".into());
        let path;
        {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::ToolDone {
                        result: core_protocol::ToolResult {
                            tool_use_id: "call-1".into(),
                            content: "ok".into(),
                            is_error: true,
                            trust: Trust::Workspace,
                            latency_ms: 3,
                        },
                        effect_id: None,
                        tool: Some("grep".into()),
                    },
                })
                .unwrap();
            path = rollout.path().to_path_buf();
        }
        // Rewind that line to the shape a pre-I-42 writer produced — a successful terminal with
        // neither name nor admission — and re-anchor the chain over it, so `replay` is judging the
        // record and not a corrupted hash.
        let stored = std::fs::read_to_string(&path).unwrap();
        let mut line: serde_json::Value = serde_json::from_str(stored.trim()).unwrap();
        let kind = line["payload"]["kind"].as_object_mut().unwrap();
        kind.remove("tool");
        kind["result"]["is_error"] = serde_json::Value::Bool(false);
        let prev = line["prev"].as_str().unwrap().to_owned();
        let seq = line["seq"].as_u64().unwrap();
        line["hash"] = serde_json::Value::String(hash_line(&prev, seq, &line["payload"]));
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&line).unwrap()),
        )
        .unwrap();

        let events = replay(&path).unwrap();
        assert!(matches!(
            events[0].kind,
            EventKind::ToolDone {
                effect_id: None,
                tool: None,
                ..
            }
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_07_future_provider_state_replays_and_crosses_a_fork() {
        let dir = test_dir("provider-state-forward-compatible");
        std::fs::create_dir_all(&dir).unwrap();
        let parent = RunId("provider-state-parent".into());
        let tenant = TenantId::default();

        let genesis = Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: dir.display().to_string(),
                model: "model".into(),
                effort: core_protocol::Effort::Medium,
                created_at: 1,
                environment: None,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest: String::new(),
                agent_definition_tag: None,
                max_usd: None,
            },
        };
        let genesis_payload = serde_json::to_value(genesis).unwrap();
        let genesis_hash = hash_line(ZERO_HASH, 0, &genesis_payload);
        let genesis_line = ChainLine {
            seq: 0,
            tenant: tenant.0.clone(),
            prev: ZERO_HASH.into(),
            hash: genesis_hash.clone(),
            payload: genesis_payload,
            // Hand-built test line: no writer, so no segment origin to measure from.
            ts_us: None,
        };

        let message = Event {
            seq: Seq(1),
            turn: TurnId(1),
            kind: EventKind::Message {
                message: Message {
                    role: Role::Assistant,
                    content: vec![Block::ProviderState(ProviderState {
                        route_scope: "provider/model".into(),
                        format: ProviderStateFormat::Unknown(
                            "openai.responses.output-items.v2".into(),
                        ),
                        payload: serde_json::json!({"opaque":"future"}),
                    })],
                },
            },
        };
        let mut message_payload = serde_json::to_value(message).unwrap();
        message_payload["kind"]["message"]["content"][0]
            .as_object_mut()
            .unwrap()
            .insert(
                "added_by_newer_core".into(),
                serde_json::json!({"must":"not break replay"}),
            );
        let message_hash = hash_line(&genesis_hash, 1, &message_payload);
        let message_line = ChainLine {
            seq: 1,
            tenant: tenant.0.clone(),
            prev: genesis_hash,
            hash: message_hash,
            payload: message_payload,
            // Hand-built test line: no writer, so no segment origin to measure from.
            ts_us: None,
        };
        let physical = format!(
            "{}\n{}\n",
            serde_json::to_string(&genesis_line).unwrap(),
            serde_json::to_string(&message_line).unwrap()
        );
        std::fs::write(dir.join(format!("{parent}.jsonl")), physical).unwrap();

        let replayed = replay(&dir.join(format!("{parent}.jsonl"))).unwrap();
        assert_eq!(replayed.len(), 2);
        let child = fork(&dir, &parent, Seq(1), &tenant).unwrap();
        let logical_child = load_forked(&dir, &child).unwrap();
        let state = logical_child
            .iter()
            .find_map(|event| match &event.kind {
                EventKind::Message { message } => message.content.iter().find_map(|block| {
                    if let Block::ProviderState(state) = block {
                        Some(state)
                    } else {
                        None
                    }
                }),
                _ => None,
            })
            .expect("the verified parent provider state must survive logical fork replay");
        assert_eq!(
            state.format,
            ProviderStateFormat::Unknown("openai.responses.output-items.v2".into())
        );
        assert_eq!(state.payload, serde_json::json!({"opaque":"future"}));
        std::fs::remove_dir_all(dir).ok();
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
                    if path == &dir.canonicalize().unwrap().join("locked-run.jsonl")
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
    fn open_existing_never_creates_a_missing_resume_target_and_holds_the_writer_lock() {
        let dir = test_dir("open-existing");
        std::fs::create_dir_all(&dir).unwrap();
        let run = RunId("existing-run".into());
        let path = dir.join("existing-run.jsonl");

        assert!(Rollout::open_existing(&dir, &run, TenantId::default()).is_err());
        assert!(
            !path.exists(),
            "an invalid --resume id must not create an empty rollout"
        );

        drop(Rollout::open(&dir, &run, TenantId::default()).unwrap());
        let locked = Rollout::open_existing(&dir, &run, TenantId::default()).unwrap();
        assert!(matches!(
            Rollout::open(&dir, &run, TenantId::default()),
            Err(RecordError::WriterBusy { .. })
        ));
        drop(locked);
        assert!(Rollout::open_existing(&dir, &run, TenantId::default()).is_ok());
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
    fn secrets_in_notice_are_scrubbed_and_replayable() {
        let dir = test_dir("notice-redact");
        let run = RunId("notice-redact".into());
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Notice {
                        text: format!("provider echoed {secret}"),
                    },
                })
                .unwrap();
        }

        let path = dir.join("notice-redact.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains(secret),
            "notice leaked into the durable record"
        );
        assert!(raw.contains("[REDACTED"), "notice secret must be masked");
        let replayed = replay(&path).unwrap();
        assert!(matches!(
            &replayed[0].kind,
            EventKind::Notice { text } if text.contains("[REDACTED")
        ));
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
    fn d9_11_g3_mid_file_tamper_still_breaks_the_streamed_chain() {
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
        assert!(matches!(
            Rollout::open(&dir, &run, TenantId::default()),
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

    #[test]
    fn d13_14_frozen_rollouts_hash_verify_replay_and_preserve_shape() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root exists");
        let contract: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("governance/schema-compatibility.json"))
                .expect("compatibility contract is readable"),
        )
        .expect("compatibility contract is JSON");
        let surface = contract["surfaces"]
            .as_array()
            .expect("surfaces is an array")
            .iter()
            .find(|surface| surface["id"] == "record.rollout")
            .expect("record surface is declared");
        let mut compatibility_shims = surface["compatibility_shims"]
            .as_array()
            .expect("compatibility shims is an array")
            .iter()
            .collect::<Vec<_>>();
        compatibility_shims.sort_by(|left, right| {
            left["target_version"]
                .as_u64()
                .cmp(&right["target_version"].as_u64())
                .then_with(|| left["old_field"].as_str().cmp(&right["old_field"].as_str()))
        });
        let active_fields = surface["fields"]
            .as_array()
            .expect("surface fields is an array")
            .iter()
            .map(|field| {
                field["name"]
                    .as_str()
                    .expect("surface field name is a string")
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        let current_version = surface["current_version"]
            .as_u64()
            .expect("surface current version is an integer");

        for fixture in surface["fixtures"]
            .as_array()
            .expect("fixtures is an array")
        {
            let relative = fixture["path"].as_str().expect("fixture path is a string");
            let path = root.join(relative);
            let physical = std::fs::read_to_string(&path).expect("rollout fixture is UTF-8");
            let lines = physical
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            for line in &lines {
                let typed_line: ChainLine =
                    serde_json::from_value(line.clone()).unwrap_or_else(|error| {
                        panic!("{} is not runtime-readable: {error}", path.display())
                    });
                let encoded = serde_json::to_value(typed_line).unwrap();
                let raw = line.as_object().expect("rollout line is an object");
                let mut canonical = raw.clone();
                for shim in &compatibility_shims {
                    let old_field = shim["old_field"]
                        .as_str()
                        .expect("shim old field is a string");
                    let Some(old) = canonical.remove(old_field) else {
                        continue;
                    };
                    if raw.contains_key(old_field) {
                        assert!(
                            shim["fixtures"]
                                .as_array()
                                .expect("shim fixtures is an array")
                                .iter()
                                .any(|fixture| fixture.as_str() == Some(relative)),
                            "rollout {} uses `{old_field}` without declaring the fixture on its shim",
                            path.display()
                        );
                    }
                    if let Some(replacement) = shim["replacement"].as_str() {
                        assert!(
                            !canonical.contains_key(replacement),
                            "rollout {} migration would overwrite `{replacement}`",
                            path.display()
                        );
                        canonical.insert(replacement.to_owned(), old);
                    }
                    if let Some(version_field) = surface["version_field"].as_str() {
                        canonical.insert(version_field.to_owned(), shim["target_version"].clone());
                    }
                }
                if let Some(version_field) = surface["version_field"].as_str() {
                    canonical.insert(version_field.to_owned(), current_version.into());
                }
                let canonical_fields = canonical
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                assert!(
                    canonical_fields.is_subset(&active_fields),
                    "canonical rollout migration retained stale fields in {}: {canonical_fields:?}",
                    path.display()
                );
                let encoded = encoded
                    .as_object()
                    .expect("typed rollout line is an object");
                let encoded_fields = encoded
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                assert!(
                    encoded_fields.is_subset(&active_fields),
                    "typed rollout emitted undeclared fields in {}: {encoded_fields:?}",
                    path.display()
                );
                for (field, value) in canonical {
                    assert_eq!(
                        encoded.get(&field),
                        Some(&value),
                        "typed rollout migration changed `{field}` in {}",
                        path.display(),
                    );
                }
                if fixture["schema_version"].as_u64() == Some(current_version) {
                    assert_eq!(
                        serde_json::Value::Object(encoded.clone()),
                        *line,
                        "current rollout line changed: {}",
                        path.display()
                    );
                }
            }
            let events = replay(&path).unwrap_or_else(|error| {
                panic!("frozen rollout {} did not replay: {error}", path.display())
            });
            assert_eq!(events.len(), lines.len(), "{}", path.display());
            assert!(!events.is_empty(), "{}", path.display());
            assert!(matches!(
                events[0].kind,
                EventKind::TurnStart | EventKind::RunStart { .. }
            ));
            if fixture["schema_version"] == 4 {
                assert!(matches!(
                    &events[0].kind,
                    EventKind::RunStart {
                        environment: Some(environment),
                        ..
                    } if environment.text == "environment snapshot"
                        && environment.trust == core_protocol::Trust::Workspace
                ));
                assert!(events.iter().any(|event| matches!(
                    &event.kind,
                    EventKind::ContextInjection {
                        instructions: Some(core_protocol::DurableInstructionContext {
                            environment: Some(environment),
                            ..
                        }),
                        ..
                    } if environment.text == "environment snapshot"
                        && environment.trust == core_protocol::Trust::Workspace
                )));
            }
            for (line, event) in lines.iter().zip(events) {
                assert_eq!(
                    serde_json::to_value(event).unwrap(),
                    line["payload"],
                    "rollout event shape changed: {}",
                    path.display()
                );
            }
        }
    }

    /// I-45. Opening the first rollout in a repository creates `<repo>/.core`. Nothing used to
    /// exclude it, so the next `git add -A` committed the session transcript, memory and skills
    /// into the user's own history. The exclusion goes in `.git/info/exclude` — per-clone and
    /// untracked — and the tracked `.gitignore` is the user's file and is never touched.
    #[test]
    fn the_state_directory_excludes_itself_from_git_without_editing_the_users_ignore_file() {
        let repo = test_dir("git-exclude");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let ignore = repo.join(".gitignore");
        std::fs::write(&ignore, "target/\n").unwrap();

        let runs = repo.join(".core").join("runs");
        let rollout = Rollout::open(&runs, &RunId("first".into()), TenantId::default()).unwrap();
        drop(rollout);

        let exclude = std::fs::read_to_string(repo.join(".git/info/exclude")).unwrap();
        assert!(
            exclude.lines().any(|line| line.trim() == "/.core/**"),
            "the state directory's files must be excluded: {exclude}"
        );
        assert!(
            exclude.lines().any(|line| line.trim() == "!/.core/**/"),
            "the directories stay un-ignored so a checkpoint pathspec may name them: {exclude}"
        );
        assert_eq!(
            std::fs::read_to_string(&ignore).unwrap(),
            "target/\n",
            "the user's own ignore file is not ours to edit"
        );

        // Idempotent: a second run in the same repository does not append a duplicate stanza.
        let rollout = Rollout::open(&runs, &RunId("second".into()), TenantId::default()).unwrap();
        drop(rollout);
        assert_eq!(
            std::fs::read_to_string(repo.join(".git/info/exclude")).unwrap(),
            exclude,
            "the claim is made once, on first creation"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// I-45. Opening a rollout is not the only way the state directory comes into being: a bare
    /// `core reindex` in a fresh repository creates it too, and used to create it unclaimed — the
    /// index and its lock file were then staged by the next `git add -A`. Whichever path gets there
    /// first has to make the claim.
    #[test]
    fn maintenance_that_creates_the_state_directory_claims_the_exclusion_too() {
        let repo = test_dir("git-exclude-reindex");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let runs = repo.join(".core").join("runs");

        assert_eq!(session::reindex(&runs).unwrap(), 0);

        let exclude = std::fs::read_to_string(repo.join(".git/info/exclude"))
            .expect("reindex creating the state directory claims it");
        assert!(
            exclude.lines().any(|line| line.trim() == "/.core/**"),
            "{exclude}"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// The exclusion speaks only for Core's own directory: a runs dir configured somewhere else
    /// entirely has no `.core` state root and must not cause a write into any repository.
    #[test]
    fn a_runs_dir_outside_the_state_directory_writes_no_git_exclusion() {
        let repo = test_dir("git-exclude-foreign");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let runs = repo.join("elsewhere").join("runs");

        let rollout = Rollout::open(&runs, &RunId("only".into()), TenantId::default()).unwrap();
        drop(rollout);

        assert!(
            !repo.join(".git/info/exclude").exists(),
            "an unrelated runs dir is not a reason to write into .git"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }
}

#[cfg(test)]
mod timeline_tests {
    use super::*;
    use core_protocol::{Event, EventKind, RunId, Seq, TenantId, TurnId};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "core-timeline-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The load-bearing claim of #102: adding a per-line timestamp does not touch the chain.
    /// `hash_line` covers `(prev, seq, payload)` and `ts_us` is a sibling of `tenant`, outside it.
    /// If this ever fails, every rollout ever written stops verifying, so it is pinned directly
    /// against the hash function rather than inferred from a passing replay.
    #[test]
    fn the_timestamp_is_outside_the_hash_so_no_existing_chain_moves() {
        let dir = scratch("hash");
        let run = RunId("hash-stability".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId("default".into())).unwrap();
        for _ in 0..3 {
            rollout
                .append(&Event {
                    seq: Seq(0),
                    turn: TurnId(1),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
        }
        drop(rollout);

        let path = dir.join(format!("{}.jsonl", run.0));
        let text = std::fs::read_to_string(&path).unwrap();
        for (index, raw) in text.lines().enumerate() {
            let written: serde_json::Value = serde_json::from_str(raw).unwrap();
            // Recompute the hash from the line's OWN (prev, seq, payload) and nothing else. If
            // `ts_us` had leaked into `hash_line`, this would not reproduce -- which is exactly
            // the failure mode that would invalidate every rollout ever written.
            let recomputed = hash_line(
                written["prev"].as_str().unwrap(),
                written["seq"].as_u64().unwrap(),
                &written["payload"],
            );
            assert_eq!(
                written["hash"].as_str().unwrap(),
                recomputed,
                "line {index}: the hash covers something other than (prev, seq, payload)"
            );
            assert!(
                written["ts_us"].is_number(),
                "line {index}: a live writer must stamp its segment offset"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rollout written before #102 has no honest offset, and the reader must be able to see
    /// that rather than read a fabricated zero. Absence is the encoding; `0` stays available to
    /// mean the real thing, "at the segment origin".
    #[test]
    fn a_pre_timeline_line_reads_as_unknown_not_as_the_origin() {
        let legacy: ChainLine = serde_json::from_str(
            r#"{"seq":0,"tenant":"default","prev":"0000000000000000000000000000000000000000000000000000000000000000","hash":"x","payload":{"seq":0,"turn":0,"kind":{"kind":"turn_start"}}}"#,
        )
        .unwrap();
        assert_eq!(
            legacy.ts_us, None,
            "a line written before ts_us existed must decode as unknown"
        );
        let reserialised = serde_json::to_value(&legacy).unwrap();
        assert!(
            reserialised.get("ts_us").is_none(),
            "an unknown offset must be absent, not null: {reserialised}"
        );

        let at_origin = ChainLine {
            ts_us: Some(0),
            ..legacy
        };
        assert_eq!(
            serde_json::to_value(&at_origin).unwrap()["ts_us"],
            0,
            "a measured zero is a real observation and must survive the wire"
        );
    }

    /// Offsets rise within one writer, which is what makes a segment internally exact.
    #[test]
    fn offsets_are_monotonic_within_one_writer() {
        let dir = scratch("monotonic");
        let run = RunId("monotonic".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId("default".into())).unwrap();
        for _ in 0..4 {
            rollout
                .append(&Event {
                    seq: Seq(0),
                    turn: TurnId(1),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
        }
        drop(rollout);

        let path = dir.join(format!("{}.jsonl", run.0));
        let offsets: Vec<u64> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["ts_us"]
                    .as_u64()
                    .expect("live writer stamps every line")
            })
            .collect();
        assert_eq!(offsets.len(), 4);
        assert!(
            offsets.windows(2).all(|w| w[1] >= w[0]),
            "offsets must not go backwards inside one segment: {offsets:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The resume seam, in band. A second writer restarts its origin, so the offset DROPS at the
    /// join. That drop is the segment marker: a reader splits on it, times exactly within each
    /// segment, and reports the join itself as unknown instead of inventing a duration across two
    /// unrelated monotonic clocks. No extra field is needed to carry it.
    #[test]
    fn a_resumed_segment_restarts_its_origin_and_the_drop_is_the_seam() {
        let dir = scratch("resume");
        let run = RunId("resume".into());

        let mut first = Rollout::open(&dir, &run, TenantId("default".into())).unwrap();
        for _ in 0..3 {
            first
                .append(&Event {
                    seq: Seq(0),
                    turn: TurnId(1),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
        }
        // Let the first segment accumulate a clearly non-zero offset before it closes, so the
        // restart is unambiguous rather than a coincidence of two fast appends.
        std::thread::sleep(std::time::Duration::from_millis(20));
        first
            .append(&Event {
                seq: Seq(0),
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        drop(first);

        let mut resumed = Rollout::open_existing(&dir, &run, TenantId("default".into())).unwrap();
        resumed
            .append(&Event {
                seq: Seq(0),
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        drop(resumed);

        let path = dir.join(format!("{}.jsonl", run.0));
        let offsets: Vec<u64> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["ts_us"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(offsets.len(), 5);
        let seams: Vec<usize> = offsets
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[1] < w[0])
            .map(|(index, _)| index + 1)
            .collect();
        assert_eq!(
            seams,
            vec![4],
            "exactly one segment boundary, at the resume: {offsets:?}"
        );

        // And the chain still verifies straight through the seam: segmentation is a reading
        // concern, not a durability one.
        replay(&path).expect("a resumed rollout still replays as one verified chain");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

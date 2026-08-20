//! Session management as a projection of the rollout (SESS-1/SESS-4, R5 design §2).
//!
//! A session is not a second source of truth: it is a *projection* of its per-run rollout
//! (ADR-006). Every field of [`SessionMeta`] is derivable by replaying the record — `title`
//! from the first user message, `turns`/`cache_hit`/`last_outcome` from recorded events,
//! and `cwd`/initial model/`effort`/`created_at`/`parent` from the seq-0
//! [`EventKind::RunStart`] genesis header. Later [`EventKind::ModelSelected`] events update the
//! provider/model projection. The `.meta.json` per-run file and compacted `sessions.index` are a
//! rebuildable cache in front of that replay (R5 design §2.4): a missing or stale cache is never an
//! error, it degrades to a replay.
//!
//! Fork is a record operation, not an in-place edit. The rollout is append-only and
//! hash-chained (ADR-008), so a single log cannot branch in place. A fork is therefore a new
//! `RunId` whose genesis records the branch point by *reference* (SESS-1/SESS-5): the child
//! stores only its new events and, on load, replays the parent prefix up to the fork seq. To
//! make that reference tamper-evident (ADR-008 §4, R5-review Risk 3), the genesis pins
//! `parent_hash_at_seq` — the parent chain's hash at the fork point — so a child replay
//! detects an altered parent prefix rather than trusting it. Unknown event kinds are tolerated
//! on replay via `EventKind::Unknown` (R5-review Risk 6), so a cross-version scan does not fail.

#[path = "session_private_cache.rs"]
pub(crate) mod private_cache;
#[path = "tunables.rs"]
pub mod tunables;

use crate::{
    RecordError, Rollout, TimedEvent, ensure_tenant, validate_event_bounds, validate_run_id,
    validated_run_path,
};
use iteron_obs::{CostState, Ledger, PricingPort, PricingReplay};
use iteron_protocol::{
    Block, Effort, Event, EventKind, Message, Outcome, Role, RunId, RuntimePolicyEventVersion,
    RuntimePolicySource, RuntimePolicyState, Seq, TenantId, TurnId, Usage,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const MICROUSD_PER_USD: f64 = 1_000_000.0;
/// Projection timestamps are cache metadata, not chain state, so a pre-epoch clock reads as the
/// epoch rather than failing the projection.
const PRE_EPOCH_TIMESTAMP_SECS: u64 = 0;
pub(super) const SESSION_INDEX_HEADER: &[u8] = br#"{"version":2,"order":"updated_desc"}"#;
const SESSION_DELTA_INDEX_VERSION: u8 = 1;
const SESSION_DELTA_INDEX_FILE: &str = "sessions.delta.index";
const SESSION_DELTA_STATE_FILE: &str = "sessions.delta.state";
const SESSION_INDEX_DIRTY_FILE: &str = "sessions.index.dirty";
const SESSION_DELTA_REFS_DIR: &str = ".sessions-delta-refs";
const DEFAULT_SESSION_DELTA_COMPACT_ROWS: u64 = 512;
const DEFAULT_SESSION_DELTA_COMPACT_BYTES: u64 = 4 * 1024 * 1024;
struct SessionDeltaHardLimits {
    rows: u64,
    bytes: u64,
}

/// Crash recovery, cursor publication and compaction all share this one immutable durability
/// envelope. It is structural rather than a trainer candidate.
const SESSION_DELTA_HARD_LIMITS: SessionDeltaHardLimits = SessionDeltaHardLimits {
    rows: 4_096,
    bytes: 16 * 1024 * 1024,
};
const MAX_BACKGROUND_SESSION_COMPACTIONS: usize = 64;
const DEFAULT_SESSION_PAGE_SIZE: usize = 25;
const MAX_SESSION_PAGE_SIZE: usize = 100;
const MAX_SESSION_PAGE_SCAN_LINES: usize = 4_096;

fn max_background_session_compactions() -> usize {
    iteron_tunables::param_usize(
        "record.session.max_background_session_compactions",
        MAX_BACKGROUND_SESSION_COMPACTIONS,
    )
    .clamp(1, MAX_BACKGROUND_SESSION_COMPACTIONS)
}

fn max_session_page_size() -> usize {
    iteron_tunables::param_usize(
        "record.session.max_session_page_size",
        MAX_SESSION_PAGE_SIZE,
    )
    .clamp(1, MAX_SESSION_PAGE_SIZE)
}
/// A run id only has to be collision-resistant: a pre-epoch clock still yields a name, uniqueness
/// then resting on the pid.
const RUN_ID_NANOS_FALLBACK: u128 = 0;
/// A scoped expansion without an `upto` seq is not truncated at all, so every replayed line of the
/// run stays in scope; the bound only ever removes lines a caller explicitly asked to cut.
const UNBOUNDED_SCOPE_ADMITS_LINE: bool = true;
/// An append-era index with more than two physical writes per live rollout is abandoned after one
/// extra line and rebuilt. This makes index work O(M), independent of historical turn writes K.
const INDEX_SCAN_LINES_PER_LIVE_RUN: usize = 2;

#[cfg(test)]
std::thread_local! {
    static READ_CHAIN_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECEIPT_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static AFTER_PAGE_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

const RECEIPT_SCAN_CHUNK_BYTES: usize = 8 * 1024;

/// Legacy floating-point ceilings are compatibility data only. Rounding down is deliberately
/// conservative: reconstructing old journals must never grant one extra micro-dollar.
fn legacy_usd_to_microusd_floor(value: f64) -> u64 {
    let scaled =
        value * iteron_tunables::param_f64("record.session.microusd_per_usd", MICROUSD_PER_USD);
    if !scaled.is_finite() || scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.floor() as u64
    }
}

/// The branch point of a fork/rewind child. `parent_hash_at_seq` cross-links the child to the
/// parent chain's hash at `forked_at` so an altered parent prefix is detectable on replay
/// (ADR-008 §4 tamper-evidence, R5-review Risk 3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub parent_run: RunId,
    pub forked_at: Seq,
    pub parent_hash_at_seq: String,
}

/// One event in a verified logical fork history together with the physical journal identity that
/// originally authenticated it. Parent-prefix events deliberately retain their parent run id;
/// replay must not reinterpret them as if the child had emitted them.
#[derive(Debug, Clone)]
pub struct ScopedEvent {
    pub event: Event,
    pub tenant: TenantId,
    pub run_id: RunId,
}

/// One verified external prefix consumed by a fork session's logical history. `prefix_bytes`
/// ends exactly after `through_seq`, so later appends to the ancestor do not invalidate a child
/// projection while truncation or replacement of the pinned prefix does.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionAncestryReceipt {
    pub run_id: RunId,
    pub tenant: TenantId,
    pub through_seq: u64,
    pub prefix_bytes: u64,
    pub tail_hash: String,
    /// Complete ancestor extent observed while building this projection. Equality binds the
    /// original mtime; growth is accepted only when the old physical tail still exists at this
    /// exact boundary, distinguishing a valid append from an in-place rewrite.
    #[serde(default)]
    pub observed_record_bytes: u64,
    #[serde(default)]
    pub observed_tail_seq: u64,
    #[serde(default)]
    pub observed_tail_hash: String,
    #[serde(default)]
    pub observed_updated_at: u64,
    #[serde(default)]
    pub observed_updated_at_subsec_nanos: u32,
}

/// A session is a PROJECTION of its rollout, never a second source of truth (ADR-006). Populated
/// either from a record-writer cache or by replaying the record. Mutable cache bytes are never
/// accepted as authority for an exact monetary claim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionMeta {
    /// Projection schema for monetary truth. Legacy caches used a global placeholder price and
    /// are always rebuilt from the rollout rather than trusted.
    #[serde(default)]
    pub pricing_schema_version: u32,
    /// Projection schema independent of pricing. V3 binds fork ancestry prefix receipts;
    /// legacy caches are replayed so a resume/list cannot silently drop logical history.
    #[serde(default)]
    pub projection_schema_version: u32,
    /// Revocation generation against which every content-bearing projection was materialized.
    #[serde(default)]
    pub content_revocation_generation: u64,
    pub run_id: RunId,
    pub tenant: TenantId,
    pub cwd: PathBuf,
    /// Provider instance used by the latest recorded selection. Empty for legacy rollouts.
    #[serde(default)]
    pub provider_id: String,
    pub model: String,
    pub effort: Effort,
    /// Bounded operator-defined grouping metadata from genesis. Legacy sessions are untagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_definition_tag: Option<String>,
    /// Deterministic: the first user message's first line, truncated (SESS-3).
    pub title: String,
    /// Recorded once at run start (from the genesis header), not read at list time (ADR-006 rule 1).
    pub created_at: u64,
    /// Last-touched time. Authoritative when cached (kernel-written); on a replay it degrades to
    /// the rollout file's mtime, since the record carries no per-event wall clock.
    pub updated_at: u64,
    /// Nanosecond fraction of the same rollout mtime. It both breaks same-second continuation
    /// ties and detects accidental in-place record changes that preserve length and tail bytes.
    #[serde(default)]
    pub updated_at_subsec_nanos: u32,
    /// Physical rollout length covered by this rebuildable projection cache. Older cache files
    /// deserialize with zero and are replayed. An append-only `ModelSelected` increases the
    /// rollout length, invalidating stale provider/model projections without scanning the log.
    #[serde(default)]
    pub record_bytes: u64,
    /// Exact physical tail receipt observed by the record writer. Fast-path reads compare this
    /// pair with the bounded final record line before accepting any mutable cache fields.
    #[serde(default)]
    pub record_tail_seq: Option<u64>,
    #[serde(default)]
    pub record_tail_hash: String,
    /// Corruption detector over the complete projection plus its record receipt, with this field
    /// cleared during hashing. It is not a substitute for the hash-chained rollout; a mismatch is
    /// simply a cache miss that forces authoritative replay.
    #[serde(default)]
    pub projection_digest: String,
    /// Root-to-direct-parent receipts for every external prefix included by a fork projection.
    /// Empty for an ordinary root run. Each entry is bounded and rechecked without replaying the
    /// ancestor's full journal.
    #[serde(default)]
    pub ancestry: Vec<SessionAncestryReceipt>,
    pub turns: u32,
    /// Evidence-backed monetary state. Signed route-bound projections produce `Known`; completed
    /// provider turns without matching durable pricing evidence remain honestly `Unknown`.
    #[serde(default)]
    pub cost: CostState,
    pub cache_hit: f64,
    /// Serialized via [`outcome_opt`] (as a string), because `Outcome::BudgetExhausted` holds a
    /// `&'static str` and so cannot itself be `Deserialize`d into an owned value.
    #[serde(with = "outcome_opt")]
    pub last_outcome: Option<Outcome>,
    /// `Some(_)` iff this run is a fork/rewind child.
    pub parent: Option<Provenance>,
}

/// One bounded window from the rebuildable, newest-first session index. An absent/stale index is
/// reported as not ready instead of replaying every rollout on a latency-sensitive caller. The
/// caller may paint immediately and schedule [`reindex`] off the foreground path.
#[derive(Debug, Clone, Default)]
pub struct SessionPage {
    pub sessions: Vec<SessionMeta>,
    pub next_cursor: Option<SessionPageCursor>,
    pub has_more: bool,
    pub index_ready: bool,
    /// The caller supplied a cursor for a replaced index generation and must restart at `None`.
    pub cursor_stale: bool,
    /// The immutable projection is absent or corrupt and may be rebuilt off the authoritative
    /// rollouts. False for a short publication/compaction race, which should only be retried.
    pub rebuild_recommended: bool,
    /// Bounded diagnostic evidence; never exceeds `MAX_SESSION_PAGE_SCAN_LINES`.
    pub examined: usize,
}

/// Opaque seek cursor bound to one atomic index generation. Copying it across a rebuild fails
/// closed with `cursor_stale`, while traversing a stable generation is O(N) in total, not O(N²).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPageCursor {
    base_generation: u64,
    delta_generation: u64,
    delta_high_water: u64,
    phase: SessionPagePhase,
    byte_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum SessionPagePhase {
    Delta,
    Base,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionDeltaHeader {
    version: u8,
    generation: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionDeltaRef {
    version: u8,
    generation: u64,
    byte_offset: u64,
    #[serde(default)]
    delta_high_water: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionDeltaState {
    version: u8,
    generation: u64,
    rows: u64,
    high_water: u64,
}

impl SessionMeta {
    pub fn cost_usd(&self) -> Option<f64> {
        self.cost.usd()
    }
}

/// Incremental, rebuildable projection for the current physical run.
///
/// Construction performs one bounded, hash-verified logical replay (including a fork's pinned
/// parent prefix). After that, the kernel feeds only events whose append+fsync already succeeded,
/// so turn-boundary cache refreshes are O(1) in historical rollout length rather than replaying
/// the entire journal on every turn. The projection is never authoritative: a structurally
/// current projection may be persisted for every session shape, while only an honest `Unknown`
/// monetary state is directly readable without replay. Stale/corrupt bytes always degrade to
/// verified replay.
pub(crate) struct SessionProjection {
    runs_dir: PathBuf,
    meta: SessionMeta,
    turns: u32,
    usage: Usage,
    title: String,
    cost_ledger: Ledger,
    pricing_replay: PricingReplay,
}

impl SessionProjection {
    /// Build from the authoritative logical rollout once. Subsequent events must be supplied only
    /// after their durable append succeeds.
    pub(crate) fn load(runs_dir: &Path, run: &RunId) -> Result<Self, RecordError> {
        load_session_projection(runs_dir, run, None)
    }

    /// Apply one newly durable event from this projection's physical run.
    pub(crate) fn observe_committed(
        &mut self,
        event: &Event,
        seq: Seq,
        hash: &str,
    ) -> Result<(), RecordError> {
        let tenant = self.meta.tenant.clone();
        let run = self.meta.run_id.clone();
        self.observe_scoped(event, &tenant, &run)?;
        self.meta.record_tail_seq = Some(seq.0);
        self.meta.record_tail_hash = hash.to_string();
        Ok(())
    }

    /// Atomically refresh the per-run sidecar and canonical index when this projection is current
    /// and independently bound to the physical rollout plus any fork ancestry it consumed.
    pub(crate) fn persist_at(&mut self, expected_record_bytes: u64) -> Result<bool, RecordError> {
        if complete_record_len(&rollout_path(&self.runs_dir, &self.meta.run_id)?)
            != Some(expected_record_bytes)
        {
            self.meta.record_bytes = 0;
            return Ok(false);
        }
        let (updated_at, updated_at_subsec_nanos) =
            file_mtime(&rollout_path(&self.runs_dir, &self.meta.run_id)?)
                .unwrap_or((self.meta.created_at, 0));
        self.meta.updated_at = updated_at;
        self.meta.updated_at_subsec_nanos = updated_at_subsec_nanos;
        self.meta.record_bytes = expected_record_bytes;
        self.refresh_derived();
        self.meta.cache_hit = json_f64_fixed_point(self.meta.cache_hit)?;
        self.meta.projection_digest = projection_digest(&self.meta)?;
        if !projection_is_current(&self.runs_dir, &self.meta) {
            return Ok(false);
        }
        write_meta(&self.runs_dir, &self.meta)?;
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn projected(&self) -> &SessionMeta {
        &self.meta
    }

    fn observe_scoped(
        &mut self,
        event: &Event,
        tenant: &TenantId,
        run: &RunId,
    ) -> Result<(), RecordError> {
        self.pricing_replay
            .observe(event, tenant, run, &mut self.cost_ledger)?;
        match &event.kind {
            EventKind::TurnStart => {
                self.turns = self.turns.saturating_add(1);
            }
            EventKind::TurnEnd { usage, .. } => self.usage.add(usage),
            EventKind::SubagentFinished { metrics, .. }
            | EventKind::SubagentFinishedV2 { metrics, .. } => {
                self.turns = self.turns.saturating_add(metrics.provider_attempts);
                self.usage.add(&metrics.usage);
            }
            EventKind::Workflow {
                event: iteron_protocol::WorkflowEvent::ChildFinished { metrics, .. },
                ..
            }
            | EventKind::WorkflowV2 {
                event: iteron_protocol::WorkflowEvent::ChildFinished { metrics, .. },
                ..
            } => {
                self.turns = self.turns.saturating_add(metrics.provider_attempts);
                self.usage.add(&metrics.usage);
            }
            EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => {
                self.meta.provider_id = provider_id.clone();
                self.meta.model = model_id.clone();
            }
            EventKind::EffortChanged { effort, .. } => self.meta.effort = *effort,
            EventKind::Message { message }
                if self.title.is_empty() && message.role == Role::User =>
            {
                self.title = title_from_message(message);
            }
            EventKind::Done { outcome } => self.meta.last_outcome = parse_outcome(outcome),
            _ => {}
        }
        self.refresh_derived();
        Ok(())
    }

    fn refresh_derived(&mut self) {
        self.meta.turns = self.turns;
        self.meta.cost = self.cost_ledger.cost_state();
        self.meta.cache_hit = self.usage.cache_hit_ratio();
        self.meta.title = if self.title.is_empty() {
            "(untitled)".to_string()
        } else {
            self.title.clone()
        };
    }

    fn into_meta(self) -> SessionMeta {
        self.meta
    }
}

/// Serde adapter for `Option<Outcome>`: writes the `Debug` label as a string and reads it back
/// through [`parse_outcome`]. This sidesteps deriving `Deserialize` for `Outcome` (its
/// `BudgetExhausted(&'static str)` variant would force a `'de: 'static` bound on `SessionMeta`).
mod outcome_opt {
    use super::{Outcome, parse_outcome};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Outcome>, s: S) -> Result<S::Ok, S::Error> {
        let as_str: Option<String> = v.as_ref().map(|o| format!("{o:?}"));
        as_str.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Outcome>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        Ok(opt.as_deref().and_then(parse_outcome))
    }
}

// ---------------------------------------------------------------------------------------------
// Paths. The rollout, its per-run meta cache, and the compact index all live under `runs_dir`
// (in practice `.iteron/runs`). Co-locating the index there keeps the module dependent on the
// single directory it is handed, and the `.jsonl` listing scan naturally ignores the `.meta.json`
// and `.index` sidecars (different extensions), so they are never mistaken for rollouts.
// ---------------------------------------------------------------------------------------------

fn rollout_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".jsonl")
}

fn per_run_meta_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".meta.json")
}

fn index_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join("sessions.index")
}

fn delta_index_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join(SESSION_DELTA_INDEX_FILE)
}

fn delta_state_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join(SESSION_DELTA_STATE_FILE)
}

fn index_dirty_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join(SESSION_INDEX_DIRTY_FILE)
}

/// Invalidate every reachable global session-index generation after a private-content revocation.
/// Per-run sidecars are invalidated separately by the revocation owner. Stale direct refs are
/// harmless because the next rebuild publishes a fresh delta generation before any ref can match.
pub(crate) fn invalidate_rebuildable_indexes(runs_dir: &Path) -> io::Result<()> {
    for path in [
        index_path(runs_dir),
        delta_index_path(runs_dir),
        delta_state_path(runs_dir),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    crate::cache_io::sync_dir(runs_dir)
}

fn delta_ref_path(runs_dir: &Path, run: &RunId) -> PathBuf {
    let digest = Sha256::digest(run.0.as_bytes());
    runs_dir
        .join(SESSION_DELTA_REFS_DIR)
        .join(format!("{}.json", hex::encode(digest)))
}

/// A verified rollout line: the chain metadata plus the parsed event. The workhorse behind every
/// projection below; it re-verifies the hash chain exactly as `replay` does (a broken chain is an
/// error, not a warning) and additionally surfaces the per-line `tenant` and `hash` that `replay`
/// discards but the session projection and the fork cross-link need.
struct ReadLine {
    seq: Seq,
    tenant: TenantId,
    hash: String,
    end_bytes: u64,
    event: Event,
}

#[cfg(test)]
fn read_chain(path: &Path) -> Result<Vec<ReadLine>, RecordError> {
    let mut total_bytes = 0;
    let mut total_physical_lines = 0;
    read_chain_with_limits(path, &mut total_bytes, &mut total_physical_lines, None)
}

fn read_chain_budgeted(
    path: &Path,
    budget: &mut LogicalReplayBudget,
) -> Result<Vec<ReadLine>, RecordError> {
    read_chain_with_limits(
        path,
        &mut budget.bytes,
        &mut budget.physical_lines,
        Some(&mut budget.events),
    )
}

fn read_chain_with_limits(
    path: &Path,
    total_bytes: &mut u64,
    total_physical_lines: &mut usize,
    mut total_events: Option<&mut usize>,
) -> Result<Vec<ReadLine>, RecordError> {
    #[cfg(test)]
    READ_CHAIN_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let mut out = Vec::new();
    let mut prev = crate::ZERO_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut tenant: Option<TenantId> = None;
    let mut physical_bytes = 0u64;
    let mut genesis_tunables = tunables::GenesisTunablesState::default();
    // Tolerate a torn trailing line from a crash mid-append (code review): the resume path routes
    // through here, so a strict read would make a crashed run unresumable — exactly the tolerance
    // scan_tail already gives the append path. A partial FINAL line (no trailing newline) is dropped.
    crate::visit_record_lines_charged(path, total_bytes, total_physical_lines, |line| {
        physical_bytes = physical_bytes.saturating_add(line.len() as u64 + 1);
        if line.trim().is_empty() {
            return Ok(());
        }
        if let Some(total) = total_events.as_deref_mut() {
            admit_logical_events(total, 1)?;
        }
        let cl: crate::ChainLine = serde_json::from_str(line)?;
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
        let computed = crate::hash_line(&cl.prev, cl.seq, &cl.payload);
        if computed != cl.hash || cl.prev != prev {
            return Err(RecordError::ChainBroken {
                seq: cl.seq,
                stored: cl.hash,
                computed,
            });
        }
        // Resolve only after the immutable line hash is verified. A revoked/missing handle is a
        // terminal read failure for projections, resume, and every fork expansion.
        let mut payload = cl.payload;
        let runs_dir = path.parent().ok_or_else(|| {
            RecordError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rollout path has no runs directory",
            ))
        })?;
        crate::content_store::hydrate_event_payload(
            runs_dir,
            &TenantId(cl.tenant.clone()),
            &mut payload,
        )?;
        // Unknown event kinds deserialize to `EventKind::Unknown` (R5-review Risk 6), so a newer
        // writer's kinds do not fail the scan.
        let event: Event = serde_json::from_value(payload)?;
        validate_event_bounds(&event)?;
        genesis_tunables.observe(cl.seq, &event.kind)?;
        prev = cl.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
        out.push(ReadLine {
            seq: Seq(cl.seq),
            tenant: TenantId(cl.tenant),
            hash: cl.hash,
            end_bytes: physical_bytes,
            event,
        });
        Ok(())
    })?;
    Ok(out)
}

/// The run ids of every rollout file in `runs_dir` (the ground truth of which runs exist).
fn rollout_run_ids(runs_dir: &Path) -> Vec<RunId> {
    let mut ids = Vec::new();
    let Ok(rd) = std::fs::read_dir(runs_dir) else {
        return ids;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
            continue;
        }
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            let run = RunId(stem.to_string());
            if validate_run_id(&run).is_ok() {
                ids.push(run);
            }
        }
    }
    ids
}

fn file_mtime(path: &Path) -> Option<(u64, u32)> {
    let duration = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some((duration.as_secs(), duration.subsec_nanos()))
}

/// Return the exact physical length only when the file ends at a complete JSONL boundary.
fn complete_record_len(path: &Path) -> Option<u64> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return Some(0);
    }
    file.seek(SeekFrom::End(-1)).ok()?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).ok()?;
    (byte[0] == b'\n').then_some(len)
}

fn projection_digest(meta: &SessionMeta) -> Result<String, RecordError> {
    let mut canonical = meta.clone();
    canonical.projection_digest.clear();
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&canonical)?);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Normalize a floating-point cache field to a fixed point of this build's JSON codec. Some
/// feature combinations round a decimal by one ULP on the first parse; persisting the converged
/// value lets the projection digest bind the exact f64 without inventing an integrity tolerance.
fn json_f64_fixed_point(mut value: f64) -> Result<f64, RecordError> {
    if !value.is_finite() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session cache-hit ratio is not finite",
        )
        .into());
    }
    for _ in 0..8 {
        let encoded = serde_json::to_vec(&value)?;
        let next: f64 = serde_json::from_slice(&encoded)?;
        if next.to_bits() == value.to_bits() {
            return Ok(value);
        }
        value = next;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "session cache-hit ratio JSON encoding did not reach a fixed point",
    )
    .into())
}

struct PhysicalReceipt {
    seq: u64,
    hash: String,
    tenant: String,
}

#[cfg(test)]
fn charge_receipt_read(bytes: usize) {
    RECEIPT_BYTES_READ.with(|total| total.set(total.get().saturating_add(bytes as u64)));
}

#[cfg(not(test))]
fn charge_receipt_read(_bytes: usize) {}

/// Read the last nonblank complete chain line ending at the exact byte boundary. Work is
/// proportional to that physical line (plus one fixed chunk), not to the rollout prefix.
fn read_receipt_ending_at(path: &Path, end_bytes: u64) -> Option<PhysicalReceipt> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if end_bytes == 0 || end_bytes > len {
        return None;
    }
    file.seek(SeekFrom::Start(end_bytes - 1)).ok()?;
    let mut terminator = [0u8; 1];
    file.read_exact(&mut terminator).ok()?;
    charge_receipt_read(1);
    if terminator[0] != b'\n' {
        return None;
    }
    let mut cursor = end_bytes - 1;
    let mut reverse_chunks: Vec<Vec<u8>> = Vec::new();
    let mut candidate_len = 0usize;
    let mut scanned = 1u64;

    let line = loop {
        if cursor == 0 {
            if candidate_len == 0 {
                return None;
            }
            let mut line = Vec::with_capacity(candidate_len);
            for chunk in reverse_chunks.iter().rev() {
                line.extend_from_slice(chunk);
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            break line;
        }
        let start = cursor.saturating_sub(iteron_tunables::param_integer(
            "record.session.receipt_scan_chunk_bytes",
            RECEIPT_SCAN_CHUNK_BYTES,
        ) as u64);
        let chunk_len = usize::try_from(cursor - start).ok()?;
        let mut chunk = vec![0u8; chunk_len];
        file.seek(SeekFrom::Start(start)).ok()?;
        file.read_exact(&mut chunk).ok()?;
        charge_receipt_read(chunk_len);
        scanned = scanned.checked_add(chunk_len as u64)?;
        if scanned > crate::MAX_ROLLOUT_BYTES {
            return None;
        }

        if let Some(newline) = chunk.iter().rposition(|byte| *byte == b'\n') {
            let head = &chunk[newline + 1..];
            candidate_len = candidate_len.checked_add(head.len())?;
            if candidate_len.checked_add(1)? > crate::MAX_RECORD_LINE_BYTES {
                return None;
            }
            let nonblank = head
                .iter()
                .chain(reverse_chunks.iter().rev().flat_map(|part| part.iter()));
            if nonblank.clone().all(u8::is_ascii_whitespace) {
                // Skip a complete blank line and continue from its preceding delimiter.
                reverse_chunks.clear();
                candidate_len = 0;
                cursor = start + newline as u64;
                continue;
            }
            let mut line = Vec::with_capacity(candidate_len);
            line.extend_from_slice(head);
            for part in reverse_chunks.iter().rev() {
                line.extend_from_slice(part);
            }
            break line;
        }

        candidate_len = candidate_len.checked_add(chunk.len())?;
        if candidate_len.checked_add(1)? > crate::MAX_RECORD_LINE_BYTES {
            return None;
        }
        reverse_chunks.push(chunk);
        cursor = start;
    };

    let text = std::str::from_utf8(&line).ok()?;
    let chain: crate::ChainLine = serde_json::from_str(text).ok()?;
    (crate::hash_line(&chain.prev, chain.seq, &chain.payload) == chain.hash).then_some(
        PhysicalReceipt {
            seq: chain.seq,
            hash: chain.hash,
            tenant: chain.tenant,
        },
    )
}

fn read_tail_receipt(path: &Path) -> Option<(u64, u64, String, String)> {
    let len = std::fs::metadata(path).ok()?.len();
    let receipt = read_receipt_ending_at(path, len)?;
    Some((len, receipt.seq, receipt.hash, receipt.tenant))
}

struct GenesisProjection {
    tenant: TenantId,
    cwd: PathBuf,
    created_at: u64,
    agent_definition_tag: Option<String>,
    parent: Option<Provenance>,
}

fn read_genesis_projection(path: &Path) -> Option<GenesisProjection> {
    let Ok(file) = std::fs::File::open(path) else {
        return None;
    };
    let mut reader = std::io::BufReader::new(file);
    let Ok(Some((bytes, true, _))) = crate::read_bounded_line(&mut reader) else {
        return None;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return None;
    };
    let Ok(chain) = serde_json::from_str::<crate::ChainLine>(text) else {
        return None;
    };
    if chain.seq != 0
        || chain.prev != crate::ZERO_HASH
        || crate::hash_line(&chain.prev, chain.seq, &chain.payload) != chain.hash
    {
        return None;
    }
    let mut payload = chain.payload;
    let runs_dir = path.parent()?;
    if crate::content_store::hydrate_event_payload(
        runs_dir,
        &TenantId(chain.tenant.clone()),
        &mut payload,
    )
    .is_err()
    {
        return None;
    }
    let Ok(event) = serde_json::from_value::<Event>(payload) else {
        return None;
    };
    match event.kind {
        EventKind::RunStart {
            cwd,
            created_at,
            agent_definition_tag,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } => {
            let parent = match (parent_run, forked_at, parent_hash_at_seq) {
                (Some(parent_run), Some(forked_at), Some(parent_hash_at_seq)) => Some(Provenance {
                    parent_run: RunId(parent_run),
                    forked_at: Seq(forked_at),
                    parent_hash_at_seq,
                }),
                (None, None, None) => None,
                _ => return None,
            };
            Some(GenesisProjection {
                tenant: TenantId(chain.tenant),
                cwd: PathBuf::from(cwd),
                created_at,
                agent_definition_tag,
                parent,
            })
        }
        _ => None,
    }
}

fn genesis_matches_meta(path: &Path, meta: &SessionMeta) -> bool {
    read_genesis_projection(path).is_some_and(|genesis| {
        genesis.tenant == meta.tenant
            && genesis.cwd == meta.cwd
            && genesis.created_at == meta.created_at
            && genesis.agent_definition_tag == meta.agent_definition_tag
            && genesis.parent == meta.parent
    })
}

fn ancestry_matches_rollout(runs_dir: &Path, meta: &SessionMeta) -> bool {
    if meta.ancestry.len()
        > iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH)
    {
        return false;
    }
    let mut expected = meta.parent.clone();
    for receipt in meta.ancestry.iter().rev() {
        let Some(provenance) = expected.take() else {
            return false;
        };
        if receipt.run_id != provenance.parent_run
            || receipt.tenant != meta.tenant
            || receipt.through_seq != provenance.forked_at.0
            || receipt.tail_hash != provenance.parent_hash_at_seq
            || receipt.prefix_bytes == 0
            || receipt.prefix_bytes > crate::MAX_ROLLOUT_BYTES
            || receipt.observed_record_bytes < receipt.prefix_bytes
            || receipt.observed_record_bytes > crate::MAX_ROLLOUT_BYTES
            || receipt.observed_tail_seq < receipt.through_seq
        {
            return false;
        }
        let Ok(path) = rollout_path(runs_dir, &receipt.run_id) else {
            return false;
        };
        let prefix_matches =
            read_receipt_ending_at(&path, receipt.prefix_bytes).is_some_and(|physical| {
                physical.seq == receipt.through_seq
                    && physical.hash == receipt.tail_hash
                    && physical.tenant == receipt.tenant.0
            });
        if !prefix_matches {
            return false;
        }
        let Ok(metadata) = std::fs::metadata(&path) else {
            return false;
        };
        let observation_matches = if metadata.len() == receipt.observed_record_bytes {
            file_mtime(&path).is_some_and(|mtime| {
                mtime
                    == (
                        receipt.observed_updated_at,
                        receipt.observed_updated_at_subsec_nanos,
                    )
            })
        } else if metadata.len() > receipt.observed_record_bytes {
            read_receipt_ending_at(&path, receipt.observed_record_bytes).is_some_and(|physical| {
                physical.seq == receipt.observed_tail_seq
                    && physical.hash == receipt.observed_tail_hash
                    && physical.tenant == receipt.tenant.0
            })
        } else {
            false
        };
        if !observation_matches {
            return false;
        }
        let Some(genesis) = read_genesis_projection(&path) else {
            return false;
        };
        if genesis.tenant != meta.tenant {
            return false;
        }
        expected = genesis.parent;
    }
    expected.is_none()
}

fn projection_is_current(runs_dir: &Path, meta: &SessionMeta) -> bool {
    let Ok(path) = rollout_path(runs_dir, &meta.run_id) else {
        return false;
    };
    let digest_matches =
        projection_digest(meta).is_ok_and(|expected| expected == meta.projection_digest);
    let tail_matches = read_tail_receipt(&path).is_some_and(|(bytes, seq, hash, tenant)| {
        bytes == meta.record_bytes
            && Some(seq) == meta.record_tail_seq
            && hash == meta.record_tail_hash
            && tenant == meta.tenant.0
    });
    let mtime_matches = file_mtime(&path)
        .is_some_and(|mtime| mtime == (meta.updated_at, meta.updated_at_subsec_nanos));
    meta.pricing_schema_version == 2
        && meta.projection_schema_version == 3
        && crate::content_store::content_revocation_generation(runs_dir, &meta.tenant)
            .is_ok_and(|generation| generation == meta.content_revocation_generation)
        && meta.record_bytes > 0
        && digest_matches
        && tail_matches
        && mtime_matches
        && genesis_matches_meta(&path, meta)
        && ancestry_matches_rollout(runs_dir, meta)
}

/// Mutable caches cannot independently prove exact zero or a signed monetary amount. Those
/// structurally current projections remain useful index entries, but reads replay the rollout so
/// only an honest `Unknown` cost is ever accepted directly from cache bytes.
fn projection_covers_rollout(runs_dir: &Path, meta: &SessionMeta) -> bool {
    matches!(&meta.cost, CostState::Unknown { .. }) && projection_is_current(runs_dir, meta)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "record.session.pre_epoch_timestamp_secs",
            PRE_EPOCH_TIMESTAMP_SECS,
        ))
}

/// Deterministic title: the first user message's first non-empty line, char-truncated (SESS-3).
fn title_from_message(m: &Message) -> String {
    let text = m
        .content
        .iter()
        .find_map(|b| match b {
            Block::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("");
    title_from_text(text)
}

/// The stable first-prompt title projection shared by durable session metadata and live clients.
pub fn title_from_text(text: &str) -> String {
    let first_line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    const MAX: usize = 72;
    if first_line.chars().count() <= iteron_tunables::param_integer("record.session.max", MAX) {
        first_line.to_string()
    } else {
        let mut t: String = first_line
            .chars()
            .take(iteron_tunables::param_integer("record.session.max", MAX))
            .collect();
        t.push('…');
        t
    }
}

/// Map the kernel's recorded `Done{outcome}` (a `format!("{outcome:?}")` Debug string) back to an
/// [`Outcome`]. The `BudgetExhausted` reason is a `&'static str`, so a replay maps to the known
/// reason literal; an unrecognized string yields `None` (a projection convenience, not the record).
fn parse_outcome(s: &str) -> Option<Outcome> {
    let s = s.trim();
    match s {
        "Done" => Some(Outcome::Done),
        "Drained" => Some(Outcome::Drained),
        "Interrupted" => Some(Outcome::Interrupted),
        "Stuck" => Some(Outcome::Stuck),
        "HarnessError" => Some(Outcome::HarnessError),
        _ if s.starts_with("BudgetExhausted") => {
            let reason = if s.contains("max_turns") {
                "max_turns"
            } else if s.contains("max_usd") {
                "max_usd"
            } else if s.contains("unpriced_usd_ceiling") {
                "unpriced_usd_ceiling"
            } else if s.contains("max_tokens") {
                "max_tokens"
            } else if s.contains("max_wall_secs") {
                "max_wall_secs"
            } else if s.contains("max_consecutive_tool_errors") {
                "max_consecutive_tool_errors"
            } else if s.contains("verify_attempts") {
                "verify_attempts"
            } else {
                "budget"
            };
            Some(Outcome::BudgetExhausted(reason))
        }
        _ => None,
    }
}

/// Build a [`SessionMeta`] by replaying the run's record (the degrade path, and the truth `reindex`
/// rebuilds the cache from). Never re-reads disk state that belongs in the record: `created_at`
/// comes from the genesis header, not the clock.
fn meta_from_replay(
    runs_dir: &Path,
    run: &RunId,
    pricing: Option<Arc<dyn PricingPort>>,
) -> Result<SessionMeta, RecordError> {
    Ok(load_session_projection(runs_dir, run, pricing)?.into_meta())
}

fn load_session_projection(
    runs_dir: &Path,
    run: &RunId,
    pricing: Option<Arc<dyn PricingPort>>,
) -> Result<SessionProjection, RecordError> {
    let path = rollout_path(runs_dir, run)?;
    let complete_len_before = complete_record_len(&path);
    // Keep the child journal and its ancestry inside one logical read budget. The verified child
    // lines are reused below instead of opening and parsing the same near-cap file a second time.
    let mut replay_budget = LogicalReplayBudget::default();
    let lines = read_chain_budgeted(&path, &mut replay_budget)?;
    let physical_tail = lines.last().map(|line| (line.seq, line.hash.clone()));

    let mut tenant = TenantId::default();
    let mut cwd = PathBuf::new();
    let provider_id = String::new();
    let mut model = String::new();
    let mut effort = Effort::default();
    let mut agent_definition_tag = None;
    let mut created_at = 0u64;
    let mut parent: Option<Provenance> = None;

    if let Some(g) = lines.first() {
        tenant = g.tenant.clone();
        if let EventKind::RunStart {
            cwd: c,
            model: m,
            effort: ef,
            agent_definition_tag: tag,
            created_at: ca,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } = &g.event.kind
        {
            cwd = PathBuf::from(c);
            model = m.clone();
            effort = *ef;
            agent_definition_tag = tag.clone();
            created_at = *ca;
            if let (Some(pr), Some(fa), Some(ph)) =
                (parent_run.clone(), forked_at, parent_hash_at_seq.clone())
            {
                parent = Some(Provenance {
                    parent_run: RunId(pr),
                    forked_at: Seq(*fa),
                    parent_hash_at_seq: ph,
                });
            }
        }
    }

    // Physical fields above describe the child journal itself, but session activity is a logical
    // projection. A fork stores only its suffix, so usage/cost/title/selection/outcome must include
    // the bounded, cross-link-verified parent prefix. Preloading `lines` means every journal is
    // charged and parsed at most once in this top-level projection.
    let mut ancestry = Vec::new();
    let logical_events = expand_scoped_from(
        runs_dir,
        run,
        None,
        0,
        &mut replay_budget,
        Some(lines),
        &mut ancestry,
    )?;

    let mut projection = SessionProjection {
        runs_dir: runs_dir.to_path_buf(),
        meta: SessionMeta {
            pricing_schema_version: 2,
            projection_schema_version: 3,
            content_revocation_generation: crate::content_store::content_revocation_generation(
                runs_dir, &tenant,
            )?,
            run_id: run.clone(),
            tenant,
            cwd,
            provider_id,
            model,
            effort,
            agent_definition_tag,
            title: String::new(),
            created_at,
            updated_at: 0,
            updated_at_subsec_nanos: 0,
            record_bytes: 0,
            record_tail_seq: None,
            record_tail_hash: String::new(),
            projection_digest: String::new(),
            ancestry,
            turns: 0,
            cost: CostState::Zero,
            cache_hit: 0.0,
            last_outcome: None,
            parent,
        },
        turns: 0,
        usage: Usage::default(),
        title: String::new(),
        cost_ledger: Ledger::new(),
        pricing_replay: pricing.map(PricingReplay::trusted).unwrap_or_default(),
    };
    for scoped in &logical_events {
        projection.observe_scoped(&scoped.event, &scoped.tenant, &scoped.run_id)?;
    }
    let complete_len_after = complete_record_len(&path);
    if let (Some(before), Some(after)) = (complete_len_before, complete_len_after)
        && before == after
    {
        projection.meta.record_bytes = before;
        if let Some((seq, hash)) = physical_tail {
            projection.meta.record_tail_seq = Some(seq.0);
            projection.meta.record_tail_hash = hash;
        }
    }
    let (updated_at, updated_at_subsec_nanos) =
        file_mtime(&path).unwrap_or((projection.meta.created_at, 0));
    projection.meta.updated_at = updated_at;
    projection.meta.updated_at_subsec_nanos = updated_at_subsec_nanos;
    projection.refresh_derived();
    projection.meta.cache_hit = json_f64_fixed_point(projection.meta.cache_hit)?;
    projection.meta.projection_digest = projection_digest(&projection.meta)?;
    Ok(projection)
}

struct IndexRead {
    entries: Vec<SessionMeta>,
    exact: bool,
}

fn max_index_scan_lines(live_runs: usize) -> usize {
    live_runs.saturating_mul(iteron_tunables::param_integer(
        "record.session.index_scan_lines_per_live_run",
        INDEX_SCAN_LINES_PER_LIVE_RUN,
    ))
}

/// Read only a live-run-proportional prefix. Any malformed, torn, oversized, or over-limit cache
/// invalidates the whole prefix; trusting an early append-era entry could otherwise return an old
/// projection whose newer line was beyond the read bound.
fn read_index(runs_dir: &Path, live_runs: usize) -> IndexRead {
    // V2 starts with one content-free format/order marker. The extra allowance keeps an empty V2
    // index readable and does not change the live-run-proportional body bound.
    let max_lines = max_index_scan_lines(live_runs).saturating_add(1);
    let Ok(scan) = crate::cache_io::scan_index_lines(&index_path(runs_dir), max_lines) else {
        return IndexRead {
            entries: Vec::new(),
            exact: false,
        };
    };
    debug_assert!(scan.lines_examined <= max_lines.saturating_add(1));
    let mut lines = scan.lines;
    let has_v2_header = lines
        .first()
        .is_some_and(|line| line.as_slice() == SESSION_INDEX_HEADER);
    if has_v2_header {
        lines.remove(0);
    }
    let physical_lines = lines.len();
    if !scan.complete {
        return IndexRead {
            entries: Vec::new(),
            exact: false,
        };
    }
    let mut entries = Vec::with_capacity(physical_lines);
    for line in lines {
        if line.iter().all(u8::is_ascii_whitespace) {
            return IndexRead {
                entries: Vec::new(),
                exact: false,
            };
        }
        let Ok(meta) = private_cache::read_index_line(runs_dir, &line) else {
            return IndexRead {
                entries: Vec::new(),
                exact: false,
            };
        };
        entries.push(meta);
    }
    IndexRead {
        entries,
        exact: true,
    }
}

struct BaseIndexSnapshot {
    reader: BufReader<File>,
    generation: u64,
    header_end: u64,
    len: u64,
}

struct DeltaIndexSnapshot {
    file: File,
    generation: u64,
    header_end: u64,
    high_water: u64,
    rows: u64,
}

fn open_base_index(runs_dir: &Path) -> io::Result<BaseIndexSnapshot> {
    let file = File::open(index_path(runs_dir))?;
    let metadata = file.metadata()?;
    let generation = session_index_generation(&metadata);
    let mut reader = BufReader::new(file);
    let Some((header, true)) = read_bounded_index_line(&mut reader)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session index header is missing or torn",
        ));
    };
    if header != SESSION_INDEX_HEADER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session index version/order is unsupported",
        ));
    }
    let header_end = reader.stream_position()?;
    Ok(BaseIndexSnapshot {
        reader,
        generation,
        header_end,
        len: metadata.len(),
    })
}

fn open_delta_index(runs_dir: &Path) -> io::Result<DeltaIndexSnapshot> {
    let file = File::open(delta_index_path(runs_dir))?;
    let high_water = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let Some((header, true)) = read_bounded_index_line(&mut reader)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta header is missing or torn",
        ));
    };
    let header: SessionDeltaHeader = serde_json::from_slice(&header)?;
    if header.version != SESSION_DELTA_INDEX_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta version is unsupported",
        ));
    }
    let state = read_delta_state(runs_dir)?;
    let header_end = reader.stream_position()?;
    if state.version != SESSION_DELTA_INDEX_VERSION
        || state.generation != header.generation
        || state.high_water != high_water
        || state.high_water < header_end
        || (state.rows == 0) != (state.high_water == header_end)
        || state.rows > SESSION_DELTA_HARD_LIMITS.rows
        || state.high_water > SESSION_DELTA_HARD_LIMITS.bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta state does not match its bounded log snapshot",
        ));
    }
    Ok(DeltaIndexSnapshot {
        file: reader.into_inner(),
        generation: header.generation,
        header_end,
        high_water,
        rows: state.rows,
    })
}

fn read_delta_state(runs_dir: &Path) -> io::Result<SessionDeltaState> {
    let file = File::open(delta_state_path(runs_dir))?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta state exceeds its byte bound",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn write_delta_state_unlocked(
    runs_dir: &Path,
    state: SessionDeltaState,
) -> Result<(), RecordError> {
    let bytes = serde_json::to_vec(&state)?;
    if bytes.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta state exceeds its byte bound",
        )
        .into());
    }
    crate::cache_io::atomic_replace(&delta_state_path(runs_dir), &bytes)?;
    Ok(())
}

fn read_delta_ref(runs_dir: &Path, run: &RunId) -> Option<SessionDeltaRef> {
    let file = File::open(delta_ref_path(runs_dir, run)).ok()?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 1024 {
        return None;
    }
    let reference: SessionDeltaRef = serde_json::from_slice(&bytes).ok()?;
    (reference.version == SESSION_DELTA_INDEX_VERSION
        && reference.delta_high_water > reference.byte_offset
        && reference.delta_high_water <= SESSION_DELTA_HARD_LIMITS.bytes)
        .then_some(reference)
}

fn read_previous_delta_line(
    file: &mut File,
    line_end: u64,
    floor: u64,
) -> io::Result<Option<(u64, Vec<u8>)>> {
    if line_end <= floor {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(line_end - 1))?;
    let mut trailing = [0u8; 1];
    file.read_exact(&mut trailing)?;
    if trailing[0] != b'\n' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta has a torn trailing line",
        ));
    }

    let body_end = line_end - 1;
    let max = crate::cache_io::MAX_INDEX_LINE_BYTES as u64;
    let mut search_end = body_end;
    let mut start = floor;
    while search_end > floor {
        let chunk_start = search_end.saturating_sub(8 * 1024).max(floor);
        if body_end.saturating_sub(chunk_start) > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session delta line exceeds the cache byte limit",
            ));
        }
        let mut chunk = vec![0u8; (search_end - chunk_start) as usize];
        file.seek(SeekFrom::Start(chunk_start))?;
        file.read_exact(&mut chunk)?;
        if let Some(index) = chunk.iter().rposition(|byte| *byte == b'\n') {
            start = chunk_start + index as u64 + 1;
            break;
        }
        search_end = chunk_start;
    }
    let length = body_end.saturating_sub(start);
    if length == 0 || length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta line is empty or oversized",
        ));
    }
    let mut line = vec![0u8; length as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut line)?;
    Ok(Some((start, line)))
}

fn page_cursor(
    base_generation: u64,
    delta: Option<&DeltaIndexSnapshot>,
    phase: SessionPagePhase,
    byte_offset: u64,
) -> SessionPageCursor {
    SessionPageCursor {
        base_generation,
        delta_generation: delta.map_or(0, |snapshot| snapshot.generation),
        delta_high_water: delta.map_or(0, |snapshot| snapshot.high_water),
        phase,
        byte_offset,
    }
}

fn page_snapshot_changed(had_cursor: bool) -> SessionPage {
    if had_cursor {
        SessionPage {
            index_ready: true,
            cursor_stale: true,
            ..SessionPage::default()
        }
    } else {
        SessionPage::default()
    }
}

fn page_rebuild_needed(had_cursor: bool) -> SessionPage {
    if had_cursor {
        SessionPage {
            cursor_stale: true,
            ..SessionPage::default()
        }
    } else {
        SessionPage {
            rebuild_recommended: true,
            ..SessionPage::default()
        }
    }
}

fn index_publication_incomplete(runs_dir: &Path) -> bool {
    index_dirty_path(runs_dir).exists()
}

fn base_snapshot_is_current(runs_dir: &Path, expected_generation: u64) -> bool {
    if expected_generation == 0 {
        return !index_path(runs_dir).exists();
    }
    std::fs::metadata(index_path(runs_dir))
        .is_ok_and(|metadata| session_index_generation(&metadata) == expected_generation)
}

fn delta_snapshot_is_current(runs_dir: &Path, expected: Option<&DeltaIndexSnapshot>) -> bool {
    match expected {
        None => !delta_index_path(runs_dir).exists() && !delta_state_path(runs_dir).exists(),
        Some(expected) => open_delta_index(runs_dir).is_ok_and(|current| {
            current.generation == expected.generation
                && current.high_water == expected.high_water
                && current.rows == expected.rows
        }),
    }
}

fn delta_tail_is_published(runs_dir: &Path, snapshot: &mut DeltaIndexSnapshot) -> bool {
    if snapshot.high_water == snapshot.header_end {
        return snapshot.rows == 0;
    }
    let Ok(Some((line_start, line))) =
        read_previous_delta_line(&mut snapshot.file, snapshot.high_water, snapshot.header_end)
    else {
        return false;
    };
    let Ok(owner) = private_cache::index_line_owner(&line) else {
        return false;
    };
    read_delta_ref(runs_dir, &owner).is_some_and(|reference| {
        reference.generation == snapshot.generation
            && reference.byte_offset == line_start
            && reference.delta_high_water == snapshot.high_water
    })
}

/// Read one newest-first window without listing run filenames or hydrating unrelated rollouts.
/// A reverse-seek incremental log overlays the atomic base index, so a turn updates the picker in
/// O(1) without rewriting or reading all sessions. Cursors bind both snapshots and fail stale when
/// either changes; a complete traversal of an unchanged snapshot is therefore O(N), not O(N²).
pub fn page(
    runs_dir: &Path,
    tenant: &TenantId,
    repo: Option<&Path>,
    cursor: Option<SessionPageCursor>,
    limit: Option<usize>,
) -> SessionPage {
    let had_cursor = cursor.is_some();
    if index_publication_incomplete(runs_dir) {
        return SessionPage::default();
    }
    let limit = limit
        .unwrap_or_else(|| {
            iteron_tunables::param_usize(
                "record.session.default_session_page_size",
                DEFAULT_SESSION_PAGE_SIZE,
            )
        })
        .clamp(1, max_session_page_size());
    let mut base = match open_base_index(runs_dir) {
        Ok(snapshot) => Some(snapshot),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return page_rebuild_needed(had_cursor),
    };
    let mut delta = match open_delta_index(runs_dir) {
        Ok(snapshot) => Some(snapshot),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return page_rebuild_needed(had_cursor),
    };
    if delta
        .as_mut()
        .is_some_and(|snapshot| !delta_tail_is_published(runs_dir, snapshot))
    {
        return page_rebuild_needed(had_cursor);
    }
    if base.is_none() && delta.is_none() {
        return page_rebuild_needed(had_cursor);
    }
    let base_generation = base.as_ref().map_or(0, |snapshot| snapshot.generation);
    let delta_generation = delta.as_ref().map_or(0, |snapshot| snapshot.generation);
    let delta_high_water = delta.as_ref().map_or(0, |snapshot| snapshot.high_water);
    if let Some(cursor) = cursor
        && (cursor.base_generation != base_generation
            || cursor.delta_generation != delta_generation
            || cursor.delta_high_water != delta_high_water)
    {
        return SessionPage {
            index_ready: true,
            cursor_stale: true,
            ..SessionPage::default()
        };
    }
    #[cfg(test)]
    AFTER_PAGE_SNAPSHOT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });

    let canonical_repo = repo.and_then(|path| path.canonicalize().ok());
    let scan_ceiling = iteron_tunables::param_usize(
        "record.session.max_session_page_scan_lines",
        MAX_SESSION_PAGE_SCAN_LINES,
    )
    .clamp(limit.saturating_add(1), MAX_SESSION_PAGE_SCAN_LINES);
    let mut result = SessionPage {
        index_ready: true,
        ..SessionPage::default()
    };
    let mut phase = cursor.map_or(
        if delta.is_some() {
            SessionPagePhase::Delta
        } else {
            SessionPagePhase::Base
        },
        |cursor| cursor.phase,
    );
    let mut delta_offset = cursor
        .filter(|cursor| cursor.phase == SessionPagePhase::Delta)
        .map_or(delta_high_water, |cursor| cursor.byte_offset);
    let mut base_offset = cursor
        .filter(|cursor| cursor.phase == SessionPagePhase::Base)
        .map_or_else(
            || base.as_ref().map_or(0, |snapshot| snapshot.header_end),
            |cursor| cursor.byte_offset,
        );
    let mut seen = HashSet::new();

    while result.examined < scan_ceiling {
        let (line, retry_offset) = match phase {
            SessionPagePhase::Delta => {
                let Some(snapshot) = delta.as_mut() else {
                    phase = SessionPagePhase::Base;
                    continue;
                };
                let line_end = delta_offset;
                match read_previous_delta_line(&mut snapshot.file, line_end, snapshot.header_end) {
                    Ok(Some((line_start, line))) => {
                        delta_offset = line_start;
                        (line, line_end)
                    }
                    Ok(None) => {
                        phase = SessionPagePhase::Base;
                        continue;
                    }
                    Err(_) => return page_rebuild_needed(had_cursor),
                }
            }
            SessionPagePhase::Base => {
                let Some(snapshot) = base.as_mut() else {
                    break;
                };
                if snapshot.reader.seek(SeekFrom::Start(base_offset)).is_err() {
                    return page_rebuild_needed(had_cursor);
                }
                let line_start = base_offset;
                let line = match read_bounded_index_line(&mut snapshot.reader) {
                    Ok(Some((line, true))) => line,
                    Ok(None) => break,
                    Ok(Some((_, false))) | Err(_) => return page_rebuild_needed(had_cursor),
                };
                base_offset = snapshot.reader.stream_position().unwrap_or(snapshot.len);
                (line, line_start)
            }
        };
        result.examined = result.examined.saturating_add(1);
        let Ok(owner) = private_cache::index_line_owner(&line) else {
            return page_rebuild_needed(had_cursor);
        };
        let latest_delta = read_delta_ref(runs_dir, &owner);
        let is_latest = match phase {
            SessionPagePhase::Delta => match latest_delta {
                Some(reference)
                    if reference.generation == delta_generation
                        && reference.byte_offset == delta_offset
                        && reference.delta_high_water <= delta_high_water =>
                {
                    true
                }
                Some(reference)
                    if reference.generation == delta_generation
                        && reference.byte_offset > delta_offset =>
                {
                    false
                }
                // The newest log row is published before its direct latest-reference. Treat that
                // tiny cross-file window (or cache damage) as not-ready instead of hiding the run.
                _ => return page_rebuild_needed(had_cursor),
            },
            SessionPagePhase::Base => {
                latest_delta.is_none_or(|reference| reference.generation != delta_generation)
            }
        };
        if !is_latest || !seen.insert(owner.0.clone()) {
            continue;
        }
        let Ok(meta) = private_cache::read_index_line(runs_dir, &line) else {
            // A selected latest row must pass the full owner/surface/private-content gate. Older
            // rows are skipped by direct reference before hydration because their CAS derivative
            // is intentionally no longer retained.
            return page_rebuild_needed(had_cursor);
        };
        if meta.tenant != *tenant
            || repo.is_some_and(|requested| {
                !same_repo(&meta.cwd, requested, canonical_repo.as_deref())
            })
            || !projection_is_current(runs_dir, &meta)
        {
            continue;
        }
        if result.sessions.len() == limit {
            result.has_more = true;
            result.next_cursor = Some(page_cursor(
                base_generation,
                delta.as_ref(),
                phase,
                retry_offset,
            ));
            break;
        }
        result.sessions.push(meta);
    }

    // A mixed-tenant/repository index may require another bounded scan to fill one logical page.
    // Keep that continuation explicit rather than turning one request into O(total sessions).
    if result.examined == scan_ceiling {
        result.has_more = true;
        let byte_offset = match phase {
            SessionPagePhase::Delta => delta_offset,
            SessionPagePhase::Base => base_offset,
        };
        result.next_cursor = Some(page_cursor(
            base_generation,
            delta.as_ref(),
            phase,
            byte_offset,
        ));
    }
    if index_publication_incomplete(runs_dir)
        || !base_snapshot_is_current(runs_dir, base_generation)
        || !delta_snapshot_is_current(runs_dir, delta.as_ref())
    {
        return page_snapshot_changed(had_cursor);
    }
    result
}

fn session_index_generation(metadata: &std::fs::Metadata) -> u64 {
    let mut digest = Sha256::new();
    digest.update(metadata.len().to_be_bytes());
    if let Ok(modified) = metadata.modified().and_then(|time| {
        time.duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)
    }) {
        digest.update(modified.as_secs().to_be_bytes());
        digest.update(modified.subsec_nanos().to_be_bytes());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        digest.update(metadata.dev().to_be_bytes());
        digest.update(metadata.ino().to_be_bytes());
        digest.update(metadata.ctime().to_be_bytes());
        digest.update(metadata.ctime_nsec().to_be_bytes());
    }
    let bytes: [u8; 8] = digest.finalize()[..8].try_into().unwrap_or([0; 8]);
    u64::from_be_bytes(bytes)
}

fn read_bounded_index_line<R: BufRead>(reader: &mut R) -> io::Result<Option<(Vec<u8>, bool)>> {
    let max = crate::cache_io::MAX_INDEX_LINE_BYTES;
    let mut bytes = Vec::new();
    let consumed = (&mut *reader)
        .take((max + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if consumed == 0 {
        return Ok(None);
    }
    if consumed > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session index line exceeds its byte bound",
        ));
    }
    let terminated = bytes.last() == Some(&b'\n');
    if terminated {
        bytes.pop();
    }
    Ok(Some((bytes, terminated)))
}

// Legacy plaintext index bytes are still useful as adversarial fixtures: readers must reject or
// rebuild these pre-private-cache encodings instead of accidentally serving them. Keep the encoder
// out of production so no caller can create a plaintext session index.
#[cfg(test)]
fn encode_index<'a>(
    metas: impl IntoIterator<Item = &'a SessionMeta>,
) -> Result<Vec<u8>, RecordError> {
    let mut ordered: Vec<&SessionMeta> = metas.into_iter().collect();
    ordered.sort_by(|left, right| left.run_id.0.cmp(&right.run_id.0));
    let mut bytes = Vec::new();
    for meta in ordered {
        let line = serde_json::to_vec(meta)?;
        let physical_len = line.len().checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "session index line length overflow",
            )
        })?;
        if physical_len > crate::cache_io::MAX_INDEX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "session index entry is {physical_len} bytes, exceeding the {}-byte limit",
                    crate::cache_io::MAX_INDEX_LINE_BYTES
                ),
            )
            .into());
        }
        bytes.extend_from_slice(&line);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn rewrite_index_unlocked<'a>(
    runs_dir: &Path,
    metas: impl IntoIterator<Item = &'a SessionMeta>,
) -> Result<(), RecordError> {
    private_cache::write_index(runs_dir, &index_path(runs_dir), metas)?;
    reset_delta_index_unlocked(runs_dir)?;
    clear_index_dirty_unlocked(runs_dir)?;
    Ok(())
}

fn mark_index_dirty_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
    crate::cache_io::atomic_replace(&index_dirty_path(runs_dir), b"publication-incomplete-v1\n")?;
    Ok(())
}

fn clear_index_dirty_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
    match std::fs::remove_file(index_dirty_path(runs_dir)) {
        Ok(()) => crate::cache_io::sync_dir(runs_dir)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn compact_session_index_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
    mark_index_dirty_unlocked(runs_dir)?;
    let metas = rollout_run_ids(runs_dir)
        .into_iter()
        .filter_map(|run| meta(runs_dir, &run).ok())
        .collect::<Vec<_>>();
    rewrite_index_unlocked(runs_dir, metas.iter())
}

static BACKGROUND_SESSION_COMPACTIONS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn schedule_session_index_compaction(runs_dir: &Path) {
    let runs_dir = runs_dir
        .canonicalize()
        .unwrap_or_else(|_| runs_dir.to_path_buf());
    let active = BACKGROUND_SESSION_COMPACTIONS.get_or_init(|| Mutex::new(HashSet::new()));
    {
        let Ok(mut active) = active.lock() else {
            return;
        };
        if active.contains(&runs_dir) || active.len() >= max_background_session_compactions() {
            return;
        }
        active.insert(runs_dir.clone());
    }
    let thread_dir = runs_dir.clone();
    let spawned = std::thread::Builder::new()
        .name("iteron-session-index-compact".into())
        .spawn(move || {
            let _ = crate::cache_io::with_session_index_lock(&thread_dir, || {
                compact_session_index_unlocked(&thread_dir)
                    .map_err(|error| io::Error::other(error.to_string()))
            });
            if let Some(active) = BACKGROUND_SESSION_COMPACTIONS.get()
                && let Ok(mut active) = active.lock()
            {
                active.remove(&thread_dir);
            }
        });
    if spawned.is_err()
        && let Ok(mut active) = active.lock()
    {
        active.remove(&runs_dir);
    }
}

fn fresh_delta_generation() -> Result<u64, RecordError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|_| io::Error::other("entropy unavailable for session delta generation"))?;
    let generation = u64::from_be_bytes(bytes);
    Ok(generation.max(1))
}

fn encoded_delta_header(generation: u64) -> Result<Vec<u8>, RecordError> {
    let mut bytes = serde_json::to_vec(&SessionDeltaHeader {
        version: SESSION_DELTA_INDEX_VERSION,
        generation,
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn reset_delta_index_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
    let generation = fresh_delta_generation()?;
    let bytes = encoded_delta_header(generation)?;
    crate::cache_io::atomic_replace(&delta_index_path(runs_dir), &bytes)?;
    write_delta_state_unlocked(
        runs_dir,
        SessionDeltaState {
            version: SESSION_DELTA_INDEX_VERSION,
            generation,
            rows: 0,
            high_water: bytes.len() as u64,
        },
    )?;
    Ok(())
}

fn delta_compaction_rows() -> u64 {
    iteron_tunables::param_u64(
        "record.session.default_session_delta_compact_rows",
        DEFAULT_SESSION_DELTA_COMPACT_ROWS,
    )
    .clamp(1, SESSION_DELTA_HARD_LIMITS.rows)
}

fn delta_compaction_bytes() -> u64 {
    iteron_tunables::param_u64(
        "record.session.default_session_delta_compact_bytes",
        DEFAULT_SESSION_DELTA_COMPACT_BYTES,
    )
    .clamp(1, SESSION_DELTA_HARD_LIMITS.bytes)
}

fn append_delta_index_unlocked(
    runs_dir: &Path,
    projected: &SessionMeta,
) -> Result<bool, RecordError> {
    let path = delta_index_path(runs_dir);
    if !path.exists() {
        reset_delta_index_unlocked(runs_dir)?;
    }
    let snapshot = open_delta_index(runs_dir)?;
    let staged = private_cache::stage_index_line(runs_dir, projected)?;
    let physical_len = staged.manifest().len().checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta line length overflow",
        )
    })?;
    if physical_len > crate::cache_io::MAX_INDEX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta manifest exceeds the cache byte limit",
        )
        .into());
    }
    let next_rows = snapshot.rows.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "session delta row count overflow",
        )
    })?;
    let next_high_water = snapshot
        .high_water
        .checked_add(physical_len as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "session delta byte count overflow",
            )
        })?;
    if next_rows > SESSION_DELTA_HARD_LIMITS.rows
        || next_high_water > SESSION_DELTA_HARD_LIMITS.bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "session delta reached its hard bound and requires background compaction",
        )
        .into());
    }

    // Make the private derivative reachable before publishing its small public manifest. The
    // index is rebuildable, so a crash between these writes can leak only an unreachable cache
    // derivative; it can never publish content or bless an incomplete authoritative record.
    let manifest = staged.manifest().to_vec();
    staged.commit()?;
    let mut file = OpenOptions::new().append(true).open(&path)?;
    let byte_offset = file.metadata()?.len();
    file.write_all(&manifest)?;
    file.write_all(b"\n")?;
    // The projection is rebuildable, but a successful turn-boundary publication must remain
    // immediately pageable after a process restart. Durably publish the append before the direct
    // latest-reference below can make it reachable; a crash in between is detected as not-ready
    // and repaired off the foreground path.
    file.sync_data()?;
    write_delta_state_unlocked(
        runs_dir,
        SessionDeltaState {
            version: SESSION_DELTA_INDEX_VERSION,
            generation: snapshot.generation,
            rows: next_rows,
            high_water: next_high_water,
        },
    )?;

    let reference = serde_json::to_vec(&SessionDeltaRef {
        version: SESSION_DELTA_INDEX_VERSION,
        generation: snapshot.generation,
        byte_offset,
        delta_high_water: next_high_water,
    })?;
    std::fs::create_dir_all(runs_dir.join(SESSION_DELTA_REFS_DIR))?;
    crate::cache_io::atomic_replace_private(
        &delta_ref_path(runs_dir, &projected.run_id),
        &reference,
    )?;
    Ok(next_rows >= delta_compaction_rows() || next_high_water >= delta_compaction_bytes())
}

/// Merge candidate projections with the latest structurally current index snapshot while holding
/// the stable cross-process lock. This never replays an unrelated rollout: invalid or absent
/// entries are left for a later `list`/`reindex` repair, while concurrent valid upserts are
/// preserved. Exact `Zero`/`Known` entries are stored but remain replay-only on reads.
fn merge_rewrite_index(
    runs_dir: &Path,
    proposed: impl IntoIterator<Item = SessionMeta>,
) -> Result<(), RecordError> {
    let proposed: Vec<SessionMeta> = proposed.into_iter().collect();
    crate::cache_io::with_session_index_lock(runs_dir, || {
        if let Err(error) = mark_index_dirty_unlocked(runs_dir) {
            return Ok(Err(error));
        }
        let existing: HashSet<String> = rollout_run_ids(runs_dir)
            .into_iter()
            .map(|run| run.0)
            .collect();
        let current = read_index(runs_dir, existing.len());
        let mut by_run = HashMap::new();
        if current.exact {
            for candidate in current.entries {
                if existing.contains(&candidate.run_id.0)
                    && projection_is_current(runs_dir, &candidate)
                {
                    by_run.insert(candidate.run_id.0.clone(), candidate);
                }
            }
        }
        // Proposed values win only while they still match the exact current physical tail.
        // A concurrent append therefore drops an older proposal instead of blessing it.
        for candidate in proposed {
            if existing.contains(&candidate.run_id.0) && projection_is_current(runs_dir, &candidate)
            {
                by_run.insert(candidate.run_id.0.clone(), candidate);
            }
        }
        Ok(rewrite_index_unlocked(runs_dir, by_run.values()))
    })??;
    Ok(())
}

fn write_meta_sidecar(runs_dir: &Path, projected: &SessionMeta) -> Result<(), RecordError> {
    let path = per_run_meta_path(runs_dir, &projected.run_id)?;
    private_cache::write_sidecar(runs_dir, &path, projected, false)
}

/// The metadata for one run: a current cache may directly serve only an honest `Unknown` cost;
/// `Zero` and `Known` both require replay because mutable cache bytes cannot prove either exact
/// monetary claim. A missing, stale, or corrupt cache degrades to the record (R5 design §2.5).
pub fn meta(runs_dir: &Path, run: &RunId) -> Result<SessionMeta, RecordError> {
    let cache = per_run_meta_path(runs_dir, run)?;
    if let Ok(bytes) = crate::cache_io::read_session_meta(&cache)
        && let Ok(m) = private_cache::read_sidecar(runs_dir, &bytes)
        && m.run_id == *run
        && projection_covers_rollout(runs_dir, &m)
    {
        return Ok(m);
    }
    meta_from_replay(runs_dir, run, None)
}

/// Rebuild monetary metadata from the durable record with an explicit operator trust port. Cached
/// `Known` values are never accepted because they do not carry the HMAC evidence needed to verify
/// them independently.
pub fn meta_with_pricing(
    runs_dir: &Path,
    run: &RunId,
    pricing: Arc<dyn PricingPort>,
) -> Result<SessionMeta, RecordError> {
    meta_from_replay(runs_dir, run, Some(pricing))
}

/// List the sessions in `runs_dir` for `tenant`, newest first (R5 design §2.5). Listing is
/// O(runs), not O(historical turn writes): at most two index lines per live rollout plus one bound
/// detector are read. An append-era, torn, oversized, or corrupt index is discarded wholesale;
/// per-run cache/replay then supplies a complete atomic compacted snapshot. Never errors — a run
/// whose record cannot be projected is skipped, matching the existing degrade-to-scan posture.
/// This foreground read never rebuilds the global index: stale/active sessions are repaired only
/// by explicit [`reindex`] or a post-paint maintainer.
pub fn list(runs_dir: &Path, tenant: &TenantId) -> Vec<SessionMeta> {
    let existing: HashSet<String> = rollout_run_ids(runs_dir).into_iter().map(|r| r.0).collect();

    let mut by_run: HashMap<String, SessionMeta> = HashMap::new();
    let index = read_index(runs_dir, existing.len());
    // Fast path: a bounded legacy/V2 index, last write wins. Entries whose rollout was deleted or
    // whose record cursor is stale are ignored; a read never turns that miss into global I/O.
    for m in index.entries {
        let current = existing.contains(&m.run_id.0) && projection_is_current(runs_dir, &m);
        if current {
            let run = m.run_id.0.clone();
            if matches!(&m.cost, CostState::Unknown { .. }) {
                by_run.insert(run, m);
            }
        }
    }
    // Degrade: any rollout the index does not cover is projected from its per-run cache or record.
    for run in &existing {
        if !by_run.contains_key(run)
            && let Ok(m) = meta(runs_dir, &RunId(run.clone()))
        {
            by_run.insert(run.clone(), m);
        }
    }

    let mut metas: Vec<SessionMeta> = by_run
        .into_values()
        .filter(|m| &m.tenant == tenant)
        .collect();
    // Newest first; ties broken by run id for a stable, reproducible order (ADR-006 rule 4).
    metas.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.updated_at_subsec_nanos.cmp(&a.updated_at_subsec_nanos))
            .then_with(|| b.run_id.0.cmp(&a.run_id.0))
    });
    metas
}

/// True when a recorded working directory names the requested repository. The literal comparison is
/// the fast, normal answer (a run records the CLI's already-canonicalized repo). The canonical
/// comparison is the fallback so a record written under `/var/…` and a `--repo` canonicalized to
/// `/private/var/…` are not read as two different repositories; `canonical_requested` is resolved
/// once by the caller rather than once per session.
fn same_repo(recorded: &Path, requested: &Path, canonical_requested: Option<&Path>) -> bool {
    if recorded == requested {
        return true;
    }
    match (recorded.canonicalize(), canonical_requested) {
        (Ok(left), Some(right)) => left == right,
        _ => false,
    }
}

/// [`list`], optionally narrowed to the runs recorded in one repository. `Some(repo)` is the exact
/// scope [`most_recent`] selects from, so a listing and a continue cannot disagree about what "this
/// repository" means; `None` lists every repository the runs dir holds.
pub fn list_scoped(runs_dir: &Path, tenant: &TenantId, repo: Option<&Path>) -> Vec<SessionMeta> {
    let metas = list(runs_dir, tenant);
    let Some(repo) = repo else {
        return metas;
    };
    let canonical = repo.canonicalize().ok();
    metas
        .into_iter()
        .filter(|m| same_repo(&m.cwd, repo, canonical.as_deref()))
        .collect()
}

/// The most recent run in `cwd` for `tenant` — the target of `--continue` (R5 design §2.5). Scoped
/// to `cwd` because the prefix cache is per-repo, so a cross-worktree continue would cache-miss.
pub fn most_recent(runs_dir: &Path, cwd: &Path, tenant: &TenantId) -> Option<RunId> {
    let mut indexed = page(runs_dir, tenant, Some(cwd), None, Some(1));
    if !indexed.index_ready && indexed.rebuild_recommended {
        // A missing/torn projection may pay one explicit rebuild. The normal continuation path
        // never enumerates rollout files or hydrates unrelated sessions before the first frame.
        reindex(runs_dir).ok()?;
        indexed = page(runs_dir, tenant, Some(cwd), None, Some(1));
    }
    indexed
        .index_ready
        .then(|| indexed.sessions.into_iter().next().map(|m| m.run_id))
        .flatten()
}

/// Persist a run's projected metadata (the kernel calls this at each turn boundary). The per-run
/// sidecar is the incremental O(1) index entry. The sorted global `sessions.index` is repaired by
/// list/reindex away from the turn boundary, so foreground durability never scans all sessions.
pub(crate) fn write_meta(runs_dir: &Path, projected: &SessionMeta) -> Result<(), RecordError> {
    crate::create_state_dir(runs_dir)?;
    // The marker precedes the sidecar: a crash at any later point makes latency-sensitive readers
    // report not-ready instead of returning a ready page that silently omits this newer run. The
    // same lock serializes publication transactions; compaction is the only operation allowed to
    // clear a marker inherited from a crashed writer.
    let mut transaction_result = None;
    let mut compact_after = false;
    crate::cache_io::with_session_index_lock(runs_dir, || {
        let inherited_dirty = index_publication_incomplete(runs_dir);
        let transaction = (|| -> Result<(), RecordError> {
            if !inherited_dirty {
                mark_index_dirty_unlocked(runs_dir)?;
            }
            write_meta_sidecar(runs_dir, projected)?;
            if inherited_dirty {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "session index has an incomplete prior publication",
                )
                .into());
            }
            compact_after = append_delta_index_unlocked(runs_dir, projected)?;
            clear_index_dirty_unlocked(runs_dir)?;
            Ok(())
        })();
        if transaction.is_err() || inherited_dirty {
            compact_after = true;
        }
        transaction_result = Some(transaction);
        Ok(())
    })?;
    let transaction = transaction_result.expect("the session-index lock always executes");
    if compact_after {
        schedule_session_index_compaction(runs_dir);
    }
    transaction
}

/// Rebuild the cache from the records (R5 design §2.4): replay every rollout, rewrite each per-run
/// `.meta.json`, and rewrite `sessions.index` from scratch. Truth is the record, so this is always
/// safe to run. A corrupt/broken rollout is skipped rather than aborting the whole rebuild; returns
/// the number of runs indexed.
pub fn reindex(runs_dir: &Path) -> Result<usize, RecordError> {
    crate::create_state_dir(runs_dir)?;
    let mut metas = Vec::new();
    for run in rollout_run_ids(runs_dir) {
        if let Ok(m) = meta_from_replay(runs_dir, &run, None) {
            metas.push(m);
        }
    }
    // Rebuilding was 91% blocking fsync: every sidecar was rewritten unconditionally, and each
    // rewrite fsynced its own bytes AND the whole directory. A session whose sidecar already
    // encodes this exact projection is left alone — refreshing its mtime is the only thing that
    // would change — and the surviving writes share ONE directory sync at the end.
    let mut wrote = false;
    for m in &metas {
        if sidecar_is_unchanged(runs_dir, m) {
            continue;
        }
        let path = per_run_meta_path(runs_dir, &m.run_id)?;
        private_cache::write_sidecar(runs_dir, &path, m, true)?;
        wrote = true;
    }
    if wrote {
        crate::cache_io::sync_dir(runs_dir)?;
    }
    merge_rewrite_index(runs_dir, metas.iter().cloned())?;
    Ok(metas.len())
}

/// True when the gated CAS projection is semantically byte-identical to `projected`. The public
/// sidecar is a handle manifest, so comparing it with serialized private metadata would force
/// every warm reindex to republish an unchanged projection.
fn sidecar_is_unchanged(runs_dir: &Path, projected: &SessionMeta) -> bool {
    let Ok(path) = per_run_meta_path(runs_dir, &projected.run_id) else {
        return false;
    };
    crate::cache_io::read_session_meta(&path)
        .is_ok_and(|bytes| private_cache::sidecar_matches(runs_dir, &bytes, projected))
}

/// What [`prune`] is allowed to delete. A policy that names nothing deletes nothing: retention is
/// always explicit, because a run journal is the only durable evidence a run ever happened.
#[derive(Debug, Clone, Default)]
pub struct PrunePolicy {
    /// Delete runs whose last recorded activity is older than this many seconds.
    pub max_age_secs: Option<u64>,
    /// Keep the newest N runs; delete every older one.
    pub keep_last: Option<usize>,
    /// Select and report without unlinking anything.
    pub dry_run: bool,
}

/// What [`prune`] did, and what it declined to do. The two "kept anyway" lists are reported rather
/// than silently folded into `retained`: a caller that asked for a deletion and did not get one is
/// entitled to know which rule stopped it.
#[derive(Debug, Clone, Default)]
pub struct PruneReport {
    /// Runs the policy named and whose journal (plus sidecar) was unlinked.
    pub removed: Vec<RunId>,
    /// Runs left in place.
    pub retained: usize,
    /// Named by the policy, kept because another process holds the writer lock.
    pub active: Vec<RunId>,
    /// Named by the policy, kept because a retained fork replays through this run's prefix.
    pub ancestors: Vec<RunId>,
    /// Named by the policy, kept because a production derivative still owns private handles.
    pub derivatives: Vec<RunId>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteSessionError {
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("session {0:?} does not exist")]
    NotFound(String),
    #[error("session {0:?} is active in another process")]
    Active(String),
    #[error("session {run:?} is retained by descendant sessions: {descendants}")]
    HasDescendants { run: String, descendants: String },
    #[error("session {run:?} is retained by {owners} external private derivative owner(s)")]
    HasDerivatives { run: String, owners: u32 },
}

/// Delete exactly one inactive session and its rebuildable projection.
///
/// The journal lock stays held across unlink, and any retained fork whose logical history names
/// the target refuses the operation. This is the explicit destructive counterpart to [`prune`]:
/// callers must name one run rather than broadening a retention policy until it happens to match.
pub fn delete(runs_dir: &Path, tenant: &TenantId, run: &RunId) -> Result<(), DeleteSessionError> {
    crate::validate_run_id(run)?;
    let sessions = list(runs_dir, tenant);
    if !sessions.iter().any(|meta| meta.run_id == *run) {
        return Err(DeleteSessionError::NotFound(run.0.clone()));
    }
    let mut descendants = sessions
        .iter()
        .filter(|meta| meta.run_id != *run)
        .filter(|meta| {
            meta.parent
                .as_ref()
                .is_some_and(|parent| parent.parent_run == *run)
                || meta.ancestry.iter().any(|ancestor| ancestor.run_id == *run)
        })
        .map(|meta| meta.run_id.0.clone())
        .collect::<Vec<_>>();
    descendants.sort();
    descendants.dedup();
    if !descendants.is_empty() {
        return Err(DeleteSessionError::HasDescendants {
            run: run.0.clone(),
            descendants: descendants.join(", "),
        });
    }

    let rollout = rollout_path(runs_dir, run)?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&rollout)
        .map_err(RecordError::from)?;
    file.try_lock()
        .map_err(|_| DeleteSessionError::Active(run.0.clone()))?;
    let content_release =
        match crate::content_store::ExactRunContentRelease::prepare(runs_dir, tenant, run) {
            Ok(guard) => guard,
            Err(crate::ContentStoreError::RetainedByDerivative { owners, .. }) => {
                return Err(DeleteSessionError::HasDerivatives {
                    run: run.0.clone(),
                    owners,
                });
            }
            Err(crate::ContentStoreError::ActiveWriter { .. }) => {
                return Err(DeleteSessionError::Active(run.0.clone()));
            }
            Err(error) => return Err(RecordError::from(error).into()),
        };
    // A sidecar is rebuildable while the journal still exists. Removing it first makes every
    // crash boundary either fully recoverable from the journal or resumable from the reverse
    // content-reference graph.
    let sidecar = per_run_meta_path(runs_dir, run)?;
    if let Err(error) = std::fs::remove_file(sidecar)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(RecordError::from(error).into());
    }
    std::fs::remove_file(&rollout).map_err(RecordError::from)?;
    content_release.commit().map_err(RecordError::from)?;
    complete_deleted_session_cleanup(runs_dir, run)?;
    drop(file);
    Ok(())
}

/// Finish rebuildable projection cleanup after the authoritative journal has been unlinked.
///
/// An erasure operation can crash between the journal unlink and sidecar/index cleanup. This
/// idempotent boundary lets its durable receipt resume without claiming stale projection bytes are
/// gone. Cleanup always refuses while the journal still exists.
pub(crate) fn complete_deleted_session_cleanup(
    runs_dir: &Path,
    run: &RunId,
) -> Result<(), RecordError> {
    let rollout = rollout_path(runs_dir, run)?;
    if rollout.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "session journal still exists; projection cleanup refused",
        )
        .into());
    }
    let sidecar = per_run_meta_path(runs_dir, run)?;
    if let Err(error) = std::fs::remove_file(sidecar)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(RecordError::from(error));
    }
    merge_rewrite_index(runs_dir, [])?;
    Ok(())
}

/// Apply a retention policy to `runs_dir`, deleting the run journals it names and nothing else.
///
/// Journals are append-only and no other code path ever removes one, so this is the whole retention
/// story. Three rules bound it:
///
/// * only runs of `tenant` are even considered, so a shared runs dir cannot lose another tenant's
///   record to a policy that never saw it;
/// * a run whose writer lock is held is skipped — a live session is not garbage;
/// * a run a retained fork replays through is skipped, transitively, because deleting it would
///   leave the survivor with an unreadable logical history rather than a shorter one.
pub fn prune(
    runs_dir: &Path,
    tenant: &TenantId,
    policy: &PrunePolicy,
) -> Result<PruneReport, RecordError> {
    prune_at(runs_dir, tenant, policy, now_secs())
}

pub(crate) fn prune_at(
    runs_dir: &Path,
    tenant: &TenantId,
    policy: &PrunePolicy,
    now: u64,
) -> Result<PruneReport, RecordError> {
    if !policy.dry_run {
        crate::content_store::release_private_content_for_absent_runs(runs_dir, tenant)?;
    }
    let metas = list(runs_dir, tenant);
    let total = metas.len();
    if policy.max_age_secs.is_none() && policy.keep_last.is_none() {
        return Ok(PruneReport {
            retained: total,
            ..PruneReport::default()
        });
    }

    // `list` is newest-first, so the keep-last window is a prefix. Age uses the same recorded
    // activity timestamp the listing orders by.
    let mut selected: HashSet<String> = HashSet::new();
    for (position, meta) in metas.iter().enumerate() {
        let too_old = policy
            .max_age_secs
            .is_some_and(|max_age| now.saturating_sub(meta.updated_at) > max_age);
        let beyond_window = policy.keep_last.is_some_and(|keep| position >= keep);
        if too_old || beyond_window {
            selected.insert(meta.run_id.0.clone());
        }
    }

    // Grow the retained set through ancestry to its fixpoint: a fork's prefix is not garbage while
    // the fork survives, however old the parent is.
    let mut ancestors: Vec<RunId> = Vec::new();
    loop {
        let mut rescued = Vec::new();
        for meta in &metas {
            if selected.contains(&meta.run_id.0) {
                continue;
            }
            if let Some(parent) = &meta.parent
                && selected.contains(&parent.parent_run.0)
            {
                rescued.push(parent.parent_run.clone());
            }
        }
        if rescued.is_empty() {
            break;
        }
        for run in rescued {
            // `remove` reports whether this run was still selected, which dedupes the report: two
            // forks off one parent rescue it once, not twice.
            if selected.remove(&run.0) {
                ancestors.push(run);
            }
        }
    }

    let mut report = PruneReport {
        ancestors,
        ..PruneReport::default()
    };
    for meta in &metas {
        if !selected.contains(&meta.run_id.0) {
            continue;
        }
        let run = meta.run_id.clone();
        let rollout = rollout_path(runs_dir, &run)?;
        let Some(_journal_lock) = lock_idle_rollout(&rollout) else {
            report.active.push(run);
            continue;
        };
        let content_release =
            match crate::content_store::ExactRunContentRelease::prepare(runs_dir, tenant, &run) {
                Ok(guard) => guard,
                Err(crate::ContentStoreError::RetainedByDerivative { .. }) => {
                    report.derivatives.push(run);
                    continue;
                }
                Err(crate::ContentStoreError::ActiveWriter { .. }) => {
                    report.active.push(run);
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
        if !policy.dry_run {
            // The projection goes first. Once the journal is durably absent, the reverse reference
            // graph is sufficient to finish key shredding after any crash boundary.
            let sidecar = per_run_meta_path(runs_dir, &run)?;
            if let Err(error) = std::fs::remove_file(&sidecar)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(error.into());
            }
            std::fs::remove_file(&rollout)?;
            content_release.commit()?;
        }
        report.removed.push(run);
    }
    report.retained = total.saturating_sub(report.removed.len());
    if !policy.dry_run {
        // Drop the deleted runs from the compact index in one atomic rewrite. `merge_rewrite_index`
        // re-reads which rollouts exist, so an entry whose journal is gone is not carried over. Do
        // this even when this pass removed nothing: that is the recovery pass after a crash which
        // unlinked its last selected journal before reaching the index rewrite.
        merge_rewrite_index(runs_dir, [])?;
    }
    Ok(report)
}

/// Acquire the rollout's exclusive writer lock for the complete prune mutation. A live run is
/// never garbage, and retaining the descriptor across sidecar plus journal unlink closes the
/// probe/delete race where a writer could otherwise start between those two operations.
fn lock_idle_rollout(path: &Path) -> Option<std::fs::File> {
    let Ok(file) = OpenOptions::new().read(true).append(true).open(path) else {
        return None;
    };
    match file.try_lock() {
        Ok(()) => Some(file),
        Err(_) => None,
    }
}

/// Mint a fresh, collision-resistant run id (process id + wall-clock nanos), matching the CLI's
/// scheme. The clock crosses the nondeterminism boundary once, only to name the run.
fn mint_run_id() -> RunId {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(RUN_ID_NANOS_FALLBACK);
    RunId(format!("run-{}-{}", std::process::id(), nanos))
}

/// Fork `parent` at seq `at` into a fresh run (SESS-1, the reference model). Mints a new `RunId`,
/// opens its chain, and writes a genesis [`EventKind::RunStart`] plus the effective
/// [`EventKind::ModelSelected`] snapshot when one exists — no parent-prefix bytes are copied. The
/// genesis pins `parent_hash_at_seq` (the parent chain's hash at `at`) so the reference is
/// tamper-evident on load (ADR-008 §4, R5-review Risk 3). The child inherits the parent's session
/// config (cwd/model/effort/config_digest), exact route at the branch point, and the given `tenant`.
/// If the parent has a valid tunables snapshot this legacy-compatible API preserves and binds it,
/// but does not compare it with a current resolved set. Execution frontends must use
/// [`fork_with_resolved_tunables`] (or the explicitly snapshot-checked form).
pub fn fork(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
) -> Result<RunId, RecordError> {
    Ok(fork_internal(runs_dir, parent, at, tenant, None)?.0)
}

/// Checked fork/rewind. Exact current compatibility is established before a child file is
/// created; a legacy parent requires an explicit policy and produces a legacy child without
/// inventing a migration or a snapshot.
pub fn fork_with_tunables_snapshot(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    expected: &iteron_protocol::RunGenesisTunablesSnapshot,
    legacy: tunables::LegacyTunablesPolicy,
) -> Result<(RunId, tunables::TunablesCompatibility), RecordError> {
    let expected = ForkTunablesExpectation::V1(expected, legacy);
    let (child, compatibility) = fork_internal(runs_dir, parent, at, tenant, Some(expected))?;
    Ok((
        child,
        compatibility.expect("checked fork always computes a compatibility result"),
    ))
}

/// Resolver-typed convenience wrapper for [`fork_with_tunables_snapshot`].
pub fn fork_with_resolved_tunables(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    resolved: &iteron_tunables::ResolvedTunableSet,
    legacy: tunables::LegacyTunablesPolicy,
) -> Result<(RunId, tunables::TunablesCompatibility), RecordError> {
    let expected = ForkTunablesExpectation::Resolved(resolved, legacy);
    let (child, compatibility) = fork_internal(runs_dir, parent, at, tenant, Some(expected))?;
    Ok((
        child,
        compatibility.expect("checked fork always computes a compatibility result"),
    ))
}

#[derive(Clone, Copy)]
enum ForkTunablesExpectation<'a> {
    V1(
        &'a iteron_protocol::RunGenesisTunablesSnapshot,
        tunables::LegacyTunablesPolicy,
    ),
    Resolved(
        &'a iteron_tunables::ResolvedTunableSet,
        tunables::LegacyTunablesPolicy,
    ),
}

fn fork_internal(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    expected: Option<ForkTunablesExpectation<'_>>,
) -> Result<(RunId, Option<tunables::TunablesCompatibility>), RecordError> {
    let parent_path = rollout_path(runs_dir, parent)?;
    // Read + verify the parent chain exactly once under the same cumulative budget later used for
    // its ancestors. The verified lines are passed into logical expansion rather than reopened.
    let mut replay_budget = LogicalReplayBudget::default();
    let parent_lines = read_chain_budgeted(&parent_path, &mut replay_budget)?;
    if let Some(first) = parent_lines.first() {
        ensure_tenant(tenant, &first.tenant.0, first.seq.0)?;
    }
    let parent_snapshot = genesis_tunables_event(&parent_lines).map(|(snapshot, _)| snapshot);
    let parent_policy_snapshot =
        genesis_policy_bundle_event(&parent_lines).map(|(snapshot, _)| snapshot);
    let compatibility = if let Some(expected) = expected {
        let recorded = checked_genesis_tunables(&parent_lines)?;
        Some(match expected {
            ForkTunablesExpectation::V1(expected, legacy) => {
                let expected = tunables::TunablesCheckpoint::V1(expected.clone());
                tunables::check_checkpoint_compatibility(recorded.as_ref(), &expected, legacy)?
            }
            ForkTunablesExpectation::Resolved(resolved, legacy) => {
                tunables::check_resolved_compatibility(recorded.as_ref(), resolved, legacy)?
            }
        })
    } else {
        None
    };
    let pinned = parent_lines
        .iter()
        .find(|l| l.seq == at)
        .map(|l| l.hash.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot fork {parent} at seq {}: beyond the parent tail",
                    at.0
                ),
            )
        })?;

    let (cwd, mut model, config_digest, mut environment, agent_definition_tag) =
        match parent_lines.first().map(|l| &l.event.kind) {
            Some(EventKind::RunStart {
                cwd,
                model,
                config_digest,
                environment,
                agent_definition_tag,
                ..
            }) => (
                cwd.clone(),
                model.clone(),
                config_digest.clone(),
                environment.clone(),
                agent_definition_tag.clone(),
            ),
            _ => (String::new(), String::new(), String::new(), None, None),
        };
    // Resolve the LOGICAL prefix, not only the parent run's physical lines. At seq 0 of a nested
    // fork, the effective route may live in an ancestor prefix; filtering only `parent_lines`
    // silently lost its provider id. `expand(..., Some(at))` preserves that inherited state while
    // still excluding physical selections after the requested branch point.
    let mut ignored_ancestry = Vec::new();
    let logical_prefix = expand_scoped_from(
        runs_dir,
        parent,
        Some(at.0),
        0,
        &mut replay_budget,
        Some(parent_lines),
        &mut ignored_ancestry,
    )?;
    if environment.is_none() {
        environment = logical_prefix.iter().rev().find_map(|scoped| {
            if let EventKind::RunStart { environment, .. } = &scoped.event.kind {
                environment.clone()
            } else {
                None
            }
        });
    }
    let mut legacy_max_microusd: Option<u64> = None;
    for candidate in logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::RunStart {
                max_usd: Some(max_usd),
                ..
            } => Some(*max_usd),
            _ => None,
        })
    {
        if !candidate.is_finite() || candidate < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fork history contains an invalid max_usd ceiling",
            )
            .into());
        }
        let candidate = legacy_usd_to_microusd_floor(candidate);
        legacy_max_microusd =
            Some(legacy_max_microusd.map_or(candidate, |current| current.min(candidate)));
    }
    let mut exact_max_microusd: Option<u64> = None;
    for candidate in logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::UsdCeilingChanged { max_microusd, .. } => Some(*max_microusd),
            _ => None,
        })
    {
        exact_max_microusd =
            Some(exact_max_microusd.map_or(candidate, |current| current.min(candidate)));
    }
    // Once exact policy exists it is authoritative. The legacy f64 field is consulted only for
    // pre-policy journals and is reconstructed by flooring, never ceiling.
    let max_microusd = exact_max_microusd.or(legacy_max_microusd);
    let max_usd = max_microusd.map(|value| {
        value as f64
            / iteron_tunables::param_f64("record.session.microusd_per_usd", MICROUSD_PER_USD)
    });
    let inherited_policy =
        RuntimePolicyState::from_events(logical_prefix.iter().map(|scoped| &scoped.event));
    let inherited_selection = logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            } => Some((
                provider_id.clone(),
                model_id.clone(),
                catalog_digest.clone(),
                capability_digest.clone(),
            )),
            _ => None,
        })
        .next_back();
    if let Some((_, model_id, _, _)) = &inherited_selection {
        model = model_id.clone();
    }

    let child = mint_run_id();
    let mut rollout = Rollout::open(runs_dir, &child, tenant.clone())?;
    let genesis = Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::RunStart {
            cwd,
            model,
            // A runtime transition after genesis is authoritative at the branch point. The
            // child's genesis snapshots that value so its physical journal is independently
            // projectable without consulting mutable live state.
            effort: inherited_policy.effort,
            created_at: now_secs(),
            environment,
            parent_run: Some(parent.0.clone()),
            forked_at: Some(at.0),
            parent_hash_at_seq: Some(pinned),
            config_digest,
            agent_definition_tag,
            max_usd,
        },
    };
    if let Some(snapshot) = parent_snapshot {
        let inherited = tunables::inherited_from(&parent.0, &snapshot);
        rollout.append_genesis_checkpoint(&genesis, snapshot, Some(inherited))?;
    } else {
        rollout.append(&genesis)?;
    }
    if let Some(snapshot) = parent_policy_snapshot {
        let inherited_from = Some(iteron_protocol::RunGenesisPolicyBundleInheritance {
            parent_run: parent.0.clone(),
            parent_receipt_digest_sha256: snapshot.receipt_digest_sha256.clone(),
        });
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::PolicyBundleSnapshot {
                version: iteron_protocol::RunGenesisPolicyBundleVersion::V1,
                snapshot,
                inherited_from,
            },
        })?;
    }
    if let Some(max_microusd) = max_microusd {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Fork,
                max_microusd,
            },
        })?;
    }
    if let Some(max_turns) = inherited_policy.turn_ceiling {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::TurnCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Fork,
                max_turns,
            },
        })?;
    }
    rollout.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Fork,
            effort: inherited_policy.effort,
        },
    })?;
    rollout.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Fork,
            mode: inherited_policy.permission_mode,
            rules: inherited_policy.permission_rules,
        },
    })?;
    if let Some((provider_id, model_id, catalog_digest, capability_digest)) = inherited_selection {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            },
        })?;
    }
    Ok((child, compatibility))
}

const MAX_FORK_DEPTH: usize = 256;

/// Load a run's full logical event stream, following the reference-model fork (SESS-1). If the
/// genesis references a parent, the parent prefix (up to `forked_at`) is replayed first — VERIFYING
/// `parent_hash_at_seq` against the parent chain's actual hash at that seq and erroring with
/// [`RecordError::ForkParentMismatch`] if the parent prefix was altered (ADR-008 §4 tamper-evidence,
/// R5-review Risk 3) — then this chain's events are appended. A plain run returns its own events.
/// The kernel's `messages_from_rollout` will call this; it is exposed here, not wired.
pub fn load_forked(runs_dir: &Path, run: &RunId) -> Result<Vec<Event>, RecordError> {
    Ok(load_forked_scoped(runs_dir, run)?
        .into_iter()
        .map(|scoped| scoped.event)
        .collect())
}

/// Replay ONE run's own chain, keeping each line's segment offset (#102/#104).
///
/// Deliberately not fork-expanding. A parent prefix was written by a different process with a
/// different monotonic origin, so splicing it in would produce segments whose offsets cannot be
/// compared and a "wall time" that is the sum of two unrelated clocks. A timeline reports the run
/// it was asked about; the parent has its own.
pub fn replay_run_timed(runs_dir: &Path, run: &RunId) -> Result<Vec<TimedEvent>, RecordError> {
    crate::replay_timed(&rollout_path(runs_dir, run)?)
}

/// [`load_forked`] with the original tenant/run scope retained for every physical event.
pub fn load_forked_scoped(runs_dir: &Path, run: &RunId) -> Result<Vec<ScopedEvent>, RecordError> {
    crate::require_strict_replay_policy()?;
    let mut budget = LogicalReplayBudget::default();
    expand_scoped(runs_dir, run, None, 0, &mut budget)
}

#[derive(Default)]
struct LogicalReplayBudget {
    bytes: u64,
    events: usize,
    physical_lines: usize,
    expanded_runs: HashSet<RunId>,
}

impl LogicalReplayBudget {
    fn ensure_can_expand(&self, run: &RunId) -> Result<(), RecordError> {
        if self.expanded_runs.contains(run) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cyclic fork chain repeats run {run}"),
            )
            .into());
        }
        Ok(())
    }

    fn begin_expand(&mut self, run: &RunId) -> Result<(), RecordError> {
        self.ensure_can_expand(run)?;
        if !self.expanded_runs.insert(run.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cyclic fork chain repeats run {run}"),
            )
            .into());
        }
        Ok(())
    }
}

fn admit_logical_events(total: &mut usize, events: usize) -> Result<(), RecordError> {
    *total = total.saturating_add(events);
    if *total > crate::MAX_ROLLOUT_EVENTS {
        return Err(RecordError::TooManyEvents {
            max: crate::MAX_ROLLOUT_EVENTS,
        });
    }
    Ok(())
}

/// Recursively materialize `run`'s event stream, bounded to seq `<= upto` when set. Recurses into a
/// parent so a fork of a fork (a rewound-then-rewound session) resolves; `depth` guards against a
/// pathological/cyclic parent pointer in a hand-crafted record.
fn expand_scoped(
    runs_dir: &Path,
    run: &RunId,
    upto: Option<u64>,
    depth: usize,
    budget: &mut LogicalReplayBudget,
) -> Result<Vec<ScopedEvent>, RecordError> {
    let mut ignored_ancestry = Vec::new();
    expand_scoped_from(
        runs_dir,
        run,
        upto,
        depth,
        budget,
        None,
        &mut ignored_ancestry,
    )
}

fn expand_scoped_from(
    runs_dir: &Path,
    run: &RunId,
    upto: Option<u64>,
    depth: usize,
    budget: &mut LogicalReplayBudget,
    preloaded: Option<Vec<ReadLine>>,
    ancestry: &mut Vec<SessionAncestryReceipt>,
) -> Result<Vec<ScopedEvent>, RecordError> {
    if depth > iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fork chain for {run} exceeds max depth {MAX_FORK_DEPTH} (cyclic parent?)"),
        )
        .into());
    }

    let path = rollout_path(runs_dir, run)?;
    budget.begin_expand(run)?;
    let lines = match preloaded {
        Some(lines) => lines,
        None => read_chain_budgeted(&path, budget)?,
    };
    let mut events = Vec::new();

    if let Some(EventKind::RunStart {
        parent_run: Some(pr),
        forked_at: Some(fa),
        parent_hash_at_seq: Some(ph),
        ..
    }) = lines.first().map(|l| &l.event.kind)
    {
        let parent = RunId(pr.clone());
        if depth >= iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("fork chain for {run} exceeds max depth {MAX_FORK_DEPTH} (cyclic parent?)"),
            )
            .into());
        }
        budget.ensure_can_expand(&parent)?;
        let parent_path = rollout_path(runs_dir, &parent)?;
        // Verify the cross-link BEFORE trusting the parent prefix: the parent chain's actual hash
        // at the fork seq must equal the pinned value, or the parent prefix was tampered.
        let parent_lines = read_chain_budgeted(&parent_path, budget)?;
        if let (Some(child_first), Some(parent_first)) = (lines.first(), parent_lines.first()) {
            ensure_tenant(
                &child_first.tenant,
                &parent_first.tenant.0,
                parent_first.seq.0,
            )?;
        }
        validate_fork_tunables_inheritance(&lines, &parent, &parent_lines)?;
        validate_fork_policy_bundle_inheritance(&lines, &parent, &parent_lines)?;
        let pinned_line = parent_lines
            .iter()
            .find(|l| l.seq.0 == *fa)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parent {parent} has no seq {fa} for fork of {run}"),
                )
            })?;
        if &pinned_line.hash != ph {
            return Err(RecordError::ForkParentMismatch {
                parent: parent.0.clone(),
                forked_at: *fa,
                pinned: ph.clone(),
                actual: pinned_line.hash.clone(),
            });
        }
        let observed_tail = parent_lines
            .last()
            .expect("a verified pinned parent line implies a non-empty parent chain");
        let observed_mtime = file_mtime(&parent_path).unwrap_or_default();
        let receipt = SessionAncestryReceipt {
            run_id: parent.clone(),
            tenant: pinned_line.tenant.clone(),
            through_seq: *fa,
            prefix_bytes: pinned_line.end_bytes,
            tail_hash: pinned_line.hash.clone(),
            observed_record_bytes: observed_tail.end_bytes,
            observed_tail_seq: observed_tail.seq.0,
            observed_tail_hash: observed_tail.hash.clone(),
            observed_updated_at: observed_mtime.0,
            observed_updated_at_subsec_nanos: observed_mtime.1,
        };
        events.extend(expand_scoped_from(
            runs_dir,
            &parent,
            Some(*fa),
            depth + 1,
            budget,
            Some(parent_lines),
            ancestry,
        )?);
        ancestry.push(receipt);
    }

    for l in &lines {
        if upto
            .map(|u| l.seq.0 <= u)
            .unwrap_or(iteron_tunables::param_bool(
                "record.session.unbounded_scope_admits_line",
                UNBOUNDED_SCOPE_ADMITS_LINE,
            ))
        {
            events.push(ScopedEvent {
                event: l.event.clone(),
                tenant: l.tenant.clone(),
                run_id: run.clone(),
            });
        }
    }
    Ok(events)
}

fn genesis_tunables_event(
    lines: &[ReadLine],
) -> Option<(
    tunables::TunablesCheckpoint,
    Option<&iteron_protocol::RunGenesisTunablesInheritance>,
)> {
    match lines.get(1).map(|line| &line.event.kind) {
        Some(EventKind::TunablesSnapshot {
            snapshot,
            inherited_from,
            ..
        }) => Some((
            tunables::TunablesCheckpoint::V1(snapshot.clone()),
            inherited_from.as_ref(),
        )),
        Some(EventKind::TunablesSnapshotV2 {
            snapshot,
            inherited_from,
            ..
        }) => Some((
            tunables::TunablesCheckpoint::V2(snapshot.clone()),
            inherited_from.as_ref(),
        )),
        _ => None,
    }
}

fn genesis_policy_bundle_event(
    lines: &[ReadLine],
) -> Option<(
    iteron_protocol::RunGenesisPolicyBundleSnapshot,
    Option<&iteron_protocol::RunGenesisPolicyBundleInheritance>,
)> {
    match lines.get(2).map(|line| &line.event.kind) {
        Some(EventKind::PolicyBundleSnapshot {
            snapshot,
            inherited_from,
            ..
        }) => Some((snapshot.clone(), inherited_from.as_ref())),
        _ => None,
    }
}

fn checked_genesis_tunables(
    lines: &[ReadLine],
) -> Result<Option<tunables::TunablesCheckpoint>, RecordError> {
    let mut state = tunables::GenesisTunablesState::default();
    for line in lines {
        state.observe(line.seq.0, &line.event.kind)?;
    }
    Ok(state.finish()?.cloned())
}

/// Cross-check a fork's copied snapshot against the direct parent's actual, unique seq-1
/// snapshot. The ordinary parent hash pins only through `forked_at`; for a seq-0 fork that prefix
/// deliberately excludes seq 1, so this independent binding must be revalidated on every logical
/// load. Recursion applies the same check at every edge in a nested fork chain.
fn validate_fork_tunables_inheritance(
    child_lines: &[ReadLine],
    parent: &RunId,
    parent_lines: &[ReadLine],
) -> Result<(), RecordError> {
    match (
        genesis_tunables_event(child_lines),
        genesis_tunables_event(parent_lines),
    ) {
        (None, None) => Ok(()),
        (Some((child_snapshot, Some(binding))), Some((parent_snapshot, _)))
            if binding.parent_run == parent.0
                && binding.parent_snapshot_digest_sha256
                    == parent_snapshot.snapshot_digest_sha256()
                && child_snapshot == parent_snapshot =>
        {
            Ok(())
        }
        _ => Err(tunables::TunablesSnapshotError::GenesisOrder {
            reason: "fork tunables inheritance does not match the actual parent seq-1 snapshot",
        }
        .into()),
    }
}

fn validate_fork_policy_bundle_inheritance(
    child_lines: &[ReadLine],
    parent: &RunId,
    parent_lines: &[ReadLine],
) -> Result<(), RecordError> {
    match (
        genesis_policy_bundle_event(child_lines),
        genesis_policy_bundle_event(parent_lines),
    ) {
        (None, None) => Ok(()),
        (Some((child_snapshot, Some(binding))), Some((parent_snapshot, _)))
            if binding.parent_run == parent.0
                && binding.parent_receipt_digest_sha256
                    == parent_snapshot.receipt_digest_sha256
                && child_snapshot == parent_snapshot =>
        {
            Ok(())
        }
        _ => Err(
            crate::policy_bundle::PolicyBundleCheckpointError::GenesisOrder(
                "fork policy checkpoint inheritance does not match the parent genesis receipt",
            )
            .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Capability, PermissionMode, PermissionRules, Verdict};

    #[test]
    fn every_budget_terminal_reason_survives_the_session_projection() {
        for reason in [
            "max_turns",
            "max_tokens",
            "max_usd",
            "unpriced_usd_ceiling",
            "max_wall_secs",
            "max_consecutive_tool_errors",
            "verify_attempts",
        ] {
            let debug = format!("BudgetExhausted(\"{reason}\")");
            assert_eq!(
                parse_outcome(&debug),
                Some(Outcome::BudgetExhausted(reason)),
                "{reason}"
            );
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "core-sess-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn logical_fork_budget_bounds_cumulative_bytes_and_events() {
        let dir = tmpdir("logical-budget");
        std::fs::create_dir_all(&dir).unwrap();
        let second = dir.join("second.jsonl");
        std::fs::File::create(&second)
            .unwrap()
            .set_len(crate::MAX_ROLLOUT_BYTES / 2 + 1)
            .unwrap();
        let mut bytes = crate::MAX_ROLLOUT_BYTES / 2;
        let mut physical_lines = 0;
        assert!(matches!(
            crate::visit_record_lines_charged(&second, &mut bytes, &mut physical_lines, |_| Ok(())),
            Err(RecordError::RolloutTooLarge { .. })
        ));

        let mut events = 0;
        assert!(matches!(
            admit_logical_events(&mut events, crate::MAX_ROLLOUT_EVENTS + 1),
            Err(RecordError::TooManyEvents { .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn logical_fork_budget_bounds_cumulative_physical_lines_across_files() {
        let dir = tmpdir("logical-physical-lines");
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("first.jsonl");
        let second = dir.join("second.jsonl");
        let first_count = crate::MAX_ROLLOUT_PHYSICAL_LINES / 2 + 1;
        let second_count = crate::MAX_ROLLOUT_PHYSICAL_LINES - first_count + 1;
        std::fs::write(&first, vec![b'\n'; first_count]).unwrap();
        std::fs::write(&second, vec![b'\n'; second_count]).unwrap();

        let mut bytes = 0;
        let mut physical_lines = 0;
        crate::visit_record_lines_charged(&first, &mut bytes, &mut physical_lines, |_| Ok(()))
            .unwrap();
        assert_eq!(physical_lines, first_count);
        assert!(matches!(
            crate::visit_record_lines_charged(&second, &mut bytes, &mut physical_lines, |_| Ok(())),
            Err(RecordError::TooManyRecordLines {
                max: crate::MAX_ROLLOUT_PHYSICAL_LINES,
            })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn genesis_event(cwd: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: cwd.into(),
                model: "claude".into(),
                effort: Effort::Medium,
                created_at: 1000,
                environment: None,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest: "cfg".into(),
                agent_definition_tag: None,
                max_usd: None,
            },
        }
    }

    /// A run with a genesis header, one turn, one user message, usage, and a Done outcome.
    fn mk_run(runs_dir: &Path, run: &RunId, tenant: &TenantId, cwd: &str, task: &str) {
        let mut r = Rollout::open(runs_dir, run, tenant.clone()).unwrap();
        r.append(&genesis_event(cwd)).unwrap();
        r.append(&Event {
            seq: Seq(1),
            turn: TurnId(0),
            kind: EventKind::TurnStart,
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(2),
            turn: TurnId(0),
            kind: EventKind::Message {
                message: Message::user_text(task),
            },
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(3),
            turn: TurnId(0),
            kind: EventKind::TurnEnd {
                usage: Usage {
                    input: 100,
                    output: 10,
                    cache_creation: 0,
                    cache_read: 900,
                    thinking: 0,
                },
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(4),
            turn: TurnId(0),
            kind: EventKind::Done {
                outcome: "Done".into(),
            },
        })
        .unwrap();
    }

    /// A same-length, in-place forgery of a middle record.
    ///
    /// These tests used to rewrite the task text directly in the rollout. Content fields are now
    /// externalized into the content store, so the line carries a `core-private-ref:` digest
    /// instead of the prompt, and the old rewrite silently matched nothing and produced a file
    /// identical to the original. Flipping one hex digit of the message record's own reference is
    /// the same edit it always meant: same byte length, same middle line, and it still breaks that
    /// record's hash.
    fn forge_middle_record(original: &str) -> String {
        const MARKER: &str = "core-private-ref:v1:text:sha256:";
        // Occurrence 0 is the `run_start` cwd reference; occurrence 1 is the message record.
        let offset = original
            .match_indices(MARKER)
            .nth(1)
            .expect("the message record must carry its own content reference")
            .0
            + MARKER.len();
        let mut forged = original.to_owned();
        forged.replace_range(
            offset..offset + 1,
            if original.as_bytes()[offset] == b'0' {
                "1"
            } else {
                "0"
            },
        );
        assert_eq!(forged.len(), original.len());
        assert_ne!(forged, original);
        forged
    }

    fn complete_one_turn(runs_dir: &Path, run: &RunId, tenant: &TenantId, task: &str) {
        let mut rollout = Rollout::open(runs_dir, run, tenant.clone()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text(task),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 7,
                        output: 3,
                        cache_creation: 0,
                        cache_read: 2,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .unwrap();
    }

    fn user_texts(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::Message { message } if message.role == Role::User => {
                    message.content.iter().find_map(|b| match b {
                        Block::Text { text } => Some(text.clone()),
                        _ => None,
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn selection_event(provider_id: &str, model_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::ModelSelected {
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                catalog_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                capability_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            },
        }
    }

    fn latest_selection(events: &[Event]) -> Option<(String, String)> {
        events.iter().rev().find_map(|event| match &event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => Some((provider_id.clone(), model_id.clone())),
            _ => None,
        })
    }

    #[test]
    fn meta_projects_the_record() {
        let dir = tmpdir("meta");
        let t = TenantId::default();
        let run = RunId("s1".into());
        mk_run(&dir, &run, &t, "/repo/a", "Fix the parser bug\nmore detail");
        let m = meta(&dir, &run).unwrap();
        assert_eq!(m.run_id, run);
        assert_eq!(m.cwd, PathBuf::from("/repo/a"));
        assert_eq!(m.model, "claude");
        assert_eq!(m.effort, Effort::Medium);
        assert_eq!(m.title, "Fix the parser bug"); // first line only, deterministic
        assert_eq!(m.created_at, 1000);
        assert_eq!(m.turns, 1);
        assert!((m.cache_hit - 0.9).abs() < 1e-9);
        assert_eq!(m.pricing_schema_version, 2);
        assert_eq!(m.projection_schema_version, 3);
        assert_eq!(
            m.cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard
            },
            "replay must not apply one placeholder price across an unattributed route"
        );
        assert_eq!(m.last_outcome, Some(Outcome::Done));
        assert!(m.parent.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn workflow_child_terminal_restores_session_usage_and_attempts() {
        let dir = tmpdir("workflow-attribution");
        let tenant = TenantId::default();
        let run = RunId("workflow-attribution".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit modules");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentSpawned {
                    sub_run: "fan-0".into(),
                    agent: "investigator".into(),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::WorkflowV2 {
                    version: iteron_protocol::WorkflowEventVersion::V2,
                    workflow_id: "workflow-1".into(),
                    event: iteron_protocol::WorkflowEvent::ChildFinished {
                        task_id: 0,
                        sub_run: Some("fan-0".into()),
                        outcome: iteron_protocol::WorkflowChildOutcome::Done,
                        metrics: iteron_protocol::WorkflowMetrics {
                            provider_attempts: 3,
                            completed_turns: 2,
                            usage: Usage {
                                input: 50,
                                output: 5,
                                cache_creation: 0,
                                cache_read: 50,
                                thinking: 0,
                            },
                            tool_calls: 4,
                            tool_errors: 0,
                            model_ms: Some(10),
                            tools_ms: Some(20),
                            cost: None,
                        },
                        error_code: None,
                        error_detail: None,
                        summary_digest: Some("a".repeat(64)),
                        evidence_bytes: 100,
                    },
                },
            })
            .unwrap();
        drop(rollout);

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.turns, 4, "1 parent + 3 child attempts");
        assert!((projected.cache_hit - (950.0 / 1100.0)).abs() < 1e-9);
        assert_ne!(
            projected.cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::LegacyUnattributed
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn direct_child_v2_terminal_restores_session_attempts() {
        let dir = tmpdir("direct-v2-attribution");
        let tenant = TenantId::default();
        let run = RunId("direct-v2-attribution".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit direct child");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentSpawned {
                    sub_run: "direct-0".into(),
                    agent: "direct-investigator".into(),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentFinishedV2 {
                    version: iteron_protocol::WorkflowEventVersion::V2,
                    sub_run: "direct-0".into(),
                    outcome: iteron_protocol::WorkflowChildOutcome::Drained,
                    metrics: iteron_protocol::WorkflowMetrics {
                        provider_attempts: 2,
                        completed_turns: 1,
                        usage: Usage {
                            input: 10,
                            output: 2,
                            cache_creation: 0,
                            cache_read: 8,
                            thinking: 0,
                        },
                        ..iteron_protocol::WorkflowMetrics::default()
                    },
                    error_code: Some("operator_drain".into()),
                    error_detail: None,
                    summary_digest: None,
                    evidence_bytes: 0,
                },
            })
            .unwrap();
        drop(rollout);

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.turns, 3, "1 parent + 2 direct-child attempts");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawned_child_without_terminal_has_missing_billing_evidence() {
        let dir = tmpdir("workflow-incomplete");
        let tenant = TenantId::default();
        let run = RunId("workflow-incomplete".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit modules");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentSpawned {
                    sub_run: "fan-legacy".into(),
                    agent: "investigator".into(),
                },
            })
            .unwrap();
        drop(rollout);
        assert_eq!(
            meta(&dir, &run).unwrap().cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::BillingEvidenceMissing
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn workflow_child_started_without_terminal_has_missing_billing_evidence() {
        let dir = tmpdir("workflow-start-incomplete");
        let tenant = TenantId::default();
        let run = RunId("workflow-start-incomplete".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit modules");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Workflow {
                    version: iteron_protocol::WorkflowEventVersion::V1,
                    workflow_id: "workflow-1".into(),
                    event: iteron_protocol::WorkflowEvent::ChildStarted {
                        task_id: 0,
                        sub_run: "fan-started".into(),
                        spawn_seq: Seq(1),
                        budget: iteron_protocol::Budget::default(),
                    },
                },
            })
            .unwrap();
        drop(rollout);
        assert_eq!(
            meta(&dir, &run).unwrap().cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::BillingEvidenceMissing
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn model_selection_updates_provider_and_model_projection() {
        let dir = tmpdir("selection-meta");
        let tenant = TenantId::default();
        let run = RunId("selected".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::ModelSelected {
                    provider_id: "openai-work".into(),
                    model_id: "gpt-5-codex".into(),
                    catalog_digest: "catalog-v1".into(),
                    capability_digest: "cap-v1".into(),
                },
            })
            .unwrap();
        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.provider_id, "openai-work");
        assert_eq!(projected.model, "gpt-5-codex");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn meta_projects_the_latest_runtime_effort_snapshot() {
        let dir = tmpdir("runtime-effort-meta");
        let tenant = TenantId::default();
        let run = RunId("runtime-effort".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    effort: Effort::Max,
                },
            })
            .unwrap();
        assert_eq!(meta(&dir, &run).unwrap().effort, Effort::Max);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn appended_selection_invalidates_stale_meta_and_index_projections() {
        let dir = tmpdir("selection-cache");
        let tenant = TenantId::default();
        let run = RunId("cached-selection".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        assert_eq!(reindex(&dir).unwrap(), 1);
        let cached = meta(&dir, &run).unwrap();
        assert!(cached.provider_id.is_empty());
        assert!(cached.record_bytes > 0);

        {
            let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            rollout
                .append(&selection_event("deepseek-work", "deepseek-coder"))
                .unwrap();
        }

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.provider_id, "deepseek-work");
        assert_eq!(projected.model, "deepseek-coder");
        assert!(projected.record_bytes > cached.record_bytes);
        let listed = list(&dir, &tenant)
            .into_iter()
            .find(|meta| meta.run_id == run)
            .unwrap();
        assert_eq!(listed.provider_id, "deepseek-work");
        assert_eq!(listed.model, "deepseek-coder");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_meta_without_provider_or_cursor_remains_readable_and_replays() {
        let dir = tmpdir("legacy-meta");
        let tenant = TenantId::default();
        let run = RunId("legacy".into());
        mk_run(&dir, &run, &tenant, "/repo/legacy", "legacy task");

        let current = meta_from_replay(&dir, &run, None).unwrap();
        let mut legacy = serde_json::to_value(&current).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.remove("provider_id");
        object.remove("record_bytes");
        let decoded: SessionMeta = serde_json::from_value(legacy.clone()).unwrap();
        assert!(decoded.provider_id.is_empty());
        assert_eq!(decoded.record_bytes, 0);

        // A legacy cache cursor cannot claim freshness. The record is replayed and the cursor is
        // upgraded in-memory without requiring a migration or making the old JSON unreadable.
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let projected = meta(&dir, &run).unwrap();
        assert!(projected.provider_id.is_empty());
        assert_eq!(projected.model, "claude");
        assert!(projected.record_bytes > 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_placeholder_cost_cache_is_replayed_as_unknown() {
        let dir = tmpdir("legacy-placeholder-cost");
        let tenant = TenantId::default();
        let run = RunId("legacy-placeholder-cost".into());
        mk_run(&dir, &run, &tenant, "/repo/legacy", "legacy task");

        // Preserve the exact rollout cursor so the pricing schema is the only reason this cache
        // is rejected. V0 stored a context-free placeholder number under `cost_usd`.
        let current = meta_from_replay(&dir, &run, None).unwrap();
        let mut legacy = serde_json::to_value(&current).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.remove("pricing_schema_version");
        object.remove("cost");
        object.insert("cost_usd".into(), serde_json::json!(123.45));
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.pricing_schema_version, 2);
        assert_eq!(
            projected.cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard
            }
        );
        assert_eq!(projected.cost_usd(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_is_newest_first_and_tenant_scoped() {
        let dir = tmpdir("list");
        let t = TenantId("acme".into());
        let other = TenantId("globex".into());
        mk_run(&dir, &RunId("a".into()), &t, "/repo/a", "task a");
        mk_run(&dir, &RunId("b".into()), &t, "/repo/b", "task b");
        mk_run(&dir, &RunId("c".into()), &other, "/repo/c", "task c");
        let ls = list(&dir, &t);
        assert_eq!(ls.len(), 2, "only this tenant's runs");
        assert!(ls.iter().all(|m| m.tenant == t));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn most_recent_is_cwd_scoped() {
        let dir = tmpdir("recent");
        let t = TenantId::default();
        mk_run(&dir, &RunId("x".into()), &t, "/repo/x", "task x");
        mk_run(&dir, &RunId("y".into()), &t, "/repo/y", "task y");
        assert_eq!(
            most_recent(&dir, Path::new("/repo/x"), &t),
            Some(RunId("x".into()))
        );
        assert_eq!(most_recent(&dir, Path::new("/nope"), &t), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_most_recent_uses_subsecond_activity_before_the_run_id_tiebreaker() {
        let dir = tmpdir("d9-01-subsecond-recent");
        let tenant = TenantId::default();
        let older = RunId("z-older".into());
        let newer = RunId("a-newer".into());
        mk_run(&dir, &older, &tenant, "/repo/same", "older task");
        mk_run(&dir, &newer, &tenant, "/repo/same", "newer task");
        let same_second = 2_000;
        for (run, nanos) in [(&older, 100), (&newer, 200)] {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(rollout_path(&dir, run).unwrap())
                .unwrap();
            file.set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::new(same_second, nanos),
            ))
            .unwrap();
        }
        assert_eq!(reindex(&dir).unwrap(), 2);
        let listed = list(&dir, &tenant);
        assert_eq!(listed[0].updated_at, same_second);
        assert_eq!(listed[1].updated_at, same_second);
        assert_eq!(listed[0].run_id, newer);
        assert_eq!(
            most_recent(&dir, Path::new("/repo/same"), &tenant),
            Some(newer)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_g1_g2_turn_boundaries_auto_cache_and_covered_reads_replay_zero_rollouts() {
        let dir = tmpdir("d9-01-auto-fast-path");
        let tenant = TenantId("acme".into());
        let runs: Vec<RunId> = (0..4)
            .map(|position| RunId(format!("auto-{position}")))
            .collect();
        for (position, run) in runs.iter().enumerate() {
            mk_run(
                &dir,
                run,
                &tenant,
                &format!("/repo/fast-{position}"),
                &format!("authoritative task {position}"),
            );
            assert!(
                per_run_meta_path(&dir, run).unwrap().is_file(),
                "Done must automatically persist the per-run projection"
            );
        }

        let indexed = page(&dir, &tenant, None, None, Some(runs.len() + 1));
        assert!(indexed.index_ready);
        assert!(!indexed.cursor_stale);
        assert_eq!(indexed.sessions.len(), runs.len());
        assert_eq!(
            indexed
                .sessions
                .iter()
                .map(|meta| meta.run_id.clone())
                .collect::<HashSet<_>>(),
            runs.iter().cloned().collect()
        );

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let listed = list(&dir, &tenant);
        assert_eq!(listed.len(), runs.len());
        assert!(listed.iter().all(|meta| meta.turns == 1));
        assert_eq!(
            most_recent(&dir, Path::new("/repo/fast-2"), &tenant),
            Some(RunId("auto-2".into()))
        );
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            0,
            "covered list/continue selection must not replay a rollout"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_zero_attempt_terminal_is_indexed_but_its_monetary_claim_replays() {
        let dir = tmpdir("d9-01-zero-attempt");
        let tenant = TenantId::default();
        let run = RunId("zero-attempt".into());
        {
            let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/zero")).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Done {
                        outcome: "Done".into(),
                    },
                })
                .unwrap();
        }

        let sidecar_path = per_run_meta_path(&dir, &run).unwrap();
        assert!(sidecar_path.is_file());
        let persisted = private_cache::read_sidecar(
            &dir,
            &crate::cache_io::read_session_meta(&sidecar_path).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.cost, CostState::Zero);
        assert!(projection_is_current(&dir, &persisted));
        assert!(!projection_covers_rollout(&dir, &persisted));
        let indexed = page(&dir, &tenant, None, None, Some(2));
        assert!(indexed.index_ready);
        assert_eq!(indexed.sessions.len(), 1);
        assert_eq!(indexed.sessions[0].run_id, run);
        assert_eq!(
            indexed.sessions[0].projection_digest,
            persisted.projection_digest
        );

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(meta(&dir, &run).unwrap().cost, CostState::Zero);
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_fork_projection_is_fast_and_bound_to_the_pinned_parent_prefix() {
        let dir = tmpdir("d9-01-fork-fast-prefix");
        let tenant = TenantId::default();
        let parent = RunId("fork-fast-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/fork-fast", "parent task");
        let parent_tail = read_chain(&rollout_path(&dir, &parent).unwrap())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let child = fork(&dir, &parent, parent_tail, &tenant).unwrap();
        complete_one_turn(&dir, &child, &tenant, "child task");

        let child_sidecar = per_run_meta_path(&dir, &child).unwrap();
        assert!(child_sidecar.is_file());
        let persisted = private_cache::read_sidecar(
            &dir,
            &crate::cache_io::read_session_meta(&child_sidecar).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.parent.as_ref().unwrap().parent_run, parent);
        assert_eq!(persisted.ancestry.len(), 1);
        assert_eq!(persisted.ancestry[0].run_id, parent);
        assert!(projection_covers_rollout(&dir, &persisted));
        let indexed = page(&dir, &tenant, None, None, Some(3));
        assert!(indexed.index_ready);
        assert!(indexed.sessions.iter().any(|m| m.run_id == child));

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(meta(&dir, &child).unwrap().turns, 2);
        assert!(list(&dir, &tenant).iter().any(|m| m.run_id == child));
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            0,
            "covered fork meta/list must not replay the child or its parent"
        );

        // A same-length in-place change keeps both the fork-point and physical tail receipts
        // byte-identical. The ancestor observation mtime must still invalidate the child cache,
        // after which full fork replay exposes the broken parent chain.
        let parent_path = rollout_path(&dir, &parent).unwrap();
        let original_parent = std::fs::read_to_string(&parent_path).unwrap();
        let original_parent_tail = read_tail_receipt(&parent_path).unwrap();
        let parent_receipt = &persisted.ancestry[0];
        let corrupted_parent = forge_middle_record(&original_parent);
        std::fs::write(&parent_path, corrupted_parent).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&parent_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        parent_receipt.observed_updated_at.saturating_add(1),
                        parent_receipt.observed_updated_at_subsec_nanos,
                    ),
            ))
            .unwrap();
        assert_eq!(
            read_tail_receipt(&parent_path).unwrap(),
            original_parent_tail
        );
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert!(matches!(
            meta(&dir, &child),
            Err(RecordError::ChainBroken { .. })
        ));
        assert!(READ_CHAIN_CALLS.with(std::cell::Cell::get) >= 2);

        // Restore the exact observed parent state so the same child cache can next prove that a
        // legitimate append-only suffix is accepted without replay.
        std::fs::write(&parent_path, original_parent).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&parent_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        parent_receipt.observed_updated_at,
                        parent_receipt.observed_updated_at_subsec_nanos,
                    ),
            ))
            .unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(meta(&dir, &child).unwrap().turns, 2);
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 0);

        // The receipt binds only the consumed prefix. A valid suffix appended after the fork
        // point must leave the child's cache current.
        {
            let mut parent_rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
            parent_rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(1),
                    kind: EventKind::Notice {
                        text: "later parent suffix".into(),
                    },
                })
                .unwrap();
            assert!(parent_rollout.refresh_session_cache().unwrap());
        }
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            meta(&dir, &child).unwrap().projection_digest,
            persisted.projection_digest
        );
        assert!(list(&dir, &tenant).iter().any(|m| m.run_id == child));
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 0);

        // Truncating even one byte from the pinned prefix invalidates the cache and then makes the
        // authoritative fork replay fail rather than returning a projection with missing history.
        let pinned_bytes = persisted.ancestry[0].prefix_bytes;
        std::fs::OpenOptions::new()
            .write(true)
            .open(rollout_path(&dir, &parent).unwrap())
            .unwrap()
            .set_len(pinned_bytes - 1)
            .unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert!(meta(&dir, &child).is_err());
        assert!(READ_CHAIN_CALLS.with(std::cell::Cell::get) >= 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_nested_fork_projection_records_every_ancestor_and_reads_without_replay() {
        let dir = tmpdir("d9-01-nested-fork-cache");
        let tenant = TenantId::default();
        let root = RunId("nested-cache-root".into());
        mk_run(&dir, &root, &tenant, "/repo/nested-cache", "root task");
        let root_tail = read_chain(&rollout_path(&dir, &root).unwrap())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let first = fork(&dir, &root, root_tail, &tenant).unwrap();
        {
            let mut first_rollout = Rollout::open(&dir, &first, tenant.clone()).unwrap();
            first_rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Done {
                        outcome: "Done".into(),
                    },
                })
                .unwrap();
        }
        let first_tail = read_chain(&rollout_path(&dir, &first).unwrap())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let second = fork(&dir, &first, first_tail, &tenant).unwrap();
        complete_one_turn(&dir, &second, &tenant, "nested child task");

        let persisted = private_cache::read_sidecar(
            &dir,
            &crate::cache_io::read_session_meta(&per_run_meta_path(&dir, &second).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted
                .ancestry
                .iter()
                .map(|receipt| receipt.run_id.clone())
                .collect::<Vec<_>>(),
            vec![root.clone(), first.clone()]
        );
        assert!(projection_covers_rollout(&dir, &persisted));

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(meta(&dir, &second).unwrap().turns, 2);
        assert_eq!(list(&dir, &tenant).len(), 3);
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            0,
            "nested fork coverage checks may read receipts but not replay journals"
        );

        let root_receipt = persisted
            .ancestry
            .iter()
            .find(|receipt| receipt.run_id == root)
            .unwrap();
        let root_path = rollout_path(&dir, &root).unwrap();
        let original_root = std::fs::read_to_string(&root_path).unwrap();
        let corrupted_root = forge_middle_record(&original_root);
        assert_eq!(corrupted_root.len(), original_root.len());
        std::fs::write(&root_path, corrupted_root).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&root_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        root_receipt.observed_updated_at.saturating_add(1),
                        root_receipt.observed_updated_at_subsec_nanos,
                    ),
            ))
            .unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert!(matches!(
            meta(&dir, &second),
            Err(RecordError::ChainBroken { .. })
        ));
        assert!(READ_CHAIN_CALLS.with(std::cell::Cell::get) >= 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_tail_receipt_io_is_independent_of_the_rollout_prefix() {
        let dir = tmpdir("d9-01-tail-receipt-bound");
        let run = RunId("long-tail-receipt".into());
        // Content fields are externalized into the content store, so a handful of large payloads
        // no longer produce a large rollout: each line is a digest marker. Grow the prefix by line
        // count until it genuinely exceeds the scan window, or this test asserts nothing.
        let appended = {
            let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
            rollout.append(&genesis_event("/repo/long-tail")).unwrap();
            let path = rollout_path(&dir, &run).unwrap();
            let mut appended = 0u64;
            while std::fs::metadata(&path).unwrap().len() <= (RECEIPT_SCAN_CHUNK_BYTES * 4) as u64 {
                rollout
                    .append(&Event {
                        seq: Seq::ZERO,
                        turn: TurnId(0),
                        kind: EventKind::Notice {
                            text: format!("{}-{appended}", "x".repeat(4_096)),
                        },
                    })
                    .unwrap();
                appended += 1;
                assert!(
                    appended < 100_000,
                    "the rollout prefix never grew past the scan window"
                );
            }
            appended
        };
        let path = rollout_path(&dir, &run).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > (RECEIPT_SCAN_CHUNK_BYTES * 4) as u64);
        RECEIPT_BYTES_READ.with(|bytes| bytes.set(0));
        let (_, seq, _, _) = read_tail_receipt(&path).unwrap();
        assert_eq!(seq, appended);
        assert!(
            RECEIPT_BYTES_READ.with(std::cell::Cell::get) <= RECEIPT_SCAN_CHUNK_BYTES as u64 + 1,
            "tail validation must read at most one fixed chunk for a short final line"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_subprecision_cache_hit_tampering_is_not_tolerated() {
        let dir = tmpdir("d9-01-cache-hit-exact-digest");
        let tenant = TenantId::default();
        let run = RunId("cache-hit-exact".into());
        mk_run(&dir, &run, &tenant, "/repo/cache-hit", "truth");
        let mut forged = meta_from_replay(&dir, &run, None).unwrap();
        let honest_bits = forged.cache_hit.to_bits();
        forged.cache_hit += 1e-13;
        assert_ne!(forged.cache_hit.to_bits(), honest_bits);
        // Retain the old exact digest: even a mutation far below display precision is a cache miss.
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&forged).unwrap(),
        )
        .unwrap();
        std::fs::write(index_path(&dir), encode_index([&forged]).unwrap()).unwrap();

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let recovered = meta(&dir, &run).unwrap();
        assert_eq!(recovered.cache_hit.to_bits(), 0.9_f64.to_bits());
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_same_length_middle_record_corruption_invalidates_the_cache_by_mtime() {
        let dir = tmpdir("d9-01-middle-record-corruption");
        let tenant = TenantId::default();
        let run = RunId("middle-record-corruption".into());
        mk_run(&dir, &run, &tenant, "/repo/middle-corruption", "truth");
        let cached = private_cache::read_sidecar(
            &dir,
            &crate::cache_io::read_session_meta(&per_run_meta_path(&dir, &run).unwrap()).unwrap(),
        )
        .unwrap();
        let path = rollout_path(&dir, &run).unwrap();
        let original_tail = read_tail_receipt(&path).unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let corrupted = forge_middle_record(&original);
        std::fs::write(&path, corrupted).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        cached.updated_at.saturating_add(1),
                        cached.updated_at_subsec_nanos,
                    ),
            ))
            .unwrap();
        assert_eq!(
            read_tail_receipt(&path).unwrap(),
            original_tail,
            "the injected corruption deliberately preserves length and tail receipt"
        );
        assert!(!projection_is_current(&dir, &cached));

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert!(matches!(
            meta(&dir, &run),
            Err(RecordError::ChainBroken { .. })
        ));
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_incremental_projection_matches_full_replay_and_initializes_once() {
        let dir = tmpdir("d9-01-incremental-equivalence");
        let tenant = TenantId::default();
        let run = RunId("incremental-equivalence".into());
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout.append(&genesis_event("/repo/incremental")).unwrap();

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&selection_event("provider-a", "model-a"))
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("incremental title\nsecond line"),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 11,
                        output: 7,
                        cache_creation: 2,
                        cache_read: 3,
                        thinking: 1,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        assert!(rollout.refresh_session_cache().unwrap());
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 5,
                        output: 4,
                        cache_creation: 0,
                        cache_read: 1,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .unwrap();
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            1,
            "K turn-boundary refreshes must pay for only the initialization replay"
        );

        let persisted = private_cache::read_sidecar(
            &dir,
            &crate::cache_io::read_session_meta(&per_run_meta_path(&dir, &run).unwrap()).unwrap(),
        )
        .unwrap();
        let in_memory = match &rollout.session_projection {
            crate::SessionProjectionState::Ready(projection) => projection.projected().clone(),
            _ => panic!("the incremental projection must remain ready"),
        };
        assert!((in_memory.cache_hit - persisted.cache_hit).abs() < 1e-12);
        let mut stable_in_memory = in_memory;
        let mut stable_persisted = persisted.clone();
        stable_in_memory.cache_hit = 0.0;
        stable_persisted.cache_hit = 0.0;
        assert_eq!(
            serde_json::to_value(stable_in_memory).unwrap(),
            serde_json::to_value(stable_persisted).unwrap(),
            "the sidecar must serialize the exact in-memory projection"
        );
        assert_eq!(
            projection_digest(&persisted).unwrap(),
            persisted.projection_digest
        );
        assert!(genesis_matches_meta(
            &rollout_path(&dir, &run).unwrap(),
            &persisted
        ));
        assert!(projection_covers_rollout(&dir, &persisted));
        let cached = meta(&dir, &run).unwrap();
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        let replayed = meta_from_replay(&dir, &run, None).unwrap();
        assert_eq!(cached.turns, 2);
        assert_eq!(cached.provider_id, "provider-a");
        assert_eq!(cached.model, "model-a");
        assert_eq!(cached.title, "incremental title");
        assert!((cached.cache_hit - replayed.cache_hit).abs() < 1e-12);
        let mut stable_cached = cached;
        let mut stable_replayed = replayed;
        stable_cached.cache_hit = 0.0;
        stable_replayed.cache_hit = 0.0;
        assert_eq!(
            serde_json::to_value(&stable_cached).unwrap(),
            serde_json::to_value(&stable_replayed).unwrap(),
            "incremental projection must equal replay on every exact field"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_resumed_writer_replays_once_and_preserves_a_prior_missing_usage_attempt() {
        let dir = tmpdir("d9-01-resume-missing-usage");
        let tenant = TenantId::default();
        let run = RunId("resume-missing-usage".into());
        {
            let mut first = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            first.append(&genesis_event("/repo/resume")).unwrap();
            first
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
            first
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Notice {
                        text: "provider attempt failed before reporting usage".into(),
                    },
                })
                .unwrap();
            let _ = first.refresh_session_cache();
        }

        let mut resumed = Rollout::open(&dir, &run, tenant).unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        resumed
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        resumed
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Message {
                    message: Message::user_text("resumed task"),
                },
            })
            .unwrap();
        resumed
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 3,
                        output: 1,
                        cache_creation: 0,
                        cache_read: 0,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        resumed
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .unwrap();
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            1,
            "a resumed writer must initialize from history only once"
        );
        let cached = meta(&dir, &run).unwrap();
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        assert_eq!(cached.turns, 2);
        assert_eq!(cached.title, "resumed task");
        assert!(matches!(cached.cost, CostState::Unknown { .. }));
        let replayed = meta_from_replay(&dir, &run, None).unwrap();
        assert_eq!(cached.turns, replayed.turns);
        assert_eq!(cached.cost, replayed.cost);
        assert_eq!(cached.record_tail_seq, replayed.record_tail_seq);
        assert_eq!(cached.record_tail_hash, replayed.record_tail_hash);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_g4_later_selection_and_first_message_invalidate_an_untitled_cache() {
        let dir = tmpdir("d9-01-stale-title-route");
        let tenant = TenantId::default();
        let run = RunId("stale-title-route".into());
        let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
        rollout.append(&genesis_event("/repo/stale")).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 1,
                        output: 1,
                        cache_creation: 0,
                        cache_read: 0,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        assert!(rollout.refresh_session_cache().unwrap());
        let before = meta(&dir, &run).unwrap();
        assert_eq!(before.title, "(untitled)");

        rollout
            .append(&selection_event("provider-b", "model-b"))
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("new authoritative title"),
                },
            })
            .unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let after = meta(&dir, &run).unwrap();
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        assert!(after.record_bytes > before.record_bytes);
        assert_eq!(after.provider_id, "provider-b");
        assert_eq!(after.model, "model-b");
        assert_eq!(after.title, "new authoritative title");
        assert_eq!(list(&dir, &tenant)[0].title, "new authoritative title");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_projection_uses_the_same_durable_redacted_event_as_replay() {
        let dir = tmpdir("d9-01-redacted-projection");
        let tenant = TenantId::default();
        let run = RunId("redacted-projection".into());
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout.append(&genesis_event("/repo/redacted")).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text(secret),
                },
            })
            .unwrap();
        rollout.append(&selection_event(secret, secret)).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 3,
                        output: 2,
                        cache_creation: 0,
                        cache_read: 0,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .unwrap();

        let cached = meta(&dir, &run).unwrap();
        let replayed = meta_from_replay(&dir, &run, None).unwrap();
        assert_eq!(cached.title, replayed.title);
        assert_eq!(cached.provider_id, replayed.provider_id);
        assert_eq!(cached.model, replayed.model);
        assert!(cached.title.contains("[REDACTED"));
        let all_cache_and_record_bytes = [
            std::fs::read_to_string(dir.join("redacted-projection.jsonl")).unwrap(),
            std::fs::read_to_string(per_run_meta_path(&dir, &run).unwrap()).unwrap(),
            std::fs::read_to_string(delta_index_path(&dir)).unwrap(),
        ]
        .join("\n");
        assert!(!all_cache_and_record_bytes.contains(secret));
        assert!(all_cache_and_record_bytes.contains("[REDACTED"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_g3_same_length_cache_tampering_degrades_to_tenant_correct_replay() {
        let dir = tmpdir("d9-01-cache-tamper");
        let tenant = TenantId("acme".into());
        let attacker = TenantId("evil".into());
        let run = RunId("tamper".into());
        mk_run(&dir, &run, &tenant, "/repo/tamper", "truth");

        let mut forged = meta_from_replay(&dir, &run, None).unwrap();
        forged.title = "false".into();
        forged.tenant = attacker.clone();
        // Deliberately retain the old digest. Both mutations preserve JSON shape and byte length,
        // so a cursor-only cache check would accept them.
        let forged_sidecar = serde_json::to_vec_pretty(&forged).unwrap();
        std::fs::write(per_run_meta_path(&dir, &run).unwrap(), forged_sidecar).unwrap();
        std::fs::write(index_path(&dir), encode_index([&forged]).unwrap()).unwrap();

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let direct = meta(&dir, &run).unwrap();
        assert_eq!(direct.title, "truth");
        assert_eq!(direct.tenant, tenant);
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);

        // Corrupt both cache layers again so the listing itself must take the replay path.
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&forged).unwrap(),
        )
        .unwrap();
        std::fs::write(index_path(&dir), encode_index([&forged]).unwrap()).unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let listed = list(&dir, &tenant);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].title, "truth");
        assert!(list(&dir, &attacker).is_empty());
        assert!(READ_CHAIN_CALLS.with(std::cell::Cell::get) >= 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_g3_missing_torn_and_oversized_caches_all_replay_correctly() {
        let dir = tmpdir("d9-01-cache-degrade");
        let tenant = TenantId::default();
        let run = RunId("cache-degrade".into());
        mk_run(&dir, &run, &tenant, "/repo/cache-degrade", "authoritative");
        assert_eq!(reindex(&dir).unwrap(), 1);
        let sidecar = per_run_meta_path(&dir, &run).unwrap();
        let index = index_path(&dir);

        let corruptions = [
            b"{".to_vec(),
            vec![b'x'; crate::cache_io::MAX_SESSION_META_BYTES],
            vec![b'x'; crate::cache_io::MAX_SESSION_META_BYTES + 1],
        ];
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::remove_file(&index).unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        assert_eq!(list(&dir, &tenant)[0].title, "authoritative");
        assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);

        for corrupt in corruptions {
            std::fs::write(&sidecar, &corrupt).unwrap();
            std::fs::write(&index, &corrupt).unwrap();
            READ_CHAIN_CALLS.with(|calls| calls.set(0));
            let listed = list(&dir, &tenant);
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].title, "authoritative");
            assert_eq!(READ_CHAIN_CALLS.with(std::cell::Cell::get), 1);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_fork_cache_cannot_hide_its_parent_provenance() {
        let dir = tmpdir("d9-01-fork-cache-forge");
        let tenant = TenantId::default();
        let parent = RunId("fork-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/fork", "parent task");
        let tail = read_chain(&rollout_path(&dir, &parent).unwrap())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let child = fork(&dir, &parent, tail, &tenant).unwrap();
        let mut forged = meta_from_replay(&dir, &child, None).unwrap();
        assert!(forged.parent.is_some());
        forged.parent = None;
        forged.projection_digest = projection_digest(&forged).unwrap();
        assert!(
            !projection_covers_rollout(&dir, &forged),
            "the child genesis must contradict a cache-forged parent=None"
        );
        write_meta_sidecar(&dir, &forged).unwrap();

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let recovered = meta(&dir, &child).unwrap();
        assert_eq!(recovered.parent.unwrap().parent_run, parent);
        assert!(READ_CHAIN_CALLS.with(std::cell::Cell::get) >= 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_repeated_refresh_never_replays_unrelated_noncoverable_runs() {
        let dir = tmpdir("d9-01-no-unrelated-replay");
        let tenant = TenantId::default();
        let current = RunId("current".into());
        let parent = RunId("parent".into());
        mk_run(&dir, &current, &tenant, "/repo/current", "current task");
        mk_run(&dir, &parent, &tenant, "/repo/parent", "parent task");

        let zero = RunId("zero".into());
        let mut zero_rollout = Rollout::open(&dir, &zero, tenant.clone()).unwrap();
        zero_rollout.append(&genesis_event("/repo/zero")).unwrap();
        drop(zero_rollout);
        let parent_tail = read_chain(&rollout_path(&dir, &parent).unwrap())
            .unwrap()
            .last()
            .unwrap()
            .seq;
        let child = fork(&dir, &parent, parent_tail, &tenant).unwrap();
        assert!(
            meta_from_replay(&dir, &child, None)
                .unwrap()
                .parent
                .is_some()
        );

        let mut current_rollout = Rollout::open(&dir, &current, tenant).unwrap();
        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        for _ in 0..12 {
            assert!(current_rollout.refresh_session_cache().unwrap());
        }
        assert_eq!(
            READ_CHAIN_CALLS.with(std::cell::Cell::get),
            1,
            "only the current rollout may be replayed once to initialize its writer projection"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn incremental_page_keeps_active_run_fresh_and_invalidates_old_cursor() {
        let dir = tmpdir("incremental-page");
        let tenant = TenantId::default();
        let active = RunId("active-page-run".into());
        let older = RunId("older-page-run".into());
        mk_run(&dir, &older, &tenant, "/repo/page", "older");
        mk_run(&dir, &active, &tenant, "/repo/page", "active");
        reindex(&dir).unwrap();

        let mut rollout = Rollout::open(&dir, &active, tenant.clone()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnEnd {
                    usage: Usage::default(),
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        assert!(rollout.refresh_session_cache().unwrap());

        let first = page(&dir, &tenant, Some(Path::new("/repo/page")), None, Some(1));
        assert!(first.index_ready);
        assert_eq!(first.sessions[0].run_id, active);
        let cursor = first.next_cursor.expect("one older session remains");

        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(2),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(2),
                kind: EventKind::TurnEnd {
                    usage: Usage::default(),
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        assert!(rollout.refresh_session_cache().unwrap());
        let stale = page(
            &dir,
            &tenant,
            Some(Path::new("/repo/page")),
            Some(cursor),
            Some(1),
        );
        assert!(stale.cursor_stale);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn incomplete_publication_and_unpublished_delta_tail_are_never_ready() {
        let dir = tmpdir("page-incomplete-publication");
        let tenant = TenantId::default();
        let run = RunId("incomplete-page-run".into());
        mk_run(&dir, &run, &tenant, "/repo/page", "visible");
        reindex(&dir).unwrap();
        let projected = meta_from_replay(&dir, &run, None).unwrap();

        crate::cache_io::with_session_index_lock(&dir, || {
            mark_index_dirty_unlocked(&dir).unwrap();
            write_meta_sidecar(&dir, &projected).unwrap();
            Ok(())
        })
        .unwrap();
        let crashed = page(&dir, &tenant, None, None, Some(25));
        assert!(!crashed.index_ready);
        assert!(!crashed.rebuild_recommended);
        assert!(crashed.sessions.is_empty());

        reindex(&dir).unwrap();
        write_meta(&dir, &projected).unwrap();
        std::fs::remove_file(delta_ref_path(&dir, &run)).unwrap();
        let unpublished = page(&dir, &tenant, None, None, Some(25));
        assert!(!unpublished.index_ready);
        assert!(unpublished.rebuild_recommended);
        assert!(unpublished.sessions.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn page_detects_snapshot_change_after_open_for_first_page_and_cursor() {
        let dir = tmpdir("page-concurrent-generation");
        let tenant = TenantId::default();
        let runs = [
            RunId("concurrent-page-a".into()),
            RunId("concurrent-page-b".into()),
        ];
        for run in &runs {
            mk_run(&dir, run, &tenant, "/repo/page", &run.0);
        }
        reindex(&dir).unwrap();
        let initial = page(&dir, &tenant, None, None, Some(1));
        assert!(initial.next_cursor.is_some());
        let projected = meta_from_replay(&dir, &runs[0], None).unwrap();

        let hook_dir = dir.clone();
        let hook_meta = projected.clone();
        AFTER_PAGE_SNAPSHOT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                write_meta(&hook_dir, &hook_meta).unwrap();
            }));
        });
        let first_page = page(&dir, &tenant, None, None, Some(1));
        assert!(!first_page.index_ready);
        assert!(!first_page.rebuild_recommended);
        assert!(first_page.sessions.is_empty());

        let refreshed = page(&dir, &tenant, None, None, Some(1));
        let cursor = refreshed.next_cursor.expect("the second session remains");
        let hook_dir = dir.clone();
        AFTER_PAGE_SNAPSHOT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                write_meta(&hook_dir, &projected).unwrap();
            }));
        });
        let continuation = page(&dir, &tenant, None, Some(cursor), Some(1));
        assert!(continuation.index_ready);
        assert!(continuation.cursor_stale);
        assert!(continuation.sessions.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn delta_hard_bounds_refuse_growth_and_locked_compaction_resets_state() {
        let dir = tmpdir("delta-hard-bound");
        let tenant = TenantId::default();
        let run = RunId("delta-bound-run".into());
        mk_run(&dir, &run, &tenant, "/repo/delta", "bounded");
        reindex(&dir).unwrap();
        let projected = meta_from_replay(&dir, &run, None).unwrap();
        write_meta(&dir, &projected).unwrap();
        assert_eq!(read_delta_state(&dir).unwrap().rows, 1);

        crate::cache_io::with_session_index_lock(&dir, || {
            let mut file = OpenOptions::new()
                .append(true)
                .open(delta_index_path(&dir))?;
            file.write_all(b"\n")?;
            file.sync_data()?;
            let high_water = file.metadata()?.len();
            write_delta_state_unlocked(
                &dir,
                SessionDeltaState {
                    version: SESSION_DELTA_INDEX_VERSION,
                    generation: read_delta_state(&dir)?.generation,
                    rows: SESSION_DELTA_HARD_LIMITS.rows,
                    high_water,
                },
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            assert!(matches!(
                append_delta_index_unlocked(&dir, &projected),
                Err(RecordError::Io(ref error)) if error.kind() == io::ErrorKind::WouldBlock
            ));
            compact_session_index_unlocked(&dir)
                .map_err(|error| io::Error::other(error.to_string()))
        })
        .unwrap();
        let state = read_delta_state(&dir).unwrap();
        assert_eq!(state.rows, 0);
        assert!(state.high_water <= SESSION_DELTA_HARD_LIMITS.bytes);
        assert!(page(&dir, &tenant, None, None, Some(25)).index_ready);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_01_concurrent_upserts_preserve_exactly_one_entry_per_run() {
        let dir = tmpdir("d9-01-concurrent-upsert");
        let tenant = TenantId::default();
        let run_count = 8usize;
        let mut rollouts = Vec::new();
        for position in 0..run_count {
            let run = RunId(format!("concurrent-{position}"));
            let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            rollout
                .append(&genesis_event(&format!("/repo/concurrent-{position}")))
                .unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text(format!("concurrent task {position}")),
                    },
                })
                .unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnEnd {
                        usage: Usage {
                            input: 2,
                            output: 1,
                            cache_creation: 0,
                            cache_read: 0,
                            thinking: 0,
                        },
                        ttft_ms: None,
                        decode_ms: None,
                        stream_items: None,
                    },
                })
                .unwrap();
            rollouts.push(rollout);
        }
        // TurnEnd performs the normal automatic boundary write. The barrier below exercises
        // simultaneous O(1) delta publications from eight live record-owned projections without
        // requiring or rewriting the sorted base index.

        let barrier = Arc::new(std::sync::Barrier::new(run_count));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for mut rollout in rollouts {
                let barrier = Arc::clone(&barrier);
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    let published = rollout.refresh_session_cache();
                    (rollout, published)
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        for (mut rollout, published) in results {
            if let Err(RecordError::Io(error)) = &published {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(rollout.refresh_session_cache().unwrap());
            } else {
                assert!(published.unwrap());
            }
        }

        let state = read_delta_state(&dir).unwrap();
        assert_eq!(state.rows, (run_count * 2) as u64);
        let indexed = page(&dir, &tenant, None, None, Some(run_count + 1));
        assert!(indexed.index_ready);
        assert_eq!(indexed.sessions.len(), run_count);
        let ids: HashSet<RunId> = indexed
            .sessions
            .iter()
            .map(|meta| meta.run_id.clone())
            .collect();
        assert_eq!(ids.len(), run_count);
        assert_eq!(list(&dir, &tenant).len(), run_count);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_cache_failure_never_poisons_the_authoritative_writer() {
        let dir = tmpdir("d9-01-cache-failure");
        let tenant = TenantId::default();
        let run = RunId("cache-failure".into());
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&genesis_event("/repo/cache-failure"))
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("survives cache failure"),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 1,
                        output: 1,
                        cache_creation: 0,
                        cache_read: 0,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();

        // Replace the O(1) append log with a directory to inject a projection-publication failure
        // at the next explicit refresh. The durable rollout writer must remain usable.
        std::fs::remove_file(delta_index_path(&dir)).unwrap();
        std::fs::create_dir_all(delta_index_path(&dir)).unwrap();
        assert!(rollout.refresh_session_cache().is_err());
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .expect("a rebuildable-cache failure must not poison the journal writer");
        std::fs::remove_dir(delta_index_path(&dir)).unwrap();
        drop(rollout);
        assert_eq!(reindex(&dir).unwrap(), 1);

        assert_eq!(meta(&dir, &run).unwrap().title, "survives cache failure");
        assert!(
            matches!(
                crate::replay(&rollout_path(&dir, &run).unwrap())
                    .unwrap()
                    .last()
                    .map(|event| &event.kind),
                Some(EventKind::Done { outcome }) if outcome == "Done"
            ),
            "the durable terminal event must survive the failed cache refresh"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_01_failed_append_is_never_observed_by_the_projection() {
        let dir = tmpdir("d9-01-failed-append-projection");
        let tenant = TenantId::default();
        let run = RunId("failed-append-projection".into());
        let attempted_title = "must never become a cached title";
        let path;
        {
            let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            rollout
                .append(&genesis_event("/repo/failed-append"))
                .unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
            path = rollout.path().to_path_buf();

            // Simulate an out-of-band torn write after the writer's durable cursor. The next
            // append must fail before writing or projecting its caller-provided event.
            let mut external = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut external, b"{torn").unwrap();
            external.sync_all().unwrap();
            let error = rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text(attempted_title),
                    },
                })
                .unwrap_err();
            assert!(matches!(error, RecordError::Io(_)));
            assert!(
                !std::fs::read_to_string(&path)
                    .unwrap()
                    .contains(attempted_title)
            );
            assert!(!rollout.refresh_session_cache().unwrap());
        }

        // Reopen truncates the torn suffix and gives a fresh projection one bounded replay.
        let mut recovered = Rollout::open(&dir, &run, tenant).unwrap();
        recovered
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: Usage {
                        input: 1,
                        output: 1,
                        cache_creation: 0,
                        cache_read: 0,
                        thinking: 0,
                    },
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            })
            .unwrap();
        recovered
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "Done".into(),
                },
            })
            .unwrap();
        drop(recovered);
        assert_eq!(meta(&dir, &run).unwrap().title, "(untitled)");
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains(attempted_title)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_meta_and_reindex_round_trip() {
        let dir = tmpdir("cache");
        let t = TenantId::default();
        let run = RunId("z".into());
        mk_run(&dir, &run, &t, "/repo/z", "cache me");
        // reindex builds the cache from the record
        assert_eq!(reindex(&dir).unwrap(), 1);
        assert!(per_run_meta_path(&dir, &run).unwrap().exists());
        // A cache can be edited independently of the hash-chained rollout and carries no HMAC
        // evidence. Even a schema-current cache-only Known claim must be ignored by default.
        let mut m = meta_from_replay(&dir, &run, None).unwrap();
        m.cost = CostState::Known {
            amount_microusd: 1_230_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        write_meta(&dir, &m).unwrap();
        let via_cache = meta(&dir, &run).unwrap();
        assert_eq!(
            via_cache.cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
            },
            "cache-only Known must be rebuilt without monetary trust"
        );
        let listed = list(&dir, &t);
        assert_eq!(listed.len(), 1);
        assert!(matches!(listed[0].cost, CostState::Unknown { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_10_g2_interrupted_meta_replacement_keeps_a_valid_covering_projection() {
        let dir = tmpdir("cache-atomic-projection");
        let tenant = TenantId::default();
        let run = RunId("atomic-projection".into());
        mk_run(&dir, &run, &tenant, "/repo/atomic", "original title");
        assert_eq!(reindex(&dir).unwrap(), 1);
        let path = per_run_meta_path(&dir, &run).unwrap();
        let old = std::fs::read(&path).unwrap();
        let old_meta = private_cache::read_sidecar(&dir, &old).unwrap();
        assert!(projection_covers_rollout(&dir, &old_meta));

        let mut replacement = old_meta.clone();
        replacement.title = "replacement title".into();
        let error = crate::cache_io::fail_before_rename(
            &path,
            &serde_json::to_vec_pretty(&replacement).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(std::fs::read(&path).unwrap(), old);

        let after = private_cache::read_sidecar(&dir, &std::fs::read(&path).unwrap()).unwrap();
        assert!(projection_covers_rollout(&dir, &after));
        assert_eq!(meta(&dir, &run).unwrap().title, "original title");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_12_g1_turn_boundary_writes_upsert_one_index_line_per_run() {
        let dir = tmpdir("bounded-index-upsert");
        let tenant = TenantId::default();
        let runs = [RunId("index-a".into()), RunId("index-b".into())];
        for (position, run) in runs.iter().enumerate() {
            mk_run(
                &dir,
                run,
                &tenant,
                "/repo/index",
                &format!("task {position}"),
            );
        }

        for write in 0..32u64 {
            let run = &runs[(write as usize) % runs.len()];
            let projected = meta_from_replay(&dir, run, None).unwrap();
            write_meta(&dir, &projected).unwrap();
        }

        let state = read_delta_state(&dir).unwrap();
        assert_eq!(state.rows, 2 * runs.len() as u64 + 32);
        assert!(state.rows < SESSION_DELTA_HARD_LIMITS.rows);
        assert!(state.high_water < SESSION_DELTA_HARD_LIMITS.bytes);
        assert!(runs.iter().all(|run| read_delta_ref(&dir, run).is_some()));
        let indexed = page(&dir, &tenant, None, None, Some(runs.len() + 1));
        assert!(indexed.index_ready);
        let ids: HashSet<RunId> = indexed
            .sessions
            .iter()
            .map(|meta| meta.run_id.clone())
            .collect();
        assert_eq!(ids, runs.iter().cloned().collect());
        assert_eq!(list(&dir, &tenant).len(), runs.len());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_12_g1_append_era_index_scan_is_o_live_runs_and_line_bounded() {
        let dir = tmpdir("bounded-index-read");
        let tenant = TenantId::default();
        let runs = [
            RunId("bounded-a".into()),
            RunId("bounded-b".into()),
            RunId("bounded-c".into()),
        ];
        let mut projected = Vec::new();
        for (position, run) in runs.iter().enumerate() {
            mk_run(
                &dir,
                run,
                &tenant,
                "/repo/bounded",
                &format!("bounded task {position}"),
            );
            projected.push(meta_from_replay(&dir, run, None).unwrap());
        }

        let mut historical = Vec::new();
        for _ in 0..128 {
            historical.extend_from_slice(&encode_index(projected.iter()).unwrap());
        }
        std::fs::write(index_path(&dir), historical).unwrap();

        let max_lines = max_index_scan_lines(runs.len());
        let scan = crate::cache_io::scan_index_lines(&index_path(&dir), max_lines).unwrap();
        assert!(!scan.complete, "K historical writes must abandon the cache");
        assert_eq!(scan.lines_examined, max_lines + 1);
        assert!(
            scan.lines.is_empty(),
            "an incomplete prefix is never trusted"
        );

        let listed = list(&dir, &tenant);
        assert_eq!(listed.len(), runs.len());
        let unavailable = page(&dir, &tenant, None, None, Some(runs.len()));
        assert!(!unavailable.index_ready && unavailable.rebuild_recommended);
        assert_eq!(reindex(&dir).unwrap(), runs.len());
        let repaired = read_index(&dir, runs.len());
        assert!(repaired.exact);
        assert_eq!(repaired.entries.len(), runs.len());

        let oversized = vec![b'x'; crate::cache_io::MAX_INDEX_LINE_BYTES + 1];
        std::fs::write(index_path(&dir), oversized).unwrap();
        let oversized_scan =
            crate::cache_io::scan_index_lines(&index_path(&dir), max_lines).unwrap();
        assert!(!oversized_scan.complete);
        assert_eq!(oversized_scan.lines_examined, 1);
        assert!(oversized_scan.lines.is_empty());
        assert_eq!(list(&dir, &tenant).len(), runs.len());
        let unavailable = page(&dir, &tenant, None, None, Some(runs.len()));
        assert!(!unavailable.index_ready && unavailable.rebuild_recommended);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn d9_12_g2_crash_mid_compaction_replays_and_repairs_without_wrong_listing() {
        let dir = tmpdir("index-compaction-crash");
        let tenant = TenantId::default();
        let runs = [RunId("crash-a".into()), RunId("crash-b".into())];
        let mut current = Vec::new();
        for (position, run) in runs.iter().enumerate() {
            mk_run(
                &dir,
                run,
                &tenant,
                "/repo/crash",
                &format!("authoritative task {position}"),
            );
            current.push(meta_from_replay(&dir, run, None).unwrap());
        }

        let mut stale = current.clone();
        for meta in &mut stale {
            meta.record_bytes = 0;
            meta.title = "forged stale title".into();
        }
        let mut append_era = Vec::new();
        for _ in 0..16 {
            append_era.extend_from_slice(&encode_index(stale.iter()).unwrap());
        }
        crate::cache_io::atomic_replace(&index_path(&dir), &append_era).unwrap();
        let old = std::fs::read(index_path(&dir)).unwrap();

        let compacted = encode_index(current.iter()).unwrap();
        let error = crate::cache_io::fail_before_rename(&index_path(&dir), &compacted)
            .expect_err("injected crash must interrupt the exact atomic replacement primitive");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read(index_path(&dir)).unwrap(), old);

        let listed = list(&dir, &tenant);
        assert_eq!(listed.len(), runs.len());
        assert!(
            listed
                .iter()
                .all(|meta| meta.title.starts_with("authoritative task")),
            "the stale pre-crash index prefix must never become a listing"
        );
        let unavailable = page(&dir, &tenant, None, None, Some(runs.len()));
        assert!(!unavailable.index_ready && unavailable.rebuild_recommended);
        assert_eq!(reindex(&dir).unwrap(), runs.len());
        let repaired = read_index(&dir, runs.len());
        assert!(repaired.exact);
        assert_eq!(repaired.entries.len(), runs.len());
        let repaired_ids: HashSet<RunId> = repaired.entries.into_iter().map(|m| m.run_id).collect();
        assert_eq!(repaired_ids, runs.iter().cloned().collect());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn forged_zero_cache_and_index_are_replayed_instead_of_trusted() {
        let dir = tmpdir("cache-forged-zero");
        let tenant = TenantId::default();
        let run = RunId("forged-zero".into());
        mk_run(&dir, &run, &tenant, "/repo/z", "billable request");
        let mut forged = meta_from_replay(&dir, &run, None).unwrap();
        assert!(forged.record_bytes > 0);
        forged.cost = CostState::Zero;
        write_meta(&dir, &forged).unwrap();

        let direct = meta(&dir, &run).unwrap();
        assert_eq!(
            direct.cost,
            CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
            },
            "an unauthenticated cache cannot prove exact zero after a provider turn"
        );
        let listed = list(&dir, &tenant);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].cost, direct.cost);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn session_paths_reject_traversal_in_record_and_cache_run_ids() {
        let root = tmpdir("run-id-traversal");
        let runs = root.join("runs");
        let tenant = TenantId::default();
        let safe = RunId("safe".into());
        mk_run(&runs, &safe, &tenant, "/repo/safe", "safe task");

        let escaped_name = "escaped-session-meta";
        let attack = RunId(format!("../{escaped_name}"));
        let meta_error = meta(&runs, &attack).expect_err("meta lookup must reject a traversal id");
        assert!(matches!(meta_error, RecordError::InvalidRunId { .. }));

        let mut projected = meta(&runs, &safe).unwrap();
        projected.run_id = attack;
        let write_error =
            write_meta(&runs, &projected).expect_err("cache writes must reject a traversal id");
        assert!(matches!(write_error, RecordError::InvalidRunId { .. }));
        assert!(
            !root.join(format!("{escaped_name}.meta.json")).exists(),
            "a hostile run id must not escape runs_dir through a sidecar write"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fork_rejects_a_caller_from_another_tenant_before_creating_a_child() {
        let dir = tmpdir("fork-tenant-boundary");
        let acme = TenantId("acme".into());
        let parent = RunId("acme-parent".into());
        mk_run(&dir, &parent, &acme, "/repo/acme", "tenant task");
        let before = rollout_run_ids(&dir).len();

        let error = fork(&dir, &parent, Seq(4), &TenantId("globex".into()))
            .expect_err("cross-tenant fork must be rejected");
        assert!(matches!(
            error,
            RecordError::TenantMismatch {
                seq: 0,
                ref expected,
                ref found,
            } if expected == "globex" && found == "acme"
        ));
        assert_eq!(
            rollout_run_ids(&dir).len(),
            before,
            "tenant validation must happen before minting/writing the child"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_forked_rejects_a_handcrafted_cross_tenant_parent_edge() {
        let dir = tmpdir("fork-chain-tenant-boundary");
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let parent = RunId("acme-parent".into());
        mk_run(&dir, &parent, &acme, "/repo/acme", "parent task");
        let parent_lines = read_chain(&rollout_path(&dir, &parent).unwrap()).unwrap();
        let pinned = parent_lines
            .iter()
            .find(|line| line.seq == Seq(4))
            .unwrap()
            .hash
            .clone();

        // Public `fork` now prevents this shape. Write a valid child journal directly to model a
        // malicious/legacy record whose genesis crosses the tenant boundary.
        let child = RunId("globex-child".into());
        {
            let mut rollout = Rollout::open(&dir, &child, globex).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::RunStart {
                        cwd: "/repo/globex".into(),
                        model: "claude".into(),
                        effort: Effort::Medium,
                        created_at: 1001,
                        environment: None,
                        parent_run: Some(parent.0.clone()),
                        forked_at: Some(4),
                        parent_hash_at_seq: Some(pinned),
                        config_digest: "cfg".into(),
                        agent_definition_tag: None,
                        max_usd: None,
                    },
                })
                .unwrap();
        }

        let error = load_forked(&dir, &child)
            .expect_err("a cross-tenant fork edge must not be materialized");
        assert!(matches!(
            error,
            RecordError::TenantMismatch {
                seq: 0,
                ref expected,
                ref found,
            } if expected == "globex" && found == "acme"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_references_the_parent_and_load_concatenates() {
        let dir = tmpdir("fork");
        let t = TenantId::default();
        let parent = RunId("p".into());
        mk_run(&dir, &parent, &t, "/repo/p", "parent-task");
        // fork at the parent tail (seq 4), then add a follow-up to the child
        let child = fork(&dir, &parent, Seq(4), &t).unwrap();
        {
            let mut r = Rollout::open(&dir, &child, t.clone()).unwrap();
            r.append(&Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("child-follow-up"),
                },
            })
            .unwrap();
        }
        // the child's own meta shows the provenance cross-link
        let cm = meta(&dir, &child).unwrap();
        let prov = cm.parent.expect("child records provenance");
        assert_eq!(prov.parent_run, parent);
        assert_eq!(prov.forked_at, Seq(4));
        assert!(!prov.parent_hash_at_seq.is_empty());
        // load_forked replays the parent prefix, then appends the child's events
        let events = load_forked(&dir, &child).unwrap();
        assert_eq!(user_texts(&events), vec!["parent-task", "child-follow-up"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_inherits_the_bounded_agent_definition_tag() {
        let dir = tmpdir("fork-agent-definition-tag");
        let tenant = TenantId::default();
        let parent = RunId("tagged-parent".into());
        let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
        let mut genesis = genesis_event("/repo");
        if let EventKind::RunStart {
            agent_definition_tag,
            ..
        } = &mut genesis.kind
        {
            *agent_definition_tag = Some("reviewer-a".into());
        }
        rollout.append(&genesis).unwrap();
        let at = crate::replay(rollout.path()).unwrap().last().unwrap().seq;

        let child = fork(&dir, &parent, at, &tenant).unwrap();
        let child_meta = meta(&dir, &child).unwrap();
        assert_eq!(
            child_meta.agent_definition_tag.as_deref(),
            Some("reviewer-a")
        );
        let child_events = crate::replay(&rollout_path(&dir, &child).unwrap()).unwrap();
        assert!(matches!(
            &child_events[0].kind,
            EventKind::RunStart {
                agent_definition_tag: Some(tag),
                ..
            } if tag == "reviewer-a"
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_11_fork_reads_the_direct_parent_once_under_the_logical_budget() {
        let dir = tmpdir("fork-single-read");
        let tenant = TenantId::default();
        let parent = RunId("fork-single-read-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/p", "parent-task");

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();
        let reads = READ_CHAIN_CALLS.with(std::cell::Cell::get);
        assert_eq!(reads, 1, "fork must reuse its verified parent lines");

        let _ = std::fs::remove_file(rollout_path(&dir, &child).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn d9_11_meta_reads_each_child_and_parent_journal_once_under_one_budget() {
        let dir = tmpdir("meta-single-read");
        let tenant = TenantId::default();
        let parent = RunId("meta-single-read-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/p", "parent-task");
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();

        READ_CHAIN_CALLS.with(|calls| calls.set(0));
        let projected = meta_from_replay(&dir, &child, None).unwrap();
        let reads = READ_CHAIN_CALLS.with(std::cell::Cell::get);
        assert_eq!(projected.parent.unwrap().parent_run, parent);
        assert_eq!(
            reads, 2,
            "meta must read the child and parent exactly once each"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_inherits_the_latest_selection_at_or_before_the_exact_sequence() {
        let dir = tmpdir("fork-selection-seq");
        let tenant = TenantId::default();
        let parent = RunId("route-parent".into());
        {
            let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/routes")).unwrap(); // seq 0
            rollout
                .append(&selection_event("anthropic-a", "claude-a"))
                .unwrap(); // seq 1
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text("between routes"),
                    },
                })
                .unwrap(); // seq 2
            rollout
                .append(&selection_event("openai-b", "gpt-b"))
                .unwrap(); // seq 3
        }

        let before_second = fork(&dir, &parent, Seq(2), &tenant).unwrap();
        let at_second = fork(&dir, &parent, Seq(3), &tenant).unwrap();
        assert_eq!(
            latest_selection(&crate::replay(&rollout_path(&dir, &before_second).unwrap()).unwrap()),
            Some(("anthropic-a".into(), "claude-a".into()))
        );
        assert_eq!(
            latest_selection(&crate::replay(&rollout_path(&dir, &at_second).unwrap()).unwrap()),
            Some(("openai-b".into(), "gpt-b".into()))
        );
        let projected = meta(&dir, &at_second).unwrap();
        assert_eq!(projected.provider_id, "openai-b");
        assert_eq!(projected.model, "gpt-b");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_snapshots_effective_runtime_policy_at_the_exact_branch_point() {
        let dir = tmpdir("fork-runtime-policy");
        let tenant = TenantId::default();
        let parent = RunId("policy-parent".into());
        let mut denied_code = PermissionRules::new();
        denied_code.set_cap(Capability::CodeExecuting, Verdict::Deny);
        {
            let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/policy")).unwrap(); // seq 0
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::EffortChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        effort: Effort::High,
                    },
                })
                .unwrap(); // seq 1
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::PolicyChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        mode: PermissionMode::AcceptEdits,
                        rules: denied_code.clone(),
                    },
                })
                .unwrap(); // seq 2
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::EffortChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        effort: Effort::Max,
                    },
                })
                .unwrap(); // seq 3
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::PolicyChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        mode: PermissionMode::Plan,
                        rules: PermissionRules::new(),
                    },
                })
                .unwrap(); // seq 4
        }

        let early = fork(&dir, &parent, Seq(2), &tenant).unwrap();
        let late = fork(&dir, &parent, Seq(4), &tenant).unwrap();

        let early_physical = crate::replay(&rollout_path(&dir, &early).unwrap()).unwrap();
        let early_state = RuntimePolicyState::from_events(&early_physical);
        assert_eq!(early_state.effort, Effort::High);
        assert_eq!(early_state.permission_mode, PermissionMode::AcceptEdits);
        assert_eq!(early_state.permission_rules, denied_code);
        assert!(early_physical.iter().any(|event| matches!(
            event.kind,
            EventKind::EffortChanged {
                source: RuntimePolicySource::Fork,
                ..
            }
        )));
        assert!(early_physical.iter().any(|event| matches!(
            event.kind,
            EventKind::PolicyChanged {
                source: RuntimePolicySource::Fork,
                ..
            }
        )));

        let late_physical = crate::replay(&rollout_path(&dir, &late).unwrap()).unwrap();
        let late_state = RuntimePolicyState::from_events(&late_physical);
        assert_eq!(late_state.effort, Effort::Max);
        assert_eq!(late_state.permission_mode, PermissionMode::Plan);
        assert!(late_state.permission_rules.is_empty());

        let late_logical = load_forked(&dir, &late).unwrap();
        assert_eq!(RuntimePolicyState::from_events(&late_logical), late_state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nested_fork_at_child_genesis_inherits_the_ancestor_route() {
        let dir = tmpdir("nested-fork-selection");
        let tenant = TenantId::default();
        let root = RunId("route-root".into());
        {
            let mut rollout = Rollout::open(&dir, &root, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/routes")).unwrap();
            rollout
                .append(&selection_event(
                    "fireworks-work",
                    "accounts/a/models/coder",
                ))
                .unwrap();
        }
        let first = fork(&dir, &root, Seq(1), &tenant).unwrap();
        // seq 0 is the first child's physical genesis. Its effective state already includes the
        // root prefix, so a fork here must retain the ancestor provider as well as the model.
        let second = fork(&dir, &first, Seq(0), &tenant).unwrap();
        let physical = crate::replay(&rollout_path(&dir, &second).unwrap()).unwrap();
        assert_eq!(
            latest_selection(&physical),
            Some(("fireworks-work".into(), "accounts/a/models/coder".into()))
        );
        let logical = load_forked(&dir, &second).unwrap();
        assert_eq!(latest_selection(&logical), latest_selection(&physical));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forking_a_legacy_record_preserves_model_without_inventing_provider() {
        let dir = tmpdir("legacy-fork-route");
        let tenant = TenantId::default();
        let parent = RunId("legacy-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/legacy", "legacy task");
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();
        let physical = crate::replay(&rollout_path(&dir, &child).unwrap()).unwrap();
        assert!(latest_selection(&physical).is_none());
        let projected = meta(&dir, &child).unwrap();
        assert!(projected.provider_id.is_empty());
        assert_eq!(projected.model, "claude");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_at_replay_tail_preserves_the_whole_kernel_written_parent() {
        // End-to-end regression for the CRITICAL fork data-loss bug, mirroring the REAL flow: the
        // kernel writes every payload with a placeholder seq (Seq::ZERO), and the CLI computes the
        // fork point as `replay(parent).last().seq`. Before the fix that was 0, so the child forked
        // at genesis and reconstructed ZERO parent messages. The prior fork test missed this by
        // writing distinct payload seqs and forking at a hardcoded Seq(4).
        let dir = tmpdir("fork-kernel");
        let t = TenantId::default();
        let parent = RunId("pk".into());
        {
            let mut r = Rollout::open(&dir, &parent, t.clone()).unwrap();
            // all payloads Seq::ZERO, exactly like kernel `emit`
            r.append(&genesis_event("/repo/pk")).unwrap();
            for text in ["first-turn", "second-turn"] {
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text(text),
                    },
                })
                .unwrap();
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnEnd {
                        usage: Usage::default(),
                        ttft_ms: None,
                        decode_ms: None,
                        stream_items: None,
                    },
                })
                .unwrap();
            }
        }
        // Compute the fork point the way the CLI does — from the replayed tail seq.
        let events = crate::replay(&rollout_path(&dir, &parent).unwrap()).unwrap();
        let at = events.last().map(|e| e.seq).unwrap();
        assert_ne!(
            at,
            Seq(0),
            "replay tail must be the real last seq, not the placeholder 0"
        );
        let child = fork(&dir, &parent, at, &t).unwrap();
        // Resuming the child must reconstruct BOTH parent turns, not an empty transcript.
        let loaded = load_forked(&dir, &child).unwrap();
        assert_eq!(user_texts(&loaded), vec!["first-turn", "second-turn"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_the_parent_prefix_is_detected_on_fork_load() {
        // ADR-008 §4 / R5-review Risk 3: an attacker who edits the parent prefix AND re-hashes the
        // parent chain (so it is internally valid again) must still be caught by the pinned
        // parent_hash_at_seq. We simulate that by rebuilding the parent as a valid-but-different
        // chain; load_forked must reject the child with ForkParentMismatch.
        let dir = tmpdir("tamper");
        let t = TenantId::default();
        let parent = RunId("p".into());
        mk_run(&dir, &parent, &t, "/repo/p", "original-parent-task");
        let child = fork(&dir, &parent, Seq(2), &t).unwrap();

        // Rebuild the parent with altered content at seq 2 but a fully valid hash chain.
        std::fs::remove_file(rollout_path(&dir, &parent).unwrap()).unwrap();
        {
            let mut r = Rollout::open(&dir, &parent, t.clone()).unwrap();
            r.append(&genesis_event("/repo/p")).unwrap();
            r.append(&Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
            r.append(&Event {
                seq: Seq(2),
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("TAMPERED-parent-task"),
                },
            })
            .unwrap();
        }
        // The rebuilt parent is internally valid (a plain replay of it succeeds)...
        assert!(read_chain(&rollout_path(&dir, &parent).unwrap()).is_ok());
        // ...but the child's pinned cross-link no longer matches: tamper detected.
        let err = load_forked(&dir, &child).unwrap_err();
        assert!(
            matches!(err, RecordError::ForkParentMismatch { forked_at: 2, .. }),
            "expected ForkParentMismatch, got {err:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_event_kinds_do_not_fail_the_scan() {
        // R5-review Risk 6: a newer writer's event kind deserializes to EventKind::Unknown, so the
        // projection still works over a rollout that carries one.
        let dir = tmpdir("unknown");
        let t = TenantId::default();
        let run = RunId("u".into());
        mk_run(&dir, &run, &t, "/repo/u", "with an unknown event");
        // Append a hand-written chain line whose payload has an unrecognized kind, keeping the
        // hash chain valid by using the crate's own hashing over the tail.
        let path = rollout_path(&dir, &run).unwrap();
        let tail = read_chain(&path).unwrap();
        let last = tail.last().unwrap();
        let payload =
            serde_json::json!({"seq":0,"turn":0,"kind":{"kind":"from_the_future","extra":1}});
        let seq = last.seq.0 + 1;
        let hash = crate::hash_line(&last.hash, seq, &payload);
        let cl = serde_json::json!({
            "seq": seq, "tenant": t.0, "prev": last.hash, "hash": hash, "payload": payload
        });
        let mut line = serde_json::to_string(&cl).unwrap();
        line.push('\n');
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
        // The scan tolerates the unknown kind rather than failing.
        let m = meta(&dir, &run).unwrap();
        assert_eq!(m.title, "with an unknown event");
        std::fs::remove_dir_all(&dir).ok();
    }
    /// I-46. Journals are append-only and nothing else ever deletes one, so `prune` is the whole
    /// retention story — and it must delete exactly what its policy names. A policy that names
    /// nothing, and a dry run, both leave the store untouched.
    #[test]
    fn d11_46_prune_removes_exactly_what_the_policy_names_and_nothing_else() {
        let dir = tmpdir("prune-policy");
        let tenant = TenantId::default();
        for index in 0..4 {
            mk_run(
                &dir,
                &RunId(format!("run-{index}")),
                &tenant,
                "/repo/prune",
                "task",
            );
        }
        reindex(&dir).unwrap();

        let report = prune_at(&dir, &tenant, &PrunePolicy::default(), now_secs()).unwrap();
        assert!(
            report.removed.is_empty(),
            "no policy names nothing: {report:?}"
        );
        assert_eq!(report.retained, 4);
        assert_eq!(rollout_run_ids(&dir).len(), 4);

        let dry = PrunePolicy {
            keep_last: Some(2),
            dry_run: true,
            ..PrunePolicy::default()
        };
        let report = prune_at(&dir, &tenant, &dry, now_secs()).unwrap();
        assert_eq!(report.removed.len(), 2);
        assert_eq!(rollout_run_ids(&dir).len(), 4, "a dry run unlinks nothing");

        // Keep-last is a window on the same newest-first order the listing uses.
        let survivors: Vec<RunId> = list(&dir, &tenant)
            .into_iter()
            .take(2)
            .map(|m| m.run_id)
            .collect();
        let policy = PrunePolicy {
            keep_last: Some(2),
            ..PrunePolicy::default()
        };
        let report = prune_at(&dir, &tenant, &policy, now_secs()).unwrap();
        assert_eq!(report.removed.len(), 2);
        assert_eq!(report.retained, 2);
        assert!(report.active.is_empty() && report.ancestors.is_empty());

        let mut left: Vec<String> = rollout_run_ids(&dir).into_iter().map(|r| r.0).collect();
        left.sort();
        let mut expected: Vec<String> = survivors.iter().map(|r| r.0.clone()).collect();
        expected.sort();
        assert_eq!(left, expected, "only the named runs are gone");
        for run in &report.removed {
            assert!(
                !per_run_meta_path(&dir, run).unwrap().exists(),
                "a deleted run's rebuildable sidecar goes with it"
            );
        }
        for run in &survivors {
            assert!(per_run_meta_path(&dir, run).unwrap().exists());
        }
        assert!(
            index_path(&dir).exists(),
            "the shared index is rewritten, never deleted"
        );
        assert_eq!(list(&dir, &tenant).len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I-46. The age rule is measured against the same recorded activity time the listing orders
    /// by, so the same store answers differently only because the clock moved.
    #[test]
    fn d11_46_prune_age_policy_reads_the_recorded_activity_time() {
        let dir = tmpdir("prune-age");
        let tenant = TenantId::default();
        mk_run(&dir, &RunId("young".into()), &tenant, "/repo/age", "task");
        let now = now_secs();
        let policy = PrunePolicy {
            max_age_secs: Some(24 * 60 * 60),
            ..PrunePolicy::default()
        };

        let report = prune_at(&dir, &tenant, &policy, now).unwrap();
        assert!(report.removed.is_empty(), "a fresh record is not garbage");
        assert_eq!(rollout_run_ids(&dir).len(), 1);

        let report = prune_at(&dir, &tenant, &policy, now + 7 * 24 * 60 * 60).unwrap();
        assert_eq!(report.removed, vec![RunId("young".into())]);
        assert!(rollout_run_ids(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I-46. A fork stores only its own tail and replays the parent prefix, so deleting an
    /// ancestor a survivor still needs would leave an unreadable history rather than a shorter
    /// one. Retention grows through ancestry before anything is unlinked.
    #[test]
    fn d11_46_prune_never_orphans_a_surviving_fork() {
        let dir = tmpdir("prune-ancestry");
        let tenant = TenantId::default();
        let parent = RunId("parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/fork", "parent task");
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();

        // The child is newer, so keep-last(1) names the parent. The parent is kept anyway.
        let policy = PrunePolicy {
            keep_last: Some(1),
            ..PrunePolicy::default()
        };
        let report = prune_at(&dir, &tenant, &policy, now_secs()).unwrap();
        assert!(report.removed.is_empty(), "{report:?}");
        assert_eq!(report.ancestors, vec![parent.clone()]);
        assert!(rollout_path(&dir, &parent).unwrap().exists());
        load_forked(&dir, &child).expect("the survivor's logical history still reads");

        // Two forks off one parent rescue it once. Reporting the same run twice would read as two
        // separate rules having fired on two separate records.
        let sibling = fork(&dir, &parent, Seq(4), &tenant).unwrap();
        let both_forks = PrunePolicy {
            keep_last: Some(2),
            ..PrunePolicy::default()
        };
        let report = prune_at(&dir, &tenant, &both_forks, now_secs()).unwrap();
        assert!(report.removed.is_empty(), "{report:?}");
        assert_eq!(
            report.ancestors,
            vec![parent.clone()],
            "a shared ancestor is named once, not once per fork"
        );
        load_forked(&dir, &sibling).expect("the second survivor still reads too");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn explicit_delete_refuses_live_and_ancestor_runs_then_removes_exactly_one_session() {
        let dir = tmpdir("explicit-delete");
        let tenant = TenantId::default();
        let parent = RunId("parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/delete", "parent task");
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();
        reindex(&dir).unwrap();

        assert!(matches!(
            delete(&dir, &tenant, &parent),
            Err(DeleteSessionError::HasDescendants { .. })
        ));
        assert!(rollout_path(&dir, &parent).unwrap().exists());

        let active = Rollout::open_existing(&dir, &child, tenant.clone()).unwrap();
        assert!(matches!(
            delete(&dir, &tenant, &child),
            Err(DeleteSessionError::Active(_))
        ));
        drop(active);

        delete(&dir, &tenant, &child).unwrap();
        assert!(!rollout_path(&dir, &child).unwrap().exists());
        assert!(!per_run_meta_path(&dir, &child).unwrap().exists());
        assert_eq!(list(&dir, &tenant).len(), 1);

        delete(&dir, &tenant, &parent).unwrap();
        assert!(list(&dir, &tenant).is_empty());
        assert!(matches!(
            delete(&dir, &tenant, &parent),
            Err(DeleteSessionError::NotFound(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I-47. A rebuild used to rewrite every sidecar unconditionally and fsync per file, so a warm
    /// reindex with nothing to do still refreshed every mtime and paid the whole fsync bill. An
    /// unchanged projection is now left alone — byte-for-byte, same inode — while a session that
    /// actually grew is still rebuilt.
    #[test]
    fn d11_47_a_warm_reindex_replaces_no_unchanged_sidecar() {
        let dir = tmpdir("reindex-warm");
        let tenant = TenantId::default();
        let run = RunId("warm".into());
        mk_run(&dir, &run, &tenant, "/repo/warm", "task");
        assert_eq!(reindex(&dir).unwrap(), 1);

        let sidecar = per_run_meta_path(&dir, &run).unwrap();
        let before = std::fs::metadata(&sidecar).unwrap();
        let before_bytes = std::fs::read(&sidecar).unwrap();
        assert_eq!(reindex(&dir).unwrap(), 1);
        let after = std::fs::metadata(&sidecar).unwrap();

        assert_eq!(std::fs::read(&sidecar).unwrap(), before_bytes);
        assert_eq!(
            before.modified().unwrap(),
            after.modified().unwrap(),
            "a warm rebuild must not refresh an mtime"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                before.ino(),
                after.ino(),
                "an unchanged sidecar is not replaced by a rename"
            );
        }

        complete_one_turn(&dir, &run, &tenant, "another turn");
        assert_eq!(reindex(&dir).unwrap(), 1);
        #[cfg(unix)]
        let grown = std::fs::metadata(&sidecar).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_ne!(
                before.ino(),
                grown.ino(),
                "a changed session is still reindexed"
            );
        }
        let refreshed =
            private_cache::read_sidecar(&dir, &std::fs::read(&sidecar).unwrap()).unwrap();
        assert!(refreshed.turns > 1, "{refreshed:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// I-51. `--sessions` promised "in this repo" while listing every repository, and `--continue`
    /// filtered. Both now select from one scope, including when the record's spelling of the path
    /// and the caller's canonicalized one differ.
    #[test]
    fn d11_51_a_scoped_listing_and_continue_select_from_the_same_set() {
        let dir = tmpdir("scoped-listing");
        let tenant = TenantId::default();
        mk_run(&dir, &RunId("here".into()), &tenant, "/repo/here", "here");
        mk_run(
            &dir,
            &RunId("there".into()),
            &tenant,
            "/repo/there",
            "there",
        );

        assert_eq!(list_scoped(&dir, &tenant, None).len(), 2, "unscoped is all");
        let scoped: Vec<String> = list_scoped(&dir, &tenant, Some(Path::new("/repo/here")))
            .into_iter()
            .map(|m| m.run_id.0)
            .collect();
        assert_eq!(scoped, vec!["here".to_string()]);
        assert_eq!(
            most_recent(&dir, Path::new("/repo/here"), &tenant),
            Some(RunId("here".into())),
            "continue picks from exactly what the listing showed"
        );
        assert!(
            list_scoped(&dir, &tenant, Some(Path::new("/repo/nowhere"))).is_empty()
                && most_recent(&dir, Path::new("/repo/nowhere"), &tenant).is_none()
        );

        // A record written under an uncanonicalized path (`/var/…` on macOS) and a `--repo` the
        // CLI canonicalized (`/private/var/…`) are one repository, not two.
        let workspace = tmpdir("scoped-workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        mk_run(
            &dir,
            &RunId("spelled".into()),
            &tenant,
            &workspace.display().to_string(),
            "spelled",
        );
        let canonical = workspace.canonicalize().unwrap();
        assert_eq!(list_scoped(&dir, &tenant, Some(&canonical)).len(), 1);
        assert_eq!(
            most_recent(&dir, &canonical, &tenant),
            Some(RunId("spelled".into()))
        );
        std::fs::remove_dir_all(&workspace).ok();
        std::fs::remove_dir_all(&dir).ok();
    }
}

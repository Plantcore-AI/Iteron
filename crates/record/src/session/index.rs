//! Rebuildable metadata catalog, retained index snapshots and serialized cache publication.
//! No mutable projection state is shared with this owner; values must match actual record receipts.
#[cfg(test)]
use super::AFTER_PAGE_SNAPSHOT;
use super::cache_receipts::{projection_covers_rollout, projection_is_current};
use super::model::SessionMeta;
use super::paths::{per_run_meta_path, rollout_run_ids};
use super::private_cache;
use super::projection::meta_from_replay;
use crate::{RecordError, validate_run_id};
use iteron_obs::{CostState, PricingPort};
use iteron_protocol::{RunId, TenantId};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

pub(super) const SESSION_INDEX_HEADER: &[u8] = br#"{"version":2,"order":"updated_desc"}"#;

pub(super) const SESSION_DELTA_INDEX_VERSION: u8 = 1;

const SESSION_DELTA_INDEX_FILE: &str = "sessions.delta.index";

const SESSION_DELTA_STATE_FILE: &str = "sessions.delta.state";

const SESSION_INDEX_DIRTY_FILE: &str = "sessions.index.dirty";

const SESSION_DELTA_REFS_DIR: &str = ".sessions-delta-refs";

const DEFAULT_SESSION_DELTA_COMPACT_ROWS: u64 = 512;

const DEFAULT_SESSION_DELTA_COMPACT_BYTES: u64 = 4 * 1024 * 1024;

pub(super) struct SessionDeltaHardLimits {
    pub(super) rows: u64,
    pub(super) bytes: u64,
}

/// Crash recovery, cursor publication and compaction all share this one immutable durability
/// envelope. It is structural rather than a trainer candidate.
pub(super) const SESSION_DELTA_HARD_LIMITS: SessionDeltaHardLimits = SessionDeltaHardLimits {
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

/// An append-era index with more than two physical writes per live rollout is abandoned after one
/// extra line and rebuilt. This makes index work O(M), independent of historical turn writes K.
const INDEX_SCAN_LINES_PER_LIVE_RUN: usize = 2;

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
pub(super) struct SessionDeltaRef {
    pub(super) version: u8,
    pub(super) generation: u64,
    pub(super) byte_offset: u64,
    #[serde(default)]
    pub(super) delta_high_water: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionDeltaState {
    pub(super) version: u8,
    pub(super) generation: u64,
    pub(super) rows: u64,
    pub(super) high_water: u64,
}

pub(super) fn index_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join("sessions.index")
}

pub(super) fn delta_index_path(runs_dir: &Path) -> PathBuf {
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

pub(super) fn delta_ref_path(runs_dir: &Path, run: &RunId) -> PathBuf {
    let digest = Sha256::digest(run.0.as_bytes());
    runs_dir
        .join(SESSION_DELTA_REFS_DIR)
        .join(format!("{}.json", hex::encode(digest)))
}

pub(super) struct IndexRead {
    entries: Vec<SessionMeta>,
    exact: bool,
}
#[cfg(test)]
impl IndexRead {
    pub(super) fn exact(&self) -> bool {
        self.exact
    }
    pub(super) fn entries(&self) -> &[SessionMeta] {
        &self.entries
    }
    pub(super) fn into_entries(self) -> Vec<SessionMeta> {
        self.entries
    }
}

pub(super) fn max_index_scan_lines(live_runs: usize) -> usize {
    live_runs.saturating_mul(iteron_tunables::param_integer(
        "record.session.index_scan_lines_per_live_run",
        INDEX_SCAN_LINES_PER_LIVE_RUN,
    ))
}

/// Read only a live-run-proportional prefix. Any malformed, torn, oversized, or over-limit cache
/// invalidates the whole prefix; trusting an early append-era entry could otherwise return an old
/// projection whose newer line was beyond the read bound.
pub(super) fn read_index(runs_dir: &Path, live_runs: usize) -> IndexRead {
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

pub(super) struct BaseIndexSnapshot {
    reader: BufReader<File>,
    generation: u64,
    header_end: u64,
    len: u64,
}
#[cfg(test)]
impl BaseIndexSnapshot {
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}

struct DeltaIndexSnapshot {
    file: File,
    generation: u64,
    header_end: u64,
    high_water: u64,
    rows: u64,
}

pub(super) fn open_base_index(runs_dir: &Path) -> io::Result<BaseIndexSnapshot> {
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

pub(super) fn read_delta_state(runs_dir: &Path) -> io::Result<SessionDeltaState> {
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

pub(super) fn write_delta_state_unlocked(
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

pub(super) fn read_delta_ref(runs_dir: &Path, run: &RunId) -> Option<SessionDeltaRef> {
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

pub(super) fn index_publication_incomplete(runs_dir: &Path) -> bool {
    index_dirty_path(runs_dir).exists()
}

pub(super) fn base_snapshot_is_current(runs_dir: &Path, expected_generation: u64) -> bool {
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
    if crate::session_maintenance::flush().is_err()
        || !crate::session_maintenance::marked_projections_current(runs_dir)
    {
        return page_rebuild_needed(cursor.is_some());
    }

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
    match SessionIndexReader::open(runs_dir) {
        Ok(reader) => reader.read(tenant, repo, cursor, limit),
        Err(_) => page_rebuild_needed(had_cursor),
    }
}

/// Retained descriptors and their exact published generations belong to one paging operation.
/// The caller cannot replace the namespace or mix snapshots from different runs directories.
struct SessionIndexReader<'a> {
    runs_dir: &'a Path,
    base: Option<BaseIndexSnapshot>,
    delta: Option<DeltaIndexSnapshot>,
}
impl<'a> SessionIndexReader<'a> {
    fn open(runs_dir: &'a Path) -> io::Result<Self> {
        let base = match open_base_index(runs_dir) {
            Ok(snapshot) => Some(snapshot),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut delta = match open_delta_index(runs_dir) {
            Ok(snapshot) => Some(snapshot),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if delta
            .as_mut()
            .is_some_and(|snapshot| !delta_tail_is_published(runs_dir, snapshot))
            || (base.is_none() && delta.is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session index snapshot is not published",
            ));
        }
        Ok(Self {
            runs_dir,
            base,
            delta,
        })
    }
    fn read(
        self,
        tenant: &TenantId,
        repo: Option<&Path>,
        cursor: Option<SessionPageCursor>,
        limit: usize,
    ) -> SessionPage {
        let Self {
            runs_dir,
            mut base,
            mut delta,
        } = self;
        let had_cursor = cursor.is_some();
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
                    match read_previous_delta_line(
                        &mut snapshot.file,
                        line_end,
                        snapshot.header_end,
                    ) {
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
            || !crate::session_maintenance::marked_projections_current(runs_dir)
            || !base_snapshot_is_current(runs_dir, base_generation)
            || !delta_snapshot_is_current(runs_dir, delta.as_ref())
        {
            return page_snapshot_changed(had_cursor);
        }
        result
    }
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
pub(super) fn encode_index<'a>(
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

pub(super) fn mark_index_dirty_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
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

pub(super) fn compact_session_index_unlocked(runs_dir: &Path) -> Result<(), RecordError> {
    mark_index_dirty_unlocked(runs_dir)?;
    let metas = rollout_run_ids(runs_dir)
        .into_iter()
        .filter_map(|run| meta_after_publication(runs_dir, &run).ok())
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

pub(super) fn append_delta_index_unlocked(
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
pub(super) fn merge_rewrite_index(
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

pub(super) fn write_meta_sidecar(
    runs_dir: &Path,
    projected: &SessionMeta,
) -> Result<(), RecordError> {
    let path = per_run_meta_path(runs_dir, &projected.run_id)?;
    private_cache::write_sidecar(runs_dir, &path, projected, false)
}

/// The metadata for one run: a current cache may directly serve only an honest `Unknown` cost;
/// `Zero` and `Known` both require replay because mutable cache bytes cannot prove either exact
/// monetary claim. A missing, stale, or corrupt cache degrades to the record (R5 design §2.5).
pub fn meta(runs_dir: &Path, run: &RunId) -> Result<SessionMeta, RecordError> {
    crate::session_maintenance::flush()?;
    meta_after_publication(runs_dir, run)
}

// Internal index maintenance already owns publication ordering. Waiting for the worker while
// holding the index lock would invert its worker -> index-lock acquisition order.
fn meta_after_publication(runs_dir: &Path, run: &RunId) -> Result<SessionMeta, RecordError> {
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
    let _ = crate::session_maintenance::flush();

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
            && let Ok(m) = meta_after_publication(runs_dir, &RunId(run.clone()))
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
    if !indexed.index_ready {
        // One rebuild also recovers a crashed publication's global dirty marker. Its sidecar
        // may already match the record while the index row was never committed. The ready path
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
    SessionIndexPublication {
        runs_dir,
        projected,
        require_current: false,
    }
    .commit()
}

pub(crate) fn write_meta_if_current(
    runs_dir: &Path,
    projected: &SessionMeta,
) -> Result<(), RecordError> {
    SessionIndexPublication {
        runs_dir,
        projected,
        require_current: true,
    }
    .commit()
}

pub(crate) fn cached_projection_is_current(runs_dir: &Path, run: &RunId) -> bool {
    let Ok(path) = per_run_meta_path(runs_dir, run) else {
        return false;
    };
    let Ok(bytes) = crate::cache_io::read_session_meta(&path) else {
        return false;
    };
    private_cache::read_sidecar(runs_dir, &bytes)
        .is_ok_and(|meta| projection_is_current(runs_dir, &meta))
}

/// One immutable metadata proposal; the actual cross-process index lease covers its complete
/// marker -> sidecar -> delta -> latest-reference -> marker-clear transaction.
struct SessionIndexPublication<'a> {
    runs_dir: &'a Path,
    projected: &'a SessionMeta,
    require_current: bool,
}
impl SessionIndexPublication<'_> {
    fn commit(self) -> Result<(), RecordError> {
        let Self {
            runs_dir,
            projected,
            require_current,
        } = self;
        validate_run_id(&projected.run_id)?;

        crate::create_state_dir(runs_dir)?;
        // The marker precedes the sidecar: a crash at any later point makes latency-sensitive readers
        // report not-ready instead of returning a ready page that silently omits this newer run. The
        // same lock serializes publication transactions; compaction is the only operation allowed to
        // clear a marker inherited from a crashed writer.
        let mut transaction_result = None;
        let mut compact_after = false;
        crate::cache_io::with_session_index_lock(runs_dir, || {
            if require_current && !projection_is_current(runs_dir, projected) {
                transaction_result = Some(Ok(()));
                return Ok(());
            }

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
}

/// Rebuild the cache from the records (R5 design §2.4): replay every rollout, rewrite each per-run
/// `.meta.json`, and rewrite `sessions.index` from scratch. Truth is the record, so this is always
/// safe to run. A corrupt/broken rollout is skipped rather than aborting the whole rebuild; returns
/// the number of runs indexed.
pub fn reindex(runs_dir: &Path) -> Result<usize, RecordError> {
    crate::session_maintenance::flush()?;

    crate::create_state_dir(runs_dir)?;
    let recovery = crate::session_maintenance::ReindexRecovery::acquire(runs_dir)?;
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
    recovery.complete()?;
    Ok(metas.len())
}

/// True when the gated CAS projection is semantically byte-identical to `projected`. The public
/// sidecar is a handle manifest, so comparing it with serialized private metadata would force
/// every warm reindex to republish an unchanged projection.
pub(super) fn sidecar_is_unchanged(runs_dir: &Path, projected: &SessionMeta) -> bool {
    let Ok(path) = per_run_meta_path(runs_dir, &projected.run_id) else {
        return false;
    };
    crate::cache_io::read_session_meta(&path)
        .is_ok_and(|bytes| private_cache::sidecar_matches(runs_dir, &bytes, projected))
}

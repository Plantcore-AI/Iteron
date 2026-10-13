//! Product TurnStart V2 admission authority. This snapshot is authoritative, not a cache.
//!
//! One stable kernel file lock serializes all tenants' operations within their respective
//! record-root namespace. The atomically replaced snapshot contains both the request binding
//! and the admission fact; only `StoreDecision::Admitted` permits a caller to start execution.
//! A lost acknowledgement, failed barrier, corrupt snapshot or dead admitted owner never
//! authorizes replay. The gateway owns the 32-request / 64-per-second admission limits.
//!
//! Waiting for the lock is bounded to five seconds. Filesystem system calls are synchronous and
//! cannot be forcibly cancelled; callers must not start execution on a late result after their
//! own deadline. Expired unresolved turns retain their occupancy and count against capacity.

use iteron_protocol::product_contract::ProductTurnId;
use iteron_protocol::{RunId, SessionId, SubmissionId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CAPACITY: usize = 1024;
pub const MAX_ENTRY_BYTES: usize = 2048;
pub const WINDOW_MS: u64 = 30 * 60 * 1000;
pub const FUTURE_TOLERANCE_MS: u64 = 5 * 60 * 1000;
const MAX_SNAPSHOT_BYTES: usize = CAPACITY * MAX_ENTRY_BYTES + 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const OWNER_SLOTS: u16 = CAPACITY as u16;
const REQUEST_SLOTS: u8 = 32;
const INITIALIZED: &[u8] = b"iteron-turn-start-v2\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRequest {
    request_key: String,
    thread_id: SessionId,
    created_ms: u64,
}
impl PreparedRequest {
    pub fn request_key(&self) -> &str {
        &self.request_key
    }
    pub fn thread_id(&self) -> &SessionId {
        &self.thread_id
    }
    pub fn created_ms(&self) -> u64 {
        self.created_ms
    }
    pub fn window_closed(&self, now_ms: u64) -> bool {
        now_ms >= self.created_ms.saturating_add(WINDOW_MS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    RequestConflict,
    InvalidRequestKey,
    RequestKeyExpired,
    RequestKeyInFuture,
    InvalidTurnText,
    ThreadUnavailable,
    TurnActive,
    CapacityFull,
    Busy,
    RateLimited,
    RuntimeDisconnected,
}
impl RefusalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestConflict => "request_conflict",
            Self::InvalidRequestKey => "invalid_request_key",
            Self::RequestKeyExpired => "request_key_expired",
            Self::RequestKeyInFuture => "request_key_in_future",
            Self::InvalidTurnText => "invalid_turn_text",
            Self::ThreadUnavailable => "thread_unavailable",
            Self::TurnActive => "turn_active",
            Self::CapacityFull => "capacity_full",
            Self::Busy => "busy",
            Self::RateLimited => "rate_limited",
            Self::RuntimeDisconnected => "runtime_disconnected",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRefusal {
    pub request_key: Option<String>,
    pub reason: RefusalReason,
    pub definitely_unregistered: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreState {
    Pending,
    Admitted,
    Running,
    Completed,
    Interrupted,
    Drained,
    BudgetExhausted,
    Stuck,
    Failed,
    Unknown,
    AdmissionUnknown,
}
impl StoreState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Interrupted => "interrupted",
            Self::Drained => "drained",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Stuck => "stuck",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::AdmissionUnknown => "admission_unknown",
        }
    }
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Interrupted
                | Self::Drained
                | Self::BudgetExhausted
                | Self::Stuck
                | Self::Failed
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalState {
    Completed,
    Interrupted,
    Drained,
    BudgetExhausted,
    Stuck,
    Failed,
}
impl From<TerminalState> for StoreState {
    fn from(state: TerminalState) -> Self {
        match state {
            TerminalState::Completed => Self::Completed,
            TerminalState::Interrupted => Self::Interrupted,
            TerminalState::Drained => Self::Drained,
            TerminalState::BudgetExhausted => Self::BudgetExhausted,
            TerminalState::Stuck => Self::Stuck,
            TerminalState::Failed => Self::Failed,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionIdentity {
    pub run_id: RunId,
    pub submission_id: SubmissionId,
    pub turn_id: ProductTurnId,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreReceipt {
    pub request_key: String,
    pub thread_id: SessionId,
    pub state: StoreState,
    pub identity: Option<AdmissionIdentity>,
    pub window_closed: bool,
}
#[derive(Clone, Debug)]
pub struct Reservation {
    request: PreparedRequest,
    target_run: RunId,
    owner: OwnerToken,
    nonce: String,
    _lease: Arc<OwnerLease>,
}
impl Reservation {
    pub fn request(&self) -> &PreparedRequest {
        &self.request
    }
    pub fn target_run(&self) -> &RunId {
        &self.target_run
    }
}
#[derive(Clone, Debug)]
pub enum StoreDecision {
    /// Proven not admitted: either absent or an orphaned pending record. No execution authority.
    Vacant,
    Reserved(Box<Reservation>),
    /// A NEW successful durable admission; the returned identity is authoritative.
    Admitted(StoreReceipt),
    /// Recovery/duplicate/unknown result. NEVER authorizes execution.
    Receipt(StoreReceipt),
    Refused(StoreRefusal),
}

/// Validate the canonical UUIDv7 and its salted digest before all semantic/time/capacity checks.
/// The exact UTF-8 bytes are hashed; no normalization or trimming is used for identity.
pub fn prepare(
    request_key: &str,
    thread_id: &SessionId,
    text: &str,
) -> Result<PreparedRequest, StoreRefusal> {
    let (uuid, created_ms) = parse_key(request_key).ok_or(StoreRefusal {
        request_key: None,
        reason: RefusalReason::InvalidRequestKey,
        definitely_unregistered: false,
    })?;
    let mut digest = Sha256::new();
    digest.update(uuid);
    digest.update((thread_id.0.len() as u64).to_be_bytes());
    digest.update(thread_id.0.as_bytes());
    digest.update((text.len() as u64).to_be_bytes());
    digest.update(text.as_bytes());
    if hex::encode(digest.finalize()) != request_key[37..] {
        return Err(refusal(request_key, RefusalReason::RequestConflict, false));
    }
    if thread_id.0.is_empty() || thread_id.0.len() > 256 {
        return Err(refusal(
            request_key,
            RefusalReason::ThreadUnavailable,
            false,
        ));
    }
    if text.len() > 1024 * 1024 || text.trim().is_empty() {
        return Err(refusal(request_key, RefusalReason::InvalidTurnText, false));
    }
    Ok(PreparedRequest {
        request_key: request_key.into(),
        thread_id: thread_id.clone(),
        created_ms,
    })
}
fn parse_key(key: &str) -> Option<([u8; 16], u64)> {
    let b = key.as_bytes();
    if b.len() != 101
        || b[36] != b':'
        || b[14] != b'7'
        || !matches!(b[19], b'8' | b'9' | b'a' | b'b')
    {
        return None;
    }
    let mut raw = [0u8; 16];
    let mut n = 0;
    let mut high = None;
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return None;
            }
        } else if i == 36 {
            continue;
        } else {
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => return None,
            };
            if i < 36 {
                if let Some(h) = high.take() {
                    raw[n] = h * 16 + v;
                    n += 1;
                } else {
                    high = Some(v);
                }
            }
        }
    }
    let mut timestamp = [0u8; 8];
    timestamp[2..].copy_from_slice(&raw[..6]);
    Some((raw, u64::from_be_bytes(timestamp)))
}
fn refusal(key: &str, reason: RefusalReason, definitely_unregistered: bool) -> StoreRefusal {
    StoreRefusal {
        request_key: Some(key.into()),
        reason,
        definitely_unregistered,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerToken {
    slot: u16,
    nonce: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    thread_id: SessionId,
    created_ms: u64,
    target_run: RunId,
    owner: OwnerToken,
    reservation: String,
    state: StoreState,
    identity: Option<AdmissionIdentity>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEnvelope {
    checksum_sha256: String,
    snapshot: Snapshot,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    tenant_digest: String,
    wall_floor_ms: u64,
    /// Global monotonic product identity survives expiry/GC, without an unbounded per-run map.
    last_product_turn: u64,
    rate_tokens_milli: u64,
    rate_refill_ms: u64,
    entries: BTreeMap<String, Entry>,
}
#[derive(Debug)]
struct OwnerLease {
    _file: File,
    token: OwnerToken,
}

/// Retain through all blocking work, including after an async caller has timed out.
#[derive(Clone, Debug)]
pub struct RequestGuard {
    _file: Arc<File>,
}
#[derive(Clone)]
pub struct TurnStartStore {
    directory: PathBuf,
    tenant_digest: String,
    #[cfg(test)]
    fail_commit: Arc<std::sync::atomic::AtomicU8>,
}
impl std::fmt::Debug for TurnStartStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnStartStore")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

/// Detect an existing V2 namespace without creating one for ordinary legacy submissions.
/// A present malformed file, symlink, or missing initialized snapshot is NOT treated as absence;
/// opening that authority must fail closed rather than restarting a product identity counter.
pub fn authority_exists(root: &Path, tenant: &TenantId) -> io::Result<bool> {
    let namespace = root.join(".turn-start-v2");
    match std::fs::symlink_metadata(&namespace) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(invalid("malformed admission namespace")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let digest = hex::encode(Sha256::digest(tenant.0.as_bytes()));
    match std::fs::symlink_metadata(namespace.join(digest)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

impl TurnStartStore {
    /// Open lazily for V2 callers only. This never rebuilds corrupt/lost initialized authority.
    pub fn open(root: &Path, tenant: &TenantId) -> io::Result<Self> {
        let tenant_digest = hex::encode(Sha256::digest(tenant.0.as_bytes()));
        let directory = root.join(".turn-start-v2").join(&tenant_digest);
        provision_directory(&directory)?;
        let mut guard = lock(&directory)?;
        let state_path = directory.join("state.json");
        let mut marker = Vec::new();
        (&mut guard.0)
            .take((INITIALIZED.len() + 1) as u64)
            .read_to_end(&mut marker)?;
        if !marker.is_empty() && marker != INITIALIZED {
            return Err(invalid("invalid admission authority marker"));
        }
        match File::open(&state_path) {
            Ok(_) => {
                read_snapshot(&directory, &tenant_digest)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && marker.is_empty() => {
                let snapshot = Snapshot {
                    version: 2,
                    tenant_digest: tenant_digest.clone(),
                    wall_floor_ms: 0,
                    last_product_turn: 0,
                    rate_tokens_milli: 64000,
                    rate_refill_ms: 0,
                    entries: BTreeMap::new(),
                };
                replace_snapshot(&directory, &snapshot)?;
            }
            Err(e) => return Err(e),
        }
        if marker.is_empty() {
            guard.0.seek(SeekFrom::Start(0))?;
            guard.0.write_all(INITIALIZED)?;
            guard.0.sync_all()?;
            sync_directory(&directory)?;
        }
        Ok(Self {
            directory,
            tenant_digest,
            #[cfg(test)]
            fail_commit: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }

    /// Reserve an identity for a generic or runtime-followup product Turn in a namespace that
    /// already has V2 authority. Callers must not publish/start the Turn if this returns an error.
    /// Every allocation shares the same persistent high-water as V2 admission, including after
    /// key expiry/GC; merely seeding an in-memory counter at startup would permit later reuse.
    pub fn allocate_product_turn(
        &self,
        candidate: ProductTurnId,
        now_ms: u64,
    ) -> io::Result<ProductTurnId> {
        let started = Instant::now();
        let _guard = lock(&self.directory)?;
        let mut snapshot = read_snapshot(&self.directory, &self.tenant_digest)?;
        snapshot.wall_floor_ms = snapshot.wall_floor_ms.max(now_ms);
        let next = candidate.0.max(
            snapshot
                .last_product_turn
                .checked_add(1)
                .ok_or_else(|| invalid("product turn identity exhausted"))?,
        );
        snapshot.last_product_turn = next;
        if started.elapsed() >= LOCK_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "product identity deadline elapsed",
            ));
        }
        replace_snapshot(&self.directory, &snapshot)?;
        if started.elapsed() >= LOCK_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "product identity commit exceeded deadline",
            ));
        }
        Ok(ProductTurnId(next))
    }

    /// Authority-wide concurrency and token-bucket gate. Call only after `prepare`, before
    /// lookup/reservation, retaining the guard until blocking work has actually finished.
    pub fn enter_request(
        &self,
        request: &PreparedRequest,
        now_ms: u64,
    ) -> Result<RequestGuard, StoreDecision> {
        let mut effective_now = now_ms;
        let result = (|| -> io::Result<Result<RequestGuard, StoreDecision>> {
            let mut selected = None;
            for slot in 0..REQUEST_SLOTS {
                let file = private_file(
                    &self.directory.join(format!("request-{slot:02}.lock")),
                    true,
                )?;
                match file.try_lock() {
                    Ok(()) => {
                        selected = Some(RequestGuard {
                            _file: Arc::new(file),
                        });
                        break;
                    }
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Error(e)) => return Err(e),
                }
            }
            let Some(guard) = selected else {
                return Ok(Err(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::RateLimited,
                    false,
                ))));
            };
            let started = Instant::now();
            let _lock = lock(&self.directory)?;
            let mut snapshot = read_snapshot(&self.directory, &self.tenant_digest)?;
            effective_now = now_ms.max(snapshot.wall_floor_ms);
            snapshot.wall_floor_ms = effective_now;
            let refill = effective_now
                .saturating_sub(snapshot.rate_refill_ms)
                .saturating_mul(64);
            snapshot.rate_tokens_milli =
                snapshot.rate_tokens_milli.saturating_add(refill).min(64000);
            snapshot.rate_refill_ms = effective_now;
            let allowed = snapshot.rate_tokens_milli >= 1000;
            if allowed {
                snapshot.rate_tokens_milli -= 1000;
            }
            if started.elapsed() >= LOCK_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "admission gate deadline elapsed",
                ));
            }
            replace_snapshot(&self.directory, &snapshot)?;
            if started.elapsed() >= LOCK_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "admission gate commit exceeded deadline",
                ));
            }
            Ok(if allowed {
                Ok(guard)
            } else {
                Err(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::RateLimited,
                    false,
                )))
            })
        })();
        result.unwrap_or_else(|_| Err(unknown(request, effective_now)))
    }

    pub fn lookup(&self, request: &PreparedRequest, now_ms: u64) -> StoreDecision {
        self.transaction(request, now_ms, |store, snapshot, now| {
            if let Some(reason) = time_refusal(request, now) {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    reason,
                    false,
                )));
            }
            match snapshot.entries.get(&request.request_key) {
                Some(entry)
                    if entry.state == StoreState::Pending && !store.owner_live(&entry.owner)? =>
                {
                    Ok(StoreDecision::Vacant)
                }
                Some(entry) => Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?)),
                None => Ok(StoreDecision::Vacant),
            }
        })
    }

    pub fn reserve(
        &self,
        request: &PreparedRequest,
        target_run: &RunId,
        thread_active: bool,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(request, now_ms, |store, snapshot, now| {
            if let Some(reason) = time_refusal(request, now) {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    reason,
                    false,
                )));
            }
            if let Some(entry) = snapshot.entries.get(&request.request_key)
                && (entry.state != StoreState::Pending || store.owner_live(&entry.owner)?)
            {
                return Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?));
            }
            let absent = !snapshot.entries.contains_key(&request.request_key);
            if target_run.0.is_empty() || target_run.0.len() > 256 {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::ThreadUnavailable,
                    absent,
                )));
            }
            let mut occupied = thread_active;
            for (key, entry) in &snapshot.entries {
                if key != &request.request_key
                    && entry.thread_id == request.thread_id
                    && !entry.state.terminal()
                    && (entry.state != StoreState::Pending || store.owner_live(&entry.owner)?)
                {
                    occupied = true;
                    break;
                }
            }
            if occupied {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::TurnActive,
                    absent,
                )));
            }
            if absent && snapshot.entries.len() >= CAPACITY {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::CapacityFull,
                    true,
                )));
            }
            let lease = store.reserve_owner()?;
            let reservation = Reservation {
                request: request.clone(),
                target_run: target_run.clone(),
                owner: lease.token.clone(),
                nonce: random_nonce()?,
                _lease: Arc::new(lease),
            };
            let entry = Entry {
                thread_id: request.thread_id.clone(),
                created_ms: request.created_ms,
                target_run: target_run.clone(),
                owner: reservation.owner.clone(),
                reservation: reservation.nonce.clone(),
                state: StoreState::Pending,
                identity: None,
            };
            // Reserve room for all identity fields before registering anything. JSON escaping of
            // arbitrary UTF-8 identifiers must count against the byte limit too.
            let mut largest = entry.clone();
            largest.identity = Some(AdmissionIdentity {
                run_id: target_run.clone(),
                submission_id: SubmissionId(u64::MAX),
                turn_id: ProductTurnId(u64::MAX),
            });
            largest.state = StoreState::BudgetExhausted;
            if entry_bytes(&request.request_key, &largest)? > MAX_ENTRY_BYTES {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::ThreadUnavailable,
                    absent,
                )));
            }
            snapshot.entries.insert(request.request_key.clone(), entry);
            Ok(StoreDecision::Reserved(Box::new(reservation)))
        })
    }

    /// Atomically commit the admission fact and allocate a durable monotonic product Turn ID.
    /// The proposed turn ID is a lower bound; callers MUST use the identity in the returned receipt.
    pub fn admit(
        &self,
        reservation: &Reservation,
        mut identity: AdmissionIdentity,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(&reservation.request, now_ms, |store, snapshot, now| {
            let request = &reservation.request;
            let Some(entry) = snapshot.entries.get(&request.request_key) else {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::RuntimeDisconnected,
                    true,
                )));
            };
            if entry.state != StoreState::Pending {
                return Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?));
            }
            if !store.owns(reservation, entry) || identity.run_id != reservation.target_run {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    RefusalReason::RequestConflict,
                    false,
                )));
            }
            if let Some(reason) = time_refusal(request, now) {
                return Ok(StoreDecision::Refused(refusal(
                    &request.request_key,
                    reason,
                    false,
                )));
            }
            identity.turn_id = ProductTurnId(
                identity.turn_id.0.max(
                    snapshot
                        .last_product_turn
                        .checked_add(1)
                        .ok_or_else(|| invalid("product turn identity exhausted"))?,
                ),
            );
            snapshot.last_product_turn = identity.turn_id.0;
            let entry = snapshot
                .entries
                .get_mut(&request.request_key)
                .expect("entry checked");
            entry.identity = Some(identity);
            entry.state = StoreState::Admitted;
            Ok(StoreDecision::Admitted(store.receipt(request, entry, now)?))
        })
    }

    /// Called only after the active runtime has actually started this admitted product Turn.
    pub fn mark_running(
        &self,
        request: &PreparedRequest,
        identity: &AdmissionIdentity,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(request, now_ms, |store, snapshot, now| {
            let Some(entry) = snapshot.entries.get_mut(&request.request_key) else {
                return Err(invalid("missing admitted turn"));
            };
            if entry.identity.as_ref() != Some(identity) {
                return Err(invalid("admission identity mismatch"));
            }
            if matches!(entry.state, StoreState::Admitted | StoreState::Running)
                && store.owner_live(&entry.owner)?
            {
                entry.state = StoreState::Running;
            }
            Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?))
        })
    }

    /// The caller must supply the whole product Turn's terminal evidence, not a model TurnEnd.
    /// The terminal fact becomes authoritative only after this snapshot's durable commit succeeds.
    pub fn finish(
        &self,
        request: &PreparedRequest,
        identity: &AdmissionIdentity,
        terminal: TerminalState,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(request, now_ms, |store, snapshot, now| {
            let Some(entry) = snapshot.entries.get_mut(&request.request_key) else {
                return Err(invalid("missing admitted turn"));
            };
            if entry.identity.as_ref() != Some(identity) {
                return Err(invalid("admission identity mismatch"));
            }
            let terminal = StoreState::from(terminal);
            if entry.state.terminal() && entry.state != terminal {
                return Err(invalid("terminal fact mismatch"));
            }
            entry.state = terminal;
            Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?))
        })
    }

    /// Undo only a proven not-admitted reservation after queue/runtime refusal.
    pub fn release_pending(
        &self,
        reservation: &Reservation,
        reason: RefusalReason,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(&reservation.request, now_ms, |store, snapshot, now| {
            let request = &reservation.request;
            if let Some(entry) = snapshot.entries.get(&request.request_key) {
                if entry.state != StoreState::Pending {
                    return Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?));
                }
                if !store.owns(reservation, entry) {
                    return Err(invalid("pending owner mismatch"));
                }
                snapshot.entries.remove(&request.request_key);
            }
            Ok(StoreDecision::Refused(refusal(
                &request.request_key,
                reason,
                true,
            )))
        })
    }

    /// Explicit loss of a running runtime. The durable admission and thread occupancy remain.
    pub fn abandon(
        &self,
        request: &PreparedRequest,
        identity: &AdmissionIdentity,
        now_ms: u64,
    ) -> StoreDecision {
        self.transaction(request, now_ms, |store, snapshot, now| {
            let Some(entry) = snapshot.entries.get_mut(&request.request_key) else {
                return Err(invalid("missing admitted turn"));
            };
            if entry.identity.as_ref() != Some(identity) {
                return Err(invalid("admission identity mismatch"));
            }
            if !entry.state.terminal() {
                entry.state = StoreState::Unknown;
            }
            Ok(StoreDecision::Receipt(store.receipt(request, entry, now)?))
        })
    }
    fn reserve_owner(&self) -> io::Result<OwnerLease> {
        // Called inside the authority lock. The separate nonce file can be read even on Windows,
        // where a whole-file kernel lock can also exclude ordinary reads of its lock file.
        for slot in 0..OWNER_SLOTS {
            let file = private_file(&owner_path(&self.directory, slot), true)?;
            match file.try_lock() {
                Ok(()) => {
                    let token = OwnerToken {
                        slot,
                        nonce: random_nonce()?,
                    };
                    crate::cache_io::atomic_replace_private(
                        &owner_token_path(&self.directory, slot),
                        token.nonce.as_bytes(),
                    )?;
                    sync_directory(&self.directory)?;
                    return Ok(OwnerLease { _file: file, token });
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(e)) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "admission execution owner slots exhausted",
        ))
    }
    fn owns(&self, reservation: &Reservation, entry: &Entry) -> bool {
        entry.owner == reservation._lease.token
            && entry.owner == reservation.owner
            && entry.reservation == reservation.nonce
            && entry.target_run == reservation.target_run
            && entry.thread_id == reservation.request.thread_id
    }
    fn receipt(
        &self,
        request: &PreparedRequest,
        entry: &Entry,
        now: u64,
    ) -> io::Result<StoreReceipt> {
        let state = if matches!(entry.state, StoreState::Admitted | StoreState::Running)
            && !self.owner_live(&entry.owner)?
        {
            StoreState::Unknown
        } else {
            entry.state
        };
        Ok(StoreReceipt {
            request_key: request.request_key.clone(),
            thread_id: request.thread_id.clone(),
            state,
            identity: entry.identity.clone(),
            window_closed: request.window_closed(now),
        })
    }
    fn owner_live(&self, owner: &OwnerToken) -> io::Result<bool> {
        let file = private_file(&owner_path(&self.directory, owner.slot), false)?;
        match file.try_lock() {
            Ok(()) => {
                file.unlock()?;
                Ok(false)
            }
            Err(TryLockError::WouldBlock) => {
                let mut nonce = String::new();
                File::open(owner_token_path(&self.directory, owner.slot))?
                    .take(33)
                    .read_to_string(&mut nonce)?;
                Ok(nonce == owner.nonce)
            }
            Err(TryLockError::Error(e)) => Err(e),
        }
    }
    fn transaction(
        &self,
        request: &PreparedRequest,
        now_ms: u64,
        action: impl FnOnce(&Self, &mut Snapshot, u64) -> io::Result<StoreDecision>,
    ) -> StoreDecision {
        let mut effective_now = now_ms;
        let result = (|| {
            let started = Instant::now();
            let _guard = lock(&self.directory)?;
            let mut snapshot = read_snapshot(&self.directory, &self.tenant_digest)?;
            effective_now = effective_now.max(snapshot.wall_floor_ms);
            snapshot.wall_floor_ms = effective_now;
            // Never discard unresolved admitted occupancy, even when the recovery key expires.
            // Keep the current key until after its operation (finish can arrive after expiry).
            let mut removable = Vec::new();
            for (key, entry) in &snapshot.entries {
                if key != &request.request_key
                    && effective_now >= entry.created_ms.saturating_add(WINDOW_MS)
                    && (entry.state.terminal()
                        || (entry.state == StoreState::Pending
                            && !self.owner_live(&entry.owner)?))
                {
                    removable.push(key.clone());
                }
            }
            for key in removable {
                snapshot.entries.remove(&key);
            }
            if let Some(entry) = snapshot.entries.get(&request.request_key)
                && (entry.thread_id != request.thread_id || entry.created_ms != request.created_ms)
            {
                return Err(invalid("request record binding mismatch"));
            }
            let decision = action(self, &mut snapshot, effective_now)?;
            if started.elapsed() >= LOCK_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "admission deadline elapsed",
                ));
            }
            #[cfg(test)]
            let injected_failure = self
                .fail_commit
                .swap(0, std::sync::atomic::Ordering::SeqCst);
            #[cfg(test)]
            if injected_failure == 1 {
                return Err(io::Error::other("injected before durable commit"));
            }
            // Even read/refusal operations persist the monotonic floor and GC together. Rewriting
            // also re-establishes a directory barrier after an earlier uncertain publication.
            replace_snapshot(&self.directory, &snapshot)?;
            #[cfg(test)]
            if injected_failure == 2 {
                return Err(io::Error::other(
                    "injected lost durable commit acknowledgement",
                ));
            }
            if started.elapsed() >= LOCK_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "admission commit exceeded deadline",
                ));
            }
            Ok(decision)
        })();
        result.unwrap_or_else(|_| unknown(request, effective_now))
    }
}

fn unknown(request: &PreparedRequest, now: u64) -> StoreDecision {
    StoreDecision::Receipt(StoreReceipt {
        request_key: request.request_key.clone(),
        thread_id: request.thread_id.clone(),
        state: StoreState::AdmissionUnknown,
        identity: None,
        window_closed: request.window_closed(now),
    })
}
fn time_refusal(request: &PreparedRequest, now: u64) -> Option<RefusalReason> {
    if request.window_closed(now) {
        Some(RefusalReason::RequestKeyExpired)
    } else if request.created_ms > now.saturating_add(FUTURE_TOLERANCE_MS) {
        Some(RefusalReason::RequestKeyInFuture)
    } else {
        None
    }
}
fn entry_bytes(key: &str, entry: &Entry) -> io::Result<usize> {
    Ok(serde_json::to_vec(&(key, entry))
        .map_err(io::Error::other)?
        .len())
}
fn read_snapshot(directory: &Path, tenant_digest: &str) -> io::Result<Snapshot> {
    let file = File::open(directory.join("state.json"))?;
    let mut bytes = Vec::new();
    file.take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid("admission snapshot exceeds byte limit"));
    }
    let envelope: SnapshotEnvelope = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let canonical = serde_json::to_vec(&envelope.snapshot).map_err(io::Error::other)?;
    if hex::encode(Sha256::digest(&canonical)) != envelope.checksum_sha256 {
        return Err(invalid("admission snapshot integrity mismatch"));
    }
    validate_snapshot(&envelope.snapshot, tenant_digest)?;
    Ok(envelope.snapshot)
}
fn validate_snapshot(snapshot: &Snapshot, tenant_digest: &str) -> io::Result<()> {
    if snapshot.version != 2
        || snapshot.tenant_digest != tenant_digest
        || snapshot.entries.len() > CAPACITY
        || snapshot.rate_tokens_milli > 64000
        || snapshot.rate_refill_ms > snapshot.wall_floor_ms
    {
        return Err(invalid(
            "admission snapshot version, tenant or capacity mismatch",
        ));
    }
    for (key, entry) in &snapshot.entries {
        let (_, created) = parse_key(key).ok_or_else(|| invalid("invalid stored request key"))?;
        if created != entry.created_ms
            || entry.thread_id.0.is_empty()
            || entry.thread_id.0.len() > 256
            || entry.target_run.0.is_empty()
            || entry.target_run.0.len() > 256
            || entry.owner.slot >= OWNER_SLOTS
            || !is_nonce(&entry.owner.nonce)
            || !is_nonce(&entry.reservation)
            || entry_bytes(key, entry)? > MAX_ENTRY_BYTES
            || entry.state == StoreState::AdmissionUnknown
            || (entry.state == StoreState::Pending) != entry.identity.is_none()
            || entry.identity.as_ref().is_some_and(|id| {
                id.run_id != entry.target_run || id.turn_id.0 > snapshot.last_product_turn
            })
        {
            return Err(invalid("invalid admission entry"));
        }
    }
    Ok(())
}
fn replace_snapshot(directory: &Path, snapshot: &Snapshot) -> io::Result<()> {
    validate_snapshot(snapshot, &snapshot.tenant_digest)?;
    let canonical = serde_json::to_vec(snapshot).map_err(io::Error::other)?;
    // A checksum detects damaged but still parseable authority. It is an integrity check, not
    // authentication against a principal already authorized to replace the whole record root.
    let bytes = serde_json::to_vec(&serde_json::json!({
        "checksum_sha256": hex::encode(Sha256::digest(&canonical)), "snapshot": snapshot,
    }))
    .map_err(io::Error::other)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid("admission snapshot exceeds byte limit"));
    }
    crate::cache_io::atomic_replace_private(&directory.join("state.json"), &bytes)?;
    // The cache primitive already flushes Unix namespaces; its non-Unix no-op is deliberately
    // supplemented here. This is a required authority barrier, never best effort.
    #[cfg(not(unix))]
    sync_directory(directory)?;
    Ok(())
}
fn random_nonce() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| io::Error::other("admission owner entropy unavailable"))?;
    Ok(hex::encode(bytes))
}
fn is_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn owner_path(directory: &Path, slot: u16) -> PathBuf {
    directory.join(format!("owner-{slot:02}.lock"))
}
fn owner_token_path(directory: &Path, slot: u16) -> PathBuf {
    directory.join(format!("owner-{slot:02}.token"))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn private_file(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
fn lock(directory: &Path) -> io::Result<Lock> {
    let file = private_file(&directory.join("authority.lock"), true)?;
    let started = Instant::now();
    for attempt in 0..1001 {
        match file.try_lock() {
            Ok(()) => return Ok(Lock(file)),
            Err(TryLockError::WouldBlock) if started.elapsed() < LOCK_TIMEOUT && attempt < 1000 => {
                std::thread::sleep(
                    Duration::from_millis(5).min(LOCK_TIMEOUT.saturating_sub(started.elapsed())),
                );
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "admission authority lock timed out",
                ));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }
    }
    unreachable!("bounded lock attempts return")
}
fn provision_directory(directory: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = directory;
    while !ancestor.exists() {
        if missing.len() >= 64 {
            return Err(invalid("admission directory nesting limit"));
        }
        missing.push(ancestor.to_path_buf());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("missing admission directory ancestor"))?;
    }
    crate::create_state_dir(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in &missing {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // Persist newly created links outward from the existing ancestor, including the authority's
    // parent. A surviving authority marker must never refer to a lost newly created namespace.
    for path in missing.iter().rev() {
        sync_directory(path)?;
        sync_directory(
            path.parent()
                .ok_or_else(|| invalid("missing directory parent"))?,
        )?;
    }
    sync_directory(directory)
}
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
#[cfg(windows)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    windows_barrier::sync_directory(directory)
}
#[cfg(not(any(unix, windows)))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable admission namespace barrier unavailable",
    ))
}

#[cfg(windows)]
mod windows_barrier {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Prefix};
    #[repr(C)]
    struct IoStatus {
        status: usize,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtFlushBuffersFileEx(
            handle: *mut c_void,
            flags: u32,
            parameters: *const c_void,
            length: u32,
            status: *mut IoStatus,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetVolumeInformationByHandleW(
            handle: *mut c_void,
            name: *mut u16,
            name_len: u32,
            serial: *mut u32,
            component_len: *mut u32,
            flags: *mut u32,
            fs_name: *mut u16,
            fs_len: u32,
        ) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
        // Match the existing support adapter's documented local NTFS contract without creating
        // a record -> support -> record dependency. Remote/removable/unknown media fail closed.
        let absolute = std::fs::canonicalize(path)?;
        let drive = match absolute.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(c) | Prefix::VerbatimDisk(c) => c,
                _ => return Err(invalid("admission requires local NTFS")),
            },
            _ => return Err(invalid("admission requires an absolute local path")),
        };
        let root: Vec<u16> = std::ffi::OsStr::new(&format!("{}:\\", drive as char))
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: root is a terminated UTF-16 drive-root string.
        if unsafe { GetDriveTypeW(root.as_ptr()) } != 3 {
            return Err(invalid("admission requires a fixed local drive"));
        }
        let file = OpenOptions::new()
            .access_mode(0x0010_0003)
            .share_mode(0x0000_0003)
            .custom_flags(0x0200_0000 | 0x0020_0000 | 0x8000_0000)
            .open(&absolute)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("admission directory is a reparse point"));
        }
        let mut name = [0u16; 16];
        // SAFETY: all optional outputs are null; the live handle and bounded filesystem-name buffer are valid.
        if unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                name.as_mut_ptr(),
                name.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if name[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
            return Err(invalid("admission requires NTFS"));
        }
        let mut status = IoStatus {
            status: 0,
            information: 0,
        };
        // SAFETY: synchronous directory handle has FILE_ADD_FILE (write-data) access; flags zero
        // flushes metadata and the storage cache. This is the same barrier used by durable_windows_state.
        let result = unsafe {
            NtFlushBuffersFileEx(file.as_raw_handle(), 0, std::ptr::null(), 0, &mut status)
        };
        if result < 0 {
            return Err(io::Error::other("admission directory flush failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

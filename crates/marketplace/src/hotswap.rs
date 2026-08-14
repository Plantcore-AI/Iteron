//! Transactional, host-owned replacement of one stateful implementation generation.
//!
//! Providers can move bounded state and report readiness. Only this coordinator may advance the
//! active generation, and it does so once, after readiness, with a durable hash-chained receipt.

mod runtime_executor;
pub use runtime_executor::{
    ActiveImplementationHandle, RuntimeGenerationError, RuntimeHotSwapExecutor,
    implementation_authority_sha256,
};

use crate::implementation_protocol::ImplementationState;
use iteron_tunables::ModuleId;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const HOTSWAP_LEDGER_SCHEMA: &str = "iteron-hotswap-ledger/1";
pub const MAX_HOTSWAP_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_HOTSWAP_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_HOTSWAP_DEADLINE_MS: u64 = 3_600_000;
const MAX_HOTSWAP_ID_BYTES: usize = 128;
const MAX_HOTSWAP_REASON_BYTES: usize = 1024;
const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotSwapPhase {
    Verify,
    ShadowLoad,
    Quiesce,
    Snapshot,
    Migrate,
    Restore,
    Readiness,
    AtomicSwitch,
    Drain,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotSwapLedgerOutcome {
    Applied,
    Blocked,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotSwapBlockKind {
    Validation,
    Dependency,
    Provider,
    Deadline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotSwapGeneration {
    pub generation: u64,
    pub implementation_id: String,
    pub artifact_sha256: String,
    pub state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwapRequest {
    pub transaction_id: String,
    pub module: ModuleId,
    pub candidate_sha256: String,
    pub old: HotSwapGeneration,
    pub new: HotSwapGeneration,
    pub authority_sha256: String,
    pub deadline_ms: u64,
}

/// A validated, immutable transaction intent. Execution consumes it exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwapTransaction {
    request: HotSwapRequest,
}

impl HotSwapTransaction {
    pub fn new(request: HotSwapRequest) -> Result<Self, HotSwapError> {
        request.validate()?;
        Ok(Self { request })
    }

    #[must_use]
    pub fn request(&self) -> &HotSwapRequest {
        &self.request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwapStageError {
    pub kind: HotSwapBlockKind,
    pub reason: String,
}

impl HotSwapStageError {
    #[must_use]
    pub fn new(kind: HotSwapBlockKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: bounded_reason(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwapBlocked {
    pub transaction_id: String,
    pub phase: HotSwapPhase,
    pub kind: HotSwapBlockKind,
    pub reason: String,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotSwapResult {
    Committed(HotSwapGeneration),
    RolledBack(HotSwapBlocked),
}

/// Process ownership remains with the executor. `rollback` must stop/reap the shadow process and,
/// if the atomic switch ran, restore the old generation before returning success.
pub trait HotSwapExecutor {
    fn protocol_version(&self) -> u16;
    fn verify(&mut self, request: &HotSwapRequest, end: Instant) -> Result<(), HotSwapStageError>;
    fn shadow_load(
        &mut self,
        request: &HotSwapRequest,
        end: Instant,
    ) -> Result<(), HotSwapStageError>;
    fn quiesce(&mut self, request: &HotSwapRequest, end: Instant) -> Result<(), HotSwapStageError>;
    fn snapshot(
        &mut self,
        request: &HotSwapRequest,
        end: Instant,
    ) -> Result<ImplementationState, HotSwapStageError>;
    fn migrate(
        &mut self,
        request: &HotSwapRequest,
        snapshot: &ImplementationState,
        end: Instant,
    ) -> Result<ImplementationState, HotSwapStageError>;
    fn restore(
        &mut self,
        request: &HotSwapRequest,
        migrated: &ImplementationState,
        end: Instant,
    ) -> Result<(), HotSwapStageError>;
    fn readiness(
        &mut self,
        request: &HotSwapRequest,
        migrated: &ImplementationState,
        end: Instant,
    ) -> Result<(), HotSwapStageError>;
    fn atomic_switch(
        &mut self,
        request: &HotSwapRequest,
        end: Instant,
    ) -> Result<(), HotSwapStageError>;
    fn drain(&mut self, request: &HotSwapRequest, end: Instant) -> Result<(), HotSwapStageError>;
    fn rollback(&mut self, request: &HotSwapRequest) -> Result<(), HotSwapStageError>;
    /// Release the host routing reservation only after the committed ledger record is durable.
    fn committed(&mut self, request: &HotSwapRequest) -> Result<(), HotSwapStageError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationLedgerRecord {
    pub schema_id: String,
    pub sequence: u64,
    pub previous_sha256: String,
    pub record_sha256: String,
    pub transaction_id: String,
    pub module: ModuleId,
    pub candidate_sha256: String,
    pub old_generation: u64,
    pub old_implementation_id: String,
    pub old_artifact_sha256: String,
    pub old_state_sha256: String,
    pub new_generation: u64,
    pub new_implementation_id: String,
    pub new_artifact_sha256: String,
    pub new_state_sha256: String,
    pub authority_sha256: String,
    pub phase: HotSwapPhase,
    pub outcome: HotSwapLedgerOutcome,
    pub block_kind: Option<HotSwapBlockKind>,
    pub reason: Option<String>,
    pub started_unix_ms: u64,
    pub elapsed_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum HotSwapError {
    #[error("invalid hot-swap request: {0}")]
    InvalidRequest(&'static str),
    #[error("hot-swap ledger I/O failed: {0}")]
    LedgerIo(String),
    #[error("hot-swap ledger is malformed: {0}")]
    LedgerMalformed(&'static str),
    #[error("hot-swap rollback failed: {0}")]
    RollbackFailed(String),
    #[error("hot-swap committed but finalization failed: {0}")]
    CommitFinalization(String),
}

pub struct ActivationLedger {
    path: PathBuf,
    next_sequence: u64,
    previous_sha256: String,
    file_bytes: u64,
    seen: BTreeSet<(String, HotSwapPhase)>,
}

impl ActivationLedger {
    pub fn open(
        path: impl Into<PathBuf>,
    ) -> Result<(Self, Vec<ActivationLedgerRecord>), HotSwapError> {
        let path = path.into();
        reject_non_regular(&path)?;
        let records = replay_ledger(&path)?;
        let file_bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let previous_sha256 = records
            .last()
            .map(|record| record.record_sha256.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_owned());
        let next_sequence = records.last().map_or(0, |record| record.sequence + 1);
        let seen = records
            .iter()
            .map(|record| (record.transaction_id.clone(), record.phase))
            .collect();
        Ok((
            Self {
                path,
                next_sequence,
                previous_sha256,
                file_bytes,
                seen,
            },
            records,
        ))
    }

    fn append(&mut self, mut record: ActivationLedgerRecord) -> Result<(), HotSwapError> {
        if !self
            .seen
            .insert((record.transaction_id.clone(), record.phase))
        {
            return Err(HotSwapError::LedgerMalformed("duplicate transaction phase"));
        }
        reject_non_regular(&self.path)?;
        let actual = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if actual != self.file_bytes {
            return Err(HotSwapError::LedgerMalformed(
                "ledger changed during transaction",
            ));
        }
        record.sequence = self.next_sequence;
        record.previous_sha256 = self.previous_sha256.clone();
        record.record_sha256 = record_hash(&record)?;
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| HotSwapError::LedgerIo(error.to_string()))?;
        if bytes.len() + 1 > MAX_HOTSWAP_RECORD_BYTES {
            return Err(HotSwapError::LedgerMalformed("record exceeds bound"));
        }
        bytes.push(b'\n');
        if self.file_bytes.saturating_add(bytes.len() as u64) > MAX_HOTSWAP_LEDGER_BYTES {
            return Err(HotSwapError::LedgerMalformed("ledger exceeds bound"));
        }
        let mut file = open_append(&self.path)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_data())
            .map_err(|error| HotSwapError::LedgerIo(error.to_string()))?;
        self.file_bytes += bytes.len() as u64;
        self.next_sequence += 1;
        self.previous_sha256 = record.record_sha256;
        Ok(())
    }
}

pub struct HotSwapCoordinator {
    ledger: ActivationLedger,
    active: BTreeMap<ModuleId, HotSwapGeneration>,
}

impl HotSwapCoordinator {
    pub fn open(
        path: impl Into<PathBuf>,
        initial: impl IntoIterator<Item = (ModuleId, HotSwapGeneration)>,
    ) -> Result<Self, HotSwapError> {
        let (ledger, records) = ActivationLedger::open(path)?;
        let mut active: BTreeMap<_, _> = initial.into_iter().collect();
        for record in records {
            if record.phase == HotSwapPhase::Committed
                && record.outcome == HotSwapLedgerOutcome::Committed
            {
                let old = old_generation(&record);
                if active.get(&record.module) != Some(&old) {
                    return Err(HotSwapError::LedgerMalformed(
                        "committed generation chain does not match predecessor",
                    ));
                }
                active.insert(record.module, new_generation(&record));
            }
        }
        Ok(Self { ledger, active })
    }

    #[must_use]
    pub fn current_generation(&self, module: ModuleId) -> Option<&HotSwapGeneration> {
        self.active.get(&module)
    }

    pub fn transact<E: HotSwapExecutor>(
        &mut self,
        request: HotSwapRequest,
        executor: &mut E,
    ) -> Result<HotSwapResult, HotSwapError> {
        self.transact_prepared(HotSwapTransaction::new(request)?, executor)
    }

    pub fn transact_prepared<E: HotSwapExecutor>(
        &mut self,
        transaction: HotSwapTransaction,
        executor: &mut E,
    ) -> Result<HotSwapResult, HotSwapError> {
        let request = transaction.request;
        let started = Instant::now();
        let started_unix_ms = unix_ms()?;
        let end = started + Duration::from_millis(request.deadline_ms);
        if executor.protocol_version() != crate::IMPLEMENTATION_PROCESS_PROTOCOL_VERSION {
            return self.rollback(
                &request,
                executor,
                HotSwapPhase::Verify,
                HotSwapStageError::new(
                    HotSwapBlockKind::Validation,
                    "hot swap requires implementation protocol v2",
                ),
                started,
                started_unix_ms,
            );
        }
        if self.active.get(&request.module) != Some(&request.old) {
            return self.rollback(
                &request,
                executor,
                HotSwapPhase::Verify,
                HotSwapStageError::new(
                    HotSwapBlockKind::Dependency,
                    "active generation does not match transaction predecessor",
                ),
                started,
                started_unix_ms,
            );
        }

        macro_rules! stage {
            ($phase:expr, $operation:expr) => {{
                if Instant::now() >= end {
                    return self.rollback(
                        &request,
                        executor,
                        $phase,
                        HotSwapStageError::new(
                            HotSwapBlockKind::Deadline,
                            "transaction deadline elapsed",
                        ),
                        started,
                        started_unix_ms,
                    );
                }
                match $operation {
                    Ok(value) => {
                        if let Err(error) = self.record(
                            &request,
                            $phase,
                            HotSwapLedgerOutcome::Applied,
                            None,
                            started,
                            started_unix_ms,
                        ) {
                            executor.rollback(&request).map_err(|rollback| {
                                HotSwapError::RollbackFailed(rollback.reason)
                            })?;
                            return Err(error);
                        }
                        value
                    }
                    Err(error) => {
                        return self.rollback(
                            &request,
                            executor,
                            $phase,
                            error,
                            started,
                            started_unix_ms,
                        );
                    }
                }
            }};
        }

        stage!(HotSwapPhase::Verify, executor.verify(&request, end));
        stage!(
            HotSwapPhase::ShadowLoad,
            executor.shadow_load(&request, end)
        );
        stage!(HotSwapPhase::Quiesce, executor.quiesce(&request, end));
        let snapshot = stage!(HotSwapPhase::Snapshot, executor.snapshot(&request, end));
        if !state_matches(&snapshot, request.module, &request.old) {
            return self.rollback(
                &request,
                executor,
                HotSwapPhase::Migrate,
                HotSwapStageError::new(HotSwapBlockKind::Validation, "snapshot identity mismatch"),
                started,
                started_unix_ms,
            );
        }
        let migrated = stage!(
            HotSwapPhase::Migrate,
            executor.migrate(&request, &snapshot, end)
        );
        if !state_matches(&migrated, request.module, &request.new)
            || migrated.run_id != snapshot.run_id
            || migrated.state_schema != snapshot.state_schema
        {
            return self.rollback(
                &request,
                executor,
                HotSwapPhase::Restore,
                HotSwapStageError::new(
                    HotSwapBlockKind::Validation,
                    "migrated state identity mismatch",
                ),
                started,
                started_unix_ms,
            );
        }
        stage!(
            HotSwapPhase::Restore,
            executor.restore(&request, &migrated, end)
        );
        stage!(
            HotSwapPhase::Readiness,
            executor.readiness(&request, &migrated, end)
        );
        stage!(
            HotSwapPhase::AtomicSwitch,
            executor.atomic_switch(&request, end)
        );
        stage!(HotSwapPhase::Drain, executor.drain(&request, end));
        if let Err(error) = self.record(
            &request,
            HotSwapPhase::Committed,
            HotSwapLedgerOutcome::Committed,
            None,
            started,
            started_unix_ms,
        ) {
            executor
                .rollback(&request)
                .map_err(|rollback| HotSwapError::RollbackFailed(rollback.reason))?;
            return Err(error);
        }
        self.active.insert(request.module, request.new.clone());
        executor
            .committed(&request)
            .map_err(|error| HotSwapError::CommitFinalization(error.reason))?;
        Ok(HotSwapResult::Committed(request.new))
    }

    fn rollback<E: HotSwapExecutor>(
        &mut self,
        request: &HotSwapRequest,
        executor: &mut E,
        phase: HotSwapPhase,
        failure: HotSwapStageError,
        started: Instant,
        started_unix_ms: u64,
    ) -> Result<HotSwapResult, HotSwapError> {
        let blocked_record = self.record(
            request,
            phase,
            HotSwapLedgerOutcome::Blocked,
            Some(&failure),
            started,
            started_unix_ms,
        );
        let rollback = executor.rollback(request);
        rollback.map_err(|error| HotSwapError::RollbackFailed(error.reason))?;
        blocked_record?;
        self.record(
            request,
            HotSwapPhase::RolledBack,
            HotSwapLedgerOutcome::RolledBack,
            Some(&failure),
            started,
            started_unix_ms,
        )?;
        Ok(HotSwapResult::RolledBack(HotSwapBlocked {
            transaction_id: request.transaction_id.clone(),
            phase,
            kind: failure.kind,
            reason: failure.reason,
            deadline_ms: request.deadline_ms,
        }))
    }

    fn record(
        &mut self,
        request: &HotSwapRequest,
        phase: HotSwapPhase,
        outcome: HotSwapLedgerOutcome,
        failure: Option<&HotSwapStageError>,
        started: Instant,
        started_unix_ms: u64,
    ) -> Result<(), HotSwapError> {
        self.ledger.append(ActivationLedgerRecord {
            schema_id: HOTSWAP_LEDGER_SCHEMA.to_owned(),
            sequence: 0,
            previous_sha256: String::new(),
            record_sha256: String::new(),
            transaction_id: request.transaction_id.clone(),
            module: request.module,
            candidate_sha256: request.candidate_sha256.clone(),
            old_generation: request.old.generation,
            old_implementation_id: request.old.implementation_id.clone(),
            old_artifact_sha256: request.old.artifact_sha256.clone(),
            old_state_sha256: request.old.state_sha256.clone(),
            new_generation: request.new.generation,
            new_implementation_id: request.new.implementation_id.clone(),
            new_artifact_sha256: request.new.artifact_sha256.clone(),
            new_state_sha256: request.new.state_sha256.clone(),
            authority_sha256: request.authority_sha256.clone(),
            phase,
            outcome,
            block_kind: failure.map(|error| error.kind),
            reason: failure.map(|error| error.reason.clone()),
            started_unix_ms,
            elapsed_ms: duration_ms(started.elapsed()),
            deadline_ms: request.deadline_ms,
        })
    }
}

impl HotSwapRequest {
    fn validate(&self) -> Result<(), HotSwapError> {
        if !valid_id(&self.transaction_id)
            || !valid_digest(&self.candidate_sha256)
            || !valid_digest(&self.authority_sha256)
            || self.deadline_ms == 0
            || self.deadline_ms > MAX_HOTSWAP_DEADLINE_MS
        {
            return Err(HotSwapError::InvalidRequest("invalid transaction identity"));
        }
        self.old.validate()?;
        self.new.validate()?;
        if self.new.generation != self.old.generation.saturating_add(1) {
            return Err(HotSwapError::InvalidRequest(
                "generation is not consecutive",
            ));
        }
        Ok(())
    }
}

impl HotSwapGeneration {
    fn validate(&self) -> Result<(), HotSwapError> {
        if self.generation == 0
            || !valid_id(&self.implementation_id)
            || !valid_digest(&self.artifact_sha256)
            || !valid_digest(&self.state_sha256)
        {
            return Err(HotSwapError::InvalidRequest("invalid generation identity"));
        }
        Ok(())
    }
}

pub fn replay_ledger(path: &Path) -> Result<Vec<ActivationLedgerRecord>, HotSwapError> {
    reject_non_regular(path)?;
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(HotSwapError::LedgerIo(error.to_string())),
    };
    if bytes.len() as u64 > MAX_HOTSWAP_LEDGER_BYTES {
        return Err(HotSwapError::LedgerMalformed("ledger exceeds bound"));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(HotSwapError::LedgerMalformed("unterminated record"));
    }
    let mut records = Vec::new();
    let mut previous = GENESIS_HASH.to_owned();
    let mut seen = BTreeSet::new();
    let mut transitions: BTreeMap<String, (usize, bool)> = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (sequence, line) in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if line.len() + 1 > MAX_HOTSWAP_RECORD_BYTES {
            return Err(HotSwapError::LedgerMalformed("record exceeds bound"));
        }
        let value = crate::implementation_protocol::strict_json_value(line)
            .map_err(|_| HotSwapError::LedgerMalformed("record is not strict JSON"))?;
        let record: ActivationLedgerRecord = serde_json::from_value(value)
            .map_err(|_| HotSwapError::LedgerMalformed("record shape is invalid"))?;
        if record.schema_id != HOTSWAP_LEDGER_SCHEMA
            || record.sequence != sequence as u64
            || record.previous_sha256 != previous
            || !valid_record(&record)
            || record_hash(&record)? != record.record_sha256
            || !seen.insert((record.transaction_id.clone(), record.phase))
        {
            return Err(HotSwapError::LedgerMalformed(
                "record identity or hash is invalid",
            ));
        }
        let identity = ledger_identity(&record);
        if identities
            .entry(record.transaction_id.clone())
            .or_insert_with(|| identity.clone())
            != &identity
        {
            return Err(HotSwapError::LedgerMalformed(
                "transaction identity changed between phases",
            ));
        }
        validate_transition(&record, &mut transitions)?;
        previous = record.record_sha256.clone();
        records.push(record);
    }
    if transitions
        .values()
        .any(|(position, blocked)| *blocked || *position != 10)
    {
        return Err(HotSwapError::LedgerMalformed(
            "transaction has no terminal outcome",
        ));
    }
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LedgerIdentity {
    module: ModuleId,
    candidate_sha256: String,
    old: HotSwapGeneration,
    new: HotSwapGeneration,
    authority_sha256: String,
    started_unix_ms: u64,
    deadline_ms: u64,
}

fn ledger_identity(record: &ActivationLedgerRecord) -> LedgerIdentity {
    LedgerIdentity {
        module: record.module,
        candidate_sha256: record.candidate_sha256.clone(),
        old: HotSwapGeneration {
            generation: record.old_generation,
            implementation_id: record.old_implementation_id.clone(),
            artifact_sha256: record.old_artifact_sha256.clone(),
            state_sha256: record.old_state_sha256.clone(),
        },
        new: new_generation(record),
        authority_sha256: record.authority_sha256.clone(),
        started_unix_ms: record.started_unix_ms,
        deadline_ms: record.deadline_ms,
    }
}

fn validate_transition(
    record: &ActivationLedgerRecord,
    transitions: &mut BTreeMap<String, (usize, bool)>,
) -> Result<(), HotSwapError> {
    const PHASES: [HotSwapPhase; 10] = [
        HotSwapPhase::Verify,
        HotSwapPhase::ShadowLoad,
        HotSwapPhase::Quiesce,
        HotSwapPhase::Snapshot,
        HotSwapPhase::Migrate,
        HotSwapPhase::Restore,
        HotSwapPhase::Readiness,
        HotSwapPhase::AtomicSwitch,
        HotSwapPhase::Drain,
        HotSwapPhase::Committed,
    ];
    let entry = transitions
        .entry(record.transaction_id.clone())
        .or_insert((0, false));
    if entry.1 {
        if record.phase != HotSwapPhase::RolledBack
            || record.outcome != HotSwapLedgerOutcome::RolledBack
        {
            return Err(HotSwapError::LedgerMalformed("invalid rollback transition"));
        }
        entry.1 = false;
        entry.0 = PHASES.len();
        return Ok(());
    }
    if entry.0 >= PHASES.len() || record.phase != PHASES[entry.0] {
        return Err(HotSwapError::LedgerMalformed(
            "non-contiguous phase transition",
        ));
    }
    match record.outcome {
        HotSwapLedgerOutcome::Applied if record.phase != HotSwapPhase::Committed => entry.0 += 1,
        HotSwapLedgerOutcome::Blocked if record.phase != HotSwapPhase::Committed => entry.1 = true,
        HotSwapLedgerOutcome::Committed if record.phase == HotSwapPhase::Committed => {
            entry.0 += 1;
        }
        _ => return Err(HotSwapError::LedgerMalformed("invalid phase outcome")),
    }
    Ok(())
}

fn valid_record(record: &ActivationLedgerRecord) -> bool {
    valid_id(&record.transaction_id)
        && valid_id(&record.old_implementation_id)
        && valid_id(&record.new_implementation_id)
        && valid_digest(&record.candidate_sha256)
        && valid_digest(&record.old_artifact_sha256)
        && valid_digest(&record.new_artifact_sha256)
        && valid_digest(&record.old_state_sha256)
        && valid_digest(&record.new_state_sha256)
        && valid_digest(&record.authority_sha256)
        && valid_digest(&record.previous_sha256)
        && valid_digest(&record.record_sha256)
        && record.old_generation > 0
        && record.new_generation == record.old_generation.saturating_add(1)
        && record.deadline_ms > 0
        && record.reason.as_ref().is_none_or(|reason| {
            !reason.is_empty()
                && reason.len() <= MAX_HOTSWAP_REASON_BYTES
                && !reason
                    .chars()
                    .any(|character| matches!(character, '\n' | '\r' | '\0'))
        })
        && (record.block_kind.is_some() == record.reason.is_some())
        && match record.outcome {
            HotSwapLedgerOutcome::Applied | HotSwapLedgerOutcome::Committed => {
                record.block_kind.is_none()
            }
            HotSwapLedgerOutcome::Blocked | HotSwapLedgerOutcome::RolledBack => {
                record.block_kind.is_some()
            }
        }
}

fn record_hash(record: &ActivationLedgerRecord) -> Result<String, HotSwapError> {
    let mut unsigned = record.clone();
    unsigned.record_sha256.clear();
    let bytes =
        serde_json::to_vec(&unsigned).map_err(|error| HotSwapError::LedgerIo(error.to_string()))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
}

fn new_generation(record: &ActivationLedgerRecord) -> HotSwapGeneration {
    HotSwapGeneration {
        generation: record.new_generation,
        implementation_id: record.new_implementation_id.clone(),
        artifact_sha256: record.new_artifact_sha256.clone(),
        state_sha256: record.new_state_sha256.clone(),
    }
}

fn old_generation(record: &ActivationLedgerRecord) -> HotSwapGeneration {
    HotSwapGeneration {
        generation: record.old_generation,
        implementation_id: record.old_implementation_id.clone(),
        artifact_sha256: record.old_artifact_sha256.clone(),
        state_sha256: record.old_state_sha256.clone(),
    }
}

fn state_matches(
    state: &ImplementationState,
    module: ModuleId,
    generation: &HotSwapGeneration,
) -> bool {
    state.validate().is_ok()
        && state.module == module
        && state.implementation_id == generation.implementation_id
        && state.generation == generation.generation
        && state.state_sha256 == generation.state_sha256
}

fn reject_non_regular(path: &Path) -> Result<(), HotSwapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            HotSwapError::LedgerMalformed("ledger is not a regular file"),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(HotSwapError::LedgerIo(error.to_string())),
    }
}

fn open_append(path: &Path) -> Result<File, HotSwapError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| HotSwapError::LedgerIo(error.to_string()))
}

fn unix_ms() -> Result<u64, HotSwapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_ms)
        .map_err(|error| HotSwapError::LedgerIo(error.to_string()))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn bounded_reason(mut reason: String) -> String {
    reason.retain(|character| !matches!(character, '\0' | '\n' | '\r'));
    if reason.is_empty() {
        return "unspecified failure".to_owned();
    }
    while reason.len() > MAX_HOTSWAP_REASON_BYTES {
        reason.pop();
    }
    reason
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HOTSWAP_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
        })
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

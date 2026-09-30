//! Independent evidence for optional cache writes. This owner never shares an unlocked Rollout
//! with a worker. Read projections advance only after the maintenance journal's own barrier.
mod cache;
mod pool;
mod store;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use iteron_protocol::advisory_maintenance::{
    MaintenanceEvidenceSourceV1, MaintenanceJobIdV1, MaintenanceJobV1, MaintenanceKindV1,
    MaintenanceObservationV1, MaintenanceStateV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

const MAX_JOBS: usize = 256;
const MAX_READ_JOBS: usize = 64;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES: usize = 256 * 1024;
const QUEUE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MaintenanceReadError {
    #[error("maintenance observation bounds are invalid")]
    InvalidBounds,
    #[error("maintenance journal has not become available")]
    Unavailable,
    #[error("maintenance IO or durable publication needs reconciliation")]
    ReconciliationNeeded,
}

#[async_trait]
pub(crate) trait AdvisoryMaintenanceReadPort: Send + Sync {
    /// Bounded current-state projection, rather than a lossless stream of every transition.
    fn observe(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> Result<MaintenanceObservationV1, MaintenanceReadError>;
    async fn wait(
        &self,
        after_revision: u64,
        timeout_ms: u64,
    ) -> Result<MaintenanceObservationV1, MaintenanceReadError>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    scope_sha256: String,
    revision: u64,
    next_job: u64,
    jobs: Vec<MaintenanceJobV1>,
    dropped_jobs: u64,
}
impl Snapshot {
    fn empty(scope_sha256: String) -> Self {
        Self {
            version: 1,
            scope_sha256,
            revision: 1,
            next_job: 1,
            jobs: Vec::new(),
            dropped_jobs: 0,
        }
    }
    fn validate(&self, scope: &str) -> Result<(), MaintenanceReadError> {
        if self.version != 1
            || self.scope_sha256 != scope
            || !valid_hash(scope)
            || self.revision == 0
            || self.next_job == 0
            || self.jobs.len() > MAX_JOBS
            || self
                .dropped_jobs
                .checked_add(self.jobs.len() as u64)
                .and_then(|count| count.checked_add(1))
                != Some(self.next_job)
        {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        let mut previous = 0;
        for job in &self.jobs {
            if job.job_id.0 <= previous
                || job.job_id.0 >= self.next_job
                || !valid_hash(&job.input_sha256)
                || job.last_revision == 0
                || job.last_revision > self.revision
                || job.reason_code.as_ref().is_some_and(|code| {
                    code.len() > 64
                        || !code
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                })
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            match job.state {
                MaintenanceStateV1::Queued
                    if job.started_unix_ms.is_none()
                        && job.finished_unix_ms.is_none()
                        && job.reason_code.is_none() => {}
                MaintenanceStateV1::Running
                    if job.started_unix_ms.is_some()
                        && job.finished_unix_ms.is_none()
                        && job.reason_code.is_none() => {}
                MaintenanceStateV1::Completed
                    if job.started_unix_ms.is_some()
                        && job.finished_unix_ms.is_some()
                        && job.reason_code.is_none() => {}
                MaintenanceStateV1::Failed | MaintenanceStateV1::ReconciliationNeeded
                    if job.finished_unix_ms.is_some() && job.reason_code.is_some() => {}
                _ => return Err(MaintenanceReadError::ReconciliationNeeded),
            }
            previous = job.job_id.0;
        }
        Ok(())
    }
    fn advance(&mut self) -> Result<(), MaintenanceReadError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
        Ok(())
    }
}

struct Writer {
    store: Box<dyn store::MaintenanceJournal>,
    snapshot: Snapshot,
}
struct View {
    snapshot: Snapshot,
    sha256: String,
}

pub(super) struct MaintenanceOwner {
    scope: String,
    directory: PathBuf,
    writer: Mutex<Option<Writer>>,
    view: Mutex<Result<Option<View>, MaintenanceReadError>>,
    blocked: AtomicUsize,
    faulted: AtomicBool,
    changed: Notify,
    uncertain_leases: Mutex<Vec<cache::CacheLease>>,
}

pub(super) struct MaintenanceTask {
    kind: Option<MaintenanceKindV1>,
    turn: u32,
    input_sha256: String,
    target_sha256: String,
    target: Option<PathBuf>,
    queued_unix_ms: u64,
    queued_at: Instant,
    input: Vec<u8>,
}

impl MaintenanceOwner {
    pub(super) fn new(directory: PathBuf, scope: String) -> Arc<Self> {
        Arc::new(Self {
            scope,
            directory,
            writer: Mutex::new(None),
            view: Mutex::new(Ok(None)),
            blocked: AtomicUsize::new(0),
            faulted: AtomicBool::new(false),
            changed: Notify::new(),
            uncertain_leases: Mutex::new(Vec::new()),
        })
    }
    pub(super) fn scope(&self) -> &str {
        &self.scope
    }
    pub(super) fn initialize(self: &Arc<Self>) -> bool {
        pool::enqueue(
            self.clone(),
            MaintenanceTask {
                kind: None,
                turn: 0,
                input_sha256: hash(b"initialization"),
                target_sha256: self.scope.clone(),
                target: None,
                queued_unix_ms: now_ms(),
                queued_at: Instant::now(),
                input: Vec::new(),
            },
        )
    }
    /// True proves only bounded memory-queue acceptance. It does not prove a Queued barrier,
    /// actual cache IO, completion, or a future read observation.
    pub(super) fn enqueue(
        self: &Arc<Self>,
        kind: MaintenanceKindV1,
        turn: u32,
        input: &[u8],
        target: &Path,
    ) -> bool {
        if input.len()
            > match kind {
                MaintenanceKindV1::LastSuccessfulRoute => 16 * 1024,
                MaintenanceKindV1::TokenCalibration => MAX_INPUT_BYTES,
            }
            || target.as_os_str().is_empty()
        {
            return false;
        }
        // Hash the host path's exact native bytes; lossy rendering must not merge distinct paths.
        let target_sha256 = hash(target.as_os_str().as_encoded_bytes());
        pool::enqueue(
            self.clone(),
            MaintenanceTask {
                kind: Some(kind),
                turn,
                input_sha256: hash(input),
                target_sha256,
                target: Some(target.to_owned()),
                queued_unix_ms: now_ms(),
                queued_at: Instant::now(),
                input: input.to_vec(),
            },
        )
    }
    pub(super) fn deadline_unknown(&self) {
        self.blocked.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
    pub(super) fn deadline_finished(&self) {
        self.blocked.fetch_sub(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
    fn unavailable(&self, error: MaintenanceReadError) {
        self.faulted.store(true, Ordering::Release);
        if let Ok(mut view) = self.view.lock() {
            *view = Err(error);
        }
        self.changed.notify_waiters();
    }
    fn publish(&self, writer: &mut Writer, next: Snapshot) -> Result<(), MaintenanceReadError> {
        next.validate(&self.scope)?;
        writer.store.commit(Some(writer.snapshot.revision), &next)?;
        let sha256 = hash(
            &serde_json::to_vec(&next).map_err(|_| MaintenanceReadError::ReconciliationNeeded)?,
        );
        writer.snapshot = next;
        let mut view = self
            .view
            .lock()
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        *view = Ok(Some(View {
            snapshot: writer.snapshot.clone(),
            sha256,
        }));
        drop(view);
        self.changed.notify_waiters();
        Ok(())
    }
    fn open_writer(&self) -> Result<Writer, MaintenanceReadError> {
        let mut store: Box<dyn store::MaintenanceJournal> =
            Box::new(store::FileJournal::open(&self.directory)?);
        let loaded = store.load()?;
        let mut snapshot = match loaded {
            Some(snapshot) => {
                snapshot.validate(&self.scope)?;
                snapshot
            }
            None => {
                let snapshot = Snapshot::empty(self.scope.clone());
                store.commit(None, &snapshot)?;
                snapshot
            }
        };
        // A recovered Running record cannot prove a cache write completed. Persist the unknown
        // before exposing a view or permitting another job; never replay the cache operation.
        if snapshot.jobs.iter().any(|job| {
            matches!(
                job.state,
                MaintenanceStateV1::Queued | MaintenanceStateV1::Running
            )
        }) {
            let expected = snapshot.revision;
            snapshot.advance()?;
            for job in &mut snapshot.jobs {
                if matches!(
                    job.state,
                    MaintenanceStateV1::Queued | MaintenanceStateV1::Running
                ) {
                    job.state = MaintenanceStateV1::ReconciliationNeeded;
                    job.finished_unix_ms = Some(now_ms());
                    job.reason_code = Some("restart_unfinished".into());
                    job.last_revision = snapshot.revision;
                }
            }
            store.commit(Some(expected), &snapshot)?;
        }
        let sha256 = hash(
            &serde_json::to_vec(&snapshot)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?,
        );
        let mut view = self
            .view
            .lock()
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        *view = Ok(Some(View {
            snapshot: snapshot.clone(),
            sha256,
        }));
        drop(view);
        self.changed.notify_waiters();
        Ok(Writer { store, snapshot })
    }
    pub(super) fn worker_panicked(&self) {
        self.unavailable(MaintenanceReadError::ReconciliationNeeded);
    }
    pub(super) fn execute(&self, task: MaintenanceTask) -> bool {
        self.perform(task, None)
    }
    pub(super) fn reject(&self, task: MaintenanceTask, reason: &'static str) {
        let _ = self.perform(task, Some(reason));
    }
    fn perform(&self, task: MaintenanceTask, rejection: Option<&'static str>) -> bool {
        if self.faulted.load(Ordering::Acquire) {
            return false;
        }
        let mut physical_known = true;
        let result = (|| {
            let mut slot = self
                .writer
                .lock()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            if slot.is_none() {
                *slot = Some(self.open_writer()?);
            }
            let writer = slot.as_mut().ok_or(MaintenanceReadError::Unavailable)?;
            let Some(kind) = task.kind else {
                return Ok(());
            };
            let mut next = writer.snapshot.clone();
            if next.jobs.len() >= MAX_JOBS {
                let removable = next.jobs.iter().position(|job| {
                    matches!(
                        job.state,
                        MaintenanceStateV1::Completed | MaintenanceStateV1::Failed
                    )
                });
                let index = removable.ok_or(MaintenanceReadError::ReconciliationNeeded)?;
                next.jobs.remove(index);
                next.dropped_jobs = next
                    .dropped_jobs
                    .checked_add(1)
                    .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
            }
            let id = MaintenanceJobIdV1(next.next_job);
            next.next_job = next
                .next_job
                .checked_add(1)
                .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
            next.advance()?;
            next.jobs.push(MaintenanceJobV1 {
                job_id: id,
                kind,
                turn: task.turn,
                state: MaintenanceStateV1::Queued,
                input_sha256: task.input_sha256,
                queued_unix_ms: task.queued_unix_ms,
                started_unix_ms: None,
                finished_unix_ms: None,
                last_revision: next.revision,
                reason_code: None,
            });
            self.publish(writer, next)?;
            let rejection = rejection.or_else(|| {
                (task.queued_at.elapsed() >= QUEUE_DEADLINE).then_some("queue_deadline_exceeded")
            });
            if let Some(reason) = rejection {
                return self.terminal(writer, id, MaintenanceStateV1::Failed, Some(reason));
            }
            if writer
                .snapshot
                .jobs
                .iter()
                .any(|job| job.kind == kind && job.turn > task.turn)
            {
                return self.terminal(
                    writer,
                    id,
                    MaintenanceStateV1::Failed,
                    Some("stale_turn_snapshot"),
                );
            }
            // Preserve all unknown jobs and their target leases. A crash or uncertain cache
            // publication never silently authorizes another write in this run.
            if writer
                .snapshot
                .jobs
                .iter()
                .any(|job| job.state == MaintenanceStateV1::ReconciliationNeeded)
            {
                return self.terminal(
                    writer,
                    id,
                    MaintenanceStateV1::Failed,
                    Some("prior_outcome_unknown"),
                );
            }
            let mut next = writer.snapshot.clone();
            next.advance()?;
            let job = next
                .jobs
                .iter_mut()
                .find(|job| job.job_id == id)
                .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
            job.state = MaintenanceStateV1::Running;
            job.started_unix_ms = Some(now_ms());
            job.last_revision = next.revision;
            self.publish(writer, next)?;
            let target = task
                .target
                .as_deref()
                .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
            let mut target_lease = match cache::CacheLease::open(target, kind) {
                Ok(lease) => lease,
                Err(_) => {
                    return self.terminal(
                        writer,
                        id,
                        MaintenanceStateV1::Failed,
                        Some("target_lease_unavailable"),
                    );
                }
            };
            // A native publisher panic does not become a no-effect failure. Retain its lease
            // and record uncertainty through the same durable terminal path.
            let known = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                target_lease.publish(&task.input)
            }))
            .is_ok_and(|result| result.is_ok());
            let terminal = self.terminal(
                writer,
                id,
                if known {
                    MaintenanceStateV1::Completed
                } else {
                    MaintenanceStateV1::ReconciliationNeeded
                },
                (!known).then_some("cache_publication_unknown"),
            );
            physical_known = known && terminal.is_ok();
            if !physical_known {
                // Retain an absorbing target marker across processes. A stopped native call may
                // still have published bytes; another run must not automatically rerun it.
                let _ = target_lease.quarantine();
                // Even an uncertain quarantine barrier retains the actual native writer lease;
                // this vector is bounded by the per-run retained job/admission cap.
                let mut leases = self
                    .uncertain_leases
                    .lock()
                    .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
                if leases.len() < MAX_JOBS {
                    leases.push(target_lease);
                }
            }
            terminal
        })();
        if let Err(error) = result {
            self.unavailable(error);
            return false;
        }
        physical_known
    }
    fn terminal(
        &self,
        writer: &mut Writer,
        id: MaintenanceJobIdV1,
        state: MaintenanceStateV1,
        reason: Option<&str>,
    ) -> Result<(), MaintenanceReadError> {
        let mut next = writer.snapshot.clone();
        next.advance()?;
        let job = next
            .jobs
            .iter_mut()
            .find(|job| job.job_id == id)
            .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
        job.state = state;
        job.finished_unix_ms = Some(now_ms());
        job.last_revision = next.revision;
        job.reason_code = reason.map(str::to_owned);
        self.publish(writer, next)
    }
}

#[async_trait]
impl AdvisoryMaintenanceReadPort for MaintenanceOwner {
    fn observe(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> Result<MaintenanceObservationV1, MaintenanceReadError> {
        if limit == 0 || limit > MAX_READ_JOBS {
            return Err(MaintenanceReadError::InvalidBounds);
        }
        if self.blocked.load(Ordering::Acquire) != 0 {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        let view = self
            .view
            .lock()
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        let view = view
            .as_ref()
            .map_err(|error| *error)?
            .as_ref()
            .ok_or(MaintenanceReadError::Unavailable)?;
        if after_revision > view.snapshot.revision {
            return Err(MaintenanceReadError::InvalidBounds);
        }
        let omitted_jobs = view.snapshot.jobs.len().saturating_sub(limit);
        Ok(MaintenanceObservationV1 {
            version: 1,
            scope_sha256: self.scope.clone(),
            journal_revision: view.snapshot.revision,
            journal_sha256: view.sha256.clone(),
            evidence_source: MaintenanceEvidenceSourceV1::MaintenanceJournal,
            jobs: view
                .snapshot
                .jobs
                .iter()
                .skip(omitted_jobs)
                .cloned()
                .collect(),
            dropped_jobs: view.snapshot.dropped_jobs,
            omitted_jobs,
        })
    }
    async fn wait(
        &self,
        after_revision: u64,
        timeout_ms: u64,
    ) -> Result<MaintenanceObservationV1, MaintenanceReadError> {
        if timeout_ms == 0 || timeout_ms > 60_000 {
            return Err(MaintenanceReadError::InvalidBounds);
        }
        // Register before inspection, so a barrier between inspection and await is not lost.
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        match self.observe(after_revision, MAX_READ_JOBS) {
            Ok(view) if view.journal_revision > after_revision => return Ok(view),
            Err(MaintenanceReadError::Unavailable) => {}
            Err(error) => return Err(error),
            _ => {}
        }
        let _ = tokio::time::timeout(Duration::from_millis(timeout_ms), changed).await;
        self.observe(after_revision, MAX_READ_JOBS)
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

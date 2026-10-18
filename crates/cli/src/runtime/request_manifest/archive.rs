//! Optional diagnostics are captured into a bounded per-agent queue and published only at an
//! explicit quiescent completion/inspection boundary. Artifact publication can share owner locks
//! with tools, so it must never run on a background worker alongside active tool execution.
use crate::artifacts::{
    ArtifactStoreError, DurableArtifactStore,
    request_manifest::{CapturedRequest, RequestManifestScope},
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_PENDING_REQUESTS: usize = 64;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const DRAIN_BUDGET: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Status {
    accepting: AtomicBool,
    draining: AtomicBool,
    pending: AtomicUsize,
    bytes: AtomicUsize,
    submitted: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    first_error: AtomicU8,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Failure {
    Capacity = 1,
    Closed = 2,
    Scope = 3,
    Unavailable = 4,
    PublicationUnknown = 5,
    Corrupt = 6,
    InvalidRequest = 7,
    DrainBudget = 8,
    PendingPreparation = 9,
    Busy = 10,
}
impl Status {
    fn fail(&self, failure: Failure) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        let _ = self.first_error.compare_exchange(
            0,
            failure as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn result(&self) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) == 0 {
            Ok(())
        } else {
            Err(format!(
                "request diagnostic archive incomplete: {} ({} failures)",
                self.error_code(),
                self.failed.load(Ordering::Acquire)
            ))
        }
    }
    fn error_code(&self) -> &'static str {
        match self.first_error.load(Ordering::Acquire) {
            0 => "none",
            1 => "capacity",
            2 => "capture_closed",
            3 => "scope",
            4 => "unavailable",
            5 => "publication_unknown",
            6 => "corrupt",
            7 => "invalid_request",
            8 => "drain_budget",
            9 => "pending_preparation",
            10 => "queue_busy",
            _ => "unknown",
        }
    }
    fn artifact_failure(&self, error: ArtifactStoreError) {
        self.fail(match error {
            ArtifactStoreError::Scope => Failure::Scope,
            ArtifactStoreError::Unavailable => Failure::Unavailable,
            ArtifactStoreError::PublicationUnknown => Failure::PublicationUnknown,
            ArtifactStoreError::Corrupt => Failure::Corrupt,
            ArtifactStoreError::Capacity => Failure::Capacity,
            ArtifactStoreError::InvalidRequest => Failure::InvalidRequest,
        });
    }
    fn view(&self) -> Value {
        let enabled = self.accepting.load(Ordering::Acquire);
        json!({
            "enabled": enabled,
            "mode": if enabled { "deferred_diagnostic" } else { "compact_effect_journal" },
            "availability": if self.failed.load(Ordering::Acquire) != 0 {
                "incomplete"
            } else if self.pending.load(Ordering::Acquire) != 0 {
                "pending"
            } else if self.submitted.load(Ordering::Acquire) == 0 {
                "not_captured"
            } else {
                "drained"
            },
            "submitted_requests": self.submitted.load(Ordering::Acquire),
            "completed_requests": self.completed.load(Ordering::Acquire),
            "failed_captures": self.failed.load(Ordering::Acquire),
            "pending_requests": self.pending.load(Ordering::Acquire),
            "pending_bytes": self.bytes.load(Ordering::Acquire),
            "first_error_code": self.error_code(),
            "max_pending_requests": MAX_PENDING_REQUESTS,
            "max_pending_bytes": MAX_PENDING_BYTES,
            "dispatch_evidence": "effect_journal_local_intent_not_remote_ack",
        })
    }
}

/// Reservations include captures awaiting dispatch, queued jobs and the current publication.
/// They are released on every success/error/cancellation path, including failed queue admission.
pub(super) struct Reservation {
    status: Arc<Status>,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.status.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.status.pending.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) enum Publication {
    Prepared {
        scope: Arc<RequestManifestScope>,
        capture: CapturedRequest,
        dispatched: bool,
    },
    Unavailable {
        scope: Arc<RequestManifestScope>,
        reason: &'static str,
    },
}
struct Job {
    store: DurableArtifactStore,
    publication: Publication,
    _reservation: Reservation,
}

#[derive(Clone)]
pub(super) struct ArchiveSender {
    accepting: Arc<AtomicBool>,
    queue: Arc<Mutex<Vec<Job>>>,
    status: Arc<Status>,
}
impl ArchiveSender {
    pub(super) fn scope_failure(&self, error: ArtifactStoreError) {
        self.status.artifact_failure(error);
    }
    pub(super) fn reserve(&self, bytes: Option<usize>) -> Option<Reservation> {
        if !self.accepting.load(Ordering::Acquire) {
            self.status.fail(Failure::Closed);
            return None;
        }
        let Some(bytes) = bytes.filter(|bytes| *bytes <= MAX_PENDING_BYTES) else {
            self.status.fail(Failure::Capacity);
            return None;
        };
        if self
            .status
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_PENDING_REQUESTS).then_some(count + 1)
            })
            .is_err()
        {
            self.status.fail(Failure::Capacity);
            return None;
        }
        if self
            .status
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|sum| *sum <= MAX_PENDING_BYTES)
            })
            .is_err()
        {
            self.status.pending.fetch_sub(1, Ordering::AcqRel);
            self.status.fail(Failure::Capacity);
            return None;
        }
        Some(Reservation {
            status: self.status.clone(),
            bytes,
        })
    }
    fn submit(
        &self,
        store: DurableArtifactStore,
        publication: Publication,
        reservation: Reservation,
    ) {
        self.enqueue(|| Job {
            store,
            publication,
            _reservation: reservation,
        });
    }
    fn enqueue(&self, job: impl FnOnce() -> Job) {
        // Contention can lose only optional diagnostic evidence, never user input or a send.
        let Ok(mut queue) = self.queue.try_lock() else {
            self.status.fail(Failure::Busy);
            return;
        };
        if !self.accepting.load(Ordering::Acquire) {
            self.status.fail(Failure::Closed);
            return;
        }
        queue.push(job());
        self.status.submitted.fetch_add(1, Ordering::Release);
    }
}

/// The authenticated store is captured from the actual writer for this request factory.
/// Queued jobs keep this scope even if the Agent later adopts a different run.
#[derive(Clone)]
pub(in crate::runtime) struct ScopedArchive {
    sender: ArchiveSender,
    store: DurableArtifactStore,
}
impl ScopedArchive {
    pub(super) fn scope_failure(&self, error: ArtifactStoreError) {
        self.sender.scope_failure(error);
    }
    pub(super) fn reserve(&self, bytes: Option<usize>) -> Option<Reservation> {
        self.sender.reserve(bytes)
    }
    pub(super) fn submit(&self, publication: Publication, reservation: Reservation) {
        self.sender
            .submit(self.store.clone(), publication, reservation);
    }
}

struct ArchiveOwner {
    sender: ArchiveSender,
}
struct DrainGuard<'a>(&'a AtomicBool);
impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl ArchiveOwner {
    fn drain(&self) -> Result<(), String> {
        if self
            .sender
            .status
            .draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.sender.status.fail(Failure::Busy);
            return self.sender.status.result();
        }
        let _guard = DrainGuard(&self.sender.status.draining);
        let jobs = match self.sender.queue.try_lock() {
            Ok(mut queue) => std::mem::take(&mut *queue),
            Err(_) => {
                self.sender.status.fail(Failure::Busy);
                return self.sender.status.result();
            }
        };
        let started = Instant::now();
        for job in jobs {
            // No detached worker survives this return. A store call already in progress follows
            // the store's IO contract; the elapsed budget is checked before each bounded job.
            if started.elapsed() >= DRAIN_BUDGET {
                self.sender.status.fail(Failure::DrainBudget);
                continue;
            }
            let result = match &job.publication {
                Publication::Prepared {
                    scope,
                    capture,
                    dispatched,
                } => job
                    .store
                    .publish_prepared_request(scope, capture)
                    .and_then(|prepared| {
                        if *dispatched {
                            job.store.publish_request_dispatch_intent(scope, &prepared)
                        } else {
                            Ok(())
                        }
                    }),
                Publication::Unavailable { scope, reason } => {
                    job.store.publish_request_unavailable(scope, reason)
                }
            };
            if let Err(error) = result {
                self.sender.status.artifact_failure(error);
            } else {
                self.sender.status.completed.fetch_add(1, Ordering::Release);
            }
        }
        if self.sender.status.pending.load(Ordering::Acquire) != 0 {
            self.sender.status.fail(Failure::PendingPreparation);
        }
        self.sender.status.result()
    }
}
impl Drop for ArchiveOwner {
    fn drop(&mut self) {
        self.sender.accepting.store(false, Ordering::Release);
        self.sender.status.accepting.store(false, Ordering::Release);
        // Explicit flush lets the host handle failure before exit. This fallback also drains
        // normal owner destruction and never silently claims incomplete diagnostics succeeded.
        if let Err(error) = self.drain() {
            eprintln!("{error}");
        }
    }
}

/// Disabled by default. Enabling and draining occur outside active provider/tool execution.
#[derive(Default)]
pub(crate) struct RequestArchive {
    owner: Option<ArchiveOwner>,
    status: Arc<Status>,
}
impl RequestArchive {
    pub(in crate::runtime) fn enable(
        &mut self,
        rollout: &iteron_record::Rollout,
        workspace: &std::path::Path,
    ) -> Result<(), String> {
        if self.owner.is_some() {
            return self.status.result();
        }
        DurableArtifactStore::from_rollout_writer(rollout, workspace)
            .map_err(|error| error.to_string())?;
        self.status.accepting.store(true, Ordering::Release);
        self.owner = Some(ArchiveOwner {
            sender: ArchiveSender {
                accepting: Arc::new(AtomicBool::new(true)),
                queue: Arc::new(Mutex::new(Vec::with_capacity(MAX_PENDING_REQUESTS))),
                status: self.status.clone(),
            },
        });
        Ok(())
    }
    pub(in crate::runtime) fn disable(&mut self) -> Result<(), String> {
        drop(self.owner.take());
        self.status.result()
    }
    pub(in crate::runtime) fn flush(&self) -> Result<(), String> {
        match &self.owner {
            Some(owner) => owner.drain(),
            None => self.status.result(),
        }
    }
    pub(in crate::runtime) fn capture(
        &self,
        rollout: &iteron_record::Rollout,
        workspace: &std::path::Path,
    ) -> Option<ScopedArchive> {
        let owner = self.owner.as_ref()?;
        match DurableArtifactStore::from_rollout_writer(rollout, workspace) {
            Ok(store) => Some(ScopedArchive {
                sender: owner.sender.clone(),
                store,
            }),
            Err(error) => {
                self.status.artifact_failure(error);
                None
            }
        }
    }
    #[allow(
        dead_code,
        reason = "backs the synchronous inspection port; the resident host uses reader"
    )]
    pub(in crate::runtime) fn status(&self) -> Value {
        self.status.view()
    }
    pub(in crate::runtime) fn reader(&self) -> Arc<dyn Fn() -> Value + Send + Sync> {
        let status = self.status.clone();
        Arc::new(move || status.view())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded_sender() -> ArchiveSender {
        let status = Arc::new(Status::default());
        status.accepting.store(true, Ordering::Release);
        ArchiveSender {
            accepting: Arc::new(AtomicBool::new(true)),
            queue: Arc::new(Mutex::new(Vec::new())),
            status,
        }
    }

    #[test]
    fn diagnostic_reservations_bound_prepared_queued_and_active_memory() {
        let sender = bounded_sender();
        let reservations: Vec<_> = (0..MAX_PENDING_REQUESTS)
            .map(|_| sender.reserve(Some(1)).unwrap())
            .collect();
        assert!(sender.reserve(Some(1)).is_none());
        assert_eq!(
            sender.status.pending.load(Ordering::Acquire),
            MAX_PENDING_REQUESTS
        );
        assert_eq!(sender.status.error_code(), "capacity");
        drop(reservations);
        assert_eq!(sender.status.pending.load(Ordering::Acquire), 0);
        assert_eq!(sender.status.bytes.load(Ordering::Acquire), 0);
        let whole_budget = sender.reserve(Some(MAX_PENDING_BYTES)).unwrap();
        assert!(sender.reserve(Some(1)).is_none());
        assert_eq!(sender.status.pending.load(Ordering::Acquire), 1);
        drop(whole_budget);
        assert_eq!(sender.status.bytes.load(Ordering::Acquire), 0);
        assert!(sender.reserve(None).is_none());
        assert_eq!(sender.status.pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn default_archive_reader_is_live_and_honest_about_unavailable_diagnostics() {
        let archive = RequestArchive::default();
        let reader = archive.reader();
        assert_eq!(reader()["enabled"], false);
        assert_eq!(reader()["availability"], "not_captured");
        archive.status.accepting.store(true, Ordering::Release);
        assert_eq!(reader()["enabled"], true);
        archive.status.fail(Failure::Capacity);
        assert_eq!(reader()["availability"], "incomplete");
        archive.status.accepting.store(false, Ordering::Release);
        assert_eq!(reader()["enabled"], false);
        assert!(archive.flush().is_err());
    }

    #[test]
    fn disable_then_reenable_never_reactivates_an_old_sender() {
        let root = std::env::temp_dir().join(format!(
            "iteron-archive-generation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let rollout = iteron_record::Rollout::open(
            &root.join("runs"),
            &iteron_protocol::RunId("generation".into()),
            iteron_protocol::TenantId::default(),
        )
        .unwrap();
        let mut archive = RequestArchive::default();
        let reader = archive.reader();
        archive.enable(&rollout, &root).unwrap();
        let old = archive.owner.as_ref().unwrap().sender.clone();
        archive.disable().unwrap();
        archive.enable(&rollout, &root).unwrap();
        let current = &archive.owner.as_ref().unwrap().sender;
        assert_eq!(reader()["enabled"], true);
        assert!(!Arc::ptr_eq(&old.accepting, &current.accepting));
        assert!(old.reserve(Some(1)).is_none());
        old.enqueue(|| panic!("closed owner must not enqueue into its abandoned queue"));
        assert!(old.queue.lock().unwrap().is_empty());
        assert!(current.queue.lock().unwrap().is_empty());
        assert!(current.reserve(Some(1)).is_some());
        assert_eq!(reader()["pending_requests"], 0);
        assert_eq!(reader()["submitted_requests"], 0);
        assert_eq!(reader()["first_error_code"], "capture_closed");
        drop(archive);
        drop(rollout);
        std::fs::remove_dir_all(root).unwrap();
    }
}

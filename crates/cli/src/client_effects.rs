//! Shared native client effects. Frontends render data and consume receipts; this owner retains
//! physical process/content authority independently of the observer's lifetime.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod capability_fs;
mod export;
mod payload;
mod process;
pub(crate) mod shell;
pub(crate) mod worker;

pub(crate) use export::{CollisionPolicy, MAX_TRANSCRIPT_EXPORT_BYTES};
pub(crate) use process::{ProcessRegistry, ReapOutcome, RegisteredChild};
pub(crate) use worker::{WorkerFailure, WorkerRun, worker_main, worker_requested};

use crate::runtime::Agent;
use iteron_protocol::{RunId, TenantId};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedRwLockReadGuard, OwnedSemaphorePermit};

/// No Deserialize/path-taking public constructor: source identity comes from the real writer.
#[derive(Clone)]
pub(crate) struct NativeExportScope {
    runs_dir: PathBuf,
    tenant: TenantId,
    run: RunId,
    workspace: PathBuf,
    #[cfg(test)]
    stage_pause: Option<
        Arc<
            Mutex<(
                std::sync::mpsc::SyncSender<()>,
                std::sync::mpsc::Receiver<()>,
            )>,
        >,
    >,
}
impl NativeExportScope {
    pub(crate) fn capture(agent: &Agent) -> Option<Self> {
        Some(Self {
            runs_dir: agent.rollout.path().parent()?.to_owned(),
            tenant: agent.rollout.tenant().clone(),
            run: agent.rollout.run_id().clone(),
            workspace: agent.workspace.clone(),
            #[cfg(test)]
            stage_pause: None,
        })
    }
    pub(crate) fn run(&self) -> &RunId {
        &self.run
    }
    pub(crate) fn workspace(&self) -> &std::path::Path {
        &self.workspace
    }
    #[cfg(test)]
    pub(crate) fn from_verified_fixture(path: &std::path::Path) -> Self {
        let (tenant, run) = iteron_record::verified_rollout_identity(path).unwrap();
        Self {
            runs_dir: path.parent().unwrap().to_owned(),
            tenant,
            run,
            workspace: path.parent().unwrap().to_owned(),
            stage_pause: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn pause_stage(
        &mut self,
        started: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        self.stage_pause = Some(Arc::new(Mutex::new((started, resume))));
    }
}

/// One actual effect admission, retained through physical CAS work, helper settlement and cleanup.
pub(crate) struct ExportLease {
    _slot: OwnedSemaphorePermit,
    _scope: OwnedRwLockReadGuard<()>,
}
impl ExportLease {
    pub(crate) fn new(slot: OwnedSemaphorePermit, scope: OwnedRwLockReadGuard<()>) -> Self {
        Self {
            _slot: slot,
            _scope: scope,
        }
    }
}

/// Unknown publication retains the single operation lease. Adoption and later export remain
/// refused; neither numeric process IDs nor a canceled observer authorize automatic retry.
#[derive(Default)]
pub(crate) struct ExportQuarantine(Mutex<Option<ExportLease>>);
impl ExportQuarantine {
    pub(crate) fn is_quarantined(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
    pub(crate) fn retain(&self, lease: ExportLease) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lease);
    }
}

/// File publication and private-content cleanup are separate facts. A known published file
/// remains visible even if cleanup is unavailable; the original admission stays quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContentCleanup {
    NotStaged,
    Released,
    Unobserved,
}
#[derive(Debug)]
pub(crate) struct ExportReceipt {
    pub(crate) publication: WorkerRun,
    pub(crate) private_content_cleanup: ContentCleanup,
}
impl ExportReceipt {
    pub(crate) fn before_dispatch(publication: WorkerRun) -> Self {
        Self {
            publication,
            private_content_cleanup: ContentCleanup::NotStaged,
        }
    }
    pub(crate) fn unobserved(publication: WorkerRun) -> Self {
        Self {
            publication,
            private_content_cleanup: ContentCleanup::Unobserved,
        }
    }
}
/// Fail-closed custody also covers a native worker panic: dropping an unconfirmed custody
/// retains admission rather than letting another effect race unresolved publication/cleanup.
struct LeaseCustody {
    lease: Option<ExportLease>,
    quarantine: Arc<ExportQuarantine>,
}
impl LeaseCustody {
    fn confirmed(mut self) {
        drop(self.lease.take());
    }
}
impl Drop for LeaseCustody {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.quarantine.retain(lease);
        }
    }
}

pub(crate) async fn export_transcript(
    source: NativeExportScope,
    body: Vec<u8>,
    requested: String,
    collision: CollisionPolicy,
    mut cancelled: tokio::sync::watch::Receiver<bool>,
    lease: ExportLease,
    quarantine: Arc<ExportQuarantine>,
) -> ExportReceipt {
    if body.len() > MAX_TRANSCRIPT_EXPORT_BYTES
        || body.capacity() > MAX_TRANSCRIPT_EXPORT_BYTES
        || requested.len() > 4096
        || requested.capacity() > 8192
    {
        return ExportReceipt::before_dispatch(known(
            "transcript export exceeds its finite input bound",
        ));
    }
    if *cancelled.borrow() || cancelled.has_changed().is_err() {
        return ExportReceipt::before_dispatch(WorkerRun::Cancelled);
    }
    let custody = LeaseCustody {
        lease: Some(lease),
        quarantine,
    };
    let staged = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some(pause) = &source.stage_pause {
            let pause = pause.lock().unwrap();
            let _ = pause.0.send(());
            if pause
                .1
                .recv_timeout(std::time::Duration::from_secs(3))
                .is_err()
            {
                custody.confirmed();
                return Err(ExportReceipt::before_dispatch(known(
                    "fixture storage worker was not released",
                )));
            }
        }
        let payload = match payload::ManagedExportPayload::stage(&source, &body) {
            Ok(payload) => payload,
            Err(failure) => {
                if failure.cleanup == ContentCleanup::NotStaged {
                    custody.confirmed();
                }
                return Err(ExportReceipt {
                    publication: known(failure.reason),
                    private_content_cleanup: failure.cleanup,
                });
            }
        };
        let bytes = match payload.read() {
            Ok(bytes) => bytes,
            Err(reason) => {
                let cleanup = payload.finish();
                if cleanup == ContentCleanup::Released {
                    custody.confirmed();
                }
                return Err(ExportReceipt {
                    publication: known(reason),
                    private_content_cleanup: cleanup,
                });
            }
        };
        Ok((source.workspace, payload, bytes, custody))
    })
    .await;
    let (workspace, payload, bytes, custody) = match staged {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(receipt)) => return receipt,
        Err(_) => {
            return ExportReceipt::unobserved(known(
                "transcript export storage worker ended before file dispatch",
            ));
        }
    };
    // The service owns this registry; a presentation observer cannot mint or swap child handles.
    let processes = ProcessRegistry::default();
    let publication = if *cancelled.borrow() || cancelled.has_changed().is_err() {
        WorkerRun::Cancelled
    } else {
        worker::run_export_worker(
            &workspace,
            &requested,
            collision,
            &bytes,
            &mut cancelled,
            &processes,
        )
        .await
    };
    let uncertain = matches!(
        &publication,
        WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown { .. }))
    );
    // No async input loop destructor performs native cleanup. Detached host work retains custody
    // until actual process settlement and the private graph release have both been observed.
    let cleanup = tokio::task::spawn_blocking(move || {
        let process_cleanup = processes.close_and_reap();
        let content_cleanup = payload.finish();
        if !uncertain && process_cleanup.unknown == 0 && content_cleanup == ContentCleanup::Released
        {
            custody.confirmed();
        }
        content_cleanup
    })
    .await
    .unwrap_or(ContentCleanup::Unobserved);
    ExportReceipt {
        publication,
        private_content_cleanup: cleanup,
    }
}
fn known(reason: &str) -> WorkerRun {
    WorkerRun::Completed(Err(WorkerFailure::KnownFailure(reason.into())))
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn export_fixture(
    workspace: &std::path::Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
) -> Result<PathBuf, String> {
    export::export_bytes(workspace, requested, bytes, collision).map_err(|error| error.to_string())
}

//! Host-bound transcript effects. The same read lease used by ordinary owner controls prevents
//! adoption throughout admitted physical work; a final snapshot check cannot undo a stale write.
use super::{activity_control::ActivitySurface, product_contract::ContractReader};
use crate::client_effects::{
    self, CollisionPolicy, ExportLease, ExportQuarantine, ExportReceipt, NativeExportScope,
    WorkerFailure, WorkerRun,
};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{Arc, OnceLock};
use tokio::sync::{RwLock, Semaphore};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TranscriptExportV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) text: String,
    pub(crate) requested: String,
    pub(crate) collision: CollisionPolicy,
}
impl TranscriptExportV1 {
    fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 200
            || self.run_id.0.is_empty()
            || self.run_id.0.len() > 200
            || self.text.len() > client_effects::MAX_TRANSCRIPT_EXPORT_BYTES
            || self.text.capacity() > client_effects::MAX_TRANSCRIPT_EXPORT_BYTES
            || self.requested.is_empty()
            || self.requested.len() > 4096
            || self.requested.chars().any(char::is_control)
            || self.requested.as_str().contains('\\')
            || self.requested.as_str().contains(':')
            || self.requested.split('/').count() > 128
            || self
                .requested
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || std::path::Path::new(&self.requested).is_absolute()
        {
            return Err("transcript export request exceeds its scope/text/relative-path bound");
        }
        Ok(())
    }
}

pub(super) fn dispatch(
    reader: ContractReader,
    command: TranscriptExportV1,
    reply: tokio::sync::oneshot::Sender<super::ControlReply>,
) {
    if let Err(reason) = command.validate() {
        let _ = reply.send(super::ControlReply::Refused(reason.into()));
        return;
    }
    let Some(binding) = reader
        .export_binding()
        .filter(|binding| binding.thread == command.thread_id && binding.run == command.run_id)
    else {
        let _ = reply.send(super::ControlReply::Refused(
            "transcript export scope mismatch".into(),
        ));
        return;
    };
    let lease = match binding.admit(&reader) {
        Ok(lease) => lease,
        Err(reason) => {
            let _ = reply.send(super::ControlReply::Refused(reason.into()));
            return;
        }
    };
    let workspace = binding.source.workspace().to_owned();
    tokio::spawn(async move {
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        let outcome = binding
            .execute_admitted(
                command.text.into_bytes(),
                command.requested,
                command.collision,
                cancelled,
                lease,
            )
            .await;
        drop(cancel);
        let mut data = match outcome.publication {
            WorkerRun::Completed(Ok(path)) => {
                serde_json::json!({"status":"published","path":path.strip_prefix(&workspace).ok().and_then(std::path::Path::to_str)})
            }
            WorkerRun::Completed(Err(WorkerFailure::KnownFailure(reason))) => {
                serde_json::json!({"status":"not_published","reason":reason})
            }
            WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
                stage,
                detail,
                cleanup,
            })) => {
                serde_json::json!({"status":"publication_unknown","stage":stage.to_string(),"reason":detail,"cleanup":cleanup.to_string()})
            }
            WorkerRun::Cancelled => {
                serde_json::json!({"status":"not_published","reason":"cancelled before file dispatch"})
            }
        };
        data["private_content_cleanup"] = serde_json::json!(outcome.private_content_cleanup);
        let _=reply.send(super::ControlReply::TranscriptExport(serde_json::json!({"type":"transcript_export_v1","thread_id":command.thread_id,"run_id":command.run_id,"receipt":data})));
    });
}

pub(super) struct ExportService {
    gate: Arc<RwLock<()>>,
    capacity: OnceLock<Arc<Semaphore>>,
    quarantine: Arc<ExportQuarantine>,
}
#[derive(Clone)]
pub(super) struct ExportBinding {
    thread: SessionId,
    run: RunId,
    source: NativeExportScope,
    service: Arc<ExportService>,
}
pub(crate) struct TranscriptExportPort {
    binding: ExportBinding,
    reader: ContractReader,
}
impl TranscriptExportPort {
    pub(super) fn capture(
        binding: ExportBinding,
        reader: ContractReader,
        run: &RunId,
    ) -> Option<Self> {
        (binding.run == *run).then_some(Self { binding, reader })
    }
    pub(crate) async fn export_transcript(
        self,
        body: Vec<u8>,
        requested: String,
        collision: CollisionPolicy,
        cancelled: tokio::sync::watch::Receiver<bool>,
    ) -> ExportReceipt {
        self.binding
            .execute(self.reader, body, requested, collision, cancelled)
            .await
    }
}
impl ExportBinding {
    pub(super) fn matches_scope(&self, thread: &SessionId, run: &RunId) -> bool {
        &self.thread == thread && &self.run == run
    }
    pub(super) fn capture(
        agent: &Agent,
        reader: &ContractReader,
        activity: &ActivitySurface,
    ) -> Option<Self> {
        let snapshot = reader.snapshot()?;
        let source = NativeExportScope::capture(agent)?;
        if source.run() != &snapshot.run_id {
            return None;
        }
        Some(Self {
            thread: snapshot.thread_id,
            run: snapshot.run_id,
            source,
            service: Arc::new(ExportService {
                gate: activity.client_effect_gate(),
                capacity: OnceLock::new(),
                quarantine: Arc::new(ExportQuarantine::default()),
            }),
        })
    }
    pub(super) fn refreshed(&self, agent: &Agent, thread: SessionId) -> Option<Self> {
        let source = NativeExportScope::capture(agent)?;
        Some(Self {
            thread,
            run: source.run().clone(),
            source,
            service: self.service.clone(),
        })
    }
    fn admit(&self, reader: &ContractReader) -> Result<ExportLease, &'static str> {
        if self.service.quarantine.is_quarantined() {
            return Err("prior export publication is unknown; automatic retry is refused");
        }
        let scope = self
            .service
            .gate
            .clone()
            .try_read_owned()
            .map_err(|_| "session adoption is pending")?;
        if reader
            .snapshot()
            .is_none_or(|current| current.thread_id != self.thread || current.run_id != self.run)
        {
            return Err("transcript export scope changed before admission");
        }
        let capacity = self
            .service
            .capacity
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        let slot = capacity
            .try_acquire_owned()
            .map_err(|_| "a physical transcript export is already admitted")?;
        Ok(ExportLease::new(slot, scope))
    }
    pub(super) async fn execute(
        self,
        reader: ContractReader,
        body: Vec<u8>,
        requested: String,
        collision: CollisionPolicy,
        cancelled: tokio::sync::watch::Receiver<bool>,
    ) -> ExportReceipt {
        let lease = match self.admit(&reader) {
            Ok(lease) => lease,
            Err(reason) => return known(reason),
        };
        self.execute_admitted(body, requested, collision, cancelled, lease)
            .await
    }
    async fn execute_admitted(
        self,
        body: Vec<u8>,
        requested: String,
        collision: CollisionPolicy,
        cancelled: tokio::sync::watch::Receiver<bool>,
        lease: ExportLease,
    ) -> ExportReceipt {
        let quarantine = self.service.quarantine.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = client_effects::export_transcript(
                self.source,
                body,
                requested,
                collision,
                cancelled,
                lease,
                quarantine,
            )
            .await;
            let _ = send.send(result);
        });
        match tokio::time::timeout(std::time::Duration::from_secs(10), receive).await {
            Ok(Ok(receipt)) => receipt,
            _ => ExportReceipt::unobserved(WorkerRun::Completed(Err(
                WorkerFailure::OutcomeUnknown {
                    stage: client_effects::worker::PostDispatchStage::MissingResponse,
                    detail:
                        "host export receipt is unobserved; physical work retains its admission"
                            .into(),
                    cleanup: client_effects::worker::Cleanup::OutcomeUnknown,
                },
            ))),
        }
    }
}
fn known(reason: &str) -> ExportReceipt {
    ExportReceipt::before_dispatch(WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
        reason.into(),
    ))))
}

#[cfg(test)]
mod tests;

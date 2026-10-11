//! Readonly retained commit snapshots for the currently bound picker row. The native worker
//! retains its one process-wide slot after an observer closes; these are not a workspace scan.
use crate::app_server::AppServerClient;
use iteron_protocol::{
    Capability, RunId, SessionId,
    client_artifact::{CLIENT_ARTIFACT_VERSION, ClientArtifactCommandV1},
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

static READ_CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Summary {
    complete_diffs: usize,
    evicted_objects: u64,
}
impl Summary {
    pub(super) fn capture(
        value: &Value,
        thread: &SessionId,
        run: &RunId,
    ) -> Result<Self, &'static str> {
        if value["type"] != "artifacts_v1"
            || value["contract_version"] != CLIENT_ARTIFACT_VERSION
            || value["thread_id"] != thread.0
            || value["run_id"] != run.0
            || value["retained_catalog_available"] != true
        {
            return Err("retained change owner unavailable or scope changed");
        }
        let entries = value["artifacts"]
            .as_array()
            .filter(|entries| entries.len() <= 512)
            .ok_or("retained change listing exceeds its bound")?;
        let resident = value["resident_artifact_ids"]
            .as_array()
            .filter(|ids| ids.len() <= 512)
            .ok_or("retained change provenance unavailable")?;
        for id in resident {
            if !id.as_str().is_some_and(valid_id) {
                return Err("retained change provenance invalid");
            }
        }
        let mut complete_diffs = 0;
        let mut seen = BTreeSet::new();
        for entry in entries {
            let descriptor = super::artifact_view::bounded_descriptor(entry)?;
            if !valid_id(&descriptor.artifact_id)
                || !seen.insert(
                    entry["artifact_id"]
                        .as_str()
                        .ok_or("retained identity invalid")?,
                )
            {
                return Err("retained change identity invalid");
            }
            if descriptor.schema == "iteron.file-diff.v1"
                && descriptor.complete
                && descriptor.mime_type == "application/json"
                && descriptor.required_capability == Capability::ReadOnly
                && !resident
                    .iter()
                    .any(|id| id.as_str() == Some(descriptor.artifact_id.as_str()))
            {
                complete_diffs += 1;
            }
        }
        Ok(Self {
            complete_diffs,
            evicted_objects: value["evicted_artifacts"]
                .as_u64()
                .ok_or("retained change eviction count unavailable")?,
        })
    }
    pub(super) fn label(self) -> String {
        format!(
            "retained diff snapshots {} · evicted objects {} · current workspace not scanned",
            self.complete_diffs, self.evicted_objects
        )
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn start_read(
    client: AppServerClient,
    thread: SessionId,
    run: RunId,
    permit: OwnedSemaphorePermit,
    #[cfg(test)] pause: Option<Pause>,
) -> JoinHandle<Result<Summary, &'static str>> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        if let Some(pause) = pause {
            let _ = pause.started.send(());
            let _ = pause.resume.recv();
        }
        let current = || {
            client
                .thread_snapshot_v1()
                .is_some_and(|scope| scope.thread_id == thread && scope.run_id == run)
        };
        if !current() {
            return Err("retained change scope changed");
        }
        let listing = client.artifacts_v1(ClientArtifactCommandV1::List {
            thread_id: thread.clone(),
        });
        if !current() {
            return Err("retained change scope changed");
        }
        Summary::capture(&listing, &thread, &run)
    })
}
pub(super) async fn observe(
    client: AppServerClient,
    thread: SessionId,
    run: RunId,
) -> Result<Summary, &'static str> {
    let capacity = READ_CAPACITY
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone();
    let permit = capacity
        .try_acquire_owned()
        .map_err(|_| "retained change reader busy")?;
    let read = start_read(
        client,
        thread,
        run,
        permit,
        #[cfg(test)]
        None,
    );
    tokio::time::timeout(Duration::from_secs(2), read)
        .await
        .map_err(|_| "retained change observation timed out; native read may still be running")?
        .map_err(|_| "retained change worker unavailable")?
}

#[cfg(test)]
struct Pause {
    started: tokio::sync::oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
mod tests;

//! Presentation history reads use the same scoped host commands as ordinary external clients.
use crate::app_server::{AppServerClient, Control, ControlReply, ControlRequest};
use iteron_protocol::{RunId, SessionId, thread_lifecycle::ThreadLifecycleCommandV1};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
#[derive(Clone)]
pub(super) struct HistoryClient {
    client: AppServerClient,
    control: mpsc::Sender<ControlRequest>,
    thread: SessionId,
    run: RunId,
}
impl HistoryClient {
    pub(super) fn capture(
        client: AppServerClient,
        control: mpsc::Sender<ControlRequest>,
    ) -> Option<Self> {
        let scope = client.thread_snapshot_v1()?;
        Some(Self {
            client,
            control,
            thread: scope.thread_id,
            run: scope.run_id,
        })
    }
    pub(super) fn is_current(&self) -> bool {
        self.client
            .thread_snapshot_v1()
            .is_some_and(|scope| scope.thread_id == self.thread && scope.run_id == self.run)
    }
    pub(super) async fn request(&self, command: ThreadLifecycleCommandV1) -> Result<Value, String> {
        if !self.is_current() {
            return Err("history observation belongs to a previous selected run".into());
        }
        command.validate().map_err(str::to_owned)?;
        let (reply, received) = oneshot::channel();
        let response = tokio::time::timeout(Duration::from_secs(15), async {
            self.control
                .send(ControlRequest {
                    control: Control::ThreadLifecycle(command),
                    reply,
                })
                .await
                .map_err(|_| "history host is unavailable")?;
            received
                .await
                .map_err(|_| "history host ended without a receipt")
        })
        .await
        .map_err(|_| {
            "history host observation timed out; physical work may still be running".to_owned()
        })?
        .map_err(str::to_owned)?;
        if !self.is_current() {
            return Err("selected run changed during history observation".into());
        }
        match response {
            ControlReply::ThreadLifecycle(value) => Ok(value),
            ControlReply::Refused(reason) => Err(reason),
            _ => Err("unexpected history host reply".into()),
        }
    }
    pub(super) async fn title(&self) -> String {
        self.request(ThreadLifecycleCommandV1::Read {
            run_id: self.run.clone(),
        })
        .await
        .ok()
        .and_then(|value| value["title"].as_str().map(str::to_owned))
        .filter(|title| !title.trim().is_empty())
        .unwrap_or_else(|| "New session".into())
    }
    pub(super) async fn repair_index(&self) -> Result<Value, String> {
        self.request(ThreadLifecycleCommandV1::Reindex {
            thread_id: self.thread.clone(),
            run_id: self.run.clone(),
        })
        .await
    }
}

#[cfg(test)]
mod tests;

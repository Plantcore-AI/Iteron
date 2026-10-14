//! Private navigation observation state. Native providers, history and writer leases stay in host.
use super::{SessionPreview, session_inspection};
use crate::app_server::{Control, ControlReply, ControlRequest, NavigatedSession};
use iteron_protocol::{
    RunId, SessionId, product_contract::ThreadSnapshotV1, session_navigation::SessionNavigationV1,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(Clone, PartialEq, Eq)]
struct NavigationScope {
    thread: SessionId,
    run: RunId,
}
impl NavigationScope {
    fn from_view(view: &ThreadSnapshotV1) -> Self {
        Self {
            thread: view.thread_id.clone(),
            run: view.run_id.clone(),
        }
    }
    fn matches(&self, view: &ThreadSnapshotV1) -> bool {
        self.thread == view.thread_id && self.run == view.run_id
    }
}
struct PreviewResult {
    generation: u64,
    result: Result<SessionPreview, String>,
}
pub(super) enum AdoptionUpdate {
    Ready(Box<NavigatedSession>),
    Failed(String),
    Cancelled,
}
#[derive(Default)]
pub(super) struct SessionNavigationOwner {
    preview: Option<JoinHandle<PreviewResult>>,
    preview_scope: Option<NavigationScope>,
    preview_generation: u64,
    adoption: Option<JoinHandle<Result<ControlReply, String>>>,
    adoption_scope: Option<NavigationScope>,
    cancel: Option<Arc<AtomicBool>>,
}
impl SessionNavigationOwner {
    pub(super) fn has_work(&self) -> bool {
        self.preview.is_some() || self.adoption.is_some()
    }
    pub(super) fn adoption_busy(&self) -> bool {
        self.adoption.is_some()
    }
    pub(super) fn cancel_adoption(&mut self) {
        // This cancels before host adoption if still possible. Keep receiving the authoritative
        // reply: cancellation cannot hide an adoption already committed by the host.
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Release);
        }
    }
    pub(super) fn cancel_preview(&mut self) {
        self.preview_generation = self.preview_generation.wrapping_add(1);
        self.preview_scope = None;
        if let Some(previous) = self.preview.take() {
            previous.abort();
        }
    }
    pub(super) fn invalidate(&mut self) {
        self.cancel_preview();
        self.cancel_adoption();
    }
    pub(super) fn queue_adoption(
        &mut self,
        scope: &ThreadSnapshotV1,
        sender: mpsc::Sender<ControlRequest>,
        command: SessionNavigationV1,
    ) -> bool {
        if self.adoption_busy()
            || command.thread_id() != &scope.thread_id
            || command.run_id() != &scope.run_id
            || command.validate().is_err()
        {
            return false;
        }
        self.cancel_preview();
        self.adoption_scope = Some(NavigationScope::from_view(scope));
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.adoption = Some(tokio::spawn(async move {
            let (reply, received) = oneshot::channel();
            sender
                .send(ControlRequest {
                    control: Control::SessionNavigate {
                        command,
                        cancel: Some(cancel),
                    },
                    reply,
                })
                .await
                .map_err(|_| "session host stopped before navigation admission".to_owned())?;
            received.await.map_err(|_|"session host ended without a navigation result; inspect the actual run before retrying".to_owned())
        }));
        true
    }
    pub(super) fn queue_preview(
        &mut self,
        scope: &ThreadSnapshotV1,
        sender: mpsc::Sender<ControlRequest>,
        run: String,
    ) {
        self.cancel_preview();
        self.preview_scope = Some(NavigationScope::from_view(scope));
        let generation = self.preview_generation;
        self.preview = Some(tokio::spawn(async move {
            PreviewResult {
                generation,
                result: session_inspection::request(sender, run).await,
            }
        }));
    }
    pub(super) async fn poll_preview(
        &mut self,
        current: Option<&ThreadSnapshotV1>,
    ) -> Option<Result<SessionPreview, String>> {
        if !self.preview.as_ref().is_some_and(|job| job.is_finished()) {
            return None;
        }
        let result = self
            .preview
            .take()
            .expect("finished preview was present")
            .await;
        let matches = current.is_some_and(|view| {
            self.preview_scope
                .as_ref()
                .is_some_and(|scope| scope.matches(view))
        });
        self.preview_scope = None;
        if !matches {
            return None;
        }
        match result {
            Ok(preview) if preview.generation == self.preview_generation => Some(preview.result),
            Ok(_) => None,
            Err(error) => Some(Err(format!("session preview worker failed: {error}"))),
        }
    }
    pub(super) async fn poll_adoption(
        &mut self,
        current: Option<&ThreadSnapshotV1>,
    ) -> Option<AdoptionUpdate> {
        if !self.adoption.as_ref().is_some_and(|job| job.is_finished()) {
            return None;
        }
        let result = self
            .adoption
            .take()
            .expect("finished navigation was present")
            .await;
        Some(self.complete_adoption(current, result))
    }
    fn complete_adoption(
        &mut self,
        current: Option<&ThreadSnapshotV1>,
        result: Result<Result<ControlReply, String>, tokio::task::JoinError>,
    ) -> AdoptionUpdate {
        let origin = self.adoption_scope.take();
        let cancelled = self
            .cancel
            .take()
            .is_some_and(|signal| signal.load(Ordering::Acquire));
        match result {
            Ok(Ok(ControlReply::SessionNavigated(reply))) => {
                let fact = &reply.presentation;
                let origin_matches = origin.as_ref().is_some_and(|origin| {
                    origin.thread == fact.thread_id && origin.run == fact.origin_run_id
                });
                let actual_matches = current.is_some_and(|scope| {
                    scope.thread_id == fact.thread_id && scope.run_id == fact.run_id
                });
                if origin_matches
                    && actual_matches
                    && fact.version == 1
                    && fact.run_id.0 == reply.adopted.run_id
                {
                    AdoptionUpdate::Ready(reply)
                } else {
                    AdoptionUpdate::Failed("session navigation reply is stale; the current host selection remains authoritative".into())
                }
            }
            other => {
                if !current
                    .is_some_and(|view| origin.as_ref().is_some_and(|origin| origin.matches(view)))
                {
                    return AdoptionUpdate::Cancelled;
                }
                match other {
                    Ok(Ok(ControlReply::Refused(reason))) => AdoptionUpdate::Failed(reason),
                    Ok(Err(reason)) => AdoptionUpdate::Failed(reason),
                    Err(error) => AdoptionUpdate::Failed(format!(
                        "navigation observer failed: {error}; inspect the actual host selection before retrying"
                    )),
                    _ if cancelled => AdoptionUpdate::Cancelled,
                    _ => AdoptionUpdate::Failed(
                        "navigation ended without a usable host reply".into(),
                    ),
                }
            }
        }
    }
}
impl Drop for SessionNavigationOwner {
    fn drop(&mut self) {
        self.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::{AdoptionUpdate, NavigationScope, SessionNavigationOwner};
    use crate::app_server::{ControlReply, ControlRequest, attach, navigation_agent};
    use iteron_protocol::{
        RunId, SessionId, product_contract::ThreadSnapshotV1,
        session_navigation::SessionNavigationV1,
    };
    fn scope(run: &str) -> ThreadSnapshotV1 {
        ThreadSnapshotV1 {
            contract_version: 1,
            thread_id: SessionId("thread".into()),
            run_id: RunId(run.into()),
            source_event_seq: 0,
            turn: None,
            submissions: Vec::new(),
            evicted_submissions: 0,
        }
    }
    #[tokio::test]
    async fn cancel_keeps_request_observation_and_blocks_replacement_until_actual_reply() {
        let (sender, mut requests) = tokio::sync::mpsc::channel::<ControlRequest>(1);
        let origin = scope("origin");
        let mut owner = SessionNavigationOwner::default();
        let command = || SessionNavigationV1::New {
            thread_id: origin.thread_id.clone(),
            run_id: origin.run_id.clone(),
        };
        assert!(owner.queue_adoption(&origin, sender.clone(), command()));
        let request = requests.recv().await.unwrap();
        let crate::app_server::Control::SessionNavigate {
            cancel: Some(cancel),
            ..
        } = &request.control
        else {
            panic!("typed host command")
        };
        owner.cancel_adoption();
        assert!(cancel.load(std::sync::atomic::Ordering::Acquire));
        assert!(owner.adoption_busy());
        assert!(!owner.queue_adoption(&origin, sender.clone(), command()));
        request
            .reply
            .send(ControlReply::Refused(
                "cancelled before native creation".into(),
            ))
            .unwrap();
        let result = owner.adoption.take().unwrap().await;
        assert!(
            matches!(owner.complete_adoption(Some(&origin),result),AdoptionUpdate::Failed(reason) if reason.contains("before native creation"))
        );
        assert!(!owner.adoption_busy());
        owner.adoption_scope = Some(NavigationScope::from_view(&origin));
        assert!(matches!(
            owner.complete_adoption(
                Some(&scope("different")),
                Ok(Ok(ControlReply::Refused("old reply".into())))
            ),
            AdoptionUpdate::Cancelled
        ));
    }
    #[tokio::test]
    async fn late_cancel_cannot_hide_real_host_adoption_and_origin_reply_cannot_bind_a_third_run() {
        let root = std::env::temp_dir().join(format!(
            "iteron-nav-late-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let attached = attach(navigation_agent(&root), true, false).unwrap();
        let origin = attached.handle.client.thread_snapshot_v1().unwrap();
        let mut owner = SessionNavigationOwner::default();
        assert!(owner.queue_adoption(
            &origin,
            attached.handle.control.clone(),
            SessionNavigationV1::New {
                thread_id: origin.thread_id.clone(),
                run_id: origin.run_id.clone()
            }
        ));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            owner.adoption.take().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        owner.cancel_adoption();
        let current = attached.handle.client.thread_snapshot_v1().unwrap();
        assert_ne!(current.run_id, origin.run_id);
        assert!(
            matches!(
                owner.complete_adoption(Some(&current), Ok(result)),
                AdoptionUpdate::Ready(_)
            ),
            "confirmed host selection survives late UI cancellation"
        );
        drop(owner);
        drop(attached.handle);
        tokio::time::timeout(std::time::Duration::from_secs(10), attached.task)
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

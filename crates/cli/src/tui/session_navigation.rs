//! Private navigation work and observation lifetime, separate from the picker and compositor.
//! Cancellation retains physical preparation admission until the actual task ends.
mod preparation;
use super::{PreparedAdoption, PreparedAdoptionResult, SessionPreview, session_inspection};
use crate::app_server::ControlRequest;
use crate::providers::{ModelSelection, ProviderDirectory};
use iteron_protocol::{RunId, SessionId, product_contract::ThreadSnapshotV1};
use std::path::PathBuf;
use tokio::{sync::mpsc, task::JoinHandle};

pub(super) enum PreparationKind {
    Existing(String),
    Fresh,
}
pub(super) struct PreparationSource {
    pub(super) runs: PathBuf,
    pub(super) directory: ProviderDirectory,
    pub(super) selection: ModelSelection,
    pub(super) kind: PreparationKind,
}
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
    Ready(PreparedAdoption),
    Failed {
        message: String,
        handoff_run: Option<String>,
    },
    Cancelled,
}
#[derive(Default)]
pub(super) struct SessionNavigationOwner {
    preview: Option<JoinHandle<PreviewResult>>,
    preview_scope: Option<NavigationScope>,
    preview_generation: u64,
    adoption: Option<JoinHandle<PreparedAdoptionResult>>,
    adoption_scope: Option<NavigationScope>,
    adoption_cancelled: bool,
}
impl SessionNavigationOwner {
    pub(super) fn has_work(&self) -> bool {
        self.preview.is_some() || self.adoption.is_some()
    }
    pub(super) fn adoption_busy(&self) -> bool {
        self.adoption.is_some()
    }
    pub(super) fn cancel_adoption(&mut self) {
        // A blocking task can hold a physical writer lease even after its observer stops. Keep
        // its slot until completion, then drop the prepared receipt instead of dispatching it.
        self.adoption_cancelled = true;
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
        source: PreparationSource,
    ) -> bool {
        if self.adoption_busy() {
            return false;
        }
        self.cancel_preview();
        self.adoption_scope = Some(NavigationScope::from_view(scope));
        self.adoption_cancelled = false;
        self.adoption = Some(tokio::task::spawn_blocking(move || {
            preparation::prepare(source)
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
            .expect("finished adoption was present")
            .await;
        Some(self.complete_adoption(current, result))
    }
    fn complete_adoption(
        &mut self,
        current: Option<&ThreadSnapshotV1>,
        result: Result<PreparedAdoptionResult, tokio::task::JoinError>,
    ) -> AdoptionUpdate {
        let matches = current.is_some_and(|view| {
            self.adoption_scope
                .as_ref()
                .is_some_and(|scope| scope.matches(view))
        });
        self.adoption_scope = None;
        if self.adoption_cancelled || !matches {
            return AdoptionUpdate::Cancelled;
        }
        match result {
            Ok(PreparedAdoptionResult::Ready(prepared)) => AdoptionUpdate::Ready(prepared),
            Ok(PreparedAdoptionResult::Failed {
                message,
                handoff_run,
            }) => AdoptionUpdate::Failed {
                message,
                handoff_run,
            },
            Err(error) => AdoptionUpdate::Failed {
                message: format!("session adoption worker failed: {error}"),
                handoff_run: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdoptionUpdate, NavigationScope, PreparedAdoptionResult, SessionNavigationOwner};
    use iteron_protocol::{RunId, SessionId, product_contract::ThreadSnapshotV1};
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    async fn cancelled_navigation_keeps_actual_writer_lease_and_drops_observation_after_physical_finish()
     {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "iteron-navigation-slot-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let requested = RunId("requested".into());
        let mut lease =
            iteron_record::Rollout::open(&root, &requested, iteron_protocol::TenantId::default())
                .unwrap();
        lease
            .append(&iteron_protocol::Event {
                seq: iteron_protocol::Seq(0),
                turn: iteron_protocol::TurnId(0),
                kind: iteron_protocol::EventKind::RunStart {
                    cwd: root.to_string_lossy().into_owned(),
                    model: "fixture".into(),
                    effort: iteron_protocol::Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let mut owner = SessionNavigationOwner::default();
        let origin = scope("origin");
        owner.adoption_scope = Some(NavigationScope::from_view(&origin));
        owner.adoption = Some(tokio::task::spawn_blocking(move || {
            let _physical_lease = lease;
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            PreparedAdoptionResult::Failed {
                message: "actual physical preparation ended".into(),
                handoff_run: None,
            }
        }));
        owner.cancel_adoption();
        assert!(owner.adoption_busy());
        assert!(owner.poll_adoption(Some(&origin)).await.is_none());
        assert!(
            iteron_record::Rollout::open_existing(
                &root,
                &requested,
                iteron_protocol::TenantId::default()
            )
            .is_err()
        );
        release_tx.send(()).unwrap();
        let completed = owner.adoption.take().unwrap().await;
        assert!(matches!(
            owner.complete_adoption(Some(&origin), completed),
            AdoptionUpdate::Cancelled
        ));
        assert!(!owner.adoption_busy());
        let reopened = iteron_record::Rollout::open_existing(
            &root,
            &requested,
            iteron_protocol::TenantId::default(),
        )
        .unwrap();
        drop(reopened);
        owner.adoption_cancelled = false;
        owner.adoption_scope = Some(NavigationScope::from_view(&origin));
        assert!(matches!(
            owner.complete_adoption(
                Some(&scope("adopted")),
                Ok(PreparedAdoptionResult::Failed {
                    message: "old scope result".into(),
                    handoff_run: Some(requested.0),
                })
            ),
            AdoptionUpdate::Cancelled
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}

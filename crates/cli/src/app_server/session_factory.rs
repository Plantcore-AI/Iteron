//! Trusted native session factory. Provider constructors, verified replay and writer leases never
//! cross into presentation. Existing SQ slot permits exclude submissions through the journal swap.
mod workspace_rewind;
pub(super) use workspace_rewind::{CompletedRewind, PreparedRewind, RewindPreparation};
#[cfg(test)]
mod tests;
use crate::app_server::{AppServerClient, ModelSelection};
use crate::providers::{ModelSelection as RouteSelection, ProviderDirectory};
use iteron_protocol::{
    EventKind, RunId, SessionId, TenantId,
    session_navigation::{SessionNavigationV1, SessionTranscriptV1},
};
use iteron_record::{
    Rollout, ScopedEvent,
    bounded_replay::{ReplayReadLimits, load_forked_scoped_bounded},
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) struct SubmissionExclusion {
    data: Arc<Semaphore>,
    priority: Arc<Semaphore>,
    data_count: u32,
    priority_count: u32,
}
pub(super) struct SubmissionExclusionLease {
    _data: OwnedSemaphorePermit,
    _priority: OwnedSemaphorePermit,
}
impl SubmissionExclusion {
    /// Called only while the actual newly constructed queue has not yet been exposed to a client.
    pub(super) fn capture(data: Arc<Semaphore>, priority: Arc<Semaphore>) -> Option<Self> {
        let data_count = u32::try_from(data.available_permits()).ok()?;
        let priority_count = u32::try_from(priority.available_permits()).ok()?;
        if data_count == 0 || priority_count == 0 {
            return None;
        }
        Some(Self {
            data,
            priority,
            data_count,
            priority_count,
        })
    }
    pub(super) fn try_exclude(&self) -> Result<SubmissionExclusionLease, String> {
        let data = self
            .data
            .clone()
            .try_acquire_many_owned(self.data_count)
            .map_err(|_| "pending submissions prevent session navigation")?;
        let priority = self
            .priority
            .clone()
            .try_acquire_many_owned(self.priority_count)
            .map_err(|_| "pending priority commands prevent session navigation")?;
        Ok(SubmissionExclusionLease {
            _data: data,
            _priority: priority,
        })
    }
}
pub(super) struct SessionFactory {
    inventory: Arc<crate::client_inventory::ClientInventoryOwner>,
    runs: PathBuf,
    workspace: PathBuf,
    tenant: TenantId,
    exclusion: SubmissionExclusion,
}
pub(super) struct PreparationOrigin {
    pub(super) thread: SessionId,
    pub(super) run: RunId,
    pub(super) selection: RouteSelection,
    pub(super) checkpoint: iteron_record::TunablesCheckpoint,
}
enum NativeSessionStart {
    Fresh {
        created_at: u64,
        route: ModelSelection,
    },
    Existing,
}
pub(super) struct PreparedSession {
    origin: PreparationOrigin,
    rollout: Rollout,
    route: ModelSelection,
    fresh: bool,
    created_at: Option<u64>,
    projection: SessionTranscriptV1,
    substituted: Option<String>,
    admission: SubmissionExclusionLease,
}
pub(super) struct NavigationPresentation {
    pub(super) origin_thread: SessionId,
    pub(super) origin_run: RunId,
    pub(super) retained_run: RunId,
    pub(super) projection: SessionTranscriptV1,
    pub(super) substituted: Option<String>,
}
impl PreparedSession {
    pub(super) fn run_id(&self) -> &RunId {
        self.rollout.run_id()
    }
    pub(super) fn into_parts(
        self,
    ) -> (
        super::AdoptRun,
        NavigationPresentation,
        SubmissionExclusionLease,
    ) {
        let retained_run = self.rollout.run_id().clone();
        (
            super::AdoptRun {
                rollout: self.rollout,
                route: Box::new(self.route),
                fresh: self.fresh,
                created_at: self.created_at,
            },
            NavigationPresentation {
                origin_thread: self.origin.thread,
                origin_run: self.origin.run,
                retained_run,
                projection: self.projection,
                substituted: self.substituted,
            },
            self.admission,
        )
    }
}
impl SessionFactory {
    pub(super) fn capture(
        agent: &crate::runtime::Agent,
        client: &AppServerClient,
    ) -> Option<Arc<Self>> {
        let inventory = agent.client_inventory_owner()?;
        let runs = agent.rollout.path().parent()?.canonicalize().ok()?;
        let workspace = agent.workspace.canonicalize().ok()?;
        let exclusion = client.session_submission_exclusion()?;
        Some(Arc::new(Self {
            inventory,
            runs,
            workspace,
            tenant: agent.rollout.tenant().clone(),
            exclusion,
        }))
    }
    pub(super) async fn prepare(
        self: &Arc<Self>,
        origin: PreparationOrigin,
        command: SessionNavigationV1,
        cancel: Option<Arc<AtomicBool>>,
    ) -> Result<PreparedSession, String> {
        command.validate().map_err(str::to_owned)?;
        if command.thread_id() != &origin.thread || command.run_id() != &origin.run {
            return Err("session navigation belongs to a previous thread/run".into());
        }
        if matches!(&command, SessionNavigationV1::Resume {target_run_id,..} if target_run_id == &origin.run)
        {
            return Err("that session is already live".into());
        }
        let admission = self.exclusion.try_exclude()?;
        let directory = self.inventory.session_directory();
        let owner = self.clone();
        // This owned worker keeps both queue exclusions and every native lease even if its caller
        // disconnects. No timeout releases admission while physical work can still be running.
        tokio::task::spawn_blocking(move || {
            owner.prepare_native(origin, command, cancel, admission, directory)
        })
        .await
        .map_err(|_| "native session preparation worker failed".to_owned())?
    }
    fn prepare_native(
        &self,
        origin: PreparationOrigin,
        command: SessionNavigationV1,
        cancel: Option<Arc<AtomicBool>>,
        admission: SubmissionExclusionLease,
        directory: ProviderDirectory,
    ) -> Result<PreparedSession, String> {
        cancelled(cancel.as_deref())?;
        // Refuse a unavailable current route before the first new-record creation effect.
        let start = if matches!(&command, SessionNavigationV1::New { .. }) {
            NativeSessionStart::Fresh {
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "new session clock unavailable")?
                    .as_secs(),
                route: self.build_route(&directory, &origin.selection)?,
            }
        } else {
            NativeSessionStart::Existing
        };
        let (rollout, scoped) = match command {
            SessionNavigationV1::New { .. } => {
                let mut entropy = [0_u8; 16];
                getrandom::fill(&mut entropy).map_err(|_| "new session identity unavailable")?;
                let run = RunId(format!("run-{}", hex::encode(entropy)));
                let rollout = Rollout::open(&self.runs, &run, self.tenant.clone())
                    .map_err(|_| "new session writer unavailable")?;
                (rollout, Vec::new())
            }
            SessionNavigationV1::Resume { target_run_id, .. } => {
                // Lock before replay so route/source recovery cannot race an unrelated writer.
                let rollout =
                    Rollout::open_existing(&self.runs, &target_run_id, self.tenant.clone())
                        .map_err(|_| "session writer unavailable; another process may own it")?;
                let scoped = self.verified(&target_run_id)?;
                (rollout, scoped)
            }
            SessionNavigationV1::Fork { through_seq, .. } => {
                let parent = self.verified(&origin.run)?;
                let through_seq = through_seq
                    .or_else(|| {
                        parent
                            .iter()
                            .rev()
                            .find(|event| event.run_id == origin.run)
                            .map(|event| event.event.seq.0)
                    })
                    .filter(|seq| *seq > 0)
                    .ok_or("nothing to fork beyond genesis")?;
                if !parent
                    .iter()
                    .any(|event| event.run_id == origin.run && event.event.seq.0 == through_seq)
                {
                    return Err("fork sequence is absent from the current physical run".into());
                }
                cancelled(cancel.as_deref())?;
                let (run, _) = iteron_record::session::fork_with_checkpoint(
                    &self.runs,
                    &origin.run,
                    iteron_protocol::Seq(through_seq),
                    &self.tenant,
                    &origin.checkpoint,
                    iteron_record::LegacyTunablesPolicy::RejectUnpinned,
                )
                .map_err(|_| "verified session fork failed")?;
                let rollout = Rollout::open_existing(&self.runs, &run, self.tenant.clone())
                    .map_err(|_| {
                        format!("forked session writer unavailable; retained run {}", run.0)
                    })?;
                let scoped = self
                    .verified(&run)
                    .map_err(|reason| format!("{reason}; retained run {}", run.0))?;
                (rollout, scoped)
            }
        };
        // A new/forked journal can already exist here. Cancellation never claims its creation was
        // rolled back; the refusal includes the real retained identity for inspection or cleanup.
        if cancel
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::Acquire))
        {
            return Err(format!(
                "session navigation cancelled before adoption; retained run {}",
                rollout.run_id().0
            ));
        }
        self.finish_native(origin, rollout, start, scoped, admission, &directory)
    }
    fn finish_native(
        &self,
        origin: PreparationOrigin,
        rollout: Rollout,
        start: NativeSessionStart,
        scoped: Vec<ScopedEvent>,
        admission: SubmissionExclusionLease,
        directory: &ProviderDirectory,
    ) -> Result<PreparedSession, String> {
        let (fresh, created_at, admitted_route) = match start {
            NativeSessionStart::Fresh { created_at, route } => {
                (true, Some(created_at), Some(route))
            }
            NativeSessionStart::Existing => (false, None, None),
        };
        let recorded = recorded_route(&scoped);
        let (selection, substituted) = match recorded {
            Some((Some(provider_id), model_id)) => {
                let selection = RouteSelection {
                    provider_id,
                    model_id,
                };
                if directory.validate_selection(&selection, true).is_ok() {
                    (selection, None)
                } else {
                    (
                        origin.selection.clone(),
                        Some("recorded route is unavailable in the captured host directory".into()),
                    )
                }
            }
            Some((None, _)) => (
                origin.selection.clone(),
                Some("legacy record has no provider identity; using the current host route".into()),
            ),
            None => (
                origin.selection.clone(),
                if fresh {
                    None
                } else {
                    Some("record has no route; using the current host route".into())
                },
            ),
        };
        let route = match admitted_route {
            Some(route) => route,
            None => self
                .build_route(directory, &selection)
                .map_err(|reason| format!("{reason}; retained run {}", rollout.run_id().0))?,
        };
        let projection = crate::session_transcript::project(&scoped);
        Ok(PreparedSession {
            origin,
            rollout,
            route,
            fresh,
            created_at,
            projection,
            substituted,
            admission,
        })
    }
    fn build_route(
        &self,
        directory: &ProviderDirectory,
        selection: &RouteSelection,
    ) -> Result<ModelSelection, String> {
        crate::model_route::HostModelSelection::capture(directory, selection)
            .map_err(|_| "captured host route cannot construct a provider".to_owned())
    }
    fn verified(&self, run: &RunId) -> Result<Vec<ScopedEvent>, String> {
        let scoped = load_forked_scoped_bounded(
            &self.runs,
            run,
            ReplayReadLimits {
                physical_bytes: 64 * 1024 * 1024,
                hydrated_bytes: 64 * 1024 * 1024,
                events: 100_000,
            },
        )
        .map_err(|_| "bounded verified session history unavailable")?;
        if scoped.iter().any(|event| event.tenant != self.tenant) {
            return Err("session belongs to another tenant".into());
        }
        let workspace = scoped
            .iter()
            .find_map(|event| {
                if &event.run_id != run {
                    return None;
                }
                if let EventKind::RunStart { cwd, .. } = &event.event.kind {
                    Some(Path::new(cwd))
                } else {
                    None
                }
            })
            .and_then(|cwd| cwd.canonicalize().ok())
            .ok_or("session workspace provenance unavailable")?;
        if workspace != self.workspace {
            return Err("session belongs to another workspace".into());
        }
        Ok(scoped)
    }
}
fn cancelled(cancel: Option<&AtomicBool>) -> Result<(), String> {
    if cancel.is_some_and(|signal| signal.load(Ordering::Acquire)) {
        Err("session navigation cancelled before native preparation".into())
    } else {
        Ok(())
    }
}
fn recorded_route(events: &[ScopedEvent]) -> Option<(Option<String>, String)> {
    events
        .iter()
        .rev()
        .find_map(|event| match &event.event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => Some((Some(provider_id.clone()), model_id.clone())),
            _ => None,
        })
        .or_else(|| {
            events.iter().find_map(|event| match &event.event.kind {
                EventKind::RunStart { model, .. } if !model.is_empty() => {
                    Some((None, model.clone()))
                }
                _ => None,
            })
        })
}

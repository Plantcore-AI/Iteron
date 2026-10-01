//! Verified logical target selection, native preparation and real restore/rollback results.
//! Workers retain the actual submission exclusion through every physical stage and adoption.
use super::{
    NativeSessionStart, NavigationPresentation, PreparationOrigin, PreparedSession, SessionFactory,
    SubmissionExclusionLease, cancelled,
};
use crate::runtime::workspace_rewind::WorkspaceRewindPermit;
use iteron_protocol::{
    EventKind, Seq,
    workspace_rewind::{
        RewindExecutionV1, RewindFilesV1, RewindPointV1, RewindPreviewV1, RewindScopeV1,
        RewindTargetV1, RewindUnrecordedV1, WorkspaceRewindCommandV1, WorkspaceRewindReplyV1,
    },
};
use iteron_record::{Rollout, ScopedEvent, Snapshot};
use std::sync::{Arc, atomic::AtomicBool};

const MAX_POINTS: usize = 30;
const MAX_PATH_DISPLAY: usize = 120;
pub(in crate::app_server) enum RewindPreparation {
    Observed(WorkspaceRewindReplyV1),
    Apply(PreparedRewind),
}
pub(in crate::app_server) struct PreparedRewind {
    owner: Arc<SessionFactory>,
    reply: WorkspaceRewindReplyV1,
    snapshot: Option<Snapshot>,
    child: Option<PreparedSession>,
    admission: Option<SubmissionExclusionLease>,
    cancel: Option<Arc<AtomicBool>>,
}
pub(in crate::app_server) struct AuthorizedRewind {
    prepared: PreparedRewind,
    permit: WorkspaceRewindPermit,
}
pub(in crate::app_server) struct CompletedRewind {
    pub(in crate::app_server) prepared: PreparedRewind,
    pub(in crate::app_server) files: RewindFilesV1,
}
impl SessionFactory {
    pub(in crate::app_server) async fn prepare_rewind(
        self: &Arc<Self>,
        origin: PreparationOrigin,
        command: WorkspaceRewindCommandV1,
        cancel: Option<Arc<AtomicBool>>,
    ) -> Result<RewindPreparation, String> {
        command.validate().map_err(str::to_owned)?;
        if command.thread_id() != &origin.thread || command.run_id() != &origin.run {
            return Err("rewind belongs to a previous thread/run".into());
        }
        let admission = self.exclusion.try_exclude()?;
        let directory = self.inventory.session_directory();
        let owner = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(
                owner.prepare_rewind_native(origin, command, cancel, admission, directory),
            )
        })
        .await
        .map_err(|_| "native rewind preparation failed".to_owned())?
    }
    async fn prepare_rewind_native(
        self: &Arc<Self>,
        origin: PreparationOrigin,
        command: WorkspaceRewindCommandV1,
        cancel: Option<Arc<AtomicBool>>,
        admission: SubmissionExclusionLease,
        directory: crate::providers::ProviderDirectory,
    ) -> Result<RewindPreparation, String> {
        cancelled(cancel.as_deref())?;
        let scoped = self.verified(&origin.run)?;
        let mut reply = WorkspaceRewindReplyV1 {
            version: 1,
            thread_id: origin.thread.clone(),
            origin_run_id: origin.run.clone(),
            points: Vec::new(),
            omitted_points: 0,
            preview: None,
            execution: None,
        };
        let (target, scope, unrecorded, apply) = match command {
            WorkspaceRewindCommandV1::List { .. } => {
                let mut points = scoped.iter().rev().filter(|entry| {
                    matches!(
                        &entry.event.kind,
                        EventKind::Checkpoint { .. } | EventKind::TurnStart
                    )
                });
                reply.points = points
                    .by_ref()
                    .take(MAX_POINTS)
                    .map(|entry| RewindPointV1 {
                        target: RewindTargetV1 {
                            run_id: entry.run_id.clone(),
                            seq: entry.event.seq,
                        },
                        turn: entry.event.turn.0,
                        file_checkpoint: matches!(&entry.event.kind, EventKind::Checkpoint { .. }),
                    })
                    .collect();
                reply.omitted_points = points.count();
                return Ok(RewindPreparation::Observed(reply));
            }
            WorkspaceRewindCommandV1::Preview {
                target,
                scope,
                unrecorded,
                ..
            } => (target, scope, unrecorded, false),
            WorkspaceRewindCommandV1::Apply {
                target,
                scope,
                unrecorded,
                ..
            } => (target, scope, unrecorded, true),
        };
        let position = target_position(&scoped, &target)?;
        let snapshot = scope
            .touches_files()
            .then(|| checkpoint_before(&scoped[..=position]))
            .flatten();
        if scope.touches_files() && snapshot.is_none() {
            return Err("no verified workspace checkpoint precedes that logical target".into());
        }
        reply.preview = Some(match snapshot.as_ref() {
            Some(snapshot) => {
                let mut review = crate::workspace_review::observe(&self.workspace).await?;
                // Runtime state is not editable workspace content, independently of Git ignore.
                let relative = self.runs.strip_prefix(&self.workspace).ok();
                if let Some(relative) = relative {
                    review
                        .changes
                        .entries
                        .retain(|entry| !std::path::Path::new(&entry.path).starts_with(relative));
                }
                let preview = crate::workspace_review::preview_restore(
                    &review,
                    snapshot,
                    &self.workspace,
                    changeset_scope(scope),
                    changeset_unrecorded(unrecorded),
                )?;
                let all_paths = preview
                    .overwritten
                    .iter()
                    .map(|entry| format!("restore {}", entry.path))
                    .chain(
                        preview
                            .irrecoverable()
                            .iter()
                            .map(|entry| format!("delete {}", entry.path)),
                    )
                    .collect::<Vec<_>>();
                let path_display = all_paths
                    .iter()
                    .take(MAX_PATH_DISPLAY)
                    .map(|path| iteron_record::redact::scrub(path))
                    .collect::<Vec<_>>();
                let omitted_paths = all_paths.len().saturating_sub(path_display.len());
                RewindPreviewV1 {
                    target: target.clone(),
                    checkpoint: Some(RewindTargetV1 {
                        run_id: snapshot.run.clone(),
                        seq: snapshot.at,
                    }),
                    scope,
                    unrecorded,
                    conclusive: preview.is_conclusive(),
                    overlay: preview.inexact,
                    overwritten_paths: preview.overwritten.len(),
                    deleted_paths: preview.irrecoverable().len(),
                    preserved_unrecorded_paths: if unrecorded == RewindUnrecordedV1::Keep {
                        preview.not_in_snapshot.len()
                    } else {
                        0
                    },
                    path_display,
                    omitted_paths,
                    protected_runtime_state: true,
                }
            }
            None => RewindPreviewV1 {
                target: target.clone(),
                checkpoint: None,
                scope,
                unrecorded,
                conclusive: true,
                overlay: false,
                overwritten_paths: 0,
                deleted_paths: 0,
                preserved_unrecorded_paths: 0,
                path_display: Vec::new(),
                omitted_paths: 0,
                protected_runtime_state: true,
            },
        });
        if !apply {
            return Ok(RewindPreparation::Observed(reply));
        }
        if reply
            .preview
            .as_ref()
            .is_some_and(|preview| scope.touches_files() && !preview.conclusive)
        {
            return Err(
                "workspace apply requires a complete actual change-set and snapshot inventory"
                    .into(),
            );
        }
        cancelled(cancel.as_deref())?;
        // Admit route, fork, writer and replay before any working file can change. A later refusal
        // retains and reports this child; there is no branch-creation rollback claim.
        let (child, admission) = if scope.touches_conversation() {
            self.build_route(&directory, &origin.selection)?;
            let (run, _) = iteron_record::session::fork_with_checkpoint(
                &self.runs,
                &target.run_id,
                target.seq,
                &self.tenant,
                &origin.checkpoint,
                iteron_record::LegacyTunablesPolicy::RejectUnpinned,
            )
            .map_err(|_| "verified conversation branch failed".to_owned())?;
            let result = (|| {
                let rollout = Rollout::open_existing(&self.runs, &run, self.tenant.clone())
                    .map_err(|_| "prepared conversation writer unavailable".to_owned())?;
                let scoped = self.verified(&run)?;
                self.finish_native(
                    origin,
                    rollout,
                    NativeSessionStart::Existing,
                    scoped,
                    admission,
                    &directory,
                )
            })();
            let child = result.map_err(|reason| format!("{reason}; retained run {}", run.0))?;
            (Some(child), None)
        } else {
            (None, Some(admission))
        };
        reply.execution = Some(RewindExecutionV1 {
            files: if scope.touches_files() {
                RewindFilesV1::NotStarted
            } else {
                RewindFilesV1::NotRequested
            },
            intent_seq: None,
            safety_checkpoint_seq: None,
            terminal_seq: None,
            retained_child_run: child.as_ref().map(|child| child.run_id().clone()),
            conversation_adopted: false,
            reason: None,
        });
        Ok(RewindPreparation::Apply(PreparedRewind {
            owner: self.clone(),
            reply,
            snapshot,
            child,
            admission,
            cancel,
        }))
    }
}
impl PreparedRewind {
    pub(in crate::app_server) fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
    }
    pub(in crate::app_server) fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }
    pub(in crate::app_server) fn reply_mut(&mut self) -> &mut WorkspaceRewindReplyV1 {
        &mut self.reply
    }
    pub(in crate::app_server) fn retained_child(&self) -> Option<iteron_protocol::RunId> {
        self.child.as_ref().map(|child| child.run_id().clone())
    }
    pub(in crate::app_server) async fn create_safety(
        self,
        permit: WorkspaceRewindPermit,
    ) -> Result<(AuthorizedRewind, Result<Snapshot, String>), String> {
        tokio::task::spawn_blocking(move || {
            let result = (|| {
                let target = self
                    .snapshot
                    .as_ref()
                    .ok_or("file restore target unavailable")?;
                if !permit.matches(
                    &self.reply.origin_run_id,
                    &self.owner.tenant,
                    &self.owner.workspace,
                    target,
                ) {
                    return Err(
                        "restore admission does not match the actual prepared target".into(),
                    );
                }
                cancelled(self.cancel.as_deref())?;
                iteron_record::checkpoint_excluding_runtime_state(
                    &self.reply.origin_run_id,
                    permit.intent_sequence(),
                    &self.owner.workspace,
                    permit.runtime_state(),
                )
                .map_err(|_| {
                    "pre-restore safety capture failed before working-file mutation".into()
                })
            })();
            (
                AuthorizedRewind {
                    prepared: self,
                    permit,
                },
                result,
            )
        })
        .await
        .map_err(|_| "native safety capture worker has no observed result".into())
    }
    pub(in crate::app_server) fn into_parts(
        self,
    ) -> (
        WorkspaceRewindReplyV1,
        Option<(super::super::AdoptRun, NavigationPresentation)>,
        SubmissionExclusionLease,
    ) {
        match self.child {
            Some(child) => {
                let (native, presentation, admission) = child.into_parts();
                (self.reply, Some((native, presentation)), admission)
            }
            None => (
                self.reply,
                None,
                self.admission
                    .expect("code-only preparation retains its queue exclusion"),
            ),
        }
    }
}
impl AuthorizedRewind {
    pub(in crate::app_server) fn into_prepared(self) -> PreparedRewind {
        self.prepared
    }
    pub(in crate::app_server) async fn restore(
        self,
        safety: Snapshot,
    ) -> Result<CompletedRewind, String> {
        tokio::task::spawn_blocking(move || {
            let files =
                if cancelled(self.prepared.cancel.as_deref()).is_err() {
                    RewindFilesV1::NotStarted
                } else if let Some(target) = self.prepared.snapshot.as_ref() {
                    let delete =
                        self.prepared.reply.preview.as_ref().is_some_and(|preview| {
                            preview.unrecorded == RewindUnrecordedV1::Delete
                        });
                    if iteron_record::rewind_workspace_excluding_runtime_state(
                        target,
                        &self.prepared.owner.workspace,
                        delete,
                        self.permit.runtime_state(),
                    )
                    .is_ok()
                    {
                        RewindFilesV1::Restored
                    } else if iteron_record::rewind_workspace_excluding_runtime_state(
                        &safety,
                        &self.prepared.owner.workspace,
                        true,
                        self.permit.runtime_state(),
                    )
                    .is_ok()
                    {
                        RewindFilesV1::RolledBack
                    } else {
                        RewindFilesV1::ReconciliationNeeded
                    }
                } else {
                    RewindFilesV1::NotStarted
                };
            CompletedRewind {
                prepared: self.prepared,
                files,
            }
        })
        .await
        .map_err(|_| "native restore worker has no observed result".into())
    }
}
fn target_position(scoped: &[ScopedEvent], target: &RewindTargetV1) -> Result<usize, String> {
    scoped
        .iter()
        .position(|entry| entry.run_id == target.run_id && entry.event.seq == target.seq)
        .ok_or_else(|| "rewind target is absent from the verified logical history".into())
}
fn checkpoint_before(scoped: &[ScopedEvent]) -> Option<Snapshot> {
    scoped
        .iter()
        .rev()
        .find_map(|entry| match &entry.event.kind {
            EventKind::Checkpoint { at, tree_ref } if at.0 <= entry.event.seq.0 => Some(Snapshot {
                run: entry.run_id.clone(),
                at: *at,
                tree_ref: tree_ref.clone(),
                created_at: 0,
            }),
            _ => None,
        })
}
fn changeset_scope(scope: RewindScopeV1) -> iteron_changeset::Scope {
    match scope {
        RewindScopeV1::CodeAndConversation => iteron_changeset::Scope::CodeAndConversation,
        RewindScopeV1::CodeOnly => iteron_changeset::Scope::CodeOnly,
        RewindScopeV1::ConversationOnly => iteron_changeset::Scope::ConversationOnly,
    }
}
fn changeset_unrecorded(policy: RewindUnrecordedV1) -> iteron_changeset::Unrecorded {
    match policy {
        RewindUnrecordedV1::Keep => iteron_changeset::Unrecorded::Keep,
        RewindUnrecordedV1::Delete => iteron_changeset::Unrecorded::Delete,
    }
}

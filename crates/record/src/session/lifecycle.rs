//! Explicit session deletion and retention, holding actual journal and derivative leases.
use super::index::{list, merge_rewrite_index};
use super::paths::{now_secs, per_run_meta_path, rollout_path};
use crate::RecordError;
use iteron_protocol::{RunId, TenantId};
use std::{collections::HashSet, fs::OpenOptions, io, path::Path};

/// What [`prune`] is allowed to delete. A policy that names nothing deletes nothing: retention is
/// always explicit, because a run journal is the only durable evidence a run ever happened.
#[derive(Debug, Clone, Default)]
pub struct PrunePolicy {
    /// Delete runs whose last recorded activity is older than this many seconds.
    pub max_age_secs: Option<u64>,
    /// Keep the newest N runs; delete every older one.
    pub keep_last: Option<usize>,
    /// Select and report without unlinking anything.
    pub dry_run: bool,
}

/// What [`prune`] did, and what it declined to do. The two "kept anyway" lists are reported rather
/// than silently folded into `retained`: a caller that asked for a deletion and did not get one is
/// entitled to know which rule stopped it.
#[derive(Debug, Clone, Default)]
pub struct PruneReport {
    /// Runs the policy named and whose journal (plus sidecar) was unlinked.
    pub removed: Vec<RunId>,
    /// Runs left in place.
    pub retained: usize,
    /// Named by the policy, kept because another process holds the writer lock.
    pub active: Vec<RunId>,
    /// Named by the policy, kept because a retained fork replays through this run's prefix.
    pub ancestors: Vec<RunId>,
    /// Named by the policy, kept because a production derivative still owns private handles.
    pub derivatives: Vec<RunId>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeleteSessionError {
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("session {0:?} does not exist")]
    NotFound(String),
    #[error("session {0:?} is active in another process")]
    Active(String),
    #[error("session {run:?} is retained by descendant sessions: {descendants}")]
    HasDescendants { run: String, descendants: String },
    #[error("session {run:?} is retained by {owners} external private derivative owner(s)")]
    HasDerivatives { run: String, owners: u32 },
}

/// Delete exactly one inactive session and its rebuildable projection.
///
/// The journal lock stays held across unlink, and any retained fork whose logical history names
/// the target refuses the operation. This is the explicit destructive counterpart to [`prune`]:
/// callers must name one run rather than broadening a retention policy until it happens to match.
pub fn delete(runs_dir: &Path, tenant: &TenantId, run: &RunId) -> Result<(), DeleteSessionError> {
    crate::session_maintenance::flush()?;

    crate::validate_run_id(run)?;
    let sessions = list(runs_dir, tenant);
    if !sessions.iter().any(|meta| meta.run_id == *run) {
        return Err(DeleteSessionError::NotFound(run.0.clone()));
    }
    let mut descendants = sessions
        .iter()
        .filter(|meta| meta.run_id != *run)
        .filter(|meta| {
            meta.parent
                .as_ref()
                .is_some_and(|parent| parent.parent_run == *run)
                || meta.ancestry.iter().any(|ancestor| ancestor.run_id == *run)
        })
        .map(|meta| meta.run_id.0.clone())
        .collect::<Vec<_>>();
    descendants.sort();
    descendants.dedup();
    if !descendants.is_empty() {
        return Err(DeleteSessionError::HasDescendants {
            run: run.0.clone(),
            descendants: descendants.join(", "),
        });
    }

    let rollout = rollout_path(runs_dir, run)?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&rollout)
        .map_err(RecordError::from)?;
    file.try_lock()
        .map_err(|_| DeleteSessionError::Active(run.0.clone()))?;
    let content_release =
        match crate::content_store::ExactRunContentRelease::prepare(runs_dir, tenant, run) {
            Ok(guard) => guard,
            Err(crate::ContentStoreError::RetainedByDerivative { owners, .. }) => {
                return Err(DeleteSessionError::HasDerivatives {
                    run: run.0.clone(),
                    owners,
                });
            }
            Err(crate::ContentStoreError::ActiveWriter { .. }) => {
                return Err(DeleteSessionError::Active(run.0.clone()));
            }
            Err(error) => return Err(RecordError::from(error).into()),
        };
    // A sidecar is rebuildable while the journal still exists. Removing it first makes every
    // crash boundary either fully recoverable from the journal or resumable from the reverse
    // content-reference graph.
    let sidecar = per_run_meta_path(runs_dir, run)?;
    if let Err(error) = std::fs::remove_file(sidecar)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(RecordError::from(error).into());
    }
    std::fs::remove_file(&rollout).map_err(RecordError::from)?;
    content_release.commit().map_err(RecordError::from)?;
    complete_deleted_session_cleanup(runs_dir, run)?;
    drop(file);
    Ok(())
}

/// Finish rebuildable projection cleanup after the authoritative journal has been unlinked.
///
/// An erasure operation can crash between the journal unlink and sidecar/index cleanup. This
/// idempotent boundary lets its durable receipt resume without claiming stale projection bytes are
/// gone. Cleanup always refuses while the journal still exists.
pub(crate) fn complete_deleted_session_cleanup(
    runs_dir: &Path,
    run: &RunId,
) -> Result<(), RecordError> {
    let rollout = rollout_path(runs_dir, run)?;
    if rollout.try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "session journal still exists; projection cleanup refused",
        )
        .into());
    }
    let sidecar = per_run_meta_path(runs_dir, run)?;
    if let Err(error) = std::fs::remove_file(sidecar)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(RecordError::from(error));
    }
    merge_rewrite_index(runs_dir, [])?;
    Ok(())
}

/// Apply a retention policy to `runs_dir`, deleting the run journals it names and nothing else.
///
/// Journals are append-only and no other code path ever removes one, so this is the whole retention
/// story. Three rules bound it:
///
/// * only runs of `tenant` are even considered, so a shared runs dir cannot lose another tenant's
///   record to a policy that never saw it;
/// * a run whose writer lock is held is skipped — a live session is not garbage;
/// * a run a retained fork replays through is skipped, transitively, because deleting it would
///   leave the survivor with an unreadable logical history rather than a shorter one.
pub fn prune(
    runs_dir: &Path,
    tenant: &TenantId,
    policy: &PrunePolicy,
) -> Result<PruneReport, RecordError> {
    prune_at(runs_dir, tenant, policy, now_secs())
}

pub(crate) fn prune_at(
    runs_dir: &Path,
    tenant: &TenantId,
    policy: &PrunePolicy,
    now: u64,
) -> Result<PruneReport, RecordError> {
    crate::session_maintenance::flush()?;

    if !policy.dry_run {
        crate::content_store::release_private_content_for_absent_runs(runs_dir, tenant)?;
    }
    let metas = list(runs_dir, tenant);
    let total = metas.len();
    if policy.max_age_secs.is_none() && policy.keep_last.is_none() {
        return Ok(PruneReport {
            retained: total,
            ..PruneReport::default()
        });
    }

    // `list` is newest-first, so the keep-last window is a prefix. Age uses the same recorded
    // activity timestamp the listing orders by.
    let mut selected: HashSet<String> = HashSet::new();
    for (position, meta) in metas.iter().enumerate() {
        let too_old = policy
            .max_age_secs
            .is_some_and(|max_age| now.saturating_sub(meta.updated_at) > max_age);
        let beyond_window = policy.keep_last.is_some_and(|keep| position >= keep);
        if too_old || beyond_window {
            selected.insert(meta.run_id.0.clone());
        }
    }

    // Grow the retained set through ancestry to its fixpoint: a fork's prefix is not garbage while
    // the fork survives, however old the parent is.
    let mut ancestors: Vec<RunId> = Vec::new();
    loop {
        let mut rescued = Vec::new();
        for meta in &metas {
            if selected.contains(&meta.run_id.0) {
                continue;
            }
            if let Some(parent) = &meta.parent
                && selected.contains(&parent.parent_run.0)
            {
                rescued.push(parent.parent_run.clone());
            }
        }
        if rescued.is_empty() {
            break;
        }
        for run in rescued {
            // `remove` reports whether this run was still selected, which dedupes the report: two
            // forks off one parent rescue it once, not twice.
            if selected.remove(&run.0) {
                ancestors.push(run);
            }
        }
    }

    let mut report = PruneReport {
        ancestors,
        ..PruneReport::default()
    };
    for meta in &metas {
        if !selected.contains(&meta.run_id.0) {
            continue;
        }
        let run = meta.run_id.clone();
        let rollout = rollout_path(runs_dir, &run)?;
        let Some(_journal_lock) = lock_idle_rollout(&rollout) else {
            report.active.push(run);
            continue;
        };
        let content_release =
            match crate::content_store::ExactRunContentRelease::prepare(runs_dir, tenant, &run) {
                Ok(guard) => guard,
                Err(crate::ContentStoreError::RetainedByDerivative { .. }) => {
                    report.derivatives.push(run);
                    continue;
                }
                Err(crate::ContentStoreError::ActiveWriter { .. }) => {
                    report.active.push(run);
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
        if !policy.dry_run {
            // The projection goes first. Once the journal is durably absent, the reverse reference
            // graph is sufficient to finish key shredding after any crash boundary.
            let sidecar = per_run_meta_path(runs_dir, &run)?;
            if let Err(error) = std::fs::remove_file(&sidecar)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(error.into());
            }
            std::fs::remove_file(&rollout)?;
            content_release.commit()?;
        }
        report.removed.push(run);
    }
    report.retained = total.saturating_sub(report.removed.len());
    if !policy.dry_run {
        // Drop the deleted runs from the compact index in one atomic rewrite. `merge_rewrite_index`
        // re-reads which rollouts exist, so an entry whose journal is gone is not carried over. Do
        // this even when this pass removed nothing: that is the recovery pass after a crash which
        // unlinked its last selected journal before reaching the index rewrite.
        merge_rewrite_index(runs_dir, [])?;
    }
    Ok(report)
}

/// Acquire the rollout's exclusive writer lock for the complete prune mutation. A live run is
/// never garbage, and retaining the descriptor across sidecar plus journal unlink closes the
/// probe/delete race where a writer could otherwise start between those two operations.
fn lock_idle_rollout(path: &Path) -> Option<std::fs::File> {
    let Ok(file) = OpenOptions::new().read(true).append(true).open(path) else {
        return None;
    };
    match file.try_lock() {
        Ok(()) => Some(file),
        Err(_) => None,
    }
}

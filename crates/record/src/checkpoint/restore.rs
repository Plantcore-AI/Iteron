//! Complete file-restore planning and the protected runtime-state boundary. The caller owns
//! operation authorization and exclusion of concurrent writers; this owner cannot mint authority.
use super::{
    IsolatedGit, Snapshot, checked_workspace_path, nul_path_set, run_repo_git,
    runtime_state_relative, valid_object_id,
};
use crate::RecordError;
use std::{io, path::Path};

pub(super) fn restore(
    snapshot: &Snapshot,
    workspace: &Path,
    delete_unrecorded: bool,
    runtime_state: Option<&Path>,
) -> Result<(), RecordError> {
    if !valid_object_id(&snapshot.tree_ref) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint tree_ref is not a full Git object id",
        )
        .into());
    }
    let workspace = workspace.canonicalize()?;
    let excluded = runtime_state
        .map(|root| runtime_state_relative(&workspace, root))
        .transpose()?
        .flatten();
    let isolated = IsolatedGit::create(&snapshot.run, snapshot.at, &workspace)?;
    isolated.run(&["read-tree", &snapshot.tree_ref])?;
    let snapshot_files = nul_path_set(&isolated.run(&["ls-files", "-z"])?)?;
    // Older snapshots may contain runtime files. Refuse before the first working-file mutation;
    // silently dropping them would misrepresent the requested tree as an exact restore.
    for path in &snapshot_files {
        if excluded.as_ref().is_some_and(|root| overlaps(path, root)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "checkpoint intersects the protected runtime-state directory",
            )
            .into());
        }
        checked_workspace_path(&workspace, path)?;
    }
    let current = run_repo_git(
        &workspace,
        &["ls-files", "-z", "-o", "-c", "--exclude-standard"],
    )?;
    let mut removals = nul_path_set(&current)?
        .into_iter()
        .filter(|path| !snapshot_files.contains(path))
        .filter(|path| !excluded.as_ref().is_some_and(|root| overlaps(path, root)))
        .collect::<Vec<_>>();
    removals.sort_unstable();
    if delete_unrecorded {
        for path in &removals {
            checked_workspace_path(&workspace, path)?;
        }
    }
    // Same isolated configuration as capture: no repository/global smudge or process driver.
    isolated.run(&["checkout-index", "-a", "-f"])?;
    if delete_unrecorded {
        for relative in removals {
            let path = checked_workspace_path(&workspace, &relative)?;
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn overlaps(path: &str, protected: &str) -> bool {
    // The runtime locator is canonical. macOS/Windows can still resolve an ASCII case variant
    // from a historical Git tree to that same destination, so retain the broader refusal there.
    #[cfg(any(target_os = "macos", windows))]
    let (path, protected) = (path.to_lowercase(), protected.to_lowercase());
    let path: &str = path.as_ref();
    let protected: &str = protected.as_ref();
    path == protected
        || path
            .strip_prefix(protected)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || protected
            .strip_prefix(path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests;

//! Bounded, validating multi-file exact-anchor patching.
//!
//! Every path and hunk is planned in memory before a destination is touched. Updated contents are
//! then staged as fsynced same-directory files and committed as one registry effect; a commit-time
//! I/O failure triggers byte-exact restoration of any member already replaced.

use crate::edit::{UniqueEditError, plan_unique_edit};
use crate::multi_file_patch_error::PatchFailure;
/// The tests in this module read the compiled ceilings directly through `use super::*`, which is
/// what makes them a check on the accessors rather than a restatement of them.
#[cfg(test)]
use crate::multi_file_patch_input::MAX_FILES;
use crate::multi_file_patch_input::{FilePatch, max_files, max_hunks_per_file, parse_requests};
use crate::write_file::{StagedWrite, atomic_replace_with_boundary};
use crate::{Registry, ToolError, err_result, ok_result, resolve_in_root};
use iteron_protocol::{Capability, Purity, ToolSpec};
use serde_json::Value;
use std::collections::HashSet;
use std::ops::Range;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncReadExt;

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 16 * 1024 * 1024;

struct PlannedFile {
    file_index: usize,
    path: String,
    target: PathBuf,
    original: Vec<u8>,
    updated: Vec<u8>,
    stamp: FileStamp,
    #[cfg(unix)]
    confined_target: Option<Arc<crate::confined_fs::ConfinedTarget>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

struct ReadSnapshot {
    bytes: Vec<u8>,
    stamp: FileStamp,
}

struct SnapshotEdit {
    hunk_index: usize,
    span: Range<usize>,
    replacement: String,
}

#[derive(Default)]
struct PatchIoStats {
    file_reads: usize,
    file_writes: usize,
}

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    let confined = registry.confine_execution_handle();
    let test_helper_thread = registry.test_helper_thread_handle();
    registry.push_candidate_change_effect_tool(
        ToolSpec {
            name: "apply_patch".into(),
            description: format!(
                "Apply an all-or-nothing unique-anchor patch across up to {} existing UTF-8 \
                 files. Exact matching is tried first; an exact miss may use deterministic \
                 line-edge whitespace/EOL normalization. Every anchor must still have one \
                 candidate in its original snapshot, and overlapping hunks are refused before any \
                 write. Errors identify the failing file and hunk.",
                max_files()
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": max_files(),
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "hunks": {
                                    "type": "array",
                                    "minItems": 1,
                                    "maxItems": max_hunks_per_file(),
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "old": {
                                                "type": "string",
                                                "description": "unique exact or line-edge-whitespace-normalized anchor"
                                            },
                                            "new": {"type": "string"}
                                        },
                                        "required": ["old", "new"]
                                    }
                                }
                            },
                            "required": ["path", "hunks"]
                        }
                    }
                },
                "required": ["files"]
            }),
            purity: Purity::Effecting,
            // Paths are nested, while the current dynamic elevation seam understands one
            // top-level `path`. Fail closed until that seam accepts a bounded path set.
            capability: Capability::TrustMutating,
        },
        move |call, root| {
            let confined = confined.clone();
            let test_helper_thread = test_helper_thread.clone();
            crate::effectfut::box_it(async move {
                if confined.load(std::sync::atomic::Ordering::Relaxed) {
                    return crate::confined_helper::execute(
                        &root,
                        call,
                        test_helper_thread.load(std::sync::atomic::Ordering::Relaxed),
                    )
                    .await;
                }
                let id = call.id.clone();
                let mut stats = PatchIoStats::default();
                let result = execute_patch(&root, &call.input, &mut stats, false).await;
                crate::ToolExecution::Definite(match result {
                    Ok((files, hunks)) => {
                        ok_result(id, format!("patched {files} files ({hunks} hunks)"))
                    }
                    Err(error) => err_result(id, error.model_json()),
                })
            })
        },
    )
}

async fn execute_patch(
    root: &Path,
    input: &Value,
    stats: &mut PatchIoStats,
    confined: bool,
) -> Result<(usize, usize), PatchFailure> {
    let requests = parse_requests(input)?;
    let total_hunks = requests.iter().map(|file| file.hunks.len()).sum::<usize>();
    let plans = plan_patch(root, requests, stats, confined).await?;
    commit_patch(root, &plans, stats, confined).await?;
    Ok((plans.len(), total_hunks))
}

pub(crate) async fn apply_patch_confined(root: &Path, input: &Value) -> Result<String, String> {
    let mut stats = PatchIoStats::default();
    execute_patch(root, input, &mut stats, true)
        .await
        .map(|(files, hunks)| format!("patched {files} files ({hunks} hunks)"))
        .map_err(|failure| failure.model_json())
}

async fn plan_patch(
    root: &Path,
    requests: Vec<FilePatch>,
    stats: &mut PatchIoStats,
    confined: bool,
) -> Result<Vec<PlannedFile>, PatchFailure> {
    #[cfg(not(unix))]
    if confined {
        return Err(PatchFailure::global(
            "unsupported",
            "resolve",
            "confined patches require a descriptor-relative backend",
        ));
    }
    let mut resolved = Vec::with_capacity(requests.len());
    let mut unique_targets = HashSet::with_capacity(requests.len());
    // Resolve every path before reading or planning a hunk. One escaping member rejects the whole
    // proposal while all destinations are still untouched.
    for (file_index, request) in requests.into_iter().enumerate() {
        let target = resolve_in_root(root, &request.path).map_err(|error| {
            PatchFailure::file(
                "path_outside_workspace",
                "resolve",
                file_index,
                &request.path,
                error,
            )
        })?;
        if !unique_targets.insert(target.clone()) {
            return Err(PatchFailure::file(
                "duplicate_target",
                "resolve",
                file_index,
                &request.path,
                "the same canonical file appears more than once",
            ));
        }
        resolved.push((file_index, request, target));
    }

    let mut plans = Vec::with_capacity(resolved.len());
    let mut total_file_bytes = 0usize;
    for (file_index, request, target) in resolved {
        #[cfg(unix)]
        let confined_target = if confined {
            Some(Arc::new(
                crate::confined_fs::ConfinedTarget::open(root, &target, false).map_err(
                    |error| {
                        PatchFailure::file(
                            "path_outside_workspace",
                            "bind",
                            file_index,
                            &request.path,
                            error.to_string(),
                        )
                    },
                )?,
            ))
        } else {
            None
        };
        #[cfg(unix)]
        let snapshot_result = if let Some(bound) = &confined_target {
            read_bounded_confined(bound, stats).await
        } else {
            read_bounded(&target, stats).await
        };
        #[cfg(not(unix))]
        let snapshot_result = read_bounded(&target, stats).await;
        let snapshot = snapshot_result.map_err(|error| {
            PatchFailure::file(error.0, "read", file_index, &request.path, error.1)
        })?;
        total_file_bytes = total_file_bytes
            .checked_add(snapshot.bytes.len())
            .ok_or_else(|| {
                PatchFailure::global("patch_too_large", "read", "file byte count overflow")
            })?;
        let max_total_file_bytes = iteron_tunables::param_usize(
            "tools.multi_file_patch.max_total_file_bytes",
            iteron_tunables::param_integer(
                "tools.multi_file_patch.max_total_file_bytes",
                MAX_TOTAL_FILE_BYTES,
            ),
        );
        if total_file_bytes > max_total_file_bytes {
            return Err(PatchFailure::global(
                "patch_too_large",
                "read",
                format!("target files exceed {max_total_file_bytes} total bytes"),
            ));
        }
        let original_text = String::from_utf8(snapshot.bytes.clone()).map_err(|_| {
            PatchFailure::file(
                "non_utf8_file",
                "read",
                file_index,
                &request.path,
                "target is not UTF-8 text",
            )
        })?;
        let mut edits: Vec<SnapshotEdit> = Vec::with_capacity(request.hunks.len());
        for (hunk_index, hunk) in request.hunks.iter().enumerate() {
            let edit = plan_unique_edit(&original_text, &hunk.old, &hunk.new).map_err(|error| {
                unique_edit_failure(error, file_index, hunk_index, &request.path)
            })?;
            let span = edit.span;
            if let Some(conflict) = edits.iter().find(|prior| spans_overlap(&span, &prior.span)) {
                return Err(PatchFailure::conflict(
                    file_index,
                    hunk_index,
                    conflict.hunk_index,
                    &request.path,
                ));
            }
            edits.push(SnapshotEdit {
                hunk_index,
                span,
                replacement: edit.replacement,
            });
        }
        let updated = render_snapshot_edits(&original_text, edits).map_err(|hunk_index| {
            PatchFailure::hunk(
                "updated_file_too_large",
                file_index,
                hunk_index,
                &request.path,
                format!("updated file exceeds {MAX_FILE_BYTES} bytes"),
            )
        })?;
        if updated.as_bytes() == snapshot.bytes {
            return Err(PatchFailure::file(
                "no_change",
                "validate",
                file_index,
                &request.path,
                "patch would not change target bytes",
            ));
        }
        plans.push(PlannedFile {
            file_index,
            path: request.path,
            target,
            original: snapshot.bytes,
            updated: updated.into_bytes(),
            stamp: snapshot.stamp,
            #[cfg(unix)]
            confined_target,
        });
    }
    Ok(plans)
}

fn unique_edit_failure(
    error: UniqueEditError,
    file_index: usize,
    hunk_index: usize,
    path: &str,
) -> PatchFailure {
    let message = error.to_string();
    match error {
        UniqueEditError::AnchorNotFound { nearest_line } => {
            PatchFailure::anchor_not_found(file_index, hunk_index, path, nearest_line, message)
        }
        UniqueEditError::EmptyAnchor => {
            PatchFailure::hunk("empty_anchor", file_index, hunk_index, path, message)
        }
        UniqueEditError::NoChange => {
            PatchFailure::hunk("no_change", file_index, hunk_index, path, message)
        }
        UniqueEditError::SuspiciousUnicode(_) => {
            PatchFailure::hunk("suspicious_unicode", file_index, hunk_index, path, message)
        }
        UniqueEditError::AmbiguousAnchor { .. } => {
            PatchFailure::hunk("ambiguous_anchor", file_index, hunk_index, path, message)
        }
        UniqueEditError::NormalizationLimit(_) => {
            PatchFailure::hunk("normalization_limit", file_index, hunk_index, path, message)
        }
    }
}

fn spans_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn render_snapshot_edits(original: &str, mut edits: Vec<SnapshotEdit>) -> Result<String, usize> {
    let max_file_bytes =
        iteron_tunables::param_usize("tools.multi_file_patch.max_file_bytes", MAX_FILE_BYTES);
    let mut output_len = original.len();
    for edit in &edits {
        output_len = output_len
            .checked_sub(edit.span.len())
            .and_then(|length| length.checked_add(edit.replacement.len()))
            .filter(|&length| length <= max_file_bytes)
            .ok_or(edit.hunk_index)?;
    }
    edits.sort_by_key(|edit| edit.span.start);
    let mut updated = String::with_capacity(output_len);
    let mut cursor = 0usize;
    for edit in edits {
        updated.push_str(&original[cursor..edit.span.start]);
        updated.push_str(&edit.replacement);
        cursor = edit.span.end;
    }
    updated.push_str(&original[cursor..]);
    Ok(updated)
}

async fn read_bounded(
    path: &Path,
    stats: &mut PatchIoStats,
) -> Result<ReadSnapshot, (&'static str, String)> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    let before = file
        .metadata()
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    let max_file_bytes =
        iteron_tunables::param_usize("tools.multi_file_patch.max_file_bytes", MAX_FILE_BYTES);
    let mut bytes = Vec::with_capacity(64 * 1024);
    let mut limited = file.take((max_file_bytes + 1) as u64);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    stats.file_reads += 1;
    if bytes.len() > max_file_bytes {
        return Err((
            "file_too_large",
            format!("target exceeds {max_file_bytes} bytes"),
        ));
    }
    let after = limited
        .into_inner()
        .metadata()
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    let before = file_stamp(&before);
    let after = file_stamp(&after);
    if before != after {
        return Err((
            "file_changed",
            "file changed while its snapshot was being read; re-read and retry".into(),
        ));
    }
    Ok(ReadSnapshot {
        bytes,
        stamp: after,
    })
}

#[cfg(unix)]
async fn read_bounded_confined(
    target: &crate::confined_fs::ConfinedTarget,
    stats: &mut PatchIoStats,
) -> Result<ReadSnapshot, (&'static str, String)> {
    let file = target
        .open_existing()
        .map_err(|error| ("read_failed", error.to_string()))?;
    let before = file
        .metadata()
        .map_err(|error| ("read_failed", error.to_string()))?;
    let file = tokio::fs::File::from_std(file);
    let max_file_bytes =
        iteron_tunables::param_usize("tools.multi_file_patch.max_file_bytes", MAX_FILE_BYTES);
    let mut bytes = Vec::with_capacity(64 * 1024);
    let mut limited = file.take(max_file_bytes.saturating_add(1) as u64);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    stats.file_reads += 1;
    if bytes.len() > max_file_bytes {
        return Err((
            "file_too_large",
            format!("target exceeds {max_file_bytes} bytes"),
        ));
    }
    let after = limited
        .into_inner()
        .metadata()
        .await
        .map_err(|error| ("read_failed", error.to_string()))?;
    let path_after = target
        .metadata()
        .map_err(|error| ("read_failed", error.to_string()))?
        .ok_or(("file_changed", "target disappeared".to_owned()))?;
    if file_stamp(&before) != file_stamp(&after) || file_stamp(&after) != file_stamp(&path_after) {
        return Err((
            "file_changed",
            "file changed while its snapshot was being read; re-read and retry".into(),
        ));
    }
    Ok(ReadSnapshot {
        bytes,
        stamp: file_stamp(&after),
    })
}

fn file_stamp(metadata: &std::fs::Metadata) -> FileStamp {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        change_seconds: metadata.ctime(),
        #[cfg(unix)]
        change_nanoseconds: metadata.ctime_nsec(),
    }
}

async fn commit_patch(
    root: &Path,
    plans: &[PlannedFile],
    stats: &mut PatchIoStats,
    confined: bool,
) -> Result<(), PatchFailure> {
    let mut staged = Vec::with_capacity(plans.len());
    for plan in plans {
        #[cfg(unix)]
        let write = if let Some(bound) = &plan.confined_target {
            StagedWrite::prepare_confined(&plan.target, &plan.updated, bound.clone()).await
        } else {
            StagedWrite::prepare_with_boundary(&plan.target, &plan.updated, None).await
        };
        #[cfg(not(unix))]
        let write = StagedWrite::prepare_with_boundary(
            &plan.target,
            &plan.updated,
            confined.then_some(root),
        )
        .await;
        staged.push(write.map_err(|error| {
            PatchFailure::file(
                "stage_failed",
                "stage",
                plan.file_index,
                &plan.path,
                error.to_string(),
            )
        })?);
    }

    // Staging can take time. Recheck the identity stamp before the first rename so an operator
    // edit made underneath the patch is refused while our write set is still zero. This is a
    // metadata-only check: each file's content is read exactly once into its planning snapshot.
    for plan in plans {
        if confined {
            crate::workspace_boundary::validate_coding_write_target(root, &plan.target).map_err(
                |reason| {
                    PatchFailure::file(
                        "path_outside_workspace",
                        "precommit",
                        plan.file_index,
                        &plan.path,
                        reason,
                    )
                },
            )?;
        }
        #[cfg(unix)]
        let current = if let Some(bound) = &plan.confined_target {
            bound.metadata().and_then(|metadata| {
                metadata.ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "target disappeared")
                })
            })
        } else {
            tokio::fs::metadata(&plan.target).await
        };
        #[cfg(not(unix))]
        let current = tokio::fs::metadata(&plan.target).await;
        let current = current.map_err(|error| {
            PatchFailure::file(
                "read_failed",
                "precommit",
                plan.file_index,
                &plan.path,
                error.to_string(),
            )
        })?;
        if file_stamp(&current) != plan.stamp {
            return Err(PatchFailure::file(
                "file_changed",
                "precommit",
                plan.file_index,
                &plan.path,
                "file changed while the patch was being staged; re-read and retry",
            ));
        }
    }

    let mut committed = Vec::with_capacity(plans.len());
    for (index, write) in staged.into_iter().enumerate() {
        if let Err(failure) = write.commit().await {
            if failure.target_replaced {
                committed.push(index);
                stats.file_writes += 1;
            }
            let commit_message = failure.error.to_string();
            let rollback_error = rollback(root, plans, &committed, confined).await;
            return Err(match rollback_error {
                None => PatchFailure::file(
                    "commit_failed_rolled_back",
                    "commit",
                    plans[index].file_index,
                    &plans[index].path,
                    format!("commit failed and prior files were restored: {commit_message}"),
                ),
                Some(error) => PatchFailure::file(
                    "rollback_failed",
                    "rollback",
                    plans[index].file_index,
                    &plans[index].path,
                    format!("commit failed ({commit_message}); rollback also failed: {error}"),
                ),
            });
        }
        committed.push(index);
        stats.file_writes += 1;
    }
    Ok(())
}

async fn rollback(
    _root: &Path,
    plans: &[PlannedFile],
    committed: &[usize],
    _confined: bool,
) -> Option<String> {
    let mut first_error = None;
    for &index in committed.iter().rev() {
        #[cfg(unix)]
        let replacement = if let Some(bound) = &plans[index].confined_target {
            async {
                let staged = StagedWrite::prepare_confined(
                    &plans[index].target,
                    &plans[index].original,
                    bound.clone(),
                )
                .await?;
                staged.commit().await.map_err(|failure| failure.error)
            }
            .await
        } else {
            atomic_replace_with_boundary(&plans[index].target, &plans[index].original, None).await
        };
        #[cfg(not(unix))]
        let replacement = atomic_replace_with_boundary(
            &plans[index].target,
            &plans[index].original,
            _confined.then_some(_root),
        )
        .await;
        if let Err(error) = replacement
            && first_error.is_none()
        {
            first_error = Some(format!("{}: {error}", plans[index].path));
        }
    }
    first_error
}

#[cfg(test)]
#[path = "multi_file_patch_tests.rs"]
mod tests;

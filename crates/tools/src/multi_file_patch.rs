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
use crate::write_file::{StagedWrite, atomic_replace};
use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use iteron_protocol::{Capability, Purity, ToolSpec};
use serde_json::Value;
use std::collections::HashSet;
use std::ops::Range;
use std::path::{Path, PathBuf};
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
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
    registry.push_tool(
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
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let mut stats = PatchIoStats::default();
                let result = execute_patch(&root, &call.input, &mut stats).await;
                match result {
                    Ok((files, hunks)) => {
                        ok_result(id, format!("patched {files} files ({hunks} hunks)"))
                    }
                    Err(error) => err_result(id, error.model_json()),
                }
            })
        },
    )
}

async fn execute_patch(
    root: &Path,
    input: &Value,
    stats: &mut PatchIoStats,
) -> Result<(usize, usize), PatchFailure> {
    let requests = parse_requests(input)?;
    let total_hunks = requests.iter().map(|file| file.hunks.len()).sum::<usize>();
    let plans = plan_patch(root, requests, stats).await?;
    commit_patch(&plans, stats).await?;
    Ok((plans.len(), total_hunks))
}

async fn plan_patch(
    root: &Path,
    requests: Vec<FilePatch>,
    stats: &mut PatchIoStats,
) -> Result<Vec<PlannedFile>, PatchFailure> {
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
        let snapshot = read_bounded(&target, stats).await.map_err(|error| {
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
        plans.push(PlannedFile {
            file_index,
            path: request.path,
            target,
            original: snapshot.bytes,
            updated: updated.into_bytes(),
            stamp: snapshot.stamp,
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

fn file_stamp(metadata: &std::fs::Metadata) -> FileStamp {
    FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    }
}

async fn commit_patch(plans: &[PlannedFile], stats: &mut PatchIoStats) -> Result<(), PatchFailure> {
    let mut staged = Vec::with_capacity(plans.len());
    for plan in plans {
        staged.push(
            StagedWrite::prepare(&plan.target, &plan.updated)
                .await
                .map_err(|error| {
                    PatchFailure::file(
                        "stage_failed",
                        "stage",
                        plan.file_index,
                        &plan.path,
                        error.to_string(),
                    )
                })?,
        );
    }

    // Staging can take time. Recheck the identity stamp before the first rename so an operator
    // edit made underneath the patch is refused while our write set is still zero. This is a
    // metadata-only check: each file's content is read exactly once into its planning snapshot.
    for plan in plans {
        let current = tokio::fs::metadata(&plan.target).await.map_err(|error| {
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
            let rollback_error = rollback(plans, &committed).await;
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

async fn rollback(plans: &[PlannedFile], committed: &[usize]) -> Option<String> {
    let mut first_error = None;
    for &index in committed.iter().rev() {
        if let Err(error) = atomic_replace(&plans[index].target, &plans[index].original).await
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

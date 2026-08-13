//! Bounded input parsing for the multi-file exact-anchor patch tool.

use crate::edit::suspicious_unicode;
use crate::multi_file_patch_error::PatchFailure;
use serde_json::Value;

pub(crate) const MAX_FILES: usize = 16;
pub(crate) const MAX_HUNKS_PER_FILE: usize = 32;
const MAX_TOTAL_HUNKS: usize = 128;

/// The advertised schema and the parser have to quote the same number, so both read the parameter
/// through these two accessors rather than the constants directly. With no profile installed each
/// returns its own compiled constant.
pub(crate) fn max_files() -> usize {
    iteron_tunables::param_usize("tools.multi_file_patch_input.max_files", MAX_FILES)
}

pub(crate) fn max_hunks_per_file() -> usize {
    iteron_tunables::param_usize(
        "tools.multi_file_patch_input.max_hunks_per_file",
        iteron_tunables::param_integer(
            "tools.multi_file_patch_input.max_hunks_per_file",
            MAX_HUNKS_PER_FILE,
        ),
    )
}
const MAX_PATCH_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4_096;

pub(crate) struct Hunk {
    pub(crate) old: String,
    pub(crate) new: String,
}

pub(crate) struct FilePatch {
    pub(crate) path: String,
    pub(crate) hunks: Vec<Hunk>,
}

pub(crate) fn parse_requests(input: &Value) -> Result<Vec<FilePatch>, PatchFailure> {
    let files = input
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PatchFailure::global("invalid_input", "parse", "`files` must be an array")
        })?;
    let max_files = max_files();
    if files.is_empty() || files.len() > max_files {
        return Err(PatchFailure::global(
            "file_count_out_of_bounds",
            "parse",
            format!("patch must contain 1..={max_files} files"),
        ));
    }

    let mut total_hunks = 0usize;
    let mut total_input_bytes = 0usize;
    let mut requests = Vec::with_capacity(files.len());
    for (file_index, file) in files.iter().enumerate() {
        let path = file.get("path").and_then(Value::as_str).ok_or_else(|| {
            PatchFailure::file(
                "invalid_input",
                "parse",
                file_index,
                "",
                "`path` must be a string",
            )
        })?;
        if path.is_empty() {
            return Err(PatchFailure::file(
                "invalid_path",
                "parse",
                file_index,
                path,
                "path must not be empty",
            ));
        }
        if path.len()
            > iteron_tunables::param_integer(
                "tools.multi_file_patch_input.max_path_bytes",
                MAX_PATH_BYTES,
            )
        {
            return Err(PatchFailure::file(
                "invalid_path",
                "parse",
                file_index,
                path,
                format!("path exceeds {MAX_PATH_BYTES} bytes"),
            ));
        }
        if let Some(codepoint) = suspicious_unicode(path) {
            return Err(PatchFailure::file(
                "suspicious_unicode",
                "parse",
                file_index,
                path,
                format!("suspicious Unicode U+{codepoint:04X} in path"),
            ));
        }
        total_input_bytes = bounded_add(total_input_bytes, path.len())?;
        let hunks = file.get("hunks").and_then(Value::as_array).ok_or_else(|| {
            PatchFailure::file(
                "invalid_input",
                "parse",
                file_index,
                path,
                "`hunks` must be an array",
            )
        })?;
        let max_hunks_per_file = max_hunks_per_file();
        if hunks.is_empty() || hunks.len() > max_hunks_per_file {
            return Err(PatchFailure::file(
                "hunk_count_out_of_bounds",
                "parse",
                file_index,
                path,
                format!("file must contain 1..={max_hunks_per_file} hunks"),
            ));
        }
        total_hunks = total_hunks.checked_add(hunks.len()).ok_or_else(|| {
            PatchFailure::global("patch_too_large", "parse", "hunk count overflow")
        })?;
        let max_total_hunks = iteron_tunables::param_usize(
            "tools.multi_file_patch_input.max_total_hunks",
            iteron_tunables::param_integer(
                "tools.multi_file_patch_input.max_total_hunks",
                MAX_TOTAL_HUNKS,
            ),
        );
        if total_hunks > max_total_hunks {
            return Err(PatchFailure::global(
                "patch_too_large",
                "parse",
                format!("patch exceeds {max_total_hunks} total hunks"),
            ));
        }

        let mut parsed_hunks = Vec::with_capacity(hunks.len());
        for (hunk_index, hunk) in hunks.iter().enumerate() {
            let old = hunk.get("old").and_then(Value::as_str).ok_or_else(|| {
                PatchFailure::hunk(
                    "invalid_input",
                    file_index,
                    hunk_index,
                    path,
                    "`old` must be a string",
                )
            })?;
            let new = hunk.get("new").and_then(Value::as_str).ok_or_else(|| {
                PatchFailure::hunk(
                    "invalid_input",
                    file_index,
                    hunk_index,
                    path,
                    "`new` must be a string",
                )
            })?;
            total_input_bytes = bounded_add(total_input_bytes, old.len())?;
            total_input_bytes = bounded_add(total_input_bytes, new.len())?;
            parsed_hunks.push(Hunk {
                old: old.into(),
                new: new.into(),
            });
        }
        requests.push(FilePatch {
            path: path.into(),
            hunks: parsed_hunks,
        });
    }
    Ok(requests)
}

fn bounded_add(current: usize, added: usize) -> Result<usize, PatchFailure> {
    let total = current.checked_add(added).ok_or_else(|| {
        PatchFailure::global("patch_too_large", "parse", "patch byte count overflow")
    })?;
    let max_patch_input_bytes = iteron_tunables::param_usize(
        "tools.multi_file_patch_input.max_patch_input_bytes",
        iteron_tunables::param_integer(
            "tools.multi_file_patch_input.max_patch_input_bytes",
            MAX_PATCH_INPUT_BYTES,
        ),
    );
    if total > max_patch_input_bytes {
        return Err(PatchFailure::global(
            "patch_too_large",
            "parse",
            format!("patch input exceeds {max_patch_input_bytes} bytes"),
        ));
    }
    Ok(total)
}

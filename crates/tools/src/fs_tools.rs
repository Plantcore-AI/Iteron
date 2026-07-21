//! Pure/ReadOnly tools: read_file, list_dir, grep. These are the tools the scheduler may
//! dispatch early (at content_block_stop) because they have no observable effect.

use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use core_protocol::{Capability, Purity, ToolSpec};
use std::path::Path;
use tokio::io::AsyncReadExt;
use walkdir::WalkDir;

const MAX_READ_OUTPUT_BYTES: usize = 40_000;
const MAX_READ_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const TRUNCATION_MARKER_RESERVE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadWindow {
    /// Absolute, 1-based first line to return.
    offset: u64,
    /// Maximum lines to return; `None` means through EOF or the byte cap.
    limit: Option<u64>,
}

impl ReadWindow {
    fn from_input(input: &serde_json::Value) -> Result<Self, String> {
        let offset = positive_integer(input, "offset")?.unwrap_or(1);
        let limit = positive_integer(input, "limit")?;
        Ok(Self { offset, limit })
    }
}

fn positive_integer(input: &serde_json::Value, field: &str) -> Result<Option<u64>, String> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .filter(|value| *value > 0)
        .map(Some)
        .ok_or_else(|| format!("read_file: `{field}` must be a positive integer (minimum 1)"))
}

async fn read_numbered_file(path: &Path, window: ReadWindow) -> std::io::Result<String> {
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if metadata.len() > MAX_READ_SOURCE_BYTES as u64 {
        return Ok(format!(
            "(oversized file, not shown; read_file source limit is {MAX_READ_SOURCE_BYTES} bytes)"
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_READ_SOURCE_BYTES)
            .min(MAX_READ_SOURCE_BYTES)
            .saturating_add(1),
    );
    file.take(MAX_READ_SOURCE_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_READ_SOURCE_BYTES {
        return Ok(format!(
            "(oversized file, not shown; read_file source limit is {MAX_READ_SOURCE_BYTES} bytes)"
        ));
    }
    if bytes.contains(&0) {
        return Ok("(binary or unsupported encoded file, not shown)".into());
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => return Ok("(binary or non-UTF-8 file, not shown)".into()),
    };

    let mut absolute_line = 0_u64;
    let mut emitted = 0_u64;
    let mut output = String::new();
    let mut truncated_before = None;

    for line in text.lines() {
        absolute_line = absolute_line
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("read_file line counter overflow"))?;
        if absolute_line < window.offset {
            continue;
        }

        let numbered = format!("{absolute_line:>6}\t{line}");
        let separator_bytes = usize::from(!output.is_empty());
        if output
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(numbered.len())
            > MAX_READ_OUTPUT_BYTES - TRUNCATION_MARKER_RESERVE_BYTES
        {
            truncated_before = Some(absolute_line);
            break;
        }
        if separator_bytes > 0 {
            output.push('\n');
        }
        output.push_str(&numbered);
        emitted += 1;
        if window.limit.is_some_and(|limit| emitted >= limit) {
            break;
        }
    }

    if let Some(next_line) = truncated_before {
        let marker = format!(
            "… (truncated before line {next_line}; read_file output is capped at \
             {MAX_READ_OUTPUT_BYTES} bytes; continue with offset={next_line})"
        );
        if marker.len() >= TRUNCATION_MARKER_RESERVE_BYTES {
            return Err(std::io::Error::other(
                "read_file truncation marker exceeded its reserved output budget",
            ));
        }
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&marker);
        debug_assert!(output.len() <= MAX_READ_OUTPUT_BYTES);
    }

    if output.is_empty() {
        if absolute_line == 0 {
            Ok("(empty file)".into())
        } else {
            Ok(format!(
                "(no lines in requested range; file has {absolute_line} lines)"
            ))
        }
    } else {
        Ok(output)
    }
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    register_outline(r)?;
    crate::grep_tool::register(r)?;
    r.push_tool(
        ToolSpec {
            name: "read_file".into(),
            description: "Read a bounded window of a UTF-8 text file relative to the workspace \
                          root. Returns absolute 1-based line numbers so edits can reference exact \
                          text. `offset` is the optional 1-based first line (default 1); `limit` is \
                          the optional number of lines. Output is capped at 40,000 bytes and source \
                          reads at 8 MiB; binary, unsupported-encoding, and oversized files are not \
                          injected. Truncation reports the next offset to read."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "path":{"type":"string","description":"path relative to the repo root"},
                    "offset":{
                        "type":"integer",
                        "minimum":1,
                        "description":"optional 1-based first line to return; defaults to 1"
                    },
                    "limit":{
                        "type":"integer",
                        "minimum":1,
                        "description":"optional maximum number of lines to return; the 40,000-byte output cap still applies"
                    }
                },
                "required":["path"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let path = call.input.get("path").and_then(|x| x.as_str()).unwrap_or("");
                let window = match ReadWindow::from_input(&call.input) {
                    Ok(window) => window,
                    Err(error) => return err_result(id, error),
                };
                match resolve_in_root(&root, path) {
                    Err(e) => err_result(id, e),
                    Ok(p) => match read_numbered_file(&p, window).await {
                        Ok(content) => ok_result(id, content),
                        Err(e) => err_result(id, format!("read {path}: {e}")),
                    },
                }
            })
        },
    )?;

    r.push_tool(
        ToolSpec {
            name: "list_dir".into(),
            description: "List files under a directory (relative to the repo root), skipping \
                          .git and common build/vendor dirs. Returns paths, one per line."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"path":{"type":"string","description":"dir relative to repo root; default '.'"}},
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let rel = call.input.get("path").and_then(|x| x.as_str()).unwrap_or(".");
                match resolve_in_root(&root, rel) {
                    Err(e) => err_result(id, e),
                    Ok(base) => {
                        let mut out = Vec::new();
                        for entry in WalkDir::new(&base)
                            .max_depth(6)
                            .into_iter()
                            .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
                            .flatten()
                        {
                            if entry.file_type().is_file()
                                && let Ok(p) = entry.path().strip_prefix(&root) {
                                    out.push(p.display().to_string());
                                }
                            if out.len() > 400 {
                                out.push("… (truncated at 400 entries; narrow the path)".into());
                                break;
                            }
                        }
                        ok_result(id, out.join("\n"))
                    }
                }
            })
        },
    )?;

    r.push_tool(
        ToolSpec {
            name: "glob".into(),
            description: "Find files by glob pattern relative to the repo root: `*` matches within a \
                          path segment, `**` matches across segments, `?` matches one char. e.g. \
                          `src/**/*.rs`, `**/*.toml`. Skips .git/build/vendor dirs. Paths, one per line."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "required":["pattern"],
                "properties":{"pattern":{"type":"string","description":"glob relative to the repo root, e.g. src/**/*.rs"}},
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(pattern) = call.input.get("pattern").and_then(|x| x.as_str()) else {
                    return err_result(id, "glob: a `pattern` is required".into());
                };
                let mut out = Vec::new();
                for entry in WalkDir::new(&root)
                    .max_depth(20)
                    .into_iter()
                    .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
                    .flatten()
                {
                    if entry.file_type().is_file()
                        && let Ok(p) = entry.path().strip_prefix(&root)
                    {
                        let rel = p.to_string_lossy().replace('\\', "/");
                        if glob_match(pattern, &rel) {
                            out.push(rel);
                        }
                    }
                    if out.len() > 400 {
                        out.push("… (truncated at 400 matches; narrow the pattern)".into());
                        break;
                    }
                }
                if out.is_empty() {
                    return ok_result(id, format!("no files match `{pattern}`"));
                }
                ok_result(id, out.join("\n"))
            })
        },
    )?;

    Ok(())
}

fn is_ignored(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "dist" | "build" | "__pycache__"
    )
}

/// Match a `/`-separated path against a glob: `?`=one char, `*`=any run WITHIN a segment (never `/`),
/// `**`=any number of whole segments (incl. zero). Case-sensitive. Recursive backtracking over the
/// segment list; paths/patterns are short so the worst case is bounded in practice.
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    seg_match(&pat, &seg)
}
fn seg_match(pat: &[&str], seg: &[&str]) -> bool {
    match pat.split_first() {
        None => seg.is_empty(),
        Some((&"**", rest)) => (0..=seg.len()).any(|k| seg_match(rest, &seg[k..])),
        Some((p, rest)) => !seg.is_empty() && wild_seg(p, seg[0]) && seg_match(rest, &seg[1..]),
    }
}
/// Single-segment wildcard: `*` any run (no `/`), `?` one char, else literal.
fn wild_seg(pat: &str, s: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some(('*', rest)) => (0..=t.len()).any(|k| go(rest, &t[k..])),
            Some(('?', rest)) => !t.is_empty() && go(rest, &t[1..]),
            Some((c, rest)) => !t.is_empty() && t[0] == *c && go(rest, &t[1..]),
        }
    }
    go(
        &pat.chars().collect::<Vec<_>>(),
        &s.chars().collect::<Vec<_>>(),
    )
}

/// The localization-ladder tool: a repo skeleton (declarations only), fit to a token budget.
/// Agentless: the skeleton beats whole-file localization by +5.3pp at 7.5x less cost. This is
/// the map the agent should read FIRST on an unfamiliar repo, before materializing any file.
pub(crate) fn register_outline(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "repo_map".into(),
            description: "Get a skeleton of the repository: every code file and its top-level \
                          declarations (functions, classes, types), no bodies. Read this FIRST \
                          on an unfamiliar repo to localize, then read_file only the files you \
                          actually need. Optional `query` task text or identifiers boost files \
                          that declare those identifiers above unrelated declaration-heavy files."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "query":{
                        "type":"string",
                        "description":"optional task text or identifier names for deterministic relevance ranking"
                    }
                }
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                // Budget the map so it never dominates the window (late materialization).
                let query = call
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let map = core_ctx::repo_outline_for_task(&root, 6_000, query);
                ok_result(id, map)
            })
        },
    )
}

#[cfg(test)]
#[path = "fs_tools_tests.rs"]
mod tests;

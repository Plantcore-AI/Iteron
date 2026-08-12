//! Pure/ReadOnly tools: read_file, list_dir, grep. These are the tools the scheduler may
//! dispatch early (at content_block_stop) because they have no observable effect.

use crate::{
    ObservationToolPolicy, Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root,
};
use iteron_protocol::{Capability, Purity, ToolSpec};
use std::path::Path;
use tokio::io::AsyncReadExt;
use walkdir::WalkDir;

/// Retained output for one `read_file` window. Raised from 40 KB (owner-directed 2026-08-05): the
/// old ceiling truncated ordinary source files, and the model's only recovery was to re-issue the
/// call with an offset — turning one read into three or four and burning the turn budget the run
/// was actually bounded by. Still a ceiling, because an unbounded read is a context overflow.
const TRUNCATION_MARKER_RESERVE_BYTES: usize = 256;

/// Which pagination boundary ended a `read_file`. Both resume identically; they differ only in
/// what the operator can do about it, which is exactly what the marker has to say.
#[derive(Clone, Copy)]
enum TruncationCause {
    Window,
    OutputBytes,
}
const UTF8_BOM: &[u8; 3] = b"\xef\xbb\xbf";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEnding {
    Lf,
    CrLf,
}

impl LineEnding {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::CrLf => "\r\n",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextFileError {
    BinaryOrUnsupported,
    NonUtf8,
}

impl std::fmt::Display for TextFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryOrUnsupported => {
                formatter.write_str("target is binary or uses an unsupported encoding")
            }
            Self::NonUtf8 => formatter.write_str("target is binary or non-UTF-8 text"),
        }
    }
}

/// UTF-8 text plus the byte-level format that an edit is not allowed to change.
pub(crate) struct EditableText<'a> {
    content: &'a str,
    has_bom: bool,
    line_ending: Option<LineEnding>,
    trailing_line_ending: Option<LineEnding>,
}

impl<'a> EditableText<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, TextFileError> {
        let (has_bom, content_bytes) = bytes
            .strip_prefix(UTF8_BOM)
            .map_or((false, bytes), |content| (true, content));
        if content_bytes.contains(&0) {
            return Err(TextFileError::BinaryOrUnsupported);
        }
        let content = std::str::from_utf8(content_bytes).map_err(|_| TextFileError::NonUtf8)?;
        let line_ending = content
            .as_bytes()
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|newline| {
                if newline > 0 && content.as_bytes()[newline - 1] == b'\r' {
                    LineEnding::CrLf
                } else {
                    LineEnding::Lf
                }
            });
        Ok(Self {
            content,
            has_bom,
            line_ending,
            trailing_line_ending: content.ends_with('\n').then(|| {
                if content.ends_with("\r\n") {
                    LineEnding::CrLf
                } else {
                    LineEnding::Lf
                }
            }),
        })
    }

    pub(crate) fn content(&self) -> &'a str {
        self.content
    }

    pub(crate) fn normalize_replacement(&self, replacement: &str) -> String {
        match self.line_ending {
            None => replacement.to_owned(),
            Some(LineEnding::Lf) => replacement.replace("\r\n", "\n"),
            Some(LineEnding::CrLf) => replacement.replace("\r\n", "\n").replace('\n', "\r\n"),
        }
    }

    pub(crate) fn encode(&self, mut updated: String) -> Vec<u8> {
        if let Some(trailing_line_ending) = self.trailing_line_ending {
            if !updated.ends_with('\n') {
                updated.push_str(trailing_line_ending.as_str());
            }
        } else {
            while updated.ends_with('\n') {
                updated.pop();
                if updated.ends_with('\r') {
                    updated.pop();
                }
            }
        }

        let bom_bytes = usize::from(self.has_bom) * UTF8_BOM.len();
        let mut encoded = Vec::with_capacity(updated.len().saturating_add(bom_bytes));
        if self.has_bom {
            encoded.extend_from_slice(UTF8_BOM);
        }
        encoded.extend_from_slice(updated.as_bytes());
        encoded
    }
}

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

async fn read_numbered_file(
    path: &Path,
    window: ReadWindow,
    policy: crate::ReadFilePolicy,
) -> std::io::Result<String> {
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if metadata.len() > policy.source_max_bytes as u64 {
        return Ok(format!(
            "(oversized file, not shown; read_file source limit is {} bytes)",
            policy.source_max_bytes
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(policy.source_max_bytes)
            .min(policy.source_max_bytes)
            .saturating_add(1),
    );
    file.take(policy.source_max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > policy.source_max_bytes {
        return Ok(format!(
            "(oversized file, not shown; read_file source limit is {} bytes)",
            policy.source_max_bytes
        ));
    }
    let text = match EditableText::parse(&bytes) {
        Ok(text) => text.content(),
        Err(TextFileError::BinaryOrUnsupported) => {
            return Ok("(binary or unsupported encoded file, not shown)".into());
        }
        Err(TextFileError::NonUtf8) => {
            return Ok("(binary or non-UTF-8 file, not shown)".into());
        }
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

        // Policy and caller windows are pagination boundaries, not silent EOF. Check before
        // rendering the next available line so the marker can name the exact resume offset. If
        // the file ended exactly at the boundary this branch is never reached and no false
        // truncation marker is emitted.
        if emitted >= policy.max_lines as u64 || window.limit.is_some_and(|limit| emitted >= limit)
        {
            truncated_before = Some((absolute_line, TruncationCause::Window));
            break;
        }

        let numbered = format!("{absolute_line:>6}\t{line}");
        let separator_bytes = usize::from(!output.is_empty());
        if output
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(numbered.len())
            > policy.output_max_bytes - TRUNCATION_MARKER_RESERVE_BYTES
        {
            truncated_before = Some((absolute_line, TruncationCause::OutputBytes));
            break;
        }
        if separator_bytes > 0 {
            output.push('\n');
        }
        output.push_str(&numbered);
        emitted += 1;
    }

    if let Some((next_line, cause)) = truncated_before {
        // Name the boundary that actually stopped the read. Both are pagination boundaries and
        // both resume the same way, but reporting a caller's own `limit` as a byte cap tells the
        // operator the file is larger than their window in a way they cannot act on, and hides
        // the one case where raising `limit` would not help.
        let reason = match cause {
            TruncationCause::Window => "the requested line window ended here".to_owned(),
            TruncationCause::OutputBytes => format!(
                "read_file output is capped at {} bytes",
                policy.output_max_bytes
            ),
        };
        let marker = format!(
            "… (truncated before line {next_line}; {reason}; continue with offset={next_line})"
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
        debug_assert!(output.len() <= policy.output_max_bytes);
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

/// Append a truncation marker without letting the marker itself violate the pinned byte ceiling.
/// Data lines at the tail are discarded if necessary; the marker is more important because it
/// makes the loss explicit and tells the caller why traversal stopped.
fn append_bounded_marker(lines: &mut Vec<String>, cap: usize, marker: String) {
    debug_assert!(marker.len() <= cap);
    while !lines.is_empty()
        && lines
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(lines.len())
            .saturating_add(marker.len())
            > cap
    {
        lines.pop();
    }
    if marker.len() <= cap {
        lines.push(marker);
    }
    debug_assert!(lines.join("\n").len() <= cap);
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    register_outline(r)?;
    crate::grep_tool::register(r)?;
    let read_policy = r.observation_tool_policy_handle();
    r.push_tool(
        ToolSpec {
            name: "read_file".into(),
            description: format!(
                "Read a bounded window of a UTF-8 text file. `path` may be relative to the \
                 workspace root or an absolute host path. Returns absolute 1-based line numbers so \
                 edits can reference exact text. `offset` is the optional 1-based first line \
                 (default 1); `limit` is the optional number of lines. Output is capped at \
                 {} bytes by the canonical default; the effective source/output ceilings are \
                 pinned in the run checkpoint. Binary, unsupported-encoding, and oversized files \
                 are not injected. Truncation reports the next offset to read.",
                ObservationToolPolicy::default().read_file.output_max_bytes,
            ),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "path":{
                        "type":"string",
                        "description":"path relative to the repo root, or an absolute host path"
                    },
                    "offset":{
                        "type":"integer",
                        "minimum":1,
                        "description":"optional 1-based first line to return; defaults to 1"
                    },
                    "limit":{
                        "type":"integer",
                        "minimum":1,
                        "description":"optional maximum number of lines to return; the pinned runtime output-byte cap still applies"
                    }
                },
                "required":["path"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let policy = read_policy.get().copied();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = policy else {
                    return err_result(id, "read_file: runtime policy was not installed".into());
                };
                let path = call
                    .input
                    .get("path")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let window = match ReadWindow::from_input(&call.input) {
                    Ok(window) => window,
                    Err(error) => return err_result(id, error),
                };
                match resolve_in_root(&root, path) {
                    Err(e) => err_result(id, e),
                    Ok(p) => match read_numbered_file(&p, window, policy.read_file).await {
                        Ok(content) => ok_result(id, content),
                        Err(e) => err_result(id, format!("read {path}: {e}")),
                    },
                }
            })
        },
    )?;

    let list_policy = r.observation_tool_policy_handle();
    r.push_tool(
        ToolSpec {
            name: "list_dir".into(),
            description: "List files under a directory, skipping .git and common build/vendor \
                          dirs. `path` may be relative to the repo root or an absolute host path. \
                          Returns one path per line: relative when the file is under the repo \
                          root, absolute when it is not."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"path":{"type":"string","description":"dir relative to the repo root, or an absolute host path; default '.'"}},
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let policy = list_policy.get().copied();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = policy else {
                    return err_result(id, "list_dir: runtime policy was not installed".into());
                };
                let rel = call.input.get("path").and_then(|x| x.as_str()).unwrap_or(".");
                match resolve_in_root(&root, rel) {
                    Err(e) => err_result(id, e),
                    Ok(base) => {
                        let mut out = Vec::new();
                        let mut output_bytes = 0usize;
                        let mut emitted_entries = 0usize;
                        for entry in WalkDir::new(&base)
                            .max_depth(policy.list_dir.max_depth)
                            .into_iter()
                            .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
                            .flatten()
                        {
                            if entry.file_type().is_file() {
                                if emitted_entries >= policy.list_dir.max_entries {
                                    append_bounded_marker(
                                        &mut out,
                                        policy.list_dir.output_max_bytes,
                                        format!(
                                            "… (truncated at {} entries; narrow the path)",
                                            policy.list_dir.max_entries
                                        ),
                                    );
                                    break;
                                }
                                let line = crate::display_path(&root, entry.path());
                                let framed = line.len().saturating_add(usize::from(!out.is_empty()));
                                if output_bytes.saturating_add(framed)
                                    > policy.list_dir.output_max_bytes
                                {
                                    append_bounded_marker(
                                        &mut out,
                                        policy.list_dir.output_max_bytes,
                                        "… (truncated at the pinned output-byte ceiling)".into(),
                                    );
                                    break;
                                }
                                output_bytes = output_bytes.saturating_add(framed);
                                out.push(line);
                                emitted_entries = emitted_entries.saturating_add(1);
                            }
                        }
                        ok_result(id, out.join("\n"))
                    }
                }
            })
        },
    )?;

    let glob_policy = r.observation_tool_policy_handle();
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
        move |call, root| {
            let policy = glob_policy.get().copied();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = policy else {
                    return err_result(id, "glob: runtime policy was not installed".into());
                };
                let Some(pattern) = call.input.get("pattern").and_then(|x| x.as_str()) else {
                    return err_result(id, "glob: a `pattern` is required".into());
                };
                let mut out = Vec::new();
                let mut output_bytes = 0usize;
                let mut emitted_results = 0usize;
                for entry in WalkDir::new(&root)
                    .max_depth(policy.glob.max_depth)
                    .into_iter()
                    .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
                    .flatten()
                {
                    if entry.file_type().is_file()
                        && let Ok(p) = entry.path().strip_prefix(&root)
                    {
                        let rel = p.to_string_lossy().replace('\\', "/");
                        if glob_match(pattern, &rel) {
                            if emitted_results >= policy.glob.max_results {
                                append_bounded_marker(
                                    &mut out,
                                    policy.glob.output_max_bytes,
                                    format!(
                                        "… (truncated at {} matches; narrow the pattern)",
                                        policy.glob.max_results
                                    ),
                                );
                                break;
                            }
                            let framed = rel.len().saturating_add(usize::from(!out.is_empty()));
                            if output_bytes.saturating_add(framed) > policy.glob.output_max_bytes {
                                append_bounded_marker(
                                    &mut out,
                                    policy.glob.output_max_bytes,
                                    "… (truncated at the pinned output-byte ceiling)".into(),
                                );
                                break;
                            }
                            output_bytes = output_bytes.saturating_add(framed);
                            out.push(rel);
                            emitted_results = emitted_results.saturating_add(1);
                        }
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
    let repo_map_policy = r.observation_tool_policy_handle();
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
        move |call, root| {
            let policy = repo_map_policy.get().copied();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = policy else {
                    return err_result(id, "repo_map: runtime policy was not installed".into());
                };
                // Budget the map so it never dominates the window (late materialization).
                let query = call
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let map = iteron_ctx::repo_outline_for_task_with_limits(
                    &root,
                    policy.repo_map.max_files,
                    policy.repo_map.max_depth,
                    policy.repo_map.max_tokens,
                    query,
                );
                ok_result(id, map)
            })
        },
    )
}

#[cfg(test)]
#[path = "fs_tools_tests.rs"]
mod tests;

//! Pure/ReadOnly tools: read_file, list_dir, grep. These are the tools the scheduler may
//! dispatch early (at content_block_stop) because they have no observable effect.

use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use core_protocol::{Capability, Purity, ToolSpec};
use walkdir::WalkDir;

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    register_outline(r)?;
    r.push_tool(
        ToolSpec {
            name: "read_file".into(),
            description: "Read a UTF-8 text file relative to the workspace root. Returns the \
                          content with 1-based line numbers so edits can reference exact lines."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"path":{"type":"string","description":"path relative to the repo root"}},
                "required":["path"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let path = call.input.get("path").and_then(|x| x.as_str()).unwrap_or("");
                match resolve_in_root(&root, path) {
                    Err(e) => err_result(id, e),
                    Ok(p) => match tokio::fs::read_to_string(&p).await {
                        Ok(s) => {
                            let numbered: String = s
                                .lines()
                                .enumerate()
                                .map(|(i, l)| format!("{:>6}\t{}", i + 1, l))
                                .collect::<Vec<_>>()
                                .join("\n");
                            // Cap output so a huge file can't blow the context window; UTF-8-safe.
                            let bounded = core_protocol::text::elide_middle(&numbered, 40_000);
                            ok_result(id, if bounded.is_empty() { "(empty file)".into() } else { bounded })
                        }
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

    r.push_tool(
        ToolSpec {
            name: "grep".into(),
            description: "Search file contents for a substring under the repo root. Returns \
                          matching `path:line: text`, capped. Prefer this over reading whole \
                          files (push the filter into the tool)."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "pattern":{"type":"string"},
                    "path":{"type":"string","description":"subtree relative to repo root; default '.'"}
                },
                "required":["pattern"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let pat = call.input.get("pattern").and_then(|x| x.as_str()).unwrap_or("");
                let rel = call.input.get("path").and_then(|x| x.as_str()).unwrap_or(".");
                if pat.is_empty() {
                    return err_result(id, "empty pattern".into());
                }
                let base = match resolve_in_root(&root, rel) {
                    Ok(b) => b,
                    Err(e) => return err_result(id, e),
                };
                let mut hits = Vec::new();
                for entry in WalkDir::new(&base)
                    .max_depth(8)
                    .into_iter()
                    .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or("")))
                    .flatten()
                {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                        let rel_path = entry
                            .path()
                            .strip_prefix(&root)
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        for (i, line) in content.lines().enumerate() {
                            if line.contains(pat) {
                                hits.push(format!("{}:{}: {}", rel_path, i + 1, line.trim()));
                                if hits.len() >= 100 {
                                    hits.push("… (100+ matches; narrow the search)".into());
                                    return ok_result(id, hits.join("\n"));
                                }
                            }
                        }
                    }
                }
                ok_result(id, if hits.is_empty() { format!("no matches for `{pat}`") } else { hits.join("\n") })
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
                          actually need."
                .into(),
            input_schema: serde_json::json!({"type":"object","properties":{}}),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                // Budget the map so it never dominates the window (late materialization).
                let map = core_ctx::repo_outline(&root, 6_000);
                ok_result(id, map)
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn glob_matches_segments_and_globstar() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "src/main.rs")); // `*` never crosses a `/`
        assert!(glob_match("src/*.rs", "src/main.rs"));
        assert!(!glob_match("src/*.rs", "src/a/b.rs"));
        assert!(glob_match("**/*.rs", "a/b/c.rs"));
        assert!(glob_match("**/*.rs", "c.rs")); // `**` matches zero segments
        assert!(glob_match("src/**/*.rs", "src/a/b.rs"));
        assert!(glob_match("src/**/*.rs", "src/b.rs"));
        assert!(!glob_match("src/**/*.rs", "lib/b.rs"));
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
        assert!(glob_match("**", "any/thing/here"));
        assert!(glob_match("Cargo.toml", "Cargo.toml"));
        assert!(!glob_match("Cargo.toml", "crates/Cargo.toml"));
    }
}

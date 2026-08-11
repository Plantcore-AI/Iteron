//! Bounded, ignore-aware repository search.

use crate::{
    Registry, ToolError, boxfut, edit::suspicious_unicode, err_result, ok_result, resolve_in_root,
};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use iteron_protocol::{Capability, Purity, ToolSpec};
use regex::{Regex, RegexBuilder};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_GREP_PATTERN_BYTES: usize = 4 * 1024;
const MAX_GREP_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_GREP_TOTAL_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_GREP_ENTRIES: usize = 50_000;
/// Owner-directed 2026-08-05: 100 matches was below the size of an ordinary answer ("every call
/// site of X" in this workspace routinely exceeds it), so the cap was reached on searches whose
/// results were then silently incomplete. Raised an order of magnitude; still bounded.
const GREP_NOTICE_RESERVE_BYTES: usize = 1_024;
const MAX_REGEX_COMPILED_BYTES: usize = 1024 * 1024;
const MAX_GITIGNORE_FILES: usize = 128;
const MAX_GITIGNORE_FILE_BYTES: usize = 64 * 1024;
const MAX_GITIGNORE_TOTAL_BYTES: usize = 256 * 1024;
const MAX_GITIGNORE_PATTERNS: usize = 4_096;

enum Matcher {
    Literal(String),
    Regex(Regex),
}

impl Matcher {
    fn compile(pattern: &str, regex: bool) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("grep: `pattern` must not be empty".into());
        }
        if pattern.len() > MAX_GREP_PATTERN_BYTES {
            return Err(format!(
                "grep: pattern exceeds the {MAX_GREP_PATTERN_BYTES}-byte limit"
            ));
        }
        if suspicious_unicode(pattern).is_some() {
            return Err("grep: pattern contains bidi or zero-width control characters".into());
        }
        if !regex {
            return Ok(Self::Literal(pattern.to_owned()));
        }
        RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_COMPILED_BYTES)
            .dfa_size_limit(MAX_REGEX_COMPILED_BYTES)
            .build()
            .map(Self::Regex)
            .map_err(|error| format!("grep: invalid or oversized regex: {error}"))
    }

    fn is_match(&self, line: &str) -> bool {
        match self {
            Self::Literal(pattern) => line.contains(pattern),
            Self::Regex(pattern) => pattern.is_match(line),
        }
    }
}

#[derive(Default)]
struct SearchResult {
    hits: Vec<String>,
    hit_bytes: usize,
    skipped_files: usize,
    skipped_for_budget: usize,
    walk_errors: usize,
    traversal_limited: bool,
    results_capped: bool,
}

impl SearchResult {
    fn push_hit(&mut self, hit: String, policy: crate::GrepPolicy) -> bool {
        let added = hit.len().saturating_add(usize::from(!self.hits.is_empty()));
        if self.hits.len() >= policy.max_matches
            || self.hit_bytes.saturating_add(added)
                > policy
                    .output_max_bytes
                    .saturating_sub(GREP_NOTICE_RESERVE_BYTES)
        {
            self.results_capped = true;
            return false;
        }
        self.hit_bytes += added;
        self.hits.push(hit);
        true
    }

    fn render(self, pattern: &str, policy: crate::GrepPolicy) -> String {
        let mut output = if self.hits.is_empty() {
            format!("no matches for `{pattern}`")
        } else {
            self.hits.join("\n")
        };
        if self.results_capped {
            output.push_str(&format!(
                "\n[results capped at {} matches / {} output bytes; narrow the search]",
                policy.max_matches, policy.output_max_bytes
            ));
        }
        if self.skipped_files > 0 {
            output.push_str(&format!(
                "\n[{} files skipped as binary, unsafe, unreadable, symlinked, or over the {MAX_GREP_FILE_BYTES}-byte per-file limit]",
                self.skipped_files
            ));
        }
        if self.skipped_for_budget > 0 {
            output.push_str(&format!(
                "\n[{} files skipped after the {MAX_GREP_TOTAL_SOURCE_BYTES}-byte total source budget]",
                self.skipped_for_budget
            ));
        }
        if self.walk_errors > 0 {
            output.push_str(&format!(
                "\n[{} repository entries could not be inspected]",
                self.walk_errors
            ));
        }
        if self.traversal_limited {
            output.push_str(&format!(
                "\n[repository traversal stopped at the {MAX_GREP_ENTRIES}-entry limit]"
            ));
        }
        if output.len() > policy.output_max_bytes {
            iteron_protocol::text::head(&output, policy.output_max_bytes)
        } else {
            output
        }
    }
}

#[derive(Default)]
struct IgnoreRules {
    rules: Vec<(PathBuf, Gitignore)>,
}

impl IgnoreRules {
    fn push(&mut self, root: PathBuf, matcher: Gitignore) {
        self.rules.push((root, matcher));
        self.rules.sort_by(|(left, _), (right, _)| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then(left.cmp(right))
        });
    }

    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for (root, matcher) in &self.rules {
            if !path.starts_with(root) {
                continue;
            }
            let matched = matcher.matched_path_or_any_parents(path, is_dir);
            if matched.is_ignore() {
                ignored = true;
            } else if matched.is_whitelist() {
                ignored = false;
            }
        }
        ignored
    }
}

struct IgnoreBudget {
    files: usize,
    bytes: usize,
    patterns: usize,
}

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    let policy_cell = registry.observation_tool_policy_handle();
    registry.push_tool(
        ToolSpec {
            name: "grep".into(),
            description: "Search bounded UTF-8 files while respecting .gitignore. `path` may be \
                          relative to the repo root or an absolute host path. Literal matching is \
                          the backward-compatible default; set `regex=true` for a Rust regular \
                          expression. Returns `path:line: text` with absolute 1-based line \
                          numbers, the path relative when it is under the repo root and absolute \
                          when it is not. File, traversal, source-byte, match, and output limits \
                          are always disclosed."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "pattern":{"type":"string"},
                    "path":{"type":"string","description":"subtree relative to the repo root, or an absolute host path; default '.'"},
                    "regex":{"type":"boolean","description":"interpret pattern as a Rust regex; default false"}
                },
                "required":["pattern"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let policy_cell = policy_cell.clone();
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(policy) = policy_cell.get().copied().map(|policy| policy.grep) else {
                    return err_result(
                        id,
                        "grep refused: immutable observation-tool policy was not installed".into(),
                    );
                };
                let pattern = call
                    .input
                    .get("pattern")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let matcher = match Matcher::compile(
                    pattern,
                    call.input
                        .get("regex")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                ) {
                    Ok(matcher) => matcher,
                    Err(error) => return err_result(id, error),
                };
                let relative = call
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(".");
                let base = match resolve_in_root(&root, relative) {
                    Ok(base) => base,
                    Err(error) => return err_result(id, error),
                };
                let pattern = pattern.to_owned();
                match tokio::task::spawn_blocking(move || search(&root, &base, &matcher, policy))
                    .await
                {
                    Ok(Ok(result)) => ok_result(id, result.render(&pattern, policy)),
                    Ok(Err(error)) => err_result(id, error),
                    Err(error) => err_result(id, format!("grep worker failed: {error}")),
                }
            })
        },
    )
}

fn search(
    root: &Path,
    base: &Path,
    matcher: &Matcher,
    policy: crate::GrepPolicy,
) -> Result<SearchResult, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("grep cannot canonicalize workspace root: {error}"))?;
    let mut result = SearchResult::default();
    let mut paths = Vec::new();
    let root_ignore = root.join(".gitignore");
    let mut ignore_budget = IgnoreBudget {
        files: 0,
        bytes: 0,
        patterns: 0,
    };
    let mut ignore_rules = IgnoreRules::default();
    if let Some((rule_root, matcher)) = load_ignore(&root, &root_ignore, &mut ignore_budget)? {
        ignore_rules.push(rule_root, matcher);
    }
    let mut nested_ignores = Vec::new();

    {
        let walker = WalkDir::new(base)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                entry.depth() == 0
                    || (!is_default_ignored(entry.file_name().to_str().unwrap_or(""))
                        && !ignore_rules.is_ignored(entry.path(), entry.file_type().is_dir()))
            });
        for (entry_index, entry) in walker.enumerate() {
            if entry_index == MAX_GREP_ENTRIES {
                result.traversal_limited = true;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    result.walk_errors = result.walk_errors.saturating_add(1);
                    continue;
                }
            };
            if entry.file_type().is_file() {
                if entry.file_name() == ".gitignore" && entry.path() != root_ignore {
                    nested_ignores.push(entry.path().to_path_buf());
                }
                paths.push(entry.into_path());
            }
        }
    }
    nested_ignores.sort();
    nested_ignores.dedup();
    for ignore_path in nested_ignores {
        if let Some((rule_root, matcher)) = load_ignore(&root, &ignore_path, &mut ignore_budget)? {
            ignore_rules.push(rule_root, matcher);
        }
    }
    paths.retain(|path| !ignore_rules.is_ignored(path, false));
    paths.sort();

    let mut source_bytes = 0usize;
    'files: for path in paths {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) | Err(_) => {
                result.skipped_files = result.skipped_files.saturating_add(1);
                continue;
            }
        };
        let file_bytes = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if file_bytes > MAX_GREP_FILE_BYTES {
            result.skipped_files = result.skipped_files.saturating_add(1);
            continue;
        }
        let remaining = MAX_GREP_TOTAL_SOURCE_BYTES.saturating_sub(source_bytes);
        if file_bytes > remaining || remaining == 0 {
            result.skipped_for_budget = result.skipped_for_budget.saturating_add(1);
            continue;
        }
        // Repository scope keeps the hardening that repo-controlled content needs — containment
        // under the root and `O_NOFOLLOW` — and it is what every in-workspace hit still uses. A
        // file the operator reached by naming a path outside the workspace cannot pass that check
        // by construction, and silently counting it as "skipped as binary or unreadable" was a
        // wrong answer dressed as a bounded one. Such a file is operator-owned content, which is
        // exactly what `User` scope is for.
        let scope = if path.starts_with(&root) {
            iteron_ctx::source::SourceScope::Repository
        } else {
            iteron_ctx::source::SourceScope::User
        };
        let content = match iteron_ctx::source::read_bounded_utf8(
            &root,
            &path,
            remaining.min(MAX_GREP_FILE_BYTES),
            scope,
        ) {
            Ok(Some(content)) => content,
            Ok(None) | Err(_) => {
                result.skipped_files = result.skipped_files.saturating_add(1);
                continue;
            }
        };
        if content.as_bytes().contains(&0) || suspicious_unicode(&content).is_some() {
            result.skipped_files = result.skipped_files.saturating_add(1);
            continue;
        }
        source_bytes = source_bytes.saturating_add(content.len());
        let relative = crate::display_path(&root, &path);
        if suspicious_unicode(&relative).is_some() {
            result.skipped_files = result.skipped_files.saturating_add(1);
            continue;
        }
        for (line_index, line) in content.lines().enumerate() {
            if !matcher.is_match(line) {
                continue;
            }
            let snippet = iteron_protocol::text::head(line.trim(), policy.snippet_max_bytes);
            let hit = format!("{}:{}: {snippet}", relative, line_index + 1);
            if !result.push_hit(hit, policy) {
                break 'files;
            }
        }
    }
    Ok(result)
}

fn load_ignore(
    workspace_root: &Path,
    path: &Path,
    budget: &mut IgnoreBudget,
) -> Result<Option<(PathBuf, Gitignore)>, String> {
    if budget.files >= MAX_GITIGNORE_FILES {
        return Err(format!(
            "grep: repository exceeds the {MAX_GITIGNORE_FILES}-file .gitignore limit"
        ));
    }
    let remaining = MAX_GITIGNORE_TOTAL_BYTES.saturating_sub(budget.bytes);
    if remaining == 0 {
        return Err(format!(
            "grep: .gitignore sources exceed the {MAX_GITIGNORE_TOTAL_BYTES}-byte total limit"
        ));
    }
    let content = match iteron_ctx::source::read_bounded_utf8(
        workspace_root,
        path,
        remaining.min(MAX_GITIGNORE_FILE_BYTES),
        iteron_ctx::source::SourceScope::Repository,
    ) {
        Ok(Some(content)) => content,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "grep cannot safely read .gitignore: {}",
                error.reason()
            ));
        }
    };
    if suspicious_unicode(&content).is_some() {
        return Err("grep: .gitignore contains bidi or zero-width control characters".into());
    }
    budget.files += 1;
    budget.bytes = budget.bytes.saturating_add(content.len());
    let rule_root = path
        .parent()
        .ok_or_else(|| "grep: .gitignore has no parent directory".to_string())?
        .to_path_buf();
    let mut builder = GitignoreBuilder::new(&rule_root);
    for (line_index, line) in content.lines().enumerate() {
        budget.patterns = budget.patterns.saturating_add(1);
        if budget.patterns > MAX_GITIGNORE_PATTERNS {
            return Err(format!(
                "grep: .gitignore sources exceed the {MAX_GITIGNORE_PATTERNS}-line limit"
            ));
        }
        let line = if line_index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        builder
            .add_line(Some(path.to_path_buf()), line)
            .map_err(|error| format!("grep: invalid .gitignore pattern: {error}"))?;
    }
    let matcher = builder
        .build()
        .map_err(|error| format!("grep: cannot compile bounded .gitignore rules: {error}"))?;
    Ok(Some((rule_root, matcher)))
}

fn is_default_ignored(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | "__pycache__"
            | ".iteron"
    )
}

#[cfg(test)]
#[path = "grep_tool_tests.rs"]
mod tests;

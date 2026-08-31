//! Bounded, ignore-aware repository search.

use crate::{
    Registry, ToolError, boxfut, edit::suspicious_unicode, err_result, ok_result,
    resolve_from_canonical_root,
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
/// Context is caller-selected and remains bounded independently from match and output limits.
const MAX_GREP_CONTEXT_LINES: usize = 64;
/// Multi-term proximity is a relevance control, not another unbounded repository scan.
const MAX_GREP_RELATED_TERMS: usize = 8;
const DEFAULT_GREP_PROXIMITY_LINES: usize = 64;
const MAX_GREP_PROXIMITY_LINES: usize = 512;
const EXACT_FOCUS_PATH_RELEVANCE: u64 = 1_u64 << 48;
const MAX_GREP_INCOMPLETE_PATH_HINTS: usize = 8;

fn exact_focus_path_relevance() -> u64 {
    iteron_tunables::param_u64(
        "tools.grep_tool.exact_focus_path_relevance",
        EXACT_FOCUS_PATH_RELEVANCE,
    )
}

fn max_grep_incomplete_path_hints() -> usize {
    iteron_tunables::param_usize(
        "tools.grep_tool.max_grep_incomplete_path_hints",
        MAX_GREP_INCOMPLETE_PATH_HINTS,
    )
}
/// File bodies are the expensive part of grep. Keep traversal and ignore resolution ordered, then
/// fan only the already-bounded body reads across a small fixed worker set. The hard ceiling is
/// intentionally not tunable: a bad profile must not turn one tool call into a thread bomb.
const DEFAULT_GREP_PARALLELISM: usize = 8;
const MAX_GREP_PARALLELISM: usize = 32;
/// Owner-directed 2026-08-05: 100 matches was below the size of an ordinary answer ("every call
/// site of X" in this workspace routinely exceeds it), so the cap was reached on searches whose
/// results were then silently incomplete. Raised an order of magnitude; still bounded.
const GREP_NOTICE_RESERVE_BYTES: usize = 1_024;
const MAX_REGEX_COMPILED_BYTES: usize = 1024 * 1024;
const MAX_GITIGNORE_FILES: usize = 128;
const MAX_GITIGNORE_FILE_BYTES: usize = 64 * 1024;
const MAX_GITIGNORE_TOTAL_BYTES: usize = 256 * 1024;
const MAX_GITIGNORE_PATTERNS: usize = 4_096;
/// Owner override for calls that omit `regex`. When false, omitted calls use conservative regex
/// intent detection; when true, every omitted call uses regex mode. Explicit call values win.
const DEFAULT_GREP_REGEX_MODE: bool = false;

#[derive(Clone)]
enum Matcher {
    Literal(String),
    Regex(Regex),
}

#[derive(Default)]
struct FileSearchResult {
    hits: Vec<SearchHit>,
    skipped: bool,
}

struct SearchHit {
    rendered: String,
    structural_rendered: Option<String>,
    evidence_facet: EvidenceFacet,
    evidence_start: usize,
    evidence_end: usize,
    focused_path: bool,
    relevance: u64,
    path: String,
    line: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceFacet {
    Definition,
    CallEdge,
    Schema,
    Test,
    Sibling,
}

impl EvidenceFacet {
    const fn label(self) -> &'static str {
        match self {
            Self::Definition => "definition",
            Self::CallEdge => "caller/callee",
            Self::Schema => "schema",
            Self::Test => "test",
            Self::Sibling => "sibling/usage",
        }
    }
}

impl Matcher {
    fn compile(pattern: &str, regex: bool) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("grep: `pattern` must not be empty".into());
        }
        let max_pattern_bytes = iteron_tunables::param_usize(
            "tools.grep_tool.max_grep_pattern_bytes",
            iteron_tunables::param_integer(
                "tools.grep_tool.max_grep_pattern_bytes",
                MAX_GREP_PATTERN_BYTES,
            ),
        );
        if pattern.len() > max_pattern_bytes {
            return Err(format!(
                "grep: pattern exceeds the {max_pattern_bytes}-byte limit"
            ));
        }
        if suspicious_unicode(pattern).is_some() {
            return Err("grep: pattern contains bidi or zero-width control characters".into());
        }
        if !regex {
            return Ok(Self::Literal(pattern.to_owned()));
        }
        let max_regex_compiled_bytes = iteron_tunables::param_usize(
            "tools.grep_tool.max_regex_compiled_bytes",
            iteron_tunables::param_integer(
                "tools.grep_tool.max_regex_compiled_bytes",
                MAX_REGEX_COMPILED_BYTES,
            ),
        );
        RegexBuilder::new(pattern)
            .size_limit(max_regex_compiled_bytes)
            .dfa_size_limit(max_regex_compiled_bytes)
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

fn regex_mode(pattern: &str, requested: Option<bool>) -> bool {
    requested.unwrap_or_else(|| {
        iteron_tunables::param_bool(
            "tools.grep_tool.default_grep_regex_mode",
            DEFAULT_GREP_REGEX_MODE,
        ) || has_common_regex_intent(pattern)
    })
}

fn has_common_regex_intent(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut escaped = false;
    let mut in_brackets = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            if matches!(byte, b'b' | b'B' | b'd' | b'D' | b's' | b'S' | b'w' | b'W') {
                return true;
            }
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'[' => in_brackets = true,
            b']' => in_brackets = false,
            b'|' if !in_brackets => return true,
            b'^' if index == 0 => return true,
            b'$' if index + 1 == bytes.len() => return true,
            _ => {}
        }
    }
    false
}

#[derive(Default)]
struct SearchResult {
    hits: Vec<SearchHit>,
    skipped_files: usize,
    skipped_for_budget: usize,
    eligible_files: usize,
    eligible_bytes: usize,
    admitted_files: usize,
    admitted_bytes: usize,
    incomplete_paths: Vec<String>,
    incomplete_strata: usize,
    incomplete_paths_truncated: bool,
    walk_errors: usize,
    traversal_limited: bool,
    results_capped: bool,
}

impl SearchResult {
    fn push_hit(&mut self, hit: SearchHit, policy: crate::GrepPolicy) {
        let retained_limit = policy.max_matches.saturating_add(1);
        if self.hits.len() < retained_limit {
            self.hits.push(hit);
            return;
        }
        self.results_capped = true;
        let Some((worst_index, worst)) = self
            .hits
            .iter()
            .enumerate()
            .min_by(|(_, left), (_, right)| compare_search_hits(left, right))
        else {
            return;
        };
        if compare_search_hits(&hit, worst).is_gt() {
            self.hits[worst_index] = hit;
        }
    }

    fn render(
        mut self,
        pattern: &str,
        policy: crate::GrepPolicy,
        related_terms: &[(String, Matcher)],
        proximity_lines: usize,
        evidence_comparison: bool,
        explicitly_narrowed_scope: bool,
    ) -> String {
        let corpus_incomplete = self.skipped_files > 0
            || self.skipped_for_budget > 0
            || self.walk_errors > 0
            || self.traversal_limited;
        self.hits
            .sort_by(|left, right| compare_search_hits(right, left));
        if self.hits.len() > policy.max_matches {
            self.hits.truncate(policy.max_matches);
            self.results_capped = true;
        }
        // A model need not use one privileged localization tool. An explicit workspace subpath is
        // also a provable narrowing step when the actual published result remains within the same
        // small file-set bound as the exact-read working set. This promotion is deliberately local
        // to this call: a later repository-wide grep cannot inherit it and masquerade as focused.
        if explicitly_narrowed_scope {
            let files = self
                .hits
                .iter()
                .map(|hit| hit.path.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if !files.is_empty() && files.len() <= crate::MAX_OBSERVATION_FOCUS_FILES {
                for hit in &mut self.hits {
                    hit.focused_path = true;
                }
            }
        }
        let evidence_summary = evidence_comparison.then(|| EvidenceSummary::from_hits(&self.hits));
        let preferred_structural_hits = preferred_structural_hits(&self.hits);
        let output_budget = policy
            .output_max_bytes
            .saturating_sub(iteron_tunables::param_integer(
                "tools.grep_tool.grep_notice_reserve_bytes",
                GREP_NOTICE_RESERVE_BYTES,
            ));
        // Enclosing blocks are high-signal but much more expensive than one-line hits. Spend at
        // most one quarter of the already-installed output budget on expansion, then keep the
        // remaining matches compact. This preserves both contract context and cross-repository
        // breadth without introducing another absolute/provider-specific token constant.
        let structural_budget = output_budget / 4;
        let mut rendered_hits = Vec::new();
        let mut rendered_bytes = 0usize;
        let mut structural_bytes = 0usize;
        for hit in self.hits {
            let rendered = hit
                .structural_rendered
                .as_deref()
                .filter(|structural| {
                    if !preferred_structural_hits
                        .iter()
                        .any(|(path, line)| path == &hit.path && *line == hit.line)
                    {
                        return false;
                    }
                    let separator = usize::from(!rendered_hits.is_empty());
                    let added = structural.len().saturating_add(separator);
                    structural_bytes.saturating_add(added) <= structural_budget
                        && rendered_bytes.saturating_add(added) <= output_budget
                })
                .unwrap_or(&hit.rendered);
            let added = rendered
                .len()
                .saturating_add(usize::from(!rendered_hits.is_empty()));
            if rendered_bytes.saturating_add(added) > output_budget {
                self.results_capped = true;
                break;
            }
            rendered_bytes = rendered_bytes.saturating_add(added);
            if hit
                .structural_rendered
                .as_deref()
                .is_some_and(|structural| std::ptr::eq(structural, rendered))
            {
                structural_bytes = structural_bytes.saturating_add(added);
            }
            rendered_hits.push(rendered.to_owned());
        }
        let mut output = if rendered_hits.is_empty() {
            if corpus_incomplete && related_terms.is_empty() {
                format!("no matches for `{pattern}` in the admitted corpus")
            } else if corpus_incomplete {
                format!(
                    "no matches for `{pattern}` within {proximity_lines} lines of every related term in the admitted corpus"
                )
            } else if related_terms.is_empty() {
                format!("no matches for `{pattern}`")
            } else {
                format!(
                    "no matches for `{pattern}` within {proximity_lines} lines of every related term"
                )
            }
        } else {
            rendered_hits.join("\n")
        };
        if let Some(summary) = evidence_summary {
            output.insert_str(
                0,
                &format!(
                    "{}\n",
                    summary.render(corpus_incomplete, !related_terms.is_empty())
                ),
            );
        }
        if !related_terms.is_empty() {
            output.push_str(&format!(
                concat!(
                    "\n[contrast note: `related_terms` filter out contexts that omit `{pattern}`; ",
                    "compare the stable definition, symbol, behavior, schema, sibling, or test ",
                    "without hiding the competing hypothesis]"
                ),
                pattern = pattern
            ));
        }
        if self.results_capped {
            output.push_str(&format!(
                "\n[results capped at {} matches / {} output bytes; narrow the search]",
                policy.max_matches, policy.output_max_bytes
            ));
        }
        output.push_str(&format!(
            "\n[corpus coverage: eligible_files={}; admitted_files={}; eligible_bytes={}; admitted_bytes={}]",
            self.eligible_files, self.admitted_files, self.eligible_bytes, self.admitted_bytes
        ));
        if let Some(first) = self.incomplete_paths.first() {
            let paths = self
                .incomplete_paths
                .iter()
                .map(|path| serde_json::to_string(path).unwrap_or_else(|_| "\"?\"".into()))
                .collect::<Vec<_>>()
                .join(",");
            let first = serde_json::to_string(first).unwrap_or_else(|_| "\"?\"".into());
            output.push_str(&format!(
                "\n[corpus incomplete: incomplete_paths={paths}; incomplete_strata={}; paths_truncated={}; repeat same grep with path={first}]",
                self.incomplete_strata, self.incomplete_paths_truncated
            ));
        } else if corpus_incomplete {
            output.push_str(
                "\n[corpus incomplete: incomplete_paths=unavailable; repeat same grep with a narrower explicit path]",
            );
        }
        if self.skipped_files > 0 {
            output.push_str(&format!(
                "\n[{} files skipped as binary, unsafe, unreadable, symlinked, or over the {}-byte per-file limit]",
                self.skipped_files,
                iteron_tunables::param_usize(
                    "tools.grep_tool.max_grep_file_bytes",
                    MAX_GREP_FILE_BYTES
                )
            ));
        }
        if self.skipped_for_budget > 0 {
            output.push_str(&format!(
                "\n[{} files skipped after the {}-byte total source budget]",
                self.skipped_for_budget,
                iteron_tunables::param_usize(
                    "tools.grep_tool.max_grep_total_source_bytes",
                    iteron_tunables::param_integer(
                        "tools.grep_tool.max_grep_total_source_bytes",
                        MAX_GREP_TOTAL_SOURCE_BYTES
                    )
                )
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
                "\n[repository traversal stopped at the {}-entry limit]",
                iteron_tunables::param_usize("tools.grep_tool.max_grep_entries", MAX_GREP_ENTRIES)
            ));
        }
        if output.len() > policy.output_max_bytes {
            iteron_protocol::text::head(&output, policy.output_max_bytes)
        } else {
            output
        }
    }
}

struct EvidenceSummary {
    contexts: usize,
    files: usize,
    facets: Vec<EvidenceFacet>,
    focused: usize,
}

impl EvidenceSummary {
    fn from_hits(hits: &[SearchHit]) -> Self {
        let contexts = hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.evidence_start, hit.evidence_end))
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let files = hits
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let facets = hits
            .iter()
            .map(|hit| hit.evidence_facet)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let focused = hits.iter().filter(|hit| hit.focused_path).count();
        Self {
            contexts,
            files,
            facets,
            focused,
        }
    }

    fn render(&self, corpus_incomplete: bool, explicit_relation_filter: bool) -> String {
        let facets = self
            .facets
            .iter()
            .map(|facet| facet.label())
            .collect::<Vec<_>>()
            .join(",");
        // Lexical co-occurrence is useful observation but never causal authority. Even a focused
        // cross-file/cross-facet result with an explicit relation filter can repeat the same wrong
        // interpretation. Only `submit_repair_evidence` can reopen role-labelled exact spans and
        // issue a positive receipt, so grep always emits neutral typed insufficiency metadata.
        let source_anchors_now_useful = explicit_relation_filter
            && (self.files >= 2 || (self.files == 1 && self.facets.len() >= 2));
        let (reason, remediation) = if self.contexts == 0 && corpus_incomplete {
            ("coverage_incomplete", "repeat_same_grep_with_narrow_path")
        } else if self.contexts == 0 {
            ("no_match", "choose_related_bounded_path_or_anchor")
        } else if self.focused == 0 {
            (
                "no_focused_context",
                "rerun_with_explicit_narrow_path_or_read_exact_file",
            )
        } else if self.contexts == 1 {
            (
                "single_context",
                "add_one_bounded_definition_caller_schema_test_or_sibling",
            )
        } else if source_anchors_now_useful {
            (
                "source_anchors_required",
                "submit_role_labelled_exact_source_spans",
            )
        } else if !explicit_relation_filter {
            (
                "causal_contrast_unproven",
                "add_related_terms_or_submit_existing_exact_source_spans",
            )
        } else {
            (
                "undifferentiated_contexts",
                "add_one_bounded_contrasting_facet_or_file",
            )
        };
        format!(
            "{} reason={reason}; remediation={remediation}; contexts={}; files={}; focused={}; facets={}]",
            crate::WORKSPACE_EVIDENCE_INSUFFICIENT_MARKER,
            self.contexts,
            self.files,
            self.focused,
            facets
        )
    }
}

fn preferred_structural_hits(hits: &[SearchHit]) -> Vec<(String, usize)> {
    let mut selected = hits
        .iter()
        .filter(|hit| hit.focused_path && hit.structural_rendered.is_some())
        .map(|hit| (hit.path.clone(), hit.line))
        .collect::<Vec<_>>();
    let mut alternatives = hits
        .iter()
        .filter(|hit| !hit.focused_path && hit.structural_rendered.is_some())
        .collect::<Vec<_>>();
    alternatives.sort_by(|left, right| {
        right
            .relevance
            .cmp(&left.relevance)
            .then(left.path.cmp(&right.path))
            .then(left.line.cmp(&right.line))
    });
    selected.extend(
        alternatives
            .into_iter()
            .take(3)
            .map(|hit| (hit.path.clone(), hit.line)),
    );
    selected
}

fn compare_search_hits(left: &SearchHit, right: &SearchHit) -> std::cmp::Ordering {
    left.relevance
        .cmp(&right.relevance)
        .then_with(|| right.path.cmp(&left.path))
        .then_with(|| right.line.cmp(&left.line))
}

fn classify_evidence_facet(
    path: &str,
    match_line: &str,
    lines: &[&str],
    start: usize,
    end: usize,
) -> EvidenceFacet {
    let lower_path = path.to_ascii_lowercase();
    if lower_path
        .split(['/', '\\', '.', '-', '_'])
        .any(|part| matches!(part, "test" | "tests" | "spec" | "specs"))
    {
        return EvidenceFacet::Test;
    }
    if lower_path.contains("schema")
        || lines[start.min(lines.len())..end.min(lines.len())]
            .iter()
            .any(|line| {
                [
                    "interface ",
                    "type ",
                    "struct ",
                    "enum ",
                    "trait ",
                    "message ",
                ]
                .iter()
                .any(|keyword| line.contains(keyword))
            })
    {
        return EvidenceFacet::Schema;
    }
    let trimmed = match_line.trim_start();
    if [
        "fn ",
        "def ",
        "class ",
        "function ",
        "const ",
        "let ",
        "var ",
        "impl ",
    ]
    .iter()
    .any(|keyword| trimmed.starts_with(keyword))
    {
        EvidenceFacet::Definition
    } else if match_line.contains('(')
        || match_line.contains("await ")
        || match_line.contains("->")
        || match_line.contains("=>")
    {
        EvidenceFacet::CallEdge
    } else {
        EvidenceFacet::Sibling
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

const GREP_DESCRIPTION: &str = "Search bounded UTF-8 files while respecting .gitignore. `path` may \
be relative to the repo root or an absolute host path. Omit `regex` for conservative auto-detection; \
set false for literal matching or true for Rust regex. Stable symbols automatically include a \
bounded enclosing code block; use `context_lines` only for a fixed window. Prefer one focused call \
combining `path`, `context_lines`, and `related_terms` over a series of synonym-only calls. When \
multiple independent evidence facets are needed, issue their focused calls together so the scheduler \
can run them concurrently. `related_terms` is a nearby-term relevance filter, not proof. Results are \
ranked toward recently read files and report incomplete coverage with a bounded path continuation. \
Paths use repository-relative names when possible and line numbers are 1-based.";

fn grep_description() -> &'static str {
    iteron_tunables::param_str("tools.grep_tool.grep_description", GREP_DESCRIPTION)
}

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    let policy_cell = registry.observation_tool_policy_handle();
    let observation_focus = registry.observation_focus_handle();
    registry.push_targeted_observation_tool(
        ToolSpec {
            name: "grep".into(),
            description: grep_description().into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "pattern":{"type":"string"},
                    "path":{"type":"string","description":"subtree relative to the repo root, or an absolute host path; default '.'"},
                    "regex":{"type":"boolean","description":"true uses Rust regex; false forces literal matching; when omitted, conservatively auto-detect anchors, unescaped alternation, and standard shorthand escapes"},
                    "context_lines":{"type":"integer","minimum":0,"description":"surrounding lines before and after each match; default 0, bounded by runtime policy"},
                    "max_results":{"type":"integer","minimum":1,"description":"per-call match limit, capped by the installed runtime policy"},
                    "related_terms":{"type":"array","items":{"type":"string"},"maxItems":8,"description":"optional literal terms that must each occur near the primary match; this is a relevance filter only, never causal or repair authority"},
                    "proximity_lines":{"type":"integer","minimum":1,"description":"maximum line distance from the primary hit for every related term; defaults to a bounded structural neighborhood"}
                },
                "required":["pattern"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        move |call, root| {
            let policy_cell = policy_cell.clone();
            let observation_focus = observation_focus.clone();
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
                    regex_mode(
                        pattern,
                        call.input
                            .get("regex")
                            .and_then(serde_json::Value::as_bool),
                    ),
                ) {
                    Ok(matcher) => matcher,
                    Err(error) => return err_result(id, error),
                };
                let relative = call
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(".");
                let root = match root.canonicalize() {
                    Ok(root) => root,
                    Err(error) => {
                        return err_result(id, format!("grep cannot canonicalize workspace root: {error}"));
                    }
                };
                let base = match resolve_from_canonical_root(&root, relative) {
                    Ok(base) => base,
                    Err(error) => return err_result(id, error),
                };
                let explicitly_narrowed_scope = base.starts_with(&root) && base != root;
                let auto_structural_context = call.input.get("context_lines").is_none();
                let evidence_anchor = is_stable_evidence_anchor(pattern);
                let stable_anchor_context = auto_structural_context && evidence_anchor;
                let context_lines = match call.input.get("context_lines") {
                    None => 0,
                    Some(value) => {
                        let Some(value) = value.as_u64() else {
                            return err_result(
                                id,
                                "grep: `context_lines` must be an integer".into(),
                            );
                        };
                        usize::try_from(value).unwrap_or(usize::MAX)
                    }
                };
                let max_context_lines = iteron_tunables::param_usize(
                    "tools.grep_tool.max_grep_context_lines",
                    MAX_GREP_CONTEXT_LINES,
                );
                if context_lines > max_context_lines {
                    return err_result(
                        id,
                        format!(
                            "grep: `context_lines` exceeds the {max_context_lines}-line policy limit"
                        ),
                    );
                }
                let related_terms = match parse_related_terms(&call.input) {
                    Ok(related_terms) => related_terms,
                    Err(error) => return err_result(id, error),
                };
                let structural_context = stable_anchor_context
                    || (auto_structural_context && !related_terms.is_empty());
                let evidence_comparison = explicitly_narrowed_scope
                    || evidence_anchor
                    || context_lines > 0
                    || !related_terms.is_empty();
                let max_proximity_lines = iteron_tunables::param_usize(
                    "tools.grep_tool.max_grep_proximity_lines",
                    MAX_GREP_PROXIMITY_LINES,
                );
                let proximity_lines = match call.input.get("proximity_lines") {
                    None => iteron_tunables::param_usize(
                        "tools.grep_tool.default_grep_proximity_lines",
                        DEFAULT_GREP_PROXIMITY_LINES,
                    ),
                    Some(value) => {
                        let Some(value) = value.as_u64() else {
                            return err_result(
                                id,
                                "grep: `proximity_lines` must be an integer".into(),
                            );
                        };
                        usize::try_from(value).unwrap_or(usize::MAX)
                    }
                };
                if proximity_lines == 0 || proximity_lines > max_proximity_lines {
                    return err_result(
                        id,
                        format!(
                            "grep: `proximity_lines` must be between 1 and the {max_proximity_lines}-line policy limit"
                        ),
                    );
                }
                let mut policy = policy;
                let installed_max_matches = policy.max_matches;
                if let Some(requested) = call.input.get("max_results") {
                    let Some(requested) = requested.as_u64() else {
                        return err_result(id, "grep: `max_results` must be an integer".into());
                    };
                    let requested = usize::try_from(requested).unwrap_or(usize::MAX);
                    if requested == 0 || requested > policy.max_matches {
                        return err_result(
                            id,
                            format!(
                                "grep: `max_results` must be between 1 and the {}-match policy limit",
                                policy.max_matches
                            ),
                        );
                    }
                    policy.max_matches = requested;
                }
                if context_lines > 0 {
                    let lines_per_result = context_lines.saturating_mul(2).saturating_add(1);
                    let contextual_cap = installed_max_matches
                        .checked_div(lines_per_result)
                        .unwrap_or(0)
                        .max(1);
                    policy.max_matches = policy.max_matches.min(contextual_cap);
                }
                let pattern = pattern.to_owned();
                let search_related_terms = related_terms.clone();
                let focus = observation_focus.snapshot();
                match tokio::task::spawn_blocking(move || {
                    let result = search(
                        &root,
                        &base,
                        &matcher,
                        SearchOptions {
                            policy,
                            context_lines,
                            auto_structural_context,
                            stable_anchor_context: structural_context,
                            evidence_anchor,
                            structural_context_max_lines: max_context_lines,
                            related_terms: &search_related_terms,
                            proximity_lines,
                            focus: &focus,
                        },
                    )?;
                    Ok::<_, String>(result)
                })
                    .await
                {
                    Ok(Ok(result)) => {
                        let output = result.render(
                            &pattern,
                            policy,
                            &related_terms,
                            proximity_lines,
                            evidence_comparison,
                            explicitly_narrowed_scope,
                        );
                        ok_result(id, output)
                    }
                    Ok(Err(error)) => err_result(id, error),
                    Err(error) => err_result(id, format!("grep worker failed: {error}")),
                }
            })
        },
    )
}

pub(super) fn is_stable_evidence_anchor(pattern: &str) -> bool {
    let pattern = pattern.trim();
    (3..=256).contains(&pattern.len())
        && !pattern.bytes().any(|byte| byte.is_ascii_whitespace())
        && pattern.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'$' | b'-' | b'.' | b'/' | b':' | b'#')
        })
}

fn parse_related_terms(input: &serde_json::Value) -> Result<Vec<(String, Matcher)>, String> {
    let Some(value) = input.get("related_terms") else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err("grep: `related_terms` must be an array of strings".into());
    };
    let max_terms = iteron_tunables::param_usize(
        "tools.grep_tool.max_grep_related_terms",
        MAX_GREP_RELATED_TERMS,
    );
    if values.is_empty() || values.len() > max_terms {
        return Err(format!(
            "grep: `related_terms` must contain between 1 and {max_terms} strings"
        ));
    }
    let mut terms = Vec::with_capacity(values.len());
    for value in values {
        let Some(term) = value.as_str() else {
            return Err("grep: `related_terms` must be an array of strings".into());
        };
        let matcher = Matcher::compile(term, false)?;
        if terms.iter().any(|(existing, _)| existing == term) {
            continue;
        }
        terms.push((term.to_owned(), matcher));
    }
    if terms.is_empty() {
        return Err("grep: `related_terms` must contain at least one distinct string".into());
    }
    Ok(terms)
}

#[derive(Clone, Copy)]
struct SearchOptions<'a> {
    policy: crate::GrepPolicy,
    context_lines: usize,
    auto_structural_context: bool,
    stable_anchor_context: bool,
    evidence_anchor: bool,
    structural_context_max_lines: usize,
    related_terms: &'a [(String, Matcher)],
    proximity_lines: usize,
    focus: &'a crate::ObservationFocusSnapshot,
}

#[derive(Clone, Copy)]
struct SearchSourceLimits {
    max_file_bytes: usize,
    max_total_source_bytes: usize,
    max_files: usize,
}

fn search(
    root: &Path,
    base: &Path,
    matcher: &Matcher,
    options: SearchOptions<'_>,
) -> Result<SearchResult, String> {
    search_with_source_limits(
        root,
        base,
        matcher,
        options,
        SearchSourceLimits {
            max_file_bytes: iteron_tunables::param_usize(
                "tools.grep_tool.max_grep_file_bytes",
                MAX_GREP_FILE_BYTES,
            ),
            max_total_source_bytes: iteron_tunables::param_usize(
                "tools.grep_tool.max_grep_total_source_bytes",
                iteron_tunables::param_integer(
                    "tools.grep_tool.max_grep_total_source_bytes",
                    MAX_GREP_TOTAL_SOURCE_BYTES,
                ),
            ),
            max_files: iteron_tunables::param_usize(
                "tools.grep_tool.max_grep_entries",
                MAX_GREP_ENTRIES,
            ),
        },
    )
}

fn search_with_source_limits(
    root: &Path,
    base: &Path,
    matcher: &Matcher,
    options: SearchOptions<'_>,
    source_limits: SearchSourceLimits,
) -> Result<SearchResult, String> {
    let SearchOptions { policy, .. } = options;
    let root = root.to_path_buf();
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
            if entry_index
                == iteron_tunables::param_usize(
                    "tools.grep_tool.max_grep_entries",
                    MAX_GREP_ENTRIES,
                )
            {
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

    let SearchSourceLimits {
        max_file_bytes,
        max_total_source_bytes,
        max_files,
    } = source_limits;
    // Inspect metadata before concurrent reads, then admit the already-bounded candidates with the
    // shared deterministic fair scheduler. Lexically early top-level trees cannot consume the
    // entire byte budget, while both the selected corpus and rendered result remain independent of
    // traversal and worker completion order.
    let mut candidates = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) | Err(_) => {
                result.skipped_files = result.skipped_files.saturating_add(1);
                continue;
            }
        };
        let file_bytes = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if file_bytes > max_file_bytes {
            result.skipped_files = result.skipped_files.saturating_add(1);
            continue;
        }
        candidates.push((path, file_bytes));
    }
    let admission =
        iteron_ctx::source::admit_paths_fair(base, candidates, max_files, max_total_source_bytes);
    result.eligible_files = admission.eligible_files;
    result.eligible_bytes = admission.eligible_bytes;
    result.admitted_files = admission.admitted.len();
    result.admitted_bytes = admission.admitted_bytes;
    result.skipped_for_budget = admission
        .eligible_files
        .saturating_sub(admission.admitted.len());
    result.incomplete_strata = admission.incomplete_strata;
    result.incomplete_paths = admission
        .coverage
        .iter()
        .filter(|coverage| !coverage.is_complete())
        .take(max_grep_incomplete_path_hints())
        .map(|coverage| crate::display_path(&root, &coverage.path))
        .collect();
    result.incomplete_paths_truncated =
        admission.coverage_truncated || admission.incomplete_strata > result.incomplete_paths.len();
    let admitted = admission.admitted;

    let max_workers =
        iteron_tunables::param_usize("tools.grep_tool.max_grep_parallelism", MAX_GREP_PARALLELISM)
            .clamp(1, MAX_GREP_PARALLELISM);
    let requested_workers = iteron_tunables::param_usize(
        "tools.grep_tool.default_grep_parallelism",
        DEFAULT_GREP_PARALLELISM,
    )
    .clamp(1, max_workers);
    let available_workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let worker_count = requested_workers
        .min(available_workers)
        .min(admitted.len().max(1));
    // A fixed scoped pool handles the whole call; do not create a fresh OS thread for every file
    // or wave. At most `worker_count` jobs and results are in flight. Completed results are held in
    // a bounded reorder map and committed by stable path index, so concurrency cannot change the
    // output or grow memory with the full repository.
    std::thread::scope(|scope| -> Result<(), String> {
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<(usize, &Path)>(worker_count);
        let job_rx = std::sync::Arc::new(std::sync::Mutex::new(job_rx));
        let (result_tx, result_rx) =
            std::sync::mpsc::sync_channel::<(usize, FileSearchResult)>(worker_count);
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let job_rx = std::sync::Arc::clone(&job_rx);
            let result_tx = result_tx.clone();
            let search_root = &root;
            workers.push(scope.spawn(move || {
                loop {
                    let job = job_rx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok((index, path)) = job else { break };
                    let searched = search_file(search_root, path, matcher, max_file_bytes, options);
                    if result_tx.send((index, searched)).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(result_tx);

        let mut submitted = 0usize;
        let mut inflight = 0usize;
        while submitted < admitted.len() && inflight < worker_count {
            job_tx
                .send((submitted, admitted[submitted].as_path()))
                .map_err(|_| "grep worker pool closed before admission".to_string())?;
            submitted += 1;
            inflight += 1;
        }

        let mut next = 0usize;
        let mut reordered = std::collections::BTreeMap::new();
        while inflight > 0 {
            let (index, searched) = result_rx
                .recv()
                .map_err(|_| "grep worker pool closed before producing every result".to_string())?;
            inflight -= 1;
            reordered.insert(index, searched);
            while let Some(file) = reordered.remove(&next) {
                next += 1;
                if file.skipped {
                    result.skipped_files = result.skipped_files.saturating_add(1);
                    continue;
                }
                for hit in file.hits {
                    result.push_hit(hit, policy);
                }
            }
            while submitted < admitted.len() && submitted.saturating_sub(next) < worker_count {
                job_tx
                    .send((submitted, admitted[submitted].as_path()))
                    .map_err(|_| "grep worker pool closed during admission".to_string())?;
                submitted += 1;
                inflight += 1;
            }
        }
        drop(job_tx);
        for worker in workers {
            worker.join().map_err(|_| {
                "grep worker panicked before producing a complete result".to_string()
            })?;
        }
        Ok(())
    })?;
    Ok(result)
}

fn search_file(
    root: &Path,
    path: &Path,
    matcher: &Matcher,
    max_file_bytes: usize,
    options: SearchOptions<'_>,
) -> FileSearchResult {
    let SearchOptions {
        policy,
        context_lines,
        auto_structural_context,
        stable_anchor_context,
        evidence_anchor,
        structural_context_max_lines,
        related_terms,
        proximity_lines,
        focus,
    } = options;
    let mut result = FileSearchResult::default();
    let scope = if path.starts_with(root) {
        iteron_ctx::source::SourceScope::Repository
    } else {
        iteron_ctx::source::SourceScope::User
    };
    let content = match iteron_ctx::source::read_bounded_utf8(root, path, max_file_bytes, scope) {
        Ok(Some(content)) => content,
        Ok(None) | Err(_) => {
            result.skipped = true;
            return result;
        }
    };
    if content.as_bytes().contains(&0) || suspicious_unicode(&content).is_some() {
        result.skipped = true;
        return result;
    }
    let relative = crate::display_path(root, path);
    if suspicious_unicode(&relative).is_some() {
        result.skipped = true;
        return result;
    }
    let lines = content.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        if !matcher.is_match(line) {
            continue;
        }
        let Some(related_hits) = related_hits(&lines, line_index, related_terms, proximity_lines)
        else {
            continue;
        };
        let related_label = if related_hits.is_empty() {
            String::new()
        } else {
            format!(
                " [related: {}]",
                related_hits
                    .iter()
                    .map(|(term, related_line)| {
                        let distance = related_line.abs_diff(line_index);
                        format!("{term}@{} ({distance} lines)", related_line + 1)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let relevance_start = line_index.saturating_sub(proximity_lines);
        let relevance_end = line_index
            .saturating_add(proximity_lines)
            .saturating_add(1)
            .min(lines.len());
        let relevance_context = lines[relevance_start..relevance_end].join("\n");
        let mut relevance = focus.relevance(&relevance_context);
        let exact_path_recency = focus.exact_path_recency(path);
        if let Some(recency) = exact_path_recency {
            relevance = relevance.saturating_add(
                exact_focus_path_relevance()
                    .saturating_sub(u64::try_from(recency).unwrap_or(u64::MAX)),
            );
        }
        let rendered = if context_lines == 0 {
            let snippet = iteron_protocol::text::head(line.trim(), policy.snippet_max_bytes);
            format!("{}:{}{related_label}: {snippet}", relative, line_index + 1)
        } else {
            let start = line_index.saturating_sub(context_lines);
            let end = line_index
                .saturating_add(context_lines)
                .saturating_add(1)
                .min(lines.len());
            let mut block = format!("{}:{}-{}{related_label}", relative, start + 1, end);
            for (context_index, context_line) in lines[start..end].iter().enumerate() {
                let absolute_index = start + context_index;
                let marker = if absolute_index == line_index {
                    '>'
                } else {
                    ' '
                };
                let snippet =
                    iteron_protocol::text::head(context_line.trim_end(), policy.snippet_max_bytes);
                block.push_str(&format!(
                    "\n{marker} {}:{}: {snippet}",
                    relative,
                    absolute_index + 1
                ));
            }
            block
        };
        let structural_span = (auto_structural_context && stable_anchor_context)
            .then(|| {
                crate::fs_tools::structural_context::enclosing_span(
                    &lines,
                    line_index,
                    structural_context_max_lines,
                )
            })
            .flatten();
        let structural_rendered = structural_span.map(|(start, end)| {
            render_structural_context_block(
                &relative,
                &lines,
                line_index,
                (start, end),
                &related_label,
                policy.snippet_max_bytes,
            )
        });
        let fixed_context_span = (evidence_anchor && context_lines > 0).then(|| {
            (
                line_index.saturating_sub(context_lines),
                line_index
                    .saturating_add(context_lines)
                    .saturating_add(1)
                    .min(lines.len()),
            )
        });
        let (evidence_start, evidence_end) = structural_span
            .or(fixed_context_span)
            .unwrap_or((line_index, line_index.saturating_add(1)));
        result.hits.push(SearchHit {
            rendered,
            structural_rendered,
            evidence_facet: classify_evidence_facet(
                &relative,
                line,
                &lines,
                evidence_start,
                evidence_end,
            ),
            evidence_start,
            evidence_end,
            focused_path: exact_path_recency.is_some(),
            relevance,
            path: relative.clone(),
            line: line_index + 1,
        });
        // Retain one bounded overflow sentinel so the stable-order aggregator can distinguish an
        // exact N-match result from N+1 and emit the truthful truncation notice. The aggregator
        // still publishes at most `max_matches` hits.
        if result.hits.len() > policy.max_matches {
            break;
        }
    }
    result
}

fn render_structural_context_block(
    relative: &str,
    lines: &[&str],
    line_index: usize,
    span: (usize, usize),
    related_label: &str,
    snippet_max_bytes: usize,
) -> String {
    let (start, end) = span;
    let mut block = format!(
        "{}:{}-{}{related_label} [auto structural context]",
        relative,
        start + 1,
        end
    );
    for (context_index, context_line) in lines[start..end].iter().enumerate() {
        let absolute_index = start + context_index;
        let marker = if absolute_index == line_index {
            '>'
        } else {
            ' '
        };
        let snippet = iteron_protocol::text::head(context_line.trim_end(), snippet_max_bytes);
        block.push_str(&format!(
            "\n{marker} {}:{}: {snippet}",
            relative,
            absolute_index + 1
        ));
    }
    block
}

fn related_hits<'a>(
    lines: &[&str],
    primary_line: usize,
    related_terms: &'a [(String, Matcher)],
    proximity_lines: usize,
) -> Option<Vec<(&'a str, usize)>> {
    let start = primary_line.saturating_sub(proximity_lines);
    let end = primary_line
        .saturating_add(proximity_lines)
        .saturating_add(1)
        .min(lines.len());
    let mut hits = Vec::with_capacity(related_terms.len());
    for (term, matcher) in related_terms {
        let related_line = (start..end)
            .filter(|index| matcher.is_match(lines[*index]))
            .min_by_key(|index| index.abs_diff(primary_line))?;
        hits.push((term.as_str(), related_line));
    }
    Some(hits)
}

fn load_ignore(
    workspace_root: &Path,
    path: &Path,
    budget: &mut IgnoreBudget,
) -> Result<Option<(PathBuf, Gitignore)>, String> {
    let max_gitignore_files =
        iteron_tunables::param_usize("tools.grep_tool.max_gitignore_files", MAX_GITIGNORE_FILES);
    if budget.files >= max_gitignore_files {
        return Err(format!(
            "grep: repository exceeds the {max_gitignore_files}-file .gitignore limit"
        ));
    }
    let max_gitignore_total_bytes = iteron_tunables::param_usize(
        "tools.grep_tool.max_gitignore_total_bytes",
        iteron_tunables::param_integer(
            "tools.grep_tool.max_gitignore_total_bytes",
            MAX_GITIGNORE_TOTAL_BYTES,
        ),
    );
    let remaining = max_gitignore_total_bytes.saturating_sub(budget.bytes);
    if remaining == 0 {
        return Err(format!(
            "grep: .gitignore sources exceed the {max_gitignore_total_bytes}-byte total limit"
        ));
    }
    let content = match iteron_ctx::source::read_bounded_utf8(
        workspace_root,
        path,
        remaining.min(iteron_tunables::param_usize(
            "tools.grep_tool.max_gitignore_file_bytes",
            iteron_tunables::param_integer(
                "tools.grep_tool.max_gitignore_file_bytes",
                MAX_GITIGNORE_FILE_BYTES,
            ),
        )),
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
    let max_gitignore_patterns = iteron_tunables::param_usize(
        "tools.grep_tool.max_gitignore_patterns",
        iteron_tunables::param_integer(
            "tools.grep_tool.max_gitignore_patterns",
            MAX_GITIGNORE_PATTERNS,
        ),
    );
    for (line_index, line) in content.lines().enumerate() {
        budget.patterns = budget.patterns.saturating_add(1);
        if budget.patterns > max_gitignore_patterns {
            return Err(format!(
                "grep: .gitignore sources exceed the {max_gitignore_patterns}-line limit"
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
    name == ".iteron" || iteron_ctx::source::is_default_pruned_component(name)
}

#[cfg(test)]
mod evidence_contract_tests {
    use super::GREP_DESCRIPTION;

    #[test]
    fn description_prefers_focused_and_concurrent_evidence_searches() {
        for guidance in [
            "one focused call",
            "`path`, `context_lines`, and `related_terms`",
            "synonym-only calls",
            "calls together",
            "run them concurrently",
        ] {
            assert!(GREP_DESCRIPTION.contains(guidance), "{guidance}");
        }
    }
}

#[cfg(test)]
#[path = "grep_tool_tests.rs"]
mod tests;

//! `Decomposer` — the deterministic task-class router and plan instantiator.
//!
//! "Control flow is not the model's" (`user-prior-art.md` §3 #6). So the harness owns the topology:
//! a deterministic `route()` heuristic picks a `TaskClass`, and `plan()` instantiates a fixed
//! `Fan → Reduce` topology for the evidence classes (the model only ever fills the leaf prompts).
//! A task that names a concrete location routes to `Localized` → the caller falls back to the
//! single-agent loop, because fan-out is net-negative on a localized change (ADR-005).
//!
//! The heuristic is coarse by design — a cheap-model classifier is a designed pluggable upgrade
//! (ADR-011), not built here. It is a pure function of `(task, RepoSignals)` with no I/O, so the
//! routing decision is reproducible and unit-testable.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::stage::{AgentTask, Stage, WorkflowPlan};

/// The fan-out ceiling (ADR-004: the fan-out ceiling is cited at the call site; cap 4–6). Leaves
/// beyond this are truncated, and the truncation is recorded on the `WorkflowPlan`.
pub const FAN_CAP: usize = 6;

/// Hard limit for one normalized investigation objective, measured in Unicode scalar values rather
/// than bytes so slicing can never split UTF-8. Over-limit leaves are rejected and counted instead
/// of being silently truncated into a different question.
pub const LEAF_MAX_CHARS: usize = 512;

/// Result of the pure leaf-normalization boundary. This is public so callers can surface rejection
/// diagnostics even when every candidate is invalid and `plan()` therefore returns `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedLeaves {
    /// Valid unique objectives, in first-declaration order. This list is intentionally uncapped;
    /// `plan()` applies `FAN_CAP` only after deduplication.
    pub leaves: Vec<String>,
    /// Case-insensitive duplicates removed after whitespace/prefix normalization.
    pub duplicates_removed: usize,
    /// Empty, unsafe, control-bearing, or over-limit inputs removed.
    pub invalid_removed: usize,
}

/// The class of a substantive task — the axis on which workflow-vs-agent is selected (ADR-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// Names a concrete path / symbol / line / stack frame → single-agent loop (no fan-out).
    Localized,
    /// Under-specified localization: the *where* is unknown; fan out to find it.
    UnderSpecified,
    /// Spans many files (rename / refactor / cross-cutting change); fan out to cover them.
    MultiFile,
    /// Requires running/reproducing to understand (a crash, a failing/flaky test, a regression).
    RunToUnderstand,
}

impl TaskClass {
    /// Does this class engage the fan-out DAG (vs. fall back to the single-agent loop)?
    pub fn fans_out(self) -> bool {
        !matches!(self, TaskClass::Localized)
    }
}

/// Repo-side signals that shape routing (kept small and load-bearing). These come from the caller's
/// cheap repo inspection, not from the model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSignals {
    /// The repo exposes a runnable test/reproduce command — makes a "make the tests pass"-style ask
    /// a `RunToUnderstand` rather than an under-specified one.
    pub has_test_command: bool,
    /// Approximate breadth of the working tree — a broad ask on a large tree fans across files.
    pub file_count: usize,
}

/// The deterministic router + plan instantiator. A unit struct: routing is stateless (the pluggable
/// classifier upgrade would carry state, hence the type rather than free functions).
pub struct Decomposer;

impl Decomposer {
    /// Route a task to a class (deterministic, no model call).
    pub fn route(task: &str, repo: &RepoSignals) -> TaskClass {
        // Explicit run/multi-file intent outranks an incidental path, symbol, or backtick in the
        // same sentence. Otherwise "audit each module across `crates/...`" collapses to a
        // localized single-agent task merely because it names one starting point. A mere symptom
        // word (for example `panic` inside a concrete stack frame) is not intent, so it remains
        // below the concrete-location check.
        if let Some(evidence) = explicit_evidence_intent(task, repo) {
            return evidence;
        }
        if names_concrete_location(task) {
            return TaskClass::Localized;
        }
        evidence_class(task, repo)
    }

    /// Normalize model-emitted leaf lines without applying `FAN_CAP`.
    ///
    /// Legal Markdown list prefixes are removed, whitespace is collapsed, unsafe/non-visible
    /// controls and over-limit objectives are rejected, and case-insensitive duplicates keep their
    /// first declaration. A leading path component such as `.github/` is content, not a list
    /// prefix, and is preserved.
    pub fn normalize_leaves(leaves: Vec<String>) -> NormalizedLeaves {
        let mut seen = HashSet::new();
        let mut normalized = Vec::with_capacity(leaves.len());
        let mut duplicates_removed = 0;
        let mut invalid_removed = 0;

        for raw in leaves {
            let Some(leaf) = normalize_leaf(&raw) else {
                invalid_removed += 1;
                continue;
            };
            let dedup_key = leaf.to_lowercase();
            if !seen.insert(dedup_key) {
                duplicates_removed += 1;
                continue;
            }
            normalized.push(leaf);
        }

        NormalizedLeaves {
            leaves: normalized,
            duplicates_removed,
            invalid_removed,
        }
    }

    /// Instantiate the fixed topology for `class` from the model-emitted `leaves`.
    ///
    /// `Localized` returns `None` (the caller runs the single-agent loop). An evidence class returns
    /// a `Fan → Reduce` plan. Leaves are normalized and deduplicated before `FAN_CAP` is applied;
    /// cap drops, duplicates, and invalid inputs are recorded separately — never silently. Empty
    /// normalized leaves return `None` (nothing to fan → single agent).
    pub fn plan(class: TaskClass, leaves: Vec<String>) -> Option<WorkflowPlan> {
        if !class.fans_out() {
            return None;
        }
        let normalized = Self::normalize_leaves(leaves);
        let total = normalized.leaves.len();
        let kept: Vec<String> = normalized.leaves.into_iter().take(FAN_CAP).collect();
        if kept.is_empty() {
            return None;
        }
        let truncated = (total > FAN_CAP).then(|| total - FAN_CAP);
        let tasks: Vec<AgentTask> = kept
            .into_iter()
            .enumerate()
            .map(|(id, objective)| AgentTask::investigator(id, objective))
            .collect();
        Some(WorkflowPlan {
            stages: vec![Stage::Fan { tasks }, Stage::Reduce],
            class,
            truncated,
            duplicates_removed: normalized.duplicates_removed,
            invalid_removed: normalized.invalid_removed,
        })
    }
}

/// Normalize one untrusted model line. The input is already valid UTF-8 by type; every remaining
/// bound is measured/constructed by `char` iteration, so no byte slicing can corrupt it.
fn normalize_leaf(raw: &str) -> Option<String> {
    let without_prefix = strip_list_prefix(raw.trim());
    let leaf = without_prefix
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let char_count = leaf.chars().count();
    if char_count == 0 || char_count > LEAF_MAX_CHARS {
        return None;
    }
    if crate::suspicious_unicode(&leaf).is_some()
        || leaf.chars().any(|c| c.is_control() && !c.is_whitespace())
    {
        return None;
    }
    Some(leaf)
}

/// Strip one legal Markdown/ordered-list prefix only when its required whitespace separator is
/// present. In particular, a leading `.` by itself is never stripped (`.github/workflows/...`).
fn strip_list_prefix(input: &str) -> &str {
    for marker in ["-", "*", "+", "•"] {
        if let Some(rest) = input.strip_prefix(marker)
            && rest.chars().next().is_some_and(char::is_whitespace)
        {
            return rest.trim_start();
        }
    }

    let digit_end = input.bytes().take_while(u8::is_ascii_digit).count();
    if digit_end > 0 {
        let rest = &input[digit_end..];
        if let Some(rest) = rest.strip_prefix('.').or_else(|| rest.strip_prefix(')'))
            && rest.chars().next().is_some_and(char::is_whitespace)
        {
            return rest.trim_start();
        }
    }

    if let Some(rest) = input.strip_prefix('(') {
        let digit_end = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digit_end > 0 {
            let rest = &rest[digit_end..];
            if let Some(rest) = rest.strip_prefix(')')
                && rest.chars().next().is_some_and(char::is_whitespace)
            {
                return rest.trim_start();
            }
        }
    }

    input
}

// --- routing heuristic (pure, zero-dep, no regex) -----------------------------------------------

const CODE_EXTS: &[&str] = &[
    ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".rb",
    ".java", ".kt", ".toml", ".json", ".yaml", ".yml", ".sh", ".sql", ".cs", ".php", ".swift",
    ".scala", ".ex", ".exs", ".lua", ".md",
];

const FRAME_MARKERS: &[&str] = &[
    "panicked at",
    "stack trace",
    "stacktrace",
    "traceback",
    "backtrace",
    " at line ",
    "thread 'main'",
];

const RUN_MARKERS: &[&str] = &[
    "reproduce",
    "repro ",
    "crash",
    "panic",
    "hang",
    "deadlock",
    "fails",
    "failing",
    "flaky",
    "regression",
    "bisect",
    "segfault",
    "stack overflow",
    "times out",
    "timeout",
    "doesn't work",
    "not working",
    "broken",
];

/// Action words that explicitly ask the harness to reproduce/execute an investigation. Kept
/// narrower than `RUN_MARKERS`: a symptom in an already-localized stack frame is not by itself a
/// request to fan out.
const RUN_INTENT_MARKERS: &[&str] = &[
    "reproduce",
    "repro ",
    "bisect",
    "run the ",
    "run this ",
    "execute the ",
];

/// High-signal non-English intent markers. These deliberately stay small and explicit: routing
/// is a deterministic proposal, so an unbounded language detector or locale-dependent tokenizer
/// would be a worse fit than a reviewed vocabulary. Unicode lowercasing handles cased scripts;
/// CJK entries compare directly.
const INTERNATIONAL_RUN_MARKERS: &[&str] = &[
    "复现",
    "重现",
    "再現",
    "reproducir",
    "reproduire",
    "reproduzieren",
];

const MULTI_MARKERS: &[&str] = &[
    "across",
    "everywhere",
    "all callers",
    "all call sites",
    "all usages",
    "all references",
    "throughout",
    "codebase-wide",
    "project-wide",
    "rename",
    "refactor",
    "migrate",
    "wherever",
    "every file",
    "multiple files",
    "many files",
    "each module",
];

const INTERNATIONAL_MULTI_MARKERS: &[&str] = &[
    "重命名",
    "重构",
    "迁移",
    "所有地方",
    "所有文件",
    "所有调用",
    "所有引用",
    "全局替换",
    "跨文件",
    "名前を変更",
    "すべてのファイル",
    "renombrar",
    "en todas partes",
    "todos los archivos",
    "renommer partout",
    "umbenennen",
    "in allen dateien",
];

const TEST_INTENT: &[&str] = &[
    "make the tests pass",
    "get the tests passing",
    "get tests passing",
    "pass the tests",
    "green the tests",
    "fix the tests",
    "make tests pass",
];

const BROAD_VERBS: &[&str] = &[
    "improve",
    "optimize",
    "clean up",
    "restructure",
    "audit",
    "review",
    "harden",
    "modernize",
    "simplify",
];

/// A broad ask on a tree this large or larger leans multi-file rather than under-specified.
const LARGE_REPO: usize = 200;

fn evidence_class(task: &str, repo: &RepoSignals) -> TaskClass {
    let lower = task.to_lowercase();
    if RUN_MARKERS
        .iter()
        .chain(INTERNATIONAL_RUN_MARKERS)
        .any(|m| lower.contains(m))
    {
        return TaskClass::RunToUnderstand;
    }
    if MULTI_MARKERS
        .iter()
        .chain(INTERNATIONAL_MULTI_MARKERS)
        .any(|m| lower.contains(m))
    {
        return TaskClass::MultiFile;
    }
    // Repo-shaped tie-breaks (RepoSignals is load-bearing here, not decoration).
    if repo.has_test_command && TEST_INTENT.iter().any(|m| lower.contains(m)) {
        return TaskClass::RunToUnderstand;
    }
    if repo.file_count >= LARGE_REPO && BROAD_VERBS.iter().any(|m| lower.contains(m)) {
        return TaskClass::MultiFile;
    }
    TaskClass::UnderSpecified
}

fn explicit_evidence_intent(task: &str, repo: &RepoSignals) -> Option<TaskClass> {
    let lower = task.to_lowercase();
    if RUN_INTENT_MARKERS
        .iter()
        .chain(INTERNATIONAL_RUN_MARKERS)
        .any(|m| lower.contains(m))
        || (repo.has_test_command && TEST_INTENT.iter().any(|m| lower.contains(m)))
    {
        return Some(TaskClass::RunToUnderstand);
    }
    if MULTI_MARKERS
        .iter()
        .chain(INTERNATIONAL_MULTI_MARKERS)
        .any(|m| lower.contains(m))
        || (repo.file_count >= LARGE_REPO && BROAD_VERBS.iter().any(|m| lower.contains(m)))
    {
        return Some(TaskClass::MultiFile);
    }
    None
}

/// Does the task name a concrete path / symbol / line / stack frame?
fn names_concrete_location(task: &str) -> bool {
    let lower = task.to_ascii_lowercase();
    if FRAME_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    if lower.contains("::") {
        // A Rust-style path segment (`Agent::run`, `crate::foo`).
        return true;
    }
    if task.matches('`').count() >= 2 {
        // The operator quoted a code identifier inline.
        return true;
    }
    if contains_line_number_phrase(&lower) {
        return true;
    }
    task.split_whitespace().any(|tok| {
        token_is_path(tok)
            || token_has_code_ext(tok)
            || token_is_file_line(tok)
            || token_is_symbol(tok)
    })
}

/// Strip a trailing `:<digits>[:<digits>]` line/column reference: `login.rs:42:5` -> `login.rs`.
fn strip_trailing_line_ref(tok: &str) -> &str {
    match tok.split_once(':') {
        Some((head, rest)) if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) => head,
        _ => tok,
    }
}

fn token_has_code_ext(tok: &str) -> bool {
    let base = strip_trailing_line_ref(
        tok.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | ';')),
    );
    let lower = base.to_ascii_lowercase();
    CODE_EXTS.iter().any(|e| lower.ends_with(e))
}

fn token_is_path(tok: &str) -> bool {
    let base = strip_trailing_line_ref(tok);
    if !base.contains('/') || base.starts_with("http://") || base.starts_with("https://") {
        return false;
    }
    let segs: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return false;
    }
    // Require a real code marker so prose like "and/or" or "he/she" does not read as a path.
    token_has_code_ext(base) || base.contains('.') || segs.len() >= 3
}

fn token_is_file_line(tok: &str) -> bool {
    let core = tok.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | ';' | '(' | ')'));
    match core.split_once(':') {
        Some((head, rest)) => {
            let line_ok = rest
                .split(':')
                .next()
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
            line_ok && (token_has_code_ext(head) || head.contains('/'))
        }
        None => false,
    }
}

fn token_is_symbol(tok: &str) -> bool {
    let trimmed = tok.trim();
    if trimmed.chars().count() >= 3 && trimmed.starts_with('`') && trimmed.ends_with('`') {
        return true;
    }
    let core = trimmed.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | ';' | '.'));
    if core.contains("::") {
        return true;
    }
    // Call form: `identifier(` — a named function/method the operator pointed at.
    if let Some(idx) = tok.find('(') {
        let head = &tok[..idx];
        if !head.is_empty()
            && head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && head
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            return true;
        }
    }
    false
}

fn contains_line_number_phrase(lower: &str) -> bool {
    let toks: Vec<&str> = lower.split_whitespace().collect();
    toks.windows(2)
        .any(|w| w[0] == "line" && w[1].chars().next().is_some_and(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> RepoSignals {
        RepoSignals::default()
    }

    #[test]
    fn localized_when_task_names_a_concrete_location() {
        let s = sig();
        assert_eq!(
            Decomposer::route("fix crates/agents/src/lib.rs:42 panic", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("the bug is in login.rs", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("Agent::run returns the wrong value", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("`parse_def` mishandles empty tools", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("panicked at 'index out of bounds'", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("off-by-one on line 88", &s),
            TaskClass::Localized
        );
        assert_eq!(
            Decomposer::route("spawn_subagent() never joins", &s),
            TaskClass::Localized
        );
    }

    #[test]
    fn explicit_evidence_intent_outranks_incidental_locations() {
        let small = sig();
        let large = RepoSignals {
            has_test_command: true,
            file_count: 5_000,
        };
        assert_eq!(
            Decomposer::route(
                "audit each module across `crates/kernel/src/lib.rs` and its callers",
                &small,
            ),
            TaskClass::MultiFile,
            "an incidental starting path must not erase explicit cross-module intent"
        );
        assert_eq!(
            Decomposer::route("reproduce the crash in crates/kernel/src/lib.rs", &small),
            TaskClass::RunToUnderstand,
            "run/reproduction intent must outrank a named location"
        );
        assert_eq!(
            Decomposer::route("audit `crates/kernel/src/lib.rs`", &large),
            TaskClass::MultiFile,
            "broad intent plus a bounded large-repo signal must outrank an incidental path"
        );
        assert_eq!(
            Decomposer::route("audit `crates/kernel/src/lib.rs`", &small),
            TaskClass::Localized,
            "the same broad verb remains concrete when repository breadth does not justify fan-out"
        );
    }

    #[test]
    fn run_to_understand_on_repro_signals() {
        let s = sig();
        assert_eq!(
            Decomposer::route("the server crashes under load, find out why", &s),
            TaskClass::RunToUnderstand
        );
        assert_eq!(
            Decomposer::route("a test is flaky, figure it out", &s),
            TaskClass::RunToUnderstand
        );
        assert_eq!(
            Decomposer::route("bisect the regression that broke checkout", &s),
            TaskClass::RunToUnderstand
        );
    }

    #[test]
    fn multi_file_on_breadth_signals() {
        let s = sig();
        assert_eq!(
            Decomposer::route("rename the config field everywhere", &s),
            TaskClass::MultiFile
        );
        assert_eq!(
            Decomposer::route("update all callers of the old API", &s),
            TaskClass::MultiFile
        );
        assert_eq!(
            Decomposer::route("migrate the codebase to the new logger", &s),
            TaskClass::MultiFile
        );
    }

    #[test]
    fn non_english_intent_routes_deterministically() {
        let repo = RepoSignals {
            has_test_command: true,
            file_count: 5_000,
        };
        let cases = [
            ("请复现这个崩溃并找到原因", TaskClass::RunToUnderstand),
            ("把这个配置字段在所有地方重命名", TaskClass::MultiFile),
            ("クラッシュを再現してください", TaskClass::RunToUnderstand),
            ("renombrar el campo en todas partes", TaskClass::MultiFile),
        ];
        for (task, expected) in cases {
            assert_eq!(Decomposer::route(task, &repo), expected);
            for _ in 0..32 {
                assert_eq!(Decomposer::route(task, &repo), expected);
            }
        }
    }

    #[test]
    fn under_specified_is_the_default() {
        let s = sig();
        assert_eq!(
            Decomposer::route("add authentication to the app", &s),
            TaskClass::UnderSpecified
        );
        assert_eq!(
            Decomposer::route("figure out how sessions work", &s),
            TaskClass::UnderSpecified
        );
    }

    #[test]
    fn repo_signals_are_load_bearing() {
        // "make the tests pass" is under-specified with no suite, run-to-understand with one.
        let none = RepoSignals {
            has_test_command: false,
            file_count: 10,
        };
        let has = RepoSignals {
            has_test_command: true,
            file_count: 10,
        };
        assert_eq!(
            Decomposer::route("make the tests pass", &none),
            TaskClass::UnderSpecified
        );
        assert_eq!(
            Decomposer::route("make the tests pass", &has),
            TaskClass::RunToUnderstand
        );

        // A broad verb becomes multi-file only on a large tree.
        let big = RepoSignals {
            has_test_command: false,
            file_count: 5_000,
        };
        assert_eq!(
            Decomposer::route("improve error handling", &sig()),
            TaskClass::UnderSpecified
        );
        assert_eq!(
            Decomposer::route("improve error handling", &big),
            TaskClass::MultiFile
        );
    }

    #[test]
    fn plan_none_for_localized_and_empty() {
        assert!(Decomposer::plan(TaskClass::Localized, vec!["x".into()]).is_none());
        assert!(Decomposer::plan(TaskClass::MultiFile, vec![]).is_none());
    }

    #[test]
    fn plan_builds_fan_then_reduce() {
        let leaves = vec!["find callers".into(), "find the schema".into()];
        let plan = Decomposer::plan(TaskClass::MultiFile, leaves).unwrap();
        assert_eq!(plan.stages.len(), 2);
        assert!(matches!(plan.stages[0], Stage::Fan { .. }));
        assert!(matches!(plan.stages[1], Stage::Reduce));
        assert_eq!(plan.class, TaskClass::MultiFile);
        assert_eq!(plan.truncated, None);
        assert_eq!(plan.duplicates_removed, 0);
        assert_eq!(plan.invalid_removed, 0);
        assert_eq!(plan.fan_tasks().len(), 2);
        assert!(plan.fan_tasks()[0].agent_type.is_none());
        assert_eq!(plan.fan_tasks()[0].id, 0);
        assert_eq!(plan.fan_tasks()[0].objective, "find callers");
        assert_eq!(plan.fan_tasks()[0].scope, crate::INVESTIGATOR_SCOPE);
        assert_eq!(
            plan.fan_tasks()[0].deliverable,
            crate::INVESTIGATOR_DELIVERABLE
        );
        assert!(
            plan.fan_tasks()[0]
                .prompt
                .contains("Assigned question: find callers")
        );
        assert!(plan.fan_tasks()[0].prompt.contains("exact file:line"));
    }

    #[test]
    fn plan_truncates_to_fan_cap_and_records_it() {
        let leaves: Vec<String> = (0..10).map(|i| format!("leaf {i}")).collect();
        let plan = Decomposer::plan(TaskClass::UnderSpecified, leaves).unwrap();
        assert_eq!(plan.fan_tasks().len(), FAN_CAP, "capped at FAN_CAP");
        assert_eq!(
            plan.truncated,
            Some(4),
            "the 4 dropped leaves are recorded, not silent"
        );
    }

    #[test]
    fn leaf_normalization_strips_only_legal_prefixes_and_preserves_paths() {
        let normalized = Decomposer::normalize_leaves(vec![
            "  1.   inspect   auth   flow  ".into(),
            "- trace\tcallers".into(),
            "(3) inspect schema".into(),
            ".github/workflows/ci.yml owns CI".into(),
            "-not-a-list-prefix".into(),
        ]);
        assert_eq!(
            normalized.leaves,
            vec![
                "inspect auth flow",
                "trace callers",
                "inspect schema",
                ".github/workflows/ci.yml owns CI",
                "-not-a-list-prefix",
            ]
        );
        assert_eq!(normalized.duplicates_removed, 0);
        assert_eq!(normalized.invalid_removed, 0);
    }

    #[test]
    fn deduplicates_before_fan_cap_and_reports_each_drop_reason() {
        let mut leaves = vec![
            "1. First question".into(),
            "first   QUESTION".into(),
            "\u{202e}unsafe".into(),
            String::new(),
        ];
        leaves.extend((2..=7).map(|n| format!("question {n}")));

        let plan = Decomposer::plan(TaskClass::MultiFile, leaves).unwrap();
        assert_eq!(plan.duplicates_removed, 1);
        assert_eq!(plan.invalid_removed, 2);
        assert_eq!(plan.truncated, Some(1));
        assert_eq!(plan.fan_tasks().len(), FAN_CAP);
        assert_eq!(plan.fan_tasks()[0].objective, "First question");
        assert_eq!(plan.fan_tasks()[5].objective, "question 6");
    }

    #[test]
    fn unicode_limit_is_scalar_safe_and_never_byte_truncates() {
        let exact = "界".repeat(LEAF_MAX_CHARS);
        let too_long = "界".repeat(LEAF_MAX_CHARS + 1);
        let normalized = Decomposer::normalize_leaves(vec![exact.clone(), too_long]);
        assert_eq!(normalized.leaves, vec![exact]);
        assert_eq!(normalized.invalid_removed, 1);
        assert_eq!(normalized.duplicates_removed, 0);
    }

    #[test]
    fn all_invalid_leaves_still_have_inspectable_diagnostics() {
        let normalized = Decomposer::normalize_leaves(vec![
            "  ".into(),
            "contains\u{0}control".into(),
            "x".repeat(LEAF_MAX_CHARS + 1),
        ]);
        assert!(normalized.leaves.is_empty());
        assert_eq!(normalized.invalid_removed, 3);
        assert!(Decomposer::plan(TaskClass::UnderSpecified, vec!["\u{200b}".into()],).is_none());
    }
}

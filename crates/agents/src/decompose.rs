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
//!
//! # `core/router` behind the frozen slot seam
//!
//! [`Decomposer::route`] *is* the `core/router` decision the spec names ("把任务或子任务路由到哪条
//! 处理路径", `docs/spec/evolution.md:72`), and until now it was reachable only as an inherent
//! function, so the pluggable-classifier upgrade ADR-011 promises had nowhere to plug in.
//! [`RouterStrategy`] puts that same heuristic behind [`iteron_protocol::slot::StrategySlot`], and
//! [`RouterStrategy::route_with`] is the narrowing-enforced call every caller uses instead of
//! `decide` — so a replacement classifier is a slot swap rather than a kernel change.
//!
//! Routing is an observation, not an authority: a route may only *narrow* what the caller already
//! permitted. Concretely, a decision may decline fan-out that was on offer, and may ask for fewer
//! leaves than the caller's ceiling; it can never turn fan-out on where the caller forbade it, nor
//! raise the breadth ceiling. Both directions are rejected by
//! [`RouterRoute::validate_against`], not merely discouraged, because a router that could widen
//! breadth would be a way to spend a budget the caller had already bounded.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};

use crate::stage::{AgentTask, Stage, WorkflowPlan};

/// The fan-out ceiling (ADR-004: the fan-out ceiling is cited at the call site). Leaves beyond this
/// are truncated, and the truncation is recorded on the `WorkflowPlan`. `WorkflowEngine` runs the
/// fan bounded-concurrent (owned `tokio::spawn` per worker under one `Governor`), so the breadth
/// ceiling is raised to 16 and actual wall-clock concurrency is bounded separately by the permit
/// count (`min(FAN_CAP, cores-2, admitted_workers)`), never by this cap alone.
pub const FAN_CAP: usize = 16;

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
        Self::plan_within(class, leaves, FAN_CAP)
    }

    /// Instantiate the topology under a breadth ceiling the router chose for this task.
    ///
    /// `plan` is this with the crate-wide `FAN_CAP`. The separate entry point exists so a
    /// `core/router` decision that asks for a *narrower* fan than `FAN_CAP` actually gets one:
    /// without it the router's breadth choice would be recorded and then ignored, which is the
    /// failure mode a slot seam is supposed to make impossible. `cap` is clamped to `FAN_CAP`
    /// rather than trusted, so this cannot become a way to widen the crate ceiling.
    pub fn plan_within(class: TaskClass, leaves: Vec<String>, cap: usize) -> Option<WorkflowPlan> {
        Self::plan_within_with(
            &crate::PlannerStrategy::default(),
            class,
            leaves,
            cap,
            CapabilitySet::only(Capability::ReadOnly),
        )
        .ok()
        .flatten()
    }

    /// Instantiate the same topology through the pinned `core/planner` seat. The slot sees only
    /// normalized objectives and returns positions into that caller-owned list; it can narrow or
    /// reorder the fan but cannot author prompts or exceed the router's breadth ceiling.
    pub fn plan_within_with(
        planner: &dyn StrategySlot,
        class: TaskClass,
        leaves: Vec<String>,
        cap: usize,
        ceiling: CapabilitySet,
    ) -> Result<Option<WorkflowPlan>, crate::PlannerError> {
        if !class.fans_out() {
            return Ok(None);
        }
        let cap = cap.min(FAN_CAP);
        let normalized = Self::normalize_leaves(leaves);
        let total = normalized.leaves.len();
        let proposal = crate::PlannerStrategy::plan_with(
            planner,
            &crate::PlannerObservation {
                version: crate::PLANNER_SLOT_VERSION,
                class,
                leaves: normalized.leaves.clone(),
                max_leaves: cap,
            },
            ceiling,
        )?;
        let kept: Vec<String> = proposal
            .plan
            .selected
            .into_iter()
            .map(|index| normalized.leaves[index].clone())
            .collect();
        if kept.is_empty() {
            return Ok(None);
        }
        let truncated = (total > kept.len()).then(|| total - kept.len());
        let tasks: Vec<AgentTask> = kept
            .into_iter()
            .enumerate()
            .map(|(id, objective)| AgentTask::investigator(id, objective))
            .collect();
        Ok(Some(WorkflowPlan {
            stages: vec![Stage::Fan { tasks }, Stage::Reduce],
            class,
            truncated,
            duplicates_removed: normalized.duplicates_removed,
            invalid_removed: normalized.invalid_removed,
        }))
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
    let iteron = tok.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | ';' | '(' | ')'));
    match iteron.split_once(':') {
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
    let iteron = trimmed.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | ';' | '.'));
    if iteron.contains("::") {
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

// --- the `core/router` slot ---------------------------------------------------------------------

/// Wire version of the router observation and decision. A decision this build cannot decode is
/// [`RouterSlotDecision::Unknown`], which carries no authority and no route.
pub const ROUTER_SLOT_VERSION: u16 = 1;

/// Upper bound on the task text a routing decision may be shown.
///
/// Deliberately the same 64 KiB `iteron_ctx::context_strategy` bounds its own task query at: the two
/// slots are handed the *same* submission text by the runtime, so a different bound here would mean
/// a task that routes but cannot have context selected for it, or the reverse.
pub const MAX_ROUTER_TASK_BYTES: usize = 64 * 1024;

/// The already-gathered inputs to one routing decision.
///
/// The caller owns every field. `repo` is the caller's cheap repo inspection (a router performs no
/// I/O and cannot go looking), and `fan_out_permitted`/`max_leaves` are ceilings, never requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterSlotObservation {
    pub version: u16,
    /// The submission being routed.
    pub task: String,
    /// Caller-gathered repo signals. A router may not gather its own.
    pub repo: RepoSignals,
    /// Whether fan-out is admissible at all for this run. `false` means the only routes on offer
    /// are non-fanning ones.
    pub fan_out_permitted: bool,
    /// The most investigation leaves the caller will fan. Bounded by [`FAN_CAP`]; meaningful only
    /// when `fan_out_permitted`.
    pub max_leaves: u16,
}

impl RouterSlotObservation {
    /// The conservative baseline: fan-out on offer up to the crate-wide [`FAN_CAP`].
    pub fn baseline(task: impl Into<String>, repo: RepoSignals) -> Self {
        Self {
            version: ROUTER_SLOT_VERSION,
            task: task.into(),
            repo,
            fan_out_permitted: true,
            max_leaves: FAN_CAP as u16,
        }
    }

    /// Withdraw fan-out from the offer without touching any other field.
    pub fn without_fan_out(mut self) -> Self {
        self.fan_out_permitted = false;
        self.max_leaves = 0;
        self
    }

    fn validate(&self) -> Result<(), RouterSlotError> {
        if self.version != ROUTER_SLOT_VERSION {
            return Err(RouterSlotError::UnsupportedVersion);
        }
        if self.task.len() > MAX_ROUTER_TASK_BYTES {
            return Err(RouterSlotError::InvalidObservation(
                "router task exceeds its bounded observation",
            ));
        }
        if self.max_leaves as usize > FAN_CAP {
            return Err(RouterSlotError::InvalidObservation(
                "router breadth ceiling exceeds the crate fan cap",
            ));
        }
        if self.fan_out_permitted && self.max_leaves == 0 {
            return Err(RouterSlotError::InvalidObservation(
                "fan-out was offered with no breadth to fan into",
            ));
        }
        Ok(())
    }
}

/// Which handling path a task takes, and how wide it may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterRoute {
    pub class: TaskClass,
    /// Leaves this route reserves. Always `0` for a class that does not fan out.
    pub max_leaves: u16,
}

impl RouterRoute {
    /// The single-agent loop: no fan-out, no breadth. Also the fail-closed answer.
    pub fn direct(class: TaskClass) -> Self {
        Self {
            class,
            max_leaves: 0,
        }
    }

    /// Does this route engage the fan-out DAG?
    ///
    /// Reserved breadth is the answer, not the class. A class that *could* fan still runs as the
    /// single-agent loop when the caller withdrew the offer, and the class is kept rather than
    /// rewritten so the durable record still says what the task actually looked like.
    pub fn fans_out(self) -> bool {
        self.max_leaves > 0
    }

    /// Reject a decision that reached past what the caller offered.
    ///
    /// Typed rather than clamped, for the reason the sibling slots give: silently clamping a
    /// widened route back to the ceiling would let a pinned policy ship a breadth nobody notices
    /// is being ignored.
    fn validate_against(&self, observation: &RouterSlotObservation) -> Result<(), RouterSlotError> {
        if !self.fans_out() {
            return Ok(());
        }
        if !self.class.fans_out() {
            return Err(RouterSlotError::InvalidDecision(
                "a non-fanning class must not reserve fan breadth",
            ));
        }
        if !observation.fan_out_permitted {
            return Err(RouterSlotError::DecisionWidened(
                "route fans out where the caller permitted no fan-out",
            ));
        }
        if self.max_leaves > observation.max_leaves {
            return Err(RouterSlotError::DecisionWidened(
                "route breadth escaped the caller's leaf ceiling",
            ));
        }
        Ok(())
    }
}

/// The version-skew boundary for a router-slot decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterSlotDecision {
    Route {
        route: RouterRoute,
    },
    #[serde(other)]
    Unknown,
}

/// A route plus the capabilities still eligible after intersection with the caller ceiling.
/// Eligibility is evidence for a later gate, never authority to run anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterProposal {
    pub route: RouterRoute,
    pub eligible: CapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterSlotError {
    WrongSlot,
    NotReadOnly,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    DecisionWidened(&'static str),
    UnsupportedVersion,
}

impl fmt::Display for RouterSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSlot => formatter.write_str("strategy does not implement core/router"),
            Self::NotReadOnly => {
                formatter.write_str("routing was not admitted as a read-only observation")
            }
            Self::InvalidObservation(reason)
            | Self::InvalidDecision(reason)
            | Self::DecisionWidened(reason) => formatter.write_str(reason),
            Self::UnsupportedVersion => formatter.write_str("unsupported router slot version"),
        }
    }
}

impl std::error::Error for RouterSlotError {}

/// The slot identity this module implements.
pub fn router_slot() -> SlotId {
    SlotId("core/router".into())
}

/// Hand-written baseline implementation of `core/router`: [`Decomposer::route`] behind the seam.
#[derive(Debug, Clone)]
pub struct RouterStrategy {
    slot: SlotId,
}

impl Default for RouterStrategy {
    fn default() -> Self {
        Self {
            slot: router_slot(),
        }
    }
}

impl RouterStrategy {
    /// Typed facade for callers of the built-in baseline.
    pub fn route(
        &self,
        input: &RouterSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<RouterProposal, RouterSlotError> {
        Self::route_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    ///
    /// This, not [`StrategySlot::decide`], is what callers use: it is where the slot identity is
    /// checked, where `decide_narrowed` enforces that a route cannot mint authority, and where a
    /// widened breadth is refused.
    pub fn route_with(
        slot: &dyn StrategySlot,
        input: &RouterSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<RouterProposal, RouterSlotError> {
        if slot.slot().as_persisted_str() != "core/router" {
            return Err(RouterSlotError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input)
            .map_err(|_| RouterSlotError::InvalidObservation("router observation is invalid"))?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::ReadOnly) {
            return Err(RouterSlotError::NotReadOnly);
        }
        let decision = serde_json::from_value::<RouterSlotDecision>(outcome.decision)
            .map_err(|_| RouterSlotError::InvalidDecision("router decision is invalid"))?;
        let RouterSlotDecision::Route { route } = decision else {
            return Err(RouterSlotError::UnsupportedVersion);
        };
        route.validate_against(input)?;
        Ok(RouterProposal {
            route,
            eligible: outcome.admitted,
        })
    }

    /// The baseline route: the existing deterministic heuristic, narrowed to the offer.
    ///
    /// A fanning class the caller did not permit becomes a direct route rather than an error —
    /// "you may not fan out" is an answer the router can honour. The class is preserved, so the
    /// record still says what the task looked like even when it was not allowed to fan.
    fn decide_typed(input: &RouterSlotObservation) -> RouterRoute {
        let class = Decomposer::route(&input.task, &input.repo);
        if class.fans_out() && input.fan_out_permitted {
            return RouterRoute {
                class,
                max_leaves: input.max_leaves,
            };
        }
        RouterRoute::direct(class)
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(RouterSlotDecision::Unknown)
                .expect("unit router decision serializes"),
        }
    }
}

impl StrategySlot for RouterStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<RouterSlotObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        SlotOutcome {
            admitted: CapabilitySet::only(Capability::ReadOnly).intersect(observation.ceiling),
            decision: serde_json::to_value(RouterSlotDecision::Route {
                route: Self::decide_typed(&input),
            })
            .expect("router route serializes"),
        }
    }
}

#[cfg(test)]
mod router_slot_tests {
    use super::*;

    fn broad() -> RouterSlotObservation {
        RouterSlotObservation::baseline(
            "rename the config field everywhere",
            RepoSignals {
                has_test_command: false,
                file_count: 4_000,
            },
        )
    }

    fn read_only() -> CapabilitySet {
        CapabilitySet::only(Capability::ReadOnly)
    }

    #[test]
    fn the_slot_returns_the_same_class_the_inherent_heuristic_does() {
        let input = broad();
        let proposal = RouterStrategy::default()
            .route(&input, read_only())
            .unwrap();
        assert_eq!(
            proposal.route.class,
            Decomposer::route(&input.task, &input.repo),
            "putting route() behind the seam must not change what it decides"
        );
        assert_eq!(proposal.route.max_leaves, FAN_CAP as u16);
        assert!(proposal.eligible.contains(Capability::ReadOnly));
    }

    #[test]
    fn a_localized_task_reserves_no_breadth() {
        let input = RouterSlotObservation::baseline(
            "fix the panic in crates/cli/src/runtime.rs:42",
            RepoSignals::default(),
        );
        let proposal = RouterStrategy::default()
            .route(&input, read_only())
            .unwrap();
        assert_eq!(proposal.route.class, TaskClass::Localized);
        assert!(!proposal.route.fans_out());
        assert_eq!(proposal.route.max_leaves, 0);
    }

    #[test]
    fn withdrawing_the_fan_out_offer_forces_the_single_agent_loop() {
        let input = broad().without_fan_out();
        let proposal = RouterStrategy::default()
            .route(&input, read_only())
            .unwrap();
        assert!(
            !proposal.route.fans_out(),
            "a task that would fan must not fan when the caller offered no fan-out"
        );
        assert_eq!(proposal.route.max_leaves, 0);
        assert_eq!(
            proposal.route.class,
            TaskClass::MultiFile,
            "the class the task actually looked like is preserved for the record"
        );
    }

    #[test]
    fn a_non_fanning_class_may_not_reserve_breadth() {
        struct Confused(SlotId);
        impl StrategySlot for Confused {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::only(Capability::ReadOnly),
                    decision: serde_json::to_value(RouterSlotDecision::Route {
                        route: RouterRoute {
                            class: TaskClass::Localized,
                            max_leaves: 2,
                        },
                    })
                    .unwrap(),
                }
            }
        }

        assert_eq!(
            RouterStrategy::route_with(&Confused(router_slot()), &broad(), read_only()),
            Err(RouterSlotError::InvalidDecision(
                "a non-fanning class must not reserve fan breadth"
            ))
        );
    }

    #[test]
    fn a_narrower_leaf_ceiling_is_honoured_not_ignored() {
        let mut input = broad();
        input.max_leaves = 3;
        let proposal = RouterStrategy::default()
            .route(&input, read_only())
            .unwrap();
        assert_eq!(proposal.route.max_leaves, 3);

        let leaves: Vec<String> = (0..9).map(|index| format!("leaf {index}")).collect();
        let plan = Decomposer::plan_within(
            proposal.route.class,
            leaves,
            proposal.route.max_leaves as usize,
        )
        .expect("a fanning route plans");
        assert_eq!(plan.fan_tasks().len(), 3);
        assert_eq!(plan.truncated, Some(6));
    }

    #[test]
    fn a_route_cannot_fan_where_the_caller_forbade_it() {
        struct Sneaky(SlotId);
        impl StrategySlot for Sneaky {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::only(Capability::ReadOnly),
                    decision: serde_json::to_value(RouterSlotDecision::Route {
                        route: RouterRoute {
                            class: TaskClass::MultiFile,
                            max_leaves: 1,
                        },
                    })
                    .unwrap(),
                }
            }
        }

        assert_eq!(
            RouterStrategy::route_with(
                &Sneaky(router_slot()),
                &broad().without_fan_out(),
                read_only(),
            ),
            Err(RouterSlotError::DecisionWidened(
                "route fans out where the caller permitted no fan-out"
            ))
        );
    }

    #[test]
    fn a_route_cannot_widen_the_leaf_ceiling() {
        struct Greedy(SlotId);
        impl StrategySlot for Greedy {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: RouterSlotObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                SlotOutcome {
                    admitted: CapabilitySet::only(Capability::ReadOnly),
                    decision: serde_json::to_value(RouterSlotDecision::Route {
                        route: RouterRoute {
                            class: TaskClass::MultiFile,
                            max_leaves: input.max_leaves.saturating_add(1),
                        },
                    })
                    .unwrap(),
                }
            }
        }

        let mut input = broad();
        input.max_leaves = 4;
        assert_eq!(
            RouterStrategy::route_with(&Greedy(router_slot()), &input, read_only()),
            Err(RouterSlotError::DecisionWidened(
                "route breadth escaped the caller's leaf ceiling"
            ))
        );
    }

    #[test]
    fn a_route_cannot_mint_authority_it_was_not_shown() {
        struct Grabby(SlotId);
        impl StrategySlot for Grabby {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::from_iter_capabilities([
                        Capability::ReadOnly,
                        Capability::CodeExecuting,
                        Capability::IrreversibleExternal,
                    ]),
                    decision: serde_json::to_value(RouterSlotDecision::Route {
                        route: RouterRoute::direct(TaskClass::Localized),
                    })
                    .unwrap(),
                }
            }
        }

        let proposal =
            RouterStrategy::route_with(&Grabby(router_slot()), &broad(), read_only()).unwrap();
        assert!(proposal.eligible.contains(Capability::ReadOnly));
        assert!(!proposal.eligible.contains(Capability::CodeExecuting));
        assert!(!proposal.eligible.contains(Capability::IrreversibleExternal));
        assert!(proposal.eligible.is_subset_of(read_only()));
    }

    #[test]
    fn a_closed_ceiling_refuses_to_route_at_all() {
        assert_eq!(
            RouterStrategy::default().route(&broad(), CapabilitySet::none()),
            Err(RouterSlotError::NotReadOnly)
        );
    }

    #[test]
    fn an_unknown_wire_version_degrades_without_authority_or_a_route() {
        let strategy = RouterStrategy::default();
        let mut input = broad();
        input.version = ROUTER_SLOT_VERSION + 1;
        let outcome = strategy.decide(&SlotObservation {
            slot: strategy.slot().clone(),
            ceiling: CapabilitySet::from_iter_capabilities([
                Capability::ReadOnly,
                Capability::CodeExecuting,
            ]),
            payload: serde_json::to_value(&input).unwrap(),
        });
        assert!(outcome.admitted.is_empty());
        assert_eq!(
            serde_json::from_value::<RouterSlotDecision>(outcome.decision).unwrap(),
            RouterSlotDecision::Unknown
        );
        assert_eq!(
            strategy.route(&input, read_only()),
            Err(RouterSlotError::UnsupportedVersion)
        );
    }

    #[test]
    fn an_observation_that_breaks_its_own_bounds_is_refused_before_any_route() {
        let strategy = RouterStrategy::default();

        let mut over_cap = broad();
        over_cap.max_leaves = FAN_CAP as u16 + 1;
        assert_eq!(
            strategy.route(&over_cap, read_only()),
            Err(RouterSlotError::InvalidObservation(
                "router breadth ceiling exceeds the crate fan cap"
            ))
        );

        let mut empty_offer = broad();
        empty_offer.max_leaves = 0;
        assert_eq!(
            strategy.route(&empty_offer, read_only()),
            Err(RouterSlotError::InvalidObservation(
                "fan-out was offered with no breadth to fan into"
            ))
        );

        let mut oversized = broad();
        oversized.task = "x".repeat(MAX_ROUTER_TASK_BYTES + 1);
        assert_eq!(
            strategy.route(&oversized, read_only()),
            Err(RouterSlotError::InvalidObservation(
                "router task exceeds its bounded observation"
            ))
        );
    }

    #[test]
    fn a_strategy_for_another_slot_is_refused_by_identity_not_by_luck() {
        struct Impostor(SlotId);
        impl StrategySlot for Impostor {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::only(Capability::ReadOnly),
                    decision: serde_json::to_value(RouterSlotDecision::Route {
                        route: RouterRoute::direct(TaskClass::Localized),
                    })
                    .unwrap(),
                }
            }
        }

        assert_eq!(
            RouterStrategy::route_with(
                &Impostor(SlotId("core/planner".into())),
                &broad(),
                read_only(),
            ),
            Err(RouterSlotError::WrongSlot)
        );
    }

    #[test]
    fn the_slot_identity_is_nameable_by_a_policy_bundle() {
        let slot = router_slot();
        assert!(slot.validate().is_ok());
        assert_eq!(slot.as_persisted_str(), "core/router");
        assert_eq!(
            serde_json::to_value(&slot).unwrap(),
            serde_json::json!("core/router")
        );
    }

    #[test]
    fn the_decision_wire_form_is_forward_compatible() {
        let unknown: RouterSlotDecision =
            serde_json::from_str(r#"{"kind":"detour","route":{"class":"multi_file"}}"#).unwrap();
        assert_eq!(unknown, RouterSlotDecision::Unknown);
        let route: RouterSlotDecision = serde_json::from_str(
            r#"{"kind":"route","route":{"class":"multi_file","max_leaves":2}}"#,
        )
        .unwrap();
        assert_eq!(
            route,
            RouterSlotDecision::Route {
                route: RouterRoute {
                    class: TaskClass::MultiFile,
                    max_leaves: 2
                }
            }
        );
    }
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
        let leaves: Vec<String> = (0..(FAN_CAP + 4)).map(|i| format!("leaf {i}")).collect();
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
        leaves.extend((2..=17).map(|n| format!("question {n}")));

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

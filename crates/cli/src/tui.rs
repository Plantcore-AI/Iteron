//! The interactive TUI (ratatui + crossterm) — the product face, like Codex/Claude Code.
//!
//! Layout: a full-width semantic transcript; an on-demand activity shelf and explicit steer/after-
//! turn lanes; one framed composer; contextual help; and a stable bottom status line. Metrics
//! progressively disclose instead of becoming permanent dashboard chrome. Ctrl-C/Esc request a
//! safe-point stop; Esc/Ctrl-D quits when idle.
//!
//! The agent runs in a background task and streams `UiEvent`s over a channel; the render loop
//! drains them and redraws. The kernel does the work; this is a thin, replaceable front-end
//! on the same core (ADR-010: frontends are adapters).

use crate::commands;
use crate::editor::Editor;
use crate::providers::{ModelSelection, ProviderDirectory};
use crate::{block, surface, theme};
use core_ctx::ContextEstimate;
use core_kernel::{
    Agent, UiEvent, WorkflowAgentOutcomeUi, WorkflowPhaseUi, WorkflowRunOutcomeUi, WorkflowUiEvent,
};
use core_obs::CostState;
use core_protocol::{
    Capability, Effort, Op, Outcome, PermissionMode, PermissionRules, ReasoningEffort,
    RuntimePolicySource, SubmissionId, Usage, Verdict,
};
use core_provider::EffortApplication;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as CEvent, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::{cursor, execute, terminal};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::{Frame, Terminal};
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A pending capability approval the operator must answer (mode produced an `Ask` verdict).
struct Pending {
    id: SubmissionId,
    tool: String,
    cap: Capability,
    reason: String,
    arguments: serde_json::Value,
    workspace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalChoice {
    Once,
    Session,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalInput {
    Consumed,
    Answer { approved: bool, remember: bool },
}

enum RunCompletion {
    Outcome(Outcome),
    Error(String),
}

/// A human label for a capability class, for a security prompt. NEVER the raw `{:?}` Debug (which
/// leaks `IrreversibleExternal` etc. into a user-facing approval — review R5). Kept local to the TUI
/// so the protocol `Capability` enum is untouched.
fn cap_label(cap: Capability) -> &'static str {
    match cap {
        Capability::ReadOnly => "read-only",
        Capability::ReversibleLocal => "reversible edit",
        Capability::CodeExecuting => "runs code",
        Capability::TrustMutating => "mutates trust config",
        Capability::IrreversibleExternal => "external egress",
    }
}

fn capability_can_be_remembered(cap: Capability) -> bool {
    matches!(cap, Capability::ReversibleLocal | Capability::CodeExecuting)
}

fn approval_operation_text(pending: &Pending) -> String {
    let verb = block::verb_for(&pending.tool);
    let string_arg = |keys: &[&str]| {
        keys.iter().find_map(|key| {
            pending
                .arguments
                .get(*key)
                .and_then(serde_json::Value::as_str)
        })
    };
    if let Some(command) = string_arg(&["command", "cmd"]) {
        return format!("{verb}: {command}");
    }
    if let Some(path) = string_arg(&["path", "file", "file_path", "filename"]) {
        return format!("{verb}: {path}");
    }
    if let Some(target) = string_arg(&["url", "host", "query", "pattern"]) {
        return format!("{verb}: {target}");
    }
    let encoded = match &pending.arguments {
        serde_json::Value::Null => String::new(),
        value => serde_json::to_string(value).unwrap_or_else(|_| "[unrenderable arguments]".into()),
    };
    if encoded.is_empty() {
        verb
    } else {
        format!("{verb}: {encoded}")
    }
}

/// A human label for a run `Outcome`, for the status slot. NEVER the raw `{:?}` Debug (which leaks
/// `BudgetExhausted("max_turns")` — escaped quotes and all — into the most-visible chrome; TUI v3 §7).
/// Kept local to the TUI so the protocol enum is untouched.
fn outcome_label(o: &Outcome) -> String {
    match o {
        Outcome::Done => "done".into(),
        Outcome::Interrupted => "interrupted".into(),
        Outcome::Stuck => "stuck".into(),
        Outcome::HarnessError => "harness error".into(),
        Outcome::BudgetExhausted(kind) => match *kind {
            "max_turns" => "hit the turn budget".into(),
            "max_usd" | "max_cost" => "hit the cost budget".into(),
            other => format!("hit the {other} budget"),
        },
    }
}

fn request_input_tokens(usage: Usage) -> u64 {
    usage
        .input
        .saturating_add(usage.cache_read)
        .saturating_add(usage.cache_creation)
}

fn fmt_token_count(tokens: u64) -> String {
    if tokens >= 1_000_000 {
        format!("{:.1}m", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}k", tokens as f64 / 1_000.0)
    } else {
        tokens.to_string()
    }
}

fn effort_application_detail(application: EffortApplication) -> String {
    match application {
        EffortApplication::Exact { requested } => {
            format!(
                "{} sent unchanged (model support not catalog-proven)",
                requested.label()
            )
        }
        EffortApplication::Mapped { requested, sent } => {
            format!("{} requested → {} sent", requested.label(), sent.label())
        }
        EffortApplication::BudgetBased {
            requested,
            budget_tokens,
        } => format!(
            "{} requested; {}-token thinking budget (not exact)",
            requested.label(),
            fmt_token_count(u64::from(budget_tokens))
        ),
        EffortApplication::ToggleOnly { requested, enabled } => format!(
            "{} requested; thinking {} only (not exact)",
            requested.label(),
            if enabled { "enabled" } else { "disabled" }
        ),
        EffortApplication::Unsupported { requested } => {
            format!(
                "{} requested; adapter/model does not enforce it",
                requested.label()
            )
        }
    }
}

fn effort_symbol(effort: ReasoningEffort) -> &'static str {
    match effort {
        ReasoningEffort::Low => "○",
        ReasoningEffort::Medium => "◐",
        ReasoningEffort::High => "●",
        ReasoningEffort::XHigh => "⦿",
        ReasoningEffort::Max => "◉",
    }
}

fn visual_reasoning_effort(effort: ReasoningEffort) -> String {
    format!("{} {}", effort_symbol(effort), effort.label())
}

fn visual_selected_effort(effort: Effort) -> String {
    if effort == Effort::Ultracode {
        "◉ max · ultracode".into()
    } else {
        visual_reasoning_effort(effort.reasoning_effort())
    }
}

/// Claude-style effort symbol, but derived from the adapter's observed application rather than the
/// picker alone. Mapping and non-exact enforcement stay visible instead of being prettified away.
fn effort_status_label(app: &App) -> String {
    match app.effort_application {
        Some(EffortApplication::Exact { requested }) => {
            let exact = visual_reasoning_effort(requested);
            if app.effort == Effort::Ultracode {
                format!("{exact} · ultracode")
            } else {
                exact
            }
        }
        Some(EffortApplication::Mapped { requested, sent }) => {
            let mapped = if requested == sent {
                visual_reasoning_effort(sent)
            } else {
                format!(
                    "{} ← {} requested",
                    visual_reasoning_effort(sent),
                    requested.label()
                )
            };
            if app.effort == Effort::Ultracode {
                format!("{mapped} · ultracode")
            } else {
                mapped
            }
        }
        Some(EffortApplication::BudgetBased { requested, .. }) => {
            format!("{} · token budget", visual_reasoning_effort(requested))
        }
        Some(EffortApplication::ToggleOnly { requested, enabled }) => format!(
            "{} · thinking {} only",
            visual_reasoning_effort(requested),
            if enabled { "on" } else { "off" }
        ),
        Some(EffortApplication::Unsupported { requested }) => {
            format!("{} · not enforced", visual_reasoning_effort(requested))
        }
        None => visual_selected_effort(app.effort),
    }
}

/// Convert untrusted display text into the only representation allowed to enter retained TUI
/// state. Secret-shaped substrings are redacted and terminal control characters are escaped so a
/// tool/user string cannot inject terminal commands or rewrite earlier rows.
fn ui_safe_text(text: &str) -> String {
    let scrubbed = core_record::redact::scrub(text);
    let mut safe = String::with_capacity(scrubbed.len());
    for ch in scrubbed.chars() {
        match ch {
            '\n' | '\t' => safe.push(ch),
            ch if ch.is_control() => safe.extend(ch.escape_default()),
            ch => safe.push(ch),
        }
    }
    safe
}

fn ui_safe_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(text) => Value::String(ui_safe_text(text)),
        Value::Array(values) => Value::Array(values.iter().map(ui_safe_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (ui_safe_text(key), ui_safe_json(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

/// Split a composer line's leading command token for first-token semantic coloring (TUI v3 §8): a
/// `/`,`@`,`#` sigil token → `accent`, a `!` shell token → `warn`. Returns `(token, remainder, color)`
/// or `None` when the line has no leading sigil. The sigil chars are ASCII, so byte-slicing on the
/// first whitespace is char-boundary-safe.
fn command_token(line: &str, theme: &theme::Theme) -> Option<(String, String, Color)> {
    let first = line.chars().next()?;
    let color = match first {
        '/' | '@' | '#' => theme.accent,
        '!' => theme.warn,
        _ => return None,
    };
    let end = line.find(char::is_whitespace).unwrap_or(line.len());
    Some((line[..end].to_string(), line[end..].to_string(), color))
}

/// An open autocomplete menu (slash commands or `@file` paths).
struct Completion {
    /// Menu entries: (replacement-token, one-line description).
    items: Vec<(String, String)>,
    sel: usize,
    /// Byte index in the input where the token being completed starts (after '/' or '@').
    token_start: usize,
    /// The prefix char ('/' for slash, '@' for file) — kept for the accepted replacement.
    lead: char,
}

/// What applying a picked item does. An enum (not a boxed closure) because the TUI is single-threaded
/// and the action is applied to the idle agent directly (ADR-015 R7.a / C2 — no model→effort child).
#[derive(Clone)]
enum PickAction {
    SetModel(ModelSelection),
    SetEffort(Effort),
    SetMode(PermissionMode),
    SetCap(Capability, Verdict),
    SetTheme(theme::Theme),
    /// Prepare an explicit restart command in the composer. This never swaps or executes an Agent.
    PrepareResume(String),
    /// Informational row (agents/skills browse) — accepting does nothing.
    Info,
}

/// One row in a picker. Flat pickers leave `parent` empty and `depth` at zero; tree pickers keep
/// stable item indices and point children at their parent. A disabled leaf remains navigable (so its
/// reason is discoverable), but cannot be accepted.
struct PickItem {
    label: String,
    hint: String,
    is_current: bool,
    action: PickAction,
    parent: Option<usize>,
    depth: usize,
    expandable: bool,
    expanded: bool,
    enabled: bool,
    disabled_reason: Option<String>,
}

impl PickItem {
    /// Preserve the original behaviour for all non-hierarchical pickers.
    fn flat(
        label: impl Into<String>,
        hint: impl Into<String>,
        is_current: bool,
        action: PickAction,
    ) -> Self {
        Self {
            label: label.into(),
            hint: hint.into(),
            is_current,
            action,
            parent: None,
            depth: 0,
            expandable: false,
            expanded: false,
            enabled: true,
            disabled_reason: None,
        }
    }
}

/// A modal selection overlay — the interactive picker for model/effort/mode/permissions/theme/…
/// (R7.a). Owns the keyboard while open (C6). For a theme picker it live-previews on nav and restores
/// `saved_theme` on Esc (C1).
struct Picker {
    title: String,
    items: Vec<PickItem>,
    sel: usize,
    /// Incremental, Unicode-safe filter text. Bounded so an open picker cannot retain an
    /// arbitrarily large paste/key stream.
    query: String,
    /// Snapshot of the theme before a theme-picker opened, so Esc restores it (C1). `Some` only for
    /// the theme picker (also the "am I a live-preview picker?" flag).
    saved_theme: Option<theme::Theme>,
}

const MAX_PICKER_QUERY_CHARS: usize = 96;

impl Picker {
    /// Return stable item indices for rows whose complete ancestor chain is expanded. Invalid or
    /// cyclic parent links fail closed by hiding the affected row instead of hanging the UI.
    fn visible_indices(&self) -> Vec<usize> {
        if !self.has_query() {
            return (0..self.items.len())
                .filter(|&index| self.item_is_visible(index))
                .collect();
        }

        // Search is a projection over the stable tree. A matching leaf brings its complete ancestor
        // path into view; a matching branch brings its descendants too, so searching a provider or
        // family does not leave a dead header with nothing selectable beneath it.
        let direct: Vec<bool> = (0..self.items.len())
            .map(|index| self.item_matches_query(index))
            .collect();
        let mut included = vec![false; self.items.len()];
        for (index, matched) in direct.iter().copied().enumerate() {
            if !matched {
                continue;
            }
            included[index] = true;
            self.include_ancestors(index, &mut included);
            if self.items.get(index).is_some_and(|item| item.expandable) {
                for (descendant, is_included) in included.iter_mut().enumerate() {
                    if self.item_descends_from(descendant, index) {
                        *is_included = true;
                    }
                }
            }
        }
        (0..self.items.len())
            .filter(|&index| included[index])
            .collect()
    }

    fn has_query(&self) -> bool {
        !self.query.is_empty()
    }

    fn item_matches_query(&self, index: usize) -> bool {
        let Some(item) = self.items.get(index) else {
            return false;
        };
        let haystack = format!(
            "{} {} {}",
            item.label,
            item.hint,
            item.disabled_reason.as_deref().unwrap_or_default()
        )
        .to_lowercase();
        self.query
            .to_lowercase()
            .split_whitespace()
            .all(|term| haystack.contains(term))
    }

    fn include_ancestors(&self, index: usize, included: &mut [bool]) {
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 || parent_index >= included.len() {
                return;
            }
            remaining -= 1;
            included[parent_index] = true;
            parent = self.items.get(parent_index).and_then(|item| item.parent);
        }
    }

    fn item_descends_from(&self, index: usize, ancestor: usize) -> bool {
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            if parent_index == ancestor {
                return true;
            }
            parent = self.items.get(parent_index).and_then(|item| item.parent);
        }
        false
    }

    fn normalize_selection(&mut self, visible: &[usize]) {
        if visible.is_empty() {
            return;
        }
        if visible.contains(&self.sel)
            && (!self.has_query()
                || self.item_matches_query(self.sel)
                || self
                    .items
                    .get(self.sel)
                    .is_some_and(|item| item.enabled && !item.expandable))
        {
            return;
        }
        if self.has_query()
            && let Some(index) = visible.iter().copied().find(|&index| {
                self.item_matches_query(index)
                    && self
                        .items
                        .get(index)
                        .is_some_and(|item| item.enabled && !item.expandable)
            })
        {
            self.sel = index;
            return;
        }
        self.sel = visible
            .iter()
            .copied()
            .find(|&index| {
                self.items
                    .get(index)
                    .is_some_and(|item| item.enabled && !item.expandable)
            })
            .unwrap_or(visible[0]);
    }

    fn item_is_visible(&self, index: usize) -> bool {
        let Some(item) = self.items.get(index) else {
            return false;
        };
        let mut parent = item.parent;
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            let Some(ancestor) = self.items.get(parent_index) else {
                return false;
            };
            if !ancestor.expandable || !ancestor.expanded {
                return false;
            }
            parent = ancestor.parent;
        }
        true
    }

    fn visible_selection(&self, visible: &[usize]) -> usize {
        visible
            .iter()
            .position(|&index| index == self.sel)
            .unwrap_or(0)
    }

    fn ancestor_breadcrumb(&self, index: usize) -> String {
        let mut labels = Vec::new();
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return String::new();
            }
            remaining -= 1;
            let Some(item) = self.items.get(parent_index) else {
                return String::new();
            };
            labels.push(item.label.clone());
            parent = item.parent;
        }
        labels.reverse();
        labels.join(" / ")
    }
}

/// The outcome of a keypress routed to an open picker.
enum PickerEvent {
    /// The key was consumed (navigation/preview); redraw.
    Consumed,
    /// Enter/Tab: apply this action.
    Accept(PickAction),
    /// Esc: close (theme already restored).
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionAdmission {
    Accept,
    IgnoreEmpty,
    Reject,
}

/// The semantic destination of Enter for the current draft. Dispatch, composer title and footer
/// all consult this one reducer so the UI cannot promise “steer” while routing the same bytes to a
/// post-turn command lane (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputDestination {
    StartTurn,
    SteerCurrentRun,
    AfterTurn,
}

fn input_destination(running: bool, text: &str) -> InputDestination {
    if !running {
        InputDestination::StartTurn
    } else if text.trim_start().starts_with(['/', '!']) {
        InputDestination::AfterTurn
    } else {
        InputDestination::SteerCurrentRun
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingInput {
    seq: u64,
    text: String,
}

/// A model tool which is active in the activity shelf but has not yet earned a transcript row.
///
/// This is deliberately a presentation projection: the kernel/rollout already owns the durable
/// lifecycle. Holding the card here prevents a sub-300 ms tool from flashing a `running` row and
/// immediately replacing it with a settled one; it never suppresses the eventual completed card.
struct PendingToolProjection {
    id: String,
    name: String,
    args: serde_json::Value,
    started: Instant,
    reveal_deadline: Instant,
}

/// TUI state.
struct App {
    /// The structured semantic transcript (ADR-015): typed self-rendering blocks, not a flat log.
    transcript: Vec<block::Block>,
    /// Monotonic block-id source; a `ToolEnd` mutates its card by id, never by Vec position (R2).
    next_id: u64,
    /// Revealed tool_use id -> the block id of its card, so a late `ToolEnd` finds its originating
    /// card. Starts live in `pending_tools` during the anti-flash reveal delay.
    tool_index: std::collections::HashMap<String, u64>,
    /// Start-ordered tool projections waiting for the reveal deadline. The activity shelf is
    /// updated immediately, independently of this transcript delay.
    pending_tools: VecDeque<PendingToolProjection>,
    /// workflow run id -> its one live card. Lifecycle events mutate this block in place.
    workflow_index: std::collections::HashMap<String, u64>,
    /// The active color theme (ADR-015 §4).
    theme: theme::Theme,
    theme_epoch: u64,
    /// Settled semantic blocks render once per width/theme/revision. Active blocks bypass this cache
    /// so spinner and workflow state remain live.
    /// One render slot per settled block. Replacing the `(revision, rows)` tuple on mutation keeps
    /// repeated fold/unfold cycles bounded instead of retaining every historical revision.
    render_cache: std::collections::HashMap<u64, (u64, Vec<Line<'static>>)>,
    render_cache_width: u16,
    render_cache_theme_epoch: u64,
    editor: Editor,
    status: String,
    running: bool,
    interrupting: bool,
    /// Rows scrolled UP from the bottom (0 = pinned to the newest line).
    bottom_offset: u16,
    /// Whether new output follows the tail. Scrolling up disables follow until Ctrl-End or the
    /// viewport returns to the bottom, so streaming never steals the reader's position.
    follow_tail: bool,
    unread_updates: u32,
    last_total_rows: u16,
    last_view_h: u16,
    /// true once the user asks to quit and no run is active.
    quit: bool,
    // live-accumulating current assistant paragraph (so streamed text coalesces into one line)
    cur_text: String,
    cur_text_revision: u64,
    cur_doc_revision: u64,
    cur_doc: Option<crate::markdown::MarkdownDoc>,
    // Hold the unfinished token across arbitrary provider deltas so a split credential cannot be
    // rendered for one frame before the complete token becomes recognizable.
    text_scrubber: crate::output::StreamingScrubber,
    // live extended-thinking tail, shown dimmed while the model reasons (bounded).
    cur_think: String,
    thinking_scrubber: crate::output::StreamingScrubber,
    /// The operator's current permission posture (mirrors the agent's; shown in the status line).
    mode: PermissionMode,
    effort: Effort,
    model: String,
    /// Provider identity is independent from model identity. The pair changes atomically.
    provider_id: String,
    /// Cumulative run economics. Unknown is first-class; the UI never formats an unverified rate.
    cost: CostState,
    /// Provider-reported usage for the most recently completed direct model request. This is not
    /// merged with children and is never accumulated into a fake current-context number.
    last_turn_usage: Option<Usage>,
    /// Preflight estimate for the exact request projection that produced `last_turn_usage`.
    last_context: Option<ContextEstimate>,
    /// Catalog-advertised context window for the selected model. Unknown remains `None`; the
    /// compaction trigger is a policy threshold and must never be substituted here.
    model_context_window: Option<u64>,
    /// Output allowance reserved by the exact request admission that produced the last telemetry.
    reserved_output_tokens: Option<u32>,
    compaction_trigger_tokens: usize,
    /// What the selected adapter actually did with the semantic effort request on the last turn.
    effort_application: Option<EffortApplication>,
    /// Completed model turns this session; wide active shelves and `/status` may disclose it.
    turns: u32,
    /// An approval the kernel is blocked on, awaiting a y/n/a answer.
    pending: Option<Pending>,
    /// Keyboard focus inside the blocking permission decision. Deny is the fail-closed default.
    approval_choice: ApprovalChoice,
    /// The open autocomplete menu, if any.
    completion: Option<Completion>,
    /// The open selection picker, if any (owns the keyboard while open).
    picker: Option<Picker>,
    /// Exact restart command prepared by a session selection. It is display/copy state only: an
    /// unchanged handoff is never submitted to the model or executed inside this process.
    resume_handoff: Option<String>,
    /// When the current run started (for the elapsed/spinner indicator).
    run_started: Option<Instant>,
    /// Currently-running tool calls, ordered by start time. This feeds the one-line activity shelf;
    /// full details remain in correlated transcript cards.
    active_tools: VecDeque<(String, String)>,
    spin: usize,
    /// Hit-test map built each frame: the transcript block index for each rendered transcript row
    /// (usize::MAX for spacers / the streaming tail), so a mouse click can fold the right card (R9).
    row_map: Vec<usize>,
    /// The transcript viewport's top row and current scroll (in rendered rows), for click math.
    view_top: u16,
    view_scroll: u16,
    view_h: u16,
    /// Follow-ups composed WHILE the agent was running, each dispatched (in order) when the run
    /// finishes. A Vec (not a joined blob) so each item is classified separately — a queued
    /// `/compact` then a task run as two distinct actions (round-3 review).
    queued: VecDeque<PendingInput>,
    /// FIFO previews of steering submissions accepted by the frontend but not yet acknowledged at a
    /// kernel safe point. Kernel acknowledgement is count-based today, so FIFO is the honest interim
    /// projection until the App Server protocol supplies stable submission ids.
    steer_previews: VecDeque<PendingInput>,
    next_submission_seq: u64,
}

impl App {
    fn new() -> Self {
        let theme = theme::Theme::detect();
        // The pet landing is a one-time terminal-native signature in the transcript, not permanent
        // chrome. It progressively collapses with width and naturally scrolls away after work starts.
        let welcome = block::Block::new(
            0,
            block::BlockKind::Welcome {
                tagline: "Core Code · Build, explain, and verify".into(),
            },
        );
        App {
            transcript: vec![welcome],
            next_id: 1,
            tool_index: std::collections::HashMap::new(),
            pending_tools: VecDeque::new(),
            workflow_index: std::collections::HashMap::new(),
            theme,
            theme_epoch: 0,
            render_cache: std::collections::HashMap::new(),
            render_cache_width: 0,
            render_cache_theme_epoch: 0,
            editor: Editor::new(),
            status: "idle".into(),
            running: false,
            interrupting: false,
            bottom_offset: 0,
            follow_tail: true,
            unread_updates: 0,
            last_total_rows: 0,
            last_view_h: 0,
            quit: false,
            cur_text: String::new(),
            cur_text_revision: 0,
            cur_doc_revision: 0,
            cur_doc: None,
            text_scrubber: crate::output::StreamingScrubber::default(),
            cur_think: String::new(),
            thinking_scrubber: crate::output::StreamingScrubber::default(),
            mode: PermissionMode::default(),
            effort: Effort::default(),
            model: String::new(),
            provider_id: String::new(),
            cost: CostState::Zero,
            last_turn_usage: None,
            last_context: None,
            model_context_window: None,
            reserved_output_tokens: None,
            compaction_trigger_tokens: core_ctx::CompactionPolicy::default().trigger_tokens,
            effort_application: None,
            turns: 0,
            pending: None,
            approval_choice: ApprovalChoice::Deny,
            completion: None,
            picker: None,
            resume_handoff: None,
            run_started: None,
            active_tools: VecDeque::new(),
            spin: 0,
            row_map: Vec::new(),
            view_top: 0,
            view_scroll: 0,
            view_h: 0,
            queued: VecDeque::new(),
            steer_previews: VecDeque::new(),
            next_submission_seq: 0,
        }
    }

    /// Recompute the autocomplete menu from the current editor state (called after each edit while
    /// idle or while composing a queued follow-up). Sets `self.completion` to a slash menu, a file
    /// menu, or None. A running agent must not degrade the editor into a text-only field.
    fn refresh_completion(&mut self, repo: &std::path::Path) {
        self.completion = None;
        let text = self.editor.text();
        if text.contains('\n') {
            return; // no menu in multi-line mode
        }
        // slash-command menu
        if let Some(prefix) = commands::slash_prefix(&text) {
            let items: Vec<(String, String)> = commands::complete_slash(prefix)
                .into_iter()
                .map(|c| (c.name.to_string(), format!("{}  {}", c.args, c.help)))
                .collect();
            if !items.is_empty() {
                self.completion = Some(Completion {
                    items,
                    sel: 0,
                    token_start: 1,
                    lead: '/',
                });
            }
            return;
        }
        // @file menu (path completion at the cursor)
        let cursor_bytes = byte_index(&text, self.editor.cursor());
        if let Some((at, partial)) = commands::at_mention_at(&text, cursor_bytes) {
            let matches = complete_path(repo, partial);
            if !matches.is_empty() {
                let items = matches.into_iter().map(|p| (p, String::new())).collect();
                self.completion = Some(Completion {
                    items,
                    sel: 0,
                    token_start: at + 1,
                    lead: '@',
                });
            }
        }
    }

    /// Accept the selected completion: replace the WHOLE token (from `token_start` to the next
    /// whitespace or end — not just up to the cursor) with the chosen item + a single trailing
    /// space, and place the cursor right after it. Replacing the whole token fixes corruption when
    /// the cursor is in the middle of the token (review).
    fn accept_completion(&mut self) {
        let Some(comp) = self.completion.take() else {
            return;
        };
        let Some((item, _)) = comp.items.get(comp.sel).cloned() else {
            return;
        };
        let text = self.editor.text();
        let token_end = text[comp.token_start.min(text.len())..]
            .find(char::is_whitespace)
            .map(|i| comp.token_start + i)
            .unwrap_or(text.len());
        // A directory item (ends with '/') gets NO trailing space, so the mention token stays open
        // and the menu re-populates for drill-down (review: accepting a dir closed the menu).
        let sep = if item.ends_with('/') { "" } else { " " };
        let mut new = String::new();
        new.push_str(&text[..comp.token_start]);
        new.push_str(&item);
        new.push_str(sep);
        new.push_str(text[token_end..].trim_start_matches(' ')); // avoid a double space
        let want =
            text[..comp.token_start].chars().count() + item.chars().count() + sep.chars().count();
        self.editor.clear();
        self.editor.insert_str(&new);
        self.editor.home();
        for _ in 0..want {
            self.editor.right();
        }
    }

    /// Enter activates a slash-menu entry when the command has no required arguments. Tab remains
    /// completion-only, and commands with required arguments (for example `/memory`) leave the
    /// composer open for the missing value. Keeping this decision separate from dispatch prevents
    /// one physical Enter from both opening a picker and accepting its first row.
    fn accept_completion_for_enter(&mut self) -> bool {
        let submit = self.completion.as_ref().is_some_and(|completion| {
            if completion.lead != '/' {
                return false;
            }
            let Some((name, _)) = completion.items.get(completion.sel) else {
                return false;
            };
            commands::COMMANDS.iter().any(|command| {
                command.name == name && (command.args.is_empty() || command.args.starts_with('['))
            })
        });
        self.accept_completion();
        submit
    }

    /// Push a single-line harness notice. The old `push(style,text)` sites keep working, but the
    /// STYLE is now mapped to a semantic `NoticeLevel` and rendered as a structured `Notice` block —
    /// there is NO plain-text path (R7.e). Color literal encodes intent: green→Ok, red→Err,
    /// yellow→Warn, else→Info.
    fn push(&mut self, style: Style, text: impl Into<String>) {
        let level = match style.fg {
            Some(Color::Green) => block::NoticeLevel::Ok,
            Some(Color::Red) => block::NoticeLevel::Err,
            Some(Color::Yellow) => block::NoticeLevel::Warn,
            _ => block::NoticeLevel::Info,
        };
        self.note(level, text);
    }

    /// Push a one-line notice at an explicit level.
    fn note(&mut self, level: block::NoticeLevel, text: impl Into<String>) {
        self.flush_text();
        self.push_block(block::BlockKind::Notice {
            level,
            text: ui_safe_text(&text.into()),
        });
    }

    /// Push a completed operator `!shell` command as an OPEN Tool card (❯ Run · output · ✓/✗) —
    /// never plain lines (R7.b "see shell").
    fn push_shell_card(&mut self, cmd: &str, mut output: String, ok: bool, exit_code: i32) {
        self.flush_text();
        let cmd = ui_safe_text(cmd);
        output = ui_safe_text(&output);
        if !ok {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&format!("[exit {exit_code}]"));
        }
        let card = block::ToolCard {
            name: "bash".into(),
            args: serde_json::json!({ "command": cmd }),
            status: if ok {
                block::ToolStatus::Ok
            } else {
                block::ToolStatus::Err
            },
            output,
            diff: None,
            exit_code: Some(exit_code),
            started: Instant::now(),
            elapsed: Some(Duration::ZERO),
            open: true, // shell output is the point — default open
        };
        self.push_block(block::BlockKind::Tool(card));
    }

    /// Push a structured command-output Panel (titled card of typed rows). Rows are bounded (C4).
    // `_icon` is retained in the signature so the ~13 call sites read cleanly, but the per-panel icon
    // is no longer rendered (TUI v3 §2 deleted the panel icons — the title carries identity).
    fn panel(&mut self, _icon: &str, title: &str, mut rows: Vec<block::PanelRow>) {
        const CAP: usize = 120;
        if rows.len() > CAP {
            let extra = rows.len() - CAP;
            rows.truncate(CAP);
            rows.push(block::PanelRow::Note(format!("… {extra} more")));
        }
        for row in &mut rows {
            match row {
                block::PanelRow::KeyValue { key, value } => {
                    *key = ui_safe_text(key);
                    *value = ui_safe_text(value);
                }
                block::PanelRow::Item { label, hint } => {
                    *label = ui_safe_text(label);
                    *hint = ui_safe_text(hint);
                }
                block::PanelRow::Note(text) => *text = ui_safe_text(text),
            }
        }
        self.flush_text();
        self.push_block(block::BlockKind::Panel {
            title: ui_safe_text(title),
            rows,
        });
    }

    /// Push a structured block, assigning a monotonic id; returns the id.
    fn push_block(&mut self, kind: block::BlockKind) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.transcript.push(block::Block::new(id, kind));
        self.autoscroll();
        id
    }

    /// Echo the operator's submitted prompt as a User block.
    fn push_user(&mut self, text: impl Into<String>) {
        self.flush_text();
        self.push_block(block::BlockKind::User(ui_safe_text(&text.into())));
    }

    /// Append streamed assistant text; the in-flight buffer renders as a live markdown block.
    fn stream_text(&mut self, delta: &str) {
        self.flush_think();
        if let Some(complete) = self.text_scrubber.push(delta) {
            if complete.is_empty() {
                return;
            }
            self.cur_text.push_str(&ui_safe_text(&complete));
            self.cur_text_revision = self.cur_text_revision.wrapping_add(1);
            self.autoscroll();
        }
    }

    /// Append streamed reasoning; the in-flight buffer renders as a live Thinking block (bounded).
    fn stream_think(&mut self, delta: &str) {
        if let Some(complete) = self.thinking_scrubber.push(delta) {
            if complete.is_empty() {
                return;
            }
            self.cur_think.push_str(&ui_safe_text(&complete));
            self.autoscroll();
        }
        let count = self.cur_think.chars().count();
        if count > 4000 {
            self.cur_think = self.cur_think.chars().skip(count - 4000).collect();
        }
    }

    /// Finalize streamed reasoning into a persisted (collapsed) Thinking block — kept, not wiped.
    fn flush_think(&mut self) {
        if let Some(pending) = self.thinking_scrubber.finish() {
            self.cur_think.push_str(&ui_safe_text(&pending));
        }
        if !self.cur_think.trim().is_empty() {
            let t = std::mem::take(&mut self.cur_think);
            self.push_block(block::BlockKind::Thinking {
                text: t,
                open: false,
            });
        } else {
            self.cur_think.clear();
        }
    }

    /// Finalize streamed assistant text into a parsed Assistant markdown block.
    fn flush_text(&mut self) {
        self.flush_think();
        if let Some(pending) = self.text_scrubber.finish() {
            self.cur_text.push_str(&ui_safe_text(&pending));
            self.cur_text_revision = self.cur_text_revision.wrapping_add(1);
        }
        if !self.cur_text.trim().is_empty() {
            let t = std::mem::take(&mut self.cur_text);
            self.push_block(block::BlockKind::Assistant(
                crate::markdown::MarkdownDoc::parse(&t),
            ));
        } else {
            self.cur_text.clear();
        }
        self.cur_doc = None;
        self.cur_doc_revision = self.cur_text_revision;
    }

    /// A tool is starting: finalize streaming and expose it in the activity shelf immediately, but
    /// delay its transcript card briefly. This copies Codex's anti-flash state-machine boundary
    /// without borrowing its hook-only deletion policy: Core's current `UiEvent` has no explicit
    /// ephemeral disposition, so every completed model tool still settles into history.
    fn tool_start(&mut self, id: String, name: String, args: serde_json::Value) {
        self.tool_start_at(id, name, args, Instant::now());
    }

    fn tool_start_at(&mut self, id: String, name: String, args: serde_json::Value, now: Instant) {
        self.flush_text();
        let name = ui_safe_text(&name);
        let args = ui_safe_json(&args);
        let activity = block::activity_label(&name, &args);
        self.active_tools.retain(|(active_id, _)| active_id != &id);
        self.active_tools.push_back((id.clone(), activity));
        while self.active_tools.len() > 16 {
            self.active_tools.pop_front();
        }

        // Duplicate starts refresh one projection instead of leaking an orphan running card. A
        // start arriving after reveal keeps the existing id-correlated card; protocol ids are
        // expected to be unique within a run, but a repeated transport notification must be safe.
        if self.tool_index.contains_key(&id) {
            self.autoscroll();
            return;
        }
        self.pending_tools.retain(|pending| pending.id != id);
        while self.pending_tools.len() >= MAX_PENDING_TOOL_PROJECTIONS {
            let oldest = self
                .pending_tools
                .pop_front()
                .expect("the pending projection cap was reached");
            self.reveal_tool(oldest);
        }
        self.pending_tools.push_back(PendingToolProjection {
            id,
            name,
            args,
            started: now,
            reveal_deadline: now + TOOL_REVEAL_DELAY,
        });
        self.autoscroll();
    }

    /// Advance the anti-flash timer. Passing `now` makes the state machine deterministic in tests;
    /// production calls it from the existing 100 ms active-session cadence.
    fn advance_tool_presentations(&mut self, now: Instant) -> bool {
        let mut changed = false;
        while self
            .pending_tools
            .front()
            .is_some_and(|pending| now >= pending.reveal_deadline)
        {
            let pending = self
                .pending_tools
                .pop_front()
                .expect("front was checked above");
            self.reveal_tool(pending);
            changed = true;
        }
        changed
    }

    fn reveal_tool(&mut self, pending: PendingToolProjection) {
        let id = pending.id;
        let card = block::ToolCard {
            name: pending.name,
            args: pending.args,
            status: block::ToolStatus::Running,
            output: String::new(),
            diff: None,
            exit_code: None,
            started: pending.started,
            elapsed: None,
            open: false,
        };
        let bid = self.push_block(block::BlockKind::Tool(card));
        self.tool_index.insert(id, bid);
    }

    /// A tool finished: mutate its originating card by id (R2), or append one if the start was missed.
    fn tool_end(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<core_protocol::FileDiff>,
    ) {
        self.tool_end_at(id, ok, exit_code, output, diff, Instant::now());
    }

    fn tool_end_at(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<core_protocol::FileDiff>,
        now: Instant,
    ) {
        let output = ui_safe_text(&output);
        self.active_tools.retain(|(active_id, _)| active_id != id);
        let status = if ok {
            block::ToolStatus::Ok
        } else {
            block::ToolStatus::Err
        };

        // A fast completion becomes one already-settled card: no running-row flash, no deletion.
        // Failures, diffs, mutations, and ordinary read/search/list results therefore all retain
        // their transcript evidence until the protocol grows an explicit Ephemeral disposition.
        if let Some(index) = self
            .pending_tools
            .iter()
            .position(|pending| pending.id == id)
        {
            let pending = self
                .pending_tools
                .remove(index)
                .expect("position came from this deque");
            let card = block::ToolCard {
                name: pending.name,
                args: pending.args,
                status,
                output,
                diff,
                exit_code,
                started: pending.started,
                elapsed: Some(now.saturating_duration_since(pending.started)),
                open: false,
            };
            self.push_block(block::BlockKind::Tool(card));
            return;
        }

        if let Some(&bid) = self.tool_index.get(id)
            && let Some(b) = self.transcript.iter_mut().find(|b| b.id == bid)
            && let block::BlockKind::Tool(card) = &mut b.kind
        {
            card.status = status;
            card.output = output;
            card.diff = diff;
            card.exit_code = exit_code;
            card.elapsed = Some(now.saturating_duration_since(card.started));
            b.touch();
            self.tool_index.remove(id);
            self.autoscroll();
            return;
        }
        let card = block::ToolCard {
            name: "tool".into(),
            args: serde_json::Value::Null,
            status,
            output,
            diff,
            exit_code,
            started: Instant::now(),
            elapsed: Some(Duration::ZERO),
            open: false,
        };
        self.push_block(block::BlockKind::Tool(card));
    }

    fn settle_unfinished_tools(&mut self) {
        let mut ids: Vec<String> = self
            .pending_tools
            .iter()
            .map(|pending| pending.id.clone())
            .chain(self.tool_index.keys().cloned())
            .collect();
        ids.sort();
        ids.dedup();
        for id in ids {
            self.tool_end(
                &id,
                false,
                None,
                "tool ended without a terminal event because the run stopped".into(),
                None,
            );
        }
        self.active_tools.clear();
    }

    fn workflow_card_mut(&mut self, run_id: &str) -> Option<&mut block::WorkflowCard> {
        let block_id = *self.workflow_index.get(run_id)?;
        self.transcript
            .iter_mut()
            .find(|block| block.id == block_id)
            .and_then(|block| match &mut block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
    }

    /// Project one id-correlated kernel lifecycle update into one live workflow card.
    fn workflow_event(&mut self, event: WorkflowUiEvent) {
        let changed = match event {
            WorkflowUiEvent::RunStarted {
                run_id,
                name,
                class,
            } => {
                self.flush_text();
                let card = block::WorkflowCard {
                    run_id: ui_safe_text(&run_id),
                    name: ui_safe_text(&name),
                    class: ui_safe_text(&class),
                    status: block::WorkflowStatus::Planning,
                    tasks: Vec::new(),
                    dropped: 0,
                    duplicates_removed: 0,
                    invalid_removed: 0,
                    execution_mode: core_kernel::WorkflowExecutionModeUi::Direct,
                    fan_turn_budget: 0,
                    writer_turn_reserve: 0,
                    fan_wall_secs: 0,
                    writer_wall_reserve_secs: 0,
                    started: Instant::now(),
                    elapsed: None,
                    reason: None,
                    provider_attempts: 0,
                    turns: 0,
                    tokens: 0,
                    tool_calls: 0,
                    failed_tasks: 0,
                    skipped_tasks: 0,
                    open: true,
                };
                let block_id = self.push_block(block::BlockKind::Workflow(card));
                self.workflow_index.insert(run_id, block_id);
                false // push_block already recorded the visible update
            }
            WorkflowUiEvent::PlanReady {
                run_id,
                tasks,
                dropped,
                duplicates_removed,
                invalid_removed,
                execution_mode,
                fan_turn_budget,
                writer_turn_reserve,
                fan_wall_secs,
                writer_wall_reserve_secs,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.tasks = tasks
                        .into_iter()
                        .map(|task| block::WorkflowTaskCard {
                            id: task.id,
                            label: ui_safe_text(&task.label),
                            status: block::WorkflowTaskStatus::Queued,
                            started: None,
                            elapsed: None,
                            turns: 0,
                            tokens: 0,
                            tool_calls: 0,
                            turn_budget: 0,
                            sub_run: None,
                            activity: None,
                            summary_preview: None,
                            error_preview: None,
                        })
                        .collect();
                    card.dropped = dropped;
                    card.duplicates_removed = duplicates_removed;
                    card.invalid_removed = invalid_removed;
                    card.execution_mode = execution_mode;
                    card.fan_turn_budget = fan_turn_budget;
                    card.writer_turn_reserve = writer_turn_reserve;
                    card.fan_wall_secs = fan_wall_secs;
                    card.writer_wall_reserve_secs = writer_wall_reserve_secs;
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::PhaseChanged { run_id, phase } => {
                if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.status = match phase {
                        WorkflowPhaseUi::Planning => block::WorkflowStatus::Planning,
                        WorkflowPhaseUi::Exploring => block::WorkflowStatus::Exploring,
                        WorkflowPhaseUi::Synthesizing => block::WorkflowStatus::Synthesizing,
                        WorkflowPhaseUi::Writing => block::WorkflowStatus::Writing,
                        WorkflowPhaseUi::Direct => block::WorkflowStatus::Direct,
                    };
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentStarted {
                run_id,
                agent_id,
                sub_run,
                turn_budget,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                {
                    task.status = block::WorkflowTaskStatus::Running;
                    task.started = Some(Instant::now());
                    task.sub_run = Some(ui_safe_text(&sub_run));
                    task.turn_budget = turn_budget;
                    task.activity = Some("starting read-only investigation".into());
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentActivity {
                run_id,
                agent_id,
                activity,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                    && task.status == block::WorkflowTaskStatus::Running
                {
                    task.activity = Some(ui_safe_text(&activity));
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::AgentFinished {
                run_id,
                agent_id,
                outcome,
                turns,
                tokens,
                tool_calls,
                elapsed_ms,
                summary_preview,
                error_preview,
            } => {
                if let Some(card) = self.workflow_card_mut(&run_id)
                    && let Some(task) = card.tasks.iter_mut().find(|task| task.id == agent_id)
                {
                    task.status = match outcome {
                        WorkflowAgentOutcomeUi::Done => block::WorkflowTaskStatus::Done,
                        WorkflowAgentOutcomeUi::Failed => block::WorkflowTaskStatus::Failed,
                        WorkflowAgentOutcomeUi::Interrupted => {
                            block::WorkflowTaskStatus::Interrupted
                        }
                        WorkflowAgentOutcomeUi::SkippedBudget => {
                            block::WorkflowTaskStatus::SkippedBudget
                        }
                        WorkflowAgentOutcomeUi::NotStarted => block::WorkflowTaskStatus::NotStarted,
                    };
                    task.elapsed = Some(Duration::from_millis(elapsed_ms));
                    task.turns = turns;
                    task.tokens = tokens;
                    task.tool_calls = tool_calls;
                    task.activity = None;
                    task.summary_preview = summary_preview.map(|text| ui_safe_text(&text));
                    task.error_preview = error_preview.map(|text| ui_safe_text(&text));
                    true
                } else {
                    false
                }
            }
            WorkflowUiEvent::RunFinished {
                run_id,
                outcome,
                reason,
                elapsed_ms,
                provider_attempts,
                turns,
                tokens,
                tool_calls,
                failed_tasks,
                skipped_tasks,
            } => {
                let changed = if let Some(card) = self.workflow_card_mut(&run_id) {
                    card.status = match outcome {
                        WorkflowRunOutcomeUi::Done => block::WorkflowStatus::Done,
                        WorkflowRunOutcomeUi::Degraded => block::WorkflowStatus::Degraded,
                        WorkflowRunOutcomeUi::BudgetExhausted => {
                            block::WorkflowStatus::BudgetExhausted
                        }
                        WorkflowRunOutcomeUi::Stuck => block::WorkflowStatus::Stuck,
                        WorkflowRunOutcomeUi::Failed => block::WorkflowStatus::Failed,
                        WorkflowRunOutcomeUi::Stopped => block::WorkflowStatus::Stopped,
                    };
                    card.elapsed = Some(Duration::from_millis(elapsed_ms));
                    card.reason = reason.map(|text| ui_safe_text(&text));
                    card.provider_attempts = provider_attempts;
                    card.turns = turns;
                    card.tokens = tokens;
                    card.tool_calls = tool_calls;
                    card.failed_tasks = failed_tasks;
                    card.skipped_tasks = skipped_tasks;
                    for task in &mut card.tasks {
                        if matches!(
                            task.status,
                            block::WorkflowTaskStatus::Queued | block::WorkflowTaskStatus::Running
                        ) {
                            if task.status == block::WorkflowTaskStatus::Running {
                                task.elapsed = task
                                    .started
                                    .map(|started| started.elapsed())
                                    .or(Some(Duration::ZERO));
                            }
                            // Missing terminal evidence is an observation gap, never an inferred
                            // skip/interruption. The card stays open and names the uncertainty.
                            task.status = block::WorkflowTaskStatus::Unknown;
                            task.error_preview = Some("terminal evidence unavailable".into());
                        }
                    }
                    // Successful runs collapse to one calm summary; anything exceptional remains
                    // open so failure/skip evidence cannot disappear behind progressive disclosure.
                    card.open = outcome != WorkflowRunOutcomeUi::Done
                        || card
                            .tasks
                            .iter()
                            .any(|task| task.status != block::WorkflowTaskStatus::Done);
                    true
                } else {
                    false
                };
                self.workflow_index.remove(&run_id);
                changed
            }
        };
        if changed {
            self.autoscroll();
        }
    }

    /// Toggle the fold of a collapsible block at transcript index `i`.
    fn toggle_fold(&mut self, i: usize) {
        if let Some(b) = self.transcript.get_mut(i) {
            let changed = match &mut b.kind {
                block::BlockKind::Tool(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::Workflow(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::Thinking { open, .. } => {
                    *open = !*open;
                    true
                }
                block::BlockKind::Error { open, .. } => {
                    *open = !*open;
                    true
                }
                _ => false,
            };
            if changed {
                b.touch();
            }
        }
    }

    /// Ctrl-O: toggle the fold of the most recent collapsible block (Claude Code's `ctrl+o` expand
    /// affordance; teardown D10 — a keyboard-truthful replacement for the removed mouse click).
    fn toggle_last_fold(&mut self) {
        if let Some(i) = self.transcript.iter().rposition(|b| {
            matches!(
                b.kind,
                block::BlockKind::Tool(_)
                    | block::BlockKind::Thinking { .. }
                    | block::BlockKind::Workflow(_)
                    | block::BlockKind::Error { .. }
            )
        }) {
            self.toggle_fold(i);
        }
    }

    /// Route a keypress to the open picker. Returns None if no picker is open (fall through to normal
    /// key handling). The picker OWNS the keyboard while open — no fall-through to editor/history/
    /// Shift+Tab (C6). Take-then-apply on accept (C5); theme live-preview on nav + Esc-restore (C1).
    #[cfg(test)]
    fn picker_key(&mut self, code: KeyCode) -> Option<PickerEvent> {
        self.picker_key_with_modifiers(code, KeyModifiers::NONE)
    }

    fn picker_key_with_modifiers(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
    ) -> Option<PickerEvent> {
        self.picker.as_ref()?;
        // Esc first clears an active filter. A second Esc closes and restores a live-preview theme.
        if code == KeyCode::Esc {
            if self.picker.as_ref().is_some_and(Picker::has_query) {
                let pk = self.picker.as_mut()?;
                pk.query.clear();
                let visible = pk.visible_indices();
                pk.normalize_selection(&visible);
            } else {
                self.close_picker_restore_theme();
                return Some(PickerEvent::Cancel);
            }
        } else if code == KeyCode::Backspace {
            let pk = self.picker.as_mut()?;
            pk.query.pop();
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        } else if let KeyCode::Char(ch) = code
            && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && !ch.is_control()
        {
            let pk = self.picker.as_mut()?;
            if pk.query.chars().count() < MAX_PICKER_QUERY_CHARS {
                pk.query.push(ch);
            }
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        }

        let visible = self.picker.as_ref()?.visible_indices();
        if visible.is_empty() {
            return Some(PickerEvent::Consumed);
        }

        // A catalog refresh or ancestor collapse may invalidate the old selection. Normalize before
        // handling Enter so a hidden child can never be accepted accidentally.
        self.picker.as_mut()?.normalize_selection(&visible);

        let pos = self.picker.as_ref()?.visible_selection(&visible);
        match code {
            KeyCode::Up => {
                let next = (pos + visible.len() - 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::Down => {
                let next = (pos + 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::PageUp => {
                self.picker.as_mut()?.sel = visible[pos.saturating_sub(8)];
            }
            KeyCode::PageDown => {
                self.picker.as_mut()?.sel = visible[(pos + 8).min(visible.len() - 1)];
            }
            KeyCode::Home => self.picker.as_mut()?.sel = visible[0],
            KeyCode::End => self.picker.as_mut()?.sel = *visible.last()?,
            KeyCode::Right => {
                let pk = self.picker.as_mut()?;
                if let Some(item) = pk.items.get_mut(pk.sel)
                    && item.expandable
                {
                    item.expanded = true;
                }
            }
            KeyCode::Left => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get(pk.sel) else {
                    return Some(PickerEvent::Consumed);
                };
                let (expandable, expanded, parent) = (item.expandable, item.expanded, item.parent);
                if expandable && expanded {
                    if let Some(item) = pk.items.get_mut(pk.sel) {
                        item.expanded = false;
                    }
                } else if let Some(parent) = parent
                    && visible.contains(&parent)
                {
                    pk.sel = parent;
                }
            }
            KeyCode::Enter | KeyCode::Tab => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get_mut(pk.sel) else {
                    return Some(PickerEvent::Consumed);
                };
                if item.expandable {
                    item.expanded = true;
                    return Some(PickerEvent::Consumed);
                }
                if !item.enabled {
                    return Some(PickerEvent::Consumed);
                }
                let action = item.action.clone();
                self.picker = None; // borrow dropped before apply (C5)
                return Some(PickerEvent::Accept(action));
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char(_) => {}
            _ => return Some(PickerEvent::Consumed),
        }
        // theme live-preview: apply the newly-selected theme (extract, then assign — no borrow clash)
        let preview = self.picker.as_ref().and_then(|pk| {
            if pk.saved_theme.is_some() {
                match pk.items.get(pk.sel).map(|i| &i.action) {
                    Some(PickAction::SetTheme(t)) => Some(t.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });
        if let Some(t) = preview {
            self.set_theme(t);
        }
        Some(PickerEvent::Consumed)
    }

    fn close_picker_restore_theme(&mut self) {
        if let Some(pk) = self.picker.take()
            && let Some(theme) = pk.saved_theme
        {
            self.set_theme(theme);
        }
    }

    /// Route one physical key through the blocking permission control. Navigation only changes
    /// focus; Enter emits exactly one answer for that focus. Direct y/a/n shortcuts remain
    /// available, but an impossible session-wide grant is never constructed.
    fn approval_key(&mut self, code: KeyCode) -> ApprovalInput {
        let Some(pending) = self.pending.as_ref() else {
            return ApprovalInput::Consumed;
        };
        let choices: &[ApprovalChoice] = if capability_can_be_remembered(pending.cap) {
            &[
                ApprovalChoice::Once,
                ApprovalChoice::Session,
                ApprovalChoice::Deny,
            ]
        } else {
            &[ApprovalChoice::Once, ApprovalChoice::Deny]
        };
        if !choices.contains(&self.approval_choice) {
            self.approval_choice = ApprovalChoice::Deny;
        }
        let position = choices
            .iter()
            .position(|choice| *choice == self.approval_choice)
            .unwrap_or(choices.len() - 1);
        match code {
            KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
                self.approval_choice = choices[(position + choices.len() - 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
                self.approval_choice = choices[(position + 1) % choices.len()];
                ApprovalInput::Consumed
            }
            KeyCode::Enter => match self.approval_choice {
                ApprovalChoice::Once => ApprovalInput::Answer {
                    approved: true,
                    remember: false,
                },
                ApprovalChoice::Session if capability_can_be_remembered(pending.cap) => {
                    ApprovalInput::Answer {
                        approved: true,
                        remember: true,
                    }
                }
                ApprovalChoice::Session | ApprovalChoice::Deny => ApprovalInput::Answer {
                    approved: false,
                    remember: false,
                },
            },
            KeyCode::Char('y') | KeyCode::Char('Y') => ApprovalInput::Answer {
                approved: true,
                remember: false,
            },
            KeyCode::Char('a') | KeyCode::Char('A')
                if capability_can_be_remembered(pending.cap) =>
            {
                ApprovalInput::Answer {
                    approved: true,
                    remember: true,
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ApprovalInput::Answer {
                approved: false,
                remember: false,
            },
            _ => ApprovalInput::Consumed,
        }
    }

    /// Legacy terminals encode Alt+key as `ESC` followed by the key bytes. When an automation (or
    /// a fast typist) starts the next command immediately after dismissing a picker, crossterm can
    /// therefore surface `Esc` + `/` as one `Alt+/` event. A picker otherwise consumes every
    /// printable key, so the slash and the rest of the command would disappear into the modal.
    ///
    /// Printable Alt keys have no picker binding, so while a picker owns the keyboard we can safely
    /// recover this ambiguous sequence as "cancel, then type". Terminals with disambiguated key
    /// reporting continue to send an ordinary `Esc` and never enter this compatibility path.
    fn recover_picker_escape_prefixed_char(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        repo: &Path,
    ) -> bool {
        if self.picker.is_none()
            || !modifiers.contains(KeyModifiers::ALT)
            || modifiers.contains(KeyModifiers::CONTROL)
        {
            return false;
        }
        let KeyCode::Char(ch) = code else {
            return false;
        };
        if ch.is_control() {
            return false;
        }

        // Route the synthetic cancellation through picker_key so theme live-preview restoration
        // remains identical to a separately reported Esc.
        self.close_picker_restore_theme();
        self.editor.insert(ch);
        self.refresh_completion(repo);
        true
    }

    fn autoscroll(&mut self) {
        if self.follow_tail {
            self.bottom_offset = 0;
        } else {
            // Transport deltas are not user-meaningful item counts. This is an honest boolean
            // signal that visible output changed while the operator was reading history.
            self.unread_updates = 1;
        }
        // Bounded: evict the oldest settled blocks past the cap. A nonterminal workflow is a live
        // projection of durable state, so pin its one card until RunFinished arrives; otherwise a
        // long foreground transcript can silently discard the only place the terminal update can
        // land. With the current one-foreground-run TUI there is always an evictable settled block.
        if self.transcript.len() > MAX_BLOCKS {
            let mut drop = self.transcript.len() - MAX_BLOCKS;
            let pinned = self
                .workflow_index
                .values()
                .copied()
                .collect::<std::collections::HashSet<_>>();
            let mut evicted = std::collections::HashSet::new();
            self.transcript.retain(|block| {
                if drop > 0 && !pinned.contains(&block.id) {
                    drop -= 1;
                    evicted.insert(block.id);
                    false
                } else {
                    true
                }
            });
            self.render_cache
                .retain(|block_id, _| !evicted.contains(block_id));
            self.tool_index.retain(|_, bid| !evicted.contains(bid));
            self.workflow_index.retain(|_, bid| !evicted.contains(bid));
        }
    }

    fn follow_latest(&mut self) {
        self.follow_tail = true;
        self.bottom_offset = 0;
        self.unread_updates = 0;
    }

    fn set_theme(&mut self, theme: theme::Theme) {
        self.theme = theme;
        self.theme_epoch = self.theme_epoch.wrapping_add(1);
        self.render_cache.clear();
    }

    fn prepare_resume_handoff(&mut self, run_id: &str) {
        let command = format_resume_command(run_id);
        self.editor.clear();
        self.editor.insert_str(&command);
        self.completion = None;
        self.resume_handoff = Some(command.clone());
        self.note(
            block::NoticeLevel::Info,
            format!("not resumed here — copy this restart command into a new terminal: {command}"),
        );
    }

    fn is_resume_handoff_draft(&self) -> bool {
        self.resume_handoff
            .as_deref()
            .is_some_and(|command| command == self.editor.text())
    }

    fn scroll_up(&mut self, rows: u16) {
        self.follow_tail = false;
        self.bottom_offset = self.bottom_offset.saturating_add(rows);
    }

    fn scroll_down(&mut self, rows: u16) {
        self.bottom_offset = self.bottom_offset.saturating_sub(rows);
        if self.bottom_offset == 0 {
            self.follow_latest();
        }
    }

    fn queue_after_turn(&mut self, text: String) -> Result<(), String> {
        let pending = self.queued.len().saturating_add(self.steer_previews.len());
        match self.submission_admission(&text, pending, "pending input") {
            SubmissionAdmission::Accept => {
                let input = self.pending_input(text);
                self.queued.push_back(input);
            }
            SubmissionAdmission::IgnoreEmpty => {}
            SubmissionAdmission::Reject => return Err(text),
        }
        Ok(())
    }

    fn steer_admission(&mut self, text: &str) -> SubmissionAdmission {
        let pending = self.queued.len().saturating_add(self.steer_previews.len());
        self.submission_admission(text, pending, "pending input")
    }

    fn submission_admission(
        &mut self,
        text: &str,
        pending: usize,
        lane: &str,
    ) -> SubmissionAdmission {
        if text.trim().is_empty() {
            return SubmissionAdmission::IgnoreEmpty;
        }
        if text.len() > MAX_SUBMISSION_BYTES {
            self.note(
                block::NoticeLevel::Warn,
                format!(
                    "{lane} accepts at most {MAX_SUBMISSION_BYTES} bytes; the draft was preserved"
                ),
            );
            return SubmissionAdmission::Reject;
        }
        if pending >= MAX_PENDING_SUBMISSIONS {
            self.note(
                block::NoticeLevel::Warn,
                format!("{lane} is full; the draft was preserved"),
            );
            return SubmissionAdmission::Reject;
        }
        SubmissionAdmission::Accept
    }

    fn track_steer(&mut self, text: String) {
        debug_assert!(!text.trim().is_empty());
        debug_assert!(text.len() <= MAX_SUBMISSION_BYTES);
        debug_assert!(self.steer_previews.len() < MAX_PENDING_SUBMISSIONS);
        let input = self.pending_input(text);
        self.steer_previews.push_back(input);
    }

    fn pending_input(&mut self, text: String) -> PendingInput {
        let seq = self.next_submission_seq;
        self.next_submission_seq = self.next_submission_seq.wrapping_add(1);
        PendingInput { seq, text }
    }

    fn requeue_unadmitted(&mut self, unadmitted: Vec<String>) -> (usize, usize) {
        let count = unadmitted.len();
        for text in unadmitted {
            let input = if let Some(preview) = self.steer_previews.pop_front() {
                PendingInput {
                    seq: preview.seq,
                    text,
                }
            } else {
                self.pending_input(text)
            };
            self.queued.push_back(input);
        }
        // The producer join + final event drain should make this empty: every submitted preview is
        // either acknowledged by SteerApplied or returned by take_unadmitted_steers. If those two
        // counts ever disagree, preserve at-least-once operator intent as ordered after-turn input
        // instead of silently dropping the words with `mem::take(...).count()`.
        let unmatched_previews = self.steer_previews.len();
        self.queued.extend(self.steer_previews.drain(..));
        self.queued.make_contiguous().sort_by_key(|input| input.seq);
        debug_assert!(self.queued.len() <= MAX_PENDING_SUBMISSIONS);
        (count, unmatched_previews)
    }
}

/// Parse a capability class name for `/permissions` (snake_case, matching the serde rename).
fn parse_cap(s: &str) -> Option<Capability> {
    match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "read_only" | "read" => Some(Capability::ReadOnly),
        "reversible_local" | "edit" | "edits" => Some(Capability::ReversibleLocal),
        "code_executing" | "code" | "bash" => Some(Capability::CodeExecuting),
        "trust_mutating" | "trust" => Some(Capability::TrustMutating),
        "irreversible_external" | "external" | "egress" => Some(Capability::IrreversibleExternal),
        _ => None,
    }
}

const INLINE_SHELL_TIMEOUT: Duration = Duration::from_secs(120);
const INLINE_SHELL_HEAD_BYTES: usize = 48 * 1024;
const INLINE_SHELL_TAIL_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct InlineShellCapture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl InlineShellCapture {
    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        let head_len = bytes
            .len()
            .min(INLINE_SHELL_HEAD_BYTES.saturating_sub(self.head.len()));
        self.head.extend_from_slice(&bytes[..head_len]);
        let remainder = &bytes[head_len..];
        if remainder.len() >= INLINE_SHELL_TAIL_BYTES {
            self.tail.clear();
            self.tail
                .extend(&remainder[remainder.len() - INLINE_SHELL_TAIL_BYTES..]);
            return;
        }
        let overflow = self
            .tail
            .len()
            .saturating_add(remainder.len())
            .saturating_sub(INLINE_SHELL_TAIL_BYTES);
        if overflow > 0 {
            self.tail.drain(..overflow);
        }
        self.tail.extend(remainder);
    }

    fn finish(self, stream: &str) -> String {
        let retained = self.head.len().saturating_add(self.tail.len()) as u64;
        let omitted = self.total.saturating_sub(retained);
        let mut bytes = self.head;
        if omitted > 0 {
            bytes.extend_from_slice(
                format!("\n[… {stream} truncated: {omitted} bytes omitted …]\n").as_bytes(),
            );
        }
        bytes.extend(self.tail);
        ui_safe_text(&decode_shell_bytes(bytes))
    }
}

fn decode_shell_bytes(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut text = String::from("[invalid UTF-8 escaped]\n");
            for byte in error.into_bytes() {
                match byte {
                    b'\n' => text.push('\n'),
                    b'\t' => text.push('\t'),
                    0x20..=0x7e => text.push(char::from(byte)),
                    byte => text.push_str(&format!("\\x{byte:02x}")),
                }
            }
            text
        }
    }
}

async fn drain_inline_shell<R>(
    reader: &mut R,
    capture: &mut InlineShellCapture,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        capture.push(&chunk[..read]);
    }
}

#[cfg(unix)]
fn kill_inline_shell_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: the command is spawned with process_group(0), so -pid names only that group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_inline_shell_group(_pid: Option<u32>) {}

/// Run an operator `!cmd` without the model sandbox, but with provider credentials removed, fixed
/// memory capture, a deadline, process-group cleanup, terminal-safe decoding and secret redaction.
async fn run_bash_inline(
    app: &mut App,
    repo: &std::path::Path,
    cmd: &str,
    credential_env_names: &[String],
) {
    if cmd.is_empty() {
        return;
    }
    let mut command = tokio::process::Command::new("bash");
    command
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(cmd)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    for name in credential_env_names {
        command.env_remove(name);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            app.push_block(block::BlockKind::Error {
                title: ui_safe_text(&format!("shell failed to launch: {error}")),
                detail: ui_safe_text(&format!("command: {cmd}")),
                open: true,
            });
            return;
        }
    };
    let child_group = child.id();
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        app.note(block::NoticeLevel::Err, "shell stdout pipe was unavailable");
        return;
    };
    let Some(mut stderr) = child.stderr.take() else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        app.note(block::NoticeLevel::Err, "shell stderr pipe was unavailable");
        return;
    };
    let mut out = InlineShellCapture::default();
    let mut err = InlineShellCapture::default();
    let completed = tokio::time::timeout(INLINE_SHELL_TIMEOUT, async {
        let (out_result, err_result, status) = tokio::join!(
            drain_inline_shell(&mut stdout, &mut out),
            drain_inline_shell(&mut stderr, &mut err),
            child.wait(),
        );
        out_result?;
        err_result?;
        status
    })
    .await;
    let (status, timed_out) = match completed {
        Ok(Ok(status)) => (Some(status), false),
        Ok(Err(error)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("shell output failed: {error}"),
            );
            (None, false)
        }
        Err(_) => {
            kill_inline_shell_group(child_group);
            let _ = child.start_kill();
            let status = child.wait().await.ok();
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                let _ = tokio::join!(
                    drain_inline_shell(&mut stdout, &mut out),
                    drain_inline_shell(&mut stderr, &mut err),
                );
            })
            .await;
            (status, true)
        }
    };
    let code = status.and_then(|status| status.code()).unwrap_or(-1);
    let mut body = out.finish("stdout");
    let stderr = err.finish("stderr");
    if !stderr.trim().is_empty() {
        if !body.trim().is_empty() {
            body.push_str("\n[stderr]\n");
        }
        body.push_str(&stderr);
    }
    if timed_out {
        body.insert_str(0, "[timed out after 120s]\n");
    }
    let ok = !timed_out && status.is_some_and(|status| status.success());
    app.push_shell_card(cmd, body, ok, code);
}

/// Terminal display width of a char: wide (CJK/Hangul/Kana/fullwidth/most emoji) = 2, zero-width /
/// combining = 0, else 1. A small zero-dep approximation of unicode-width for cursor/column math
/// (review: the input cursor was misplaced for CJK/emoji).
///
/// The transcript's marker/connector glyphs are all deliberately width-1 here: `●` (U+25CF), `⎿`
/// (U+23BF), `✻`/`✢`/`✳`/`✶`/`✽`/`·` (the spinner). `⏺` (U+23FA) is emoji-presentation (width 2) on
/// some non-mac terminals — which is exactly why `block::primary_marker()` only EMITS `⏺` on macOS
/// (where it draws width-1) and `●` elsewhere. So every glyph this renderer emits matches the width
/// this function reports, and rows never overlap (the 乱码 bug).
pub(crate) fn char_width(c: char) -> u16 {
    let u = c as u32;
    if u == 0 {
        return 0;
    }
    if matches!(u, 0x200B..=0x200F | 0x202A..=0x202E | 0xFE00..=0xFE0F | 0x0300..=0x036F | 0x2060..=0x2064)
    {
        return 0;
    }
    if matches!(u,
        0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE4F | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6 | 0x1_F300..=0x1_FAFF | 0x2_0000..=0x3_FFFD)
    {
        return 2;
    }
    1
}

/// Display width of the first `n_chars` chars of `s`. Saturating so a pathologically long line
/// cannot overflow the u16 (review LOW).
fn display_col(s: &str, n_chars: usize) -> u16 {
    s.chars()
        .take(n_chars)
        .map(char_width)
        .fold(0u16, |a, w| a.saturating_add(w))
}

/// Convert a char index into a byte index within `s` (the editor counts chars; string slicing
/// needs bytes). Clamps to the string length.
fn byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

/// Complete a relative path `partial` under `repo` for `@file` mentions. Returns up to 8 matching
/// entries (dirs get a trailing '/'), skipping hidden/build dirs. Bounded (invariant #1).
fn complete_path(repo: &std::path::Path, partial: &str) -> Vec<String> {
    // Confine to the repo: a `..` or absolute partial would let `repo.join` escape the root (review).
    if partial.contains("..") || std::path::Path::new(partial).is_absolute() {
        return Vec::new();
    }
    let (dir_part, file_part) = match partial.rfind('/') {
        Some(i) => (&partial[..=i], &partial[i + 1..]),
        None => ("", partial),
    };
    let base = repo.join(dir_part);
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&base) else {
        return out;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && !file_part.starts_with('.') {
            continue;
        }
        if matches!(name.as_str(), "target" | "node_modules" | ".git") {
            continue;
        }
        if !name
            .to_ascii_lowercase()
            .starts_with(&file_part.to_ascii_lowercase())
        {
            continue;
        }
        let is_dir = e.path().is_dir();
        out.push(format!("{dir_part}{name}{}", if is_dir { "/" } else { "" }));
        if out.len() >= 8 {
            break;
        }
    }
    out
}

fn fg(c: Color) -> Style {
    Style::default().fg(c)
}
fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}
fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}
/// A Panel key-value row.
fn kv(key: &str, value: &str) -> block::PanelRow {
    block::PanelRow::KeyValue {
        key: key.into(),
        value: value.into(),
    }
}
/// A Panel list-item row (label + dim hint). The leading `_glyph` arg is retained so the ~9 call
/// sites read cleanly, but the per-row glyph is no longer rendered — the icon zoo was deleted (TUI v3
/// §2), identity is the label + panel title (findings 5/6/15/16).
fn item(_glyph: &str, label: &str, hint: &str) -> block::PanelRow {
    block::PanelRow::Item {
        label: label.into(),
        hint: hint.into(),
    }
}

/// Best-effort terminal restore: leave raw mode + alt screen + mouse capture + bracketed paste. Shared
/// by `TermGuard::Drop`, the panic hook, and the SIGTERM/SIGHUP handler — `process::exit` skips Drop, so
/// the signal path must restore EXPLICITLY, else a `kill <pid>` / terminal-close leaves the tty in raw +
/// mouse-capture mode spewing 乱码.
fn restore_terminal() {
    let _ = terminal::disable_raw_mode();
    // Keep every cleanup independent: a broken/closing terminal can reject one escape while still
    // accepting the rest. One multi-command `execute!` would stop at the first write failure and
    // could leave the shell cursor hidden or its style inverted after a picker/signal exit.
    let mut stdout = std::io::stdout();
    let _ = execute!(stdout, DisableBracketedPaste);
    let _ = execute!(stdout, DisableMouseCapture);
    let _ = execute!(stdout, cursor::Show);
    let _ = execute!(
        stdout,
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
    );
    let _ = execute!(stdout, crossterm::style::ResetColor);
    let _ = execute!(stdout, terminal::LeaveAlternateScreen);
}

/// Restores the terminal (leaves raw mode + alternate screen) on drop, so the terminal is never
/// left broken — the #1 TUI failure mode. Covers early `?` returns AND panics (a panic unwinds
/// through the guard). A panic hook additionally restores before printing the panic message.
struct TermGuard;
impl TermGuard {
    fn new() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        // EnableMouseCapture so trackpad/wheel scroll arrives as ScrollUp/Down events and scrolls the
        // CHAT transcript. WITHOUT capture the terminal maps scroll to ↑/↓, which then drives prompt
        // history — the user wants scroll=chat, arrow keys=history, so the two must be distinct events.
        // Cleanup runs on every CATCHABLE exit: the Drop below AND the panic hook restore raw-mode +
        // alt-screen + mouse capture, so a `?`-return, panic, or normal quit never leaves 乱码. Only a
        // hard `kill -9` (uncatchable) can leave capture on → `reset` clears it (documented tradeoff).
        if let Err(error) = execute!(
            std::io::stdout(),
            terminal::EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture
        ) {
            // Construction has not returned a guard yet, so rollback this partially-entered state
            // explicitly. Without this branch an I/O failure after raw-mode enable would leave the
            // operator's terminal unusable.
            restore_terminal();
            return Err(error);
        }
        // Install a panic hook that restores the terminal (incl. mouse capture) first, then the default.
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            default(info);
        }));
        Ok(TermGuard)
    }
}
impl Drop for TermGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Max transcript BLOCKS kept in memory (bounded, invariant #1): oldest blocks are evicted once
/// past the cap (each block's stored output was already bounded at the kernel seam, R5).
const MAX_BLOCKS: usize = 1200;
/// Minimum active runtime before a model tool is shown as running in transcript history. Faster
/// completions are inserted once in their settled state, avoiding a two-frame flash.
const TOOL_REVEAL_DELAY: Duration = Duration::from_millis(300);
/// Bound anti-flash bookkeeping independently from transcript retention. Reaching the cap reveals
/// the oldest running tool early; it never drops lifecycle evidence.
const MAX_PENDING_TOOL_PROJECTIONS: usize = 64;
/// Bound both visible pending lanes and the number of outstanding operations this frontend can put
/// into the legacy runtime's channel before acknowledgement.
const MAX_PENDING_SUBMISSIONS: usize = 32;
/// A single interactive follow-up is deliberately smaller than tool/model context limits. Oversize
/// drafts stay in the editor so the operator can trim or save them instead of losing text.
const MAX_SUBMISSION_BYTES: usize = 64 * 1024;

/// Run the TUI. The agent runs in a background task streaming `UiEvent`s; the render loop drains
/// them and redraws. For follow-ups the same agent continues via `follow_up`.
pub async fn run(
    mut agent: Agent,
    initial_task: Option<String>,
    providers: ProviderDirectory,
    provider_id: String,
) -> anyhow::Result<()> {
    // RAII: the terminal is restored on ANY exit path (error/panic/normal).
    let _guard = TermGuard::new()?;
    // Catchable termination signals (kill <pid> = SIGTERM, terminal close = SIGHUP) bypass Drop via
    // process::exit — restore the terminal explicitly before exiting so a kill never leaves 乱码.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        for kind in [SignalKind::terminate(), SignalKind::hangup()] {
            if let Ok(mut s) = signal(kind) {
                tokio::spawn(async move {
                    s.recv().await;
                    restore_terminal();
                    std::process::exit(143);
                });
            }
        }
    }
    let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
    let mut term = Terminal::new(backend)?;

    let repo = agent.workspace.clone();
    let mut app = App::new();
    app.mode = agent.permission_mode();
    app.effort = agent.effort();
    app.model = agent.model.clone();
    app.model_context_window = agent.model_context_window;
    app.provider_id = provider_id;
    let provider_credential_envs = providers.credential_env_names();
    let interrupt = Arc::new(AtomicBool::new(false));
    agent.set_interrupt(interrupt.clone());

    // The approvals channel back into the running kernel (the one genuinely-new runtime path,
    // R5 §4): an `Ask` verdict makes the kernel emit UiEvent::ApprovalRequest and block on this
    // receiver for an `Op::ApprovalResponse`. One channel for the whole session; the receiver
    // travels with the agent in/out of the run task, the sender stays here to answer.
    let (atx, arx): (UnboundedSender<Op>, UnboundedReceiver<Op>) =
        tokio::sync::mpsc::unbounded_channel();
    agent.set_approvals(arx);

    // The agent runs in a background task; it streams UiEvents back. We move the agent into the
    // task while running, and take it back when the run completes (via a oneshot returning it).
    let mut agent_slot: Option<Agent> = Some(agent);
    let mut run_handle: Option<tokio::task::JoinHandle<(Agent, RunCompletion)>> = None;
    let mut rx: Option<UnboundedReceiver<UiEvent>> = None;
    let mut first_task = initial_task;
    let mut redraw = true;

    loop {
        // Kick off the initial task once the terminal is up.
        if let Some(task) = first_task.take()
            && !task.trim().is_empty()
        {
            start_run(
                &mut agent_slot,
                &mut run_handle,
                &mut rx,
                &interrupt,
                &mut app,
                task,
                true,
            );
            redraw = true;
        }

        // Drain any pending UI events (non-blocking).
        if let Some(r) = rx.as_mut() {
            while let Ok(ev) = r.try_recv() {
                apply_event(&mut app, ev);
                redraw = true;
            }
        }
        if app.advance_tool_presentations(Instant::now()) {
            redraw = true;
        }

        // Has the run finished? Reclaim the agent. If the run task PANICKED, the agent is lost;
        // we surface the error and stay idle (the user can quit) rather than hanging forever.
        if let Some(h) = run_handle.as_mut()
            && h.is_finished()
        {
            redraw = true;
            let handle = run_handle.take().unwrap();
            let joined = handle.await;
            // Completion is the synchronization barrier for the producer. Drain once more after
            // joining so the tail Text/ToolEnd/SteerApplied events sent between the earlier Empty
            // observation and task completion cannot be discarded with the receiver.
            if let Some(r) = rx.as_mut() {
                while let Ok(ev) = r.try_recv() {
                    apply_event(&mut app, ev);
                }
            }
            app.running = false;
            app.interrupting = false;
            app.run_started = None;
            app.flush_text();
            app.pending = None; // a pending approval cannot outlive its run
            app.settle_unfinished_tools();
            interrupt.store(false, Ordering::Relaxed);
            match joined {
                Ok((mut agent_back, completion)) => {
                    // A channel send is not delivery. Atomically drain the reclaimed Agent's
                    // unadmitted operations, then move those exact raw texts (not the display
                    // previews) into the global submission order. This prevents loss, duplicate
                    // injection, and cross-lane reordering on the next run.
                    let unadmitted = agent_back.take_unadmitted_steers();
                    let (count, unmatched_previews) = app.requeue_unadmitted(unadmitted);
                    if count > 0 {
                        app.note(
                            block::NoticeLevel::Warn,
                            format!(
                                "{count} steering submission(s) missed the safe point; queued after the turn"
                            ),
                        );
                    }
                    if unmatched_previews > 0 {
                        app.note(
                            block::NoticeLevel::Warn,
                            format!(
                                "delivery could not be confirmed for {unmatched_previews} steering submission(s); preserved after the turn"
                            ),
                        );
                    }
                    // refresh the status-line mirrors from the reclaimed agent.
                    app.mode = agent_back.permission_mode();
                    app.effort = agent_back.effort();
                    app.model = agent_back.model.clone();
                    app.cost = agent_back.ledger.cost_state();
                    app.last_turn_usage = agent_back.ledger.last_turn_usage;
                    agent_slot = Some(agent_back);
                    match completion {
                        RunCompletion::Outcome(outcome) => {
                            app.status = format!("idle · last: {}", outcome_label(&outcome));
                        }
                        RunCompletion::Error(detail) => {
                            app.push_block(block::BlockKind::Error {
                                title: "run failed".into(),
                                detail,
                                open: true,
                            });
                            app.status = "idle · last: run failed".into();
                        }
                    }
                }
                Err(e) => {
                    let unconfirmed = app.steer_previews.len();
                    app.steer_previews.clear();
                    if unconfirmed > 0 {
                        app.note(
                            block::NoticeLevel::Warn,
                            format!(
                                "delivery is unknown for {unconfirmed} steering submission(s); the run task was lost"
                            ),
                        );
                    }
                    app.push_block(block::BlockKind::Error {
                            title: format!("run task failed: {e}"),
                            detail: "the session cannot continue — press Esc to quit (resume later with --resume).".into(),
                            open: true,
                        });
                    app.status = "error (no agent) — Esc to quit".into();
                }
            }
            rx = None;
            // Dispatch queued follow-ups IN ORDER, each classified separately (round-3 review:
            // a joined blob mis-classified `/compact`+task). Commands execute inline; the first
            // PROSE item starts a run and we stop — the remaining items dispatch on the next
            // reclaim (a run is single-writer; we cannot start two at once).
            while !app.queued.is_empty() && agent_slot.is_some() {
                let q = app
                    .queued
                    .pop_front()
                    .expect("queue checked non-empty")
                    .text;
                let q = q.trim().to_string();
                if q.is_empty() {
                    continue;
                } else if let Some(cmd) = q.strip_prefix('/') {
                    app.push(bold(app.theme.accent), format!("/{cmd}"));
                    let is_compact = cmd == "compact"
                        || cmd
                            .strip_prefix("compact")
                            .is_some_and(|r| r.starts_with(char::is_whitespace));
                    if is_compact {
                        if let Some(ag) = agent_slot.as_mut() {
                            let focus =
                                cmd.strip_prefix("compact").unwrap_or("").trim().to_string();
                            match ag
                                .compact_now(if focus.is_empty() { None } else { Some(focus) })
                                .await
                            {
                                Ok(r) => app.push(
                                    fg(Color::Green),
                                    format!("compacted {} -> {} messages", r.before, r.after),
                                ),
                                Err(e) => app.push(fg(Color::Red), format!("compact failed: {e}")),
                            }
                        }
                    } else {
                        handle_command(&mut app, &mut agent_slot, &providers, cmd).await;
                    }
                } else if let Some(bash) = q.strip_prefix('!') {
                    run_bash_inline(&mut app, &repo, bash.trim(), &provider_credential_envs).await;
                } else {
                    app.push_user(q.clone());
                    start_run(
                        &mut agent_slot,
                        &mut run_handle,
                        &mut rx,
                        &interrupt,
                        &mut app,
                        q,
                        false,
                    );
                    break; // a run started; remaining items dispatch after it finishes
                }
            }
        }

        // Active animation targets a 100 ms cadence; input may request an additional immediate
        // frame. Idle is event-driven and does not repaint on the lifecycle poll.
        if app.running {
            app.spin = app.spin.wrapping_add(1);
            redraw = true;
        }

        if redraw {
            term.draw(|f| draw(f, &mut app))?;
            redraw = false;
        }

        // A running session polls at the animation/event cadence. Idle wakes occasionally only for
        // lifecycle checks; without input or events it does no rendering work.
        let poll_for = if app.running {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        if event::poll(poll_for)? {
            redraw = true;
            match event::read()? {
                // Bracketed paste: insert the WHOLE pasted text (incl. newlines) into the editor
                // rather than letting each pasted newline submit a partial line (review HIGH).
                CEvent::Paste(pasted) => {
                    app.editor.insert_str(&pasted);
                    app.refresh_completion(&repo);
                }
                // Mouse: wheel/trackpad scroll moves the CHAT transcript (prompt history stays on ↑/↓);
                // a left-click on a card row folds/unfolds it.
                CEvent::Mouse(m) => match m.kind {
                    MouseEventKind::ScrollUp => {
                        app.scroll_up(3);
                    }
                    MouseEventKind::ScrollDown => {
                        app.scroll_down(3);
                    }
                    MouseEventKind::Down(MouseButton::Left)
                        if m.row >= app.view_top && m.row < app.view_top + app.view_h =>
                    {
                        let idx = app.view_scroll as usize + (m.row - app.view_top) as usize;
                        if let Some(&bi) = app.row_map.get(idx)
                            && bi != usize::MAX
                        {
                            app.toggle_fold(bi);
                        }
                    }
                    _ => {}
                },
                CEvent::Key(k) => {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);

                    // On terminals without key-disambiguation, a standalone Esc immediately
                    // followed by the next command's first printable byte arrives as Alt+char.
                    // Recover it before the modal's keyboard-ownership branch consumes the byte.
                    if app.recover_picker_escape_prefixed_char(k.code, k.modifiers, &repo) {
                        continue;
                    }

                    // An open picker OWNS the keyboard (C6): route the key to it, apply on accept
                    // (take-then-apply, C5), and fully consume — no fall-through to editor/history/mode.
                    if app.picker.is_some() {
                        match app.picker_key_with_modifiers(k.code, k.modifiers) {
                            Some(PickerEvent::Accept(action)) => {
                                apply_action(&mut app, &mut agent_slot, &providers, action)
                            }
                            Some(PickerEvent::Cancel) | Some(PickerEvent::Consumed) | None => {}
                        }
                        continue;
                    }

                    // While the kernel is blocked on a capability approval, y/n/a/Esc answer it and
                    // arrows/Tab + Enter make it a real focusable control; nothing falls through to
                    // the editor. This is the in-TUI approval UX (R5 §4.4).
                    if app.running && app.pending.is_some() {
                        if k.code == KeyCode::Char('c') && ctrl {
                            // Ctrl-C while pending = deny this call + park the run at a safe point.
                            let _ = atx.send(Op::Interrupt);
                            app.interrupting = true;
                            if let Some(p) = app.pending.take() {
                                app.note(
                                    block::NoticeLevel::Err,
                                    format!("denied `{}` and interrupting", p.tool),
                                );
                            }
                            continue;
                        }
                        if let ApprovalInput::Answer { approved, remember } =
                            app.approval_key(k.code)
                            && let Some(p) = app.pending.take()
                        {
                            let _ = atx.send(Op::ApprovalResponse {
                                id: p.id,
                                approved,
                                remember,
                            });
                            let verb = match (approved, remember) {
                                (true, true) => "approved (always)",
                                (true, false) => "approved",
                                _ => "denied",
                            };
                            app.note(
                                if approved {
                                    block::NoticeLevel::Ok
                                } else {
                                    block::NoticeLevel::Err
                                },
                                format!("{verb} `{}` ({})", p.tool, cap_label(p.cap)),
                            );
                        }
                        continue; // consume the key; do not fall through to normal input handling
                    }

                    let alt = k.modifiers.contains(KeyModifiers::ALT);
                    let shift = k.modifiers.contains(KeyModifiers::SHIFT);
                    let menu_open = app.completion.is_some();
                    let mut refresh = false;
                    match k.code {
                        KeyCode::Char('c') if ctrl => {
                            if app.running {
                                if interrupt.load(Ordering::Relaxed) {
                                    // Second Ctrl-C: the cooperative interrupt did not land. Hard-abort.
                                    if let Some(h) = run_handle.take() {
                                        h.abort();
                                    }
                                    app.running = false;
                                    app.interrupting = false;
                                    app.flush_text();
                                    app.pending = None;
                                    app.steer_previews.clear();
                                    app.active_tools.clear();
                                    app.run_started = None;
                                    interrupt.store(false, Ordering::Relaxed);
                                    rx = None;
                                    app.push_block(block::BlockKind::Error {
                                    title: "hard-aborted".into(),
                                    detail: "the agent is gone; resume this session with `core --resume <run>`. Press Esc to quit.".into(),
                                    open: true,
                                });
                                    app.status = "aborted (no agent) — Esc to quit".into();
                                } else {
                                    interrupt.store(true, Ordering::Relaxed);
                                    app.interrupting = true;
                                    app.push(bold(Color::Yellow), "interrupting at the next safe point… (Ctrl-C again to hard-abort)");
                                }
                            } else if !app.editor.is_empty() {
                                app.editor.clear_recoverable();
                                app.completion = None;
                                app.resume_handoff = None;
                            } else {
                                app.quit = true;
                            }
                        }
                        // Ctrl-O: expand/collapse the most recent tool/thinking/error block (CC's ctrl+o).
                        KeyCode::Char('o') if ctrl => app.toggle_last_fold(),
                        // One bounded draft slot: Ctrl-C/Esc clears safely; Ctrl-Z restores once
                        // without conflating submitted history with unsent recovery.
                        KeyCode::Char('z') if ctrl && app.editor.restore_recently_cleared() => {
                            app.resume_handoff = None;
                            refresh = true;
                        }
                        KeyCode::Char('d') if ctrl && !app.running => {
                            if app.editor.is_empty() {
                                app.quit = true;
                            } else {
                                app.editor.delete();
                                refresh = true;
                            }
                        }
                        KeyCode::BackTab if !app.running => {
                            if let Some(ag) = agent_slot.as_mut() {
                                let next = ag.permission_mode().next();
                                if commit_permission_mode(&mut app, ag, next) {
                                    app.push(fg(Color::Cyan), format!("mode: {}", next.label()));
                                }
                            }
                        }
                        // ---- completion menu navigation (menu open) ----
                        KeyCode::Down if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = (c.sel + 1) % c.items.len();
                            }
                        }
                        KeyCode::Up if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = (c.sel + c.items.len() - 1) % c.items.len();
                            }
                        }
                        // Unified menu nav (TUI v3 §9 — same PageUp/PageDown/Home/End as the picker).
                        KeyCode::PageDown if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = (c.sel + 8).min(c.items.len().saturating_sub(1));
                            }
                        }
                        KeyCode::PageUp if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = c.sel.saturating_sub(8);
                            }
                        }
                        KeyCode::Home if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = 0;
                            }
                        }
                        KeyCode::End if menu_open => {
                            if let Some(c) = app.completion.as_mut() {
                                c.sel = c.items.len().saturating_sub(1);
                            }
                        }
                        KeyCode::Tab if menu_open => {
                            app.accept_completion();
                            refresh = true;
                        }
                        KeyCode::Enter if menu_open => {
                            let submit = app.accept_completion_for_enter();
                            if submit && !app.running {
                                // Consume this physical Enter exactly once: it submits the command,
                                // but the picker opened by that command does not see the same key.
                                let line = app.editor.take_submit();
                                let trimmed = line.trim();
                                app.completion = None;
                                if let Some(cmd) = trimmed.strip_prefix('/') {
                                    dispatch_slash_command(
                                        &mut term,
                                        &mut app,
                                        &mut agent_slot,
                                        &providers,
                                        cmd,
                                    )
                                    .await?;
                                }
                            } else {
                                refresh = true;
                            }
                        }
                        KeyCode::Esc if menu_open => {
                            app.completion = None;
                        }
                        // ---- input history (idle, no menu) ----
                        KeyCode::Up if !app.running => {
                            app.editor.history_prev();
                            refresh = true;
                        }
                        KeyCode::Down if !app.running => {
                            app.editor.history_next();
                            refresh = true;
                        }
                        // ---- cursor + readline editing (idle or composing while running) ----
                        KeyCode::Left if alt => app.editor.word_left(),
                        KeyCode::Right if alt => app.editor.word_right(),
                        KeyCode::Char('b') if alt => app.editor.word_left(),
                        KeyCode::Char('f') if alt => app.editor.word_right(),
                        KeyCode::Left => {
                            app.editor.left();
                            refresh = true;
                        }
                        KeyCode::Right => {
                            app.editor.right();
                            refresh = true;
                        }
                        KeyCode::End if ctrl => app.follow_latest(),
                        KeyCode::Home => app.editor.home(),
                        KeyCode::End => app.editor.end(),
                        KeyCode::Char('a') if ctrl => app.editor.home(),
                        KeyCode::Char('e') if ctrl => app.editor.end(),
                        KeyCode::Char('u') if ctrl => {
                            app.editor.kill_to_start();
                            refresh = true;
                        }
                        KeyCode::Char('k') if ctrl => {
                            app.editor.kill_to_end();
                            refresh = true;
                        }
                        KeyCode::Char('w') if ctrl => {
                            app.editor.delete_word_before();
                            refresh = true;
                        }
                        // Ctrl-J is the portable newline fallback on terminals that cannot report
                        // Shift-Enter distinctly.
                        KeyCode::Char('j') if ctrl => {
                            app.editor.newline();
                            refresh = true;
                        }
                        // A queued (not yet delivered) follow-up is safe to take back for editing.
                        KeyCode::Up if alt && app.running && app.editor.is_empty() => {
                            if let Some(input) = app.queued.pop_back() {
                                app.editor.insert_str(&input.text);
                                refresh = true;
                            }
                        }
                        KeyCode::Delete => {
                            app.editor.delete();
                            refresh = true;
                        }
                        KeyCode::Backspace => {
                            app.editor.backspace();
                            refresh = true;
                        }
                        // ---- multi-line (Alt/Shift+Enter, or a trailing backslash) ----
                        KeyCode::Enter if alt || shift => {
                            app.editor.newline();
                            refresh = true;
                        }
                        // Esc clears a non-empty line first (like a shell / the leading agent); quits only
                        // on an already-empty line — so typed-but-unsent input is never silently discarded.
                        KeyCode::Esc if !app.running && !app.editor.is_empty() => {
                            app.editor.clear_recoverable();
                            app.resume_handoff = None;
                            refresh = true;
                        }
                        KeyCode::Esc if !app.running => app.quit = true,
                        KeyCode::Enter if !app.running => {
                            if app.is_resume_handoff_draft() {
                                let command = app.editor.text();
                                app.note(
                                    block::NoticeLevel::Info,
                                    format!(
                                        "restart handoff kept for copying; run it in a new terminal: {command}"
                                    ),
                                );
                            } else if app.editor.wants_continuation() {
                                app.editor.newline();
                            } else {
                                app.resume_handoff = None;
                                let line = app.editor.take_submit();
                                let trimmed = line.trim().to_string();
                                app.completion = None;
                                if trimmed.is_empty() {
                                    // nothing
                                } else if let Some(cmd) = trimmed.strip_prefix('/') {
                                    dispatch_slash_command(
                                        &mut term,
                                        &mut app,
                                        &mut agent_slot,
                                        &providers,
                                        cmd,
                                    )
                                    .await?;
                                } else if let Some(bash) = trimmed.strip_prefix('!') {
                                    run_bash_inline(
                                        &mut app,
                                        &repo,
                                        bash.trim(),
                                        &provider_credential_envs,
                                    )
                                    .await;
                                } else {
                                    app.push_user(trimmed.to_string());
                                    start_run(
                                        &mut agent_slot,
                                        &mut run_handle,
                                        &mut rx,
                                        &interrupt,
                                        &mut app,
                                        trimmed,
                                        false,
                                    );
                                }
                            }
                        }
                        // Enter while running: STEER at the next turn-atomic safe point. Slash/shell
                        // input remains a
                        // post-run frontend action; it must not be injected as model prose.
                        KeyCode::Enter if app.running && !app.editor.is_empty() => {
                            let text = app.editor.take_submit();
                            match input_destination(app.running, &text) {
                                InputDestination::AfterTurn => {
                                    if let Err(text) = app.queue_after_turn(text) {
                                        app.editor.insert_str(&text);
                                    }
                                }
                                InputDestination::SteerCurrentRun => {
                                    match app.steer_admission(&text) {
                                        SubmissionAdmission::Accept => {
                                            if atx.send(Op::Steer { text: text.clone() }).is_ok() {
                                                app.track_steer(text);
                                            } else {
                                                // Receiver disappeared at the run boundary:
                                                // preserve the words as an ordered follow-up.
                                                if let Err(text) = app.queue_after_turn(text) {
                                                    app.editor.insert_str(&text);
                                                }
                                            }
                                        }
                                        SubmissionAdmission::IgnoreEmpty => {}
                                        SubmissionAdmission::Reject => app.editor.insert_str(&text),
                                    }
                                }
                                InputDestination::StartTurn => unreachable!(
                                    "the running Enter branch cannot resolve to StartTurn"
                                ),
                            }
                            app.completion = None;
                        }
                        // Codex/Claude-style explicit queue: Tab defers the text until this run ends.
                        KeyCode::Tab if app.running && !app.editor.is_empty() => {
                            let text = app.editor.take_submit();
                            if let Err(text) = app.queue_after_turn(text) {
                                app.editor.insert_str(&text);
                            }
                            app.completion = None;
                        }
                        // Esc while running interrupts at the next safe point (like the leading agent).
                        KeyCode::Esc if app.running && !app.interrupting => {
                            interrupt.store(true, Ordering::Relaxed);
                            app.interrupting = true;
                            app.push(bold(Color::Yellow), "interrupting at the next safe point…");
                        }
                        KeyCode::Char('?')
                            if !app.running && app.editor.is_empty() && !menu_open =>
                        {
                            handle_command(&mut app, &mut agent_slot, &providers, "help").await;
                        }
                        // ordinary typing works in both idle and running composer states.
                        KeyCode::Char(c) if !ctrl && !alt => {
                            app.editor.insert(c);
                            refresh = true;
                        }
                        KeyCode::PageUp => app.scroll_up(10),
                        KeyCode::PageDown => app.scroll_down(10),
                        _ => {}
                    }
                    if refresh {
                        app.refresh_completion(&repo);
                    }
                } // end CEvent::Key
                _ => {} // resize etc. -> next draw handles it
            }
        }

        if app.quit && !app.running {
            break;
        }
    }

    // teardown (the guard also restores on drop; show_cursor is the only extra step).
    let _ = term.show_cursor();
    Ok(())
}

/// Execute one already-submitted slash command. Both ordinary Enter and Enter on a slash
/// completion use this path, so completion activation cannot drift into a second dispatch path.
async fn dispatch_slash_command(
    term: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    agent_slot: &mut Option<Agent>,
    providers: &ProviderDirectory,
    cmd: &str,
) -> anyhow::Result<()> {
    app.push(bold(app.theme.accent), format!("/{cmd}"));
    let is_compact = cmd == "compact"
        || cmd
            .strip_prefix("compact")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace));
    if !is_compact {
        handle_command(app, agent_slot, providers, cmd).await;
        return Ok(());
    }

    let focus = cmd.strip_prefix("compact").unwrap_or("").trim().to_string();
    if let Some(agent) = agent_slot.as_mut() {
        app.push(dim(), "compacting…");
        term.draw(|frame| draw(frame, app))?;
        match agent
            .compact_now((!focus.is_empty()).then_some(focus))
            .await
        {
            Ok(result) => app.push(
                fg(Color::Green),
                format!("compacted {} -> {} messages", result.before, result.after),
            ),
            Err(error) => app.push(fg(Color::Red), format!("compact failed: {error}")),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_run(
    agent_slot: &mut Option<Agent>,
    run_handle: &mut Option<tokio::task::JoinHandle<(Agent, RunCompletion)>>,
    rx: &mut Option<UnboundedReceiver<UiEvent>>,
    _interrupt: &Arc<AtomicBool>,
    app: &mut App,
    task: String,
    is_first: bool,
) {
    let Some(mut agent) = agent_slot.take() else {
        return;
    };
    let (tx, new_rx) = tokio::sync::mpsc::unbounded_channel();
    agent.set_ui(tx);
    *rx = Some(new_rx);
    app.running = true;
    app.interrupting = false;
    app.status = "running…".into();
    app.run_started = Some(Instant::now());
    app.completion = None;
    *run_handle = Some(tokio::spawn(async move {
        let outcome = if is_first {
            agent.run(&task).await
        } else {
            agent.follow_up(&task).await
        };
        let completion = match outcome {
            Ok(outcome) => RunCompletion::Outcome(outcome),
            Err(error) => RunCompletion::Error(error.public_summary()),
        };
        (agent, completion)
    }));
}

/// Instantiate and validate the new `(provider, model)` pair before mutating either field. A
/// failed construction leaves the old provider and old model together, avoiding cross-provider
/// requests with a model id from a different account.
fn apply_model_selection(
    app: &mut App,
    agent: &mut Agent,
    directory: &ProviderDirectory,
    selection: ModelSelection,
) {
    let provider = match directory.build(&selection) {
        Ok(provider) => provider,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("cannot switch model: {error}"),
            );
            return;
        }
    };

    let changed = agent.model != selection.model_id || app.provider_id != selection.provider_id;
    let provider_name = directory
        .entry(&selection.provider_id)
        .map(|entry| entry.display_name().to_owned())
        .unwrap_or_else(|| selection.provider_id.clone());

    // Write-ahead audit: if the hash-chained record cannot durably accept the route, keep the old
    // provider/model pair. The frontend never sends a turn through an unrecorded destination.
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    if let Err(error) = agent.record_model_selection(
        selection.provider_id.clone(),
        selection.model_id.clone(),
        catalog_digest,
        capability_digest,
    ) {
        app.note(
            block::NoticeLevel::Err,
            format!("cannot record model switch; old selection retained: {error}"),
        );
        return;
    }

    // Commit point: adapter construction, availability validation, and durable recording have
    // all succeeded.
    agent.provider = provider;
    agent.model = selection.model_id.clone();
    let capabilities = directory.selection_capabilities(&selection);
    agent.model_context_window = capabilities.context_window_tokens;
    agent.model_max_output_tokens = capabilities.max_output_tokens;
    app.model = selection.model_id.clone();
    app.provider_id = selection.provider_id.clone();
    if changed {
        clear_last_turn_telemetry(app, &mut agent.ledger);
    }
    app.model_context_window = agent.model_context_window;
    app.note(
        block::NoticeLevel::Ok,
        format!(
            "model set to {}:{}  ·  {provider_name} backend",
            selection.provider_id, selection.model_id
        ),
    );
    if changed {
        app.note(
            block::NoticeLevel::Warn,
            "switching model re-reads the history uncached (new prefix cache)",
        );
    }
}

fn clear_last_turn_telemetry(app: &mut App, ledger: &mut core_obs::Ledger) {
    // These fields describe one exact provider/model/effort request. Until snapshots carry an
    // explicit route identity, clearing on a route/effort change is the only truthful projection.
    ledger.last_turn_usage = None;
    app.last_turn_usage = None;
    app.last_context = None;
    app.reserved_output_tokens = None;
    app.effort_application = None;
}

/// Resolve an explicit model-leaf retry without weakening normal selection. A qualified value is
/// treated as `provider:model` only when the prefix names a configured provider, preserving model
/// ids such as OpenAI fine-tunes that themselves contain colons.
fn model_retry_selection(
    directory: &ProviderDirectory,
    current_provider: &str,
    current_model: &str,
    value: &str,
) -> Result<ModelSelection, String> {
    let value = value.trim();
    if value.is_empty() {
        if current_provider.is_empty() || current_model.is_empty() {
            return Err("no current provider/model is available to retry".into());
        }
        return Ok(ModelSelection {
            provider_id: current_provider.to_owned(),
            model_id: current_model.to_owned(),
        });
    }
    if let Some((provider_id, model_id)) = value
        .split_once(':')
        .filter(|(provider_id, _)| directory.entry(provider_id).is_some())
    {
        if model_id.is_empty() {
            return Err("retry target must include a model id".into());
        }
        return Ok(ModelSelection {
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
        });
    }
    if current_provider.is_empty() {
        return Err("retry a non-current provider with provider:model-id".into());
    }
    Ok(ModelSelection {
        provider_id: current_provider.to_owned(),
        model_id: value.to_owned(),
    })
}

/// Commit one runtime setting through the kernel's durable policy transaction. Frontend mirrors
/// change only after the record append + fsync succeeds, so a visible control can never claim a
/// state that resume/fork would lose.
fn commit_effort(app: &mut App, agent: &mut Agent, next: Effort) -> bool {
    match agent.transition_effort(next, RuntimePolicySource::Operator) {
        Ok(changed) => {
            if changed {
                clear_last_turn_telemetry(app, &mut agent.ledger);
            }
            app.effort = agent.effort();
            true
        }
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("effort was not changed: {}", error.public_summary()),
            );
            false
        }
    }
}

fn commit_permission_mode(app: &mut App, agent: &mut Agent, next: PermissionMode) -> bool {
    match agent.transition_permission_mode(next, RuntimePolicySource::Operator) {
        Ok(_) => {
            app.mode = agent.permission_mode();
            true
        }
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!(
                    "permission mode was not changed: {}",
                    error.public_summary()
                ),
            );
            false
        }
    }
}

fn commit_permission_capability(
    app: &mut App,
    agent: &mut Agent,
    capability: Capability,
    verdict: Verdict,
) -> bool {
    match agent.transition_permission_capability_rule(
        capability,
        verdict,
        RuntimePolicySource::Operator,
    ) {
        Ok(_) => {
            app.mode = agent.permission_mode();
            true
        }
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!(
                    "permission rule was not changed: {}",
                    error.public_summary()
                ),
            );
            false
        }
    }
}

/// Apply a picked action to the idle agent + UI state (C5 take-then-apply calls this after dropping
/// the picker borrow). Surfaces a Notice if the agent is gone rather than silently no-op'ing (C6).
fn apply_action(
    app: &mut App,
    agent: &mut Option<Agent>,
    directory: &ProviderDirectory,
    action: PickAction,
) {
    if let PickAction::PrepareResume(run_id) = &action {
        app.prepare_resume_handoff(run_id);
        return;
    }
    if matches!(&action, PickAction::Info) {
        return;
    }
    let Some(ag) = agent.as_mut() else {
        app.note(
            block::NoticeLevel::Err,
            "no active agent — selection not applied",
        );
        return;
    };
    match action {
        PickAction::SetModel(selection) => apply_model_selection(app, ag, directory, selection),
        PickAction::SetEffort(e) => {
            if commit_effort(app, ag, e) {
                let lvl = if e == Effort::Ultracode {
                    block::NoticeLevel::Warn
                } else {
                    block::NoticeLevel::Ok
                };
                app.note(lvl, format!("effort set to {} — {}", e.label(), e.hint()));
            }
        }
        PickAction::SetMode(m) => {
            if commit_permission_mode(app, ag, m) {
                app.note(block::NoticeLevel::Ok, format!("mode set to {}", m.label()));
            }
        }
        PickAction::SetCap(c, v) => {
            let vl = match v {
                Verdict::Auto => "allow",
                Verdict::Ask => "ask",
                Verdict::Deny => "deny",
            };
            if commit_permission_capability(app, ag, c, v) {
                app.note(
                    block::NoticeLevel::Ok,
                    format!("permission rule: {} → {vl}", cap_label(c)),
                );
            }
        }
        PickAction::SetTheme(theme) => apply_theme_selection(app, theme),
        PickAction::PrepareResume(_) | PickAction::Info => unreachable!("handled before agent"),
    }
}

fn apply_theme_selection(app: &mut App, theme: theme::Theme) {
    // Navigation live-previews, while immediate Enter on the first row applies it here.
    app.set_theme(theme);
    app.note(block::NoticeLevel::Ok, "theme applied");
}

fn model_picker_items(
    directory: &ProviderDirectory,
    current_provider: &str,
    current_model: &str,
) -> Vec<PickItem> {
    let mut items = Vec::new();
    let mut current_provider_seen = false;

    for entry in directory.entries() {
        let is_current_provider = entry.id() == current_provider;
        current_provider_seen |= is_current_provider;
        let provider_reason = directory.blocked_reason(entry);
        let provider_index = items.len();
        items.push(PickItem {
            label: entry.display_name().to_owned(),
            hint: directory.status_label(entry),
            is_current: is_current_provider,
            action: PickAction::Info,
            parent: None,
            depth: 0,
            expandable: true,
            expanded: is_current_provider,
            enabled: provider_reason.is_none(),
            disabled_reason: provider_reason.clone(),
        });

        let mut current_model_seen = false;
        if let Some(catalog) = &entry.catalog {
            for family in &catalog.families {
                let family_has_current = is_current_provider
                    && family
                        .models
                        .iter()
                        .any(|model| model.raw.id == current_model);
                current_model_seen |= family_has_current;
                let family_index = items.len();
                items.push(PickItem {
                    label: family.display_name.clone(),
                    hint: format!("{} models", family.models.len()),
                    is_current: false,
                    action: PickAction::Info,
                    parent: Some(provider_index),
                    depth: 1,
                    expandable: true,
                    expanded: family_has_current,
                    enabled: provider_reason.is_none(),
                    disabled_reason: provider_reason.clone(),
                });
                for model in &family.models {
                    let model_reason = provider_reason
                        .clone()
                        .or_else(|| directory.model_blocked_reason(entry.id(), &model.raw.id))
                        .or_else(|| match model.selectability {
                            core_provider::Selectability::Selectable => None,
                            core_provider::Selectability::Disabled { reason } => {
                                Some(reason.into())
                            }
                        });
                    let label = model
                        .raw
                        .display_name
                        .as_deref()
                        .filter(|name| *name != model.raw.id)
                        .map(|name| format!("{} · {name}", model.raw.id))
                        .unwrap_or_else(|| model.raw.id.clone());
                    let hint = model
                        .raw
                        .owned_by
                        .as_deref()
                        .map(|owner| format!("owned by {owner}"))
                        .unwrap_or_default();
                    items.push(PickItem {
                        label,
                        hint,
                        is_current: is_current_provider && model.raw.id == current_model,
                        action: PickAction::SetModel(ModelSelection {
                            provider_id: entry.id().to_owned(),
                            model_id: model.raw.id.clone(),
                        }),
                        parent: Some(family_index),
                        depth: 2,
                        expandable: false,
                        expanded: false,
                        enabled: model_reason.is_none(),
                        disabled_reason: model_reason,
                    });
                }
            }
        }

        // Keep the active pair visible even if a refresh no longer returns it. It is disabled when
        // the provider promised a catalog, and selectable only for an operator-declared
        // catalog-disabled gateway.
        if is_current_provider && !current_model.is_empty() && !current_model_seen {
            let family_index = items.len();
            items.push(PickItem {
                label: "Current / unverified".into(),
                hint: "pinned from this session".into(),
                is_current: false,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: true,
                expanded: true,
                enabled: provider_reason.is_none() && !entry.catalog_enabled,
                disabled_reason: provider_reason.clone(),
            });
            let reason = provider_reason.clone().or_else(|| {
                entry
                    .catalog_enabled
                    .then(|| "not present in the current provider catalog".into())
            });
            items.push(PickItem {
                label: current_model.to_owned(),
                hint: "current selection".into(),
                is_current: true,
                action: PickAction::SetModel(ModelSelection {
                    provider_id: entry.id().to_owned(),
                    model_id: current_model.to_owned(),
                }),
                parent: Some(family_index),
                depth: 2,
                expandable: false,
                expanded: false,
                enabled: reason.is_none(),
                disabled_reason: reason,
            });
        } else if entry.catalog.is_none() {
            let reason = provider_reason
                .clone()
                .or_else(|| entry.catalog_error.clone())
                .unwrap_or_else(|| "no dynamic catalog loaded".into());
            items.push(PickItem {
                label: "Models unavailable".into(),
                hint: String::new(),
                is_current: false,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: false,
                expanded: false,
                enabled: false,
                disabled_reason: Some(reason),
            });
        }
    }

    if !current_provider_seen && (!current_provider.is_empty() || !current_model.is_empty()) {
        let provider_index = items.len();
        items.push(PickItem {
            label: if current_provider.is_empty() {
                "Unresolved provider".into()
            } else {
                current_provider.to_owned()
            },
            hint: "current provider is not configured".into(),
            is_current: true,
            action: PickAction::Info,
            parent: None,
            depth: 0,
            expandable: true,
            expanded: true,
            enabled: false,
            disabled_reason: Some("provider is not configured".into()),
        });
        if !current_model.is_empty() {
            items.push(PickItem {
                label: current_model.to_owned(),
                hint: "current selection".into(),
                is_current: true,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: false,
                expanded: false,
                enabled: false,
                disabled_reason: Some("provider is not configured".into()),
            });
        }
    }
    items
}

fn permission_picker_items(rules: &PermissionRules) -> Vec<PickItem> {
    let caps = [
        (Capability::ReversibleLocal, "Reversible edits"),
        (Capability::CodeExecuting, "Code execution"),
        (Capability::TrustMutating, "Trust and policy changes"),
        (
            Capability::IrreversibleExternal,
            "External actions and network access",
        ),
    ];
    let verdicts = [
        (Verdict::Auto, "allow automatically"),
        (Verdict::Ask, "ask every time"),
        (Verdict::Deny, "deny"),
    ];
    let mut items = vec![PickItem {
        label: "Read-only operations → always allow".into(),
        hint: "viewing files and metadata does not prompt".into(),
        is_current: false,
        action: PickAction::Info,
        parent: None,
        depth: 0,
        expandable: false,
        expanded: false,
        enabled: false,
        disabled_reason: Some(
            "read-only operations are always allowed and are not configurable".into(),
        ),
    }];

    for (capability, capability_label) in caps {
        for (verdict, verdict_label) in verdicts {
            let forbidden_auto = verdict == Verdict::Auto
                && matches!(
                    capability,
                    Capability::TrustMutating | Capability::IrreversibleExternal
                );
            items.push(PickItem {
                label: format!("{capability_label} → {verdict_label}"),
                hint: String::new(),
                is_current: rules.cap_rule(capability) == Some(verdict),
                action: PickAction::SetCap(capability, verdict),
                parent: None,
                depth: 0,
                expandable: false,
                expanded: false,
                enabled: !forbidden_auto,
                disabled_reason: forbidden_auto
                    .then(|| "non-negotiable: this capability always requires approval".into()),
            });
        }
    }
    items
}

fn format_resume_command(run_id: &str) -> String {
    let argument = if !run_id.is_empty()
        && run_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        run_id.to_string()
    } else {
        // Display-only POSIX shell quoting. The command is never executed by Core.
        format!("'{}'", run_id.replace('\'', "'\"'\"'"))
    };
    format!("core --resume {argument}")
}

fn session_picker_items(
    mut sessions: Vec<core_record::SessionMeta>,
    current_run: &str,
) -> Vec<PickItem> {
    sessions.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| left.run_id.0.cmp(&right.run_id.0))
    });
    sessions
        .into_iter()
        .map(|session| {
            let cost = session
                .cost_usd()
                .map(|value| format!("${value:.4}"))
                .unwrap_or_else(|| "cost unknown".into());
            let route = match (
                session.provider_id.trim().is_empty(),
                session.model.trim().is_empty(),
            ) {
                (false, false) => format!("{}/{}", session.provider_id, session.model),
                (false, true) => session.provider_id.clone(),
                (true, false) => session.model.clone(),
                (true, true) => "route unknown".into(),
            };
            let run_id = session.run_id.0;
            PickItem::flat(
                session.title,
                format!(
                    "run {run_id} · {} · {cost} · {route}",
                    block::plural(session.turns as usize, "turn")
                ),
                run_id == current_run,
                PickAction::PrepareResume(run_id),
            )
        })
        .collect()
}

fn open_session_picker(app: &mut App, ag: &Agent) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before browsing sessions",
        );
        return;
    }
    let runs = ag
        .rollout
        .path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current_run = ag
        .rollout
        .path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let items = session_picker_items(
        core_record::list(&runs, &core_protocol::TenantId::default()),
        current_run,
    );
    if items.is_empty() {
        app.note(block::NoticeLevel::Info, "no sessions recorded yet");
        return;
    }
    let sel = initial_picker_selection(&items);
    app.picker = Some(Picker {
        title: "Sessions · restart to resume".into(),
        items,
        sel,
        query: String::new(),
        saved_theme: None,
    });
}

/// Build a picker's items, pre-selecting the current value, and open it — refusing (with a Notice)
/// when a run/approval is in flight so accepting can never hit a taken agent (C6).
fn open_picker(app: &mut App, ag: &Agent, directory: &ProviderDirectory, kind: &str) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before opening a picker",
        );
        return;
    }
    let (title, mut items): (&str, Vec<PickItem>) = match kind {
        "model" => {
            let cur = ag.model.clone();
            (
                "Model",
                model_picker_items(directory, &app.provider_id, &cur),
            )
        }
        "effort" => {
            let cur = ag.effort();
            let items = Effort::ALL
                .iter()
                .map(|e| PickItem::flat(e.label(), e.hint(), *e == cur, PickAction::SetEffort(*e)))
                .collect();
            ("Effort", items)
        }
        "mode" => {
            let cur = ag.permission_mode();
            let modes = [
                (PermissionMode::Default, "edits prompt live"),
                (PermissionMode::AcceptEdits, "edits auto; code still gated"),
                (PermissionMode::Plan, "read-only; propose a plan first"),
                (
                    PermissionMode::Yolo,
                    "auto-approve (still asks for trust-mutating + egress)",
                ),
            ];
            let items = modes
                .iter()
                .map(|(m, h)| PickItem::flat(m.label(), *h, *m == cur, PickAction::SetMode(*m)))
                .collect();
            ("Permission mode", items)
        }
        "permissions" => (
            "Permissions",
            permission_picker_items(ag.permission_rules()),
        ),
        "theme" => {
            let items = theme::Theme::presets()
                .into_iter()
                .map(|(name, t)| {
                    PickItem::flat(
                        name,
                        "preview: ↑↓ · Enter to keep · Esc to revert",
                        false,
                        PickAction::SetTheme(t),
                    )
                })
                .collect();
            let saved = app.theme.clone();
            app.picker = Some(Picker {
                title: "Theme".into(),
                items,
                sel: 0,
                query: String::new(),
                saved_theme: Some(saved),
            });
            return;
        }
        _ => return,
    };
    let sel = initial_picker_selection(&items);
    expand_selection_ancestors(&mut items, sel);
    app.picker = Some(Picker {
        title: title.into(),
        items,
        sel,
        query: String::new(),
        saved_theme: None,
    });
}

fn initial_picker_selection(items: &[PickItem]) -> usize {
    items
        .iter()
        .position(|item| {
            item.is_current
                && item.enabled
                && !item.expandable
                && !matches!(&item.action, PickAction::Info)
        })
        .or_else(|| {
            items.iter().position(|item| {
                item.enabled && !item.expandable && !matches!(&item.action, PickAction::Info)
            })
        })
        // If no actionable leaf exists, retain the disabled current selection so its reason stays
        // discoverable instead of focusing an unrelated header.
        .or_else(|| {
            items
                .iter()
                .position(|item| item.is_current && !item.expandable)
        })
        .or_else(|| items.iter().position(|item| item.is_current))
        .or_else(|| items.iter().position(|item| item.enabled))
        .unwrap_or(0)
}

/// Make an initially focused hierarchical leaf visible before the first keypress. Without this,
/// a no-current session selected a hidden model under collapsed ancestors; Enter normalized focus
/// back to the provider header and appeared to require two or three presses.
fn expand_selection_ancestors(items: &mut [PickItem], selection: usize) {
    let mut parent = items.get(selection).and_then(|item| item.parent);
    let mut remaining = items.len();
    while let Some(index) = parent {
        if remaining == 0 {
            break;
        }
        remaining -= 1;
        let Some(item) = items.get_mut(index) else {
            break;
        };
        item.expanded = true;
        parent = item.parent;
    }
}

fn ensure_real_workspace_dir(root: &Path, name: &str) -> Result<PathBuf, String> {
    if Path::new(name).components().count() != 1 {
        return Err("directory name must be one workspace component".into());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace is unavailable: {error}"))?;
    let path = root.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!("{} is not a real directory", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&path)
                .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
            std::fs::File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("cannot sync workspace directory: {error}"))?;
        }
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if !canonical.starts_with(&root) {
        return Err("directory escapes the workspace".into());
    }
    Ok(canonical)
}

/// Resolve an operator-supplied export path inside the workspace. Existing symlinks and parent
/// symlink escapes are refused; `/export` is a workspace operation, not an ambient filesystem
/// write primitive.
fn confined_workspace_output(root: &Path, requested: &str) -> Result<PathBuf, String> {
    let relative = Path::new(requested);
    if requested.is_empty()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("path must be a non-empty workspace-relative path without `..`".into());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace is unavailable: {error}"))?;
    let candidate = root.join(relative);
    let parent = candidate
        .parent()
        .ok_or_else(|| "export path has no parent".to_string())?
        .canonicalize()
        .map_err(|error| format!("export parent is unavailable: {error}"))?;
    if !parent.starts_with(&root) {
        return Err("path escapes the workspace through a symlink".into());
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&candidate) {
        if metadata.file_type().is_symlink() {
            return Err("target must not be a symlink".into());
        }
        if !metadata.is_file() {
            return Err("target must be a regular file".into());
        }
    }
    Ok(candidate)
}

fn temporary_peer(path: &Path) -> Result<PathBuf, std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("output path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");
    for ordinal in 0..32_u32 {
        let candidate = parent.join(format!(".{name}.core-tmp-{}-{ordinal}", std::process::id()));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a temporary output file",
    ))
}

/// Same-directory write + fsync + rename, so an interrupted export keeps either the old complete
/// file or the new complete file rather than a truncated transcript.
fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let temporary = temporary_peer(path)?;
    let write = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    write
}

/// Create an initialization file without a check/write race and make its contents durable before
/// reporting success. Existing files are never overwritten.
fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Slash-command dispatcher (runs only when idle; `agent` is Some). Built-ins operate on the
/// idle agent + UI state; commands needing the memory/session modules are wired as those land.
async fn handle_command(
    app: &mut App,
    agent: &mut Option<Agent>,
    directory: &ProviderDirectory,
    cmd: &str,
) {
    let mut parts = cmd.split_whitespace();
    let name = parts.next().unwrap_or("");
    let arg = parts.collect::<Vec<_>>().join(" ");
    let Some(ag) = agent.as_mut() else {
        app.push(fg(Color::Red), "no agent available");
        return;
    };
    match name {
        "help" | "?" => {
            let mut rows: Vec<block::PanelRow> = commands::COMMANDS
                .iter()
                .map(|c| item("/", &format!("{} {}", c.name, c.args), c.help))
                .collect();
            rows.push(block::PanelRow::Note("keys: ↑↓ history · ←→/Ctrl-A/E/U/K/W edit · @file · !shell · Shift+Tab mode · Ctrl-C interrupt".into()));
            rows.push(block::PanelRow::Note(
                "while running: Enter steer · Tab queue · Ctrl-J newline · Alt-Up edit queued · Ctrl-End follow".into(),
            ));
            app.panel("?", "commands", rows);
        }
        "clear" => {
            app.transcript.clear();
            app.tool_index.clear();
            app.workflow_index.clear();
            app.cur_text.clear();
            app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
            app.cur_doc_revision = app.cur_text_revision;
            app.cur_doc = None;
            app.cur_think.clear();
            app.render_cache.clear();
            app.push(dim(), "transcript cleared");
        }
        "effort" => {
            if arg.is_empty() {
                open_picker(app, ag, directory, "effort"); // interactive picker (R7.a)
            } else if let Some(e) = core_protocol::Effort::parse(&arg) {
                if commit_effort(app, ag, e) {
                    app.push(fg(Color::Green), format!("effort set to {}", e.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown effort (low|medium|high|xhigh|max|ultracode)",
                );
            }
        }
        "model" => {
            if arg.is_empty() {
                open_picker(app, ag, directory, "model"); // interactive picker (R7.a)
            } else if arg == "retry" || arg.starts_with("retry ") {
                let value = arg.strip_prefix("retry").unwrap_or_default().trim();
                let selection =
                    match model_retry_selection(directory, &app.provider_id, &ag.model, value) {
                        Ok(selection) => selection,
                        Err(error) => {
                            app.note(
                                block::NoticeLevel::Err,
                                format!("cannot retry model: {error}"),
                            );
                            return;
                        }
                    };
                match directory.clear_model_unavailable_for_retry(&selection) {
                    Ok(true) => apply_model_selection(app, ag, directory, selection),
                    Ok(false) => app.note(
                        block::NoticeLevel::Warn,
                        "that model is not blocked; normal /model selection is unchanged",
                    ),
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("cannot retry model: {error}"),
                    ),
                }
            } else {
                match directory.resolve_model(&arg, Some(&app.provider_id)) {
                    Ok(selection) => apply_model_selection(app, ag, directory, selection),
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("cannot select model: {error}"),
                    ),
                }
            }
        }
        "theme" => {
            open_picker(app, ag, directory, "theme");
        }
        "status" => {
            let run = ag
                .rollout
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            let mut rows = vec![
                kv("provider", &app.provider_id),
                kv("model", &ag.model),
                kv("effort requested", ag.effort().label()),
            ];
            if let Some(application) = app.effort_application {
                rows.push(kv(
                    "effort applied",
                    &effort_application_detail(application),
                ));
            } else {
                rows.push(kv("effort applied", "not observed yet"));
            }
            rows.extend([
                kv("mode", ag.permission_mode().label()),
                kv("cwd", &ag.workspace.display().to_string()),
                kv("run", &run),
                block::PanelRow::Note(ag.ledger.summary()),
            ]);
            app.panel("≡", "status", rows);
        }
        "cost" => {
            app.panel(
                "$",
                "cost",
                vec![block::PanelRow::Note(ag.ledger.summary())],
            );
        }
        "context" => {
            let mut rows = Vec::new();
            if let Some(context) = app.last_context {
                rows.extend([
                    kv(
                        "request estimate",
                        &format!("≈{} tokens", fmt_token_count(context.total_tokens as u64)),
                    ),
                    kv(
                        "  system / tools",
                        &format!(
                            "≈{} / ≈{}",
                            fmt_token_count(context.system_tokens as u64),
                            fmt_token_count(context.tool_tokens as u64)
                        ),
                    ),
                    kv(
                        "  transcript / framing",
                        &format!(
                            "≈{} / ≈{}",
                            fmt_token_count(context.transcript_tokens as u64),
                            fmt_token_count(context.framing_tokens as u64)
                        ),
                    ),
                    block::PanelRow::Note(
                        "estimate: deterministic UTF-8 bytes/3.5 plus wire framing".into(),
                    ),
                ]);
            } else {
                rows.push(block::PanelRow::Note(
                    "no provider request has completed in this UI session yet".into(),
                ));
            }
            if let Some(usage) = app.last_turn_usage {
                let reported_input = request_input_tokens(usage);
                rows.extend([
                    kv(
                        "provider-reported input",
                        &format!("{} tokens", fmt_token_count(reported_input)),
                    ),
                    kv(
                        "  uncached / cache read / write",
                        &format!(
                            "{} / {} / {}",
                            fmt_token_count(usage.input),
                            fmt_token_count(usage.cache_read),
                            fmt_token_count(usage.cache_creation)
                        ),
                    ),
                    kv(
                        "output / thinking",
                        &format!(
                            "{} / {}",
                            fmt_token_count(usage.output),
                            fmt_token_count(usage.thinking)
                        ),
                    ),
                    kv(
                        "last-turn cache hit",
                        &format!("{:.0}%", usage.cache_hit_ratio() * 100.0),
                    ),
                ]);
            }
            match app.model_context_window.filter(|window| *window > 0) {
                Some(window) => {
                    let estimated_input = app
                        .last_context
                        .map(|context| context.total_tokens as u64)
                        .unwrap_or(0);
                    let reserve = u64::from(app.reserved_output_tokens.unwrap_or_default());
                    let admitted = estimated_input.saturating_add(reserve);
                    let remaining = window.saturating_sub(admitted);
                    let pct_left = remaining as f64 / window as f64 * 100.0;
                    rows.push(kv(
                        "model context window",
                        &format!(
                            "{} · {} admission headroom ({pct_left:.0}%)",
                            fmt_token_count(window),
                            fmt_token_count(remaining)
                        ),
                    ));
                    if app.last_context.is_some() {
                        rows.push(kv(
                            "reserved output",
                            &format!("{} tokens", fmt_token_count(reserve)),
                        ));
                    }
                }
                None => rows.push(kv(
                    "model context window",
                    "unknown (not proven for this exact route)",
                )),
            }
            rows.push(kv(
                "compaction trigger",
                &format!(
                    "{} tokens (policy threshold, not the model window)",
                    fmt_token_count(ag.compaction.trigger_tokens as u64)
                ),
            ));
            if let Some(application) = app.effort_application {
                rows.push(kv(
                    "effort applied",
                    &effort_application_detail(application),
                ));
            }
            app.panel("◔", "context — last provider turn", rows);
        }
        "mode" => {
            if arg.is_empty() {
                open_picker(app, ag, directory, "mode"); // interactive picker (Shift+Tab still cycles)
            } else if let Some(m) = PermissionMode::parse(&arg) {
                if commit_permission_mode(app, ag, m) {
                    app.push(fg(Color::Green), format!("mode set to {}", m.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown mode (default|acceptEdits|plan|yolo)",
                );
            }
        }
        "permissions" | "perms" => {
            let mut sub = arg.split_whitespace();
            match sub.next() {
                None => open_picker(app, ag, directory, "permissions"),
                Some("show" | "list") => {
                    let mut rows = vec![kv("mode", ag.permission_mode().label())];
                    let rules = ag.permission_rules().describe();
                    if rules.is_empty() {
                        rows.push(block::PanelRow::Note(
                            "no session rules (mode defaults apply)".into(),
                        ));
                    } else {
                        for r in rules {
                            rows.push(item("•", &r, ""));
                        }
                    }
                    app.panel("⚿", "permissions", rows);
                }
                Some(word) => {
                    let verdict = match word {
                        "allow" => Some(Verdict::Auto),
                        "ask" => Some(Verdict::Ask),
                        "deny" => Some(Verdict::Deny),
                        _ => None,
                    };
                    let cap = sub.next().and_then(parse_cap);
                    match (verdict, cap) {
                        (Some(v), Some(c)) => {
                            let verdict_label = match v {
                                Verdict::Auto => "allow",
                                Verdict::Ask => "ask",
                                Verdict::Deny => "deny",
                            };
                            if commit_permission_capability(app, ag, c, v) {
                                app.note(
                                    block::NoticeLevel::Ok,
                                    format!(
                                        "permission rule: {} → {verdict_label}",
                                        cap_label(c)
                                    ),
                                );
                            }
                        }
                        _ => app.push(fg(Color::Red), "usage: /permissions [allow|ask|deny <read_only|reversible_local|code_executing|trust_mutating|irreversible_external>]"),
                    }
                }
            }
        }
        "allow-code" | "allow_code" => match arg.as_str() {
            "on" | "true" | "" => {
                if commit_permission_capability(app, ag, Capability::CodeExecuting, Verdict::Auto) {
                    app.push(
                        fg(Color::Yellow),
                        "code execution ALLOWED (egress-off sandbox)",
                    );
                }
            }
            "off" | "false" => {
                if commit_permission_capability(app, ag, Capability::CodeExecuting, Verdict::Ask) {
                    app.push(fg(Color::Yellow), "code execution now asks per call");
                }
            }
            _ => app.push(fg(Color::Red), "usage: /allow-code on|off"),
        },
        "memory" | "mem" => {
            let ws = ag.memory_workspace.clone();
            let Some(ws) = ws else {
                app.push(fg(Color::Red), "memory not available");
                return;
            };
            let store = core_ctx::MemoryStore::at(&ws);
            let mut sub = arg.split_whitespace();
            match sub.next() {
                Some("add") => {
                    let text = arg.strip_prefix("add").unwrap_or("").trim().to_string();
                    if text.is_empty() {
                        app.push(fg(Color::Red), "usage: /memory add <fact>");
                    } else {
                        match store.add(&text) {
                            Ok(id) => app.push(
                                fg(Color::Green),
                                format!("remembered ({id}) — applies next turn"),
                            ),
                            Err(e) => app.push(fg(Color::Red), format!("memory add failed: {e}")),
                        }
                    }
                }
                Some("list") | None => {
                    let facts = store.load();
                    if facts.is_empty() {
                        app.note(
                            block::NoticeLevel::Info,
                            "no memory yet — /memory add <fact>",
                        );
                    } else {
                        let rows = facts
                            .iter()
                            .map(|f| {
                                item(
                                    "◆",
                                    f.text.lines().next().unwrap_or(""),
                                    &format!("[{}]", f.id),
                                )
                            })
                            .collect();
                        app.panel("◆", &block::plural(facts.len(), "remembered fact"), rows);
                    }
                }
                Some("forget") | Some("rm") => {
                    let id = sub.next().unwrap_or("");
                    if store.remove(id) {
                        app.push(fg(Color::Green), format!("forgot {id}"));
                    } else {
                        app.push(fg(Color::Red), format!("no memory {id}"));
                    }
                }
                Some(x) => app.push(
                    fg(Color::Red),
                    format!("unknown /memory subcommand `{x}` (add|list|forget)"),
                ),
            }
        }
        "diff" => {
            // Reuse the same absolute-executable, filter-disabled, process-group-bounded runner as
            // the registry tool. This operator command is still awaiting the universal effect WAL.
            let stat = arg.trim() == "stat";
            match core_tools::git_diff_observation(&ag.workspace, stat, None).await {
                Ok(output) => {
                    // Scrub before semantic parsing/rendering; newlines are preserved.
                    let text = core_record::redact::scrub(&output);
                    if text.trim().is_empty() || text.trim() == "(no uncommitted changes)" {
                        app.note(
                            block::NoticeLevel::Info,
                            "no uncommitted changes (try /diff stat for a summary)",
                        );
                    } else if stat {
                        // --stat is a SUMMARY, not a unified diff — render as a Panel, not a Diff card.
                        let rows = text
                            .lines()
                            .take(120)
                            .map(|l| block::PanelRow::Note(l.to_string()))
                            .collect();
                        app.panel("±", "diff --stat", rows);
                    } else {
                        let diffs = core_protocol::FileDiff::from_unified(&text);
                        if diffs.is_empty() {
                            app.note(block::NoticeLevel::Info, "no parseable diff");
                        } else {
                            for d in diffs {
                                app.push_block(block::BlockKind::Diff(d));
                            }
                        }
                    }
                }
                Err(error) => app.push(
                    fg(Color::Red),
                    format!("could not read bounded Git diff: {error}"),
                ),
            }
        }
        "sessions" => {
            open_session_picker(app, ag);
        }
        "workflows" | "tasks" => {
            let mut rows = Vec::new();
            for card in app.transcript.iter().rev().filter_map(|entry| {
                if let block::BlockKind::Workflow(card) = &entry.kind {
                    Some(card)
                } else {
                    None
                }
            }) {
                let settled = card
                    .tasks
                    .iter()
                    .filter(|task| {
                        matches!(
                            task.status,
                            block::WorkflowTaskStatus::Done
                                | block::WorkflowTaskStatus::Failed
                                | block::WorkflowTaskStatus::Interrupted
                                | block::WorkflowTaskStatus::SkippedBudget
                                | block::WorkflowTaskStatus::NotStarted
                                | block::WorkflowTaskStatus::Unknown
                        )
                    })
                    .count();
                let progress = if card.tasks.is_empty() {
                    card.class.clone()
                } else {
                    format!("{settled}/{} investigators", card.tasks.len())
                };
                rows.push(block::PanelRow::Item {
                    label: format!(
                        "{} · {}",
                        card.name,
                        block::workflow_status_label(card.status)
                    ),
                    hint: format!("{} · {}", card.run_id, progress),
                });
            }
            if rows.is_empty() {
                rows.push(block::PanelRow::Note(
                    "no workflow has run in this transcript".into(),
                ));
            }
            app.panel("", "workflows", rows);
        }
        "fork" => {
            // Fork the CURRENT session at its tail into a new branch (shared past, divergent future).
            let path = ag.rollout.path().to_path_buf();
            let runs = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            match core_record::replay(&path) {
                Ok(events) if !events.is_empty() => {
                    let at = events.last().map(|e| e.seq).unwrap();
                    match core_record::fork(
                        &runs,
                        &core_protocol::RunId(stem),
                        at,
                        &core_protocol::TenantId::default(),
                    ) {
                        Ok(child) => app.push(
                            fg(Color::Green),
                            format!("forked -> {child} (resume with: core --resume {child})"),
                        ),
                        Err(e) => app.push(fg(Color::Red), format!("fork failed: {e}")),
                    }
                }
                Ok(_) => app.push(fg(Color::Red), "nothing to fork yet"),
                Err(e) => app.push(fg(Color::Red), format!("cannot read this session: {e}")),
            }
        }
        "agents" => {
            let user = std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".core").join("agents"))
                .unwrap_or_default();
            let catalog = core_agents::AgentCatalog::discover(&user, &ag.workspace);
            let defs = catalog.defs();
            let mut rows: Vec<block::PanelRow> = defs
                .iter()
                .map(|d| item("⑂", &d.name, &d.description))
                .collect();
            if rows.is_empty() {
                rows.push(block::PanelRow::Note(
                    "no agent definitions (built-in `investigator` is always available)".into(),
                ));
            }
            for e in catalog.errors() {
                rows.push(block::PanelRow::Note(format!(
                    "rejected: {} ({})",
                    e.source, e.reason
                )));
            }
            app.panel("⑂", "agents", rows);
        }
        "skills" => {
            let user = core_ctx::skills::user_skills_dir().unwrap_or_default();
            let cat = core_ctx::skills::SkillCatalog::discover(&user, &ag.workspace);
            let mut rows: Vec<block::PanelRow> = cat
                .defs()
                .iter()
                .map(|s| item("◇", &s.name, &s.description))
                .collect();
            if rows.is_empty() {
                rows.push(block::PanelRow::Note(
                    "no skills (add <repo>/.core/skills/<name>/SKILL.md)".into(),
                ));
            }
            for e in cat.errors() {
                rows.push(block::PanelRow::Note(format!(
                    "rejected: {} ({})",
                    e.source, e.reason
                )));
            }
            app.panel("◇", "skills", rows);
        }
        "config" => {
            let mut rows = vec![
                kv(
                    "provider",
                    if app.provider_id.is_empty() {
                        "(unresolved)"
                    } else {
                        &app.provider_id
                    },
                ),
                kv("model", &ag.model),
                kv("effort", ag.effort().label()),
                kv("mode", ag.permission_mode().label()),
            ];
            match crate::config::FileConfig::load(&ag.workspace) {
                Ok(f) => {
                    // human values, never raw Option Debug (`Some(5.0)`/`None` in a panel is a toy tell)
                    let mt = f
                        .max_turns
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "default".into());
                    let mu = f
                        .max_usd
                        .map(|v| format!("${v:.2}"))
                        .unwrap_or_else(|| "none".into());
                    rows.push(kv("max_turns", &mt));
                    rows.push(kv("max_usd", &mu));
                }
                Err(e) => rows.push(block::PanelRow::Note(format!("config load failed: {e}"))),
            }
            app.panel("⚙", "config", rows);
        }
        "tools" => {
            // Visualize every tool + its capability tier + purity (user: tool 所有能的可视化).
            let cap_glyph = |c: Capability| match c {
                Capability::ReadOnly => "read-only",
                Capability::ReversibleLocal => "edits (reversible)",
                Capability::CodeExecuting => "runs code",
                Capability::TrustMutating => "trust-mutating",
                Capability::IrreversibleExternal => "external/egress",
            };
            let mut specs = ag.registry.specs();
            specs.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: Vec<block::PanelRow> = specs
                .iter()
                .map(|s| block::PanelRow::Item {
                    label: format!("{}  [{}]", s.name, cap_glyph(s.capability)),
                    hint: core_protocol::text::head(&s.description, 70),
                })
                .collect();
            app.panel("⚙", &format!("{} tools available", rows.len()), rows);
        }
        "mcp" => {
            let mcp: Vec<_> = ag
                .registry
                .specs()
                .into_iter()
                .filter(|s| s.name.contains("__"))
                .collect();
            if mcp.is_empty() {
                app.note(
                    block::NoticeLevel::Info,
                    "no MCP tools connected (configure servers in ~/.core/config.json)",
                );
            } else {
                let rows = mcp
                    .iter()
                    .map(|s| item("◈", &s.name, &core_protocol::text::head(&s.description, 80)))
                    .collect();
                app.panel("◈", "MCP tools", rows);
            }
        }
        "hooks" => {
            let home = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            let hooks = core_kernel::hooks::Hooks::load_user(&home);
            if hooks.is_empty() {
                app.note(
                    block::NoticeLevel::Info,
                    "no lifecycle hooks (add a \"hooks\" block to ~/.core/config.json)",
                );
            } else {
                app.note(
                    block::NoticeLevel::Ok,
                    "lifecycle hooks loaded from ~/.core/config.json (user config)",
                );
            }
        }
        "export" => {
            let requested = if arg.trim().is_empty() {
                "core-transcript.md"
            } else {
                arg.trim()
            };
            let path = match confined_workspace_output(&ag.workspace, requested) {
                Ok(path) => path,
                Err(error) => {
                    app.push(fg(Color::Red), format!("export refused: {error}"));
                    return;
                }
            };
            let mut body = String::from("# Core Code transcript\n\n");
            for b in &app.transcript {
                body.push_str(&b.to_text());
                body.push('\n');
            }
            match atomic_replace(&path, body.as_bytes()) {
                Ok(_) => app.push(
                    fg(Color::Green),
                    format!("exported transcript -> {}", path.display()),
                ),
                Err(e) => app.push(fg(Color::Red), format!("export failed: {e}")),
            }
        }
        "init" => {
            let dir = match ensure_real_workspace_dir(&ag.workspace, ".core") {
                Ok(dir) => dir,
                Err(error) => {
                    app.push(fg(Color::Red), format!("init refused: {error}"));
                    return;
                }
            };
            let cfg = dir.join("config.json");
            if cfg.exists() {
                app.push(
                    dim(),
                    format!("{} already exists — not overwritten", cfg.display()),
                );
            } else {
                // Repository config can only choose a bare model and tighten ceilings. Provider,
                // MCP, hooks, effort, and grants belong in trusted ~/.core/config.json.
                let starter =
                    "{\n  \"model\": null,\n  \"max_turns\": 40,\n  \"allow_code\": false\n}\n";
                match write_new_synced(&cfg, starter.as_bytes()) {
                    Ok(_) => app.push(fg(Color::Green), format!("wrote {}", cfg.display())),
                    Err(e) => app.push(fg(Color::Red), format!("init failed: {e}")),
                }
            }
            let agents_md = ag.workspace.join("AGENTS.md");
            if !agents_md.exists() {
                match write_new_synced(
                    &agents_md,
                    b"# Project instructions for coding agents\n\n- (describe build/test commands, conventions, and gotchas here)\n",
                ) {
                    Ok(()) => app.push(
                        fg(Color::Green),
                        format!("wrote {}", agents_md.display()),
                    ),
                    Err(error) => {
                        app.push(fg(Color::Red), format!("init failed: {error}"));
                    }
                }
            }
        }
        "rewind" => {
            // Conversation rewind: branch at an EARLIER seq (shared past, divergent future). With no
            // arg it lists the turn boundaries; `/rewind <seq>` forks at that point. (Workspace-file
            // rewind needs recorded checkpoints, which normal runs don't yet emit — honest gap.)
            let path = ag.rollout.path().to_path_buf();
            let runs = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            match core_record::replay(&path) {
                Ok(events) if !events.is_empty() => {
                    let tail = events.last().map(|e| e.seq.0).unwrap();
                    if let Ok(seq) = arg.trim().parse::<u64>() {
                        let at = core_protocol::Seq(seq.min(tail));
                        match core_record::fork(&runs, &core_protocol::RunId(stem), at, &core_protocol::TenantId::default()) {
                            Ok(child) => app.push(fg(Color::Green), format!("rewound to seq {} -> {child} (resume with: core --resume {child})", at.0)),
                            Err(e) => app.push(fg(Color::Red), format!("rewind failed: {e}")),
                        }
                    } else {
                        let mut rows = vec![block::PanelRow::Note(format!(
                            "usage: /rewind <seq>  (0..{tail})"
                        ))];
                        for e in events
                            .iter()
                            .filter(|e| matches!(e.kind, core_protocol::EventKind::TurnStart))
                            .rev()
                            .take(20)
                        {
                            rows.push(item(
                                "•",
                                &format!("seq {}", e.seq.0),
                                &format!("turn {}", e.turn.0),
                            ));
                        }
                        app.panel("↩", "rewind — turn boundaries", rows);
                    }
                }
                Ok(_) => app.push(fg(Color::Red), "nothing to rewind yet"),
                Err(e) => app.push(fg(Color::Red), format!("cannot read this session: {e}")),
            }
        }
        "resume" => {
            if arg.is_empty() {
                open_session_picker(app, ag);
            } else {
                let runs = ag
                    .rollout
                    .path()
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                let exists = core_record::list(&runs, &core_protocol::TenantId::default())
                    .iter()
                    .any(|session| session.run_id.0 == arg);
                if exists {
                    app.prepare_resume_handoff(&arg);
                } else {
                    app.note(
                        block::NoticeLevel::Err,
                        format!("no recorded session with run id `{}`", ui_safe_text(&arg)),
                    );
                }
            }
        }
        "quit" | "exit" => app.quit = true,
        other => app.push(
            fg(Color::Red),
            format!("unknown command /{other} (try /help)"),
        ),
    }
}

fn apply_event(app: &mut App, ev: UiEvent) {
    match ev {
        UiEvent::Text(t) => app.stream_text(&t),
        UiEvent::Thinking(t) => app.stream_think(&t),
        UiEvent::ToolStart { id, name, args } => app.tool_start(id, name, args),
        UiEvent::ToolEnd {
            id,
            ok,
            exit_code,
            output,
            diff,
        } => app.tool_end(&id, ok, exit_code, output, diff),
        UiEvent::Phase(p) => app.status = p.label().into(),
        UiEvent::TurnEnd {
            cost,
            usage,
            context,
            model_context_window,
            reserved_output_tokens,
            compaction_trigger_tokens,
            effort,
        } => {
            // A provider turn is a semantic token boundary. Release the last held word only after
            // scrubbing the complete token; keep it in the live block until Done/tool framing.
            if let Some(pending) = app.text_scrubber.finish() {
                app.cur_text.push_str(&ui_safe_text(&pending));
                app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
            }
            if let Some(pending) = app.thinking_scrubber.finish() {
                app.cur_think.push_str(&ui_safe_text(&pending));
            }
            app.cost = cost;
            app.last_turn_usage = Some(usage);
            app.last_context = Some(context);
            app.model_context_window = model_context_window;
            app.reserved_output_tokens = Some(reserved_output_tokens);
            app.compaction_trigger_tokens = compaction_trigger_tokens;
            app.effort_application = Some(effort);
            app.turns = app.turns.saturating_add(1);
            app.status = "running…".into();
        }
        UiEvent::Workflow(event) => app.workflow_event(event),
        UiEvent::SteerApplied { count } => {
            for _ in 0..count {
                let _ = app.steer_previews.pop_front();
            }
        }
        UiEvent::Notice(n) => {
            app.push_block(block::BlockKind::Notice {
                level: block::NoticeLevel::Info,
                text: n,
            });
        }
        UiEvent::ApprovalRequest {
            id,
            tool,
            capability,
            reason,
            arguments,
            workspace,
        } => {
            app.flush_text();
            app.status = "approval required".into();
            app.approval_choice = ApprovalChoice::Deny;
            app.pending = Some(Pending {
                id,
                tool,
                cap: capability,
                reason,
                arguments: ui_safe_json(&arguments),
                workspace: ui_safe_text(&workspace),
            });
        }
        UiEvent::Done(o) => {
            app.flush_text(); // finalize any in-flight answer/reasoning into blocks
            let _ = o; // the reclaimed run publishes the human outcome in the active shelf
        }
    }
}

use block::SPINNER;

/// `m:ss` elapsed for the active shelf. `73s` → `1:13`.
fn fmt_mmss(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

/// Pad a run of spans with a trailing filler so the row fills `width` cells; when `bg` is Some the
/// filler carries that background, extending a selection bar edge-to-edge (TUI v3 §9 — the selection
/// is ONE full-width inverted bar).
fn pad_line_to(spans: &mut Vec<Span<'static>>, width: u16, fill: Style) {
    let w: u16 = spans
        .iter()
        .flat_map(|s| s.content.chars())
        .map(char_width)
        .fold(0u16, |a, x| a.saturating_add(x));
    if w < width {
        spans.push(Span::styled(" ".repeat((width - w) as usize), fill));
    }
}

/// One row of a list popup: a `lead` label (accent when `lead_accent`, else fg) and a dim `aux` tail
/// (description / hint / "(current)"). The completion menu and the selection picker are both built from
/// these — ONE component (TUI v3 §9), so width, height, border, nav and the selection bar can't drift.
struct PopupRow {
    lead: String,
    lead_accent: bool,
    aux: String,
    enabled: bool,
}

/// A modal must never own the keyboard while being completely invisible. When a terminal cannot
/// spare the three rows or columns required for a bordered menu, render a one/two-line selection
/// strip over the available frame. Detail yields, but focus and the escape route remain visible.
fn render_compact_popup(
    f: &mut Frame,
    anchor: Rect,
    title: &str,
    rows: &[PopupRow],
    sel: usize,
    theme: &theme::Theme,
    width: u16,
) {
    let frame = f.area();
    let height = frame.height.min(2);
    if width == 0 || height == 0 {
        return;
    }
    let x = anchor
        .x
        .min(frame.right().saturating_sub(width))
        .max(frame.x);
    let max_y = frame.bottom().saturating_sub(height);
    let y = anchor.y.saturating_sub(height).clamp(frame.y, max_y);
    let area = Rect::new(x, y, width, height).intersection(frame);
    if area.width == 0 || area.height == 0 {
        return;
    }

    let mut lines = Vec::new();
    if area.height == 2 {
        lines.push(Line::from(Span::styled(
            clip_text(&format!("{title} · enter/esc"), area.width),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
    }
    let row = rows.get(sel);
    let enabled = row.is_some_and(|row| row.enabled);
    let selection = if theme.mono || !enabled {
        Style::default()
            .fg(if enabled { theme.fg } else { theme.muted })
            .add_modifier(Modifier::REVERSED)
    } else {
        Style::default().fg(theme.on_accent).bg(theme.accent)
    };
    let label = row
        .map(|row| format!("› {}", row.lead))
        .unwrap_or_else(|| "no matches · esc".into());
    let mut spans = vec![Span::styled(clip_text(&label, area.width), selection)];
    pad_line_to(&mut spans, area.width, selection);
    lines.push(Line::from(spans));

    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(Paragraph::new(lines), area);
}

/// The ONE list-popup renderer (TUI v3 §9): the completion menu AND the picker both call this, so they
/// share a plain terminal border, responsive width, visible-height budget, windowing, title
/// grammar, and — critically — the selection bar. Selection = a SINGLE full-width inverted bar:
/// `fg(on_accent).bg(accent)` in color, `REVERSED` under mono (so NO_COLOR, where accent==Reset, still
/// shows the bar; and no raw `Color::Black` — review R3/R4). Left-aligned above `anchor`, always
/// clamped to the frame so a short terminal can't panic ratatui's `Clear` (round-3 review).
fn render_list_popup(
    f: &mut Frame,
    anchor: Rect,
    title: &str,
    rows: &[PopupRow],
    sel: usize,
    query: Option<&str>,
    theme: &theme::Theme,
) {
    let frame = f.area();
    let total = rows.len();
    let w = match surface::Density::for_width(anchor.width) {
        surface::Density::Compact => anchor.width,
        surface::Density::Standard => anchor.width.min(72),
        surface::Density::Wide => anchor.width.min(88),
    }
    .min(frame.width);
    if w == 0 {
        return;
    }
    let bar_w = w.saturating_sub(2); // inside the border
    let max_h = anchor.y.saturating_sub(frame.y).min(frame.height).min(14);
    if w < 3 || max_h < 3 {
        render_compact_popup(f, anchor, title, rows, sel, theme, w);
        return;
    }
    let selected_detail = rows.get(sel).map(|row| row.aux.trim()).unwrap_or("");
    let inner_h = max_h.saturating_sub(2);
    let query_h = u16::from(query.is_some() && inner_h >= 3);
    // The footer owns the interaction legend; the border title carries identity only. Reserve one
    // navigable row before selected detail so a short popup remains an actionable control.
    let footer_h = u16::from(inner_h.saturating_sub(query_h) >= 2);
    let min_list_h = u16::try_from(total.clamp(1, 2))
        .unwrap_or(2)
        .min(inner_h.saturating_sub(query_h).saturating_sub(footer_h));
    let detail_budget = if max_h >= 6 {
        inner_h
            .saturating_sub(query_h)
            .saturating_sub(footer_h)
            .saturating_sub(min_list_h)
            .min(3)
    } else {
        0
    };
    let detail_lines = popup_detail_lines(
        selected_detail,
        bar_w,
        detail_budget as usize,
        Style::default().fg(theme.muted),
    );
    let detail_h = u16::try_from(detail_lines.len()).unwrap_or(detail_budget);
    let vis = (inner_h
        .saturating_sub(query_h)
        .saturating_sub(footer_h)
        .saturating_sub(detail_h) as usize)
        .clamp(1, 10);
    let start = if total == 0 {
        0
    } else {
        sel.saturating_sub(vis.saturating_sub(1))
            .min(total.saturating_sub(vis))
    };
    // The selection bar style (mono-safe): one signal, edge-to-edge.
    let sel_style = if theme.mono {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default().fg(theme.on_accent).bg(theme.accent)
    };
    // Disabled rows remain focusable so the operator can read why a model is unavailable. Keep
    // their text muted even while focused, with reversal as the independent selection signal.
    let disabled_sel_style = Style::default()
        .fg(theme.muted)
        .add_modifier(Modifier::REVERSED);
    let mut visible: Vec<Line> = Vec::new();
    if query_h > 0 {
        let query = query.unwrap_or_default();
        let value = if query.is_empty() {
            "type to filter".to_string()
        } else {
            query.to_string()
        };
        visible.push(Line::from(vec![
            Span::styled(" search  ", Style::default().fg(theme.muted)),
            Span::styled(
                clip_text(&value, bar_w.saturating_sub(9)),
                Style::default().fg(theme.fg),
            ),
        ]));
    }
    if total == 0 {
        let message = query
            .filter(|query| !query.is_empty())
            .map(|query| {
                format!(
                    "No matches for “{}”",
                    clip_text(query, bar_w.saturating_sub(18))
                )
            })
            .unwrap_or_else(|| "No selectable items".into());
        visible.push(Line::from(Span::styled(
            clip_text(&message, bar_w),
            Style::default().fg(theme.muted),
        )));
    }
    visible.extend(rows.iter().enumerate().skip(start).take(vis).map(|(i, r)| {
        let selected = i == sel;
        let (lead_style, aux_style) = if selected {
            let selected_style = if r.enabled {
                sel_style
            } else {
                disabled_sel_style
            };
            (selected_style, selected_style)
        } else if !r.enabled {
            (
                Style::default().fg(theme.muted),
                Style::default().fg(theme.faint),
            )
        } else {
            let lead = if r.lead_accent {
                theme.accent
            } else {
                theme.fg
            };
            (Style::default().fg(lead), Style::default().fg(theme.muted))
        };
        let aux_gap = u16::from(!r.aux.is_empty()) * 2;
        let lead_budget = if r.aux.is_empty() {
            bar_w
        } else {
            bar_w.saturating_mul(3) / 5
        };
        let lead = clip_text(&r.lead, lead_budget);
        let mut sp = vec![Span::styled(lead.clone(), lead_style)];
        if !r.aux.is_empty() && text_width(&lead).saturating_add(aux_gap) < bar_w {
            let aux_w = bar_w
                .saturating_sub(text_width(&lead))
                .saturating_sub(aux_gap);
            sp.push(Span::styled(
                format!("  {}", clip_text(&r.aux, aux_w)),
                aux_style,
            ));
        }
        pad_line_to(
            &mut sp,
            bar_w,
            if selected {
                if r.enabled {
                    sel_style
                } else {
                    disabled_sel_style
                }
            } else {
                Style::default()
            },
        );
        Line::from(sp)
    }));
    visible.extend(detail_lines);
    if footer_h > 0 {
        let footer_text = if total == 0 {
            " no matches · type to search · backspace edit · esc clear".to_string()
        } else if query.is_some() {
            format!(
                " {}/{}  type filter · ↑↓ navigate · enter select · esc clear/close",
                sel + 1,
                total
            )
        } else {
            format!(
                " {}/{}  ↑↓ navigate · enter select · esc close",
                sel + 1,
                total
            )
        };
        let footer = clip_text(&footer_text, bar_w);
        visible.push(Line::from(Span::styled(
            footer,
            Style::default().fg(theme.muted),
        )));
    }
    let n = visible.len() as u16;
    let h = (n + 2).min(max_h);
    let y = anchor.y.saturating_sub(h);
    let area = Rect {
        x: anchor.x.min(frame.right().saturating_sub(w)),
        y,
        width: w,
        height: h,
    }
    .intersection(frame);
    if area.height < 3 || area.width < 3 {
        return;
    }
    let full = clip_text(&format!(" {title} "), w.saturating_sub(4));
    let popup = Paragraph::new(visible).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme.accent))
            .title(full),
    );
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(popup, area);
}

/// Wrap a selected row's full auxiliary detail by terminal cells. `max_rows` is a layout budget,
/// not a fixed one-line clip; if the detail still exceeds that budget, the final visible row gets a
/// truthful ellipsis. The popup retains at least one (normally two) navigable list rows above it.
fn popup_detail_lines(
    detail: &str,
    width: u16,
    max_rows: usize,
    style: Style,
) -> Vec<Line<'static>> {
    if detail.is_empty() || width == 0 || max_rows == 0 {
        return Vec::new();
    }
    let mut rows = crate::render::wrap_spans(&[Span::styled(detail.to_string(), style)], width);
    if rows.len() <= max_rows {
        return rows;
    }
    rows.truncate(max_rows);
    if let Some(last) = rows.last_mut() {
        let text = last
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        let visible = clip_text(&text, width.saturating_sub(1));
        *last = Line::from(Span::styled(format!("{visible}…"), style));
    }
    rows
}

fn text_width(text: &str) -> u16 {
    text.chars().map(char_width).fold(0u16, u16::saturating_add)
}

fn spans_width(spans: &[Span<'_>]) -> u16 {
    spans
        .iter()
        .map(|span| text_width(span.content.as_ref()))
        .fold(0u16, u16::saturating_add)
}

fn clip_text(text: &str, width: u16) -> String {
    if text_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".into();
    }
    let budget = width - 1;
    let mut used = 0u16;
    let mut out = String::new();
    for ch in text.chars() {
        let cw = char_width(ch);
        if used.saturating_add(cw) > budget {
            break;
        }
        out.push(ch);
        used = used.saturating_add(cw);
    }
    out.push('…');
    out
}

fn one_line_preview(text: &str, width: u16) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    clip_text(&collapsed, width)
}

fn render_lr_line(f: &mut Frame, area: Rect, left: Vec<Span<'static>>, right: Vec<Span<'static>>) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let left_w = spans_width(&left);
    let right_w = spans_width(&right);
    let gap = area.width.saturating_sub(left_w.saturating_add(right_w));
    let mut spans = left;
    if gap > 0 {
        spans.push(Span::raw(" ".repeat(gap as usize)));
    }
    spans.extend(right);
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn status_right_bits(app: &App, density: surface::Density) -> Vec<String> {
    let mut bits = Vec::new();
    // Economics is drill-down information and the first metadata dropped under pressure. Keep it
    // off the standard surface; `/cost` remains the authoritative full-run view.
    if density == surface::Density::Wide
        && let Some(cost_usd) = app.cost.usd().filter(|value| *value > 0.0)
    {
        bits.push(format!("${cost_usd:.2}"));
    }
    if density == surface::Density::Wide && app.turns > 0 {
        bits.push(format!("turn {}", app.turns));
    }
    if density != surface::Density::Compact
        && let Some(usage) = app.last_turn_usage
    {
        bits.push(format!("cache {:.0}%", usage.cache_hit_ratio() * 100.0));
        let used = app
            .last_context
            .map(|context| context.total_tokens as u64)
            .unwrap_or_else(|| request_input_tokens(usage));
        if let Some(window) = app.model_context_window.filter(|window| *window > 0) {
            let admitted =
                used.saturating_add(u64::from(app.reserved_output_tokens.unwrap_or_default()));
            let left = window.saturating_sub(admitted) as f64 / window as f64 * 100.0;
            bits.push(format!("context {left:.0}% left"));
        } else {
            bits.push(format!("context {} used", fmt_token_count(used)));
        }
    }
    if app.mode != PermissionMode::Default {
        bits.push(app.mode.label().to_string());
    }
    let pending = app.steer_previews.len().saturating_add(app.queued.len());
    if pending > 0 {
        bits.push(format!("{pending} pending"));
    }
    // Route and effective effort are one high-priority identity unit. Keeping them last means the
    // progressive truncation loop drops economics/context first and never leaves a naked model with
    // a hidden effort level.
    let route = route_label(app);
    let effort = effort_status_label(app);
    if route.is_empty() {
        bits.push(effort);
    } else {
        bits.push(format!("{route} │ {effort}"));
    }
    bits
}

fn render_status(f: &mut Frame, area: Rect, density: surface::Density, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let th = &app.theme;
    let muted = Style::default().fg(th.muted);
    let accent = Style::default().fg(th.accent).add_modifier(Modifier::BOLD);
    let warn = Style::default().fg(th.warn).add_modifier(Modifier::BOLD);

    let mut left = if app.pending.is_some() {
        vec![
            Span::styled("! ", warn),
            Span::styled("approval required", warn),
        ]
    } else if app.interrupting {
        vec![
            Span::styled("! ", warn),
            Span::styled("interrupt requested · stopping at a safe point", warn),
        ]
    } else if !app.follow_tail {
        let unread = if app.unread_updates == 0 {
            String::new()
        } else {
            " · new output".to_string()
        };
        vec![Span::styled(
            format!("↑ reading history{unread} · ctrl+end to follow"),
            Style::default().fg(th.warn),
        )]
    } else if app.running {
        let phase = match app.status.trim() {
            "" | "running…" => "working",
            other => other,
        };
        let mut spans = vec![
            Span::styled(format!("{} ", SPINNER[app.spin % SPINNER.len()]), accent),
            Span::styled(phase.to_string(), accent),
        ];
        if let Some((_, activity)) = app.active_tools.back() {
            let activity = clip_text(activity, (area.width / 3).max(12));
            spans.push(Span::styled(format!(" · {activity}"), muted));
            if app.active_tools.len() > 1 {
                spans.push(Span::styled(
                    format!(" +{}", app.active_tools.len() - 1),
                    muted,
                ));
            }
        }
        if let Some(started) = app.run_started {
            spans.push(Span::styled(
                format!(" · {}", fmt_mmss(started.elapsed())),
                muted,
            ));
        }
        spans
    } else {
        vec![Span::styled(
            if app.status.trim().is_empty() || app.status.trim() == "idle" {
                "ready".to_string()
            } else {
                app.status.clone()
            },
            muted,
        )]
    };

    // Right-side metadata is progressively disclosed. When it does not fit, low-priority economics
    // disappear first; the route/pending state at the end survives and is clipped explicitly.
    let mut bits = status_right_bits(app, density);
    let left_budget = if bits.is_empty() {
        area.width
    } else {
        area.width.saturating_mul(2) / 3
    };
    if spans_width(&left) > left_budget {
        let summary = left
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        left = vec![Span::styled(clip_text(&summary, left_budget), accent)];
    }
    let left_w = spans_width(&left);
    let available = area.width.saturating_sub(left_w.saturating_add(2));
    while bits.len() > 1 && text_width(&bits.join(" │ ")) > available {
        bits.remove(0);
    }
    let right_text = clip_text(&bits.join(" │ "), available);
    let right = if right_text.is_empty() {
        Vec::new()
    } else {
        vec![Span::styled(right_text, muted)]
    };
    render_lr_line(f, area, left, right);
}

fn render_pending_lanes(f: &mut Frame, area: Rect, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    let label_w = if area.width >= 72 { 19 } else { 9 };
    if let Some(input) = app.steer_previews.front() {
        let label = if area.width >= 72 {
            "  next safe point  "
        } else {
            "  steer  "
        };
        let suffix = app
            .steer_previews
            .len()
            .checked_sub(1)
            .filter(|count| *count > 0)
            .map(|count| format!("  +{count}"))
            .unwrap_or_default();
        let preview_w = area
            .width
            .saturating_sub(label_w)
            .saturating_sub(text_width(&suffix));
        lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(app.theme.accent)),
            Span::styled(
                one_line_preview(&ui_safe_text(&input.text), preview_w),
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(suffix, Style::default().fg(app.theme.muted)),
        ]));
    }
    if let Some(input) = app.queued.front() {
        let label = if area.width >= 72 {
            "  after this turn  "
        } else {
            "  queued "
        };
        let suffix = app
            .queued
            .len()
            .checked_sub(1)
            .filter(|count| *count > 0)
            .map(|count| format!("  +{count}"))
            .unwrap_or_default();
        let preview_w = area
            .width
            .saturating_sub(label_w)
            .saturating_sub(text_width(&suffix));
        lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(app.theme.muted)),
            Span::styled(
                one_line_preview(&ui_safe_text(&input.text), preview_w),
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(suffix, Style::default().fg(app.theme.muted)),
        ]));
    }
    lines.truncate(area.height as usize);
    f.render_widget(Paragraph::new(lines), area);
}

fn approval_action_line(app: &App, pending: &Pending, width: u16) -> Line<'static> {
    let rememberable = capability_can_be_remembered(pending.cap);
    let choices: Vec<(ApprovalChoice, String)> = if width >= 60 {
        let mut choices = vec![(ApprovalChoice::Once, "[y] Allow once".into())];
        if rememberable {
            choices.push((
                ApprovalChoice::Session,
                format!("[a] Allow {} this session", cap_label(pending.cap)),
            ));
        }
        choices.push((ApprovalChoice::Deny, "[n] Deny".into()));
        choices
    } else if width >= 24 {
        let mut choices = vec![(ApprovalChoice::Once, "[y] once".into())];
        if rememberable {
            choices.push((ApprovalChoice::Session, "[a] session".into()));
        }
        choices.push((ApprovalChoice::Deny, "[n] deny".into()));
        choices
    } else {
        let mut choices = vec![(ApprovalChoice::Once, "[y]".into())];
        if rememberable {
            choices.push((ApprovalChoice::Session, "[a]".into()));
        }
        choices.push((ApprovalChoice::Deny, "[n]".into()));
        choices
    };
    let choice_style = |choice: ApprovalChoice| {
        let selected = app.approval_choice == choice;
        if selected && app.theme.mono {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else if selected {
            Style::default()
                .fg(app.theme.on_accent)
                .bg(app.theme.accent)
                .add_modifier(Modifier::BOLD)
        } else if choice == ApprovalChoice::Deny {
            Style::default().fg(app.theme.error)
        } else {
            Style::default().fg(app.theme.fg)
        }
    };
    let separator = if width < 24 { " " } else { "  " };
    let required = choices
        .iter()
        .map(|(_, label)| text_width(label))
        .fold(0u16, u16::saturating_add)
        .saturating_add(
            text_width(separator)
                .saturating_mul(u16::try_from(choices.len().saturating_sub(1)).unwrap_or(u16::MAX)),
        );
    if required > width
        && let Some((choice, label)) = choices
            .iter()
            .find(|(choice, _)| *choice == app.approval_choice)
    {
        // This is an intentional one-slot pager, not a reordered button row: arrow navigation changes
        // the focused label in place, while the canonical y → a → n order returns as soon as it fits.
        let mut spans = vec![Span::styled(label.clone(), choice_style(*choice))];
        let remaining = width.saturating_sub(text_width(label));
        if remaining >= 3 {
            spans.push(Span::styled(" <>", Style::default().fg(app.theme.muted)));
        }
        return Line::from(spans);
    }
    let mut spans = Vec::new();
    for (index, (choice, label)) in choices.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                separator,
                Style::default().fg(app.theme.faint),
            ));
        }
        spans.push(Span::styled(label, choice_style(choice)));
    }
    Line::from(spans)
}

fn render_composer(f: &mut Frame, area: Rect, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    if area.height == 1
        && let Some(pending) = &app.pending
    {
        // At the physical minimum, fail-closed choice visibility outranks title and transcript.
        f.render_widget(
            Paragraph::new(approval_action_line(app, pending, area.width)),
            area,
        );
        return;
    }
    let text = app.editor.text();
    let is_bash = text.starts_with('!');
    let line_color = if app.pending.is_some() {
        app.theme.warn
    } else if !text.is_empty() || app.running {
        app.theme.accent
    } else {
        app.theme.border
    };
    let title = if app.pending.is_some() {
        "Permission required"
    } else if app.running {
        match input_destination(true, &text) {
            InputDestination::AfterTurn => "Queue after this turn",
            InputDestination::SteerCurrentRun => "Steer current run",
            InputDestination::StartTurn => unreachable!("running destination"),
        }
    } else if app.is_resume_handoff_draft() {
        "Restart handoff — copy to a new terminal"
    } else if app.mode == PermissionMode::Plan {
        "Plan request"
    } else if is_bash {
        "Local shell"
    } else {
        "Prompt"
    };
    // One frame owns the complete input/approval surface. Tiny terminals cannot spare two border
    // rows, so they deliberately fall back to the unframed fail-closed control above/below.
    let body = if area.width >= 3 && area.height >= 3 {
        let composer = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(line_color))
            .title(format!(
                " {} ",
                clip_text(title, area.width.saturating_sub(4))
            ));
        let inner = composer.inner(area);
        f.render_widget(composer, area);
        inner
    } else {
        area
    };
    if body.height == 0 {
        return;
    }

    if let Some(pending) = &app.pending {
        let verb = block::verb_for(&pending.tool);
        let title = clip_text(
            &format!("Allow {verb}? · {}", cap_label(pending.cap)),
            body.width,
        );
        let operation = approval_operation_text(pending);
        let title_line = Line::from(Span::styled(
            title,
            Style::default()
                .fg(app.theme.fg)
                .add_modifier(Modifier::BOLD),
        ));
        let operation_style = Style::default().fg(app.theme.fg);
        let mut operation_lines = popup_detail_lines(
            &format!("› {operation}"),
            body.width,
            if body.height >= 6 { 2 } else { 1 },
            operation_style,
        );
        if operation_lines.is_empty() {
            operation_lines.push(Line::from(Span::styled(
                "› operation unavailable",
                operation_style,
            )));
        }
        let workspace_line = Line::from(Span::styled(
            clip_text(&format!("workspace {}", pending.workspace), body.width),
            Style::default().fg(app.theme.muted),
        ));
        let reason_line = Line::from(Span::styled(
            clip_text(&pending.reason, body.width),
            Style::default().fg(app.theme.muted),
        ));
        let choice_line = approval_action_line(app, pending, body.width);
        // Security action is the last thing allowed to disappear. The exact operation outranks
        // explanatory prose, so even a two-row body shows operation + allow/deny.
        let mut lines = match body.height {
            0 => Vec::new(),
            1 => vec![choice_line.clone()],
            2 => vec![operation_lines.remove(0), choice_line.clone()],
            3 => vec![
                title_line.clone(),
                operation_lines.remove(0),
                choice_line.clone(),
            ],
            4 => vec![
                title_line.clone(),
                operation_lines.remove(0),
                reason_line.clone(),
                choice_line.clone(),
            ],
            _ => {
                let mut rows = vec![title_line.clone()];
                rows.append(&mut operation_lines);
                rows.push(workspace_line.clone());
                rows.push(reason_line.clone());
                rows.push(choice_line.clone());
                rows
            }
        };
        if lines.len() > body.height as usize {
            let choice = lines.pop().unwrap_or(choice_line);
            lines.truncate(body.height.saturating_sub(1) as usize);
            lines.push(choice);
        }
        f.render_widget(Paragraph::new(lines), body);
        return;
    }

    let marker_color = if is_bash {
        app.theme.warn
    } else {
        app.theme.accent
    };
    let marker = if is_bash { "! " } else { "› " };
    let marker_area = Rect::new(body.x, body.y, body.width.min(2), body.height);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            marker,
            Style::default()
                .fg(marker_color)
                .add_modifier(Modifier::BOLD),
        ))),
        marker_area,
    );
    let text_area = Rect::new(
        body.x.saturating_add(2),
        body.y,
        body.width.saturating_sub(2),
        body.height,
    );
    let (crow, ccol) = app.editor.cursor_row_col();
    let cur_line = text.split('\n').nth(crow).unwrap_or("");
    let cur_disp = display_col(cur_line, ccol);
    let scroll_x = cur_disp.saturating_sub(text_area.width.saturating_sub(1));
    let crow_u16 = u16::try_from(crow).unwrap_or(u16::MAX);
    let scroll_y = crow_u16.saturating_sub(text_area.height.saturating_sub(1));

    if text.is_empty() {
        let placeholder = if app.running {
            "add direction while the agent works"
        } else {
            "describe a task, question, or change"
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clip_text(placeholder, text_area.width),
                Style::default().fg(app.theme.muted),
            ))),
            text_area,
        );
    } else {
        let base = Style::default().fg(app.theme.fg);
        let lines: Vec<Line> = text
            .split('\n')
            .enumerate()
            .map(|(index, line)| {
                if index == 0
                    && let Some((token, rest, color)) = command_token(line, &app.theme)
                {
                    return Line::from(vec![
                        Span::styled(
                            token,
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(rest, base),
                    ]);
                }
                Line::from(Span::styled(line.to_string(), base))
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).scroll((scroll_y, scroll_x)),
            text_area,
        );
    }
    let cursor_x = text_area
        .x
        .saturating_add(cur_disp.saturating_sub(scroll_x));
    let cursor_y = text_area
        .y
        .saturating_add(crow_u16.saturating_sub(scroll_y));
    if app.picker.is_none() && cursor_x < text_area.right() && cursor_y < text_area.bottom() {
        f.set_cursor_position((cursor_x, cursor_y));
    }
}

fn route_label(app: &App) -> String {
    if app.model.is_empty() {
        return String::new();
    }
    let model = app
        .model
        .split(['/', ':'])
        .next_back()
        .unwrap_or(&app.model);
    if app.provider_id.is_empty() {
        model.to_string()
    } else {
        format!("{}/{model}", app.provider_id)
    }
}

fn footer_spans(text: &str, theme: &theme::Theme) -> Vec<Span<'static>> {
    const KEYS: &[&str] = &[
        "enter", "tab", "esc", "ctrl+j", "ctrl+z", "alt+↑", "ctrl+end", "y", "a", "n", "n/esc",
        "/", "@", "!", "?",
    ];
    let mut spans = Vec::new();
    for (index, item) in text.split(" · ").enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(theme.faint)));
        }
        let (head, tail) = item.split_once(' ').unwrap_or((item, ""));
        if KEYS.contains(&head) {
            let key_style = if theme.mono {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            };
            spans.push(Span::styled(head.to_string(), key_style));
            if !tail.is_empty() {
                spans.push(Span::styled(
                    format!(" {tail}"),
                    Style::default().fg(theme.muted),
                ));
            }
        } else {
            spans.push(Span::styled(
                item.to_string(),
                Style::default().fg(theme.muted),
            ));
        }
    }
    spans
}

fn render_hint(f: &mut Frame, area: Rect, density: surface::Density, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let text = app.editor.text();
    let left = if app.pending.is_some() {
        let rememberable = app
            .pending
            .as_ref()
            .is_some_and(|pending| capability_can_be_remembered(pending.cap));
        if density == surface::Density::Compact && rememberable {
            "y once · a session-wide · n deny"
        } else if density == surface::Density::Compact {
            "y once · n deny"
        } else if rememberable {
            "y allow once · a remembers this capability for the session · n/esc deny"
        } else {
            "y allow once · n/esc deny · approval is required every time"
        }
    } else if app.is_resume_handoff_draft() {
        "copy to a new terminal · enter keeps draft · esc clear"
    } else if app.running && !text.is_empty() {
        let queues_after_turn = input_destination(true, &text) == InputDestination::AfterTurn;
        if density == surface::Density::Compact && queues_after_turn {
            "enter queue · ctrl+j newline · esc stop"
        } else if queues_after_turn {
            "enter queues after this turn · ctrl+j newline · esc interrupt"
        } else if density == surface::Density::Compact {
            "enter steer · tab queue · esc stop"
        } else {
            "enter steer · tab queue · ctrl+j newline · esc interrupt"
        }
    } else if app.running && !app.queued.is_empty() {
        if density == surface::Density::Compact {
            "type · esc stop · alt+↑ queued"
        } else {
            "type to steer · alt+↑ edit last queued · esc interrupt"
        }
    } else if app.running {
        if density == surface::Density::Compact {
            "type · esc stop · ctrl+j newline"
        } else {
            "type to steer · tab queues · ctrl+j newline · esc interrupt"
        }
    } else if !text.is_empty() {
        "enter send · ctrl+j newline · esc clear"
    } else if density == surface::Density::Compact {
        "/ commands · @ files · ? help"
    } else {
        "/ commands · @ files · ! shell · ? shortcuts"
    };
    let left = if !app.running && text.is_empty() && app.editor.has_recently_cleared() {
        format!("{left} · ctrl+z restore")
    } else {
        left.to_string()
    };
    let left = clip_text(&left, area.width);
    render_lr_line(f, area, footer_spans(&left, &app.theme), Vec::new());
}

/// Refresh the parsed streaming Markdown document only when its source revision changed. Returns
/// whether a parse occurred, which makes the performance contract directly regression-testable.
fn ensure_stream_doc(app: &mut App) -> bool {
    if app.cur_text.trim().is_empty()
        || (app.cur_doc.is_some() && app.cur_doc_revision == app.cur_text_revision)
    {
        return false;
    }
    app.cur_doc = Some(crate::markdown::MarkdownDoc::parse(&app.cur_text));
    app.cur_doc_revision = app.cur_text_revision;
    true
}

fn draw(f: &mut Frame, app: &mut App) {
    // The dock grows for multiline input, bounded to six editable rows. A blocking approval asks
    // for the full six-row decision surface; short terminals degrade through Surface::resolve.
    let n_input_rows = app.editor.text().split('\n').count().clamp(1, 6) as u16;
    let lane_rows = if app.pending.is_some() {
        0
    } else {
        u16::from(!app.steer_previews.is_empty()) + u16::from(!app.queued.is_empty())
    };
    // The status line is stable chrome below the composer, including on the fresh landing. Surface
    // geometry drops it only when a physically tiny frame cannot spare the row.
    let show_status = true;
    let surface = surface::Surface::resolve(
        f.area(),
        if app.pending.is_some() {
            6
        } else {
            n_input_rows
        },
        lane_rows,
        show_status,
        app.pending.is_some(),
    );

    // Reset the complete alternate-screen frame, then draw only semantic terminal primitives.
    // There is intentionally no desktop canvas, window fill, chrome strip, or card background.
    f.render_widget(ratatui::widgets::Clear, f.area());

    // transcript — each structured block self-renders to ALREADY-WRAPPED rows at `inner_w`
    // (ADR-015 §3), so the concatenation is fed to the exact pre-wrap→scroll-unit math unchanged
    // (the load-bearing R6 invariant). No outer box: a full-width flow with per-block gutters reads
    // far less like a toy than a dense boxed log. All body regions now share one exact grid; the
    // scrollbar owns its own stage-gutter rect (or overlays the compact edge only when necessary).
    let inner_w = surface.transcript.width;
    if app.render_cache_width != inner_w || app.render_cache_theme_epoch != app.theme_epoch {
        app.render_cache.clear();
        app.render_cache_width = inner_w;
        app.render_cache_theme_epoch = app.theme_epoch;
    }
    // Streaming Markdown is parsed only when provider text changes. Active frames still re-render
    // at 10 fps for the caret/activity animation, but unchanged deltas do not repeatedly rebuild
    // the semantic document.
    ensure_stream_doc(app);
    let mut lines: Vec<Line> = Vec::new();
    let mut row_map: Vec<usize> = Vec::new(); // block index per rendered row (usize::MAX = spacer/stream)
    {
        let theme = &app.theme;
        let spin = app.spin;
        let render_cache = &mut app.render_cache;
        for (bi, b) in app.transcript.iter().enumerate() {
            if bi > 0 {
                // Variable rhythm (critique P1): a bigger gap at real turn boundaries, none between
                // adjacent tool cards / notices / dividers, so structure is scannable, not monotone.
                let gap = block::gap_before(&app.transcript[bi - 1].kind, &b.kind);
                for _ in 0..gap {
                    lines.push(Line::from(""));
                    row_map.push(usize::MAX);
                }
            }
            let rows = if b.cacheable() {
                match render_cache.get(&b.id) {
                    Some((revision, rows)) if *revision == b.revision => rows.clone(),
                    _ => {
                        let rows = b.render(inner_w, theme, spin);
                        render_cache.insert(b.id, (b.revision, rows.clone()));
                        rows
                    }
                }
            } else {
                b.render(inner_w, theme, spin)
            };
            for _ in 0..rows.len() {
                row_map.push(bi);
            }
            lines.extend(rows);
        }
        // live streaming blocks (reasoning, then the in-flight answer) through the SAME render path
        if !app.cur_think.trim().is_empty() {
            if !lines.is_empty() {
                lines.push(Line::from(""));
                row_map.push(usize::MAX);
            }
            let tb = block::Block::new(
                u64::MAX,
                block::BlockKind::Thinking {
                    text: app.cur_think.clone(),
                    open: true,
                },
            );
            let rows = tb.render(inner_w, theme, spin);
            row_map.extend(std::iter::repeat_n(usize::MAX, rows.len()));
            lines.extend(rows);
        }
        if !app.cur_text.trim().is_empty() {
            if !lines.is_empty() {
                lines.push(Line::from(""));
                row_map.push(usize::MAX);
            }
            let rows = block::render_assistant_doc(
                app.cur_doc
                    .as_ref()
                    .expect("non-empty streaming text has a parsed document"),
                inner_w,
                theme,
            );
            row_map.extend(std::iter::repeat_n(usize::MAX, rows.len()));
            lines.extend(rows);
            // blinking caret on the last row while streaming
            if app.running
                && (app.spin / 4).is_multiple_of(2)
                && let Some(last) = lines.last_mut()
                && crate::render::line_width(last) < inner_w
            {
                last.spans
                    .push(Span::styled("▋", Style::default().fg(theme.role_assistant)));
            }
        }
    }
    let total = u16::try_from(lines.len()).unwrap_or(u16::MAX); // saturating (review LOW: >65535 rows)
    let view_h = surface.transcript.height;
    let max_scroll = total.saturating_sub(view_h);
    if !app.follow_tail && app.last_view_h > 0 {
        // Preserve the same absolute rendered-row index when append or layout changes the scrollable
        // extent. This is exact for append-only updates and shelf height changes; resize/fold can
        // reflow content at that row, so a future block-id/logical-row anchor is still required.
        // `bottom_offset` may already include a user PageUp/Down delta made since the previous frame.
        let previous_extent = app.last_total_rows.saturating_sub(app.last_view_h);
        if max_scroll >= previous_extent {
            app.bottom_offset = app
                .bottom_offset
                .saturating_add(max_scroll - previous_extent);
        } else {
            app.bottom_offset = app
                .bottom_offset
                .saturating_sub(previous_extent - max_scroll);
        }
    }
    app.last_total_rows = total;
    app.last_view_h = view_h;
    app.bottom_offset = app.bottom_offset.min(max_scroll); // clamp: can't scroll above the top
    if app.bottom_offset == 0 && !app.follow_tail {
        app.follow_latest();
    }
    let scroll = max_scroll - app.bottom_offset;
    // stash viewport params for mouse hit-testing (click-to-fold, wheel scroll — R9)
    app.row_map = row_map;
    app.view_top = surface.transcript.y;
    app.view_scroll = scroll;
    app.view_h = view_h;
    let transcript = Paragraph::new(lines).scroll((scroll, 0)); // NO .wrap(): rows == scroll units
    f.render_widget(transcript, surface.transcript);

    // Scrollbar in the reserved right column — a position indicator (polish backlog P0). Only when
    // the content overflows the viewport, so a short session stays clean.
    if total > view_h {
        let mut sb_state = ScrollbarState::new(total as usize)
            .position(scroll as usize)
            .viewport_content_length(view_h as usize);
        let sb = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .thumb_symbol("█")
            .track_symbol(Some("│"))
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(app.theme.muted))
            .track_style(Style::default().fg(app.theme.code_bg));
        f.render_stateful_widget(sb, surface.scrollbar, &mut sb_state);
    }

    render_pending_lanes(f, surface.lanes, app);

    render_composer(f, surface.composer, app);
    render_hint(f, surface.hint, surface.density, app);
    // One permanent footer row: live state on the left, truthful route/effort/context on the right.
    render_status(f, surface.status, surface.density, app);

    // completion popup, overlaid just above the input box. The rect is ALWAYS clamped to the frame
    // (review CRITICAL: an unclamped rect on a short terminal made ratatui's Clear index out of the
    // buffer and panic the whole TUI). Items are WINDOWED around the selection so a selection past
    // the visible rows stays on screen.
    if let Some(comp) = &app.completion {
        let rows: Vec<PopupRow> = comp
            .items
            .iter()
            .map(|(name, desc)| PopupRow {
                lead: ui_safe_text(&format!("{}{}", comp.lead, name)),
                lead_accent: true,
                aux: ui_safe_text(desc),
                enabled: true,
            })
            .collect();
        let title = if comp.lead == '@' {
            "files"
        } else {
            "commands"
        };
        render_list_popup(
            f,
            surface.overlay_anchor,
            title,
            &rows,
            comp.sel,
            None,
            &app.theme,
        );
    }

    // Selection picker overlay (R7.a) — the SAME component as the completion menu (TUI v3 §9), so the
    // width, height, border, nav, title grammar and selection bar are identical. Rendered last so it
    // sits above any stray completion.
    if let Some(pk) = &app.picker {
        let visible = pk.visible_indices();
        let rows: Vec<PopupRow> = visible
            .iter()
            .filter_map(|&index| pk.items.get(index).map(|item| (index, item)))
            .map(|(index, it)| {
                let mut aux = String::new();
                if index == pk.sel {
                    let breadcrumb = pk.ancestor_breadcrumb(index);
                    if !breadcrumb.is_empty() {
                        aux.push_str(&breadcrumb);
                    }
                }
                if !it.hint.is_empty() {
                    if !aux.is_empty() {
                        aux.push_str("  ·  ");
                    }
                    aux.push_str(&it.hint);
                }
                if !it.enabled && !it.expandable {
                    if !aux.is_empty() {
                        aux.push_str("  ");
                    }
                    aux.push_str("unavailable: ");
                    aux.push_str(it.disabled_reason.as_deref().unwrap_or("disabled"));
                }
                let disclosure = if it.expandable {
                    if pk.has_query() || it.expanded {
                        "▾ "
                    } else {
                        "▸ "
                    }
                } else if it.parent.is_some() || it.depth > 0 {
                    "  "
                } else {
                    ""
                };
                PopupRow {
                    lead: ui_safe_text(&format!(
                        "{}{}{}{}",
                        "  ".repeat(it.depth.min(32)),
                        disclosure,
                        it.label,
                        if it.is_current { "  current" } else { "" }
                    )),
                    lead_accent: false,
                    aux: ui_safe_text(&aux),
                    // Expansion stays available through picker_key even when account selection is
                    // blocked; rendering keeps the provider header grey so billing/auth state is
                    // visible at the top level, not only on descendant leaves.
                    enabled: it.enabled,
                }
            })
            .collect();
        // Just the title — the modal-title icon zoo (◇◆▷⚿◈, three indistinguishable diamonds) is gone
        // (findings 5); identity is the word, like the tool line.
        render_list_popup(
            f,
            surface.overlay_anchor,
            &ui_safe_text(&pk.title),
            &rows,
            pk.visible_selection(&visible),
            Some(&pk.query),
            &app.theme,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn_end(cost: f64, usage: Usage) -> UiEvent {
        let total = request_input_tokens(usage) as usize;
        UiEvent::TurnEnd {
            cost: CostState::Known {
                amount_microusd: (cost * 1_000_000.0).round() as u64,
                rate_card_digest: "sha256:test-rate-card".into(),
            },
            usage,
            context: ContextEstimate {
                system_tokens: total / 4,
                tool_tokens: total / 4,
                transcript_tokens: total / 2,
                framing_tokens: 0,
                total_tokens: total,
                provenance: core_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
            },
            model_context_window: None,
            reserved_output_tokens: 8_192,
            compaction_trigger_tokens: 120_000,
            effort: EffortApplication::Exact {
                requested: core_protocol::ReasoningEffort::Medium,
            },
        }
    }

    fn pick(label: &str, action: PickAction) -> PickItem {
        PickItem::flat(label, "", false, action)
    }

    #[allow(clippy::too_many_arguments)]
    fn tree_pick(
        label: &str,
        parent: Option<usize>,
        depth: usize,
        expandable: bool,
        expanded: bool,
        enabled: bool,
        reason: Option<&str>,
        action: PickAction,
    ) -> PickItem {
        PickItem {
            label: label.into(),
            hint: String::new(),
            is_current: false,
            action,
            parent,
            depth,
            expandable,
            expanded,
            enabled,
            disabled_reason: reason.map(str::to_owned),
        }
    }

    fn model_tree() -> Vec<PickItem> {
        vec![
            tree_pick("OpenAI", None, 0, true, false, true, None, PickAction::Info),
            tree_pick("GPT", Some(0), 1, true, false, true, None, PickAction::Info),
            tree_pick(
                "gpt-5",
                Some(1),
                2,
                false,
                false,
                true,
                None,
                PickAction::SetModel(ModelSelection {
                    provider_id: "openai".into(),
                    model_id: "gpt-5".into(),
                }),
            ),
            tree_pick(
                "gpt-4.1",
                Some(1),
                2,
                false,
                false,
                false,
                Some("insufficient quota"),
                PickAction::SetModel(ModelSelection {
                    provider_id: "openai".into(),
                    model_id: "gpt-4.1".into(),
                }),
            ),
            tree_pick(
                "Anthropic",
                None,
                0,
                true,
                false,
                true,
                None,
                PickAction::Info,
            ),
        ]
    }

    fn session_meta(
        run_id: &str,
        title: &str,
        updated_at: u64,
        provider_id: &str,
        model: &str,
        turns: u32,
    ) -> core_record::SessionMeta {
        core_record::SessionMeta {
            pricing_schema_version: 1,
            projection_schema_version: 1,
            run_id: core_protocol::RunId(run_id.into()),
            tenant: core_protocol::TenantId::default(),
            cwd: std::path::PathBuf::from("/tmp/project"),
            provider_id: provider_id.into(),
            model: model.into(),
            effort: Effort::Medium,
            title: title.into(),
            created_at: updated_at.saturating_sub(10),
            updated_at,
            record_bytes: 100,
            turns,
            cost: CostState::Known {
                amount_microusd: 2_500_000,
                rate_card_digest: "sha256:test".into(),
            },
            cache_hit: 0.25,
            last_outcome: None,
            parent: None,
        }
    }

    #[test]
    fn picker_query_reveals_leaf_and_ancestors_then_accepts_with_one_enter() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items: model_tree(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });

        for ch in "gpt-5".chars() {
            app.picker_key(KeyCode::Char(ch));
        }
        let picker = app.picker.as_ref().unwrap();
        assert_eq!(picker.visible_indices(), vec![0, 1, 2]);
        assert_eq!(picker.sel, 2, "search focuses the actionable matching leaf");
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetModel(ModelSelection {
                provider_id,
                model_id,
            }))) if provider_id == "openai" && model_id == "gpt-5"
        ));
    }

    #[test]
    fn picker_query_is_cjk_safe_bounded_and_has_an_explicit_no_result_state() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items: vec![
                pick("通义千问", PickAction::Info),
                pick("智谱 GLM", PickAction::SetEffort(Effort::High)),
            ],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        for ch in "智谱".chars() {
            app.picker_key(KeyCode::Char(ch));
        }
        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![1]);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);

        app.picker_key(KeyCode::Char('x'));
        assert!(app.picker.as_ref().unwrap().visible_indices().is_empty());
        assert!(render_text(&mut app, 80, 18).contains("No matches"));
        for _ in 0..(MAX_PICKER_QUERY_CHARS + 20) {
            app.picker_key(KeyCode::Char('a'));
        }
        assert!(app.picker.as_ref().unwrap().query.chars().count() <= MAX_PICKER_QUERY_CHARS);

        app.picker_key(KeyCode::Esc);
        assert!(app.picker.is_some(), "first Esc clears the query");
        assert!(app.picker.as_ref().unwrap().query.is_empty());
        app.picker_key(KeyCode::Esc);
        assert!(app.picker.is_none(), "second Esc closes the picker");
    }

    #[test]
    fn session_picker_is_latest_first_and_discloses_route_cost_turns_and_run() {
        let items = session_picker_items(
            vec![
                session_meta("older", "Older task", 10, "openai", "gpt-5", 2),
                session_meta("newer", "Newest task", 30, "glm", "glm-5.2", 7),
                session_meta("middle", "Middle task", 20, "anthropic", "sonnet", 4),
            ],
            "",
        );
        assert_eq!(items[0].label, "Newest task");
        assert!(matches!(&items[0].action, PickAction::PrepareResume(id) if id == "newer"));
        for expected in ["run newer", "7 turns", "$2.5000", "glm/glm-5.2"] {
            assert!(
                items[0].hint.contains(expected),
                "missing {expected}: {}",
                items[0].hint
            );
        }
    }

    #[test]
    fn session_picker_one_enter_prepares_but_never_executes_restart_handoff() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "sessions".into(),
            items: session_picker_items(
                vec![session_meta(
                    "run-42",
                    "Fix parser",
                    42,
                    "glm",
                    "glm-5.2",
                    3,
                )],
                "",
            ),
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("one Enter should select the session"),
        };
        let PickAction::PrepareResume(run_id) = action else {
            panic!("session selection returned the wrong action")
        };
        app.prepare_resume_handoff(&run_id);
        assert_eq!(app.editor.text(), "core --resume run-42");
        assert!(app.is_resume_handoff_draft());
        let screen = render_text(&mut app, 100, 18);
        assert!(screen.contains("Restart handoff"));
        assert!(screen.contains("core --resume run-42"));
        assert!(
            app.transcript
                .iter()
                .any(|block| block.to_text().contains("not resumed here"))
        );
        assert_eq!(
            format_resume_command("run with space"),
            "core --resume 'run with space'"
        );
    }

    #[test]
    fn permission_picker_uses_human_labels_only() {
        let text = permission_picker_items(&PermissionRules::new())
            .into_iter()
            .map(|item| item.label)
            .collect::<Vec<_>>()
            .join("\n");
        for raw in [
            "read_only",
            "reversible_local",
            "code_executing",
            "trust_mutating",
            "irreversible_external",
        ] {
            assert!(!text.contains(raw), "raw schema spelling leaked: {raw}");
        }
        assert!(text.contains("Read-only operations"));
        assert!(text.contains("Reversible edits"));
        assert!(text.contains("External actions and network access"));
    }

    #[test]
    fn picker_nav_wraps_and_accept_returns_action() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "effort".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: vec![
                pick("low", PickAction::SetEffort(Effort::Low)),
                pick("high", PickAction::SetEffort(Effort::High)),
            ],
        });
        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        let accepted = matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetEffort(Effort::High)))
        );
        assert!(accepted, "Enter returns the selected action");
        assert!(app.picker.is_none(), "picker closes on accept");
    }

    #[test]
    fn picker_initial_focus_prefers_current_leaf_over_provider_header() {
        let mut items = model_tree();
        items[0].is_current = true;
        items[0].expanded = true;
        items[1].expanded = true;
        items[2].is_current = true;
        assert_eq!(initial_picker_selection(&items), 2);
    }

    #[test]
    fn no_current_model_leaf_is_visible_and_accepts_with_one_enter() {
        let mut items = model_tree();
        let selection = initial_picker_selection(&items);
        assert_eq!(selection, 2, "first actionable model should be focused");
        expand_selection_ancestors(&mut items, selection);
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            items,
            sel: selection,
            query: String::new(),
            saved_theme: None,
        });
        assert!(
            app.picker
                .as_ref()
                .unwrap()
                .visible_indices()
                .contains(&selection)
        );
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Accept(PickAction::SetModel(ModelSelection {
                provider_id,
                model_id,
            }))) if provider_id == "openai" && model_id == "gpt-5"
        ));
    }

    #[test]
    fn permissions_picker_starts_actionable_and_accepts_in_one_enter() {
        let mut rules = PermissionRules::new();
        let items = permission_picker_items(&rules);
        let selection = initial_picker_selection(&items);
        assert_ne!(
            selection, 0,
            "the fixed read-only note must not get initial focus"
        );
        assert!(items[selection].enabled);

        let mut app = App::new();
        app.picker = Some(Picker {
            title: "permissions".into(),
            items,
            sel: selection,
            query: String::new(),
            saved_theme: None,
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("one Enter should accept the focused permission rule"),
        };
        let PickAction::SetCap(capability, verdict) = action else {
            panic!("permission picker returned a non-permission action");
        };
        rules.try_set_cap(capability, verdict).unwrap();
        assert_eq!(rules.cap_rule(capability), Some(verdict));
        assert!(app.picker.is_none());
    }

    #[test]
    fn permissions_picker_marks_current_rule_and_cannot_select_unsafe_auto() {
        let mut rules = PermissionRules::new();
        rules
            .try_set_cap(Capability::CodeExecuting, Verdict::Deny)
            .unwrap();
        let items = permission_picker_items(&rules);
        let current = initial_picker_selection(&items);
        assert!(matches!(
            &items[current].action,
            PickAction::SetCap(Capability::CodeExecuting, Verdict::Deny)
        ));

        let unsafe_auto = items
            .iter()
            .position(|item| {
                matches!(
                    &item.action,
                    PickAction::SetCap(Capability::TrustMutating, Verdict::Auto)
                )
            })
            .unwrap();
        assert!(!items[unsafe_auto].enabled);
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "permissions".into(),
            items,
            sel: unsafe_auto,
            query: String::new(),
            saved_theme: None,
        });
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "unsafe choice must remain unapplied");
        assert!(
            rules
                .try_set_cap(Capability::TrustMutating, Verdict::Auto)
                .is_err(),
            "the protocol boundary independently rejects the same choice"
        );
    }

    #[test]
    fn hierarchical_picker_expands_collapses_and_moves_to_parent() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: model_tree(),
        });

        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![0, 4]);
        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 4],
            "Enter expands a provider header"
        );

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        app.picker_key(KeyCode::Right);
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 2, 3, 4],
            "Right expands a family header"
        );

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 2);
        app.picker_key(KeyCode::Left);
        assert_eq!(
            app.picker.as_ref().unwrap().sel,
            1,
            "Left on a leaf moves to its parent"
        );
        app.picker_key(KeyCode::Left);
        assert_eq!(
            app.picker.as_ref().unwrap().visible_indices(),
            vec![0, 1, 4]
        );
        assert_eq!(app.picker.as_ref().unwrap().sel, 1);
        app.picker_key(KeyCode::Left);
        assert_eq!(app.picker.as_ref().unwrap().sel, 0);
        app.picker_key(KeyCode::Left);
        assert_eq!(app.picker.as_ref().unwrap().visible_indices(), vec![0, 4]);
    }

    #[test]
    fn hierarchical_navigation_uses_only_visible_rows() {
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: model_tree(),
        });

        app.picker_key(KeyCode::Down);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
        app.picker_key(KeyCode::Down);
        assert_eq!(
            app.picker.as_ref().unwrap().sel,
            0,
            "Down wraps across visible roots without entering hidden descendants"
        );
        app.picker_key(KeyCode::End);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
        app.picker_key(KeyCode::Home);
        assert_eq!(app.picker.as_ref().unwrap().sel, 0);
        app.picker_key(KeyCode::PageDown);
        assert_eq!(app.picker.as_ref().unwrap().sel, 4);
    }

    #[test]
    fn disabled_model_cannot_be_accepted() {
        let mut items = model_tree();
        items[0].expanded = true;
        items[1].expanded = true;
        let mut app = App::new();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 3,
            query: String::new(),
            saved_theme: None,
            items,
        });

        assert!(matches!(
            app.picker_key(KeyCode::Enter),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "disabled model keeps the picker open");
        assert_eq!(app.picker.as_ref().unwrap().sel, 3);
        assert!(matches!(
            app.picker_key(KeyCode::Tab),
            Some(PickerEvent::Consumed)
        ));
        assert!(app.picker.is_some(), "Tab cannot bypass disabled state");
    }

    #[test]
    fn theme_picker_esc_restores_pre_open_theme() {
        // C1: live-preview on nav, Esc restores the snapshot.
        let mut app = App::new();
        let orig = app.theme.clone();
        let light = theme::Theme::light();
        app.picker = Some(Picker {
            title: "theme".into(),
            sel: 0,
            query: String::new(),
            saved_theme: Some(orig.clone()),
            items: vec![
                pick("dark", PickAction::SetTheme(orig.clone())),
                pick("light", PickAction::SetTheme(light.clone())),
            ],
        });
        app.picker_key(KeyCode::Down); // preview light
        assert_eq!(app.theme.fg, light.fg, "nav previews the theme");
        app.picker_key(KeyCode::Esc); // restore
        assert_eq!(app.theme.fg, orig.fg, "Esc restores the pre-open theme");
        assert!(app.picker.is_none());
    }

    #[test]
    fn fused_picker_esc_and_slash_preserves_the_next_exact_command() {
        let mut app = App::new();
        let mut unavailable =
            PickItem::flat("unavailable", "missing credential", true, PickAction::Info);
        unavailable.enabled = false;
        unavailable.disabled_reason = Some("missing credential".into());
        app.picker = Some(Picker {
            title: "model".into(),
            items: vec![unavailable],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        let repo = std::env::temp_dir();

        assert!(app.recover_picker_escape_prefixed_char(
            KeyCode::Char('/'),
            KeyModifiers::ALT,
            &repo,
        ));
        assert!(app.picker.is_none(), "the Esc half must cancel the picker");
        assert_eq!(app.editor.text(), "/", "the slash half must not be lost");

        // Exercise the same completion-to-submit path used by the event loop. This is the failure
        // mode seen in a real clean-HOME PTY: without the recovery above, every byte through Enter
        // is consumed by the disabled model picker and `/quit` can never reach dispatch.
        app.editor.insert_str("quit");
        app.refresh_completion(&repo);
        assert_eq!(
            app.completion
                .as_ref()
                .and_then(|menu| menu.items.get(menu.sel))
                .map(|item| item.0.as_str()),
            Some("quit")
        );
        assert!(app.accept_completion_for_enter());
        assert_eq!(app.editor.take_submit().trim(), "/quit");
    }

    #[test]
    fn theme_picker_first_row_enter_applies_without_prior_navigation() {
        let mut app = App::new();
        let original = theme::Theme::dark();
        let selected = theme::Theme::light();
        app.set_theme(original.clone());
        app.picker = Some(Picker {
            title: "theme".into(),
            sel: 0,
            query: String::new(),
            saved_theme: Some(original),
            items: vec![pick("light", PickAction::SetTheme(selected.clone()))],
        });
        let action = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(action)) => action,
            _ => panic!("Enter should accept the first theme row"),
        };
        match action {
            PickAction::SetTheme(theme) => apply_theme_selection(&mut app, theme),
            _ => panic!("theme picker returned the wrong action"),
        }
        assert_eq!(app.theme.fg, selected.fg);
    }

    #[test]
    fn picker_open_renders_on_short_terminals_without_panic() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        let mut items = model_tree();
        items[0].expanded = true;
        items[1].expanded = true;
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 3,
            query: String::new(),
            saved_theme: None,
            items,
        });
        for (w, h) in [(80u16, 24u16), (40, 9), (20, 4), (10, 3), (6, 2), (3, 1)] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
            assert!(
                t.backend().buffer().content().iter().any(|cell| {
                    cell.bg == app.theme.accent || cell.modifier.contains(Modifier::REVERSED)
                }),
                "picker focus remains visible at {w}x{h}"
            );
            if w == 80 {
                let rendered = t
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>();
                assert!(
                    rendered.contains("insufficient quota"),
                    "the disabled reason is rendered in the hierarchy"
                );
            }
        }
    }

    #[test]
    fn mono_menu_reverses_exactly_the_selected_row() {
        // Finding R4: under NO_COLOR (accent == Reset) an `fg(Black).bg(accent)` bar is invisible; the
        // unified popup must fall back to REVERSED so the selection is still a visible full-width bar.
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        app.theme = theme::Theme::mono();
        app.picker = Some(Picker {
            title: "model".into(),
            sel: 0,
            query: String::new(),
            saved_theme: None,
            items: (0..4)
                .map(|i| PickItem::flat(format!("m{i}"), "", false, PickAction::Info))
                .collect(),
        });
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let buffer = t.backend().buffer();
        let row_text = |y: u16| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        };
        let selected_y = (0..buffer.area.height)
            .find(|y| row_text(*y).contains("m0"))
            .expect("selected model row");
        let adjacent_y = (0..buffer.area.height)
            .find(|y| row_text(*y).contains("m1"))
            .expect("adjacent model row");
        let left = (0..buffer.area.width)
            .find(|x| buffer[(*x, selected_y)].symbol() == "│")
            .expect("popup left edge");
        let right = (0..buffer.area.width)
            .rfind(|x| buffer[(*x, selected_y)].symbol() == "│")
            .expect("popup right edge");
        assert!(left < right);
        assert!(
            (left + 1..right).all(|x| buffer[(x, selected_y)]
                .modifier
                .contains(Modifier::REVERSED)),
            "the complete selected row is visible without color"
        );
        assert!(
            (left + 1..right).all(|x| !buffer[(x, adjacent_y)]
                .modifier
                .contains(Modifier::REVERSED)),
            "reversal expresses focus, not generic menu chrome"
        );
    }

    #[test]
    fn cap_label_is_human_not_debug() {
        // Finding R5: a security prompt must never surface the raw `{:?}` Debug of a Capability.
        assert_eq!(
            cap_label(Capability::IrreversibleExternal),
            "external egress"
        );
        assert_eq!(cap_label(Capability::ReadOnly), "read-only");
        for c in [
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ] {
            let l = cap_label(c);
            assert!(
                !l.contains("Irreversible")
                    && !l.contains("ReadOnly")
                    && !l.contains("CodeExecuting"),
                "no Debug spelling leaks: {l}"
            );
        }
    }

    #[test]
    fn stream_text_accumulates_then_flushes_to_a_block() {
        let mut app = App::new();
        let base = app.transcript.len();
        app.stream_text("hello ");
        app.stream_text("world");
        // still buffered as the in-flight block; no committed block yet
        assert_eq!(app.transcript.len(), base);
        assert_eq!(app.cur_text, "hello ");
        app.flush_text();
        assert_eq!(app.transcript.len(), base + 1);
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains("hello world")
        );
    }

    #[test]
    fn streaming_markdown_is_reparsed_only_after_text_revision_changes() {
        let mut app = App::new();
        app.stream_text("**first** ");
        assert!(app.cur_doc.is_none());
        assert_ne!(app.cur_doc_revision, app.cur_text_revision);

        assert!(ensure_stream_doc(&mut app), "the first revision is parsed");
        assert!(
            !ensure_stream_doc(&mut app),
            "an unchanged frame skips the Markdown parser"
        );
        let first_screen = render_text(&mut app, 80, 18);
        assert!(first_screen.contains("first"));
        assert!(app.cur_doc.is_some());
        assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        let first_revision = app.cur_doc_revision;
        let first_doc = app.cur_doc.clone();

        let second_screen = render_text(&mut app, 80, 18);
        assert!(second_screen.contains("first"));
        assert_eq!(app.cur_doc_revision, first_revision);
        assert_eq!(
            app.cur_doc, first_doc,
            "an unchanged frame reuses the parsed doc"
        );

        app.stream_text("_second_ ");
        assert_ne!(app.cur_doc_revision, app.cur_text_revision);
        assert!(
            ensure_stream_doc(&mut app),
            "a new source revision is parsed"
        );
        assert!(!ensure_stream_doc(&mut app));
        let updated_screen = render_text(&mut app, 80, 18);
        assert!(updated_screen.contains("first"));
        assert!(updated_screen.contains("second"));
        assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        assert_ne!(app.cur_doc_revision, first_revision);
    }

    #[test]
    fn tui_never_renders_a_credential_split_across_provider_deltas() {
        let mut app = App::new();
        let secret = "sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        app.stream_text("answer sk-ant-api03-AbCd");
        assert_eq!(app.cur_text, "answer ");
        app.stream_text("EfGhIjKlMnOpQrStUvWx");
        assert!(!app.cur_text.contains(secret));
        app.stream_text(" done");
        assert!(!app.cur_text.contains(secret));
        assert!(app.cur_text.contains("[REDACTED"));
        app.flush_text();
        assert!(
            !app.transcript
                .last()
                .expect("assistant block")
                .to_text()
                .contains(secret)
        );
    }

    #[tokio::test]
    async fn inline_shell_is_bounded_terminal_safe_and_secret_scrubbed() {
        let mut app = App::new();
        let secret = "sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let command = format!(
            "printf '%s\\n' '{secret}'; head -c 180000 /dev/zero | tr '\\0' x; printf '\\377'"
        );
        run_bash_inline(&mut app, &std::env::temp_dir(), &command, &[]).await;
        let text = app.transcript.last().expect("shell card").to_text();
        assert!(!text.contains(secret));
        assert!(text.contains("[REDACTED"));
        assert!(text.contains("truncated"));
        assert!(text.contains("invalid UTF-8 escaped"));
        assert!(!text.contains('�'));
        assert!(
            text.len() < 150_000,
            "capture remains bounded: {}",
            text.len()
        );
    }

    #[test]
    fn pending_input_is_globally_bounded_and_requeues_in_submission_order() {
        let mut app = App::new();
        app.queue_after_turn("queued first".into()).unwrap();
        assert_eq!(
            app.steer_admission("late steer"),
            SubmissionAdmission::Accept
        );
        app.track_steer("late steer".into());
        app.queue_after_turn("queued last".into()).unwrap();
        let (moved, unmatched) = app.requeue_unadmitted(vec!["late steer".into()]);
        assert_eq!((moved, unmatched), (1, 0));
        assert_eq!(
            app.queued
                .iter()
                .map(|input| input.text.as_str())
                .collect::<Vec<_>>(),
            vec!["queued first", "late steer", "queued last"]
        );

        while app.queued.len() < MAX_PENDING_SUBMISSIONS {
            app.queue_after_turn(format!("item {}", app.queued.len()))
                .unwrap();
        }
        let rejected = "must remain editable".to_string();
        assert_eq!(
            app.queue_after_turn(rejected.clone()),
            Err(rejected),
            "the 33rd item is rejected rather than dropping an older preview"
        );
    }

    #[test]
    fn unmatched_steer_previews_are_preserved_as_ordered_follow_ups() {
        let mut app = App::new();
        app.track_steer("returned by kernel".into());
        app.track_steer("preview missing from reclaim report".into());
        app.queue_after_turn("already queued".into()).unwrap();

        let (reported, preserved) = app.requeue_unadmitted(vec!["returned by kernel".into()]);

        assert_eq!((reported, preserved), (1, 1));
        assert!(app.steer_previews.is_empty());
        assert_eq!(
            app.queued
                .iter()
                .map(|input| input.text.as_str())
                .collect::<Vec<_>>(),
            vec![
                "returned by kernel",
                "preview missing from reclaim report",
                "already queued"
            ],
            "count mismatch must preserve at-least-once operator intent in submission order"
        );
    }

    #[test]
    fn settled_render_cache_keeps_one_revision_per_block() {
        let mut app = App::new();
        app.push_block(block::BlockKind::Thinking {
            text: "bounded cache".into(),
            open: false,
        });
        for _ in 0..64 {
            let _ = render_text(&mut app, 80, 18);
            app.toggle_last_fold();
        }
        let _ = render_text(&mut app, 80, 18);
        assert!(app.render_cache.len() <= app.transcript.len());
        assert!(app.render_cache.contains_key(&1));
        assert_eq!(
            app.render_cache.get(&1).map(|(revision, _)| *revision),
            Some(app.transcript[1].revision)
        );
    }

    #[test]
    fn transcript_is_bounded() {
        let mut app = App::new();
        for i in 0..(MAX_BLOCKS + 300) {
            app.push(dim(), format!("line {i}"));
        }
        assert!(
            app.transcript.len() <= MAX_BLOCKS,
            "transcript must be bounded, got {}",
            app.transcript.len()
        );
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains(&format!("line {}", MAX_BLOCKS + 299))
        );
    }

    #[test]
    fn transcript_pressure_pins_active_workflow_until_terminal_truth_lands() {
        let mut app = App::new();
        let run_id = "workflow-under-pressure";
        app.workflow_event(WorkflowUiEvent::RunStarted {
            run_id: run_id.into(),
            name: "ultracode".into(),
            class: "repository-wide".into(),
        });
        let block_id = *app
            .workflow_index
            .get(run_id)
            .expect("active workflow is indexed");

        for i in 0..(MAX_BLOCKS + 300) {
            app.push(dim(), format!("pressure line {i}"));
        }
        assert!(app.transcript.len() <= MAX_BLOCKS);
        assert_eq!(app.workflow_index.get(run_id), Some(&block_id));
        assert!(app.transcript.iter().any(|block| block.id == block_id));

        app.workflow_event(WorkflowUiEvent::RunFinished {
            run_id: run_id.into(),
            outcome: WorkflowRunOutcomeUi::Degraded,
            reason: Some("one investigator failed".into()),
            elapsed_ms: 42,
            provider_attempts: 3,
            turns: 2,
            tokens: 900,
            tool_calls: 4,
            failed_tasks: 1,
            skipped_tasks: 0,
        });
        assert!(!app.workflow_index.contains_key(run_id));
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("terminal update lands on the pinned workflow card");
        assert_eq!(card.status, block::WorkflowStatus::Degraded);
        assert_eq!(card.reason.as_deref(), Some("one investigator failed"));
    }

    #[test]
    fn draw_renders_all_states_without_panic() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = App::new();
        app.push(fg(Color::White), "# a markdown header");
        app.push(fg(Color::Blue), "· read_file {\"path\":\"a\"}");
        app.push(fg(Color::White), "```rust");
        // idle + slash menu open
        app.editor.insert_str("/mo");
        app.refresh_completion(&std::env::temp_dir());
        term.draw(|f| draw(f, &mut app)).unwrap();
        // multi-line input
        app.editor.clear();
        app.editor.insert_str("line1");
        app.editor.newline();
        app.editor.insert_str("line2");
        app.completion = None;
        term.draw(|f| draw(f, &mut app)).unwrap();
        // running + a pending approval
        app.running = true;
        app.spin = 3;
        app.cost = CostState::Known {
            amount_microusd: 120_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        app.last_turn_usage = Some(Usage {
            input: 60,
            cache_read: 40,
            ..Usage::default()
        });
        app.pending = Some(Pending {
            id: SubmissionId(1),
            tool: "edit".into(),
            cap: Capability::ReversibleLocal,
            reason: "update src/main.rs".into(),
            arguments: serde_json::json!({"path": "src/main.rs"}),
            workspace: "/tmp/project".into(),
        });
        term.draw(|f| draw(f, &mut app)).unwrap();
        // CRITICAL regression: the completion menu OPEN on short terminals must not panic (the
        // popup rect must clamp to the frame). Sweep sizes below the popup height.
        app.running = false;
        app.pending = None;
        app.editor.clear();
        app.editor.insert_str("/"); // 25-command menu -> tall popup
        app.refresh_completion(&std::env::temp_dir());
        assert!(app.completion.is_some());
        for (w, h) in [
            (80u16, 24u16),
            (40, 9),
            (40, 5),
            (20, 4),
            (10, 3),
            (6, 2),
            (3, 1),
        ] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
        }
        // selection windowing: move past the visible window, still no panic on a short terminal
        for _ in 0..20 {
            if let Some(c) = app.completion.as_mut() {
                c.sel = (c.sel + 1) % c.items.len();
            }
            let mut t = Terminal::new(TestBackend::new(40, 8)).unwrap();
            t.draw(|f| draw(f, &mut app)).unwrap();
        }
    }

    /// Read a TestBackend buffer as one big string (cell symbols concatenated row by row).
    #[cfg(test)]
    fn buffer_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buf = term.backend().buffer();
        let area = buf.area;
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        buffer_text(&terminal)
    }

    const PRODUCT_SIZES: [(u16, u16); 4] = [(40, 12), (80, 24), (120, 32), (200, 40)];

    #[test]
    fn composer_is_an_unmistakable_terminal_prompt() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let mut terminal = Terminal::new(TestBackend::new(40, 3)).unwrap();
        terminal
            .draw(|frame| render_composer(frame, frame.area(), &app))
            .unwrap();
        let buf = terminal.backend().buffer();
        for y in 0..3 {
            for x in 0..40 {
                assert_eq!(
                    buf[(x, y)].bg,
                    Color::Reset,
                    "the terminal-native composer must not paint a card at ({x},{y})"
                );
            }
        }
        let screen = buffer_text(&terminal);
        assert!(screen.contains("Prompt"));
        assert!(screen.contains('›'));
        assert_eq!(buf[(0, 0)].symbol(), "╭");
        assert_eq!(buf[(39, 0)].symbol(), "╮");
        assert_eq!(buf[(0, 2)].symbol(), "╰");
        assert_eq!(buf[(39, 2)].symbol(), "╯");
    }

    #[test]
    fn full_width_composer_precedes_a_stable_bottom_statusline() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.provider_id = "glm".into();
        app.model = "glm-5.2".into();
        app.effort = Effort::High;
        let expected = surface::Surface::resolve(Rect::new(0, 0, 80, 12), 1, 0, true, false);
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();

        assert_eq!(expected.composer.x, 0);
        assert_eq!(expected.composer.right(), 80);
        assert_eq!(
            expected.status.y,
            expected.composer.bottom() + expected.hint.height
        );
        assert_eq!(expected.status.bottom(), 12);
        assert_eq!(buffer[(0, expected.composer.y)].symbol(), "╭");
        assert_eq!(buffer[(79, expected.composer.y)].symbol(), "╮");
        let bottom: String = (0..80)
            .map(|x| buffer[(x, expected.status.y)].symbol())
            .collect();
        assert!(
            bottom.contains("glm/glm-5.2"),
            "route stays in bottom row: {bottom:?}"
        );
        assert!(
            bottom.contains("● high"),
            "effort stays in bottom row: {bottom:?}"
        );
    }

    #[test]
    fn effort_symbols_match_claude_grammar_without_hiding_enforcement_truth() {
        assert_eq!(effort_symbol(ReasoningEffort::Low), "○");
        assert_eq!(effort_symbol(ReasoningEffort::Medium), "◐");
        assert_eq!(effort_symbol(ReasoningEffort::High), "●");
        assert_eq!(effort_symbol(ReasoningEffort::XHigh), "⦿");
        assert_eq!(effort_symbol(ReasoningEffort::Max), "◉");

        let mut app = App::new();
        app.effort = Effort::Ultracode;
        assert_eq!(effort_status_label(&app), "◉ max · ultracode");
        app.effort = Effort::High;
        app.effort_application = Some(EffortApplication::Mapped {
            requested: ReasoningEffort::High,
            sent: ReasoningEffort::Max,
        });
        assert_eq!(effort_status_label(&app), "◉ max ← high requested");
        app.effort_application = Some(EffortApplication::Unsupported {
            requested: ReasoningEffort::High,
        });
        assert_eq!(effort_status_label(&app), "● high · not enforced");
    }

    #[test]
    fn terminal_native_surface_is_coherent_across_product_breakpoints() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.theme = theme::Theme::dark();
            app.model = "claude-sonnet-4-5".into();
            app.provider_id = "anthropic".into();
            let screen = render_text(&mut app, width, height);
            assert!(
                screen.contains("██████╗"),
                "historical Core wordmark at {width}x{height}"
            );
            assert!(screen.contains('›'), "composer at {width}x{height}");
            assert!(
                screen.contains("commands"),
                "discoverability at {width}x{height}"
            );
            assert!(
                !screen.contains('┃'),
                "no permanent rail at {width}x{height}"
            );
            assert!(screen.contains('╭') && screen.contains('╯'));
            assert!(!screen.contains('�'), "valid unicode at {width}x{height}");
        }
    }

    #[test]
    fn one_app_survives_resize_round_trip_and_invalidates_width_cache() {
        let mut app = App::new();
        app.push_user("inspect the responsive surface across a deliberately long wrapped line");
        app.note(block::NoticeLevel::Info, "stable semantic block");
        app.stream_text("streaming **markdown** remains parsed across resize ");

        let mut cache_widths = Vec::new();
        for (width, height) in [(40, 12), (80, 24), (120, 32), (200, 40), (80, 24), (40, 12)] {
            let screen = render_text(&mut app, width, height);
            if height >= 24 {
                assert!(screen.contains("responsive"));
            }
            assert!(screen.contains("markdown"));
            assert!(!screen.contains('�'));
            cache_widths.push(app.render_cache_width);
            assert_eq!(app.cur_doc_revision, app.cur_text_revision);
        }
        assert_ne!(cache_widths[0], cache_widths[1]);
        assert_eq!(cache_widths[0], cache_widths[5]);
        assert_eq!(cache_widths[1], cache_widths[4]);
        assert_eq!(cache_widths, vec![40, 80, 120, 200, 80, 40]);
    }

    #[test]
    fn running_surface_shows_real_steer_and_queue_lanes() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.running = true;
            app.status = "verifying".into();
            app.run_started = Some(Instant::now());
            app.active_tools
                .push_back(("tool-1".into(), "Bash(cargo test -p core-cli)".into()));
            app.track_steer("also cover narrow terminals".into());
            app.queue_after_turn("then update the design record".into())
                .unwrap();
            let screen = render_text(&mut app, width, height);
            assert!(screen.contains("steer"), "steer lane at {width}x{height}");
            assert!(screen.contains("queued"), "queue lane at {width}x{height}");
            assert!(
                screen.contains("esc"),
                "interrupt remains visible at {width}x{height}"
            );
            assert!(
                screen.contains("also cover") || screen.contains("narrow"),
                "actual steer preview at {width}x{height}"
            );
        }
    }

    #[test]
    fn approval_is_a_blocking_decision_surface_with_reason() {
        for (width, height) in PRODUCT_SIZES {
            let mut app = App::new();
            app.running = true;
            apply_event(
                &mut app,
                UiEvent::ApprovalRequest {
                    id: SubmissionId(7),
                    tool: "bash".into(),
                    capability: Capability::CodeExecuting,
                    reason: "run repository tests".into(),
                    arguments: serde_json::json!({"command": "cargo test --workspace"}),
                    workspace: "/tmp/project".into(),
                },
            );
            let screen = render_text(&mut app, width, height);
            assert!(screen.contains("Permission"));
            assert!(screen.contains("runs code"));
            assert!(screen.contains("cargo test"));
            assert!(screen.contains("run repository tests"));
            assert!(screen.contains("once"));
            assert!(screen.contains("session"));
            assert!(screen.contains("deny"));
        }
    }

    #[test]
    fn approval_keeps_actions_on_short_screens_and_never_offers_impossible_remember() {
        for height in [3, 4, 5] {
            let mut app = App::new();
            app.running = true;
            apply_event(
                &mut app,
                UiEvent::ApprovalRequest {
                    id: SubmissionId(9),
                    tool: "write_trust_file".into(),
                    capability: Capability::TrustMutating,
                    reason: "update CI policy".into(),
                    arguments: serde_json::json!({"path": ".github/workflows/ci.yml"}),
                    workspace: "/tmp/project".into(),
                },
            );
            let screen = render_text(&mut app, 56, height);
            assert!(screen.contains("[y]"), "allow once at height {height}");
            assert!(screen.contains("deny"), "deny at height {height}");
            assert!(
                !screen.contains("[a]"),
                "trust-mutating work cannot be remembered at height {height}"
            );
        }
    }

    #[test]
    fn approval_default_deny_remains_visible_at_physical_minimums() {
        for width in [3, 6, 8, 12, 20] {
            for height in [1, 2] {
                let mut app = App::new();
                app.running = true;
                apply_event(
                    &mut app,
                    UiEvent::ApprovalRequest {
                        id: SubmissionId(91),
                        tool: "bash".into(),
                        capability: Capability::CodeExecuting,
                        reason: "verify the build".into(),
                        arguments: serde_json::json!({"command": "cargo test"}),
                        workspace: "/tmp/project".into(),
                    },
                );
                let screen = render_text(&mut app, width, height);
                assert!(
                    screen.contains("[n]"),
                    "fail-closed focus at {width}x{height}: {screen:?}"
                );
                assert_eq!(app.approval_choice, ApprovalChoice::Deny);
            }
        }
    }

    #[test]
    fn narrow_approval_keeps_canonical_order_or_uses_an_explicit_single_slot_pager() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(92),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "verify the build".into(),
                arguments: serde_json::json!({"command": "cargo test"}),
                workspace: "/tmp/project".into(),
            },
        );
        let text = |line: Line<'static>| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect::<String>()
        };

        let canonical = text(approval_action_line(
            &app,
            app.pending.as_ref().unwrap(),
            20,
        ));
        assert!(canonical.find("[y]") < canonical.find("[a]"));
        assert!(canonical.find("[a]") < canonical.find("[n]"));
        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        let after_move = text(approval_action_line(
            &app,
            app.pending.as_ref().unwrap(),
            20,
        ));
        assert_eq!(
            canonical, after_move,
            "focus does not reorder visible actions"
        );

        let paged = text(approval_action_line(&app, app.pending.as_ref().unwrap(), 8));
        assert_eq!(paged, "[a] <>");
        assert_eq!(app.approval_key(KeyCode::Right), ApprovalInput::Consumed);
        let deny_page = text(approval_action_line(&app, app.pending.as_ref().unwrap(), 8));
        assert_eq!(deny_page, "[n] <>");
    }

    #[test]
    fn runtime_approval_is_focusable_and_enter_defaults_to_deny() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(10),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "verify the build".into(),
                arguments: serde_json::json!({"command": "cargo test"}),
                workspace: "/tmp/project".into(),
            },
        );
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
        for theme in [theme::Theme::dark(), theme::Theme::mono()] {
            app.theme = theme;
            let pending = app.pending.as_ref().expect("pending approval");
            let line = approval_action_line(&app, pending, 80);
            let deny = line
                .spans
                .iter()
                .find(|span| span.content.contains("[n]"))
                .expect("deny choice");
            let once = line
                .spans
                .iter()
                .find(|span| span.content.contains("[y]"))
                .expect("once choice");
            if app.theme.mono {
                assert!(deny.style.add_modifier.contains(Modifier::REVERSED));
                assert!(!once.style.add_modifier.contains(Modifier::REVERSED));
            } else {
                assert_eq!(deny.style.bg, Some(app.theme.accent));
                assert_ne!(once.style.bg, Some(app.theme.accent));
            }
        }
        assert_eq!(
            app.approval_key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: false,
                remember: false,
            }
        );

        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Session);
        assert_eq!(
            app.approval_key(KeyCode::Enter),
            ApprovalInput::Answer {
                approved: true,
                remember: true,
            }
        );
        assert_eq!(app.approval_key(KeyCode::Right), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
    }

    #[test]
    fn runtime_approval_never_constructs_an_impossible_session_grant() {
        let mut app = App::new();
        app.running = true;
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(11),
                tool: "write_trust_file".into(),
                capability: Capability::TrustMutating,
                reason: "change repository policy".into(),
                arguments: serde_json::json!({"path": ".github/workflows/ci.yml"}),
                workspace: "/tmp/project".into(),
            },
        );
        assert_eq!(app.approval_key(KeyCode::Left), ApprovalInput::Consumed);
        assert_eq!(app.approval_choice, ApprovalChoice::Once);
        assert_eq!(
            app.approval_key(KeyCode::Char('a')),
            ApprovalInput::Consumed
        );
        assert_ne!(app.approval_choice, ApprovalChoice::Session);
    }

    #[test]
    fn conversation_and_composer_structure_survive_color_and_mono() {
        for theme in [theme::Theme::dark(), theme::Theme::mono()] {
            let mut app = App::new();
            app.theme = theme;
            app.transcript.clear();
            app.push_user("请检查 provider 路由");
            app.stream_text("I found the route and its tests.");
            app.flush_text();
            let screen = render_text(&mut app, 80, 18);
            assert!(screen.contains("provider"));
            assert!(screen.contains("I found the route and its tests."));
            assert!(!screen.contains("YOU ›"));
            assert!(!screen.contains("CORE  I found"));
            assert!(screen.contains("Prompt"));
            assert!(!screen.contains('�'));
        }
    }

    #[test]
    fn running_command_draft_truthfully_switches_composer_route() {
        let mut app = App::new();
        app.running = true;
        app.editor.insert_str("/model");
        let command = render_text(&mut app, 80, 16);
        assert!(command.contains("Queue after this turn"));
        assert!(command.contains("enter queues after this turn"));
        assert!(!command.contains("Steer current run"));

        app.editor.clear();
        app.editor.insert_str("also inspect the tests");
        let prose = render_text(&mut app, 80, 16);
        assert!(prose.contains("Steer current run"));
        assert!(prose.contains("enter steer"));
    }

    #[test]
    fn one_input_destination_reducer_drives_enter_routing() {
        assert_eq!(
            input_destination(false, "/model"),
            InputDestination::StartTurn
        );
        assert_eq!(
            input_destination(true, "  /model"),
            InputDestination::AfterTurn
        );
        assert_eq!(
            input_destination(true, "!cargo test"),
            InputDestination::AfterTurn
        );
        assert_eq!(
            input_destination(true, "please inspect the failure"),
            InputDestination::SteerCurrentRun
        );
    }

    #[test]
    fn scrolling_up_holds_the_view_when_new_output_arrives() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        for index in 0..40 {
            app.note(block::NoticeLevel::Info, format!("historical row {index}"));
        }
        let mut terminal = Terminal::new(TestBackend::new(60, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let bottom_scroll = app.view_scroll;
        app.scroll_up(8);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(
            app.view_scroll,
            bottom_scroll.saturating_sub(8),
            "the first PageUp delta remains exact when the reading shelf appears"
        );
        let prior_scroll = app.view_scroll;
        let prior_offset = app.bottom_offset;
        app.note(block::NoticeLevel::Info, "new output while reading");
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(!app.follow_tail);
        assert_eq!(
            app.view_scroll, prior_scroll,
            "logical viewport stays anchored"
        );
        assert!(app.bottom_offset > prior_offset);
        assert_eq!(app.unread_updates, 1);
        assert!(buffer_text(&terminal).contains("new output"));
    }

    #[test]
    fn unread_signal_tracks_visible_change_not_transport_noise() {
        let mut app = App::new();
        app.scroll_up(1);
        app.stream_text("sk-ant-api03-AbCd");
        assert_eq!(
            app.unread_updates, 0,
            "a scrubber-held credential fragment produced no visible output"
        );
        app.workflow_event(WorkflowUiEvent::PhaseChanged {
            run_id: "unknown-run".into(),
            phase: WorkflowPhaseUi::Exploring,
        });
        assert_eq!(app.unread_updates, 0, "unknown workflow event is a no-op");
        app.stream_text(" plain text ");
        assert_eq!(app.unread_updates, 1);
    }

    #[test]
    fn popup_keeps_selected_detail_discoverable_on_compact_width() {
        let mut app = App::new();
        app.editor.insert_str("/m");
        app.completion = Some(Completion {
            items: vec![(
                "model".into(),
                "choose a provider, family, and available model".into(),
            )],
            sel: 0,
            token_start: 1,
            lead: '/',
        });
        let screen = render_text(&mut app, 56, 18);
        assert!(screen.contains("/model"));
        assert!(screen.contains("provider, family"));
    }

    #[test]
    fn popup_detail_wraps_by_screen_rows_instead_of_clipping_to_one_line() {
        let rows = popup_detail_lines(
            "credential is missing; configure the provider in settings before selecting this model",
            24,
            4,
            Style::default(),
        );
        assert!(
            rows.len() > 1,
            "long detail must occupy multiple screen rows"
        );
        assert!(
            rows.iter()
                .all(|line| crate::render::line_width(line) <= 24),
            "every detail row stays within the popup's cell width"
        );
        let text = rows
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(
            text.contains("settings"),
            "later wrapped detail remains visible"
        );
    }

    #[test]
    fn short_popup_keeps_a_list_row_and_action_legend() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let rows = vec![
            PopupRow {
                lead: "model-a".into(),
                lead_accent: false,
                aux: "a long model explanation that cannot own the short screen".into(),
                enabled: true,
            },
            PopupRow {
                lead: "model-b".into(),
                lead_accent: false,
                aux: String::new(),
                enabled: true,
            },
        ];
        let mut terminal = Terminal::new(TestBackend::new(56, 4)).unwrap();
        terminal
            .draw(|frame| {
                render_list_popup(
                    frame,
                    Rect::new(0, 4, 56, 0),
                    "model",
                    &rows,
                    0,
                    None,
                    &theme::Theme::dark(),
                );
            })
            .unwrap();
        let screen = buffer_text(&terminal);
        assert!(screen.contains("model-a"), "navigation row survives");
        assert!(screen.contains("enter"), "accept action survives");
        assert!(screen.contains("esc"), "cancel action survives");
    }

    #[test]
    fn standard_popup_has_one_rounded_frame_left_aligned_to_its_anchor() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let rows = vec![PopupRow {
            lead: "glm-5.2".into(),
            lead_accent: false,
            aux: "current route".into(),
            enabled: true,
        }];
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                render_list_popup(
                    frame,
                    Rect::new(3, 20, 74, 3),
                    "Model",
                    &rows,
                    0,
                    None,
                    &theme::Theme::dark(),
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let corner = (0..24)
            .flat_map(|y| (0..80).map(move |x| (x, y)))
            .find(|(x, y)| buffer[(*x, *y)].symbol() == "╭")
            .expect("rounded popup corner");
        assert_eq!(corner.0, 3, "popup begins on the anchor's text column");
        let rounded = (0..24)
            .flat_map(|y| (0..80).map(move |x| (x, y)))
            .filter(|(x, y)| matches!(buffer[(*x, *y)].symbol(), "╭" | "╮" | "╰" | "╯"))
            .count();
        assert_eq!(rounded, 4, "one popup frame has exactly four corners");
    }

    #[test]
    fn terminal_native_surface_does_not_paint_desktop_layers() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        assert!(
            buffer.content().iter().all(|cell| cell.bg == Color::Reset),
            "idle surface uses the terminal background end to end"
        );
        let screen = buffer_text(&terminal);
        assert!(
            screen.contains("██████╗"),
            "historical CORE wordmark is visible"
        );
        assert!(screen.contains("Prompt"));
        assert!(screen.contains('›'));
    }

    #[test]
    fn composer_shows_prompt_marker_and_ghost_placeholder() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 12)).unwrap();
        let mut app = App::new();
        // Empty + idle → the › prompt marker and the ghost placeholder are both visible.
        term.draw(|f| draw(f, &mut app)).unwrap();
        let screen = buffer_text(&term);
        assert!(
            screen.contains('›'),
            "empty composer shows the › prompt marker"
        );
        assert!(
            screen.contains("describe a task"),
            "empty composer shows a quiet task placeholder"
        );
        // A `!shell` buffer flips the marker to `!` (bash mode) and hides the placeholder.
        app.editor.insert_str("!ls");
        let mut term2 = Terminal::new(TestBackend::new(80, 12)).unwrap();
        term2.draw(|f| draw(f, &mut app)).unwrap();
        let s2 = buffer_text(&term2);
        assert!(s2.contains("ls"), "typed shell command is shown");
        assert!(
            !s2.contains("ask Core"),
            "placeholder hidden once typing starts"
        );

        // Running keeps a real composer and teaches the steer/queue split instead of claiming Send.
        app.editor.clear();
        app.running = true;
        app.track_steer("also cover narrow terminals".into());
        let mut term3 = Terminal::new(TestBackend::new(100, 12)).unwrap();
        term3.draw(|f| draw(f, &mut app)).unwrap();
        let s3 = buffer_text(&term3);
        assert!(s3.contains("Steer current run"));
        assert!(s3.contains("also cover narrow terminals"));
        assert!(s3.contains("steer"));
        assert!(s3.contains("tab queue"));
        assert!(s3.contains("1 pending"));
    }

    #[test]
    fn command_token_first_token_coloring() {
        // TUI v3 §8: the leading sigil token is colored so you SEE the mode as you type.
        let th = theme::Theme::dark();
        let (tok, rest, col) = command_token("/model foo", &th).expect("slash token");
        assert_eq!(tok, "/model");
        assert_eq!(rest, " foo");
        assert_eq!(col, th.accent);
        assert_eq!(
            command_token("!ls -la", &th).unwrap().2,
            th.warn,
            "! shell token = warn"
        );
        assert_eq!(command_token("@src/x.rs", &th).unwrap().0, "@src/x.rs");
        assert!(
            command_token("just a task", &th).is_none(),
            "plain prose has no command token"
        );
    }

    #[test]
    fn outcome_label_is_human_not_debug() {
        // TUI v3 §7: the status slot never shows `BudgetExhausted("max_turns")` Debug.
        assert_eq!(outcome_label(&Outcome::Done), "done");
        assert_eq!(outcome_label(&Outcome::Stuck), "stuck");
        assert_eq!(
            outcome_label(&Outcome::BudgetExhausted("max_turns")),
            "hit the turn budget"
        );
        let l = outcome_label(&Outcome::BudgetExhausted("max_usd"));
        assert!(
            !l.contains('"') && !l.contains("BudgetExhausted"),
            "no Debug tuple leak: {l}"
        );
    }

    #[test]
    fn welcome_is_a_responsive_core_wordmark_in_the_transcript() {
        let app = App::new();
        let wide: String = app.transcript[0]
            .render(80, &app.theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(wide.contains("██████╗"), "wordmark present: {wide:?}");
        assert!(
            wide.contains("Build, explain, and verify"),
            "tagline present: {wide:?}"
        );
        let rows = app.transcript[0].render(20, &app.theme, 0);
        for r in &rows {
            assert!(
                crate::render::line_width(r) <= 20,
                "narrow welcome stays within width"
            );
        }
        let narrow: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(narrow.contains("core"), "narrow Core marker: {narrow:?}");
    }

    #[test]
    fn welcome_wordmark_is_one_startup_block_and_scrolls_away() {
        let mut app = App::new();
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| matches!(block.kind, block::BlockKind::Welcome { .. }))
                .count(),
            1
        );
        let first = render_text(&mut app, 40, 12);
        assert!(first.contains("██████╗"));
        for index in 0..32 {
            app.push_user(format!(
                "later task {index}: keep the active transcript at the tail"
            ));
        }
        let tail = render_text(&mut app, 40, 12);
        assert!(!tail.contains("██████╗"), "the pet is entrance, not chrome");
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| matches!(block.kind, block::BlockKind::Welcome { .. }))
                .count(),
            1,
            "redraw and scrolling never duplicate the welcome"
        );
    }

    #[test]
    fn newest_line_visible_when_transcript_wraps() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(40, 12)).unwrap();
        let mut app = App::new();
        // many LONG lines that wrap at width 40, then a short newest line.
        for i in 0..40 {
            app.push(fg(Color::White), format!("row {i} {}", "x".repeat(80)));
        }
        app.push(fg(Color::White), "NEWESTMARKER");
        app.bottom_offset = 0; // pinned to bottom
        term.draw(|f| draw(f, &mut app)).unwrap();
        let content: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            content.contains("NEWESTMARKER"),
            "the newest line must render when earlier lines wrap (CRITICAL scroll fix)"
        );
    }

    #[test]
    fn slash_completion_menu_opens_and_accepts() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/mod");
        app.refresh_completion(&repo);
        let comp = app.completion.as_ref().expect("slash menu should open");
        assert!(
            comp.items.iter().any(|(n, _)| n == "model" || n == "mode"),
            "expected model/mode"
        );
        assert_eq!(comp.lead, '/');
        app.accept_completion();
        let text = app.editor.text();
        assert!(
            text.starts_with('/') && text.ends_with(' '),
            "accepted: {text:?}"
        );
    }

    #[test]
    fn slash_completion_enter_submits_optional_command_exactly_once() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/per");
        app.refresh_completion(&repo);
        assert!(
            app.accept_completion_for_enter(),
            "permissions is runnable without an argument and should activate on Enter"
        );
        assert_eq!(app.editor.text(), "/permissions ");
        assert!(app.completion.is_none());
        assert!(
            !app.accept_completion_for_enter(),
            "the consumed completion cannot emit a second submit signal"
        );
    }

    #[test]
    fn slash_completion_enter_keeps_required_arguments_editable() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/mem");
        app.refresh_completion(&repo);
        assert!(
            !app.accept_completion_for_enter(),
            "memory requires an argument, so Enter completes without dispatching"
        );
        assert_eq!(app.editor.text(), "/memory ");
        assert!(app.completion.is_none());
    }

    #[test]
    fn at_file_completion_lists_and_accepts() {
        let dir = std::env::temp_dir().join(format!("core-tuifc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hello.txt"), "x").unwrap();
        let mut app = App::new();
        app.editor.insert_str("look @hel");
        app.refresh_completion(&dir);
        let comp = app.completion.as_ref().expect("@file menu should open");
        assert_eq!(comp.lead, '@');
        assert!(comp.items.iter().any(|(p, _)| p == "hello.txt"));
        app.accept_completion();
        assert!(
            app.editor.text().contains("@hello.txt"),
            "got {:?}",
            app.editor.text()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_completion_replaces_whole_token_mid_cursor() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("/model");
        app.editor.home();
        for _ in 0..4 {
            app.editor.right();
        } // cursor in the middle: "/mod|el"
        app.refresh_completion(&repo);
        assert!(app.completion.is_some());
        app.accept_completion();
        let t = app.editor.text();
        assert!(
            t.starts_with("/model "),
            "whole token replaced, no leftover suffix: {t:?}"
        );
        assert!(
            !t.contains("modelel") && !t.contains("modele"),
            "no corruption: {t:?}"
        );
    }

    #[test]
    fn complete_path_refuses_traversal() {
        assert!(complete_path(std::path::Path::new("/tmp"), "../etc").is_empty());
        assert!(complete_path(std::path::Path::new("/tmp"), "/etc/passwd").is_empty());
    }

    #[test]
    fn no_menu_for_plain_text_or_multiline() {
        let mut app = App::new();
        let repo = std::env::temp_dir();
        app.editor.insert_str("just a task");
        app.refresh_completion(&repo);
        assert!(app.completion.is_none());
        app.editor.clear();
        app.editor.insert_str("/mode");
        app.editor.newline();
        app.refresh_completion(&repo);
        assert!(app.completion.is_none(), "no menu in multi-line");

        app.editor.clear();
        app.editor.insert_str("/mod");
        app.running = true;
        app.refresh_completion(&repo);
        assert!(
            app.completion.is_some(),
            "running follow-ups keep slash/@ completion"
        );
    }

    #[test]
    fn apply_event_updates_state() {
        let mut app = App::new();
        let before_start = app.transcript.len();
        apply_event(
            &mut app,
            UiEvent::ToolStart {
                id: "t1".into(),
                name: "read_file".into(),
                args: serde_json::json!({"path":"a"}),
            },
        );
        // Activity is immediate, but the transcript waits out the anti-flash reveal delay.
        assert!(!app.tool_index.contains_key("t1"));
        assert_eq!(app.pending_tools.len(), 1);
        assert_eq!(app.transcript.len(), before_start);
        assert!(app.active_tools.iter().any(|(id, _)| id == "t1"));
        let reveal_at = app.pending_tools.front().unwrap().reveal_deadline;
        assert!(app.advance_tool_presentations(reveal_at));
        assert!(app.tool_index.contains_key("t1"));
        assert!(
            app.transcript
                .last()
                .unwrap()
                .to_text()
                .contains("read_file")
        );
        // ToolEnd mutates the SAME card (by id, R2), not a new sibling
        let before = app.transcript.len();
        apply_event(
            &mut app,
            UiEvent::ToolEnd {
                id: "t1".into(),
                ok: true,
                exit_code: None,
                output: "ok".into(),
                diff: None,
            },
        );
        assert_eq!(
            app.transcript.len(),
            before,
            "ToolEnd mutates the originating card, not a new block"
        );
        let theme = theme::Theme::dark();
        let rendered: String = app
            .transcript
            .last()
            .unwrap()
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        // Completion is the marker + `  ⎿  ` connector summary now (no ✓ dingbat — TUI v3 §4).
        assert!(
            rendered.contains(block::CONNECTOR),
            "completed card shows the '  ⎿  ' result connector"
        );
        assert!(
            rendered.contains("Read"),
            "completed card shows the CC-style result summary"
        );
        assert!(
            !rendered.contains('✓'),
            "status is the marker color, not a ✓ glyph"
        );
        apply_event(
            &mut app,
            turn_end(
                0.05,
                Usage {
                    input: 50,
                    cache_read: 50,
                    ..Usage::default()
                },
            ),
        );
        assert_eq!(app.cost.usd(), Some(0.05));
        assert_eq!(
            app.last_turn_usage.map(|usage| usage.cache_hit_ratio()),
            Some(0.5)
        );
        app.track_steer("first".into());
        app.track_steer("second".into());
        apply_event(&mut app, UiEvent::SteerApplied { count: 1 });
        assert_eq!(app.steer_previews.len(), 1);
        assert_eq!(app.steer_previews.front().unwrap().text, "second");
    }

    #[test]
    fn tool_projection_is_hidden_for_300ms_then_reveals_deterministically() {
        let mut app = App::new();
        let base = app.transcript.len();
        let started = Instant::now();
        app.tool_start_at(
            "slow-read".into(),
            "read_file".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );

        assert_eq!(app.transcript.len(), base);
        assert!(app.active_tools.iter().any(|(id, _)| id == "slow-read"));
        assert!(
            !app.advance_tool_presentations(started + TOOL_REVEAL_DELAY - Duration::from_millis(1))
        );
        assert_eq!(app.transcript.len(), base);
        assert!(app.advance_tool_presentations(started + TOOL_REVEAL_DELAY));
        assert_eq!(app.transcript.len(), base + 1);
        assert!(app.tool_index.contains_key("slow-read"));
        assert!(matches!(
            app.transcript.last().map(|block| &block.kind),
            Some(block::BlockKind::Tool(block::ToolCard {
                status: block::ToolStatus::Running,
                ..
            }))
        ));
    }

    #[test]
    fn fast_tool_completion_inserts_one_settled_audit_card_without_running_flash() {
        let mut app = App::new();
        let base = app.transcript.len();
        let started = Instant::now();
        app.tool_start_at(
            "fast-read".into(),
            "read_file".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );
        app.tool_end_at(
            "fast-read",
            true,
            None,
            "1\tpub fn run() {}".into(),
            None,
            started + Duration::from_millis(42),
        );

        assert_eq!(app.transcript.len(), base + 1);
        assert!(app.pending_tools.is_empty());
        assert!(app.active_tools.is_empty());
        assert!(!app.tool_index.contains_key("fast-read"));
        let block::BlockKind::Tool(card) = &app.transcript.last().unwrap().kind else {
            panic!("expected a settled tool card");
        };
        assert_eq!(card.status, block::ToolStatus::Ok);
        assert_eq!(card.elapsed, Some(Duration::from_millis(42)));
        assert_eq!(card.output, "1\tpub fn run() {}");
    }

    #[test]
    fn run_completion_terminalizes_pending_and_revealed_tool_cards() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "pending".into(),
            "read_file".into(),
            serde_json::json!({"path":"a"}),
            started,
        );
        app.tool_start_at(
            "revealed".into(),
            "bash".into(),
            serde_json::json!({"command":"true"}),
            started,
        );
        assert!(app.advance_tool_presentations(started + TOOL_REVEAL_DELAY));

        app.settle_unfinished_tools();

        assert!(app.pending_tools.is_empty());
        assert!(app.tool_index.is_empty());
        assert!(app.active_tools.is_empty());
        let cards: Vec<_> = app
            .transcript
            .iter()
            .filter_map(|block| match &block.kind {
                block::BlockKind::Tool(card) => Some(card),
                _ => None,
            })
            .collect();
        assert_eq!(cards.len(), 2);
        assert!(
            cards
                .iter()
                .all(|card| card.status == block::ToolStatus::Err)
        );
        assert!(
            cards
                .iter()
                .all(|card| card.output.contains("without a terminal event"))
        );
    }

    #[test]
    fn fast_failures_and_diffs_are_never_suppressed() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "failed".into(),
            "grep".into(),
            serde_json::json!({"pattern":"needle"}),
            started,
        );
        app.tool_end_at(
            "failed",
            false,
            Some(2),
            "permission denied".into(),
            None,
            started + Duration::from_millis(10),
        );
        app.tool_start_at(
            "edited".into(),
            "edit".into(),
            serde_json::json!({"path":"src/lib.rs"}),
            started,
        );
        app.tool_end_at(
            "edited",
            true,
            None,
            "updated".into(),
            Some(core_protocol::FileDiff::from_replacement(
                "src/lib.rs",
                "old",
                "new",
            )),
            started + Duration::from_millis(20),
        );

        let cards = app
            .transcript
            .iter()
            .filter_map(|block| match &block.kind {
                block::BlockKind::Tool(card) => Some(card),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].status, block::ToolStatus::Err);
        assert_eq!(cards[0].output, "permission denied");
        assert!(cards[1].diff.is_some());
    }

    #[test]
    fn revealed_success_persists_beyond_the_hook_linger_floor() {
        let mut app = App::new();
        let started = Instant::now();
        app.tool_start_at(
            "visible".into(),
            "list_dir".into(),
            serde_json::json!({"path":"."}),
            started,
        );
        app.advance_tool_presentations(started + TOOL_REVEAL_DELAY);
        let count = app.transcript.len();
        app.tool_end_at(
            "visible",
            true,
            None,
            "src/lib.rs".into(),
            None,
            started + TOOL_REVEAL_DELAY + Duration::from_millis(1),
        );

        // Codex's hook cell lingers a quiet success for 600 ms. Core model-tool events are
        // audit-bearing and have no Ephemeral flag, so the stronger policy is to persist them.
        app.advance_tool_presentations(started + TOOL_REVEAL_DELAY + Duration::from_millis(601));
        assert_eq!(app.transcript.len(), count);
        assert!(matches!(
            app.transcript.last().map(|block| &block.kind),
            Some(block::BlockKind::Tool(block::ToolCard {
                status: block::ToolStatus::Ok,
                ..
            }))
        ));
    }

    #[test]
    fn workflow_events_mutate_one_live_card_and_collapse_on_success() {
        let mut app = App::new();
        let run_id = "workflow-9";
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::RunStarted {
                run_id: run_id.into(),
                name: "ultracode".into(),
                class: "multi-file".into(),
            }),
        );
        let block_count = app.transcript.len();
        let block_id = *app.workflow_index.get(run_id).expect("indexed workflow");
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PlanReady {
                run_id: run_id.into(),
                tasks: vec![core_kernel::WorkflowTaskUi {
                    id: 0,
                    label: "inspect the runtime".into(),
                }],
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: core_kernel::WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 4,
                writer_turn_reserve: 20,
                fan_wall_secs: 60,
                writer_wall_reserve_secs: 120,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                run_id: run_id.into(),
                phase: WorkflowPhaseUi::Exploring,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentStarted {
                run_id: run_id.into(),
                agent_id: 0,
                sub_run: "fan-0".into(),
                turn_budget: 4,
            }),
        );
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentActivity {
                run_id: run_id.into(),
                agent_id: 0,
                activity: "read_file · crates/kernel/src/lib.rs".into(),
            }),
        );
        let live = render_text(&mut app, 120, 32);
        assert!(live.contains("NOW"));
        assert!(live.contains("read_file"));
        assert!(live.contains("RESERVE"));
        assert!(live.contains("sequential"));
        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                run_id: run_id.into(),
                agent_id: 0,
                outcome: WorkflowAgentOutcomeUi::Done,
                turns: 2,
                tokens: 1_200,
                tool_calls: 3,
                elapsed_ms: 800,
                summary_preview: Some("found runtime owner".into()),
                error_preview: None,
            }),
        );
        assert_eq!(
            app.transcript.len(),
            block_count,
            "lifecycle updates must not append sibling log lines"
        );
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("workflow block");
        assert_eq!(card.status, block::WorkflowStatus::Exploring);
        assert_eq!(card.tasks[0].status, block::WorkflowTaskStatus::Done);
        assert_eq!(card.tasks[0].tokens, 1_200);

        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                run_id: run_id.into(),
                phase: WorkflowPhaseUi::Writing,
            }),
        );
        let writing = render_text(&mut app, 80, 24);
        assert!(writing.contains("writing"));
        assert!(writing.contains("WRITE"));

        apply_event(
            &mut app,
            UiEvent::Workflow(WorkflowUiEvent::RunFinished {
                run_id: run_id.into(),
                outcome: WorkflowRunOutcomeUi::Done,
                reason: None,
                elapsed_ms: 1_000,
                provider_attempts: 4,
                turns: 4,
                tokens: 2_000,
                tool_calls: 3,
                failed_tasks: 0,
                skipped_tasks: 0,
            }),
        );
        assert!(!app.workflow_index.contains_key(run_id));
        let card = app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
            .expect("workflow block");
        assert_eq!(card.status, block::WorkflowStatus::Done);
        assert!(
            !card.open,
            "an all-success workflow collapses to its summary"
        );
    }

    #[test]
    fn terminal_workflow_never_freezes_nonterminal_children_in_cache() {
        let mut app = App::new();
        let run_id = "workflow-stopped";
        app.workflow_event(WorkflowUiEvent::RunStarted {
            run_id: run_id.into(),
            name: "ultracode".into(),
            class: "multi-file".into(),
        });
        app.workflow_event(WorkflowUiEvent::PlanReady {
            run_id: run_id.into(),
            tasks: vec![
                core_kernel::WorkflowTaskUi {
                    id: 0,
                    label: "running child".into(),
                },
                core_kernel::WorkflowTaskUi {
                    id: 1,
                    label: "queued child".into(),
                },
            ],
            dropped: 0,
            duplicates_removed: 0,
            invalid_removed: 0,
            execution_mode: core_kernel::WorkflowExecutionModeUi::Sequential,
            fan_turn_budget: 6,
            writer_turn_reserve: 20,
            fan_wall_secs: 60,
            writer_wall_reserve_secs: 120,
        });
        app.workflow_event(WorkflowUiEvent::AgentStarted {
            run_id: run_id.into(),
            agent_id: 0,
            sub_run: "fan-0".into(),
            turn_budget: 3,
        });
        app.workflow_event(WorkflowUiEvent::RunFinished {
            run_id: run_id.into(),
            outcome: WorkflowRunOutcomeUi::Stopped,
            reason: Some("stopped by operator".into()),
            elapsed_ms: 500,
            provider_attempts: 1,
            turns: 0,
            tokens: 0,
            tool_calls: 0,
            failed_tasks: 1,
            skipped_tasks: 1,
        });
        let card = app
            .transcript
            .iter()
            .find_map(|block| match &block.kind {
                block::BlockKind::Workflow(card) if card.run_id == run_id => Some(card),
                _ => None,
            })
            .unwrap();
        assert!(
            card.tasks
                .iter()
                .all(|task| task.status == block::WorkflowTaskStatus::Unknown)
        );
        let screen = render_text(&mut app, 80, 24);
        assert!(screen.contains("stopped"));
        assert!(!screen.contains("running child  running"));
        assert!(!screen.contains("queued child  queued"));
    }

    #[test]
    fn cjk_text_does_not_panic_the_transcript() {
        // streamed multibyte text must not panic anywhere in the state path
        let mut app = App::new();
        app.stream_text("写代码 ");
        app.stream_text("测试😀");
        app.flush_text();
        assert!(app.transcript.iter().any(|b| b.to_text().contains("测试")));
    }

    #[test]
    fn huge_single_line_paste_cursor_does_not_overflow() {
        // round-4 review: display_col saturates at 65535, and the cursor-position math must not form
        // a >u16 intermediate (which panics with overflow-checks on, i.e. every debug/test build).
        // A single-line paste of >65535 display cells must draw cleanly.
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = App::new();
        app.editor.insert_str(&"a".repeat(66_000));
        term.draw(|f| draw(f, &mut app)).unwrap();
        // and with the cursor pulled back to the start (scroll_x == 0, cur_disp large is not in play,
        // but exercise the other branch) it must also be fine.
        app.editor.home();
        term.draw(|f| draw(f, &mut app)).unwrap();
    }

    #[test]
    fn turn_counter_increments_on_turn_end() {
        // The usage projection increments once per completed provider turn.
        let mut app = App::new();
        assert_eq!(app.turns, 0);
        apply_event(&mut app, turn_end(0.01, Usage::default()));
        apply_event(&mut app, turn_end(0.03, Usage::default()));
        assert_eq!(app.turns, 2, "turns++ per completed turn");
    }

    #[test]
    fn route_or_effort_change_clears_request_telemetry_but_not_static_capacity() {
        let usage = Usage {
            input: 10,
            cache_read: 20,
            ..Usage::default()
        };
        let mut app = App::new();
        app.last_turn_usage = Some(usage);
        app.last_context = Some(ContextEstimate {
            system_tokens: 1,
            tool_tokens: 2,
            transcript_tokens: 3,
            framing_tokens: 4,
            total_tokens: 10,
            provenance: core_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
        });
        app.model_context_window = Some(200_000);
        app.effort_application = Some(EffortApplication::Unsupported {
            requested: core_protocol::ReasoningEffort::High,
        });
        let mut ledger = core_obs::Ledger::new();
        ledger.last_turn_usage = Some(usage);

        clear_last_turn_telemetry(&mut app, &mut ledger);

        assert!(ledger.last_turn_usage.is_none());
        assert!(app.last_turn_usage.is_none());
        assert!(app.last_context.is_none());
        assert_eq!(app.model_context_window, Some(200_000));
        assert!(app.effort_application.is_none());
    }

    #[test]
    fn status_uses_last_turn_truth_and_never_invents_a_context_window() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.model = "gpt-5".into();
        app.provider_id = "openai".into();
        app.effort = Effort::High;
        let usage = Usage {
            input: 30,
            cache_read: 70,
            output: 9,
            ..Usage::default()
        };
        let mut event = turn_end(0.02, usage);
        if let UiEvent::TurnEnd {
            effort,
            model_context_window,
            ..
        } = &mut event
        {
            *effort = EffortApplication::Unsupported {
                requested: core_protocol::ReasoningEffort::High,
            };
            *model_context_window = None;
        }
        apply_event(&mut app, event);

        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|frame| draw(frame, &mut app)).unwrap();
        let screen = buffer_text(&term);
        assert!(screen.contains("cache 70%"), "cache is the last-turn ratio");
        assert!(
            screen.contains("context 100 used"),
            "unknown window reports only provider-observed input"
        );
        assert!(
            !screen.contains("context 120.0k") && !screen.contains("% left"),
            "the compaction trigger must never masquerade as a model window"
        );
        assert!(
            screen.contains("● high · not enforced"),
            "effort degradation is visible instead of implied exact"
        );
    }

    #[test]
    fn active_shelf_progressively_discloses_run_metrics() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new();
        app.running = true;
        app.status = "thinking".into();
        app.cost = CostState::Known {
            amount_microusd: 80_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        app.last_turn_usage = Some(Usage {
            input: 39,
            cache_read: 61,
            ..Usage::default()
        });
        app.turns = 4;
        app.effort = Effort::Ultracode;
        app.run_started = Some(Instant::now());
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let s = buffer_text(&term);
        let statusline = s.lines().last().unwrap_or_default();
        assert!(
            !statusline.contains('█') && !statusline.contains('░'),
            "statusline has no permanent gauge chrome: {statusline:?}"
        );
        assert!(s.contains("cache 61%"), "wide shelf shows cache-hit text");
        assert!(s.contains("turn 4"), "wide shelf shows the turn counter");
        assert!(s.contains("$0.08"), "wide shelf shows cost");
        assert!(s.contains("thinking"), "shelf shows the live phase word");
        assert!(
            s.contains("ultracode"),
            "shelf shows the special effort mode"
        );
        // m:ss run clock present (0:00 at t≈0).
        assert!(s.contains("0:0"), "HUD shows an m:ss run clock: {s:?}");
    }

    #[test]
    fn interrupt_state_replaces_stale_phase_in_active_shelf() {
        let mut app = App::new();
        app.running = true;
        app.interrupting = true;
        app.status = "verifying".into();
        let screen = render_text(&mut app, 80, 16);
        assert!(screen.contains("interrupt requested"));
        assert!(screen.contains("safe point"));
        assert!(!screen.contains("✢ verifying"));
    }

    #[test]
    fn export_path_is_workspace_confined_and_atomic() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("core-export-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("reports")).unwrap();
        assert!(confined_workspace_output(&root, "../outside").is_err());
        assert!(confined_workspace_output(&root, "/tmp/outside").is_err());
        let output = confined_workspace_output(&root, "reports/session.md").unwrap();
        atomic_replace(&output, b"first").unwrap();
        atomic_replace(&output, b"second").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"second");
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_symlink_target_and_parent_escape() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "core-export-symlink-{}-{nonce}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "core-export-outside-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("target"), "outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.join("target"), root.join("linked.md")).unwrap();
        assert!(confined_workspace_output(&root, "escape/new.md").is_err());
        assert!(confined_workspace_output(&root, "linked.md").is_err());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn init_directory_refuses_a_workspace_symlink() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("core-init-symlink-{}-{nonce}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("core-init-outside-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".core")).unwrap();

        assert!(ensure_real_workspace_dir(&root, ".core").is_err());
        assert!(!outside.join("config.json").exists());

        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }
}

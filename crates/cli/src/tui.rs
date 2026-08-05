//! The interactive TUI (ratatui + crossterm) — the product face, like Codex/Claude Code.
//!
//! Layout: a full-width semantic transcript; an on-demand activity shelf and explicit steer/after-
//! turn lanes; one framed composer; contextual help; and a stable bottom status line. Metrics
//! progressively disclose instead of becoming permanent dashboard chrome. Ctrl-C/Esc request a
//! safe-point stop; Ctrl-D drains active work (or quits when idle); Ctrl-T toggles terminal-native
//! selection; Esc quits when idle.
//!
//! The agent runs in a background task and streams `UiEvent`s over a channel; the render loop
//! drains them and redraws. The kernel does the work; this is a thin, replaceable front-end
//! on the same core (ADR-010: frontends are adapters).

#[cfg(target_os = "linux")]
mod capability_fs;
mod clipboard;
pub(crate) mod hyperlink;
mod keyboard_enhancement;
mod mouse_capture;
mod notification;
mod terminal_input;
pub(crate) mod transcript_effect;
mod transcript_export;
mod transcript_viewer;
mod tunables_view;

pub(crate) mod app_server;
pub(crate) mod headless;
use crate::commands::{self, SlashCommand};
use crate::config::PromptHistoryMode;
use crate::editor::Editor;
use crate::file_input;
use crate::image_input::{self, ImageAttachments};
use crate::providers::{ModelSelection, ProviderDirectory};
use crate::route::RouteView;
use crate::runtime::{
    UiEvent, WorkflowAgentOutcomeUi, WorkflowPhaseUi, WorkflowRunOutcomeUi, WorkflowUiEvent,
};
use crate::{block, keymap, prompt_history, startup, surface, theme};
use core_ctx::ContextEstimate;
use core_obs::CostState;
use core_protocol::{
    Capability, Effort, Op, PermissionMode, PermissionRules, ReasoningEffort, SubmissionId, Usage,
    Verdict,
};
use core_provider::EffortApplication;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as CEvent, KeyCode, KeyEventKind,
    KeyModifiers, MouseButton, MouseEventKind,
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
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;

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

/// Everything the frontend holds of the runtime: queue endpoints, a negotiated version, and the
/// facts that cannot change for the life of the session.
///
/// This replaces `Option<Agent>`. The frontend used to own the runtime outright and encode "a run is
/// in flight" as "the slot is empty" — which is why `/model`, `/effort` and `/compact` were
/// unreachable mid-turn: the borrow checker, not the design, was enforcing it. The `Agent` now lives
/// in the App Server task and the frontend reaches it only through the wire.
pub(crate) struct Session {
    /// The versioned SQ client. Every `Op` the frontend sends goes through this and nothing else.
    client: app_server::AppServerClient,
    /// The control plane. See `app_server::Control` for why these are not `Op`s.
    control: tokio::sync::mpsc::Sender<app_server::ControlRequest>,
    /// Runtime state the status line mirrors. Refreshed from every control reply and from the
    /// terminal event of every turn — the frontend never reads it off an `Agent` again.
    state: app_server::SessionSnapshot,
    /// Facts fixed for the session, captured once at composition. Reading these used to require the
    /// `Agent` to be idle in the frontend's hands.
    facts: app_server::SessionFacts,
}

impl Session {
    fn new(
        handle_client: app_server::AppServerClient,
        control: tokio::sync::mpsc::Sender<app_server::ControlRequest>,
        state: app_server::SessionSnapshot,
        facts: app_server::SessionFacts,
    ) -> Self {
        Self {
            client: handle_client,
            control,
            state,
            facts,
        }
    }

    // Accessors mirroring the shapes the frontend used to read straight off the `Agent`. Keeping
    // the names lets the call sites stay readable; what changed is where the value comes from —
    // a snapshot the server published, or a fact captured once at composition.
    pub(crate) fn workspace(&self) -> &std::path::Path {
        &self.facts.workspace
    }

    pub(crate) fn memory_workspace(&self) -> Option<&std::path::Path> {
        self.facts.memory_workspace.as_deref()
    }

    pub(crate) fn rollout_path(&self) -> &std::path::Path {
        &self.facts.rollout_path
    }

    pub(crate) fn model(&self) -> &str {
        &self.state.model
    }

    pub(crate) fn effort(&self) -> Effort {
        self.state.effort
    }

    pub(crate) fn permission_mode(&self) -> PermissionMode {
        self.state.mode
    }

    pub(crate) fn permission_rules(&self) -> &PermissionRules {
        &self.state.permission_rules
    }

    pub(crate) fn ledger_summary(&self) -> &str {
        &self.state.ledger_summary
    }

    /// Provider quota from the last response's headers, if the route publishes any (I-53).
    pub(crate) fn rate_limit(&self) -> Option<&str> {
        self.state.rate_limit.as_deref()
    }

    pub(crate) fn compaction_trigger_tokens(&self) -> usize {
        self.facts.compaction_trigger_tokens
    }

    /// A session wired to a bare SQ, for tests that assert on what the frontend submits. Test-only
    /// so that production code has exactly one way to obtain a `Session`: `app_server::wire`.
    #[cfg(test)]
    pub(crate) fn for_test(
        submissions: tokio::sync::mpsc::Sender<core_protocol::SqEnvelope>,
    ) -> Self {
        let (control, _control_rx) = tokio::sync::mpsc::channel(1);
        Self {
            client: app_server::AppServerClient::connect(
                core_protocol::PROTOCOL_VERSION,
                submissions,
            )
            .expect("the in-process server speaks the current protocol"),
            control,
            state: app_server::SessionSnapshot {
                mode: core_protocol::PermissionMode::default(),
                effort: core_protocol::Effort::default(),
                model: "test-model".into(),
                cost: core_obs::CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
            },
            facts: app_server::SessionFacts {
                workspace: std::path::PathBuf::new(),
                memory_workspace: None,
                rollout_path: std::path::PathBuf::new(),
                compaction_trigger_tokens: 0,
                initial_model_context_window: None,
                registry_tools: Vec::new(),
                agent_catalog: Arc::new(core_agents::AgentCatalog::builtin_only()),
            },
        }
    }

    pub(crate) fn registry_tools(&self) -> &[app_server::ToolFact] {
        &self.facts.registry_tools
    }

    /// The execution catalog captured by the App Server at attach time. This is deliberately not
    /// reconstructed from `workspace` or an ambient operator home: those paths may drift while the
    /// resident runtime continues resolving children against this immutable snapshot.
    pub(crate) fn agent_catalog(&self) -> &core_agents::AgentCatalog {
        &self.facts.agent_catalog
    }

    /// Adopt the runtime state carried by a terminal event.
    pub(crate) fn adopt(&mut self, snapshot: app_server::SessionSnapshot) {
        self.state = snapshot;
    }

    /// Follow the runtime onto another run.
    ///
    /// `rollout_path` is the one session fact that is NOT a session invariant once a session can
    /// change runs in place. Everything else in `SessionFacts` is per-process — the workspace, the
    /// pinned agent catalog, the registered tools — and deliberately survives. Leaving the old path
    /// here would point `/sessions`, `/rewind` and the transcript export at the run this session
    /// just left.
    pub(crate) fn adopt_run(
        &mut self,
        rollout_path: std::path::PathBuf,
        snapshot: app_server::SessionSnapshot,
    ) {
        self.facts.rollout_path = rollout_path;
        self.state = snapshot;
    }

    /// Submit one operation on the SQ.
    pub(crate) fn submit(&self, op: Op) -> Result<(), app_server::SubmitError> {
        self.client.submit(op)
    }

    /// Make one control request and wait for its answer.
    ///
    /// Returns `None` when the server is gone. The round trip is what makes the answer trustworthy:
    /// the frontend renders the state the runtime actually reached, not the state it asked for.
    pub(crate) async fn control(
        &mut self,
        control: app_server::Control,
    ) -> Option<app_server::ControlReply> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.control
            .send(app_server::ControlRequest {
                control,
                reply: reply_tx,
            })
            .await
            .ok()?;
        let reply = reply_rx.await.ok()?;
        if let app_server::ControlReply::State(snapshot) = &reply {
            self.state = (**snapshot).clone();
        }
        Some(reply)
    }
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
pub(crate) fn ui_safe_text(text: &str) -> String {
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

/// Invisible directional/formatting characters and terminal controls are unsafe in every bounded
/// TUI display/query projection. Keep this predicate shared so filtering and rendered Detail text
/// cannot disagree about which code points are admitted.
fn is_unsafe_display_char(character: char) -> bool {
    let value = character as u32;
    character.is_control()
        || matches!(
            value,
            0x061c
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
        )
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

#[derive(Debug, Clone, Copy)]
struct ComposerHitbox {
    text_area: Rect,
    scroll_x: u16,
    scroll_y: u16,
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
    /// Take over that recorded run in THIS process: the live session adopts its journal, identity
    /// and transcript. The documented restart command remains the fallback when a run cannot be
    /// adopted here — another process holding its writer lock is the ordinary case.
    AdoptRun(String),
    /// Open one bounded, read-only L1 detail panel from the tunables L0 registry picker.
    InspectTunable(tunables_view::Detail),
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
const MAX_PICKER_QUERY_BYTES: usize = MAX_PICKER_QUERY_CHARS * 4;
const MAX_PICKER_PASTE_SCAN_BYTES: usize = 4 * 1024;

impl Picker {
    /// Append terminal text to the modal's filter without letting controls, invisible formatting,
    /// or an arbitrarily large bracketed paste enter retained UI state. Whitespace becomes one
    /// ordinary separator so a multiline paste remains a predictable multi-term query.
    fn append_query_text(&mut self, text: &str) {
        let mut query_chars = self.query.chars().count();
        let mut scanned_bytes = 0usize;
        for source in text.chars() {
            scanned_bytes = scanned_bytes.saturating_add(source.len_utf8());
            if scanned_bytes > MAX_PICKER_PASTE_SCAN_BYTES || query_chars >= MAX_PICKER_QUERY_CHARS
            {
                break;
            }
            let character = if source.is_whitespace() {
                if self.query.is_empty() || self.query.ends_with(' ') {
                    continue;
                }
                ' '
            } else if is_unsafe_display_char(source) {
                continue;
            } else {
                source
            };
            if self.query.len().saturating_add(character.len_utf8()) > MAX_PICKER_QUERY_BYTES {
                break;
            }
            self.query.push(character);
            query_chars += 1;
        }
    }

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

/// The filesystem half of the drop discriminator. `symlink_metadata` answers for a dangling
/// symlink too, and never follows one.
fn path_exists_on_disk(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `commands::slash_command_body` bound to the real filesystem: the single place the frontend
/// decides whether a leading `/` opens a command or is a file the operator dropped on the
/// terminal. Every lane that can consume a draft — Enter while idle, Enter/Tab while running, and
/// the after-turn queue drain — asks this one question, so a drop cannot be a path in one lane and
/// a command in another.
fn slash_command_body(text: &str) -> Option<&str> {
    commands::slash_command_body(text, &path_exists_on_disk)
}

fn input_destination(running: bool, text: &str) -> InputDestination {
    if !running {
        InputDestination::StartTurn
    } else if slash_command_body(text).is_some() || text.trim_start().starts_with('!') {
        // `!` keeps the bare-prefix test: it is unambiguous local-shell intent, and a dropped
        // absolute path never starts with it (a drop that did would still be shell input, which is
        // what `!` promises).
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

/// How long a model request may go without a first token before the interface stops calling it
/// ordinary, and before it stops calling it merely slow. Both sit well inside the 60s response
/// header deadline and the 120s stream idle deadline, which is the point: the operator learns
/// which failure they are watching while the request is still open (I-64).
const FIRST_TOKEN_SLOW_AFTER: std::time::Duration = std::time::Duration::from_secs(10);
/// The one-keystroke retry offer printed under a failed run (I-39).
const RETRY_HINT: &str = "ctrl+r re-sends this turn. Whatever the model had already streamed is \
recorded as an interrupted message, so a retry continues from it rather than from nothing.";
const FIRST_TOKEN_STALL_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether a silent provider is being described as slow or as stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstTokenState {
    Slow,
    Stalled,
}

/// A first-token wait long enough to say something about.
#[derive(Debug, Clone, Copy)]
struct FirstTokenStall {
    state: FirstTokenState,
    waited: std::time::Duration,
}

impl FirstTokenStall {
    fn label(self) -> String {
        let seconds = self.waited.as_secs();
        match self.state {
            FirstTokenState::Slow => format!("waiting for the first token · {seconds}s"),
            FirstTokenState::Stalled => format!(
                "no response for {seconds}s · the connection may be stalled · esc to interrupt"
            ),
        }
    }
}

/// TUI state.
struct App {
    /// The structured semantic transcript (ADR-015): typed self-rendering blocks, not a flat log.
    transcript: Vec<Arc<block::Block>>,
    /// Fullscreen, presentation-only inspection state. Its bounded index reconciles against the
    /// authoritative transcript's stable ids and revisions only when this authority revision
    /// changes; ordinary redraws never rescan or refold transcript bytes.
    transcript_viewer: transcript_viewer::Viewer,
    /// Monotonic notification for semantic transcript insertions, mutations, clears, and eviction.
    /// This is the O(1) stable-frame seam for the fullscreen viewer.
    transcript_revision: u64,
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
    /// QuickJS `core-workflow` run id -> its one live phase→agent tree card (design §3.2 store).
    /// The interactive-REPL seam, driven by `workflow_run_ui_event` (ADR-0001 step 1).
    workflow_run_index: std::collections::HashMap<String, u64>,
    /// The active color theme (ADR-015 §4).
    theme: theme::Theme,
    /// Captured once at startup; runtime `/theme` previews are projected to the same terminal depth.
    color_depth: theme::capabilities::ColorDepth,
    theme_epoch: u64,
    /// Session-stable, conservatively admitted OSC 8 support and local-link workspace boundary.
    hyperlink_policy: hyperlink::Policy,
    /// Settled semantic blocks render once per width/theme/revision. Active blocks bypass this cache
    /// so spinner and workflow state remain live.
    /// One render slot per settled block. Replacing the `(revision, rows)` tuple on mutation keeps
    /// repeated fold/unfold cycles bounded instead of retaining every historical revision.
    render_cache: std::collections::HashMap<u64, (u64, crate::render::RenderedLines)>,
    render_cache_width: u16,
    render_cache_theme_epoch: u64,
    editor: Editor,
    status: String,
    /// The canonical result-v5 object from the most recently terminalized run.
    ///
    /// TUI chrome is presentation, but it must consume the same terminal authority as one-shot and
    /// headless. Keeping the object (rather than a Debug-formatted completion string) also gives
    /// parity tests one typed seam to inspect without scraping terminal cells.
    last_result: Option<serde_json::Value>,
    running: bool,
    interrupting: bool,
    draining: bool,
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
    /// Captured delivers wheel/click events to Core; released gives mouse ownership back to the
    /// terminal for native text selection and copying.
    mouse_capture: mouse_capture::State,
    /// Truthful projection of the live keymap/Vim state; updated before routing each key.
    keymap_status: String,
    /// Char index the visual selection is anchored at; `None` outside visual mode.
    vim_anchor: Option<usize>,
    // live-accumulating current assistant paragraph (so streamed text coalesces into one line)
    cur_text: String,
    cur_text_revision: u64,
    cur_doc_revision: u64,
    cur_doc: Option<crate::markdown::MarkdownDoc>,
    /// How much of `cur_doc` is settled, so a delta re-parses only the tail it changed. Reset with
    /// `cur_doc` on every stream boundary.
    cur_doc_parse: crate::markdown::StreamingParse,
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
    /// THE resolved route: provider, model, api_root, adapter, credential source, catalog
    /// provenance and the run's effective limits. Every display reads this and derives nothing of
    /// its own, so what is on screen is the request that goes out (I-26).
    route: RouteView,
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
    /// The text of the last plain-text turn, retained only while a failed run offers to re-send
    /// it. A mid-stream failure is not retried automatically — only 429/529 are, and a bare
    /// transport error says nothing about whether the provider already billed the request — so
    /// the operator is the idempotency key, and this makes saying yes one keystroke (I-39).
    retryable_task: Option<String>,
    /// When the model phase began without a token yet arriving, and `None` again the instant one
    /// does. The response-header deadline is 60s and the stream idle deadline 120s, so without
    /// this a dead connection and a slow prefill looked identical for a full minute (I-64). It is
    /// the frontend end of the same first-token instrumentation `TurnEnd.ttft_ms` records.
    awaiting_first_token_since: Option<Instant>,
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
    /// Text-cell projection from the last rendered composer frame. A click is resolved against this
    /// snapshot; every coordinate is re-clamped by the editor so a simultaneous resize is benign.
    composer_hitbox: Option<ComposerHitbox>,
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
    #[cfg(test)]
    fn new() -> Self {
        let environment = theme::capabilities::Environment::capture();
        let detected = theme::Theme::detect_with(environment, None);
        Self::new_with_detected_theme(detected)
    }

    fn new_with_detected_theme(detected: theme::DetectedTheme) -> Self {
        let theme::DetectedTheme { theme, color_depth } = detected;
        // The pet landing is a one-time terminal-native signature in the transcript, not permanent
        // chrome. It progressively collapses with width and naturally scrolls away after work starts.
        let welcome = block::Block::new(
            0,
            block::BlockKind::Welcome {
                tagline: "Core Code · Build, explain, and verify".into(),
            },
        );
        App {
            transcript: vec![Arc::new(welcome)],
            transcript_viewer: transcript_viewer::Viewer::default(),
            transcript_revision: 0,
            next_id: 1,
            tool_index: std::collections::HashMap::new(),
            pending_tools: VecDeque::new(),
            workflow_index: std::collections::HashMap::new(),
            workflow_run_index: std::collections::HashMap::new(),
            theme,
            color_depth,
            theme_epoch: 0,
            hyperlink_policy: hyperlink::Policy::disabled(),
            render_cache: std::collections::HashMap::new(),
            render_cache_width: 0,
            render_cache_theme_epoch: 0,
            editor: Editor::new(),
            status: "idle".into(),
            last_result: None,
            running: false,
            interrupting: false,
            draining: false,
            bottom_offset: 0,
            follow_tail: true,
            unread_updates: 0,
            last_total_rows: 0,
            last_view_h: 0,
            quit: false,
            mouse_capture: mouse_capture::State::default(),
            keymap_status: "keys:standard".into(),
            vim_anchor: None,
            cur_text: String::new(),
            cur_text_revision: 0,
            cur_doc_revision: 0,
            cur_doc: None,
            cur_doc_parse: crate::markdown::StreamingParse::default(),
            text_scrubber: crate::output::StreamingScrubber::default(),
            cur_think: String::new(),
            thinking_scrubber: crate::output::StreamingScrubber::default(),
            mode: PermissionMode::default(),
            effort: Effort::default(),
            model: String::new(),
            route: RouteView::unresolved(),
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
            retryable_task: None,
            awaiting_first_token_since: None,
            active_tools: VecDeque::new(),
            spin: 0,
            row_map: Vec::new(),
            view_top: 0,
            view_scroll: 0,
            view_h: 0,
            composer_hitbox: None,
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
        self.transcript.push(Arc::new(block::Block::new(id, kind)));
        self.mark_transcript_changed();
        self.autoscroll();
        id
    }

    fn mark_transcript_changed(&mut self) {
        self.transcript_revision = self.transcript_revision.wrapping_add(1);
    }

    /// Echo the operator's submitted prompt as a User block.
    fn push_user(&mut self, text: impl Into<String>) {
        self.flush_text();
        self.push_block(block::BlockKind::User(ui_safe_text(&text.into())));
    }

    /// How long the provider has been silent since the model phase opened, and whether that is
    /// merely slow or long enough to describe as stalled. `None` once a token has arrived, when no
    /// model request is open, or while the wait is still ordinary (I-64).
    fn first_token_stall(&self) -> Option<FirstTokenStall> {
        if !self.running {
            return None;
        }
        let waited = self.awaiting_first_token_since?.elapsed();
        let state = if waited >= FIRST_TOKEN_STALL_AFTER {
            FirstTokenState::Stalled
        } else if waited >= FIRST_TOKEN_SLOW_AFTER {
            FirstTokenState::Slow
        } else {
            return None;
        };
        Some(FirstTokenStall { state, waited })
    }

    /// Append streamed assistant text; the in-flight buffer renders as a live markdown block.
    fn stream_text(&mut self, delta: &str) {
        // A token arrived: this connection is slow at worst, not stalled (I-64).
        self.awaiting_first_token_since = None;
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
        // Extended thinking is the model producing tokens, so it stops the stall clock exactly
        // like text does — the same rule `TurnEnd.ttft_ms` already measures by (I-64).
        self.awaiting_first_token_since = None;
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

    /// When the next queued tool card stops being suppressed, so the render loop can sleep exactly
    /// that long instead of polling for it.
    fn next_tool_reveal(&self) -> Option<Instant> {
        self.pending_tools
            .front()
            .map(|pending| pending.reveal_deadline)
    }

    /// Advance the anti-flash timer. Passing `now` makes the state machine deterministic in tests;
    /// production calls it once per render-loop wakeup, scheduled by `next_tool_reveal`.
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
            && let block::BlockKind::Tool(card) = &mut Arc::make_mut(b).kind
        {
            card.status = status;
            card.output = output;
            card.diff = diff;
            card.exit_code = exit_code;
            card.elapsed = Some(now.saturating_duration_since(card.started));
            Arc::make_mut(b).touch();
            self.tool_index.remove(id);
            self.mark_transcript_changed();
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
            .map(Arc::make_mut)
            .and_then(|block| match &mut block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
    }

    /// Project one id-correlated kernel lifecycle update into one live workflow card.
    fn workflow_event(&mut self, event: WorkflowUiEvent) {
        let existing_block_id = match &event {
            WorkflowUiEvent::RunStarted { run_id, .. }
            | WorkflowUiEvent::PlanReady { run_id, .. }
            | WorkflowUiEvent::PhaseChanged { run_id, .. }
            | WorkflowUiEvent::AgentStarted { run_id, .. }
            | WorkflowUiEvent::AgentActivity { run_id, .. }
            | WorkflowUiEvent::AgentFinished { run_id, .. }
            | WorkflowUiEvent::RunFinished { run_id, .. } => {
                self.workflow_index.get(run_id).copied()
            }
        };
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
                    execution_mode: crate::runtime::WorkflowExecutionModeUi::Direct,
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
            if let Some(block_id) = existing_block_id
                && let Some(block) = self
                    .transcript
                    .iter_mut()
                    .find(|block| block.id == block_id)
            {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed();
            self.autoscroll();
        }
    }

    /// Project one script-engine lifecycle message onto the live phase→agent tree (ADR-0001 step 1,
    /// `crate::workflow::WorkflowRunUiEvent`).
    ///
    /// The three shapes are the three things the card needs that the `ProgressEvent` stream cannot
    /// say on its own: when a run BEGINS (so the card exists, named, with its declared phase boxes
    /// already laid out), what happened next, and when the run SETTLED — `ingest` never sets
    /// `finished`, so without the last one the tree would spin for the rest of the session. The
    /// match is total: a new seam variant does not compile until it is rendered.
    fn workflow_run_ui_event(&mut self, event: crate::workflow::WorkflowRunUiEvent) {
        match event {
            crate::workflow::WorkflowRunUiEvent::Started {
                run_id,
                name,
                phases,
            } => self.workflow_run_started(&run_id, &name, &phases),
            // The name is only read if `Started` never arrived, which the EQ's authoritative
            // delivery rules out; `list_runs` uses the same word for a run whose manifest is
            // missing, so an unnamed card reads the same way there and here.
            crate::workflow::WorkflowRunUiEvent::Progress { run_id, event } => {
                self.workflow_run_event(&run_id, "workflow", event)
            }
            crate::workflow::WorkflowRunUiEvent::Finished { run_id } => {
                self.workflow_run_finished(&run_id)
            }
        }
    }

    /// Open the card for a run before its first event, seeded with the script's declared
    /// `meta.phases` so the whole shape of the run is on the first frame. Idempotent: a repeated
    /// `Started` for a live run re-declares nothing (`declare_phases` skips titles it already has).
    fn workflow_run_started(&mut self, run_id: &str, name: &str, phases: &[String]) {
        if self.workflow_run_card_mut(run_id).is_none() {
            self.flush_text();
            let card = block::WorkflowRunCard::new(
                ui_safe_text(run_id),
                crate::workflow::ui_safe_label(name),
            );
            let block_id = self.push_block(block::BlockKind::WorkflowRun(card));
            self.workflow_run_index.insert(run_id.to_string(), block_id);
        }
        let block_id = self.workflow_run_index.get(run_id).copied();
        if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.declare_phases(
                phases
                    .iter()
                    .map(|title| crate::workflow::ui_safe_label(title)),
            );
        }
        if let Some(block) =
            block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
        {
            Arc::make_mut(block).touch();
        }
        self.mark_transcript_changed();
        self.autoscroll();
    }

    // REPL seam (see workflow_run_index). Live since ADR-0001 step 1: `app_server::ServerEvent`
    // carries the engine's progress off the kernel thread and `workflow_run_ui_event` lands it here.
    fn workflow_run_card_mut(&mut self, run_id: &str) -> Option<&mut block::WorkflowRunCard> {
        let block_id = *self.workflow_run_index.get(run_id)?;
        self.transcript
            .iter_mut()
            .find(|block| block.id == block_id)
            .map(Arc::make_mut)
            .and_then(|block| match &mut block.kind {
                block::BlockKind::WorkflowRun(card) => Some(card),
                _ => None,
            })
    }

    /// Upsert one QuickJS `core-workflow` progress event into its one live phase→agent tree card
    /// (design §3.2), creating the card on first sight of a run id. This is the interactive-TUI seam
    /// for a workflow launched from the REPL; the one-shot `core workflow run` command drives an
    /// equivalent card through its own live loop (`workflow::run_live`). Wired up by ADR-0001
    /// step 1 (docs/project/decisions/0001-workflow-renderer-convergence.md).
    fn workflow_run_event(
        &mut self,
        run_id: &str,
        name: &str,
        event: core_workflow::events::ProgressEvent,
    ) {
        if self.workflow_run_card_mut(run_id).is_none() {
            self.flush_text();
            let card = block::WorkflowRunCard::new(ui_safe_text(run_id), ui_safe_text(name));
            let block_id = self.push_block(block::BlockKind::WorkflowRun(card));
            self.workflow_run_index.insert(run_id.to_string(), block_id);
        }
        let changed = if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.ingest(event);
            true
        } else {
            false
        };
        if changed {
            let block_id = self.workflow_run_index.get(run_id).copied();
            if let Some(block) =
                block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
            {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed();
        }
        self.autoscroll();
    }

    /// Mark a QuickJS workflow run terminal (its engine future resolved). The card collapses finished
    /// agents but stays in the transcript.
    fn workflow_run_finished(&mut self, run_id: &str) {
        let block_id = self.workflow_run_index.get(run_id).copied();
        let changed = if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.finished = true;
            true
        } else {
            false
        };
        if changed {
            if let Some(block) =
                block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
            {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed();
        }
        self.workflow_run_index.remove(run_id);
        self.autoscroll();
    }

    /// Toggle the fold of a collapsible block at transcript index `i`.
    fn toggle_fold(&mut self, i: usize) {
        if let Some(b) = self.transcript.get_mut(i) {
            let b = Arc::make_mut(b);
            let changed = match &mut b.kind {
                block::BlockKind::Tool(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::Workflow(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::WorkflowRun(c) => {
                    // The verbose toggle (design §3.3): reveal every finished agent, or collapse them.
                    c.verbose = !c.verbose;
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
                self.mark_transcript_changed();
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
            && !is_unsafe_display_char(ch)
        {
            let pk = self.picker.as_mut()?;
            let mut encoded = [0; 4];
            pk.append_query_text(ch.encode_utf8(&mut encoded));
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

    /// Bracketed paste belongs to an open picker just like keypresses do. Returning `false` means
    /// no picker was open; returning `true` means the event was fully consumed and must never reach
    /// the composer or image-attachment parser.
    fn picker_paste(&mut self, pasted: &str) -> bool {
        let Some(picker) = self.picker.as_mut() else {
            return false;
        };
        picker.append_query_text(pasted);
        let visible = picker.visible_indices();
        picker.normalize_selection(&visible);
        true
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
        self.theme = self.color_depth.project_theme(theme);
        self.theme_epoch = self.theme_epoch.wrapping_add(1);
        self.render_cache.clear();
    }

    /// Adopt a theme that late terminal evidence detected AFTER the first frame was painted.
    /// Detection now happens behind the frame, so an identical result must stay a no-op: bumping
    /// the epoch would throw away a warm render cache for a repaint nobody can see.
    fn adopt_detected_theme(&mut self, detected: theme::DetectedTheme) -> bool {
        if detected.theme == self.theme {
            return false;
        }
        self.set_theme(detected.theme);
        true
    }

    /// The fallback after an adoption this process could not perform — most often because another
    /// `core` process holds that run's exclusive writer lock, which no amount of retrying here will
    /// change. The command is display/copy state only; nothing executes it.
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
///
/// Even though the operator is the human at the keyboard, the process spawn is still a
/// `CodeExecuting` effect and MUST pass the same capability broker (`core_protocol::gate`) as the
/// agent's own shell tool — otherwise a Plan-mode ("explore, don't touch") session, or an explicit
/// `/permissions deny code_executing`, would be silently punched through by a `!cmd`. A `Deny`
/// verdict refuses the spawn; `Ask`/`Auto` proceed (the operator's own keystroke is the approval).
async fn run_bash_inline(
    app: &mut App,
    repo: &std::path::Path,
    cmd: &str,
    credential_env_names: &[String],
    mode: PermissionMode,
    rules: &PermissionRules,
) {
    if cmd.is_empty() {
        return;
    }
    // The capability broker, not the `!` parser, decides whether code may run. This is the exact
    // gate the kernel applies to the model's `bash` tool: it is a pure function the operator cannot
    // accidentally bypass, so the operator escape hatch can never be a hole in a read-only posture.
    if core_protocol::gate(mode, rules, "bash", Capability::CodeExecuting) == Verdict::Deny {
        app.push_block(block::BlockKind::Error {
            title: "operator shell blocked by permission mode".into(),
            detail: ui_safe_text(&format!(
                "{} mode denies code execution; the operator `!` shell routes through the same capability gate as the agent. blocked command: {cmd}",
                mode.label()
            )),
            open: true,
        });
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

/// Resolve a terminal-cell click into the editor's character-index coordinate system.
///
/// Wide characters deliberately divide their two cells: clicking the leading cell lands before the
/// scalar and clicking the trailing cell lands after it. Combining marks remain attached to the
/// previous printable character. Rows and columns past the current draft clamp to its final
/// boundary, which is the only safe answer for a click racing a resize or edit.
fn editor_char_index_at_cell(text: &str, wanted_row: usize, wanted_col: u16) -> usize {
    let mut absolute = 0usize;
    for (row, line) in text.split('\n').enumerate() {
        if row != wanted_row {
            absolute = absolute
                .saturating_add(line.chars().count())
                .saturating_add(1);
            continue;
        }

        let mut cell = 0u16;
        let mut chars = 0usize;
        for character in line.chars() {
            let width = char_width(character);
            if width == 0 {
                chars = chars.saturating_add(1);
                continue;
            }
            if wanted_col < cell.saturating_add(width) {
                let trailing_half = wanted_col.saturating_sub(cell) >= width.div_ceil(2);
                return absolute
                    .saturating_add(chars)
                    .saturating_add(usize::from(trailing_half));
            }
            cell = cell.saturating_add(width);
            chars = chars.saturating_add(1);
        }
        return absolute.saturating_add(chars);
    }
    text.chars().count()
}

fn place_editor_cursor_from_mouse(app: &mut App, column: u16, row: u16) -> bool {
    let Some(hitbox) = app.composer_hitbox else {
        return false;
    };
    let area = hitbox.text_area;
    if column < area.x || column >= area.right() || row < area.y || row >= area.bottom() {
        return false;
    }
    let logical_row = hitbox.scroll_y.saturating_add(row.saturating_sub(area.y)) as usize;
    let logical_col = hitbox
        .scroll_x
        .saturating_add(column.saturating_sub(area.x));
    let char_index = editor_char_index_at_cell(&app.editor.text(), logical_row, logical_col);
    app.editor.set_cursor(char_index);
    true
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
fn restore_terminal(keyboard: &keyboard_enhancement::Restorer) {
    // Keep every cleanup independent: a broken/closing terminal can reject one escape while still
    // accepting the rest. One multi-command `execute!` would stop at the first write failure and
    // could leave the shell cursor hidden or its style inverted after a picker/signal exit.
    let mut stdout = std::io::stdout();
    let _ = keyboard.restore(&mut stdout);
    restore_terminal_modes(&mut stdout);
}

fn restore_terminal_modes(stdout: &mut impl Write) {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(stdout, DisableBracketedPaste);
    let _ = mouse_capture::release(stdout);
    let _ = execute!(stdout, cursor::Show);
    let _ = execute!(
        stdout,
        crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
    );
    let _ = execute!(stdout, crossterm::style::ResetColor);
    let _ = execute!(stdout, terminal::LeaveAlternateScreen);
}

/// Panic hooks run before unwinding releases a writer/state guard. If keyboard negotiation itself
/// is panicking, defer all stdout work to `TermGuard::Drop`; attempting terminal I/O here could
/// re-enter the same stdout lock in addition to the keyboard gate.
fn restore_terminal_after_panic(keyboard: &keyboard_enhancement::Restorer) {
    let mut stdout = std::io::stdout();
    let _ = restore_terminal_after_panic_to(keyboard, &mut stdout);
}

fn restore_terminal_after_panic_to(
    keyboard: &keyboard_enhancement::Restorer,
    stdout: &mut impl Write,
) -> bool {
    if matches!(
        keyboard.restore_after_panic(stdout),
        Ok(keyboard_enhancement::PanicRestoreOutcome::Deferred)
    ) {
        return false;
    }
    restore_terminal_modes(stdout);
    true
}

/// Restores the terminal (leaves raw mode + alternate screen) on drop, so the terminal is never
/// left broken — the #1 TUI failure mode. Covers early `?` returns AND panics (a panic unwinds
/// through the guard). A panic hook additionally restores before printing the panic message.
struct TermGuard {
    keyboard: keyboard_enhancement::Controller,
    mouse_capture: mouse_capture::Controller<std::io::Stdout>,
}
impl TermGuard {
    fn new() -> std::io::Result<Self> {
        let keyboard = keyboard_enhancement::Controller::default();
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
            EnableBracketedPaste
        ) {
            // Construction has not returned a guard yet, so rollback this partially-entered state
            // explicitly. Without this branch an I/O failure after raw-mode enable would leave the
            // operator's terminal unusable.
            restore_terminal(&keyboard.restorer());
            return Err(error);
        }
        let mouse_capture = match mouse_capture::Controller::capture(std::io::stdout()) {
            Ok(mouse_capture) => mouse_capture,
            Err(error) => {
                restore_terminal(&keyboard.restorer());
                return Err(error);
            }
        };
        // Install a panic hook that restores the terminal (incl. mouse capture) first, then the default.
        let default = std::panic::take_hook();
        let panic_keyboard = keyboard.restorer();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal_after_panic(&panic_keyboard);
            default(info);
        }));
        Ok(TermGuard {
            keyboard,
            mouse_capture,
        })
    }

    fn keyboard_restorer(&self) -> keyboard_enhancement::Restorer {
        self.keyboard.restorer()
    }

    fn negotiate_keyboard(
        &self,
        terminal_input: &mut terminal_input::TerminalInput,
        environment: &theme::capabilities::Environment,
    ) -> std::io::Result<bool> {
        self.keyboard
            .negotiate(terminal_input.supports_keyboard_enhancement(environment))
    }

    fn toggle_mouse_capture(&mut self) -> std::io::Result<mouse_capture::State> {
        self.mouse_capture.toggle()
    }

    /// Temporarily hand the physical terminal to an operator-owned external editor. Keyboard
    /// enhancement is popped before leaving and deliberately stays off after resume: the panic
    /// hook owns the original restorer, so blindly pushing a second frame would make cleanup
    /// ambiguous. Portable input remains fully functional.
    fn suspend_for_external_editor(&mut self) -> std::io::Result<mouse_capture::State> {
        let desired_mouse = self.mouse_capture.state();
        self.mouse_capture.release()?;
        let mut stdout = std::io::stdout();
        let suspended = (|| {
            let _ = self.keyboard.restorer().restore(&mut stdout)?;
            terminal::disable_raw_mode()?;
            execute!(stdout, DisableBracketedPaste)?;
            execute!(stdout, cursor::Show)?;
            execute!(
                stdout,
                crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
            )?;
            execute!(stdout, crossterm::style::ResetColor)?;
            execute!(stdout, terminal::LeaveAlternateScreen)?;
            Ok(())
        })();
        if suspended.is_err() {
            restore_terminal_modes(&mut stdout);
        }
        suspended.map(|()| desired_mouse)
    }

    fn resume_after_external_editor(
        &mut self,
        desired_mouse: mouse_capture::State,
    ) -> std::io::Result<()> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(
            std::io::stdout(),
            terminal::EnterAlternateScreen,
            EnableBracketedPaste
        ) {
            restore_terminal(&self.keyboard.restorer());
            return Err(error);
        }
        self.mouse_capture.set(desired_mouse)?;
        Ok(())
    }
}
impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = self.mouse_capture.release();
        restore_terminal(&self.keyboard.restorer());
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
/// A burst of streamed deltas costs ONE frame: the loop wakes on the first delta of the burst and
/// then holds the next draw for this long so the rest of the burst folds into it. Visible token
/// latency is bounded by this interval instead of by a fixed input-poll period.
const FRAME_COALESCE: Duration = Duration::from_millis(16);
/// A permanently full 1024-slot EQ must yield every loop turn to draw, lifecycle signals, effect
/// completion, and operator input. Ordering is unchanged because the sole receiver still consumes
/// the same FIFO stream; only the per-turn batch size is bounded.
const MAX_EQ_EVENTS_PER_TICK: usize = 64;

fn eq_tick_slots() -> std::ops::Range<usize> {
    0..MAX_EQ_EVENTS_PER_TICK
}
/// Spinner/elapsed animation cadence. The loop is event-driven, so the animation carries its own
/// clock rather than riding on an input poll's timeout.
const SPINNER_TICK: Duration = Duration::from_millis(100);
/// How long the input thread blocks in one crossterm read before looking at its channel again. It
/// matches the idle cadence the loop used to poll at, so moving input off the loop costs no extra
/// wakeups on an idle session.
const TERMINAL_READ_SLICE: Duration = Duration::from_secs(1);

/// The next instant the render loop must wake up on its own account: a frame that is being held
/// back by the coalescing interval, the animation tick of a live run, or a queued tool card whose
/// anti-flash delay expires. `None` means "nothing is scheduled" — the loop then sleeps until real
/// input or a real runtime event arrives instead of burning a fixed poll.
fn next_wake(
    frame_held: bool,
    next_frame_at: Instant,
    running: bool,
    last_spin: Instant,
    next_tool_reveal: Option<Instant>,
) -> Option<Instant> {
    let mut wake: Option<Instant> = None;
    let mut at_earliest = |candidate: Instant| {
        wake = Some(wake.map_or(candidate, |current: Instant| current.min(candidate)));
    };
    if frame_held {
        at_earliest(next_frame_at);
    }
    if running {
        at_earliest(last_spin + SPINNER_TICK);
    }
    if let Some(reveal) = next_tool_reveal {
        at_earliest(reveal);
    }
    wake
}

/// Sleep until `deadline`, or forever when nothing is scheduled.
async fn wake_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

enum InputThreadControl {
    Pause(std::sync::mpsc::SyncSender<()>),
    Resume,
}

fn service_input_control(receiver: &std::sync::mpsc::Receiver<InputThreadControl>) -> bool {
    let Ok(command) = receiver.try_recv() else {
        return true;
    };
    match command {
        InputThreadControl::Resume => true,
        InputThreadControl::Pause(acknowledge) => {
            let _ = acknowledge.send(());
            loop {
                match receiver.recv() {
                    Ok(InputThreadControl::Resume) => return true,
                    Ok(InputThreadControl::Pause(acknowledge)) => {
                        let _ = acknowledge.send(());
                    }
                    Err(_) => return false,
                }
            }
        }
    }
}

fn update_keymap_status(app: &mut App, keymap: &keymap::Keymap, vim: &keymap::Vim) {
    app.keymap_status = match (keymap.mode(), vim.state()) {
        (keymap::Mode::Standard, _) if keymap.is_custom() => "keys:custom",
        (keymap::Mode::Standard, _) => "keys:standard",
        (keymap::Mode::Vim, keymap::VimState::Insert) => "vim:insert",
        (keymap::Mode::Vim, keymap::VimState::Normal) => "vim:normal",
        (keymap::Mode::Vim, keymap::VimState::Visual) => "vim:visual",
    }
    .into();
}

fn apply_vim_action(app: &mut App, action: keymap::VimAction) {
    match action {
        keymap::VimAction::EnterInsert
        | keymap::VimAction::EnterNormal
        | keymap::VimAction::Consumed => {}
        keymap::VimAction::AppendInsert => app.editor.right(),
        keymap::VimAction::AppendEndInsert => app.editor.end(),
        keymap::VimAction::InsertStart => app.editor.home(),
        keymap::VimAction::Left => app.editor.left(),
        keymap::VimAction::Right => app.editor.right(),
        keymap::VimAction::Home => app.editor.home(),
        keymap::VimAction::End => app.editor.end(),
        keymap::VimAction::WordLeft => app.editor.word_left(),
        keymap::VimAction::WordRight => app.editor.word_right(),
        keymap::VimAction::Delete => app.editor.delete(),
        keymap::VimAction::Clear => app.editor.clear_recoverable(),
        keymap::VimAction::HistoryPrevious if !app.running => app.editor.history_prev(),
        keymap::VimAction::HistoryNext if !app.running => app.editor.history_next(),
        keymap::VimAction::HistoryPrevious | keymap::VimAction::HistoryNext => {}
        keymap::VimAction::EnterVisual => app.vim_anchor = Some(app.editor.cursor()),
        keymap::VimAction::LeaveVisual => app.vim_anchor = None,
        keymap::VimAction::ExtendSelection(motion) => {
            // The anchor stays put; only the free end moves. Entering visual mode always sets the
            // anchor, so a missing one means the state machine and the frontend disagree -- anchor
            // here rather than move a selection that does not exist.
            if app.vim_anchor.is_none() {
                app.vim_anchor = Some(app.editor.cursor());
            }
            match motion {
                keymap::VimMotion::Left => app.editor.left(),
                keymap::VimMotion::Right => app.editor.right(),
                keymap::VimMotion::Home => app.editor.home(),
                keymap::VimMotion::End => app.editor.end(),
                keymap::VimMotion::WordLeft => app.editor.word_left(),
                keymap::VimMotion::WordRight => app.editor.word_right(),
            }
        }
        keymap::VimAction::DeleteSelection => {
            if let Some(anchor) = app.vim_anchor.take() {
                app.editor.delete_span(anchor, app.editor.cursor());
            }
        }
        keymap::VimAction::YankSelection => {
            if let Some(anchor) = app.vim_anchor.take() {
                let text = app.editor.span(anchor, app.editor.cursor());
                if !text.is_empty() {
                    app.note(
                        block::NoticeLevel::Info,
                        format!("yanked {} characters", text.chars().count()),
                    );
                }
            }
        }
    }
}

fn reload_operator_keymap(
    app: &mut App,
    active: &mut keymap::Keymap,
    vim: &mut keymap::Vim,
    external_editor_command: &mut Option<Vec<String>>,
) {
    match crate::config::FileConfig::load_user().and_then(|config| {
        let keymap =
            keymap::Keymap::from_config(config.tui_keymap.as_ref()).map_err(anyhow::Error::msg)?;
        Ok((keymap, config.external_editor))
    }) {
        Ok((next, editor)) => {
            *active = next;
            *external_editor_command = editor;
            vim.reset();
            app.note(
                block::NoticeLevel::Info,
                "reloaded operator keymap and external-editor configuration",
            );
        }
        Err(error) => {
            *active = keymap::Keymap::default();
            *external_editor_command = None;
            vim.reset();
            app.note(
                block::NoticeLevel::Warn,
                format!("keymap reload failed; using built-in bindings: {error}"),
            );
        }
    }
    update_keymap_status(app, active, vim);
}

async fn external_edit_round_trip(
    term: &mut Terminal<
        ratatui::backend::CrosstermBackend<notification::LiveTerminalWriter<std::io::Stdout>>,
    >,
    guard: &mut TermGuard,
    input_control: &std::sync::mpsc::Sender<InputThreadControl>,
    workspace: &Path,
    configured: Option<Vec<String>>,
    draft: &str,
    sensitive_env_names: &[String],
) -> Result<Result<String, String>, String> {
    let (acknowledge, acknowledged) = std::sync::mpsc::sync_channel(0);
    input_control
        .send(InputThreadControl::Pause(acknowledge))
        .map_err(|_| "terminal input reader is no longer available".to_owned())?;
    if acknowledged
        .recv_timeout(TERMINAL_READ_SLICE + Duration::from_secs(1))
        .is_err()
    {
        // The reader may observe Pause after this timeout. Queue Resume before returning so it
        // cannot become stranded in the pause loop with exclusive ownership of stdin.
        let _ = input_control.send(InputThreadControl::Resume);
        return Ok(Err("terminal input reader did not pause in time".to_owned()));
    }

    let desired_mouse = match guard.suspend_for_external_editor() {
        Ok(state) => state,
        Err(error) => {
            let _ = input_control.send(InputThreadControl::Resume);
            return Err(format!(
                "could not suspend the Core terminal for editing: {error}"
            ));
        }
    };
    let edited = crate::external_editor::edit(
        crate::config::config_home(),
        workspace,
        configured,
        draft,
        sensitive_env_names,
    )
    .await;
    let resumed = guard
        .resume_after_external_editor(desired_mouse)
        .map_err(|error| format!("could not restore the Core terminal after editing: {error}"));
    let _ = input_control.send(InputThreadControl::Resume);
    resumed?;
    term.clear()
        .map_err(|error| format!("could not repaint after external editing: {error}"))?;
    Ok(edited)
}

/// Run the TUI. The agent runs in a background task streaming `UiEvent`s; the render loop drains
/// them and redraws. For follow-ups the same agent continues via `follow_up`.
/// Enter the interactive frontend.
///
/// The composition root hands this frontend an already-attached client. Everything below this line
/// holds queue endpoints, a negotiated protocol version and immutable session facts; the TUI cannot
/// name or reclaim the runtime type.
///
/// Both the handshake and its refusal happen before ANY terminal setup. A frontend that cannot
/// speak the runtime's protocol has nothing useful to draw, and a diagnostic printed from inside
/// the alternate screen is a diagnostic nobody reads: the terminal guard restores the screen on the
/// way out and takes the message with it.
pub(crate) struct RunConfig {
    pub(crate) completion_notifications: bool,
    pub(crate) history_mode: PromptHistoryMode,
    pub(crate) keymap: Option<keymap::Config>,
    pub(crate) external_editor: Option<Vec<String>>,
    pub(crate) sensitive_env_names: Vec<String>,
}

pub async fn run(
    attached: app_server::Attached,
    initial_task: Option<String>,
    mut providers: ProviderDirectory,
    route: RouteView,
    config: RunConfig,
    mut startup: startup::StartupTiming,
) -> anyhow::Result<()> {
    let RunConfig {
        completion_notifications,
        history_mode,
        keymap: keymap_config,
        external_editor: mut external_editor_command,
        sensitive_env_names,
    } = config;
    eprintln!(
        "app server: TUI attached as a versioned client (SQ/EQ protocol v{})",
        attached.handle.client.negotiated_version()
    );
    let app_server::Attached {
        handle,
        task: server_task,
        facts,
        initial_state,
        interrupt,
        drain,
    } = attached;
    // Resolve and read operator-owned prompt state before entering raw mode. Persistence is
    // fail-soft: an unavailable or malformed history file cannot prevent an interactive session,
    // but its diagnostic is retained for the first rendered transcript.
    let mut history_warning = None;
    let history_store = match prompt_history::Store::resolve(
        history_mode,
        crate::config::config_home(),
        &facts.workspace,
    ) {
        Ok(store) => store,
        Err(error) => {
            history_warning = Some(format!("prompt history disabled for this session: {error}"));
            None
        }
    };
    let history_state = history_store.as_ref().and_then(|store| match store.load() {
        Ok(state) => Some(state),
        Err(error) => {
            history_warning = Some(format!("prompt history could not be restored: {error}"));
            None
        }
    });
    let history_writer = prompt_history::Writer::new(history_store);
    let (mut active_keymap, initial_keymap_warning) =
        match keymap::Keymap::from_config(keymap_config.as_ref()) {
            Ok(keymap) => (keymap, None),
            Err(error) => (
                keymap::Keymap::default(),
                Some(format!("invalid keymap; using built-in bindings: {error}")),
            ),
        };
    let mut vim = keymap::Vim::default();
    let mut keymap_watcher = keymap::Watcher::new(crate::config::user_config_path());
    // Drain promises a real workspace checkpoint. Probe once before raw mode so a non-Git
    // workspace can reject that verb explicitly without blocking or breaking the terminal.
    let drain_available = core_record::checkpoint_supported(&facts.workspace);
    // RAII: the terminal is restored on ANY exit path (error/panic/normal).
    let mut guard = TermGuard::new()?;
    // Catchable termination signals restore the terminal immediately, then wake the owned event
    // loop. The loop reaps any transcript helper before it performs the final process exit.
    let (termination_tx, mut termination_rx) = tokio::sync::mpsc::channel::<i32>(1);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let keyboard = guard.keyboard_restorer();
        // Preserve the frontend's existing catchable-termination contract: both routes restore and
        // exit 143 after owned cleanup.
        for (kind, exit_code) in [(SignalKind::terminate(), 143), (SignalKind::hangup(), 143)] {
            if let Ok(mut s) = signal(kind) {
                let keyboard = keyboard.clone();
                let termination_tx = termination_tx.clone();
                tokio::spawn(async move {
                    s.recv().await;
                    restore_terminal(&keyboard);
                    let _ = termination_tx.send(exit_code).await;
                });
            }
        }
    }
    // Retain one sender so unsupported platforms do not observe an immediately closed channel.
    let _termination_tx = termination_tx;
    let mut terminal_input = terminal_input::TerminalInput::default();
    // BOTH capability probes are deliberately deferred until after the first frame. The
    // progressive-keyboard query blocks up to 2000 ms and OSC 11 another 80 ms; running them here,
    // between EnterAlternateScreen and the first draw, is exactly how a terminal that never answers
    // held a freshly blanked screen for two seconds. The environment alone decides the first
    // frame's theme; a background reply only repaints it.
    let environment = theme::capabilities::Environment::capture();
    let detected_theme = theme::Theme::detect_with(environment.clone(), None);
    let (terminal_writer, mut notification_writer) = notification::LiveTerminalWriter::stdout();
    let backend = ratatui::backend::CrosstermBackend::new(terminal_writer);
    let mut term = Terminal::new(backend)?;
    let mut notifier = notification::TerminalNotifier::new(completion_notifications);

    let repo = facts.workspace.clone();
    let mut app = App::new_with_detected_theme(detected_theme);
    if let Some(state) = history_state {
        app.editor.restore_persisted(state.history, state.draft);
    }
    if let Some(warning) = history_warning {
        app.note(block::NoticeLevel::Warn, warning);
    }
    if let Some(warning) = initial_keymap_warning {
        app.note(block::NoticeLevel::Warn, warning);
    }
    update_keymap_status(&mut app, &active_keymap, &vim);
    app.hyperlink_policy = hyperlink::Policy::detect(&repo);
    app.mode = initial_state.mode;
    app.effort = initial_state.effort;
    app.model = initial_state.model.clone();
    app.model_context_window = facts.initial_model_context_window;
    app.route = route;

    // Paint before probing. Everything the first frame needs is already resolved, and a terminal
    // that answers neither query must not be able to delay it.
    term.draw(|f| draw(f, &mut app))?;
    // The query is fail-soft: terminals that do not implement the protocol keep the portable
    // Ctrl-J path and receive neither a push nor a pop. Signal/panic cleanup is installed before
    // negotiation so even an exit during startup can restore an already-pushed stack frame.
    let _ = guard.negotiate_keyboard(&mut terminal_input, &environment);
    // OSC 11 runs after raw-mode entry. The input adapter demultiplexes the response from operator
    // events, replays unrelated startup input, and remains armed to swallow a late reply.
    if let Some(background) = terminal_input.query_background(&environment) {
        let probed = theme::Theme::detect_with(environment, Some(background));
        app.adopt_detected_theme(probed);
    }
    startup.mark(startup::StartupPhase::TerminalProbe);
    startup.flush();

    let mut session = Session::new(handle.client, handle.control, initial_state, facts);
    let mut events = handle.events;
    let mut last_event_seq = 0;
    let mut first_task = initial_task;
    let mut redraw = true;

    // Terminal input moves onto its own thread so the loop can wait on stdin AND the event queue at
    // the same time. The loop used to poll stdin alone for a fixed 100 ms and only afterwards drain
    // the queue, so a delta batch landing 1 ms into a poll waited out the other 99 ms — and an idle
    // session sat in a 1 s poll hole. The demultiplexer moves with the reader, so a late OSC 11 or
    // keyboard-enhancement reply is still swallowed instead of becoming synthetic operator input.
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<std::io::Result<CEvent>>(256);
    let (input_control_tx, input_control_rx) = std::sync::mpsc::channel::<InputThreadControl>();
    std::thread::spawn(move || {
        loop {
            if input_tx.is_closed() {
                return;
            }
            if !service_input_control(&input_control_rx) {
                return;
            }
            match terminal_input.read(TERMINAL_READ_SLICE) {
                Ok(None) => continue,
                Ok(Some(event)) => {
                    if input_tx.blocking_send(Ok(event)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = input_tx.blocking_send(Err(error));
                    return;
                }
            }
        }
    });
    // A runtime event observed by the wait is handed back to the drain at the top of the loop, so
    // the EQ still has exactly one consumer and one ordering check.
    let mut pending_event = None;
    let mut input_open = true;
    let mut eq_open = true;
    let mut last_spin = Instant::now();
    let mut next_frame_at = Instant::now();
    let mut persisted_revision = app.editor.persistence_revision();
    let mut persisted_history_len = app.editor.history_len();
    let mut transcript_effects = transcript_effect::Supervisor::default();
    let mut termination_exit = None;

    // All interactive-loop exits, including draw/input/editor/dispatch errors, flow through this
    // result boundary. Cleanup below therefore awaits the effect supervisor before the function can
    // return; relying on `Drop` would only abort the async shell and could orphan a helper process.
    let tui_result: anyhow::Result<()> = async {
    loop {
        // Kick off the initial task once the terminal is up.
        if let Some(task) = first_task.take()
            && !task.trim().is_empty()
        {
            submit_turn(&mut app, &session, &mut notifier, task);
            redraw = true;
        }

        // Drain the EQ (non-blocking). One long-lived subscription for the whole session: the
        // frontend used to create and retire a receiver per run, which is why there was no event
        // stream at all while idle and why the join had to double as a drain barrier.
        for _ in eq_tick_slots() {
            let Some(envelope) = pending_event.take().or_else(|| events.try_recv().ok()) else {
                break;
            };
            let event_seq = envelope.sequence();
            if event_seq <= last_event_seq {
                app.note(
                    block::NoticeLevel::Err,
                    format!(
                        "the runtime event stream reordered or duplicated live sequence \
                         {event_seq} after {last_event_seq}; no further updates will be shown"
                    ),
                );
                app.quit = true;
                break;
            }
            last_event_seq = event_seq;
            let event = match envelope.into_current() {
                Ok(event) => event,
                Err(error) => {
                    // Not recoverable by retrying: the runtime is emitting a shape this frontend
                    // cannot render. Say so in the transcript and stop reading the queue.
                    app.note(
                        block::NoticeLevel::Err,
                        format!("the runtime is speaking a protocol this frontend cannot read ({error}); no further updates will be shown"),
                    );
                    app.quit = true;
                    break;
                }
            };
            apply_server_event(
                &mut app,
                &mut session,
                event,
                &mut notifier,
                &mut notification_writer,
                &interrupt,
                &drain,
            );
            redraw = true;
        }
        if app.transcript_viewer.is_open()
            && app
                .transcript_viewer
                .sync_if_changed(&app.transcript, app.transcript_revision)
        {
            redraw = true;
        }
        if let Some(effect) = app.transcript_viewer.take_ready_effect() {
            schedule_transcript_viewer_effect(
                &mut app,
                session.workspace(),
                &mut transcript_effects,
                effect,
            );
            redraw = true;
        }
        if app.advance_tool_presentations(Instant::now()) {
            redraw = true;
        }

        // A turn ends when the server says so, on the EQ, not when a handle the frontend owned
        // finishes. `apply_server_event` handles `RunEnded`; the only thing left here is the
        // follow-up queue, which is now gated on the run state the server reports rather than on
        // whether an `Option<Agent>` happens to be full.
        if !app.running && !app.queued.is_empty() {
            // a joined blob mis-classified `/compact`+task). Commands execute inline; the first
            // PROSE item starts a run and we stop — the remaining items dispatch on the next
            // reclaim (a run is single-writer; we cannot start two at once).
            while !app.queued.is_empty() && !app.running {
                let q = app
                    .queued
                    .pop_front()
                    .expect("queue checked non-empty")
                    .text;
                let q = q.trim().to_string();
                if q.is_empty() {
                    continue;
                } else if let Some(cmd) = slash_command_body(&q) {
                    settle_providers_for(&mut providers, cmd).await;
                    dispatch_slash_command(
                        &mut term,
                        &mut app,
                        &mut session,
                        &providers,
                        &mut transcript_effects,
                        cmd,
                    )
                    .await?;
                } else if let Some(bash) = q.strip_prefix('!') {
                    // The runtime is resident, so these are always the live values. The old fallback to
                    // `(app.mode, PermissionRules::new())` ran `!bash` against DEFAULT-EMPTY rules
                    // whenever the `Agent` was away in a run task — a real correctness gap that
                    // inverting the ownership closes.
                    let (mode, rules) = (
                        session.permission_mode(),
                        session.permission_rules().clone(),
                    );
                    run_bash_inline(
                        &mut app,
                        &repo,
                        bash.trim(),
                        &sensitive_env_names,
                        mode,
                        &rules,
                    )
                    .await;
                } else {
                    app.push_user(q.clone());
                    submit_turn(&mut app, &session, &mut notifier, q);
                    break; // a run started; remaining items dispatch after it finishes
                }
            }
        }

        // Attention is a client concern: a quiet live run receives one fixed notification after
        // the bounded idle interval, then rearms only when another typed EQ event arrives.
        if let Some(trigger) = notifier.poll_idle(app.running) {
            notifier.emit_transport(&mut notification_writer, trigger);
        }

        // Active animation targets a 100 ms cadence off its own clock: the loop now wakes once per
        // delta, so riding the wait's timeout would spin the animation at the token rate. Idle is
        // event-driven and does not repaint at all.
        let now = Instant::now();
        if !app.running {
            last_spin = now;
        } else if now.duration_since(last_spin) >= SPINNER_TICK {
            app.spin = app.spin.wrapping_add(1);
            last_spin = now;
            redraw = true;
        }

        // Coalescing: the first change of a burst draws immediately, and everything that arrives
        // within FRAME_COALESCE of that frame folds into the next one. A streamed burst therefore
        // costs one frame instead of one frame per delta batch.
        if redraw && now >= next_frame_at {
            term.draw(|f| draw(f, &mut app))?;
            redraw = false;
            next_frame_at = now + FRAME_COALESCE;
        }

        if !input_open && !eq_open {
            // Neither the operator's terminal nor the runtime can wake this loop again; leave
            // rather than sleep forever.
            break;
        }
        // Wait on everything that can change the frame at once. There is no fixed poll period any
        // more: a delta is visible one coalescing interval after it arrives, and an idle session
        // sleeps until something actually happens.
        // Locally cheap transcript work is an immediate loop source. A MiB-scale block projection
        // runs on the viewer's sole bounded worker and wakes this select explicitly when ready, so
        // the TUI neither executes it synchronously nor polls it in a hot loop.
        let viewer_work_notification = app.transcript_viewer.work_notification();
        let viewer_work_active = viewer_work_notification.is_some();
        let wake = if app.transcript_viewer.is_open() && app.transcript_viewer.work_ready() {
            Some(Instant::now())
        } else {
            next_wake(
                redraw,
                next_frame_at,
                app.running,
                last_spin,
                app.next_tool_reveal(),
            )
        };
        let mut next_input = None;
        let effect_active = transcript_effects.is_active();
        tokio::select! {
            biased;
            // Explicit priority plus the bounded EQ phase above gives every control plane a
            // deterministic service point under a continuously refilled runtime queue. Effects
            // are single-flight, so placing their completion ahead of input cannot starve input.
            signal = termination_rx.recv() => {
                if let Some(exit_code) = signal {
                    termination_exit = Some(exit_code);
                }
            },
            effect = transcript_effects.recv(), if effect_active => {
                if let Some(effect) = effect {
                    apply_transcript_effect_event(&mut app, effect);
                    redraw = true;
                }
            },
            result = input_rx.recv(), if input_open => match result {
                Some(Ok(event)) => next_input = Some(event),
                Some(Err(error)) => return Err(error.into()),
                None => input_open = false,
            },
            _ = async {
                if let Some(notification) = viewer_work_notification {
                    notification.notified().await;
                }
            }, if viewer_work_active => {},
            envelope = events.recv(), if eq_open => match envelope {
                Some(envelope) => pending_event = Some(envelope),
                None => eq_open = false,
            },
            () = wake_until(wake) => {}
        }
        if termination_exit.is_some() {
            break;
        }
        if let Some(input_event) = next_input {
            redraw = true;
            match input_event {
                CEvent::Paste(pasted) if app.transcript_viewer.is_open() => {
                    app.transcript_viewer.handle_paste(
                        &pasted,
                        &app.transcript,
                        app.transcript_revision,
                    );
                }
                // A modal picker owns bracketed paste as well as physical keys. Consume a bounded,
                // sanitized query here before the generic composer/image path can mutate draft
                // text, cursor, or attachments.
                CEvent::Paste(pasted) if app.picker.is_some() => {
                    let _ = app.picker_paste(&pasted);
                }
                // Bracketed paste: insert the WHOLE pasted text (incl. newlines) into the editor
                // rather than letting each pasted newline submit a partial line (review HIGH).
                CEvent::Paste(pasted) => {
                    let pasted_image = if app.running {
                        Ok(None)
                    } else {
                        image_input::parse_explicit_image_path(&pasted)
                    };
                    match pasted_image {
                        Ok(Some(reference)) => {
                            let image_path = if reference.path().is_absolute() {
                                reference.path().to_path_buf()
                            } else {
                                repo.join(reference.path())
                            };
                            let attached =
                                app.editor.attach_image_path(&image_path).map(|attachment| {
                                    (
                                        attachment.display_name().to_owned(),
                                        attachment.media_type(),
                                        attachment.file_bytes(),
                                    )
                                });
                            match attached {
                                Ok((name, media_type, file_bytes)) => app.note(
                                    block::NoticeLevel::Ok,
                                    format!(
                                        "attached {} ({}, {} bytes)",
                                        name,
                                        media_type.as_str(),
                                        file_bytes
                                    ),
                                ),
                                Err(error) => app.note(
                                    block::NoticeLevel::Warn,
                                    format!("image attachment refused: {error}"),
                                ),
                            }
                            app.completion = None;
                        }
                        Ok(None) => {
                            // Not an image. A whole-input paste that is an absolute path already
                            // inside the workspace is a dragged-in file, and becomes a file chip
                            // on the same terms; anything else is ordinary pasted text.
                            match (app.running, file_input::parse_dropped_file_path(&repo, &pasted))
                            {
                                (false, Some(dropped)) => {
                                    let attached = app
                                        .editor
                                        .attach_file_path(&repo, &dropped)
                                        .map(|attachment| {
                                            (
                                                attachment.display_name().to_owned(),
                                                attachment.text_bytes(),
                                            )
                                        });
                                    match attached {
                                        Ok((name, text_bytes)) => app.note(
                                            block::NoticeLevel::Ok,
                                            format!("attached {name} ({text_bytes} bytes)"),
                                        ),
                                        Err(error) => app.note(
                                            block::NoticeLevel::Warn,
                                            format!("file attachment refused: {error}"),
                                        ),
                                    }
                                    app.completion = None;
                                }
                                _ => {
                                    app.editor.insert_str(&pasted);
                                    app.refresh_completion(&repo);
                                }
                            }
                        }
                        Err(error) => app.note(
                            block::NoticeLevel::Warn,
                            format!("image attachment refused: {error}"),
                        ),
                    }
                }
                CEvent::Mouse(m) if app.transcript_viewer.is_open() => match m.kind {
                    MouseEventKind::ScrollUp => app.transcript_viewer.scroll_up(3),
                    MouseEventKind::ScrollDown => app.transcript_viewer.scroll_down(3),
                    _ => {}
                },
                // Mouse: wheel/trackpad scroll moves the CHAT transcript (prompt history stays on ↑/↓);
                // a left-click on a card row folds/unfolds it.
                CEvent::Mouse(m) if app.mouse_capture.is_captured() => match m.kind {
                    MouseEventKind::ScrollUp => {
                        app.scroll_up(3);
                    }
                    MouseEventKind::ScrollDown => {
                        app.scroll_down(3);
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        if m.row >= app.view_top && m.row < app.view_top.saturating_add(app.view_h)
                        {
                            // `row_map` covers the visible window only, so the click row IS the index.
                            let idx = (m.row - app.view_top) as usize;
                            if let Some(&bi) = app.row_map.get(idx)
                                && bi != usize::MAX
                            {
                                app.toggle_fold(bi);
                            }
                        } else if app.picker.is_none()
                            && app.pending.is_none()
                            && place_editor_cursor_from_mouse(&mut app, m.column, m.row)
                        {
                            // Mouse focus belongs to the composer now; update any cursor-relative
                            // `@file` completion against the new boundary.
                            app.refresh_completion(&repo);
                        }
                    }
                    _ => {}
                },
                // A terminal can have already queued one last mouse report when Ctrl-T releases
                // capture. Ignore it so native selection cannot mutate transcript state.
                CEvent::Mouse(_) => {}
                CEvent::Key(k) => {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    if keymap_watcher.changed() {
                        reload_operator_keymap(
                            &mut app,
                            &mut active_keymap,
                            &mut vim,
                            &mut external_editor_command,
                        );
                    }
                    let mapped_action = active_keymap.action_for(k.code, k.modifiers);
                    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);

                    // Global even while a picker or approval owns normal keyboard input: Ctrl-T is
                    // the escape hatch that gives mouse ownership back to native terminal selection.
                    if k.code == KeyCode::Char('t') && ctrl {
                        match guard.toggle_mouse_capture() {
                            Ok(state) => app.mouse_capture = state,
                            Err(error) => app.note(
                                block::NoticeLevel::Err,
                                format!("could not change terminal mouse capture: {error}"),
                            ),
                        }
                        continue;
                    }

                    // Approval and lifecycle keys retain priority over optional fullscreen
                    // inspection. In particular, a queued approval cannot have its first key
                    // swallowed before the next draw closes the viewer, and Ctrl-C/Ctrl-D still
                    // reach the kernel/teardown paths below.
                    if app.pending.is_some() && app.transcript_viewer.is_open() {
                        app.transcript_viewer.close();
                    }
                    let lifecycle_key =
                        ctrl && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('d'));
                    if app.transcript_viewer.is_open() && !lifecycle_key {
                        if let Some(effect) =
                            app.transcript_viewer
                                .key(
                                    k.code,
                                    k.modifiers,
                                    &app.transcript,
                                    app.transcript_revision,
                                )
                        {
                            schedule_transcript_viewer_effect(
                                &mut app,
                                session.workspace(),
                                &mut transcript_effects,
                                effect,
                            );
                        }
                        continue;
                    }
                    if lifecycle_key && app.transcript_viewer.is_open() {
                        app.transcript_viewer.close();
                    }

                    if mapped_action == Some(keymap::Action::TranscriptViewer)
                        && app.pending.is_none()
                    {
                        open_transcript_viewer(&mut app, &transcript_effects, "");
                        continue;
                    }

                    // Ctrl-V asks a fixed platform clipboard adapter for image bytes. Ordinary text
                    // paste continues to arrive as `CEvent::Paste`; this branch owns only bitmap
                    // capture and is intentionally unavailable for mid-run steering.
                    if k.code == KeyCode::Char('v') && ctrl && !app.running {
                        match clipboard_image_bytes().await {
                            Ok(Some(bytes)) => {
                                let attached = app
                                    .editor
                                    .attach_image_bytes("clipboard.png", &bytes)
                                    .map(|attachment| {
                                        (
                                            attachment.display_name().to_owned(),
                                            attachment.media_type(),
                                            attachment.file_bytes(),
                                        )
                                    });
                                match attached {
                                    Ok((name, media_type, file_bytes)) => app.note(
                                        block::NoticeLevel::Ok,
                                        format!(
                                            "attached {name} ({}, {file_bytes} bytes)",
                                            media_type.as_str()
                                        ),
                                    ),
                                    Err(error) => app.note(
                                        block::NoticeLevel::Warn,
                                        format!("clipboard image refused: {error}"),
                                    ),
                                }
                            }
                            Ok(None) => app.note(
                                block::NoticeLevel::Info,
                                "no supported clipboard image adapter found; paste or drag an image path instead",
                            ),
                            Err(error) => app.note(block::NoticeLevel::Warn, error),
                        }
                        continue;
                    }

                    // Ctrl-D while active is the graceful drain verb: stop admitting turns,
                    // checkpoint at the next safe point, and return a resumable Drained outcome.
                    // Idle Ctrl-D retains shell-like quit/delete behavior below.
                    if k.code == KeyCode::Char('d') && ctrl && app.running {
                        request_drain(&mut app, &session, &drain, drain_available);
                        continue;
                    }

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
                                apply_action(&mut app, &mut session, &providers, action).await
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
                            let _ = session.submit(Op::Interrupt);
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
                            let _ = session.submit(Op::ApprovalResponse {
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

                    if let Some(action) = mapped_action {
                        match action {
                            keymap::Action::ExternalEditor if !app.running => {
                                let original = app.editor.text();
                                match external_edit_round_trip(
                                    &mut term,
                                    &mut guard,
                                    &input_control_tx,
                                    &repo,
                                    external_editor_command.clone(),
                                    &original,
                                    &sensitive_env_names,
                                )
                                .await
                                {
                                    Ok(Ok(edited)) => {
                                        app.editor.replace_text(&edited);
                                        app.completion = None;
                                        app.resume_handoff = None;
                                        app.note(
                                            block::NoticeLevel::Ok,
                                            format!(
                                                "external editor applied a {}-byte draft",
                                                edited.len()
                                            ),
                                        );
                                        app.refresh_completion(&repo);
                                    }
                                    Ok(Err(error)) => app.note(block::NoticeLevel::Warn, error),
                                    Err(error) => return Err(anyhow::anyhow!(error)),
                                }
                                vim.reset();
                                update_keymap_status(&mut app, &active_keymap, &vim);
                                continue;
                            }
                            keymap::Action::ExternalEditor => {
                                app.note(
                                    block::NoticeLevel::Info,
                                    "external editing is available between turns",
                                );
                                continue;
                            }
                            keymap::Action::ToggleFold => {
                                app.toggle_last_fold();
                                continue;
                            }
                            keymap::Action::RestoreDraft if !app.running => {
                                if app.editor.restore_recently_cleared() {
                                    app.resume_handoff = None;
                                    app.refresh_completion(&repo);
                                }
                                continue;
                            }
                            keymap::Action::ReverseSearch if !app.running && !menu_open => {
                                if !shift
                                    && app.editor.is_empty()
                                    && let Some(task) = app.retryable_task.clone()
                                {
                                    submit_turn(&mut app, &session, &mut notifier, task);
                                } else if !app.editor.reverse_search_previous() {
                                    app.status = "no older matching prompt".into();
                                }
                                app.refresh_completion(&repo);
                                continue;
                            }
                            keymap::Action::RestoreDraft | keymap::Action::ReverseSearch => {
                                continue;
                            }
                            keymap::Action::TranscriptViewer => unreachable!(
                                "the global transcript action is routed before modal/editor input"
                            ),
                        }
                    }

                    // Pickers and approvals have already consumed their keys above. The completion
                    // menu gets first Esc/navigation handling below; otherwise Vim normal mode owns
                    // ordinary editor keys before readline insertion can see them.
                    if !menu_open
                        && let Some(action) = vim.route(
                            active_keymap.mode() == keymap::Mode::Vim,
                            k.code,
                            k.modifiers,
                        )
                    {
                        apply_vim_action(&mut app, action);
                        update_keymap_status(&mut app, &active_keymap, &vim);
                        app.refresh_completion(&repo);
                        continue;
                    }

                    let mut refresh = false;
                    match k.code {
                        KeyCode::Char('c') if ctrl => {
                            if app.running {
                                if interrupt.load(Ordering::Relaxed) {
                                    // Second Ctrl-C: the cooperative interrupt did not land.
                                    //
                                    // This used to `abort()` the task that held the `Agent`,
                                    // destroying the runtime and leaving the session in an
                                    // unrecoverable "no agent — Esc to quit" state. The runtime is
                                    // resident now, so there is nothing to kill: escalate to
                                    // `Drain`, which the kernel honours at its next safe point, and
                                    // the session survives.
                                    let _ = session.submit(Op::Drain);
                                    app.running = false;
                                    app.interrupting = false;
                                    app.draining = false;
                                    app.flush_text();
                                    app.pending = None;
                                    app.steer_previews.clear();
                                    app.active_tools.clear();
                                    app.run_started = None;
                                    interrupt.store(false, Ordering::Relaxed);
                                    app.push_block(block::BlockKind::Error {
                                        title: "interrupt escalated to drain".into(),
                                        detail: "the cooperative interrupt did not land; the runtime will stop at its next safe point."
                                            .into(),
                                        open: true,
                                    });
                                    app.status = "draining…".into();
                                } else {
                                    interrupt.store(true, Ordering::Relaxed);
                                    app.interrupting = true;
                                    app.push(bold(Color::Yellow), "interrupting at the next safe point… (Ctrl-C again to hard-abort)");
                                }
                            } else if app.editor.has_submission() {
                                app.editor.clear_recoverable();
                                app.completion = None;
                                app.resume_handoff = None;
                            } else {
                                app.quit = true;
                            }
                        }
                        KeyCode::Char('d') if ctrl && !app.running => {
                            if !app.editor.has_submission() {
                                app.quit = true;
                            } else if app.editor.is_empty() {
                                let _ = app.editor.remove_last_attachment();
                            } else {
                                app.editor.delete();
                                refresh = true;
                            }
                        }
                        KeyCode::BackTab if !app.running => {
                            let next = session.permission_mode().next();
                            if commit_permission_mode(&mut app, &mut session, next).await {
                                app.push(fg(Color::Cyan), format!("mode: {}", next.label()));
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
                                    settle_providers_for(&mut providers, cmd).await;
                                    dispatch_slash_command(
                                        &mut term,
                                        &mut app,
                                        &mut session,
                                        &providers,
                                        &mut transcript_effects,
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
                        KeyCode::Backspace
                            if alt && !app.running && app.editor.chip_count() > 0 =>
                        {
                            let _ = app.editor.remove_last_attachment();
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
                        KeyCode::Esc if !app.running && app.editor.has_submission() => {
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
                                let line = app.editor.text();
                                let trimmed = line.trim().to_string();
                                let has_attachments = app.editor.chip_count() > 0;
                                app.completion = None;
                                if trimmed.is_empty() && !has_attachments {
                                    // nothing
                                } else if !has_attachments
                                    && let Some(cmd) = slash_command_body(&trimmed)
                                {
                                    // The words outlive a bad guess: a name the registry does not
                                    // serve returns to the composer after the notice, so nothing
                                    // the operator typed or dropped is consumed by a misparse.
                                    let restore =
                                        commands::parse(cmd).is_err().then(|| line.clone());
                                    let _ = app.editor.take_submit();
                                    settle_providers_for(&mut providers, cmd).await;
                                    dispatch_slash_command(
                                        &mut term,
                                        &mut app,
                                        &mut session,
                                        &providers,
                                        &mut transcript_effects,
                                        cmd,
                                    )
                                    .await?;
                                    if let Some(draft) = restore {
                                        app.editor.insert_str(&draft);
                                    }
                                } else if !has_attachments
                                    && let Some(bash) = trimmed.strip_prefix('!')
                                {
                                    let _ = app.editor.take_submit();
                                    let (mode, rules) = (
                                        session.permission_mode(),
                                        session.permission_rules().clone(),
                                    );
                                    run_bash_inline(
                                        &mut app,
                                        &repo,
                                        bash.trim(),
                                        &sensitive_env_names,
                                        mode,
                                        &rules,
                                    )
                                    .await;
                                } else {
                                    submit_composer(&mut app, &session, &mut notifier);
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
                                            if session
                                                .submit(Op::Steer { text: text.clone() })
                                                .is_ok()
                                            {
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
                            if !app.running && !app.editor.has_submission() && !menu_open =>
                        {
                            handle_registered_command(
                                &mut app,
                                &mut session,
                                &providers,
                                &mut transcript_effects,
                                SlashCommand::Help,
                                "",
                            )
                            .await;
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

        // Keep writes off the key path and bounded. A submitted prompt is scheduled immediately;
        // unsent drafts are coalesced every 32 mutations and always flushed on normal teardown.
        let revision = app.editor.persistence_revision();
        let history_len = app.editor.history_len();
        if history_len != persisted_history_len || revision.wrapping_sub(persisted_revision) >= 32 {
            history_writer.schedule(app.editor.persistence_state());
            persisted_revision = revision;
            persisted_history_len = history_len;
        }
    }
    Ok(())
    }
    .await;

    // teardown (the guard also restores on drop; show_cursor is the only extra step).
    let tui_result = transcript_effects.finish(tui_result).await;
    if termination_exit.is_none() {
        termination_exit = termination_rx.try_recv().ok();
    }
    let _ = term.show_cursor();
    history_writer.finish(app.editor.persistence_state());
    if let Some(exit_code) = termination_exit {
        drop(session);
        restore_terminal(&guard.keyboard_restorer());
        std::process::exit(exit_code);
    }
    // Dropping the last SQ sender is how the server learns the session is over. Wait for it to run
    // out — the runtime's own shutdown (the final rollout flush) happens in there, and returning
    // before it completes would race the process exit against the record on disk.
    drop(session);
    let _ = server_task.await;
    tui_result
}

/// Execute one already-submitted slash command. Both ordinary Enter and Enter on a slash
/// completion use this path, so completion activation cannot drift into a second dispatch path.
/// Join deferred provider discovery for the one command that reads catalogs the launch did not
/// resolve eagerly. `/model` opens the hierarchical picker over every instance and is therefore the
/// waiter for the background handle; nothing else pays for providers this session never routes to.
async fn settle_providers_for(providers: &mut ProviderDirectory, cmd: &str) {
    let named = commands::dispatch(cmd).is_ok_and(|routed| {
        matches!(
            routed.route,
            commands::DispatchRoute::InProcess(SlashCommand::Model)
        )
    });
    if named {
        providers.settle().await;
    }
}

async fn dispatch_slash_command(
    term: &mut Terminal<
        ratatui::backend::CrosstermBackend<notification::LiveTerminalWriter<std::io::Stdout>>,
    >,
    app: &mut App,
    session: &mut Session,
    providers: &ProviderDirectory,
    transcript_effects: &mut transcript_effect::Supervisor,
    cmd: &str,
) -> anyhow::Result<()> {
    app.push(bold(app.theme.accent), format!("/{cmd}"));
    let routed = match commands::dispatch(cmd) {
        Ok(routed) => routed,
        Err(unknown) => {
            app.push(
                fg(Color::Red),
                format!(
                    "unknown command /{} (try /help)",
                    ui_safe_text(unknown.name)
                ),
            );
            return Ok(());
        }
    };

    match routed.route {
        commands::DispatchRoute::InProcess(command) => {
            handle_registered_command(
                app,
                session,
                providers,
                transcript_effects,
                command,
                &routed.invocation.args,
            )
            .await;
        }
        commands::DispatchRoute::NotHere(commands::TerminalIntercept::Compact) => {
            let focus = routed.invocation.args;
            app.push(dim(), "compacting…");
            term.draw(|frame| draw(frame, app))?;
            // A control request, not a `&mut Agent` held across an `.await` in the event loop.
            // The old shape blocked input, redraw and the whole event stream for the duration of
            // the compaction; this one yields, and if a turn is running the request is applied at
            // its boundary instead of racing it.
            match session
                .control(app_server::Control::Compact {
                    focus: (!focus.is_empty()).then_some(focus),
                })
                .await
            {
                Some(app_server::ControlReply::Compacted { report, snapshot }) => {
                    // Compaction moves the ledger; the status line must not keep showing the
                    // pre-compaction figures.
                    app.cost = snapshot.cost.clone();
                    app.last_turn_usage = snapshot.last_turn_usage;
                    session.adopt(*snapshot);
                    app.push(
                        fg(Color::Green),
                        format!("compacted {} -> {} messages", report.before, report.after),
                    );
                }
                Some(app_server::ControlReply::Refused(reason)) => {
                    app.push(fg(Color::Red), format!("compact failed: {reason}"))
                }
                _ => app.push(fg(Color::Red), "the runtime is no longer reachable"),
            }
        }
        commands::DispatchRoute::NotHere(commands::TerminalIntercept::Side) => {
            let request = side_request_for(&routed.invocation.args);
            let asking = matches!(request, app_server::SideRequest::Ask(_));
            if asking {
                // Same reason compaction redraws here: this is about to await a provider call, and
                // an operator who sees nothing cannot tell a slow answer from a dead terminal.
                app.push(dim(), "asking on the side…");
                term.draw(|frame| draw(frame, app))?;
            }
            match session.control(app_server::Control::Side(request)).await {
                Some(app_server::ControlReply::SideAnswer(answer)) => {
                    show_side_answer(app, &answer);
                }
                Some(app_server::ControlReply::SideStatus { status, closed }) => {
                    show_side_status(app, status.as_deref(), closed);
                }
                Some(app_server::ControlReply::Refused(reason)) => app.push(
                    fg(Color::Red),
                    format!("side conversation refused: {reason}"),
                ),
                _ => app.push(fg(Color::Red), "the runtime is no longer reachable"),
            }
        }
    }
    Ok(())
}

/// Resolve one `/side` argument into a control request.
///
/// Pure so the three-way split is testable without a runtime. `status` and `close` are the only
/// reserved words and they are reserved exactly: `/side status of the parser` is a question about
/// the parser, not a status request, because a bare word is the only spelling an operator can have
/// meant as a verb.
fn side_request_for(argument: &str) -> app_server::SideRequest {
    match argument.trim() {
        "" | "status" => app_server::SideRequest::Status,
        "close" | "end" => app_server::SideRequest::Close,
        question => app_server::SideRequest::Ask(question.to_owned()),
    }
}

/// Render one side answer.
///
/// Deliberately a Panel and not an Assistant block: an Assistant block IS this session's
/// conversation, and the whole point of a side conversation is that its words are not. The books
/// travel with the answer for the same reason — a second conversation the operator is paying for
/// separately must show its own number, not silently move the session's.
fn show_side_answer(app: &mut App, answer: &crate::runtime::SideAnswer) {
    let mut rows = vec![block::PanelRow::Note(format!(
        "side run {} · {} · {}",
        answer.status.run_id,
        block::plural(answer.status.turns as usize, "turn"),
        side_cost_text(&answer.status)
    ))];
    let text = answer.text.trim();
    if text.is_empty() {
        rows.push(block::PanelRow::Note(format!(
            "no answer ({})",
            side_outcome_label(&answer.outcome)
        )));
    } else {
        rows.extend(text.lines().map(|line| block::PanelRow::Note(line.into())));
    }
    app.panel("~", "side conversation", rows);
}

/// Render the side conversation's identity and books without an answer.
fn show_side_status(app: &mut App, status: Option<&crate::runtime::SideStatus>, closed: bool) {
    let Some(status) = status else {
        app.note(
            block::NoticeLevel::Info,
            if closed {
                "no side conversation was open"
            } else {
                "no side conversation yet — `/side <question>` starts one with its own context, cost and record"
            },
        );
        return;
    };
    app.panel(
        "~",
        if closed {
            "side conversation · closed"
        } else {
            "side conversation"
        },
        vec![
            kv("run", &status.run_id),
            kv("record", &status.record_path.display().to_string()),
            kv("asked", &block::plural(status.asks as usize, "question")),
            kv("turns", &status.turns.to_string()),
            kv("cost", &side_cost_text(status)),
            block::PanelRow::Note(status.ledger_summary.clone()),
            block::PanelRow::Note(
                "this conversation's own context, cost and record; nothing here entered the session transcript".into(),
            ),
        ],
    );
}

/// Why a side ask produced nothing. A local label rather than `output::outcome_name`, which is a
/// frozen machine-contract token and must not grow a second, human-facing caller.
fn side_outcome_label(outcome: &core_protocol::Outcome) -> &'static str {
    use core_protocol::Outcome;
    match outcome {
        Outcome::Done => "the model answered with nothing",
        Outcome::Drained => "drained before answering",
        Outcome::Interrupted => "interrupted before answering",
        Outcome::Stuck => "stuck before answering",
        Outcome::BudgetExhausted(_) => "the side conversation's own budget is exhausted",
        Outcome::HarnessError => "the side conversation failed",
    }
}

/// The side conversation's own money, never the session's. An unknown cost stays the word
/// "unknown": a zero would read as free.
fn side_cost_text(status: &crate::runtime::SideStatus) -> String {
    match status.cost.usd() {
        Some(usd) => format!("${usd:.4}"),
        None => "cost unknown".into(),
    }
}

fn request_drain(
    app: &mut App,
    session: &Session,
    drain: &Arc<AtomicBool>,
    checkpoint_supported: bool,
) {
    if !app.running || app.draining {
        return;
    }
    if !checkpoint_supported {
        app.note(
            block::NoticeLevel::Warn,
            "drain requires a Git worktree because no durable workspace checkpoint is available",
        );
        return;
    }
    if session.submit(Op::Drain).is_err() {
        app.note(
            block::NoticeLevel::Err,
            "could not request a drain because the active run is no longer reachable",
        );
        return;
    }
    // The queue event is the durable ordering source; the shared flag lets an already-admitted
    // child observe the request at its own next turn boundary while the parent awaits it.
    drain.store(true, Ordering::Relaxed);
    app.draining = true;
    app.status = "draining at the next checkpoint".into();
    if app.pending.take().is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "drain requested · pending approval denied · checkpointing at the next safe point",
        );
    } else {
        app.push(
            bold(Color::Yellow),
            "draining at the next safe point · the session will remain resumable",
        );
    }
}

/// Submit a turn on the SQ.
///
/// This replaces `start_run`, which took the `Agent` out of the frontend's slot, moved it into a
/// task, and handed back a `JoinHandle`. The frontend no longer decides `run` versus `follow_up`
/// either — that is session state and it belongs to the server.
///
/// A refusal is shown, never swallowed: `Busy` means the operator's input did not land, and the one
/// thing worse than a full queue is a full queue that looks like acceptance.
fn submit_turn(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    task: String,
) {
    let _ = submit_operation(app, session, notifier, Op::UserInput { text: task.clone() });
    app.retryable_task = Some(task);
}

fn submit_operation(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    op: Op,
) -> bool {
    match session.submit(op) {
        Ok(()) => {
            notifier.begin_run();
            app.running = true;
            app.interrupting = false;
            app.draining = false;
            app.status = "running…".into();
            app.run_started = Some(Instant::now());
            // A new run must not inherit the previous one's first-token clock; the next
            // `Phase(Model)` starts it honestly (I-64).
            app.awaiting_first_token_since = None;
            app.completion = None;
            true
        }
        Err(app_server::SubmitError::Busy) => {
            app.note(
                block::NoticeLevel::Warn,
                "the runtime is saturated; this submission was not accepted — try again",
            );
            false
        }
        Err(app_server::SubmitError::Disconnected) => {
            app.push_block(block::BlockKind::Error {
                title: "the runtime is no longer reachable".into(),
                detail:
                    "the App Server has stopped — press Esc to quit (resume later with --resume)."
                        .into(),
                open: true,
            });
            app.status = "error (no runtime) — Esc to quit".into();
            false
        }
    }
}

/// Resolve explicit `@path.png` mentions into the same bounded attachment collection used by
/// drag/drop, then submit one legacy or multimodal SQ operation. Work is staged against a clone:
/// an invalid file or a saturated SQ leaves the operator's draft and chips intact.
fn submit_composer(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
) {
    let raw = app.editor.text();
    let mentions = match image_input::parse_image_mentions(&raw) {
        Ok(mentions) => mentions,
        Err(error) => {
            app.note(
                block::NoticeLevel::Warn,
                format!("image attachment refused: {error}"),
            );
            return;
        }
    };
    let mut staged: ImageAttachments = app.editor.attachments().clone();
    for mention in &mentions {
        let reference = mention.reference().path();
        let path = if reference.is_absolute() {
            reference.to_path_buf()
        } else {
            session.workspace().join(reference)
        };
        if let Err(error) = staged.attach_path(&path) {
            app.note(
                block::NoticeLevel::Warn,
                format!("image attachment refused: {error}"),
            );
            return;
        }
    }
    // File mentions resolve on the same terms, into the same kind of staged clone, and are
    // contained by `file_input::FileAttachments` — which routes every path through the workspace
    // containment `read_file` uses. A refusal here leaves the draft and its chips untouched.
    let file_mentions = match file_input::parse_file_mentions(&raw) {
        Ok(mentions) => mentions,
        Err(error) => {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {error}"),
            );
            return;
        }
    };
    let mut staged_files: file_input::FileAttachments = app.editor.files().clone();
    for mention in &file_mentions {
        if let Err(error) = staged_files.attach_path(session.workspace(), mention.path()) {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {error}"),
            );
            return;
        }
    }

    let mut text = raw;
    // Both mention kinds are cut out of the prompt by byte range, so the ranges must be removed
    // from the end backwards across the *union* of them, not once per kind: two independent
    // reverse passes shift the offsets the second pass is still holding.
    let mut cuts: Vec<std::ops::Range<usize>> = mentions
        .iter()
        .map(|mention| mention.byte_range.clone())
        .chain(
            file_mentions
                .iter()
                .map(|mention| mention.byte_range.clone()),
        )
        .collect();
    cuts.sort_by_key(|range| range.start);
    for range in cuts.iter().rev() {
        text.replace_range(range.clone(), "");
    }
    let text = text.trim().to_owned();
    if text.is_empty() && staged.is_empty() && staged_files.is_empty() {
        return;
    }
    let op = if !staged_files.is_empty() {
        // Files present: the one operation that can carry them, images included. Admission is
        // re-run by the kernel, so a refusal here buys the operator a message in the composer
        // rather than being the only thing standing between a bad payload and a turn.
        let images = staged
            .as_slice()
            .iter()
            .map(|attachment| attachment.content().clone())
            .collect::<Vec<_>>();
        let files = staged_files.to_file_contents();
        if let Err(reason) = core_protocol::input::validate_file_submission(&text, &images, &files)
        {
            app.note(
                block::NoticeLevel::Warn,
                format!("file attachment refused: {reason}"),
            );
            return;
        }
        Op::UserInputV3 {
            text: text.clone(),
            images,
            files,
        }
    } else if staged.is_empty() {
        Op::UserInput { text: text.clone() }
    } else {
        let segments = match staged.to_content_segments(text.clone()) {
            Ok(segments) => segments,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Warn,
                    format!("image attachment refused: {error}"),
                );
                return;
            }
        };
        Op::UserInputV2 { segments }
    };
    if submit_operation(app, session, notifier, op) {
        // Only the plain-text turn is offered back: re-sending staged attachments would re-read
        // files that may have changed since, which is a different request, not a retry (I-39).
        app.retryable_task = (staged.is_empty() && staged_files.is_empty()).then(|| text.clone());
        let image_count = staged.len();
        let file_count = staged_files.len();
        let _ = app.editor.take_submit();
        app.push_user(if text.is_empty() {
            let mut summary = String::from("[");
            if image_count > 0 {
                summary.push_str(&format!(
                    "{image_count} image attachment{}",
                    if image_count == 1 { "" } else { "s" }
                ));
            }
            if file_count > 0 {
                if image_count > 0 {
                    summary.push_str(", ");
                }
                summary.push_str(&format!(
                    "{file_count} file attachment{}",
                    if file_count == 1 { "" } else { "s" }
                ));
            }
            summary.push(']');
            summary
        } else {
            text
        });
    }
}

#[derive(Clone)]
struct ClipboardCommand {
    program: OsString,
    args: &'static [&'static str],
}

#[cfg(target_os = "macos")]
fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![ClipboardCommand {
        program: "pngpaste".into(),
        args: &["-"],
    }]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![
        ClipboardCommand {
            program: "wl-paste".into(),
            args: &["--no-newline", "--type", "image/png"],
        },
        ClipboardCommand {
            program: "xclip".into(),
            args: &["-selection", "clipboard", "-t", "image/png", "-o"],
        },
    ]
}

#[cfg(windows)]
fn clipboard_commands(environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    const SCRIPT: &str = "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName \
        System.Drawing; $i=[System.Windows.Forms.Clipboard]::GetImage(); if($null -eq $i){exit 3}; \
        $m=New-Object System.IO.MemoryStream; \
        $i.Save($m,[System.Drawing.Imaging.ImageFormat]::Png); $b=$m.ToArray(); \
        [Console]::OpenStandardOutput().Write($b,0,$b.Length)";
    windows_clipboard_powershell_program(environment)
        .map(|program| {
            vec![ClipboardCommand {
                program,
                args: &["-NoProfile", "-NonInteractive", "-Sta", "-Command", SCRIPT],
            }]
        })
        .unwrap_or_default()
}

#[cfg(not(any(unix, windows)))]
fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    Vec::new()
}

const MAX_CLIPBOARD_ENV_BYTES: usize = 4 * 1024;
#[cfg(any(windows, test))]
const MAX_WINDOWS_SYSTEM_ROOT_BYTES: usize = 1_024;

fn bounded_clipboard_environment_value(value: OsString) -> Option<OsString> {
    if value.as_encoded_bytes().len() > MAX_CLIPBOARD_ENV_BYTES
        || value
            .to_str()
            .is_some_and(|text| text.chars().any(char::is_control))
    {
        None
    } else {
        Some(value)
    }
}

fn clipboard_child_environment_with(
    mut source: impl FnMut(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    let mut environment = Vec::new();
    #[cfg(target_os = "macos")]
    environment.push((
        "PATH".into(),
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".into(),
    ));
    #[cfg(all(unix, not(target_os = "macos")))]
    environment.push(("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()));
    #[cfg(unix)]
    {
        environment.push(("LANG".into(), "C.UTF-8".into()));
        environment.push(("LC_ALL".into(), "C.UTF-8".into()));
        for name in [
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "DISPLAY",
            "XAUTHORITY",
        ] {
            if let Some(value) = source(name).and_then(bounded_clipboard_environment_value) {
                environment.push((name.into(), value));
            }
        }
    }
    #[cfg(windows)]
    {
        environment.extend(windows_clipboard_environment_with(
            trusted_windows_directory(),
            |name| source(name),
            native_windows_clipboard_root,
        ));
    }
    environment
}

#[cfg(any(windows, test))]
fn windows_clipboard_environment_with(
    trusted_root: Option<OsString>,
    mut source: impl FnMut(&str) -> Option<OsString>,
    admissible_root: impl Fn(&Path) -> bool,
) -> Vec<(OsString, OsString)> {
    let Some(root) = trusted_root
        .and_then(bounded_clipboard_environment_value)
        .filter(|value| value.as_encoded_bytes().len() <= MAX_WINDOWS_SYSTEM_ROOT_BYTES)
        .filter(|value| {
            value
                .to_str()
                .is_some_and(|text| !text.contains(';') && !text.contains('"'))
        })
        .filter(|value| admissible_root(Path::new(value)))
    else {
        return Vec::new();
    };

    let powershell_dir = append_windows_subpath(&root, r"System32\WindowsPowerShell\v1.0");
    let system32 = append_windows_subpath(&root, "System32");
    let wbem = append_windows_subpath(&root, r"System32\Wbem");
    let mut path = OsString::new();
    for directory in [&powershell_dir, &system32, &root, &wbem] {
        if !path.is_empty() {
            path.push(";");
        }
        path.push(directory);
    }
    let Some(path) = bounded_clipboard_environment_value(path) else {
        return Vec::new();
    };

    let mut environment = vec![
        ("PATH".into(), path),
        ("SystemRoot".into(), root.clone()),
        ("WINDIR".into(), root),
    ];
    for name in ["TEMP", "TMP"] {
        if let Some(value) = source(name).and_then(bounded_clipboard_environment_value) {
            environment.push((name.into(), value));
        }
    }
    environment
}

#[cfg(any(windows, test))]
fn append_windows_subpath(root: &std::ffi::OsStr, subpath: &str) -> OsString {
    let mut path = root.to_os_string();
    if !root
        .to_string_lossy()
        .as_bytes()
        .last()
        .is_some_and(|byte| matches!(byte, b'\\' | b'/'))
    {
        path.push("\\");
    }
    path.push(subpath);
    path
}

#[cfg(any(windows, test))]
fn windows_clipboard_powershell_program(environment: &[(OsString, OsString)]) -> Option<OsString> {
    let root = environment
        .iter()
        .find_map(|(name, value)| (name == "SystemRoot").then_some(value))?;
    Some(append_windows_subpath(
        root,
        r"System32\WindowsPowerShell\v1.0\powershell.exe",
    ))
}

#[cfg(windows)]
fn native_windows_clipboard_root(path: &Path) -> bool {
    use std::path::Prefix;

    if !path.is_absolute() {
        return false;
    }
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _))
    )
}

#[cfg(windows)]
fn trusted_windows_directory() -> Option<OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    // The OS, not an inherited environment variable, selects the executable trust root. Refuse an
    // unexpectedly large path instead of allocating from an unbounded native return value.
    let mut buffer = vec![0_u16; MAX_WINDOWS_SYSTEM_ROOT_BYTES + 1];
    // SAFETY: `buffer` is writable for its declared length and retained until the call returns.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(OsString::from_wide(&buffer[..length]))
}

/// Read a clipboard image through a fixed platform adapter. The subprocess has no shell, stderr is
/// discarded, stdout is capped before retention, the environment is an explicit display-only
/// allowlist, and the whole operation has a short timeout.
async fn clipboard_image_bytes() -> Result<Option<Vec<u8>>, &'static str> {
    let environment = clipboard_child_environment_with(|name| std::env::var_os(name));
    for specification in clipboard_commands(&environment) {
        let mut command = tokio::process::Command::new(&specification.program);
        command
            .env_clear()
            .envs(environment.iter().cloned())
            .args(specification.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            continue;
        };
        let capture = async {
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 16 * 1024];
            loop {
                let read = stdout
                    .read(&mut chunk)
                    .await
                    .map_err(|_| "could not read the clipboard image")?;
                if read == 0 {
                    break;
                }
                if bytes.len().saturating_add(read) > image_input::MAX_IMAGE_FILE_BYTES {
                    return Err("clipboard image exceeds the per-file limit");
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            let status = child
                .wait()
                .await
                .map_err(|_| "could not finish clipboard image capture")?;
            Ok::<_, &'static str>((status.success(), bytes))
        };
        match tokio::time::timeout(Duration::from_secs(3), capture).await {
            Ok(Ok((true, bytes))) if !bytes.is_empty() => return Ok(Some(bytes)),
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err("clipboard image capture timed out");
            }
        }
    }
    Ok(None)
}

/// Apply one EQ envelope.
///
/// The frontend's whole view of the runtime arrives through here. `RunEnded` carries what the
/// `handle.await` reclaim used to read straight off the `Agent`; there is no join any more, so the
/// terminal event is also the refresh point.
#[allow(clippy::too_many_arguments)]
fn apply_server_event<T: notification::NotificationTransport + ?Sized>(
    app: &mut App,
    session: &mut Session,
    event: app_server::ServerEvent,
    notifier: &mut notification::TerminalNotifier,
    writer: &mut T,
    interrupt: &Arc<AtomicBool>,
    drain: &Arc<AtomicBool>,
) {
    match event {
        app_server::ServerEvent::Ui(event) => apply_live_event(app, event, notifier, writer),
        app_server::ServerEvent::WorkflowRun(event) => app.workflow_run_ui_event(event),
        app_server::ServerEvent::Notice(text) => app.note(block::NoticeLevel::Warn, text),
        app_server::ServerEvent::Lagged { dropped } => app.note(
            block::NoticeLevel::Warn,
            format!(
                "{dropped} streamed update(s) were dropped to keep the event queue bounded; the \
                 transcript above is incomplete at that point"
            ),
        ),
        app_server::ServerEvent::RunEnded { snapshot, summary } => {
            let completion_notification = notifier.run_completed();
            app.running = false;
            app.interrupting = false;
            app.draining = false;
            app.run_started = None;
            app.awaiting_first_token_since = None;
            app.flush_text();
            app.pending = None; // a pending approval cannot outlive its run
            app.settle_unfinished_tools();
            interrupt.store(false, Ordering::Relaxed);
            drain.store(false, Ordering::Relaxed);

            // A channel send is not delivery. The exact raw texts the kernel did not admit come
            // back on the snapshot and go into the frontend's own submission order, so nothing is
            // lost, duplicated, or reordered across the turn boundary.
            let (count, unmatched_previews) =
                app.requeue_unadmitted(snapshot.unadmitted_steers.clone());
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

            app.mode = snapshot.mode;
            app.effort = snapshot.effort;
            app.model = snapshot.model.clone();
            app.cost = snapshot.cost.clone();
            app.last_turn_usage = snapshot.last_turn_usage;
            session.adopt(*snapshot);

            let result = summary.result_v5();
            let canonical_outcome = result
                .get("outcome")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("harness_error");
            if let Some(detail) = result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            {
                // Everything already streamed is on the record as an interrupted message, so a
                // retry continues from evidence rather than from nothing (I-39).
                let detail = if app.retryable_task.is_some() {
                    format!("{detail}\n\n{RETRY_HINT}")
                } else {
                    detail
                };
                app.push_block(block::BlockKind::Error {
                    title: "run failed".into(),
                    detail,
                    open: true,
                });
            } else {
                // The turn landed; there is nothing to re-send.
                app.retryable_task = None;
            }
            // A budget stop is not a failure and gets no error block, so without this the operator
            // saw only `idle · last: budget_exhausted` — true, and silent about the fact that the
            // turn ceiling is raisable in place.
            if canonical_outcome == "budget_exhausted" {
                let reason = result
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "stopped on the {reason} ceiling — {}",
                        crate::output::budget_remedy(reason)
                    ),
                );
            }
            app.status = format!("idle · last: {canonical_outcome}");
            app.last_result = Some(result);
            if let Some(trigger) = completion_notification {
                notifier.emit_transport(writer, trigger);
            }
        }
    }
}

/// Instantiate and validate the new `(provider, model)` pair before mutating either field. A
/// failed construction leaves the old provider and old model together, avoiding cross-provider
/// requests with a model id from a different account.
async fn apply_model_selection(
    app: &mut App,
    session: &mut Session,
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

    let changed =
        session.model() != selection.model_id || app.route.provider_id != selection.provider_id;
    let provider_name = directory
        .entry(&selection.provider_id)
        .map(|entry| entry.display_name().to_owned())
        .unwrap_or_else(|| selection.provider_id.clone());

    // One transaction, applied by the runtime. The write-ahead audit, the capability fields and the
    // rate-card rebind used to be four separate statements here, each able to fail after the
    // previous one had already taken effect; the server now applies them in the kernel's required
    // order and answers with the state it actually reached.
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let reply = session
        .control(app_server::Control::SelectModel(Box::new(
            app_server::ModelSelection {
                provider,
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest,
                capability_digest,
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
            },
        )))
        .await;
    let state = match reply {
        Some(app_server::ControlReply::State(state)) => state,
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason);
            return;
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            return;
        }
    };

    app.model = state.model.clone();
    // Re-derive the ONE route view from the directory, so the statusline, /status and /config all
    // move together with the request the next turn dispatches. The model comes from the state the
    // runtime actually reached, not from what was requested of it.
    let applied = ModelSelection {
        provider_id: selection.provider_id.clone(),
        model_id: state.model.clone(),
    };
    app.route = app.route.reselect(directory, &applied);
    app.model_context_window = capabilities.context_window_tokens;
    // A model chosen in the TUI is an operator decision, and until now it evaporated at exit:
    // nothing in the product ever wrote the user config (I-25). Persist it through the same single
    // atomic writer `core config set` uses, so the next launch starts on the route the operator
    // picked (I-26). Provider and model go in ONE transaction: persisting the model alone would
    // leave the next launch pairing a new model with the previous provider.
    let persisted_provider = applied.provider_id.clone();
    let persisted_model = applied.model_id.clone();
    match crate::config::update_user_config(move |config| {
        crate::config::apply_setting(config, "provider", &persisted_provider)?;
        crate::config::apply_setting(config, "model", &persisted_model)
    }) {
        Ok(_) => {}
        Err(error) => app.note(
            block::NoticeLevel::Warn,
            format!("route applied for this session but not persisted: {error}"),
        ),
    }
    if changed {
        clear_last_turn_telemetry_from(app, &state);
    }
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

/// Clear the per-request telemetry after a route or effort change, from a server snapshot.
///
/// The ledger half of the old function reached into `agent.ledger` to reset it; the resident runtime
/// does that on its own side when it applies the transition, so the frontend only has to stop
/// displaying values that no longer describe anything.
fn clear_last_turn_telemetry_from(app: &mut App, state: &app_server::SessionSnapshot) {
    app.last_turn_usage = state.last_turn_usage;
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
async fn commit_effort(app: &mut App, session: &mut Session, next: Effort) -> bool {
    // A control round trip, not a method call on an `Agent` the frontend happens to hold. The
    // answer is the state the runtime actually reached: `app.effort` is set from the reply, so a
    // refusal leaves the display showing what is true rather than what was asked for.
    match session.control(app_server::Control::SetEffort(next)).await {
        Some(app_server::ControlReply::State(state)) => {
            app.effort = state.effort;
            clear_last_turn_telemetry_from(app, &state);
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("effort was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

async fn commit_permission_mode(
    app: &mut App,
    session: &mut Session,
    next: PermissionMode,
) -> bool {
    match session
        .control(app_server::Control::SetPermissionMode(next))
        .await
    {
        Some(app_server::ControlReply::State(state)) => {
            app.mode = state.mode;
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("permission mode was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

async fn commit_permission_capability(
    app: &mut App,
    session: &mut Session,
    capability: Capability,
    verdict: Verdict,
) -> bool {
    match session
        .control(app_server::Control::SetCapabilityRule {
            capability,
            verdict,
        })
        .await
    {
        Some(app_server::ControlReply::State(state)) => {
            app.mode = state.mode;
            true
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(
                block::NoticeLevel::Err,
                format!("the permission rule was not changed: {reason}"),
            );
            false
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            false
        }
    }
}

/// Apply a picked action to the idle agent + UI state (C5 take-then-apply calls this after dropping
/// the picker borrow). Surfaces a Notice if the agent is gone rather than silently no-op'ing (C6).
async fn apply_action(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    action: PickAction,
) {
    match action {
        PickAction::AdoptRun(run_id) => adopt_session(app, session, directory, &run_id).await,
        PickAction::InspectTunable(detail) => show_tunable_detail(app, detail),
        PickAction::Info => {}
        PickAction::SetModel(selection) => {
            apply_model_selection(app, session, directory, selection).await
        }
        PickAction::SetEffort(e) => {
            if commit_effort(app, session, e).await {
                let lvl = if e == Effort::Ultracode {
                    block::NoticeLevel::Warn
                } else {
                    block::NoticeLevel::Ok
                };
                app.note(lvl, format!("effort set to {} — {}", e.label(), e.hint()));
            }
        }
        PickAction::SetMode(m) => {
            if commit_permission_mode(app, session, m).await {
                app.note(block::NoticeLevel::Ok, format!("mode set to {}", m.label()));
            }
        }
        PickAction::SetCap(c, v) => {
            let vl = match v {
                Verdict::Auto => "allow",
                Verdict::Ask => "ask",
                Verdict::Deny => "deny",
            };
            if commit_permission_capability(app, session, c, v).await {
                app.note(
                    block::NoticeLevel::Ok,
                    format!("permission rule: {} → {vl}", cap_label(c)),
                );
            }
        }
        PickAction::SetTheme(theme) => apply_theme_selection(app, theme),
    }
}

fn show_tunable_detail(app: &mut App, detail: tunables_view::Detail) {
    let (family_id, detail_rows, notes) = detail.into_panel();
    let mut rows: Vec<block::PanelRow> = detail_rows
        .into_iter()
        .map(|(key, value)| kv(&key, &value))
        .collect();
    rows.extend(notes.into_iter().map(block::PanelRow::Note));
    app.panel("", &format!("tunable · {family_id}"), rows);
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

/// Build the `/mode` picker. The code clause is *derived* from the same gate the runtime consults,
/// never asserted: a session rule (`--allow-code`, `/permissions allow code_executing`) outranks the
/// mode table, so a hard-coded "code still gated" mislabels every session that carries such a grant.
fn mode_picker_items(current: PermissionMode, rules: &PermissionRules) -> Vec<PickItem> {
    let code_clause = |mode: PermissionMode| match core_protocol::gate(
        mode,
        rules,
        "bash",
        Capability::CodeExecuting,
    ) {
        Verdict::Auto => "code auto",
        Verdict::Deny => "code denied",
        Verdict::Ask => "code still gated",
    };
    let modes = [
        (
            PermissionMode::Default,
            format!(
                "edits prompt live; {}",
                code_clause(PermissionMode::Default)
            ),
        ),
        (
            PermissionMode::AcceptEdits,
            format!("edits auto; {}", code_clause(PermissionMode::AcceptEdits)),
        ),
        (
            PermissionMode::Plan,
            "read-only; propose a plan first".to_string(),
        ),
        (
            PermissionMode::Yolo,
            "auto-approve (still asks for trust-mutating + egress)".to_string(),
        ),
    ];
    modes
        .into_iter()
        .map(|(mode, hint)| {
            PickItem::flat(
                mode.label(),
                hint,
                mode == current,
                PickAction::SetMode(mode),
            )
        })
        .collect()
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

/// Most transcript blocks an adopted run contributes to the live transcript.
///
/// The kernel replays the WHOLE record — the next turn continues all of it. This is the screen
/// bound only, so a thousand-turn session cannot push the live transcript past its own eviction cap
/// on the way in. The notice above the projection says how much was left out, because a history
/// silently rendered short reads as a shorter conversation than the one the model will see.
const MAX_ADOPTED_BLOCKS: usize = 120;

/// Bound on one recorded tool result rendered back into a card.
const MAX_ADOPTED_TOOL_OUTPUT_BYTES: usize = 4 * 1024;

/// The `(provider_id, model_id)` an existing record says its last turn dispatched on.
///
/// Same rule the `--resume` startup path applies: the last durable `ModelSelected` is authoritative;
/// a legacy journal that predates provider identity offers only `RunStart.model`, and its model is
/// never used to guess a provider.
fn recorded_route(events: &[core_protocol::Event]) -> Option<(Option<String>, String)> {
    if let Some(route) = events.iter().rev().find_map(|event| match &event.kind {
        core_protocol::EventKind::ModelSelected {
            provider_id,
            model_id,
            ..
        } => Some((Some(provider_id.clone()), model_id.clone())),
        _ => None,
    }) {
        return Some(route);
    }
    events.iter().find_map(|event| match &event.kind {
        core_protocol::EventKind::RunStart { model, .. } if !model.is_empty() => {
            Some((None, model.clone()))
        }
        _ => None,
    })
}

/// One recorded tool call, rebuilt from the durable transcript.
struct AdoptedTool {
    is_error: bool,
    content: String,
    latency_ms: u64,
}

/// Project an adopted run's durable transcript into settled transcript blocks.
///
/// This renders the RECORD, not a replay of the run: no tool is re-executed, no card is live, and
/// nothing here can start a turn. Returns `(rendered, total)` so the caller can state the bound it
/// applied instead of quietly showing a shorter conversation.
fn adopted_transcript_blocks(events: &[core_protocol::Event]) -> (Vec<block::BlockKind>, usize) {
    use core_protocol::{Block as MessageBlock, EventKind, Role};

    let mut results: std::collections::HashMap<String, AdoptedTool> =
        std::collections::HashMap::new();
    for event in events {
        let EventKind::Message { message } = &event.kind else {
            continue;
        };
        for block in &message.content {
            if let MessageBlock::ToolResult(result) = block {
                results.insert(
                    result.tool_use_id.clone(),
                    AdoptedTool {
                        is_error: result.is_error,
                        content: result.content.clone(),
                        latency_ms: result.latency_ms,
                    },
                );
            }
        }
    }

    let mut blocks = Vec::new();
    for event in events {
        let EventKind::Message { message } = &event.kind else {
            continue;
        };
        for block in &message.content {
            match block {
                MessageBlock::Text { text } if text.trim().is_empty() => {}
                MessageBlock::Text { text } => {
                    let text = ui_safe_text(text);
                    blocks.push(match message.role {
                        Role::User => block::BlockKind::User(text),
                        Role::Assistant => {
                            block::BlockKind::Assistant(crate::markdown::MarkdownDoc::parse(&text))
                        }
                    });
                }
                MessageBlock::Thinking { thinking } if !thinking.trim().is_empty() => {
                    blocks.push(block::BlockKind::Thinking {
                        text: ui_safe_text(thinking),
                        open: false,
                    });
                }
                MessageBlock::ToolUse(call) => {
                    // A recorded call with no recorded result is a real shape: the run stopped
                    // between the two. Saying so beats inventing a status for it.
                    let recorded = results.get(&call.id);
                    let (status, output, elapsed) = match recorded {
                        Some(result) => (
                            if result.is_error {
                                block::ToolStatus::Err
                            } else {
                                block::ToolStatus::Ok
                            },
                            ui_safe_text(&bounded_prefix(
                                &result.content,
                                MAX_ADOPTED_TOOL_OUTPUT_BYTES,
                            )),
                            Some(Duration::from_millis(result.latency_ms)),
                        ),
                        None => (
                            block::ToolStatus::Err,
                            "no recorded result — the run stopped before this tool answered".into(),
                            None,
                        ),
                    };
                    blocks.push(block::BlockKind::Tool(block::ToolCard {
                        name: ui_safe_text(&call.name),
                        args: call.input.clone(),
                        status,
                        output,
                        diff: None,
                        exit_code: None,
                        started: Instant::now(),
                        elapsed,
                        open: false,
                    }));
                }
                MessageBlock::Thinking { .. }
                | MessageBlock::ToolResult(_)
                | MessageBlock::ProviderState(_) => {}
            }
        }
    }

    let total = blocks.len();
    if total > MAX_ADOPTED_BLOCKS {
        blocks.drain(..total - MAX_ADOPTED_BLOCKS);
    }
    (blocks, total)
}

/// Truncate on a char boundary, never mid-UTF-8.
fn bounded_prefix(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated for display]", &text[..end])
}

/// Drop every projection of the run being left.
///
/// Retained UI state is per-run exactly as kernel state is: a card, an index entry or a half-streamed
/// paragraph from the previous run would render under the adopted run's identity.
fn clear_transcript_for_adoption(app: &mut App) {
    app.transcript.clear();
    app.mark_transcript_changed();
    app.tool_index.clear();
    app.pending_tools.clear();
    app.workflow_index.clear();
    app.workflow_run_index.clear();
    app.active_tools.clear();
    app.render_cache.clear();
    app.cur_text.clear();
    app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
    app.cur_doc_revision = app.cur_text_revision;
    app.cur_doc = None;
    app.cur_think.clear();
    app.last_result = None;
    app.retryable_task = None;
    app.resume_handoff = None;
    app.follow_latest();
}

/// Adopt a recorded session into THIS running TUI: the live session takes over that run's journal,
/// identity and transcript, and the next turn continues it.
///
/// # Why the client opens the rollout
///
/// Opening it is what takes the target run's exclusive writer lock, and that is the refusal an
/// operator actually meets — another `core` process is on that session. Taking it here means such an
/// adoption is refused before the resident runtime is asked to do anything, so a session that cannot
/// be adopted cannot disturb the one that is running.
///
/// # Why a route is always sent
///
/// The kernel restores the adopted record's route but cannot resolve a provider for it. Sending the
/// route the session will actually dispatch on — the record's own when this process can build it,
/// this process's current route otherwise — is what makes the adopted run's next request match its
/// own record instead of being refused by the route gate.
async fn adopt_session(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    run_id: &str,
) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before resuming another session",
        );
        return;
    }
    if !app.queued.is_empty() || !app.steer_previews.is_empty() {
        // Those submissions were composed for THIS run. Dispatching them into an adopted session
        // would send the operator's words to a conversation they were not written for.
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "{} still pending for this session; send or clear them before resuming another one",
                block::plural(
                    app.queued.len().saturating_add(app.steer_previews.len()),
                    "submission"
                )
            ),
        );
        return;
    }
    let rollout_path = session.rollout_path().to_path_buf();
    let runs = rollout_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current_run = rollout_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if run_id == current_run {
        app.note(
            block::NoticeLevel::Info,
            "that session is already the live one",
        );
        return;
    }
    let run = core_protocol::RunId(run_id.to_owned());
    let tenant = core_protocol::TenantId::default();

    // One read of the record serves both halves: the route to bind and the history to render.
    let events = match core_record::load_forked(&runs, &run) {
        Ok(events) => events,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("cannot read session {}: {error}", ui_safe_text(run_id)),
            );
            return;
        }
    };

    // The record's own route when this process can build it. A provider the operator has not
    // configured, or one that fails to construct, is NOT silently substituted — the session
    // continues on the route this process is already using, and says so.
    let recorded = recorded_route(&events);
    let current_selection = ModelSelection {
        provider_id: app.route.provider_id.clone(),
        model_id: session.model().to_owned(),
    };
    let (selection, built, substituted) = match &recorded {
        Some((Some(provider_id), model_id)) => {
            let candidate = ModelSelection {
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
            };
            // Building it IS the resolvability test, and the instance is kept: constructing a
            // second one to answer the same question would open a second client for nothing.
            match directory.build(&candidate) {
                Ok(provider) => (candidate, Some(provider), None),
                Err(error) => (
                    current_selection,
                    None,
                    Some(format!(
                        "the recorded route {provider_id}:{model_id} is not usable here ({error})"
                    )),
                ),
            }
        }
        Some((None, model_id)) => (
            current_selection,
            None,
            Some(format!(
                "this session predates provider identity and records only model `{model_id}`"
            )),
        ),
        None => (
            current_selection,
            None,
            Some("this session records no route".into()),
        ),
    };
    let provider = match built {
        Some(provider) => provider,
        None => match directory.build(&selection) {
            Ok(provider) => provider,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("cannot resume that session here: {error}"),
                );
                return;
            }
        },
    };

    // Takes the target run's exclusive writer lock. The live run keeps its own until the runtime
    // swaps them, so a refusal here costs the operator nothing.
    let rollout = match core_record::Rollout::open_existing(&runs, &run, tenant) {
        Ok(rollout) => rollout,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!(
                    "cannot take over session {}: {error}. Another core process may still be \
                     running it.",
                    ui_safe_text(run_id)
                ),
            );
            app.prepare_resume_handoff(run_id);
            return;
        }
    };

    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let reply = session
        .control(app_server::Control::AdoptRun(Box::new(
            app_server::AdoptRun {
                rollout,
                route: Box::new(app_server::ModelSelection {
                    provider,
                    provider_id: selection.provider_id.clone(),
                    model_id: selection.model_id.clone(),
                    catalog_digest,
                    capability_digest,
                    context_window_tokens: capabilities.context_window_tokens,
                    max_output_tokens: capabilities.max_output_tokens,
                }),
            },
        )))
        .await;
    let (adopted, state, blocked) = match reply {
        Some(app_server::ControlReply::Adopted {
            adopted,
            snapshot,
            blocked,
        }) => (adopted, snapshot, blocked),
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason);
            // The documented restart still works, so the operator keeps a way through.
            app.prepare_resume_handoff(run_id);
            return;
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the runtime is no longer reachable",
            );
            return;
        }
    };

    // Everything below renders the identity the RUNTIME reached. The frontend never displays a run
    // the next turn would not continue.
    clear_transcript_for_adoption(app);
    let (blocks, total) = adopted_transcript_blocks(&events);
    let rendered = blocks.len();
    if rendered < total {
        app.note(
            block::NoticeLevel::Info,
            format!(
                "showing the last {rendered} of {total} recorded transcript blocks; the model \
                 continues from all of them"
            ),
        );
    }
    for kind in blocks {
        app.push_block(kind);
    }

    session.adopt_run(adopted.rollout_path.clone(), (*state).clone());
    app.mode = state.mode;
    app.effort = state.effort;
    app.model = state.model.clone();
    app.cost = state.cost.clone();
    app.turns = adopted.turns;
    app.route = app.route.reselect(
        directory,
        &ModelSelection {
            provider_id: selection.provider_id.clone(),
            model_id: state.model.clone(),
        },
    );
    app.model_context_window = capabilities.context_window_tokens;
    clear_last_turn_telemetry_from(app, &state);
    app.status = format!("idle · resumed {}", adopted.run_id);

    if let Some(reason) = substituted {
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "{reason}; this session continues on {}:{}",
                selection.provider_id, selection.model_id
            ),
        );
    } else if let Some((recorded_provider, recorded_model)) = adopted
        .recorded_route
        .as_ref()
        .filter(|(provider_id, model_id)| {
            provider_id != &selection.provider_id || model_id != &selection.model_id
        })
    {
        // The kernel reports the route it restored FROM THE RECORD, independently of what this
        // frontend parsed out of the same events. A disagreement means the session is dispatching
        // on a route its own record does not name, which the operator has to be told.
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "the runtime restored route {recorded_provider}:{recorded_model} from that record, \
                 but this session dispatches on {}:{}",
                selection.provider_id, selection.model_id
            ),
        );
    }
    app.note(
        block::NoticeLevel::Ok,
        format!(
            "resumed {} here · {} · {} · {}:{} · left {}",
            adopted.run_id,
            block::plural(adopted.messages, "message"),
            block::plural(adopted.turns as usize, "turn"),
            selection.provider_id,
            state.model,
            adopted.previous_run_id
        ),
    );

    // The session moved and cannot dispatch. The identity above is still rendered — it is where the
    // runtime is — and this says, last and loudest, that the process has to be restarted to use it.
    if let Some(blocked) = blocked {
        app.note(block::NoticeLevel::Err, blocked);
        app.prepare_resume_handoff(&adopted.run_id);
    }
}

fn session_picker_items(
    mut sessions: Vec<core_record::SessionMeta>,
    current_run: &str,
) -> Vec<PickItem> {
    sessions.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| {
                right
                    .updated_at_subsec_nanos
                    .cmp(&left.updated_at_subsec_nanos)
            })
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
                PickAction::AdoptRun(run_id),
            )
        })
        .collect()
}

fn open_session_picker(app: &mut App, session: &Session) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before browsing sessions",
        );
        return;
    }
    let runs = session
        .rollout_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current_run = session
        .rollout_path()
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
        title: "Sessions · resume here".into(),
        items,
        sel,
        query: String::new(),
        saved_theme: None,
    });
}

fn open_tunables_picker(app: &mut App, session: &Session, argument: &str) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before browsing tunables",
        );
        return;
    }
    let argument = argument.trim();
    let (catalog, initial_query) = if argument == "load" {
        app.note(
            block::NoticeLevel::Err,
            "usage: /tunables load <workspace-relative-request.json>",
        );
        return;
    } else if let Some(path) = argument.strip_prefix("load ") {
        match tunables_view::load_workspace_request(session.workspace(), path.trim()) {
            Ok(catalog) => (catalog, String::new()),
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("tunables simulation refused: {error}"),
                );
                return;
            }
        }
    } else {
        (
            tunables_view::registry_catalog(),
            argument.chars().take(MAX_PICKER_QUERY_CHARS).collect(),
        )
    };
    let (title, entries) = catalog.into_parts();
    let items = entries
        .into_iter()
        .map(|detail| {
            PickItem::flat(
                detail.picker_label().to_owned(),
                detail.picker_hint().to_owned(),
                false,
                PickAction::InspectTunable(detail),
            )
        })
        .collect();
    let mut picker = Picker {
        title,
        items,
        sel: 0,
        query: String::new(),
        saved_theme: None,
    };
    picker.append_query_text(&initial_query);
    let visible = picker.visible_indices();
    picker.normalize_selection(&visible);
    app.picker = Some(picker);
}

/// Build a picker's items, pre-selecting the current value, and open it — refusing (with a Notice)
/// when a run/approval is in flight so accepting can never hit a taken agent (C6).
fn open_picker(app: &mut App, session: &Session, directory: &ProviderDirectory, kind: &str) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before opening a picker",
        );
        return;
    }
    let (title, mut items): (&str, Vec<PickItem>) = match kind {
        "model" => {
            let cur = session.model().to_string();
            (
                "Model",
                model_picker_items(directory, &app.route.provider_id, &cur),
            )
        }
        "effort" => {
            let cur = session.effort();
            let items = Effort::ALL
                .iter()
                .map(|e| PickItem::flat(e.label(), e.hint(), *e == cur, PickAction::SetEffort(*e)))
                .collect();
            ("Effort", items)
        }
        "mode" => (
            "Permission mode",
            mode_picker_items(session.permission_mode(), session.permission_rules()),
        ),
        "permissions" => (
            "Permissions",
            permission_picker_items(session.permission_rules()),
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

/// Test seam retained at the composition root: viewer and slash exports share one byte projection.
#[cfg(test)]
fn transcript_export_body(
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
) -> Result<Vec<u8>, String> {
    transcript_export::body(blocks, selected_ids)
}

#[cfg(all(test, target_os = "linux"))]
fn export_transcript(
    workspace: &Path,
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
    requested: &str,
) -> Result<PathBuf, String> {
    let bytes = transcript_export::body(blocks, selected_ids)?;
    transcript_export::export_bytes(
        workspace,
        requested,
        &bytes,
        transcript_export::CollisionPolicy::Refuse,
    )
    .map_err(|error| error.to_string())
}

fn schedule_transcript_viewer_effect(
    app: &mut App,
    workspace: &Path,
    supervisor: &mut transcript_effect::Supervisor,
    effect: transcript_viewer::Effect,
) {
    let snapshot_revision = effect.snapshot_revision();
    app.transcript_viewer
        .reconcile_if_changed(&app.transcript, app.transcript_revision);
    if snapshot_revision != app.transcript_revision {
        app.transcript_viewer
            .set_notice("transcript changed before the effect snapshot was captured");
        return;
    }
    if let Some(active) = supervisor.label() {
        app.transcript_viewer.set_notice(format!(
            "{active} already pending; effects are single-flight"
        ));
        return;
    }
    let request = match effect {
        transcript_viewer::Effect::Copy {
            text,
            subject,
            snapshot_revision: _,
        } => transcript_effect::Request::Copy {
            text,
            subject,
            origin: transcript_effect::Origin::Viewer,
        },
        transcript_viewer::Effect::Export {
            scope,
            snapshot_revision,
        } => {
            let ids = match app.transcript_viewer.export_ids(scope, snapshot_revision) {
                Ok(ids) => ids,
                Err(error) => {
                    app.transcript_viewer.set_notice(error);
                    return;
                }
            };
            let requested = match scope {
                transcript_viewer::ExportScope::Filtered => "core-transcript-filtered.md",
                transcript_viewer::ExportScope::All => "core-transcript.md",
            };
            transcript_effect::Request::Export {
                workspace: workspace.to_path_buf(),
                blocks: app.transcript.clone(),
                selected_ids: ids,
                requested: requested.into(),
                collision: transcript_export::CollisionPolicy::Versioned,
                origin: transcript_effect::Origin::Viewer,
            }
        }
    };
    let label = request.label();
    if supervisor.start(request).is_ok() {
        app.transcript_viewer.begin_effect(label);
    } else {
        app.transcript_viewer
            .set_notice("another transcript effect is already pending");
    }
}

fn open_transcript_viewer(app: &mut App, supervisor: &transcript_effect::Supervisor, query: &str) {
    app.transcript_viewer
        .open(query, &app.transcript, app.transcript_revision);
    if let Some(label) = supervisor.label() {
        app.transcript_viewer.begin_effect(label);
    }
}

fn schedule_slash_export(
    app: &mut App,
    workspace: &Path,
    supervisor: &mut transcript_effect::Supervisor,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
) {
    if let Some(active) = supervisor.label() {
        app.note(
            block::NoticeLevel::Warn,
            format!("export not started: {active} already pending"),
        );
        return;
    }
    let request = transcript_effect::Request::Export {
        workspace: workspace.to_path_buf(),
        blocks: app.transcript.clone(),
        selected_ids: None,
        requested: requested.into(),
        collision,
        origin: transcript_effect::Origin::Slash,
    };
    if supervisor.start(request).is_ok() {
        app.note(block::NoticeLevel::Info, "transcript export pending…");
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "transcript export not started: another effect is pending",
        );
    }
}

fn apply_transcript_effect_event(app: &mut App, event: transcript_effect::Event) {
    let message = ui_safe_text(&event.message);
    if event.origin == transcript_effect::Origin::Viewer && app.transcript_viewer.is_open() {
        if event.is_final() {
            app.transcript_viewer.finish_effect(message);
        } else {
            app.transcript_viewer.set_notice(message);
        }
        return;
    }
    let level = match event.outcome {
        transcript_effect::Disposition::Success => block::NoticeLevel::Ok,
        transcript_effect::Disposition::KnownFailure
        | transcript_effect::Disposition::OutcomeUnknown => block::NoticeLevel::Warn,
    };
    app.note(level, message);
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

/// Render the catalog the resident runtime can actually execute. The session fact is captured once
/// at App Server attach, so opening this panel performs no filesystem or ambient-home discovery.
fn show_agent_catalog(app: &mut App, session: &Session) {
    let catalog = session.agent_catalog();
    let mut rows: Vec<block::PanelRow> = catalog
        .defs()
        .iter()
        .map(|definition| item("⑂", &definition.name, &definition.description))
        .collect();
    if rows.is_empty() {
        rows.push(block::PanelRow::Note(
            "no agent definitions (built-in `generic` is normally available)".into(),
        ));
    }
    for error in catalog.errors() {
        rows.push(block::PanelRow::Note(format!(
            "rejected: {} ({})",
            error.source, error.reason
        )));
    }
    // `App::panel` applies the shared 120-row ceiling plus credential/control sanitization before
    // retaining any catalog-derived text in the transcript.
    app.panel("⑂", "agents", rows);
}

/// In-process half of the slash-command dispatcher (runs only while idle). Matching the typed
/// identity exhaustively makes a newly registered variant a compile error until it has a handler.
async fn handle_registered_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    transcript_effects: &mut transcript_effect::Supervisor,
    command: SlashCommand,
    arg: &str,
) {
    match command {
        SlashCommand::Help => {
            let mut rows: Vec<block::PanelRow> = commands::COMMANDS
                .iter()
                .map(|c| item("/", &format!("{} {}", c.name, c.args), c.help))
                .collect();
            rows.push(block::PanelRow::Note("keys: ↑↓ history · Ctrl-R prompt search · Ctrl-F transcript · Ctrl-G external editor · ←→/Ctrl-A/E/U/K/W edit · @file · !shell · Shift+Tab permission mode · Ctrl-T mouse/native selection · Ctrl-C interrupt".into()));
            rows.push(block::PanelRow::Note(
                "operator config: tui_keymap supports standard/vim and five conflict-checked actions; lifecycle keys remain reserved".into(),
            ));
            rows.push(block::PanelRow::Note(
                "while running: Enter steer · Tab queue · Ctrl-J newline · Alt-Up edit queued · Ctrl-End follow".into(),
            ));
            app.panel("?", "commands", rows);
        }
        SlashCommand::Clear => {
            app.transcript.clear();
            app.mark_transcript_changed();
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
        SlashCommand::Effort => {
            if arg.is_empty() {
                open_picker(app, session, directory, "effort"); // interactive picker (R7.a)
            } else if let Some(e) = core_protocol::Effort::parse(arg) {
                if commit_effort(app, session, e).await {
                    app.push(fg(Color::Green), format!("effort set to {}", e.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown effort (low|medium|high|xhigh|max|ultracode)",
                );
            }
        }
        SlashCommand::Model => {
            if arg.is_empty() {
                open_picker(app, session, directory, "model"); // interactive picker (R7.a)
            } else if arg == "retry" || arg.starts_with("retry ") {
                let value = arg.strip_prefix("retry").unwrap_or_default().trim();
                let selection = match model_retry_selection(
                    directory,
                    &app.route.provider_id,
                    session.model(),
                    value,
                ) {
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
                    Ok(true) => apply_model_selection(app, session, directory, selection).await,
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
                match directory.resolve_model(arg, Some(&app.route.provider_id)) {
                    Ok(selection) => {
                        apply_model_selection(app, session, directory, selection).await
                    }
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("cannot select model: {error}"),
                    ),
                }
            }
        }
        SlashCommand::Theme => {
            open_picker(app, session, directory, "theme");
        }
        SlashCommand::Status => {
            let run = session
                .rollout_path()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            // Every route row comes from the one resolved view; only the live runtime policy
            // (effort/mode/cwd) is read off the session.
            let mut rows: Vec<block::PanelRow> = app
                .route
                .rows()
                .iter()
                .map(|(key, value)| kv(key, value))
                .collect();
            rows.push(kv("effort requested", session.effort().label()));
            if let Some(application) = app.effort_application {
                rows.push(kv(
                    "effort applied",
                    &effort_application_detail(application),
                ));
            } else {
                rows.push(kv("effort applied", "not observed yet"));
            }
            rows.extend([
                kv("mode", session.permission_mode().label()),
                kv("cwd", &session.workspace().display().to_string()),
                kv("run", &run),
            ]);
            // Before a rejection, not after it: this is the only place the operator can see the
            // budget shrinking while there is still time to act on it (I-53).
            rows.push(kv(
                "provider quota",
                session
                    .rate_limit()
                    .unwrap_or("not published by this route"),
            ));
            rows.push(block::PanelRow::Note(session.ledger_summary().to_string()));
            app.panel("≡", "status", rows);
        }
        SlashCommand::Cost => {
            app.panel(
                "$",
                "cost",
                vec![block::PanelRow::Note(session.ledger_summary().to_string())],
            );
        }
        SlashCommand::Budget => {
            // The turn ceiling counts the whole session, so it is the one budget an operator can
            // saturate mid-task with no way out except restarting the process. `/budget <turns>`
            // is that way out; the bare form shows how close the session already is.
            let requested = arg.trim();
            let set = if requested.is_empty() {
                None
            } else {
                match requested.parse::<u32>() {
                    Ok(turns) => Some(turns),
                    Err(_) => {
                        app.push(fg(Color::Red), "usage: /budget [turns]");
                        return;
                    }
                }
            };
            match session
                .control(app_server::Control::TurnBudget { set })
                .await
            {
                Some(app_server::ControlReply::TurnBudget(state)) => {
                    if set.is_some() {
                        app.note(
                            block::NoticeLevel::Ok,
                            format!(
                                "turn ceiling is now {} ({} used, {} left this session)",
                                state.max_turns,
                                state.used,
                                state.remaining()
                            ),
                        );
                    } else {
                        app.panel(
                            "◷",
                            "turn budget",
                            vec![
                                kv("ceiling", &state.max_turns.to_string()),
                                kv(
                                    "used",
                                    &format!("{} (this session, subagents included)", state.used),
                                ),
                                kv("remaining", &state.remaining().to_string()),
                                block::PanelRow::Note(
                                    "/budget <turns> raises the ceiling without restarting".into(),
                                ),
                            ],
                        );
                    }
                }
                Some(app_server::ControlReply::Refused(reason)) => app.note(
                    block::NoticeLevel::Err,
                    format!("the turn ceiling was not changed: {reason}"),
                ),
                _ => app.note(
                    block::NoticeLevel::Err,
                    "the runtime is no longer reachable",
                ),
            }
        }
        SlashCommand::Context => {
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
                    fmt_token_count(session.compaction_trigger_tokens() as u64)
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
        SlashCommand::Mode => {
            if arg.is_empty() {
                open_picker(app, session, directory, "mode"); // interactive picker (Shift+Tab still cycles)
            } else if let Some(m) = PermissionMode::parse(arg) {
                if commit_permission_mode(app, session, m).await {
                    app.push(fg(Color::Green), format!("mode set to {}", m.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown mode (default|acceptEdits|plan|yolo)",
                );
            }
        }
        SlashCommand::Permissions => {
            let mut sub = arg.split_whitespace();
            match sub.next() {
                None => open_picker(app, session, directory, "permissions"),
                Some("show" | "list") => {
                    let mut rows = vec![kv("mode", session.permission_mode().label())];
                    let rules = session.permission_rules().describe();
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
                            if commit_permission_capability(app, session, c, v).await {
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
        SlashCommand::AllowCode => match arg {
            "on" | "true" | "" => {
                if commit_permission_capability(
                    app,
                    session,
                    Capability::CodeExecuting,
                    Verdict::Auto,
                )
                .await
                {
                    app.push(
                        fg(Color::Yellow),
                        "code execution ALLOWED (egress-off sandbox)",
                    );
                }
            }
            "off" | "false" => {
                if commit_permission_capability(
                    app,
                    session,
                    Capability::CodeExecuting,
                    Verdict::Ask,
                )
                .await
                {
                    app.push(fg(Color::Yellow), "code execution now asks per call");
                }
            }
            _ => app.push(fg(Color::Red), "usage: /allow-code on|off"),
        },
        SlashCommand::Memory => {
            let ws = session.memory_workspace();
            let Some(ws) = ws else {
                app.push(fg(Color::Red), "memory not available");
                return;
            };
            let store = core_ctx::MemoryStore::at(ws);
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
        SlashCommand::Diff => {
            // Reuse the same absolute-executable, filter-disabled, process-group-bounded runner as
            // the registry tool. This operator command is still awaiting the universal effect WAL.
            let stat = arg.trim() == "stat";
            match core_tools::git_diff_observation(session.workspace(), stat, None).await {
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
        SlashCommand::Sessions => {
            open_session_picker(app, session);
        }
        SlashCommand::Workflows => {
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
            // QuickJS `core-workflow` phase→agent trees (design §3.3), newest first.
            for card in app.transcript.iter().rev().filter_map(|entry| {
                if let block::BlockKind::WorkflowRun(card) = &entry.kind {
                    Some(card)
                } else {
                    None
                }
            }) {
                let done = card
                    .agents
                    .iter()
                    .filter(|a| a.state == core_workflow::events::WorkflowState::Done)
                    .count();
                let status = if card.finished { "finished" } else { "running" };
                rows.push(block::PanelRow::Item {
                    label: format!("{} · {status}", card.name),
                    hint: format!("{} · {done}/{} agents", card.run_id, card.agents.len()),
                });
            }
            if rows.is_empty() {
                rows.push(block::PanelRow::Note(
                    "no workflow has run in this transcript".into(),
                ));
            }
            app.panel("", "workflows", rows);
        }
        SlashCommand::Fork => {
            // Fork the CURRENT session at its tail into a new branch (shared past, divergent future).
            let path = session.rollout_path().to_path_buf();
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
        SlashCommand::Agents => {
            show_agent_catalog(app, session);
        }
        SlashCommand::Skills => {
            let cat = match core_ctx::skills::user_skills_dir() {
                Some(user) => core_ctx::skills::SkillCatalog::discover(&user, session.workspace()),
                None => core_ctx::skills::SkillCatalog::discover_without_user(session.workspace()),
            };
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
        SlashCommand::Config => {
            // `/config` used to re-read the REPOSITORY config document, so it reported what was on
            // disk instead of the layered value the kernel enforces: `core --max-turns 5` printed
            // `max_turns: default`. It reads the one resolved route and the same effective limits
            // the budget was built from (I-26).
            let mut rows: Vec<block::PanelRow> = app
                .route
                .rows()
                .iter()
                .map(|(key, value)| kv(key, value))
                .collect();
            rows.push(kv("effort", session.effort().label()));
            rows.push(kv("mode", session.permission_mode().label()));
            for (key, value) in app.route.limits.rows() {
                rows.push(kv(key, &value));
            }
            rows.push(block::PanelRow::Note(
                "persist a choice with `core config set <key> <value>`".into(),
            ));
            app.panel("⚙", "config", rows);
        }
        SlashCommand::Tunables => {
            open_tunables_picker(app, session, arg);
        }
        SlashCommand::Login => {
            // The credential half of the setup state machine deliberately does NOT run here. A
            // pasted key inside the TUI would land in a rendered, scrollable transcript buffer;
            // `core setup` owns collection precisely so a secret never reaches this surface.
            // What `/login` runs is the rest of the same machine: name the credential source, then
            // ask the provider whether it actually works, which is the check that used to happen
            // only on the first paid turn.
            let provider_id = if arg.trim().is_empty() {
                app.route.provider_id.clone()
            } else {
                arg.trim().to_owned()
            };
            let mut rows = vec![
                kv("provider", &provider_id),
                kv("api_root", &app.route.api_root),
                kv("credential", &app.route.credential),
            ];
            match directory.entry(&provider_id) {
                Some(entry) => {
                    rows.push(kv("state", &directory.status_label(entry)));
                    if let Some(reason) = directory.blocked_reason(entry) {
                        rows.push(kv("blocked", &reason));
                    }
                }
                None => rows.push(kv("state", &directory.resolution_error(&provider_id))),
            }
            rows.push(block::PanelRow::Note(format!(
                "sign in or replace this credential with `core setup --byok {provider_id}` (or `core setup --plan`); inspect it with `core auth status`"
            )));
            app.panel("⚿", "login", rows);
        }
        SlashCommand::Tools => {
            // Visualize every tool + its capability tier + purity (user: tool 所有能的可视化).
            let cap_glyph = |c: Capability| match c {
                Capability::ReadOnly => "read-only",
                Capability::ReversibleLocal => "edits (reversible)",
                Capability::CodeExecuting => "runs code",
                Capability::TrustMutating => "trust-mutating",
                Capability::IrreversibleExternal => "external/egress",
            };
            let mut tools: Vec<&app_server::ToolFact> = session.registry_tools().iter().collect();
            tools.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: Vec<block::PanelRow> = tools
                .iter()
                .map(|tool| block::PanelRow::Item {
                    label: format!("{}  [{}]", tool.name, cap_glyph(tool.capability)),
                    hint: core_protocol::text::head(&tool.description, 70),
                })
                .collect();
            app.panel("⚙", &format!("{} tools available", rows.len()), rows);
        }
        SlashCommand::Mcp => {
            let mcp: Vec<_> = session
                .registry_tools()
                .iter()
                .filter(|tool| tool.name.contains("__"))
                .collect();
            if mcp.is_empty() {
                app.note(
                    block::NoticeLevel::Info,
                    "no MCP tools connected (configure servers in ~/.core/config.json)",
                );
            } else {
                let rows = mcp
                    .iter()
                    .map(|tool| {
                        item(
                            "◈",
                            &tool.name,
                            &core_protocol::text::head(&tool.description, 80),
                        )
                    })
                    .collect();
                app.panel("◈", "MCP tools", rows);
            }
        }
        SlashCommand::Hooks => {
            let hooks = core_protocol::home::operator()
                .map(|home| crate::runtime::hooks::Hooks::load_user(&home))
                .unwrap_or_default();
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
        SlashCommand::Transcript => {
            open_transcript_viewer(app, transcript_effects, arg.trim());
        }
        SlashCommand::Export => {
            let (requested, collision) = if arg.trim().is_empty() {
                (
                    "core-transcript.md",
                    transcript_export::CollisionPolicy::Versioned,
                )
            } else {
                (arg.trim(), transcript_export::CollisionPolicy::Refuse)
            };
            schedule_slash_export(
                app,
                session.workspace(),
                transcript_effects,
                requested,
                collision,
            );
        }
        SlashCommand::Init => {
            let dir = match ensure_real_workspace_dir(session.workspace(), ".core") {
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
                let starter = crate::config::starter_project_config();
                match write_new_synced(&cfg, starter.as_bytes()) {
                    Ok(_) => app.push(fg(Color::Green), format!("wrote {}", cfg.display())),
                    Err(e) => app.push(fg(Color::Red), format!("init failed: {e}")),
                }
            }
            let agents_md = session.workspace().join("AGENTS.md");
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
        SlashCommand::Rewind => {
            // Conversation rewind: branch at an EARLIER seq (shared past, divergent future). With no
            // arg it lists the turn boundaries; `/rewind <seq>` forks at that point. (Workspace-file
            // rewind needs recorded checkpoints, which normal runs don't yet emit — honest gap.)
            let path = session.rollout_path().to_path_buf();
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
        SlashCommand::Resume => {
            if arg.is_empty() {
                open_session_picker(app, session);
            } else {
                let runs = session
                    .rollout_path()
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                let exists = core_record::list(&runs, &core_protocol::TenantId::default())
                    .iter()
                    .any(|session| session.run_id.0 == arg);
                if exists {
                    adopt_session(app, session, directory, arg).await;
                } else {
                    app.note(
                        block::NoticeLevel::Err,
                        format!("no recorded session with run id `{}`", ui_safe_text(arg)),
                    );
                }
            }
        }
        SlashCommand::Quit => app.quit = true,
        SlashCommand::Compact => app.note(
            block::NoticeLevel::Err,
            "compact requires the interactive terminal dispatcher",
        ),
        SlashCommand::Side => app.note(
            block::NoticeLevel::Err,
            "side conversations require the interactive terminal dispatcher",
        ),
    }
}

/// Project one live event into retained UI state, then send any fixed terminal notification
/// directly through the backend. Keeping the writer outside `App` makes it impossible for an OSC
/// payload to enter transcript blocks or ratatui's frame buffer.
fn apply_live_event<T: notification::NotificationTransport + ?Sized>(
    app: &mut App,
    ev: UiEvent,
    notifier: &mut notification::TerminalNotifier,
    writer: &mut T,
) {
    let trigger = notifier.trigger_for_event(&ev);
    apply_event(app, ev);
    if let Some(trigger) = trigger {
        notifier.emit_transport(writer, trigger);
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
        UiEvent::Phase(p) => {
            // Entering the model phase starts the first-token clock; every other phase stops it,
            // because only a model request can be waiting on a provider's first byte (I-64).
            app.awaiting_first_token_since = (p == core_protocol::Phase::Model).then(Instant::now);
            app.status = p.label().into();
        }
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
            app.transcript_viewer.close();
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

pub(crate) fn clip_text(text: &str, width: u16) -> String {
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
    // Mouse ownership is persistent user-facing state, but yields first when a narrow status row
    // needs its safety/liveness text. The hint row independently keeps the Ctrl-T action visible.
    let mut bits = vec![app.mouse_capture.status_label().to_string()];
    if app.keymap_status != "keys:standard" {
        bits.push(app.keymap_status.clone());
    }
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

    let mut left = if app.draining {
        vec![
            Span::styled("! ", warn),
            Span::styled("draining · checkpointing at a safe point", warn),
        ]
    } else if app.pending.is_some() {
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
    } else if let Some(stall) = app.first_token_stall() {
        // A dead connection and a slow prefill are the same picture for a full minute unless the
        // interface says which one it is looking at, and it knows: no token has arrived yet
        // (I-64). Both states still spin, because the request is genuinely still open.
        let style = match stall.state {
            FirstTokenState::Slow => accent,
            FirstTokenState::Stalled => warn,
        };
        vec![
            Span::styled(format!("{} ", SPINNER[app.spin % SPINNER.len()]), style),
            Span::styled(stall.label(), style),
        ]
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

fn render_composer(f: &mut Frame, area: Rect, app: &mut App) {
    app.composer_hitbox = None;
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
    let image_count = app.editor.attachments().len();
    let file_count = app.editor.files().len();
    let attachment_count = image_count + file_count;
    let is_bash = text.starts_with('!');
    let line_color = if app.pending.is_some() {
        app.theme.warn
    } else if !text.is_empty() || attachment_count > 0 || app.running {
        app.theme.accent
    } else {
        app.theme.border
    };
    let mut title = if app.pending.is_some() {
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
    }
    .to_owned();
    if app.pending.is_none() && image_count > 0 {
        title.push_str(&format!(
            " · {image_count} image{}",
            if image_count == 1 { "" } else { "s" }
        ));
    }
    if app.pending.is_none() && file_count > 0 {
        title.push_str(&format!(
            " · {file_count} file{}",
            if file_count == 1 { "" } else { "s" }
        ));
    }
    // One frame owns the complete input/approval surface. Tiny terminals cannot spare two border
    // rows, so they deliberately fall back to the unframed fail-closed control above/below.
    let body = if area.width >= 3 && area.height >= 3 {
        let composer = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(line_color))
            .title(format!(
                " {} ",
                clip_text(&title, area.width.saturating_sub(4))
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

    let input_body = if attachment_count > 0 && body.height > 0 {
        let chip_area = Rect::new(body.x, body.y, body.width, 1);
        let mut chips = String::new();
        for (index, attachment) in app.editor.attachments().as_slice().iter().enumerate() {
            if index > 0 {
                chips.push_str("  ");
            }
            chips.push_str("▧ ");
            chips.push_str(attachment.display_name());
            chips.push_str(" · ");
            chips.push_str(&format_attachment_size(attachment.file_bytes()));
        }
        // File chips share the row and the glyph grammar: a different mark, the same sanitised
        // label and the same honest byte count. Nothing here prints file text.
        for (index, attachment) in app.editor.files().as_slice().iter().enumerate() {
            if index > 0 || image_count > 0 {
                chips.push_str("  ");
            }
            chips.push_str("▤ ");
            chips.push_str(attachment.display_name());
            chips.push_str(" · ");
            chips.push_str(&format_attachment_size(attachment.text_bytes()));
        }
        let suffix = if body.width >= 36 {
            "  alt+backspace removes last"
        } else {
            ""
        };
        chips.push_str(suffix);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                clip_text(&chips, chip_area.width),
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ))),
            chip_area,
        );
        Rect::new(
            body.x,
            body.y.saturating_add(1),
            body.width,
            body.height.saturating_sub(1),
        )
    } else {
        body
    };
    if input_body.height == 0 {
        return;
    }

    let marker_color = if is_bash {
        app.theme.warn
    } else {
        app.theme.accent
    };
    let marker = if is_bash { "! " } else { "› " };
    let marker_area = Rect::new(
        input_body.x,
        input_body.y,
        input_body.width.min(2),
        input_body.height,
    );
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
        input_body.x.saturating_add(2),
        input_body.y,
        input_body.width.saturating_sub(2),
        input_body.height,
    );
    let (crow, ccol) = app.editor.cursor_row_col();
    let cur_line = text.split('\n').nth(crow).unwrap_or("");
    let cur_disp = display_col(cur_line, ccol);
    let scroll_x = cur_disp.saturating_sub(text_area.width.saturating_sub(1));
    let crow_u16 = u16::try_from(crow).unwrap_or(u16::MAX);
    let scroll_y = crow_u16.saturating_sub(text_area.height.saturating_sub(1));
    app.composer_hitbox = Some(ComposerHitbox {
        text_area,
        scroll_x,
        scroll_y,
    });

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

fn format_attachment_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn route_label(app: &App) -> String {
    // The statusline used to build `provider/model` out of two loose `App` fields. It reads the
    // one route view now, so it cannot label a request the run is not making (I-26).
    app.route.short_label()
}

fn footer_spans(text: &str, theme: &theme::Theme) -> Vec<Span<'static>> {
    const KEYS: &[&str] = &[
        "enter",
        "tab",
        "esc",
        "ctrl+j",
        "ctrl+t",
        "ctrl+v",
        "ctrl+z",
        "ctrl+g",
        "ctrl+r",
        "alt+↑",
        "alt+backspace",
        "ctrl+end",
        "y",
        "a",
        "n",
        "n/esc",
        "/",
        "@",
        "!",
        "?",
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
    } else if !text.is_empty() || app.editor.chip_count() > 0 {
        "enter send · ctrl+j newline · ctrl+g edit · alt+backspace remove chip · esc clear"
    } else if density == surface::Density::Compact {
        "/ commands · @ image/file · ctrl+v image · ? help"
    } else {
        "/ commands · @ image/file · ctrl+v image · ! shell · ? help"
    };
    let left = if !app.running && text.is_empty() && app.editor.has_recently_cleared() {
        format!("{left} · ctrl+z restore")
    } else {
        left.to_string()
    };
    let left = format!("{left} · {}", app.mouse_capture.hint());
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
    // Incremental: `cur_text` only ever grows between stream boundaries, and `cur_doc` is dropped at
    // every boundary, so `cur_doc == None` is exactly the "this is a new document" signal and is the
    // one place the settled prefix has to be reset. Re-parsing the whole accumulated answer on every
    // delta batch is quadratic in answer length, which is why long answers visibly slowed down as
    // they streamed.
    if app.cur_doc.is_none() {
        app.cur_doc = Some(crate::markdown::MarkdownDoc { blocks: Vec::new() });
        app.cur_doc_parse = crate::markdown::StreamingParse::default();
    }
    let doc = app.cur_doc.as_mut().expect("just ensured a live document");
    app.cur_doc_parse.extend(doc, &app.cur_text);
    app.cur_doc_revision = app.cur_text_revision;
    true
}

/// Where one contiguous run of transcript rows lives while a frame is being laid out. Nothing here
/// owns a copy of the rows: a settled block points at the per-block render cache by id, the animated
/// and streaming pieces point into this frame's `live` arena, and a gap is pure geometry.
enum TranscriptRows {
    Blank,
    Cached(u64),
    Live(usize),
}

/// Copy one already-rendered run's `[from, to)` rows into the frame's viewport buffers. Hyperlink
/// rows are translated into ABSOLUTE transcript coordinates (what `apply_to_buffer` subtracts the
/// scroll from); `row_map` receives one entry per VISIBLE row.
#[allow(clippy::too_many_arguments)]
fn push_viewport_rows(
    rendered: &crate::render::RenderedLines,
    block_index: usize,
    segment_start: usize,
    from: usize,
    to: usize,
    lines: &mut Vec<Line<'static>>,
    row_map: &mut Vec<usize>,
    hyperlinks: &mut Vec<crate::render::HyperlinkRegion>,
) {
    for row in from..to {
        lines.push(rendered.lines[row].clone());
        row_map.push(block_index);
    }
    for region in &rendered.hyperlinks {
        if region.row >= from && region.row < to {
            let mut region = region.clone();
            region.row = region.row.saturating_add(segment_start);
            hyperlinks.push(region);
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    // A newly arrived capability decision outranks optional inspection chrome. The viewer cannot
    // hide a fail-closed approval surface while the runtime is blocked on it.
    if app.pending.is_some() && app.transcript_viewer.is_open() {
        app.transcript_viewer.close();
    }
    if app.transcript_viewer.is_open() {
        transcript_viewer::render(f, &mut app.transcript_viewer, &app.theme);
        return;
    }
    // The dock grows for multiline input, bounded to six editable rows. A blocking approval asks
    // for the full six-row decision surface; short terminals degrade through Surface::resolve.
    let n_input_rows = (app.editor.text().split('\n').count().clamp(1, 6) as u16)
        .saturating_add(u16::from(app.editor.chip_count() > 0))
        .min(6);
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
        0,
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
    // scrollbar owns its own stage-gutter rect. Reserving it before wrapping keeps the indicator
    // from overwriting the final evidence cell when the transcript overflows.
    let inner_w = surface.transcript_content_width();
    if app.render_cache_width != inner_w || app.render_cache_theme_epoch != app.theme_epoch {
        app.render_cache.clear();
        app.render_cache_width = inner_w;
        app.render_cache_theme_epoch = app.theme_epoch;
    }
    // Streaming Markdown is parsed only when provider text changes. Active frames still re-render
    // at 10 fps for the caret/activity animation, but unchanged deltas do not repeatedly rebuild
    // the semantic document.
    ensure_stream_doc(app);
    // A frame no longer materialises the whole transcript. Pass one renders only what is missing —
    // into the per-block cache, or into `live` for the animated cards that must not be cached — and
    // records how many rows each piece occupies. Pass two adds the counts up to place the viewport.
    // Pass three copies ONLY the rows the viewport shows. The old walk cloned every cached
    // `RenderedLines` and extended one flat vector with them, so a settled session paid for its
    // whole history on every single frame.
    let mut live: Vec<crate::render::RenderedLines> = Vec::new();
    let mut plan: Vec<(TranscriptRows, usize, usize)> = Vec::new();
    let mut total_rows: usize = 0;
    {
        let theme = &app.theme;
        let spin = app.spin;
        let hyperlink_policy = &app.hyperlink_policy;
        let render_cache = &mut app.render_cache;
        for (bi, b) in app.transcript.iter().enumerate() {
            if bi > 0 {
                // Variable rhythm (critique P1): a bigger gap at real turn boundaries, none between
                // adjacent tool cards / notices / dividers, so structure is scannable, not monotone.
                let gap = usize::from(block::gap_before(&app.transcript[bi - 1].kind, &b.kind));
                if gap > 0 {
                    plan.push((TranscriptRows::Blank, gap, usize::MAX));
                    total_rows += gap;
                }
            }
            let rows = if b.cacheable() {
                if render_cache.get(&b.id).map(|(revision, _)| *revision) != Some(b.revision) {
                    let rendered = b.render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy);
                    render_cache.insert(b.id, (b.revision, rendered));
                }
                let count = render_cache
                    .get(&b.id)
                    .map_or(0, |(_, rendered)| rendered.lines.len());
                plan.push((TranscriptRows::Cached(b.id), count, bi));
                count
            } else {
                let rendered = b.render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy);
                let count = rendered.lines.len();
                plan.push((TranscriptRows::Live(live.len()), count, bi));
                live.push(rendered);
                count
            };
            total_rows += rows;
        }
        // live streaming blocks (reasoning, then the in-flight answer) through the SAME render path
        if !app.cur_think.trim().is_empty() {
            if total_rows > 0 {
                plan.push((TranscriptRows::Blank, 1, usize::MAX));
                total_rows += 1;
            }
            let tb = block::Block::new(
                u64::MAX,
                block::BlockKind::Thinking {
                    text: app.cur_think.clone(),
                    open: true,
                },
            );
            let rendered = crate::render::RenderedLines::plain(tb.render(inner_w, theme, spin));
            let count = rendered.lines.len();
            plan.push((TranscriptRows::Live(live.len()), count, usize::MAX));
            live.push(rendered);
            total_rows += count;
        }
        if !app.cur_text.trim().is_empty() {
            if total_rows > 0 {
                plan.push((TranscriptRows::Blank, 1, usize::MAX));
                total_rows += 1;
            }
            let mut rendered = block::render_assistant_doc_with_hyperlinks(
                app.cur_doc
                    .as_ref()
                    .expect("non-empty streaming text has a parsed document"),
                inner_w,
                theme,
                hyperlink_policy,
            );
            // blinking caret on the last row while streaming
            if app.running
                && (app.spin / 4).is_multiple_of(2)
                && let Some(last) = rendered.lines.last_mut()
                && crate::render::line_width(last) < inner_w
            {
                last.spans
                    .push(Span::styled("▋", Style::default().fg(theme.role_assistant)));
            }
            let count = rendered.lines.len();
            plan.push((TranscriptRows::Live(live.len()), count, usize::MAX));
            live.push(rendered);
            total_rows += count;
        }
    }
    let total = u16::try_from(total_rows).unwrap_or(u16::MAX); // saturating (review LOW: >65535 rows)
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
    // Pass three: materialise the window only. `hyperlink_regions` keeps ABSOLUTE transcript rows —
    // that is the coordinate `apply_to_buffer` subtracts the scroll from — while `row_map` is now
    // viewport-relative, because the hit-test already knows which row the viewport starts at.
    let first_row = usize::from(scroll);
    let last_row = first_row
        .saturating_add(usize::from(view_h))
        .min(total_rows);
    let window = last_row.saturating_sub(first_row);
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(window);
    let mut row_map: Vec<usize> = Vec::with_capacity(window); // block index per VISIBLE row (usize::MAX = spacer/stream)
    let mut hyperlink_regions = Vec::new();
    let mut cursor = 0usize;
    for (rows, count, bi) in &plan {
        let segment_start = cursor;
        cursor = cursor.saturating_add(*count);
        if cursor <= first_row || segment_start >= last_row {
            continue;
        }
        let from = first_row.max(segment_start) - segment_start;
        let to = last_row.min(cursor) - segment_start;
        match rows {
            TranscriptRows::Blank => {
                for _ in from..to {
                    lines.push(Line::from(""));
                    row_map.push(usize::MAX);
                }
            }
            TranscriptRows::Cached(id) => {
                if let Some((_, rendered)) = app.render_cache.get(id) {
                    push_viewport_rows(
                        rendered,
                        *bi,
                        segment_start,
                        from,
                        to,
                        &mut lines,
                        &mut row_map,
                        &mut hyperlink_regions,
                    );
                }
            }
            TranscriptRows::Live(index) => push_viewport_rows(
                &live[*index],
                *bi,
                segment_start,
                from,
                to,
                &mut lines,
                &mut row_map,
                &mut hyperlink_regions,
            ),
        }
    }
    // stash viewport params for mouse hit-testing (click-to-fold, wheel scroll — R9)
    app.row_map = row_map;
    app.view_top = surface.transcript.y;
    app.view_scroll = scroll;
    app.view_h = view_h;
    let transcript = Paragraph::new(lines); // NO .wrap(): rows == scroll units, and only the window is built
    f.render_widget(transcript, surface.transcript);
    hyperlink::apply_to_buffer(
        f.buffer_mut(),
        surface.transcript,
        scroll,
        &hyperlink_regions,
        &app.hyperlink_policy,
    );

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

    #[test]
    fn agents_panel_renders_the_attached_catalog_after_the_filesystem_drifts() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let workspace = std::env::temp_dir().join(format!(
            "core-tui-agent-snapshot-{}-{nonce}",
            std::process::id()
        ));
        let definitions = workspace.join(".core/agents");
        std::fs::create_dir_all(&definitions).unwrap();
        let pinned_path = definitions.join("pinned.md");
        std::fs::write(
            &pinned_path,
            "---\nname: pinned-reviewer\ndescription: Pinned before attach.\n---\nReview the run.\n",
        )
        .unwrap();
        const SECRET: &str = "ghp_AbCdEf1234567890AbCdEf1234567890";
        std::fs::write(
            definitions.join(format!("{SECRET}.md")),
            "not front matter\n",
        )
        .unwrap();

        let pinned = core_agents::AgentCatalog::discover_without_user(&workspace);
        let pinned_digest = pinned.execution_digest();
        assert!(pinned.get("pinned-reviewer").is_some());
        assert!(
            pinned
                .errors()
                .iter()
                .any(|error| error.source.contains(SECRET)),
            "the fixture must put credential-shaped source text on the display path"
        );

        let (submissions, _submission_rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(submissions);
        session.facts.workspace = workspace.clone();
        session.facts.agent_catalog = Arc::new(pinned);

        std::fs::remove_file(pinned_path).unwrap();
        std::fs::write(
            definitions.join("late.md"),
            "---\nname: late-reviewer\ndescription: Added after attach.\n---\nReview later.\n",
        )
        .unwrap();
        let live = core_agents::AgentCatalog::discover_without_user(&workspace);
        assert!(live.get("pinned-reviewer").is_none());
        assert!(live.get("late-reviewer").is_some());

        let mut app = App::new();
        show_agent_catalog(&mut app, &session);
        let retained = app.transcript.last().expect("agents panel").to_text();
        assert!(retained.contains("pinned-reviewer"));
        assert!(!retained.contains("late-reviewer"));
        assert!(!retained.contains(SECRET));
        assert!(retained.contains("[REDACTED"));

        let screen = render_text(&mut app, 200, 32);
        assert!(screen.contains("pinned-reviewer"));
        assert!(!screen.contains("late-reviewer"));
        assert!(!screen.contains(SECRET));
        assert!(screen.contains("[REDACTED"), "{screen}");
        assert_eq!(session.agent_catalog().execution_digest(), pinned_digest);

        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn continuously_refilled_1024_eq_yields_every_tick_to_control_and_draw_phases() {
        let mut queue = (0..1024usize).collect::<VecDeque<_>>();
        let mut next = 1024usize;
        let mut draws = 0usize;
        let mut inputs = 0usize;
        let mut effects = 0usize;
        let mut effect_pending = true;

        for _tick in 0..32 {
            let mut drained = 0usize;
            for _ in eq_tick_slots() {
                let _event = queue.pop_front().expect("permanent EQ backlog");
                drained += 1;
                queue.push_back(next);
                next += 1;
            }
            assert_eq!(drained, MAX_EQ_EVENTS_PER_TICK);
            assert_eq!(queue.len(), 1024, "the fixture remains permanently ready");

            // The draw phase precedes the select. With a one-shot effect and continuously ready
            // input, the production select consumes the effect first and input on every later
            // tick; the ready EQ never takes either control slot.
            draws += 1;
            if effect_pending {
                effects += 1;
                effect_pending = false;
            } else {
                inputs += 1;
            }
        }

        assert_eq!((draws, effects, inputs), (32, 1, 31));
        assert_eq!(next, 1024 + 32 * MAX_EQ_EVENTS_PER_TICK);

        // A lifecycle signal is the first biased branch and therefore wins its very first service
        // point even when effect, input, and EQ are simultaneously ready; the real loop then exits.
        let signal_ready = true;
        let effect_ready = true;
        let input_ready = true;
        let selected = [
            ("signal", signal_ready),
            ("effect", effect_ready),
            ("input", input_ready),
            ("eq", !queue.is_empty()),
        ]
        .into_iter()
        .find_map(|(lane, ready)| ready.then_some(lane));
        assert_eq!(selected, Some("signal"));
    }

    #[test]
    fn active_keyboard_panic_restore_pops_once_and_restores_terminal_modes() {
        let controller = keyboard_enhancement::Controller::default();
        let restorer = controller.restorer();
        let mut output = Vec::new();

        assert!(controller.negotiate_with(&mut output, true).unwrap());
        assert!(restore_terminal_after_panic_to(&restorer, &mut output));

        for sequence in [
            b"\x1b[<1u".as_slice(),
            b"\x1b[?2004l".as_slice(),
            b"\x1b[?25h".as_slice(),
            b"\x1b[?1049l".as_slice(),
        ] {
            assert!(
                output
                    .windows(sequence.len())
                    .any(|bytes| bytes == sequence),
                "panic restore omitted {sequence:?}"
            );
        }
        assert_eq!(
            output
                .windows(b"\x1b[<1u".len())
                .filter(|bytes| *bytes == b"\x1b[<1u")
                .count(),
            1
        );

        let after_panic_restore = output.clone();
        assert_eq!(
            restorer.restore(&mut output).unwrap(),
            keyboard_enhancement::RestoreOutcome::AlreadyInactive
        );
        assert_eq!(output, after_panic_restore);
    }

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
            pricing_schema_version: 2,
            projection_schema_version: 1,
            run_id: core_protocol::RunId(run_id.into()),
            tenant: core_protocol::TenantId::default(),
            cwd: std::path::PathBuf::from("/tmp/project"),
            provider_id: provider_id.into(),
            model: model.into(),
            effort: Effort::Medium,
            agent_definition_tag: None,
            title: title.into(),
            created_at: updated_at.saturating_sub(10),
            updated_at,
            updated_at_subsec_nanos: 0,
            record_bytes: 100,
            record_tail_seq: None,
            record_tail_hash: String::new(),
            projection_digest: String::new(),
            ancestry: Vec::new(),
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
    fn picker_paste_is_bounded_sanitized_and_never_mutates_the_composer() {
        const IMAGE: &[u8] = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";

        let mut app = App::new();
        app.editor.insert_str("draft-你好");
        app.editor.set_cursor(3);
        app.editor
            .attach_image_bytes("kept.gif", IMAGE)
            .expect("attach test image");
        let original_text = app.editor.text();
        let original_cursor = app.editor.cursor();
        let original_attachments = app.editor.attachments().clone();
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

        assert!(app.picker_paste("智谱\n\u{1b}\u{202e}"));
        let picker = app.picker.as_ref().expect("picker remains open");
        assert_eq!(picker.query, "智谱 ");
        assert_eq!(picker.visible_indices(), vec![1]);
        assert_eq!(picker.sel, 1);

        let unsafe_codepoints: Vec<char> = (0x00..=0x1f)
            .chain(0x7f..=0x9f)
            .chain(std::iter::once(0x061c))
            .chain(0x200b..=0x200f)
            .chain(0x202a..=0x202e)
            .chain(0x2060..=0x206f)
            .chain(std::iter::once(0xfeff))
            .filter_map(char::from_u32)
            .collect();
        for unsafe_character in unsafe_codepoints {
            app.picker
                .as_mut()
                .expect("picker remains open")
                .query
                .clear();
            assert!(app.picker_paste(&format!("安全{unsafe_character}😀")));
            let query = &app.picker.as_ref().expect("picker remains open").query;
            assert!(query.contains("安全"));
            assert!(query.contains('😀'));
            assert!(!query.contains(unsafe_character));
            assert!(!query.chars().any(is_unsafe_display_char));
        }

        assert!(app.picker_paste(&"无匹配😀".repeat(2_000)));
        let picker = app.picker.as_ref().expect("picker remains open");
        assert!(picker.visible_indices().is_empty());
        assert!(picker.query.chars().count() <= MAX_PICKER_QUERY_CHARS);
        assert!(picker.query.len() <= MAX_PICKER_QUERY_BYTES);
        assert!(!picker.query.chars().any(is_unsafe_display_char));
        assert!(render_text(&mut app, 80, 18).contains("No matches"));

        assert_eq!(app.editor.text(), original_text);
        assert_eq!(app.editor.cursor(), original_cursor);
        assert_eq!(
            app.editor.attachments().as_slice(),
            original_attachments.as_slice()
        );
    }

    #[test]
    fn tunables_l0_search_and_l1_detail_are_terminal_rendered_and_truthful() {
        let mut app = App::new();
        let (submissions, _submitted) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(submissions);

        open_tunables_picker(&mut app, &session, "route_selection");
        let picker = app.picker.as_ref().expect("tunables picker opens");
        assert_eq!(picker.items.len(), core_tunables::EXPECTED_FAMILY_COUNT);
        assert_eq!(picker.query, "route_selection");
        assert_eq!(picker.visible_indices(), vec![0]);
        let l0 = render_text(&mut app, 110, 26);
        assert!(l0.contains("tunables · catalog"));
        assert!(l0.contains("provider"));
        assert!(l0.contains("simulation only"));

        let detail = match app.picker_key(KeyCode::Enter) {
            Some(PickerEvent::Accept(PickAction::InspectTunable(detail))) => detail,
            _ => panic!("Enter must select the one filtered tunable"),
        };
        show_tunable_detail(&mut app, detail);
        let l1 = render_text(&mut app, 120, 40);
        assert!(l1.contains("tunable · provider"));
        assert!(l1.contains("runtime_bound=false"));
        assert!(l1.contains("not supplied (no frozen request loaded)"));
        assert!(l1.contains("SWE-bench Pro"));
        assert!(l1.contains("does not edit config"));
    }

    /// UX-3 frontend surface: `/side` splits into exactly three requests, and only a bare
    /// reserved word is a verb.
    #[test]
    fn side_argument_resolves_to_status_close_or_a_question() {
        assert!(matches!(
            side_request_for(""),
            app_server::SideRequest::Status
        ));
        assert!(matches!(
            side_request_for("  status "),
            app_server::SideRequest::Status
        ));
        assert!(matches!(
            side_request_for("close"),
            app_server::SideRequest::Close
        ));
        assert!(matches!(
            side_request_for("end"),
            app_server::SideRequest::Close
        ));
        match side_request_for("  what is the status of the parser?  ") {
            app_server::SideRequest::Ask(question) => {
                assert_eq!(question, "what is the status of the parser?");
            }
            _ => panic!("a sentence containing a reserved word is still a question"),
        }
    }

    fn side_status_fixture(run_id: &str, asks: u32) -> crate::runtime::SideStatus {
        crate::runtime::SideStatus {
            run_id: run_id.into(),
            record_path: std::path::PathBuf::from("/tmp/runs/side/side-1.jsonl"),
            asks,
            turns: 2,
            cost: core_obs::CostState::Known {
                amount_microusd: 12_300,
                rate_card_digest: "digest".into(),
            },
            ledger_summary: "2 turns".into(),
        }
    }

    /// The answer is rendered as its OWN panel carrying its OWN run id and cost, and never as an
    /// assistant block — an assistant block IS this session's conversation.
    #[test]
    fn a_side_answer_renders_as_its_own_panel_with_its_own_run_and_cost() {
        let mut app = App::new();
        show_side_answer(
            &mut app,
            &crate::runtime::SideAnswer {
                text: "read crates/cli/src/tui.rs:1 for the composer".into(),
                outcome: core_protocol::Outcome::Done,
                status: side_status_fixture("side-run-1", 1),
            },
        );
        let screen = render_text(&mut app, 100, 24);
        assert!(screen.contains("side conversation"), "{screen}");
        assert!(screen.contains("side-run-1"), "{screen}");
        assert!(screen.contains("$0.0123"), "{screen}");
        assert!(screen.contains("crates/cli/src/tui.rs:1"), "{screen}");
        assert!(
            app.transcript.iter().all(|block| !matches!(
                block.kind,
                block::BlockKind::Assistant(_) | block::BlockKind::User(_)
            )),
            "a side answer must not enter the session transcript as a conversation turn"
        );
    }

    #[test]
    fn an_unopened_side_conversation_says_so_instead_of_showing_zero_cost() {
        let mut app = App::new();
        show_side_status(&mut app, None, false);
        let screen = render_text(&mut app, 100, 16);
        assert!(screen.contains("no side conversation yet"), "{screen}");
        assert!(
            !screen.contains("$0.0000"),
            "an absent conversation must never be rendered as a free one: {screen}"
        );
    }

    #[test]
    fn closing_reports_the_books_of_the_conversation_it_closed() {
        let mut app = App::new();
        show_side_status(&mut app, Some(&side_status_fixture("side-run-9", 3)), true);
        let screen = render_text(&mut app, 110, 24);
        assert!(screen.contains("closed"), "{screen}");
        assert!(screen.contains("side-run-9"), "{screen}");
        assert!(screen.contains("3 questions"), "{screen}");
        assert!(screen.contains("$0.0123"), "{screen}");
    }

    fn adopted_event(seq: u64, kind: core_protocol::EventKind) -> core_protocol::Event {
        core_protocol::Event {
            seq: core_protocol::Seq(seq),
            turn: core_protocol::TurnId(1),
            kind,
        }
    }

    fn adopted_message(
        role: core_protocol::Role,
        content: Vec<core_protocol::Block>,
    ) -> core_protocol::Message {
        core_protocol::Message { role, content }
    }

    #[test]
    fn an_adopted_record_renders_its_conversation_and_its_recorded_tool_results() {
        use core_protocol::{Block as MessageBlock, EventKind, Role};
        let events = vec![
            adopted_event(
                1,
                EventKind::Message {
                    message: core_protocol::Message::user_text("find the parser bug"),
                },
            ),
            adopted_event(
                2,
                EventKind::Message {
                    message: adopted_message(
                        Role::Assistant,
                        vec![
                            MessageBlock::Text {
                                text: "reading the parser".into(),
                            },
                            MessageBlock::ToolUse(core_protocol::ToolUse {
                                id: "call-1".into(),
                                name: "read_file".into(),
                                input: serde_json::json!({ "path": "src/parse.rs" }),
                            }),
                            MessageBlock::ToolUse(core_protocol::ToolUse {
                                id: "call-2".into(),
                                name: "bash".into(),
                                input: serde_json::json!({ "command": "cargo test" }),
                            }),
                        ],
                    ),
                },
            ),
            adopted_event(
                3,
                EventKind::Message {
                    message: adopted_message(
                        Role::User,
                        vec![MessageBlock::ToolResult(core_protocol::ToolResult {
                            tool_use_id: "call-1".into(),
                            content: "fn parse() {}".into(),
                            is_error: false,
                            trust: core_protocol::Trust::Workspace,
                            latency_ms: 12,
                        })],
                    ),
                },
            ),
        ];

        let (blocks, total) = adopted_transcript_blocks(&events);
        assert_eq!(total, 4, "user text, assistant text, and two tool calls");
        assert_eq!(blocks.len(), 4);
        assert!(
            matches!(&blocks[0], block::BlockKind::User(text) if text == "find the parser bug")
        );
        assert!(matches!(&blocks[1], block::BlockKind::Assistant(_)));
        let block::BlockKind::Tool(answered) = &blocks[2] else {
            panic!("the recorded tool call must render as a card")
        };
        assert_eq!(answered.name, "read_file");
        assert!(matches!(answered.status, block::ToolStatus::Ok));
        assert_eq!(answered.output, "fn parse() {}");
        assert_eq!(answered.elapsed, Some(Duration::from_millis(12)));
        let block::BlockKind::Tool(unanswered) = &blocks[3] else {
            panic!("a call with no recorded result is still real history")
        };
        // The run stopped between the call and its result. Saying so beats inventing a status.
        assert!(matches!(unanswered.status, block::ToolStatus::Err));
        assert!(unanswered.output.contains("no recorded result"));
        assert!(unanswered.elapsed.is_none());
    }

    #[test]
    fn an_adopted_transcript_is_bounded_on_screen_and_reports_what_it_left_out() {
        use core_protocol::EventKind;
        let events: Vec<core_protocol::Event> = (0..MAX_ADOPTED_BLOCKS as u64 + 40)
            .map(|index| {
                adopted_event(
                    index,
                    EventKind::Message {
                        message: core_protocol::Message::user_text(format!("message {index}")),
                    },
                )
            })
            .collect();
        let (blocks, total) = adopted_transcript_blocks(&events);
        assert_eq!(total, MAX_ADOPTED_BLOCKS + 40);
        assert_eq!(blocks.len(), MAX_ADOPTED_BLOCKS);
        // The TAIL is what a returning operator needs: the newest exchange, not the oldest.
        assert!(
            matches!(blocks.last(), Some(block::BlockKind::User(text)) if text.ends_with(&format!("{}", MAX_ADOPTED_BLOCKS + 39))),
            "the bound must keep the newest blocks"
        );
    }

    #[test]
    fn the_route_to_bind_comes_from_the_records_last_durable_selection() {
        use core_protocol::EventKind;
        let selection = |provider: &str, model: &str| EventKind::ModelSelected {
            provider_id: provider.into(),
            model_id: model.into(),
            catalog_digest: String::new(),
            capability_digest: String::new(),
        };
        let events = vec![
            adopted_event(1, selection("glm", "glm-5.1")),
            adopted_event(2, selection("anthropic", "sonnet")),
        ];
        assert_eq!(
            recorded_route(&events),
            Some((Some("anthropic".into()), "sonnet".into()))
        );
        // A journal with no selection at all offers no route, and its model is never used to guess
        // a provider that was never recorded.
        assert_eq!(recorded_route(&[]), None);
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
        assert!(matches!(&items[0].action, PickAction::AdoptRun(id) if id == "newer"));
        for expected in ["run newer", "7 turns", "$2.5000", "glm/glm-5.2"] {
            assert!(
                items[0].hint.contains(expected),
                "missing {expected}: {}",
                items[0].hint
            );
        }
    }

    #[test]
    fn session_picker_one_enter_selects_the_run_to_adopt_in_process() {
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
        let PickAction::AdoptRun(run_id) = action else {
            panic!("session selection returned the wrong action")
        };
        assert_eq!(run_id, "run-42");
        // The restart handoff is now the FALLBACK, taken when a run cannot be adopted here — most
        // often because another process holds its writer lock. It must still be exact.
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
    fn mode_picker_hint_tracks_the_effective_code_grant() {
        let hint_for = |rules: &PermissionRules, mode: PermissionMode| {
            mode_picker_items(mode, rules)
                .into_iter()
                .find(|item| item.label == mode.label())
                .expect("every mode is offered")
                .hint
        };

        // Deny-by-default: nothing seeded, so acceptEdits really does still gate code.
        let none = PermissionRules::new();
        assert_eq!(
            hint_for(&none, PermissionMode::AcceptEdits),
            "edits auto; code still gated"
        );
        assert_eq!(
            hint_for(&none, PermissionMode::Default),
            "edits prompt live; code still gated"
        );

        // With the operator's code grant in the session the old hard-coded hint lied: the rule
        // outranks the mode table, so acceptEdits auto-runs bash.
        let mut allowed = PermissionRules::new();
        allowed.allow_cap(Capability::CodeExecuting);
        assert_eq!(
            hint_for(&allowed, PermissionMode::AcceptEdits),
            "edits auto; code auto"
        );

        let mut denied = PermissionRules::new();
        denied
            .try_set_cap(Capability::CodeExecuting, Verdict::Deny)
            .unwrap();
        assert_eq!(
            hint_for(&denied, PermissionMode::AcceptEdits),
            "edits auto; code denied"
        );

        // The two modes whose posture no session rule can change keep their fixed wording.
        assert_eq!(
            hint_for(&allowed, PermissionMode::Plan),
            "read-only; propose a plan first"
        );
        assert_eq!(
            hint_for(&allowed, PermissionMode::Yolo),
            "auto-approve (still asks for trust-mutating + egress)"
        );
        assert!(
            mode_picker_items(PermissionMode::Plan, &none)
                .iter()
                .any(|item| item.label == PermissionMode::Plan.label() && item.is_current),
            "the active mode stays pre-selected"
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
        assert_eq!(
            app.theme.fg,
            app.color_depth.project_color(light.fg),
            "nav previews the theme at the detected color depth"
        );
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
        assert_eq!(app.theme.fg, app.color_depth.project_color(selected.fg));
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
        run_bash_inline(
            &mut app,
            &std::env::temp_dir(),
            &command,
            &[],
            PermissionMode::Default,
            &PermissionRules::new(),
        )
        .await;
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
            .draw(|frame| render_composer(frame, frame.area(), &mut app))
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
    fn composer_renders_attachment_chips_and_submit_preview_without_payload_bytes() {
        let mut app = App::new();
        app.editor.insert_str("inspect");
        app.editor
            .attach_image_bytes(
                "clipboard.png",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();

        let screen = render_text(&mut app, 80, 14);
        assert!(screen.contains("1 image"));
        assert!(screen.contains("clipboard.png"));
        assert!(screen.contains("alt+backspace"));
        assert!(screen.contains("inspect"));
        assert!(!screen.contains("R0lGOD"));
    }

    #[test]
    fn composer_renders_a_file_chip_beside_an_image_chip_and_never_its_contents() {
        let root = std::env::temp_dir().join(format!("core-tui-file-chip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test workspace");
        let secret = "SUPER_SECRET_FILE_BODY";
        std::fs::write(root.join("notes.md"), format!("# notes\n{secret}\n")).expect("fixture");

        let mut app = App::new();
        app.editor.insert_str("inspect");
        app.editor
            .attach_image_bytes(
                "clipboard.png",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();
        app.editor
            .attach_file_path(&root, Path::new("notes.md"))
            .expect("a plain workspace file");

        let screen = render_text(&mut app, 100, 14);
        assert!(screen.contains("1 image"), "{screen}");
        assert!(screen.contains("1 file"), "{screen}");
        assert!(screen.contains("clipboard.png"), "{screen}");
        assert!(screen.contains("notes.md"), "{screen}");
        assert!(screen.contains("inspect"), "{screen}");
        assert!(
            !screen.contains(secret),
            "a chip is a reference; the composer never prints the file it stands for"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn captured_mouse_click_focuses_the_composer_at_a_terminal_cell_boundary() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        assert_eq!(editor_char_index_at_cell("ab\n写z", 0, 1), 1);
        assert_eq!(editor_char_index_at_cell("ab\n写z", 1, 0), 3);
        assert_eq!(
            editor_char_index_at_cell("ab\n写z", 1, 1),
            4,
            "the trailing cell of a wide character lands after it"
        );
        assert_eq!(editor_char_index_at_cell("ab\n写z", 9, 9), 5);

        let mut app = App::new();
        app.editor.insert_str("ab写d");
        let mut terminal = Terminal::new(TestBackend::new(24, 3)).unwrap();
        terminal
            .draw(|frame| render_composer(frame, frame.area(), &mut app))
            .unwrap();
        let hitbox = app
            .composer_hitbox
            .expect("composer published a hit-test map");
        assert!(place_editor_cursor_from_mouse(
            &mut app,
            hitbox.text_area.x.saturating_add(3),
            hitbox.text_area.y,
        ));
        app.editor.insert('X');
        assert_eq!(
            app.editor.text(),
            "ab写Xd",
            "clicking the wide glyph's trailing cell focuses after it"
        );
        assert!(
            !place_editor_cursor_from_mouse(&mut app, u16::MAX, u16::MAX),
            "off-composer clicks are ignored"
        );
    }

    #[test]
    fn full_width_composer_precedes_a_stable_bottom_statusline() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        app.route.provider_id = "glm".into();
        app.route.model_id = "glm-5.2".into();
        app.model = "glm-5.2".into();
        app.effort = Effort::High;
        let expected = surface::Surface::resolve(Rect::new(0, 0, 80, 12), 1, 0, 0, true, false);
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
    fn mouse_capture_state_is_visible_in_hint_and_status_chrome() {
        let mut app = App::new();
        let captured = render_text(&mut app, 80, 12);
        assert!(captured.contains("mouse:on"));
        assert!(captured.contains("ctrl+t select"));

        app.mouse_capture = mouse_capture::State::Released;
        let released = render_text(&mut app, 80, 12);
        assert!(released.contains("selection:on"));
        assert!(released.contains("ctrl+t mouse"));
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
            app.route.provider_id = "anthropic".into();
            app.route.model_id = "claude-sonnet-4-5".into();
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
        // One column short of the terminal at every size: transcript content now yields the final
        // column to the scrollbar (`Surface::transcript_content_width`), so the cache is keyed by
        // the width text actually gets rather than by the width of the window. The relations above
        // -- distinct widths produce distinct entries, repeated widths reuse them -- are what this
        // test exists to pin, and they are unchanged.
        assert_eq!(cache_widths, vec![39, 79, 119, 199, 79, 39]);
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

    /// N-2: a file dropped on the terminal DURING a run was routed to the after-turn queue by the
    /// bare `starts_with('/')` test, and the drain then dispatched it as a slash command — so the
    /// path was destroyed instead of reaching the model. Every row here is a drop form that failed.
    #[test]
    fn a_drop_during_a_run_steers_instead_of_queueing_a_command() {
        let drops = [
            "/Users/op/IMG_0042.heic",
            "/Users/op/notes.pdf",
            "/Users/op/notes.txt",
            "/Users/op/logo.svg",
            "/Users/op/shot.png",
            "/Users/op/Pictures",
            "/Users/op/a.png /Users/op/b.png",
            r"/Users/op/My\ Trip.heic",
            "/Users/op/shot.png\n",
            "  /Users/op/shot.png",
        ];
        for drop in drops {
            assert_eq!(
                input_destination(true, drop),
                InputDestination::SteerCurrentRun,
                "{drop:?} was routed to the command queue"
            );
        }
        for command in ["/model", "/compact", "/?", "/perms", "/helpp", "/"] {
            assert_eq!(
                input_destination(true, command),
                InputDestination::AfterTurn,
                "{command:?} stopped queueing as a command"
            );
        }
        assert_eq!(
            input_destination(true, "!cargo test"),
            InputDestination::AfterTurn,
        );
    }

    /// The frontend's binding of the discriminator really consults the filesystem: `/tmp` and
    /// `/etc` are single-segment, so nothing but a `stat` can tell them from a mistyped command.
    #[cfg(unix)]
    #[test]
    fn the_drop_probe_reads_this_filesystem() {
        assert!(path_exists_on_disk(Path::new("/tmp")));
        assert_eq!(slash_command_body("/tmp"), None);
        assert_eq!(slash_command_body("/etc"), None);
        // A dropped folder created for this test, named like nothing in the registry.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dropped = std::env::temp_dir().join(format!(
            "core-tui-drop-{}-{nonce}/IMG_0042.heic",
            std::process::id()
        ));
        std::fs::create_dir_all(dropped.parent().unwrap()).unwrap();
        std::fs::write(&dropped, b"not really an image").unwrap();
        assert_eq!(slash_command_body(dropped.to_str().unwrap()), None);
        std::fs::remove_dir_all(dropped.parent().unwrap()).unwrap();
        // …while a name with no path evidence still reaches the unknown-command notice.
        assert!(!path_exists_on_disk(Path::new("/helpp")));
        assert_eq!(slash_command_body("/helpp"), Some("helpp"));
    }

    /// N-2 (draft loss): `take_submit` clears the composer BEFORE dispatch, so a name the registry
    /// does not serve used to consume the line as well as reject it. The Enter lane now puts an
    /// unknown command back; a recognized one is still consumed.
    #[test]
    fn an_unknown_command_returns_the_line_to_the_composer() {
        for (line, survives) in [("/helpp", true), ("/help", false)] {
            let mut app = App::new();
            app.editor.insert_str(line);
            let trimmed = app.editor.text().trim().to_string();
            let cmd = slash_command_body(&trimmed).expect("a typo is still a command");
            let restore = commands::parse(cmd).is_err().then(|| trimmed.clone());
            let _ = app.editor.take_submit();
            if let Some(draft) = restore {
                app.editor.insert_str(&draft);
            }
            assert_eq!(
                app.editor.text(),
                if survives { line } else { "" },
                "{line:?} draft handling regressed"
            );
        }
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
    fn the_render_loop_is_event_driven_and_coalesces_a_delta_burst_into_one_frame() {
        // The loop used to block in a stdin poll for a fixed 100 ms while running and 1 s while
        // idle, and only afterwards drain the event queue — so a delta batch landing 1 ms into a
        // poll waited out the remaining 99 ms, and an idle session woke every second for nothing.
        // The wait is now a select whose only timeout is a deadline something actually asked for.
        let now = Instant::now();
        assert_eq!(
            next_wake(false, now, false, now, None),
            None,
            "an idle session schedules no wakeup at all: it sleeps on input and events"
        );
        // A burst costs one frame: the first change draws, the rest fold into the frame held until
        // the coalescing deadline, which is the only thing the loop waits for.
        let next_frame_at = now + FRAME_COALESCE;
        assert_eq!(
            next_wake(true, next_frame_at, false, now, None),
            Some(next_frame_at)
        );
        assert!(
            FRAME_COALESCE < SPINNER_TICK,
            "visible token latency is bounded by coalescing, not by the old input-poll period"
        );
        // A live run animates off its own clock, and a queued tool card has its own anti-flash
        // deadline. Whichever comes first wins; nothing polls for the others.
        assert_eq!(
            next_wake(false, next_frame_at, true, now, None),
            Some(now + SPINNER_TICK)
        );
        let reveal = now + Duration::from_millis(3);
        assert_eq!(
            next_wake(true, next_frame_at, true, now, Some(reveal)),
            Some(reveal)
        );
    }

    #[test]
    fn a_frame_materialises_only_the_viewport_and_reproduces_the_unwindowed_rows() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        // Transcript rows as text, minus the final column reserved for the overflow scrollbar.
        fn transcript_rows(
            term: &ratatui::Terminal<ratatui::backend::TestBackend>,
            top: u16,
            height: u16,
        ) -> Vec<String> {
            let buf = term.backend().buffer();
            (top..top.saturating_add(height))
                .map(|y| {
                    (0..buf.area.width.saturating_sub(1))
                        .map(|x| buf[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect()
        }

        let mut app = App::new();
        for index in 0..40 {
            app.note(
                block::NoticeLevel::Info,
                format!("historical row {index:03}"),
            );
        }
        // A terminal tall enough to hold the whole transcript needs no window, so its frame is the
        // reference the windowed frame has to reproduce exactly.
        let mut tall = Terminal::new(TestBackend::new(60, 120)).unwrap();
        tall.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(app.view_scroll, 0, "the reference frame shows every row");
        let reference = transcript_rows(&tall, app.view_top, app.view_h);
        let total = usize::from(app.last_total_rows);
        assert!(total > 0 && total <= reference.len());

        let mut short = Terminal::new(TestBackend::new(60, 14)).unwrap();
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        let view_h = usize::from(app.view_h);
        assert!(
            total > view_h,
            "the transcript has to overflow to be a test"
        );
        assert_eq!(
            usize::from(app.last_total_rows),
            total,
            "windowing changes what is built, never how tall the transcript is"
        );
        assert_eq!(
            app.row_map.len(),
            view_h,
            "the frame materialises one row per VISIBLE row, not one per transcript row"
        );
        assert_eq!(
            transcript_rows(&short, app.view_top, app.view_h),
            reference[total - view_h..total],
            "the tail window is byte-identical to the unwindowed render"
        );

        app.scroll_up(9);
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        let scroll = usize::from(app.view_scroll);
        assert!(scroll > 0 && scroll + view_h <= total);
        let rows = transcript_rows(&short, app.view_top, app.view_h);
        assert_eq!(
            rows,
            reference[scroll..scroll + view_h],
            "a scrolled window is byte-identical to the same slice of the unwindowed render"
        );

        // `row_map` is what a mouse click indexes. It now covers the viewport only, so the click row
        // IS the index; the old scroll-relative index would run off the end of a scrolled frame.
        assert_eq!(app.row_map.len(), view_h);
        let mut checked = 0;
        for (idx, row) in rows.iter().enumerate() {
            let Some(at) = row.find("historical row ") else {
                continue;
            };
            let marker = row[at..at + "historical row 000".len()].to_string();
            let expected = app
                .transcript
                .iter()
                .position(|candidate| candidate.to_text().contains(&marker))
                .expect("the rendered notice is still in the transcript");
            assert_eq!(
                app.row_map[idx], expected,
                "viewport row {idx} must fold the block drawn on it"
            );
            checked += 1;
        }
        assert!(checked >= 3, "the window showed {checked} notice rows");

        // Frame cost is independent of session length: ten times the history, same materialisation.
        app.follow_latest();
        for index in 40..440 {
            app.note(
                block::NoticeLevel::Info,
                format!("historical row {index:03}"),
            );
        }
        short.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(usize::from(app.last_total_rows) > total * 5);
        assert_eq!(app.row_map.len(), view_h);
    }

    #[test]
    fn overflow_scrollbar_never_overwrites_the_final_transcript_cell() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let target = format!("{}Z", "x".repeat(114));
        let mut rows = (0..40)
            .map(|index| block::PanelRow::Note(format!("historical row {index:03}")))
            .collect::<Vec<_>>();
        rows.push(block::PanelRow::Note(target.clone()));
        let mut app = App::new();
        app.panel("", "commands", rows);

        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(
            app.last_total_rows > app.view_h,
            "the scrollbar must be visible"
        );

        let buffer = terminal.backend().buffer();
        let content = (app.view_top..app.view_top.saturating_add(app.view_h))
            .flat_map(|y| {
                (0..buffer.area.width.saturating_sub(1))
                    .flat_map(move |x| buffer[(x, y)].symbol().chars())
            })
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(
            content.contains(&target),
            "the scrollbar gutter must not erase the last content cell"
        );
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

    #[derive(Clone)]
    struct ClientParityCapture {
        one_shot: serde_json::Value,
        headless: serde_json::Value,
        tui: serde_json::Value,
        tui_status: String,
    }

    fn pairwise_result_equality(capture: &ClientParityCapture) -> [bool; 3] {
        [
            capture.one_shot == capture.headless,
            capture.headless == capture.tui,
            capture.tui == capture.one_shot,
        ]
    }

    fn one_shot_terminal_result(summary: &app_server::TerminalSummary) -> serde_json::Value {
        // This is the exact constructor used by the one-shot client after it receives RunEnded.
        // Do not route this leg through TerminalSummary::result_v5: an accidental sibling-client
        // normalizer must remain observable to this parity proof.
        crate::output::final_result(
            &summary.outcome,
            &summary.assistant_text,
            &summary.run_id,
            &summary.cost,
            summary.turns,
            summary.kernel_tax,
            summary.error.as_deref(),
        )
    }

    fn tui_terminal_result(summary: &app_server::TerminalSummary) -> (serde_json::Value, String) {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: summary.cost.clone(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
            }),
            summary: Box::new(summary.clone()),
        };
        let mut notifier = notification::TerminalNotifier::new(false);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        // Exercise the TUI's real RunEnded branch, including its native status projection. The
        // canonical object is retained internally for parity; it is not printed as machine JSON.
        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        (
            app.last_result
                .expect("RunEnded stores the canonical result"),
            app.status,
        )
    }

    fn capture_client_parity(summary: &app_server::TerminalSummary) -> ClientParityCapture {
        let one_shot = one_shot_terminal_result(summary);
        // Destructuring the versioned transport frame is the sole normalization in this proof.
        // Every result-v5 field remains untouched and participates in raw Value equality.
        let (protocol_version, seq, headless) =
            headless::capture_terminal_result_frame(41, summary);
        assert_eq!(protocol_version, core_protocol::PROTOCOL_VERSION);
        assert_eq!(seq, 41);
        let (tui, tui_status) = tui_terminal_result(summary);
        ClientParityCapture {
            one_shot,
            headless,
            tui,
            tui_status,
        }
    }

    #[test]
    fn three_client_production_paths_are_pairwise_identical_for_every_terminal_outcome() {
        let cases = [
            (core_protocol::Outcome::Done, "done", 0_u64),
            (core_protocol::Outcome::Drained, "drained", 0),
            (
                core_protocol::Outcome::BudgetExhausted("max_turns"),
                "budget_exhausted",
                3,
            ),
            (core_protocol::Outcome::Interrupted, "interrupted", 130),
            (core_protocol::Outcome::Stuck, "stuck", 4),
            (core_protocol::Outcome::HarnessError, "harness_error", 2),
        ];

        for (outcome, expected_outcome, expected_exit_code) in cases {
            let summary = app_server::TerminalSummary {
                error: matches!(&outcome, core_protocol::Outcome::HarnessError)
                    .then(|| "synthetic harness failure".into()),
                outcome,
                assistant_text: "parity reply".into(),
                run_id: "run-client-parity".into(),
                cost: CostState::default(),
                turns: 1,
                kernel_tax: core_obs::KernelTax::default(),
                memo_hits: 0,
                memo_misses: 0,
            };
            let capture = capture_client_parity(&summary);

            assert_eq!(
                pairwise_result_equality(&capture),
                [true, true, true],
                "{expected_outcome} diverged across production client projections"
            );
            for result in [&capture.one_shot, &capture.headless, &capture.tui] {
                assert_eq!(result["outcome"], expected_outcome);
                assert_eq!(
                    result["exit_code"].as_u64(),
                    Some(expected_exit_code),
                    "{expected_outcome} changed its process contract"
                );
            }
            assert_eq!(
                capture.tui_status,
                format!("idle · last: {expected_outcome}"),
                "native TUI presentation is checked separately from machine-object parity"
            );

            // Normalizer canary: a substantive field changed in only one captured result must not
            // be erased by envelope handling or a presentation-oriented comparison.
            let mut divergent = capture.clone();
            divergent.headless["assistant_text"] =
                serde_json::Value::String("headless-only mutation".into());
            assert_eq!(
                pairwise_result_equality(&divergent),
                [false, false, true],
                "raw pairwise equality must expose a one-client result-v5 mutation"
            );

            // Source-mutation canary: changing the shared authority must move all three production
            // outputs together and preserve parity, proving the assertion is not three literals.
            let mut changed_summary = summary.clone();
            changed_summary.assistant_text = "parity reply after summary mutation".into();
            let changed = capture_client_parity(&changed_summary);
            assert_eq!(pairwise_result_equality(&changed), [true, true, true]);
            assert_ne!(changed.one_shot, capture.one_shot);
            assert_ne!(changed.headless, capture.headless);
            assert_ne!(changed.tui, capture.tui);
            assert_eq!(
                changed.one_shot["assistant_text"],
                "parity reply after summary mutation"
            );
        }
    }

    #[test]
    fn run_terminal_chrome_is_derived_from_the_canonical_result_v5_object() {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let summary = app_server::TerminalSummary {
            outcome: core_protocol::Outcome::Done,
            assistant_text: "the typed answer".into(),
            run_id: "run-tui-parity".into(),
            cost: CostState::default(),
            turns: 3,
            kernel_tax: core_obs::KernelTax::default(),
            error: None,
            memo_hits: 0,
            memo_misses: 0,
        };
        let expected = crate::output::final_result(
            &summary.outcome,
            &summary.assistant_text,
            &summary.run_id,
            &summary.cost,
            summary.turns,
            summary.kernel_tax,
            summary.error.as_deref(),
        );
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
            }),
            summary: Box::new(summary),
        };
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        assert_eq!(app.last_result.as_ref(), Some(&expected));
        assert_eq!(app.status, "idle · last: done");
        assert_eq!(
            notification_bytes, b"\x07",
            "the authoritative RunEnded boundary emits one run-complete notification"
        );
    }

    /// A budget stop is not an error, so it produced no block at all: the operator saw
    /// `idle · last: budget_exhausted` and nothing about the session turn ceiling being raisable
    /// in place. The terminal boundary has to say what clears the ceiling it just hit.
    #[test]
    fn a_budget_stop_tells_the_operator_which_ceiling_and_how_to_clear_it() {
        let mut app = App::new();
        app.running = true;
        let (sq, _rx) = tokio::sync::mpsc::channel(1);
        let mut session = Session::for_test(sq);
        let event = app_server::ServerEvent::RunEnded {
            snapshot: Box::new(app_server::SessionSnapshot {
                mode: PermissionMode::default(),
                effort: Effort::default(),
                model: "test-model".into(),
                cost: CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                ledger_summary: String::new(),
                rate_limit: None,
            }),
            summary: Box::new(app_server::TerminalSummary {
                outcome: core_protocol::Outcome::BudgetExhausted("max_turns"),
                assistant_text: String::new(),
                run_id: "run-budget-remedy".into(),
                cost: CostState::default(),
                turns: 40,
                kernel_tax: core_obs::KernelTax::default(),
                error: None,
                memo_hits: 0,
                memo_misses: 0,
            }),
        };
        let mut notifier = notification::TerminalNotifier::new(false);
        notifier.begin_run();
        let mut notification_bytes = Vec::new();
        let interrupt = Arc::new(AtomicBool::new(false));
        let drain = Arc::new(AtomicBool::new(false));

        apply_server_event(
            &mut app,
            &mut session,
            event,
            &mut notifier,
            &mut notification_bytes,
            &interrupt,
            &drain,
        );

        assert_eq!(app.status, "idle · last: budget_exhausted");
        let notice = app
            .transcript
            .last()
            .expect("the budget stop leaves a notice")
            .to_text();
        assert!(notice.contains("max_turns"), "{notice:?} names the ceiling");
        assert!(
            notice.contains("/budget"),
            "{notice:?} names the in-session command that raises the ceiling"
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
    fn quickjs_workflow_run_events_upsert_one_live_tree() {
        use core_workflow::events::{ProgressEvent, WorkflowState};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_run_1";

        // First event mints the card; subsequent events upsert into the SAME block by run id.
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::Phase {
                index: 1,
                title: "Explore".into(),
            },
        );
        let block_id = *app
            .workflow_run_index
            .get(run_id)
            .expect("indexed run card");
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::Log {
                message: "scanning".into(),
            },
        );
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::AgentStarted {
                index: 0,
                label: "scan modules".into(),
                phase: Some("Explore".into()),
                model: Some("haiku".into()),
            },
        );
        app.workflow_run_event(
            run_id,
            "audit",
            ProgressEvent::AgentFinished {
                index: 0,
                label: "scan modules".into(),
                state: WorkflowState::Done,
                tokens: 1_200,
                tool_calls: 2,
                duration_ms: 3_200,
                result_preview: None,
                last_tool_summary: None,
                error: None,
            },
        );

        // Exactly one WorkflowRun block, still keyed by run id, mutated in place.
        let run_blocks = app
            .transcript
            .iter()
            .filter(|b| matches!(b.kind, block::BlockKind::WorkflowRun(_)))
            .count();
        assert_eq!(run_blocks, 1, "one live tree, not a line-per-event log");
        assert_eq!(*app.workflow_run_index.get(run_id).unwrap(), block_id);
        let card = match &app
            .transcript
            .iter()
            .find(|b| b.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card,
            _ => unreachable!(),
        };
        assert_eq!(card.agents.len(), 1);
        assert_eq!(card.agents[0].state, WorkflowState::Done);
        assert_eq!(card.phases.len(), 1);
        assert_eq!(card.logs, vec!["scanning".to_string()]);
        assert!(!card.finished);

        // It renders through the transcript draw path.
        let screen = render_text(&mut app, 80, 20);
        assert!(screen.contains("Explore"));
        assert!(screen.contains("scanning"));

        // Terminal transition flips `finished` and drops the live index.
        app.workflow_run_finished(run_id);
        assert!(!app.workflow_run_index.contains_key(run_id));
        let finished = match &app
            .transcript
            .iter()
            .find(|b| b.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.finished,
            _ => unreachable!(),
        };
        assert!(finished);
    }

    /// The wire this slice built: a workflow launched from inside the interactive TUI arrives as
    /// `app_server::ServerEvent::WorkflowRun`, and the operator watches a live tree instead of a
    /// silent turn. Everything below crosses the real seam — `crate::workflow::UiProgressSink` is
    /// what the kernel installs, `workflow_run_ui_event` is what the frontend dispatches to.
    #[test]
    fn a_workflow_launched_in_the_tui_renders_a_live_progress_tree() {
        use core_workflow::events::{ProgressEvent, ProgressSink, WorkflowState};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_repl_1";

        // Declared `meta.phases` lay the boxes out before the first agent runs.
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: run_id.into(),
            name: "audit".into(),
            phases: vec!["Explore".into(), "Report".into()],
        });
        let block_id = *app
            .workflow_run_index
            .get(run_id)
            .expect("the card exists before the engine emits anything");

        // The kernel's sink is the only thing between the engine and this channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = crate::workflow::UiProgressSink::new(run_id, tx);
        sink.emit(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        sink.emit(ProgressEvent::Log {
            message: "scanning modules".into(),
        });
        sink.emit(ProgressEvent::AgentQueued {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: Some("core-model-1".into()),
        });
        sink.emit(ProgressEvent::AgentStarted {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: Some("core-model-1".into()),
        });
        sink.emit(ProgressEvent::AgentActivity {
            index: 0,
            tokens: 900,
            tool_calls: 1,
            last_tool_summary: Some("read src/lib.rs".into()),
        });
        sink.emit(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan modules".into(),
            state: WorkflowState::Done,
            tokens: 1_200,
            tool_calls: 2,
            duration_ms: 3_200,
            result_preview: Some("14 modules, 2 without tests".into()),
            last_tool_summary: None,
            error: None,
        });
        drop(sink);
        while let Ok(event) = rx.try_recv() {
            app.workflow_run_ui_event(event);
        }

        let card = match &app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .expect("the run keeps its one block")
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.clone(),
            _ => unreachable!("the block is the phase→agent tree"),
        };
        assert_eq!(card.name, "audit");
        assert_eq!(
            card.phases.len(),
            2,
            "a declared phase reached at runtime binds back by title instead of opening a \
             second box"
        );
        assert_eq!(card.agents.len(), 1, "one agent(), one row");
        assert_eq!(card.agents[0].state, WorkflowState::Done);
        assert_eq!(card.agents[0].tokens, 1_200);
        assert_eq!(
            card.logs,
            vec!["scanning modules".to_string()],
            "log() has no counterpart in the native vocabulary and is carried, not dropped"
        );
        assert!(!card.finished, "the run has not settled yet");

        let live = render_text(&mut app, 100, 30);
        assert!(live.contains("Explore"), "{live}");
        assert!(live.contains("Report"), "{live}");
        assert!(live.contains("scan modules"), "{live}");
        assert!(live.contains("scanning modules"), "{live}");

        // Settling is a separate message because `ingest` never sets it; without it the tree spins.
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Finished {
            run_id: run_id.into(),
        });
        assert!(!app.workflow_run_index.contains_key(run_id));
        let settled = match &app
            .transcript
            .iter()
            .find(|block| block.id == block_id)
            .unwrap()
            .kind
        {
            block::BlockKind::WorkflowRun(card) => card.finished,
            _ => unreachable!(),
        };
        assert!(settled);
    }

    /// A workflow script is untrusted input and the interactive transcript is retained state, so
    /// nothing hostile in a label or a narrator line survives the trip.
    #[test]
    fn a_hostile_workflow_script_cannot_write_control_sequences_into_the_transcript() {
        use core_workflow::events::{ProgressEvent, ProgressSink};

        let mut app = App::new();
        app.theme = theme::Theme::dark();
        let run_id = "wf_repl_hostile";
        app.workflow_run_ui_event(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: run_id.into(),
            name: "audit\u{1b}[2J".into(),
            phases: vec!["Explore\u{1b}[2J".into()],
        });

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = crate::workflow::UiProgressSink::new(run_id, tx);
        sink.emit(ProgressEvent::Log {
            message: "narrating\u{1b}[2J\u{7}".into(),
        });
        sink.emit(ProgressEvent::AgentStarted {
            index: 0,
            label: "row\u{1b}[2J".into(),
            phase: None,
            model: None,
        });
        drop(sink);
        while let Ok(event) = rx.try_recv() {
            app.workflow_run_ui_event(event);
        }

        let screen = render_text(&mut app, 100, 30);
        assert!(
            !screen.chars().any(|c| c == '\u{1b}' || c == '\u{7}'),
            "a raw control character reached the frame buffer: {screen:?}"
        );
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
                tasks: vec![crate::runtime::WorkflowTaskUi {
                    id: 0,
                    label: "inspect the runtime".into(),
                }],
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
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
        // The running investigator keeps its own branch row (I-04): no NOW hoist, no filtered row.
        assert!(live.contains("inspect the runtime · running"));
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
                crate::runtime::WorkflowTaskUi {
                    id: 0,
                    label: "running child".into(),
                },
                crate::runtime::WorkflowTaskUi {
                    id: 1,
                    label: "queued child".into(),
                },
            ],
            dropped: 0,
            duplicates_removed: 0,
            invalid_removed: 0,
            execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
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
    fn only_an_accepted_submission_arms_run_completion_notification() {
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
        let accepted_session = Session::for_test(accepted_tx);
        let mut accepted_app = App::new();
        let mut accepted_notifier = notification::TerminalNotifier::new(true);

        submit_turn(
            &mut accepted_app,
            &accepted_session,
            &mut accepted_notifier,
            "accepted".into(),
        );

        assert!(accepted_app.running);
        assert!(matches!(
            accepted_rx
                .try_recv()
                .expect("accepted task reaches the SQ")
                .into_current()
                .expect("current protocol envelope"),
            Op::UserInput { text } if text == "accepted"
        ));
        assert_eq!(
            accepted_notifier.run_completed(),
            Some(notification::Trigger::RunComplete)
        );

        let (busy_tx, _busy_rx) = tokio::sync::mpsc::channel(1);
        busy_tx
            .try_send(core_protocol::SqEnvelope::current(Op::Interrupt))
            .expect("fixture fills the bounded SQ");
        let busy_session = Session::for_test(busy_tx);
        let mut busy_app = App::new();
        let mut busy_notifier = notification::TerminalNotifier::new(true);

        submit_turn(
            &mut busy_app,
            &busy_session,
            &mut busy_notifier,
            "refused".into(),
        );

        assert!(!busy_app.running);
        assert_eq!(busy_notifier.run_completed(), None);
        assert!(
            busy_app
                .transcript
                .iter()
                .any(|block| block.to_text().contains("submission was not accepted"))
        );
    }

    #[test]
    fn composer_attachment_submits_one_multimodal_sq_envelope() {
        let image_bytes = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let session = Session::for_test(tx);
        let mut app = App::new();
        app.editor.insert_str("describe this");
        app.editor
            .attach_image_bytes("clipboard.png", image_bytes)
            .unwrap();
        let mut notifier = notification::TerminalNotifier::new(false);

        submit_composer(&mut app, &session, &mut notifier);

        assert!(app.running);
        assert!(!app.editor.has_submission());
        let op = rx
            .try_recv()
            .expect("composer submits through the bounded SQ")
            .into_current()
            .expect("current protocol envelope");
        let Op::UserInputV2 { segments } = op else {
            panic!("image composer must use the additive multimodal operation");
        };
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, image_bytes);
        assert_eq!(
            serde_json::to_value(&segments).expect("serialize composer segments"),
            serde_json::json!([
                {"type": "text", "text": "describe this"},
                {
                    "type": "image",
                    "image": {
                        "media_type": "image/gif",
                        "data": encoded,
                    },
                },
            ]),
            "the composer must preserve ordered text and the exact attached bytes"
        );
        assert_eq!(segments.text(), "describe this");
        let images = segments.images().collect::<Vec<_>>();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].media_type, core_protocol::ImageMediaType::Gif);
        assert_eq!(
            app.transcript
                .iter()
                .filter(|block| block.to_text().contains("describe this"))
                .count(),
            1,
            "the submit preview is projected once without image bytes"
        );
    }

    #[test]
    fn clipboard_helper_environment_cannot_inherit_provider_credentials_or_proxies() {
        let environment = clipboard_child_environment_with(|name| {
            Some(
                match name {
                    "WAYLAND_DISPLAY" => "wayland-1",
                    "XDG_RUNTIME_DIR" => "/tmp/core-runtime",
                    "DISPLAY" => ":1",
                    "XAUTHORITY" => "/tmp/core-xauthority",
                    "SystemRoot" | "SYSTEMROOT" | "WINDIR" => r"C:\Windows",
                    "PATHEXT" => ".EXE;.CMD",
                    "TEMP" | "TMP" => r"C:\Temp",
                    _ => "must-not-cross",
                }
                .into(),
            )
        });
        let keys = environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<std::collections::BTreeSet<_>>();
        for forbidden in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "CORE_RELEASE_SMOKE_KEY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        ] {
            assert!(
                !keys.contains(forbidden),
                "{forbidden} crossed the allowlist"
            );
        }
        assert!(
            environment
                .iter()
                .all(|(_, value)| value != "must-not-cross"),
            "an unrecognized parent value crossed the clipboard helper boundary"
        );
    }

    /// I-64: the response-header deadline is 60s and the stream idle deadline 120s, so a dead
    /// connection and a slow prefill used to look identical for a full minute. The interface must
    /// say which one it is watching, and must stop saying it the instant a token arrives.
    #[test]
    fn a_stalled_provider_is_described_differently_from_a_slow_one_before_the_deadline() {
        let mut app = App::new();
        app.running = true;
        apply_event(&mut app, UiEvent::Phase(core_protocol::Phase::Model));

        // An ordinary wait says nothing at all; the phase label already covers it.
        assert!(app.first_token_stall().is_none());

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_SLOW_AFTER);
        let slow = app
            .first_token_stall()
            .expect("a slow prefill is described");
        assert_eq!(slow.state, FirstTokenState::Slow);
        assert!(slow.label().contains("waiting for the first token"));

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        let stalled = app
            .first_token_stall()
            .expect("a stalled stream is described");
        assert_eq!(stalled.state, FirstTokenState::Stalled);
        assert!(stalled.label().contains("may be stalled"));
        assert_ne!(
            slow.label(),
            stalled.label(),
            "the two failures must not share one sentence"
        );
        assert!(
            FIRST_TOKEN_STALL_AFTER < std::time::Duration::from_secs(60),
            "the operator must learn this before the response-header deadline expires"
        );

        // Extended thinking is the model producing tokens, so it clears the clock exactly like
        // text does — the same rule `TurnEnd.ttft_ms` measures by.
        apply_event(&mut app, UiEvent::Thinking("reasoning".into()));
        assert!(app.first_token_stall().is_none());

        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        apply_event(&mut app, UiEvent::Text("answer".into()));
        assert!(app.first_token_stall().is_none());

        // Leaving the model phase stops the clock: only a provider request can be waiting on one.
        apply_event(&mut app, UiEvent::Phase(core_protocol::Phase::Model));
        app.awaiting_first_token_since = Some(Instant::now() - FIRST_TOKEN_STALL_AFTER);
        apply_event(&mut app, UiEvent::Phase(core_protocol::Phase::Tools));
        assert!(app.first_token_stall().is_none());
    }

    #[test]
    fn windows_clipboard_plan_ignores_parent_roots_and_uses_fixed_stock_powershell_path() {
        fn simulated_windows_root(path: &Path) -> bool {
            let text = path.to_string_lossy();
            if text.starts_with("\\\\?\\") || text.starts_with("\\\\.\\") {
                return false;
            }
            let bytes = text.as_bytes();
            (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
                || text.starts_with(r"\\")
        }

        let environment = windows_clipboard_environment_with(
            Some(r"C:\Windows".into()),
            |name| {
                Some(
                    match name {
                        "TEMP" | "TMP" => r"C:\Temp",
                        "SystemRoot" | "SYSTEMROOT" | "WINDIR" => r"D:\attacker",
                        _ => "must-not-cross",
                    }
                    .into(),
                )
            },
            simulated_windows_root,
        );
        assert_eq!(
            windows_clipboard_powershell_program(&environment),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())
        );
        assert_eq!(
            environment
                .iter()
                .find_map(|(name, value)| (name == "PATH").then_some(value))
                .map(OsString::as_os_str),
            Some(std::ffi::OsStr::new(
                r"C:\Windows\System32\WindowsPowerShell\v1.0;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
            ))
        );
        let keys = environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            ["PATH", "SystemRoot", "TEMP", "TMP", "WINDIR"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        for forbidden in ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"] {
            assert!(!keys.contains(forbidden));
        }

        let ignored_parent_root = windows_clipboard_environment_with(
            Some(r"D:\Windows".into()),
            |name| {
                matches!(name, "SystemRoot" | "SYSTEMROOT" | "WINDIR")
                    .then(|| r"C:\attacker".into())
            },
            simulated_windows_root,
        );
        assert_eq!(
            windows_clipboard_powershell_program(&ignored_parent_root),
            Some(r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into())
        );
        for invalid in [
            r"relative\Windows",
            r"\\?\C:\Windows",
            r"\\.\C:\Windows",
            r"C:\Windows;C:\attacker",
        ] {
            assert!(
                windows_clipboard_environment_with(
                    Some(invalid.into()),
                    |_| None,
                    simulated_windows_root,
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn notifications_use_only_the_out_of_band_writer_and_never_stream_deltas() {
        let mut app = App::new();
        let mut output = Vec::new();
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();

        apply_live_event(
            &mut app,
            UiEvent::Text("visible streamed answer".into()),
            &mut notifier,
            &mut output,
        );
        assert!(
            output.is_empty(),
            "a streamed delta must remain byte-silent"
        );

        apply_live_event(
            &mut app,
            turn_end(0.01, Usage::default()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Phase(core_protocol::Phase::Model),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            turn_end(0.02, Usage::default()),
            &mut notifier,
            &mut output,
        );
        assert!(
            output.is_empty(),
            "a provider TurnEnd is not the authoritative run-complete boundary"
        );

        let approval = UiEvent::ApprovalRequest {
            id: SubmissionId(41),
            tool: "hostile\x1b]9;injected".into(),
            capability: Capability::CodeExecuting,
            reason: "fixture".into(),
            arguments: serde_json::json!({"command": "true"}),
            workspace: "/fixture".into(),
        };
        apply_live_event(&mut app, approval.clone(), &mut notifier, &mut output);
        apply_live_event(&mut app, approval, &mut notifier, &mut output);
        assert_eq!(
            output, b"\x07",
            "a repeated approval id is notified only once"
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("legacy presentation".into()),
            &mut notifier,
            &mut output,
        );
        assert_eq!(
            output, b"\x07",
            "UiEvent::Done cannot masquerade as App Server run completion"
        );
        assert!(
            !String::from_utf8_lossy(&output).contains("injected"),
            "untrusted event content must not enter a control sequence"
        );

        app.flush_text();
        for block in &app.transcript {
            let retained = block.to_text();
            assert!(!retained.contains('\x1b'));
            assert!(!retained.contains('\x07'));
        }
    }

    #[test]
    fn provider_turns_and_done_wait_for_the_authoritative_run_boundary() {
        let mut app = App::new();
        let mut output = Vec::new();
        let mut notifier = notification::TerminalNotifier::new(true);
        notifier.begin_run();

        apply_live_event(
            &mut app,
            UiEvent::Phase(core_protocol::Phase::Model),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            turn_end(0.01, Usage::default()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("Done".into()),
            &mut notifier,
            &mut output,
        );
        apply_live_event(
            &mut app,
            UiEvent::Done("duplicate transport delivery".into()),
            &mut notifier,
            &mut output,
        );
        assert_eq!(
            output, b"",
            "model phases, provider turns, and Done are all run-completion byte-silent"
        );

        let trigger = notifier
            .run_completed()
            .expect("the accepted run owns one terminal boundary");
        notifier.emit(&mut output, trigger);
        assert_eq!(
            output, b"\x07",
            "the authoritative run boundary emits exactly one notification"
        );
        assert_eq!(notifier.run_completed(), None);
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
        // The runtime clears the ledger's last-turn usage on a model change (see
        // `app_server::apply_control`) and reports the result on the snapshot; the frontend adopts
        // whatever the snapshot says rather than deciding for itself.
        let state = app_server::SessionSnapshot {
            mode: core_protocol::PermissionMode::default(),
            effort: core_protocol::Effort::default(),
            model: "claude-opus-5".into(),
            cost: core_obs::CostState::default(),
            last_turn_usage: None,
            unadmitted_steers: Vec::new(),
            permission_rules: PermissionRules::new(),
            ledger_summary: String::new(),
            rate_limit: None,
        };

        clear_last_turn_telemetry_from(&mut app, &state);

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
        app.route.provider_id = "openai".into();
        app.route.model_id = "gpt-5".into();
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
    fn running_ctrl_d_requests_exactly_one_drain_and_surfaces_checkpointing() {
        let mut app = App::new();
        app.running = true;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session = Session::for_test(tx);
        let drain = Arc::new(AtomicBool::new(false));

        request_drain(&mut app, &session, &drain, true);
        request_drain(&mut app, &session, &drain, true);

        assert!(app.draining);
        assert!(drain.load(Ordering::Relaxed));
        assert!(app.status.contains("draining"));
        assert!(matches!(
            rx.try_recv()
                .expect("Ctrl-D submits one control envelope")
                .into_current()
                .expect("current protocol envelope"),
            Op::Drain
        ));
        assert!(
            rx.try_recv().is_err(),
            "repeated Ctrl-D must not spam drain submissions"
        );
        let screen = render_text(&mut app, 80, 16);
        assert!(screen.contains("draining"));
        assert!(screen.contains("checkpoint"));
    }

    #[test]
    fn running_ctrl_d_refuses_cleanly_when_workspace_cannot_be_checkpointed() {
        let mut app = App::new();
        app.running = true;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let session = Session::for_test(tx);
        let drain = Arc::new(AtomicBool::new(false));

        request_drain(&mut app, &session, &drain, false);

        assert!(!app.draining);
        assert!(!drain.load(Ordering::Relaxed));
        assert!(rx.try_recv().is_err());
        let screen = render_text(&mut app, 90, 16);
        assert!(screen.contains("requires a Git worktree"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn export_path_uses_the_shared_capability_snapshot_writer() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("core-export-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let blocks = vec![
            Arc::new(block::Block::new(
                1,
                block::BlockKind::User("first semantic record".into()),
            )),
            Arc::new(block::Block::new(
                2,
                block::BlockKind::Notice {
                    level: block::NoticeLevel::Info,
                    text: "second semantic record".into(),
                },
            )),
        ];
        let exported = export_transcript(&root, &blocks, Some(&[2]), "reports/session.md").unwrap();
        assert_eq!(exported, root.join("reports/session.md"));
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            transcript_export_body(&blocks, Some(&[2])).unwrap(),
            "viewer and slash export persist the exact semantic snapshot builder bytes"
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(target_os = "linux")]
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
        let blocks = vec![Arc::new(block::Block::new(
            1,
            block::BlockKind::User("safe".into()),
        ))];
        assert!(export_transcript(&root, &blocks, None, "escape/new.md").is_err());
        assert!(export_transcript(&root, &blocks, None, "linked.md").is_err());
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

    #[test]
    fn approval_event_preempts_an_open_transcript_viewer_immediately() {
        let mut app = App::new();
        app.transcript_viewer
            .open("", &app.transcript, app.transcript_revision);
        assert!(app.transcript_viewer.is_open());
        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(77),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "fixture".into(),
                arguments: serde_json::json!({"command": "true"}),
                workspace: "/fixture".into(),
            },
        );
        assert!(!app.transcript_viewer.is_open());
        assert!(app.pending.is_some());
        assert_eq!(app.approval_choice, ApprovalChoice::Deny);
    }

    #[tokio::test]
    async fn pending_transcript_effect_never_blocks_an_approval_transition() {
        let mut app = App::new();
        app.transcript_viewer
            .open("", &app.transcript, app.transcript_revision);
        let mut effects = transcript_effect::Supervisor::default();
        effects
            .start(transcript_effect::Request::Delay {
                duration: Duration::from_millis(50),
                origin: transcript_effect::Origin::Viewer,
            })
            .unwrap();
        app.transcript_viewer.begin_effect("test effect");

        apply_event(
            &mut app,
            UiEvent::ApprovalRequest {
                id: SubmissionId(78),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "must preempt background UI effects".into(),
                arguments: serde_json::json!({"command": "true"}),
                workspace: "/fixture".into(),
            },
        );

        assert!(effects.is_active());
        assert!(!app.transcript_viewer.is_open());
        assert!(app.pending.is_some());
        effects.shutdown().await;
    }

    #[tokio::test]
    async fn reopening_viewer_restores_the_authoritative_pending_effect_marker() {
        let mut app = App::new();
        let mut effects = transcript_effect::Supervisor::default();
        effects
            .start(transcript_effect::Request::Delay {
                duration: Duration::from_millis(50),
                origin: transcript_effect::Origin::Viewer,
            })
            .unwrap();
        open_transcript_viewer(&mut app, &effects, "");
        assert_eq!(
            app.transcript_viewer.pending_effect_label(),
            Some("test effect")
        );

        app.transcript_viewer.close();
        open_transcript_viewer(&mut app, &effects, "");
        assert_eq!(
            app.transcript_viewer.pending_effect_label(),
            Some("test effect"),
            "reopen must derive pending state from the live single-flight supervisor"
        );
        effects.shutdown().await;
    }
}

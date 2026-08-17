//! The interactive TUI (ratatui + crossterm) — the product face, like Codex/Claude Code.
//!
//! Layout: a full-width semantic transcript; an on-demand activity shelf and explicit steer/after-
//! turn lanes; one framed composer; contextual help; and a stable bottom status line. Metrics
//! progressively disclose instead of becoming permanent dashboard chrome. Ctrl-C/Esc request a
//! safe-point stop; a second Ctrl-C exits; Ctrl-D drains active work (or quits when idle); wheel/trackpad input scrolls the
//! in-session transcript by default, while Ctrl-T releases mouse capture for native selection; Esc
//! quits when idle.
//!
//! The agent runs in a background task and streams `UiEvent`s over a channel; the render loop
//! drains them and redraws. The kernel does the work; this is a thin, replaceable front-end
//! on the same iteron (ADR-010: frontends are adapters).

mod app_init;
mod app_input_state;
mod app_picker;
mod app_transcript;
mod app_workflow;
mod app_workflow_legacy;
#[cfg(target_os = "linux")]
mod capability_fs;
mod clipboard;
mod command_dispatch;
mod command_surfaces;
mod composer_images;
mod context_chips;
mod control_submission;
mod driver_support;
mod event_actions;
mod event_projection;
mod experiment_lab;
pub(crate) mod hyperlink;
mod inline_shell;
mod jobs;
mod keyboard_enhancement;
mod live_markdown;
mod mcp_command;
mod mouse_capture;
mod notification;
mod picker_catalog;
mod session_adoption;
mod session_management;
mod session_picker;
mod status_command;
mod status_line;
mod submission;
mod terminal_input;
mod terminal_lifecycle;
pub(crate) mod transcript_effect;
mod transcript_export;
mod transcript_layout;
mod transcript_viewer;
mod tunables_view;
mod workflow_panel_projection;
mod workflow_region;
mod workflow_rehydrate;
mod workflows_panel;
mod workspace_command;

pub(crate) mod headless;
use crate::app_server;
use crate::commands::{self, SlashCommand};
use crate::config::PromptHistoryMode;
use crate::editor::Editor;
use crate::file_input;
use crate::image_input::{self, ImageAttachments};
use crate::paste_input;
use crate::providers::{ModelSelection, ProviderDirectory};
use crate::route::RouteView;
use crate::runtime::{
    UiEvent, WorkflowAgentOutcomeUi, WorkflowPhaseUi, WorkflowRunOutcomeUi, WorkflowUiEvent,
};
use crate::semantic_text::{is_unsafe_display_char, ui_safe_json, ui_safe_text};
use crate::{block, keymap, prompt_history, startup, surface, theme};
use app_init::build_completion;
use block::spinner;
use command_surfaces::*;
use composer_images::*;
use control_submission::*;
use crossterm::event::{
    Event as CEvent, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use driver_support::*;
pub(crate) use driver_support::{char_width, text_width};
use event_actions::*;
use event_projection::*;
use iteron_ctx::ContextEstimate;
use iteron_obs::CostState;
use iteron_protocol::{
    Capability, Effort, Op, PermissionMode, PermissionRules, ReasoningEffort, SubmissionId, Usage,
    Verdict,
};
use iteron_provider::EffortApplication;
use picker_catalog::*;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::{Frame, Terminal, TerminalOptions, Viewport};
use session_adoption::*;
use session_picker::*;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Write;
#[cfg(windows)]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use submission::*;
use terminal_lifecycle::{TermGuard, restore_terminal};
#[cfg(test)]
use terminal_lifecycle::{
    replace_terminal_title_to, restore_terminal_after_panic_to, restore_terminal_title_to,
    set_terminal_title_to,
};
use tokio::io::AsyncReadExt as _;
use workflow_panel_projection::*;

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
    /// Shared bounded content-free lifecycle flight recorder.
    lifecycle: iteron_obs::lifecycle::LifecycleBus,
    lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
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
        lifecycle: iteron_obs::lifecycle::LifecycleBus,
        lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
        state: app_server::SessionSnapshot,
        facts: app_server::SessionFacts,
    ) -> Self {
        Self {
            client: handle_client,
            control,
            lifecycle,
            lifecycle_otel,
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

    pub(crate) fn session_id(&self) -> &iteron_protocol::SessionId {
        &self.facts.session_id
    }

    pub(crate) fn lifecycle_snapshot(&self) -> iteron_obs::lifecycle::FlightRecorderSnapshot {
        self.lifecycle.snapshot()
    }

    pub(crate) fn lifecycle_otel_snapshot(
        &self,
    ) -> Option<iteron_obs::otel::lifecycle::LifecycleTelemetrySnapshot> {
        self.lifecycle_otel
            .as_ref()
            .map(|runtime| runtime.snapshot())
    }

    pub(crate) fn context_ledger_snapshot(&self) -> iteron_ctx::ContextLedgerSnapshot {
        self.facts.context_ledgers.snapshot()
    }

    pub(crate) fn memory_trace_snapshot(&self) -> iteron_ctx::MemoryTraceSnapshot {
        self.facts.memory_traces.snapshot()
    }

    pub(crate) fn hook_health_snapshot(
        &self,
    ) -> crate::runtime::lifecycle_hooks::LifecycleHookHealthSnapshot {
        self.facts.hook_health.snapshot()
    }

    pub(crate) fn telemetry_export_health_snapshot(
        &self,
    ) -> Option<crate::runtime::telemetry::TelemetryHealthSnapshot> {
        self.facts
            .telemetry_health
            .as_ref()
            .map(|health| health.snapshot())
    }

    pub(crate) fn record_lifecycle(
        &self,
        event_name: &str,
        payload: iteron_protocol::LifecyclePayload,
    ) {
        self.client.record_lifecycle(event_name, payload);
    }

    pub(crate) fn memory_workspace(&self) -> Option<&std::path::Path> {
        self.facts.memory_workspace.as_deref()
    }

    pub(crate) fn rollout_path(&self) -> &std::path::Path {
        &self.facts.rollout_path
    }

    pub(crate) fn tunables_checkpoint(&self) -> Option<&iteron_record::TunablesCheckpoint> {
        self.facts.tunables_checkpoint.as_ref()
    }

    pub(crate) fn tunables_effective_digest(&self) -> Option<&str> {
        match self.tunables_checkpoint()? {
            iteron_record::TunablesCheckpoint::V1(snapshot) => {
                Some(&snapshot.effective_digest_sha256)
            }
            iteron_record::TunablesCheckpoint::V2(snapshot) => {
                Some(&snapshot.effective_digest_sha256)
            }
        }
    }

    pub(crate) fn runtime_profile_id(&self) -> Option<&'static str> {
        let digest = match self.tunables_checkpoint()? {
            iteron_record::TunablesCheckpoint::V1(snapshot) => {
                snapshot.profile_digest_sha256.as_deref()
            }
            iteron_record::TunablesCheckpoint::V2(snapshot) => {
                snapshot.profile_digest_sha256.as_deref()
            }
        }?;
        iteron_tunables::RuntimeProfile::ALL
            .into_iter()
            .find(|profile| {
                iteron_tunables::runtime_profile_digest(*profile)
                    .ok()
                    .as_deref()
                    == Some(digest)
            })
            .map(iteron_tunables::RuntimeProfile::id)
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

    pub(crate) fn bypass_permissions(&self) -> bool {
        self.facts.bypass_permissions
    }

    pub(crate) fn permission_rules(&self) -> &PermissionRules {
        &self.state.permission_rules
    }

    /// Ordered, durable provenance for the mutable policy fields projected beside the immutable
    /// run-genesis tunables checkpoint. `None` is reserved for legacy or unsealed runtimes and is
    /// never interpreted as "the genesis value is still current".
    pub(crate) fn runtime_policy(&self) -> Option<&crate::runtime::RuntimePolicyOverlaySnapshot> {
        self.state.runtime_policy.as_ref()
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
        submissions: tokio::sync::mpsc::Sender<iteron_protocol::SqEnvelope>,
    ) -> Self {
        let (control, _control_rx) = tokio::sync::mpsc::channel(1);
        Self {
            client: app_server::AppServerClient::connect(
                iteron_protocol::PROTOCOL_VERSION,
                submissions,
            )
            .expect("the in-process server speaks the current protocol"),
            control,
            lifecycle: iteron_obs::lifecycle::LifecycleBus::default(),
            lifecycle_otel: None,
            state: app_server::SessionSnapshot {
                mode: iteron_protocol::PermissionMode::default(),
                effort: iteron_protocol::Effort::default(),
                model: "test-model".into(),
                provider_id: "test-provider".into(),
                cost: iteron_obs::CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                permission_rules: PermissionRules::new(),
                runtime_policy: None,
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            },
            facts: app_server::SessionFacts {
                session_id: iteron_protocol::SessionId("session-test".into()),
                context_ledgers: iteron_ctx::ContextLedgerStore::default(),
                memory_traces: iteron_ctx::MemoryTraceStore::default(),
                hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth::default(),
                telemetry_health: None,
                workspace: std::path::PathBuf::new(),
                memory_workspace: None,
                rollout_path: std::path::PathBuf::new(),
                compaction_trigger_tokens: 0,
                bypass_permissions: false,
                initial_model_context_window: None,
                registry_tools: Vec::new(),
                dependency_skill_dirs: Vec::new(),
                agent_catalog: Arc::new(iteron_agents::AgentCatalog::builtin_only()),
                tunables_checkpoint: None,
            },
        }
    }

    pub(crate) fn registry_tools(&self) -> &[app_server::ToolFact] {
        &self.facts.registry_tools
    }

    pub(crate) fn dependency_skill_dirs(&self) -> &[(std::path::PathBuf, std::path::PathBuf)] {
        &self.facts.dependency_skill_dirs
    }

    /// The execution catalog captured by the App Server at attach time. This is deliberately not
    /// reconstructed from `workspace` or an ambient operator home: those paths may drift while the
    /// resident runtime continues resolving children against this immutable snapshot.
    pub(crate) fn agent_catalog(&self) -> &iteron_agents::AgentCatalog {
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
        tunables_checkpoint: iteron_record::TunablesCheckpoint,
        compaction_trigger_tokens: usize,
        snapshot: app_server::SessionSnapshot,
    ) {
        self.facts.rollout_path = rollout_path;
        self.facts.tunables_checkpoint = Some(tunables_checkpoint);
        self.facts.compaction_trigger_tokens = compaction_trigger_tokens;
        self.state = snapshot;
    }

    /// Submit one operation on the SQ.
    pub(crate) fn submit(&self, op: Op) -> Result<(), app_server::SubmitError> {
        self.client.submit(op)
    }

    pub(crate) fn submit_identified(
        &self,
        op: Op,
    ) -> Result<SubmissionId, app_server::SubmitError> {
        self.client.submit_identified(op)
    }

    pub(crate) fn control_sender(&self) -> tokio::sync::mpsc::Sender<app_server::ControlRequest> {
        self.control.clone()
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
        "◉ max".into()
    } else {
        visual_reasoning_effort(effort.reasoning_effort())
    }
}

/// Claude-style effort symbol, but derived from the adapter's observed application rather than the
/// picker alone. Mapping and non-exact enforcement stay visible instead of being prettified away.
///
fn effort_status_label(app: &App) -> String {
    match app.effort_application {
        Some(EffortApplication::Exact { requested }) => visual_reasoning_effort(requested),
        Some(EffortApplication::Mapped { requested, sent }) => {
            if requested == sent {
                visual_reasoning_effort(sent)
            } else {
                format!(
                    "{} ← {} requested",
                    visual_reasoning_effort(sent),
                    requested.label()
                )
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentEffectState {
    Idle,
    Queued,
    Reading,
    Decoding,
    Ready,
    Failed,
    Cancelled,
}

struct PresentedActivity {
    event: iteron_protocol::ActivityEvent,
    observed_at: Instant,
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
            if scanned_bytes
                > iteron_tunables::param_integer(
                    "cli.tui.max_picker_paste_scan_bytes",
                    MAX_PICKER_PASTE_SCAN_BYTES,
                )
                || query_chars
                    >= iteron_tunables::param_integer(
                        "cli.tui.max_picker_query_chars",
                        MAX_PICKER_QUERY_CHARS,
                    )
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
            if self.query.len().saturating_add(character.len_utf8())
                > iteron_tunables::param_integer(
                    "cli.tui.max_picker_query_bytes",
                    MAX_PICKER_QUERY_BYTES,
                )
            {
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
            .unwrap_or(iteron_tunables::param_integer(
                "cli.tui.selection_offscreen_row",
                SELECTION_OFFSCREEN_ROW,
            ))
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
    /// A control whose owner is intentionally reachable while the resident Agent is borrowed.
    ImmediateCommand,
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

fn is_immediate_running_command(text: &str) -> bool {
    let Some(command) = slash_command_body(text) else {
        return false;
    };
    commands::dispatch(command).is_ok_and(|routed| {
        matches!(
            routed.route,
            commands::DispatchRoute::InProcess(SlashCommand::Mcp | SlashCommand::Status)
        )
    })
}

fn input_destination(running: bool, interrupting: bool, text: &str) -> InputDestination {
    if !running {
        InputDestination::StartTurn
    } else if is_immediate_running_command(text) {
        InputDestination::ImmediateCommand
    } else if interrupting
        || slash_command_body(text).is_some()
        || text.trim_start().starts_with('!')
    {
        // Once an interrupt is requested, the current turn is closing. Sending new prose as a
        // steer at that point races the kernel's last admission boundary; the same bytes can be
        // reported unadmitted, admitted just before the stop, or refused by a saturated SQ. The
        // frontend already owns an ordered after-turn lane, so Enter becomes an unambiguous "next
        // prompt" while the operator keeps the same focused composer.
        // `!` keeps the bare-prefix test: it is unambiguous local-shell intent, and a dropped
        // absolute path never starts with it (a drop that did would still be shell input, which is
        // what `!` promises).
        InputDestination::AfterTurn
    } else {
        InputDestination::SteerCurrentRun
    }
}

/// Filesystem-free destination used by paint and ordinary key routing. Ambiguous `/tmp`-shaped
/// drafts are conservatively shown as after-turn controls; only Enter performs the one disk check
/// needed to decide whether they are actually dropped paths.
fn cached_input_destination(
    running: bool,
    interrupting: bool,
    shape: crate::editor::DraftShape,
) -> InputDestination {
    if !running {
        InputDestination::StartTurn
    } else if matches!(
        shape,
        crate::editor::DraftShape::Slash {
            immediate_while_running: true
        }
    ) {
        InputDestination::ImmediateCommand
    } else if interrupting
        || matches!(
            shape,
            crate::editor::DraftShape::Slash { .. } | crate::editor::DraftShape::Shell
        )
    {
        InputDestination::AfterTurn
    } else {
        InputDestination::SteerCurrentRun
    }
}

#[derive(Clone)]
struct PendingInput {
    seq: u64,
    text: String,
    /// The chips this submission was composed with, moved out of the composer when it was queued.
    ///
    /// They travel WITH the text because `Editor::take_submit` clears the attachment stores: an
    /// image dropped during a run and queued behind it would otherwise be discarded on the way to
    /// the queue, or — worse — still be sitting in the composer when the operator writes an
    /// unrelated message next, and would be sent with that one instead. Neither is a thing anyone
    /// asked for. A steer cannot carry them at all (`Op::Steer` is text, and the protocol is
    /// frozen), which is why a draft with chips is always routed to this queue.
    images: image_input::ImageAttachments,
    files: file_input::FileAttachments,
}

struct PendingTurnReceipt {
    id: SubmissionId,
    editor_revision: u64,
    clear_composer: bool,
    display_text: String,
}

/// Identity of a queued submission is what it will send: its order, its words, and how many chips
/// ride with it. The attachment stores hold decoded bytes and are deliberately not compared —
/// equality is used by the queue-ordering assertions, not to decide whether two images are alike.
impl PartialEq for PendingInput {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.text == other.text
            && self.images.len() == other.images.len()
            && self.files.len() == other.files.len()
    }
}

impl Eq for PendingInput {}

impl std::fmt::Debug for PendingInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInput")
            .field("seq", &self.seq)
            .field("text", &self.text)
            .field("images", &self.images.len())
            .field("files", &self.files.len())
            .finish()
    }
}

impl PendingInput {
    fn has_attachments(&self) -> bool {
        !self.images.is_empty() || !self.files.is_empty()
    }
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
/// ordinary, and before it stops calling it merely slow. Both sit well inside the 45s provider
/// inactivity deadline, which is the point: the operator learns
/// which failure they are watching while the request is still open (I-64).
const FIRST_TOKEN_SLOW_AFTER: std::time::Duration = std::time::Duration::from_secs(3);
/// The one-keystroke retry offer printed under a failed run (I-39).
const RETRY_HINT: &str = "ctrl+r re-sends this turn. Whatever the model had already streamed is \
recorded as an interrupted message, so a retry continues from it rather than from nothing.";

fn retry_hint() -> &'static str {
    iteron_tunables::param_str("cli.tui.retry_hint", RETRY_HINT)
}
const FIRST_TOKEN_STALL_AFTER: std::time::Duration = std::time::Duration::from_secs(12);

/// Row a list falls back to when the selected item is not in the visible window. The first row,
/// so a filtered view opens on something rather than on nothing.
const SELECTION_OFFSCREEN_ROW: usize = 0;
/// Slack added to `workflow::SHUTDOWN_GRACE` when waiting out the server task on a catchable
/// termination, so the wait outlives the grace it is supposed to observe rather than racing it.
const SHUTDOWN_WAIT_SLACK: std::time::Duration = std::time::Duration::from_secs(1);
/// Codex-style bounded second-press window: one Ctrl-C interrupts, a second exits even while a
/// workflow or tool is still settling. Outside this window Ctrl-C simply arms the gesture again.
const CTRL_C_QUIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// Local workers do not publish on the runtime EQ. Poll only while one exists so completion,
/// session loading and attachment work cannot finish silently while an otherwise-idle TUI sleeps.
const LOCAL_JOB_POLL: std::time::Duration = std::time::Duration::from_millis(16);
/// How long a clipboard-image capture subprocess may run before it is killed. Bounded because a
/// wedged helper must not hang the paste path.
const CLIPBOARD_CAPTURE_TIMEOUT: Duration = Duration::from_secs(3);
/// List height used when the row count does not fit a `u16` at all. Two rows keep the popup
/// navigable, matching the upper end of the clamp the conversion is fed.
const MIN_LIST_ROWS_ON_OVERFLOW: u16 = 2;

/// Whether a silent provider is being described as slow or as stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstTokenState {
    Slow,
    Stalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunningCtrlCAction {
    InterruptAndArm,
    ForceQuit,
}

fn running_ctrl_c_action(
    deadline: &mut Option<Instant>,
    now: Instant,
    window: Duration,
) -> RunningCtrlCAction {
    if deadline.is_some_and(|deadline| now <= deadline) {
        *deadline = None;
        RunningCtrlCAction::ForceQuit
    } else {
        *deadline = Some(now + window);
        RunningCtrlCAction::InterruptAndArm
    }
}

fn local_job_wake(wake: Option<Instant>, now: Instant, active: bool) -> Option<Instant> {
    if !active {
        return wake;
    }
    let job_wake = now + iteron_tunables::param_duration("cli.tui.local_job_poll", LOCAL_JOB_POLL);
    Some(wake.map_or(job_wake, |scheduled| scheduled.min(job_wake)))
}

/// A first-token wait long enough to say something about.
#[derive(Debug, Clone, Copy)]
struct FirstTokenStall {
    state: FirstTokenState,
    waited: std::time::Duration,
    accepted: bool,
}

impl FirstTokenStall {
    fn label(self) -> String {
        let seconds = self.waited.as_secs();
        match (self.accepted, self.state) {
            (false, FirstTokenState::Slow) => {
                format!("request sent · waiting for provider response · {seconds}s")
            }
            (false, FirstTokenState::Stalled) => {
                format!("request sent · no provider response for {seconds}s · esc to interrupt")
            }
            (true, FirstTokenState::Slow) => {
                format!("accepted · model generating · waiting for first token · {seconds}s")
            }
            (true, FirstTokenState::Stalled) => format!(
                "accepted · no token for {seconds}s · provider may be stalled · esc to interrupt"
            ),
        }
    }
}

/// TUI state.
struct App {
    /// Stable operator-facing identity of the current rollout. This follows session adoption and
    /// rename, and is reused by footer, fullscreen panels, and the physical terminal tab title.
    session_name: String,
    /// The structured semantic transcript (ADR-015): typed self-rendering blocks, not a flat log.
    transcript: Vec<Arc<block::Block>>,
    /// Fullscreen, presentation-only inspection state. Its bounded index reconciles against the
    /// authoritative transcript's stable ids and revisions only when this authority revision
    /// changes; ordinary redraws never rescan or refold transcript bytes.
    transcript_viewer: transcript_viewer::Viewer,
    /// Monotonic notification for semantic transcript insertions, mutations, clears, and eviction.
    /// This is the O(1) stable-frame seam for the fullscreen viewer.
    transcript_revision: u64,
    /// Lowest transcript block whose retained geometry may have changed. `None` means the height
    /// index is current; appends and card updates splice only this suffix on the next paint.
    transcript_dirty_from: Option<usize>,
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
    /// The workflow region's store: the QuickJS `iteron-workflow` runs this TUI is watching, each
    /// bound to the one live phase→agent tree card that renders it (design §3.2 store), plus the
    /// region's focus and collapse state. The interactive-REPL seam, driven by
    /// `workflow_run_ui_event` (ADR-0001 step 1). The transcript card remains the authority the
    /// renderer reads; see `workflow_region` for what this store deliberately does not copy.
    workflow_monitor: workflow_region::WorkflowMonitor,
    /// Fullscreen workflow inspection/control state. The run tree itself stays in transcript
    /// cards; this owns only selection, action feedback and the latest supervisor inventory.
    workflows_panel: workflows_panel::View,
    /// `<runtime_state_dir>/subagents/workflows` — the directory `iteron workflow list` enumerates,
    /// derived the same way the kernel derives it (the rollout file's parent). It is what lets the
    /// monitor rebuild prior runs after a restart; `None` for a session with no rollout parent,
    /// which simply restores nothing.
    workflows_dir: Option<std::path::PathBuf>,
    /// Local output cursor for `/jobs attach`; the process remains owned by the runtime supervisor.
    attached_job: Option<jobs::AttachedJob>,
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
    /// Prefix-sum geometry retained across frames. An unchanged 1,200-block transcript is located
    /// with two binary searches instead of being walked for every spinner tick.
    transcript_layout: transcript_layout::HeightIndex,
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
    force_cancelling: bool,
    cancel_requested_at: Option<Instant>,
    draining: bool,
    /// Rows scrolled UP from the bottom (0 = pinned to the newest line).
    bottom_offset: u16,
    /// Whether new output follows the tail. Scrolling up disables follow until Ctrl-End or the
    /// viewport returns to the bottom, so streaming never steals the reader's position.
    follow_tail: bool,
    unread_updates: u32,
    last_total_rows: u16,
    last_view_h: u16,
    /// True once the user asks to quit; a forced double-Ctrl-C may set it during an active run.
    quit: bool,
    /// A bounded double-Ctrl-C exits the client even while the runtime owns active work. Teardown
    /// still gives the server one bounded grace period to terminalize workflows and flush records.
    force_quit_requested: bool,
    ctrl_c_quit_deadline: Option<Instant>,
    /// Truthful projection of the live keymap/Vim state; updated before routing each key.
    keymap_status: String,
    /// Char index the visual selection is anchored at; `None` outside visual mode.
    vim_anchor: Option<usize>,
    // live-accumulating current assistant paragraph (so streamed text coalesces into one line)
    cur_text: String,
    /// Exact safe assistant bytes projected for the current model turn. `RunEnded` reconciles this
    /// with its terminal authority; it is not display markdown and is never inferred from blocks.
    assistant_stream_authority: String,
    /// Assistant blocks belonging to that same model turn. A terminal rewrite can replace only
    /// these ids atomically while preserving prior turns and intervening tool cards.
    assistant_turn_block_ids: Vec<u64>,
    cur_text_revision: u64,
    cur_doc_revision: u64,
    cur_doc: Option<crate::markdown::MarkdownDoc>,
    /// How much of `cur_doc` is settled, so a delta re-parses only the tail it changed. Reset with
    /// `cur_doc` on every stream boundary.
    cur_doc_parse: crate::markdown::StreamingParse,
    /// Retained layout of the active assistant answer. Only appended source is processed; frames
    /// materialize visible rows instead of cloning the entire unfinished answer.
    live_markdown_layout: live_markdown::LiveMarkdownLayout,
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
    completion_due: Option<Instant>,
    completion_generation: u64,
    completion_job: Option<tokio::task::JoinHandle<(u64, String, Option<Completion>)>>,
    /// The open selection picker, if any (owns the keyboard while open).
    picker: Option<Picker>,
    /// One cancel-on-replacement session-page worker. Opening the modal is immediate; disk/index
    /// enumeration never runs in the key/command branch.
    session_picker_job: Option<tokio::task::JoinHandle<SessionPageResult>>,
    session_picker_backing: Option<SessionPickerBacking>,
    session_picker_generation: u64,
    session_preview_job: Option<tokio::task::JoinHandle<SessionPreviewResult>>,
    session_preview_generation: u64,
    session_adoption_job: Option<tokio::task::JoinHandle<PreparedAdoptionResult>>,
    /// At most one disk/process-heavy slash command. Completion carries bounded semantic actions;
    /// the key/render loop never awaits Git, record traversal, or workspace mutation.
    workspace_command_job: Option<tokio::task::JoinHandle<Vec<workspace_command::Action>>>,
    attachment_job: Option<tokio::task::JoinHandle<AttachmentEffectResult>>,
    attachment_generation: u64,
    attachment_progress: Option<tokio::sync::mpsc::Receiver<AttachmentEffectState>>,
    attachment_effect_state: AttachmentEffectState,
    activities: std::collections::BTreeMap<String, PresentedActivity>,
    /// Recently terminalized activity ids. A late cosmetic event cannot resurrect an old-turn
    /// spinner after the authoritative RunEnded boundary, even if a new turn has already started.
    retired_activity_ids: VecDeque<String>,
    /// Exact restart command prepared by a session selection. It is display/copy state only: an
    /// unchanged handoff is never submitted to the model or executed inside this process.
    resume_handoff: Option<String>,
    /// When the current run started (for the elapsed/spinner indicator).
    run_started: Option<Instant>,
    /// Cached after a terminal run boundary; rendering never asks the runtime or record store.
    last_run_latency: Option<Duration>,
    /// Best-effort workspace dirtiness sampled after first paint on the hydration worker.
    workspace_dirty: Option<bool>,
    /// The text of the last plain-text turn, retained only while a failed run offers to re-send
    /// it. A mid-stream failure is not retried automatically — only 429/529 are, and a bare
    /// transport error says nothing about whether the provider already billed the request — so
    /// the operator is the idempotency key, and this makes saying yes one keystroke (I-39).
    retryable_task: Option<String>,
    /// When the model phase began without a token yet arriving, and `None` again the instant one
    /// does. The provider inactivity deadline is 45s, so without
    /// this a dead connection and a slow prefill looked identical for a full minute (I-64). It is
    /// the frontend end of the same first-token instrumentation `TurnEnd.ttft_ms` records.
    awaiting_first_token_since: Option<Instant>,
    /// True only after provider response authority, never merely because a request was sent.
    provider_accepted: bool,
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
    /// Core owns mouse input by default so the wheel scrolls this session, not terminal history.
    /// Ctrl-T releases ownership for native drag selection without leaving the full-screen TUI.
    mouse_capture: mouse_capture::State,
    /// Text-cell projection from the last rendered composer frame. A click is resolved against this
    /// snapshot; every coordinate is re-clamped by the editor so a simultaneous resize is benign.
    /// Follow-ups composed WHILE the agent was running, each dispatched (in order) when the run
    /// finishes. A Vec (not a joined blob) so each item is classified separately — a queued
    /// `/compact` then a task run as two distinct actions (round-3 review).
    queued: VecDeque<PendingInput>,
    /// FIFO previews of steering submissions accepted by the frontend but not yet acknowledged at a
    /// kernel safe point. Kernel acknowledgement is count-based today, so FIFO is the honest interim
    /// projection until the App Server protocol supplies stable submission ids.
    steer_previews: VecDeque<PendingInput>,
    next_submission_seq: u64,
    pending_turn_receipt: Option<PendingTurnReceipt>,
    /// Dropped image paths this session has already refused out loud.
    ///
    /// Bare-path admission runs only at paste/drop/submit boundaries, but an unreadable path may be
    /// retried at more than one of those boundaries. Bounded and cleared wholesale on overflow: a
    /// set keyed by operator input with no ceiling is a leak, and forgetting a refusal only costs
    /// one repeated notice, never a missed attachment — the attach itself is always retried.
    #[cfg(test)]
    refused_image_paths: HashSet<PathBuf>,
}

/// How many distinct refused paths are remembered before the set is dropped and rebuilt. Sized for
/// "the operator is fighting with one screenshot", not for a corpus.
#[cfg(test)]
const MAX_REFUSED_IMAGE_PATHS: usize = 32;

/// Run the TUI. The agent runs in a background task streaming `UiEvent`s; the render loop drains
/// them and redraws. For follow-ups the same agent continues via `follow_up`.
/// Enter the interactive frontend.
///
/// The composition root hands this frontend an already-attached client. Everything below this line
/// holds queue endpoints, a negotiated protocol version and immutable session facts; the TUI cannot
/// name or reclaim the runtime type.
///
/// Both the handshake and its refusal happen before ANY terminal setup. A frontend that cannot
/// speak the runtime's protocol has nothing useful to draw, and a diagnostic printed after terminal
/// modes change is easy to lose or garble: negotiate first, then let the terminal guard own every
/// mode transition until the frontend exits.
pub(crate) struct RunConfig {
    pub(crate) completion_notifications: bool,
    pub(crate) history_mode: PromptHistoryMode,
    pub(crate) keymap: Option<keymap::Config>,
    pub(crate) external_editor: Option<Vec<String>>,
    pub(crate) sensitive_env_names: Vec<String>,
    /// Structured, content-free diagnostics emitted before alternate-screen attachment. They are
    /// replayed as notices only after the input-ready shell has painted, so startup evidence is not
    /// hidden on the primary screen.
    pub(crate) initial_diagnostics: Vec<iteron_kernel::diagnostics::KernelDiagnostic>,
    /// Human-readable, credential-free startup posture lines printed before attachment. The
    /// alternate screen hides the primary transcript, so replay them after first paint as well.
    pub(crate) initial_notices: Vec<String>,
    /// Durable transcript authority for a startup `--resume`/`--continue` invocation. The runtime
    /// already resumes the full model history; this copy exists only so the first TUI frame shows
    /// the same conversation instead of a fresh-session welcome surface.
    pub(crate) initial_transcript_events: Option<Vec<iteron_protocol::Event>>,
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
        initial_diagnostics,
        initial_notices,
        initial_transcript_events,
    } = config;
    let app_server::Attached {
        handle,
        task: mut server_task,
        facts,
        initial_state,
        interrupt,
        drain,
    } = attached;
    // History/content-store hydration is independent of input readiness. Resolve it on one bounded
    // worker and adopt the result only after the shell has painted; 10,000 sessions therefore cost
    // the first frame exactly the same as an empty store.
    let history_source_run = prompt_history::source_run_from_rollout(&facts.rollout_path);
    let (history_tx, mut history_rx) = tokio::sync::mpsc::channel(1);
    let history_workspace = facts.workspace.clone();
    let history_runs_dir = facts
        .rollout_path
        .parent()
        .map(std::path::Path::to_path_buf);
    let history_config_home = crate::config::config_home();
    let history_bootstrap_run = history_source_run.clone();
    let title_rollout = facts.rollout_path.clone();
    let workflow_hydrate_dir = facts
        .rollout_path
        .parent()
        .map(|state_dir| state_dir.join("subagents").join("workflows"));
    tokio::task::spawn_blocking(move || {
        let hyperlink_policy = hyperlink::Policy::detect(&history_workspace);
        let history_started = Instant::now();
        let hydrated = prompt_history::bootstrap(
            history_mode,
            history_config_home,
            &history_workspace,
            history_runs_dir,
            history_bootstrap_run,
        );
        let history_elapsed = history_started.elapsed();
        let title_started = Instant::now();
        let title = session_display_name(&title_rollout);
        let title_elapsed = title_started.elapsed();
        let mut workflow_monitor = workflow_region::WorkflowMonitor::default();
        workflow_monitor.rehydrate(workflow_hydrate_dir.as_deref());
        let workspace_dirty = cached_workspace_dirty(&history_workspace);
        let _ = history_tx.blocking_send((
            hydrated,
            title,
            workflow_monitor,
            workspace_dirty,
            hyperlink_policy,
            history_elapsed,
            title_elapsed,
        ));
    });
    let mut history_writer = prompt_history::Writer::new(None);
    let mut history_open = true;
    let (mut active_keymap, initial_keymap_warning) =
        match keymap::Keymap::from_config(keymap_config.as_ref()) {
            Ok(keymap) => (keymap, None),
            Err(error) => (
                keymap::Keymap::default(),
                Some(format!("invalid keymap; using built-in bindings: {error}")),
            ),
        };
    let mut vim = keymap::Vim::default();
    // Drain is a runtime/session control and never depends on Git availability.
    let drain_available = true;
    let terminal_capabilities = iteron_statusline::Capabilities::detect(|name| {
        std::env::var(name).ok().filter(|value| value.len() <= 128)
    });
    // The exact title is a cache, not a reason to enumerate every session before paint. New runs
    // acquire their title from the first accepted prompt; resumed runs use their O(1) rollout id
    // until a background/session-picker projection provides a friendlier label.
    let initial_session_name = facts
        .rollout_path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("New session")
        .to_owned();
    // RAII: the terminal is restored on ANY exit path (error/panic/normal).
    let mut guard = TermGuard::new()?;
    let _ = guard.set_title(
        terminal_capabilities,
        &format!("Iteron · {initial_session_name}"),
    );
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
    // BOTH capability probes are deliberately deferred until after the first frame. The
    // progressive-keyboard query blocks up to 2000 ms and OSC 11 another 80 ms; running them here,
    // between raw-mode entry and the first draw, is exactly how a terminal that never answers held
    // the initial surface for two seconds. The environment alone decides the first frame's theme;
    // a background reply only repaints it.
    let environment = theme::capabilities::Environment::capture();
    let detected_theme = theme::Theme::detect_with(environment.clone(), None);
    let (terminal_writer, mut notification_writer) = notification::LiveTerminalWriter::stdout();
    let backend = ratatui::backend::CrosstermBackend::new(terminal_writer);
    // The conversation is a complete application surface: TermGuard has already entered the
    // alternate screen and captured mouse input, while Ratatui owns the entire physical frame.
    // This keeps the wheel inside the current session instead of exposing older shell scrollback.
    let mut term = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Fullscreen,
        },
    )?;
    let mut notifier = notification::TerminalNotifier::new(completion_notifications);

    let repo = facts.workspace.clone();
    let mut app = App::new_with_detected_theme(detected_theme);
    app.session_name = initial_session_name;
    if terminal_capabilities.presentation == iteron_statusline::Presentation::Semantic {
        // Screen-reader mode keeps the same keyboard-complete interaction model, but removes the
        // raster logo and colour-only distinctions from the initial surface. Later blocks already
        // carry role/status words in addition to glyphs, so monochrome preserves their semantics.
        app.set_theme(theme::Theme::mono());
        app.transcript.clear();
        app.transcript.push(Arc::new(block::Block::new(
            0,
            block::BlockKind::Notice {
                level: block::NoticeLevel::Info,
                text: "Iteron. Ready. Screen-reader semantic presentation is active.".into(),
            },
        )));
        app.mark_transcript_changed();
    } else if !terminal_capabilities.may_use_color() {
        app.set_theme(theme::Theme::mono());
    }
    if let Some(events) = initial_transcript_events.as_deref() {
        project_recorded_transcript(&mut app, events);
    }
    if let Some(warning) = initial_keymap_warning {
        app.note(block::NoticeLevel::Warn, warning);
    }
    update_keymap_status(&mut app, &active_keymap, &vim);
    // The same derivation the kernel uses (`Agent::runtime_state_dir` is the rollout's parent), so
    // the runs this frontend restores are exactly the runs this session's own workflows land in.
    app.workflows_dir = facts
        .rollout_path
        .parent()
        .map(|state_dir| state_dir.join("subagents").join("workflows"));
    app.mode = initial_state.mode;
    app.effort = initial_state.effort;
    app.model = initial_state.model.clone();
    app.model_context_window = facts.initial_model_context_window;
    app.route = route;

    // Arm the response demultiplexer before the query exists, then enqueue both exact query frames
    // on the same writer Ratatui owns. `LiveTerminalWriter::flush` emits the retained shell first
    // and only then these frames, so no worker races stdout or changes its file-status flags.
    let mut terminal_input = terminal_input::TerminalInput::default();
    terminal_input.start_probes(&environment, |sequence| {
        notification_writer.admit_probe(sequence)
    });

    // Paint before probing. Everything the first frame needs is already resolved, and a terminal
    // that answers neither query must not be able to delay it. The probes are appended at this
    // frame's flush boundary, after the shell bytes are visible.
    term.draw(|f| draw(f, &mut app))?;
    startup.mark(startup::StartupPhase::FirstFrame);
    // The watcher takes its first metadata snapshot on its worker. Starting it after paint keeps
    // both thread startup and every filesystem query outside the first-frame path.
    let mut keymap_watcher = keymap::Watcher::new(crate::config::user_config_path());
    for diagnostic in initial_diagnostics {
        match diagnostic {
            iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {} => app.note(
                block::NoticeLevel::Err,
                "durable record append failed before the interface attached; review /status before continuing",
            ),
            iteron_kernel::diagnostics::KernelDiagnostic::ResumeRedactionDegraded {
                redacted_tool_results,
                count_saturated,
            } => app.note(
                block::NoticeLevel::Warn,
                format!(
                    "resumed context used redacted tool results ({redacted_tool_results}{}); the reconstructed model context differs from the original live turn",
                    if count_saturated { "+" } else { "" }
                ),
            ),
        }
    }
    for notice in initial_notices {
        app.note(block::NoticeLevel::Info, notice);
    }
    let mut session = Session::new(
        handle.client,
        handle.control,
        handle.lifecycle,
        handle.lifecycle_otel,
        initial_state,
        facts,
    );
    // Provider discovery is a presentation enrichment, never an input-path prerequisite.  A clone
    // owns the deferred join after the first frame and publishes one settled immutable directory;
    // `/model` remains immediately usable with the eager/cache-backed catalog meanwhile.
    let (provider_directory_tx, mut provider_directory_rx) = tokio::sync::mpsc::channel(1);
    // Cross the post-paint boundary synchronously before the initial task can be submitted. This
    // starts no pre-paint network and prevents route admission from racing a merely scheduled
    // settler that has not yet moved Dormant discovery to Pending.
    let _ = providers.begin_settle_after_paint();
    let mut settling_providers = providers.clone();
    tokio::spawn(async move {
        settling_providers.settle().await;
        let _ = provider_directory_tx.send(settling_providers).await;
    });
    let mut provider_directory_open = true;
    let mut events = handle.events;
    let mut last_event_seq = 0;
    let startup_waits_for_initial_answer = initial_task
        .as_deref()
        .is_some_and(|task| !task.trim().is_empty());
    let mut startup_initial_finalized = !startup_waits_for_initial_answer;
    let mut startup_history_ready = false;
    let mut first_task = initial_task;
    let mut redraw = true;

    // Terminal input moves onto its own thread so the loop can wait on stdin AND the event queue at
    // the same time. The loop used to poll stdin alone for a fixed 100 ms and only afterwards drain
    // the queue, so a delta batch landing 1 ms into a poll waited out the other 99 ms — and an idle
    // session sat in a 1 s poll hole. The demultiplexer moves with the reader, so a late OSC 11 or
    // keyboard-enhancement reply is still swallowed instead of becoming synthetic operator input.
    let (input_tx, mut input_rx) =
        tokio::sync::mpsc::channel::<std::io::Result<terminal_input::ReadResult>>(256);
    // Pause/resume is a two-command protocol. Capacity two admits one complete round trip even if
    // the reader is between terminal reads, while `try_send` keeps the TUI thread non-blocking.
    let (input_control_tx, input_control_rx) =
        std::sync::mpsc::sync_channel::<InputThreadControl>(2);
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
    startup.mark(startup::StartupPhase::TerminalProbe);
    startup.mark(startup::StartupPhase::InputReady);
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
    // Physical-key dispatch never waits for provider/control/filesystem work. Commands enter this
    // small FIFO after an immediate chip/status acknowledgement and are serviced one at a time.
    // The queue is deliberately tiny: an operator can always keep the unaccepted text in the
    // composer rather than creating an unbounded hidden command backlog.
    let mut pending_slash_commands: VecDeque<(String, Option<String>)> = VecDeque::new();
    let mut termination_exit = None;
    let mut terminal_session_name = app.session_name.clone();
    let mut catch_up = CatchUp::default();
    let mut eq_backlog_since: Option<Instant> = None;
    let mut resize_due: Option<Instant> = None;

    // All interactive-loop exits, including draw/input/editor/dispatch errors, flow through this
    // result boundary. Cleanup below therefore awaits the effect supervisor before the function can
    // return; relying on `Drop` would only abort the async shell and could orphan a helper process.
    let tui_result: anyhow::Result<()> = async {
    loop {
        // Kick off the initial task once the terminal is up.
        if let Some(task) = first_task.take()
            && !task.trim().is_empty()
        {
            startup.mark(startup::StartupPhase::InitialSubmission);
            submit_turn(&mut app, &session, &mut notifier, task);
            redraw = true;
        }

        // Drain the EQ (non-blocking). One long-lived subscription for the whole session: the
        // frontend used to create and retire a receiver per run, which is why there was no event
        // stream at all while idle and why the join had to double as a drain barrier.
        let eq_depth = events.len().saturating_add(usize::from(pending_event.is_some()));
        let now = Instant::now();
        if eq_depth == 0 {
            eq_backlog_since = None;
        } else {
            eq_backlog_since.get_or_insert(now);
        }
        let eq_age = eq_backlog_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default();
        catch_up.update(eq_depth, eq_age, now);
        for _ in catch_up.slots() {
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
            if let app_server::ServerEvent::Activity(activity) = &event {
                let measured = Duration::from_millis(
                    activity
                        .updated_at_unix_ms
                        .saturating_sub(activity.started_at_unix_ms),
                );
                match activity.detail_code {
                    Some(iteron_protocol::ActivityDetailCode::RequestSent) => {
                        startup.mark_duration(startup::StartupPhase::RequestSent, measured);
                    }
                    Some(iteron_protocol::ActivityDetailCode::AnswerComplete)
                        if activity.state.is_terminal() =>
                    {
                        startup.mark_duration(startup::StartupPhase::AnswerComplete, measured);
                    }
                    Some(iteron_protocol::ActivityDetailCode::Finalizing)
                        if activity.state.is_terminal() =>
                    {
                        startup.mark_duration(startup::StartupPhase::Finalization, measured);
                        startup_initial_finalized = true;
                        if startup_history_ready {
                            // End the responsiveness trace at initial-answer finalization. Waiting
                            // until TUI exit mislabeled the operator's entire session as startup.
                            startup.flush();
                        }
                    }
                    _ => {}
                }
            }
            apply_server_event(
                &mut app,
                &mut session,
                event,
                &mut notifier,
                &mut notification_writer,
                &interrupt,
                &drain,
                Some(&providers),
            );
            redraw = true;
        }
        if app
            .session_picker_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .session_picker_job
                .take()
                .expect("finished session picker job was present");
            if let Ok(mut page) = job.await
                && page.generation == app.session_picker_generation
                && app
                    .picker
                    .as_ref()
                    .is_some_and(|picker| picker.title == "Sessions · resume here")
            {
                if let Some(warning) = page.warning.take() {
                    app.note(block::NoticeLevel::Info, warning);
                }
                if page.replace {
                    if page.items.is_empty() {
                        let mut empty = PickItem::flat(
                            "No sessions recorded yet",
                            "start a prompt to create one",
                            false,
                            PickAction::Info,
                        );
                        empty.enabled = false;
                        page.items.push(empty);
                    }
                    if let Some(picker) = app.picker.as_mut() {
                        picker.sel = initial_picker_selection(&page.items);
                        picker.items = page.items;
                    }
                    app.session_picker_backing = Some(SessionPickerBacking {
                        runs: page.runs,
                        current_run: page.current_run,
                        next_cursor: page.next_cursor,
                        has_more: page.has_more,
                        generation: page.generation,
                    });
                } else if let Some(backing) = app.session_picker_backing.as_mut()
                    && backing.generation == page.generation
                {
                    backing.next_cursor = page.next_cursor;
                    backing.has_more = page.has_more;
                    if let Some(picker) = app.picker.as_mut() {
                        picker.items.extend(page.items);
                    }
                }
                maybe_prefetch_session_page(&mut app);
                redraw = true;
            }
        }
        if app
            .session_preview_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .session_preview_job
                .take()
                .expect("finished session preview job was present");
            if let Ok(preview) = job.await
                && preview.generation == app.session_preview_generation
            {
                match preview.result {
                    Ok(preview) => {
                        let mut rows = vec![
                            kv("run", &preview.run),
                            kv("title", &preview.title),
                            kv("turns", &preview.turns.to_string()),
                            kv("state", preview.state),
                            kv(
                                "transcript",
                                &block::plural(preview.total_blocks, "visible block"),
                            ),
                        ];
                        rows.extend(preview.blocks.iter().map(|text| {
                            block::PanelRow::Note(one_line_preview(text, 160))
                        }));
                        app.panel("◫", "session preview", rows);
                        app.status = "idle · session preview ready".into();
                    }
                    Err(error) => {
                        app.note(block::NoticeLevel::Err, error);
                        app.status = "idle · session preview failed".into();
                    }
                }
                redraw = true;
            }
        }
        if app
            .session_adoption_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .session_adoption_job
                .take()
                .expect("finished session adoption job was present");
            match job.await {
                Ok(PreparedAdoptionResult::Ready(prepared)) => {
                    let PreparedAdoption {
                        fresh,
                        control,
                        run_id,
                        events,
                        selection,
                        substituted,
                        context_window_tokens,
                    } = prepared;
                    let request = transcript_effect::Request::Control {
                        sender: session.control_sender(),
                        control,
                        interrupt: interrupt.clone(),
                        kind: transcript_effect::ControlKind::Adopt {
                            fresh,
                            run_id,
                            events,
                            selection,
                            substituted,
                            context_window_tokens,
                        },
                    };
                    if transcript_effects.start(request).is_err() {
                        app.note(
                            block::NoticeLevel::Warn,
                            "session adoption not started: another local effect is pending",
                        );
                        app.status = "idle · session not resumed".into();
                    }
                }
                Ok(PreparedAdoptionResult::Failed {
                    message,
                    handoff_run,
                }) => {
                    app.note(block::NoticeLevel::Err, message);
                    if let Some(run_id) = handoff_run {
                        app.prepare_resume_handoff(&run_id);
                    }
                    app.status = "idle · session not resumed".into();
                }
                Err(error) if error.is_cancelled() => {
                    app.status = "idle · session loading cancelled".into();
                }
                Err(error) => {
                    app.note(
                        block::NoticeLevel::Err,
                        format!("session adoption worker failed: {error}"),
                    );
                    app.status = "idle · session not resumed".into();
                }
            }
            redraw = true;
        }
        if app
            .completion_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .completion_job
                .take()
                .expect("finished completion job was present");
            if let Ok((generation, source, completion)) = job.await
                && generation == app.completion_generation
                && source == app.editor.text()
            {
                app.completion = completion;
                redraw = true;
            }
        }
        if app
            .workspace_command_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .workspace_command_job
                .take()
                .expect("finished workspace command job was present");
            match job.await {
                Ok(actions) => workspace_command::apply(&mut app, &session, &providers, actions),
                Err(error) if error.is_cancelled() => {}
                Err(error) => app.note(
                    block::NoticeLevel::Err,
                    format!("workspace command worker failed: {error}"),
                ),
            }
            redraw = true;
        }
        if app.completion_job.is_none()
            && app.completion_due.is_some_and(|due| due <= Instant::now())
        {
            app.completion_due = None;
            let source = app.editor.text();
            let cursor = app.editor.cursor();
            let generation = app.completion_generation;
            let completion_repo = repo.clone();
            app.completion_job = Some(tokio::task::spawn_blocking(move || {
                let completion = build_completion(&source, cursor, &completion_repo);
                (generation, source, completion)
            }));
        }
        if app.attachment_job.is_some()
            && app.attachment_effect_state == AttachmentEffectState::Queued
        {
            app.attachment_effect_state = AttachmentEffectState::Reading;
            redraw = true;
        }
        if let Some(progress) = app.attachment_progress.as_mut() {
            while let Ok(state) = progress.try_recv() {
                app.attachment_effect_state = state;
                redraw = true;
            }
        }
        if app
            .attachment_job
            .as_ref()
            .is_some_and(|job| job.is_finished())
        {
            let job = app
                .attachment_job
                .take()
                .expect("finished attachment job was present");
            app.attachment_progress = None;
            match job.await {
                Ok(effect) => finish_attachment_effect(&mut app, &session, &mut notifier, effect),
                Err(error) if error.is_cancelled() => {
                    app.attachment_effect_state = AttachmentEffectState::Cancelled;
                }
                Err(error) => {
                    app.attachment_effect_state = AttachmentEffectState::Failed;
                    app.note(
                        block::NoticeLevel::Warn,
                        format!("attachment worker failed: {error}"),
                    );
                }
            }
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
                session.rollout_path(),
                &mut transcript_effects,
                effect,
            );
            redraw = true;
        }
        if app.advance_tool_presentations(Instant::now()) {
            redraw = true;
        }

        if let Some((command, restore)) = pending_slash_commands.pop_front() {
            app.status = format!("running /{command}…");
            dispatch_slash_command(
                &mut app,
                &mut session,
                &providers,
                &mut transcript_effects,
                &interrupt,
                &command,
            )?;
            if let Some(draft) = restore {
                app.editor.insert_str(&draft);
            }
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
                let item = app.queued.pop_front().expect("queue checked non-empty");
                // An item composed with chips is a submission, not a line of text: it goes out
                // through the same staging the composer uses, so the images and files it was queued
                // with are on the wire and the `[Image #N]` anchors it names still decide their
                // order. A slash command or `!bash` cannot carry attachments, so this branch owns
                // the whole classification for them.
                if item.has_attachments() {
                    if let Err(item) =
                        submit_queued_model_input(&mut app, &session, &mut notifier, item)
                    {
                        app.queued.push_front(*item);
                    }
                    break; // a run started; remaining items dispatch after it finishes
                }
                let q = item.text.trim().to_string();
                if q.is_empty() {
                    continue;
                } else if let Some(cmd) = slash_command_body(&q) {
                    if pending_slash_commands.len() < 8 {
                        pending_slash_commands.push_back((cmd.to_owned(), None));
                    } else {
                        app.queued.push_front(item);
                    }
                    break;
                } else if let Some(bash) = q.strip_prefix('!') {
                    // The runtime is resident, so these are always the live values. The old fallback to
                    // `(app.mode, PermissionRules::new())` ran `!bash` against DEFAULT-EMPTY rules
                    // whenever the `Agent` was away in a run task — a real correctness gap that
                    // inverting the ownership closes.
                    let (mode, rules) = (
                        session.permission_mode(),
                        session.permission_rules().clone(),
                    );
                    let request = transcript_effect::Request::Shell {
                        workspace: repo.clone(),
                        command: bash.trim().to_owned(),
                        sensitive_env_names: sensitive_env_names.clone(),
                        mode,
                        rules,
                    };
                    if transcript_effects.start(request).is_ok() {
                        app.note(
                            block::NoticeLevel::Info,
                            "shell running · Ctrl-C or Esc cancels it",
                        );
                    } else {
                        app.queued.push_front(item);
                        break;
                    }
                } else {
                    if let Err(item) =
                        submit_queued_model_input(&mut app, &session, &mut notifier, item)
                    {
                        app.queued.push_front(*item);
                    }
                    break; // a run started; remaining items dispatch after it finishes
                }
            }
        }

        // Attention is a client concern: a quiet live run receives one fixed notification after
        // the bounded idle interval, then rearms only when another typed EQ event arrives.
        if let Some(trigger) = notifier.poll_idle(app.running) {
            notifier.emit_transport(&mut notification_writer, trigger);
        }

        // Active animation owns a small cadence clock: 50 ms before first token makes accepted/
        // waiting state feel live, then 80 ms while streaming. Event-driven redraws remain
        // immediate; idle schedules no animation wake at all.
        let now = Instant::now();
        let activity_animation = app.running || !app.activities.is_empty();
        let spinner_tick = if app.awaiting_first_token_since.is_some() {
            iteron_tunables::param_duration(
                "cli.tui.driver_support.first_token_spinner_tick",
                FIRST_TOKEN_SPINNER_TICK,
            )
        } else {
            iteron_tunables::param_duration(
                "cli.tui.driver_support.spinner_tick",
                SPINNER_TICK,
            )
        };
        if resize_due.is_some_and(|due| now >= due) {
            resize_due = None;
            redraw = true;
        }
        if !activity_animation {
            last_spin = now;
        } else if now.duration_since(last_spin) >= spinner_tick {
            app.spin = app.spin.wrapping_add(1);
            last_spin = now;
            redraw = true;
        }

        // Coalescing: the first change of a burst draws immediately, and everything that arrives
        // within FRAME_COALESCE of that frame folds into the next one. A streamed burst therefore
        // costs one frame instead of one frame per delta batch.
        if redraw && now >= next_frame_at {
            if terminal_session_name != app.session_name {
                let _ = guard.replace_title(
                    terminal_capabilities,
                    &format!("Iteron · {}", app.session_name),
                );
                terminal_session_name.clone_from(&app.session_name);
            }
            term.draw(|f| draw(f, &mut app))?;
            redraw = false;
            next_frame_at = now + iteron_tunables::param_duration("cli.tui.driver_support.frame_coalesce", FRAME_COALESCE);
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
        let mut wake = if app.transcript_viewer.is_open() && app.transcript_viewer.work_ready() {
            Some(Instant::now())
        } else {
            next_wake(
                redraw,
                next_frame_at,
                activity_animation,
                last_spin,
                app.next_tool_reveal(),
                spinner_tick,
            )
        };
        if let Some(completion_due) = app.completion_due {
            wake = Some(wake.map_or(completion_due, |scheduled| scheduled.min(completion_due)));
        }
        if let Some(due) = resize_due {
            wake = Some(wake.map_or(due, |scheduled| scheduled.min(due)));
        }
        let local_job_active = app.session_picker_job.is_some()
            || app.session_preview_job.is_some()
            || app.session_adoption_job.is_some()
            || app.completion_job.is_some()
            || app.workspace_command_job.is_some()
            || app.attachment_job.is_some();
        wake = local_job_wake(wake, now, local_job_active);
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
                    apply_transcript_effect_event(&mut app, &mut session, &providers, effect);
                    redraw = true;
                }
            },
            hydrated = history_rx.recv(), if history_open => {
                history_open = false;
                startup_history_ready = true;
                if let Some((
                    hydrated,
                    hydrated_title,
                    hydrated_workflows,
                    workspace_dirty,
                    hyperlink_policy,
                    history_elapsed,
                    title_elapsed,
                )) = hydrated {
                    startup.mark_duration(startup::StartupPhase::HistoryHydrate, history_elapsed);
                    startup.mark_duration(startup::StartupPhase::Title, title_elapsed);
                    let current_draft = app.editor.text();
                    let has_live_chips = app.editor.chip_count() > 0;
                    if let Some(state) = hydrated.state {
                        if has_live_chips {
                            app.note(
                                block::NoticeLevel::Info,
                                "prompt history became ready after attachments were added; the live draft was preserved",
                            );
                        } else {
                            app.editor.restore_persisted(state.history, state.draft);
                            if !current_draft.is_empty() {
                                app.editor.replace_text(&current_draft);
                            }
                            persisted_revision = app.editor.persistence_revision();
                            persisted_history_len = app.editor.history_len();
                        }
                    }
                    if let Some(warning) = hydrated.warning {
                        app.note(block::NoticeLevel::Warn, warning);
                    }
                    history_writer = prompt_history::Writer::new(hydrated.store);
                    if hydrated_title != "New session" && !hydrated_title.trim().is_empty() {
                        app.session_name = hydrated_title;
                    }
                    if app.workflow_monitor.live_count() == 0 {
                        app.workflow_monitor = hydrated_workflows;
                    }
                    app.workspace_dirty = workspace_dirty;
                    app.hyperlink_policy = hyperlink_policy;
                    app.render_cache.clear();
                    app.live_markdown_layout = Default::default();
                    app.mark_transcript_changed();
                    redraw = true;
                }
                if startup_initial_finalized {
                    startup.flush();
                }
            },
            settled = provider_directory_rx.recv(), if provider_directory_open => {
                provider_directory_open = false;
                if let Some(settled) = settled {
                    providers = settled;
                    app.note(block::NoticeLevel::Info, "provider catalog ready");
                    redraw = true;
                }
            },
            result = input_rx.recv(), if input_open => match result {
                Some(Ok(terminal_input::ReadResult::Event(event))) => next_input = Some(event),
                Some(Ok(terminal_input::ReadResult::Probe(update))) => {
                    match update {
                        terminal_input::ProbeUpdate::KeyboardEnhancement => {
                            let _ = guard.enable_keyboard_enhancement();
                        }
                        terminal_input::ProbeUpdate::Background(background) => {
                            let probed = theme::Theme::detect_with(
                                environment.clone(),
                                Some(background),
                            );
                            app.adopt_detected_theme(probed);
                        }
                    }
                    redraw = true;
                }
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
            if !matches!(input_event, CEvent::Resize(_, _)) {
                redraw = true;
            }
            match input_event {
                CEvent::Resize(_, _) => {
                    resize_due = Some(
                        Instant::now()
                            + iteron_tunables::param_duration(
                                "cli.tui.driver_support.resize_debounce",
                                RESIZE_DEBOUNCE,
                            ),
                    );
                }
                CEvent::Paste(pasted) if app.transcript_viewer.is_open() => {
                    app.transcript_viewer.handle_paste(
                        &pasted,
                        &app.transcript,
                        app.transcript_revision,
                    );
                }
                CEvent::Paste(_) if app.workflows_panel.is_open() => {
                    app.workflows_panel
                        .finish_action("paste is disabled in the workflow panel; press n for a new prompt");
                }
                // A modal picker owns bracketed paste as well as physical keys. Consume a bounded,
                // sanitized query here before the generic composer/image path can mutate draft
                // text, cursor, or attachments.
                CEvent::Paste(pasted) if app.picker.is_some() => {
                    let _ = app.picker_paste(&pasted);
                }
                // Bracketed paste: insert the WHOLE pasted text (incl. newlines) into the editor
                // rather than letting each pasted newline submit a partial line (review HIGH).
                CEvent::Paste(pasted) => handle_composer_paste(&mut app, &repo, &pasted),
                CEvent::Mouse(m) if app.transcript_viewer.is_open() => match m.kind {
                    MouseEventKind::ScrollUp => app.transcript_viewer.scroll_up(3),
                    MouseEventKind::ScrollDown => app.transcript_viewer.scroll_down(3),
                    _ => {}
                },
                CEvent::Mouse(_) if app.workflows_panel.is_open() => {}
                // In app-mouse mode, wheel/trackpad input moves only this session's transcript;
                // prompt-history navigation remains a keyboard-only editor action. A left click
                // folds the transcript card under the pointer.
                CEvent::Mouse(m) if app.mouse_capture.is_captured() => match m.kind {
                    MouseEventKind::ScrollUp => app.scroll_up(3),
                    MouseEventKind::ScrollDown => app.scroll_down(3),
                    MouseEventKind::Down(MouseButton::Left) => {
                        if m.row >= app.view_top
                            && m.row < app.view_top.saturating_add(app.view_h)
                        {
                            let index = usize::from(m.row - app.view_top);
                            if let Some(&block_index) = app.row_map.get(index)
                                && block_index != usize::MAX
                            {
                                app.toggle_fold(block_index);
                            }
                        }
                    }
                    _ => {}
                },
                // A report can already be queued when Ctrl-T releases capture. Ignore it so native
                // selection mode cannot mutate transcript or composer state.
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

                    // Global even while a picker or approval owns ordinary keyboard input: Ctrl-T
                    // switches between application transcript scrolling and native drag selection
                    // without leaving the alternate-screen TUI.
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
                    if app.pending.is_some() {
                        if app.transcript_viewer.is_open() {
                            app.transcript_viewer.close();
                        }
                        if app.workflows_panel.is_open() {
                            app.workflows_panel.close();
                        }
                    }
                    let lifecycle_key =
                        ctrl && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('d'));
                    if app.workflows_panel.is_open() && !lifecycle_key {
                        let runs = workflow_panel_runs(&app);
                        if let Some(action) =
                            app.workflows_panel.key(k.code, k.modifiers, &runs)
                        {
                            queue_workflows_panel_action(
                                &mut app,
                                &session,
                                &mut transcript_effects,
                                &interrupt,
                                action,
                            );
                        }
                        continue;
                    }
                    if lifecycle_key && app.workflows_panel.is_open() {
                        app.workflows_panel.close();
                    }
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
                                session.rollout_path(),
                                &mut transcript_effects,
                                effect,
                            );
                        }
                        if !app.transcript_viewer.is_open() {
                            // Inline viewport cells may have been physically cleared/reflowed by a
                            // resize while the viewer was open. Invalidate Ratatui's retained
                            // frame before returning to the composer so unchanged prompt cells are
                            // emitted again instead of being mistaken for cells still on screen.
                            term.clear()?;
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
                    // capture. It is available during a run for the same reason a drop is: the
                    // capture lands as a chip on the draft, and a draft with chips is queued behind
                    // the turn rather than steered into it.
                    if k.code == KeyCode::Char('v') && ctrl {
                        app.note(
                            block::NoticeLevel::Info,
                            "clipboard image queued · you can keep typing",
                        );
                        queue_clipboard_image_effect(&mut app);
                        continue;
                    }

                    // Ctrl-D while active stops in-flight work immediately, checkpoints, and
                    // returns a resumable Drained outcome.
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
                    if app.recover_running_escape_prefixed_char(
                        k.code,
                        k.modifiers,
                        &repo,
                        active_keymap.mode() == keymap::Mode::Standard,
                        mapped_action.is_none(),
                    ) {
                        request_interrupt(&mut app, &session, &interrupt);
                        app.push(
                            bold(Color::Yellow),
                            "interrupting now…",
                        );
                        continue;
                    }

                    // An open picker OWNS the keyboard (C6): route the key to it, apply on accept
                    // (take-then-apply, C5), and fully consume — no fall-through to editor/history/mode.
                    if app.picker.is_some() {
                        let picker_event = app.picker_key_with_modifiers(k.code, k.modifiers);
                        maybe_prefetch_session_page(&mut app);
                        match picker_event {
                            Some(PickerEvent::Accept(PickAction::SetEffort(effort))) => queue_effort(
                                &mut app,
                                &session,
                                &mut transcript_effects,
                                &interrupt,
                                effort,
                            ),
                            Some(PickerEvent::Accept(PickAction::SetMode(mode))) => {
                                queue_permission_mode(
                                    &mut app,
                                    &session,
                                    &mut transcript_effects,
                                    &interrupt,
                                    mode,
                                )
                            }
                            Some(PickerEvent::Accept(PickAction::SetCap(capability, verdict))) => {
                                queue_permission_capability(
                                    &mut app,
                                    &session,
                                    &mut transcript_effects,
                                    &interrupt,
                                    capability,
                                    verdict,
                                )
                            }
                            Some(PickerEvent::Accept(PickAction::SetModel(selection))) => {
                                queue_model_selection(
                                    &mut app,
                                    &session,
                                    &providers,
                                    &mut transcript_effects,
                                    &interrupt,
                                    selection,
                                )
                            }
                            Some(PickerEvent::Accept(PickAction::InspectTunable(detail))) => {
                                show_tunable_detail(&mut app, detail)
                            }
                            Some(PickerEvent::Accept(PickAction::SetTheme(theme))) => {
                                apply_theme_selection(&mut app, theme)
                            }
                            Some(PickerEvent::Accept(PickAction::Info)) => {}
                            Some(PickerEvent::Accept(PickAction::AdoptRun(run_id))) => {
                                start_adopt_session(&mut app, &session, &providers, run_id)
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
                            request_interrupt(&mut app, &session, &interrupt);
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
                                        app.schedule_completion();
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
                                    app.schedule_completion();
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
                                app.schedule_completion();
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
                        app.schedule_completion();
                        continue;
                    }

                    let mut refresh = false;
                    match k.code {
                        KeyCode::Char('c') if ctrl => {
                            if app.running {
                                match running_ctrl_c_action(
                                    &mut app.ctrl_c_quit_deadline,
                                    Instant::now(),
                                    iteron_tunables::param_duration(
                                        "cli.tui.ctrl_c_quit_window",
                                        CTRL_C_QUIT_WINDOW,
                                    ),
                                ) {
                                    RunningCtrlCAction::InterruptAndArm => {
                                        if transcript_effects.is_active() {
                                            let _ = transcript_effects.cancel();
                                        }
                                        request_interrupt(&mut app, &session, &interrupt);
                                        app.push(
                                            bold(Color::Yellow),
                                            "interrupting now… (Ctrl-C again to exit)",
                                        );
                                    }
                                    RunningCtrlCAction::ForceQuit => {
                                        if transcript_effects.is_active() {
                                            let _ = transcript_effects.cancel();
                                        }
                                        if app.interrupting {
                                            force_cancel_turn(&mut app, &session);
                                        }
                                        app.force_quit_requested = true;
                                        app.quit = true;
                                        app.status = "shutting down…".into();
                                    }
                                }
                            } else if transcript_effects.is_active() {
                                let _ = transcript_effects.cancel();
                                app.note(
                                    block::NoticeLevel::Warn,
                                    "local transcript effect cancelled",
                                );
                            } else if app.editor.has_submission() {
                                app.editor.clear_recoverable();
                                app.completion = None;
                                app.resume_handoff = None;
                            } else {
                                app.force_quit_requested = app.workflow_monitor.live_count() > 0
                                    || !app.activities.is_empty();
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
                            queue_permission_mode(
                                &mut app,
                                &session,
                                &mut transcript_effects,
                                &interrupt,
                                next,
                            );
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
                                    if pending_slash_commands.len() < 8 {
                                        pending_slash_commands.push_back((cmd.to_owned(), None));
                                        app.status = format!("queued /{cmd}");
                                    } else {
                                        app.note(
                                            block::NoticeLevel::Warn,
                                            "command queue is full; draft restored",
                                        );
                                        app.editor.insert_str(&line);
                                    }
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
                        KeyCode::Esc if !app.running && transcript_effects.is_active() => {
                            let _ = transcript_effects.cancel();
                            app.note(block::NoticeLevel::Warn, "cancelling local effect…");
                        }
                        KeyCode::Esc if !app.running && app.session_adoption_job.is_some() => {
                            if let Some(job) = app.session_adoption_job.take() {
                                job.abort();
                            }
                            app.status = "idle · session loading cancelled".into();
                        }
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
                                    if pending_slash_commands.len() < 8 {
                                        pending_slash_commands
                                            .push_back((cmd.to_owned(), restore));
                                        app.status = format!("queued /{cmd}");
                                    } else {
                                        app.note(
                                            block::NoticeLevel::Warn,
                                            "command queue is full; draft restored",
                                        );
                                        app.editor.insert_str(&line);
                                    }
                                } else if !has_attachments
                                    && let Some(bash) = trimmed.strip_prefix('!')
                                {
                                    let _ = app.editor.take_submit();
                                    let (mode, rules) = (
                                        session.permission_mode(),
                                        session.permission_rules().clone(),
                                    );
                                    let request = transcript_effect::Request::Shell {
                                        workspace: repo.clone(),
                                        command: bash.trim().to_owned(),
                                        sensitive_env_names: sensitive_env_names.clone(),
                                        mode,
                                        rules,
                                    };
                                    if transcript_effects.start(request).is_ok() {
                                        app.note(
                                            block::NoticeLevel::Info,
                                            "shell running · Ctrl-C or Esc cancels it",
                                        );
                                    } else {
                                        app.note(
                                            block::NoticeLevel::Warn,
                                            "shell not started: another local effect is pending",
                                        );
                                        app.editor.insert_str(&trimmed);
                                    }
                                } else {
                                    // The operator may ask for multi-agent orchestration in the
                                    // prompt itself, not only through `/effort ultracode`. The
                                    // detector reads the DRAFT — what was typed — rather than the
                                    // expanded submission: pasted blocks are inert by design (see
                                    // `submit_prepared_composer`), and bytes the operator did not
                                    // write must never be able to escalate a turn.
                                    //
                                    // What this seam can and cannot do today: the request is
                                    // detected and said out loud, but the turn is NOT re-routed,
                                    // because there is no per-turn orchestration hook to set.
                                    // Orchestration is decided in the resident runtime from the
                                    // SESSION effort (`runtime.rs`: `let orchestrate =
                                    // allow_orchestration && self.effort_orchestration(self.effort)
                                    // == OrchestrationMode::Orchestrated && …`), and the only lever
                                    // the frontend holds is `app_server::Control::SetEffort`, which
                                    // moves the operator's persisted effort for every later turn
                                    // too — and would race the submission besides, since the
                                    // control channel and the SQ are separate. Closing this needs
                                    // one boolean carried with the submission and OR'd into that
                                    // predicate, in `app_server`/`runtime`.
                                    if crate::keyword_trigger::requests_orchestration(&trimmed) {
                                        let already = app.effort == Effort::Ultracode;
                                        app.note(
                                            block::NoticeLevel::Info,
                                            if already {
                                                "orchestration requested in the prompt · this \
                                                 session is already ultracode"
                                            } else {
                                                "orchestration requested in the prompt · this turn \
                                                 still runs at the session effort — `/effort \
                                                 ultracode` enables internal fan-out"
                                            },
                                        );
                                    }
                                    submit_composer(&mut app, &session, &mut notifier);
                                }
                            }
                        }
                        // Enter while running: STEER at the next turn-atomic safe point. Slash/shell
                        // input remains a
                        // post-run frontend action; it must not be injected as model prose.
                        KeyCode::Enter if app.running && !app.editor.is_empty() => {
                            // A draft carrying chips has exactly one honest destination. `Op::Steer`
                            // is text — the protocol is frozen, there is no image or file field on
                            // it — so steering this draft would mean sending the words and dropping
                            // the attachment the operator just watched land. The chips are taken out
                            // of the composer WITH the text, because `take_submit` clears the stores
                            // and anything left behind would ride the next, unrelated message.
                            if queue_bare_image_path(
                                &mut app,
                                &repo,
                                AttachmentFollowup::QueueRunningDraft,
                            ) {
                                continue;
                            }
                            if app.editor.chip_count() > 0 {
                                // Refusal (queue bound or byte ceiling) leaves the draft, its pasted
                                // blocks and its chips exactly where they are, with the reason in
                                // the transcript.
                                queue_draft_with_chips(&mut app);
                            } else {
                                let text = app.editor.take_submit();
                                match input_destination(app.running, app.interrupting, &text) {
                                    InputDestination::ImmediateCommand => {
                                        let command = slash_command_body(&text)
                                            .expect("the destination admitted a slash command");
                                        if pending_slash_commands.len() < 8 {
                                            pending_slash_commands
                                                .push_back((command.to_owned(), None));
                                            app.status = format!("queued /{command}");
                                        } else if let Err(text) = app.queue_after_turn(text) {
                                            app.editor.insert_str(&text);
                                        }
                                    }
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
                                            SubmissionAdmission::Reject => {
                                                app.editor.insert_str(&text)
                                            }
                                        }
                                    }
                                    InputDestination::StartTurn => unreachable!(
                                        "the running Enter branch cannot resolve to StartTurn"
                                    ),
                                }
                            }
                            app.completion = None;
                        }
                        // Codex/Claude-style explicit queue: Tab defers the text until this run ends.
                        KeyCode::Tab if app.running && !app.editor.is_empty() => {
                            if queue_bare_image_path(
                                &mut app,
                                &repo,
                                AttachmentFollowup::QueueRunningDraft,
                            ) {
                                continue;
                            }
                            if app.editor.chip_count() > 0 {
                                queue_draft_with_chips(&mut app);
                            } else {
                                let text = app.editor.take_submit();
                                if let Err(text) = app.queue_after_turn(text) {
                                    app.editor.insert_str(&text);
                                }
                            }
                            app.completion = None;
                        }
                        // Esc while running interrupts at the next safe point (like the leading agent).
                        KeyCode::Esc if app.running => {
                            if transcript_effects.is_active() {
                                let _ = transcript_effects.cancel();
                                cancel_local_effect_then_turn(
                                    &mut app,
                                    &session,
                                    &interrupt,
                                );
                            } else if app.interrupting {
                                force_cancel_turn(&mut app, &session);
                            } else {
                                let pending = app
                                    .steer_previews
                                    .len()
                                    .saturating_add(app.queued.len());
                                request_interrupt(&mut app, &session, &interrupt);
                                app.push(bold(Color::Yellow), if pending == 0 {
                                    "interrupting now… (Esc again for stronger cancellation)".into()
                                } else {
                                    format!(
                                        "interrupting now… {pending} pending submission(s) will send next"
                                    )
                                });
                            }
                        }
                        KeyCode::Char('?')
                            if !app.running && !app.editor.has_submission() && !menu_open =>
                        {
                            command_dispatch::show_help(&mut app);
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
                        // File/image discovery is deliberately not performed per key. Paste/drop
                        // and submit boundaries enqueue attachment work; typing stays pure memory.
                        app.schedule_completion();
                    }
                } // end CEvent::Key
                _ => {} // resize etc. -> next draw handles it
            }
        }

        if app.quit {
            break;
        }

        // Keep writes off the key path and bounded. A submitted prompt is scheduled immediately;
        // unsent drafts are coalesced every 32 mutations and always flushed on normal teardown.
        let revision = app.editor.persistence_revision();
        let history_len = app.editor.history_len();
        if history_len != persisted_history_len || revision.wrapping_sub(persisted_revision) >= 32 {
            if let Some(active_run) =
                prompt_history::source_run_from_rollout(session.rollout_path())
            {
                history_writer.schedule(app.editor.persistence_state(), active_run);
            }
            persisted_revision = revision;
            persisted_history_len = history_len;
        }
    }
    if let Some(job) = app.session_picker_job.take() {
        job.abort();
    }
    if let Some(job) = app.session_preview_job.take() {
        job.abort();
    }
    if let Some(job) = app.session_adoption_job.take() {
        job.abort();
    }
    if let Some(job) = app.workspace_command_job.take() {
        job.abort();
    }
    Ok(())
    }
    .await;
    startup.flush();

    // A repeated Ctrl-C is an emergency operator boundary. Restore the physical terminal before
    // any bounded cleanup so process/history durability work cannot look like a frozen UI. The
    // ordinary exit path still joins every local effect before restoration.
    let force_quit_requested = app.force_quit_requested;
    if force_quit_requested {
        let _ = term.show_cursor();
        restore_terminal(&guard.keyboard_restorer());
        let _ = transcript_effects.cancel();
    }
    let tui_result = if force_quit_requested {
        tui_result
    } else {
        transcript_effects.finish(tui_result).await
    };
    if termination_exit.is_none() {
        termination_exit = termination_rx.try_recv().ok();
    }
    let _ = term.show_cursor();
    let active_run = prompt_history::source_run_from_rollout(session.rollout_path());
    let history_flushed = if force_quit_requested {
        if let Some(active_run) = active_run {
            history_writer.schedule(app.editor.persistence_state(), active_run);
        }
        drop(history_writer);
        true
    } else if let Some(active_run) = active_run {
        history_writer.finish_bounded(app.editor.persistence_state(), active_run)
    } else {
        drop(history_writer);
        true
    };
    if let Some(exit_code) = termination_exit {
        drop(session);
        // A catchable termination still gives the server its shutdown: that is where a live
        // workflow run is cancelled and its terminal record written, and `process::exit` below
        // would otherwise kill the run's thread mid-flight and leave it listing as `running`
        // forever. Bounded, because a signal must not be answered by hanging — with no live run
        // this resolves immediately, so the wait exists exactly when it is earning something.
        let stopped = wait_for_server_shutdown(&mut server_task).await;
        restore_terminal(&guard.keyboard_restorer());
        if !history_flushed {
            eprintln!(
                "prompt history is still finalizing in the background; shutdown did not wait past 250ms"
            );
        }
        report_stopped_workflows(&stopped);
        std::process::exit(exit_code);
    }
    // Dropping the last SQ sender is how the server learns the session is over. Wait for it to run
    // out — the runtime's own shutdown (the final rollout flush, and cancelling any workflow run
    // the session still owned) happens in there, and returning before it completes would race the
    // process exit against the record on disk.
    drop(session);
    let stopped = if force_quit_requested {
        wait_for_forced_server_shutdown(&mut server_task).await
    } else {
        server_task.await.unwrap_or_default()
    };
    // The terminal modes go back to normal BEFORE this prints. A run the operator was never told
    // about is the failure this report exists to prevent, so cleanup and reporting stay ordered.
    drop(guard);
    if !history_flushed {
        eprintln!(
            "prompt history is still finalizing in the background; terminal shutdown did not wait past 250ms"
        );
    }
    report_stopped_workflows(&stopped);
    tui_result
}

#[derive(Clone)]
struct ClipboardCommand {
    program: OsString,
    args: Vec<String>,
}

#[cfg(target_os = "macos")]
fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![ClipboardCommand {
        program: "pngpaste".into(),
        args: vec!["-".into()],
    }]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![
        ClipboardCommand {
            program: "wl-paste".into(),
            args: vec!["--no-newline".into(), "--type".into(), "image/png".into()],
        },
        ClipboardCommand {
            program: "xclip".into(),
            args: vec![
                "-selection".into(),
                "clipboard".into(),
                "-t".into(),
                "image/png".into(),
                "-o".into(),
            ],
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
                args: vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Sta".into(),
                    "-Command".into(),
                    iteron_tunables::param_str("cli.tui.script", SCRIPT).into(),
                ],
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
    if value.as_encoded_bytes().len()
        > iteron_tunables::param_integer("cli.tui.max_clipboard_env_bytes", MAX_CLIPBOARD_ENV_BYTES)
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
    let mut buffer = vec![
        0_u16;
        iteron_tunables::param_integer(
            "cli.tui.max_windows_system_root_bytes",
            MAX_WINDOWS_SYSTEM_ROOT_BYTES
        ) + 1
    ];
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
        match tokio::time::timeout(
            iteron_tunables::param_duration(
                "cli.tui.clipboard_capture_timeout",
                CLIPBOARD_CAPTURE_TIMEOUT,
            ),
            capture,
        )
        .await
        {
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
        .map(|span| text_width(span.content.as_ref()))
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
        .unwrap_or(iteron_tunables::param_integer(
            "cli.tui.min_list_rows_on_overflow",
            MIN_LIST_ROWS_ON_OVERFLOW,
        ))
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

fn spans_width(spans: &[Span<'_>]) -> u16 {
    spans
        .iter()
        .map(|span| text_width(span.content.as_ref()))
        .fold(0u16, u16::saturating_add)
}

fn clip_spans(spans: Vec<Span<'static>>, width: u16) -> Vec<Span<'static>> {
    let mut remaining = width;
    let mut clipped = Vec::new();
    for span in spans {
        if remaining == 0 {
            break;
        }
        let span_width = text_width(span.content.as_ref());
        if span_width <= remaining {
            remaining = remaining.saturating_sub(span_width);
            clipped.push(span);
            continue;
        }
        clipped.push(Span::styled(
            clip_text(span.content.as_ref(), remaining),
            span.style,
        ));
        break;
    }
    clipped
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
    for grapheme in unicode_segmentation::UnicodeSegmentation::graphemes(text, true) {
        let cw = grapheme_width(grapheme);
        if used.saturating_add(cw) > budget {
            break;
        }
        out.push_str(grapheme);
        used = used.saturating_add(cw);
    }
    out.push('…');
    out
}

fn one_line_preview(text: &str, width: u16) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    clip_text(&collapsed, width)
}

/// Sample one cached status bit after first paint without ever retaining an unbounded `git status`
/// result. Reading a single porcelain byte includes tracked, staged, and untracked changes; the
/// child is stopped immediately once dirtiness is proven.
fn cached_workspace_dirty(repo: &std::path::Path) -> Option<bool> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut first = [0_u8; 1];
    let read = child.stdout.take()?.read(&mut first).ok()?;
    if read > 0 {
        let _ = child.kill();
    }
    let status = child.wait().ok()?;
    (read > 0 || status.success()).then_some(read > 0)
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

fn effort_status_accent(app: &App) -> status_line::Accent {
    match app.effort_application {
        Some(EffortApplication::Mapped { requested, sent }) if requested != sent => {
            status_line::Accent::Warning
        }
        Some(
            EffortApplication::BudgetBased { .. }
            | EffortApplication::ToggleOnly { .. }
            | EffortApplication::Unsupported { .. },
        ) => status_line::Accent::Warning,
        _ => status_line::Accent::Model,
    }
}

/// Build the factual portion of the footer through the public status-line contract. Runtime/UI
/// activity affordances remain separate groups, but model/tokens/cost/context/session have one
/// renderer and one unknown-value policy across the product.
fn canonical_statusline(app: &App) -> String {
    let tokens = app.last_turn_usage.map(|usage| {
        usage
            .input
            .saturating_add(usage.output)
            .saturating_add(usage.cache_creation)
            .saturating_add(usage.cache_read)
            .saturating_add(usage.thinking)
    });
    canonical_statusline_with_tokens(app, tokens)
}

fn canonical_statusline_with_tokens(app: &App, tokens: Option<u64>) -> String {
    use iteron_statusline::{Field, StatusLine, StatusSnapshot, Value};
    use std::sync::OnceLock;

    static LINE: OnceLock<StatusLine> = OnceLock::new();
    let line = LINE.get_or_init(|| {
        StatusLine::from_names(["model", "tokens", "cost", "context", "session"])
            .expect("the built-in status fields are closed and valid")
    });
    let model = route_label(app);
    let context = app
        .model_context_window
        .filter(|window| *window > 0)
        .map(|window| {
            let used = app
                .last_context
                .map(|context| context.total_tokens as u64)
                .or_else(|| app.last_turn_usage.map(request_input_tokens))
                .unwrap_or_default()
                .saturating_add(u64::from(app.reserved_output_tokens.unwrap_or_default()));
            let left = window.saturating_sub(used).saturating_mul(100) / window;
            u8::try_from(left.min(100)).unwrap_or(100)
        });
    let cost_milli = app
        .cost
        .usd()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|value| (value * 1_000.0).round() as u64);
    let snapshot = StatusSnapshot::new(
        app.transcript_revision,
        [
            (
                Field::Model,
                if model.is_empty() {
                    Value::Unknown
                } else {
                    Value::Text(model)
                },
            ),
            (Field::Tokens, tokens.map_or(Value::Unknown, Value::Count)),
            (
                Field::CostUsd,
                cost_milli.map_or(Value::Unknown, Value::Milli),
            ),
            (
                Field::ContextPercent,
                context.map_or(Value::Unknown, Value::Percent),
            ),
            (Field::SessionId, Value::Text(app.session_name.clone())),
        ],
    )
    .expect("the frontend supplies each closed status field once with its declared type");
    line.render_snapshot(&snapshot)
}

fn status_right_groups(app: &App, density: surface::Density) -> Vec<status_line::Group> {
    use status_line::{Accent, Group};

    // Mouse ownership yields first under width pressure; the hint row independently exposes the
    // Ctrl-T transition. The label always says who owns the next drag/wheel gesture.
    let mut groups = vec![Group::single(
        app.mouse_capture.status_label(),
        Accent::Metadata,
    )];
    if app.keymap_status != "keys:standard" {
        groups.push(Group::single(app.keymap_status.clone(), Accent::Mode));
    }
    // A live QuickJS workflow run announces itself only through its transcript card, and a
    // terminal too short for that card — the workflow region negotiates down to zero rows before
    // the status row gives up its last one (`surface::Surface::resolve`) — showed no sign that a
    // run was still going at all. This bit is that sign and nothing more: `⟳ n run(s)`, the
    // smallest thing that answers "is something still running?".
    //
    // It follows the keymap bit's rule — say it only when it is not the default — so an operator
    // with no workflow running never pays a column for it. It is placed here, immediately after
    // mouse ownership, because it is a redundancy: whenever the region itself is on screen the
    // region is the better answer, so under width pressure this yields ahead of context, mode,
    // the pending count, and the route/effort identity, which have no second place to be read.
    let live_runs = app.workflow_monitor.live_count();
    if live_runs > 0 {
        groups.push(Group::single(
            format!(
                "\u{27f3} {live_runs} run{}", // ⟳
                if live_runs == 1 { "" } else { "s" }
            ),
            Accent::Progress,
        ));
    }
    if density == surface::Density::Wide && app.turns > 0 {
        groups.push(Group::single(
            format!("turn {}", app.turns),
            Accent::Metadata,
        ));
    }
    if density == surface::Density::Wide && app.workspace_dirty == Some(true) {
        groups.push(Group::single("dirty", Accent::Warning));
    }
    if density == surface::Density::Wide
        && let Some(latency) = app.last_run_latency
    {
        groups.push(Group::single(
            format!("last {}", fmt_mmss(latency)),
            Accent::Metadata,
        ));
    }
    if app.running && !app.assistant_stream_authority.is_empty() {
        let approximate_tokens = app.assistant_stream_authority.chars().count().div_ceil(4);
        groups.push(Group::single(
            format!("~{approximate_tokens} tok"),
            Accent::Usage,
        ));
    }
    if density != surface::Density::Compact
        && let Some(usage) = app.last_turn_usage
    {
        groups.push(Group::single(
            format!("cache {:.0}%", usage.cache_hit_ratio() * 100.0),
            Accent::Usage,
        ));
    }
    if app.mode != PermissionMode::Default {
        groups.push(Group::single(app.mode.label(), Accent::Mode));
    }
    let pending = app.steer_previews.len().saturating_add(app.queued.len());
    if pending > 0 {
        groups.push(Group::single(
            format!("{pending} pending"),
            Accent::Progress,
        ));
    }
    // The canonical renderer owns model/tokens/cost/context/session and their unknown semantics.
    // Keep it near the high-priority end, while effort remains an Iteron-specific semantic beside
    // it rather than being smuggled into the model field.
    groups.push(Group::single(canonical_statusline(app), Accent::Metadata));
    // Ultracode is a harness MODE (internal fan-out orchestration), not just a thinking level, so
    // it announces itself once, the way the permission mode does. The adjacent effort segment
    // reports only the adapter's reasoning level/application.
    if app.effort == Effort::Ultracode {
        groups.push(Group::single("✦ ultracode", Accent::Mode));
    }
    let effort = effort_status_label(app);
    groups.push(Group::single(effort, effort_status_accent(app)));
    groups
}

#[cfg(test)]
fn status_right_bits(app: &App, density: surface::Density) -> Vec<String> {
    status_right_groups(app, density)
        .iter()
        .map(status_line::Group::text)
        .collect()
}

fn activity_label(event: &iteron_protocol::ActivityEvent) -> &'static str {
    use iteron_protocol::ActivityDetailCode as Detail;
    match event.detail_code {
        Some(Detail::Boot) => "starting Iteron",
        Some(Detail::Config) => "loading configuration",
        Some(Detail::AgentDiscovery) => "discovering agents",
        Some(Detail::PluginVerification) => "verifying plugins",
        Some(Detail::ProviderRefresh) => "refreshing providers",
        Some(Detail::FirstPaint) => "painting interface",
        Some(Detail::HistoryHydrate) => "loading prompt history",
        Some(Detail::SessionIndex) => "indexing sessions",
        Some(Detail::WorkflowRehydrate) => "restoring workflows",
        Some(Detail::SubmissionAdmission) => "admitting submission",
        Some(Detail::ContextAssembly) => "assembling context",
        Some(Detail::HookGate) => "running hook gate",
        Some(Detail::RoutePermit) => "waiting for route permit",
        Some(Detail::RequestSerialization) => "building request",
        Some(Detail::TransportConnect) => "connecting to provider",
        Some(Detail::RequestSent) => "request sent · waiting for provider",
        Some(Detail::WaitingFirstByte) => "request sent · waiting for first byte",
        Some(Detail::WaitingFirstToken) => "accepted · waiting for first token",
        Some(Detail::Reasoning) if event.kind.is_reasoning() => "thinking",
        Some(Detail::Reasoning) => "reasoning activity",
        Some(Detail::Responding) => "responding",
        Some(Detail::ToolProposed) => "tool proposed",
        Some(Detail::ToolHook) => "running tool hook",
        Some(Detail::ToolApproval) => "waiting for tool approval",
        Some(Detail::ToolQueued) => "tool queued",
        Some(Detail::ToolRunning) => "tool running",
        Some(Detail::ToolPostProcessing) => "processing tool result",
        Some(Detail::RetryBackoff) => "retry backoff",
        Some(Detail::RouteFailover) => "switching provider route",
        Some(Detail::Compaction) => "compacting context",
        Some(Detail::Verification) => "verifying result",
        Some(Detail::Checkpoint) => "writing checkpoint",
        Some(Detail::RecordCommit) => "committing run record",
        Some(Detail::StopHooks) => "running stop hooks",
        Some(Detail::WorkflowResultPersist) => "saving workflow result",
        Some(Detail::AnswerComplete) => "answer complete",
        Some(Detail::Finalizing) => "finalizing",
        Some(Detail::InputReady) => "input ready",
        None => match event.kind {
            iteron_protocol::ActivityKind::ProviderReasoning => "thinking",
            iteron_protocol::ActivityKind::ModelRequest => "model request",
            iteron_protocol::ActivityKind::Tool => "tool activity",
            iteron_protocol::ActivityKind::Workflow => "workflow activity",
            iteron_protocol::ActivityKind::Attachment => "attachment",
            iteron_protocol::ActivityKind::Completion => "completion",
            iteron_protocol::ActivityKind::HistoryHydration => "prompt history",
            iteron_protocol::ActivityKind::SessionIndex => "session index",
            iteron_protocol::ActivityKind::WorkflowHydration => "workflow restore",
            iteron_protocol::ActivityKind::TerminalProbe => "terminal probe",
            iteron_protocol::ActivityKind::Verification => "verification",
            iteron_protocol::ActivityKind::Persistence => "persistence",
            iteron_protocol::ActivityKind::Finalization => "finalizing",
            iteron_protocol::ActivityKind::Cancellation => "cancelling",
            iteron_protocol::ActivityKind::Startup => "starting",
        },
    }
}

fn visible_activity(app: &App) -> Option<(&PresentedActivity, Duration)> {
    if app.first_token_stall().is_some() {
        return None;
    }
    let activity = app
        .activities
        .values()
        .max_by_key(|activity| activity.event.updated_at_unix_ms)?;
    let elapsed = activity.observed_at.elapsed();
    (elapsed >= Duration::from_millis(250)).then_some((activity, elapsed))
}

fn render_status(f: &mut Frame, area: Rect, density: surface::Density, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let th = &app.theme;
    let muted = Style::default().fg(th.muted);
    let accent = Style::default().fg(th.accent).add_modifier(Modifier::BOLD);
    let success = Style::default().fg(th.success).add_modifier(Modifier::BOLD);
    let warn = Style::default().fg(th.warn).add_modifier(Modifier::BOLD);
    let error = Style::default().fg(th.error).add_modifier(Modifier::BOLD);

    let mut left = if app.draining {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("draining session", warn),
        ]
    } else if app.force_cancelling {
        vec![
            Span::styled("◆ ", error),
            Span::styled("stronger cancellation requested", error),
        ]
    } else if app.pending.is_some() {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("approval required", warn),
        ]
    } else if app.interrupting {
        vec![
            Span::styled("◆ ", warn),
            Span::styled("interrupt requested · stopping now", warn),
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
    } else if let Some((activity, elapsed)) = visible_activity(app) {
        let mut label = activity_label(&activity.event).to_owned();
        if elapsed >= Duration::from_secs(1) {
            label.push_str(&format!(" · {}", fmt_mmss(elapsed)));
        }
        if activity.event.limit > 1 {
            label.push_str(&format!(
                " · attempt {}/{}",
                activity.event.attempt, activity.event.limit
            ));
        }
        if let Some(progress) = activity.event.progress {
            if activity.event.detail_code == Some(iteron_protocol::ActivityDetailCode::ToolQueued) {
                label.push_str(&format!(
                    " · {}/{} permits",
                    progress.completed, progress.total
                ));
            } else {
                label.push_str(&format!(" · {}/{}", progress.completed, progress.total));
            }
        }
        if elapsed >= Duration::from_secs(2) {
            label.push_str(match activity.event.cancelability {
                iteron_protocol::ActivityCancelability::None => " · /status for remedy",
                _ => " · Esc to cancel",
            });
        }
        vec![
            Span::styled(
                format!("{} ", spinner()[app.spin % spinner().len()]),
                accent,
            ),
            Span::styled(label, accent),
        ]
    } else if let Some(stall) = app.first_token_stall() {
        // A dead connection and a slow prefill are the same picture for a full minute unless the
        // interface says which one it is looking at, and it knows: no token has arrived yet
        // (I-64). Both states still spin, because the request is genuinely still open.
        let style = match stall.state {
            FirstTokenState::Slow => accent,
            FirstTokenState::Stalled => warn,
        };
        vec![
            Span::styled(format!("{} ", spinner()[app.spin % spinner().len()]), style),
            Span::styled(stall.label(), style),
        ]
    } else if app.running {
        let phase = match app.status.trim() {
            "" | "running…" => "working",
            other => other,
        };
        let mut spans = vec![
            Span::styled(
                format!("{} ", spinner()[app.spin % spinner().len()]),
                accent,
            ),
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
        let label = if app.status.trim().is_empty() || app.status.trim() == "idle" {
            "ready".to_string()
        } else {
            app.status.clone()
        };
        let normalized = label.to_ascii_lowercase();
        let beacon = if normalized.contains("failed")
            || normalized.contains("error")
            || normalized.contains("stuck")
        {
            error
        } else if normalized.contains("budget") || normalized.contains("interrupt") {
            warn
        } else if label == "ready" || normalized.contains("success") {
            success
        } else {
            accent
        };
        vec![Span::styled("◆ ", beacon), Span::styled(label, muted)]
    };
    // Right-side metadata is progressively disclosed. When it does not fit, low-priority economics
    // disappear first; the route/pending state at the end survives and is clipped explicitly.
    let mut groups = status_right_groups(app, density);
    let left_budget = if groups.is_empty() {
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
    while groups.len() > 1 && status_line::width(&groups) > available {
        groups.remove(0);
    }
    let right = clip_spans(status_line::spans(&groups, th), available);
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
    let attachment_count = app.editor.chip_count();
    let is_bash = text.starts_with('!');
    let line_color = if app.pending.is_some() {
        app.theme.warn
    } else if !text.is_empty() || attachment_count > 0 || app.running {
        app.theme.accent
    } else {
        app.theme.border
    };
    // Blocking security decisions retain a complete, titled frame. Ordinary composition uses one
    // low-contrast input surface, one semantic left rail, and no redundant title or perimeter.
    let body = if app.pending.is_some() && area.width >= 3 && area.height >= 3 {
        let approval = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(line_color))
            .title(format!(
                " {} ",
                clip_text("Permission required", area.width.saturating_sub(4))
            ));
        let inner = approval.inner(area);
        f.render_widget(approval, area);
        inner
    } else if app.pending.is_some() {
        area
    } else {
        let surface_style = if app.theme.mono {
            Style::default()
        } else {
            Style::default().fg(app.theme.user_fg).bg(app.theme.user_bg)
        };
        f.render_widget(Block::default().style(surface_style), area);

        let rail_glyph = if app.theme.mono { "┃" } else { "▌" };
        let rail_style = Style::default()
            .fg(line_color)
            .bg(if app.theme.mono {
                Color::Reset
            } else {
                app.theme.user_bg
            })
            .add_modifier(Modifier::BOLD);
        let rail = (0..area.height)
            .map(|_| Line::from(Span::styled(rail_glyph, rail_style)))
            .collect::<Vec<_>>();
        f.render_widget(
            Paragraph::new(rail),
            Rect::new(area.x, area.y, area.width.min(1), area.height),
        );

        let left = u16::from(area.width >= 2) + u16::from(area.width >= 3);
        let vertical = u16::from(area.height >= 3);
        Rect::new(
            area.x.saturating_add(left),
            area.y.saturating_add(vertical),
            area.width.saturating_sub(left).saturating_sub(1),
            area.height.saturating_sub(vertical.saturating_mul(2)),
        )
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
        let mut workspace_spans = vec![Span::styled(
            "workspace ",
            Style::default().fg(app.theme.muted),
        )];
        workspace_spans.extend(crate::semantic_text::spans(
            &pending.workspace,
            crate::semantic_text::Tone::Muted,
            &app.theme,
        ));
        let workspace_line = Line::from(clip_spans(workspace_spans, body.width));
        let reason_line = Line::from(clip_spans(
            crate::semantic_text::spans(
                &pending.reason,
                crate::semantic_text::Tone::Muted,
                &app.theme,
            ),
            body.width,
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
        let chips = app.editor.chips();
        let chip_height = u16::try_from(chips.len())
            .unwrap_or(u16::MAX)
            .min(body.height);
        let chip_area = Rect::new(body.x, body.y, body.width, chip_height);
        let chip_lines = chips
            .iter()
            .enumerate()
            .map(|(index, chip)| {
                let mut text = match chip {
                    crate::editor::DraftChip::Image(attachment) => format!(
                        "▧ #{} {} · {}",
                        attachment.id(),
                        attachment.display_name(),
                        format_attachment_size(attachment.file_bytes())
                    ),
                    crate::editor::DraftChip::File(attachment) => format!(
                        "{} [{}] {} · {} · {}",
                        attachment.kind().glyph(),
                        attachment.kind().label(),
                        attachment.display_name(),
                        format_attachment_size(attachment.text_bytes()),
                        attachment.digest().get(..8).unwrap_or(attachment.digest())
                    ),
                    crate::editor::DraftChip::Paste(paste) => format!(
                        "▥ #{} held paste · {} line{} · {}",
                        paste.id(),
                        paste.lines() + 1,
                        if paste.lines() == 0 { "" } else { "s" },
                        format_attachment_size(paste.bytes())
                    ),
                };
                if index + 1 == chips.len() && body.width >= 36 {
                    text.push_str(" · alt+backspace removes last");
                }
                Line::from(clip_spans(
                    crate::semantic_text::spans(
                        &text,
                        crate::semantic_text::Tone::Muted,
                        &app.theme,
                    ),
                    chip_area.width,
                ))
            })
            .collect::<Vec<_>>();
        f.render_widget(Paragraph::new(chip_lines), chip_area);
        Rect::new(
            body.x,
            body.y.saturating_add(chip_height),
            body.width,
            body.height.saturating_sub(chip_height),
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
    if text.is_empty() {
        let placeholder = if app.running {
            "steer the current run"
        } else {
            "ask about this codebase or describe a task"
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
            spans.extend(crate::semantic_text::spans(
                item,
                crate::semantic_text::Tone::Muted,
                theme,
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
        match cached_input_destination(true, app.interrupting, app.editor.draft_shape()) {
            InputDestination::ImmediateCommand if density == surface::Density::Compact => {
                "enter control · ctrl+j newline · esc stop"
            }
            InputDestination::ImmediateCommand => {
                "enter runs this control now · ctrl+j newline · esc interrupt"
            }
            InputDestination::AfterTurn if density == surface::Density::Compact => {
                "enter queue · ctrl+j newline · esc stop"
            }
            InputDestination::AfterTurn => {
                "enter queues after this turn · ctrl+j newline · esc interrupt"
            }
            InputDestination::SteerCurrentRun if density == surface::Density::Compact => {
                "enter steer · tab queue · esc stop"
            }
            InputDestination::SteerCurrentRun => {
                "enter steer · tab queue · ctrl+j newline · esc interrupt"
            }
            InputDestination::StartTurn => unreachable!("the app is running"),
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
        app.cur_doc = Some(crate::markdown::MarkdownDoc {
            blocks: Vec::new(),
            source: None,
        });
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
    Live(usize),
    LiveAssistant,
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

#[allow(clippy::too_many_arguments)]
fn push_live_markdown_rows(
    layout: &live_markdown::LiveMarkdownLayout,
    theme: &theme::Theme,
    width: u16,
    running: bool,
    caret_on: bool,
    segment_start: usize,
    from: usize,
    to: usize,
    lines: &mut Vec<Line<'static>>,
    row_map: &mut Vec<usize>,
    hyperlinks: &mut Vec<crate::render::HyperlinkRegion>,
) {
    let last = layout.len().saturating_sub(1);
    for row in from..to {
        let Some(mut line) = layout.line(row, theme) else {
            continue;
        };
        if running && caret_on && row == last && crate::render::line_width(&line) < width {
            line.spans
                .push(Span::styled("▋", Style::default().fg(theme.role_assistant)));
        }
        lines.push(line);
        row_map.push(usize::MAX);
    }
    hyperlinks.extend(layout.visible_hyperlinks(from, to, segment_start));
}

/// The largest number of rows the workflow region may ask for on a frame this tall.
///
/// The region is pinned chrome, not the conversation. A fan of forty investigators renders a tree
/// far taller than any terminal, and `Surface::resolve` would hand it everything down to the
/// transcript's one-row floor — so the operator would be watching a workflow with no record of the
/// turn that launched it. Half the frame is the bound; the tree windows into it and reports what it
/// hid, which is a truthful summary rather than a silent clip.
///
/// A zero- or one-row frame yields zero: on a frame that small the composer and the fail-closed
/// decision surface outrank inspection chrome.
fn workflow_region_cap(frame_height: u16) -> u16 {
    if frame_height < 2 {
        return 0;
    }
    frame_height.div_ceil(2)
}

fn draw(f: &mut Frame, app: &mut App) {
    // Durable workflow inventory is fetched only when `/workflows` is opened. Rendering — including
    // the first frame — is a pure projection and never scans sidecars.
    // A newly arrived capability decision outranks optional inspection chrome. The viewer cannot
    // hide a fail-closed approval surface while the runtime is blocked on it.
    if app.pending.is_some() {
        if app.transcript_viewer.is_open() {
            app.transcript_viewer.close();
        }
        if app.workflows_panel.is_open() {
            app.workflows_panel.close();
        }
    }
    if app.workflows_panel.is_open() {
        let runs = workflow_panel_runs(app);
        workflows_panel::render(
            f,
            &mut app.workflows_panel,
            &runs,
            &app.session_name,
            &app.theme,
            app.spin,
        );
        return;
    }
    if app.transcript_viewer.is_open() {
        transcript_viewer::render(f, &mut app.transcript_viewer, &app.theme);
        return;
    }
    // The dock grows for multiline input, bounded to six editable rows. A blocking approval asks
    // for the full six-row decision surface; short terminals degrade through Surface::resolve.
    let n_input_rows = (app.editor.text().split('\n').count().clamp(1, 6) as u16)
        .saturating_add(u16::try_from(app.editor.chip_count()).unwrap_or(u16::MAX));
    let lane_rows = if app.pending.is_some() {
        0
    } else {
        u16::from(!app.steer_previews.is_empty()) + u16::from(!app.queued.is_empty())
    };
    // The status line is stable chrome below the composer, including on the fresh landing. Surface
    // geometry drops it only when a physically tiny frame cannot spare the row.
    let show_status = true;
    // The workflow region asks for its own height. A live script run's tree is drawn HERE, pinned
    // above the composer, and the transcript pass below skips that block, so the tree exists on
    // exactly one surface. Rows are built once and reused: the natural count is the request, and
    // the granted height windows the SAME rows (see `block::window_workflow_rows`). Every region
    // shares the stage's full-width grid (`surface::Surface::resolve`, asserted by
    // `product_widths_keep_one_full_width_body_grid`), so the frame width is the region's width.
    let workflow_rows = app.workflow_region_rows(f.area().width);
    let requested_workflow_rows = u16::try_from(workflow_rows.len())
        .unwrap_or(u16::MAX)
        .min(workflow_region_cap(f.area().height));
    let fresh_landing = !app.running
        && app.pending.is_none()
        && app.transcript.len() == 1
        && matches!(
            app.transcript.first().map(|block| &block.kind),
            Some(block::BlockKind::Welcome { .. })
        );
    let surface = if fresh_landing {
        let landing_width = f.area().width.min(surface::LANDING_MAX_WIDTH);
        let welcome_rows = match landing_width {
            0..=15 => 1,
            16..=27 => 2,
            _ => 6,
        };
        surface::Surface::resolve_landing(f.area(), n_input_rows, welcome_rows, show_status)
    } else {
        surface::Surface::resolve(
            f.area(),
            if app.pending.is_some() {
                6
            } else {
                n_input_rows
            },
            lane_rows,
            requested_workflow_rows,
            show_status,
            app.pending.is_some(),
        )
    };

    // Which block the transcript must NOT draw, because the region is drawing it. Decided from the
    // GRANTED height rather than the request: a frame too small to spare the region even one row
    // grants zero, and hiding the run from the transcript as well would leave a running workflow
    // rendered nowhere at all. On such a frame the run falls back into the conversation.
    let region_block = (surface.workflow.height > 0)
        .then(|| app.workflow_monitor.region_block())
        .flatten();

    // Reset the complete full-screen frame, then draw only semantic terminal primitives. There is
    // intentionally no desktop canvas, window fill, chrome strip, or card background.
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
    if !app.cur_text.trim().is_empty() {
        let App {
            live_markdown_layout,
            cur_doc,
            cur_doc_parse,
            cur_text,
            theme,
            theme_epoch,
            hyperlink_policy,
            ..
        } = app;
        live_markdown_layout.update(
            cur_doc
                .as_ref()
                .expect("non-empty streaming text has a parsed document"),
            cur_doc_parse,
            cur_text,
            live_markdown::LiveMarkdownRenderContext {
                width: inner_w,
                theme_epoch: *theme_epoch,
                theme,
                hyperlinks: hyperlink_policy,
            },
        );
    }
    // Rebuild retained block geometry only when its semantic key changes. Ordinary spinner and
    // streaming frames reuse the prefix sums below and locate their viewport with two binary
    // searches; they never walk all 1,200 retained blocks.
    let full_layout_rebuild =
        !app.transcript_layout
            .matches(inner_w, app.theme_epoch, region_block);
    let dirty_from = full_layout_rebuild
        .then_some(0)
        .or(app.transcript_dirty_from);
    if let Some(dirty_from) = dirty_from {
        let mut entries = Vec::new();
        let theme = &app.theme;
        let spin = app.spin;
        let hyperlink_policy = &app.hyperlink_policy;
        let render_cache = &mut app.render_cache;
        let mut previous: Option<&block::BlockKind> = app.transcript[..dirty_from]
            .iter()
            .rev()
            .find(|block| Some(block.id) != region_block)
            .map(|block| &block.kind);
        for (block_index, block) in app.transcript.iter().enumerate().skip(dirty_from) {
            if Some(block.id) == region_block {
                continue;
            }
            if let Some(previous) = previous {
                let gap = usize::from(block::gap_before(previous, &block.kind));
                if gap > 0 {
                    entries.push(transcript_layout::Entry::blank(gap, block_index));
                }
            }
            previous = Some(&block.kind);
            if block.cacheable() {
                if render_cache.get(&block.id).map(|(revision, _)| *revision)
                    != Some(block.revision)
                {
                    let rendered =
                        block.render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy);
                    render_cache.insert(block.id, (block.revision, rendered));
                }
                let rows = render_cache
                    .get(&block.id)
                    .map_or(0, |(_, rendered)| rendered.lines.len());
                entries.push(transcript_layout::Entry::cached(
                    block.id,
                    block_index,
                    rows,
                ));
            } else {
                let rows = block
                    .render_with_hyperlinks(inner_w, theme, spin, hyperlink_policy)
                    .lines
                    .len();
                entries.push(transcript_layout::Entry::live(block_index, rows));
            }
        }
        if full_layout_rebuild {
            app.transcript_layout
                .rebuild(inner_w, app.theme_epoch, region_block, entries);
        } else {
            app.transcript_layout.rebuild_suffix(dirty_from, entries);
        }
        app.transcript_dirty_from = None;
    }

    // The two in-flight projections are not retained transcript blocks. Their plan is bounded to
    // four entries (gap + thinking + gap + answer) and is appended after the indexed geometry.
    let mut live: Vec<crate::render::RenderedLines> = Vec::new();
    let mut tail_plan: Vec<(TranscriptRows, usize, usize)> = Vec::new();
    let retained_rows = app.transcript_layout.total_rows();
    let mut total_rows = retained_rows;
    {
        let theme = &app.theme;
        let spin = app.spin;
        if !app.cur_think.trim().is_empty() {
            if total_rows > 0 {
                tail_plan.push((TranscriptRows::Blank, 1, usize::MAX));
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
            tail_plan.push((TranscriptRows::Live(live.len()), count, usize::MAX));
            live.push(rendered);
            total_rows += count;
        }
        if !app.cur_text.trim().is_empty() {
            if total_rows > 0 {
                tail_plan.push((TranscriptRows::Blank, 1, usize::MAX));
                total_rows += 1;
            }
            let count = app.live_markdown_layout.len();
            tail_plan.push((TranscriptRows::LiveAssistant, count, usize::MAX));
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
    let retained_visible = app
        .transcript_layout
        .visible_range(first_row, last_row.min(retained_rows));
    for entry_index in retained_visible {
        let Some(entry) = app.transcript_layout.entry(entry_index).copied() else {
            continue;
        };
        let segment_start = app.transcript_layout.row_start(entry_index);
        let segment_end = segment_start.saturating_add(entry.rows);
        let from = first_row.max(segment_start) - segment_start;
        let to = last_row.min(segment_end) - segment_start;
        match entry.source {
            transcript_layout::Source::Blank => {
                for _ in from..to {
                    lines.push(Line::from(""));
                    row_map.push(usize::MAX);
                }
            }
            transcript_layout::Source::Cached(id) => {
                if let Some((_, rendered)) = app.render_cache.get(&id) {
                    push_viewport_rows(
                        rendered,
                        entry.block_index,
                        segment_start,
                        from,
                        to,
                        &mut lines,
                        &mut row_map,
                        &mut hyperlink_regions,
                    );
                }
            }
            transcript_layout::Source::LiveBlock(block_index) => {
                if let Some(block) = app.transcript.get(block_index) {
                    let rendered = block.render_with_hyperlinks(
                        inner_w,
                        &app.theme,
                        app.spin,
                        &app.hyperlink_policy,
                    );
                    push_viewport_rows(
                        &rendered,
                        entry.block_index,
                        segment_start,
                        from,
                        to.min(rendered.lines.len()),
                        &mut lines,
                        &mut row_map,
                        &mut hyperlink_regions,
                    );
                }
            }
        }
    }

    let mut cursor = retained_rows;
    for (rows, count, block_index) in &tail_plan {
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
            TranscriptRows::Live(index) => push_viewport_rows(
                &live[*index],
                *block_index,
                segment_start,
                from,
                to,
                &mut lines,
                &mut row_map,
                &mut hyperlink_regions,
            ),
            TranscriptRows::LiveAssistant => push_live_markdown_rows(
                &app.live_markdown_layout,
                &app.theme,
                inner_w,
                app.running,
                (app.spin / 4).is_multiple_of(2),
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
            // The track is a hairline BEHIND the thumb, so it must be the dimmer of the two.
            // `code_bg` is a background token — `Color::Reset` in the default theme — and using it
            // as a foreground painted the track brighter than the `muted` thumb.
            .thumb_style(Style::default().fg(app.theme.muted))
            .track_style(Style::default().fg(app.theme.border));
        f.render_stateful_widget(sb, surface.scrollbar, &mut sb_state);
    }

    // The workflow region, between the transcript and the queued/steer lanes. On every frame with
    // no live run the height is 0 and this paints nothing — the region is free until it is earned.
    // A granted height smaller than the tree is not a clip: `window_workflow_rows` keeps the totals
    // footer and states how many rows it hid above and below.
    if surface.workflow.height > 0 && !workflow_rows.is_empty() {
        let rows = block::window_workflow_rows(
            workflow_rows,
            usize::from(surface.workflow.height),
            &app.theme,
        );
        f.render_widget(Paragraph::new(rows), surface.workflow);
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
include!("tui/tests.rs");

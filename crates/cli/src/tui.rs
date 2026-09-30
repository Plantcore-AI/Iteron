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

mod driver;
pub(crate) use driver::{RunConfig, run};
mod frame_render;
use frame_render::{draw, ensure_stream_doc, route_label, workflow_region_cap};

mod session_client;
pub(crate) use session_client::Session;
mod picker;
use picker::{PickAction, PickItem, Picker, PickerEvent};
mod clipboard_image;
#[cfg(test)]
use clipboard_image::{
    clipboard_child_environment_with, windows_clipboard_environment_with,
    windows_clipboard_powershell_program,
};
mod popup_render;
pub(crate) use popup_render::clip_text;
use popup_render::{
    PopupRow, clip_spans, one_line_preview, popup_detail_lines, render_list_popup, spans_width,
};
mod status_render;
use status_render::{
    activity_label, canonical_statusline_with_tokens, render_lr_line, render_status,
};
#[cfg(test)]
use status_render::{canonical_statusline, status_right_bits, visible_activity};
mod composer_render;
use composer_render::{format_attachment_size, render_composer, render_pending_lanes};

#[cfg(test)]
use composer_render::approval_action_line;

mod activity_center;
mod advisory_maintenance;
mod app_init;
mod app_input_state;
mod app_picker;
mod app_transcript;
mod app_workflow;
mod app_workflow_legacy;
mod artifacts;
mod attachment_owner;
#[cfg(target_os = "linux")]
mod capability_fs;
mod clipboard;
mod command_dispatch;
mod command_surfaces;
mod completion_owner;
mod composer_images;
mod context_chips;
mod control_submission;
mod driver_support;
mod event_actions;
mod event_projection;
mod experiment_lab;
pub(crate) mod hyperlink;
mod inline_shell;
mod input_dispatch;
mod input_lanes;
use input_lanes::{PendingInput, SubmissionAdmission};
mod inventory;
mod jobs;
mod keyboard_enhancement;
mod live_markdown;
mod live_workflows;
mod mcp_command;
mod mcp_input;
mod mouse_capture;
mod notification;
mod ordinary_extensions;
mod persistent_agents;
mod picker_catalog;
mod picker_owner;
mod plugins;
mod product_projection;
mod session_adoption;
mod session_inspection;
mod session_management;
mod session_navigation;
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
mod turn_publication;
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
#[cfg(test)]
use attachment_owner::AttachmentEffectState;
use attachment_owner::{
    AttachmentEffectResult, AttachmentFollowup, AttachmentOrigin, AttachmentWorkerOutput,
};
use block::spinner;
use command_surfaces::{
    apply_transcript_effect_event, clear_conversation, ensure_real_workspace_dir,
    expand_selection_ancestors, export_transcript, initial_picker_selection, open_picker,
    open_transcript_viewer, open_tunables_picker, schedule_slash_export,
    schedule_transcript_viewer_effect, show_agent_catalog, transcript_export_body,
    write_new_synced,
};
#[cfg(test)]
use completion_owner::Completion;
use composer_images::{
    attach_bare_image_paths, dropped_image_reference, finish_attachment_effect,
    handle_composer_paste, queue_bare_image_path, queue_clipboard_image_effect,
    queue_context_diff_effect, queue_draft_with_chips, queue_file_path_effect,
    queue_image_path_effect,
};
use control_submission::{
    cancel_local_effect_then_turn, dispatch_slash_command, force_cancel_turn,
    report_stopped_workflows, request_drain, request_interrupt, show_side_answer, show_side_status,
    side_request_for, submit_operation, submit_queued_model_input, submit_turn,
    wait_for_forced_server_shutdown, wait_for_server_shutdown,
};
use crossterm::event::{
    Event as CEvent, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use driver_support::{
    CatchUp, FIRST_TOKEN_SPINNER_TICK, FRAME_COALESCE, InputThreadControl, MAX_BLOCKS,
    MAX_EQ_EVENTS_PER_TICK, MAX_PENDING_SUBMISSIONS, MAX_PENDING_TOOL_PROJECTIONS,
    MAX_SUBMISSION_BYTES, RESIZE_DEBOUNCE, SPINNER_TICK, TERMINAL_READ_SLICE, TOOL_REVEAL_DELAY,
    apply_vim_action, bold, byte_index, complete_path, dim, display_col, eq_tick_slots,
    external_edit_round_trip, fg, grapheme_width, item, kv, next_wake, parse_cap,
    reload_operator_keymap, service_input_control, update_keymap_status, wake_until,
};
pub(crate) use driver_support::{char_width, text_width};
use event_actions::{
    apply_server_event, apply_theme_selection, clear_last_turn_telemetry_from,
    model_retry_selection, queue_effort, queue_model_selection, queue_permission_capability,
    queue_permission_mode, queue_workflows_panel_action, show_tunable_detail,
};
use event_projection::{apply_event, apply_live_event};
use iteron_ctx::ContextEstimate;
use iteron_obs::CostState;
use iteron_protocol::{
    Capability, Effort, Op, PermissionMode, PermissionRules, ReasoningEffort, SubmissionId, Usage,
    Verdict,
};
use iteron_provider::EffortApplication;
use picker_catalog::{
    mode_picker_items, model_picker_items, permission_mode_row_value, permission_picker_items,
};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::{Frame, Terminal, TerminalOptions, Viewport};
use session_adoption::{
    MAX_ADOPTED_BLOCKS, adopted_transcript_blocks,
    format_resume_command, project_recorded_transcript, recorded_route, start_adopt_session,
    start_fresh_session,
};
#[cfg(test)]
use session_picker::{
    SessionPickerBacking, apply_session_page_result, load_session_page, session_picker_items,
    spawn_session_page_load,
};
use session_picker::{
    SessionPreview, handle_sessions_command, maybe_prefetch_session_page, open_session_picker,
    session_display_name,
};
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
use submission::{submit_composer, submit_prepared_composer, submit_staged_input};
use terminal_lifecycle::{TermGuard, restore_terminal};
#[cfg(test)]
use terminal_lifecycle::{
    replace_terminal_title_to, restore_terminal_after_panic_to, restore_terminal_title_to,
    set_terminal_title_to,
};
use workflow_panel_projection::workflow_panel_runs;

/// A pending capability approval the operator must answer (mode produced an `Ask` verdict).
struct Pending {
    id: SubmissionId,
    tool: String,
    cap: Capability,
    reason: String,
    arguments: serde_json::Value,
    workspace: String,
    /// An incomplete public prompt cannot authorize an effect, even if a legacy EQ copy was
    /// available. The App Server product projection is the visible approval authority.
    prompt_complete: bool,
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

struct PresentedActivity {
    event: iteron_protocol::ActivityEvent,
    observed_at: Instant,
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

struct PendingTurnReceipt {
    id: SubmissionId,
    editor_revision: u64,
    clear_composer: bool,
    display_text: String,
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
    /// Public controller snapshots used to target the exact observed incarnation/turn.
    persistent_agent_views: Vec<iteron_protocol::agent_control::AgentViewV1>,
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
    pending_mcp_input: Option<mcp_input::PendingMcpInput>,
    queued_mcp_inputs: VecDeque<app_server::McpInputPrompt>,
    status: String,
    /// The canonical current-version result object from the most recently terminalized run.
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
    text_scrubber: crate::machine_projection::StreamingScrubber,
    // live extended-thinking tail, shown dimmed while the model reasons (bounded).
    cur_think: String,
    thinking_scrubber: crate::machine_projection::StreamingScrubber,
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
    completions: completion_owner::CompletionOwner,
    pickers: picker_owner::PickerOwner,
    navigation: session_navigation::SessionNavigationOwner,
    /// At most one disk/process-heavy slash command. Completion carries bounded semantic actions;
    /// the key/render loop never awaits Git, record traversal, or workspace mutation.
    workspace_command_job: Option<tokio::task::JoinHandle<Vec<workspace_command::Action>>>,
    attachments: attachment_owner::AttachmentOwner,
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
    /// Bounded frontend input ownership, separate from editor and transcript presentation.
    input_lanes: input_lanes::InputLanes,
    pending_turn_receipt: Option<PendingTurnReceipt>,
    pending_approval_response: Option<SubmissionId>,
    /// Ordinary TUI content follows the same bounded Product V1 cursor as headless clients.
    /// Legacy EQ remains for richer tool cards, metrics, and compatibility on older servers.
    product_stream_active: bool,
    product_terminal_answer: Option<String>,
    product_turn_status: Option<String>,
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

fn fmt_mmss(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

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

#[cfg(test)]
include!("tui/tests.rs");

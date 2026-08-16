use super::*;
use unicode_segmentation::UnicodeSegmentation as _;
use unicode_width::UnicodeWidthStr as _;

/// Parse a capability class name for `/permissions` (snake_case, matching the serde rename).
pub(super) fn parse_cap(s: &str) -> Option<Capability> {
    match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "read_only" | "read" => Some(Capability::ReadOnly),
        "reversible_local" | "edit" | "edits" => Some(Capability::ReversibleLocal),
        "code_executing" | "code" | "bash" => Some(Capability::CodeExecuting),
        "trust_mutating" | "trust" => Some(Capability::TrustMutating),
        "irreversible_external" | "external" | "egress" => Some(Capability::IrreversibleExternal),
        _ => None,
    }
}

/// Terminal width from the same Unicode tables as the renderer. Hand-maintained ranges diverged on
/// emoji presentation selectors, newer CJK, ZWJ sequences, and combining marks.
pub(crate) fn char_width(c: char) -> u16 {
    if c == '\t' {
        return 1;
    }
    #[cfg(target_os = "macos")]
    if c == '⏺' {
        return 1;
    }
    u16::try_from(unicode_width::UnicodeWidthChar::width(c).unwrap_or(0)).unwrap_or(u16::MAX)
}

/// Width of one extended grapheme cluster. Terminal cells belong to graphemes, not Unicode scalar
/// values: summing the scalars in a family emoji, flag, or emoji+variation-selector over-counts it
/// and can place the cursor in the middle of what the terminal paints as one glyph.
pub(crate) fn grapheme_width(grapheme: &str) -> u16 {
    if grapheme == "\t" {
        return 1;
    }
    #[cfg(target_os = "macos")]
    if grapheme == "⏺" {
        return 1;
    }
    u16::try_from(grapheme.width()).unwrap_or(u16::MAX)
}

/// Terminal-cell width of a complete string, preserving extended grapheme clusters.
pub(crate) fn text_width(text: &str) -> u16 {
    text.graphemes(true)
        .map(grapheme_width)
        .fold(0u16, u16::saturating_add)
}

/// Display width of the first `n_chars` chars of `s`. Saturating so a pathologically long line
/// cannot overflow the u16 (review LOW).
pub(super) fn display_col(s: &str, n_chars: usize) -> u16 {
    let mut consumed_chars = 0usize;
    let mut columns = 0u16;
    for grapheme in s.graphemes(true) {
        let next = consumed_chars.saturating_add(grapheme.chars().count());
        // A stale/mouse-supplied scalar index can land inside a cluster. Use the cluster's leading
        // boundary instead of counting a partial ZWJ/flag/VS sequence that no terminal can draw.
        if next > n_chars {
            break;
        }
        consumed_chars = next;
        columns = columns.saturating_add(grapheme_width(grapheme));
    }
    columns
}

/// Convert a char index into a byte index within `s` (the editor counts chars; string slicing
/// needs bytes). Clamps to the string length.
pub(super) fn byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

/// Complete a relative path `partial` under `repo` for `@file` mentions. Returns up to 8 matching
/// entries (dirs get a trailing '/'), skipping hidden/build dirs. Bounded (invariant #1).
pub(super) fn complete_path(repo: &std::path::Path, partial: &str) -> Vec<String> {
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
    for (name, is_dir) in cached_completion_directory(&base) {
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
        out.push(format!("{dir_part}{name}{}", if is_dir { "/" } else { "" }));
        if out.len() >= 8 {
            break;
        }
    }
    out
}

const COMPLETION_DIRECTORY_CACHE_ENTRIES: usize = 32;
const COMPLETION_DIRECTORY_CACHE_TTL: Duration = Duration::from_secs(1);

fn completion_directory_cache_entries() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.completion_directory_cache_entries",
        COMPLETION_DIRECTORY_CACHE_ENTRIES,
    )
    .max(1)
}

fn completion_directory_cache_ttl() -> Duration {
    iteron_tunables::param_duration(
        "cli.tui.driver_support.completion_directory_cache_ttl",
        COMPLETION_DIRECTORY_CACHE_TTL,
    )
}
type CompletionDirectoryEntry = (std::path::PathBuf, Instant, Vec<(String, bool)>);

#[derive(Default)]
struct CompletionDirectoryCache {
    entries: VecDeque<CompletionDirectoryEntry>,
}

/// Cache the expensive read_dir/file-type/sort projection, not the typed prefix. Different
/// keystrokes in the same directory therefore filter one retained list while the bounded one-second
/// TTL still reveals newly-created files promptly.
fn cached_completion_directory(base: &std::path::Path) -> Vec<(String, bool)> {
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<CompletionDirectoryCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(CompletionDirectoryCache::default()));
    let now = Instant::now();
    if let Ok(mut cache) = cache.lock()
        && let Some(index) = cache.entries.iter().position(|(path, inserted, _)| {
            path == base
                && now.saturating_duration_since(*inserted) <= completion_directory_cache_ttl()
        })
        && let Some(entry) = cache.entries.remove(index)
    {
        let result = entry.2.clone();
        cache.entries.push_back(entry);
        return result;
    }

    let mut entries = std::fs::read_dir(base)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            entry.file_type().ok().map(|kind| (name, kind.is_dir()))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if let Ok(mut cache) = cache.lock() {
        cache.entries.retain(|(path, inserted, _)| {
            path != base
                && now.saturating_duration_since(*inserted) <= completion_directory_cache_ttl()
        });
        while cache.entries.len() >= completion_directory_cache_entries() {
            cache.entries.pop_front();
        }
        cache
            .entries
            .push_back((base.to_path_buf(), now, entries.clone()));
    }
    entries
}

pub(super) fn fg(c: Color) -> Style {
    Style::default().fg(c)
}
pub(super) fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}
pub(super) fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}
/// A Panel key-value row.
pub(super) fn kv(key: &str, value: &str) -> block::PanelRow {
    block::PanelRow::KeyValue {
        key: key.into(),
        value: value.into(),
    }
}
/// A Panel list-item row (label + dim hint). The leading `_glyph` arg is retained so the ~9 call
/// sites read cleanly, but the per-row glyph is no longer rendered — the icon zoo was deleted (TUI v3
/// §2), identity is the label + panel title (findings 5/6/15/16).
pub(super) fn item(_glyph: &str, label: &str, hint: &str) -> block::PanelRow {
    block::PanelRow::Item {
        label: label.into(),
        hint: hint.into(),
    }
}

/// Max transcript BLOCKS kept in memory (bounded, invariant #1): oldest blocks are evicted once
/// past the cap (each block's stored output was already bounded at the kernel seam, R5).
pub(super) const MAX_BLOCKS: usize = 1200;
/// Minimum active runtime before a model tool is shown as running in transcript history. Faster
/// completions are inserted once in their settled state, avoiding a two-frame flash.
pub(super) const TOOL_REVEAL_DELAY: Duration = Duration::from_millis(300);
/// Bound anti-flash bookkeeping independently from transcript retention. Reaching the cap reveals
/// the oldest running tool early; it never drops lifecycle evidence.
pub(super) const MAX_PENDING_TOOL_PROJECTIONS: usize = 64;
/// Bound both visible pending lanes and the number of outstanding operations this frontend can put
/// into the legacy runtime's channel before acknowledgement.
pub(super) const MAX_PENDING_SUBMISSIONS: usize = 32;
/// A single interactive follow-up is deliberately smaller than tool/model context limits. Oversize
/// drafts stay in the editor so the operator can trim or save them instead of losing text.
pub(super) const MAX_SUBMISSION_BYTES: usize = 64 * 1024;
/// A burst of streamed deltas costs ONE frame: the loop wakes on the first delta of the burst and
/// then holds the next draw for this long so the rest of the burst folds into it. Visible token
/// latency is bounded by this interval instead of by a fixed input-poll period.
pub(super) const FRAME_COALESCE: Duration = Duration::from_millis(16);
/// A permanently full 1024-slot EQ must yield every loop turn to draw, lifecycle signals, effect
/// completion, and operator input. Ordering is unchanged because the sole receiver still consumes
/// the same FIFO stream; only the per-turn batch size is bounded.
pub(super) const MAX_EQ_EVENTS_PER_TICK: usize = 64;

pub(super) fn eq_tick_slots() -> std::ops::Range<usize> {
    0..iteron_tunables::param_integer(
        "cli.tui.driver_support.max_eq_events_per_tick",
        MAX_EQ_EVENTS_PER_TICK,
    )
}

const CATCH_UP_ENTER_DEPTH: usize = 8;
const CATCH_UP_ENTER_AGE: Duration = Duration::from_millis(120);
const CATCH_UP_EXIT_DEPTH: usize = 2;
const CATCH_UP_EXIT_AGE: Duration = Duration::from_millis(40);
const CATCH_UP_HOLD: Duration = Duration::from_millis(250);
const CATCH_UP_SEVERE_DEPTH: usize = 64;
const CATCH_UP_SEVERE_AGE: Duration = Duration::from_millis(300);

fn catch_up_enter_depth() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.catch_up_enter_depth",
        CATCH_UP_ENTER_DEPTH,
    )
}

fn catch_up_enter_age() -> Duration {
    iteron_tunables::param_duration(
        "cli.tui.driver_support.catch_up_enter_age",
        CATCH_UP_ENTER_AGE,
    )
}

fn catch_up_exit_depth() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.catch_up_exit_depth",
        CATCH_UP_EXIT_DEPTH,
    )
}

fn catch_up_exit_age() -> Duration {
    iteron_tunables::param_duration(
        "cli.tui.driver_support.catch_up_exit_age",
        CATCH_UP_EXIT_AGE,
    )
}

fn catch_up_hold() -> Duration {
    iteron_tunables::param_duration("cli.tui.driver_support.catch_up_hold", CATCH_UP_HOLD)
}

fn catch_up_severe_depth() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.driver_support.catch_up_severe_depth",
        CATCH_UP_SEVERE_DEPTH,
    )
}

fn catch_up_severe_age() -> Duration {
    iteron_tunables::param_duration(
        "cli.tui.driver_support.catch_up_severe_age",
        CATCH_UP_SEVERE_AGE,
    )
}

/// Hysteretic stream catch-up controller. Depth reacts to bursts; oldest-observed age catches a
/// shallow but stalled queue. Exit and re-entry holds prevent frame cadence from oscillating.
#[derive(Debug, Default)]
pub(super) struct CatchUp {
    active: bool,
    severe: bool,
    exit_eligible_since: Option<Instant>,
    reentry_after: Option<Instant>,
}

impl CatchUp {
    pub(super) fn update(&mut self, depth: usize, age: Duration, now: Instant) {
        if self.active {
            self.severe = depth >= catch_up_severe_depth() || age >= catch_up_severe_age();
            if depth <= catch_up_exit_depth() && age <= catch_up_exit_age() {
                let eligible = *self.exit_eligible_since.get_or_insert(now);
                if now.saturating_duration_since(eligible) >= catch_up_hold() {
                    self.active = false;
                    self.severe = false;
                    self.exit_eligible_since = None;
                    self.reentry_after = Some(now + catch_up_hold());
                }
            } else {
                self.exit_eligible_since = None;
            }
            return;
        }
        let held = self.reentry_after.is_some_and(|until| now < until);
        if !held && (depth >= catch_up_enter_depth() || age >= catch_up_enter_age()) {
            self.active = true;
            self.severe = depth >= catch_up_severe_depth() || age >= catch_up_severe_age();
        }
    }

    pub(super) fn slots(&self) -> std::ops::Range<usize> {
        let baseline = eq_tick_slots().end;
        let limit = if self.severe {
            baseline.saturating_mul(4)
        } else if self.active {
            baseline.saturating_mul(2)
        } else {
            baseline
        };
        0..limit
    }

    #[cfg(test)]
    pub(super) fn state(&self) -> (bool, bool) {
        (self.active, self.severe)
    }
}
/// Spinner/elapsed animation cadence. The loop is event-driven, so the animation carries its own
/// clock rather than riding on an input poll's timeout.
pub(super) const SPINNER_TICK: Duration = Duration::from_millis(80);
pub(super) const FIRST_TOKEN_SPINNER_TICK: Duration = Duration::from_millis(50);
pub(super) const RESIZE_DEBOUNCE: Duration = Duration::from_millis(50);
/// How long the input thread blocks in one crossterm read before looking at its channel again. It
/// matches the idle cadence the loop used to poll at, so moving input off the loop costs no extra
/// wakeups on an idle session.
pub(super) const TERMINAL_READ_SLICE: Duration = Duration::from_secs(1);
/// Slack added to one read slice when waiting for the input thread to acknowledge a pause. The
/// reader can only observe Pause between reads, so the wait must outlast a full in-flight slice.
pub(super) const INPUT_PAUSE_ACK_SLACK: Duration = Duration::from_secs(1);

/// The next instant the render loop must wake up on its own account: a frame that is being held
/// back by the coalescing interval, the animation tick of a live run, or a queued tool card whose
/// anti-flash delay expires. `None` means "nothing is scheduled" — the loop then sleeps until real
/// input or a real runtime event arrives instead of burning a fixed poll.
pub(super) fn next_wake(
    frame_held: bool,
    next_frame_at: Instant,
    running: bool,
    last_spin: Instant,
    next_tool_reveal: Option<Instant>,
    spinner_tick: Duration,
) -> Option<Instant> {
    let mut wake: Option<Instant> = None;
    let mut at_earliest = |candidate: Instant| {
        wake = Some(wake.map_or(candidate, |current: Instant| current.min(candidate)));
    };
    if frame_held {
        at_earliest(next_frame_at);
    }
    if running {
        at_earliest(last_spin + spinner_tick);
    }
    if let Some(reveal) = next_tool_reveal {
        at_earliest(reveal);
    }
    wake
}

/// Sleep until `deadline`, or forever when nothing is scheduled.
pub(super) async fn wake_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

pub(super) enum InputThreadControl {
    Pause(std::sync::mpsc::SyncSender<()>),
    Resume,
}

fn try_input_control(
    sender: &std::sync::mpsc::SyncSender<InputThreadControl>,
    command: InputThreadControl,
) -> Result<(), String> {
    sender.try_send(command).map_err(|error| match error {
        std::sync::mpsc::TrySendError::Full(_) => {
            "terminal input control queue is busy; retry the action".to_owned()
        }
        std::sync::mpsc::TrySendError::Disconnected(_) => {
            "terminal input reader is no longer available".to_owned()
        }
    })
}

pub(super) fn service_input_control(
    receiver: &std::sync::mpsc::Receiver<InputThreadControl>,
) -> bool {
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

pub(super) fn update_keymap_status(app: &mut App, keymap: &keymap::Keymap, vim: &keymap::Vim) {
    app.keymap_status = match (keymap.mode(), vim.state()) {
        (keymap::Mode::Standard, _) if keymap.is_custom() => "keys:custom",
        (keymap::Mode::Standard, _) => "keys:standard",
        (keymap::Mode::Vim, keymap::VimState::Insert) => "vim:insert",
        (keymap::Mode::Vim, keymap::VimState::Normal) => "vim:normal",
        (keymap::Mode::Vim, keymap::VimState::Visual) => "vim:visual",
    }
    .into();
}

pub(super) fn apply_vim_action(app: &mut App, action: keymap::VimAction) {
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

pub(super) fn reload_operator_keymap(
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

pub(super) async fn external_edit_round_trip<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    guard: &mut TermGuard,
    input_control: &std::sync::mpsc::SyncSender<InputThreadControl>,
    workspace: &Path,
    configured: Option<Vec<String>>,
    draft: &str,
    sensitive_env_names: &[String],
) -> Result<Result<String, String>, String> {
    let (acknowledge, acknowledged) = std::sync::mpsc::sync_channel(0);
    try_input_control(input_control, InputThreadControl::Pause(acknowledge))?;
    if acknowledged
        .recv_timeout(
            iteron_tunables::param_duration(
                "cli.tui.driver_support.terminal_read_slice",
                TERMINAL_READ_SLICE,
            ) + iteron_tunables::param_duration(
                "cli.tui.driver_support.input_pause_ack_slack",
                INPUT_PAUSE_ACK_SLACK,
            ),
        )
        .is_err()
    {
        // The reader may observe Pause after this timeout. Queue Resume before returning so it
        // cannot become stranded in the pause loop with exclusive ownership of stdin.
        let _ = try_input_control(input_control, InputThreadControl::Resume);
        return Ok(Err("terminal input reader did not pause in time".to_owned()));
    }

    let desired_mouse = match guard.suspend_for_external_editor() {
        Ok(state) => state,
        Err(error) => {
            let _ = try_input_control(input_control, InputThreadControl::Resume);
            return Err(format!(
                "could not suspend the Iteron terminal for editing: {error}"
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
        .map_err(|error| format!("could not restore the Iteron terminal after editing: {error}"));
    let _ = try_input_control(input_control, InputThreadControl::Resume);
    resumed?;
    term.clear()
        .map_err(|error| format!("could not repaint after external editing: {error}"))?;
    Ok(edited)
}

#[cfg(test)]
mod input_control_tests {
    use super::*;

    #[test]
    fn bounded_input_control_refuses_immediately_when_full() {
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        try_input_control(&sender, InputThreadControl::Resume).unwrap();
        assert_eq!(
            try_input_control(&sender, InputThreadControl::Resume).unwrap_err(),
            "terminal input control queue is busy; retry the action"
        );
    }
}

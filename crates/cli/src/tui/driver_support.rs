use super::*;

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
pub(super) fn display_col(s: &str, n_chars: usize) -> u16 {
    s.chars()
        .take(n_chars)
        .map(char_width)
        .fold(0u16, |a, w| a.saturating_add(w))
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
/// Spinner/elapsed animation cadence. The loop is event-driven, so the animation carries its own
/// clock rather than riding on an input poll's timeout.
pub(super) const SPINNER_TICK: Duration = Duration::from_millis(100);
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
) -> Option<Instant> {
    let mut wake: Option<Instant> = None;
    let mut at_earliest = |candidate: Instant| {
        wake = Some(wake.map_or(candidate, |current: Instant| current.min(candidate)));
    };
    if frame_held {
        at_earliest(next_frame_at);
    }
    if running {
        at_earliest(
            last_spin
                + iteron_tunables::param_duration(
                    "cli.tui.driver_support.spinner_tick",
                    SPINNER_TICK,
                ),
        );
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

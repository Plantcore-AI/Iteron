//! The structured semantic transcript (ADR-015 §2/§3). The transcript is a `Vec<Block>` of typed,
//! self-rendering blocks — not a flat line log. Each block renders to ALREADY-WRAPPED rows at a given
//! width (reusing `wrap_spans`), so the concatenation feeds the unchanged exact scroll math and the
//! pre-wrap→scroll-unit invariant is preserved. Every block carries a monotonic `u64` id so a late
//! `ToolEnd` mutates its ORIGINATING card by id, never by a `Vec` position that eviction would shift
//! (R2).

mod links;
mod workflow_run;

#[cfg(test)]
use workflow_run::WorkflowRunAgent;
pub use workflow_run::WorkflowRunCard;
pub(crate) use workflow_run::{render_workflow_run, window_workflow_rows};

use crate::markdown::{MarkdownDoc, render_doc, render_doc_with_hyperlinks};
use crate::render::{RenderedLines, line_width, wrap_spans};
use crate::theme::Theme;
use crate::tui::hyperlink::Policy as HyperlinkPolicy;
use iteron_protocol::{DiffTag, FileDiff};
use iteron_workflow::events::{self, ProgressEvent, WorkflowState};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::time::{Duration, Instant};

/// Key-column width for a panel with no `KeyValue` rows at all. Zero, so a panel of plain lines
/// gets no phantom indent.
const EMPTY_KEY_COLUMN_WIDTH: usize = 0;
/// Line number assumed when a hunk header carries no range. The `from_replacement` header
/// (`@@ {path} @@`) has none, and its change is numbered sequentially from the top of the file.
const HUNK_DEFAULT_START_LINE: u32 = 1;

/// The spinner, shared by tool cards and the status line (unified — was duplicated at two different
/// frame counts against the same counter, a latent drift bug). These are Claude Code's OWN macOS
/// frames (`· ✢ ✳ ✶ ✻ ✽`) — every glyph is a guaranteed width-1 dingbat (TUI v3 §2).
pub const SPINNER: [&str; 6] = ["·", "✢", "✳", "✶", "✻", "✽"];

pub fn spinner() -> &'static [&'static str] {
    iteron_tunables::param_str_list("cli.block.spinner", &SPINNER)
}

/// Claude Code's braille-dot activity spinner (WORKFLOW-REPLICATION-DESIGN.md §3.3), advanced every
/// ~80ms. Drives the live phase→agent tree's running indicators (the QuickJS `iteron-workflow` runtime,
/// distinct from the native ultracode `SPINNER` above). Every frame is a guaranteed width-1 glyph.
pub const BRAILLE_SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn braille_spinner() -> &'static [&'static str] {
    iteron_tunables::param_str_list("cli.block.braille_spinner", &BRAILLE_SPINNER)
}

/// The primary machine-line marker (TUI v3 §1/§2). Claude Code ships `⏺` (U+23FA) on macOS and falls
/// back to `●` (U+25CF) elsewhere — precisely because `⏺` has emoji-presentation (double-width) on
/// some non-mac terminals, which is the 乱码/overlap bug. Replicate the exact platform switch so the
/// marker is always the width `char_width` reports (1).
pub fn primary_marker() -> &'static str {
    if cfg!(target_os = "macos") {
        "⏺"
    } else {
        "●"
    }
}

/// The literal result/nested connector Claude Code uses: two spaces, `⎿` (U+23BF), two spaces. Nested
/// content therefore begins at column 5 (TUI v3 §1). `char_width('⎿') == 1`, so this is exactly 5 cells.
pub const CONNECTOR: &str = "  ⎿  ";

/// Status lives on the one primary marker. Settled work deliberately recedes; only live work and
/// failures hold a strong color, keeping a long transcript calm and easy to scan.
fn tool_marker_color(card: &ToolCard, theme: &Theme) -> Color {
    let bad_exit = card.exit_code.is_some_and(|c| c != 0);
    if card.status == ToolStatus::Running {
        theme.accent
    } else if card.status == ToolStatus::Err || bad_exit {
        theme.error
    } else {
        theme.faint
    }
}

/// Notice severity is encoded once, on its marker. Informational notices recede; confirmations and
/// exceptional states retain their semantic state color.
fn notice_color(level: NoticeLevel, theme: &Theme) -> Color {
    match level {
        NoticeLevel::Ok => theme.success,
        NoticeLevel::Info => theme.faint,
        NoticeLevel::Warn => theme.warn,
        NoticeLevel::Err => theme.error,
    }
}

/// Render a single horizontal-rule row at `width` — glyph `─`, colored `faint`, spanning the FULL
/// width (findings 8: a stubby left-aligned 60-cell rule read as an accidental underline; a full-width
/// hairline reads as a real separator). Markdown `---` renders through this single primitive.
pub fn rule_line(width: u16, theme: &Theme) -> Vec<Line<'static>> {
    vec![Line::from(Span::styled(
        "─".repeat(width as usize),
        Style::default().fg(theme.faint),
    ))]
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToolStatus {
    Running,
    Ok,
    Err,
}

/// A single tool invocation, rendered as one coherent card (glyph · verb · args · status · elapsed),
/// mutated in place when its `ToolEnd` arrives.
#[derive(Clone)]
pub struct ToolCard {
    pub name: String,
    pub args: serde_json::Value,
    pub status: ToolStatus,
    pub output: String,
    pub diff: Option<FileDiff>,
    /// Exit code (bash) — colors the card ✗/red on a non-zero exit WITHOUT flipping is_error (C9).
    pub exit_code: Option<i32>,
    pub started: Instant,
    pub elapsed: Option<Duration>,
    pub open: bool,
}

/// The severity of a one-line harness notice, driving its gutter color + glyph (ADR-015 R7.e / C3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoticeLevel {
    Ok,
    Info,
    Warn,
    Err,
}

/// User-facing lifecycle of one workflow card. This is a frontend projection of the kernel's
/// id-correlated events, not an execution engine hidden in the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowStatus {
    Planning,
    Exploring,
    Synthesizing,
    Writing,
    Direct,
    Done,
    Degraded,
    BudgetExhausted,
    Stuck,
    Failed,
    Stopped,
}

impl WorkflowStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Done
                | Self::Degraded
                | Self::BudgetExhausted
                | Self::Stuck
                | Self::Failed
                | Self::Stopped
        )
    }
}

/// State of a declared read-only investigator. The fan is bounded-concurrent, so SEVERAL may be
/// `Running` at once; the live tree renders one row per task so no concurrent investigator is
/// hidden behind another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowTaskStatus {
    Queued,
    Running,
    Done,
    Failed,
    Interrupted,
    SkippedBudget,
    NotStarted,
    Unknown,
}

#[derive(Clone)]
pub struct WorkflowTaskCard {
    pub id: usize,
    pub label: String,
    pub status: WorkflowTaskStatus,
    pub started: Option<Instant>,
    pub elapsed: Option<Duration>,
    pub turns: u32,
    pub tokens: u64,
    pub tool_calls: u64,
    pub turn_budget: u32,
    pub sub_run: Option<String>,
    pub activity: Option<String>,
    pub summary_preview: Option<String>,
    pub error_preview: Option<String>,
}

/// One workflow occupies one transcript block and mutates in place for its whole lifetime. That
/// prevents a multi-agent run from becoming a noisy line log and gives mouse/Ctrl-O one fold target.
#[derive(Clone)]
pub struct WorkflowCard {
    pub run_id: String,
    pub name: String,
    pub class: String,
    pub status: WorkflowStatus,
    pub tasks: Vec<WorkflowTaskCard>,
    pub dropped: usize,
    pub duplicates_removed: usize,
    pub invalid_removed: usize,
    pub execution_mode: crate::runtime::WorkflowExecutionModeUi,
    pub fan_turn_budget: u32,
    pub writer_turn_reserve: u32,
    pub fan_wall_secs: u64,
    pub writer_wall_reserve_secs: u64,
    pub started: Instant,
    pub elapsed: Option<Duration>,
    pub reason: Option<String>,
    pub provider_attempts: u32,
    pub turns: u32,
    pub tokens: u64,
    pub tool_calls: u64,
    pub failed_tasks: u32,
    pub skipped_tasks: u32,
    pub open: bool,
}

// ---------------------------------------------------------------------------------------------

/// A typed row inside a `Panel` (structured command output). NO free-styled-text row — that would be
/// `Log` in disguise (C7). Command output uses these three shapes only.
#[derive(Clone)]
pub enum PanelRow {
    /// An aligned `key   value` pair (/status, /context, /cost).
    KeyValue { key: String, value: String },
    /// A list row: label + a dim right-hand hint (/help, /sessions, /agents, /skills, …). No per-row
    /// glyph — the icon zoo was deleted (TUI v3 §2); identity is the label, like the tool line.
    Item { label: String, hint: String },
    /// A dim sub-note (a caption / "… N more" / a hint line).
    Note(String),
}

#[derive(Clone)]
pub enum BlockKind {
    User(String),
    Assistant(MarkdownDoc),
    Thinking {
        text: String,
        open: bool,
    },
    Tool(ToolCard),
    /// A live, id-correlated workflow/agent tree (ultracode today; generic workflow vocabulary).
    Workflow(WorkflowCard),
    /// The live QuickJS `iteron-workflow` phase→agent tree (design §3.3), fed by `ProgressEvent`s.
    /// Interactive `WorkflowRunUiEvent`s drive it: `App::workflow_run_started` pushes the card,
    /// then progress and finished events mutate it in place.
    WorkflowRun(WorkflowRunCard),
    /// A one-line harness hint / confirmation (its level sets color + glyph).
    Notice {
        level: NoticeLevel,
        text: String,
    },
    /// A multi-line failure with a title + collapsible detail (reserve for the kernel-run failure).
    Error {
        title: String,
        detail: String,
        open: bool,
    },
    /// A standalone code diff (/diff, git_diff) — the same card an edit tool embeds.
    Diff(FileDiff),
    /// A titled card of typed rows — the structured home for ALL multi-line command output. Replaces
    /// the rejected `Log` plain-text escape hatch (R7.e). Rows are bounded at build (C4). The
    /// per-panel icon is gone (TUI v3 §2 deleted the 13 panel icons); the title carries identity.
    Panel {
        title: String,
        rows: Vec<PanelRow>,
    },
    /// The one-time terminal-native iteron pet landing. It is ordinary scrollable transcript content,
    /// not persistent chrome, a window, or a full-screen splash.
    Welcome {
        tagline: String,
    },
}

/// A transcript block with a stable monotonic id (R2).
#[derive(Clone)]
pub struct Block {
    pub id: u64,
    /// Monotonic presentation revision. Stable blocks can be cached; folds bump this value.
    pub revision: u64,
    pub kind: BlockKind,
}

impl Block {
    pub fn new(id: u64, kind: BlockKind) -> Self {
        Block {
            id,
            revision: 0,
            kind,
        }
    }

    pub fn touch(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    pub fn cacheable(&self) -> bool {
        match &self.kind {
            BlockKind::Tool(card) => card.status != ToolStatus::Running,
            BlockKind::Workflow(card) => card.status.is_terminal(),
            BlockKind::WorkflowRun(card) => card.finished,
            _ => true,
        }
    }

    /// Plain-text rendering for `/export` (the tool output here is already secret-scrubbed at the
    /// kernel seam, so the export inherits R1's redaction).
    pub fn to_text(&self) -> String {
        match &self.kind {
            BlockKind::User(t) => format!("### you\n{t}\n"),
            BlockKind::Assistant(doc) => format!("### iteron\n{}", doc.to_text()),
            BlockKind::Thinking { text, .. } => format!("<thinking>\n{text}\n</thinking>\n"),
            BlockKind::Tool(c) => {
                let mut s = format!("$ {} {}\n", c.name, humanize_args(&c.name, &c.args));
                if !c.output.trim().is_empty() {
                    s.push_str(&c.output);
                    s.push('\n');
                }
                s
            }
            BlockKind::Workflow(card) => {
                let mut s = format!(
                    "## {} workflow {} ({}, {})\n",
                    card.name,
                    card.run_id,
                    card.class,
                    workflow_status_label(card.status)
                );
                for task in &card.tasks {
                    s.push_str(&format!(
                        "- [{}] {} — {}",
                        task.id + 1,
                        task.label,
                        workflow_task_status_label(task.status)
                    ));
                    if task.status != WorkflowTaskStatus::Queued {
                        s.push_str(&format!(
                            " ({} turns, {} tokens, {} tools)",
                            task.turns, task.tokens, task.tool_calls
                        ));
                    }
                    s.push('\n');
                    if let Some(summary) = &task.summary_preview {
                        s.push_str(&format!("  evidence: {summary}\n"));
                    }
                    if let Some(error) = &task.error_preview {
                        s.push_str(&format!("  reason: {error}\n"));
                    }
                }
                if card.dropped > 0 {
                    s.push_str(&format!(
                        "- {} tasks omitted by the fan limit\n",
                        card.dropped
                    ));
                }
                s
            }
            BlockKind::WorkflowRun(card) => {
                let mut s = format!("## workflow \"{}\" ({})\n", card.name, card.run_id);
                for phase in &card.phases {
                    s.push_str(&format!("### {} ({})\n", phase.title, phase.index));
                }
                for agent in &card.agents {
                    let state = match agent.state {
                        WorkflowState::Queued => "queued",
                        WorkflowState::Running => "running",
                        WorkflowState::Done => "done",
                        WorkflowState::Error => "error",
                        WorkflowState::Skipped => "skipped",
                    };
                    s.push_str(&format!(
                        "- #{} {} — {} ({} tok, {} tools, {})\n",
                        agent.index,
                        agent.label,
                        state,
                        events::fmt_count(agent.tokens),
                        agent.tool_calls,
                        events::fmt_duration(agent.duration_ms)
                    ));
                    if let Some(error) = &agent.error {
                        s.push_str(&format!("  reason: {error}\n"));
                    }
                }
                s
            }
            BlockKind::Notice { text, .. } => format!("[{text}]\n"),
            BlockKind::Error { title, detail, .. } => format!("[error] {title}\n{detail}\n"),
            BlockKind::Diff(d) => {
                let mut s = format!("--- {} (+{} -{})\n", d.path, d.adds, d.dels);
                for h in &d.hunks {
                    for l in &h.lines {
                        let m = match l.tag {
                            DiffTag::Add => '+',
                            DiffTag::Del => '-',
                            DiffTag::Ctx => ' ',
                        };
                        s.push(m);
                        s.push_str(&l.text);
                        s.push('\n');
                    }
                }
                s
            }
            BlockKind::Welcome { tagline } => format!("start here — {tagline}\n"),
            BlockKind::Panel { title, rows, .. } => {
                let mut s = format!("## {title}\n");
                for r in rows {
                    match r {
                        PanelRow::KeyValue { key, value } => {
                            s.push_str(&format!("- {key}: {value}\n"))
                        }
                        PanelRow::Item { label, hint } => {
                            s.push_str(&format!("- {label}"));
                            if !hint.is_empty() {
                                s.push_str(&format!("  ({hint})"));
                            }
                            s.push('\n');
                        }
                        PanelRow::Note(t) => s.push_str(&format!("  {t}\n")),
                    }
                }
                s
            }
        }
    }

    /// Render the block to already-wrapped display rows at `width`, with semantic transcript cues.
    /// `spin` animates a running tool's spinner; fenced code is syntax-highlighted internally (R6).
    pub fn render(&self, width: u16, theme: &Theme, spin: usize) -> Vec<Line<'static>> {
        match &self.kind {
            BlockKind::User(text) => {
                if width == 0 {
                    return vec![Line::default()];
                }
                // A submitted prompt is one quiet full-width gray band with vertical breathing
                // space, following the history-cell treatment used by the reference coding agents.
                // Mono keeps the same ownership surface through reverse video without inventing a
                // color. Assistant prose remains open, so history is distinguishable at a glance.
                let surface = if theme.mono {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default().fg(theme.user_fg).bg(theme.user_bg)
                };
                let breathing = Line::from(Span::styled(" ".repeat(width as usize), surface));
                if width < 3 {
                    let marker: String = "› ".chars().take(width as usize).collect();
                    let marker_style = surface.patch(
                        Style::default()
                            .fg(theme.role_user)
                            .add_modifier(Modifier::BOLD),
                    );
                    return vec![
                        breathing.clone(),
                        Line::from(Span::styled(marker, marker_style)),
                        breathing,
                    ];
                }
                let content = vec![Span::styled(
                    text.clone(),
                    Style::default().fg(theme.user_fg),
                )];
                let mut rows = marker_wrap(
                    "› ",
                    Style::default()
                        .fg(theme.role_user)
                        .add_modifier(Modifier::BOLD),
                    &content,
                    width.saturating_sub(1), // Codex-style one-cell right breathing margin
                );
                for row in &mut rows {
                    let used = line_width(row);
                    if used < width {
                        row.spans
                            .push(Span::styled(" ".repeat((width - used) as usize), surface));
                    }
                    for span in &mut row.spans {
                        span.style = surface.patch(span.style);
                    }
                }
                rows.insert(0, breathing.clone());
                rows.push(breathing);
                rows
            }
            BlockKind::Assistant(doc) => render_assistant_doc(doc, width, theme),
            // Machine activity uses the same marker + connector tree as the reference coding agents.
            // A second full-height rail duplicated status and made every event look equally heavy.
            BlockKind::Thinking { text, open } => render_thinking(text, *open, width, theme),
            BlockKind::Tool(card) => render_tool(card, width, theme, spin),
            BlockKind::Workflow(card) => render_workflow(card, width, theme, spin),
            BlockKind::WorkflowRun(card) => render_workflow_run(card, width, theme, spin),
            BlockKind::Notice { level, text } => render_notice(*level, text, width, theme),
            BlockKind::Error {
                title,
                detail,
                open,
            } => render_error(title, detail, *open, width, theme),
            BlockKind::Diff(d) => render_diff(d, width, theme),
            BlockKind::Panel { title, rows, .. } => render_panel(title, rows, width, theme),
            BlockKind::Welcome { tagline } => render_welcome(tagline, width, theme),
        }
    }

    /// TUI rendering with OSC 8 regions kept as non-printing metadata. Assistant Markdown carries
    /// its parsed link spans; typed tool/file/diff surfaces are annotated only after ordinary
    /// rendering, so capability never changes their visible bytes or cell geometry.
    pub(crate) fn render_with_hyperlinks(
        &self,
        width: u16,
        theme: &Theme,
        spin: usize,
        hyperlinks: &HyperlinkPolicy,
    ) -> RenderedLines {
        match &self.kind {
            BlockKind::Assistant(doc) => {
                render_assistant_doc_with_hyperlinks(doc, width, theme, hyperlinks)
            }
            _ => links::annotate(&self.kind, self.render(width, theme, spin), hyperlinks),
        }
    }
}

/// Render both settled and streaming assistant prose with one compact bullet. User prompts retain
/// their `›` surface; the two shapes keep input/output obvious without repeated product-name labels.
pub(crate) fn render_assistant_doc(
    doc: &MarkdownDoc,
    width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if width
        < iteron_tunables::param_integer("cli.block.render_assistant_doc.gutter", 2_u16)
            .saturating_add(1)
    {
        return render_doc(doc, width, theme);
    }
    render_doc(
        doc,
        width.saturating_sub(iteron_tunables::param_integer(
            "cli.block.render_assistant_doc.gutter",
            2_u16,
        )),
        theme,
    )
    .into_iter()
    .enumerate()
    .map(|(index, mut row)| {
        let mut spans = vec![Span::styled(
            if index == 0 { "● " } else { "  " },
            if index == 0 {
                Style::default().fg(theme.role_assistant)
            } else {
                Style::default()
            },
        )];
        spans.append(&mut row.spans);
        Line::from(spans)
    })
    .collect()
}

pub(crate) fn render_assistant_doc_with_hyperlinks(
    doc: &MarkdownDoc,
    width: u16,
    theme: &Theme,
    hyperlinks: &HyperlinkPolicy,
) -> RenderedLines {
    let gutter = assistant_gutter(width);
    if gutter == 0 {
        return render_doc_with_hyperlinks(doc, width, theme, hyperlinks);
    }
    let mut rendered =
        render_doc_with_hyperlinks(doc, width.saturating_sub(gutter), theme, hyperlinks);
    rendered.shift_columns(gutter);
    for (index, row) in rendered.lines.iter_mut().enumerate() {
        let mut spans = vec![Span::styled(
            if index == 0 { "● " } else { "  " },
            if index == 0 {
                Style::default().fg(theme.role_assistant)
            } else {
                Style::default()
            },
        )];
        spans.append(&mut row.spans);
        *row = Line::from(spans);
    }
    rendered
}

/// Width reserved by the assistant marker. Streaming and settled renderers share this exact
/// decision so switching a live answer to its terminal block never changes wrapping geometry.
pub(crate) fn assistant_gutter(width: u16) -> u16 {
    let gutter = iteron_tunables::param_integer(
        "cli.block.render_assistant_doc_with_hyperlinks.gutter",
        2_u16,
    );
    if width >= gutter.saturating_add(1) {
        gutter
    } else {
        0
    }
}

/// How many blank rows to place before `next`, given the `prev` block. Adjacent tool cards / notices
/// tighten to 0; a real conversational turn boundary (user or assistant after tool activity) breathes.
pub fn gap_before(prev: &BlockKind, next: &BlockKind) -> u16 {
    use BlockKind::*;
    let prev_toolish = matches!(
        prev,
        Tool(_) | Workflow(_) | WorkflowRun(_) | Diff(_) | Notice { .. }
    );
    let next_toolish = matches!(
        next,
        Tool(_) | Workflow(_) | WorkflowRun(_) | Diff(_) | Notice { .. }
    );
    // consecutive tool activity / notices stay tight
    if prev_toolish && next_toolish {
        return 0;
    }
    // User history owns a tinted breathing row above and below, so one external row is enough.
    // An assistant answer following dense tool activity still gets the larger voice-change gap.
    if matches!(next, Assistant(_)) && prev_toolish {
        return 2;
    }
    1
}

/// Wrap `content` at `width - marker` and prepend a leading `marker` on the FIRST row, aligning every
/// continuation under the content column with matching spaces (R3: the composed row stays ≤ `width`).
/// This is the ONE primitive for a marked line (`⏺ …`, `> …`, `✻ …`, panel header).
fn marker_wrap(
    marker: &str,
    marker_style: Style,
    content: &[Span],
    width: u16,
) -> Vec<Line<'static>> {
    let mw = marker.chars().map(crate::tui::char_width).sum::<u16>();
    let rows = wrap_spans(content, width.saturating_sub(mw));
    let indent = " ".repeat(mw as usize);
    rows.into_iter()
        .enumerate()
        .map(|(i, mut l)| {
            let mut sp = vec![if i == 0 {
                Span::styled(marker.to_string(), marker_style)
            } else {
                Span::raw(indent.clone())
            }];
            sp.append(&mut l.spans);
            Line::from(sp)
        })
        .collect()
}

/// Wrap `content` at `width - indent` and prepend a plain `indent` (spaces) to EVERY row. Used to keep
/// nested body/continuation rows aligned under the connector column (col 5) or a panel row (col 2).
fn indent_wrap(indent: &str, content: &[Span], width: u16) -> Vec<Line<'static>> {
    let iw = indent.chars().map(crate::tui::char_width).sum::<u16>();
    let rows = wrap_spans(content, width.saturating_sub(iw));
    rows.into_iter()
        .map(|mut l| {
            let mut sp = vec![Span::raw(indent.to_string())];
            sp.append(&mut l.spans);
            Line::from(sp)
        })
        .collect()
}

/// Render one or more logical result/nested lines under a machine line: the FIRST rendered row leads
/// with the literal `"  ⎿  "` connector (faint), every later row aligns at col 5. Each logical line
/// wraps within `width` (TUI v3 §1 — Claude Code's connector tree).
fn connector_lines(lines: &[Vec<Span>], width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let iw = iteron_tunables::param_str("cli.block.connector", CONNECTOR)
        .chars()
        .map(crate::tui::char_width)
        .sum::<u16>();
    let indent = " ".repeat(iw as usize);
    for (li, spans) in lines.iter().enumerate() {
        // width measured via char_width (not byte .len()) — one shared width table everywhere (findings 9).
        let rows = wrap_spans(spans, width.saturating_sub(iw));
        for (ri, mut r) in rows.into_iter().enumerate() {
            let lead = if li == 0 && ri == 0 {
                // The `⎿` connector is `muted`, NOT `faint`: it anchors the result line, the most
                // important line of a settled tool run, so it must stay scannable rather than dimmer
                // than the body preview (findings 2).
                Span::styled(
                    iteron_tunables::param_str("cli.block.connector", CONNECTOR).to_string(),
                    Style::default().fg(theme.muted),
                )
            } else {
                Span::raw(indent.clone())
            };
            let mut sp = vec![lead];
            sp.append(&mut r.spans);
            out.push(Line::from(sp));
        }
    }
    out
}

/// `1 file` / `3 files` — real pluralization, never `file(s)` (TUI v3 §10).
pub(crate) fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

fn render_notice(level: NoticeLevel, text: &str, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    // A harness notice is a primary machine line: the ⏺/● marker's COLOR carries the level (no second
    // dingbat — TUI v3 §2 deleted ✓·!✗). The body is calm
    // fg/muted, red only for an error.
    let color = notice_color(level, theme);
    let tone = match level {
        NoticeLevel::Info => crate::semantic_text::Tone::Muted,
        NoticeLevel::Err => crate::semantic_text::Tone::Error,
        _ => crate::semantic_text::Tone::Body,
    };
    // Wrap each LOGICAL line separately. `wrap_spans` breaks rows on display width only, and
    // `char_width('\n')` is 0, so a newline inside a notice occupied no cell and produced no row
    // break: a multi-line notice (streamed process output, most of all) rendered as one run-on
    // line with its own line endings silently eaten.
    let marker = format!("{} ", primary_marker());
    let marker_width = marker.chars().map(crate::tui::char_width).sum::<u16>();
    let indent = " ".repeat(marker_width as usize);
    let body_width = width.saturating_sub(marker_width);
    let mut out: Vec<Line<'static>> = Vec::new();
    for logical in text.split('\n') {
        let content = crate::semantic_text::spans(logical, tone, theme);
        // An empty logical line still yields one row, which is what preserves blank lines.
        for row in wrap_spans(&content, body_width) {
            let lead = if out.is_empty() {
                Span::styled(marker.clone(), Style::default().fg(color))
            } else {
                Span::raw(indent.clone())
            };
            let mut spans = vec![lead];
            spans.extend(row.spans);
            out.push(Line::from(spans));
        }
    }
    out
}

pub(crate) fn workflow_status_label(status: WorkflowStatus) -> &'static str {
    match status {
        WorkflowStatus::Planning => "planning",
        WorkflowStatus::Exploring => "exploring",
        WorkflowStatus::Synthesizing => "synthesizing",
        WorkflowStatus::Writing => "writing",
        WorkflowStatus::Direct => "single-agent",
        WorkflowStatus::Done => "done",
        WorkflowStatus::Degraded => "partial",
        WorkflowStatus::BudgetExhausted => "budget exhausted",
        WorkflowStatus::Stuck => "stuck",
        WorkflowStatus::Failed => "failed",
        WorkflowStatus::Stopped => "stopped",
    }
}

fn workflow_task_status_label(status: WorkflowTaskStatus) -> &'static str {
    match status {
        WorkflowTaskStatus::Queued => "queued",
        WorkflowTaskStatus::Running => "running",
        WorkflowTaskStatus::Done => "done",
        WorkflowTaskStatus::Failed => "failed",
        WorkflowTaskStatus::Interrupted => "interrupted",
        WorkflowTaskStatus::SkippedBudget => "budget-skipped",
        WorkflowTaskStatus::NotStarted => "not started",
        WorkflowTaskStatus::Unknown => "status unknown",
    }
}

fn workflow_marker_color(card: &WorkflowCard, theme: &Theme) -> Color {
    match card.status {
        WorkflowStatus::Done => theme.faint,
        WorkflowStatus::Degraded
        | WorkflowStatus::BudgetExhausted
        | WorkflowStatus::Stuck
        | WorkflowStatus::Stopped => theme.warn,
        WorkflowStatus::Failed => theme.error,
        _ => theme.accent,
    }
}

fn compact_count(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

/// Compact Claude-style activity tree. The task words remain the visual anchor; state and metrics
/// recede, while failure retains the strongest color. Rows are real declared tasks, not inferred
/// from streamed prose, so the tree remains deterministic and exportable.
fn render_workflow(
    card: &WorkflowCard,
    width: u16,
    theme: &Theme,
    spin: usize,
) -> Vec<Line<'static>> {
    let running = !card.status.is_terminal();
    let marker = if running {
        format!("{} ", spinner()[spin % spinner().len()])
    } else {
        format!("{} ", primary_marker())
    };
    let done = card
        .tasks
        .iter()
        .filter(|task| task.status == WorkflowTaskStatus::Done)
        .count();
    let settled = card
        .tasks
        .iter()
        .filter(|task| task.status != WorkflowTaskStatus::Queued)
        .filter(|task| task.status != WorkflowTaskStatus::Running)
        .count();
    let mut head = vec![Span::styled(
        title_case(&card.name),
        Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
    )];
    head.push(Span::styled(
        format!(" · {}", workflow_status_label(card.status)),
        Style::default().fg(workflow_marker_color(card, theme)),
    ));
    if !card.tasks.is_empty()
        && card.status.is_terminal()
        && (card.failed_tasks > 0 || card.skipped_tasks > 0)
    {
        head.push(Span::styled(
            format!(
                " · {done} done · {} failed · {} skipped",
                card.failed_tasks, card.skipped_tasks
            ),
            Style::default().fg(theme.muted),
        ));
    } else if !card.tasks.is_empty() {
        head.push(Span::styled(
            format!(" · {done}/{}", card.tasks.len()),
            Style::default().fg(theme.muted),
        ));
    } else if width >= 60 {
        head.push(Span::styled(
            format!(" · {}", card.class),
            Style::default().fg(theme.muted),
        ));
    }
    let elapsed = card.elapsed.unwrap_or_else(|| card.started.elapsed());
    if width >= 60 {
        head.push(Span::styled(
            format!(" · {}", fmt_dur(elapsed)),
            Style::default().fg(theme.muted),
        ));
    }
    let observed_tokens = if card.tokens > 0 {
        card.tokens
    } else {
        card.tasks.iter().map(|task| task.tokens).sum()
    };
    let observed_tools = if card.tool_calls > 0 {
        card.tool_calls
    } else {
        card.tasks.iter().map(|task| task.tool_calls).sum()
    };
    if width >= 100 && observed_tokens > 0 {
        head.push(Span::styled(
            format!(
                " · {} tok · {} tools",
                compact_count(observed_tokens),
                observed_tools
            ),
            Style::default().fg(theme.muted),
        ));
    }
    let mut out = marker_wrap(
        &marker,
        Style::default()
            .fg(workflow_marker_color(card, theme))
            .add_modifier(Modifier::BOLD),
        &head,
        width,
    );

    if !card.open {
        return out;
    }

    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    if let Some(reason) = &card.reason {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled(
                reason.clone(),
                Style::default().fg(if matches!(card.status, WorkflowStatus::Failed) {
                    theme.error
                } else {
                    theme.warn
                }),
            ),
        ]);
    }
    if card.tasks.is_empty() {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled("single-agent route", Style::default().fg(theme.fg)),
            Span::styled(
                format!(" · {}", workflow_status_label(card.status)),
                Style::default().fg(theme.muted),
            ),
        ]);
    } else {
        if width >= 80
            && running
            && card.execution_mode != crate::runtime::WorkflowExecutionModeUi::Direct
        {
            let posture = match card.execution_mode {
                crate::runtime::WorkflowExecutionModeUi::Concurrent => "concurrent",
                _ => "sequential",
            };
            rows.push(vec![
                Span::styled("│  ", Style::default().fg(theme.faint)),
                Span::styled("RESERVE  ", Style::default().fg(theme.faint)),
                Span::styled(
                    format!(
                        "{} fan / {} writer turns · {posture}",
                        card.fan_turn_budget, card.writer_turn_reserve
                    ),
                    Style::default().fg(theme.muted),
                ),
            ]);
        }

        // One row per declared task, running rows included: the fan is bounded-concurrent, so
        // several investigators are live at once and each needs its own animated arm. Collapsing
        // them into a single "NOW" line made three of four concurrent workers disappear.
        for (index, task) in card.tasks.iter().enumerate() {
            let last = index + 1 == card.tasks.len()
                && card.dropped == 0
                && card.duplicates_removed == 0
                && card.invalid_removed == 0;
            let branch = if last { "└─ " } else { "├─ " };
            let (glyph, color) = match task.status {
                WorkflowTaskStatus::Queued => ("○", theme.faint),
                WorkflowTaskStatus::Running => (spinner()[spin % spinner().len()], theme.accent),
                WorkflowTaskStatus::Done => ("✓", theme.success),
                WorkflowTaskStatus::Failed => ("×", theme.error),
                WorkflowTaskStatus::Interrupted => ("■", theme.warn),
                WorkflowTaskStatus::SkippedBudget => ("–", theme.warn),
                WorkflowTaskStatus::NotStarted => ("○", theme.faint),
                WorkflowTaskStatus::Unknown => ("?", theme.warn),
            };
            let mut row = vec![
                Span::styled(branch.to_string(), Style::default().fg(theme.faint)),
                Span::styled(format!("{glyph} "), Style::default().fg(color)),
                Span::styled(
                    task.label.clone(),
                    Style::default().fg(if task.status == WorkflowTaskStatus::Queued {
                        theme.muted
                    } else {
                        theme.fg
                    }),
                ),
                Span::styled(
                    format!(" · {}", workflow_task_status_label(task.status)),
                    Style::default().fg(color),
                ),
            ];
            // A running row carries its own live tool line; that context used to exist only on the
            // single NOW line, so it was lost for every investigator but the first.
            if task.status == WorkflowTaskStatus::Running
                && let Some(activity) = &task.activity
            {
                row.push(Span::styled(
                    format!(" · {activity}"),
                    Style::default().fg(theme.muted),
                ));
            }
            // A still-running task has no settled `elapsed`; its clock runs from `started`.
            let elapsed = task
                .elapsed
                .or_else(|| task.started.map(|started| started.elapsed()))
                .unwrap_or_default();
            if width >= 100 && task.status != WorkflowTaskStatus::Queued {
                row.push(Span::styled(
                    format!(
                        " · {} turns · {} tok · {} tools · {}",
                        task.turns,
                        compact_count(task.tokens),
                        task.tool_calls,
                        fmt_dur(elapsed)
                    ),
                    Style::default().fg(theme.muted),
                ));
            } else if width >= 60 && task.status != WorkflowTaskStatus::Queued {
                row.push(Span::styled(
                    format!(" · {}", fmt_dur(elapsed)),
                    Style::default().fg(theme.muted),
                ));
            }
            if width >= 100 && task.status == WorkflowTaskStatus::Running && task.turn_budget > 0 {
                row.push(Span::styled(
                    format!(" · ≤{} turns", task.turn_budget),
                    Style::default().fg(theme.faint),
                ));
            }
            rows.push(row);

            if let Some(error) = &task.error_preview {
                rows.push(vec![
                    Span::styled("│     └─ ", Style::default().fg(theme.faint)),
                    Span::styled(error.clone(), Style::default().fg(theme.error)),
                ]);
            } else if width >= 80
                && let Some(summary) = &task.summary_preview
            {
                rows.push(vec![
                    Span::styled("│     └─ ", Style::default().fg(theme.faint)),
                    Span::styled(
                        format!("evidence · {summary}"),
                        Style::default().fg(theme.muted),
                    ),
                ]);
            }
        }
    }
    if card.dropped > 0 {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled(
                format!("{} more omitted by the fan limit", card.dropped),
                Style::default().fg(theme.warn),
            ),
        ]);
    }
    if card.duplicates_removed > 0 || card.invalid_removed > 0 {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled(
                format!(
                    "plan normalized · {} duplicate · {} invalid removed",
                    card.duplicates_removed, card.invalid_removed
                ),
                Style::default().fg(theme.faint),
            ),
        ]);
    }
    if card.status == WorkflowStatus::Synthesizing {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled(
                format!("MERGE  {settled}/{} reports settled", card.tasks.len()),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
    } else if card.status == WorkflowStatus::Writing {
        rows.push(vec![
            Span::styled("└─ ", Style::default().fg(theme.faint)),
            Span::styled(
                format!("WRITE  single writer · {done} evidence report(s) available"),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
    }
    out.extend(connector_lines(&rows, width, theme));
    out
}

/// The current braille spinner frame (advanced ~80ms by the caller).
fn braille_frame(spin: usize) -> &'static str {
    braille_spinner()[spin % braille_spinner().len()]
}

const BRAND_ICON_WIDTH: u16 = 16;

/// One terminal row of the public Plantcore icon: a fixed canvas prefix followed by its layered
/// planes. Color, rather than texture, distinguishes overlap on normal terminals.
fn brand_icon_row(width: u16, prefix: &str, parts: &[(&str, Color)]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(
        width.saturating_sub(iteron_tunables::param_integer(
            "cli.block.brand_icon_width",
            BRAND_ICON_WIDTH,
        )) as usize
            / 2,
    ))];
    spans.push(Span::raw(prefix.to_string()));
    spans.extend(parts.iter().map(|(shape, color)| {
        Span::styled(
            (*shape).to_string(),
            Style::default().fg(*color).add_modifier(Modifier::BOLD),
        )
    }));
    Line::from(spans)
}

/// Reproduce the public Plantcore icon's three overlapping planes in a compact 16×5 terminal grid.
/// This is intentionally a character adaptation, not a raster asset embedded in the binary.
fn plantcore_icon(width: u16, theme: &Theme) -> Vec<Line<'static>> {
    vec![
        brand_icon_row(width, "         ", &[("▄", theme.brand_back)]),
        brand_icon_row(
            width,
            "      ",
            &[("▄██", theme.brand_mid), ("█████", theme.brand_back)],
        ),
        brand_icon_row(
            width,
            "    ",
            &[
                ("▄██", theme.brand_front),
                ("███", theme.brand_mid),
                ("██████", theme.brand_back),
            ],
        ),
        brand_icon_row(
            width,
            "  ",
            &[
                ("▄█", theme.brand_mid),
                ("███████", theme.brand_front),
                ("█████", theme.brand_back),
            ],
        ),
        brand_icon_row(
            width,
            "",
            &[
                ("██", theme.brand_mid),
                ("████████", theme.brand_front),
                ("██████", theme.brand_back),
            ],
        ),
    ]
}

/// A terminal-native startup signature that scrolls away with the conversation. Wide terminals use
/// the Plantcore icon adaptation; narrow terminals keep the established transcript marker grammar.
fn render_welcome(tagline: &str, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    if width == 0 {
        return vec![Line::default()];
    }
    if width < 16 {
        let compact = [
            Span::styled("<", Style::default().fg(theme.muted)),
            Span::styled(
                "iteron",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(">", Style::default().fg(theme.muted)),
        ];
        return vec![
            wrap_spans(&compact, width)
                .into_iter()
                .next()
                .unwrap_or_default(),
        ];
    }

    if width >= 28 {
        let mut out = plantcore_icon(width, theme);
        // `one_line` appends an ellipsis when truncated, so reserve its final cell.
        let tagline = one_line(tagline, width.saturating_sub(1) as usize);
        let tagline_width = tagline.chars().count() as u16;
        let pad = width.saturating_sub(tagline_width) / 2;
        out.push(Line::from(vec![
            Span::raw(" ".repeat(pad as usize)),
            Span::styled(tagline, Style::default().fg(theme.muted)),
        ]));
        out
    } else {
        let mut out = marker_wrap(
            &format!("{} ", primary_marker()),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
            &[Span::styled(
                "iteron",
                Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
            )],
            width,
        );
        out.extend(connector_lines(
            &[vec![Span::styled(
                tagline.to_string(),
                Style::default().fg(theme.muted),
            )]],
            width,
            theme,
        ));
        out
    }
}

fn render_panel(title: &str, rows: &[PanelRow], width: u16, theme: &Theme) -> Vec<Line<'static>> {
    // Panel header is a primary machine line: an ACCENT marker + a bold fg title, matching the panel's
    // accent marker. The per-panel icon is gone (§2). Rows hang on
    // the ONE `  ⎿  ` connector grid at col 5 (§1), the same grid tool/error use.
    let mut out = marker_wrap(
        &format!("{} ", primary_marker()),
        Style::default().fg(theme.accent),
        &[Span::styled(
            title.to_string(),
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
        )],
        width,
    );
    // align key column for KeyValue rows
    let key_w = rows
        .iter()
        .filter_map(|r| match r {
            PanelRow::KeyValue { key, .. } => Some(key.chars().count()),
            _ => None,
        })
        .max()
        .unwrap_or(iteron_tunables::param_integer(
            "cli.block.empty_key_column_width",
            EMPTY_KEY_COLUMN_WIDTH,
        ))
        .min(24);
    let row_lines: Vec<Vec<Span<'static>>> = rows
        .iter()
        .map(|r| match r {
            PanelRow::KeyValue { key, value } => {
                let mut spans = vec![Span::styled(
                    format!("{key:<key_w$}  "),
                    Style::default().fg(theme.muted),
                )];
                spans.extend(crate::semantic_text::spans(
                    value,
                    crate::semantic_text::Tone::Body,
                    theme,
                ));
                spans
            }
            PanelRow::Item { label, hint } => {
                // NO per-row bullet (findings 4): the row already rides the `  ⎿  ` connector grid, so a
                // leading `• ` was a second marker that pushed the list edge to col 7 and made panel
                // lists jump vs markdown lists. The label sits directly on the connector column; identity
                // is the label (matching this row's own contract — the icon zoo was deleted, §2).
                let mut sp =
                    crate::semantic_text::spans(label, crate::semantic_text::Tone::Body, theme);
                if !hint.is_empty() {
                    sp.push(Span::styled("  ", Style::default().fg(theme.muted)));
                    sp.extend(crate::semantic_text::spans(
                        hint,
                        crate::semantic_text::Tone::Muted,
                        theme,
                    ));
                }
                sp
            }
            PanelRow::Note(t) => {
                crate::semantic_text::spans(t, crate::semantic_text::Tone::Muted, theme)
                    .into_iter()
                    .map(|mut span| {
                        span.style = span.style.add_modifier(Modifier::DIM);
                        span
                    })
                    .collect()
            }
        })
        .collect();
    out.extend(connector_lines(&row_lines, width, theme));
    out
}

/// Map a tool name to a human verb — a Title-case proper noun (TUI v3 §4). NO glyph (the glyph zoo
/// was deleted — §2), NO snake_case id leak. Unknown/MCP/custom tools are humanized so they read as
/// cleanly as the built-ins (`mcp__notion__…` → `Notion`, `create_pull_request` → `Create`), never
/// the generic `Tool` fallback that collapsed the whole MCP surface into one word.
pub fn verb_for(name: &str) -> String {
    known_verb(name).unwrap_or_else(|| humanize_verb(name))
}

/// The known-tool label mapping itself. `None` means the harness has no label for this id — an
/// UNKNOWN (MCP / custom / third-party) tool, which is humanized for display but is NOT one of the
/// shapes whose output we understand. That distinction is a budget input: opencode
/// (`index.tsx:1811-1813`) renders an unknown tool's output with a smaller budget than a known one.
fn known_verb(name: &str) -> Option<String> {
    Some(match name {
        "read_file" | "read" | "cat" => "Read".into(),
        "grep" | "search" | "rg" => "Search".into(),
        "list_dir" | "ls" | "list" | "glob" | "repo_map" => "List".into(),
        "bash" | "shell" | "run" => "Bash".into(),
        "edit" | "str_replace" => "Edit".into(),
        "write" | "create" | "write_file" => "Write".into(),
        "apply_patch" | "update" => "Update".into(),
        "task" => "Task".into(),
        n if n.contains("memory") || n.contains("mem") => "Memory".into(),
        n if n.contains("skill") => "Skill".into(),
        n if n.contains("agent") || n.contains("dispatch") => "Subagent".into(),
        _ => return None,
    })
}

/// A tool id the known-tool label mapping ([`known_verb`]) does not answer for.
fn is_unknown_tool(name: &str) -> bool {
    known_verb(name).is_none()
}

/// Compact, already-humanized label for the active shelf. The live shelf and the transcript card
/// therefore use the same vocabulary and never expose raw tool JSON.
pub fn activity_label(name: &str, args: &serde_json::Value) -> String {
    let verb = verb_for(name);
    let arg = humanize_args(name, args);
    if arg.is_empty() {
        verb
    } else {
        format!("{verb}({})", one_line(&arg, 96))
    }
}

/// Humanize an unknown tool id into a Title-case proper noun. For an MCP id `mcp__<server>__<op>` the
/// SERVER reads best as the verb (`mcp__notion__API-post-search` → `Notion`); otherwise the first
/// meaningful token (`create_pull_request` → `Create`). Never leaks the raw snake_case id.
fn humanize_verb(name: &str) -> String {
    let token = if let Some(rest) = name.strip_prefix("mcp__") {
        rest.split("__").next().unwrap_or(rest)
    } else {
        name.split(['_', '-', '.'])
            .find(|t| !t.is_empty())
            .unwrap_or(name)
    };
    title_case(token)
}

/// Uppercase the first char, lowercase the rest (`notion` → `Notion`, `API` → `Api`). Width-safe.
fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(|c| c.to_lowercase()))
            .collect(),
        None => String::new(),
    }
}

/// Extract the OPERATION token from an MCP tool id `mcp__<server>__<op>`, cleaned to a short verb-noun
/// so read vs write is distinguishable (findings 8): `mcp__notion__API-post-search` → `search`,
/// `mcp__notion__API-patch-page` → `patch-page`, `mcp__lark__im_v1_message_create` → `create`.
/// Without this, the whole MCP surface collapsed to the bare server name (`Notion` for both read and
/// write), so the operation was invisible. Never leaks a raw snake_case id.
fn mcp_op(name: &str) -> Option<String> {
    let rest = name.strip_prefix("mcp__")?;
    let op = rest.split("__").nth(1)?;
    // drop a REST-ish namespace prefix (`API-`, `api_`) and a read/create HTTP verb (`post-`, `get-`).
    let op = op
        .strip_prefix("API-")
        .or_else(|| op.strip_prefix("api_"))
        .unwrap_or(op);
    let op = op
        .strip_prefix("post-")
        .or_else(|| op.strip_prefix("get-"))
        .unwrap_or(op);
    // a snake_case op keeps only its last segment (the operation verb), so no snake id leaks;
    // a dash-cased op (Notion) is already the clean verb-noun and is kept whole.
    let op = if op.contains('_') && !op.contains('-') {
        op.rsplit('_').next().unwrap_or(op)
    } else {
        op
    };
    (!op.is_empty()).then(|| op.to_string())
}

/// Humanize a tool's args into a short label (path / command / pattern), never raw JSON.
fn humanize_args(name: &str, args: &serde_json::Value) -> String {
    // MCP tools: the arg is the OPERATION token (Notion(search) / Notion(patch-page)), not the JSON
    // payload — so the read/write surface is legible at a glance (findings 8).
    if let Some(op) = mcp_op(name) {
        return op;
    }
    let get = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    if let Some(cmd) = get("command").or_else(|| get("cmd")) {
        return one_line(&cmd, 80);
    }
    let path = get("path")
        .or_else(|| get("file"))
        .or_else(|| get("file_path"))
        .or_else(|| get("filename"));
    if let Some(p) = get("pattern").or_else(|| get("query")) {
        return match path {
            Some(fp) => format!("{} in {}", one_line(&p, 40), fp),
            None => one_line(&p, 60),
        };
    }
    if let Some(p) = path {
        return p;
    }
    if (name.contains("agent") || name.contains("dispatch"))
        && let Some(t) = get("task")
    {
        return one_line(&t, 70);
    }
    // Fallback: NO arg. An unmatched object must NOT leak its raw snake_case KEY names (the `⏺
    // Tool(page_id, properties)` toy tell — TUI v3 §4); the humanized verb alone carries identity, so
    // the line reads `⏺ Notion`. Only a bare scalar (rare) is shown.
    match args {
        serde_json::Value::Object(_) | serde_json::Value::Null => String::new(),
        other => one_line(&other.to_string(), 60),
    }
}

fn one_line(s: &str, max: usize) -> String {
    let first = s.lines().next().unwrap_or("");
    let t: String = first.chars().take(max).collect();
    if first.chars().count() > max || s.lines().count() > 1 {
        format!("{t}…")
    } else {
        t
    }
}

/// A read-only lookup whose success is uninteresting — rendered as ONE dim line (progressive
/// disclosure): only diffs / real output / errors earn a full card (ref-teardown).
fn is_trivial_tool(name: &str) -> bool {
    matches!(
        name,
        "read_file"
            | "read"
            | "cat"
            | "grep"
            | "search"
            | "rg"
            | "list_dir"
            | "ls"
            | "list"
            | "glob"
            | "repo_map"
    )
}

/// The non-empty output lines of a tool run (blank lines dropped). The first is HOISTED onto the `⎿`
/// connector for a generic tool; the rest form the collapsible tail (findings 1).
fn body_lines(card: &ToolCard) -> Vec<&str> {
    card.output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect()
}

/// The CC-style one-line result summary shown on the `  ⎿  ` connector. `None` while running — the
/// spinner in the marker carries liveness, so the literal `running…` is dropped (findings 7). A COUNT
/// (`Read 214 lines`, `3 matches`) is reserved for Read/Search/List, whose whole result IS the count;
/// a generic tool (Bash, …) instead HOISTS its first output line here (findings 1), so the row the eye
/// lands on shows real output (`running 42 tests`) instead of a redundant `12 lines` that then repeats
/// below. Writes say `Wrote …`, edits `Updated …` (findings 7 — a Write no longer claims `0 removals`).
fn result_summary(card: &ToolCard, verb: &str) -> Option<String> {
    if card.status == ToolStatus::Running {
        return None;
    }
    if let Some(d) = &card.diff {
        let file = d.path.rsplit(['/', '\\']).next().unwrap_or(&d.path);
        // A from-empty write is not an edit: `Wrote main.rs (12 lines)`, never `Updated … with 12
        // additions and 0 removals` (findings 7). `Write`/`Create`/`Write_file` all map to verb `Write`.
        if verb == "Write" {
            return Some(format!(
                "Wrote {file} ({})",
                plural(d.adds as usize, "line")
            ));
        }
        return Some(format!(
            "Updated {file} with {} and {}",
            plural(d.adds as usize, "addition"),
            plural(d.dels as usize, "removal")
        ));
    }
    if card.exit_code.is_some_and(|c| c != 0) {
        return Some(format!("exited {}", card.exit_code.unwrap_or_default()));
    }
    let body = body_lines(card);
    if card.status == ToolStatus::Err && body.is_empty() {
        return Some("failed".into());
    }
    Some(match verb {
        // count-shaped tools: the count IS the result (reserve the count here — findings 1).
        "Read" => format!("Read {}", plural(body.len(), "line")),
        "Search" | "List" => plural(body.len(), "match"),
        // generic tool: hoist the first output line onto the connector (the tail renders below).
        _ if body.is_empty() => "done".into(),
        _ => one_line(body[0], 80),
    })
}

/// Visible rows of a tool's output tail when the card is collapsed. FIVE, from codex
/// (`exec_cell/render.rs:695-700`, which shows 5 lines of command output). This is deliberately NOT a
/// function of terminal width: the question the tail answers is "is this enough to see whether it
/// worked", and that answer does not change when the window is resized. The previous
/// `width < 60 → 1 / width < 100 → 2 / else 3` ladder made the same run render differently in two
/// panes and let a wide terminal justify more noise.
fn tool_tail_budget_rows() -> usize {
    iteron_tunables::param_usize("cli.block.tool_tail_budget_rows", 5)
}

/// Of that budget, how many rows come from the HEAD; the remainder are the last rows, with the
/// elision line between them. Seeing the start AND the end is what tells an operator "it started and
/// then failed at the end" — five leading rows do not. codex's 5-line cell is the size; head+tail is
/// the shape.
fn tool_tail_head_rows() -> usize {
    iteron_tunables::param_usize("cli.block.tool_tail_head_rows", 2)
}

/// An UNKNOWN tool (one the known-tool mapping [`known_verb`] has no label for) gets a SMALLER
/// budget than a known one — opencode `index.tsx:1811-1813`. We do not know the shape of its output,
/// so it earns less of the transcript.
fn tool_tail_budget_rows_unknown() -> usize {
    iteron_tunables::param_usize("cli.block.tool_tail_budget_rows_unknown", 3)
}

/// Floor of the per-row character allowance, from opencode `util/collapse-tool-output.ts:1-19`:
/// the character budget is `maxLines × max(20, contentWidth − 6)`.
fn tool_tail_min_chars_per_row() -> usize {
    iteron_tunables::param_usize("cli.block.tool_tail_min_chars_per_row", 20)
}

/// Columns subtracted from the pane width before the per-row character allowance, same source
/// (`contentWidth − 6`) — it pays for the `  ⎿  `-grid indent the tail hangs on.
fn tool_tail_width_reserve() -> u16 {
    u16::try_from(iteron_tunables::param_usize(
        "cli.block.tool_tail_width_reserve",
        6,
    ))
    .unwrap_or(6)
}

/// Rows of a tool output tail to show when collapsed, as `(head, tail)`; `head + tail ==
/// rows.len()` means everything fits and NO elision line is drawn.
///
/// Two budgets, both from the comparators: a ROW budget (codex, 5 lines) and, on top of it, a
/// CHARACTER budget (opencode `collapse-tool-output.ts`, `maxLines × max(20, contentWidth − 6)`,
/// counted with `Array.from(...)` — i.e. by CHARACTERS, not bytes, so a CJK or emoji-heavy log is
/// measured the same way a viewer reads it). The character budget is what stops one 4000-character
/// line from defeating a 5-row budget; it can only ever cut EARLIER than the row budget.
fn tool_tail_window(
    rows: &[Line<'static>],
    budget_rows: usize,
    char_budget: usize,
) -> (usize, usize) {
    let row_chars = |line: &Line<'static>| -> usize {
        line.spans
            .iter()
            .map(|s| s.content.chars().count())
            .sum::<usize>()
    };
    let total_chars: usize = rows.iter().map(row_chars).sum();
    // Whole tail inside both budgets: render it all, no elision line (nothing is being hidden, so
    // claiming "0 more rows" would be a lie and an extra row of chrome).
    if rows.len() <= budget_rows && total_chars <= char_budget {
        return (rows.len(), 0);
    }
    // Eliding costs a row: the `… N more rows` line is INSIDE the budget, so a 5-row budget renders
    // 2 + elision + 2, exactly as codex's cell is 5 rows tall — the collapse never buys space by
    // spending more of it. At least one row must actually end up hidden, or the elision line would
    // cost a row and buy nothing.
    let content_budget = budget_rows.saturating_sub(1);
    let window_cap = rows.len().saturating_sub(1).min(content_budget);
    // Head-heavy but never head-ONLY: at the smaller unknown-tool budget this keeps the shape
    // 1 + elision + 1 rather than collapsing to a pure head, which is the whole point of head+tail.
    let mut head = tool_tail_head_rows()
        .min(content_budget.div_ceil(2))
        .min(window_cap);
    let mut tail = window_cap - head;
    // Character budget on top of the row budget: shrink the window (from the tail end first, so the
    // opening rows — where a command announces what it is doing — survive longest).
    while head + tail > 0 {
        let shown: usize = rows[..head].iter().map(row_chars).sum::<usize>()
            + rows[rows.len() - tail..]
                .iter()
                .map(row_chars)
                .sum::<usize>();
        if shown <= char_budget {
            break;
        }
        if tail > 0 {
            tail -= 1;
        } else {
            head -= 1;
        }
    }
    (head, tail)
}

fn render_tool(card: &ToolCard, width: u16, theme: &Theme, spin: usize) -> Vec<Line<'static>> {
    let verb = verb_for(&card.name);
    let bad_exit = card.exit_code.is_some_and(|c| c != 0);
    let errored = card.status == ToolStatus::Err || bad_exit;

    // Primary machine line: `⏺ Verb(arg)`. One marker carries the whole status signal: live=accent,
    // failure=error, settled=faint. No duplicated rail, status glyph, tool icon or snake_case id.
    let marker_color = tool_marker_color(card, theme);
    let marker = if card.status == ToolStatus::Running {
        format!("{} ", spinner()[spin % spinner().len()])
    } else {
        format!("{} ", primary_marker())
    };
    let arg = humanize_args(&card.name, &card.args);
    // Only the VERB is bold; the `(arg)` recedes to `muted`/regular so the line isn't an all-bold wall
    // and the verb reads as the identity (findings 7). Under an all-bold title both verb and path
    // competed for the eye.
    let mut title_spans = vec![Span::styled(
        verb.clone(),
        Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
    )];
    if !arg.is_empty() {
        title_spans.push(Span::styled("(", Style::default().fg(theme.faint)));
        title_spans.extend(crate::semantic_text::spans(
            &arg,
            crate::semantic_text::Tone::Muted,
            theme,
        ));
        title_spans.push(Span::styled(")", Style::default().fg(theme.faint)));
    }
    // elapsed shows only for slow tools (≥1s) — a millisecond column on every fast tool is noise CC
    // omits. `muted`, not `faint`, so a real duration stays scannable (findings).
    if card.status != ToolStatus::Running
        && let Some(d) = card.elapsed
        && d.as_millis() >= 1000
    {
        title_spans.push(Span::styled(
            format!("  {}", fmt_dur(d)),
            Style::default().fg(theme.muted),
        ));
    }
    let mut out = marker_wrap(
        &marker,
        Style::default()
            .fg(marker_color)
            .add_modifier(Modifier::BOLD),
        &title_spans,
        width,
    );

    // While running the spinner marker is the whole liveness signal — no `⎿ running…` line (findings 7).
    let Some(summary) = result_summary(card, &verb) else {
        return out;
    };

    // The ok result summary is `muted` (not `faint`) — it is the line the eye lands on, so it must be
    // legible, not dimmer than the body preview (findings 2). Errors stay red.
    let summary_tone = if errored {
        crate::semantic_text::Tone::Error
    } else {
        crate::semantic_text::Tone::Body
    };
    out.extend(connector_lines(
        &[crate::semantic_text::spans(&summary, summary_tone, theme)],
        width,
        theme,
    ));

    // Trivial read-only success: just the primary line + the one-line `⎿` count summary, no body (§4).
    if is_trivial_tool(&card.name) && card.status == ToolStatus::Ok && card.diff.is_none() {
        return out;
    }

    if let Some(diff) = &card.diff {
        // Diff body hangs further in, under the connector column. `false` = suppress the `@@` hunk
        // header (a git machine tell) for an INLINE edit result — findings 2.
        out.extend(render_diff_body(diff, width, theme, false));
    } else {
        // Command/tool output TAIL: the first non-empty line is already hoisted onto the connector
        // (findings 1), so render lines[1..]. On a bad exit the summary is `exited N` (not output), so
        // the whole body is the tail. Collapsible at col 5.
        let body = body_lines(card);
        let tail: &[&str] = if bad_exit {
            &body
        } else {
            body.get(1..).unwrap_or(&[])
        };
        if !tail.is_empty() {
            let tone = if errored {
                crate::semantic_text::Tone::Error
            } else {
                crate::semantic_text::Tone::Muted
            };
            let rendered: Vec<Line<'static>> = tail
                .iter()
                .flat_map(|line| {
                    indent_wrap(
                        "     ",
                        &crate::semantic_text::spans(line, tone, theme),
                        width,
                    )
                })
                .collect();
            if card.open {
                out.extend(rendered.iter().cloned());
            } else {
                // Budget by CONTENT, not by pane width — see `tool_tail_budget_rows()`. An unknown
                // tool gets the smaller budget (opencode `index.tsx:1811-1813`).
                let budget = if is_unknown_tool(&card.name) {
                    tool_tail_budget_rows_unknown()
                } else {
                    tool_tail_budget_rows()
                };
                let char_budget = budget
                    * (width.saturating_sub(tool_tail_width_reserve()) as usize)
                        .max(tool_tail_min_chars_per_row());
                let (head, tail_rows) = tool_tail_window(&rendered, budget, char_budget);
                out.extend(rendered.iter().take(head).cloned());
                let more = rendered.len() - head - tail_rows;
                if more > 0 {
                    out.extend(indent_wrap(
                        "     ",
                        &[Span::styled(
                            format!("… {more} more rows (ctrl+o to expand)"),
                            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
                        )],
                        width,
                    ));
                }
                out.extend(rendered[rendered.len() - tail_rows..].iter().cloned());
            }
        }
    }
    out
}

/// Standalone diff block (`/diff`, git_diff): a primary `⏺ path  +adds -dels` header + the body.
fn render_diff(diff: &FileDiff, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let head = vec![
        Span::styled(
            diff.path.clone(),
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  +{}", diff.adds),
            Style::default().fg(theme.added),
        ),
        Span::styled(
            format!(" -{}", diff.dels),
            Style::default().fg(theme.removed),
        ),
    ];
    // The diff header earns an ACCENT marker (a diff is a
    // rich viewer, not washed-out chrome). A standalone `/diff` KEEPS the `@@` hunk header (it's a
    // genuine viewer), unlike an inline edit result which suppresses it (findings 2).
    let mut out = marker_wrap(
        &format!("{} ", primary_marker()),
        Style::default().fg(theme.accent),
        &head,
        width,
    );
    out.extend(render_diff_body(diff, width, theme, true));
    out
}

/// Parse a hunk header's starting line numbers. Unified headers read `@@ -old[,n] +new[,m] @@`; the
/// `from_replacement` header (`@@ {path} @@`) has no ranges, so both default to 1 (sequential
/// numbering from the top of the change). Never panics on a malformed header.
fn hunk_start(header: &str) -> (u32, u32) {
    let mut old = iteron_tunables::param_integer(
        "cli.block.hunk_default_start_line",
        HUNK_DEFAULT_START_LINE,
    );
    let mut new = iteron_tunables::param_integer(
        "cli.block.hunk_default_start_line",
        HUNK_DEFAULT_START_LINE,
    );
    for tok in header.split_whitespace() {
        if let Some(n) = tok.strip_prefix('-') {
            old = n.split(',').next().and_then(|x| x.parse().ok()).unwrap_or(
                iteron_tunables::param_integer(
                    "cli.block.hunk_default_start_line",
                    HUNK_DEFAULT_START_LINE,
                ),
            );
        } else if let Some(n) = tok.strip_prefix('+') {
            new = n.split(',').next().and_then(|x| x.parse().ok()).unwrap_or(
                iteron_tunables::param_integer(
                    "cli.block.hunk_default_start_line",
                    HUNK_DEFAULT_START_LINE,
                ),
            );
        }
    }
    (old, new)
}

/// The lexer language hint for a file path — normally its extension, passed straight to the
/// highlighter (its `spec_for` matches `rs`/`py`/`ts`/… directly). `None` → no highlighting at all,
/// which is the deliberate answer whenever we cannot NAME the language.
///
/// Extensionless build/config files are named, not suffixed, so a basename table is consulted
/// FIRST: `Makefile`, `Dockerfile` and friends otherwise reach the extension split, find nothing,
/// and render plain. Only names the highlighter actually has a `LangSpec` for are mapped; the rest
/// (`Justfile`, `CMakeLists.txt`, the ignore files) map to `None` on purpose — a plain render beats
/// a plausible-looking wrong lexer.
fn lang_for_path(path: &str) -> Option<&str> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match base {
        "Makefile" | "makefile" | "GNUmakefile" => return Some("make"),
        "Dockerfile" | "Containerfile" => return Some("dockerfile"),
        "Cargo.lock" => return Some("toml"),
        // `just`, `cmake` and the gitignore grammar have no LangSpec — do not guess a near neighbor.
        "Justfile" | "justfile" | "CMakeLists.txt" | ".gitignore" | ".dockerignore" => return None,
        _ => {}
    }
    base.rsplit('.')
        .next()
        .filter(|e| !e.is_empty() && *e != base)
}

/// The diff hunks: a dim `@@` header, then each row = a right-aligned `old│new` line-number gutter
/// (the biggest missing diff cue), a single dim sign cell, and the code text — SYNTAX-HIGHLIGHTED, not
/// flat-colored. Add/del is encoded ONCE by the edge-to-edge background tint + the sign; the code keeps
/// its syntax foreground (like delta/GitHub — TUI v3 §5, review R1/R2). Context rows carry no tint.
/// Rows hang at col 5 (under the connector) so the body reads as nested result.
fn render_diff_body(
    diff: &FileDiff,
    width: u16,
    theme: &Theme,
    show_header: bool,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let indent = "     "; // col 5, under the connector
    let lang = lang_for_path(&diff.path);

    // Pre-pass: the widest line number in the whole diff → the gutter column width.
    let mut max_no = 1u32;
    for h in &diff.hunks {
        let (mut o, mut n) = hunk_start(&h.header);
        for dl in &h.lines {
            match dl.tag {
                DiffTag::Add => {
                    max_no = max_no.max(n);
                    n += 1;
                }
                DiffTag::Del => {
                    max_no = max_no.max(o);
                    o += 1;
                }
                DiffTag::Ctx => {
                    max_no = max_no.max(o.max(n));
                    o += 1;
                    n += 1;
                }
            }
        }
    }
    let gw = max_no.to_string().len();
    let blank = " ".repeat(gw);
    let gutter_style = Style::default().fg(theme.faint);

    // The twin `old│new ` + `sign ` gutter's display width — code hangs under this column (findings 5).
    let gutter_w = 2 * gw + 4; // og(gw) │(1) "ng "(gw+1) "sign "(2)
    let indent_w = indent.chars().count(); // 5, the col-5 connector indent

    for (hi, h) in diff.hunks.iter().enumerate() {
        if show_header {
            // A standalone `/diff` keeps the `@@ …` hunk header (a genuine viewer — findings 2).
            out.extend(indent_wrap(
                indent,
                &[Span::styled(h.header.clone(), gutter_style)],
                width,
            ));
        } else if hi > 0 {
            // Inline edit result: SUPPRESS the `@@` git tell; a blank row separates successive hunks.
            out.push(Line::from(""));
        }
        let (mut o, mut n) = hunk_start(&h.header);
        let mut st = crate::highlight::LexState::new();
        for dl in &h.lines {
            let (sign, bg, og, ng, changed) = match dl.tag {
                DiffTag::Add => (
                    "+",
                    Some(theme.added_bg),
                    blank.clone(),
                    format!("{n:>gw$}"),
                    theme.added,
                ),
                DiffTag::Del => (
                    "-",
                    Some(theme.removed_bg),
                    format!("{o:>gw$}"),
                    blank.clone(),
                    theme.removed,
                ),
                DiffTag::Ctx => (
                    " ",
                    None,
                    format!("{o:>gw$}"),
                    format!("{n:>gw$}"),
                    theme.faint,
                ),
            };
            match dl.tag {
                DiffTag::Add => n += 1,
                DiffTag::Del => o += 1,
                DiffTag::Ctx => {
                    o += 1;
                    n += 1;
                }
            }
            // add/del is carried PRIMARILY by the sign + the changed-side line number in green/red
            // (delta/Claude Code style), with the row tint as a supporting band. Coloring the sign and
            // number is the load-bearing cue — the dark-theme tint alone (~10/channel off the bg) is too
            // subtle to read, which made the whole card look flat (findings). Context stays faint.
            let sign_style = Style::default().fg(changed);
            let old_style = Style::default().fg(if dl.tag == DiffTag::Del {
                changed
            } else {
                theme.faint
            });
            let new_style = Style::default().fg(if dl.tag == DiffTag::Add {
                changed
            } else {
                theme.faint
            });
            // Expand tabs to spaces BEFORE highlight/wrap: `char_width('\t') == 1` here but the terminal
            // draws a tab as a jump to the next stop, so a tab-indented diff would misalign and its
            // row tint would truncate short of the real right edge (findings 7).
            let expanded = expand_tabs(&dl.text);
            let code_spans = crate::highlight::code_spans(lang, &expanded, &mut st, theme);
            let gutter_spans = || {
                vec![
                    Span::styled(og.clone(), old_style),
                    Span::styled("│".to_string(), gutter_style),
                    Span::styled(format!("{ng} "), new_style),
                    Span::styled(format!("{sign} "), sign_style),
                ]
            };
            let code_col = (indent_w + gutter_w) as u16;
            let mut rows: Vec<Line<'static>> = if code_col < width {
                // HANGING INDENT (findings 5): the gutter (`old│new sign `) prefixes row 0 only; a
                // wrapped continuation gets that gutter width in (faint) spaces so the code stays
                // left-aligned under the code column, never under the line-number gutter. Wrap the CODE
                // at width − code column.
                wrap_spans(&code_spans, width - code_col)
                    .into_iter()
                    .enumerate()
                    .map(|(ri, mut cr)| {
                        let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];
                        if ri == 0 {
                            spans.extend(gutter_spans());
                        } else {
                            spans.push(Span::styled(" ".repeat(gutter_w), gutter_style));
                        }
                        spans.append(&mut cr.spans);
                        Line::from(spans)
                    })
                    .collect()
            } else {
                // Pathologically narrow terminal (the gutter alone won't fit a code column): fall back to
                // wrapping gutter+code together so the composed row still respects `<= width` (the
                // pre-wrap→scroll-unit invariant). No hanging indent is possible here anyway.
                let mut spans = gutter_spans();
                spans.extend(code_spans);
                indent_wrap(indent, &spans, width)
            };
            if !theme.mono
                && let Some(bg) = bg
            {
                for row in &mut rows {
                    let w = line_width(row);
                    if w < width {
                        row.spans.push(Span::raw(" ".repeat((width - w) as usize)));
                    }
                    // skip the col-5 connector indent (first span) so the left margin stays neutral;
                    // the tint then runs edge-to-edge from the gutter across the row.
                    for s in row.spans.iter_mut().skip(1) {
                        if s.style.bg.is_none() {
                            s.style = s.style.bg(bg);
                        }
                    }
                }
            }
            out.extend(rows);
        }
    }
    out
}

/// Body rows of a COLLAPSED reasoning block. ONE — opencode `index.tsx:1589-1590` keeps reasoning to
/// a single line, for the stated reason that a single line makes the layout never jump. Reasoning
/// streams token by token, so any budget above 1 re-lays the transcript on every chunk.
fn thinking_closed_rows() -> usize {
    iteron_tunables::param_usize("cli.block.thinking_closed_rows", 1)
}

/// Characters of that one line — a teaser: enough to recognize the thought, short enough to stay a
/// single row on any ordinary pane. It is a CHARACTER cap, not a cell cap, so on a pane narrower than
/// ~66 columns the teaser can wrap to two rows; that height is still CONSTANT as reasoning streams,
/// which is the property being bought.
fn thinking_closed_chars() -> usize {
    iteron_tunables::param_usize("cli.block.thinking_closed_chars", 60)
}

/// The first sentence of `line` if it ends within `max` characters, else the first `max` characters.
/// Sentence-first (rather than a hard cut) so the collapsed reasoning row reads as a thought, not as
/// a severed clause. `more_after` lets the caller declare that further lines exist even when this one
/// fits, so the `…` is honest about the whole block. Counted in CHARACTERS, never bytes.
fn first_sentence_or(line: &str, max: usize, more_after: bool) -> String {
    let line = line.trim();
    let total = line.chars().count();
    let sentence_end = line
        .chars()
        .take(max)
        .position(|c| matches!(c, '.' | '!' | '?' | '。' | '！' | '？'));
    let (take, elided) = match sentence_end {
        // A complete sentence that IS the whole reasoning keeps its terminator; one with more behind
        // it drops the terminator so the elision reads `…`, not `.…`.
        Some(i) if total == i + 1 && !more_after => (i + 1, false),
        Some(i) => (i, true),
        None => (max.min(total), more_after || total > max),
    };
    let head: String = line.chars().take(take).collect();
    if elided {
        format!("{}…", head.trim_end())
    } else {
        head
    }
}

fn render_thinking(text: &str, open: bool, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    // Thinking is an ordinary machine block: the ⏺/● primary marker (faint), a lowercase `thinking…`
    // header (TUI v3 §1/§10 — ✻ is reserved for the spinner), and the body on the ONE `  ⎿  `
    // connector grid at col 5, like every other nested content. No "(N lines)".
    let hdr = Style::default()
        .fg(theme.muted)
        .add_modifier(Modifier::ITALIC);
    let mut out = marker_wrap(
        &format!("{} ", primary_marker()),
        Style::default().fg(theme.muted),
        &[Span::styled("thinking…", hdr)],
        width,
    );
    let muted_italic = Style::default()
        .fg(theme.muted)
        .add_modifier(Modifier::ITALIC);
    // CLOSED: exactly ONE body row — a teaser of the first sentence (`thinking_closed_rows()`). The
    // old `min(3)` grew from 1 to 2 to 3 rows as the reasoning streamed, so the whole transcript
    // below it moved twice per thought. A `… N more` row is deliberately NOT added here: it would
    // make the collapsed form two rows and reintroduce the same jump when the count appears. The
    // trailing `…` is the affordance; `ctrl+o` still expands.
    let body: Vec<Vec<Span<'static>>> = if open {
        lines
            .iter()
            .map(|l| vec![Span::styled((*l).to_string(), muted_italic)])
            .collect()
    } else {
        let teaser = first_sentence_or(
            lines.first().copied().unwrap_or_default(),
            thinking_closed_chars(),
            lines.len() > thinking_closed_rows(),
        );
        if teaser.is_empty() {
            Vec::new()
        } else {
            vec![vec![Span::styled(teaser, muted_italic)]]
        }
    };
    out.extend(connector_lines(&body, width, theme));
    out
}

fn render_error(
    title: &str,
    detail: &str,
    open: bool,
    width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    // Primary machine line with the error-colored marker; detail hangs under the connector (col 5).
    let mut out = marker_wrap(
        &format!("{} ", primary_marker()),
        Style::default()
            .fg(theme.error)
            .add_modifier(Modifier::BOLD),
        &[Span::styled(
            title.to_string(),
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        )],
        width,
    );
    if open && !detail.trim().is_empty() {
        let lines: Vec<Vec<Span>> = detail
            .lines()
            .map(|l| {
                vec![Span::styled(
                    l.to_string(),
                    Style::default().fg(theme.error),
                )]
            })
            .collect();
        out.extend(connector_lines(&lines, width, theme));
    }
    out
}

/// Expand `\t` to spaces on a 4-cell tab grid (the width `char_width` reports for the resulting
/// spaces matches what the terminal draws — a raw `\t` does not). Used before diff highlight/wrap.
fn expand_tabs(s: &str) -> String {
    let mut out = String::new();
    let mut col = 0usize;
    for c in s.chars() {
        if c == '\t' {
            let n = 4 - (col % 4);
            out.push_str(&" ".repeat(n));
            col += n;
        } else {
            out.push(c);
            col += crate::tui::char_width(c) as usize;
        }
    }
    out
}

fn fmt_dur(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::line_width;

    #[test]
    fn lang_for_path_reads_named_files_not_just_extensions() {
        // Extensionless build files are NAMED, so the basename table runs before the extension split.
        assert_eq!(lang_for_path("Makefile"), Some("make"));
        assert_eq!(lang_for_path("sub/dir/GNUmakefile"), Some("make"));
        assert_eq!(lang_for_path("docker/Dockerfile"), Some("dockerfile"));
        assert_eq!(lang_for_path("Containerfile"), Some("dockerfile"));
        assert_eq!(lang_for_path("Cargo.lock"), Some("toml"));
        // Named, but with no LangSpec behind the name: plain, never a near-neighbor guess.
        assert_eq!(lang_for_path("justfile"), None);
        assert_eq!(lang_for_path("CMakeLists.txt"), None);
        assert_eq!(lang_for_path(".gitignore"), None);
        // Extensions still win everywhere else.
        assert_eq!(lang_for_path("crates/cli/src/block.rs"), Some("rs"));
        assert_eq!(lang_for_path("a/b.py"), Some("py"));
        assert_eq!(lang_for_path("README"), None);
        assert_eq!(lang_for_path("dir.d/README"), None);
    }

    fn card(name: &str, args: serde_json::Value, status: ToolStatus, output: &str) -> Block {
        Block::new(
            1,
            BlockKind::Tool(ToolCard {
                name: name.into(),
                args,
                status,
                output: output.into(),
                diff: None,
                exit_code: None,
                started: Instant::now(),
                elapsed: Some(Duration::from_millis(120)),
                open: false,
            }),
        )
    }

    fn workflow_task(id: usize, label: &str, status: WorkflowTaskStatus) -> WorkflowTaskCard {
        WorkflowTaskCard {
            id,
            label: label.into(),
            status,
            started: None,
            elapsed: Some(Duration::from_millis(900)),
            turns: 2,
            tokens: 1_200,
            tool_calls: 3,
            turn_budget: 4,
            sub_run: Some(format!("fan-{id}")),
            activity: None,
            summary_preview: None,
            error_preview: None,
        }
    }

    fn plain(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn welcome_plantcore_icon_is_responsive_layered_and_cell_bounded() {
        let welcome = Block::new(
            0,
            BlockKind::Welcome {
                tagline: "type a task, or /help for shortcuts".into(),
            },
        );

        for theme in [Theme::dark(), Theme::light(), Theme::mono()] {
            for width in 0u16..=200 {
                let rows = welcome.render(width, &theme, 0);
                assert!(!rows.is_empty(), "welcome has a row at width {width}");
                for row in &rows {
                    assert!(
                        line_width(row) <= width,
                        "welcome row exceeded width {width}: {row:?}"
                    );
                    assert!(
                        row.spans.iter().all(|span| span.style.bg.is_none()),
                        "welcome never paints a background"
                    );
                }
            }
        }

        let theme = Theme::dark();
        let compact = plain(welcome.render(20, &theme, 0));
        assert!(compact.contains("iteron"));
        assert!(!compact.contains("(o)"));
        let wide = welcome.render(80, &theme, 0);
        assert_eq!(wide.len(), 6);
        let wide_text = plain(wide.clone());
        assert!(
            wide_text.contains("▄██"),
            "Plantcore icon planes: {wide_text:?}"
        );
        assert!(wide_text.contains("shortcuts"));

        let rendered = welcome.render(80, &theme, 0);
        let icon_spans = rendered
            .iter()
            .take(5)
            .flat_map(|line| line.spans.iter())
            .collect::<Vec<_>>();
        for plane in [theme.brand_back, theme.brand_mid, theme.brand_front] {
            assert!(
                icon_spans.iter().any(|span| span.style.fg == Some(plane)),
                "each public Plantcore icon plane keeps its brand token"
            );
        }
        assert!(
            icon_spans
                .iter()
                .filter(|span| span.style.fg.is_some())
                .all(|span| span.style.add_modifier.contains(Modifier::BOLD)),
            "icon cells remain dense at terminal scale"
        );
    }

    #[test]
    fn tool_card_humanizes_not_raw_json() {
        let theme = Theme::dark();
        let b = card(
            "bash",
            serde_json::json!({"command": "cargo test --workspace"}),
            ToolStatus::Ok,
            "",
        );
        let rows = b.render(80, &theme, 0);
        let text: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(text.contains("Bash"), "verb shown (TUI v3 §4 proper noun)");
        assert!(text.contains("cargo test"), "command humanized");
        assert!(!text.contains("{\""), "no raw JSON");
        // Status is the marker + connector, not a ✓/✗ dingbat (TUI v3 §4).
        assert!(text.contains('('), "verb(arg) form: Bash(cargo test …)");
        assert!(
            !text.contains('✓'),
            "no status dingbat — status is the marker color"
        );
    }

    #[test]
    fn tool_card_is_a_marker_connector_tree() {
        let theme = Theme::dark();
        // A completed Read: `⏺ Read(path)` primary line + `  ⎿  Read N lines` connector.
        let b = card(
            "read_file",
            serde_json::json!({"path": "src/main.rs"}),
            ToolStatus::Ok,
            "a\nb\nc\n",
        );
        let rows = b.render(80, &theme, 0);
        assert!(rows.len() >= 2, "primary + connector line");
        let first: String = rows[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        let second: String = rows[1]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            first.starts_with(super::primary_marker()),
            "primary line leads with the ⏺/● marker"
        );
        assert!(first.contains("Read(src/main.rs)"), "verb(arg): {first}");
        assert!(
            second.starts_with(super::CONNECTOR),
            "result line leads with the '  ⎿  ' connector: {second:?}"
        );
        assert!(
            second.contains("Read 3 lines"),
            "CC-style summary: {second}"
        );
        // The old ▎ rail is gone from the tree entirely.
        let all: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            !all.contains('▎'),
            "no legacy left rail in the connector tree"
        );
    }

    #[test]
    fn char_width_of_marker_and_connector_glyphs_is_one() {
        // The whole point of the platform switch: every glyph in the tree is a real width-1 cell, so
        // rows never overlap (the 乱码 bug). `⏺` is only emitted on macOS (where it is width-1).
        // Every structural glyph must remain one terminal cell.
        for g in ['●', '⎿', '✻', '✢', '✳', '✶', '✽', '·', '❯', '>'] {
            assert_eq!(crate::tui::char_width(g), 1, "{g:?} must draw as one cell");
        }
        // the marker this platform actually emits is width-1
        for c in super::primary_marker().chars() {
            assert_eq!(
                crate::tui::char_width(c),
                1,
                "primary marker glyph must be width-1"
            );
        }
        assert_eq!(
            super::CONNECTOR
                .chars()
                .map(crate::tui::char_width)
                .sum::<u16>(),
            5,
            "'  ⎿  ' is 5 cells"
        );
    }

    #[test]
    fn all_blocks_render_within_width() {
        let theme = Theme::dark();
        let blocks = vec![
            Block::new(
                1,
                BlockKind::User("fix the bug in the parser module please and thanks".into()),
            ),
            Block::new(
                2,
                BlockKind::Assistant(MarkdownDoc::parse(
                    "Here is **the** fix with `code` and a longer explanation that wraps around the width boundary nicely",
                )),
            ),
            card(
                "read_file",
                serde_json::json!({"path": "src/very/long/path/to/a/file.rs"}),
                ToolStatus::Running,
                "line one\nline two\nline three\nline four\nline five",
            ),
            Block::new(
                4,
                BlockKind::Thinking {
                    text: "let me think about this\nstep two\nstep three\nstep four".into(),
                    open: false,
                },
            ),
            Block::new(
                5,
                BlockKind::Error {
                    title: "build failed".into(),
                    detail: "error[E0001]: something".into(),
                    open: true,
                },
            ),
            Block::new(
                6,
                BlockKind::Notice {
                    level: NoticeLevel::Ok,
                    text: "model set to deepseek-chat".into(),
                },
            ),
            Block::new(
                7,
                BlockKind::Notice {
                    level: NoticeLevel::Err,
                    text: "fork failed: no such run".into(),
                },
            ),
            Block::new(
                9,
                BlockKind::Diff(iteron_protocol::FileDiff::from_replacement(
                    "src/a/very/long/path.rs",
                    "let x = 1;",
                    "let x = 2;\nlet y = 3;",
                )),
            ),
            Block::new(
                8,
                BlockKind::Panel {
                    title: "status".into(),
                    rows: vec![
                        PanelRow::KeyValue {
                            key: "model".into(),
                            value: "deepseek-chat".into(),
                        },
                        PanelRow::Item {
                            label: "one".into(),
                            hint: "a hint".into(),
                        },
                        PanelRow::Note("… 3 more".into()),
                    ],
                },
            ),
        ];
        for width in [8u16, 20, 40, 60, 80, 120, 160] {
            for b in &blocks {
                for row in b.render(width, &theme, 0) {
                    assert!(
                        line_width(&row) <= width,
                        "block row over width {width}: {row:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn diff_body_has_line_number_gutter_and_syntax_not_flat_color() {
        // Findings R1 (a line-number gutter — the biggest missing diff cue) and R2 (single-encode:
        // add/del carried by the sign + row tint, code text SYNTAX-highlighted, never a flat fg).
        let theme = Theme::dark();
        let d = iteron_protocol::FileDiff::from_replacement(
            "src/a.rs",
            "let x = 1;",
            "let y = 2;\nlet z = 3;",
        );
        let rows = Block::new(1, BlockKind::Diff(d)).render(80, &theme, 0);
        let text: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        // sequential old│new line-number gutter (from_replacement numbers from 1) + one sign cell each.
        assert!(
            text.contains('1') && text.contains('2'),
            "line-number gutter present: {text:?}"
        );
        assert!(
            text.contains("- ") && text.contains("+ "),
            "one dim sign cell per changed row: {text:?}"
        );
        // the `let` keyword takes the SYNTAX keyword color — proof the body is highlighted, not flat.
        let keyword_colored = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .any(|s| s.content.contains("let") && s.style.fg == Some(theme.syn_keyword));
        assert!(
            keyword_colored,
            "diff code text is syntax-highlighted (single-encode)"
        );
        // and NO code span is painted the flat added/removed fg (that would be the triple-encode bug).
        let flat = rows.iter().flat_map(|l| l.spans.iter()).any(|s| {
            (s.content.contains("let") || s.content.contains('='))
                && (s.style.fg == Some(theme.added) || s.style.fg == Some(theme.removed))
        });
        assert!(
            !flat,
            "add/del must not be triple-encoded via a per-line code fg"
        );
    }

    #[test]
    fn unknown_and_mcp_tools_humanize_no_snake_case_leak() {
        // The #1 toy tell: an unmatched tool leaking `⏺ Tool(page_id, properties)`. Now MCP/custom
        // tools read as a clean Title-case proper noun with NO arg (TUI v3 §4, findings 1/2).
        assert_eq!(verb_for("mcp__notion__API-post-search"), "Notion");
        assert_eq!(verb_for("mcp__lark__im_v1_message_create"), "Lark");
        assert_eq!(verb_for("create_pull_request"), "Create");
        assert_eq!(verb_for("bash"), "Bash"); // §4 proper-noun table
        let theme = Theme::dark();
        let b = card(
            "mcp__notion__API-patch-page",
            serde_json::json!({"page_id": "abc", "properties": {}}),
            ToolStatus::Ok,
            "",
        );
        let text: String = b
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(text.contains("Notion"), "humanized verb: {text:?}");
        assert!(
            !text.contains("page_id") && !text.contains("properties"),
            "no raw snake_case key leak: {text:?}"
        );
        assert!(
            !text.contains("Tool("),
            "no generic Tool(...) fallback: {text:?}"
        );
    }

    #[test]
    fn mcp_op_makes_read_vs_write_distinguishable() {
        // findings 8: the whole MCP surface collapsed to the bare server name — read (search) and
        // write (patch-page) both rendered `⏺ Notion`. Now the operation rides as the arg.
        let theme = Theme::dark();
        let render = |name: &str, args: serde_json::Value| -> String {
            card(name, args, ToolStatus::Ok, "")
                .render(80, &theme, 0)
                .iter()
                .flat_map(|l| l.spans.iter())
                .map(|s| s.content.to_string())
                .collect()
        };
        let read: String = render(
            "mcp__notion__API-post-search",
            serde_json::json!({"query": "x"}),
        );
        let write: String = render(
            "mcp__notion__API-patch-page",
            serde_json::json!({"page_id": "abc"}),
        );
        assert!(read.contains("Notion(search)"), "read op carried: {read:?}");
        assert!(
            write.contains("Notion(patch-page)"),
            "write op carried: {write:?}"
        );
        assert_ne!(
            read.contains("Notion(search)"),
            write.contains("Notion(search)"),
            "read != write"
        );
        // a snake_case MCP op keeps only its verb segment — no snake id leaks.
        let lark: String = render("mcp__lark__im_v1_message_create", serde_json::json!({}));
        assert!(
            lark.contains("Lark(create)"),
            "snake op reduced to verb: {lark:?}"
        );
        assert!(!lark.contains("im_v1"), "no snake_case leak: {lark:?}");
    }

    #[test]
    fn panel_and_thinking_ride_the_one_connector_grid() {
        // The single grid: panel rows AND the thinking body hang on the same `  ⎿  ` connector at
        // col 5 that tool/error use — never a second col-2 indent (TUI v3 §1, findings 3/4).
        let theme = Theme::dark();
        let panel = Block::new(
            1,
            BlockKind::Panel {
                title: "status".into(),
                rows: vec![PanelRow::KeyValue {
                    key: "model".into(),
                    value: "x".into(),
                }],
            },
        );
        let prows = panel.render(80, &theme, 0);
        assert!(
            prows[0]
                .spans
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>()
                .starts_with(super::primary_marker()),
            "panel header leads with ⏺/●"
        );
        assert!(
            prows[1]
                .spans
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>()
                .starts_with(super::CONNECTOR),
            "panel first row on the ⎿ connector"
        );
        let think = Block::new(
            2,
            BlockKind::Thinking {
                text: "reasoning line".into(),
                open: true,
            },
        );
        let trows = think.render(80, &theme, 0);
        let hdr: String = trows[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            hdr.starts_with(super::primary_marker()),
            "thinking header uses the ⏺/● marker, not ✻"
        );
        assert!(
            !hdr.contains('✻'),
            "✻ is reserved for the spinner (TUI v3 §2)"
        );
        assert!(
            trows[1]
                .spans
                .iter()
                .map(|s| s.content.to_string())
                .collect::<String>()
                .starts_with(super::CONNECTOR),
            "thinking body on the ⎿ connector"
        );
    }

    #[test]
    fn collapsed_reasoning_is_one_line_so_the_layout_never_jumps() {
        // opencode `index.tsx:1589-1590` keeps reasoning to ONE line, for the stated reason that a
        // single line makes the layout never jump. Reasoning STREAMS, so the replaced `min(3)` grew
        // the block 1→2→3 rows mid-thought and shoved the whole transcript below it twice.
        let theme = Theme::dark();
        let stream = [
            "I should read the parser first.",
            "Then I will check the lexer.",
            "Finally run the tests.",
        ];
        let heights: Vec<usize> = (1..=stream.len())
            .map(|n| {
                Block::new(
                    1,
                    BlockKind::Thinking {
                        text: stream[..n].join("\n"),
                        open: false,
                    },
                )
                .render(80, &theme, 0)
                .len()
            })
            .collect();
        assert_eq!(
            heights,
            vec![2, 2, 2],
            "header + exactly ONE body row at every streamed length: {heights:?}"
        );

        let grown = Block::new(
            1,
            BlockKind::Thinking {
                text: stream.join("\n"),
                open: false,
            },
        );
        let text: String = grown
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            text.contains("I should read the parser first…"),
            "the one line is the first sentence, elided: {text:?}"
        );
        assert!(
            !text.contains("lexer"),
            "later reasoning is not rendered while collapsed: {text:?}"
        );

        // Expanded is unchanged: every line.
        let open = Block::new(
            2,
            BlockKind::Thinking {
                text: stream.join("\n"),
                open: true,
            },
        );
        let open_text: String = open
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(open_text.contains("lexer") && open_text.contains("Finally run the tests"));
    }

    #[test]
    fn diff_gutter_has_bar_and_default_theme_colors_the_sign() {
        // §5: the twin line-number columns read as old│new (a faint bar), not an ambiguous `12 12`.
        let dark = Theme::dark();
        let d = iteron_protocol::FileDiff::from_replacement("a.rs", "let x = 1;", "let x = 2;");
        let rows = Block::new(1, BlockKind::Diff(d)).render(80, &dark, 0);
        assert!(
            rows.iter()
                .flat_map(|l| l.spans.iter())
                .any(|s| s.content.contains('│')),
            "old│new bar separator present"
        );
        // In the DEFAULT terminal theme (added_bg/removed_bg = Reset, no visible tint) the sign cell
        // must fall back to green/red so the diff isn't two identical grey blocks (findings 7/8).
        let term = Theme::terminal();
        let d2 = iteron_protocol::FileDiff::from_replacement("a.rs", "let x = 1;", "let x = 2;");
        let rows2 = Block::new(1, BlockKind::Diff(d2)).render(80, &term, 0);
        // (wrap_spans merges the adjacent same-style number+sign, so match on `contains`, not `starts_with`.)
        let add_sign_colored = rows2
            .iter()
            .flat_map(|l| l.spans.iter())
            .any(|s| s.content.contains('+') && s.style.fg == Some(term.added));
        let del_sign_colored = rows2
            .iter()
            .flat_map(|l| l.spans.iter())
            .any(|s| s.content.contains('-') && s.style.fg == Some(term.removed));
        assert!(
            add_sign_colored,
            "default-theme + sign is green (tint invisible)"
        );
        assert!(
            del_sign_colored,
            "default-theme - sign is red (tint invisible)"
        );
    }

    /// Rendered rows of one block as plain strings, indent preserved.
    fn row_texts(b: &Block, width: u16, theme: &Theme) -> Vec<String> {
        b.render(width, theme, 0)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.to_string()).collect())
            .collect()
    }

    /// The tail rows of a tool card: the ones hanging at the col-5 indent (NOT the `  ⎿  `
    /// connector, which carries the hoisted summary).
    fn tail_rows(b: &Block, width: u16, theme: &Theme) -> Vec<String> {
        row_texts(b, width, theme)
            .into_iter()
            .filter(|t| t.starts_with("     ") && !t.trim().is_empty())
            .collect()
    }

    #[test]
    fn collapsed_tool_shows_a_fixed_head_and_tail_not_a_width_ladder() {
        // The budget is CONTENT-shaped, not window-shaped: 5 rows (codex `exec_cell/render.rs:695-700`
        // shows 5 lines of command output), rendered as first 2 · elision · last 2 so the operator can
        // see that a command started AND how it ended. The replaced `width<60 →1 / <100 →2 / else 3`
        // ladder rendered the same run three different ways depending on the pane.
        let theme = Theme::dark();
        let out: String = (0..20)
            .map(|i| format!("row {i:02}"))
            .collect::<Vec<_>>()
            .join("\n");
        let b = card(
            "bash",
            serde_json::json!({"command": "ls"}),
            ToolStatus::Ok,
            &out,
        );
        let rows = tail_rows(&b, 80, &theme);
        let joined = rows.join("\n");
        // `row 00` is hoisted onto the connector, so the tail is rows 01..=19 (19 rows).
        assert_eq!(
            rows.len(),
            5,
            "2 head + elision + 2 tail = 5 rows: {joined:?}"
        );
        assert!(
            rows[0].contains("row 01") && rows[1].contains("row 02"),
            "head is the FIRST rows of the tail: {joined:?}"
        );
        assert!(
            rows[2].contains("… 15 more rows (ctrl+o to expand)"),
            "the elision line sits BETWEEN head and tail and counts what is hidden: {joined:?}"
        );
        assert!(
            rows[3].contains("row 18") && rows[4].contains("row 19"),
            "tail is the LAST rows — 'it failed at the end' has to be visible: {joined:?}"
        );
        assert!(
            !joined.contains("row 10"),
            "the middle is elided, not rendered: {joined:?}"
        );

        // Width-independent: same shape in a narrow pane and a wide one.
        for width in [60u16, 80, 120, 160] {
            assert_eq!(
                tail_rows(&b, width, &theme).len(),
                5,
                "tail budget must not move with the terminal width ({width})"
            );
        }
    }

    #[test]
    fn a_tail_within_the_budget_renders_whole_with_no_elision_line() {
        let theme = Theme::dark();
        // 4 output lines → 1 hoisted onto the connector + a 3-row tail, inside the 5-row budget.
        let b = card(
            "bash",
            serde_json::json!({"command": "ls"}),
            ToolStatus::Ok,
            "first\nsecond\nthird\nfourth",
        );
        let rows = tail_rows(&b, 80, &theme);
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(
            !rows.iter().any(|r| r.contains("more rows")),
            "nothing is hidden, so no elision line is drawn: {rows:?}"
        );
    }

    #[test]
    fn unknown_tool_output_gets_a_smaller_budget_than_a_known_one() {
        // opencode `index.tsx:1811-1813` renders an UNKNOWN tool's output with a smaller budget than a
        // known one. `mcp__…` is not in the known-tool label mapping, so it earns 3 rows, not 5.
        let theme = Theme::dark();
        let out: String = (0..12)
            .map(|i| format!("row {i:02}"))
            .collect::<Vec<_>>()
            .join("\n");
        let known = card(
            "bash",
            serde_json::json!({"command": "ls"}),
            ToolStatus::Ok,
            &out,
        );
        let unknown = card(
            "mcp__notion__API-post-search",
            serde_json::json!({"query": "x"}),
            ToolStatus::Ok,
            &out,
        );
        assert!(super::is_unknown_tool("mcp__notion__API-post-search"));
        assert!(!super::is_unknown_tool("bash"));
        // both counts include the one elision row: 2+…+2 vs 1+…+1
        assert_eq!(tail_rows(&known, 80, &theme).len(), 5);
        assert_eq!(tail_rows(&unknown, 80, &theme).len(), 3);
    }

    #[test]
    fn tail_char_budget_is_counted_in_characters_not_bytes() {
        // opencode `util/collapse-tool-output.ts:1-19` caps the tail at `maxLines × max(20,
        // contentWidth − 6)` computed with `Array.from(...)` — CHARACTERS. Ten CJK characters are 30
        // bytes; counting bytes would have thrown away rows a reader can plainly see.
        let ten_chars = "四字节汉字十个字符啊";
        assert_eq!(ten_chars.chars().count(), 10);
        assert_eq!(ten_chars.len(), 30);
        let rows: Vec<Line<'static>> = (0..4).map(|_| Line::from(Span::raw(ten_chars))).collect();
        // 4 rows are inside the 5-row budget but over a 30-char budget, so the window shrinks to the
        // 3 rows that fit (2 head + 1 tail). Under byte counting even ONE row would have been over.
        assert_eq!(super::tool_tail_window(&rows, 5, 30), (2, 1));
        // Inside both budgets → everything, and `head + tail == rows.len()` means no elision line.
        assert_eq!(super::tool_tail_window(&rows[..2], 5, 100), (2, 0));
    }

    fn card_diff(name: &str, diff: FileDiff) -> Block {
        Block::new(
            1,
            BlockKind::Tool(ToolCard {
                name: name.into(),
                args: serde_json::json!({"path": diff.path.clone()}),
                status: ToolStatus::Ok,
                output: String::new(),
                diff: Some(diff),
                exit_code: None,
                started: Instant::now(),
                elapsed: None,
                open: false,
            }),
        )
    }

    #[test]
    fn generic_tool_hoists_first_output_line_not_a_redundant_count() {
        // findings 1: a multi-line Bash result must put its FIRST output line on the `⎿` connector (the
        // row the eye lands on) and render the rest as the tail — NOT a redundant `3 lines` count that
        // then repeats below. The count is reserved for Read/Search/List.
        let theme = Theme::dark();
        let b = card(
            "bash",
            serde_json::json!({"command": "cargo test"}),
            ToolStatus::Ok,
            "running 42 tests\nok foo\nok bar",
        );
        let rows = b.render(80, &theme, 0);
        let connector = rows
            .iter()
            .find(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
                    .starts_with(super::CONNECTOR)
            })
            .expect("a ⎿ line");
        let ctext: String = connector
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            ctext.contains("running 42 tests"),
            "first output line hoisted onto the connector: {ctext:?}"
        );
        assert!(
            !ctext.contains("3 lines") && !ctext.contains("3 line"),
            "no redundant count on the connector: {ctext:?}"
        );
        let all: String = rows
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            all.contains("ok foo") && all.contains("ok bar"),
            "tail lines[1..] still rendered: {all:?}"
        );
        // the hoisted line must NOT be duplicated in the tail
        assert_eq!(
            all.matches("running 42 tests").count(),
            1,
            "hoisted line not duplicated in the tail"
        );
    }

    #[test]
    fn running_tool_has_no_running_summary_line() {
        // findings 7: while running, the spinner marker is the whole liveness signal — no `⎿ running…`.
        let theme = Theme::dark();
        let b = card(
            "bash",
            serde_json::json!({"command": "sleep 1"}),
            ToolStatus::Running,
            "",
        );
        let all: String = b
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            !all.contains("running…"),
            "no literal running… on the connector: {all:?}"
        );
        assert!(
            !all.contains(super::CONNECTOR),
            "a running tool shows only the primary line: {all:?}"
        );
    }

    #[test]
    fn write_vs_edit_summary_and_arg_recedes() {
        // findings 7: a from-empty Write says `Wrote … (N lines)`, never `Updated … with N additions and
        // 0 removals`; an Edit says `Updated …`. And the (arg) recedes to muted while the verb stays bold.
        let theme = Theme::dark();
        let wrote = card_diff(
            "write",
            FileDiff::from_replacement("src/new.rs", "", "a\nb\nc"),
        );
        let wtext: String = wrote
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            wtext.contains("Wrote new.rs"),
            "write branches to Wrote: {wtext:?}"
        );
        assert!(
            !wtext.contains("removal"),
            "a Write does not claim `0 removals`: {wtext:?}"
        );
        let edited = card_diff("edit", FileDiff::from_replacement("src/x.rs", "old", "new"));
        let etext: String = edited
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            etext.contains("Updated x.rs") && etext.contains("removal"),
            "edit branches to Updated: {etext:?}"
        );
        // The verb is bold while the argument is semantic and regular — the title isn't an all-bold
        // wall, and a path keeps the same role here that it has in panels and notices.
        let rows = edited.render(80, &theme, 0);
        let arg_span = rows[0]
            .spans
            .iter()
            .find(|s| s.content.contains("x.rs"))
            .expect("a semantic argument span");
        assert!(
            !arg_span.style.add_modifier.contains(Modifier::BOLD),
            "argument recedes (not bold)"
        );
        assert_eq!(
            arg_span.style.fg,
            Some(theme.syn_type),
            "path arguments use the shared path token"
        );
        let verb_span = &rows[0]
            .spans
            .iter()
            .find(|s| s.content == "Edit")
            .expect("a verb span");
        assert!(
            verb_span.style.add_modifier.contains(Modifier::BOLD),
            "the verb stays bold"
        );
    }

    #[test]
    fn inline_edit_diff_suppresses_at_header_but_standalone_keeps_it() {
        // findings 2: an inline tool-result diff omits the `@@ …` hunk header (a git machine tell CC
        // hides); a standalone `/diff` viewer keeps it.
        let theme = Theme::dark();
        let inline = card_diff(
            "edit",
            FileDiff::from_replacement("a.rs", "let x = 1;", "let x = 2;"),
        );
        let itext: String = inline
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            !itext.contains("@@"),
            "inline edit diff suppresses the @@ header: {itext:?}"
        );
        let standalone = Block::new(
            1,
            BlockKind::Diff(FileDiff::from_replacement(
                "a.rs",
                "let x = 1;",
                "let x = 2;",
            )),
        );
        let stext: String = standalone
            .render(80, &theme, 0)
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            stext.contains("@@"),
            "standalone /diff keeps the @@ header: {stext:?}"
        );
    }

    #[test]
    fn wrapped_diff_line_hangs_under_the_code_column() {
        // findings 5: a long diff line that wraps must hang under the CODE column (gutter width in
        // spaces), not fall back to the col-5 line-number gutter.
        let theme = Theme::dark();
        let long =
            "let very_long_identifier = another_long_identifier + yet_another_one + and_more;";
        let d = FileDiff::from_replacement("a.rs", "x", long);
        let rows = Block::new(1, BlockKind::Diff(d)).render(40, &theme, 0);
        // gutter width for a 1-2 digit diff: 2*gw + 4. gw here is 1 → 6; code column = 5 + 6 = 11. A
        // continuation row hangs under the code column: ≥ 11 leading spaces and NO `│` gutter bar (the
        // bar only appears on the sign-bearing first row of a diff line).
        let saw_continuation = rows.iter().any(|l| {
            let full: String = l.spans.iter().map(|s| s.content.to_string()).collect();
            let text = &full;
            let leading = text.chars().take_while(|c| *c == ' ').count();
            !text.trim().is_empty() && leading >= 11 && !text.contains('│')
        });
        assert!(
            saw_continuation,
            "wrapped code hangs under the code column (≥11 leading spaces, no gutter bar)"
        );
    }

    #[test]
    fn markdown_rule_is_full_width() {
        let theme = Theme::dark();
        for w in [40u16, 80, 100] {
            let rows = super::rule_line(w, &theme);
            assert_eq!(line_width(&rows[0]), w, "rule spans full width {w}");
        }
    }

    #[test]
    fn panel_item_has_no_redundant_bullet() {
        // findings 4: a panel Item rides the ⎿ connector directly; a second `• ` marker (col 7) is gone.
        let theme = Theme::dark();
        let panel = Block::new(
            1,
            BlockKind::Panel {
                title: "help".into(),
                rows: vec![PanelRow::Item {
                    label: "explain".into(),
                    hint: "a hint".into(),
                }],
            },
        );
        let rows = panel.render(80, &theme, 0);
        let item: String = rows[1]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            item.starts_with(super::CONNECTOR),
            "item on the ⎿ connector: {item:?}"
        );
        assert!(
            !item.contains("• "),
            "no redundant per-item bullet: {item:?}"
        );
        assert!(
            item.contains("explain"),
            "label rides the connector directly: {item:?}"
        );
    }

    fn errored_card() -> Block {
        Block::new(
            1,
            BlockKind::Tool(ToolCard {
                name: "bash".into(),
                args: serde_json::json!({"command": "false"}),
                status: ToolStatus::Err,
                output: "boom".into(),
                diff: None,
                exit_code: Some(1),
                started: Instant::now(),
                elapsed: Some(Duration::from_millis(5)),
                open: false,
            }),
        )
    }

    #[test]
    fn machine_blocks_use_one_status_marker_without_a_second_rail() {
        let theme = Theme::dark();
        let marker = |b: &Block| b.render(80, &theme, 0)[0].spans[0].clone();
        // Settled work recedes instead of building a green wall.
        let ok = card(
            "bash",
            serde_json::json!({"command": "ls"}),
            ToolStatus::Ok,
            "one\ntwo",
        );
        assert_eq!(marker(&ok).style.fg, Some(theme.faint));
        // running → accent
        let run = card(
            "bash",
            serde_json::json!({"command": "sleep 1"}),
            ToolStatus::Running,
            "",
        );
        assert_eq!(
            marker(&run).style.fg,
            Some(theme.accent),
            "running tool marker is accent"
        );
        // error / non-zero exit → red
        assert_eq!(
            marker(&errored_card()).style.fg,
            Some(theme.error),
            "errored tool marker is red"
        );
        // error block → red
        let eb = Block::new(
            2,
            BlockKind::Error {
                title: "build failed".into(),
                detail: "e".into(),
                open: true,
            },
        );
        assert_eq!(
            marker(&eb).style.fg,
            Some(theme.error),
            "error marker is red"
        );
        // notice → its level color (warn here)
        let nb = Block::new(
            3,
            BlockKind::Notice {
                level: NoticeLevel::Warn,
                text: "heads up".into(),
            },
        );
        assert_eq!(
            marker(&nb).style.fg,
            Some(theme.warn),
            "notice marker is its level color"
        );
        let ni = Block::new(
            3,
            BlockKind::Notice {
                level: NoticeLevel::Info,
                text: "fyi".into(),
            },
        );
        assert_eq!(
            marker(&ni).style.fg,
            Some(theme.faint),
            "informational marker recedes"
        );
        // panel + diff → accent
        let pb = Block::new(
            4,
            BlockKind::Panel {
                title: "status".into(),
                rows: vec![PanelRow::Note("x".into())],
            },
        );
        assert_eq!(
            marker(&pb).style.fg,
            Some(theme.accent),
            "panel marker is accent"
        );
        let db = Block::new(
            5,
            BlockKind::Diff(FileDiff::from_replacement("a.rs", "x", "y")),
        );
        assert_eq!(
            marker(&db).style.fg,
            Some(theme.accent),
            "diff marker is accent"
        );
        // thinking → muted (present but calm)
        let tb = Block::new(
            6,
            BlockKind::Thinking {
                text: "hmm".into(),
                open: true,
            },
        );
        assert_eq!(
            marker(&tb).style.fg,
            Some(theme.muted),
            "thinking marker is muted"
        );
        // Assistant is open prose; the user retains one compact prompt marker and row surface.
        let ab = Block::new(7, BlockKind::Assistant(MarkdownDoc::parse("hello world")));
        let ar = ab.render(80, &theme, 0);
        let assistant: String = ar[0]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!assistant.contains('┃'));
        assert_eq!(assistant, "● hello world");
        assert!(!assistant.starts_with("CORE  "));
        let ub = Block::new(8, BlockKind::User("do the thing".into()));
        let user_rows = ub.render(80, &theme, 0);
        assert_eq!(user_rows.len(), 3, "padding + prompt + padding");
        assert_eq!(user_rows[1].spans[0].content, "› ");
        assert!(!plain(user_rows.clone()).contains("YOU"));
        assert!(user_rows.iter().all(|row| line_width(row) == 80));
        assert!(
            user_rows
                .iter()
                .flat_map(|row| row.spans.iter())
                .all(|span| span.style.bg == Some(theme.user_bg)),
            "every cell of an operator message belongs to the prompt surface"
        );
    }

    #[test]
    fn submitted_prompt_history_is_a_wrapped_full_width_gray_band() {
        let message = concat!(
            "BEGIN inspect the parser and preserve every explicit detail across wrapping ",
            "中文 🙂 e\u{301} then verify the final behavior without truncating END"
        );
        let user = Block::new(9, BlockKind::User(message.into()));

        for width in [16u16, 30, 40, 80] {
            for theme in [
                Theme::terminal(),
                Theme::dark(),
                Theme::light(),
                Theme::high_contrast(),
            ] {
                let rows = user.render(width, &theme, 0);
                assert!(rows.len() > 3, "long prompt wraps at {width} cells");
                assert!(rows.iter().all(|row| line_width(row) == width));
                assert!(
                    rows.iter()
                        .flat_map(|row| row.spans.iter())
                        .all(|span| span.style.bg == Some(theme.user_bg)),
                    "marker, body, continuation, padding, and right fill share one gray surface"
                );
                assert!(
                    rows.first()
                        .is_some_and(|row| plain(vec![row.clone()]).trim().is_empty())
                );
                assert!(
                    rows.last()
                        .is_some_and(|row| plain(vec![row.clone()]).trim().is_empty())
                );
                assert_eq!(rows[1].spans[0].content, "› ");
                for row in rows.iter().skip(2).take(rows.len().saturating_sub(3)) {
                    assert_eq!(row.spans[0].content, "  ");
                }
                let text = plain(rows);
                assert!(text.contains("BEGIN") && text.contains("END"));
                assert!(!text.contains("YOU"));

                let assistant = Block::new(
                    10,
                    BlockKind::Assistant(MarkdownDoc::parse("assistant stays open")),
                )
                .render(width, &theme, 0);
                assert!(
                    assistant
                        .iter()
                        .flat_map(|row| row.spans.iter())
                        .all(|span| span.style.bg != Some(theme.user_bg))
                );
            }

            let mono = user.render(width, &Theme::mono(), 0);
            assert!(mono.iter().all(|row| line_width(row) == width));
            assert!(mono.iter().flat_map(|row| row.spans.iter()).all(|span| {
                span.style.bg.is_none() && span.style.add_modifier.contains(Modifier::REVERSED)
            }));
            assert_eq!(mono[1].spans[0].content, "› ");
            assert!(mono[1].spans[0].style.add_modifier.contains(Modifier::BOLD));
            let text = plain(mono);
            assert!(text.contains("BEGIN") && text.contains("END"));
        }
    }

    #[test]
    fn settled_ok_marker_recedes_while_error_remains_strong() {
        let theme = Theme::dark();
        let ok = card(
            "bash",
            serde_json::json!({"command": "ls"}),
            ToolStatus::Ok,
            "done",
        );
        let m = &ok.render(80, &theme, 0)[0].spans[0];
        assert!(
            m.content.starts_with(super::primary_marker()),
            "the marker leads the line: {:?}",
            m.content
        );
        assert_eq!(m.style.fg, Some(theme.faint), "settled OK marker is quiet");
        let err = errored_card();
        let em = &err.render(80, &theme, 0)[0].spans[0];
        assert_eq!(em.style.fg, Some(theme.error), "errored marker is red");
    }

    #[test]
    fn empty_tool_error_says_failed_even_without_color() {
        let failed = ToolCard {
            name: "custom_tool".into(),
            args: serde_json::Value::Null,
            status: ToolStatus::Err,
            output: String::new(),
            diff: None,
            exit_code: None,
            started: Instant::now(),
            elapsed: Some(Duration::ZERO),
            open: false,
        };
        let block = Block::new(99, BlockKind::Tool(failed));
        let text = block
            .render(80, &Theme::mono(), 0)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("failed"));
        assert!(!text.contains("done"));

        let ok = Block::new(
            100,
            BlockKind::Tool(ToolCard {
                name: "custom_tool".into(),
                args: serde_json::Value::Null,
                status: ToolStatus::Ok,
                output: String::new(),
                diff: None,
                exit_code: None,
                started: Instant::now(),
                elapsed: Some(Duration::ZERO),
                open: false,
            }),
        );
        let ok_text = ok
            .render(80, &Theme::mono(), 0)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(ok_text.contains("done"));
    }

    #[test]
    fn marker_connector_rows_stay_within_width() {
        let theme = Theme::dark();
        let blocks = vec![
            card(
                "bash",
                serde_json::json!({"command": "a very long command that certainly wraps across the terminal"}),
                ToolStatus::Ok,
                "some output line one\nline two\nline three",
            ),
            errored_card(),
            Block::new(
                2,
                BlockKind::Diff(FileDiff::from_replacement(
                    "src/some/very/long/path/module.rs",
                    "let x = 1;",
                    "let extremely_long_identifier_name = 2;\nlet y = 3;",
                )),
            ),
        ];
        for width in [8u16, 20, 40, 60, 80, 120, 160] {
            for b in &blocks {
                for row in b.render(width, &theme, 0) {
                    assert!(
                        line_width(&row) <= width,
                        "machine row over width {width}: {row:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn workflow_card_is_a_truthful_bounded_live_tree() {
        let theme = Theme::dark();
        let workflow = Block::new(
            9,
            BlockKind::Workflow(WorkflowCard {
                run_id: "workflow-7".into(),
                name: "ultracode".into(),
                class: "multi-file".into(),
                status: WorkflowStatus::Exploring,
                tasks: vec![
                    WorkflowTaskCard {
                        id: 0,
                        label: "inspect the runtime lifecycle".into(),
                        status: WorkflowTaskStatus::Done,
                        started: None,
                        elapsed: Some(Duration::from_millis(820)),
                        turns: 2,
                        tokens: 1_240,
                        tool_calls: 3,
                        turn_budget: 4,
                        sub_run: Some("fan-0".into()),
                        activity: None,
                        summary_preview: Some("runtime ownership is in kernel.rs:42".into()),
                        error_preview: None,
                    },
                    WorkflowTaskCard {
                        id: 1,
                        label: "compare the terminal interaction model".into(),
                        status: WorkflowTaskStatus::Running,
                        started: Some(Instant::now()),
                        elapsed: None,
                        turns: 0,
                        tokens: 0,
                        tool_calls: 0,
                        turn_budget: 3,
                        sub_run: Some("fan-1".into()),
                        activity: Some("read_file · crates/cli/src/tui.rs".into()),
                        summary_preview: None,
                        error_preview: None,
                    },
                    WorkflowTaskCard {
                        id: 2,
                        label: "audit recovery behavior".into(),
                        status: WorkflowTaskStatus::Queued,
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
                    },
                ],
                dropped: 1,
                duplicates_removed: 1,
                invalid_removed: 0,
                execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 10,
                writer_turn_reserve: 39,
                fan_wall_secs: 180,
                writer_wall_reserve_secs: 360,
                started: Instant::now(),
                elapsed: None,
                reason: None,
                provider_attempts: 3,
                turns: 3,
                tokens: 1_240,
                tool_calls: 3,
                failed_tasks: 0,
                skipped_tasks: 0,
                open: true,
            }),
        );
        for width in [16u16, 24, 40, 60, 80, 120, 160] {
            let rows = workflow.render(width, &theme, 3);
            for row in &rows {
                assert!(
                    line_width(row) <= width,
                    "workflow row exceeded width {width}: {row:?}"
                );
            }
        }
        let rendered = workflow
            .render(100, &theme, 3)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("exploring"));
        // The running investigator keeps its own row (and its live tool line) instead of being
        // hoisted into a single NOW line that hid every other running worker.
        assert!(rendered.contains("compare the terminal interaction model"));
        assert!(rendered.contains("read_file"));
        assert!(rendered.contains("queued"));
        assert!(rendered.contains("1.2k tok"));
        assert!(rendered.contains("omitted by the fan limit"));
    }

    #[test]
    fn workflow_partial_and_narrow_views_keep_failure_evidence() {
        let theme = Theme::dark();
        let mut done = workflow_task(0, "map provider ownership", WorkflowTaskStatus::Done);
        done.summary_preview = Some("provider registry is owned by providers.rs:88".into());
        let mut failed = workflow_task(1, "inspect model availability", WorkflowTaskStatus::Failed);
        failed.error_preview = Some("provider timed out before evidence was produced".into());
        let queued = workflow_task(
            2,
            "audit verification coverage",
            WorkflowTaskStatus::NotStarted,
        );
        let workflow = Block::new(
            10,
            BlockKind::Workflow(WorkflowCard {
                run_id: "workflow-partial".into(),
                name: "ultracode".into(),
                class: "multi-file".into(),
                status: WorkflowStatus::Degraded,
                tasks: vec![done, failed, queued],
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: crate::runtime::WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 8,
                writer_turn_reserve: 24,
                fan_wall_secs: 120,
                writer_wall_reserve_secs: 240,
                started: Instant::now(),
                elapsed: Some(Duration::from_secs(18)),
                reason: Some("writer completed with partial investigation coverage".into()),
                provider_attempts: 5,
                turns: 4,
                tokens: 4_800,
                tool_calls: 7,
                failed_tasks: 1,
                skipped_tasks: 1,
                open: true,
            }),
        );
        for width in [40u16, 59, 60, 99, 100] {
            let lines = workflow.render(width, &theme, 0);
            assert!(lines.iter().all(|line| line_width(line) <= width));
            let text = plain(lines);
            assert!(text.contains("partial"));
            assert!(text.contains("provider timed out"));
            assert!(text.contains("not started"));
            assert!(!text.contains("parallel"));
        }
        let narrow = plain(workflow.render(40, &theme, 0));
        assert!(narrow.contains("Ultracode · partial"));
        assert!(narrow.contains("failed"));
    }

    /// The fan is bounded-concurrent: four investigators run at once. The card used to hoist the
    /// FIRST running task onto a `NOW` line and then filter every running task out of the branch
    /// list, so three of the four vanished and the per-row spinner arm was unreachable. Pin the
    /// four-running snapshot: four rows, four live spinner arms, and a header that agrees.
    #[test]
    fn workflow_card_renders_every_concurrent_investigator() {
        let theme = Theme::dark();
        let labels = [
            "map provider ownership",
            "trace the rollout writer",
            "audit the permission gate",
            "inspect verification coverage",
        ];
        let tasks = labels
            .iter()
            .enumerate()
            .map(|(id, label)| {
                let mut task = workflow_task(id, label, WorkflowTaskStatus::Running);
                task.started = Some(Instant::now());
                task.elapsed = None;
                task.activity = Some(format!("read_file · crates/{id}/lib.rs"));
                task
            })
            .collect::<Vec<_>>();
        let workflow = Block::new(
            11,
            BlockKind::Workflow(WorkflowCard {
                run_id: "workflow-concurrent".into(),
                name: "ultracode".into(),
                class: "multi-file".into(),
                status: WorkflowStatus::Exploring,
                tasks,
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: crate::runtime::WorkflowExecutionModeUi::Concurrent,
                fan_turn_budget: 8,
                writer_turn_reserve: 24,
                fan_wall_secs: 120,
                writer_wall_reserve_secs: 240,
                started: Instant::now(),
                elapsed: None,
                reason: None,
                provider_attempts: 1,
                turns: 0,
                tokens: 0,
                tool_calls: 0,
                failed_tasks: 0,
                skipped_tasks: 0,
                open: true,
            }),
        );

        let spin = 3usize;
        let arm = spinner()[spin % spinner().len()];
        let text = plain(workflow.render(120, &theme, spin));
        for label in labels {
            assert!(
                text.contains(label),
                "row for `{label}` is missing:\n{text}"
            );
        }
        // One arm per branch row (the card's own header marker also spins, hence the `+ 1`).
        assert_eq!(
            text.matches(arm).count(),
            labels.len() + 1,
            "every concurrent investigator needs its own live spinner arm:\n{text}"
        );
        assert_eq!(
            text.matches(" · running").count(),
            labels.len(),
            "every concurrent investigator must render as a running row:\n{text}"
        );
        // The done/total header still agrees with the row count.
        assert!(text.contains(&format!("0/{}", labels.len())));
        assert!(text.contains("concurrent"));
        // Each running row keeps its own live tool line (the old NOW line kept only the first).
        assert_eq!(text.matches("read_file · crates/").count(), labels.len());
        assert!(!text.contains("NOW"));

        for width in [16u16, 24, 40, 60, 80, 120, 160] {
            for row in workflow.render(width, &theme, spin) {
                assert!(
                    line_width(&row) <= width,
                    "concurrent workflow row exceeded width {width}: {row:?}"
                );
            }
        }
    }

    /// Drive a scripted `ProgressEvent` stream (2 phases, 3 agents, mixed running/done/error + a log
    /// line) through the QuickJS-workflow card and assert the design §3.3 phase-box tree renders.
    /// Prints the captured ASCII (run with `--nocapture` to see the actual look).
    #[test]
    fn workflow_run_tree_renders_phase_boxes() {
        use iteron_workflow::events::WorkflowState;

        let theme = Theme::dark();
        let mut c = WorkflowRunCard::new("wf_demo", "audit");
        c.ingest(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        c.ingest(ProgressEvent::Log {
            message: "mapping the repository".into(),
        });
        c.ingest(ProgressEvent::AgentStarted {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: Some("haiku".into()),
            queued_ms: 0,
            available_permits: 0,
        });
        c.ingest(ProgressEvent::AgentActivity {
            index: 0,
            tokens: 1_234,
            tool_calls: 3,
            last_tool_summary: Some("rg \"fn main\"".into()),
        });
        c.ingest(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan modules".into(),
            state: WorkflowState::Done,
            tokens: 1_234,
            tool_calls: 3,
            duration_ms: 3_200,
            result_preview: None,
            last_tool_summary: Some("rg \"fn main\"".into()),
            error: None,
        });
        c.ingest(ProgressEvent::AgentStarted {
            index: 1,
            label: "probe API".into(),
            phase: Some("Explore".into()),
            model: Some("haiku".into()),
            queued_ms: 0,
            available_permits: 0,
        });
        c.ingest(ProgressEvent::Log {
            message: "synthesizing findings".into(),
        });
        c.ingest(ProgressEvent::Phase {
            index: 2,
            title: "Synthesize".into(),
        });
        c.ingest(ProgressEvent::AgentStarted {
            index: 2,
            label: "merge report".into(),
            phase: Some("Synthesize".into()),
            model: Some("sonnet".into()),
            queued_ms: 0,
            available_permits: 0,
        });
        c.ingest(ProgressEvent::AgentFinished {
            index: 2,
            label: "merge report".into(),
            state: WorkflowState::Error,
            tokens: 800,
            tool_calls: 0,
            duration_ms: 5_000,
            result_preview: None,
            last_tool_summary: None,
            error: Some("provider timeout".into()),
        });

        let width = 100u16;
        let collapsed = plain(render_workflow_run(&c, width, &theme, 0));
        assert!(collapsed.contains("audit \u{b7} Synthesize \u{b7} 1/3 \u{b7} 1 failed"));
        assert!(collapsed.contains("ctrl+o expand"));
        assert!(!collapsed.contains("scan modules"));

        c.verbose = true;
        let lines = render_workflow_run(&c, width, &theme, 0);
        // Every rendered row fits the width (padded box lines land exactly at the border).
        for line in &lines {
            assert!(
                line_width(line) <= width,
                "workflow-run row exceeded width: {line:?}"
            );
        }
        let text = plain(lines);
        println!("\n===== workflow-run tree (width {width}) =====\n{text}\n=====");

        // Header (name · run-level progress · run id) + run totals line.
        assert!(text.contains("audit \u{b7} Synthesize \u{b7} 1/3 \u{b7} 1 failed"));
        assert!(text.contains("wf_demo"));
        assert!(text.contains("1/3 agents \u{b7} 1 failed \u{b7} 2k tok \u{b7} 3 tool calls"));
        // Narrator + phase boxes + rows + collapse + meta + error tail.
        assert!(text.contains("\u{276f} synthesizing findings")); // ❯ newest log
        assert!(text.contains("mapping the repository")); // prior log, dim
        assert!(text.contains("\u{256d}") && text.contains("\u{256f}")); // box corners
        assert!(text.contains("Explore") && text.contains("Synthesize"));
        assert!(text.contains("1/2") && text.contains("0/1"));
        assert!(text.contains("\u{b7} haiku")); // shared model in the Explore header
        assert!(text.contains("1 failed"));
        assert!(text.contains("✔ scan modules"));
        assert!(text.contains("probe API"));
        assert!(text.contains("merge report"));
        assert!(text.contains("800 tok") && text.contains("5s"));
        assert!(text.contains("\u{2014} provider timeout")); // — <error> tail
        assert!(text.contains("\u{2193}")); // ↓ phase separator

        // Expanded tree reveals the finished agent as a real row.
        let verbose = plain(render_workflow_run(&c, width, &theme, 0));
        assert!(verbose.contains("scan modules"));
        assert!(verbose.contains("1.2k tok")); // fmt_count k-suffix

        // Prove it draws into a real ratatui frame (TestBackend), through the Block seam.
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let block = Block::new(1, BlockKind::WorkflowRun(c));
        let mut terminal = Terminal::new(TestBackend::new(width, 20)).unwrap();
        terminal
            .draw(|frame| {
                let para = ratatui::widgets::Paragraph::new(block.render(width, &theme, 0));
                frame.render_widget(para, frame.area());
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let drawn: String = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .map(|(x, y)| buf[(x, y)].symbol())
            .collect();
        assert!(drawn.contains("audit"), "header drew into the frame");
        assert!(drawn.contains('\u{276f}'), "narrator drew into the frame");
    }

    fn bounded_workflow_card(agent_count: usize) -> WorkflowRunCard {
        let mut card = WorkflowRunCard::new("wf_bounded", "bounded audit");
        card.declare_phases(["Explore", "Synthesize"]);
        card.verbose = true;
        for index in 0..agent_count {
            card.agents.push(WorkflowRunAgent {
                index,
                label: format!("investigator {index:02}"),
                phase_index: if index + 4 < agent_count { 1 } else { 2 },
                state: WorkflowState::Error,
                agent_type: None,
                model: Some("haiku".into()),
                tokens: 100,
                tool_calls: 1,
                last_tool_summary: None,
                result_preview: None,
                started: None,
                duration_ms: 100,
                error: None,
            });
        }
        card
    }

    /// Render then window, which is what the workflow region does across the two halves of a frame.
    fn render_workflow_run_bounded(
        card: &WorkflowRunCard,
        width: u16,
        max_rows: usize,
        theme: &Theme,
        spin: usize,
    ) -> Vec<Line<'static>> {
        window_workflow_rows(
            render_workflow_run(card, width, theme, spin),
            max_rows,
            theme,
        )
    }

    fn workflow_line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn bounded_workflow_keeps_every_row_when_fewer_than_the_bound() {
        let theme = Theme::dark();
        let card = bounded_workflow_card(3);
        let full = render_workflow_run(&card, 100, &theme, 0);
        let bounded = render_workflow_run_bounded(&card, 100, full.len() + 5, &theme, 0);

        assert_eq!(bounded.len(), full.len());
        assert_eq!(plain(bounded), plain(full));
    }

    #[test]
    fn bounded_workflow_keeps_every_row_at_the_exact_bound() {
        let theme = Theme::dark();
        let card = bounded_workflow_card(3);
        let full = render_workflow_run(&card, 100, &theme, 0);
        let bounded = render_workflow_run_bounded(&card, 100, full.len(), &theme, 0);

        assert_eq!(bounded.len(), full.len());
        assert_eq!(plain(bounded), plain(full));
    }

    #[test]
    fn bounded_workflow_windows_far_more_rows_with_truthful_indicators() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let theme = Theme::dark();
        let card = bounded_workflow_card(24);
        let full = render_workflow_run(&card, 100, &theme, 0);
        let footer = workflow_line_text(full.last().expect("totals footer"));
        let max_rows = 12;
        let visible_rows = max_rows - 3; // footer + ↑/↓ indicators consume three slots
        let hidden_rows = full.len() - 1 - visible_rows;
        let hidden_above = hidden_rows / 2;
        let hidden_below = hidden_rows - hidden_above;

        let bounded = render_workflow_run_bounded(&card, 100, max_rows, &theme, 0);
        assert_eq!(bounded.len(), max_rows);
        assert_eq!(
            workflow_line_text(&bounded[0]),
            format!("\u{2191} {hidden_above} more")
        );
        assert_eq!(
            workflow_line_text(&bounded[max_rows - 2]),
            format!("\u{2193} {hidden_below} more")
        );
        assert_eq!(workflow_line_text(bounded.last().unwrap()), footer);
        for (actual, expected) in bounded[1..max_rows - 2]
            .iter()
            .zip(&full[hidden_above..hidden_above + visible_rows])
        {
            assert_eq!(workflow_line_text(actual), workflow_line_text(expected));
        }

        // Terminal-render evidence: both omission directions and the pinned totals reach the pane.
        let mut terminal = Terminal::new(TestBackend::new(100, max_rows as u16)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(
                    ratatui::widgets::Paragraph::new(bounded.clone()),
                    frame.area(),
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let drawn: String = (0..buffer.area.height)
            .flat_map(|y| (0..buffer.area.width).map(move |x| (x, y)))
            .map(|(x, y)| buffer[(x, y)].symbol())
            .collect();
        assert!(drawn.contains(&format!("\u{2191} {hidden_above} more")));
        assert!(drawn.contains(&format!("\u{2193} {hidden_below} more")));
        assert!(drawn.contains("0/24 agents"), "totals footer was clipped");
    }

    #[test]
    fn bounded_workflow_uses_an_up_indicator_next_to_a_tiny_tail() {
        let theme = Theme::dark();
        let card = bounded_workflow_card(8);
        let full = render_workflow_run(&card, 100, &theme, 0);
        let footer = workflow_line_text(full.last().unwrap());
        let bounded = render_workflow_run_bounded(&card, 100, 2, &theme, 0);

        assert_eq!(bounded.len(), 2);
        assert_eq!(
            workflow_line_text(&bounded[0]),
            format!("\u{2191} {} more", full.len() - 1)
        );
        assert_eq!(workflow_line_text(&bounded[1]), footer);
    }

    #[test]
    fn bounded_workflow_returns_only_the_footer_when_one_row_fits() {
        let theme = Theme::dark();
        let card = bounded_workflow_card(8);
        let full = render_workflow_run(&card, 100, &theme, 0);
        let footer = workflow_line_text(full.last().unwrap());
        let bounded = render_workflow_run_bounded(&card, 100, 1, &theme, 0);

        assert_eq!(bounded.len(), 1);
        assert_eq!(workflow_line_text(&bounded[0]), footer);
        assert!(workflow_line_text(&bounded[0]).contains("0/8 agents"));
    }

    #[test]
    fn bounded_workflow_returns_no_rows_when_the_budget_is_zero() {
        let theme = Theme::dark();
        let card = bounded_workflow_card(8);

        assert!(render_workflow_run_bounded(&card, 100, 0, &theme, 0).is_empty());
    }

    // ---- result_preview: what an individual agent actually RETURNED -------------------------
    //
    // `iteron_workflow::bindings::emit_finished` builds a ≤400-char excerpt of every agent's
    // text/structured outcome and puts it on `AgentFinished.result_preview`. The card used to
    // destructure it as `result_preview: _`, so a finished run reported tokens, tools and a
    // duration but never one word of what any agent came back with.

    /// One phase holding one finished agent — the shape `iteron workflow run` actually renders, where
    /// `phase_box` fits every row to the box's inner width.
    fn preview_card(preview: Option<&str>) -> WorkflowRunCard {
        let mut c = WorkflowRunCard::new("wf_preview", "audit");
        c.ingest(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        c.ingest(ProgressEvent::AgentStarted {
            index: 0,
            label: "scan modules".into(),
            phase: Some("Explore".into()),
            model: None,
            queued_ms: 0,
            available_permits: 0,
        });
        c.ingest(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan modules".into(),
            state: WorkflowState::Done,
            tokens: 1_234,
            tool_calls: 3,
            duration_ms: 3_200,
            result_preview: preview.map(str::to_string),
            last_tool_summary: None,
            error: None,
        });
        c
    }

    #[test]
    fn a_finished_agent_renders_an_excerpt_of_what_it_returned() {
        let theme = Theme::dark();
        let width = 78u16;
        let mut c = preview_card(Some(
            "4 modules touch the provider seam: cli, tools, workflow, mcp",
        ));
        assert!(
            !c.verbose,
            "this is the DEFAULT view — the one `iteron workflow run` echoes into scrollback"
        );
        assert_eq!(
            c.agents[0].result_preview.as_deref(),
            Some("4 modules touch the provider seam: cli, tools, workflow, mcp"),
            "the card must retain the preview, not destructure it away"
        );

        let folded = plain(render_workflow_run(&c, width, &theme, 0));
        assert!(folded.contains("ctrl+o expand"), "{folded}");
        assert!(!folded.contains("scan modules"), "{folded}");
        assert!(!folded.contains('\u{23bf}'), "{folded}");

        c.verbose = true;
        let lines = render_workflow_run(&c, width, &theme, 0);
        for line in &lines {
            assert!(line_width(line) <= width, "row exceeded width: {line:?}");
        }
        let text = plain(lines);
        println!("\n===== agent row with a result preview (width {width}) =====\n{text}\n=====");
        assert!(
            text.contains("\u{23bf} 4 modules touch the provider seam: cli, tools, workflow, mcp"),
            "the returned excerpt must reach the rendered row:\n{text}"
        );
        assert!(
            text.contains("scan modules"),
            "a row that has a result to show must not be collapsed away:\n{text}"
        );
        assert!(
            text.contains("   \u{23bf} 4 modules"),
            "the LAST row's excerpt hangs under it with no dangling branch:\n{text}"
        );

        // A second row makes the first one non-last: its excerpt must keep the tree's vertical
        // continuation, or the branch below it appears to belong to the excerpt.
        c.ingest(ProgressEvent::AgentFinished {
            index: 1,
            label: "probe API".into(),
            state: WorkflowState::Done,
            tokens: 10,
            tool_calls: 0,
            duration_ms: 100,
            result_preview: Some("two endpoints are unauthenticated".into()),
            last_tool_summary: None,
            error: None,
        });
        let text = plain(render_workflow_run(&c, width, &theme, 0));
        assert!(
            text.contains("\u{2502}  \u{23bf} 4 modules"),
            "a non-last row's excerpt must continue the branch with `│`:\n{text}"
        );
        assert!(
            text.contains("   \u{23bf} two endpoints are unauthenticated"),
            "the new last row's excerpt must NOT continue the branch:\n{text}"
        );
    }

    #[test]
    fn an_agent_that_returned_nothing_renders_exactly_as_it_did_before() {
        let theme = Theme::dark();
        let width = 78u16;
        // Byte-for-byte: the no-preview card is the pre-change rendering, so the feature adds
        // nothing at all — no empty stub row, no stray `⎿` connector, no lost collapse.
        let absent = plain(render_workflow_run(&preview_card(None), width, &theme, 0));
        assert!(
            !absent.contains('\u{23bf}'),
            "a result-less agent grew a stray connector:\n{absent}"
        );
        assert!(
            absent.contains("\u{b7} 1/1 \u{b7}"),
            "the folded run still reports progress:\n{absent}"
        );
        assert!(!absent.contains("scan modules"), "…and stay collapsed");

        // A preview that sanitizes down to nothing is indistinguishable from no preview at all.
        let whitespace_only = plain(render_workflow_run(
            &preview_card(Some(" \t \n ")),
            width,
            &theme,
            0,
        ));
        assert_eq!(
            whitespace_only, absent,
            "an all-whitespace preview must render as absent, not as an empty row"
        );
    }

    #[test]
    fn a_result_preview_is_neutralised_before_it_reaches_the_terminal() {
        let theme = Theme::dark();
        let width = 120u16;
        // Model-authored output trying to clear the screen, home the cursor, ring the bell, rewrite
        // the row it is on, and smuggle a credential out through the transcript.
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let hostile = format!("done\u{1b}[2J\u{1b}[1;1H gotcha\r bell\u{7} key={secret} tail");
        let mut c = preview_card(Some(&hostile));

        // Neutralised ON INGEST, so retained card state can never hold an executable escape —
        // not merely masked at draw time, where one renderer forgetting the call re-opens it.
        let stored = c.agents[0]
            .result_preview
            .as_deref()
            .expect("a hostile preview is still shown, just neutralised");
        assert!(
            !stored.chars().any(char::is_control),
            "a control character survived into retained card state: {stored:?}"
        );
        assert!(
            stored.contains("\\u{1b}") && stored.contains("\\r") && stored.contains("\\u{7}"),
            "escapes must survive as literal text, not as terminal commands: {stored:?}"
        );
        assert!(
            !stored.contains(secret) && stored.contains("[REDACTED"),
            "the shared ui_safe_text gate must redact credential shapes: {stored:?}"
        );
        assert!(
            stored.contains("gotcha") && stored.contains("tail"),
            "the benign text must survive intact: {stored:?}"
        );

        c.verbose = true;
        let lines = render_workflow_run(&c, width, &theme, 0);
        for line in &lines {
            for span in &line.spans {
                assert!(
                    !span.content.chars().any(char::is_control),
                    "a control character reached a rendered span: {:?}",
                    span.content
                );
            }
            assert!(line_width(line) <= width, "row exceeded width: {line:?}");
        }
        let text = plain(lines);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\r'));
        assert!(!text.contains(secret));
        assert!(
            text.contains("gotcha"),
            "the benign text still shows:\n{text}"
        );
    }

    /// A run name is whatever the workflow author wrote, and the totals row grows on its own as a
    /// run accumulates agents/failures/tokens/tool calls/elapsed. Both used to be handed to the
    /// pane unbudgeted, so a narrow terminal cut them at the pane edge with no marker and — with a
    /// double-width title — at a column that is inside a glyph rather than between two.
    #[test]
    fn the_run_title_and_totals_rows_are_ellipsised_at_every_width() {
        use iteron_workflow::events::WorkflowState;

        let theme = Theme::dark();
        // Wide (2-column) glyphs, so a cut that lands mid-glyph is observable as a row that is one
        // column short of the pane rather than flush with it.
        let title = "追踪一个非常长的工作流标题".repeat(6);
        let mut c = WorkflowRunCard::new("wf_a_very_long_run_identifier", title.clone());
        c.verbose = true;
        c.ingest(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        c.ingest(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan modules".into(),
            state: WorkflowState::Error,
            tokens: 123_456,
            tool_calls: 42,
            duration_ms: 3_200,
            result_preview: None,
            last_tool_summary: None,
            error: Some("provider timeout".into()),
        });

        for width in [120u16, 78, 60, 40, 30, 20, 12, 6, 2, 1] {
            let lines = render_workflow_run(&c, width, &theme, 0);
            let head = lines.first().expect("a title row");
            let footer = lines.last().expect("a totals footer");

            // Both rows land exactly on the pane edge: the marker costs a column, and a wide glyph
            // that no longer fits is dropped whole and replaced by padding, never half-drawn.
            assert_eq!(
                line_width(head),
                width,
                "width {width}: the title row is not flush: {head:?}"
            );
            assert_eq!(
                line_width(footer),
                width,
                "width {width}: the totals row is not flush: {footer:?}"
            );

            let head_text = workflow_line_text(head);
            let footer_text = workflow_line_text(footer);
            assert!(
                head_text.contains('\u{2026}'),
                "width {width}: a {}-column title was cut with no marker: {head_text:?}",
                title.chars().count() * 2
            );
            assert!(
                !head_text.contains(&title),
                "width {width}: the full title cannot fit and must not be claimed"
            );

            // What survives is a genuine PREFIX of the name — proof the cut fell between glyphs.
            // (The row may also have taken the leading space of the field after the name, since a
            // wide glyph that no longer fits leaves a single column the next field can start in.)
            if width >= 12 {
                let shown: String = head_text
                    .trim_end()
                    .trim_end_matches('\u{2026}')
                    .trim_end()
                    .chars()
                    .skip(2) // the run marker/spinner glyph and its space
                    .collect();
                assert!(
                    !shown.is_empty() && title.starts_with(&shown),
                    "width {width}: {shown:?} is not a prefix of the run name"
                );
            }

            // The totals row is the same story once a run has enough columns of evidence to report.
            assert!(
                width >= 60 || footer_text.contains('\u{2026}'),
                "width {width}: the totals row was cut with no marker: {footer_text:?}"
            );
        }

        // Wide enough for everything: no marker is spent, and the evidence is all there.
        let roomy = plain(render_workflow_run(&c, 260, &theme, 0));
        assert!(
            roomy.contains(&title),
            "a 260-column pane shows the whole name"
        );
        assert!(
            roomy.contains("0/1 agents \u{b7} 1 failed \u{b7} 123.5k tok \u{b7} 42 tool calls")
        );
        assert!(
            !roomy.lines().next().unwrap().contains('\u{2026}'),
            "a title that fits must not be marked as cut"
        );
    }

    #[test]
    fn a_long_result_preview_is_truncated_to_the_available_width() {
        let theme = Theme::dark();
        let long = "x".repeat(iteron_workflow::events::PREVIEW_MAX);
        let mut c = preview_card(Some(&long));
        c.verbose = true;

        // From "comfortably wide" down to "a phone in portrait", the phase box stays rectangular:
        // the preview is budgeted against the width its own sub-line will actually be fit to.
        // (The run title/totals rows now go through `fit_spans` as well — see
        // `the_run_title_and_totals_rows_are_ellipsised_at_every_width` — so this test pins the box
        // interior, which is where the preview lands.)
        let mut boxed_widths = 0;
        for width in [120u16, 78, 60, 40, 30, 20, 14, 8] {
            let lines = render_workflow_run(&c, width, &theme, 0);
            for line in &lines {
                let first = line.spans.first().and_then(|s| s.content.chars().next());
                let in_box = matches!(first, Some('\u{2502}' | '\u{256d}' | '\u{2570}'));
                if in_box {
                    boxed_widths += 1;
                }
                // Below width 24 `render_workflow_run` drops the boxes for the flat list, whose
                // rows were never width-fit; the preview sub-line still has to hold its own budget.
                let is_preview = line.spans.iter().any(|s| s.content.contains('\u{23bf}'));
                if in_box || is_preview {
                    assert!(
                        line_width(line) <= width,
                        "width {width}: row exceeded it: {line:?}"
                    );
                }
            }
        }
        assert!(boxed_widths > 0, "the boxed layout was never exercised");

        // At a usable width the excerpt is present, cut, and ellipsized rather than wrapped.
        let text = plain(render_workflow_run(&c, 40, &theme, 0));
        let preview_row = text
            .lines()
            .find(|line| line.contains('\u{23bf}'))
            .expect("a 40-column terminal still shows an excerpt");
        assert!(
            preview_row.contains('\u{2026}'),
            "a 400-char preview must be cut with `…`: {preview_row:?}"
        );
        assert!(
            !preview_row.contains(&"x".repeat(40)),
            "the full preview leaked into a 40-column row: {preview_row:?}"
        );

        // Too narrow to say anything (12 columns leaves 7 for text): the sub-line disappears
        // entirely instead of drawing a connector with a bare ellipsis hanging off it.
        let narrow = plain(render_workflow_run(&c, 12, &theme, 0));
        assert!(
            !narrow.contains('\u{23bf}'),
            "a stray connector survived at width 12:\n{narrow}"
        );
    }

    /// The ungrouped flat-list fallback has no phase box to fit its rows, so the preview sub-line
    /// has to hold the width budget on its own.
    #[test]
    fn a_preview_fits_the_width_in_the_ungrouped_flat_list_fallback() {
        let theme = Theme::dark();
        let mut c = WorkflowRunCard::new("wf_flat", "audit");
        c.ingest(ProgressEvent::AgentFinished {
            index: 0,
            label: "scan".into(),
            state: WorkflowState::Done,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 10,
            result_preview: Some("y".repeat(iteron_workflow::events::PREVIEW_MAX)),
            last_tool_summary: None,
            error: None,
        });
        assert!(c.phases.is_empty(), "this is the flat-list fallback");
        for width in [120u16, 78, 40, 30, 20, 14] {
            let text = plain(render_workflow_run(&c, width, &theme, 0));
            for row in text.lines().filter(|row| row.contains('\u{23bf}')) {
                let cols: u16 = row.chars().map(crate::tui::char_width).sum();
                assert!(
                    cols <= width,
                    "width {width}: preview row was {cols}: {row:?}"
                );
            }
        }
    }

    /// Twenty agents at concurrency six: the queued fourteen are declared before their permit is
    /// requested, so every row exists on the first frame and the denominator never moves. The
    /// declared `meta.phases` lay every box out in advance, empty ones included.
    #[test]
    fn workflow_run_tree_seeds_declared_phases_and_pins_the_denominator() {
        use iteron_workflow::events::WorkflowState;

        let theme = Theme::dark();
        let width = 78u16;
        let mut c = WorkflowRunCard::new("wf_fan", "audit");
        c.declare_phases(["Explore", "Synthesize", "Write"]);
        c.verbose = true;

        // Every declared phase is a box on the very first frame, before any agent exists.
        let empty = plain(render_workflow_run(&c, width, &theme, 0));
        for title in ["Explore", "Synthesize", "Write"] {
            assert!(
                empty.contains(title),
                "declared phase `{title}` is invisible"
            );
        }
        assert!(empty.contains("0/0"));

        // The whole fan is declared up front (AgentQueued precedes the permit).
        for index in 1..=20 {
            c.ingest(ProgressEvent::AgentQueued {
                index,
                label: format!("investigator {index}"),
                phase: Some("Explore".into()),
                model: Some("haiku".into()),
            });
        }
        let (_, total, _, _, _) = c.totals();
        assert_eq!(total, 20, "the denominator is fixed by the queued rows");

        // Six permits are granted; the remaining fourteen stay visibly pending.
        for index in 1..=6 {
            c.ingest(ProgressEvent::AgentStarted {
                index,
                label: format!("investigator {index}"),
                phase: Some("Explore".into()),
                model: Some("haiku".into()),
                queued_ms: 0,
                available_permits: 0,
            });
        }
        assert_eq!(
            c.agents
                .iter()
                .filter(|agent| agent.state == WorkflowState::Queued)
                .count(),
            14
        );
        assert_eq!(
            c.agents
                .iter()
                .filter(|agent| agent.state == WorkflowState::Running)
                .count(),
            6
        );
        let (_, total_after, _, _, _) = c.totals();
        assert_eq!(total_after, 20, "the denominator must not move mid-run");

        c.verbose = true;
        let text = plain(render_workflow_run(&c, width, &theme, 0));
        assert!(text.contains("0/20 agents"));
        assert_eq!(
            text.matches("\u{27f3} investigator").count(), // ⟳
            14,
            "every queued investigator renders a pending row:\n{text}"
        );
        // A declared-but-unreached phase renders an empty box with a pending glyph, not a spinner.
        assert!(text.contains("Synthesize  \u{27f3} 0/0"));
        // A reached `phase()` binds to the DECLARED box by title — no duplicate box.
        c.ingest(ProgressEvent::Phase {
            index: 1,
            title: "Explore".into(),
        });
        assert_eq!(c.phases.len(), 3);
        for line in render_workflow_run(&c, width, &theme, 0) {
            assert!(
                line_width(&line) <= width,
                "queued row over width: {line:?}"
            );
        }
    }
}

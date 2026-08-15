//! Workflow-run transcript model and renderer.

use super::*;

// QuickJS `iteron-workflow` live tree (WORKFLOW-REPLICATION-DESIGN.md §3.3)
//
// This consumes the `iteron_workflow::events::ProgressEvent` stream
// (`agent()`/`parallel()`/`phase()`/`log()` runtime) and renders the phase-box tree. Per
// ADR-0001 (docs/project/decisions/0001-workflow-renderer-convergence.md) this is the SURVIVING
// workflow renderer: new progress capability lands here, and the native-ultracode `WorkflowCard`
// above retires once ultracode's decomposition runs as a built-in script.
// ---------------------------------------------------------------------------------------------

/// One `phase(title)` group, in 1-based first-seen order (`ProgressEvent::Phase`).
#[derive(Debug, Clone)]
pub struct WorkflowRunPhase {
    pub index: usize,
    pub title: String,
}

/// One `agent()` row. State is the engine's own 5-state semantic model (reused, not duplicated).
#[derive(Debug, Clone)]
pub struct WorkflowRunAgent {
    pub index: usize,
    pub label: String,
    /// 1-based phase group; `0` = ungrouped (renders in the flat-list fallback).
    pub phase_index: usize,
    pub state: WorkflowState,
    pub agent_type: Option<String>,
    pub model: Option<String>,
    pub tokens: u64,
    pub tool_calls: u64,
    /// The live tool line for a running child (`last_tool_summary`, ≤60 chars at the emitter).
    pub last_tool_summary: Option<String>,
    /// A bounded excerpt of what this agent RETURNED (`result_preview`, ≤400 chars at the emitter —
    /// `iteron_workflow::bindings::emit_finished` builds it from the `Record`'s text/structured
    /// outcome). Untrusted model output, so it is sanitized on ingest, never at draw time. `None`
    /// for a row that returned nothing (a null/unknown outcome, or a preview that sanitized away):
    /// such a row renders exactly as it did before this field existed.
    pub result_preview: Option<String>,
    /// When this row was ADMITTED (permit acquired). A running row has no settled `duration_ms`, so
    /// this is what makes its elapsed column tick instead of reading `0s` for the whole run.
    pub started: Option<Instant>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl WorkflowRunAgent {
    fn finished(&self) -> bool {
        matches!(
            self.state,
            WorkflowState::Done | WorkflowState::Error | WorkflowState::Skipped
        )
    }
}

/// An agent's `result_preview` is model-authored text on its way into RETAINED transcript state, so
/// it goes through the same gate every other untrusted display string does — [`crate::semantic_text::ui_safe_text`]
/// (secret-shaped substrings redacted, terminal control characters escaped). That gate deliberately
/// keeps `\n`/`\t` intact for multi-line surfaces, but this one is a single tree row, so the engine's
/// own [`events::truncate_preview`] then collapses whitespace and re-bounds to
/// [`events::PREVIEW_MAX`] — escaping can only grow the string (`\u{1b}` → six chars), so the
/// emitter's bound has to be re-applied after it. A preview that sanitizes down to nothing becomes
/// `None`, which renders as no line at all rather than an empty stub.
fn safe_result_preview(preview: Option<String>) -> Option<String> {
    let safe = events::truncate_preview(
        &crate::semantic_text::ui_safe_text(preview?.as_str()),
        events::PREVIEW_MAX,
    );
    (!safe.is_empty()).then_some(safe)
}

/// The live QuickJS-workflow phase→agent tree, keyed by run id and mutated in place by
/// [`Self::ingest`] (the upsert-by-index the design §3.2 store performs). One card per run.
#[derive(Clone)]
pub struct WorkflowRunCard {
    pub run_id: String,
    pub name: String,
    pub phases: Vec<WorkflowRunPhase>,
    pub agents: Vec<WorkflowRunAgent>,
    pub logs: Vec<String>,
    pub finished: bool,
    /// Expansion toggle: false renders one live run summary; true opens the phase/agent tree.
    pub verbose: bool,
    /// The run clock, for the header's elapsed column.
    pub started: Instant,
    /// Last `phase()` seen — the group an `agent()` without an explicit `opts.phase` falls into.
    current_phase: usize,
}

impl WorkflowRunCard {
    pub fn new(run_id: impl Into<String>, name: impl Into<String>) -> Self {
        WorkflowRunCard {
            run_id: run_id.into(),
            name: name.into(),
            phases: Vec::new(),
            agents: Vec::new(),
            logs: Vec::new(),
            finished: false,
            verbose: false,
            started: Instant::now(),
            current_phase: 0,
        }
    }

    /// Seed the tree from the script's `export const meta.phases`. The metadata was parsed,
    /// populated and tested, but both call sites read only `name`/`description`, so phase boxes
    /// appeared only once execution reached them. Declared phases are laid out in advance and keep
    /// their declared order; a `phase()` the script actually reaches binds back by TITLE, so a
    /// script whose runtime order differs from its header never registers a duplicate box.
    pub fn declare_phases<I, S>(&mut self, titles: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for title in titles {
            let title = title.into();
            if title.is_empty() || self.phases.iter().any(|phase| phase.title == title) {
                continue;
            }
            let index = self.phases.iter().map(|p| p.index).max().unwrap_or(0) + 1;
            self.phases.push(WorkflowRunPhase { index, title });
        }
    }

    /// Run-level totals: `(done, total, errors, tokens, tool_calls)` across every row.
    pub fn totals(&self) -> (usize, usize, usize, u64, u64) {
        let done = self
            .agents
            .iter()
            .filter(|agent| agent.state == WorkflowState::Done)
            .count();
        let errors = self
            .agents
            .iter()
            .filter(|agent| agent.state == WorkflowState::Error)
            .count();
        let tokens = self.agents.iter().map(|agent| agent.tokens).sum();
        let tool_calls = self.agents.iter().map(|agent| agent.tool_calls).sum();
        (done, self.agents.len(), errors, tokens, tool_calls)
    }

    /// Resolve an agent's group: an explicit `opts.phase` title binds to (or registers) a phase;
    /// otherwise the agent falls into the phase active when it started.
    fn resolve_phase(&mut self, phase: Option<String>) -> usize {
        match phase {
            Some(title) if !title.is_empty() => {
                if let Some(existing) = self.phases.iter().find(|p| p.title == title) {
                    existing.index
                } else {
                    let index = self.phases.iter().map(|p| p.index).max().unwrap_or(0) + 1;
                    self.phases.push(WorkflowRunPhase { index, title });
                    index
                }
            }
            _ => self.current_phase,
        }
    }

    /// Find (or insert, keeping index order) the row for `index`.
    fn agent_mut(&mut self, index: usize) -> &mut WorkflowRunAgent {
        if let Some(pos) = self.agents.iter().position(|a| a.index == index) {
            return &mut self.agents[pos];
        }
        let row = WorkflowRunAgent {
            index,
            label: String::new(),
            phase_index: self.current_phase,
            state: WorkflowState::Queued,
            agent_type: None,
            model: None,
            tokens: 0,
            tool_calls: 0,
            last_tool_summary: None,
            result_preview: None,
            started: None,
            duration_ms: 0,
            error: None,
        };
        let pos = self
            .agents
            .iter()
            .position(|a| a.index > index)
            .unwrap_or(self.agents.len());
        self.agents.insert(pos, row);
        &mut self.agents[pos]
    }

    /// Upsert one engine progress event into the live tree (the design §3.2 store step). `ingest`
    /// alone never marks the run finished — the run driver flips `finished` when the engine future
    /// resolves.
    pub fn ingest(&mut self, event: ProgressEvent) {
        match event {
            // A reached `phase()` binds to a DECLARED box by title first, so seeding the tree from
            // `meta.phases` never produces a second box for the same phase.
            ProgressEvent::Phase { index, title } => {
                self.current_phase =
                    if let Some(existing) = self.phases.iter().find(|phase| phase.title == title) {
                        existing.index
                    } else if self.phases.iter().any(|phase| phase.index == index) {
                        let next = self.phases.iter().map(|p| p.index).max().unwrap_or(0) + 1;
                        self.phases.push(WorkflowRunPhase { index: next, title });
                        next
                    } else {
                        self.phases.push(WorkflowRunPhase { index, title });
                        index
                    };
            }
            ProgressEvent::Log { message } => self.logs.push(message),
            ProgressEvent::AgentQueued {
                index,
                label,
                phase,
                model,
            } => {
                let phase_index = self.resolve_phase(phase);
                let agent = self.agent_mut(index);
                agent.label = label;
                agent.model = model;
                agent.phase_index = phase_index;
                agent.state = WorkflowState::Queued;
            }
            ProgressEvent::AgentStarted {
                index,
                label,
                phase,
                model,
                ..
            } => {
                let phase_index = self.resolve_phase(phase);
                let agent = self.agent_mut(index);
                agent.label = label;
                agent.model = model;
                agent.phase_index = phase_index;
                agent.state = WorkflowState::Running;
                agent.started = Some(Instant::now());
            }
            ProgressEvent::AgentActivity {
                index,
                tokens,
                tool_calls,
                last_tool_summary,
            } => {
                let agent = self.agent_mut(index);
                agent.tokens = tokens;
                agent.tool_calls = tool_calls;
                if last_tool_summary.is_some() {
                    agent.last_tool_summary = last_tool_summary;
                }
            }
            ProgressEvent::AgentCancelling {
                index,
                cleanup_deadline_ms,
            } => {
                let agent = self.agent_mut(index);
                agent.state = WorkflowState::Running;
                agent.last_tool_summary = Some(format!(
                    "cancelling · cleanup deadline {cleanup_deadline_ms}ms"
                ));
            }
            ProgressEvent::AgentFinished {
                index,
                label,
                state,
                tokens,
                tool_calls,
                duration_ms,
                result_preview,
                last_tool_summary,
                error,
            } => {
                let agent = self.agent_mut(index);
                if !label.is_empty() {
                    agent.label = label;
                }
                agent.state = state;
                agent.tokens = tokens;
                agent.tool_calls = tool_calls;
                agent.duration_ms = duration_ms;
                agent.result_preview = safe_result_preview(result_preview);
                agent.error = error;
                if last_tool_summary.is_some() {
                    agent.last_tool_summary = last_tool_summary;
                }
            }
        }
    }
}

/// A row's state glyph + its optional color. Per design §3.3 glyphs are colored ONLY when finished;
/// a running row shows the animated braille frame (the §3.3 spinner), a queued row a static `⟳` —
/// both uncolored. `None` color means "render in the passive muted hue".
fn run_state_glyph(state: WorkflowState, spin: usize, theme: &Theme) -> (String, Option<Color>) {
    match state {
        WorkflowState::Done => ("\u{2714}".into(), Some(theme.success)), // ✔
        WorkflowState::Error => ("\u{2718}".into(), Some(theme.error)),  // ✘
        WorkflowState::Skipped => ("\u{2298}".into(), Some(theme.warn)), // ⊘
        WorkflowState::Running => (braille_frame(spin).into(), None),
        WorkflowState::Queued => ("\u{27f3}".into(), None), // ⟳
    }
}

/// The dim `·`-joined meta trailer (design §3.3): `[agentType, model, "<Na> tok", "<n> tool(s)",
/// duration]`, plus a running child's live tool line. `None` for a finished row with nothing to show;
/// `Some("…running")` for an active row that has not reported any metric yet.
fn agent_meta_string(agent: &WorkflowRunAgent) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = &agent.agent_type {
        parts.push(t.clone());
    }
    if let Some(m) = &agent.model {
        parts.push(m.clone());
    }
    if agent.tokens > 0 {
        parts.push(format!("{} tok", events::fmt_count(agent.tokens)));
    }
    if agent.tool_calls > 0 {
        let noun = if agent.tool_calls == 1 {
            "tool"
        } else {
            "tools"
        };
        parts.push(format!("{} {noun}", agent.tool_calls));
    }
    if agent.finished() {
        parts.push(events::fmt_duration(agent.duration_ms));
    } else {
        if let Some(tool) = &agent.last_tool_summary {
            // The live tool line — the running child's most recent tool_use, summarized (≤60 chars).
            parts.push(tool.clone());
        }
        // A running row's clock ticks from its admission instant; without it the elapsed column
        // stayed empty for the entire life of the row.
        if let Some(started) = agent.started {
            parts.push(events::fmt_duration(started.elapsed().as_millis() as u64));
        }
    }
    if parts.is_empty() {
        match agent.state {
            WorkflowState::Queued => Some("\u{2026}queued".into()), // …queued
            _ if agent.finished() => None,
            _ => Some("\u{2026}running".into()), // …running
        }
    } else {
        Some(parts.join(" \u{b7} "))
    }
}

/// The stem in front of a result-preview sub-line: three columns of tree continuation (`│  ` or
/// three spaces, matching the width of the `├─ `/`└─ ` branch above it) plus `⎿ `, the transcript's
/// own nested-content connector (see [`CONNECTOR`]). Every glyph is width-1, so this is exactly 5
/// cells and the preview's own budget is `width - 5`.
const PREVIEW_STEM_COLS: u16 = 5;
/// Below this many columns of usable text a preview is nothing but an ellipsis, so the sub-line is
/// dropped entirely rather than drawn as a stray connector with no content.
const PREVIEW_MIN_COLS: u16 = 8;

/// The dim `⎿ <excerpt>` sub-line under a finished agent row: what that agent actually RETURNED.
/// `None` when the row has no preview or the row is too narrow to say anything useful — the caller
/// then emits no line at all, so a result-less agent keeps the exact single-row shape it had before.
fn result_preview_line(
    agent: &WorkflowRunAgent,
    width: u16,
    last: bool,
    theme: &Theme,
) -> Option<Vec<Span<'static>>> {
    if !agent.finished() {
        return None;
    }
    let preview = agent.result_preview.as_deref()?;
    let budget = width.saturating_sub(iteron_tunables::param_integer(
        "cli.block.workflow_run.preview_stem_cols",
        PREVIEW_STEM_COLS,
    ));
    if budget
        < iteron_tunables::param_integer(
            "cli.block.workflow_run.preview_min_cols",
            PREVIEW_MIN_COLS,
        )
    {
        return None;
    }
    // Already sanitized at ingest; this only fits it to the columns actually available, so a 400-char
    // preview in a 40-column terminal cannot push the row past the phase box's right border.
    let text = crate::tui::clip_text(preview, budget);
    if text.trim().is_empty() {
        return None;
    }
    let stem = if last { "   " } else { "\u{2502}  " }; // │ continues the branch above
    Some(vec![
        Span::styled(
            format!("{stem}\u{23bf} "), // ⎿
            Style::default().fg(theme.faint),
        ),
        Span::styled(text, Style::default().fg(theme.muted)),
    ])
}

/// Build the branch rows for one group of agents (design §3.3 collapse + row grammar). Non-verbose
/// collapses finished (`Done`) agents into one dim `✔ n done` line; everything not-yet-done stays
/// visible so failures/liveness never disappear. Verbose shows every row.
///
/// The one exception to the collapse: a `Done` row that carries a `result_preview` stays visible and
/// renders its excerpt underneath. The collapse exists to hide rows with nothing left to say, and the
/// settled tree is echoed into scrollback verbatim (`workflow::render_live`) — collapsing a row that
/// DID return something is precisely the defect that made a finished run report no result at all.
/// A `Done` row with no preview still collapses, and still counts toward `✔ n done`.
fn agent_row_lines(
    agents: &[&WorkflowRunAgent],
    theme: &Theme,
    spin: usize,
    verbose: bool,
    width: u16,
) -> Vec<Vec<Span<'static>>> {
    let collapsible =
        |a: &WorkflowRunAgent| a.state == WorkflowState::Done && a.result_preview.is_none();
    let done_count = agents.iter().filter(|a| collapsible(a)).count();
    let visible: Vec<&&WorkflowRunAgent> = if verbose {
        agents.iter().collect()
    } else {
        agents.iter().filter(|a| !collapsible(a)).collect()
    };

    let mut lines: Vec<Vec<Span<'static>>> = Vec::new();
    if !verbose && done_count > 0 {
        lines.push(vec![
            Span::styled("\u{2714} ", Style::default().fg(theme.success)),
            Span::styled(
                format!("{done_count} done"),
                Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
            ),
        ]);
    }

    // The live tree has to stay a GLANCE, not a page. A 16-way fan put sixteen full task
    // descriptions on screen, each wrapping to three lines, and the conversation above it was
    // gone. Two bounds fix that without hiding a failure: at most MAX_LIVE_ROWS rows are drawn
    // and the remainder is counted on one line; and every row is ONE line, its label clipped to
    // the width it has rather than wrapped. Errors and still-running work sort first, so the
    // rows that survive the bound are the ones an operator was looking for. The collapse toggle
    // (`verbose`) still shows every row in full.
    const MAX_LIVE_ROWS: usize = 6;
    let mut visible = visible;
    if !verbose {
        visible.sort_by_key(|agent| match agent.state {
            WorkflowState::Error => 0,
            WorkflowState::Running => 1,
            _ => 2,
        });
    }
    let hidden = if verbose {
        0
    } else {
        visible.len().saturating_sub(iteron_tunables::param_integer(
            "cli.block.workflow_run.max_live_rows",
            MAX_LIVE_ROWS,
        ))
    };
    if hidden > 0 {
        visible.truncate(iteron_tunables::param_integer(
            "cli.block.workflow_run.max_live_rows",
            MAX_LIVE_ROWS,
        ));
    }
    // Branch glyph, state glyph and the trailing meta all take columns before the label does.
    let label_budget = width.saturating_sub(28).max(24);

    let n = visible.len();
    for (i, agent) in visible.iter().enumerate() {
        let last = i + 1 == n;
        let branch = if last {
            "\u{2514}\u{2500} "
        } else {
            "\u{251c}\u{2500} "
        }; // └─ / ├─
        let (glyph, gcolor) = run_state_glyph(agent.state, spin, theme);
        let glyph_style = Style::default().fg(gcolor.unwrap_or(theme.muted));
        // Active rows dim their label; a finished row brightens to the normal fg.
        let label_style = if agent.finished() {
            Style::default().fg(theme.fg)
        } else {
            Style::default().fg(theme.muted).add_modifier(Modifier::DIM)
        };
        let mut row = vec![
            Span::styled(branch.to_string(), Style::default().fg(theme.faint)),
            Span::styled(format!("{glyph} "), glyph_style),
            Span::styled(
                if verbose {
                    agent.label.clone()
                } else {
                    crate::tui::clip_text(&agent.label, label_budget)
                },
                label_style,
            ),
        ];
        if let Some(meta) = agent_meta_string(agent) {
            row.push(Span::styled(
                format!(" \u{b7} {meta}"),
                Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
            ));
        }
        if agent.state == WorkflowState::Error
            && let Some(err) = &agent.error
        {
            row.push(Span::styled(
                format!(" \u{2014} {err}"), // — <error>
                Style::default().fg(theme.error),
            ));
        }
        lines.push(row);
        if let Some(preview) = result_preview_line(agent, width, last, theme) {
            lines.push(preview);
        }
    }
    if hidden > 0 {
        lines.push(vec![Span::styled(
            format!("\u{2026} +{hidden} more"),
            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
        )]);
    }
    lines
}

/// Truncate `spans` to exactly `width` display columns, padding with spaces — so a bordered box's
/// right edge stays aligned regardless of styled/variable-width content.
///
/// Content that does not fit ends in `…`, the same marker [`crate::tui::clip_text`] leaves, so a
/// cut row says it was cut instead of just stopping. A double-width glyph is never split across
/// the boundary: it is dropped whole and the freed column becomes padding, which is why the marker
/// costs one column rather than replacing whatever happened to land last.
fn fit_spans(spans: Vec<Span<'static>>, width: u16) -> Vec<Span<'static>> {
    let total = spans
        .iter()
        .flat_map(|span| span.content.chars())
        .map(crate::tui::char_width)
        .fold(0u16, u16::saturating_add);
    let overflows = total > width;
    // The marker's column is reserved only when the content actually overflows; a row that fits
    // keeps every one of its columns.
    let budget = if overflows {
        width.saturating_sub(1)
    } else {
        width
    };
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut used: u16 = 0;
    let mut cut_style = Style::default();
    for span in spans {
        if used >= budget {
            break;
        }
        cut_style = span.style;
        let mut piece = String::new();
        for ch in span.content.chars() {
            let cw = crate::tui::char_width(ch);
            if used + cw > budget {
                break;
            }
            piece.push(ch);
            used += cw;
        }
        if !piece.is_empty() {
            out.push(Span::styled(piece, span.style));
        }
    }
    if overflows && width > 0 {
        out.push(Span::styled("\u{2026}".to_string(), cut_style)); // …
        used = used.saturating_add(1);
    }
    if used < width {
        out.push(Span::raw(" ".repeat((width - used) as usize)));
    }
    out
}

/// Columns available INSIDE a phase box's `│ … │` frame. Shared with [`render_phase_box`] so the
/// rows it builds are budgeted against exactly the width [`phase_box`] will later fit them to —
/// two independent copies of `- 4` is how a preview ends up one column past the right border.
fn box_inner_width(width: u16) -> u16 {
    width.saturating_sub(4).max(1) // "│ " + content + " │"
}

/// Wrap a header line + body rows in a single-border box (design §3.3 phase box). Content is fit to
/// the inner width so the `╭─╮ │ … │ ╰─╯` frame stays rectangular.
fn phase_box(
    header: Vec<Span<'static>>,
    rows: Vec<Vec<Span<'static>>>,
    width: u16,
    border: Color,
) -> Vec<Line<'static>> {
    let inner = box_inner_width(width);
    let bs = Style::default().fg(border);
    let bar = "\u{2500}".repeat((inner + 2) as usize);
    let mut out = Vec::new();
    out.push(Line::from(Span::styled(
        format!("\u{256d}{bar}\u{256e}"),
        bs,
    ))); // ╭─╮
    let mut line = vec![Span::styled("\u{2502} ".to_string(), bs)];
    line.extend(fit_spans(header, inner));
    line.push(Span::styled(" \u{2502}".to_string(), bs));
    out.push(Line::from(line));
    for row in rows {
        let mut line = vec![Span::styled("\u{2502} ".to_string(), bs)];
        line.extend(fit_spans(row, inner));
        line.push(Span::styled(" \u{2502}".to_string(), bs));
        out.push(Line::from(line));
    }
    out.push(Line::from(Span::styled(
        format!("\u{2570}{bar}\u{256f}"),
        bs,
    ))); // ╰─╯
    out
}

/// Render one phase box: `<bold title>  <glyph> <done>/<total>[ · <sharedModel>][ · <n> failed]`
/// header + the agent branch rows (design §3.3).
fn render_phase_box(
    phase: Option<&WorkflowRunPhase>,
    agents: &[&WorkflowRunAgent],
    card: &WorkflowRunCard,
    width: u16,
    theme: &Theme,
    spin: usize,
) -> Vec<Line<'static>> {
    let total = agents.len();
    let done = agents
        .iter()
        .filter(|a| a.state == WorkflowState::Done)
        .count();
    let error = agents
        .iter()
        .filter(|a| a.state == WorkflowState::Error)
        .count();
    let complete = total > 0 && agents.iter().all(|a| a.finished());
    let phase_index = phase.map(|phase| phase.index).unwrap_or(0);
    let (hglyph, hcolor) = if complete {
        if error > 0 {
            ("\u{2718}".to_string(), theme.error) // ✘
        } else {
            ("\u{2714}".to_string(), theme.success) // ✔
        }
    } else if total == 0 && phase_index == card.current_phase && !card.finished {
        // A phase is live from the instant its `phase()` event arrives, before its first child is
        // queued. This is what makes the built-in planning phase visible while the planner streams.
        (braille_frame(spin).to_string(), theme.accent)
    } else if total == 0
        && ((phase_index > 0 && phase_index < card.current_phase)
            || (card.finished && phase_index == card.current_phase))
    {
        // A reached empty phase is complete, including the current phase once the run settles.
        ("\u{2714}".to_string(), theme.success)
    } else if total == 0 {
        // Declared but not reached.
        ("\u{27f3}".to_string(), theme.faint) // ⟳
    } else {
        (braille_frame(spin).to_string(), theme.muted) // running spinner, uncolored
    };
    // sharedModel: only when every agent reports the same model.
    let shared_model = agents.first().and_then(|a| a.model.clone()).filter(|m| {
        agents
            .iter()
            .all(|a| a.model.as_deref() == Some(m.as_str()))
    });

    let title = phase
        .map(|p| p.title.clone())
        .unwrap_or_else(|| "agents".to_string());
    let mut header = vec![
        Span::styled(
            title,
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(format!("{hglyph} "), Style::default().fg(hcolor)),
        Span::styled(format!("{done}/{total}"), Style::default().fg(theme.muted)),
    ];
    if let Some(model) = &shared_model {
        header.push(Span::styled(
            format!(" \u{b7} {model}"),
            Style::default().fg(theme.muted),
        ));
    }
    if error > 0 {
        header.push(Span::styled(
            format!(" \u{b7} {error} failed"),
            Style::default().fg(theme.error),
        ));
    }

    let rows = agent_row_lines(agents, theme, spin, card.verbose, box_inner_width(width));
    // Border is `subtle` (grey) — the `permission`/blue child-phase variant needs a phase `kind`
    // the current ProgressEvent set does not carry (design §6 fidelity note).
    phase_box(header, rows, width, theme.border)
}

/// The live QuickJS `iteron-workflow` phase→agent tree (design §3.3). Consumes the accumulated
/// `ProgressEvent`s already folded into `card` and renders Claude Code's look: a narrator line,
/// per-phase single-border boxes (or a flat list when no phase indices exist), branch rows with
/// state glyphs + dim meta, collapsed finished agents, and dim `↓` separators.
pub(crate) fn render_workflow_run(
    card: &WorkflowRunCard,
    width: u16,
    theme: &Theme,
    spin: usize,
) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let (done, total, errors, tokens, tool_calls) = card.totals();
    let phase_title = card
        .phases
        .iter()
        .find(|phase| phase.index == card.current_phase)
        .map(|phase| phase.title.as_str());
    let status = if card.finished {
        if errors > 0 { "failed" } else { "done" }
    } else {
        phase_title.unwrap_or("starting")
    };

    // Title row: the tree had no header at all, so a run was a set of anonymous boxes with no name,
    // no run id, no run-level progress and no clock.
    let mut head = vec![
        Span::styled(
            if card.finished {
                primary_marker().to_string()
            } else {
                braille_frame(spin).to_string()
            },
            Style::default().fg(if card.finished {
                theme.faint
            } else {
                theme.accent
            }),
        ),
        Span::raw(" "),
        Span::styled(
            card.name.clone(),
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" \u{b7} {status} \u{b7} {done}/{total}"),
            Style::default().fg(theme.muted),
        ),
    ];
    if errors > 0 {
        head.push(Span::styled(
            format!(" \u{b7} {errors} failed"),
            Style::default().fg(theme.error),
        ));
    }
    head.push(Span::styled(
        format!(
            " \u{b7} {}",
            events::fmt_duration(card.started.elapsed().as_millis() as u64)
        ),
        Style::default().fg(theme.faint),
    ));
    if card.verbose && width >= 80 {
        head.push(Span::styled(
            format!(" \u{b7} {}", card.run_id),
            Style::default().fg(theme.faint),
        ));
    }
    if !card.verbose && width >= 48 {
        head.push(Span::styled(
            " \u{b7} ctrl+o expand".to_string(),
            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
        ));
    }
    // A run name is operator-supplied and unbounded, so the title row is the one row that can be
    // longer than the pane. Every other row in this tree is already budgeted (`fit_spans` inside
    // the phase box, `clip_text` for the result preview); the title was not, and a wide terminal
    // hid that until a narrow one cut the row at the pane edge with nothing to say it had. It goes
    // through the same helper the box rows do.
    out.push(Line::from(fit_spans(head, width)));
    if !card.verbose {
        return out;
    }
    out.push(Line::default());

    // Narrator: newest log as `❯ <msg>`, up to two prior logs dim below, then a blank margin row.
    if let Some(newest) = card.logs.last() {
        out.push(Line::from(vec![
            Span::styled(
                "\u{276f} ", // ❯
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(newest.clone(), Style::default().fg(theme.fg)),
        ]));
        let end = card.logs.len().saturating_sub(1);
        let start = card.logs.len().saturating_sub(3);
        for msg in &card.logs[start..end] {
            out.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    msg.clone(),
                    Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
                ),
            ]));
        }
        out.push(Line::default());
    }

    // A declared-but-not-yet-reached phase has no agents. Pre-registering it is not enough on its
    // own: the empty-group guard below used to skip it, so the layout still grew phase by phase.
    let use_boxes = width >= 24 && !card.phases.is_empty();

    if use_boxes {
        let mut ordered: Vec<&WorkflowRunPhase> = card.phases.iter().collect();
        ordered.sort_by_key(|p| p.index);
        let mut first = true;
        for phase in ordered {
            let agents: Vec<&WorkflowRunAgent> = card
                .agents
                .iter()
                .filter(|a| a.phase_index == phase.index)
                .collect();
            if !first {
                out.push(Line::from(Span::styled(
                    " \u{2193}", // ↓
                    Style::default().fg(theme.faint),
                )));
            }
            first = false;
            out.extend(render_phase_box(
                Some(phase),
                &agents,
                card,
                width,
                theme,
                spin,
            ));
        }
        let orphans: Vec<&WorkflowRunAgent> =
            card.agents.iter().filter(|a| a.phase_index == 0).collect();
        if !orphans.is_empty() {
            if !first {
                out.push(Line::from(Span::styled(
                    " \u{2193}",
                    Style::default().fg(theme.faint),
                )));
            }
            out.extend(render_phase_box(None, &orphans, card, width, theme, spin));
        }
    } else {
        // Flat-list fallback: no boxes, just the branch rows (design §3.3 "falls back to a flat list
        // when no agent has a phase index").
        let agents: Vec<&WorkflowRunAgent> = card.agents.iter().collect();
        for row in agent_row_lines(&agents, theme, spin, card.verbose, width) {
            out.push(Line::from(row));
        }
        if card.agents.is_empty() {
            out.push(Line::from(Span::styled(
                "\u{2026}starting workflow", // …starting workflow
                Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
            )));
        }
    }

    // Run totals. Per-agent token counts arrive on every finish event and were never summed, so a
    // finished run reported no cost evidence and no elapsed at all.
    let mut totals = vec![Span::styled(
        format!("{done}/{total} agents"),
        Style::default().fg(theme.muted),
    )];
    if errors > 0 {
        totals.push(Span::styled(
            format!(" \u{b7} {errors} failed"),
            Style::default().fg(theme.error),
        ));
    }
    if tokens > 0 {
        totals.push(Span::styled(
            format!(" \u{b7} {} tok", events::fmt_count(tokens)),
            Style::default().fg(theme.muted),
        ));
    }
    if tool_calls > 0 {
        totals.push(Span::styled(
            format!(" \u{b7} {}", plural(tool_calls as usize, "tool call")),
            Style::default().fg(theme.muted),
        ));
    }
    totals.push(Span::styled(
        format!(
            " \u{b7} {}",
            events::fmt_duration(card.started.elapsed().as_millis() as u64)
        ),
        Style::default().fg(theme.muted),
    ));
    out.push(Line::default());
    // The footer accumulates columns as a run grows (agents, failures, tokens, tool calls, clock),
    // so it outgrows a narrow pane on its own without any operator input. Same helper, same
    // guarantee: the elapsed column is the one that disappears first, and the row says so.
    out.push(Line::from(fit_spans(totals, width)));

    out
}

/// Fit already-rendered workflow rows into a fixed row budget without silently clipping either end
/// of the tree. [`render_workflow_run`] already establishes the semantic order, so this only selects
/// a contiguous window from those rows and reports how many ordered rows sit above and below it.
/// The final totals row is kept outside that window and is therefore always visible when
/// `max_rows > 0`; with a one-row budget it is the only row returned.
///
/// It takes rows rather than a card because the workflow region has to render the tree BEFORE the
/// layout is resolved — the natural row count is what it asks the layout for — and then fit the
/// height it is granted. Rendering the card a second time here would build the same live tree twice
/// per frame at 10 fps, and would let the two renders disagree if a spinner frame or an event landed
/// between them.
pub(crate) fn window_workflow_rows(
    mut rows: Vec<Line<'static>>,
    max_rows: usize,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if rows.len() <= max_rows {
        return rows;
    }
    if max_rows == 0 {
        return Vec::new();
    }

    let footer = rows
        .pop()
        .expect("workflow renderer always emits a totals footer");
    if max_rows == 1 {
        return vec![footer];
    }

    let indicator = |arrow: char, hidden: usize| {
        Line::from(Span::styled(
            format!("{arrow} {hidden} more"),
            Style::default().fg(theme.faint).add_modifier(Modifier::DIM),
        ))
    };
    let body_slots = max_rows - 1;

    // Budgets of two or three rows cannot hold both directional indicators and useful content.
    // Keep the tail nearest the immutable footer and account for everything hidden above it.
    if body_slots < 3 {
        let visible_rows = body_slots - 1;
        let hidden_above = rows.len() - visible_rows;
        let mut out = Vec::with_capacity(max_rows);
        out.push(indicator('\u{2191}', hidden_above)); // ↑
        out.extend(rows.into_iter().skip(hidden_above));
        out.push(footer);
        return out;
    }

    // A balanced window preserves context from both halves of a long, already-ordered workflow.
    // The two indicator rows are part of the hard budget, not additions after truncation.
    let visible_rows = body_slots - 2;
    let hidden_rows = rows.len() - visible_rows;
    let hidden_above = hidden_rows / 2;
    let hidden_below = hidden_rows - hidden_above;
    let mut out = Vec::with_capacity(max_rows);
    out.push(indicator('\u{2191}', hidden_above)); // ↑
    out.extend(rows.into_iter().skip(hidden_above).take(visible_rows));
    out.push(indicator('\u{2193}', hidden_below)); // ↓
    out.push(footer);
    out
}

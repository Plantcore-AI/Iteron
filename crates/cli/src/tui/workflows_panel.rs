//! Fullscreen workflow control panel.
//!
//! The panel owns selection and pending-action presentation only. Run trees remain authoritative
//! in transcript [`crate::block::WorkflowRunCard`] values; durable history remains authoritative in
//! workflow sidecars; live ownership remains authoritative in [`WorkflowSupervisor`]. The parent
//! TUI projects those sources into bounded [`Run`] snapshots for each input/render boundary.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block as WidgetBlock, Borders, Paragraph};

use crate::theme;
use crate::workflow::{SupervisedRunInfo, SupervisedRunStatus};

pub(crate) const MAX_RUNS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunState {
    Running,
    Cancelling,
    Done,
    Failed,
    Stopped,
    Pending,
}

impl RunState {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Cancelling => "stopping",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
            Self::Pending => "pending",
        }
    }

    fn glyph(self, spin: usize) -> &'static str {
        const SPIN: [&str; 4] = ["⠋", "⠙", "⠹", "⠸"];
        match self {
            Self::Running => SPIN[spin % SPIN.len()],
            Self::Cancelling => "◌",
            Self::Done => "●",
            Self::Failed => "×",
            Self::Stopped => "■",
            Self::Pending => "○",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentState {
    Queued,
    Running,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone)]
pub(crate) struct Agent {
    pub(crate) label: String,
    pub(crate) state: AgentState,
    pub(crate) meta: String,
    pub(crate) activity: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Phase {
    pub(crate) title: String,
    pub(crate) agents: Vec<Agent>,
}

#[derive(Debug, Clone)]
pub(crate) struct Run {
    pub(crate) run_id: String,
    pub(crate) name: String,
    pub(crate) model: String,
    pub(crate) state: RunState,
    pub(crate) elapsed_ms: u64,
    pub(crate) phases: Vec<Phase>,
    pub(crate) can_kill: bool,
    pub(crate) can_resume: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Cancel(String),
    Resume(String),
    NewPrompt,
}

#[derive(Default)]
pub(crate) struct View {
    open: bool,
    selected_run: Option<String>,
    selected_phase: usize,
    selected_agent: usize,
    notice: String,
    pending: Option<String>,
    owned: HashMap<String, SupervisedRunInfo>,
}

impl View {
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    pub(crate) fn open(&mut self) {
        self.open = true;
        self.notice.clear();
        self.pending = None;
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
        self.pending = None;
    }

    pub(crate) fn reset(&mut self) {
        self.close();
        self.selected_run = None;
        self.selected_phase = 0;
        self.selected_agent = 0;
        self.notice.clear();
        self.owned.clear();
    }

    pub(crate) fn update_inventory(&mut self, runs: Vec<SupervisedRunInfo>) {
        self.owned = runs
            .into_iter()
            .map(|run| (run.run_id.clone(), run))
            .collect();
    }

    pub(crate) fn owned(&self, run_id: &str) -> Option<&SupervisedRunInfo> {
        self.owned.get(run_id)
    }

    pub(crate) fn owned_runs(&self) -> impl Iterator<Item = &SupervisedRunInfo> {
        self.owned.values()
    }

    pub(crate) fn begin_action(&mut self, label: impl Into<String>) {
        let label = label.into();
        self.notice = format!("{label}…");
        self.pending = Some(label);
    }

    pub(crate) fn finish_action(&mut self, notice: impl Into<String>) {
        self.pending = None;
        self.notice = notice.into();
    }

    fn reconcile(&mut self, runs: &[Run]) {
        if runs.is_empty() {
            self.selected_run = None;
            self.selected_phase = 0;
            self.selected_agent = 0;
            return;
        }
        let selected_exists = self
            .selected_run
            .as_deref()
            .is_some_and(|selected| runs.iter().any(|run| run.run_id == selected));
        if !selected_exists {
            self.selected_run = Some(runs[0].run_id.clone());
            self.selected_phase = 0;
            self.selected_agent = 0;
        }
        let Some(run) = self.selected(runs) else {
            return;
        };
        self.selected_phase = self.selected_phase.min(run.phases.len().saturating_sub(1));
        let agents = run
            .phases
            .get(self.selected_phase)
            .map_or(0, |phase| phase.agents.len());
        self.selected_agent = self.selected_agent.min(agents.saturating_sub(1));
    }

    fn selected<'a>(&self, runs: &'a [Run]) -> Option<&'a Run> {
        let selected = self.selected_run.as_deref()?;
        runs.iter().find(|run| run.run_id == selected)
    }

    fn cycle_run(&mut self, runs: &[Run], delta: isize) {
        if runs.is_empty() {
            return;
        }
        let current = self
            .selected_run
            .as_deref()
            .and_then(|id| runs.iter().position(|run| run.run_id == id))
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(runs.len() as isize) as usize;
        self.selected_run = Some(runs[next].run_id.clone());
        self.selected_phase = 0;
        self.selected_agent = 0;
    }

    pub(crate) fn key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        runs: &[Run],
    ) -> Option<Action> {
        self.reconcile(runs);
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.close(),
            KeyCode::Tab if modifiers.contains(KeyModifiers::SHIFT) => self.cycle_run(runs, -1),
            KeyCode::BackTab => self.cycle_run(runs, -1),
            KeyCode::Tab => self.cycle_run(runs, 1),
            KeyCode::Left | KeyCode::Char('h') => {
                self.selected_phase = self.selected_phase.saturating_sub(1);
                self.selected_agent = 0;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(run) = self.selected(runs) {
                    self.selected_phase =
                        (self.selected_phase + 1).min(run.phases.len().saturating_sub(1));
                    self.selected_agent = 0;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_agent = self.selected_agent.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(run) = self.selected(runs) {
                    let agents = run
                        .phases
                        .get(self.selected_phase)
                        .map_or(0, |phase| phase.agents.len());
                    self.selected_agent = (self.selected_agent + 1).min(agents.saturating_sub(1));
                }
            }
            KeyCode::Char('x') => {
                if self.pending.is_some() {
                    self.notice = "another workflow action is still pending".into();
                } else if let Some(run) = self.selected(runs) {
                    if run.can_kill {
                        return Some(Action::Cancel(run.run_id.clone()));
                    }
                    self.notice = "selected run is not a live session-owned workflow".into();
                }
            }
            KeyCode::Char('r') => {
                if self.pending.is_some() {
                    self.notice = "another workflow action is still pending".into();
                } else if let Some(run) = self.selected(runs) {
                    if run.can_resume {
                        return Some(Action::Resume(run.run_id.clone()));
                    }
                    self.notice = "selected run must settle before it can resume".into();
                }
            }
            KeyCode::Char('n') => {
                self.close();
                return Some(Action::NewPrompt);
            }
            _ => {}
        }
        self.reconcile(runs);
        None
    }
}

fn state_style(state: RunState, theme: &theme::Theme) -> Style {
    Style::default().fg(match state {
        RunState::Running => theme.accent,
        RunState::Cancelling | RunState::Stopped => theme.warn,
        RunState::Done => theme.success,
        RunState::Failed => theme.error,
        RunState::Pending => theme.faint,
    })
}

fn agent_style(state: AgentState, theme: &theme::Theme) -> Style {
    Style::default().fg(match state {
        AgentState::Running => theme.accent,
        AgentState::Done => theme.success,
        AgentState::Failed => theme.error,
        AgentState::Queued | AgentState::Skipped => theme.faint,
    })
}

fn agent_glyph(state: AgentState, spin: usize) -> &'static str {
    const SPIN: [&str; 4] = ["⠋", "⠙", "⠹", "⠸"];
    match state {
        AgentState::Queued => "○",
        AgentState::Running => SPIN[spin % SPIN.len()],
        AgentState::Done => "●",
        AgentState::Failed => "×",
        AgentState::Skipped => "–",
    }
}

fn elapsed(ms: u64) -> String {
    let seconds = ms / 1000;
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    }
}

fn footer(view: &View, width: u16, theme: &theme::Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if !view.notice.is_empty() {
        let mut spans = vec![Span::styled("› ", Style::default().fg(theme.accent))];
        spans.extend(crate::semantic_text::spans(
            &view.notice,
            crate::semantic_text::Tone::Body,
            theme,
        ));
        lines.push(Line::from(spans));
    }
    let help = if width >= 90 {
        "tab switch run · ←→ phase · ↑↓ agent · x stop · r resume · n new prompt · q close"
    } else {
        "tab run · arrows navigate · x stop · r resume · n prompt · q close"
    };
    lines.push(Line::from(super::footer_spans(help, theme)));
    lines
}

pub(crate) fn render(
    frame: &mut Frame,
    view: &mut View,
    runs: &[Run],
    session_name: &str,
    theme: &theme::Theme,
    spin: usize,
) {
    view.reconcile(runs);
    let area = frame.area();
    frame.render_widget(ratatui::widgets::Clear, area);
    if area.width == 0 || area.height == 0 {
        return;
    }
    let footer_height = if view.notice.is_empty() { 1 } else { 2 }.min(area.height);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2.min(area.height.saturating_sub(1))),
            Constraint::Min(0),
            Constraint::Length(footer_height),
        ])
        .split(area);

    let live = runs
        .iter()
        .filter(|run| matches!(run.state, RunState::Running | RunState::Cancelling))
        .count();
    let header_style = if theme.mono {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default()
            .fg(theme.on_accent)
            .bg(theme.accent)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                " ◩ plantcore · {} · workflows  {} runs · {} live ",
                session_name,
                runs.len(),
                live
            ),
            header_style,
        ))),
        rows[0],
    );

    let mut tabs = Vec::new();
    for (index, run) in runs.iter().enumerate() {
        if index > 0 {
            tabs.push(Span::styled("  ·  ", Style::default().fg(theme.faint)));
        }
        let selected = view.selected_run.as_deref() == Some(run.run_id.as_str());
        let mut style = state_style(run.state, theme);
        if selected {
            style = if theme.mono {
                style.add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                style
                    .bg(theme.user_bg)
                    .fg(theme.user_fg)
                    .add_modifier(Modifier::BOLD)
            };
        }
        tabs.push(Span::styled(
            format!(
                " {} {} · {} ",
                run.state.glyph(spin),
                run.name,
                run.state.label()
            ),
            style,
        ));
    }
    if tabs.is_empty() {
        tabs.push(Span::styled(
            " no workflow runs yet ",
            Style::default().fg(theme.muted),
        ));
    }
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(tabs),
            Line::from(Span::styled(
                "─".repeat(rows[1].width as usize),
                Style::default().fg(theme.border),
            )),
        ]),
        rows[1],
    );

    let Some(run) = view.selected(runs) else {
        frame.render_widget(
            Paragraph::new(vec![
                Line::default(),
                Line::from(Span::styled(
                    "No workflow has been launched in this workspace.",
                    Style::default().fg(theme.muted),
                )),
                Line::from(Span::styled(
                    "Press n to return to the composer and start one.",
                    Style::default().fg(theme.faint),
                )),
            ]),
            rows[2],
        );
        frame.render_widget(Paragraph::new(footer(view, area.width, theme)), rows[3]);
        return;
    };

    let panes = if rows[2].width >= 68 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(29), Constraint::Percentage(71)])
            .split(rows[2])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
            .split(rows[2])
    };

    let mut phase_lines = Vec::new();
    for (index, phase) in run.phases.iter().enumerate() {
        let selected = index == view.selected_phase;
        let done = phase
            .agents
            .iter()
            .filter(|agent| agent.state == AgentState::Done)
            .count();
        let failed = phase
            .agents
            .iter()
            .filter(|agent| agent.state == AgentState::Failed)
            .count();
        let running = phase
            .agents
            .iter()
            .any(|agent| agent.state == AgentState::Running);
        let glyph = if failed > 0 {
            "×"
        } else if running {
            "◌"
        } else if !phase.agents.is_empty() && done == phase.agents.len() {
            "●"
        } else {
            "○"
        };
        let style = if selected {
            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.muted)
        };
        phase_lines.push(Line::from(vec![
            Span::styled(
                if selected { "› " } else { "  " },
                Style::default().fg(theme.accent),
            ),
            Span::styled(format!("{glyph} {}", phase.title), style),
            Span::styled(
                format!("  {done}/{}", phase.agents.len()),
                Style::default().fg(theme.faint),
            ),
        ]));
    }
    if phase_lines.is_empty() {
        phase_lines.push(Line::from(Span::styled(
            "  ○ awaiting phase data",
            Style::default().fg(theme.faint),
        )));
    }
    frame.render_widget(
        Paragraph::new(phase_lines).block(
            WidgetBlock::default()
                .title(" phases ")
                .borders(if rows[2].width >= 68 {
                    Borders::RIGHT
                } else {
                    Borders::BOTTOM
                })
                .border_style(Style::default().fg(theme.border)),
        ),
        panes[0],
    );

    let agents = run
        .phases
        .get(view.selected_phase)
        .map(|phase| phase.agents.as_slice())
        .unwrap_or(&[]);
    let mut agent_lines = Vec::new();
    for (index, agent) in agents.iter().enumerate() {
        let selected = index == view.selected_agent;
        let style = if selected {
            if theme.mono {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default()
                    .fg(theme.user_fg)
                    .bg(theme.user_bg)
                    .add_modifier(Modifier::BOLD)
            }
        } else {
            Style::default().fg(theme.fg)
        };
        agent_lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", agent_glyph(agent.state, spin)),
                agent_style(agent.state, theme),
            ),
            Span::styled(agent.label.clone(), style),
            Span::styled(
                if agent.meta.is_empty() {
                    String::new()
                } else {
                    format!("  · {}", agent.meta)
                },
                Style::default().fg(theme.muted),
            ),
        ]));
        if selected && let Some(activity) = &agent.activity {
            let mut spans = vec![
                Span::raw("    "),
                Span::styled("↳ ", Style::default().fg(theme.accent)),
            ];
            spans.extend(crate::semantic_text::spans(
                activity,
                crate::semantic_text::Tone::Muted,
                theme,
            ));
            agent_lines.push(Line::from(spans));
        }
    }
    if agents.is_empty() {
        agent_lines.push(Line::from(Span::styled(
            " ○ no agents declared in this phase",
            Style::default().fg(theme.faint),
        )));
    }
    let model = if run.model.is_empty() {
        String::new()
    } else {
        format!(" · {}", run.model)
    };
    let title = format!(
        " {} · {}{} · {} ",
        run.name,
        run.run_id,
        model,
        elapsed(run.elapsed_ms)
    );
    frame.render_widget(
        Paragraph::new(agent_lines).block(
            WidgetBlock::default()
                .title(title)
                .title_style(Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)),
        ),
        panes[1],
    );
    frame.render_widget(Paragraph::new(footer(view, area.width, theme)), rows[3]);
}

pub(crate) fn owned_state(info: &SupervisedRunInfo) -> RunState {
    match info.status {
        SupervisedRunStatus::Running => RunState::Running,
        SupervisedRunStatus::Cancelling => RunState::Cancelling,
        SupervisedRunStatus::Settled => RunState::Done,
        SupervisedRunStatus::Failed => RunState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(id: &str, state: RunState) -> Run {
        Run {
            run_id: id.into(),
            name: id.into(),
            model: String::new(),
            state,
            elapsed_ms: 0,
            phases: vec![Phase {
                title: "phase".into(),
                agents: vec![Agent {
                    label: "agent".into(),
                    state: AgentState::Running,
                    meta: String::new(),
                    activity: None,
                }],
            }],
            can_kill: state == RunState::Running,
            can_resume: state != RunState::Running,
        }
    }

    #[test]
    fn tab_cycles_runs_and_navigation_is_bounded() {
        let runs = vec![run("one", RunState::Running), run("two", RunState::Done)];
        let mut view = View::default();
        view.open();
        view.key(KeyCode::Tab, KeyModifiers::NONE, &runs);
        assert_eq!(view.selected_run.as_deref(), Some("two"));
        view.key(KeyCode::Down, KeyModifiers::NONE, &runs);
        assert_eq!(view.selected_agent, 0);
        view.key(KeyCode::BackTab, KeyModifiers::SHIFT, &runs);
        assert_eq!(view.selected_run.as_deref(), Some("one"));
    }

    #[test]
    fn actions_are_state_gated_and_new_prompt_closes() {
        let running = vec![run("live", RunState::Running)];
        let settled = vec![run("done", RunState::Done)];
        let mut view = View::default();
        view.open();
        assert_eq!(
            view.key(KeyCode::Char('x'), KeyModifiers::NONE, &running),
            Some(Action::Cancel("live".into()))
        );
        view.selected_run = None;
        assert_eq!(
            view.key(KeyCode::Char('r'), KeyModifiers::NONE, &settled),
            Some(Action::Resume("done".into()))
        );
        assert_eq!(
            view.key(KeyCode::Char('n'), KeyModifiers::NONE, &settled),
            Some(Action::NewPrompt)
        );
        assert!(!view.is_open());
    }

    #[test]
    fn terminal_render_exposes_tabs_phases_agents_and_real_controls() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut live = run("wf-live", RunState::Running);
        live.name = "repository audit".into();
        live.model = "model-a".into();
        live.phases[0].title = "exploring".into();
        live.phases[0].agents[0].label = "investigator · ownership".into();
        live.phases[0].agents[0].activity = Some("reading governance boundaries".into());
        let runs = vec![live];
        let mut view = View::default();
        view.open();
        let theme = theme::Theme::terminal();
        let mut terminal = Terminal::new(TestBackend::new(110, 26)).unwrap();
        terminal
            .draw(|frame| render(frame, &mut view, &runs, "Inspect repository", &theme, 1))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }

        for expected in [
            "plantcore · Inspect repository · workflows",
            "repository audit · running",
            "exploring",
            "investigator · ownership",
            "reading governance boundaries",
            "x stop · r resume · n new prompt",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?}:\n{rendered}"
            );
        }
    }
}

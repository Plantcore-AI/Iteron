//! CLI-side workflow wiring: a real provider-backed [`AgentSpawner`] and the non-TTY stdout progress
//! renderer (design §3.5). The `core workflow run` subcommand (in `main.rs`) composes these with
//! `core_workflow::WorkflowEngine`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use core_protocol::{Effort, Message};
use core_provider::{Provider, StreamItem, TurnRequest};
use core_workflow::events::{ProgressEvent, ProgressSink, WorkflowState, fmt_count, fmt_duration};
use core_workflow::{AgentCall, AgentOutcome, AgentSpawner, RunReport, RunSpec, WorkflowEngine};
use serde::{Deserialize, Serialize};

/// The system prompt every workflow sub-agent runs under. Kept terse: a workflow `agent()` call is a
/// bounded, single-shot query, not a full coding session.
const SUBAGENT_SYSTEM: &str = "You are a focused sub-agent inside a Core Code workflow. Answer the \
given task directly and concisely in plain text. Do not ask clarifying questions; produce exactly \
the requested output and nothing else.";

/// FIRST-SLICE SPAWNER: one real provider completion per `agent()` call.
///
/// This is genuine model output (not a mock), but it is a single turn with no tools and no child
/// `Agent` loop. The upgrade seam is documented: swap this for a `run_leaf`-based owned child
/// `Agent` (fresh read-only `Registry`, child `Rollout`, inherited route/pricing) — see
/// `crates/kernel` `prepare_investigator`/`PreparedInvestigator::run`. The trait boundary does not
/// change, so nothing above this line moves when that lands.
pub struct ProviderSpawner {
    provider: Arc<dyn Provider>,
    model: String,
    max_tokens: u32,
    default_effort: Effort,
}

impl ProviderSpawner {
    pub fn new(provider: Arc<dyn Provider>, model: String) -> Self {
        ProviderSpawner {
            provider,
            model,
            max_tokens: 2048,
            // Low keeps the demo fast/cheap; a per-call `opts.effort` overrides it.
            default_effort: Effort::Low,
        }
    }
}

#[async_trait]
impl AgentSpawner for ProviderSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        let effort = call.effort.unwrap_or(self.default_effort);
        let model = call.model.clone().unwrap_or_else(|| self.model.clone());
        let request = TurnRequest {
            model,
            system: SUBAGENT_SYSTEM.to_string(),
            messages: vec![Message::user_text(call.prompt.clone())],
            tools: Vec::new(),
            max_tokens: self.max_tokens,
            cache_system: false,
            thinking_budget: effort.thinking_budget(),
            reasoning_effort: effort.reasoning_effort(),
        };
        // No mid-stream overlap needed here: we only want the final text.
        let mut on_item = |_item: StreamItem| {};
        match self.provider.turn(&request, &mut on_item).await {
            Ok(result) => {
                let text = result.text();
                let tokens = result
                    .usage
                    .complete_usage()
                    .map(|usage| usage.input + usage.output)
                    .unwrap_or(0);
                if text.trim().is_empty() {
                    AgentOutcome::null("empty completion")
                } else {
                    AgentOutcome::text(text, tokens)
                }
            }
            Err(error) => AgentOutcome::null(format!("provider error: {error}")),
        }
    }
}

/// The non-TTY plain renderer (design §3.5): one line per event, no spinner, no cursor movement —
/// pipe/CI safe. Lives on stdout so it composes with normal shell redirection.
pub struct StdoutProgressSink;

impl StdoutProgressSink {
    pub fn new() -> Self {
        StdoutProgressSink
    }
}

impl Default for StdoutProgressSink {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressSink for StdoutProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let line = match event {
            ProgressEvent::Phase { title, .. } => {
                format!("\u{2500}\u{2500} {title} \u{2500}\u{2500}")
            }
            ProgressEvent::Log { message } => format!("\u{276f} {message}"),
            ProgressEvent::AgentStarted {
                index,
                label,
                model,
                ..
            } => match model {
                Some(model) => format!("[start] #{index} {label} ({model})"),
                None => format!("[start] #{index} {label}"),
            },
            // Streamed per-turn activity is not surfaced by the plain renderer (design §3.5).
            ProgressEvent::AgentActivity { .. } => return,
            ProgressEvent::AgentFinished {
                index,
                label,
                state,
                tokens,
                tool_calls,
                duration_ms,
                error,
                ..
            } => match state {
                WorkflowState::Done => {
                    let mut parts = vec![format!("{} tok", fmt_count(tokens))];
                    if tool_calls > 0 {
                        let noun = if tool_calls == 1 { "tool" } else { "tools" };
                        parts.push(format!("{tool_calls} {noun}"));
                    }
                    parts.push(fmt_duration(duration_ms));
                    format!("[done] #{index} {label} \u{b7} {}", parts.join(" \u{b7} "))
                }
                _ => {
                    let detail = error.unwrap_or_else(|| "error".into());
                    format!("[error] #{index} {label} - {detail}")
                }
            },
        };
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

/// A [`ProgressSink`] that folds every engine event into a shared live [`crate::block::WorkflowRunCard`]
/// — the TTY counterpart of [`StdoutProgressSink`]. Reading the card each frame + this upsert IS the
/// design §3.2 store step; the live loop below drives the render.
pub struct CardProgressSink {
    card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>,
}

impl CardProgressSink {
    pub fn new(card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>) -> Self {
        CardProgressSink { card }
    }
}

impl ProgressSink for CardProgressSink {
    fn emit(&self, event: ProgressEvent) {
        if let Ok(mut card) = self.card.lock() {
            card.ingest(event);
        }
    }
}

/// Restores the terminal (leaves raw mode + the alternate screen, shows the cursor) on drop, so an
/// early `?` or a Ctrl-C never leaves the terminal wedged — the #1 TUI failure mode.
struct LiveTermGuard;

impl LiveTermGuard {
    fn enter() -> anyhow::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::cursor::Hide
        )?;
        Ok(LiveTermGuard)
    }
}

impl Drop for LiveTermGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::cursor::Show,
            crossterm::terminal::LeaveAlternateScreen
        );
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Flatten rendered lines to plain text (styling dropped) so the settled tree can be echoed into the
/// normal terminal scrollback after the alternate screen is left.
fn plain_lines(lines: &[ratatui::text::Line<'static>]) -> String {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the QuickJS-workflow phase→agent tree LIVE (design §3.3) while `future` (a running or
/// background workflow) drives `card` through [`CardProgressSink`], advancing the braille spinner
/// every 80ms, then leave the alternate screen and echo the settled tree into scrollback. Shared by
/// the blocking `run`/`resume` path ([`run_live`]) and the background `launch` path ([`watch_live`]).
async fn render_live<F>(
    card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>,
    future: F,
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport>
where
    F: std::future::Future<Output = anyhow::Result<RunReport>>,
{
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;
    use ratatui::widgets::Paragraph;

    let (report, final_plain) = {
        let _guard = LiveTermGuard::enter()?;
        let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
        let mut spin: usize = 0;

        tokio::pin!(future);
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(80));

        let report = loop {
            term.draw(|frame| {
                let area = frame.area();
                let snapshot = card.lock().unwrap();
                let lines = crate::block::render_workflow_run(&snapshot, area.width, theme, spin);
                drop(snapshot);
                frame.render_widget(Paragraph::new(lines), area);
            })?;
            tokio::select! {
                result = &mut future => break result?,
                _ = ticker.tick() => spin = spin.wrapping_add(1),
            }
        };

        if let Ok(mut card) = card.lock() {
            card.finished = true;
        }
        let mut final_plain = String::new();
        term.draw(|frame| {
            let area = frame.area();
            let snapshot = card.lock().unwrap();
            let lines = crate::block::render_workflow_run(&snapshot, area.width, theme, spin);
            final_plain = plain_lines(&lines);
            frame.render_widget(Paragraph::new(lines), area);
        })?;
        (report, final_plain)
    };

    // Terminal restored — echo the settled tree into normal scrollback so it survives the run.
    if !final_plain.trim().is_empty() {
        println!("{final_plain}");
    }
    Ok(report)
}

/// Run one fully-specified [`RunSpec`] to completion on the caller's runtime, rendering the live tree
/// (design §3.3). The journal/resume-aware upgrade of the old in-memory `run_live`; `core workflow
/// run` (TTY) and `core workflow resume` (TTY) both call it. Non-TTY uses [`StdoutProgressSink`].
pub async fn run_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    let card = Arc::new(std::sync::Mutex::new(crate::block::WorkflowRunCard::new(
        spec.run_id.as_str(),
        name,
    )));
    let sink: Arc<dyn ProgressSink> = Arc::new(CardProgressSink::new(card.clone()));
    let future = WorkflowEngine::execute(spec, spawner, sink);
    render_live(card, future, theme).await
}

/// Launch a run in the BACKGROUND (via [`WorkflowEngine::launch`] → `RunHandle`, review B3) and
/// attach the live tree to it: the run drives its own OS thread + runtime while this foreground loop
/// renders the shared card and `join`s the handle. This is the `RunHandle` counterpart of
/// [`run_live`]; `core workflow watch <runId>` uses it. Non-TTY uses [`StdoutProgressSink`].
pub async fn watch_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    let card = Arc::new(std::sync::Mutex::new(crate::block::WorkflowRunCard::new(
        spec.run_id.as_str(),
        name,
    )));
    let sink: Arc<dyn ProgressSink> = Arc::new(CardProgressSink::new(card.clone()));
    let handle = WorkflowEngine::launch(spec, spawner, sink);
    let future = async move { handle.join().await };
    render_live(card, future, theme).await
}

// ---------------------------------------------------------------------------------------------
// Persistence + enumeration for the background-launch surface (`core workflow list/resume/watch`).
//
// The engine persists only the outcome `journal.jsonl` under `<workflows_dir>/<run_id>/`. To make a
// run re-launchable (`resume`/`watch`) and listable by a LATER process, the CLI writes two sidecars
// next to that journal: `run.json` (the manifest — script identity, args, route, name, timestamp)
// and, at completion, `result.json` (the return value + cache metrics + stopped flag). The script
// source itself is copied to `script.js` so a resume needs no `--script` path. None of this is the
// hash-chained rollout; it is lightweight run metadata, mirroring the journal's own posture.
// ---------------------------------------------------------------------------------------------

/// The re-launchable identity of a persisted workflow run (`<workflows_dir>/<run_id>/run.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub name: String,
    pub args: serde_json::Value,
    pub provider_id: String,
    pub model: String,
    pub created_at: u64,
}

/// The terminal outcome of a run (`<workflows_dir>/<run_id>/result.json`), written once it settles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub value: serde_json::Value,
    pub stopped: bool,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub finished_at: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `<workflows_dir>/<run_id>/`.
pub fn run_dir(workflows_dir: &Path, run_id: &str) -> PathBuf {
    workflows_dir.join(run_id)
}

/// Persist the re-launchable inputs (script source + manifest) BEFORE the run starts, so a crash
/// mid-run still leaves a resumable record.
pub fn persist_inputs(
    workflows_dir: &Path,
    manifest: &RunManifest,
    script: &str,
) -> anyhow::Result<()> {
    let dir = run_dir(workflows_dir, &manifest.run_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("script.js"), script)?;
    std::fs::write(dir.join("run.json"), serde_json::to_vec_pretty(manifest)?)?;
    Ok(())
}

/// Persist the terminal outcome once the run settles (enables `list` status + shows the value later).
pub fn persist_result(
    workflows_dir: &Path,
    run_id: &str,
    report: &RunReport,
) -> anyhow::Result<()> {
    let dir = run_dir(workflows_dir, run_id);
    std::fs::create_dir_all(&dir)?;
    let result = RunResult {
        value: report.value.clone(),
        stopped: report.stopped,
        cache_hits: report.cache_hits,
        cache_misses: report.cache_misses,
        finished_at: now_secs(),
    };
    std::fs::write(dir.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}

pub fn load_manifest(workflows_dir: &Path, run_id: &str) -> Option<RunManifest> {
    let bytes = std::fs::read(run_dir(workflows_dir, run_id).join("run.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn load_result(workflows_dir: &Path, run_id: &str) -> Option<RunResult> {
    let bytes = std::fs::read(run_dir(workflows_dir, run_id).join("result.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The persisted script source for a prior run (so `resume`/`watch` need no `--script`).
pub fn load_script(workflows_dir: &Path, run_id: &str) -> Option<String> {
    std::fs::read_to_string(run_dir(workflows_dir, run_id).join("script.js")).ok()
}

/// One row of `core workflow list`.
pub struct RunListing {
    pub run_id: String,
    pub name: String,
    pub model: String,
    pub status: &'static str,
    pub agents: usize,
    pub created_at: u64,
}

/// Number of completed `agent()` calls recorded in a run's journal (one `"type":"result"` line each).
fn journal_agent_count(workflows_dir: &Path, run_id: &str) -> usize {
    let path = run_dir(workflows_dir, run_id).join("journal.jsonl");
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|l| l.contains("\"type\":\"result\""))
            .count(),
        Err(_) => 0,
    }
}

/// Enumerate every persisted run under `<workflows_dir>`, newest first. A run's status is derived
/// from its sidecars: `done`/`stopped` once `result.json` exists, else `running` if a journal is
/// present, else `pending`.
pub fn list_runs(workflows_dir: &Path) -> Vec<RunListing> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(workflows_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().into_owned();
        let manifest = load_manifest(workflows_dir, &run_id);
        let result = load_result(workflows_dir, &run_id);
        let has_journal = run_dir(workflows_dir, &run_id)
            .join("journal.jsonl")
            .exists();
        let status = match &result {
            Some(r) if r.stopped => "stopped",
            Some(_) => "done",
            None if has_journal => "running",
            None => "pending",
        };
        let created_at = manifest.as_ref().map(|m| m.created_at).unwrap_or(0);
        out.push(RunListing {
            run_id: run_id.clone(),
            name: manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| "workflow".into()),
            model: manifest
                .as_ref()
                .map(|m| m.model.clone())
                .unwrap_or_default(),
            status,
            agents: journal_agent_count(workflows_dir, &run_id),
            created_at,
        });
    }
    out.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(b.run_id.cmp(&a.run_id))
    });
    out
}

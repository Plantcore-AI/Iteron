//! CLI-side workflow wiring: a real provider-backed [`AgentSpawner`] and the non-TTY stdout progress
//! renderer (design §3.5). The `core workflow run` subcommand (in `main.rs`) composes these with
//! `core_workflow::WorkflowEngine`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use core_protocol::{Effort, Message};
use core_provider::{Provider, StreamItem, TurnRequest};
use core_workflow::events::{
    PREVIEW_MAX, PROGRESS_SINK_PORT_VERSION, ProgressEvent, ProgressSink, TOOL_SUMMARY_MAX,
    WorkflowState, fmt_count, fmt_duration, truncate_preview,
};
use core_workflow::{
    AgentCall, AgentOutcome, AgentSpawner, RunHandle, RunReport, RunSpec, WorkflowEngine,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde::{Deserialize, Serialize};

/// The system prompt every workflow sub-agent runs under. Kept terse: a workflow `agent()` call is a
/// bounded, single-shot query, not a full coding session.
const SUBAGENT_SYSTEM: &str = "You are a focused sub-agent inside a Core Code workflow. Answer the \
given task directly and concisely in plain text. Do not ask clarifying questions; produce exactly \
the requested output and nothing else.";

/// OPT-IN FALLBACK SPAWNER: one real provider completion per `agent()` call.
///
/// This is NOT the default. `core workflow run|resume|watch` builds a
/// [`crate::runtime::KernelSpawner`] — an owned child `Agent` with a read-only `Registry`, its own
/// child `Rollout`, and the parent's inherited route/pricing. This single-turn spawner is reached
/// only through `CORE_WORKFLOW_SPAWNER=provider`, where it is useful precisely because it has no
/// tools and no child `Agent` loop: it isolates provider behavior from harness behavior. The trait
/// boundary is the same for both, so nothing above this line depends on which one is installed.
/// This fallback supports only the built-in `generic` agent and the exact model resolved by the
/// composition root; it cannot reinterpret an agent definition or resolve another route.
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

    fn null(reason: &str) -> AgentOutcome {
        AgentOutcome::null(crate::runtime::safe_agent_refusal(reason))
    }
}

#[async_trait]
impl AgentSpawner for ProviderSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        if let Err(error) = call.validate_request_metadata() {
            return Self::null(error.public_reason());
        }
        if call
            .agent_type
            .as_deref()
            .is_some_and(|agent_type| agent_type != "generic")
        {
            return Self::null(
                "single-completion fallback supports only the built-in generic agent",
            );
        }
        if call
            .model
            .as_deref()
            .is_some_and(|model| model != self.model)
        {
            return Self::null("requested agent model has no separately resolved route evidence");
        }

        let effort = call.effort.unwrap_or(self.default_effort);
        let request = TurnRequest {
            model: self.model.clone(),
            system: SUBAGENT_SYSTEM.to_string(),
            messages: vec![Message::user_text(call.prompt.clone())],
            input_images: Vec::new(),
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
                    Self::null("provider completed without a report")
                } else {
                    AgentOutcome::text(text, tokens)
                }
            }
            Err(error) => Self::null(&format!("provider: {}", error.public_summary())),
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
            ProgressEvent::AgentQueued { index, label, .. } => {
                format!("[queued] #{index} {label}")
            }
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

/// A [`ProgressSink`] that keeps only the reasons agents DEGRADED — the in-turn (`Workflow` tool)
/// counterpart of [`StdoutProgressSink`], which has no terminal to render to.
///
/// A degraded `agent()` resolves to JS `null`, and the idiomatic `parallel(...).filter(Boolean)`
/// then removes it from the script's return value. Without this the model receives a plausible
/// short result and no indication that an aggregate ceiling, a provider error, or a budget
/// exhaustion silently removed agents from its run.
#[derive(Default)]
pub struct DegradedAgentSink {
    reasons: std::sync::Mutex<Vec<String>>,
}

impl DegradedAgentSink {
    pub fn new() -> Self {
        DegradedAgentSink::default()
    }

    /// One line per degraded agent, in completion order.
    pub fn reasons(&self) -> Vec<String> {
        self.reasons
            .lock()
            .map(|reasons| reasons.clone())
            .unwrap_or_default()
    }
}

impl ProgressSink for DegradedAgentSink {
    fn emit(&self, event: ProgressEvent) {
        let ProgressEvent::AgentFinished {
            index,
            label,
            state,
            error,
            ..
        } = event
        else {
            return;
        };
        if matches!(state, WorkflowState::Done) {
            return;
        }
        if let Ok(mut reasons) = self.reasons.lock() {
            let detail = error.unwrap_or_else(|| "error".into());
            reasons.push(format!("#{index} {label}: {detail}"));
        }
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

// ---------------------------------------------------------------------------------------------
// The interactive-TUI progress seam (ADR-0001 step 1,
// docs/project/decisions/0001-workflow-renderer-convergence.md).
//
// `core workflow run` (TTY) already renders the script engine's phase→agent tree through
// `CardProgressSink` above. A workflow launched from INSIDE the interactive TUI — the `Workflow`
// tool, `runtime.rs::launch_workflow` — had no such wire: the engine emitted `ProgressEvent`s into
// a sink that kept only degradation reasons, so the operator watched a blank turn for minutes.
// This carries the same events to the frontend, which folds them into the same
// `block::WorkflowRunCard`.
//
// # Why the events are NOT translated into `crate::runtime::WorkflowUiEvent`
//
// The two vocabularies look nearly interchangeable (`Phase`/`PhaseChanged`,
// `AgentStarted`/`AgentStarted`, `Done`|`Error`/`RunFinished`), and translating would let the
// already-live `App::workflow_event` render script runs with no new seam at all. ADR-0001 rejects
// that direction, and each of its reasons is checkable in this tree:
//
//   * `WorkflowUiEvent::PhaseChanged` carries `WorkflowPhaseUi` — a CLOSED enum of five native
//     ultracode stages (`crates/cli/src/runtime.rs`). A script's `phase('build index')` has no
//     member to map onto, so every script phase title would collapse to one arbitrary stage.
//   * There is no `Log` variant anywhere in `WorkflowUiEvent`, so `log()` narrator lines would have
//     to be dropped or smuggled into another variant's string field.
//   * `WorkflowUiEvent::PlanReady` fixes the task list up front and `App::workflow_event` matches
//     every later agent event against it by `agent_id`; a script's agent set is discovered as the
//     script runs, so rows that appeared later would silently match nothing and vanish.
//
// Widening `WorkflowUiEvent` is not an option either: it is a frozen type
// (`xtask/src/schema_compat_rust_semantics_functions.rs` `TYPES`), a published `stream-json`
// surface (`cli.machine-stream.workflow-*` in `governance/schema-compatibility.json`), and a
// published event-queue wire form (`crates/cli/src/client_event.rs`). Paying a CLI schema-version
// bump to make the RETIRING renderer more expressive is the wrong direction, which is exactly why
// ADR-0001 keeps that bump as its own release-contract PR.
//
// So the decision is: keep the engine's vocabulary whole and give it its own in-process seam.
// Concretely, for the two shapes the brief calls out —
//
//   * `Log` is CARRIED, not dropped: it reaches `WorkflowRunCard.logs` and renders as the narrator
//     line (`block.rs` `render_workflow_run`). Dropping it would delete the only output a script
//     has between agent calls.
//   * `Queued`/`Running`/`Skipped` are carried as themselves. `WorkflowState` is the engine's own
//     5-state model and `WorkflowRunAgent.state` already IS that type — the card reuses it rather
//     than duplicating it, so there is no lossy projection onto `WorkflowAgentOutcomeUi` (whose
//     `SkippedBudget`/`NotStarted` would each be an invented cause).
// ---------------------------------------------------------------------------------------------

/// The bound applied to a one-line display string (a `phase()` title, an `agent()` label, a model
/// id) on its way into retained transcript state. Long enough that no realistic label is cut,
/// short enough that a script cannot push a row off the screen.
const UI_LABEL_MAX: usize = 120;

/// One lifecycle message for a QuickJS workflow run, addressed to a frontend that can render the
/// live phase→agent tree ([`crate::block::WorkflowRunCard`]).
///
/// This is an in-process seam, not a published contract: it deliberately carries the engine's own
/// unfrozen [`ProgressEvent`] rather than a mirrored wire vocabulary, for the reasons above.
#[derive(Debug, Clone)]
pub enum WorkflowRunUiEvent {
    /// A run is about to start. `phases` are the script's DECLARED `meta.phases`, so the frontend
    /// lays every phase box out on the first frame instead of growing the tree as execution
    /// reaches them — the same seeding [`new_run_card`] does for the one-shot surface.
    Started {
        run_id: String,
        name: String,
        phases: Vec<String>,
    },
    /// One engine milestone, already presentation-safe.
    Progress {
        run_id: String,
        event: ProgressEvent,
    },
    /// The engine future for this run resolved. `ingest` alone never marks a card finished, so
    /// without this the tree would spin forever.
    Finished { run_id: String },
}

/// Apply the frontend's display gate to one untrusted line: secret-shaped substrings redacted and
/// terminal control characters escaped ([`crate::tui::ui_safe_text`]), then whitespace collapsed
/// and the result re-bounded — escaping can only GROW a string (`\u{1b}` becomes six characters),
/// so the bound has to be re-applied after it, exactly as `block::safe_result_preview` does.
fn safe_line(text: &str, max: usize) -> String {
    truncate_preview(&crate::tui::ui_safe_text(text), max)
}

/// The same gate for an optional field. A line that sanitizes away to nothing becomes `None`, so
/// the card renders no row rather than an empty stub.
fn safe_line_opt(text: Option<String>, max: usize) -> Option<String> {
    let safe = safe_line(text?.as_str(), max);
    (!safe.is_empty()).then_some(safe)
}

/// The display gate for a one-line label that reaches the frontend OUTSIDE a [`ProgressEvent`] —
/// the workflow name and the declared phase titles on [`WorkflowRunUiEvent::Started`]. Both are
/// read straight out of the script's `export const meta`, so they are as untrusted as anything
/// `ui_safe_progress` handles and get the identical treatment.
pub fn ui_safe_label(text: &str) -> String {
    safe_line(text, UI_LABEL_MAX)
}

/// Project one engine [`ProgressEvent`] onto the form the interactive TUI may retain.
///
/// Every string here is authored by an untrusted party — the workflow script (`phase()` titles,
/// `log()` messages, `agent()` labels) or a child model (`result_preview`, `last_tool_summary`,
/// refusal `error`s) — and the interactive transcript is retained state, so all of them pass the
/// display gate. The one-shot `core workflow run` surface draws into an alternate screen that is
/// discarded, which is why it never needed this.
///
/// Pure, and the match is exhaustive with no wildcard arm: **a new `ProgressEvent` variant does not
/// compile until it is given a projection here.** That is the property that stops a variant from
/// being silently swallowed by the seam.
pub fn ui_safe_progress(event: ProgressEvent) -> ProgressEvent {
    match event {
        ProgressEvent::Phase { index, title } => ProgressEvent::Phase {
            index,
            title: safe_line(&title, UI_LABEL_MAX),
        },
        ProgressEvent::Log { message } => ProgressEvent::Log {
            message: safe_line(&message, PREVIEW_MAX),
        },
        ProgressEvent::AgentQueued {
            index,
            label,
            phase,
            model,
        } => ProgressEvent::AgentQueued {
            index,
            label: safe_line(&label, UI_LABEL_MAX),
            phase: safe_line_opt(phase, UI_LABEL_MAX),
            model: safe_line_opt(model, UI_LABEL_MAX),
        },
        ProgressEvent::AgentStarted {
            index,
            label,
            phase,
            model,
        } => ProgressEvent::AgentStarted {
            index,
            label: safe_line(&label, UI_LABEL_MAX),
            phase: safe_line_opt(phase, UI_LABEL_MAX),
            model: safe_line_opt(model, UI_LABEL_MAX),
        },
        ProgressEvent::AgentActivity {
            index,
            tokens,
            tool_calls,
            last_tool_summary,
        } => ProgressEvent::AgentActivity {
            index,
            tokens,
            tool_calls,
            last_tool_summary: safe_line_opt(last_tool_summary, TOOL_SUMMARY_MAX),
        },
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
        } => ProgressEvent::AgentFinished {
            index,
            label: safe_line(&label, UI_LABEL_MAX),
            state,
            tokens,
            tool_calls,
            duration_ms,
            result_preview: safe_line_opt(result_preview, PREVIEW_MAX),
            last_tool_summary: safe_line_opt(last_tool_summary, TOOL_SUMMARY_MAX),
            error: safe_line_opt(error, PREVIEW_MAX),
        },
    }
}

/// A [`ProgressSink`] that forwards every engine event to a frontend channel as a
/// [`WorkflowRunUiEvent`] — the interactive-TUI counterpart of [`CardProgressSink`], which owns its
/// card directly because it also owns the terminal.
///
/// The channel is unbounded on purpose: `emit` is called from the engine's single JS-driver thread
/// and the contract says it must not block. Backpressure is applied downstream, by the frontend's
/// bounded event queue, which is also where a drop policy can distinguish a cosmetic tick from an
/// authoritative terminal row. A send to a frontend that has gone away is discarded, never an
/// error: losing the renderer must not stop a run the operator already paid for.
pub struct UiProgressSink {
    run_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<WorkflowRunUiEvent>,
}

impl UiProgressSink {
    pub fn new(
        run_id: impl Into<String>,
        tx: tokio::sync::mpsc::UnboundedSender<WorkflowRunUiEvent>,
    ) -> Self {
        UiProgressSink {
            run_id: run_id.into(),
            tx,
        }
    }
}

impl ProgressSink for UiProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let _ = self.tx.send(WorkflowRunUiEvent::Progress {
            run_id: self.run_id.clone(),
            event: ui_safe_progress(event),
        });
    }
}

/// Deliver one engine event to several sinks. The in-turn `Workflow` tool needs two at once: the
/// model still has to be told which agents DEGRADED ([`DegradedAgentSink`]) while the operator
/// watches the tree ([`UiProgressSink`]), and the engine takes exactly one sink.
///
/// `port_version` reports the MINIMUM its members report rather than this type's own: the engine
/// refuses a sink that cannot represent every event it is about to emit, and a fan-out is only as
/// capable as its least capable member. Reporting the maximum would let a v1 member be starved of
/// the queued half of a run behind a v2 sibling's version number.
pub struct FanoutProgressSink {
    sinks: Vec<Arc<dyn ProgressSink>>,
}

impl FanoutProgressSink {
    pub fn new(sinks: Vec<Arc<dyn ProgressSink>>) -> Self {
        FanoutProgressSink { sinks }
    }
}

impl ProgressSink for FanoutProgressSink {
    fn port_version(&self) -> u32 {
        self.sinks
            .iter()
            .map(|sink| sink.port_version())
            .min()
            .unwrap_or(PROGRESS_SINK_PORT_VERSION)
    }

    fn emit(&self, event: ProgressEvent) {
        for sink in &self.sinks {
            sink.emit(event.clone());
        }
    }
}

/// The sink the in-turn `Workflow` tool hands the engine.
///
/// `degraded` is not optional: a degraded `agent()` resolves to JS `null` and the idiomatic
/// `parallel(...).filter(Boolean)` deletes it, so without it an exhausted budget reaches the model
/// as a plausibly-short result. The frontend sink is added only when one is attached, which keeps
/// the `--output-format` paths on exactly the sink they had before this seam existed.
pub fn in_turn_progress_sink(
    degraded: Arc<DegradedAgentSink>,
    run_id: &str,
    frontend: Option<tokio::sync::mpsc::UnboundedSender<WorkflowRunUiEvent>>,
) -> Arc<dyn ProgressSink> {
    match frontend {
        Some(tx) => Arc::new(FanoutProgressSink::new(vec![
            degraded,
            Arc::new(UiProgressSink::new(run_id, tx)),
        ])),
        None => degraded,
    }
}

/// Everything a workflow run needs in order to start, resolved inside the turn that asked for it.
///
/// Produced by `runtime.rs`'s `Agent::prepare_workflow` and consumed by a [`WorkflowLauncher`].
/// Preparation is where every check that must fail the `Workflow` tool call happens — an unreadable
/// `scriptPath`, an unbound route, an exhausted parent turn budget, an unwritable manifest — so a
/// value of this type is a run that has already been admitted and whose re-launchable sidecar is
/// already on disk under [`Self::workflows_dir`]. Nothing here has been started.
///
/// The three fields the engine consumes ([`Self::spec`], [`Self::spawner`], [`Self::sink`]) travel
/// with the four the caller still needs once the run exists — the run id and name for the launch
/// banner and the terminal sidecar, the declared phases that seed the live card's first frame, and
/// the [`DegradedAgentSink`] whose reasons are read after the run settles. A launcher that outlives
/// the turn will need exactly that second group too, which is why they are one value rather than a
/// tuple the launcher would have to re-derive.
pub struct PreparedWorkflow {
    /// The run's identity: its journal namespace, its sidecar directory name, and the correlation
    /// key of every [`WorkflowRunUiEvent`] the live card renders.
    pub run_id: String,
    /// The script's declared `meta.name`, or `workflow` when it declared none.
    pub name: String,
    /// The script's declared `meta.phases`, so the card shows the shape of the run on frame one
    /// instead of growing it phase by phase.
    pub declared_phases: Vec<String>,
    /// The directory `core workflow list` enumerates. The manifest is already written into it.
    pub workflows_dir: PathBuf,
    /// The engine's run request: script, args, run id, workflows dir and aggregate limits.
    pub spec: RunSpec,
    /// The parent-derived spawner every `agent()` call is admitted through.
    pub spawner: Arc<dyn AgentSpawner>,
    /// The progress sink, already fanned out to the frontend when one is attached.
    pub sink: Arc<dyn ProgressSink>,
    /// The reasons agents resolved to JS `null`. Only meaningful after the run settles.
    pub degraded: Arc<DegradedAgentSink>,
}

/// Who starts a [`PreparedWorkflow`].
///
/// The `Workflow` tool prepares a run and then joins it inside the turn, which is the whole reason a
/// run cannot outlive the turn that asked for it: the [`RunHandle`] is a local binding. This trait
/// is the single point where "who starts the run" is decided, so a session-scoped owner can later be
/// installed through `Agent::set_workflow_launcher` without the tool handler learning what a session
/// is.
///
/// It deliberately does **not** decide whether the turn joins. The kernel joins the returned handle
/// either way, so installing [`InTurnWorkflowLauncher`] — or installing nothing at all — is
/// byte-for-byte the behavior that existed before this seam. A launcher that means to *detach* has
/// to answer two questions this signature cannot express yet: what the model is told the tool
/// returned when the run's value does not exist yet, and what happens to a live run when the session
/// exits. Both are left open on purpose.
///
/// The handle is shared rather than owned because a detaching launcher must keep it: both
/// [`RunHandle::cancel`] and [`RunHandle::join`] take `&self`, so the turn's 25 ms interrupt poll and
/// an owner's later bookkeeping can hold the same run at once.
pub trait WorkflowLauncher: Send + Sync {
    fn launch(&self, prepared: PreparedWorkflow) -> Arc<RunHandle>;
}

/// The default launcher: exactly [`WorkflowEngine::launch`], owned by nobody but its caller.
///
/// This is what the kernel uses when no launcher is installed, and it is what makes "no launcher"
/// and "the in-turn launcher" the same run.
pub struct InTurnWorkflowLauncher;

impl WorkflowLauncher for InTurnWorkflowLauncher {
    fn launch(&self, prepared: PreparedWorkflow) -> Arc<RunHandle> {
        Arc::new(WorkflowEngine::launch(
            prepared.spec,
            prepared.spawner,
            prepared.sink,
        ))
    }
}

/// Start `prepared` through `launcher`, or through [`InTurnWorkflowLauncher`] when none is
/// installed.
///
/// The equivalence of those two arms is the property this slice rests on, so it lives here next to
/// the trait rather than being spelled out at the one call site: "no launcher installed" and "the
/// in-turn launcher installed" must remain the same run.
pub fn launch_prepared(
    launcher: Option<&Arc<dyn WorkflowLauncher>>,
    prepared: PreparedWorkflow,
) -> Arc<RunHandle> {
    match launcher {
        Some(launcher) => launcher.launch(prepared),
        None => InTurnWorkflowLauncher.launch(prepared),
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

/// Spinner cadence, and therefore also the worst-case latency between a Ctrl-C press and the run
/// being told to stop: the loop drains buffered key events once per frame.
const LIVE_TICK: std::time::Duration = std::time::Duration::from_millis(80);

/// What one key press means to the live workflow surface.
///
/// [`LiveTermGuard::enter`] turns raw mode ON, which clears `ISIG`: the terminal stops translating
/// Ctrl-C into `SIGINT`, so no signal handler — and in particular not `tokio::signal::ctrl_c` — can
/// ever fire while this tree is on screen. Ctrl-C arrives as an ordinary key event, and this is the
/// only place that decides what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveAction {
    /// Not a control key for this surface — keep rendering.
    Ignore,
    /// First Ctrl-C: cancel the run, then keep rendering until it actually settles.
    Cancel,
    /// Ctrl-C again while the run is still settling: stop waiting on it.
    ForceExit,
}

/// The key → action decision, kept pure so the interrupt contract is testable with no terminal.
fn live_key_action(key: KeyEvent, cancel_requested: bool) -> LiveAction {
    // Windows (and any terminal with keyboard enhancement pushed) also reports releases; only a
    // press or an auto-repeat is an operator intent.
    if matches!(key.kind, KeyEventKind::Release) {
        return LiveAction::Ignore;
    }
    let ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
    if !ctrl_c {
        return LiveAction::Ignore;
    }
    if cancel_requested {
        LiveAction::ForceExit
    } else {
        LiveAction::Cancel
    }
}

/// How the live loop ended.
enum LiveOutcome {
    /// The run settled — on its own, or as `stopped` after a cancel. `cancelled` records whether
    /// Ctrl-C was taken, because the operator deserves to be told why the tree stopped moving;
    /// `spin` is the spinner phase the last live frame used, so the settled frame continues it.
    Settled {
        report: RunReport,
        cancelled: bool,
        spin: usize,
    },
    /// A second Ctrl-C arrived while the run was still settling: stop waiting on it.
    Forced,
}

/// The live loop's control flow, with the terminal factored out behind `draw`/`next_key`/`cancel` so
/// the interrupt path can be driven headlessly in tests. Draws a frame, drains whatever keys are
/// already buffered, then waits for either the run to settle or the next spinner tick.
async fn live_loop<F, D, K, C>(
    future: F,
    mut draw: D,
    mut next_key: K,
    cancel: C,
    tick: std::time::Duration,
) -> anyhow::Result<LiveOutcome>
where
    F: std::future::Future<Output = anyhow::Result<RunReport>>,
    D: FnMut(bool, usize) -> anyhow::Result<()>,
    K: FnMut() -> Option<KeyEvent>,
    C: Fn(),
{
    let mut spin: usize = 0;
    let mut cancelled = false;

    tokio::pin!(future);
    let mut ticker = tokio::time::interval(tick);

    loop {
        // Keys are drained BEFORE the frame is drawn, so the frame the operator is looking at
        // already reflects the Ctrl-C they just pressed instead of acknowledging it a tick later —
        // or never, if the run settles immediately after being cancelled.
        while let Some(key) = next_key() {
            match live_key_action(key, cancelled) {
                LiveAction::Ignore => {}
                LiveAction::Cancel => {
                    cancelled = true;
                    // Idempotent and immediate: it trips the run's token, it does not block.
                    cancel();
                }
                LiveAction::ForceExit => return Ok(LiveOutcome::Forced),
            }
        }
        draw(cancelled, spin)?;
        tokio::select! {
            result = &mut future => {
                return Ok(LiveOutcome::Settled { report: result?, cancelled, spin });
            }
            _ = ticker.tick() => spin = spin.wrapping_add(1),
        }
    }
}

/// The banner the cancel path adds to the frame. A cancelled run whose tree simply stopped moving is
/// indistinguishable from a hung one, so the frame has to SAY it.
fn cancel_banner(settled: bool) -> &'static str {
    if settled {
        "run cancelled (Ctrl-C)"
    } else {
        "cancelling (Ctrl-C) \u{b7} press Ctrl-C again to stop waiting"
    }
}

/// One frame body: the run tree, plus the cancellation banner once Ctrl-C has been taken.
fn live_lines(
    card: &crate::block::WorkflowRunCard,
    width: u16,
    theme: &crate::theme::Theme,
    spin: usize,
    cancelled: bool,
) -> Vec<ratatui::text::Line<'static>> {
    let mut lines = crate::block::render_workflow_run(card, width, theme, spin);
    if cancelled {
        lines.push(ratatui::text::Line::default());
        lines.push(ratatui::text::Line::from(ratatui::text::Span::styled(
            cancel_banner(card.finished).to_string(),
            ratatui::style::Style::default().fg(theme.error),
        )));
    }
    lines
}

/// The real key source: drain what crossterm has already buffered, never blocking the frame loop.
/// An unreadable stdin yields `None` rather than an error — losing input must not abandon a run that
/// is still executing on its own thread.
fn next_terminal_key() -> Option<KeyEvent> {
    while crossterm::event::poll(std::time::Duration::ZERO).unwrap_or(false) {
        match crossterm::event::read() {
            Ok(crossterm::event::Event::Key(key)) => return Some(key),
            // Resize/mouse/paste: consumed, not actionable here. Keep draining.
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Render the QuickJS-workflow phase→agent tree LIVE (design §3.3) while the run behind `handle`
/// drives `card` through [`CardProgressSink`], advancing the braille spinner every 80ms, then leave
/// the alternate screen and echo the settled tree into scrollback.
///
/// The handle — not a bare future — is what makes the surface interruptible: Ctrl-C calls
/// [`RunHandle::cancel`], which aborts in-flight children and interrupts a sync JS loop, and the loop
/// keeps rendering until the run actually settles as `stopped`.
async fn render_live(
    card: Arc<std::sync::Mutex<crate::block::WorkflowRunCard>>,
    handle: RunHandle,
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;
    use ratatui::widgets::Paragraph;

    // `join` takes `&self`, so the joining future and the Ctrl-C handler share one handle.
    let handle = Arc::new(handle);
    let joiner = handle.clone();
    let future = async move { joiner.join().await };

    let mut guard = Some(LiveTermGuard::enter()?);
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    let outcome = {
        let card = card.clone();
        let draw = |cancelled: bool, spin: usize| -> anyhow::Result<()> {
            term.draw(|frame| {
                let area = frame.area();
                let snapshot = card.lock().unwrap();
                let lines = live_lines(&snapshot, area.width, theme, spin, cancelled);
                drop(snapshot);
                frame.render_widget(Paragraph::new(lines), area);
            })?;
            Ok(())
        };
        live_loop(
            future,
            draw,
            next_terminal_key,
            || handle.cancel(),
            LIVE_TICK,
        )
        .await?
    };

    let (report, cancelled, spin) = match outcome {
        LiveOutcome::Settled {
            report,
            cancelled,
            spin,
        } => (report, cancelled, spin),
        LiveOutcome::Forced => {
            // `process::exit` runs no destructors, so the guard would never restore the terminal.
            // Restore it explicitly FIRST, then leave; the run was already told to cancel.
            drop(guard.take());
            eprintln!("workflow run interrupted; cancellation requested and not awaited");
            std::process::exit(i32::from(crate::output::EXIT_INTERRUPTED));
        }
    };

    // The engine reports `stopped` for exactly the token this loop trips, so either signal is proof.
    let cancelled = cancelled || report.stopped;
    if let Ok(mut card) = card.lock() {
        card.finished = true;
    }
    let mut final_plain = String::new();
    term.draw(|frame| {
        let area = frame.area();
        let snapshot = card.lock().unwrap();
        let lines = live_lines(&snapshot, area.width, theme, spin, cancelled);
        final_plain = plain_lines(&lines);
        frame.render_widget(Paragraph::new(lines), area);
    })?;
    drop(guard.take());

    // Terminal restored — echo the settled tree into normal scrollback so it survives the run.
    if !final_plain.trim().is_empty() {
        println!("{final_plain}");
    }
    Ok(report)
}

/// Launch a run in the BACKGROUND (via [`WorkflowEngine::launch`] → [`RunHandle`], review B3) and
/// attach the live tree to it: the run drives its own OS thread + runtime while this foreground loop
/// renders the shared card, reads keys, and `join`s the handle.
async fn launch_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    let card = Arc::new(std::sync::Mutex::new(new_run_card(
        spec.run_id.as_str(),
        name,
        phases,
    )));
    let sink: Arc<dyn ProgressSink> = Arc::new(CardProgressSink::new(card.clone()));
    let handle = WorkflowEngine::launch(spec, spawner, sink);
    render_live(card, handle, theme).await
}

/// Run one fully-specified [`RunSpec`], rendering the live tree (design §3.3). `core workflow run`
/// (TTY) and `core workflow resume` (TTY) both call it. Non-TTY uses [`StdoutProgressSink`].
///
/// This used to await `WorkflowEngine::execute` directly — a bare future with no cancellation
/// handle — which is why Ctrl-C could not stop a run: raw mode had already suppressed `SIGINT`, and
/// nothing on this path could act on the key event that replaced it. It now goes through
/// [`WorkflowEngine::launch`] for the same reason [`watch_live`] always did: a [`RunHandle`] can be
/// cancelled.
pub async fn run_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    launch_live(spec, spawner, name, phases, theme).await
}

/// One live card seeded with the script's DECLARED `meta.phases`, so every phase box is laid out on
/// the first frame instead of appearing only once execution reaches it.
fn new_run_card(run_id: &str, name: &str, phases: &[String]) -> crate::block::WorkflowRunCard {
    let mut card = crate::block::WorkflowRunCard::new(run_id, name);
    card.declare_phases(phases.iter().cloned());
    card
}

/// The `RunHandle` counterpart of [`run_live`] for `core workflow watch <runId>`, which re-launches a
/// prior run. Same loop, same interrupt contract. Non-TTY uses [`StdoutProgressSink`].
pub async fn watch_live(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    name: &str,
    phases: &[String],
    theme: &crate::theme::Theme,
) -> anyhow::Result<RunReport> {
    launch_live(spec, spawner, name, phases, theme).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{Block, StopReason, Usage};
    use core_provider::{ProviderError, TurnResult, UsageReport};
    use core_workflow::{RunId, RunReport};
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordingProvider {
        turns: AtomicUsize,
        failure: Option<String>,
    }

    impl RecordingProvider {
        fn successful() -> Self {
            Self {
                turns: AtomicUsize::new(0),
                failure: None,
            }
        }

        fn failing(message: String) -> Self {
            Self {
                turns: AtomicUsize::new(0),
                failure: Some(message),
            }
        }
    }

    #[async_trait::async_trait]
    impl Provider for RecordingProvider {
        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.turns.fetch_add(1, Ordering::SeqCst);
            if let Some(message) = &self.failure {
                return Err(ProviderError::Http(message.clone()));
            }
            Ok(TurnResult {
                blocks: vec![Block::Text {
                    text: "provider result".into(),
                }],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Usage::default()),
            })
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ProgressEvent>>,
    }

    impl ProgressSink for RecordingSink {
        fn emit(&self, event: ProgressEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "core-cli-workflow-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn assert_safe_refusal_surfaces(
        workflows_dir: &Path,
        run_id: &str,
        sink: &RecordingSink,
        expected: usize,
        secret: &str,
    ) {
        let events = sink.events.lock().unwrap();
        let rendered = format!("{events:?}");
        assert!(!rendered.contains(secret), "{rendered}");
        let errors: Vec<&String> = events
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::AgentFinished {
                    state: WorkflowState::Error,
                    error: Some(error),
                    ..
                } => Some(error),
                _ => None,
            })
            .collect();
        assert_eq!(errors.len(), expected);
        assert!(errors.iter().all(|error| {
            error.len() <= 512 && !error.chars().any(char::is_control) && !error.contains(secret)
        }));
        drop(events);

        let journal =
            std::fs::read_to_string(run_dir(workflows_dir, run_id).join("journal.jsonl")).unwrap();
        assert!(!journal.contains(secret), "{journal}");
        let reasons: Vec<String> = journal
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|line| {
                line.get("record")?
                    .get("outcome")?
                    .get("reason")?
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(reasons.len(), expected);
        assert!(reasons.iter().all(|reason| {
            reason.len() <= 512 && !reason.chars().any(char::is_control) && !reason.contains(secret)
        }));
    }

    #[tokio::test]
    async fn provider_fallback_refuses_unknown_agent_and_unresolved_models_before_any_turn() {
        let workflows_dir = scratch_dir("provider-fallback-refusals");
        let provider = Arc::new(RecordingProvider::successful());
        let spawner = Arc::new(ProviderSpawner::new(
            provider.clone(),
            "parent-model".into(),
        ));
        let sink = Arc::new(RecordingSink::default());
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let script = r#"export const meta = { name: 'fallback-refusals', description: '', phases: [] };
return await parallel([
  () => agent('unknown type', {agentType: 'reviewer'}),
  () => agent('secret type', {agentType: args.secret}),
  () => agent('alternate model', {model: 'alternate-model'}),
  () => agent('secret model', {model: args.secret}),
]);
"#;
        let spec = RunSpec::new(script)
            .with_args(serde_json::json!({"secret": secret}))
            .with_run_id(RunId::new("fallback-refusals"))
            .with_workflows_dir(workflows_dir.clone());
        let report = WorkflowEngine::execute(spec, spawner, sink.clone())
            .await
            .expect("authorization refusals settle as null");
        assert_eq!(
            report.value,
            serde_json::Value::Array(vec![serde_json::Value::Null; 4])
        );
        assert_eq!(provider.turns.load(Ordering::SeqCst), 0);
        assert_safe_refusal_surfaces(&workflows_dir, "fallback-refusals", &sink, 4, secret);
        let _ = std::fs::remove_dir_all(workflows_dir);
    }

    #[tokio::test]
    async fn provider_fallback_never_reflects_raw_provider_error_into_null_journal_or_progress() {
        let workflows_dir = scratch_dir("provider-fallback-error");
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let provider = Arc::new(RecordingProvider::failing(format!(
            "request to https://gateway.invalid/{secret} failed\n\u{1b}[2J{}",
            "x".repeat(4_096)
        )));
        let spawner = Arc::new(ProviderSpawner::new(
            provider.clone(),
            "parent-model".into(),
        ));
        let sink = Arc::new(RecordingSink::default());
        let script = r#"export const meta = { name: 'fallback-error', description: '', phases: [] };
return await agent('inspect', {agentType: 'generic', model: 'parent-model'});
"#;
        let spec = RunSpec::new(script)
            .with_run_id(RunId::new("fallback-error"))
            .with_workflows_dir(workflows_dir.clone());
        let report = WorkflowEngine::execute(spec, spawner, sink.clone())
            .await
            .expect("provider failure settles as null");
        assert_eq!(report.value, serde_json::Value::Null);
        assert_eq!(provider.turns.load(Ordering::SeqCst), 1);
        assert_safe_refusal_surfaces(&workflows_dir, "fallback-error", &sink, 1, secret);
        let _ = std::fs::remove_dir_all(workflows_dir);
    }

    #[test]
    fn a_run_that_only_wrote_a_journal_lists_as_an_unnamed_running_stub() {
        // The in-turn (`Workflow` tool) path used to do exactly this: write its journal into the
        // directory `core workflow list` enumerates and never call either persistence helper. This
        // pins what that looked like, so the assertion below is a real difference.
        let workflows_dir = scratch_dir("orphan");
        let run = run_dir(&workflows_dir, "wf_orphan");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(run.join("journal.jsonl"), b"").unwrap();

        let listed = list_runs(&workflows_dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "workflow");
        assert_eq!(listed[0].model, "");
        assert_eq!(listed[0].status, "running");

        let _ = std::fs::remove_dir_all(&workflows_dir);
    }

    #[test]
    fn a_persisted_run_lists_with_its_name_model_and_terminal_state() {
        let workflows_dir = scratch_dir("persisted");
        let manifest = RunManifest {
            run_id: "wf_persisted".into(),
            name: "triage".into(),
            args: serde_json::json!({ "topic": "flaky test" }),
            provider_id: "anthropic".into(),
            model: "core-model-1".into(),
            created_at: 42,
        };
        persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
        std::fs::write(
            run_dir(&workflows_dir, "wf_persisted").join("journal.jsonl"),
            b"",
        )
        .unwrap();
        persist_result(
            &workflows_dir,
            "wf_persisted",
            &RunReport {
                run_id: RunId::new("wf_persisted"),
                value: serde_json::json!(["a", "b"]),
                stopped: false,
                cache_hits: 0,
                cache_misses: 2,
                tokens: 1_234,
                tool_calls: 7,
                elapsed_ms: 4_200,
            },
        )
        .unwrap();

        let listed = list_runs(&workflows_dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "triage");
        assert_eq!(listed[0].model, "core-model-1");
        assert_eq!(
            listed[0].status, "done",
            "a completed run must reach a terminal state, not stay `running` forever"
        );
        assert_eq!(
            load_script(&workflows_dir, "wf_persisted").as_deref(),
            Some("export const meta = {};"),
            "the inputs sidecar makes the run re-launchable"
        );

        let _ = std::fs::remove_dir_all(&workflows_dir);
    }

    #[test]
    fn a_run_whose_join_failed_still_settles_to_a_terminal_state() {
        // The in-turn path returns early when the engine hands back an error — now a reachable
        // path, because the journal refuses a second writer for a colliding run id instead of
        // interleaving into it. `persist_inputs` has ALREADY created the directory `list`
        // enumerates, so a failure that skipped `persist_result` would sit there as a stub
        // forever: the same permanent pollution as never persisting at all.
        let workflows_dir = scratch_dir("failed");
        let manifest = RunManifest {
            run_id: "wf_failed".into(),
            name: "triage".into(),
            args: serde_json::Value::Null,
            provider_id: "anthropic".into(),
            model: "core-model-1".into(),
            created_at: 7,
        };
        persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
        assert_eq!(
            list_runs(&workflows_dir)[0].status,
            "pending",
            "inputs alone are not a terminal state"
        );

        persist_result(
            &workflows_dir,
            "wf_failed",
            &RunReport {
                run_id: RunId::new("wf_failed"),
                value: serde_json::json!({ "error": "Workflow run failed: journal locked" }),
                stopped: true,
                cache_hits: 0,
                cache_misses: 0,
                tokens: 0,
                tool_calls: 0,
                elapsed_ms: 0,
            },
        )
        .unwrap();

        let listed = list_runs(&workflows_dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "triage");
        assert_eq!(listed[0].model, "core-model-1");
        assert_eq!(
            listed[0].status, "stopped",
            "a run that failed to join must reach a terminal state, not linger as running"
        );

        let _ = std::fs::remove_dir_all(&workflows_dir);
    }

    // -----------------------------------------------------------------------------------------
    // Interrupt (Ctrl-C) on the live surface.
    //
    // Raw mode clears ISIG, so Ctrl-C is a KEY EVENT, not a signal: a fix built on
    // `tokio::signal::ctrl_c` would compile, run, and never fire. These pin the decision and the
    // loop that acts on it; the terminal-restore + exit-code halves are pinned end-to-end in
    // `crates/cli/tests/workflow_interrupt_pty.rs`, which drives the real binary in a PTY.
    // -----------------------------------------------------------------------------------------

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn ctrl_c() -> KeyEvent {
        key(KeyCode::Char('c'), KeyModifiers::CONTROL)
    }

    fn settled_report() -> RunReport {
        RunReport {
            run_id: RunId::new("wf_interrupt"),
            value: serde_json::Value::Null,
            stopped: true,
            cache_hits: 0,
            cache_misses: 0,
            tokens: 0,
            tool_calls: 0,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn ctrl_c_is_the_key_that_cancels_and_nothing_else_is() {
        assert_eq!(live_key_action(ctrl_c(), false), LiveAction::Cancel);
        assert_eq!(
            live_key_action(key(KeyCode::Char('C'), KeyModifiers::CONTROL), false),
            LiveAction::Cancel,
            "a shifted Ctrl-C is still Ctrl-C"
        );
        for benign in [
            key(KeyCode::Char('c'), KeyModifiers::NONE),
            key(KeyCode::Char('c'), KeyModifiers::ALT),
            key(KeyCode::Char('d'), KeyModifiers::CONTROL),
            key(KeyCode::Esc, KeyModifiers::NONE),
            key(KeyCode::Enter, KeyModifiers::NONE),
        ] {
            assert_eq!(
                live_key_action(benign, false),
                LiveAction::Ignore,
                "{benign:?} must not stop a running workflow"
            );
        }
    }

    #[test]
    fn a_key_release_never_cancels() {
        // Windows reports a Release for every press; acting on both would cancel twice from one
        // physical Ctrl-C, i.e. force-exit before the run ever got a chance to settle.
        let mut release = ctrl_c();
        release.kind = KeyEventKind::Release;
        assert_eq!(live_key_action(release, false), LiveAction::Ignore);
        assert_eq!(live_key_action(release, true), LiveAction::Ignore);
    }

    #[test]
    fn a_second_ctrl_c_while_settling_forces_the_exit() {
        assert_eq!(live_key_action(ctrl_c(), true), LiveAction::ForceExit);
    }

    #[test]
    fn the_cancelled_frame_says_so_instead_of_just_freezing() {
        let theme = crate::theme::Theme::dark();
        let mut card = new_run_card("wf_interrupt", "triage", &["plan".to_string()]);

        let live = plain_lines(&live_lines(&card, 80, &theme, 0, true));
        assert!(live.contains("cancelling"), "{live}");
        assert!(live.contains("Ctrl-C again"), "{live}");

        card.finished = true;
        let settled = plain_lines(&live_lines(&card, 80, &theme, 0, true));
        assert!(settled.contains("run cancelled"), "{settled}");

        let untouched = plain_lines(&live_lines(&card, 80, &theme, 0, false));
        assert!(
            !untouched.contains("cancel"),
            "a run nobody interrupted must not claim it was cancelled: {untouched}"
        );
    }

    #[tokio::test]
    async fn ctrl_c_invokes_cancel_and_the_loop_keeps_rendering_until_the_run_settles() {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::new(Mutex::new(Vec::<bool>::new()));

        // The stand-in for the engine: it only resolves once cancellation was actually requested,
        // so a loop that drew a "cancelled" banner without calling `cancel()` would hang here.
        let settles_on_cancel = {
            let cancelled = cancelled.clone();
            async move {
                loop {
                    if cancelled.load(Ordering::SeqCst) {
                        return Ok(settled_report());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        };

        let mut keys = vec![ctrl_c()].into_iter();
        let draw_log = observed.clone();
        let cancel_flag = cancelled.clone();

        let outcome = live_loop(
            settles_on_cancel,
            move |cancelled, _spin| {
                draw_log.lock().unwrap().push(cancelled);
                Ok(())
            },
            move || keys.next(),
            move || cancel_flag.store(true, Ordering::SeqCst),
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("the live loop settles");

        assert!(
            cancelled.load(Ordering::SeqCst),
            "Ctrl-C must actually invoke cancel() on the run handle"
        );
        match outcome {
            LiveOutcome::Settled {
                report, cancelled, ..
            } => {
                assert!(cancelled, "the loop must report that it was interrupted");
                assert!(report.stopped, "an interrupted run settles as stopped");
            }
            LiveOutcome::Forced => panic!("one Ctrl-C must wait for the run, not force-exit"),
        }
        let frames = observed.lock().unwrap();
        assert!(
            frames.iter().any(|drawn| *drawn),
            "the operator must see at least one frame acknowledging the interrupt: {frames:?}"
        );
    }

    #[tokio::test]
    async fn a_second_ctrl_c_stops_waiting_on_a_run_that_will_not_settle() {
        let cancels = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = cancels.clone();
        // A run that ignores cancellation entirely — exactly the case a single Ctrl-C cannot fix.
        let never_settles = async {
            std::future::pending::<()>().await;
            unreachable!()
        };
        let mut keys = vec![ctrl_c(), ctrl_c()].into_iter();

        let outcome = live_loop(
            never_settles,
            |_cancelled, _spin| Ok(()),
            move || keys.next(),
            move || {
                counted.fetch_add(1, Ordering::SeqCst);
            },
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("the live loop returns instead of hanging");

        assert!(
            matches!(outcome, LiveOutcome::Forced),
            "a second Ctrl-C must stop waiting rather than hang forever"
        );
        assert_eq!(
            cancels.load(Ordering::SeqCst),
            1,
            "the run is asked to cancel once; the second press is the operator giving up"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The interactive-TUI progress seam (ADR-0001 step 1).
    //
    // The mapping is a pure function, so it is tested as one: no engine, no terminal, no channel.
    // The exhaustiveness obligation the brief names is enforced twice over — `ui_safe_progress`
    // matches every `ProgressEvent` variant with no wildcard arm (a new variant does not compile
    // until it is given a projection), and `variant_tag` below repeats that with no wildcard, so a
    // new variant also cannot be forgotten out of `every_progress_variant`.
    // -----------------------------------------------------------------------------------------

    /// A name for the shape of an event, by an exhaustive match. This exists so a `ProgressEvent`
    /// variant added tomorrow breaks THIS file too, rather than quietly making the coverage
    /// assertion below weaker by one variant.
    fn variant_tag(event: &ProgressEvent) -> &'static str {
        match event {
            ProgressEvent::Phase { .. } => "phase",
            ProgressEvent::Log { .. } => "log",
            ProgressEvent::AgentQueued { .. } => "agent_queued",
            ProgressEvent::AgentStarted { .. } => "agent_started",
            ProgressEvent::AgentActivity { .. } => "agent_activity",
            ProgressEvent::AgentFinished { .. } => "agent_finished",
        }
    }

    /// One of every variant, each carrying a hostile string in every string-shaped field: a screen-
    /// clearing control sequence and a credential-shaped token.
    ///
    /// The credential is delimited from what precedes it because `crate::tui::ui_safe_text` defers
    /// to `core_record::redact::scrub`, which matches credential-shaped TOKENS. What this pins is
    /// that the seam ROUTES untrusted strings through the frontend's one gate — not a second,
    /// private redaction implementation, which is exactly the drift that would let the two
    /// disagree about what a secret looks like.
    fn every_progress_variant(secret: &str) -> Vec<ProgressEvent> {
        vec![
            ProgressEvent::Phase {
                index: 1,
                title: format!("build \u{1b}[2Jindex {secret}"),
            },
            ProgressEvent::Log {
                message: format!("scanning \u{1b}[2J {secret}"),
            },
            ProgressEvent::AgentQueued {
                index: 0,
                label: format!("queued \u{1b}[2J {secret}"),
                phase: Some(format!("build \u{1b}[2Jindex {secret}")),
                model: Some(format!("model-x \u{1b}[2J {secret}")),
            },
            ProgressEvent::AgentStarted {
                index: 1,
                label: format!("started \u{1b}[2J {secret}"),
                phase: Some(format!("build \u{1b}[2Jindex {secret}")),
                model: Some(format!("model-x \u{1b}[2J {secret}")),
            },
            ProgressEvent::AgentActivity {
                index: 1,
                tokens: 1_200,
                tool_calls: 3,
                last_tool_summary: Some(format!("read \u{1b}[2J {secret}")),
            },
            ProgressEvent::AgentFinished {
                index: 1,
                label: format!("finished \u{1b}[2J {secret}"),
                state: WorkflowState::Error,
                tokens: 2_400,
                tool_calls: 4,
                duration_ms: 3_200,
                result_preview: Some(format!("result \u{1b}[2J {secret}")),
                last_tool_summary: Some(format!("read \u{1b}[2J {secret}")),
                error: Some(format!("refused \u{1b}[2J {secret}")),
            },
        ]
    }

    /// Every string a projected event carries, so a leak cannot hide in a field the test forgot.
    fn strings_of(event: &ProgressEvent) -> Vec<String> {
        match event {
            ProgressEvent::Phase { title, .. } => vec![title.clone()],
            ProgressEvent::Log { message } => vec![message.clone()],
            ProgressEvent::AgentQueued {
                label,
                phase,
                model,
                ..
            }
            | ProgressEvent::AgentStarted {
                label,
                phase,
                model,
                ..
            } => [Some(label.clone()), phase.clone(), model.clone()]
                .into_iter()
                .flatten()
                .collect(),
            ProgressEvent::AgentActivity {
                last_tool_summary, ..
            } => last_tool_summary.clone().into_iter().collect(),
            ProgressEvent::AgentFinished {
                label,
                result_preview,
                last_tool_summary,
                error,
                ..
            } => [
                Some(label.clone()),
                result_preview.clone(),
                last_tool_summary.clone(),
                error.clone(),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }

    #[test]
    fn no_progress_variant_is_dropped_on_its_way_to_the_frontend() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let variants = every_progress_variant(secret);
        let tags: BTreeSet<&'static str> = variants.iter().map(variant_tag).collect();
        assert_eq!(
            tags.len(),
            variants.len(),
            "the coverage fixture must hold each variant exactly once"
        );

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink = UiProgressSink::new("wf_seam", tx);
        for event in &variants {
            sink.emit(event.clone());
        }
        drop(sink);

        let mut seen: Vec<&'static str> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                WorkflowRunUiEvent::Progress { run_id, event } => {
                    assert_eq!(run_id, "wf_seam", "every row is correlated to its run");
                    seen.push(variant_tag(&event));
                }
                other => panic!("the sink emits only progress: {other:?}"),
            }
        }
        assert_eq!(
            seen,
            variants.iter().map(variant_tag).collect::<Vec<_>>(),
            "every variant must arrive, once, in order — a swallowed one is a row that never \
             appears or never settles"
        );
    }

    #[test]
    fn untrusted_strings_are_gated_before_they_enter_retained_transcript_state() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        for event in every_progress_variant(secret) {
            let projected = ui_safe_progress(event.clone());
            assert_eq!(
                variant_tag(&projected),
                variant_tag(&event),
                "the gate must not change what KIND of thing happened"
            );
            let strings = strings_of(&projected);
            assert!(
                !strings.is_empty(),
                "{}: a variant with string fields must still carry them",
                variant_tag(&projected)
            );
            for text in strings {
                assert!(
                    !text.contains(secret),
                    "credential survived the gate: {text}"
                );
                assert!(
                    !text.chars().any(char::is_control),
                    "a control sequence reached the transcript: {text:?}"
                );
            }
        }
    }

    #[test]
    fn an_oversized_label_cannot_push_a_row_off_the_screen() {
        let projected = ui_safe_progress(ProgressEvent::AgentStarted {
            index: 0,
            label: "x".repeat(10_000),
            phase: None,
            model: None,
        });
        let ProgressEvent::AgentStarted { label, .. } = projected else {
            panic!("the variant is preserved");
        };
        assert_eq!(label.chars().count(), UI_LABEL_MAX + 1); // bound + the ellipsis
        assert!(label.ends_with('…'));
    }

    #[test]
    fn the_gate_preserves_every_non_string_field() {
        let projected = ui_safe_progress(ProgressEvent::AgentFinished {
            index: 7,
            label: "row".into(),
            state: WorkflowState::Skipped,
            tokens: 2_400,
            tool_calls: 4,
            duration_ms: 3_200,
            result_preview: None,
            last_tool_summary: None,
            error: None,
        });
        // `Skipped` in particular: the engine's 5-state model is reused by the card, not projected
        // onto the native `WorkflowAgentOutcomeUi`, so no state has to be invented or collapsed.
        assert!(matches!(
            projected,
            ProgressEvent::AgentFinished {
                index: 7,
                state: WorkflowState::Skipped,
                tokens: 2_400,
                tool_calls: 4,
                duration_ms: 3_200,
                ..
            }
        ));
    }

    #[test]
    fn a_narrator_line_that_sanitizes_to_nothing_is_still_a_log_line() {
        // `Log` has no counterpart in the native `WorkflowUiEvent` vocabulary at all, which is one
        // of ADR-0001's reasons for keeping the engine's own. It is carried, never merged away.
        let projected = ui_safe_progress(ProgressEvent::Log {
            message: "   ".into(),
        });
        let ProgressEvent::Log { message } = projected else {
            panic!("a log stays a log");
        };
        assert!(message.is_empty());
    }

    #[test]
    fn the_fanout_feeds_every_sink_and_reports_its_least_capable_member() {
        struct OldSink;
        impl ProgressSink for OldSink {
            fn port_version(&self) -> u32 {
                1
            }
            fn emit(&self, _event: ProgressEvent) {}
        }

        let degraded = Arc::new(DegradedAgentSink::new());
        let recording = Arc::new(RecordingSink::default());
        let fanout = FanoutProgressSink::new(vec![degraded.clone(), recording.clone()]);
        assert_eq!(
            fanout.port_version(),
            PROGRESS_SINK_PORT_VERSION,
            "two current sinks are still current"
        );

        fanout.emit(ProgressEvent::AgentFinished {
            index: 2,
            label: "starved".into(),
            state: WorkflowState::Error,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 1,
            result_preview: None,
            last_tool_summary: None,
            error: Some("agent call ceiling 1 reached".into()),
        });

        // Both halves of the in-turn contract survive: the model is still told what degraded, and
        // the operator's tree still receives the row.
        assert_eq!(
            degraded.reasons(),
            vec!["#2 starved: agent call ceiling 1 reached".to_string()]
        );
        assert_eq!(recording.events.lock().unwrap().len(), 1);

        let with_old = FanoutProgressSink::new(vec![recording, Arc::new(OldSink)]);
        assert_eq!(
            with_old.port_version(),
            1,
            "a fan-out is only as capable as its least capable member; claiming otherwise would \
             let the engine emit events one member cannot represent"
        );
    }

    #[test]
    fn the_in_turn_sink_gains_the_tree_without_losing_the_models_degradation_reasons() {
        let starved = || ProgressEvent::AgentFinished {
            index: 2,
            label: "starved".into(),
            state: WorkflowState::Error,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 1,
            result_preview: None,
            last_tool_summary: None,
            error: Some("agent call ceiling 1 reached".into()),
        };

        // No frontend attached (`core -p`, `--output-format json`, an embedder): the sink is the
        // degraded sink itself, so this path is byte-for-byte what it was before the seam existed.
        let headless = Arc::new(DegradedAgentSink::new());
        in_turn_progress_sink(headless.clone(), "wf_headless", None).emit(starved());
        assert_eq!(
            headless.reasons(),
            vec!["#2 starved: agent call ceiling 1 reached".to_string()]
        );

        // Frontend attached: the operator gets the row AND the model still gets the reason. Losing
        // either one is a silent lie to somebody.
        let attached = Arc::new(DegradedAgentSink::new());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        in_turn_progress_sink(attached.clone(), "wf_attached", Some(tx)).emit(starved());
        assert_eq!(
            attached.reasons(),
            vec!["#2 starved: agent call ceiling 1 reached".to_string()],
            "the tree must not replace what the model is told"
        );
        match rx.try_recv().expect("the frontend saw the row") {
            WorkflowRunUiEvent::Progress { run_id, event } => {
                assert_eq!(run_id, "wf_attached");
                assert_eq!(variant_tag(&event), "agent_finished");
            }
            other => panic!("unexpected seam event: {other:?}"),
        }
    }

    #[test]
    fn the_degraded_sink_keeps_only_the_agents_that_did_not_complete() {
        let sink = DegradedAgentSink::new();
        sink.emit(ProgressEvent::AgentFinished {
            index: 1,
            label: "ok".into(),
            state: WorkflowState::Done,
            tokens: 10,
            tool_calls: 0,
            duration_ms: 5,
            result_preview: None,
            last_tool_summary: None,
            error: None,
        });
        sink.emit(ProgressEvent::AgentFinished {
            index: 2,
            label: "starved".into(),
            state: WorkflowState::Error,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 1,
            result_preview: None,
            last_tool_summary: None,
            error: Some("agent call ceiling 1 reached".into()),
        });
        sink.emit(ProgressEvent::Log {
            message: "narration".into(),
        });

        assert_eq!(
            sink.reasons(),
            vec!["#2 starved: agent call ceiling 1 reached".to_string()],
            "an exhausted budget must stay visible instead of being filtered away as a null"
        );
    }
}

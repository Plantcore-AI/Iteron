//! CLI-side workflow wiring: a real provider-backed [`AgentSpawner`] and the non-TTY stdout progress
//! renderer (design §3.5). The `iteron workflow run` subcommand (in `main.rs`) composes these with
//! `iteron_workflow::WorkflowEngine`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use iteron_protocol::{Effort, Message};
#[cfg(test)]
use iteron_provider::{Provider, StreamItem, TurnRequest};
use iteron_workflow::events::{
    PREVIEW_MAX, PROGRESS_SINK_PORT_VERSION, ProgressEvent, ProgressSink, WorkflowState, fmt_count,
    fmt_duration, truncate_preview,
};
#[cfg(test)]
use iteron_workflow::{AgentCall, AgentOutcome};
use iteron_workflow::{AgentSpawner, RunHandle, RunReport, RunSpec, WorkflowEngine};
use serde::{Deserialize, Serialize};

mod live;
mod policy_checkpoint;
mod projection;
mod tunables_checkpoint;

#[cfg(test)]
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
#[cfg(test)]
use live::{
    LiveAction, LiveOutcome, live_key_action, live_lines, live_loop, new_run_card, plain_lines,
};
pub use live::{run_live, watch_live};
pub(crate) use policy_checkpoint::{
    load as load_policy_checkpoint, persist as persist_policy_checkpoint,
};
use projection::UI_LABEL_MAX;
pub use projection::{
    KernelActivityKind, WorkflowRunTerminal, WorkflowRunUiEvent, ui_safe_label, ui_safe_progress,
};
pub(crate) use tunables_checkpoint::{
    load as load_tunables_checkpoint, persist as persist_tunables_checkpoint,
};

/// The system prompt every workflow sub-agent runs under. Kept terse: a workflow `agent()` call is a
/// bounded, single-shot query, not a full coding session.
#[cfg(test)]
const SUBAGENT_SYSTEM: &str = "You are a focused sub-agent inside a Iteron workflow. Answer the \
given task directly and concisely in plain text. Do not ask clarifying questions; produce exactly \
the requested output and nothing else.";

/// Test-only single-completion spawner: one provider completion per `agent()` call.
///
/// This is NOT the default. `iteron workflow run|resume|watch` builds a
/// [`crate::runtime::KernelSpawner`] — an owned child `Agent` with a read-only `Registry`, its own
/// child `Rollout`, and the parent's inherited route/pricing/governor. Production no longer exposes
/// a switch to this single-turn spawner because it has no child kernel effect journal. It remains a
/// focused workflow-engine fixture for isolating provider behavior from harness behavior. The trait
/// boundary is the same for both, so tests above this line do not depend on which one is installed.
/// This fallback supports only the built-in `generic` agent and the exact model resolved by the
/// composition root; it cannot reinterpret an agent definition or resolve another route.
#[cfg(test)]
pub struct ProviderSpawner {
    provider: Arc<dyn Provider>,
    model: String,
    max_tokens: u32,
    default_effort: Effort,
}

#[cfg(test)]
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

#[cfg(test)]
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
            controls: Default::default(),
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
        let event = ui_safe_progress(event);
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

/// Total bytes of already-finished agent results ONE detached run keeps so that killing it can
/// still answer with them.
///
/// Past the bound the newest results are refused rather than the oldest evicted, and every refusal
/// is counted. Keeping the earliest makes each answer a prefix of the one before it: a result a
/// client already read in one `collect` cannot disappear from the next. Evicting the oldest instead
/// would make a partial answer shrink under the client's feet, which is worse than admitting the
/// tail is missing.
const MAX_PARTIAL_RESULT_BYTES: usize = 256 * 1024;

/// One agent that finished with a result before its run was killed.
#[derive(Debug, Clone)]
pub struct FinishedAgent {
    pub index: usize,
    pub label: String,
    pub result: String,
}

/// What a run had actually produced at the moment somebody killed it.
#[derive(Debug, Clone, Default)]
pub struct PartialWork {
    /// Agents that reached [`WorkflowState::Done`], in completion order.
    pub finished: Vec<FinishedAgent>,
    /// Agents that had started and not finished when the kill was REQUESTED — not when the engine
    /// got round to honouring it, by which time it has already retired those rows as `stopped`
    /// errors and the count would flatter the kill by reading zero.
    pub running: usize,
    /// Results refused by [`MAX_PARTIAL_RESULT_BYTES`]. Counted, never silent.
    pub dropped: usize,
}

/// A [`ProgressSink`] that keeps the work a run had already finished, so that KILLING it returns
/// that work instead of nothing.
///
/// The engine resolves a cancelled run's script value to `null` deliberately — a half-evaluated JS
/// value is meaningless — so `RunReport.value` carries nothing at all after a kill. Every agent the
/// operator already paid for would therefore vanish from the answer, and a cancellation whose
/// output is discarded is indistinguishable from a crash. Between the kill and the journal on disk
/// this is the only record of that work.
///
/// It is a separate sink rather than a widening of [`DegradedAgentSink`] because the two keep
/// opposite halves: that one keeps the agents that produced NO result, this one keeps the results.
#[derive(Default)]
pub struct PartialWorkSink {
    retained: std::sync::Mutex<PartialWorkState>,
}

#[derive(Default)]
struct PartialWorkState {
    finished: Vec<FinishedAgent>,
    retained_bytes: usize,
    dropped: usize,
    /// Agents that emitted `AgentStarted` with no matching `AgentFinished` yet.
    in_flight: std::collections::BTreeSet<usize>,
    /// `in_flight.len()` sampled when the kill was requested.
    in_flight_at_kill: Option<usize>,
}

impl PartialWorkSink {
    pub fn new() -> Self {
        PartialWorkSink::default()
    }

    /// Sample what the kill is about to interrupt.
    ///
    /// Must be called BEFORE [`RunHandle::cancel`]: the engine retires in-flight rows as `stopped`
    /// errors on its way out, so a sample taken afterwards reports that nothing was running and the
    /// answer silently understates what the operator threw away.
    ///
    /// Only the FIRST kill is recorded — a second cancel of an already-stopping run must not shrink
    /// the count of what the first one interrupted.
    pub fn note_kill(&self) {
        if let Ok(mut retained) = self.retained.lock()
            && retained.in_flight_at_kill.is_none()
        {
            retained.in_flight_at_kill = Some(retained.in_flight.len());
        }
    }

    /// The work so far. `running` is the kill sample when there was a kill, else what is in flight
    /// right now.
    pub fn snapshot(&self) -> PartialWork {
        let Ok(retained) = self.retained.lock() else {
            return PartialWork::default();
        };
        PartialWork {
            finished: retained.finished.clone(),
            running: retained
                .in_flight_at_kill
                .unwrap_or_else(|| retained.in_flight.len()),
            dropped: retained.dropped,
        }
    }
}

impl ProgressSink for PartialWorkSink {
    fn emit(&self, event: ProgressEvent) {
        let Ok(mut retained) = self.retained.lock() else {
            return;
        };
        match event {
            ProgressEvent::AgentStarted { index, .. } => {
                retained.in_flight.insert(index);
            }
            ProgressEvent::AgentFinished {
                index,
                label,
                state,
                result_preview,
                ..
            } => {
                retained.in_flight.remove(&index);
                // A degraded row produced no result to keep; naming why it degraded is
                // `DegradedAgentSink`'s half of the answer, and duplicating it here would let the
                // two drift into disagreeing about what happened to one agent.
                if !matches!(state, WorkflowState::Done) {
                    return;
                }
                // Re-bounded here rather than trusted from the emitter: this is retained state, and
                // a bound that lives only in the producer is one refactor away from not existing.
                let result = truncate_preview(result_preview.as_deref().unwrap_or(""), PREVIEW_MAX);
                let label = truncate_preview(&label, UI_LABEL_MAX);
                let cost = result.len() + label.len();
                if retained.retained_bytes + cost > MAX_PARTIAL_RESULT_BYTES {
                    retained.dropped += 1;
                    return;
                }
                retained.retained_bytes += cost;
                retained.finished.push(FinishedAgent {
                    index,
                    label,
                    result,
                });
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The interactive-TUI progress seam (ADR-0001 step 1,
// docs/project/decisions/0001-workflow-renderer-convergence.md).
//
// `iteron workflow run` (TTY) already renders the script engine's phase→agent tree through
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

/// A [`ProgressSink`] that forwards every engine event to a frontend channel as a
/// [`WorkflowRunUiEvent`] — the interactive-TUI counterpart of [`live::CardProgressSink`], which owns its
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
    /// The directory `iteron workflow list` enumerates. The manifest is already written into it.
    pub workflows_dir: PathBuf,
    /// The engine's run request: script, args, run id, workflows dir and aggregate limits.
    pub spec: RunSpec,
    /// The parent-derived spawner every `agent()` call is admitted through.
    pub spawner: Arc<dyn AgentSpawner>,
    /// The progress sink, already fanned out to the frontend when one is attached.
    pub sink: Arc<dyn ProgressSink>,
    /// The reasons agents resolved to JS `null`. Only meaningful after the run settles.
    pub degraded: Arc<DegradedAgentSink>,
    /// This run should outlive its turn. **True unless the model asked to wait**
    /// (`Workflow({background: false})`), because a workflow that holds the conversation open for
    /// its whole fan-out is the thing the supervisor exists to stop.
    ///
    /// A **request**, not a guarantee. Only a launcher that can own a run past the turn may honour
    /// it; [`InTurnWorkflowLauncher`] deliberately ignores it and runs in-turn, and the kernel says
    /// so in the tool result rather than pretending the run detached. That asymmetry is what keeps
    /// a run from ever being started by nobody: the request is granted only where an owner exists.
    pub background: bool,
}

/// What a [`WorkflowLauncher`] did with a [`PreparedWorkflow`] — the answer to "does this run
/// belong to the turn or to something that outlives it".
///
/// This is the S9 half of the S8 seam. S8 could only say *who starts* a run because the return type
/// was a bare handle and the kernel always joined it; a launcher that detaches has to be able to
/// say "do not join, and here is what to tell the model instead", which is exactly the two variants
/// below.
pub enum Launched {
    /// The run belongs to this turn. The kernel joins the handle, bridges its interrupt surfaces
    /// onto it, settles the card and returns the aggregated report to the model — byte-for-byte the
    /// behavior that existed before this variant did.
    InTurn(Arc<RunHandle>),
    /// The run belongs to a session-scoped owner that outlives this turn. The kernel does **not**
    /// join, does **not** settle the card and does **not** persist a terminal sidecar: all three are
    /// the owner's obligations now, because it is the only thing still holding the run.
    Detached(DetachedRun),
}

/// A run an owner took off the turn's hands.
pub struct DetachedRun {
    pub run_id: String,
    pub name: String,
    /// One sentence naming who owns the run and what ends it, written by the owner because the
    /// owner — not the kernel — decides the session-exit rule. It is rendered verbatim into the
    /// tool result, so the model is never told a lifetime the owner does not actually enforce.
    pub ownership: String,
}

/// What an owner knows about one of its runs, in the vocabulary the `Workflow` tool answers in.
///
/// Every variant is a complete, honest answer. There is deliberately no "maybe" and no silent
/// `None`: a `collect` that returned nothing would be indistinguishable from a lost result, which
/// is the one failure a detached run must not have.
pub enum Collected {
    /// This run id is not one this owner started (or nothing owns runs here at all).
    Unknown(String),
    /// The run exists and has not settled. `elapsed_ms` is wall-clock since launch.
    Running {
        run_id: String,
        name: String,
        elapsed_ms: u64,
    },
    /// The run settled. `summary` is the SAME string the in-turn path returns to the model, built
    /// by [`run_result_summary`] so a detached result and an in-turn result cannot drift. It names
    /// the run, which is why this variant carries no separate id.
    Settled { summary: String },
    /// The run ended without a report (the engine itself failed). Reported as a tool error.
    Failed { run_id: String, error: String },
}

/// Who starts a [`PreparedWorkflow`], and whether the turn is still holding it afterwards.
///
/// The `Workflow` tool prepares a run and then hands it here. This trait is the single point where
/// "who starts the run" and "who owns it once started" are decided, so a session-scoped owner can be
/// installed through `Agent::set_workflow_launcher` without the tool handler learning what a session
/// is.
///
/// Installing [`InTurnWorkflowLauncher`] — or installing nothing at all — is byte-for-byte the
/// behavior that existed before this trait: [`Launched::InTurn`], joined by the turn.
///
/// The handle is shared rather than owned because a detaching launcher must keep it: both
/// [`RunHandle::cancel`] and [`RunHandle::join`] take `&self`, so the turn's 25 ms interrupt poll and
/// an owner's later bookkeeping can hold the same run at once.
pub trait WorkflowLauncher: Send + Sync {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched;

    /// Report on a run this owner started. Non-blocking on purpose: a `collect` that awaited would
    /// put the run back inside a turn, which is the thing detaching exists to stop.
    ///
    /// The default is the truth for every launcher that owns nothing past the turn.
    fn collect(&self, run_id: &str) -> Collected {
        Collected::Unknown(format!(
            "Workflow: run `{run_id}` is not owned by this session. Runs launched here complete \
             inside the turn that started them, so there is nothing to collect; \
             `iteron workflow list` shows every run on disk."
        ))
    }

    /// Stop a run this owner started. Same vocabulary as [`Self::collect`] so the tool has one
    /// answer shape; cancellation is a request, and the settled result is read by a later collect.
    fn cancel(&self, run_id: &str) -> Collected {
        self.collect(run_id)
    }
}

/// The default launcher: exactly [`WorkflowEngine::launch`], owned by nobody but its caller.
///
/// This is what the kernel uses when no launcher is installed, and it is what makes "no launcher"
/// and "the in-turn launcher" the same run.
pub struct InTurnWorkflowLauncher;

impl WorkflowLauncher for InTurnWorkflowLauncher {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched {
        // `prepared.background` is ignored here, and that is the point: this launcher has no life
        // beyond the caller's stack frame, so honouring the request would leave the run owned by a
        // frame that is about to return. The kernel tells the model the request was not granted.
        Launched::InTurn(Arc::new(WorkflowEngine::launch(
            prepared.spec,
            prepared.spawner,
            prepared.sink,
        )))
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
) -> Launched {
    match launcher {
        Some(launcher) => launcher.launch(prepared),
        None => InTurnWorkflowLauncher.launch(prepared),
    }
}

/// The ERROR block naming the agents that resolved to JS `null`.
///
/// One function, used by both renderings below, because a degraded `agent()` is deleted by a
/// script's idiomatic `.filter(Boolean)`: if the two summaries disagreed about how a degradation is
/// reported, an exhausted budget would reach the model as a plausibly-short result on whichever
/// path forgot it.
fn degraded_section(degraded: &[String]) -> String {
    if degraded.is_empty() {
        return String::new();
    }
    format!(
        "\n\nERROR: {} agent(s) did not complete and were resolved to null:\n{}",
        degraded.len(),
        degraded
            .iter()
            .map(|reason| format!("  - {reason}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// The one rendering of a settled run for the model.
///
/// Extracted from the in-turn tool handler so the detached path cannot drift from it: a background
/// run's `collect` returns this exact string, so "ran in-turn" and "ran detached then collected"
/// differ in *when* the model is told and in nothing else.
pub fn run_result_summary(
    name: &str,
    run_id: &str,
    report: &RunReport,
    degraded: &[String],
) -> String {
    let value =
        serde_json::to_string_pretty(&report.value).unwrap_or_else(|_| report.value.to_string());
    let degraded_section = degraded_section(degraded);
    format!(
        "Workflow `{name}` (run {run_id}) {}: {} agent(s) replayed from cache, {} ran live.{degraded_section}\n\nResult:\n{value}",
        if report.stopped {
            "stopped"
        } else {
            "finished"
        },
        report.cache_hits,
        report.cache_misses
    )
}

/// The one rendering of a KILLED run for the model — the counterpart of [`run_result_summary`],
/// which renders a run that reached its own `return`.
///
/// A kill is a deliberate act with a result, not a crash, and the two must not read the same. The
/// engine cannot make that distinction here: it resolves a stopped run's value to `null` because a
/// half-evaluated script value is meaningless, so the finished agents' work survives only because
/// [`PartialWorkSink`] kept it. This states, in one string, what was produced, what was interrupted,
/// and where the durable copy is — the three facts that separate "I stopped it, and here is what I
/// got" from "it died and everything is gone".
pub fn killed_run_summary(
    name: &str,
    run_id: &str,
    report: &RunReport,
    partial: &PartialWork,
    degraded: &[String],
) -> String {
    let produced = if partial.finished.is_empty() {
        "No agent had finished when the kill was requested, so this run produced no partial result."
            .to_string()
    } else {
        format!(
            "{} agent(s) finished before the kill, and their results ARE this run's output:\n{}",
            partial.finished.len(),
            partial
                .finished
                .iter()
                .map(|agent| format!("  - #{} {}: {}", agent.index, agent.label, agent.result))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let omitted = if partial.dropped > 0 {
        format!(
            "\n({} further result(s) exceeded this session's retention bound and are omitted here; \
             the run's journal on disk has every one.)",
            partial.dropped
        )
    } else {
        String::new()
    };
    // Always stated, including as zero: "nothing was interrupted" is itself an answer the client
    // needs in order to know the partial result above is the whole result.
    let interrupted = format!(
        "\n{} agent(s) were still running when the kill was requested; their work was discarded.",
        partial.running
    );
    format!(
        "Workflow `{name}` (run {run_id}) was KILLED at the engine's next safe point. It never \
         reached its own `return`, so it has no return value — this is a cancellation with a \
         partial result, not a crash.\n\n{produced}{omitted}{interrupted}{}\n\n{} agent(s) replayed \
         from cache, {} ran live. `iteron workflow list` records the run.",
        degraded_section(degraded),
        report.cache_hits,
        report.cache_misses
    )
}

/// The terminal record for a run that produced no report of its own.
///
/// A run that never reported is still a directory `iteron workflow list` enumerates — `persist_inputs`
/// created it before the engine started — so leaving it unwritten is the "stub that never reaches a
/// terminal state" failure, one layer up. The zeroed totals mean "none were settled", which is true:
/// the engine failed before it could aggregate any. They are not a claim that the run was free.
pub fn unreported_run(run_id: &str, message: &str) -> RunReport {
    RunReport {
        run_id: iteron_workflow::RunId::new(run_id.to_string()),
        value: serde_json::json!({ "error": message }),
        stopped: true,
        cache_hits: 0,
        cache_misses: 0,
        errors: 0,
        tokens: 0,
        tool_calls: 0,
        elapsed_ms: 0,
    }
}

/// One settled background run, announced to the session loop that owns the event queue.
///
/// The supervisor cannot publish anything itself — it lives behind an `Arc` shared with a turn that
/// holds `&mut Agent` — so it reports through a channel the session's `select!` drains. That is what
/// makes a run settling while the operator is idle still reach the screen.
pub struct RunSettled {
    pub run_id: String,
    pub terminal: WorkflowRunTerminal,
    /// The operator-facing line. Names the run, its terminal state, and how to read the result.
    pub notice: String,
    /// Bounded model-facing task notification. The session owner either steers this into a live
    /// writer or starts one follow-up while idle; it is never reclassified as operator input.
    pub notification: String,
}

/// What the session did with the runs it still owned when it ended.
///
/// Returned by the session loop rather than published, because by the time it exists the event
/// queue's reader is already gone: the session ends *because* the frontend hung up. The client
/// prints it after restoring the terminal.
#[derive(Debug, Default)]
pub struct ShutdownReport {
    pub lines: Vec<String>,
}

impl ShutdownReport {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// Total bytes of settled-run summaries this owner keeps in memory for `collect`.
///
/// A bound, not a buffer: past it the OLDEST settled summary is dropped and the drop is recorded, so
/// a `collect` on an evicted run names the durable `result.json` instead of answering "unknown".
/// A silently forgotten result would be indistinguishable from a run that never happened.
const MAX_RETAINED_SUMMARY_BYTES: usize = 4 * 1024 * 1024;
const MAX_TASK_NOTIFICATION_RESULT_BYTES: usize = 48 * 1024;

fn utf8_head(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &text[..end]
}

fn workflow_task_notification(
    name: &str,
    run_id: &str,
    status: &str,
    summary: &str,
    result_path: Option<&Path>,
    report: &RunReport,
) -> String {
    let truncated = summary.len() > MAX_TASK_NOTIFICATION_RESULT_BYTES;
    let result = utf8_head(summary, MAX_TASK_NOTIFICATION_RESULT_BYTES);
    let payload = serde_json::json!({
        "task_id": run_id,
        "task_type": "local_workflow",
        "status": status,
        "summary": format!("Dynamic workflow \"{name}\" {status}"),
        "result": result,
        "result_truncated": truncated,
        "full_result_path": result_path,
        "usage": {
            "agent_count": report.cache_hits.saturating_add(report.cache_misses),
            "subagent_tokens": report.tokens,
            "tool_uses": report.tool_calls,
            "duration_ms": report.elapsed_ms,
        }
    });
    format!(
        "<task-notification>\n{}\n</task-notification>",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
    )
}

/// How long a session waits for the runs it cancelled at exit before writing their terminal record
/// itself. The engine interrupts a sync JS loop at its own safe point; this bounds the wait so
/// quitting can never hang on a script that ignores it.
pub const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Most session-owned run rows copied into one operator inventory response. Durable history remains
/// available through sidecars; this bound keeps one `/workflows` refresh independent of session age.
const MAX_OPERATOR_INVENTORY_RUNS: usize = 64;

enum SupervisedState {
    Running {
        handle: Arc<RunHandle>,
        started: std::time::Instant,
        /// Set once `cancel` has been requested, so the operator is not told "running" about a run
        /// that is already stopping.
        cancelling: bool,
    },
    /// Settled with a report. `summary` is `None` only when it was evicted under the byte bound.
    Settled { summary: Option<String> },
    /// The engine failed before producing a report.
    Failed { error: String },
}

struct SupervisedRun {
    name: String,
    workflows_dir: PathBuf,
    degraded: Arc<DegradedAgentSink>,
    /// The results this run had already produced, so a kill answers with them rather than with the
    /// `null` the engine resolves a stopped script to.
    partial: Arc<PartialWorkSink>,
    state: SupervisedState,
    /// Monotonic registration order, so eviction drops the oldest settled summary first.
    ordinal: u64,
}

/// Operator-facing state for one workflow run owned by the current interactive session.
///
/// This is deliberately smaller than [`SupervisedState`]: summaries and engine handles never
/// cross into the frontend. The TUI needs identity, lifecycle and bounded progress counters only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedRunStatus {
    Running,
    Cancelling,
    Settled,
    Failed,
}

/// A bounded snapshot of one session-owned workflow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedRunInfo {
    pub run_id: String,
    pub name: String,
    pub status: SupervisedRunStatus,
    pub elapsed_ms: u64,
    pub finished_agents: usize,
    pub running_agents: usize,
    pub dropped_results: usize,
}

fn supervised_run_info(run_id: &str, run: &SupervisedRun) -> SupervisedRunInfo {
    let partial = run.partial.snapshot();
    let (status, elapsed_ms) = match &run.state {
        SupervisedState::Running {
            started,
            cancelling,
            ..
        } => (
            if *cancelling {
                SupervisedRunStatus::Cancelling
            } else {
                SupervisedRunStatus::Running
            },
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        ),
        SupervisedState::Settled { .. } => (SupervisedRunStatus::Settled, 0),
        SupervisedState::Failed { .. } => (SupervisedRunStatus::Failed, 0),
    };
    SupervisedRunInfo {
        run_id: run_id.to_string(),
        name: run.name.clone(),
        status,
        elapsed_ms,
        finished_agents: partial.finished.len(),
        running_agents: partial.running,
        dropped_results: partial.dropped,
    }
}

/// The one answer for a settled run whose summary is no longer held in memory.
///
/// `collect` and `cancel` must give the SAME answer here. `cancel` used to reply `Unknown` — "this
/// session never started that run" — to a run this session demonstrably did start, which is
/// indistinguishable from a lost result, the one failure a detached run must not have.
fn evicted_summary(run: &SupervisedRun, run_id: &str, evicted: usize) -> String {
    format!(
        "Workflow `{}` (run {run_id}) settled, but this session no longer holds its summary in \
         memory ({evicted} older result(s) were dropped to stay within its retention bound). The \
         authoritative result is on disk at {}.",
        run.name,
        run_dir(&run.workflows_dir, run_id)
            .join("result.json")
            .display()
    )
}

#[derive(Default)]
struct SupervisorInner {
    runs: std::collections::HashMap<String, SupervisedRun>,
    next_ordinal: u64,
    retained_bytes: usize,
    evicted: usize,
}

/// The session-scoped owner of detached workflow runs.
///
/// # Why it lives beside the session loop and not inside the turn
///
/// A run cannot outlive its turn while the only thing holding it is a local binding inside a method
/// that borrows `&mut Agent`. This type is the owner that fixes that: it is an `Arc` installed on
/// the agent as a [`WorkflowLauncher`] *and* held by `app_server::serve`, i.e. it is reachable from
/// both sides of the turn's exclusive borrow without either side lending the other anything.
///
/// # What it guarantees
///
/// 1. **Nothing is orphaned.** Every detached run is registered before it is announced, and a reaper
///    task holds the handle for as long as the run lives. `serve` cannot return without going
///    through [`Self::shutdown`], which cancels and reaps.
/// 2. **No result is lost.** The reaper persists the terminal sidecar (`iteron workflow list`) and
///    keeps the model-facing summary for `collect`, which is built by [`run_result_summary`] — the
///    same function the in-turn path uses.
/// 3. **The model is never told a turn completed when it did not.** `launch` returns
///    [`Launched::Detached`] with a receipt that states, in words, that there is no result yet.
pub struct WorkflowSupervisor {
    /// A self-reference so a reaper task can be handed the owner without the launcher call site
    /// having to pass one in. `WorkflowLauncher` is implemented for `WorkflowSupervisor` (not for
    /// `Arc<WorkflowSupervisor>`), so `&self` is all `launch` receives.
    me: std::sync::Weak<WorkflowSupervisor>,
    inner: std::sync::Mutex<SupervisorInner>,
    settled: tokio::sync::mpsc::UnboundedSender<RunSettled>,
}

impl WorkflowSupervisor {
    /// The one sentence handed to the model with every receipt. A constant so the exit rule the
    /// model is told and the exit rule [`Self::shutdown`] enforces cannot drift apart.
    pub const OWNERSHIP: &'static str = "This session owns the run. Ending the session stops it at the engine's next safe point; \
         its journal is kept, so `iteron workflow resume <run-id>` continues it in a new process.";

    pub fn new(settled: tokio::sync::mpsc::UnboundedSender<RunSettled>) -> Arc<Self> {
        Arc::new_cyclic(|me| WorkflowSupervisor {
            me: me.clone(),
            inner: std::sync::Mutex::new(SupervisorInner::default()),
            settled,
        })
    }

    /// Snapshot the newest session-owned runs in registration order. The response has an explicit
    /// row ceiling and contains no model-authored result bytes.
    pub fn inventory(&self) -> Vec<SupervisedRunInfo> {
        let inner = self.inner.lock().unwrap();
        let mut runs: Vec<_> = inner
            .runs
            .iter()
            .map(|(run_id, run)| (run.ordinal, run_id.as_str(), run))
            .collect();
        runs.sort_by_key(|(ordinal, _, _)| *ordinal);
        let skip = runs.len().saturating_sub(MAX_OPERATOR_INVENTORY_RUNS);
        runs.into_iter()
            .skip(skip)
            .map(|(_, run_id, run)| supervised_run_info(run_id, run))
            .collect()
    }

    /// Whether a persisted run id may be resumed through this owner. A running or already-
    /// cancelling run must settle first; replacing its handle would orphan its reaper.
    pub fn may_resume(&self, run_id: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        !inner
            .runs
            .get(run_id)
            .is_some_and(|run| matches!(run.state, SupervisedState::Running { .. }))
    }

    /// Operator kill: trip exactly the selected detached run and return its post-request snapshot.
    /// This bypasses the model-facing `Workflow({cancel})` surface while sharing the same owner and
    /// cancellation token.
    pub fn cancel_for_operator(&self, run_id: &str) -> Result<SupervisedRunInfo, String> {
        let mut inner = self.inner.lock().unwrap();
        let Some(run) = inner.runs.get_mut(run_id) else {
            return Err(format!(
                "workflow run `{run_id}` is not owned by this session"
            ));
        };
        match &mut run.state {
            SupervisedState::Running {
                handle, cancelling, ..
            } => {
                run.partial.note_kill();
                handle.cancel();
                *cancelling = true;
                Ok(supervised_run_info(run_id, run))
            }
            SupervisedState::Settled { .. } => {
                Err(format!("workflow run `{run_id}` has already settled"))
            }
            SupervisedState::Failed { .. } => {
                Err(format!("workflow run `{run_id}` has already failed"))
            }
        }
    }

    /// Register and start one detached run, spawning the reaper that owns it from here on.
    fn detach(
        &self,
        owner: Arc<WorkflowSupervisor>,
        prepared: PreparedWorkflow,
        runtime: tokio::runtime::Handle,
    ) -> Launched {
        let PreparedWorkflow {
            run_id,
            name,
            workflows_dir,
            spec,
            spawner,
            sink,
            degraded,
            ..
        } = prepared;
        // Fanned in rather than passed by the caller: only a run that DETACHES can be killed out of
        // band, so only a detached run needs its finished work held in memory. Wrapping can never
        // lower what the fan-out reports as its port version below what `sink` already reported.
        let partial = Arc::new(PartialWorkSink::new());
        let sink: Arc<dyn ProgressSink> =
            Arc::new(FanoutProgressSink::new(vec![sink, partial.clone()]));
        let handle = Arc::new(WorkflowEngine::launch(spec, spawner, sink));
        {
            let mut inner = self.inner.lock().unwrap();
            let ordinal = inner.next_ordinal;
            inner.next_ordinal += 1;
            let replaced = inner.runs.insert(
                run_id.clone(),
                SupervisedRun {
                    name: name.clone(),
                    workflows_dir: workflows_dir.clone(),
                    degraded: degraded.clone(),
                    partial,
                    state: SupervisedState::Running {
                        handle: Arc::clone(&handle),
                        started: std::time::Instant::now(),
                        cancelling: false,
                    },
                    ordinal,
                },
            );
            if let Some(SupervisedRun {
                state:
                    SupervisedState::Settled {
                        summary: Some(summary),
                    },
                ..
            }) = replaced
            {
                inner.retained_bytes = inner.retained_bytes.saturating_sub(summary.len());
            }
        }

        // The reaper. It is the only joiner of this handle (`RunHandle::join` consumes the
        // receiver), which is why `shutdown` waits on the settled channel instead of joining too.
        let reaped_id = run_id.clone();
        let reaped_name = name.clone();
        runtime.spawn(async move {
            let outcome = handle.join().await;
            owner.settle(&reaped_id, &reaped_name, outcome);
        });

        Launched::Detached(DetachedRun {
            run_id,
            name,
            ownership: Self::OWNERSHIP.to_string(),
        })
    }

    /// Record a settled run: persist its terminal sidecar, keep its model-facing summary, announce
    /// it. Called from the reaper, and from [`Self::shutdown`] for a run that ignored its cancel.
    fn settle(&self, run_id: &str, name: &str, outcome: anyhow::Result<RunReport>) {
        let (workflows_dir, degraded, partial) = {
            let inner = self.inner.lock().unwrap();
            match inner.runs.get(run_id) {
                // Already settled (shutdown got there first). Settling twice would publish a second
                // terminal line for one run, so stop here.
                Some(run) if !matches!(run.state, SupervisedState::Running { .. }) => return,
                Some(run) => (
                    run.workflows_dir.clone(),
                    run.degraded.clone(),
                    run.partial.clone(),
                ),
                None => return,
            }
        };

        // Render first, WITHOUT the lock: both summaries are pure and the report can be large.
        let (report, state, notice, status, model_summary, terminal) = match outcome {
            Ok(report) => {
                // `stopped` is set for exactly the cancellation token this owner trips, so it is
                // the kill signal. A run that returned on its own a moment before the cancel landed
                // reports `false` and is rendered as what it is: completed.
                let summary = if report.stopped {
                    killed_run_summary(
                        name,
                        run_id,
                        &report,
                        &partial.snapshot(),
                        &degraded.reasons(),
                    )
                } else {
                    run_result_summary(name, run_id, &report, &degraded.reasons())
                };
                let terminal_text = if report.stopped {
                    "was killed and kept the results it had already produced"
                } else {
                    "finished in the background"
                };
                let status = if report.stopped {
                    "stopped"
                } else {
                    "completed"
                };
                let terminal = if report.stopped {
                    WorkflowRunTerminal::Cancelled
                } else {
                    WorkflowRunTerminal::Completed
                };
                (
                    report,
                    SupervisedState::Settled {
                        summary: Some(summary.clone()),
                    },
                    format!(
                        "Dynamic workflow `{name}` (run {run_id}) {terminal_text}; `/workflows` shows its \
                         result and controls"
                    ),
                    status,
                    summary,
                    terminal,
                )
            }
            Err(error) => {
                let message = format!("Workflow run failed: {error}");
                (
                    unreported_run(run_id, &message),
                    SupervisedState::Failed {
                        error: message.clone(),
                    },
                    format!("Workflow `{name}` (run {run_id}) failed in the background: {message}"),
                    "failed",
                    message,
                    WorkflowRunTerminal::Failed,
                )
            }
        };

        // CLAIM THE RUN BEFORE WRITING ITS FILE. `shutdown` decides whether to write a synthetic
        // terminal record while holding this same lock and reading this same state, so taking the
        // state first makes "who writes result.json" a single decision instead of a race in which
        // the loser's file lands last. A reaper that finds the state already taken writes nothing.
        let mut notice = notice;
        {
            let mut inner = self.inner.lock().unwrap();
            match inner.runs.get_mut(run_id) {
                Some(run) if matches!(run.state, SupervisedState::Running { .. }) => {
                    run.state = state;
                }
                // Shutdown claimed it in the window above and has already written its record.
                _ => return,
            }
            if let Some(SupervisedState::Settled {
                summary: Some(summary),
            }) = inner.runs.get(run_id).map(|run| &run.state)
            {
                inner.retained_bytes += summary.len();
            }
            evict_summaries(&mut inner);
        }

        let result_path = run_dir(&workflows_dir, run_id).join("result.json");
        let result_persisted = match persist_result(&workflows_dir, run_id, &report) {
            Ok(()) => true,
            Err(error) => {
                // Degrade, never destroy: a sidecar that cannot be written must not cost the
                // operator a run they already paid for. The bounded notification remains available.
                notice.push_str(&format!(
                    " (its result sidecar could not be written: {error})"
                ));
                false
            }
        };

        let notification = workflow_task_notification(
            name,
            run_id,
            status,
            &model_summary,
            result_persisted.then_some(result_path.as_path()),
            &report,
        );

        let _ = self.settled.send(RunSettled {
            run_id: run_id.to_string(),
            terminal,
            notice,
            notification,
        });
    }

    /// Cancel every run still live, wait `grace` for them to settle through their reapers, and write
    /// a terminal record for any that did not.
    ///
    /// The wait is on `settled` — the reapers' channel — because the reaper holds the only joinable
    /// receiver for each handle. Draining it here also means a run that settles *during* shutdown is
    /// recorded with its real report rather than the synthetic one below.
    pub async fn shutdown(
        &self,
        settled: &mut tokio::sync::mpsc::UnboundedReceiver<RunSettled>,
        grace: std::time::Duration,
    ) -> ShutdownReport {
        let live: Vec<String> = {
            let inner = self.inner.lock().unwrap();
            inner
                .runs
                .iter()
                .filter(|(_, run)| matches!(run.state, SupervisedState::Running { .. }))
                .map(|(id, _)| id.clone())
                .collect()
        };
        if live.is_empty() {
            return ShutdownReport::default();
        }

        {
            let inner = self.inner.lock().unwrap();
            for id in &live {
                let Some(run) = inner.runs.get(id) else {
                    continue;
                };
                let SupervisedState::Running { handle, .. } = &run.state else {
                    continue;
                };
                // Sample BEFORE the cancel, for the reason `note_kill` documents: afterwards the
                // engine has already retired the in-flight rows and the count reads zero.
                run.partial.note_kill();
                handle.cancel();
            }
        }

        let deadline = tokio::time::Instant::now() + grace;
        let mut outstanding = live.len();
        while outstanding > 0 {
            match tokio::time::timeout_at(deadline, settled.recv()).await {
                Ok(Some(message)) => {
                    if live.contains(&message.run_id) {
                        outstanding -= 1;
                    }
                }
                // The channel cannot close while the supervisor holds a sender, so `None` and a
                // timeout are the same terminal condition: stop waiting and record the truth.
                Ok(None) | Err(_) => break,
            }
        }

        let mut lines = Vec::new();
        let mut inner = self.inner.lock().unwrap();
        for id in live {
            let Some(run) = inner.runs.get_mut(&id) else {
                continue;
            };
            match &run.state {
                SupervisedState::Running { .. } => {
                    // The count goes into the record because this run never reached `settle`, so
                    // this message is the only place its partial work is named at all; `collect`
                    // will answer `Failed` with exactly this string.
                    let finished = run.partial.snapshot().finished.len();
                    let message = format!(
                        "the session ended before this run settled; it was cancelled at exit \
                         ({finished} agent result(s) had already been produced and are in its \
                         journal)"
                    );
                    let _ = persist_result(&run.workflows_dir, &id, &unreported_run(&id, &message));
                    run.state = SupervisedState::Failed { error: message };
                    lines.push(format!(
                        "workflow `{}` (run {id}) did not stop within {}s and was recorded as \
                         stopped at exit; resume it with `iteron workflow resume {id}`",
                        run.name,
                        grace.as_secs()
                    ));
                }
                _ => lines.push(format!(
                    "workflow `{}` (run {id}) was stopped when the session ended; resume it with \
                     `iteron workflow resume {id}`",
                    run.name
                )),
            }
        }
        ShutdownReport { lines }
    }
}

/// Drop the oldest settled summaries until the retained bytes fit the bound, counting the drops.
///
/// The entry itself is kept: an evicted run answers `collect` by naming its durable `result.json`,
/// which is a different and honest answer from "unknown run".
fn evict_summaries(inner: &mut SupervisorInner) {
    while inner.retained_bytes > MAX_RETAINED_SUMMARY_BYTES {
        let victim = inner
            .runs
            .iter()
            .filter(|(_, run)| matches!(run.state, SupervisedState::Settled { summary: Some(_) }))
            .min_by_key(|(_, run)| run.ordinal)
            .map(|(id, _)| id.clone());
        let Some(victim) = victim else { return };
        if let Some(run) = inner.runs.get_mut(&victim)
            && let SupervisedState::Settled { summary } = &mut run.state
            && let Some(dropped) = summary.take()
        {
            inner.retained_bytes = inner.retained_bytes.saturating_sub(dropped.len());
            inner.evicted += 1;
        }
    }
}

impl WorkflowLauncher for WorkflowSupervisor {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched {
        if !prepared.background {
            // `background: false` is the model saying it cannot proceed without the result, so the
            // run is byte-for-byte the in-turn run it always was, even with an owner installed.
            // Everything else detaches: holding the conversation open for a whole fan-out is the
            // cost this supervisor exists to remove, and a default that only applied when the model
            // remembered to ask for it did not remove it.
            return InTurnWorkflowLauncher.launch(prepared);
        }
        // No ambient runtime, or no live `Arc` to hand the reaper, means no owner for the run — and
        // a detached run with no owner is an orphan. Run it in-turn instead; the kernel tells the
        // model the request was not granted rather than pretending it was.
        let (Ok(runtime), Some(owner)) = (tokio::runtime::Handle::try_current(), self.me.upgrade())
        else {
            return InTurnWorkflowLauncher.launch(prepared);
        };
        self.detach(owner, prepared, runtime)
    }

    fn collect(&self, run_id: &str) -> Collected {
        let inner = self.inner.lock().unwrap();
        let Some(run) = inner.runs.get(run_id) else {
            return Collected::Unknown(format!(
                "Workflow: run `{run_id}` was not started by this session. `iteron workflow list` \
                 shows every run on disk."
            ));
        };
        match &run.state {
            SupervisedState::Running {
                started,
                cancelling,
                ..
            } => Collected::Running {
                run_id: run_id.to_string(),
                name: if *cancelling {
                    format!("{} (cancelling)", run.name)
                } else {
                    run.name.clone()
                },
                elapsed_ms: started.elapsed().as_millis() as u64,
            },
            SupervisedState::Settled {
                summary: Some(summary),
            } => Collected::Settled {
                summary: summary.clone(),
            },
            SupervisedState::Settled { summary: None } => Collected::Settled {
                summary: evicted_summary(run, run_id, inner.evicted),
            },
            SupervisedState::Failed { error } => Collected::Failed {
                run_id: run_id.to_string(),
                error: error.clone(),
            },
        }
    }

    /// Kill a run, and answer with what killing it produced.
    ///
    /// The kill stays a REQUEST honoured at the engine's next safe point — this returns as soon as
    /// the token is tripped, and the terminal answer is read by a later `collect`, because blocking
    /// here would put a detached run back inside the turn that detaching exists to free. What
    /// changes is that the terminal answer is now a "killed" one carrying the finished agents'
    /// results and a count of what was interrupted ([`killed_run_summary`]), instead of the engine's
    /// bare `null`.
    fn cancel(&self, run_id: &str) -> Collected {
        let mut inner = self.inner.lock().unwrap();
        // Copied out before the mutable borrow below, so the evicted-summary answer can name the
        // same drop count `collect` names.
        let evicted = inner.evicted;
        let Some(run) = inner.runs.get_mut(run_id) else {
            return Collected::Unknown(format!(
                "Workflow: run `{run_id}` was not started by this session, so there is nothing to \
                 cancel."
            ));
        };
        let partial = run.partial.clone();
        match &mut run.state {
            SupervisedState::Running {
                handle,
                started,
                cancelling,
            } => {
                // Sample, then trip the token — never the other way round (see `note_kill`).
                partial.note_kill();
                handle.cancel();
                *cancelling = true;
                Collected::Running {
                    run_id: run_id.to_string(),
                    name: format!("{} (cancelling)", run.name),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                }
            }
            SupervisedState::Settled {
                summary: Some(summary),
            } => Collected::Settled {
                summary: summary.clone(),
            },
            // Settled, but the summary was evicted. This is the SAME answer `collect` gives: a
            // `cancel` that replied "unknown" here would deny a run this session really did own.
            SupervisedState::Settled { summary: None } => Collected::Settled {
                summary: evicted_summary(run, run_id, evicted),
            },
            SupervisedState::Failed { error } => Collected::Failed {
                run_id: run_id.to_string(),
                error: error.clone(),
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Persistence + enumeration for the background-launch surface (`iteron workflow list/resume/watch`).
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
    #[serde(default)]
    pub errors: usize,
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

/// Whether `run_id` is safe to use as one direct child directory name.
///
/// Generated ids already satisfy this. Operator controls validate persisted ids again because a
/// path-bearing resume request must never turn `Path::join` into traversal outside the workflow
/// store.
pub fn valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 160
        && run_id != "."
        && run_id != ".."
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
        errors: report.errors,
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

/// One row of `iteron workflow list` (also the durable summary the TUI can rehydrate).
#[derive(Debug, Clone, PartialEq, Eq)]
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
        Ok(text) => count_agent_results(&text),
        Err(_) => 0,
    }
}

fn count_agent_results(journal: &str) -> usize {
    journal
        .lines()
        .filter(|line| line.contains("\"type\":\"result\""))
        .count()
}

fn derive_status(result: Option<&RunResult>, has_journal: bool) -> &'static str {
    match result {
        Some(r) if r.stopped => "stopped",
        Some(r) if r.errors > 0 => "failed",
        Some(_) => "done",
        None if has_journal => "running",
        None => "pending",
    }
}

/// Largest journal opened by the first-frame rehydration path. The run remains durable and
/// available to `iteron workflow list|resume`; it is merely omitted from the startup inventory.
const MAX_RECENT_JOURNAL_BYTES: u64 = 256 * 1024;

/// Strict summary used by restart rehydration. Unlike the human-invoked full listing, the first
/// frame must never publish a partial count from a killed writer or spend unbounded time on one
/// historical journal.
fn recent_journal_summary(workflows_dir: &Path, run_id: &str) -> Option<(bool, usize)> {
    let path = run_dir(workflows_dir, run_id).join("journal.jsonl");
    let len = match std::fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some((false, 0)),
        Err(_) => return None,
    };
    if len > MAX_RECENT_JOURNAL_BYTES {
        return None;
    }
    use std::io::Read as _;
    let mut bytes = Vec::with_capacity(len as usize);
    std::fs::File::open(path)
        .ok()?
        .take(MAX_RECENT_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RECENT_JOURNAL_BYTES {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    if !text.is_empty() && !text.ends_with('\n') {
        return None;
    }
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).ok()?;
    }
    Some((true, count_agent_results(&text)))
}

/// Load one restart-safe listing through the same manifest/script/result readers used by
/// `iteron workflow list|resume|watch`. A torn optional sidecar refuses this row, not its neighbours.
pub(crate) fn load_run_listing(workflows_dir: &Path, run_id: String) -> Option<RunListing> {
    let manifest = load_manifest(workflows_dir, &run_id)?;
    // A restored row advertises the run id accepted by resume/watch, so the persisted script must
    // be readable too. This calls their existing reader rather than inventing a TUI-side parser.
    load_script(workflows_dir, &run_id)?;
    let result_path = run_dir(workflows_dir, &run_id).join("result.json");
    let result = load_result(workflows_dir, &run_id);
    if result_path.exists() && result.is_none() {
        return None;
    }
    let (has_journal, agents) = recent_journal_summary(workflows_dir, &run_id)?;
    Some(RunListing {
        run_id,
        name: manifest.name,
        model: manifest.model,
        status: derive_status(result.as_ref(), has_journal),
        agents,
        created_at: manifest.created_at,
    })
}

/// Enumerate every persisted run under `<workflows_dir>`, newest first. A run's status is derived
/// from its sidecars: `done`/`failed`/`stopped` once `result.json` exists, else `running` if a
/// journal is present, else `pending`.
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
        let status = derive_status(result.as_ref(), has_journal);
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

/// Stable CLI outcome label for a settled workflow. Cancellation takes precedence because it has
/// its own operator action and exit contract even if some children failed before the interrupt.
pub fn run_status(report: &RunReport) -> &'static str {
    if report.stopped {
        "stopped"
    } else if report.errors > 0 {
        "failed"
    } else {
        "done"
    }
}

/// Stable process contract for `iteron workflow run|resume|watch`: clean success is 0, any settled
/// agent failure is 1, and operator cancellation remains 130.
pub fn run_exit_code(report: &RunReport) -> u8 {
    if report.stopped {
        crate::output::EXIT_INTERRUPTED
    } else if report.errors > 0 {
        crate::output::EXIT_WORKFLOW_FAILED
    } else {
        crate::output::EXIT_SUCCESS
    }
}

/// The terminal status line shared by TTY and piped workflow commands.
pub fn final_status_line(run_id: &str, report: &RunReport) -> String {
    format!(
        "run {run_id} \u{b7} {} \u{b7} {} failed \u{b7} {} tok \u{b7} {} tool call(s) \u{b7} {} \u{b7} cache {} hit / {} miss",
        run_status(report),
        report.errors,
        fmt_count(report.tokens),
        report.tool_calls,
        fmt_duration(report.elapsed_ms),
        report.cache_hits,
        report.cache_misses
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Block, StopReason, Usage};
    use iteron_provider::{ProviderError, TurnResult, UsageReport};
    use iteron_workflow::{RunId, RunReport};
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
            "iteron-cli-workflow-{tag}-{}-{}",
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
        assert_eq!(
            provider.turns.load(Ordering::SeqCst),
            2,
            "the workflow's bounded retry policy gives the failed logical agent one retry"
        );
        assert_safe_refusal_surfaces(&workflows_dir, "fallback-error", &sink, 1, secret);
        let _ = std::fs::remove_dir_all(workflows_dir);
    }

    #[test]
    fn a_run_that_only_wrote_a_journal_lists_as_an_unnamed_running_stub() {
        // The in-turn (`Workflow` tool) path used to do exactly this: write its journal into the
        // directory `iteron workflow list` enumerates and never call either persistence helper. This
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
                errors: 0,
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
    fn a_persisted_agent_failure_lists_as_failed() {
        let workflows_dir = scratch_dir("persisted-agent-failure");
        let manifest = RunManifest {
            run_id: "wf_agent_failed".into(),
            name: "triage".into(),
            args: serde_json::Value::Null,
            provider_id: "anthropic".into(),
            model: "core-model-1".into(),
            created_at: 43,
        };
        persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
        persist_result(
            &workflows_dir,
            "wf_agent_failed",
            &RunReport {
                run_id: RunId::new("wf_agent_failed"),
                value: serde_json::json!(["ok", null]),
                stopped: false,
                cache_hits: 0,
                cache_misses: 2,
                errors: 1,
                tokens: 7,
                tool_calls: 0,
                elapsed_ms: 10,
            },
        )
        .unwrap();

        assert_eq!(list_runs(&workflows_dir)[0].status, "failed");
        assert_eq!(
            load_result(&workflows_dir, "wf_agent_failed")
                .unwrap()
                .errors,
            1
        );
        let _ = std::fs::remove_dir_all(&workflows_dir);
    }

    #[test]
    fn workflow_failure_exit_and_status_contract_distinguishes_clean_failed_and_cancelled() {
        let report = |errors, stopped| RunReport {
            run_id: RunId::new("wf_contract"),
            value: serde_json::Value::Null,
            stopped,
            cache_hits: 0,
            cache_misses: 3,
            errors,
            tokens: 21,
            tool_calls: 0,
            elapsed_ms: 10,
        };

        let clean = report(0, false);
        assert_eq!(run_status(&clean), "done");
        assert_eq!(run_exit_code(&clean), crate::output::EXIT_SUCCESS);
        assert!(final_status_line("wf_contract", &clean).contains("done \u{b7} 0 failed"));

        for errors in [1, 3] {
            let failed = report(errors, false);
            assert_eq!(run_status(&failed), "failed");
            assert_eq!(run_exit_code(&failed), crate::output::EXIT_WORKFLOW_FAILED);
            assert!(
                final_status_line("wf_contract", &failed)
                    .contains(&format!("failed \u{b7} {errors} failed"))
            );
        }

        let cancelled = report(1, true);
        assert_eq!(run_status(&cancelled), "stopped");
        assert_eq!(run_exit_code(&cancelled), crate::output::EXIT_INTERRUPTED);
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
                errors: 0,
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
            errors: 0,
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
    /// The credential is delimited from what precedes it because `crate::semantic_text::ui_safe_text` defers
    /// to `iteron_record::redact::scrub`, which matches credential-shaped TOKENS. What this pins is
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

        // No frontend attached (`iteron -p`, `--output-format json`, an embedder): the sink is the
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

    // ---- S9: the session-scoped owner of detached runs -----------------------------------------

    /// Build a `PreparedWorkflow` for `script` the way `Agent::prepare_workflow` does, minus
    /// everything that needs a live route. The manifest is written first for the same reason the
    /// kernel writes it first: a run must be listable before anything can start it.
    fn prepared_for(tag: &str, script: &str, background: bool) -> PreparedWorkflow {
        prepared_with(
            tag,
            script,
            background,
            Arc::new(ProviderSpawner::new(
                Arc::new(RecordingProvider::successful()),
                "parent-model".into(),
            )),
        )
    }

    /// The same, with the spawner chosen by the caller: the owner tests below need to decide when
    /// an agent finishes and which one degrades, which no provider stand-in can express.
    fn prepared_with(
        tag: &str,
        script: &str,
        background: bool,
        spawner: Arc<dyn AgentSpawner>,
    ) -> PreparedWorkflow {
        let workflows_dir = scratch_dir(tag);
        let run_id = format!("wf-{tag}");
        let name = "owned".to_string();
        persist_inputs(
            &workflows_dir,
            &RunManifest {
                run_id: run_id.clone(),
                name: name.clone(),
                args: serde_json::Value::Null,
                provider_id: "provider-a".into(),
                model: "model-a".into(),
                created_at: 0,
            },
            script,
        )
        .unwrap();
        let degraded = Arc::new(DegradedAgentSink::new());
        PreparedWorkflow {
            run_id: run_id.clone(),
            name,
            declared_phases: Vec::new(),
            workflows_dir: workflows_dir.clone(),
            spec: RunSpec::new(script)
                .with_run_id(RunId::new(run_id))
                .with_workflows_dir(workflows_dir),
            spawner,
            sink: degraded.clone(),
            degraded,
            background,
        }
    }

    /// Pure QuickJS, so these tests never touch a provider.
    const OWNED_SCRIPT: &str =
        "export const meta = { name: 'owned', description: '', phases: [] };\nreturn 7;\n";
    /// A script that will not finish on its own: the only way out is cancellation.
    const ENDLESS_SCRIPT: &str =
        "export const meta = { name: 'owned', description: '', phases: [] };\nwhile (true) {}\n";

    async fn settled_line(rx: &mut tokio::sync::mpsc::UnboundedReceiver<RunSettled>) -> RunSettled {
        tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
            .await
            .expect("the reaper announced the run within the test timeout")
            .expect("the supervisor still holds a sender")
    }

    #[tokio::test]
    async fn an_unrequested_run_still_belongs_to_the_turn_even_with_an_owner_installed() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let prepared = prepared_for("owner-default", OWNED_SCRIPT, false);
        let dir = prepared.workflows_dir.clone();

        let Launched::InTurn(handle) = owner.launch(prepared) else {
            panic!("detaching is opt-in; an unrequested run must stay in-turn");
        };
        assert_eq!(handle.join().await.unwrap().value, serde_json::json!(7));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_backgrounded_run_is_detached_and_its_result_is_readable_only_by_collecting_it() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let prepared = prepared_for("owner-detach", OWNED_SCRIPT, true);
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();

        let Launched::Detached(detached) = owner.launch(prepared) else {
            panic!("an owner that can hold a run must grant the request");
        };
        assert_eq!(detached.run_id, run_id);
        assert_eq!(detached.ownership, WorkflowSupervisor::OWNERSHIP);

        // Before the run settles, collect is a status and NEVER a value: this is the property that
        // stops the model reporting a completion that has not happened.
        match owner.collect(&run_id) {
            Collected::Running { .. } | Collected::Settled { .. } => {}
            other => panic!(
                "a live detached run is running or settled, never unknown: {}",
                matches!(other, Collected::Unknown(_))
            ),
        }

        let settled = settled_line(&mut rx).await;
        assert_eq!(settled.run_id, run_id);
        assert!(settled.notice.contains("finished"), "{}", settled.notice);

        let Collected::Settled { summary } = owner.collect(&run_id) else {
            panic!("a settled run collects its result");
        };
        // The SAME rendering the in-turn path would have returned for this report.
        assert!(summary.contains(&run_id), "{summary}");
        assert!(summary.contains("finished"), "{summary}");
        assert!(summary.contains('7'), "{summary}");

        // And the result is durable, so a model that never collects has still not destroyed it.
        let listed = list_runs(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "done");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn collecting_a_run_this_session_never_started_is_answered_not_guessed() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let Collected::Unknown(message) = owner.collect("wf-never-existed") else {
            panic!("an unknown id is unknown, not a result");
        };
        assert!(message.contains("wf-never-existed"), "{message}");
        // The in-turn launcher owns nothing past the turn and says exactly that.
        assert!(matches!(
            InTurnWorkflowLauncher.collect("wf-anything"),
            Collected::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn a_session_that_ends_with_a_live_run_stops_it_and_records_a_terminal_state() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let prepared = prepared_for("owner-shutdown", ENDLESS_SCRIPT, true);
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();
        let Launched::Detached(_) = owner.launch(prepared) else {
            panic!("the run must detach for this to be a test of session exit");
        };

        let report = owner
            .shutdown(&mut rx, std::time::Duration::from_secs(10))
            .await;
        assert!(!report.is_empty(), "a stopped run is always reported");
        let line = report.lines.join("\n");
        assert!(line.contains(&run_id), "{line}");
        assert!(
            line.contains("iteron workflow resume"),
            "the operator is told how to continue it: {line}"
        );

        // The run is no longer listed as `running`: the exact "stub that never reaches a terminal
        // state" failure an unowned detached run would have created.
        let listed = list_runs(&dir);
        assert_eq!(listed.len(), 1);
        assert_ne!(listed[0].status, "running", "{:?}", listed[0].status);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_session_with_no_live_run_reports_nothing_at_exit() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        assert!(
            owner
                .shutdown(&mut rx, std::time::Duration::from_secs(1))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancelling_a_detached_run_stops_it_and_the_owner_still_records_it() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let prepared = prepared_for("owner-cancel", ENDLESS_SCRIPT, true);
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();
        let Launched::Detached(_) = owner.launch(prepared) else {
            panic!("the run must detach to be cancellable out of band");
        };

        let before = owner.inventory();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].status, SupervisedRunStatus::Running);
        let stopping = owner
            .cancel_for_operator(&run_id)
            .expect("the operator owns this run");
        assert_eq!(stopping.status, SupervisedRunStatus::Cancelling);
        assert!(!owner.may_resume(&run_id));

        let settled = settled_line(&mut rx).await;
        assert_eq!(settled.run_id, run_id);
        assert!(owner.may_resume(&run_id));
        assert_eq!(owner.inventory()[0].status, SupervisedRunStatus::Settled);
        let Collected::Settled { summary } = owner.collect(&run_id) else {
            panic!("a cancelled run still settles with a readable outcome");
        };
        assert!(summary.contains("KILLED"), "{summary}");
        assert_eq!(
            list_runs(&dir)[0].status,
            run_status(&unreported_run(&run_id, ""))
        );
        std::fs::remove_dir_all(dir).ok();
    }

    // ---- Killing a run returns the work it had already finished -------------------------------
    //
    // The engine forces a stopped run's value to `null` on purpose (a half-evaluated JS value is
    // meaningless), so nothing INSIDE it can carry the finished agents' results across a kill. If
    // the owner does not keep them, a deliberate cancellation and a crash produce byte-identical
    // answers, and the operator silently pays for work they are never shown.

    /// A spawner with no provider behind it, so these tests exercise the OWNER rather than a route.
    /// `fail_on` degrades to null; `block_on` never returns on its own, so the run's cancellation is
    /// the only way out. Every call announces itself, which is what lets a test act at a known point
    /// in the run instead of racing it.
    struct ScriptedSpawner {
        started: tokio::sync::mpsc::UnboundedSender<String>,
        calls: AtomicUsize,
        fail_on: Option<&'static str>,
        block_on: Option<&'static str>,
    }

    impl ScriptedSpawner {
        fn new(started: tokio::sync::mpsc::UnboundedSender<String>) -> Self {
            ScriptedSpawner {
                started,
                calls: AtomicUsize::new(0),
                fail_on: None,
                block_on: None,
            }
        }

        fn failing_on(mut self, prompt: &'static str) -> Self {
            self.fail_on = Some(prompt);
            self
        }

        fn blocking_on(mut self, prompt: &'static str) -> Self {
            self.block_on = Some(prompt);
            self
        }
    }

    #[async_trait::async_trait]
    impl AgentSpawner for ScriptedSpawner {
        async fn spawn(&self, call: AgentCall) -> AgentOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.started.send(call.prompt.clone());
            if self.fail_on == Some(call.prompt.as_str()) {
                return AgentOutcome::null("provider exploded");
            }
            if self.block_on == Some(call.prompt.as_str()) {
                // The engine also aborts this child on cancel; awaiting the token makes the intent
                // explicit rather than leaning on that backstop.
                call.cancel.cancelled().await;
                return AgentOutcome::null("stopped");
            }
            AgentOutcome::text(format!("{}-result", call.prompt), 3)
        }
    }

    async fn next_started(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
            .await
            .expect("the spawner reported a call within the test timeout")
            .expect("the run still holds the spawner")
    }

    /// Two agents in sequence, the second of which blocks forever: a kill therefore lands on a run
    /// with one agent's work already done and exactly one agent in flight.
    const KILL_SCRIPT: &str = "export const meta = { name: 'owned', description: '', phases: [] };\n\
         const first = await agent('alpha');\n\
         const second = await agent('beta');\n\
         return [first, second];\n";

    /// A fan of three, one of which degrades to null.
    const FAN_SCRIPT: &str = "export const meta = { name: 'owned', description: '', phases: [] };\n\
         return await parallel([() => agent('alpha'), () => agent('boom'), () => agent('gamma')]);\n";

    #[tokio::test]
    async fn killing_a_detached_run_returns_the_agents_that_had_already_finished() {
        let (settled_tx, mut settled_rx) = tokio::sync::mpsc::unbounded_channel();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(settled_tx);
        let prepared = prepared_with(
            "owner-kill-partial",
            KILL_SCRIPT,
            true,
            Arc::new(ScriptedSpawner::new(started_tx).blocking_on("beta")),
        );
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();
        let Launched::Detached(_) = owner.launch(prepared) else {
            panic!("the run must detach to be killable out of band");
        };

        // `beta` having started proves `alpha` finished: the script awaits them in sequence. So the
        // kill below lands on a run with one real result behind it and one agent still running —
        // no sleep, no polling, no race.
        assert_eq!(next_started(&mut started_rx).await, "alpha");
        assert_eq!(next_started(&mut started_rx).await, "beta");

        let Collected::Running { name, .. } = owner.cancel(&run_id) else {
            panic!("cancel stays a request honoured at the engine's next safe point");
        };
        assert!(name.contains("cancelling"), "{name}");

        settled_line(&mut settled_rx).await;
        let Collected::Settled { summary } = owner.collect(&run_id) else {
            panic!("a killed run still has a terminal answer");
        };
        assert!(
            summary.contains("alpha-result"),
            "a kill must return the work the run had already finished, or it is indistinguishable \
             from a crash: {summary}"
        );
        assert!(
            summary.contains("1 agent(s) were still running"),
            "the answer must count what the kill interrupted: {summary}"
        );
        assert!(summary.contains("KILLED"), "{summary}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn one_agent_failing_does_not_kill_the_run_or_its_siblings() {
        let (settled_tx, mut settled_rx) = tokio::sync::mpsc::unbounded_channel();
        let (started_tx, _started_rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(settled_tx);
        let spawner = Arc::new(ScriptedSpawner::new(started_tx).failing_on("boom"));
        let prepared = prepared_with("owner-one-failure", FAN_SCRIPT, true, spawner.clone());
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();
        let Launched::Detached(_) = owner.launch(prepared) else {
            panic!("the run must detach for this to be a test of the owner");
        };

        let settled = settled_line(&mut settled_rx).await;
        assert!(
            settled.notice.contains("finished"),
            "a failed agent is not a killed run: {}",
            settled.notice
        );
        let Collected::Settled { summary } = owner.collect(&run_id) else {
            panic!("the run settles");
        };
        assert!(!summary.contains("KILLED"), "{summary}");
        assert_eq!(
            spawner.calls.load(Ordering::SeqCst),
            4,
            "all three declared agents run and the failed agent receives its one bounded retry"
        );
        for survivor in ["alpha-result", "gamma-result"] {
            assert!(
                summary.contains(survivor),
                "a sibling's failure must not delete {survivor}: {summary}"
            );
        }
        assert!(
            summary.contains("provider exploded"),
            "the one that failed is named, because it resolved to JS null and a script's \
             `.filter(Boolean)` would otherwise delete it silently: {summary}"
        );
        assert_ne!(
            list_runs(&dir)[0].status,
            "stopped",
            "an agent failure must not record the run as cancelled"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_partial_work_sink_keeps_finished_results_and_counts_what_the_kill_interrupted() {
        let sink = PartialWorkSink::new();
        let started = |index: usize| ProgressEvent::AgentStarted {
            index,
            label: format!("agent-{index}"),
            phase: None,
            model: None,
        };
        let finished = |index: usize, state, preview: Option<&str>| ProgressEvent::AgentFinished {
            index,
            label: format!("agent-{index}"),
            state,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 1,
            result_preview: preview.map(str::to_string),
            last_tool_summary: None,
            error: None,
        };

        for index in 0..3 {
            sink.emit(started(index));
        }
        sink.emit(finished(0, WorkflowState::Done, Some("first")));
        assert_eq!(sink.snapshot().running, 2);

        sink.note_kill();
        // The engine retires the in-flight rows as `stopped` errors on its way out. The answer must
        // report what the kill INTERRUPTED, not the zero that is left once it has finished
        // interrupting — a sample taken after the cancel flatters the kill.
        sink.emit(finished(1, WorkflowState::Error, None));
        sink.emit(finished(2, WorkflowState::Error, None));
        sink.note_kill();

        let partial = sink.snapshot();
        assert_eq!(partial.running, 2, "the count is sampled at the first kill");
        assert_eq!(partial.finished.len(), 1, "only results are kept");
        assert_eq!(partial.finished[0].result, "first");
        assert_eq!(partial.dropped, 0);
    }

    #[test]
    fn retained_partial_results_are_bounded_and_every_refusal_is_counted() {
        let sink = PartialWorkSink::new();
        let wide = 4_000usize;
        for index in 0..wide {
            sink.emit(ProgressEvent::AgentFinished {
                index,
                label: "row".into(),
                state: WorkflowState::Done,
                tokens: 0,
                tool_calls: 0,
                duration_ms: 1,
                result_preview: Some("x".repeat(PREVIEW_MAX)),
                last_tool_summary: None,
                error: None,
            });
        }

        let partial = sink.snapshot();
        assert!(
            partial.finished.len() < wide,
            "a wide fan-out cannot be retained whole"
        );
        assert_eq!(
            partial.finished.len() + partial.dropped,
            wide,
            "every result is either kept or counted as dropped; silent truncation would make a \
             short answer look complete"
        );
        assert_eq!(
            partial.finished[0].index, 0,
            "the earliest results are the ones kept, so a result a client already read in one \
             collect cannot vanish from the next"
        );
    }

    #[test]
    fn a_killed_summary_and_a_completed_one_cannot_be_mistaken_for_each_other() {
        let killed_report = RunReport {
            run_id: RunId::new("wf_kill"),
            value: serde_json::Value::Null,
            stopped: true,
            cache_hits: 0,
            cache_misses: 2,
            errors: 1,
            tokens: 9,
            tool_calls: 0,
            elapsed_ms: 5,
        };
        let partial = PartialWork {
            finished: vec![FinishedAgent {
                index: 0,
                label: "alpha".into(),
                result: "alpha said this".into(),
            }],
            running: 2,
            dropped: 0,
        };

        let killed = killed_run_summary(
            "triage",
            "wf_kill",
            &killed_report,
            &partial,
            &["#1 beta: stopped".to_string()],
        );
        assert!(killed.contains("KILLED"), "{killed}");
        assert!(killed.contains("alpha said this"), "{killed}");
        assert!(killed.contains("2 agent(s) were still running"), "{killed}");
        assert!(killed.contains("#1 beta: stopped"), "{killed}");

        let mut done_report = killed_report.clone();
        done_report.stopped = false;
        let done = run_result_summary("triage", "wf_done", &done_report, &[]);
        assert!(done.contains("finished"), "{done}");
        assert!(
            !done.contains("KILLED"),
            "a completed run must never read as a kill: {done}"
        );

        // A kill with nothing behind it says so, rather than leaving the client to read an empty
        // list as either "no work" or "the work was dropped".
        let nothing = killed_run_summary(
            "triage",
            "wf_kill",
            &killed_report,
            &PartialWork::default(),
            &[],
        );
        assert!(nothing.contains("no partial result"), "{nothing}");
        assert!(
            nothing.contains("0 agent(s) were still running"),
            "{nothing}"
        );
    }

    #[tokio::test]
    async fn cancelling_a_run_whose_summary_was_evicted_still_admits_the_run_existed() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = WorkflowSupervisor::new(tx);
        let prepared = prepared_for("owner-evicted-cancel", OWNED_SCRIPT, true);
        let dir = prepared.workflows_dir.clone();
        let run_id = prepared.run_id.clone();
        let Launched::Detached(_) = owner.launch(prepared) else {
            panic!("the run must detach to be owned");
        };
        settled_line(&mut rx).await;

        // Force the state the byte bound eventually produces. Driving 4 MiB of real summaries
        // through the reaper would exercise the same branch a thousand times more slowly.
        {
            let mut inner = owner.inner.lock().unwrap();
            inner.evicted = 1;
            inner.runs.get_mut(&run_id).unwrap().state = SupervisedState::Settled { summary: None };
        }

        let Collected::Settled { summary } = owner.cancel(&run_id) else {
            panic!(
                "a run this session owned is never unknown to it, even once its summary is gone"
            );
        };
        assert!(summary.contains("result.json"), "{summary}");
        let Collected::Settled { summary: collected } = owner.collect(&run_id) else {
            panic!("collect gives the same answer");
        };
        assert_eq!(
            summary, collected,
            "cancel and collect disagreeing about one run is how a result gets reported as lost"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}

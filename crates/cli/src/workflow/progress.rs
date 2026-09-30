//! Progress delivery and bounded retained partial/degraded work owners.

use super::projection::{UI_LABEL_MAX, WorkflowRunUiEvent, ui_safe_progress};
use iteron_workflow::RunHandle;
use iteron_workflow::events::{
    PREVIEW_MAX, PROGRESS_SINK_PORT_VERSION, ProgressEvent, ProgressSink, WorkflowState, fmt_count,
    fmt_duration, truncate_preview,
};
use std::io::Write;
use std::sync::Arc;

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
            ProgressEvent::AgentCancelling {
                index,
                cleanup_deadline_ms,
            } => format!(
                "[cancelling] #{index} · cleanup deadline {}",
                fmt_duration(cleanup_deadline_ms)
            ),
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
pub(super) const MAX_PARTIAL_RESULT_BYTES: usize = 256 * 1024;

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
                if retained.retained_bytes + cost
                    > iteron_tunables::param_integer(
                        "cli.workflow.max_partial_result_bytes",
                        MAX_PARTIAL_RESULT_BYTES,
                    )
                {
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
/// `emit` is called from the engine's single JS-driver thread and must not block. The channel is
/// therefore bounded and uses `try_send`; authoritative terminal state is not carried by this
/// cosmetic progress seam but by the supervisor's awaited settled channel.
pub struct UiProgressSink {
    run_id: String,
    tx: tokio::sync::mpsc::Sender<WorkflowRunUiEvent>,
}

impl UiProgressSink {
    pub fn new(
        run_id: impl Into<String>,
        tx: tokio::sync::mpsc::Sender<WorkflowRunUiEvent>,
    ) -> Self {
        UiProgressSink {
            run_id: run_id.into(),
            tx,
        }
    }
}

impl ProgressSink for UiProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let _ = self.tx.try_send(WorkflowRunUiEvent::Progress {
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
    frontend: Option<tokio::sync::mpsc::Sender<WorkflowRunUiEvent>>,
) -> Arc<dyn ProgressSink> {
    match frontend {
        Some(tx) => Arc::new(FanoutProgressSink::new(vec![
            degraded,
            Arc::new(UiProgressSink::new(run_id, tx)),
        ])),
        None => degraded,
    }
}

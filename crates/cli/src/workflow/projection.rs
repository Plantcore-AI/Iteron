//! Bounded projection from workflow-engine events into frontend-retained state.

use iteron_workflow::events::{PREVIEW_MAX, ProgressEvent, TOOL_SUMMARY_MAX, truncate_preview};

pub(super) const UI_LABEL_MAX: usize = 120;

/// One lifecycle message for a QuickJS workflow run, addressed to a frontend that can render the
/// live phase→agent tree ([`crate::block::WorkflowRunCard`]).
///
/// This is an in-process seam, not a published contract: it deliberately carries the engine's own
/// unfrozen [`ProgressEvent`] rather than a mirrored wire vocabulary, for the reasons above.
#[derive(Debug, Clone)]
pub enum WorkflowRunUiEvent {
    /// Bounded progress from an internal kernel model turn. This shares the TUI-only channel with
    /// workflow engine progress so the published `UiEvent`/machine-stream schema stays frozen.
    KernelActivity {
        kind: KernelActivityKind,
        output_chars: usize,
        thinking_chars: usize,
    },
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
    Finished {
        run_id: String,
        terminal: WorkflowRunTerminal,
    },
}

/// Authoritative terminal selected by the workflow owner. Frontends may fold the card, while
/// lifecycle projections use this value instead of guessing success from "the future resolved".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowRunTerminal {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelActivityKind {
    #[allow(dead_code)]
    Planning,
    Compaction,
}

impl KernelActivityKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Compaction => "compacting",
        }
    }
}

/// Apply the frontend's display gate to one untrusted line: secret-shaped substrings redacted and
/// terminal control characters escaped ([`crate::semantic_text::ui_safe_text`]), then whitespace collapsed
/// and the result re-bounded — escaping can only GROW a string (`\u{1b}` becomes six characters),
/// so the bound has to be re-applied after it, exactly as `block::safe_result_preview` does.
fn safe_line(text: &str, max: usize) -> String {
    truncate_preview(&crate::semantic_text::ui_safe_text(text), max)
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

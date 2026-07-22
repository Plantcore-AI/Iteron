//! CLI-side workflow wiring: a real provider-backed [`AgentSpawner`] and the non-TTY stdout progress
//! renderer (design §3.5). The `core workflow run` subcommand (in `main.rs`) composes these with
//! `core_workflow::WorkflowEngine`.

use std::io::Write;
use std::sync::Arc;

use async_trait::async_trait;
use core_protocol::{Effort, Message};
use core_provider::{Provider, StreamItem, TurnRequest};
use core_workflow::events::{ProgressEvent, ProgressSink, WorkflowState, fmt_count, fmt_duration};
use core_workflow::{AgentCall, AgentOutcome, AgentSpawner};

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
            ProgressEvent::Phase { title, .. } => format!("\u{2500}\u{2500} {title} \u{2500}\u{2500}"),
            ProgressEvent::Log { message } => format!("\u{276f} {message}"),
            ProgressEvent::AgentStarted {
                index, label, model, ..
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

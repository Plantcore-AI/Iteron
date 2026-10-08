//! CLI-side workflow wiring: a real provider-backed [`AgentSpawner`] and the non-TTY stdout progress
//! renderer (design §3.5). The `iteron workflow run` subcommand (in `main.rs`) composes these with
//! `iteron_workflow::WorkflowEngine`.

#[cfg(all(test, feature = "script-workflows"))]
use std::path::{Path, PathBuf};
#[cfg(all(test, feature = "script-workflows"))]
use std::sync::Arc;

#[cfg(all(test, feature = "script-workflows"))]
use async_trait::async_trait;
#[cfg(all(test, feature = "script-workflows"))]
use iteron_protocol::{Effort, Message};
#[cfg(all(test, feature = "script-workflows"))]
use iteron_provider::{Provider, StreamItem, TurnRequest};
#[cfg(all(test, feature = "script-workflows"))]
use iteron_workflow::events::{PREVIEW_MAX, ProgressEvent, ProgressSink, WorkflowState};
#[cfg(all(test, feature = "script-workflows"))]
use iteron_workflow::{AgentCall, AgentOutcome};
#[cfg(all(test, feature = "script-workflows"))]
use iteron_workflow::{AgentSpawner, RunReport, RunSpec, WorkflowEngine};

mod launch;
mod live;
pub(crate) mod live_session;
mod policy_checkpoint;
mod progress;
mod projection;
mod restart_read;
mod restored_inventory;
mod run_store;
mod summary;
mod supervisor;
mod tunables_checkpoint;

#[cfg(all(test, feature = "script-workflows"))]
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
#[cfg(all(test, feature = "script-workflows"))]
use live::{
    LiveAction, LiveOutcome, live_key_action, live_lines, live_loop, new_run_card, plain_lines,
};
pub use live::{run_live, watch_live};
pub(crate) use policy_checkpoint::{
    load as load_policy_checkpoint, persist as persist_policy_checkpoint,
};
#[cfg(all(test, feature = "script-workflows"))]
use projection::UI_LABEL_MAX;
#[cfg(all(test, feature = "script-workflows"))]
use projection::ui_safe_progress;
pub use projection::{KernelActivityKind, WorkflowRunTerminal, WorkflowRunUiEvent, ui_safe_label};
pub(crate) use tunables_checkpoint::{
    load as load_tunables_checkpoint, persist as persist_tunables_checkpoint,
};

/// The system prompt every workflow sub-agent runs under. Kept terse: a workflow `agent()` call is a
/// bounded, single-shot query, not a full coding session.
#[cfg(all(test, feature = "script-workflows"))]
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
#[cfg(all(test, feature = "script-workflows"))]
pub struct ProviderSpawner {
    provider: Arc<dyn Provider>,
    model: String,
    max_tokens: u32,
    default_effort: Effort,
}

#[cfg(all(test, feature = "script-workflows"))]
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

#[cfg(all(test, feature = "script-workflows"))]
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
            tools: Vec::new().into(),
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

pub use launch::{
    Collected, DetachedRun, InTurnWorkflowLauncher, Launched, PreparedWorkflow, WorkflowLauncher,
    launch_prepared,
};
pub use progress::{DegradedAgentSink, StdoutProgressSink, in_turn_progress_sink};
#[cfg(any(test, feature = "script-workflows"))]
pub use progress::{FanoutProgressSink, UiProgressSink};
#[cfg(all(test, feature = "script-workflows"))]
use progress::{FinishedAgent, PartialWork, PartialWorkSink};
pub(crate) use restored_inventory::{RestoredWorkflowInventory, restored_inventory};
pub use run_store::{
    RunListing, RunManifest, list_runs, load_manifest, load_script, persist_inputs, persist_result,
    valid_run_id,
};
#[cfg(test)]
pub use run_store::{load_result, run_dir};
pub use summary::{final_status_line, run_exit_code, run_result_summary, unreported_run};
#[cfg(all(test, feature = "script-workflows"))]
use summary::{killed_run_summary, run_status};
pub use supervisor::{
    RunSettled, SHUTDOWN_GRACE, ShutdownReport, SupervisedRunInfo, SupervisedRunStatus,
    WorkflowSupervisor,
};

#[cfg(all(test, feature = "script-workflows"))]
use progress::MAX_PARTIAL_RESULT_BYTES;
#[cfg(all(test, feature = "script-workflows"))]
mod tests;

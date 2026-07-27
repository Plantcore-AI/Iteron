//! The sub-agent spawn seam. `core-workflow` never touches `core-kernel`; instead the JS `agent()`
//! primitive drives this trait, which the kernel/CLI implements over a real child `Agent` (or, in
//! the first vertical slice, a single real provider completion). Keeping the edge here — the engine
//! depends on the trait, the executor depends on the engine — is what avoids the dependency cycle
//! (WORKFLOW-REPLICATION-DESIGN.md §2.1).

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// One resolved `agent(prompt, opts)` call, marshaled out of the JS runtime. `agent_type`/`model`/
/// `effort` are the caller's requested overrides; the spawner maps them onto the host's own model
/// and effort ladder (Core's ids, not Claude Code's — see the design's fidelity notes §6).
///
/// The `schema` and `cancel` fields are additive (design §2.5 schema, §B3 cancellation): existing
/// spawners that read `prompt`/`model`/`effort` are unaffected. `schema` is the caller's JSON Schema
/// (draft 2020-12) when `agent(prompt, {schema})` was used — the engine validates the output against
/// it regardless of whether a spawner also honors it. `cancel` is the run's cancellation token,
/// threaded into every call so a cooperating spawner can `select!` on it and stop a paid child;
/// the engine also aborts the in-flight child task on cancel as a backstop.
#[derive(Debug, Clone)]
pub struct AgentCall {
    pub prompt: String,
    pub label: Option<String>,
    pub phase: Option<String>,
    pub model: Option<String>,
    pub effort: Option<core_protocol::Effort>,
    pub agent_type: Option<String>,
    /// The caller's JSON Schema (`agent(prompt, {schema})`), if any.
    pub schema: Option<serde_json::Value>,
    /// The run's cancellation token (trips on `RunHandle::cancel()`).
    pub cancel: CancellationToken,
}

/// The result an `agent()` call resolves to inside JS. `Text` becomes the string value (real model
/// output); `Null` becomes JS `null`, which the scripts' `.filter(Boolean)` idiom drops. The metric
/// fields feed the live progress row (tokens/tool_calls/last_tool_summary in Claude Code's set); a
/// single-completion spawner reports `tool_calls: 0` and no tool summary.
#[derive(Debug, Clone)]
pub enum AgentOutcome {
    Text {
        text: String,
        tokens: u64,
        tool_calls: u64,
        last_tool_summary: Option<String>,
    },
    /// A degraded/terminal-negative outcome. Resolves to JS `null` (never a thrown rejection) so the
    /// surrounding `parallel`/`pipeline` keeps other items flowing.
    Null { reason: Option<String> },
}

impl AgentOutcome {
    /// Convenience: a bare text outcome with no tool metrics (the single-completion path).
    pub fn text(text: impl Into<String>, tokens: u64) -> Self {
        AgentOutcome::Text {
            text: text.into(),
            tokens,
            tool_calls: 0,
            last_tool_summary: None,
        }
    }

    /// Convenience: a null outcome with a human reason for the progress row.
    pub fn null(reason: impl Into<String>) -> Self {
        AgentOutcome::Null {
            reason: Some(reason.into()),
        }
    }
}

/// The seam the kernel/CLI implements. `spawn` runs one genuine sub-agent turn (or child `Agent`)
/// and returns its outcome. It must be cancellation-cheap and `Send` (it is `tokio::spawn`ed onto
/// the shared multi-thread runtime by the engine's `__agent` bridge).
#[async_trait]
pub trait AgentSpawner: Send + Sync {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome;
}

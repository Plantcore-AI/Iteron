//! The sub-agent spawn seam. `core-workflow` never touches `core-kernel`; instead the JS `agent()`
//! primitive drives this trait, which the kernel/CLI implements over a real child `Agent` (or, in
//! the first vertical slice, a single real provider completion). Keeping the edge here — the engine
//! depends on the trait, the executor depends on the engine — is what avoids the dependency cycle
//! (WORKFLOW-REPLICATION-DESIGN.md §2.1).

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

pub const AGENT_SPAWNER_PORT_VERSION: u32 = 1;
/// Request-side agent names use the same documented grammar as executable agent definitions.
pub const MAX_AGENT_TYPE_BYTES: usize = 128;
/// A request-side model override is metadata, not unbounded prompt content.
pub const MAX_AGENT_MODEL_BYTES: usize = 512;

/// A request metadata refusal. Variants intentionally carry no caller-controlled text: their
/// public reason is safe to journal and render without reflecting a model id, agent name, control
/// sequence, or credential-shaped value back to a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRequestMetadataError {
    AgentType,
    Model,
}

impl AgentRequestMetadataError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::AgentType => "invalid_agent_type",
            Self::Model => "invalid_agent_model",
        }
    }

    pub fn public_reason(self) -> &'static str {
        match self {
            Self::AgentType => "agent type must be 1..=128 ASCII bytes from [A-Za-z0-9_.-]",
            Self::Model => "model override must be non-blank, control-free, and at most 512 bytes",
        }
    }
}

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

impl AgentCall {
    /// Validate caller-controlled routing metadata before catalog lookup, provider selection,
    /// rollout creation, or any other child effect. `None` keeps the pinned default.
    pub fn validate_request_metadata(&self) -> Result<(), AgentRequestMetadataError> {
        Self::validate_agent_type(self.agent_type.as_deref())?;
        Self::validate_model(self.model.as_deref())
    }

    /// Validate only an agent type. The internal fan path has an `AgentTask`-shaped
    /// request rather than an `AgentCall`, so it reuses this exact request grammar directly.
    pub fn validate_agent_type(agent_type: Option<&str>) -> Result<(), AgentRequestMetadataError> {
        let Some(agent_type) = agent_type else {
            return Ok(());
        };
        if agent_type.is_empty()
            || agent_type.len() > MAX_AGENT_TYPE_BYTES
            || !agent_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(AgentRequestMetadataError::AgentType);
        }
        Ok(())
    }

    /// Validate only a requested model id before comparing it with definition or route evidence.
    pub fn validate_model(model: Option<&str>) -> Result<(), AgentRequestMetadataError> {
        let Some(model) = model else {
            return Ok(());
        };
        if model.trim().is_empty()
            || model.len() > MAX_AGENT_MODEL_BYTES
            || model.chars().any(char::is_control)
        {
            return Err(AgentRequestMetadataError::Model);
        }
        Ok(())
    }
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
    fn port_version(&self) -> u32 {
        AGENT_SPAWNER_PORT_VERSION
    }

    async fn spawn(&self, call: AgentCall) -> AgentOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(agent_type: Option<String>, model: Option<String>) -> AgentCall {
        AgentCall {
            prompt: "inspect".into(),
            label: None,
            phase: None,
            model,
            effort: None,
            agent_type,
            schema: None,
            cancel: CancellationToken::new(),
        }
    }

    #[test]
    fn request_metadata_uses_the_documented_bounded_ascii_contract() {
        for valid in ["a", "Reviewer", "reviewer.v2", "reviewer_2", "reviewer-2"] {
            call(Some(valid.into()), Some("provider/model-v2".into()))
                .validate_request_metadata()
                .unwrap();
        }

        for invalid in [
            String::new(),
            "a".repeat(MAX_AGENT_TYPE_BYTES + 1),
            "reviewer/child".into(),
            "reviewer\nchild".into(),
            "reviewer界".into(),
        ] {
            assert_eq!(
                call(Some(invalid), None).validate_request_metadata(),
                Err(AgentRequestMetadataError::AgentType)
            );
        }

        for invalid in [
            String::new(),
            " ".into(),
            "m".repeat(MAX_AGENT_MODEL_BYTES + 1),
            "model\nother".into(),
            "model\u{1b}[2J".into(),
        ] {
            assert_eq!(
                call(None, Some(invalid)).validate_request_metadata(),
                Err(AgentRequestMetadataError::Model)
            );
        }
    }

    #[test]
    fn metadata_refusals_are_static_bounded_single_line_and_input_free() {
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let invalid = format!("{secret}/\u{1b}[2J");
        let error = call(Some(invalid), Some(secret.into()))
            .validate_request_metadata()
            .unwrap_err();
        let reason = error.public_reason();
        assert!(reason.len() <= 128);
        assert!(!reason.chars().any(char::is_control));
        assert!(!reason.contains(secret));
    }
}

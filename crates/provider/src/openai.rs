//! OpenAI-compatible provider (Chat Completions, streaming). One implementation reaches a large
//! slice of the ecosystem — OpenAI, DeepSeek, GLM/Zhipu, Together, Fireworks, OpenRouter, local
//! vLLM/Ollama, and Azure/Bedrock/Vertex behind an OpenAI-compatible gateway — by varying the
//! `base_url` and key. This is the provider-breadth production gap (P3) closed behind the same
//! `Provider` trait the kernel already uses.
//!
//! Honest difference from Anthropic (encoded, not hidden): OpenAI streams tool-call arguments as
//! fragments by index but emits no per-tool-call "stop" event, so a tool call is only known
//! complete at `finish_reason:"tool_calls"`. We therefore emit `ToolUseComplete` at the end of
//! the turn, not mid-stream — the flagship overlap is weaker here than on Anthropic (which the
//! design predicted: providers differ in how early a tool_use is identifiable). Correctness is
//! unaffected; the latency win is smaller.

use crate::sse::StreamItem;
use crate::{
    AdapterKind, ApiRoot, EffortApplication, ErrorProfile, Provider, ProviderError, TurnRequest,
    TurnResult, UsageReport,
};
use core_protocol::{
    Block, ProviderState, ReasoningEffort, Role, StopReason, StopReasonCode, ToolUse, Usage,
};
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_SSE_LINE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ASSEMBLED_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOOL_CALLS: usize = 1024;
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ROUTE_SCOPE_BYTES: usize = 256;
const MAX_REASONING_STATE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const OPENAI_CHAT_REASONING_FORMAT: &str = "openai.chat.reasoning-content.v1";

static NEXT_DIRECT_CHAT_SCOPE: AtomicU64 = AtomicU64::new(1);

pub struct OpenAiCompat {
    key: String,
    api_root: Option<ApiRoot>,
    configuration_error: Option<String>,
    error_profile: ErrorProfile,
    route_scope: String,
    static_metadata: std::sync::Arc<crate::StaticProviderMetadata>,
    client: reqwest::Client,
}

impl OpenAiCompat {
    /// Build from a key and a base URL (default OpenAI). The base URL is what selects the
    /// backend. Prefer `try_new` in new code so invalid roots are rejected immediately. This
    /// compatibility constructor remains fail-closed: an invalid root produces no network call
    /// and is returned as `ProviderError::Configuration` from `turn`.
    pub fn new(key: String, base_url: Option<String>) -> Self {
        match Self::try_new(key.clone(), base_url) {
            Ok(provider) => provider,
            Err(error) => OpenAiCompat {
                key,
                api_root: None,
                configuration_error: Some(error.to_string()),
                error_profile: ErrorProfile::CustomConservative,
                route_scope: direct_chat_route_scope(),
                static_metadata: crate::StaticProviderMetadata::embedded(),
                client: reqwest::Client::new(),
            },
        }
    }

    /// Build against an exact API root, including its complete version/path prefix.
    pub fn try_new(key: String, api_root: Option<String>) -> Result<Self, ProviderError> {
        let api_root = ApiRoot::parse(api_root.as_deref().unwrap_or("https://api.openai.com/v1"))?;
        Self::with_root(key, api_root)
    }

    pub fn with_root(key: String, api_root: ApiRoot) -> Result<Self, ProviderError> {
        Self::with_transport(key, api_root, &crate::catalog::DefaultHttpTransport)
    }

    /// Build against an exact API root, obtaining the HTTP client from an injected
    /// network-I/O port rather than constructing it inline. `with_root` delegates
    /// here with the default transport (D2-21).
    pub fn with_transport(
        key: String,
        api_root: ApiRoot,
        transport: &dyn crate::catalog::HttpTransport,
    ) -> Result<Self, ProviderError> {
        Ok(OpenAiCompat {
            key,
            api_root: Some(api_root),
            configuration_error: None,
            error_profile: ErrorProfile::CustomConservative,
            route_scope: direct_chat_route_scope(),
            static_metadata: crate::StaticProviderMetadata::embedded(),
            client: transport.client()?,
        })
    }

    pub(crate) fn with_error_profile(mut self, error_profile: ErrorProfile) -> Self {
        self.error_profile = error_profile;
        self
    }

    pub(crate) fn with_static_metadata(
        mut self,
        static_metadata: std::sync::Arc<crate::StaticProviderMetadata>,
    ) -> Self {
        self.static_metadata = static_metadata;
        self
    }

    /// Bind opaque reasoning continuation data to one provider-directory instance. Direct
    /// constructors already receive a unique process-local scope, while directory providers use
    /// their stable instance id so resume/fork can replay state through the same configured route.
    pub fn with_route_scope(mut self, route_scope: String) -> Result<Self, ProviderError> {
        validate_chat_route_scope(&route_scope)?;
        self.route_scope = route_scope;
        Ok(self)
    }

    fn body(&self, req: &TurnRequest) -> Result<serde_json::Value, ProviderError> {
        let mut messages: Vec<serde_json::Value> =
            vec![serde_json::json!({"role":"system","content":req.system})];
        for m in &req.messages {
            messages.extend(msg_to_openai(m, self.error_profile, &self.route_scope)?);
        }
        let tools: Vec<serde_json::Value> = req
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type":"function",
                    "function":{"name":t.name,"description":t.description,"parameters":t.input_schema}
                })
            })
            .collect();
        let mut b = serde_json::json!({
            "model": req.model,
            "messages": messages,
            "max_tokens": req.max_tokens,
            "stream": true,
            "stream_options": {"include_usage": true},
        });
        if !tools.is_empty() {
            b["tools"] = serde_json::json!(tools);
        }
        if let Some(level) = chat_reasoning_effort_with_metadata(
            self.error_profile,
            self.api_root.as_ref(),
            &self.static_metadata,
            &req.model,
            req.reasoning_effort,
            req.thinking_budget,
        ) {
            b["reasoning_effort"] = serde_json::json!(level.label());
        }
        if supports_thinking_toggle(self.error_profile, &req.model) {
            b["thinking"] = serde_json::json!({
                "type": if req.thinking_budget == 0 { "disabled" } else { "enabled" }
            });
        }
        Ok(b)
    }
}

fn direct_chat_route_scope() -> String {
    let sequence = NEXT_DIRECT_CHAT_SCOPE.fetch_add(1, Ordering::Relaxed);
    format!("direct-openai-chat-{}-{sequence}", std::process::id())
}

fn validate_chat_route_scope(route_scope: &str) -> Result<(), ProviderError> {
    if route_scope.is_empty()
        || route_scope.len() > MAX_ROUTE_SCOPE_BYTES
        || route_scope.chars().any(char::is_control)
    {
        return Err(ProviderError::Configuration(
            "Chat Completions route scope was empty or invalid".into(),
        ));
    }
    Ok(())
}

/// Chat-compatible vendors do not share OpenAI's optional request parameters. Until a provider
/// documents an equivalent field, omit it even when its model performs internal reasoning.
#[cfg(test)]
fn chat_reasoning_effort(
    error_profile: ErrorProfile,
    model_id: &str,
    requested: ReasoningEffort,
    thinking_budget: u32,
) -> Option<ReasoningEffort> {
    chat_reasoning_effort_proven(
        error_profile,
        model_id,
        requested,
        thinking_budget,
        crate::StaticProviderMetadata::embedded()
            .glm_model_capabilities(model_id)
            .is_some_and(|capability| capability.semantic_effort == Some(true)),
    )
}

fn chat_reasoning_effort_with_metadata(
    error_profile: ErrorProfile,
    api_root: Option<&ApiRoot>,
    static_metadata: &crate::StaticProviderMetadata,
    model_id: &str,
    requested: ReasoningEffort,
    thinking_budget: u32,
) -> Option<ReasoningEffort> {
    let glm_semantic_effort = api_root.is_some_and(|root| {
        root.as_str() == static_metadata.glm_api_root()
            && static_metadata
                .glm_model_capabilities(model_id)
                .is_some_and(|capability| capability.semantic_effort == Some(true))
    });
    chat_reasoning_effort_proven(
        error_profile,
        model_id,
        requested,
        thinking_budget,
        glm_semantic_effort,
    )
}

fn chat_reasoning_effort_proven(
    error_profile: ErrorProfile,
    model_id: &str,
    requested: ReasoningEffort,
    thinking_budget: u32,
    glm_semantic_effort: bool,
) -> Option<ReasoningEffort> {
    match error_profile {
        // The portable OpenAI reasoning surface proven by this adapter ends at `high`. Core's
        // stronger XHigh/Max dial values must not be sent as invented wire labels: clamp them and
        // report the same mapped semantic value through `effort_application` below.
        ErrorProfile::OpenAi if is_openai_reasoning_family(model_id) => Some(match requested {
            ReasoningEffort::XHigh | ReasoningEffort::Max => ReasoningEffort::High,
            supported => supported,
        }),
        // GLM-5.2's standard Chat Completions API documents `reasoning_effort`, but exposes a
        // smaller effective control surface than the portable Core dial: low/medium resolve to
        // high and xhigh resolves to max. Normalize before sending so telemetry describes the
        // value that actually reaches inference rather than merely echoing an accepted alias.
        // A zero thinking budget uses the separate `thinking: disabled` control and deliberately
        // omits this field because reasoning_effort is effective only while thinking is enabled.
        ErrorProfile::Glm if glm_semantic_effort => {
            if thinking_budget == 0 {
                None
            } else {
                match requested {
                    ReasoningEffort::Low | ReasoningEffort::Medium | ReasoningEffort::High => {
                        Some(ReasoningEffort::High)
                    }
                    ReasoningEffort::XHigh | ReasoningEffort::Max => Some(ReasoningEffort::Max),
                }
            }
        }
        // DeepSeek's documented OpenAI surface accepts only high/max. Low and medium map to high;
        // xhigh/max map to max. A zero budget disables thinking through the separate toggle.
        ErrorProfile::DeepSeek if is_deepseek_reasoning_family(model_id) => {
            if thinking_budget == 0 {
                None
            } else {
                match requested {
                    ReasoningEffort::Low | ReasoningEffort::Medium | ReasoningEffort::High => {
                        Some(ReasoningEffort::High)
                    }
                    ReasoningEffort::XHigh | ReasoningEffort::Max => Some(ReasoningEffort::Max),
                }
            }
        }
        _ => None,
    }
}

#[cfg(test)]
fn chat_effort_application(
    error_profile: ErrorProfile,
    model_id: &str,
    requested: ReasoningEffort,
    thinking_budget: u32,
) -> EffortApplication {
    if let Some(sent) = chat_reasoning_effort(error_profile, model_id, requested, thinking_budget) {
        return if sent == requested {
            EffortApplication::Exact { requested }
        } else {
            EffortApplication::Mapped { requested, sent }
        };
    }
    if supports_thinking_toggle(error_profile, model_id) {
        return EffortApplication::ToggleOnly {
            requested,
            enabled: thinking_budget > 0,
        };
    }
    EffortApplication::Unsupported { requested }
}

fn chat_effort_application_with_metadata(
    error_profile: ErrorProfile,
    api_root: Option<&ApiRoot>,
    static_metadata: &crate::StaticProviderMetadata,
    model_id: &str,
    requested: ReasoningEffort,
    thinking_budget: u32,
) -> EffortApplication {
    if let Some(sent) = chat_reasoning_effort_with_metadata(
        error_profile,
        api_root,
        static_metadata,
        model_id,
        requested,
        thinking_budget,
    ) {
        return if sent == requested {
            EffortApplication::Exact { requested }
        } else {
            EffortApplication::Mapped { requested, sent }
        };
    }
    if supports_thinking_toggle(error_profile, model_id) {
        return EffortApplication::ToggleOnly {
            requested,
            enabled: thinking_budget > 0,
        };
    }
    EffortApplication::Unsupported { requested }
}

fn is_openai_reasoning_family(model_id: &str) -> bool {
    ["o1", "o3", "o4", "gpt-5", "codex"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family))
}

fn is_deepseek_reasoning_family(model_id: &str) -> bool {
    ["deepseek-v4", "deepseek-chat", "deepseek-reasoner"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family))
}

fn supports_thinking_toggle(error_profile: ErrorProfile, model_id: &str) -> bool {
    match error_profile {
        ErrorProfile::DeepSeek => is_deepseek_reasoning_family(model_id),
        ErrorProfile::Glm => ["glm-4.5", "glm-4.6", "glm-4.7", "glm-5"]
            .into_iter()
            .any(|family| crate::model_matches_family(model_id, family)),
        _ => false,
    }
}

fn preserves_reasoning_content(error_profile: ErrorProfile) -> bool {
    matches!(
        error_profile,
        ErrorProfile::DeepSeek | ErrorProfile::Glm | ErrorProfile::Fireworks
    )
}

/// One core message -> one or more OpenAI messages. Tool results become `role:"tool"` messages;
/// an assistant message with tool_use becomes an assistant message with `tool_calls`.
fn msg_to_openai(
    m: &core_protocol::Message,
    error_profile: ErrorProfile,
    route_scope: &str,
) -> Result<Vec<serde_json::Value>, ProviderError> {
    validate_chat_route_scope(route_scope)?;
    match m.role {
        Role::User => {
            // Split into any tool_result blocks (role:tool) + text (role:user).
            let mut out = Vec::new();
            let mut text = String::new();
            for b in &m.content {
                match b {
                    Block::Text { text: t } => text.push_str(t),
                    Block::ToolResult(r) => out.push(serde_json::json!({
                        "role":"tool","tool_call_id":r.tool_use_id,"content":r.content
                    })),
                    _ => {}
                }
            }
            if !text.is_empty() {
                out.push(serde_json::json!({"role":"user","content":text}));
            }
            if out.is_empty() {
                out.push(serde_json::json!({"role":"user","content":""}));
            }
            Ok(out)
        }
        Role::Assistant => {
            let mut text = String::new();
            let mut tool_calls = Vec::new();
            for b in &m.content {
                match b {
                    Block::Text { text: t } => text.push_str(t),
                    Block::ToolUse(tu) => tool_calls.push(serde_json::json!({
                        "id": tu.id, "type":"function",
                        "function": {"name": tu.name, "arguments": tu.input.to_string()}
                    })),
                    _ => {}
                }
            }
            let mut msg = serde_json::json!({"role":"assistant"});
            msg["content"] = serde_json::json!(if text.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(text)
            });
            if !tool_calls.is_empty() {
                msg["tool_calls"] = serde_json::json!(tool_calls);
            }
            // DeepSeek explicitly requires reasoning_content to be replayed in a tool loop; GLM
            // and Fireworks use the same field. It is provider-private continuation data, not the
            // portable Thinking projection. Only an exact instance scope + format match may be
            // interpreted, preventing transcripts switched between providers from leaking it.
            if !tool_calls.is_empty()
                && preserves_reasoning_content(error_profile)
                && let Some(reasoning) = matching_reasoning_content(m, route_scope)?
            {
                msg["reasoning_content"] = serde_json::json!(reasoning);
            }
            Ok(vec![msg])
        }
    }
}

fn matching_reasoning_content(
    message: &core_protocol::Message,
    route_scope: &str,
) -> Result<Option<String>, ProviderError> {
    let mut matching = None;
    for block in &message.content {
        let Block::ProviderState(state) = block else {
            continue;
        };
        // State owned by another route or another adapter/version is opaque. Do not validate or
        // inspect its payload: this adapter has no authority to interpret it.
        if state.route_scope != route_scope || state.format != OPENAI_CHAT_REASONING_FORMAT {
            continue;
        }
        if matching.is_some() {
            return Err(ProviderError::Decode(
                "assistant message contained duplicate matching Chat reasoning state".into(),
            ));
        }
        let reasoning = reasoning_content_from_payload(&state.payload)?;
        matching = Some(reasoning.to_owned());
    }
    Ok(matching)
}

fn reasoning_content_from_payload(value: &serde_json::Value) -> Result<&str, ProviderError> {
    let payload = value.as_object().ok_or_else(|| {
        ProviderError::Decode("Chat reasoning state payload was not an object".into())
    })?;
    if payload.len() != 1 || !payload.contains_key("reasoning_content") {
        return Err(ProviderError::Decode(
            "Chat reasoning state payload had an invalid schema".into(),
        ));
    }
    let reasoning = payload["reasoning_content"].as_str().ok_or_else(|| {
        ProviderError::Decode("Chat reasoning state content was not a string".into())
    })?;
    if reasoning.is_empty() || reasoning.len() > MAX_REASONING_STATE_PAYLOAD_BYTES {
        return Err(ProviderError::Decode(format!(
            "Chat reasoning state content was empty or exceeded {MAX_REASONING_STATE_PAYLOAD_BYTES} bytes"
        )));
    }
    let encoded = serde_json::to_vec(value).map_err(|_| {
        ProviderError::Decode("Chat reasoning state payload could not be encoded".into())
    })?;
    if encoded.len() > MAX_REASONING_STATE_PAYLOAD_BYTES {
        return Err(ProviderError::Decode(format!(
            "Chat reasoning state content was empty or exceeded {MAX_REASONING_STATE_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(reasoning)
}

fn reasoning_provider_state(
    route_scope: &str,
    reasoning: &str,
) -> Result<ProviderState, ProviderError> {
    validate_chat_route_scope(route_scope)?;
    let payload = serde_json::json!({"reasoning_content": reasoning});
    reasoning_content_from_payload(&payload)?;
    Ok(ProviderState {
        route_scope: route_scope.to_owned(),
        format: OPENAI_CHAT_REASONING_FORMAT.into(),
        payload,
    })
}

/// Accumulator for a streamed tool call (OpenAI streams name once, args as fragments by index).
#[derive(Default, Clone)]
struct ToolAcc {
    id: String,
    name: String,
    args: String,
}

fn assemble_tool_uses(
    tools: Vec<ToolAcc>,
    stop_reason: StopReason,
) -> Result<Vec<ToolUse>, ProviderError> {
    // A length stop can cut JSON at any byte. No OpenAI-compatible per-call completion marker is
    // available, so none of the accumulated calls is safe to dispatch from that response.
    if stop_reason == StopReason::MaxTokens {
        return Ok(Vec::new());
    }
    if tools.is_empty() {
        return if stop_reason == StopReason::ToolUse {
            Err(ProviderError::Decode(
                "tool_calls finish reason contained no tool calls".into(),
            ))
        } else {
            Ok(Vec::new())
        };
    }
    if stop_reason != StopReason::ToolUse {
        return Err(ProviderError::Decode(
            "stream contained tool calls without a tool_calls finish reason".into(),
        ));
    }
    tools
        .into_iter()
        .map(|tool| {
            if tool.id.is_empty() || tool.name.is_empty() {
                return Err(ProviderError::Decode(
                    "tool call completed without an id or function name".into(),
                ));
            }
            let input = if tool.args.trim().is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str(&tool.args).map_err(|error| {
                    // Function names are provider-controlled output. Keep them out of surfaced
                    // diagnostics so a malicious model cannot smuggle arbitrary text through an
                    // otherwise typed decode error.
                    ProviderError::Decode(format!("tool arguments were not valid JSON: {error}"))
                })?
            };
            Ok(ToolUse {
                id: tool.id,
                name: tool.name,
                input,
            })
        })
        .collect()
}

fn decode_finish_reason(value: &str) -> Result<StopReason, ProviderError> {
    match value {
        "stop" => Ok(StopReason::EndTurn),
        "tool_calls" => Ok(StopReason::ToolUse),
        "length" => Ok(StopReason::MaxTokens),
        "stop_sequence" => Ok(StopReason::StopSequence),
        "content_filter" | "refusal" => Ok(StopReason::Refusal),
        "pause_turn" => Ok(StopReason::PauseTurn),
        future => StopReasonCode::parse(future)
            .map(StopReason::Unknown)
            .map_err(|_| ProviderError::Decode("provider finish reason code was invalid".into())),
    }
}

enum OpenAiSseLine {
    Ignore,
    Done,
    Chunk(serde_json::Value),
}

/// Parse one physical line from an OpenAI-compatible SSE stream. Standard SSE metadata and
/// comments are accepted, while malformed `data:` JSON and unknown wire text fail closed.
fn parse_sse_line(
    line: &str,
    error_profile: ErrorProfile,
    response_retry_after: Option<Duration>,
    response_request_id: Option<String>,
) -> Result<OpenAiSseLine, ProviderError> {
    let line = line.trim();
    if line.is_empty()
        || line.starts_with(':')
        || line.starts_with("event:")
        || line.starts_with("id:")
        || line.starts_with("retry:")
    {
        return Ok(OpenAiSseLine::Ignore);
    }
    let Some(data) = line.strip_prefix("data:") else {
        return Err(ProviderError::Decode(format!(
            "malformed OpenAI SSE line (expected data field, got {} bytes)",
            line.len()
        )));
    };
    let data = data.trim();
    if data == "[DONE]" {
        return Ok(OpenAiSseLine::Done);
    }
    if data.is_empty() {
        return Err(ProviderError::Decode(
            "empty OpenAI SSE data field".to_string(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(data)
        .map_err(|error| ProviderError::Decode(format!("malformed OpenAI SSE JSON: {error}")))?;
    if let Some(error) = crate::minimax_base_response_failure_for(
        AdapterKind::OpenAiCompatibleChat,
        error_profile,
        error_profile.label(),
        data,
        &value,
        response_retry_after,
        response_request_id.clone(),
    )? {
        return Err(ProviderError::Stream(error));
    }
    if value.get("error").is_some()
        || value.get("type").and_then(|value| value.as_str()) == Some("error")
    {
        return Err(ProviderError::Stream(crate::decode_stream_error_for(
            AdapterKind::OpenAiCompatibleChat,
            error_profile,
            error_profile.label(),
            data,
            response_retry_after,
            response_request_id,
        )));
    }
    Ok(OpenAiSseLine::Chunk(value))
}

fn validate_stream_end(
    byte_buf: &[u8],
    text_buf: &str,
    saw_terminal: bool,
) -> Result<(), ProviderError> {
    if !byte_buf.is_empty() {
        return Err(ProviderError::Decode(
            "OpenAI stream ended with an incomplete UTF-8 code point".to_string(),
        ));
    }
    if !text_buf.trim().is_empty() {
        return Err(ProviderError::Decode(
            "OpenAI stream ended with an incomplete SSE event".to_string(),
        ));
    }
    if !saw_terminal {
        return Err(ProviderError::Decode(
            "OpenAI stream ended before [DONE] or finish_reason".to_string(),
        ));
    }
    Ok(())
}

/// The spellings an OpenAI-compatible vendor uses for "prompt tokens written into the cache".
///
/// Both are nested under `prompt_tokens_details` and both are a subset of `prompt_tokens`, exactly
/// like `cached_tokens` — so they are subtracted from the uncached input the same way. A vendor
/// that uses neither reports nothing about cache writes, which is a different fact from reporting
/// zero of them (I-52).
const CACHE_CREATION_DETAIL_KEYS: [&str; 2] = ["cache_creation_tokens", "cache_write_tokens"];

/// What one streamed chunk said about usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportedUsage {
    /// The chunk carried no usage object at all.
    Absent,
    /// The chunk carried a usage report. `cache_creation` says whether that report named a
    /// cache-creation count; when it did not, `Usage::cache_creation` is a default, not a
    /// measurement, and must not be priced as a measured zero.
    Present { cache_creation: bool },
}

impl ReportedUsage {
    const fn present(self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

fn apply_reported_usage(
    chunk: &serde_json::Value,
    usage: &mut Usage,
) -> Result<ReportedUsage, ProviderError> {
    let Some(raw) = chunk.get("usage") else {
        return Ok(ReportedUsage::Absent);
    };
    if raw.is_null() {
        return Ok(ReportedUsage::Absent);
    }
    let object = raw.as_object().ok_or_else(|| {
        ProviderError::Decode("OpenAI-compatible usage field was not an object".into())
    })?;
    let required_token = |key: &str| -> Result<u64, ProviderError> {
        object
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ProviderError::Decode(
                    "OpenAI-compatible usage omitted a required integer token count".into(),
                )
            })
    };
    let total_input = required_token("prompt_tokens")?;
    usage.output = required_token("completion_tokens")?;
    let mut cache_creation_reported = false;
    if let Some(details) = object
        .get("prompt_tokens_details")
        .filter(|value| !value.is_null())
    {
        let details = details.as_object().ok_or_else(|| {
            ProviderError::Decode(
                "OpenAI-compatible prompt token details were not an object".into(),
            )
        })?;
        if let Some(cached) = details
            .get("cached_tokens")
            .filter(|value| !value.is_null())
        {
            usage.cache_read = cached.as_u64().ok_or_else(|| {
                ProviderError::Decode(
                    "OpenAI-compatible usage contained a non-integer token count".into(),
                )
            })?;
        }
        if let Some(written) = CACHE_CREATION_DETAIL_KEYS
            .into_iter()
            .find_map(|key| details.get(key).filter(|value| !value.is_null()))
        {
            usage.cache_creation = written.as_u64().ok_or_else(|| {
                ProviderError::Decode(
                    "OpenAI-compatible usage contained a non-integer token count".into(),
                )
            })?;
            cache_creation_reported = true;
        }
    }
    let cached_prompt = usage
        .cache_read
        .checked_add(usage.cache_creation)
        .ok_or_else(|| {
            ProviderError::Decode(
                "OpenAI-compatible cached token counts overflowed the prompt total".into(),
            )
        })?;
    usage.input = total_input.checked_sub(cached_prompt).ok_or_else(|| {
        ProviderError::Decode(
            "OpenAI-compatible cached token count exceeded total prompt tokens".into(),
        )
    })?;
    if let Some(details) = object
        .get("completion_tokens_details")
        .filter(|value| !value.is_null())
    {
        let details = details.as_object().ok_or_else(|| {
            ProviderError::Decode(
                "OpenAI-compatible completion token details were not an object".into(),
            )
        })?;
        if let Some(reasoning) = details
            .get("reasoning_tokens")
            .filter(|value| !value.is_null())
        {
            usage.thinking = reasoning.as_u64().ok_or_else(|| {
                ProviderError::Decode(
                    "OpenAI-compatible usage contained a non-integer token count".into(),
                )
            })?;
        }
    }
    Ok(ReportedUsage::Present {
        cache_creation: cache_creation_reported,
    })
}

#[async_trait::async_trait]
impl Provider for OpenAiCompat {
    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        chat_effort_application_with_metadata(
            self.error_profile,
            self.api_root.as_ref(),
            &self.static_metadata,
            &req.model,
            req.reasoning_effort,
            req.thinking_budget,
        )
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let api_root = self.api_root.as_ref().ok_or_else(|| {
            ProviderError::Configuration(
                self.configuration_error
                    .clone()
                    .unwrap_or_else(|| "invalid API root".into()),
            )
        })?;
        let deadline = Instant::now() + STREAM_TOTAL_TIMEOUT;
        let body = self.body(req)?;
        let request = self
            .client
            .post(api_root.endpoint("chat/completions")?)
            .bearer_auth(&self.key)
            .json(&body);
        let resp = tokio::time::timeout(RESPONSE_HEADER_TIMEOUT, request.send())
            .await
            .map_err(|_| {
                ProviderError::Http("OpenAI-compatible response headers timed out".into())
            })?
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let status = resp.status();
        let response_retry_after = crate::retry_after_from_headers(resp.headers());
        let response_request_id = crate::request_id_from_headers(resp.headers());
        if !status.is_success() {
            let error = tokio::time::timeout(
                RESPONSE_HEADER_TIMEOUT,
                crate::api_error_from_response(
                    resp,
                    AdapterKind::OpenAiCompatibleChat,
                    self.error_profile,
                ),
            )
            .await
            .map_err(|_| ProviderError::Http("OpenAI-compatible error body timed out".into()))?;
            return Err(error);
        }

        // Quota state is on the success headers, so it is knowable here — before a single token
        // has arrived and long before the 429 that used to be its first symptom (I-53).
        if let Some(snapshot) = crate::rate_limit_from_headers(resp.headers()) {
            on_item(StreamItem::RateLimit(snapshot));
        }

        let mut stream = resp.bytes_stream();
        // Buffer RAW bytes and decode only the complete-UTF-8 prefix: a char split across chunks
        // would be corrupted by per-chunk lossy decode (code review OAI-1, the anthropic F2 bug).
        let mut byte_buf: Vec<u8> = Vec::new();
        let mut buf = String::new();
        let mut text = String::new();
        let mut thinking = String::new();
        let mut tools: Vec<ToolAcc> = Vec::new();
        let mut usage = Usage::default();
        let mut saw_usage = false;
        let mut saw_cache_creation = false;
        let mut stop: Option<StopReason> = None;
        let mut saw_done = false;
        let mut total_stream_bytes = 0usize;
        let mut assembled_output_bytes = 0usize;

        'stream: loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProviderError::Http(
                    "OpenAI-compatible stream exceeded total deadline".into(),
                ));
            }
            let wait = remaining.min(STREAM_IDLE_TIMEOUT);
            let next = tokio::time::timeout(wait, stream.next())
                .await
                .map_err(|_| {
                    if wait == remaining {
                        ProviderError::Http(
                            "OpenAI-compatible stream exceeded total deadline".into(),
                        )
                    } else {
                        ProviderError::Http("stream stalled: no bytes for 120s".into())
                    }
                })?;
            let Some(chunk) = next else { break };
            let bytes = chunk.map_err(|e| ProviderError::Http(e.to_string()))?;
            total_stream_bytes = total_stream_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| ProviderError::Decode("stream byte counter overflow".into()))?;
            if total_stream_bytes > MAX_STREAM_BYTES {
                return Err(ProviderError::Decode(format!(
                    "OpenAI-compatible stream exceeded {MAX_STREAM_BYTES} bytes"
                )));
            }
            byte_buf.extend_from_slice(&bytes);
            let valid = match std::str::from_utf8(&byte_buf) {
                Ok(s) => {
                    buf.push_str(s);
                    byte_buf.len()
                }
                Err(e) => {
                    if e.error_len().is_some() {
                        return Err(ProviderError::Decode(
                            "OpenAI-compatible stream contained invalid UTF-8".into(),
                        ));
                    }
                    let up = e.valid_up_to();
                    buf.push_str(std::str::from_utf8(&byte_buf[..up]).unwrap());
                    up
                }
            };
            byte_buf.drain(..valid);
            while let Some(nl) = buf.find('\n') {
                if nl > MAX_SSE_LINE_BYTES {
                    return Err(ProviderError::Decode(format!(
                        "OpenAI-compatible SSE line exceeded {MAX_SSE_LINE_BYTES} bytes"
                    )));
                }
                let line = buf[..nl].to_string();
                buf.drain(..=nl);
                let parsed = parse_sse_line(
                    &line,
                    self.error_profile,
                    response_retry_after,
                    response_request_id.clone(),
                )?;
                if saw_done {
                    if matches!(parsed, OpenAiSseLine::Ignore) {
                        continue;
                    }
                    return Err(ProviderError::Decode(
                        "OpenAI-compatible stream emitted data after [DONE]".into(),
                    ));
                }
                let v = match parsed {
                    OpenAiSseLine::Ignore => continue,
                    OpenAiSseLine::Done => {
                        if stop.is_none() {
                            return Err(ProviderError::Decode(
                                "OpenAI-compatible stream reached [DONE] before finish_reason"
                                    .into(),
                            ));
                        }
                        saw_done = true;
                        continue;
                    }
                    OpenAiSseLine::Chunk(value) => value,
                };
                let reported_usage = apply_reported_usage(&v, &mut usage)?;
                if reported_usage.present() && saw_usage {
                    return Err(ProviderError::Decode(
                        "OpenAI-compatible stream emitted more than one usage report".into(),
                    ));
                }
                saw_usage |= reported_usage.present();
                saw_cache_creation |= matches!(
                    reported_usage,
                    ReportedUsage::Present {
                        cache_creation: true
                    }
                );
                let choice = match v.pointer("/choices/0") {
                    Some(c) => c,
                    None if stop.is_some()
                        && v.get("usage").is_none_or(|usage| usage.is_null()) =>
                    {
                        return Err(ProviderError::Decode(
                            "OpenAI-compatible stream emitted a non-usage chunk after finish_reason"
                                .into(),
                        ));
                    }
                    None => continue,
                };
                if stop.is_some() {
                    return Err(ProviderError::Decode(
                        "OpenAI-compatible stream emitted a choice after finish_reason".into(),
                    ));
                }
                let frame_stop = choice
                    .get("finish_reason")
                    .and_then(|value| value.as_str())
                    .map(decode_finish_reason)
                    .transpose()?;
                let delta = choice.get("delta");
                if let Some(reasoning) = delta
                    .and_then(|d| d.get("reasoning_content"))
                    .and_then(|value| value.as_str())
                {
                    assembled_output_bytes = assembled_output_bytes
                        .checked_add(reasoning.len())
                        .ok_or_else(|| {
                            ProviderError::Decode("assembled output byte counter overflow".into())
                        })?;
                    if assembled_output_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
                        return Err(ProviderError::Decode(format!(
                            "OpenAI-compatible output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
                        )));
                    }
                    thinking.push_str(reasoning);
                    on_item(StreamItem::ThinkingDelta(reasoning.to_string()));
                }
                if let Some(t) = delta
                    .and_then(|d| d.get("content"))
                    .and_then(|x| x.as_str())
                {
                    assembled_output_bytes =
                        assembled_output_bytes.checked_add(t.len()).ok_or_else(|| {
                            ProviderError::Decode("assembled output byte counter overflow".into())
                        })?;
                    if assembled_output_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
                        return Err(ProviderError::Decode(format!(
                            "OpenAI-compatible output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
                        )));
                    }
                    text.push_str(t);
                    on_item(StreamItem::TextDelta(t.to_string()));
                }
                if let Some(tcs) = delta
                    .and_then(|d| d.get("tool_calls"))
                    .and_then(|x| x.as_array())
                {
                    for tc in tcs {
                        let raw_index = tc.get("index").and_then(|x| x.as_u64()).unwrap_or(0);
                        let idx = usize::try_from(raw_index).map_err(|_| {
                            ProviderError::Decode("tool call index exceeded platform bounds".into())
                        })?;
                        if idx >= MAX_TOOL_CALLS {
                            return Err(ProviderError::Decode(format!(
                                "OpenAI-compatible output exceeded {MAX_TOOL_CALLS} tool calls"
                            )));
                        }
                        while tools.len() <= idx {
                            tools.push(ToolAcc::default());
                        }
                        if let Some(id) = tc.get("id").and_then(|x| x.as_str()) {
                            assembled_output_bytes = assembled_output_bytes
                                .checked_add(id.len())
                                .ok_or_else(|| {
                                ProviderError::Decode(
                                    "assembled output byte counter overflow".into(),
                                )
                            })?;
                            tools[idx].id = id.to_string();
                        }
                        if let Some(f) = tc.get("function") {
                            if let Some(n) = f.get("name").and_then(|x| x.as_str()) {
                                assembled_output_bytes = assembled_output_bytes
                                    .checked_add(n.len())
                                    .ok_or_else(|| {
                                        ProviderError::Decode(
                                            "assembled output byte counter overflow".into(),
                                        )
                                    })?;
                                tools[idx].name.push_str(n);
                            }
                            if let Some(a) = f.get("arguments").and_then(|x| x.as_str()) {
                                assembled_output_bytes = assembled_output_bytes
                                    .checked_add(a.len())
                                    .ok_or_else(|| {
                                        ProviderError::Decode(
                                            "assembled output byte counter overflow".into(),
                                        )
                                    })?;
                                tools[idx].args.push_str(a);
                            }
                        }
                        if assembled_output_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
                            return Err(ProviderError::Decode(format!(
                                "OpenAI-compatible output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
                            )));
                        }
                    }
                }
                if let Some(frame_stop) = frame_stop {
                    stop = Some(frame_stop);
                }
            }
            if buf.len() > MAX_SSE_LINE_BYTES {
                return Err(ProviderError::Decode(format!(
                    "OpenAI-compatible SSE line exceeded {MAX_SSE_LINE_BYTES} bytes"
                )));
            }
            if saw_done {
                // [DONE] is authoritative. Return without waiting for a peer that keeps the HTTP
                // connection alive, but reject any partial/trailing event already received in the
                // same network chunk.
                validate_stream_end(&byte_buf, &buf, stop.is_some())?;
                break 'stream;
            }
        }

        validate_stream_end(&byte_buf, &buf, stop.is_some())?;
        let stop = stop.ok_or_else(|| {
            ProviderError::Decode("OpenAI-compatible stream ended before finish_reason".into())
        })?;
        let usage = match (saw_usage, saw_cache_creation) {
            (true, true) => UsageReport::complete(usage),
            // The route answered with usage but said nothing about cache writes. Reporting this as
            // a complete report would hand pricing a default `cache_creation: 0` to multiply by a
            // cache-write rate and call free (I-52).
            (true, false) => UsageReport::cache_creation_unreported(usage),
            (false, _) => UsageReport::provider_omitted(),
        };

        // Assemble. Tool calls are known complete only now (no per-call stop event), so we emit
        // ToolUseComplete here — before the turn's TurnResult is used, still enabling next-turn
        // dispatch, just not mid-stream overlap.
        let tool_uses = assemble_tool_uses(tools, stop)?;
        let mut blocks: Vec<Block> = Vec::new();
        if !thinking.is_empty() {
            if preserves_reasoning_content(self.error_profile) && !tool_uses.is_empty() {
                blocks.push(Block::ProviderState(reasoning_provider_state(
                    &self.route_scope,
                    &thinking,
                )?));
            }
            blocks.push(Block::Thinking { thinking });
        }
        if !text.is_empty() {
            blocks.push(Block::Text { text });
        }
        for tu in tool_uses {
            blocks.push(Block::ToolUse(tu.clone()));
            on_item(StreamItem::ToolUseComplete(tu));
        }
        let result = TurnResult {
            blocks,
            stop_reason: stop,
            usage,
        };
        on_item(StreamItem::TurnComplete {
            blocks: result.blocks.clone(),
            stop_reason: result.stop_reason,
            usage: result.usage,
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::Message;

    const TEST_SCOPE: &str = "test-openai-chat";

    #[test]
    fn assistant_tool_use_maps_to_openai_tool_calls() {
        let m = Message {
            role: Role::Assistant,
            content: vec![Block::ToolUse(ToolUse {
                id: "c1".into(),
                name: "read_file".into(),
                input: serde_json::json!({"path":"a.rs"}),
            })],
        };
        let out = msg_to_openai(&m, ErrorProfile::OpenAi, TEST_SCOPE).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["tool_calls"][0]["function"]["name"], "read_file");
        assert_eq!(out[0]["tool_calls"][0]["id"], "c1");
    }

    #[test]
    fn tool_result_maps_to_role_tool() {
        let m = Message {
            role: Role::User,
            content: vec![Block::ToolResult(core_protocol::ToolResult {
                tool_use_id: "c1".into(),
                content: "fn main(){}".into(),
                is_error: false,
                trust: core_protocol::Trust::Workspace,
                latency_ms: 0,
            })],
        };
        let out = msg_to_openai(&m, ErrorProfile::OpenAi, TEST_SCOPE).unwrap();
        assert_eq!(out[0]["role"], "tool");
        assert_eq!(out[0]["tool_call_id"], "c1");
    }

    #[test]
    fn reasoning_content_requires_matching_route_state_and_documented_profile() {
        let state = reasoning_provider_state(TEST_SCOPE, "private provider reasoning").unwrap();
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(state),
                Block::Thinking {
                    thinking: "portable UI projection".into(),
                },
                Block::ToolUse(ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":"a.rs"}),
                }),
            ],
        };
        for profile in [
            ErrorProfile::DeepSeek,
            ErrorProfile::Glm,
            ErrorProfile::Fireworks,
        ] {
            let mapped = msg_to_openai(&message, profile, TEST_SCOPE).unwrap();
            assert_eq!(mapped[0]["reasoning_content"], "private provider reasoning");
        }
        for profile in [
            ErrorProfile::OpenAi,
            ErrorProfile::MiniMax,
            ErrorProfile::CustomConservative,
        ] {
            let mapped = msg_to_openai(&message, profile, TEST_SCOPE).unwrap();
            assert!(mapped[0].get("reasoning_content").is_none());
        }

        let cross_route =
            msg_to_openai(&message, ErrorProfile::DeepSeek, "other-instance").unwrap();
        assert!(cross_route[0].get("reasoning_content").is_none());
    }

    #[test]
    fn portable_thinking_is_never_reinterpreted_as_private_reasoning() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::Thinking {
                    thinking: "must remain local to the UI projection".into(),
                },
                Block::ToolUse(ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":"a.rs"}),
                }),
            ],
        };
        for profile in [
            ErrorProfile::DeepSeek,
            ErrorProfile::Glm,
            ErrorProfile::Fireworks,
        ] {
            let mapped = msg_to_openai(&message, profile, TEST_SCOPE).unwrap();
            assert!(mapped[0].get("reasoning_content").is_none());
        }
    }

    #[test]
    fn matching_reasoning_state_is_bounded_and_strict_but_cross_route_is_opaque() {
        let malformed = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(ProviderState {
                    route_scope: TEST_SCOPE.into(),
                    format: OPENAI_CHAT_REASONING_FORMAT.into(),
                    payload: serde_json::json!({
                        "reasoning_content":"secret",
                        "unexpected":true
                    }),
                }),
                Block::ToolUse(ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({}),
                }),
            ],
        };
        assert!(msg_to_openai(&malformed, ErrorProfile::DeepSeek, TEST_SCOPE).is_err());
        let portable = msg_to_openai(&malformed, ErrorProfile::DeepSeek, "other-instance").unwrap();
        assert!(portable[0].get("reasoning_content").is_none());

        let oversized = "x".repeat(MAX_REASONING_STATE_PAYLOAD_BYTES + 1);
        let oversized = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(ProviderState {
                    route_scope: TEST_SCOPE.into(),
                    format: OPENAI_CHAT_REASONING_FORMAT.into(),
                    payload: serde_json::json!({"reasoning_content":oversized}),
                }),
                Block::ToolUse(ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({}),
                }),
            ],
        };
        assert!(msg_to_openai(&oversized, ErrorProfile::DeepSeek, TEST_SCOPE).is_err());
    }

    #[test]
    fn chat_reasoning_state_debug_redacts_payload_and_direct_scopes_are_unique() {
        let state = reasoning_provider_state(TEST_SCOPE, "never print this secret").unwrap();
        let debug = format!("{state:?}");
        assert!(!debug.contains("never print this secret"));
        assert!(debug.contains("[OPAQUE]"));

        let first = OpenAiCompat::with_root(
            "key".into(),
            ApiRoot::parse("https://api.deepseek.com/v1").unwrap(),
        )
        .unwrap();
        let second = OpenAiCompat::with_root(
            "key".into(),
            ApiRoot::parse("https://api.deepseek.com/v1").unwrap(),
        )
        .unwrap();
        assert_ne!(first.route_scope, second.route_scope);
        assert!(
            first
                .with_route_scope("x".repeat(MAX_ROUTE_SCOPE_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn omitted_usage_is_distinct_from_an_explicit_zero_report() {
        let mut usage = Usage {
            input: 9,
            output: 8,
            cache_creation: 0,
            cache_read: 7,
            thinking: 6,
        };
        assert_eq!(
            apply_reported_usage(&serde_json::json!({}), &mut usage).unwrap(),
            ReportedUsage::Absent
        );
        assert_eq!(
            apply_reported_usage(&serde_json::json!({"usage":null}), &mut usage).unwrap(),
            ReportedUsage::Absent
        );
        assert!(apply_reported_usage(&serde_json::json!({"usage":{}}), &mut usage).is_err());
        assert_eq!(UsageReport::provider_omitted().complete_usage(), None);
        assert!(
            apply_reported_usage(
                &serde_json::json!({
                    "usage": {
                        "prompt_tokens":0,
                        "completion_tokens":0,
                        "prompt_tokens_details":{"cached_tokens":0},
                        "completion_tokens_details":{"reasoning_tokens":0}
                    }
                }),
                &mut usage,
            )
            .unwrap()
            .present()
        );
        assert_eq!(usage, Usage::default());
        assert_eq!(
            UsageReport::complete(usage).complete_usage(),
            Some(Usage::default())
        );
        assert!(apply_reported_usage(&serde_json::json!({"usage":0}), &mut usage).is_err());
        assert!(
            apply_reported_usage(
                &serde_json::json!({
                    "usage": {
                        "prompt_tokens": 2,
                        "completion_tokens": 1,
                        "prompt_tokens_details":{"cached_tokens":3}
                    }
                }),
                &mut usage,
            )
            .is_err()
        );
    }

    /// I-52: the mapper assigned output, cache read and input and left cache creation at its
    /// struct default, so every OpenAI-compatible route reported a measured zero it never
    /// measured. A route that names the count must be priced; a route that stays silent must be
    /// reported as unreported, not as free.
    #[test]
    fn cache_creation_is_read_where_a_vendor_reports_it_and_named_unreported_where_it_does_not() {
        for key in CACHE_CREATION_DETAIL_KEYS {
            let mut usage = Usage::default();
            assert_eq!(
                apply_reported_usage(
                    &serde_json::json!({
                        "usage": {
                            "prompt_tokens": 100,
                            "completion_tokens": 5,
                            "prompt_tokens_details": {"cached_tokens": 60, key: 30}
                        }
                    }),
                    &mut usage,
                )
                .unwrap(),
                ReportedUsage::Present {
                    cache_creation: true
                },
                "{key} is a cache-creation count and must be read"
            );
            assert_eq!(usage.cache_creation, 30);
            assert_eq!(usage.cache_read, 60);
            assert_eq!(
                usage.input, 10,
                "written prompt tokens are a subset of prompt_tokens, exactly like cached ones"
            );
        }

        let mut usage = Usage::default();
        assert_eq!(
            apply_reported_usage(
                &serde_json::json!({
                    "usage": {
                        "prompt_tokens": 100,
                        "completion_tokens": 5,
                        "prompt_tokens_details": {"cached_tokens": 60}
                    }
                }),
                &mut usage,
            )
            .unwrap(),
            ReportedUsage::Present {
                cache_creation: false
            },
            "silence about cache writes must not be reported as a measured zero"
        );
        assert_eq!(usage.cache_creation, 0);
        assert_eq!(usage.input, 40);
        assert!(!UsageReport::cache_creation_unreported(usage).cache_creation_reported());

        // A vendor whose cache classes exceed its own prompt total is a decode failure, not a
        // silently negative input count.
        assert!(
            apply_reported_usage(
                &serde_json::json!({
                    "usage": {
                        "prompt_tokens": 50,
                        "completion_tokens": 1,
                        "prompt_tokens_details": {"cached_tokens": 40, "cache_creation_tokens": 20}
                    }
                }),
                &mut Usage::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn top_level_error_chunk_is_a_structured_stream_failure() {
        let result = parse_sse_line(
            r#"data: {"error":{"message":"slow down","type":"rate_limit_error","retry_after":2}}"#,
            ErrorProfile::OpenAi,
            None,
            None,
        );
        let Err(ProviderError::Stream(error)) = result else {
            panic!("expected structured stream error");
        };
        assert_eq!(error.code.as_deref(), Some("rate_limit_error"));
        assert_eq!(error.status, Some(429));
        assert_eq!(error.retry_after, Some(Duration::from_secs(2)));
    }

    #[test]
    fn minimax_http_200_business_envelope_is_a_typed_stream_failure() {
        let result = parse_sse_line(
            r#"data: {"base_resp":{"status_code":1008,"status_msg":"insufficient balance"},"choices":[]}"#,
            ErrorProfile::MiniMax,
            None,
            Some("req-minimax".into()),
        );
        let Err(ProviderError::Stream(error)) = result else {
            panic!("expected MiniMax business failure");
        };
        assert_eq!(error.provider, "minimax");
        assert_eq!(error.code.as_deref(), Some("1008"));
        assert_eq!(error.message, "insufficient balance");
        assert_eq!(error.normalized.scope, crate::ErrorScope::Account);
        assert_eq!(error.normalized.retry, crate::RetryDisposition::Never);
        assert_eq!(
            error.normalized.availability,
            crate::AvailabilityTransition::Account(crate::AccountAvailability::BillingBlocked),
        );
        assert_eq!(error.normalized.request_id.as_deref(), Some("req-minimax"));
    }

    #[test]
    fn minimax_zero_business_code_remains_a_success_chunk() {
        let line = parse_sse_line(
            r#"data: {"base_resp":{"status_code":0,"status_msg":"success"},"choices":[]}"#,
            ErrorProfile::MiniMax,
            None,
            None,
        )
        .unwrap();
        assert!(matches!(line, OpenAiSseLine::Chunk(_)));
    }

    #[test]
    fn malformed_sse_json_and_unknown_wire_lines_fail_closed() {
        assert!(matches!(
            parse_sse_line(
                "data: {not-json",
                ErrorProfile::CustomConservative,
                None,
                None,
            ),
            Err(ProviderError::Decode(_))
        ));
        assert!(matches!(
            parse_sse_line(
                "definitely-not-sse",
                ErrorProfile::CustomConservative,
                None,
                None,
            ),
            Err(ProviderError::Decode(_))
        ));
    }

    #[test]
    fn standard_sse_metadata_and_done_are_accepted() {
        assert!(matches!(
            parse_sse_line(": ping", ErrorProfile::OpenAi, None, None).unwrap(),
            OpenAiSseLine::Ignore
        ));
        assert!(matches!(
            parse_sse_line("event: message", ErrorProfile::OpenAi, None, None).unwrap(),
            OpenAiSseLine::Ignore
        ));
        assert!(matches!(
            parse_sse_line("data: [DONE]", ErrorProfile::OpenAi, None, None).unwrap(),
            OpenAiSseLine::Done
        ));
    }

    #[test]
    fn truncated_or_unterminated_stream_is_rejected() {
        assert!(validate_stream_end(&[0xf0], "", true).is_err());
        assert!(validate_stream_end(&[], "data: {}", true).is_err());
        assert!(validate_stream_end(&[], "", false).is_err());
        assert!(validate_stream_end(&[], "", true).is_ok());
    }

    #[test]
    fn max_tokens_discards_partial_tool_calls_without_fabricating_json() {
        let partial = ToolAcc {
            id: "call_1".into(),
            name: "edit".into(),
            args: "{\"path\":\"a.rs\",\"old".into(),
        };
        assert!(
            assemble_tool_uses(vec![partial.clone()], StopReason::MaxTokens)
                .unwrap()
                .is_empty()
        );
        assert!(assemble_tool_uses(vec![partial], StopReason::ToolUse).is_err());
    }

    #[test]
    fn completed_tool_calls_require_identity() {
        let missing_id = ToolAcc {
            name: "read_file".into(),
            args: "{}".into(),
            ..ToolAcc::default()
        };
        assert!(assemble_tool_uses(vec![missing_id], StopReason::ToolUse).is_err());
    }

    #[test]
    fn finish_reason_and_tool_call_state_must_agree() {
        assert!(assemble_tool_uses(Vec::new(), StopReason::ToolUse).is_err());
        assert!(
            assemble_tool_uses(
                vec![ToolAcc {
                    id: "call_1".into(),
                    name: "read_file".into(),
                    args: "{}".into(),
                }],
                StopReason::EndTurn,
            )
            .is_err()
        );
        assert_eq!(decode_finish_reason("stop").unwrap(), StopReason::EndTurn);
        assert_eq!(
            decode_finish_reason("stop_sequence").unwrap(),
            StopReason::StopSequence
        );
        assert_eq!(
            decode_finish_reason("content_filter").unwrap(),
            StopReason::Refusal
        );
        assert_eq!(
            decode_finish_reason("pause_turn").unwrap(),
            StopReason::PauseTurn
        );
        let StopReason::Unknown(raw) = decode_finish_reason("future_reason").unwrap() else {
            panic!("future reason must remain typed and observable");
        };
        assert_eq!(raw.as_str(), "future_reason");
        assert!(decode_finish_reason(&"x".repeat(129)).is_err());
    }

    #[test]
    fn reasoning_effort_requires_a_documented_profile_and_family() {
        for profile in [
            ErrorProfile::Glm,
            ErrorProfile::MiniMax,
            ErrorProfile::Fireworks,
            ErrorProfile::CustomConservative,
        ] {
            assert_eq!(
                chat_reasoning_effort(profile, "gpt-5", ReasoningEffort::Medium, 9_000),
                None
            );
            assert_eq!(
                chat_reasoning_effort(profile, "deepseek-reasoner", ReasoningEffort::Medium, 9_000),
                None
            );
        }

        assert_eq!(
            chat_reasoning_effort(
                ErrorProfile::DeepSeek,
                "deepseek-v4-pro",
                ReasoningEffort::Medium,
                9_000
            ),
            Some(ReasoningEffort::High)
        );
        assert_eq!(
            chat_reasoning_effort(
                ErrorProfile::DeepSeek,
                "deepseek-v4-flash",
                ReasoningEffort::XHigh,
                16_384
            ),
            Some(ReasoningEffort::Max)
        );
        assert_eq!(
            chat_reasoning_effort(
                ErrorProfile::DeepSeek,
                "deepseek-v4-pro",
                ReasoningEffort::Low,
                0
            ),
            None
        );
        assert_eq!(
            chat_reasoning_effort(
                ErrorProfile::DeepSeek,
                "gpt-5",
                ReasoningEffort::Medium,
                9_000
            ),
            None
        );
        assert_eq!(
            chat_reasoning_effort(ErrorProfile::Glm, "glm-5.2", ReasoningEffort::Medium, 4_096),
            Some(ReasoningEffort::High)
        );
        assert_eq!(
            chat_reasoning_effort(ErrorProfile::Glm, "glm-5.2", ReasoningEffort::XHigh, 16_384),
            Some(ReasoningEffort::Max)
        );
        assert_eq!(
            chat_reasoning_effort(ErrorProfile::Glm, "glm-5.2", ReasoningEffort::Low, 0),
            None
        );
        assert_eq!(
            chat_reasoning_effort(ErrorProfile::Glm, "glm-5.1", ReasoningEffort::Medium, 4_096),
            None,
            "nearby GLM models must not inherit GLM-5.2's documented enum"
        );
        assert_eq!(
            chat_effort_application(ErrorProfile::Glm, "glm-5.2", ReasoningEffort::Medium, 4_096),
            EffortApplication::Mapped {
                requested: ReasoningEffort::Medium,
                sent: ReasoningEffort::High,
            }
        );
        assert_eq!(
            chat_effort_application(ErrorProfile::Glm, "glm-5.2", ReasoningEffort::Low, 0),
            EffortApplication::ToggleOnly {
                requested: ReasoningEffort::Low,
                enabled: false,
            }
        );
        assert!(supports_thinking_toggle(
            ErrorProfile::DeepSeek,
            "deepseek-reasoner"
        ));
        assert!(supports_thinking_toggle(ErrorProfile::Glm, "glm-5.1"));
        assert!(!supports_thinking_toggle(ErrorProfile::Glm, "glm-4-flash"));

        let cases = [
            ("o1-mini", Some(ReasoningEffort::Medium)),
            ("o3", Some(ReasoningEffort::Medium)),
            ("o4-mini", Some(ReasoningEffort::Medium)),
            ("gpt-5.2-codex", Some(ReasoningEffort::Medium)),
            ("codex-mini-latest", Some(ReasoningEffort::Medium)),
            ("gpt-4.1", None),
            ("gpt-50", None),
        ];
        for (model, expected) in cases {
            assert_eq!(
                chat_reasoning_effort(ErrorProfile::OpenAi, model, ReasoningEffort::Medium, 9_000),
                expected,
                "{model}"
            );
        }
        assert_eq!(
            chat_reasoning_effort(ErrorProfile::OpenAi, "gpt-5", ReasoningEffort::Low, 0),
            Some(ReasoningEffort::Low)
        );
    }

    #[test]
    fn openai_chat_high_effort_wire_matches_mapped_application() {
        let provider = OpenAiCompat::with_root(
            "test-credential".into(),
            ApiRoot::parse("https://api.openai.com/v1").unwrap(),
        )
        .unwrap()
        .with_error_profile(ErrorProfile::OpenAi);

        for requested in [ReasoningEffort::XHigh, ReasoningEffort::Max] {
            let request = TurnRequest {
                model: "gpt-5".into(),
                system: "stable system".into(),
                messages: Vec::new(),
                input_images: Vec::new(),
                tools: Vec::new(),
                max_tokens: 8_192,
                cache_system: false,
                thinking_budget: 16_384,
                reasoning_effort: requested,
            };
            let encoded = serde_json::to_vec(&provider.body(&request).unwrap()).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

            assert_eq!(
                wire["reasoning_effort"], "high",
                "{requested:?} is never serialized as an unproven OpenAI label"
            );
            assert_eq!(
                provider.effort_application(&request),
                EffortApplication::Mapped {
                    requested,
                    sent: ReasoningEffort::High,
                },
                "the reported semantic effort must equal the serialized wire value"
            );
        }
    }

    #[test]
    fn glm_52_request_body_enforces_the_effective_effort_mapping() {
        let provider = OpenAiCompat::with_root(
            "test-credential".into(),
            ApiRoot::parse("https://open.bigmodel.cn/api/paas/v4").unwrap(),
        )
        .unwrap()
        .with_error_profile(ErrorProfile::Glm);
        let mut request = TurnRequest {
            model: "glm-5.2".into(),
            system: "stable system".into(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new(),
            max_tokens: 8_192,
            cache_system: false,
            thinking_budget: 4_096,
            reasoning_effort: ReasoningEffort::Medium,
        };

        let body = provider.body(&request).unwrap();
        assert_eq!(body["thinking"]["type"], "enabled");
        assert_eq!(body["reasoning_effort"], "high");

        request.thinking_budget = 16_384;
        request.reasoning_effort = ReasoningEffort::XHigh;
        let body = provider.body(&request).unwrap();
        assert_eq!(body["reasoning_effort"], "max");

        request.thinking_budget = 0;
        request.reasoning_effort = ReasoningEffort::Low;
        let body = provider.body(&request).unwrap();
        assert_eq!(body["thinking"]["type"], "disabled");
        assert!(body.get("reasoning_effort").is_none());
    }

    #[test]
    fn refreshed_metadata_can_revoke_glm_semantic_effort_without_adapter_changes() {
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../static-provider-metadata-v1.json")).unwrap();
        document["bundle_revision"] = serde_json::json!("operator-refresh@test-v2");
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["version"] =
            serde_json::json!("glm-5.2-model-page@test-v2");
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["semantic_effort"] =
            serde_json::json!(false);
        crate::StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let metadata = std::sync::Arc::new(
            crate::StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap(),
        );
        let provider = OpenAiCompat::with_root(
            "key".into(),
            ApiRoot::parse("https://open.bigmodel.cn/api/paas/v4").unwrap(),
        )
        .unwrap()
        .with_error_profile(ErrorProfile::Glm)
        .with_static_metadata(metadata);
        let request = TurnRequest {
            model: "glm-5.2".into(),
            system: "system".into(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new(),
            max_tokens: 1_024,
            cache_system: false,
            thinking_budget: 4_096,
            reasoning_effort: ReasoningEffort::Medium,
        };
        assert!(
            provider
                .body(&request)
                .unwrap()
                .get("reasoning_effort")
                .is_none()
        );
        assert_eq!(
            provider.effort_application(&request),
            EffortApplication::ToggleOnly {
                requested: ReasoningEffort::Medium,
                enabled: true,
            }
        );
    }
}

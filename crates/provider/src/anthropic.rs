//! The live Anthropic Messages API provider. Transport only: it splits the HTTP SSE byte
//! stream into `SseFrame`s and feeds them to the pure `sse` parser, so all the interesting
//! logic stays testable without a network.

use crate::sse::{ANTHROPIC_CONTENT_BLOCKS_FORMAT, SseFrame, StreamItem, StreamParser};
use crate::{
    AdapterKind, ApiRoot, EffortApplication, ErrorProfile, Provider, ProviderError, TurnRequest,
    TurnResult,
};
use core_protocol::{Block, Message, ProviderState, Role};
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DEFAULT_API_ROOT: &str = "https://api.anthropic.com/v1";
const API_VERSION: &str = "2023-06-01";
const EFFORT_BETA_HEADER: &str = "effort-2025-11-24";
const MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_SSE_FRAME_BYTES: usize = 32 * 1024 * 1024;
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ROUTE_SCOPE_BYTES: usize = 256;
const MAX_STATE_FORMAT_BYTES: usize = 128;
const MAX_NATIVE_CONTENT_BLOCKS: usize = 4096;
const MAX_NATIVE_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOOL_ID_OR_NAME_BYTES: usize = 1024;
const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;
static NEXT_DIRECT_SCOPE: AtomicU64 = AtomicU64::new(1);

pub struct Anthropic {
    key: String,
    api_root: ApiRoot,
    route_scope: String,
    error_profile: ErrorProfile,
    client: reqwest::Client,
}

impl Anthropic {
    /// Construct against an exact API root. The complete supplied prefix is retained; callers
    /// configuring a gateway must include its version/path prefix themselves.
    pub fn new(key: String, api_root: Option<String>) -> Result<Self, ProviderError> {
        let api_root = ApiRoot::parse(api_root.as_deref().unwrap_or(DEFAULT_API_ROOT))?;
        Self::with_root(key, api_root)
    }

    pub fn with_root(key: String, api_root: ApiRoot) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            // The configured API root is an authority boundary. Never replay an API key, prompt,
            // or POST body through an HTTP redirect selected by the remote endpoint.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderError::Configuration("HTTP client could not be built".into()))?;
        Ok(Self {
            key,
            route_scope: direct_route_scope(),
            error_profile: if api_root.as_str() == DEFAULT_API_ROOT {
                ErrorProfile::Anthropic
            } else {
                ErrorProfile::CustomConservative
            },
            api_root,
            client,
        })
    }

    pub(crate) fn with_error_profile(mut self, error_profile: ErrorProfile) -> Self {
        self.error_profile = error_profile;
        self
    }

    /// Bind opaque thinking/signature continuation state to one configured provider route.
    /// Directly-constructed providers receive a process-unique scope in `with_root`; directory
    /// instances replace it with their stable instance id.
    pub fn with_route_scope(mut self, route_scope: String) -> Result<Self, ProviderError> {
        validate_route_scope(&route_scope)?;
        self.route_scope = route_scope;
        Ok(self)
    }

    /// Read the key from the Core process environment.
    pub fn from_env() -> Result<Self, ProviderError> {
        let key =
            std::env::var("ANTHROPIC_API_KEY").map_err(|_| ProviderError::MissingCredential {
                provider: "anthropic".into(),
            })?;
        Self::new(key, std::env::var("ANTHROPIC_BASE_URL").ok())
    }

    fn body(&self, req: &TurnRequest) -> Result<serde_json::Value, ProviderError> {
        let capabilities = anthropic_request_capabilities(self.error_profile, &req.model);
        // Stable prefix first (tools -> system), volatile last (messages) — the cache
        // discipline (ADR-002). cache_control on the system block marks the breakpoint.
        let system = if req.cache_system && capabilities.prompt_cache {
            serde_json::json!([{
                "type": "text",
                "text": req.system,
                "cache_control": {"type": "ephemeral"}
            }])
        } else {
            serde_json::json!(req.system)
        };

        let tools: Vec<serde_json::Value> = req
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();

        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|message| msg_to_json(message, &self.route_scope))
            .collect::<Result<_, _>>()?;

        let mut body = serde_json::json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "system": system,
            "tools": tools,
            "messages": messages,
            "stream": true,
        });
        // Unknown/legacy models omit optional capabilities. A rejected request is worse than a
        // conservative turn without thinking or prompt-cache metadata.
        if req.thinking_budget > 0 && capabilities.extended_thinking {
            body["thinking"] =
                serde_json::json!({"type":"enabled","budget_tokens": req.thinking_budget});
            let need = req.thinking_budget.saturating_add(4096);
            if req.max_tokens < need {
                body["max_tokens"] = serde_json::json!(need);
            }
        }
        if capabilities.semantic_effort {
            body["output_config"] = serde_json::json!({"effort": req.reasoning_effort.label()});
        }
        Ok(body)
    }
}

fn direct_route_scope() -> String {
    let sequence = NEXT_DIRECT_SCOPE.fetch_add(1, Ordering::Relaxed);
    format!(
        "direct-anthropic-messages-{}-{sequence}",
        std::process::id()
    )
}

fn validate_route_scope(route_scope: &str) -> Result<(), ProviderError> {
    if route_scope.is_empty()
        || route_scope.len() > MAX_ROUTE_SCOPE_BYTES
        || route_scope.chars().any(char::is_control)
    {
        return Err(ProviderError::Configuration(
            "Anthropic route scope was empty or invalid".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnthropicRequestCapabilities {
    prompt_cache: bool,
    extended_thinking: bool,
    semantic_effort: bool,
}

/// Capabilities are intentionally family allowlists, not guesses from the Messages wire shape.
/// Older and unknown Claude ids remain usable with the baseline request schema.
fn anthropic_request_capabilities(
    error_profile: ErrorProfile,
    model_id: &str,
) -> AnthropicRequestCapabilities {
    if error_profile != ErrorProfile::Anthropic {
        return AnthropicRequestCapabilities {
            prompt_cache: false,
            extended_thinking: false,
            semantic_effort: false,
        };
    }
    let claude_4 = ["claude-opus-4", "claude-sonnet-4", "claude-haiku-4"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family));
    let sonnet_37 = crate::model_matches_family(model_id, "claude-3-7-sonnet");
    let cache_only_35 = ["claude-3-5-sonnet", "claude-3-5-haiku"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family));
    // Claude Code's direct Messages implementation (effort-2025-11-24) uses an explicit model
    // allowlist. Keep this narrower than the thinking allowlist: Messages wire compatibility is
    // not evidence that a model accepts `output_config.effort`.
    let semantic_effort = ["claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family));
    AnthropicRequestCapabilities {
        prompt_cache: claude_4 || sonnet_37 || cache_only_35,
        extended_thinking: claude_4 || sonnet_37,
        semantic_effort,
    }
}

fn anthropic_effort_application(
    error_profile: ErrorProfile,
    request: &TurnRequest,
) -> EffortApplication {
    let capabilities = anthropic_request_capabilities(error_profile, &request.model);
    if capabilities.semantic_effort {
        EffortApplication::Exact {
            requested: request.reasoning_effort,
        }
    } else if capabilities.extended_thinking && request.thinking_budget > 0 {
        EffortApplication::BudgetBased {
            requested: request.reasoning_effort,
            budget_tokens: request.thinking_budget,
        }
    } else {
        EffortApplication::Unsupported {
            requested: request.reasoning_effort,
        }
    }
}

fn msg_to_json(m: &Message, route_scope: &str) -> Result<serde_json::Value, ProviderError> {
    let role = match m.role {
        Role::User => "user",
        Role::Assistant => "assistant",
    };
    if m.role == Role::Assistant
        && let Some(native_content) = matching_native_content(m, route_scope)?
    {
        return Ok(serde_json::json!({"role": role, "content": native_content}));
    }
    let content: Vec<serde_json::Value> = m
        .content
        .iter()
        // Naked thinking lacks the provider signature and must never be replayed. Only a matching,
        // validated ProviderState above is allowed to carry thinking or redacted-thinking blocks.
        .filter_map(|b| match b {
            Block::Text { text } => Some(serde_json::json!({"type":"text","text":text})),
            Block::Thinking { .. } => None,
            Block::ProviderState(_) => None,
            Block::ToolUse(t) => {
                Some(serde_json::json!({"type":"tool_use","id":t.id,"name":t.name,"input":t.input}))
            }
            Block::ToolResult(r) => Some(serde_json::json!({
                "type":"tool_result",
                "tool_use_id": r.tool_use_id,
                "content": r.content,
                "is_error": r.is_error,
            })),
        })
        .collect();
    Ok(serde_json::json!({"role": role, "content": content}))
}

fn matching_native_content(
    message: &Message,
    route_scope: &str,
) -> Result<Option<Vec<serde_json::Value>>, ProviderError> {
    validate_route_scope(route_scope)?;
    let mut matching = None;
    for block in &message.content {
        let Block::ProviderState(state) = block else {
            continue;
        };
        if state.route_scope != route_scope || state.format != ANTHROPIC_CONTENT_BLOCKS_FORMAT {
            continue;
        }
        validate_state_envelope(state)?;
        if matching.is_some() {
            return Err(ProviderError::Decode(
                "assistant message contained duplicate matching Anthropic provider state".into(),
            ));
        }
        let blocks = state.payload.as_array().ok_or_else(|| {
            ProviderError::Decode("Anthropic provider state payload was not an array".into())
        })?;
        validate_native_content(blocks)?;
        matching = Some(blocks.clone());
    }
    Ok(matching)
}

fn validate_state_envelope(state: &ProviderState) -> Result<(), ProviderError> {
    if state.route_scope.is_empty()
        || state.route_scope.len() > MAX_ROUTE_SCOPE_BYTES
        || state.route_scope.chars().any(char::is_control)
        || state.format.is_empty()
        || state.format.len() > MAX_STATE_FORMAT_BYTES
        || state.format.chars().any(char::is_control)
    {
        return Err(ProviderError::Decode(
            "provider state scope or format exceeded its bound".into(),
        ));
    }
    let encoded = serde_json::to_vec(&state.payload).map_err(|_| {
        ProviderError::Decode("Anthropic provider state could not be encoded".into())
    })?;
    if encoded.len() > MAX_NATIVE_STATE_BYTES {
        return Err(ProviderError::Decode(format!(
            "Anthropic provider state exceeded {MAX_NATIVE_STATE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_native_content(content: &[serde_json::Value]) -> Result<(), ProviderError> {
    if content.len() > MAX_NATIVE_CONTENT_BLOCKS {
        return Err(ProviderError::Decode(format!(
            "Anthropic provider state exceeded {MAX_NATIVE_CONTENT_BLOCKS} content blocks"
        )));
    }
    let encoded = serde_json::to_vec(content).map_err(|_| {
        ProviderError::Decode("Anthropic native content could not be encoded".into())
    })?;
    if encoded.len() > MAX_NATIVE_STATE_BYTES {
        return Err(ProviderError::Decode(format!(
            "Anthropic native content exceeded {MAX_NATIVE_STATE_BYTES} bytes"
        )));
    }

    for block in content {
        let object = block.as_object().ok_or_else(|| {
            ProviderError::Decode("Anthropic native content block was not an object".into())
        })?;
        let kind = required_native_string(object, "type", MAX_STATE_FORMAT_BYTES)?;
        let allowed: &[&str] = match kind {
            "text" => {
                required_native_string(object, "text", MAX_NATIVE_STATE_BYTES)?;
                &["type", "text"]
            }
            "thinking" => {
                required_native_string(object, "thinking", MAX_NATIVE_STATE_BYTES)?;
                let signature = required_native_string(object, "signature", MAX_SIGNATURE_BYTES)?;
                if signature.is_empty() {
                    return Err(ProviderError::Decode(
                        "Anthropic thinking block had an empty signature".into(),
                    ));
                }
                &["type", "thinking", "signature"]
            }
            "redacted_thinking" => {
                let data = required_native_string(object, "data", MAX_NATIVE_STATE_BYTES)?;
                if data.is_empty() {
                    return Err(ProviderError::Decode(
                        "Anthropic redacted thinking block had empty data".into(),
                    ));
                }
                &["type", "data"]
            }
            "tool_use" => {
                let id = required_native_string(object, "id", MAX_TOOL_ID_OR_NAME_BYTES)?;
                let name = required_native_string(object, "name", MAX_TOOL_ID_OR_NAME_BYTES)?;
                if id.is_empty() || name.is_empty() {
                    return Err(ProviderError::Decode(
                        "Anthropic tool block lacked an id or name".into(),
                    ));
                }
                if !object
                    .get("input")
                    .is_some_and(serde_json::Value::is_object)
                {
                    return Err(ProviderError::Decode(
                        "Anthropic tool block input was not an object".into(),
                    ));
                }
                &["type", "id", "name", "input"]
            }
            _ => {
                return Err(ProviderError::Decode(
                    "Anthropic provider state contained an unsupported block type".into(),
                ));
            }
        };
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(ProviderError::Decode(
                "Anthropic provider state block contained an unknown field".into(),
            ));
        }
    }
    Ok(())
}

fn required_native_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    max_bytes: usize,
) -> Result<&'a str, ProviderError> {
    let value = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ProviderError::Decode("Anthropic provider state string field was missing".into())
        })?;
    if value.len() > max_bytes {
        return Err(ProviderError::Decode(
            "Anthropic provider state string exceeded its bound".into(),
        ));
    }
    Ok(value)
}

/// Split a chunk of SSE text into complete `SseFrame`s. SSE frames are separated by a blank
/// line; each has an `event:` and a `data:` field. Returns (frames, leftover).
fn split_frames(buf: &str) -> (Vec<SseFrame>, String) {
    let mut frames = Vec::new();
    let mut rest = buf;
    while let Some((idx, separator_len)) = frame_boundary(rest) {
        let (block, after) = rest.split_at(idx);
        let mut event = String::new();
        let mut data_lines = Vec::new();
        for line in block.lines() {
            if let Some(e) = line.strip_prefix("event:") {
                event = e.trim().to_string();
            } else if let Some(d) = line.strip_prefix("data:") {
                data_lines.push(d.trim());
            }
        }
        let data = data_lines.join("\n");
        if !event.is_empty() && !data.is_empty() {
            frames.push(SseFrame { event, data });
        }
        rest = &after[separator_len..];
    }
    (frames, rest.to_string())
}

fn frame_boundary(buf: &str) -> Option<(usize, usize)> {
    match (buf.find("\n\n"), buf.find("\r\n\r\n")) {
        (Some(lf), Some(crlf)) if crlf < lf => Some((crlf, 4)),
        (Some(lf), _) => Some((lf, 2)),
        (None, Some(crlf)) => Some((crlf, 4)),
        (None, None) => None,
    }
}

#[async_trait::async_trait]
impl Provider for Anthropic {
    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        anthropic_effort_application(self.error_profile, req)
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        // Guard the cache prefix before spending a request (ADR-002 amendment).
        if let Some(why) = crate::cache_bomb_in_prefix(&req.system) {
            return Err(ProviderError::Decode(format!("cache-bomb refused: {why}")));
        }

        let deadline = Instant::now() + STREAM_TOTAL_TIMEOUT;
        let mut request = self
            .client
            .post(self.api_root.endpoint("messages")?)
            .header("x-api-key", &self.key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&self.body(req)?);
        if anthropic_request_capabilities(self.error_profile, &req.model).semantic_effort {
            request = request.header("anthropic-beta", EFFORT_BETA_HEADER);
        }
        let resp = tokio::time::timeout(RESPONSE_HEADER_TIMEOUT, request.send())
            .await
            .map_err(|_| ProviderError::Http("Anthropic response headers timed out".into()))?
            .map_err(|e| ProviderError::Http(e.to_string()))?;

        let status = resp.status();
        let response_retry_after = crate::retry_after_from_headers(resp.headers());
        let response_request_id = crate::request_id_from_headers(resp.headers());
        if !status.is_success() {
            let error = tokio::time::timeout(
                RESPONSE_HEADER_TIMEOUT,
                crate::api_error_from_response(
                    resp,
                    AdapterKind::AnthropicMessages,
                    self.error_profile,
                ),
            )
            .await
            .map_err(|_| ProviderError::Http("Anthropic error body timed out".into()))?;
            return Err(error);
        }

        let mut stream = resp.bytes_stream();
        // Buffer RAW bytes: a UTF-8 char can be split across network chunks, and decoding each
        // chunk in isolation corrupts it (code review F2). We decode only the complete-UTF-8
        // prefix and carry the trailing partial bytes to the next iteration.
        let mut byte_buf: Vec<u8> = Vec::new();
        let mut buf = String::new(); // decoded text awaiting frame-splitting
        let mut parser = StreamParser::with_route_scope(self.route_scope.clone())
            .map_err(ProviderError::Configuration)?; // persistent across chunks
        let mut result: Option<TurnResult> = None;
        let mut total_stream_bytes = 0usize;

        loop {
            // Idle timeout: a server that accepts the request then stalls (no bytes, no FIN)
            // would otherwise hang the run forever (code review F3). Bound each read.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProviderError::Http(
                    "Anthropic stream exceeded total deadline".into(),
                ));
            }
            let wait = remaining.min(STREAM_IDLE_TIMEOUT);
            let next = tokio::time::timeout(wait, stream.next())
                .await
                .map_err(|_| {
                    if wait == remaining {
                        ProviderError::Http("Anthropic stream exceeded total deadline".into())
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
                    "Anthropic stream exceeded {MAX_STREAM_BYTES} bytes"
                )));
            }
            byte_buf.extend_from_slice(&bytes);
            // Decode the longest valid-UTF-8 prefix; keep any trailing incomplete char in byte_buf.
            let valid = match std::str::from_utf8(&byte_buf) {
                Ok(s) => {
                    buf.push_str(s);
                    byte_buf.len()
                }
                Err(e) => {
                    if e.error_len().is_some() {
                        return Err(ProviderError::Decode(
                            "Anthropic stream contained invalid UTF-8".into(),
                        ));
                    }
                    let up_to = e.valid_up_to();
                    buf.push_str(std::str::from_utf8(&byte_buf[..up_to]).unwrap());
                    up_to
                }
            };
            byte_buf.drain(..valid);
            let (frames, leftover) = split_frames(&buf);
            buf = leftover;
            for frame in &frames {
                if result.is_some() {
                    return Err(ProviderError::Decode(
                        "Anthropic stream emitted data after message_stop".into(),
                    ));
                }
                if frame.event.len().saturating_add(frame.data.len()) > MAX_SSE_FRAME_BYTES {
                    return Err(ProviderError::Decode(format!(
                        "Anthropic SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                    )));
                }
                // Anthropic can accept a request with HTTP 200 and then report overloads or
                // other API failures in-band. Treat that as a first-class provider failure;
                // feeding it to the content parser used to silently discard it.
                if frame.event == "error" {
                    return Err(ProviderError::Stream(crate::decode_stream_error_for(
                        AdapterKind::AnthropicMessages,
                        self.error_profile,
                        "anthropic",
                        &frame.data,
                        response_retry_after,
                        response_request_id.clone(),
                    )));
                }
                // Feed each frame to the persistent parser; mid-stream items (incl. the
                // flagship ToolUseComplete) reach the callback as early as they exist.
                for item in parser.push(frame).map_err(ProviderError::Decode)? {
                    if let StreamItem::TurnComplete {
                        blocks,
                        stop_reason,
                        usage,
                    } = &item
                    {
                        result = Some(TurnResult {
                            blocks: blocks.clone(),
                            stop_reason: *stop_reason,
                            usage: *usage,
                        });
                    }
                    on_item(item);
                }
            }
            if buf.len() > MAX_SSE_FRAME_BYTES {
                return Err(ProviderError::Decode(format!(
                    "Anthropic SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                )));
            }
            // message_stop is the protocol terminal. Do not wait for the peer to close an HTTP
            // connection it may keep alive; all complete frames from this chunk were validated.
            if let Some(result) = result.take() {
                if !buf.trim().is_empty() || !byte_buf.is_empty() {
                    return Err(ProviderError::Decode(
                        "Anthropic message_stop was followed by an incomplete frame".into(),
                    ));
                }
                return Ok(result);
            }
        }

        if !byte_buf.is_empty() {
            return Err(ProviderError::Decode(
                "Anthropic stream ended with an incomplete UTF-8 code point".to_string(),
            ));
        }
        if !buf.trim().is_empty() {
            return Err(ProviderError::Decode(
                "Anthropic stream ended with an incomplete SSE frame".to_string(),
            ));
        }

        result.ok_or_else(|| ProviderError::Decode("stream ended before message_stop".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(model: &str) -> TurnRequest {
        TurnRequest {
            model: model.into(),
            system: "system".into(),
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: 100,
            cache_system: true,
            thinking_budget: 9_000,
            reasoning_effort: core_protocol::ReasoningEffort::Medium,
        }
    }

    #[test]
    fn split_frames_handles_partial_chunks() {
        let (frames, rest) =
            split_frames("event: ping\ndata: {}\n\nevent: message_stop\ndata: {}\n\nevent: par");
        assert_eq!(frames.len(), 2);
        assert!(rest.starts_with("event: par"));
    }

    #[test]
    fn split_frames_preserves_error_events_for_typed_handling() {
        let (frames, rest) = split_frames(
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n",
        );
        assert!(rest.is_empty());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, "error");
        assert!(frames[0].data.contains("overloaded_error"));
    }

    #[test]
    fn split_frames_accepts_crlf_and_multiline_data() {
        let (frames, rest) = split_frames(
            "event: error\r\ndata: {\"type\":\"error\",\r\ndata: \"message\":\"busy\"}\r\n\r\n",
        );
        assert!(rest.is_empty());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, "error");
        assert_eq!(
            frames[0].data,
            "{\"type\":\"error\",\n\"message\":\"busy\"}"
        );
    }

    #[test]
    fn optional_capabilities_are_allowlisted_by_profile_and_family() {
        let cases = [
            ("claude-opus-4-7", true, true, true),
            ("claude-opus-4-6", true, true, true),
            ("claude-sonnet-4-6", true, true, true),
            ("claude-sonnet-4-5-20250929", true, true, false),
            ("claude-opus-4-1", true, true, false),
            ("claude-3-7-sonnet-latest", true, true, false),
            ("claude-3-5-sonnet-20241022", true, false, false),
            ("claude-3-5-haiku-latest", true, false, false),
            ("claude-3-opus-20240229", false, false, false),
            ("claude-2.1", false, false, false),
            ("claude-unknown", false, false, false),
        ];
        for (model, prompt_cache, extended_thinking, semantic_effort) in cases {
            assert_eq!(
                anthropic_request_capabilities(ErrorProfile::Anthropic, model),
                AnthropicRequestCapabilities {
                    prompt_cache,
                    extended_thinking,
                    semantic_effort,
                },
                "{model}"
            );
        }
        assert_eq!(
            anthropic_request_capabilities(ErrorProfile::Glm, "claude-sonnet-4-5"),
            AnthropicRequestCapabilities {
                prompt_cache: false,
                extended_thinking: false,
                semantic_effort: false,
            }
        );
    }

    #[test]
    fn unsupported_model_omits_optional_fields_but_keeps_baseline_request() {
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();
        let old = provider.body(&request("claude-2.1")).unwrap();
        assert!(old.get("thinking").is_none());
        assert!(old["system"].is_string());
        assert_eq!(old["max_tokens"], 100);
        assert!(
            old.get("tools").is_some(),
            "tool semantics must be unchanged"
        );

        let supported = provider.body(&request("claude-sonnet-4-5")).unwrap();
        assert_eq!(supported["thinking"]["type"], "enabled");
        assert_eq!(supported["max_tokens"], 13_096);
        assert_eq!(supported["system"][0]["cache_control"]["type"], "ephemeral");
        assert!(
            supported.get("tools").is_some(),
            "tool semantics must be unchanged"
        );

        let exact = provider.body(&request("claude-opus-4-6")).unwrap();
        assert_eq!(exact["output_config"]["effort"], "medium");
        assert_eq!(
            provider.effort_application(&request("claude-opus-4-6")),
            EffortApplication::Exact {
                requested: core_protocol::ReasoningEffort::Medium
            }
        );
        assert_eq!(
            provider.effort_application(&request("claude-sonnet-4-5")),
            EffortApplication::BudgetBased {
                requested: core_protocol::ReasoningEffort::Medium,
                budget_tokens: 9_000
            }
        );
    }

    #[test]
    fn direct_instances_have_unique_route_scopes() {
        let first =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();
        let second =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();
        assert_ne!(first.route_scope, second.route_scope);
        assert!(
            first
                .with_route_scope("x".repeat(MAX_ROUTE_SCOPE_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn matching_scope_replays_native_blocks_and_other_scope_uses_portable_blocks() {
        let signature = "opaque-thinking-signature";
        let redacted = "opaque-redacted-thinking";
        let native = serde_json::json!([
            {"type":"thinking","thinking":"private reasoning","signature":signature},
            {"type":"redacted_thinking","data":redacted},
            {"type":"text","text":"checking"},
            {"type":"tool_use","id":"tool-1","name":"read_file","input":{"path":"Cargo.toml"}}
        ]);
        let state = ProviderState {
            route_scope: "anthropic-a".into(),
            format: ANTHROPIC_CONTENT_BLOCKS_FORMAT.into(),
            payload: native.clone(),
        };
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(state.clone()),
                Block::Thinking {
                    thinking: "private reasoning".into(),
                },
                Block::Text {
                    text: "checking".into(),
                },
                Block::ToolUse(core_protocol::ToolUse {
                    id: "tool-1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":"Cargo.toml"}),
                }),
            ],
        };

        let exact = msg_to_json(&message, "anthropic-a").unwrap();
        assert_eq!(exact["content"], native);

        let portable = msg_to_json(&message, "anthropic-b").unwrap();
        assert_eq!(
            portable["content"],
            serde_json::json!([
                {"type":"text","text":"checking"},
                {"type":"tool_use","id":"tool-1","name":"read_file","input":{"path":"Cargo.toml"}}
            ])
        );
        let portable_encoded = portable.to_string();
        assert!(!portable_encoded.contains(signature));
        assert!(!portable_encoded.contains(redacted));
        assert!(!portable_encoded.contains("private reasoning"));
        assert!(!format!("{state:?}").contains(signature));
        assert!(!format!("{state:?}").contains(redacted));
    }

    #[test]
    fn matching_native_state_is_strict_but_foreign_state_is_opaque() {
        let malformed = ProviderState {
            route_scope: "anthropic-a".into(),
            format: ANTHROPIC_CONTENT_BLOCKS_FORMAT.into(),
            payload: serde_json::json!([{
                "type":"thinking","thinking":"private","signature":"sig",
                "future_unvalidated_field":"must not be replayed"
            }]),
        };
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(malformed),
                Block::Thinking {
                    thinking: "private".into(),
                },
                Block::Text {
                    text: "portable".into(),
                },
            ],
        };
        assert!(msg_to_json(&message, "anthropic-a").is_err());
        assert_eq!(
            msg_to_json(&message, "anthropic-b").unwrap()["content"],
            serde_json::json!([{"type":"text","text":"portable"}])
        );
    }

    #[test]
    fn naked_thinking_is_never_replayed() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::Thinking {
                    thinking: "must remain private".into(),
                },
                Block::Text {
                    text: "visible".into(),
                },
            ],
        };
        assert_eq!(
            msg_to_json(&message, "anthropic-a").unwrap()["content"],
            serde_json::json!([{"type":"text","text":"visible"}])
        );
    }
}

//! The live Anthropic Messages API provider. Transport only: it splits the HTTP SSE byte
//! stream into `SseFrame`s and feeds them to the pure `sse` parser, so all the interesting
//! logic stays testable without a network.

use crate::sse::{ANTHROPIC_CONTENT_BLOCKS_FORMAT, SseFrame, StreamItem, StreamParser};
use crate::{
    AdapterKind, ApiRoot, CacheBreakpoint, CacheScope, EffortApplication, ErrorProfile, Provider,
    ProviderControlCapabilities, ProviderError, TurnRequest, TurnResult,
};
use futures_util::StreamExt;
use iteron_protocol::{Block, Message, ProviderState, Role};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DEFAULT_API_ROOT: &str = "https://api.anthropic.com/v1";
const API_VERSION: &str = "2023-06-01";
const MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_SSE_FRAME_BYTES: usize = 32 * 1024 * 1024;
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
    static_metadata: std::sync::Arc<crate::StaticProviderMetadata>,
    prompt_cache: bool,
    client: crate::catalog::RuntimeHttpClient,
}

impl Anthropic {
    /// Construct against an exact API root. The complete supplied prefix is retained; callers
    /// configuring a gateway must include its version/path prefix themselves.
    pub fn new(key: String, api_root: Option<String>) -> Result<Self, ProviderError> {
        let api_root = ApiRoot::parse(api_root.as_deref().unwrap_or(DEFAULT_API_ROOT))?;
        Self::with_root(key, api_root)
    }

    pub fn with_root(key: String, api_root: ApiRoot) -> Result<Self, ProviderError> {
        let client = crate::catalog::RuntimeHttpClient::default_reconfigurable()?;
        Self::with_client(key, api_root, client)
    }

    /// Construct against an exact API root while obtaining the HTTP client from an
    /// injected network-I/O port instead of building it inline. `with_root` is the
    /// default-transport convenience wrapper; a host that must broker, observe, or
    /// substitute transport injects its own [`crate::catalog::HttpTransport`] here
    /// (D2-21).
    pub fn with_transport(
        key: String,
        api_root: ApiRoot,
        transport: &dyn crate::catalog::HttpTransport,
    ) -> Result<Self, ProviderError> {
        let client = crate::catalog::RuntimeHttpClient::fixed(transport)?;
        Self::with_client(key, api_root, client)
    }

    fn with_client(
        key: String,
        api_root: ApiRoot,
        client: crate::catalog::RuntimeHttpClient,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            key,
            route_scope: direct_route_scope(),
            error_profile: if api_root.as_str() == DEFAULT_API_ROOT {
                ErrorProfile::Anthropic
            } else {
                ErrorProfile::CustomConservative
            },
            static_metadata: crate::StaticProviderMetadata::embedded(),
            prompt_cache: true,
            api_root,
            client,
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

    /// Opt this route out of prompt caching. Breakpoints are on by default for every endpoint
    /// speaking the Messages wire; this is the operator's declaration that one particular
    /// endpoint rejects `cache_control` outright instead of ignoring it.
    pub fn with_prompt_cache(mut self, prompt_cache: bool) -> Self {
        self.prompt_cache = prompt_cache;
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

    fn body(&self, req: &TurnRequest) -> Result<serde_json::Value, ProviderError> {
        let capabilities = anthropic_request_capabilities(
            self.error_profile,
            self.api_root.as_str(),
            &self.static_metadata,
            &req.model,
        );
        // Stable prefix first (tools -> system), volatile last (messages) — the cache
        // discipline (ADR-002). cache_control on the system block marks the breakpoint.
        let requested_breakpoint = match req.controls.prompt_cache.breakpoint {
            CacheBreakpoint::None if req.cache_system => CacheBreakpoint::Rolling,
            requested => requested,
        };
        let cache_prompt = requested_breakpoint != CacheBreakpoint::None
            && self.prompt_cache
            && capabilities.prompt_cache;
        let cache_control = anthropic_cache_control(req.controls.prompt_cache.ttl_seconds)?;
        let system = if cache_prompt {
            serde_json::json!([{
                "type": "text",
                "text": req.system,
                "cache_control": cache_control
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

        // The system block alone leaves the transcript uncached, and by turn five the transcript
        // is over 90% of the request. Roll a second breakpoint along with the conversation: it
        // sits on the last block of the second-to-last message, so turn N reads every prior turn
        // from cache and only the newest turn is uncached. Two of the four allowed breakpoints.
        let transcript_breakpoint = (cache_prompt
            && requested_breakpoint == CacheBreakpoint::Rolling)
            .then(|| req.messages.len().checked_sub(2))
            .flatten();
        let image_target = image_target(&req.messages, &req.input_images)?;
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .enumerate()
            .map(|(index, message)| {
                msg_to_json(
                    message,
                    &self.route_scope,
                    transcript_breakpoint == Some(index),
                    if image_target == Some(index) {
                        req.input_images.as_slice()
                    } else {
                        &[]
                    },
                )
            })
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

fn anthropic_cache_control(ttl_seconds: u32) -> Result<serde_json::Value, ProviderError> {
    match ttl_seconds {
        0 | 300 => Ok(serde_json::json!({"type": "ephemeral"})),
        3_600 => Ok(serde_json::json!({"type": "ephemeral", "ttl": "1h"})),
        _ => Err(ProviderError::Configuration(
            "Anthropic prompt-cache TTL was not capability-attested".into(),
        )),
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

/// Thinking and effort are intentionally family allowlists, not guesses from the Messages wire
/// shape. Older and unknown Claude ids remain usable with the baseline request schema.
///
/// Prompt caching is deliberately NOT in that shape. `cache_control` is a property of the
/// Messages wire itself, not a per-account entitlement, and gating it on the first-party error
/// profile (which requires the exact api.anthropic.com root) silently disabled caching for every
/// Anthropic-wire gateway — kimi, deepseek, GLM — so each of those re-sent the whole prefill
/// uncached every turn: 95000 uncached prefill tokens in one measured turn. It now defaults on
/// for anything on this adapter; the endpoint that genuinely rejects the field is declared by the
/// operator through [`Anthropic::with_prompt_cache`], not inferred from a model name.
fn anthropic_request_capabilities(
    error_profile: ErrorProfile,
    api_root: &str,
    static_metadata: &crate::StaticProviderMetadata,
    model_id: &str,
) -> AnthropicRequestCapabilities {
    let first_party = error_profile == ErrorProfile::Anthropic;
    let claude_4 = ["claude-opus-4", "claude-sonnet-4", "claude-haiku-4"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family));
    let sonnet_37 = crate::model_matches_family(model_id, "claude-3-7-sonnet");
    // The refreshable metadata keeps this narrower than the thinking allowlist: Messages wire
    // compatibility is not evidence that a model accepts `output_config.effort` or its beta header.
    let semantic_effort = first_party
        && api_root == static_metadata.anthropic_effort_api_root()
        && static_metadata.anthropic_effort_header(model_id).is_some();
    AnthropicRequestCapabilities {
        prompt_cache: !predates_prompt_caching(model_id),
        extended_thinking: first_party && (claude_4 || sonnet_37),
        semantic_effort,
    }
}

/// The Claude generations that shipped before `cache_control` existed on the Messages wire. This
/// is a bounded denylist of ids Core knows are too old, not an allowlist: an unrecognized id is a
/// gateway's own model, and refusing to cache it is what the audit measured as the defect.
fn predates_prompt_caching(model_id: &str) -> bool {
    ["claude-1", "claude-2", "claude-instant"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family))
}

fn anthropic_effort_application(
    error_profile: ErrorProfile,
    api_root: &str,
    static_metadata: &crate::StaticProviderMetadata,
    request: &TurnRequest,
) -> EffortApplication {
    let capabilities =
        anthropic_request_capabilities(error_profile, api_root, static_metadata, &request.model);
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

fn msg_to_json(
    m: &Message,
    route_scope: &str,
    cache_breakpoint: bool,
    input_images: &[iteron_protocol::ImageContent],
) -> Result<serde_json::Value, ProviderError> {
    let role = match m.role {
        Role::User => "user",
        Role::Assistant => "assistant",
    };
    if m.role == Role::Assistant
        && let Some(mut native_content) = matching_native_content(m, route_scope)?
    {
        mark_cache_breakpoint(&mut native_content, cache_breakpoint);
        return Ok(serde_json::json!({"role": role, "content": native_content}));
    }
    let mut content: Vec<serde_json::Value> = input_images
        .iter()
        .map(|image| {
            serde_json::json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": image.media_type.as_str(),
                    "data": image.data.as_str(),
                }
            })
        })
        .chain(m
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
        }))
        .collect();
    mark_cache_breakpoint(&mut content, cache_breakpoint);
    Ok(serde_json::json!({"role": role, "content": content}))
}

fn image_target(
    messages: &[Message],
    input_images: &[iteron_protocol::ImageContent],
) -> Result<Option<usize>, ProviderError> {
    if input_images.is_empty() {
        return Ok(None);
    }
    messages
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, message)| {
            (message.role == Role::User
                && message
                    .content
                    .iter()
                    .any(|block| matches!(block, Block::Text { .. })))
            .then_some(index)
        })
        .map(Some)
        .ok_or_else(|| {
            ProviderError::Decode("Anthropic image input lacked a user text submission".into())
        })
}

/// Mark the rolling transcript breakpoint on the last block of one message that can carry it. A
/// breakpoint caches the prefix up to and including its own block, so stepping back past a
/// trailing reasoning block only leaves that block uncached and never drops an earlier turn; a
/// message with no eligible block simply carries no breakpoint that turn.
fn mark_cache_breakpoint(content: &mut [serde_json::Value], cache_breakpoint: bool) {
    if !cache_breakpoint {
        return;
    }
    let Some(index) = content.iter().rposition(accepts_cache_control) else {
        return;
    };
    if let Some(object) = content[index].as_object_mut() {
        object.insert(
            "cache_control".into(),
            serde_json::json!({"type": "ephemeral"}),
        );
    }
}

/// Whether a serialized block may carry `cache_control`. The wire accepts it on content-bearing
/// blocks and rejects it on the model-internal reasoning blocks, whose schema is the closed key
/// set [`validate_native_content`] already enforces on the way in. A replayed assistant turn can
/// end in one of those — `redacted_thinking` is pushed to the native payload on its own, and a
/// turn that stops on refusal or pause after thinking never gets a trailing text block — so the
/// naive "last block" would have put `cache_control` inside a block that cannot hold it and had
/// the whole request rejected. Denylist, not allowlist: a content block Core does not emit yet
/// stays eligible rather than silently losing the transcript breakpoint.
fn accepts_cache_control(block: &serde_json::Value) -> bool {
    !matches!(
        block.get("type").and_then(serde_json::Value::as_str),
        Some("thinking" | "redacted_thinking")
    )
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
    fn control_capabilities(&self) -> ProviderControlCapabilities {
        let mut capabilities = ProviderControlCapabilities::default();
        if self.prompt_cache {
            capabilities
                .cache_breakpoints
                .extend([CacheBreakpoint::Rolling, CacheBreakpoint::Explicit]);
            // The 5 minute form is the wire default. The 1 hour form is attested only for the
            // first-party endpoint; compatible gateways commonly reject the `ttl` member.
            capabilities.cache_ttl_seconds.insert(300);
            capabilities
                .cache_scopes
                .extend([CacheScope::Request, CacheScope::Session]);
            capabilities.cache_invalidates_on_tool_change = true;
            if self.error_profile == ErrorProfile::Anthropic
                && self.api_root.as_str() == DEFAULT_API_ROOT
            {
                capabilities.cache_ttl_seconds.insert(3_600);
            }
        }
        if self.error_profile == ErrorProfile::Anthropic
            && self.api_root.as_str() == DEFAULT_API_ROOT
        {
            capabilities.idempotent_requests = true;
        }
        capabilities
    }

    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        anthropic_effort_application(
            self.error_profile,
            self.api_root.as_str(),
            &self.static_metadata,
            req,
        )
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let transport = req.controls.transport;
        let deadline = Instant::now()
            .checked_add(transport.request_total)
            .ok_or_else(|| {
                ProviderError::Configuration(
                    "provider request total deadline exceeds the platform clock range".into(),
                )
            })?;
        let client = self.client.client(transport)?;
        let mut request = client
            .post(self.api_root.endpoint("messages")?)
            .header("x-api-key", &self.key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&self.body(req)?);
        if let Some(header) = self
            .static_metadata
            .anthropic_effort_header(&req.model)
            .filter(|_| {
                self.error_profile == ErrorProfile::Anthropic
                    && self.api_root.as_str() == self.static_metadata.anthropic_effort_api_root()
            })
        {
            request = request.header("anthropic-beta", header);
        }
        let header_timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(RESPONSE_HEADER_TIMEOUT);
        let resp = tokio::time::timeout(header_timeout, request.send())
            .await
            .map_err(|_| ProviderError::Http("Anthropic response headers timed out".into()))?
            .map_err(|e| ProviderError::Http(e.to_string()))?;

        let status = resp.status();
        let response_retry_after = crate::retry_after_from_headers(resp.headers());
        let response_request_id = crate::request_id_from_headers(resp.headers());
        if !status.is_success() {
            let error = tokio::time::timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(RESPONSE_HEADER_TIMEOUT),
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

        // Quota state is on the success headers, so it is knowable here — before a single token
        // has arrived and long before the 429 that used to be its first symptom (I-53).
        if let Some(snapshot) = crate::rate_limit_from_headers(resp.headers()) {
            on_item(StreamItem::RateLimit(snapshot));
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
            let wait = remaining.min(transport.stream_idle);
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
    use iteron_protocol::{ImageContent, ImageMediaType};

    fn request(model: &str) -> TurnRequest {
        TurnRequest {
            model: model.into(),
            system: "system".into(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new(),
            max_tokens: 100,
            cache_system: true,
            thinking_budget: 9_000,
            reasoning_effort: iteron_protocol::ReasoningEffort::Medium,
            controls: Default::default(),
        }
    }

    #[tokio::test]
    async fn oversized_request_deadline_is_a_typed_pre_dispatch_refusal() {
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();
        let mut request = request("claude-sonnet-4-5");
        request.controls.transport.request_total = Duration::MAX;
        let error = provider
            .turn(&request, &mut |_| {})
            .await
            .expect_err("an unrepresentable deadline must refuse before network dispatch");
        assert!(matches!(error, ProviderError::Configuration(_)));
        assert!(error.to_string().contains("platform clock range"));
    }

    /// A request whose transcript already holds `messages` alternating turns.
    fn conversation(model: &str, messages: usize) -> TurnRequest {
        let mut request = request(model);
        request.messages = (0..messages)
            .map(|index| Message {
                role: if index % 2 == 0 {
                    Role::User
                } else {
                    Role::Assistant
                },
                content: vec![Block::Text {
                    text: format!("turn {index}"),
                }],
            })
            .collect();
        request
    }

    fn breakpoint_indices(body: &serde_json::Value) -> Vec<usize> {
        body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, message)| {
                message["content"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|block| block.get("cache_control").is_some())
            })
            .map(|(index, _)| index)
            .collect()
    }

    #[test]
    fn messages_body_encodes_base64_images_on_the_latest_user_text() {
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();
        let mut request = conversation("claude-sonnet-4-5", 3);
        request.input_images = vec![
            ImageContent::new(ImageMediaType::Png, "iVBORw0KGgo=").unwrap(),
            ImageContent::new(ImageMediaType::Webp, "UklGRg==").unwrap(),
        ];

        let body = provider.body(&request).unwrap();
        assert_eq!(
            body["messages"][2]["content"],
            serde_json::json!([
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},
                {"type":"image","source":{"type":"base64","media_type":"image/webp","data":"UklGRg=="}},
                {"type":"text","text":"turn 2"}
            ])
        );
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
        let metadata = crate::StaticProviderMetadata::embedded();
        let cases = [
            ("claude-opus-4-7", true, true, true),
            ("claude-opus-4-6", true, true, true),
            ("claude-sonnet-4-6", true, true, true),
            ("claude-sonnet-4-5-20250929", true, true, false),
            ("claude-opus-4-1", true, true, false),
            ("claude-3-7-sonnet-latest", true, true, false),
            ("claude-3-5-sonnet-20241022", true, false, false),
            ("claude-3-5-haiku-latest", true, false, false),
            // Prompt caching is a wire property, so it stays on for a model whose thinking and
            // effort support Core cannot vouch for; only the pre-`cache_control` generations
            // are excluded.
            ("claude-3-opus-20240229", true, false, false),
            ("claude-unknown", true, false, false),
            ("claude-2.1", false, false, false),
            ("claude-instant-1.2", false, false, false),
        ];
        for (model, prompt_cache, extended_thinking, semantic_effort) in cases {
            assert_eq!(
                anthropic_request_capabilities(
                    ErrorProfile::Anthropic,
                    DEFAULT_API_ROOT,
                    &metadata,
                    model,
                ),
                AnthropicRequestCapabilities {
                    prompt_cache,
                    extended_thinking,
                    semantic_effort,
                },
                "{model}"
            );
        }
        // A gateway inherits neither thinking nor effort — wire compatibility is not an
        // entitlement — but it does speak the wire, so it keeps its cache breakpoints.
        for (profile, api_root, model) in [
            (ErrorProfile::Glm, DEFAULT_API_ROOT, "claude-sonnet-4-5"),
            (
                ErrorProfile::CustomConservative,
                "https://gateway.test/anthropic",
                "kimi-k2-turbo",
            ),
            (
                ErrorProfile::DeepSeek,
                "https://api.deepseek.com/anthropic",
                "deepseek-chat",
            ),
        ] {
            assert_eq!(
                anthropic_request_capabilities(profile, api_root, &metadata, model),
                AnthropicRequestCapabilities {
                    prompt_cache: true,
                    extended_thinking: false,
                    semantic_effort: false,
                },
                "{model}"
            );
        }
    }

    #[test]
    fn refreshed_effort_snapshot_flows_into_anthropic_without_adapter_changes() {
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../static-provider-metadata-v1.json")).unwrap();
        document["bundle_revision"] = serde_json::json!("operator-refresh@test-v2");
        document["anthropic_messages"]["effort"]["version"] =
            serde_json::json!("anthropic-effort-beta@test-v2");
        document["anthropic_messages"]["effort"]["beta_header"] =
            serde_json::json!("effort-test-v2");
        document["anthropic_messages"]["effort"]["models"] =
            serde_json::json!(["claude-test-effort"]);
        crate::StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let metadata = std::sync::Arc::new(
            crate::StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap(),
        );
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap())
                .unwrap()
                .with_static_metadata(metadata.clone());
        assert_eq!(
            metadata.anthropic_effort_header("claude-test-effort-20260720"),
            Some("effort-test-v2")
        );
        assert_eq!(
            provider.effort_application(&request("claude-test-effort-20260720")),
            EffortApplication::Exact {
                requested: iteron_protocol::ReasoningEffort::Medium,
            }
        );
        assert_eq!(
            provider.effort_application(&request("claude-opus-4-7")),
            EffortApplication::BudgetBased {
                requested: iteron_protocol::ReasoningEffort::Medium,
                budget_tokens: 9_000,
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
                requested: iteron_protocol::ReasoningEffort::Medium
            }
        );
        assert_eq!(
            provider.effort_application(&request("claude-sonnet-4-5")),
            EffortApplication::BudgetBased {
                requested: iteron_protocol::ReasoningEffort::Medium,
                budget_tokens: 9_000
            }
        );
    }

    #[test]
    fn anthropic_wire_gateway_caches_and_the_operator_opt_out_suppresses_it() {
        // Audited on origin/main: prompt caching required the exact api.anthropic.com root, so a
        // gateway speaking the same Messages wire re-sent the entire prefill uncached every turn
        // (95000 uncached prefill tokens in one measured turn).
        let root = ApiRoot::parse("https://gateway.test/anthropic").unwrap();
        let gateway = Anthropic::with_root("key".into(), root.clone()).unwrap();
        assert_eq!(gateway.error_profile, ErrorProfile::CustomConservative);
        let cached = gateway.body(&conversation("kimi-k2-turbo", 3)).unwrap();
        assert_eq!(cached["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(breakpoint_indices(&cached), vec![1]);
        // Wire compatibility still buys the gateway nothing it was not measured to have.
        assert!(cached.get("thinking").is_none());
        assert!(cached.get("output_config").is_none());

        // The opt-out is the operator declaring that this endpoint rejects `cache_control`, and
        // it must clear every breakpoint, not just the system one.
        let opted_out = Anthropic::with_root("key".into(), root)
            .unwrap()
            .with_prompt_cache(false);
        let plain = opted_out.body(&conversation("kimi-k2-turbo", 3)).unwrap();
        assert!(plain["system"].is_string());
        assert!(!plain.to_string().contains("cache_control"));
    }

    #[test]
    fn transcript_carries_a_rolling_breakpoint_behind_the_newest_turn() {
        // Audited on origin/main: the only breakpoint sat on the system block, so by turn five
        // the transcript was over 90% of the request and none of it was cached.
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap()).unwrap();

        let body = provider
            .body(&conversation("claude-sonnet-4-5", 5))
            .unwrap();
        assert_eq!(
            breakpoint_indices(&body),
            vec![3],
            "the breakpoint belongs on the second-to-last message: it covers every prior turn \
             and leaves only the newest turn uncached"
        );
        assert_eq!(
            body["messages"][3]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert_eq!(
            body.to_string().matches("cache_control").count(),
            2,
            "system prefix + rolling transcript, well inside the four-breakpoint limit"
        );

        // It rolls: one more turn moves the breakpoint forward by one message.
        let next = provider
            .body(&conversation("claude-sonnet-4-5", 6))
            .unwrap();
        assert_eq!(breakpoint_indices(&next), vec![4]);

        // Nothing sits behind a single-message transcript, so it carries no breakpoint.
        let first = provider
            .body(&conversation("claude-sonnet-4-5", 1))
            .unwrap();
        assert_eq!(breakpoint_indices(&first), Vec::<usize>::new());
        assert_eq!(first.to_string().matches("cache_control").count(), 1);

        // A caller that turned caching off gets neither breakpoint.
        let mut uncached = conversation("claude-sonnet-4-5", 5);
        uncached.cache_system = false;
        let uncached = provider.body(&uncached).unwrap();
        assert!(!uncached.to_string().contains("cache_control"));
    }

    #[test]
    fn rolling_breakpoint_lands_on_a_replayed_native_assistant_message() {
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap())
                .unwrap()
                .with_route_scope("anthropic-a".into())
                .unwrap();
        let mut request = conversation("claude-sonnet-4-5", 3);
        request.messages[1] = Message {
            role: Role::Assistant,
            content: vec![Block::ProviderState(ProviderState {
                route_scope: "anthropic-a".into(),
                format: ANTHROPIC_CONTENT_BLOCKS_FORMAT.into(),
                payload: serde_json::json!([
                    {"type":"thinking","thinking":"private reasoning","signature":"sig"},
                    {"type":"text","text":"replayed"}
                ]),
            })],
        };
        let body = provider.body(&request).unwrap();
        assert_eq!(breakpoint_indices(&body), vec![1]);
        // Marking the breakpoint must not disturb the replayed blocks themselves.
        assert_eq!(
            body["messages"][1]["content"][0]["thinking"],
            "private reasoning"
        );
        assert_eq!(
            body["messages"][1]["content"][1],
            serde_json::json!({
                "type":"text","text":"replayed","cache_control":{"type":"ephemeral"}
            })
        );
    }

    #[test]
    fn rolling_breakpoint_never_lands_on_a_replayed_reasoning_block() {
        // A turn that stops on refusal or pause after thinking, or that ends on a
        // `redacted_thinking` block, replays native content whose last block is a reasoning
        // block. `cache_control` is not in that block's key set — the wire rejects the whole
        // request — so the breakpoint has to step back to the last block that can hold it.
        let provider =
            Anthropic::with_root("key".into(), ApiRoot::parse(DEFAULT_API_ROOT).unwrap())
                .unwrap()
                .with_route_scope("anthropic-a".into())
                .unwrap();
        let replayed = |payload: serde_json::Value| Message {
            role: Role::Assistant,
            content: vec![Block::ProviderState(ProviderState {
                route_scope: "anthropic-a".into(),
                format: ANTHROPIC_CONTENT_BLOCKS_FORMAT.into(),
                payload,
            })],
        };

        let mut request = conversation("claude-sonnet-4-5", 3);
        request.messages[1] = replayed(serde_json::json!([
            {"type":"text","text":"replayed"},
            {"type":"thinking","thinking":"private reasoning","signature":"sig"},
            {"type":"redacted_thinking","data":"opaque"}
        ]));
        let body = provider.body(&request).unwrap();
        let blocks = body["messages"][1]["content"].as_array().unwrap();
        assert_eq!(
            blocks[0],
            serde_json::json!({
                "type":"text","text":"replayed","cache_control":{"type":"ephemeral"}
            }),
            "the breakpoint belongs on the last block that can carry it"
        );
        for kind in ["thinking", "redacted_thinking"] {
            let reasoning = blocks
                .iter()
                .find(|block| block["type"] == kind)
                .unwrap_or_else(|| panic!("{kind} must survive the replay"));
            assert!(
                reasoning.get("cache_control").is_none(),
                "{kind} has a closed key set on the wire and rejects cache_control"
            );
        }
        // Still exactly two: system prefix plus the rolling transcript breakpoint.
        assert_eq!(body.to_string().matches("cache_control").count(), 2);

        // Nothing in the message can carry it, so that turn caches the system prefix only
        // rather than sending a request the wire will reject.
        let mut reasoning_only = conversation("claude-sonnet-4-5", 3);
        reasoning_only.messages[1] = replayed(serde_json::json!([
            {"type":"thinking","thinking":"private reasoning","signature":"sig"}
        ]));
        let body = provider.body(&reasoning_only).unwrap();
        assert_eq!(breakpoint_indices(&body), Vec::<usize>::new());
        assert_eq!(body.to_string().matches("cache_control").count(), 1);
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
                Block::ToolUse(iteron_protocol::ToolUse {
                    id: "tool-1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":"Cargo.toml"}),
                }),
            ],
        };

        let exact = msg_to_json(&message, "anthropic-a", false, &[]).unwrap();
        assert_eq!(exact["content"], native);

        let portable = msg_to_json(&message, "anthropic-b", false, &[]).unwrap();
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
        assert!(msg_to_json(&message, "anthropic-a", false, &[]).is_err());
        assert_eq!(
            msg_to_json(&message, "anthropic-b", false, &[]).unwrap()["content"],
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
            msg_to_json(&message, "anthropic-a", false, &[]).unwrap()["content"],
            serde_json::json!([{"type":"text","text":"visible"}])
        );
    }
}

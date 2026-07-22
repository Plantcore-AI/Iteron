//! Official OpenAI Responses API adapter.
//!
//! This adapter deliberately replays the complete append-only transcript on every request.
//! It does not rely on `previous_response_id`, server-side storage, or hidden conversation
//! state. Function calls become Responses input items and are only considered executable once
//! `response.function_call_arguments.done` supplies the final argument JSON.

use crate::sse::StreamItem;
use crate::{
    AdapterKind, ApiRoot, EffortApplication, ErrorProfile, Provider, ProviderError, TurnRequest,
    TurnResult, UsageReport,
};
use core_protocol::{
    Block, Message, ProviderState, ReasoningEffort, Role, StopReason, ToolUse, Usage,
};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DEFAULT_ROOT: &str = "https://api.openai.com/v1";
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const ERROR_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_SSE_FRAME_BYTES: usize = 32 * 1024 * 1024;
const MAX_ASSEMBLED_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_OUTPUT_ITEMS: usize = 4096;
const MAX_FUNCTION_CALLS: usize = 1024;
const MAX_ROUTE_SCOPE_BYTES: usize = 256;
const MAX_STATE_FORMAT_BYTES: usize = 128;
const MAX_ITEM_ID_BYTES: usize = 1024;
const MAX_FUNCTION_NAME_BYTES: usize = 1024;
const OPENAI_RESPONSES_OUTPUT_FORMAT: &str = "openai.responses.output-items.v1";

static NEXT_DIRECT_SCOPE: AtomicU64 = AtomicU64::new(1);

/// Official OpenAI `/responses` transport. `root` retains any caller-supplied path prefix;
/// `ApiRoot::endpoint` is the single URL-joining authority shared with model discovery.
pub struct OpenAiResponses {
    key: String,
    root: ApiRoot,
    route_scope: String,
    error_profile: ErrorProfile,
    client: reqwest::Client,
}

impl OpenAiResponses {
    pub fn new(key: String, base_url: Option<String>) -> Result<Self, ProviderError> {
        let root = ApiRoot::parse(base_url.as_deref().unwrap_or(DEFAULT_ROOT))?;
        Self::with_root(key, root)
    }

    pub fn with_root(key: String, root: ApiRoot) -> Result<Self, ProviderError> {
        Self::with_transport(key, root, &crate::transport::DefaultHttpTransport)
    }

    /// Build against an exact API root, obtaining the HTTP client from an injected
    /// network-I/O port rather than constructing it inline. `with_root` delegates
    /// here with the default transport (D2-21).
    pub fn with_transport(
        key: String,
        root: ApiRoot,
        transport: &dyn crate::transport::HttpTransport,
    ) -> Result<Self, ProviderError> {
        let client = transport.client()?;
        Ok(Self {
            key,
            route_scope: direct_route_scope(),
            error_profile: if root.as_str() == DEFAULT_ROOT {
                ErrorProfile::OpenAi
            } else {
                ErrorProfile::CustomConservative
            },
            root,
            client,
        })
    }

    pub(crate) fn with_error_profile(mut self, error_profile: ErrorProfile) -> Self {
        self.error_profile = error_profile;
        self
    }

    /// Bind opaque continuation state to a provider-directory instance. A state envelope is
    /// replayed only when this exact scope and the versioned Responses format both match.
    pub fn with_route_scope(mut self, route_scope: String) -> Result<Self, ProviderError> {
        validate_route_scope(&route_scope)?;
        self.route_scope = route_scope;
        Ok(self)
    }

    fn body(&self, request: &TurnRequest) -> Result<serde_json::Value, ProviderError> {
        request_body(request, self.error_profile, &self.route_scope)
    }
}

fn direct_route_scope() -> String {
    let sequence = NEXT_DIRECT_SCOPE.fetch_add(1, Ordering::Relaxed);
    format!("direct-openai-responses-{}-{sequence}", std::process::id())
}

fn validate_route_scope(route_scope: &str) -> Result<(), ProviderError> {
    if route_scope.is_empty()
        || route_scope.len() > MAX_ROUTE_SCOPE_BYTES
        || route_scope.chars().any(char::is_control)
    {
        return Err(ProviderError::Configuration(
            "Responses route scope was empty or invalid".into(),
        ));
    }
    Ok(())
}

fn request_body(
    request: &TurnRequest,
    error_profile: ErrorProfile,
    route_scope: &str,
) -> Result<serde_json::Value, ProviderError> {
    let tools: Vec<serde_json::Value> = request
        .tools
        .iter()
        .map(|tool| {
            serde_json::json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
                "strict": false,
            })
        })
        .collect();

    let mut body = serde_json::json!({
        "model": request.model,
        "instructions": request.system,
        "input": transcript_to_input(&request.messages, route_scope)?,
        // With `store: false` there is no server-side response state to refer back to. OpenAI's
        // stateless continuation contract therefore requires the encrypted reasoning item to be
        // requested, retained, and supplied as a later input item.
        "include": ["reasoning.encrypted_content"],
        "max_output_tokens": request.max_tokens,
        "stream": true,
        "store": false,
    });
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools);
    }
    if let Some(effort) =
        responses_reasoning_effort(error_profile, &request.model, request.reasoning_effort)
    {
        body["reasoning"] = serde_json::json!({"effort": effort.label(), "summary": "auto"});
    }
    Ok(body)
}

/// `reasoning` is an OpenAI Responses capability, not a generic Responses-wire extension. Both
/// the official provider profile and a documented reasoning family are required; ordinary GPT-4
/// models and unknown/custom gateways omit the object rather than risking a rejected request.
fn responses_reasoning_effort(
    error_profile: ErrorProfile,
    model_id: &str,
    requested: ReasoningEffort,
) -> Option<ReasoningEffort> {
    if error_profile != ErrorProfile::OpenAi || !is_openai_reasoning_family(model_id) {
        return None;
    }
    // The adapter's portable, catalog-proven OpenAI enum ends at `high`. Clamp stronger Core
    // values instead of emitting `xhigh`/`max` as unproven labels.
    Some(match requested {
        ReasoningEffort::XHigh | ReasoningEffort::Max => ReasoningEffort::High,
        supported => supported,
    })
}

fn responses_effort_application(
    error_profile: ErrorProfile,
    model_id: &str,
    requested: ReasoningEffort,
) -> EffortApplication {
    if let Some(sent) = responses_reasoning_effort(error_profile, model_id, requested) {
        if sent == requested {
            EffortApplication::Exact { requested }
        } else {
            EffortApplication::Mapped { requested, sent }
        }
    } else {
        EffortApplication::Unsupported { requested }
    }
}

fn is_openai_reasoning_family(model_id: &str) -> bool {
    ["o1", "o3", "o4", "gpt-5", "codex"]
        .into_iter()
        .any(|family| crate::model_matches_family(model_id, family))
}

/// Preserve transcript order by flushing contiguous text around function-call items. Thinking
/// blocks cannot be replayed safely: the protocol does not retain the Responses reasoning item
/// id/encrypted payload, so turning them into visible assistant text would leak chain of thought.
fn transcript_to_input(
    messages: &[Message],
    route_scope: &str,
) -> Result<Vec<serde_json::Value>, ProviderError> {
    validate_route_scope(route_scope)?;
    let mut input = Vec::new();
    for message in messages {
        if message.role == Role::Assistant
            && let Some(native_output) = matching_native_output(message, route_scope)?
        {
            input.extend(native_output);
            continue;
        }
        let mut text_parts: Vec<serde_json::Value> = Vec::new();
        for block in &message.content {
            match block {
                Block::Text { text } => text_parts.push(match message.role {
                    Role::User => serde_json::json!({"type": "input_text", "text": text}),
                    Role::Assistant => {
                        serde_json::json!({"type": "output_text", "text": text})
                    }
                }),
                Block::Thinking { .. } => {}
                Block::ProviderState(_) => {}
                Block::ToolUse(tool_use) => {
                    flush_message_text(message.role, &mut text_parts, &mut input);
                    input.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": tool_use.id,
                        "name": tool_use.name,
                        "arguments": tool_use.input.to_string(),
                    }));
                }
                Block::ToolResult(result) => {
                    flush_message_text(message.role, &mut text_parts, &mut input);
                    input.push(serde_json::json!({
                        "type": "function_call_output",
                        "call_id": result.tool_use_id,
                        "output": result.content,
                    }));
                }
            }
        }
        flush_message_text(message.role, &mut text_parts, &mut input);
    }
    Ok(input)
}

fn matching_native_output(
    message: &Message,
    route_scope: &str,
) -> Result<Option<Vec<serde_json::Value>>, ProviderError> {
    let mut matching = None;
    for block in &message.content {
        let Block::ProviderState(state) = block else {
            continue;
        };
        if state.route_scope != route_scope || state.format != OPENAI_RESPONSES_OUTPUT_FORMAT {
            continue;
        }
        validate_state_envelope_bounds(state)?;
        if matching.is_some() {
            return Err(ProviderError::Decode(
                "assistant message contained duplicate matching provider state".into(),
            ));
        }
        let items = state.payload.as_array().ok_or_else(|| {
            ProviderError::Decode("Responses provider state payload was not an array".into())
        })?;
        validate_native_output(items, false)?;
        matching = Some(items.clone());
    }
    Ok(matching)
}

fn flush_message_text(
    role: Role,
    content: &mut Vec<serde_json::Value>,
    input: &mut Vec<serde_json::Value>,
) {
    if content.is_empty() {
        return;
    }
    input.push(serde_json::json!({
        "type": "message",
        "role": match role { Role::User => "user", Role::Assistant => "assistant" },
        "content": std::mem::take(content),
    }));
}

#[derive(Debug)]
struct WireFrame {
    event: Option<String>,
    data: String,
}

#[derive(Default)]
struct SseDecoder {
    pending: Vec<u8>,
    total_bytes: usize,
}

impl SseDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<WireFrame>, ProviderError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ProviderError::Decode("Responses stream byte count overflow".into()))?;
        if self.total_bytes > MAX_STREAM_BYTES {
            return Err(ProviderError::Decode(format!(
                "Responses stream exceeded {MAX_STREAM_BYTES} bytes"
            )));
        }
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some((boundary, separator_len)) = frame_boundary(&self.pending) {
            if boundary > MAX_SSE_FRAME_BYTES {
                return Err(ProviderError::Decode(format!(
                    "Responses SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                )));
            }
            let block = self.pending[..boundary].to_vec();
            self.pending.drain(..boundary + separator_len);
            if let Some(frame) = parse_wire_frame(&block)? {
                frames.push(frame);
            }
        }
        if self.pending.len() > MAX_SSE_FRAME_BYTES {
            return Err(ProviderError::Decode(format!(
                "Responses SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
            )));
        }
        Ok(frames)
    }

    fn finish(&self) -> Result<(), ProviderError> {
        if self.pending.iter().all(u8::is_ascii_whitespace) {
            Ok(())
        } else {
            Err(ProviderError::Decode(
                "Responses stream ended with an incomplete SSE frame".into(),
            ))
        }
    }

    /// A terminal Responses event is authoritative, so the transport does not wait for the
    /// optional `[DONE]` sentinel. If the network chunk also began that sentinel, accept only a
    /// byte-for-byte prefix of its legal SSE encoding; arbitrary post-terminal bytes still fail
    /// closed.
    fn finish_after_terminal(&self) -> Result<(), ProviderError> {
        if self.pending.iter().all(u8::is_ascii_whitespace)
            || DONE_FRAME_ENCODINGS
                .iter()
                .any(|encoding| encoding.starts_with(&self.pending))
        {
            Ok(())
        } else {
            Err(ProviderError::Decode(
                "Responses stream contained invalid partial data after terminal event".into(),
            ))
        }
    }
}

const DONE_FRAME_ENCODINGS: &[&[u8]] = &[
    b"data: [DONE]\n\n",
    b"data:[DONE]\n\n",
    b"data: [DONE]\r\n\r\n",
    b"data:[DONE]\r\n\r\n",
];

fn frame_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for (needle, len) in [(&b"\r\n\r\n"[..], 4), (&b"\n\n"[..], 2), (&b"\r\r"[..], 2)] {
        if let Some(index) = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            && best.is_none_or(|(current, _)| index < current)
        {
            best = Some((index, len));
        }
    }
    best
}

fn parse_wire_frame(block: &[u8]) -> Result<Option<WireFrame>, ProviderError> {
    let text = std::str::from_utf8(block).map_err(|error| {
        ProviderError::Decode(format!("Responses SSE frame was not valid UTF-8: {error}"))
    })?;
    let mut event = None;
    let mut data = Vec::new();
    for line in text.split(['\r', '\n']).filter(|line| !line.is_empty()) {
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = Some(value.to_string()),
            "data" => data.push(value),
            "id" | "retry" => {}
            _ => {}
        }
    }
    if data.is_empty() {
        return Ok(None);
    }
    Ok(Some(WireFrame {
        event,
        data: data.join("\n"),
    }))
}

#[derive(Default)]
struct OutputAcc {
    text: BTreeMap<u64, String>,
    thinking: BTreeMap<(u8, u64), String>,
    tool: Option<ToolUse>,
    refusal: bool,
}

struct FunctionMeta {
    call_id: String,
    name: String,
    output_index: u64,
}

struct ResponseParser {
    outputs: BTreeMap<u64, OutputAcc>,
    functions: HashMap<String, FunctionMeta>,
    done_items: HashSet<String>,
    done_call_ids: HashSet<String>,
    output_bytes: usize,
    terminal: bool,
    saw_done_marker: bool,
    native_output: Vec<serde_json::Value>,
    route_scope: String,
    error_profile: ErrorProfile,
}

impl Default for ResponseParser {
    fn default() -> Self {
        Self::with_route_scope(ErrorProfile::OpenAi, "test-openai-responses".into())
            .expect("fixed test route scope is valid")
    }
}

impl ResponseParser {
    fn with_route_scope(
        error_profile: ErrorProfile,
        route_scope: String,
    ) -> Result<Self, ProviderError> {
        validate_route_scope(&route_scope)?;
        Ok(Self {
            outputs: BTreeMap::new(),
            functions: HashMap::new(),
            done_items: HashSet::new(),
            done_call_ids: HashSet::new(),
            output_bytes: 0,
            terminal: false,
            saw_done_marker: false,
            native_output: Vec::new(),
            route_scope,
            error_profile,
        })
    }

    fn push_frame(
        &mut self,
        frame: WireFrame,
        response_retry_after: Option<Duration>,
        response_request_id: Option<&str>,
    ) -> Result<Vec<StreamItem>, ProviderError> {
        if frame.data.trim() == "[DONE]" {
            if self.saw_done_marker {
                return Err(ProviderError::Decode(
                    "Responses stream emitted duplicate [DONE] markers".into(),
                ));
            }
            self.saw_done_marker = true;
            return Ok(Vec::new());
        }
        if self.saw_done_marker {
            return Err(ProviderError::Decode(
                "Responses stream emitted data after [DONE]".into(),
            ));
        }
        if self.terminal {
            return Err(ProviderError::Decode(
                "Responses stream emitted data after a terminal event".into(),
            ));
        }

        let value: serde_json::Value = serde_json::from_str(&frame.data).map_err(|error| {
            ProviderError::Decode(format!("malformed Responses SSE JSON: {error}"))
        })?;
        let event_type = required_str(&value, "type")?;
        if let Some(wire_event) = frame.event.as_deref()
            && wire_event != "message"
            && wire_event != event_type
        {
            return Err(ProviderError::Decode(
                "Responses SSE event/data type mismatch".into(),
            ));
        }

        match event_type {
            "response.output_text.delta" | "response.refusal.delta" => {
                let delta = required_str(&value, "delta")?;
                let output_index = required_u64(&value, "output_index")?;
                let content_index = required_u64(&value, "content_index")?;
                if event_type == "response.refusal.delta" {
                    self.mark_refusal(output_index)?;
                }
                self.append_text(output_index, content_index, delta)?;
                Ok(vec![StreamItem::TextDelta(delta.to_string())])
            }
            "response.reasoning_summary_text.delta" => {
                let delta = required_str(&value, "delta")?;
                let output_index = required_u64(&value, "output_index")?;
                let content_index = required_u64(&value, "content_index")?;
                self.append_thinking(output_index, 0, content_index, delta)?;
                Ok(vec![StreamItem::ThinkingDelta(delta.to_string())])
            }
            "response.reasoning_text.delta" => {
                let delta = required_str(&value, "delta")?;
                let output_index = required_u64(&value, "output_index")?;
                let content_index = required_u64(&value, "content_index")?;
                self.append_thinking(output_index, 1, content_index, delta)?;
                Ok(vec![StreamItem::ThinkingDelta(delta.to_string())])
            }
            "response.output_item.added" => {
                self.remember_output_item(&value)?;
                Ok(Vec::new())
            }
            "response.function_call_arguments.delta" => {
                // Deliberately do not accumulate or parse fragments. The authoritative, bounded
                // arguments arrive in `.done`; using both paths is how duplicate tool dispatches
                // and partial-JSON execution happen.
                let item_id = required_str(&value, "item_id")?;
                let _ = required_str(&value, "delta")?;
                if self.done_items.contains(item_id) {
                    return Err(ProviderError::Decode(
                        "function argument delta arrived after done".into(),
                    ));
                }
                Ok(Vec::new())
            }
            "response.function_call_arguments.done" => self.finish_function_call(&value),
            "response.completed" => {
                self.finish_response(&value, false, response_retry_after, response_request_id)
            }
            "response.incomplete" => {
                self.finish_response(&value, true, response_retry_after, response_request_id)
            }
            "response.failed" | "response.cancelled" => Err(stream_failure(
                self.error_profile,
                &value,
                response_retry_after,
                response_request_id,
            )),
            "error" => Err(ProviderError::Stream(crate::decode_stream_error_for(
                AdapterKind::OpenAiResponses,
                self.error_profile,
                "openai-responses",
                &frame.data,
                response_retry_after,
                response_request_id.map(str::to_owned),
            ))),
            // Lifecycle and final-value events carry no additional information needed by this
            // adapter. Their corresponding deltas/terminal response remain authoritative.
            "response.created"
            | "response.queued"
            | "response.in_progress"
            | "response.output_item.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.output_text.done"
            | "response.refusal.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done"
            | "response.reasoning_summary_text.done"
            | "response.reasoning_text.done" => Ok(Vec::new()),
            // Responses adds event types over time. Unknown nonterminal notifications are safe
            // to ignore because completion is reconciled against the authoritative output array;
            // unknown output item kinds fail closed there instead of becoming an empty success.
            _ => Ok(Vec::new()),
        }
    }

    fn reserve_output(&mut self, output_index: u64) -> Result<(), ProviderError> {
        if !self.outputs.contains_key(&output_index) && self.outputs.len() >= MAX_OUTPUT_ITEMS {
            return Err(ProviderError::Decode(format!(
                "Responses output exceeded {MAX_OUTPUT_ITEMS} items"
            )));
        }
        self.outputs.entry(output_index).or_default();
        Ok(())
    }

    fn reserve_bytes(&mut self, additional: usize) -> Result<(), ProviderError> {
        self.output_bytes = self
            .output_bytes
            .checked_add(additional)
            .ok_or_else(|| ProviderError::Decode("Responses output byte count overflow".into()))?;
        if self.output_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
            return Err(ProviderError::Decode(format!(
                "Responses assembled output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn append_text(
        &mut self,
        output_index: u64,
        content_index: u64,
        delta: &str,
    ) -> Result<(), ProviderError> {
        self.reserve_output(output_index)?;
        self.reserve_bytes(delta.len())?;
        self.outputs
            .get_mut(&output_index)
            .ok_or_else(|| ProviderError::Decode("Responses output state was inconsistent".into()))?
            .text
            .entry(content_index)
            .or_default()
            .push_str(delta);
        Ok(())
    }

    fn append_thinking(
        &mut self,
        output_index: u64,
        kind: u8,
        content_index: u64,
        delta: &str,
    ) -> Result<(), ProviderError> {
        self.reserve_output(output_index)?;
        self.reserve_bytes(delta.len())?;
        self.outputs
            .get_mut(&output_index)
            .ok_or_else(|| ProviderError::Decode("Responses output state was inconsistent".into()))?
            .thinking
            .entry((kind, content_index))
            .or_default()
            .push_str(delta);
        Ok(())
    }

    fn remember_output_item(&mut self, value: &serde_json::Value) -> Result<(), ProviderError> {
        let item = value.get("item").ok_or_else(|| {
            ProviderError::Decode("response.output_item.added lacked item".into())
        })?;
        if item.get("type").and_then(serde_json::Value::as_str) != Some("function_call") {
            return Ok(());
        }
        if self.functions.len() >= MAX_FUNCTION_CALLS {
            return Err(ProviderError::Decode(format!(
                "Responses output exceeded {MAX_FUNCTION_CALLS} function calls"
            )));
        }
        let item_id = required_str(item, "id")?.to_string();
        let call_id = required_str(item, "call_id")?.to_string();
        let name = required_str(item, "name")?.to_string();
        let output_index = required_u64(value, "output_index")?;
        if item_id.is_empty() || call_id.is_empty() || name.is_empty() {
            return Err(ProviderError::Decode(
                "Responses function call metadata contained an empty id or name".into(),
            ));
        }
        if self
            .functions
            .insert(
                item_id.clone(),
                FunctionMeta {
                    call_id,
                    name,
                    output_index,
                },
            )
            .is_some()
        {
            return Err(ProviderError::Decode(
                "duplicate Responses function item".into(),
            ));
        }
        self.reserve_output(output_index)
    }

    fn finish_function_call(
        &mut self,
        value: &serde_json::Value,
    ) -> Result<Vec<StreamItem>, ProviderError> {
        let item_id = required_str(value, "item_id")?;
        if self.done_items.contains(item_id) {
            return Err(ProviderError::Decode(
                "duplicate function_call_arguments.done".into(),
            ));
        }
        let (meta_call_id, meta_name, meta_output_index) = {
            let meta = self.functions.get(item_id).ok_or_else(|| {
                ProviderError::Decode("function_call_arguments.done lacked prior metadata".into())
            })?;
            (meta.call_id.clone(), meta.name.clone(), meta.output_index)
        };
        let output_index = required_u64(value, "output_index")?;
        if output_index != meta_output_index {
            return Err(ProviderError::Decode(
                "function call changed output index".into(),
            ));
        }
        let event_name = required_str(value, "name")?;
        if event_name != meta_name {
            return Err(ProviderError::Decode("function call changed name".into()));
        }
        let arguments = required_str(value, "arguments")?;
        let input = parse_arguments(event_name, arguments)?;
        let tool_use = ToolUse {
            id: meta_call_id,
            name: meta_name,
            input,
        };
        let call_id = tool_use.id.clone();
        if !self.done_call_ids.insert(call_id.clone()) {
            return Err(ProviderError::Decode("duplicate Responses call_id".into()));
        }
        self.reserve_bytes(arguments.len())?;
        let output = self.outputs.get_mut(&output_index).ok_or_else(|| {
            ProviderError::Decode("Responses function output state was inconsistent".into())
        })?;
        if output.tool.replace(tool_use.clone()).is_some() {
            return Err(ProviderError::Decode(format!(
                "multiple function calls occupied output index {output_index}"
            )));
        }
        self.done_items.insert(item_id.to_string());
        Ok(vec![StreamItem::ToolUseComplete(tool_use)])
    }

    fn finish_response(
        &mut self,
        value: &serde_json::Value,
        incomplete: bool,
        response_retry_after: Option<Duration>,
        response_request_id: Option<&str>,
    ) -> Result<Vec<StreamItem>, ProviderError> {
        let response = value.get("response").ok_or_else(|| {
            ProviderError::Decode("terminal Responses event lacked response".into())
        })?;
        let expected_status = if incomplete {
            "incomplete"
        } else {
            "completed"
        };
        if required_str(response, "status")? != expected_status {
            return Err(ProviderError::Decode(format!(
                "terminal Responses event did not have status {expected_status}"
            )));
        }

        let stop_reason = if incomplete {
            let reason = response
                .pointer("/incomplete_details/reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            if reason != "max_output_tokens" {
                return Err(incomplete_failure(
                    self.error_profile,
                    reason,
                    response_retry_after,
                    response_request_id,
                ));
            }
            StopReason::MaxTokens
        } else {
            StopReason::EndTurn
        };

        self.reconcile_output(response, incomplete)?;
        let has_refusal = self.outputs.values().any(|output| output.refusal);
        let unfinished: Vec<&str> = self
            .functions
            .keys()
            .filter(|item_id| !self.done_items.contains(*item_id))
            .map(String::as_str)
            .collect();
        if !incomplete && !unfinished.is_empty() {
            return Err(ProviderError::Decode(format!(
                "terminal Responses event left {} function call(s) incomplete",
                unfinished.len()
            )));
        }
        let usage = parse_usage(response)?;
        let blocks = self.assemble_blocks();
        let has_tool_use = blocks
            .iter()
            .any(|block| matches!(block, Block::ToolUse(_)));
        if has_refusal && has_tool_use {
            return Err(ProviderError::Decode(
                "Responses terminal mixed a refusal with function calls".into(),
            ));
        }
        let stop_reason = if stop_reason == StopReason::EndTurn && has_refusal {
            StopReason::Refusal
        } else if stop_reason == StopReason::EndTurn && has_tool_use {
            StopReason::ToolUse
        } else {
            stop_reason
        };
        self.terminal = true;
        Ok(vec![StreamItem::TurnComplete {
            blocks,
            stop_reason,
            usage,
        }])
    }

    fn reconcile_output(
        &mut self,
        response: &serde_json::Value,
        allow_incomplete_functions: bool,
    ) -> Result<(), ProviderError> {
        let output = response
            .get("output")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| ProviderError::Decode("terminal response lacked output array".into()))?;
        if output.len() > MAX_OUTPUT_ITEMS {
            return Err(ProviderError::Decode(format!(
                "Responses output exceeded {MAX_OUTPUT_ITEMS} items"
            )));
        }
        validate_native_output(output, allow_incomplete_functions)?;
        let mut native_output = Vec::with_capacity(output.len());
        for (index, item) in output.iter().enumerate() {
            let output_index = index as u64;
            let mut preserve_native_item = true;
            match required_str(item, "type")? {
                "message" => {
                    let content = item
                        .get("content")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| {
                            ProviderError::Decode("Responses message lacked content array".into())
                        })?;
                    for (content_index, part) in content.iter().enumerate() {
                        let part_type = required_str(part, "type")?;
                        let full = match part_type {
                            "output_text" => required_str(part, "text")?,
                            "refusal" => required_str(part, "refusal")?,
                            other => {
                                let _ = other;
                                return Err(ProviderError::Decode(
                                    "unsupported Responses message content type".into(),
                                ));
                            }
                        };
                        if part_type == "refusal" {
                            self.mark_refusal(output_index)?;
                        }
                        self.reconcile_text(output_index, content_index as u64, full)?;
                    }
                }
                "reasoning" => {
                    if let Some(summary) = item.get("summary").and_then(serde_json::Value::as_array)
                    {
                        for (content_index, part) in summary.iter().enumerate() {
                            self.reconcile_thinking(
                                output_index,
                                0,
                                content_index as u64,
                                required_str(part, "text")?,
                            )?;
                        }
                    }
                    if let Some(content) = item.get("content").and_then(serde_json::Value::as_array)
                    {
                        for (content_index, part) in content.iter().enumerate() {
                            self.reconcile_thinking(
                                output_index,
                                1,
                                content_index as u64,
                                required_str(part, "text")?,
                            )?;
                        }
                    }
                }
                "function_call" => {
                    let item_id = required_str(item, "id")?;
                    if !allow_incomplete_functions || self.done_items.contains(item_id) {
                        self.reconcile_function(output_index, item)?;
                    } else {
                        preserve_native_item = false;
                    }
                    // A max_output_tokens terminal may carry an unfinished argument string. It
                    // has no authoritative arguments.done event and is deliberately omitted.
                }
                other => {
                    let _ = other;
                    return Err(ProviderError::Decode(
                        "unsupported Responses output item type".into(),
                    ));
                }
            }
            if preserve_native_item {
                native_output.push(item.clone());
            }
        }
        self.native_output = native_output;
        Ok(())
    }

    fn reconcile_text(
        &mut self,
        output_index: u64,
        content_index: u64,
        full: &str,
    ) -> Result<(), ProviderError> {
        self.reserve_output(output_index)?;
        let existing = self.outputs[&output_index].text.get(&content_index);
        if let Some(existing) = existing {
            if existing != full {
                return Err(ProviderError::Decode(
                    "Responses completed text disagreed with streamed deltas".into(),
                ));
            }
            return Ok(());
        }
        self.reserve_bytes(full.len())?;
        self.outputs
            .get_mut(&output_index)
            .ok_or_else(|| ProviderError::Decode("Responses output state was inconsistent".into()))?
            .text
            .insert(content_index, full.to_string());
        Ok(())
    }

    fn mark_refusal(&mut self, output_index: u64) -> Result<(), ProviderError> {
        self.reserve_output(output_index)?;
        self.outputs
            .get_mut(&output_index)
            .ok_or_else(|| ProviderError::Decode("Responses output state was inconsistent".into()))?
            .refusal = true;
        Ok(())
    }

    fn reconcile_thinking(
        &mut self,
        output_index: u64,
        kind: u8,
        content_index: u64,
        full: &str,
    ) -> Result<(), ProviderError> {
        self.reserve_output(output_index)?;
        let key = (kind, content_index);
        let existing = self.outputs[&output_index].thinking.get(&key);
        if let Some(existing) = existing {
            if existing != full {
                return Err(ProviderError::Decode(
                    "Responses completed reasoning disagreed with streamed deltas".into(),
                ));
            }
            return Ok(());
        }
        self.reserve_bytes(full.len())?;
        self.outputs
            .get_mut(&output_index)
            .ok_or_else(|| ProviderError::Decode("Responses output state was inconsistent".into()))?
            .thinking
            .insert(key, full.to_string());
        Ok(())
    }

    fn reconcile_function(
        &self,
        output_index: u64,
        item: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        let call_id = required_str(item, "call_id")?;
        let name = required_str(item, "name")?;
        let arguments = required_str(item, "arguments")?;
        let expected = parse_arguments(name, arguments)?;
        let streamed = self
            .outputs
            .get(&output_index)
            .and_then(|output| output.tool.as_ref())
            .ok_or_else(|| {
                ProviderError::Decode(
                    "completed function call lacked function_call_arguments.done".into(),
                )
            })?;
        if streamed.id != call_id || streamed.name != name || streamed.input != expected {
            return Err(ProviderError::Decode(
                "completed function call disagreed with streamed done event".into(),
            ));
        }
        Ok(())
    }

    fn assemble_blocks(&self) -> Vec<Block> {
        let mut blocks = Vec::new();
        if !self.native_output.is_empty() {
            blocks.push(Block::ProviderState(ProviderState {
                route_scope: self.route_scope.clone(),
                format: OPENAI_RESPONSES_OUTPUT_FORMAT.into(),
                payload: serde_json::Value::Array(self.native_output.clone()),
            }));
        }
        for output in self.outputs.values() {
            let thinking = output
                .thinking
                .values()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            if !thinking.is_empty() {
                blocks.push(Block::Thinking { thinking });
            }
            let text = output.text.values().cloned().collect::<String>();
            if !text.is_empty() {
                blocks.push(Block::Text { text });
            }
            if let Some(tool) = &output.tool {
                blocks.push(Block::ToolUse(tool.clone()));
            }
        }
        blocks
    }

    fn finish(&self) -> Result<(), ProviderError> {
        if !self.terminal {
            return Err(ProviderError::Decode(
                "Responses stream ended before a terminal event".into(),
            ));
        }
        Ok(())
    }
}

fn validate_state_envelope_bounds(state: &ProviderState) -> Result<(), ProviderError> {
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
    let encoded = serde_json::to_vec(&state.payload)
        .map_err(|_| ProviderError::Decode("provider state payload could not be encoded".into()))?;
    if encoded.len() > MAX_ASSEMBLED_OUTPUT_BYTES {
        return Err(ProviderError::Decode(format!(
            "provider state payload exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_native_output(
    output: &[serde_json::Value],
    allow_incomplete_functions: bool,
) -> Result<(), ProviderError> {
    if output.len() > MAX_OUTPUT_ITEMS {
        return Err(ProviderError::Decode(format!(
            "Responses output exceeded {MAX_OUTPUT_ITEMS} items"
        )));
    }
    let encoded = serde_json::to_vec(output)
        .map_err(|_| ProviderError::Decode("Responses output could not be encoded".into()))?;
    if encoded.len() > MAX_ASSEMBLED_OUTPUT_BYTES {
        return Err(ProviderError::Decode(format!(
            "Responses native output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
        )));
    }

    let mut function_calls = 0usize;
    for item in output {
        validate_bounded_string(
            required_str(item, "id")?,
            MAX_ITEM_ID_BYTES,
            "output item id",
        )?;
        match required_str(item, "type")? {
            "message" => validate_native_message(item)?,
            "reasoning" => validate_native_reasoning(item)?,
            "function_call" => {
                function_calls = function_calls.checked_add(1).ok_or_else(|| {
                    ProviderError::Decode("Responses function count overflow".into())
                })?;
                if function_calls > MAX_FUNCTION_CALLS {
                    return Err(ProviderError::Decode(format!(
                        "Responses output exceeded {MAX_FUNCTION_CALLS} function calls"
                    )));
                }
                validate_bounded_string(
                    required_str(item, "call_id")?,
                    MAX_ITEM_ID_BYTES,
                    "function call id",
                )?;
                let name = required_str(item, "name")?;
                validate_bounded_string(name, MAX_FUNCTION_NAME_BYTES, "function name")?;
                let arguments = required_str(item, "arguments")?;
                if arguments.len() > MAX_ASSEMBLED_OUTPUT_BYTES {
                    return Err(ProviderError::Decode(
                        "Responses function arguments exceeded their byte bound".into(),
                    ));
                }
                let incomplete =
                    item.get("status").and_then(serde_json::Value::as_str) == Some("incomplete");
                if !allow_incomplete_functions || !incomplete {
                    let _ = parse_arguments(name, arguments)?;
                }
            }
            _ => {
                return Err(ProviderError::Decode(
                    "unsupported Responses output item type".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_native_message(item: &serde_json::Value) -> Result<(), ProviderError> {
    if required_str(item, "role")? != "assistant" {
        return Err(ProviderError::Decode(
            "Responses output message did not have assistant role".into(),
        ));
    }
    if let Some(phase) = item.get("phase")
        && !phase.is_null()
    {
        validate_bounded_string(
            phase.as_str().ok_or_else(|| {
                ProviderError::Decode("Responses message phase was not a string".into())
            })?,
            64,
            "message phase",
        )?;
    }
    let content = item
        .get("content")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ProviderError::Decode("Responses message lacked content array".into()))?;
    if content.len() > MAX_OUTPUT_ITEMS {
        return Err(ProviderError::Decode(
            "Responses message content exceeded its item bound".into(),
        ));
    }
    for part in content {
        match required_str(part, "type")? {
            "output_text" => {
                let _ = required_str(part, "text")?;
            }
            "refusal" => {
                let _ = required_str(part, "refusal")?;
            }
            _ => {
                return Err(ProviderError::Decode(
                    "unsupported Responses message content type".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_native_reasoning(item: &serde_json::Value) -> Result<(), ProviderError> {
    let encrypted = required_str(item, "encrypted_content")?;
    if encrypted.is_empty() || encrypted.len() > MAX_ASSEMBLED_OUTPUT_BYTES {
        return Err(ProviderError::Decode(
            "Responses reasoning lacked bounded encrypted continuation content".into(),
        ));
    }
    for (field, expected_type) in [("summary", "summary_text"), ("content", "reasoning_text")] {
        let Some(parts) = item.get(field).filter(|parts| !parts.is_null()) else {
            continue;
        };
        let parts = parts.as_array().ok_or_else(|| {
            ProviderError::Decode(format!("Responses reasoning {field} was not an array"))
        })?;
        if parts.len() > MAX_OUTPUT_ITEMS {
            return Err(ProviderError::Decode(format!(
                "Responses reasoning {field} exceeded its item bound"
            )));
        }
        for part in parts {
            if required_str(part, "type")? != expected_type {
                return Err(ProviderError::Decode(format!(
                    "Responses reasoning {field} had an unsupported part type"
                )));
            }
            let _ = required_str(part, "text")?;
        }
    }
    Ok(())
}

fn validate_bounded_string(
    value: &str,
    max_bytes: usize,
    label: &str,
) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ProviderError::Decode(format!(
            "Responses {label} was empty or exceeded its bound"
        )));
    }
    Ok(())
}

fn required_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, ProviderError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProviderError::Decode(format!("Responses event lacked string {field}")))
}

fn required_u64(value: &serde_json::Value, field: &str) -> Result<u64, ProviderError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ProviderError::Decode(format!("Responses event lacked integer {field}")))
}

fn parse_arguments(_name: &str, arguments: &str) -> Result<serde_json::Value, ProviderError> {
    if arguments.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(arguments).map_err(|error| {
        ProviderError::Decode(format!("tool arguments were not valid JSON: {error}"))
    })
}

fn parse_usage(response: &serde_json::Value) -> Result<UsageReport, ProviderError> {
    let Some(usage) = response.get("usage").filter(|usage| !usage.is_null()) else {
        return Ok(UsageReport::provider_omitted());
    };
    let total_input = required_u64(usage, "input_tokens")?;
    let cache_read = optional_nested_u64(usage, "/input_tokens_details/cached_tokens")?;
    let input = total_input.checked_sub(cache_read).ok_or_else(|| {
        ProviderError::Decode("Responses cached tokens exceeded total input tokens".into())
    })?;
    Ok(UsageReport::complete(Usage {
        input,
        output: required_u64(usage, "output_tokens")?,
        cache_creation: 0,
        cache_read,
        thinking: optional_nested_u64(usage, "/output_tokens_details/reasoning_tokens")?,
    }))
}

fn optional_nested_u64(value: &serde_json::Value, pointer: &str) -> Result<u64, ProviderError> {
    let Some(token) = value.pointer(pointer) else {
        return Ok(0);
    };
    token.as_u64().ok_or_else(|| {
        ProviderError::Decode(format!(
            "Responses usage field {pointer} was not an unsigned integer"
        ))
    })
}

fn stream_failure(
    error_profile: ErrorProfile,
    value: &serde_json::Value,
    response_retry_after: Option<Duration>,
    response_request_id: Option<&str>,
) -> ProviderError {
    let detail = value
        .pointer("/response/error")
        .or_else(|| value.get("error"))
        .cloned()
        .unwrap_or_else(
            || serde_json::json!({"code":"response_failed","message":"response generation failed"}),
        );
    let envelope = serde_json::json!({"error": detail}).to_string();
    ProviderError::Stream(crate::decode_stream_error_for(
        AdapterKind::OpenAiResponses,
        error_profile,
        "openai-responses",
        &envelope,
        response_retry_after,
        response_request_id.map(str::to_owned),
    ))
}

fn incomplete_failure(
    error_profile: ErrorProfile,
    reason: &str,
    response_retry_after: Option<Duration>,
    response_request_id: Option<&str>,
) -> ProviderError {
    let envelope = serde_json::json!({
        "error": {
            "code": reason,
            "message": "response generation ended incomplete"
        }
    })
    .to_string();
    ProviderError::Stream(crate::decode_stream_error_for(
        AdapterKind::OpenAiResponses,
        error_profile,
        "openai-responses",
        &envelope,
        response_retry_after,
        response_request_id.map(str::to_owned),
    ))
}

#[async_trait::async_trait]
impl Provider for OpenAiResponses {
    fn effort_application(&self, request: &TurnRequest) -> EffortApplication {
        responses_effort_application(self.error_profile, &request.model, request.reasoning_effort)
    }

    async fn turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let deadline = Instant::now() + STREAM_TOTAL_TIMEOUT;
        let endpoint = self.root.endpoint("responses")?;
        let body = self.body(request)?;
        let request = self
            .client
            .post(endpoint)
            .bearer_auth(&self.key)
            .header("content-type", "application/json")
            .json(&body);
        let header_timeout =
            remaining_timeout(deadline, RESPONSE_HEADER_TIMEOUT, "response headers")?;
        let response = tokio::time::timeout(header_timeout, request.send())
            .await
            .map_err(|_| ProviderError::Http("Responses response headers timed out".into()))?
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        if !response.status().is_success() {
            return Err(tokio::time::timeout(
                remaining_timeout(deadline, ERROR_RESPONSE_TIMEOUT, "error response body")?,
                crate::api_error_from_response(
                    response,
                    AdapterKind::OpenAiResponses,
                    self.error_profile,
                ),
            )
            .await
            .map_err(|_| ProviderError::Http("Responses error response body timed out".into()))?);
        }

        let response_retry_after = crate::retry_after_from_headers(response.headers());
        let response_request_id = crate::request_id_from_headers(response.headers());
        let mut stream = response.bytes_stream();
        let mut decoder = SseDecoder::default();
        let mut parser =
            ResponseParser::with_route_scope(self.error_profile, self.route_scope.clone())?;
        let mut result = None;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProviderError::Http(
                    "Responses stream exceeded total deadline".into(),
                ));
            }
            let wait = remaining.min(STREAM_IDLE_TIMEOUT);
            let next = tokio::time::timeout(wait, stream.next())
                .await
                .map_err(|_| {
                    if wait == remaining {
                        ProviderError::Http("Responses stream exceeded total deadline".into())
                    } else {
                        ProviderError::Http(format!(
                            "Responses stream stalled: no bytes for {}s",
                            STREAM_IDLE_TIMEOUT.as_secs()
                        ))
                    }
                })?;
            let Some(chunk) = next else { break };
            let bytes = chunk.map_err(|error| ProviderError::Http(error.to_string()))?;
            for frame in decoder.push(&bytes)? {
                for item in parser.push_frame(
                    frame,
                    response_retry_after,
                    response_request_id.as_deref(),
                )? {
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
            if result.is_some() {
                // The terminal event is authoritative. A `[DONE]` sentinel may share this chunk
                // or be split at any following byte; validate its partial prefix, then return
                // without waiting for a keep-alive peer to close.
                decoder.finish_after_terminal()?;
                parser.finish()?;
                return result.ok_or_else(|| {
                    ProviderError::Decode(
                        "Responses terminal event lacked an assembled result".into(),
                    )
                });
            }
        }

        decoder.finish()?;
        parser.finish()?;
        result.ok_or_else(|| {
            ProviderError::Decode("Responses stream ended without a completed result".into())
        })
    }
}

fn remaining_timeout(
    deadline: Instant,
    operation_timeout: Duration,
    operation: &str,
) -> Result<Duration, ProviderError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::Http(format!(
            "Responses turn deadline expired before {operation}"
        )));
    }
    Ok(remaining.min(operation_timeout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};

    const TEST_SCOPE: &str = "provider-openai-test";

    fn request() -> TurnRequest {
        TurnRequest {
            model: "gpt-5".into(),
            system: "You are a coding agent.".into(),
            messages: vec![
                Message::user_text("inspect the tree"),
                Message {
                    role: Role::Assistant,
                    content: vec![
                        Block::Thinking {
                            thinking: "not replayable".into(),
                        },
                        Block::Text {
                            text: "I will read it.".into(),
                        },
                        Block::ToolUse(ToolUse {
                            id: "call_1".into(),
                            name: "read_file".into(),
                            input: serde_json::json!({"path":"src/lib.rs"}),
                        }),
                    ],
                },
                Message {
                    role: Role::User,
                    content: vec![Block::ToolResult(ToolResult {
                        tool_use_id: "call_1".into(),
                        content: "fn main() {}".into(),
                        is_error: false,
                        trust: Trust::Workspace,
                        latency_ms: 1,
                    })],
                },
            ],
            tools: vec![ToolSpec {
                name: "read_file".into(),
                description: "Read a workspace file".into(),
                input_schema: serde_json::json!({
                    "type":"object",
                    "properties":{"path":{"type":"string"}},
                    "required":["path"]
                }),
                purity: Purity::Pure,
                capability: Capability::ReadOnly,
            }],
            max_tokens: 12_345,
            cache_system: true,
            thinking_budget: 9_000,
            reasoning_effort: ReasoningEffort::Medium,
        }
    }

    fn frame(value: serde_json::Value) -> WireFrame {
        WireFrame {
            event: value
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            data: value.to_string(),
        }
    }

    fn usage() -> serde_json::Value {
        serde_json::json!({
            "input_tokens": 100,
            "input_tokens_details": {"cached_tokens": 40},
            "output_tokens": 25,
            "output_tokens_details": {"reasoning_tokens": 7},
            "total_tokens": 125
        })
    }

    #[test]
    fn body_is_stateless_responses_shape_with_flat_function_tools() {
        let body = request_body(&request(), ErrorProfile::OpenAi, TEST_SCOPE).unwrap();
        assert_eq!(body["model"], "gpt-5");
        assert_eq!(body["instructions"], "You are a coding agent.");
        assert_eq!(body["max_output_tokens"], 12_345);
        assert_eq!(body["stream"], true);
        assert_eq!(body["store"], false);
        assert_eq!(
            body["include"],
            serde_json::json!(["reasoning.encrypted_content"])
        );
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["reasoning"]["effort"], "medium");
        assert_eq!(body["reasoning"]["summary"], "auto");

        let tool = &body["tools"][0];
        assert_eq!(tool["type"], "function");
        assert_eq!(tool["name"], "read_file");
        assert_eq!(tool["strict"], false);
        assert!(tool.get("function").is_none());

        let input = body["input"].as_array().unwrap();
        assert_eq!(input.len(), 4);
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"][0]["type"], "input_text");
        assert_eq!(input[1]["role"], "assistant");
        assert_eq!(input[1]["content"][0]["type"], "output_text");
        assert_eq!(input[2]["type"], "function_call");
        assert_eq!(input[2]["call_id"], "call_1");
        assert_eq!(input[2]["arguments"], r#"{"path":"src/lib.rs"}"#);
        assert_eq!(input[3]["type"], "function_call_output");
        assert_eq!(input[3]["call_id"], "call_1");
    }

    #[test]
    fn direct_instances_get_non_shared_safe_scopes_and_explicit_scopes_are_bounded() {
        let root = ApiRoot::parse(DEFAULT_ROOT).unwrap();
        let first = OpenAiResponses::with_root("key".into(), root.clone()).unwrap();
        let second = OpenAiResponses::with_root("key".into(), root).unwrap();
        assert_ne!(first.route_scope, second.route_scope);
        assert!(
            OpenAiResponses::new("key".into(), None)
                .unwrap()
                .with_route_scope(TEST_SCOPE.into())
                .is_ok()
        );
        assert!(
            OpenAiResponses::new("key".into(), None)
                .unwrap()
                .with_route_scope("x".repeat(MAX_ROUTE_SCOPE_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn openai_responses_high_effort_wire_matches_mapped_application() {
        let provider = OpenAiResponses::new("test-credential".into(), None).unwrap();

        for requested in [ReasoningEffort::XHigh, ReasoningEffort::Max] {
            let mut request = request();
            request.reasoning_effort = requested;
            let encoded = serde_json::to_vec(&provider.body(&request).unwrap()).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

            assert_eq!(
                wire["reasoning"]["effort"], "high",
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
    fn reasoning_object_requires_official_profile_and_known_family() {
        assert_eq!(
            responses_reasoning_effort(ErrorProfile::OpenAi, "gpt-5", ReasoningEffort::Low),
            Some(ReasoningEffort::Low)
        );
        assert_eq!(
            responses_reasoning_effort(ErrorProfile::OpenAi, "gpt-5", ReasoningEffort::Low),
            Some(ReasoningEffort::Low)
        );
        assert_eq!(
            responses_reasoning_effort(ErrorProfile::OpenAi, "o3-mini", ReasoningEffort::Medium),
            Some(ReasoningEffort::Medium)
        );
        assert_eq!(
            responses_reasoning_effort(
                ErrorProfile::OpenAi,
                "codex-mini-latest",
                ReasoningEffort::High
            ),
            Some(ReasoningEffort::High)
        );
        for model in ["gpt-4.1", "gpt-4o", "gpt-50", "unknown"] {
            assert_eq!(
                responses_reasoning_effort(ErrorProfile::OpenAi, model, ReasoningEffort::Medium),
                None,
                "{model}"
            );
        }
        for profile in [
            ErrorProfile::DeepSeek,
            ErrorProfile::Glm,
            ErrorProfile::MiniMax,
            ErrorProfile::Fireworks,
            ErrorProfile::CustomConservative,
        ] {
            assert_eq!(
                responses_reasoning_effort(profile, "gpt-5", ReasoningEffort::Medium),
                None
            );
        }

        let mut request = request();
        request.thinking_budget = 0;
        request.reasoning_effort = ReasoningEffort::Low;
        assert_eq!(
            request_body(&request, ErrorProfile::OpenAi, TEST_SCOPE).unwrap()["reasoning"]["effort"],
            "low"
        );
        request.thinking_budget = 9_000;
        request.model = "gpt-4.1".into();
        let body = request_body(&request, ErrorProfile::OpenAi, TEST_SCOPE).unwrap();
        assert!(body.get("reasoning").is_none());
        assert!(
            body.get("tools").is_some(),
            "tool semantics must be unchanged"
        );
    }

    #[test]
    fn function_arguments_parse_only_at_done_and_emit_once() {
        let mut parser = ResponseParser::default();
        let added = serde_json::json!({
            "type":"response.output_item.added",
            "output_index":0,
            "item":{
                "id":"fc_1",
                "type":"function_call",
                "call_id":"call_1",
                "name":"read_file",
                "arguments":"",
                "status":"in_progress"
            }
        });
        assert!(
            parser
                .push_frame(frame(added), None, None)
                .unwrap()
                .is_empty()
        );
        // Deliberately invalid partial JSON: parsing it would fail and dispatching it would be
        // unsafe. The parser waits for the authoritative `.done` event.
        let delta = serde_json::json!({
            "type":"response.function_call_arguments.delta",
            "item_id":"fc_1",
            "output_index":0,
            "delta":"{"
        });
        assert!(
            parser
                .push_frame(frame(delta), None, None)
                .unwrap()
                .is_empty()
        );
        let done = serde_json::json!({
            "type":"response.function_call_arguments.done",
            "item_id":"fc_1",
            "output_index":0,
            "name":"read_file",
            "arguments":"{\"path\":\"src/lib.rs\"}"
        });
        let items = parser.push_frame(frame(done.clone()), None, None).unwrap();
        assert_eq!(items.len(), 1);
        let StreamItem::ToolUseComplete(tool) = &items[0] else {
            panic!("expected tool completion");
        };
        assert_eq!(tool.id, "call_1");
        assert_eq!(tool.input["path"], "src/lib.rs");
        assert!(parser.push_frame(frame(done), None, None).is_err());

        let completed = serde_json::json!({
            "type":"response.completed",
            "response":{
                "status":"completed",
                "output":[{
                    "id":"fc_1",
                    "type":"function_call",
                    "call_id":"call_1",
                    "name":"read_file",
                    "arguments":"{\"path\":\"src/lib.rs\"}",
                    "status":"completed"
                }],
                "usage":usage()
            }
        });
        let expected_native = completed["response"]["output"].clone();
        // Use a fresh equivalent parser because the intentional duplicate above failed closed.
        let mut parser = ResponseParser::default();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.output_item.added","output_index":0,
                    "item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read_file"}
                })),
                None,
                None,
            )
            .unwrap();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.function_call_arguments.done","item_id":"fc_1",
                    "output_index":0,"name":"read_file","arguments":"{\"path\":\"src/lib.rs\"}"
                })),
                None,
                None,
            )
            .unwrap();
        let terminal = parser.push_frame(frame(completed), None, None).unwrap();
        let StreamItem::TurnComplete {
            blocks,
            stop_reason,
            usage,
        } = &terminal[0]
        else {
            panic!("expected terminal item");
        };
        assert_eq!(*stop_reason, StopReason::ToolUse);
        assert_eq!(blocks.len(), 2);
        let Block::ProviderState(state) = &blocks[0] else {
            panic!("expected route-scoped provider state");
        };
        assert_eq!(state.route_scope, "test-openai-responses");
        assert_eq!(state.format, OPENAI_RESPONSES_OUTPUT_FORMAT);
        assert_eq!(state.payload, expected_native);
        assert!(matches!(&blocks[1], Block::ToolUse(tool) if tool.id == "call_1"));
        let UsageReport::Complete(usage) = usage else {
            panic!("fixture supplies complete usage");
        };
        assert_eq!(usage.cache_read, 40);
        assert!(parser.finish().is_ok());
    }

    #[test]
    fn text_reasoning_and_usage_are_assembled_at_completion() {
        let mut parser = ResponseParser::default();
        let events = [
            serde_json::json!({
                "type":"response.reasoning_summary_text.delta","item_id":"rs_1",
                "output_index":0,"content_index":0,"delta":"summary"
            }),
            serde_json::json!({
                "type":"response.reasoning_text.delta","item_id":"rs_1",
                "output_index":0,"content_index":0,"delta":"reasoning"
            }),
            serde_json::json!({
                "type":"response.output_text.delta","item_id":"msg_1",
                "output_index":1,"content_index":0,"delta":"hello"
            }),
        ];
        let mut live = Vec::new();
        for event in events {
            live.extend(parser.push_frame(frame(event), None, None).unwrap());
        }
        assert!(matches!(&live[0], StreamItem::ThinkingDelta(v) if v == "summary"));
        assert!(matches!(&live[1], StreamItem::ThinkingDelta(v) if v == "reasoning"));
        assert!(matches!(&live[2], StreamItem::TextDelta(v) if v == "hello"));

        let complete = serde_json::json!({
            "type":"response.completed",
            "response":{
                "status":"completed",
                "output":[
                    {"id":"rs_1","type":"reasoning",
                     "summary":[{"type":"summary_text","text":"summary"}],
                     "content":[{"type":"reasoning_text","text":"reasoning"}],
                     "encrypted_content":"ciphertext-do-not-log"},
                    {"id":"msg_1","type":"message","role":"assistant","status":"completed",
                     "phase":"commentary",
                     "content":[{"type":"output_text","text":"hello","annotations":[]}]}
                ],
                "usage":usage()
            }
        });
        let expected_native = complete["response"]["output"].clone();
        let terminal = parser.push_frame(frame(complete), None, None).unwrap();
        let StreamItem::TurnComplete {
            blocks,
            stop_reason,
            usage,
        } = &terminal[0]
        else {
            panic!("expected terminal item");
        };
        assert_eq!(*stop_reason, StopReason::EndTurn);
        assert_eq!(blocks.len(), 3);
        let Block::ProviderState(state) = &blocks[0] else {
            panic!("expected route-scoped provider state");
        };
        assert_eq!(state.payload, expected_native);
        assert!(!format!("{state:?}").contains("ciphertext-do-not-log"));
        assert_eq!(
            &blocks[1..],
            &[
                Block::Thinking {
                    thinking: "summary\nreasoning".into()
                },
                Block::Text {
                    text: "hello".into()
                }
            ]
        );

        let assistant = Message {
            role: Role::Assistant,
            content: blocks.clone(),
        };
        let replay =
            transcript_to_input(std::slice::from_ref(&assistant), "test-openai-responses").unwrap();
        assert_eq!(serde_json::Value::Array(replay), expected_native);
        let portable = transcript_to_input(&[assistant], "different-provider-instance").unwrap();
        assert_eq!(
            portable,
            vec![serde_json::json!({
                "type":"message","role":"assistant",
                "content":[{"type":"output_text","text":"hello"}]
            })]
        );
        assert_eq!(
            *usage,
            UsageReport::complete(Usage {
                input: 60,
                output: 25,
                cache_creation: 0,
                cache_read: 40,
                thinking: 7
            })
        );
    }

    #[test]
    fn d2_22_responses_refusal_is_not_reported_as_a_successful_end_turn() {
        let mut parser = ResponseParser::default();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.refusal.delta","item_id":"msg_refusal",
                    "output_index":0,"content_index":0,"delta":"cannot comply"
                })),
                None,
                None,
            )
            .unwrap();
        let terminal = parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.completed",
                    "response":{
                        "status":"completed",
                        "output":[{
                            "id":"msg_refusal","type":"message","role":"assistant",
                            "status":"completed","content":[{
                                "type":"refusal","refusal":"cannot comply"
                            }]
                        }],
                        "usage":usage()
                    }
                })),
                None,
                None,
            )
            .unwrap();
        assert!(matches!(
            terminal.as_slice(),
            [StreamItem::TurnComplete {
                stop_reason: StopReason::Refusal,
                blocks,
                ..
            }] if blocks.iter().any(|block| matches!(block, Block::Text { text } if text == "cannot comply"))
        ));
    }

    #[test]
    fn usage_details_are_typed_and_cached_tokens_are_a_subset() {
        assert!(
            parse_usage(&serde_json::json!({
                "usage": {
                    "input_tokens": 10,
                    "input_tokens_details": {"cached_tokens": "9"},
                    "output_tokens": 1
                }
            }))
            .is_err()
        );
        assert!(
            parse_usage(&serde_json::json!({
                "usage": {
                    "input_tokens": 2,
                    "input_tokens_details": {"cached_tokens": 3},
                    "output_tokens": 1
                }
            }))
            .is_err()
        );
        assert_eq!(
            parse_usage(&serde_json::json!({
                "usage": {
                    "input_tokens": 0,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 0,
                    "output_tokens_details": {"reasoning_tokens": 0}
                }
            }))
            .unwrap()
            .complete_usage(),
            Some(Usage::default())
        );
        assert_eq!(
            parse_usage(&serde_json::json!({})).unwrap(),
            UsageReport::provider_omitted()
        );
        assert_eq!(
            parse_usage(&serde_json::json!({"usage": null})).unwrap(),
            UsageReport::provider_omitted()
        );
    }

    #[test]
    fn max_output_incomplete_is_terminal_but_other_incomplete_reasons_fail() {
        let mut parser = ResponseParser::default();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.output_text.delta","item_id":"msg_1",
                    "output_index":0,"content_index":0,"delta":"partial"
                })),
                None,
                None,
            )
            .unwrap();
        let incomplete = serde_json::json!({
            "type":"response.incomplete",
            "response":{
                "status":"incomplete",
                "incomplete_details":{"reason":"max_output_tokens"},
                "output":[{"id":"msg_1","type":"message","role":"assistant",
                           "status":"incomplete","content":[{"type":"output_text","text":"partial"}]}],
                "usage":usage()
            }
        });
        let items = parser.push_frame(frame(incomplete), None, None).unwrap();
        assert!(matches!(
            &items[0],
            StreamItem::TurnComplete {
                stop_reason: StopReason::MaxTokens,
                ..
            }
        ));

        let mut parser = ResponseParser::default();
        let filtered = serde_json::json!({
            "type":"response.incomplete",
            "response":{
                "status":"incomplete",
                "incomplete_details":{"reason":"content_filter"},
                "output":[],
                "usage":usage()
            }
        });
        assert!(matches!(
            parser.push_frame(frame(filtered), None, None),
            Err(ProviderError::Stream(_))
        ));
    }

    #[test]
    fn max_output_discards_a_function_without_arguments_done() {
        let mut parser = ResponseParser::default();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.output_item.added","output_index":0,
                    "item":{"id":"fc_partial","type":"function_call",
                            "call_id":"call_partial","name":"edit"}
                })),
                None,
                None,
            )
            .unwrap();
        parser
            .push_frame(
                frame(serde_json::json!({
                    "type":"response.function_call_arguments.delta",
                    "item_id":"fc_partial","output_index":0,"delta":"{\"path\":"
                })),
                None,
                None,
            )
            .unwrap();
        let incomplete = serde_json::json!({
            "type":"response.incomplete",
            "response":{
                "status":"incomplete",
                "incomplete_details":{"reason":"max_output_tokens"},
                "output":[{"id":"fc_partial","type":"function_call",
                           "call_id":"call_partial","name":"edit",
                           "arguments":"{\"path\":","status":"incomplete"}],
                "usage":usage()
            }
        });
        let items = parser.push_frame(frame(incomplete), None, None).unwrap();
        assert!(matches!(
            &items[0],
            StreamItem::TurnComplete {
                blocks,
                stop_reason: StopReason::MaxTokens,
                ..
            } if blocks.is_empty()
        ));
    }

    #[test]
    fn failed_error_malformed_and_nonterminal_streams_fail_closed() {
        let mut parser = ResponseParser::default();
        let failed = serde_json::json!({
            "type":"response.failed",
            "response":{
                "status":"failed",
                "error":{"code":"insufficient_quota","message":"do not expose this"}
            }
        });
        let Err(ProviderError::Stream(error)) =
            parser.push_frame(frame(failed), None, Some("req_123"))
        else {
            panic!("expected normalized stream error");
        };
        assert_eq!(error.code.as_deref(), Some("insufficient_quota"));
        assert_eq!(error.normalized.adapter, AdapterKind::OpenAiResponses);
        assert_eq!(error.normalized.retry, crate::RetryDisposition::Never);
        assert_eq!(error.normalized.request_id.as_deref(), Some("req_123"));

        let malformed = WireFrame {
            event: Some("response.output_text.delta".into()),
            data: "{not-json".into(),
        };
        assert!(matches!(
            ResponseParser::default().push_frame(malformed, None, None),
            Err(ProviderError::Decode(_))
        ));
        assert!(ResponseParser::default().finish().is_err());
    }

    #[test]
    fn bounded_decoder_handles_chunking_crlf_and_rejects_truncation() {
        let mut decoder = SseDecoder::default();
        let first = decoder
            .push(b"event: response.created\r\ndata: {\"type\":\"response.cre")
            .unwrap();
        assert!(first.is_empty());
        let second = decoder
            .push(b"ated\",\r\ndata: \"response\":{}}\r\n\r\n")
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].event.as_deref(), Some("response.created"));
        let parsed: serde_json::Value = serde_json::from_str(&second[0].data).unwrap();
        assert_eq!(parsed["type"], "response.created");
        assert!(decoder.finish().is_ok());

        let mut truncated = SseDecoder::default();
        assert!(
            truncated
                .push(b"data: {\"type\":\"response.created\"}")
                .unwrap()
                .is_empty()
        );
        assert!(truncated.finish().is_err());
    }

    #[test]
    fn route_scoped_native_output_preserves_reasoning_phase_and_tool_order() {
        let native = serde_json::json!([
            {
                "id":"rs_exact","type":"reasoning","summary":[],"content":null,
                "encrypted_content":"opaque-ciphertext"
            },
            {
                "id":"msg_exact","type":"message","role":"assistant",
                "phase":"commentary","status":"completed",
                "content":[{"type":"output_text","text":"checking"}]
            },
            {
                "id":"fc_exact","type":"function_call","call_id":"call_exact",
                "name":"read_file","arguments":"{\"path\":\"Cargo.toml\"}",
                "status":"completed"
            }
        ]);
        let state = ProviderState {
            route_scope: TEST_SCOPE.into(),
            format: OPENAI_RESPONSES_OUTPUT_FORMAT.into(),
            payload: native.clone(),
        };
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(state.clone()),
                Block::Thinking {
                    thinking: "portable summary".into(),
                },
                Block::Text {
                    text: "checking".into(),
                },
                Block::ToolUse(ToolUse {
                    id: "call_exact".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({"path":"Cargo.toml"}),
                }),
            ],
        };

        let encoded = serde_json::to_vec(&Block::ProviderState(state.clone())).unwrap();
        let decoded: Block = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, Block::ProviderState(state.clone()));
        assert!(!format!("{state:?}").contains("opaque-ciphertext"));

        let exact = transcript_to_input(std::slice::from_ref(&message), TEST_SCOPE).unwrap();
        assert_eq!(serde_json::Value::Array(exact), native);

        let portable = transcript_to_input(&[message], "another-provider-instance").unwrap();
        assert_eq!(portable.len(), 2);
        assert_eq!(portable[0]["type"], "message");
        assert_eq!(portable[0]["content"][0]["text"], "checking");
        assert_eq!(portable[1]["type"], "function_call");
        assert_eq!(portable[1]["call_id"], "call_exact");
    }

    #[test]
    fn matching_state_is_strictly_validated_but_other_routes_are_private() {
        let malformed = ProviderState {
            route_scope: TEST_SCOPE.into(),
            format: OPENAI_RESPONSES_OUTPUT_FORMAT.into(),
            payload: serde_json::json!([{
                "id":"rs_bad","type":"reasoning","summary":[],"content":null
            }]),
        };
        let message = Message {
            role: Role::Assistant,
            content: vec![
                Block::ProviderState(malformed),
                Block::Text {
                    text: "portable".into(),
                },
            ],
        };
        assert!(transcript_to_input(std::slice::from_ref(&message), TEST_SCOPE).is_err());
        assert_eq!(
            transcript_to_input(&[message], "another-provider-instance").unwrap(),
            vec![serde_json::json!({
                "type":"message","role":"assistant",
                "content":[{"type":"output_text","text":"portable"}]
            })]
        );
    }

    #[test]
    fn terminal_event_accepts_every_partial_done_prefix_and_byte_splits() {
        let completed = serde_json::json!({
            "type":"response.completed",
            "response":{"status":"completed","output":[],"usage":usage()}
        });
        let terminal = format!("event: response.completed\ndata: {}\n\n", completed);
        let done = b"data: [DONE]\n\n";

        for prefix_len in 0..=done.len() {
            let mut wire = terminal.as_bytes().to_vec();
            wire.extend_from_slice(&done[..prefix_len]);
            let mut decoder = SseDecoder::default();
            let mut parser = ResponseParser::default();
            let mut saw_terminal = false;
            for frame in decoder.push(&wire).unwrap() {
                saw_terminal |= parser
                    .push_frame(frame, None, None)
                    .unwrap()
                    .iter()
                    .any(|item| matches!(item, StreamItem::TurnComplete { .. }));
            }
            assert!(saw_terminal, "DONE prefix length {prefix_len}");
            decoder.finish_after_terminal().unwrap();
            parser.finish().unwrap();
        }

        let mut whole = terminal.into_bytes();
        whole.extend_from_slice(done);
        let mut decoder = SseDecoder::default();
        let mut parser = ResponseParser::default();
        let mut saw_terminal = false;
        for byte in whole {
            for frame in decoder.push(&[byte]).unwrap() {
                saw_terminal |= parser
                    .push_frame(frame, None, None)
                    .unwrap()
                    .iter()
                    .any(|item| matches!(item, StreamItem::TurnComplete { .. }));
            }
        }
        assert!(saw_terminal);
        decoder.finish_after_terminal().unwrap();
        parser.finish().unwrap();

        let mut invalid = SseDecoder::default();
        invalid.push(b"data: [DONT").unwrap();
        assert!(invalid.finish_after_terminal().is_err());
    }

    #[test]
    fn completed_function_without_arguments_done_is_rejected() {
        let mut parser = ResponseParser::default();
        let complete = serde_json::json!({
            "type":"response.completed",
            "response":{
                "status":"completed",
                "output":[{"id":"fc_1","type":"function_call","call_id":"call_1",
                           "name":"read_file","arguments":"{}","status":"completed"}],
                "usage":usage()
            }
        });
        assert!(matches!(
            parser.push_frame(frame(complete), None, None),
            Err(ProviderError::Decode(_))
        ));
    }
}

//! The Anthropic streaming grammar, as a pure state machine.
//!
//! Grammar (verified against Anthropic's published streaming docs, `docs/intake/_sources`):
//!   message_start
//!   ( content_block_start
//!     content_block_delta*      // text_delta | thinking_delta | input_json_delta
//!     content_block_stop )*     // <- a tool_use block's input is COMPLETE here
//!   message_delta*              // carries stop_reason + output usage
//!   message_stop
//!
//! The one fact the whole overlap flagship rests on: for a `tool_use` block, arguments
//! arrive as `input_json_delta.partial_json` fragments and are complete at that block's
//! `content_block_stop`, which is strictly before `message_stop`. So `StreamItem::ToolUseComplete`
//! is emitted mid-stream, and the scheduler may dispatch a pure tool on it immediately.
//!
//! This parser is deliberately transport-free: it consumes already-split SSE events
//! (`event:` / `data:` pairs), so it is unit-testable against a recorded fixture and is the
//! same code that would replay a recorded stream (ADR-006 promise (b)).

use core_protocol::{Block, ProviderState, StopReason, ToolUse, Usage};

const MAX_SSE_FRAME_BYTES: usize = 32 * 1024 * 1024;
const MAX_ASSEMBLED_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTENT_BLOCKS: usize = 4096;
const MAX_TOOL_ID_OR_NAME_BYTES: usize = 1024;
const MAX_ROUTE_SCOPE_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;
const REDACTED_PROVIDER_STREAM_ERROR: &str = "provider stream error (details redacted)";
pub(crate) const ANTHROPIC_CONTENT_BLOCKS_FORMAT: &str = "anthropic.messages.content-blocks.v1";

/// What the parser emits as it consumes the stream. The kernel/scheduler reacts to these.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamItem {
    /// Incremental assistant text (surface to the operator as it arrives).
    TextDelta(String),
    /// Incremental reasoning (extended thinking).
    ThinkingDelta(String),
    /// A `tool_use` block just completed: its input is fully known. THE flagship dispatch
    /// point. Emitted at `content_block_stop`, before the turn ends.
    ToolUseComplete(ToolUse),
    /// The turn ended. Carries the assembled blocks, stop reason, and usage by cache class.
    TurnComplete {
        blocks: Vec<Block>,
        stop_reason: StopReason,
        usage: Usage,
    },
}

/// One SSE frame: an `event:` name and its `data:` JSON line.
#[derive(Debug, Clone)]
pub struct SseFrame {
    pub event: String,
    pub data: String,
}

/// A block under construction. Text/thinking accumulate a string; tool_use accumulates the
/// partial-JSON fragments and parses once at `content_block_stop` (guard the parse: a
/// `max_tokens` stop can truncate a tool argument — ADR-004).
enum Building {
    Text(String),
    Thinking {
        thinking: String,
        signature: String,
        signature_started: bool,
    },
    RedactedThinking {
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        json: String,
        initial_input: serde_json::Value,
    },
}

/// A persistent streaming parser. State is carried ACROSS network chunks — the SSE frames for
/// one turn arrive in arbitrarily-split TCP chunks, so a fresh parser per chunk would reset
/// open blocks and usage and fire `message_stop` with only the last chunk's contents (the bug
/// this struct exists to prevent, see Errors.md 2026-07-10). Feed frames as they arrive; get
/// `StreamItem`s out incrementally, preserving mid-stream `ToolUseComplete`.
pub struct StreamParser {
    route_scope: String,
    blocks: Vec<Block>,
    native_blocks: Vec<serde_json::Value>,
    building: Option<Building>,
    building_index: Option<u64>,
    content_blocks_seen: usize,
    native_replay_complete: bool,
    // An invalid tool JSON may be the expected consequence of a max_tokens cut. Defer the
    // verdict until message_delta supplies the stop reason; any other terminal reason fails.
    pending_tool_error: Option<String>,
    pending_native_error: Option<String>,
    usage: Usage,
    message_start_seen: bool,
    output_usage_seen: bool,
    stop_reason_set: bool,
    stop_reason: StopReason,
    output_bytes: usize,
    terminal: bool,
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamParser {
    pub fn new() -> Self {
        Self::with_route_scope("anthropic-stream-parser".into())
            .expect("the built-in parser route scope is valid")
    }

    pub fn with_route_scope(route_scope: String) -> Result<Self, String> {
        if route_scope.is_empty()
            || route_scope.len() > MAX_ROUTE_SCOPE_BYTES
            || route_scope.chars().any(char::is_control)
        {
            return Err("Anthropic parser route scope was empty or invalid".into());
        }
        Ok(StreamParser {
            route_scope,
            native_replay_complete: true,
            stop_reason: StopReason::EndTurn,
            blocks: Vec::new(),
            native_blocks: Vec::new(),
            building: None,
            building_index: None,
            content_blocks_seen: 0,
            pending_tool_error: None,
            pending_native_error: None,
            usage: Usage::default(),
            message_start_seen: false,
            output_usage_seen: false,
            stop_reason_set: false,
            output_bytes: 0,
            terminal: false,
        })
    }

    fn reserve_output(&mut self, additional: usize) -> Result<(), String> {
        self.output_bytes = self
            .output_bytes
            .checked_add(additional)
            .ok_or_else(|| "Anthropic assembled output byte counter overflow".to_string())?;
        if self.output_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
            return Err(format!(
                "Anthropic assembled output exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
            ));
        }
        Ok(())
    }

    fn reserve_block(&self) -> Result<(), String> {
        if self.content_blocks_seen >= MAX_CONTENT_BLOCKS {
            Err(format!(
                "Anthropic output exceeded {MAX_CONTENT_BLOCKS} content blocks"
            ))
        } else {
            Ok(())
        }
    }

    /// Feed one SSE frame; get any items it produced.
    pub fn push(&mut self, f: &SseFrame) -> Result<Vec<StreamItem>, String> {
        if self.terminal {
            return Err("Anthropic parser received a frame after message_stop".into());
        }
        if f.event.len().saturating_add(f.data.len()) > MAX_SSE_FRAME_BYTES {
            return Err(format!(
                "Anthropic SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
            ));
        }
        let mut items = Vec::new();
        let v: serde_json::Value =
            serde_json::from_str(&f.data).map_err(|e| format!("bad data json: {e}"))?;
        match f.event.as_str() {
            "message_start" => {
                if self.message_start_seen || self.content_blocks_seen != 0 || self.stop_reason_set
                {
                    return Err("Anthropic stream contained duplicate message_start usage".into());
                }
                let usage = v
                    .pointer("/message/usage")
                    .and_then(serde_json::Value::as_object)
                    .ok_or("message_start lacked a usage object")?;
                self.usage.input = required_usage_u64(usage, "input_tokens")?;
                self.usage.cache_creation =
                    optional_usage_u64(usage, "cache_creation_input_tokens")?.unwrap_or(0);
                self.usage.cache_read =
                    optional_usage_u64(usage, "cache_read_input_tokens")?.unwrap_or(0);
                self.message_start_seen = true;
            }
            "content_block_start" => {
                if !self.message_start_seen || self.stop_reason_set {
                    return Err("content block started outside the message content phase".into());
                }
                if self.building.is_some() {
                    return Err("content block started before the prior block stopped".into());
                }
                let cb = v.get("content_block").ok_or("no content_block")?;
                self.reserve_block()?;
                let index = required_index(&v)?;
                if index != self.content_blocks_seen as u64 {
                    return Err("Anthropic content block index was not contiguous".into());
                }
                let kind = cb
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("content block lacked a type")?;
                let building = match kind {
                    "text" => {
                        let text = required_event_string(cb, "text")?.to_string();
                        self.reserve_output(text.len())?;
                        Building::Text(text)
                    }
                    "thinking" => {
                        let thinking = required_event_string(cb, "thinking")?.to_string();
                        self.reserve_output(thinking.len())?;
                        Building::Thinking {
                            thinking,
                            signature: String::new(),
                            signature_started: false,
                        }
                    }
                    "redacted_thinking" => {
                        let data = required_event_string(cb, "data")?.to_string();
                        if data.is_empty() {
                            return Err("redacted_thinking started with empty data".into());
                        }
                        self.reserve_output(data.len())?;
                        Building::RedactedThinking { data }
                    }
                    "tool_use" => {
                        let id = required_event_string(cb, "id")?.to_string();
                        let name = required_event_string(cb, "name")?.to_string();
                        if id.is_empty()
                            || name.is_empty()
                            || id.len() > MAX_TOOL_ID_OR_NAME_BYTES
                            || name.len() > MAX_TOOL_ID_OR_NAME_BYTES
                        {
                            return Err(
                                "tool call id or name was empty or exceeded its bound".into()
                            );
                        }
                        let initial_input =
                            cb.get("input").cloned().ok_or("tool_use lacked input")?;
                        if !initial_input.is_object() {
                            return Err("tool_use input was not an object".into());
                        }
                        let input_bytes = serde_json::to_vec(&initial_input)
                            .map_err(|_| "tool_use input could not be encoded")?
                            .len();
                        self.reserve_output(
                            id.len()
                                .saturating_add(name.len())
                                .saturating_add(input_bytes),
                        )?;
                        Building::ToolUse {
                            id,
                            name,
                            json: String::new(),
                            initial_input,
                        }
                    }
                    _ => return Err("unsupported Anthropic content block type".into()),
                };
                self.building = Some(building);
                self.building_index = Some(index);
                self.content_blocks_seen += 1;
            }
            "content_block_delta" => {
                let index = required_index(&v)?;
                if self.building_index != Some(index) {
                    return Err("Anthropic content delta index did not match its open block".into());
                }
                let d = v.get("delta").ok_or("no delta")?;
                let delta_type = d.get("type").and_then(|x| x.as_str());
                let additional = match delta_type {
                    Some("text_delta") => required_event_string(d, "text")?.len(),
                    Some("thinking_delta") => required_event_string(d, "thinking")?.len(),
                    Some("input_json_delta") => required_event_string(d, "partial_json")?.len(),
                    Some("signature_delta") => required_event_string(d, "signature")?.len(),
                    _ => return Err("unsupported Anthropic content block delta".into()),
                };
                self.reserve_output(additional)?;
                match (delta_type, self.building.as_mut()) {
                    (Some("text_delta"), Some(Building::Text(s))) => {
                        let t = required_event_string(d, "text")?;
                        s.push_str(t);
                        items.push(StreamItem::TextDelta(t.to_string()));
                    }
                    (
                        Some("thinking_delta"),
                        Some(Building::Thinking {
                            thinking,
                            signature_started,
                            ..
                        }),
                    ) => {
                        if *signature_started {
                            return Err("thinking_delta followed a signature_delta".into());
                        }
                        let t = required_event_string(d, "thinking")?;
                        thinking.push_str(t);
                        items.push(StreamItem::ThinkingDelta(t.to_string()));
                    }
                    (
                        Some("signature_delta"),
                        Some(Building::Thinking {
                            signature,
                            signature_started,
                            ..
                        }),
                    ) => {
                        let delta = d
                            .get("signature")
                            .and_then(serde_json::Value::as_str)
                            .ok_or("signature_delta lacked signature")?;
                        *signature_started = true;
                        signature.push_str(delta);
                        if signature.len() > MAX_SIGNATURE_BYTES {
                            return Err(format!(
                                "Anthropic thinking signature exceeded {MAX_SIGNATURE_BYTES} bytes"
                            ));
                        }
                    }
                    (
                        Some("input_json_delta"),
                        Some(Building::ToolUse {
                            json,
                            initial_input,
                            ..
                        }),
                    ) => {
                        if initial_input
                            .as_object()
                            .is_some_and(|object| !object.is_empty())
                        {
                            return Err(
                                "tool_use mixed non-empty initial input with JSON deltas".into()
                            );
                        }
                        let partial = required_event_string(d, "partial_json")?;
                        json.push_str(partial);
                    }
                    _ => return Err("Anthropic delta type did not match its open block".into()),
                }
            }
            "content_block_stop" => {
                let index = required_index(&v)?;
                if self.building_index.take() != Some(index) {
                    return Err("Anthropic content stop index did not match its open block".into());
                }
                match self.building.take() {
                    Some(Building::Text(text)) => {
                        self.native_blocks
                            .push(serde_json::json!({"type":"text","text":text}));
                        self.blocks.push(Block::Text { text });
                    }
                    Some(Building::Thinking {
                        thinking,
                        signature,
                        ..
                    }) => {
                        self.blocks.push(Block::Thinking {
                            thinking: thinking.clone(),
                        });
                        if signature.is_empty() {
                            self.native_replay_complete = false;
                            self.pending_native_error = Some(
                                "thinking block completed without a provider signature".into(),
                            );
                        } else {
                            self.native_blocks.push(serde_json::json!({
                                "type":"thinking","thinking":thinking,"signature":signature
                            }));
                        }
                    }
                    Some(Building::RedactedThinking { data }) => {
                        self.native_blocks.push(serde_json::json!({
                            "type":"redacted_thinking","data":data
                        }));
                    }
                    Some(Building::ToolUse {
                        id,
                        name,
                        json,
                        initial_input,
                    }) => {
                        let input: serde_json::Value = if json.trim().is_empty() {
                            initial_input
                        } else {
                            match serde_json::from_str(&json) {
                                Ok(input) => input,
                                Err(error) => {
                                    self.native_replay_complete = false;
                                    self.pending_tool_error = Some(format!(
                                        "tool arguments were not valid JSON: {error}"
                                    ));
                                    return Ok(items);
                                }
                            }
                        };
                        if !input.is_object() {
                            self.native_replay_complete = false;
                            self.pending_tool_error =
                                Some("tool call input was not a JSON object".into());
                            return Ok(items);
                        }
                        let tu = ToolUse { id, name, input };
                        self.native_blocks.push(serde_json::json!({
                            "type":"tool_use","id":tu.id,"name":tu.name,"input":tu.input
                        }));
                        self.blocks.push(Block::ToolUse(tu.clone()));
                        // THE flagship signal: emitted here, mid-stream, before message_stop.
                        items.push(StreamItem::ToolUseComplete(tu));
                    }
                    None => return Err("content_block_stop arrived without an open block".into()),
                }
            }
            "message_delta" => {
                if !self.message_start_seen {
                    return Err("message_delta arrived before message_start".into());
                }
                if let Some(sr) = v.pointer("/delta/stop_reason").and_then(|x| x.as_str()) {
                    self.stop_reason = match sr {
                        "end_turn" => StopReason::EndTurn,
                        "tool_use" => StopReason::ToolUse,
                        "max_tokens" => StopReason::MaxTokens,
                        "stop_sequence" => StopReason::StopSequence,
                        _ => {
                            return Err("Anthropic message_delta had an unknown stop reason".into());
                        }
                    };
                    self.stop_reason_set = true;
                }
                if self.building.is_some()
                    && (!self.stop_reason_set || self.stop_reason != StopReason::MaxTokens)
                {
                    return Err("message_delta arrived while a content block was open".into());
                }
                if let Some(output) = v.pointer("/usage/output_tokens") {
                    if self.output_usage_seen {
                        return Err("Anthropic stream contained duplicate output usage".into());
                    }
                    self.usage.output = output
                        .as_u64()
                        .ok_or("message_delta output_tokens was not an unsigned integer")?;
                    self.output_usage_seen = true;
                }
            }
            "message_stop" => {
                if !self.stop_reason_set {
                    return Err("message_stop arrived before a stop reason".into());
                }
                if !self.message_start_seen {
                    return Err("message_stop arrived without message_start usage".into());
                }
                if !self.output_usage_seen {
                    return Err("message_stop arrived without output token usage".into());
                }
                if let Some(building) = self.building.take() {
                    self.building_index = None;
                    if self.stop_reason != StopReason::MaxTokens {
                        return Err("stream ended with an unfinished content block".into());
                    }
                    self.native_replay_complete = false;
                    // Preserve visible partial prose/reasoning, but never fabricate or dispatch a
                    // partial tool call.
                    match building {
                        Building::Text(text) if !text.is_empty() => {
                            self.blocks.push(Block::Text { text });
                        }
                        Building::Thinking { thinking, .. } if !thinking.is_empty() => {
                            self.blocks.push(Block::Thinking { thinking });
                        }
                        Building::Text(_)
                        | Building::Thinking { .. }
                        | Building::RedactedThinking { .. }
                        | Building::ToolUse { .. } => {}
                    }
                }
                if self.stop_reason != StopReason::MaxTokens
                    && let Some(error) = self.pending_tool_error.take()
                {
                    return Err(error);
                }
                if self.stop_reason != StopReason::MaxTokens
                    && let Some(error) = self.pending_native_error.take()
                {
                    return Err(error);
                }
                self.pending_tool_error = None;
                self.pending_native_error = None;
                let has_tool_use = self
                    .blocks
                    .iter()
                    .any(|block| matches!(block, Block::ToolUse(_)));
                match self.stop_reason {
                    StopReason::ToolUse if !has_tool_use => {
                        return Err("tool_use stop reason contained no complete tool call".into());
                    }
                    StopReason::EndTurn | StopReason::StopSequence if has_tool_use => {
                        return Err(
                            "complete tool call disagreed with the Anthropic stop reason".into(),
                        );
                    }
                    StopReason::EndTurn
                    | StopReason::ToolUse
                    | StopReason::MaxTokens
                    | StopReason::StopSequence => {}
                }
                if self.native_replay_complete && !self.native_blocks.is_empty() {
                    let native_bytes = serde_json::to_vec(&self.native_blocks)
                        .map_err(|_| "Anthropic native content could not be encoded")?
                        .len();
                    if native_bytes > MAX_ASSEMBLED_OUTPUT_BYTES {
                        return Err(format!(
                            "Anthropic native content exceeded {MAX_ASSEMBLED_OUTPUT_BYTES} bytes"
                        ));
                    }
                    self.blocks.insert(
                        0,
                        Block::ProviderState(ProviderState {
                            route_scope: self.route_scope.clone(),
                            format: ANTHROPIC_CONTENT_BLOCKS_FORMAT.into(),
                            payload: serde_json::Value::Array(std::mem::take(
                                &mut self.native_blocks,
                            )),
                        }),
                    );
                } else {
                    self.native_blocks.clear();
                }
                self.terminal = true;
                items.push(StreamItem::TurnComplete {
                    blocks: std::mem::take(&mut self.blocks),
                    stop_reason: self.stop_reason,
                    usage: self.usage,
                });
            }
            "error" => {
                // The live Anthropic transport upgrades this to a structured ProviderError.
                // Keep the pure/replay parser fail-closed too: recorded error frames must never
                // become a successful empty stream merely because there is no HTTP transport.
                // Do not expose provider-controlled fields here: recorded frames can contain
                // echoed credentials, prompts, or tool output. Structured live errors retain
                // typed diagnostics through the private ProviderError path instead.
                return Err(REDACTED_PROVIDER_STREAM_ERROR.into());
            }
            _ => {} // ping and forward-compatible event types
        }
        Ok(items)
    }

    /// Validate that a complete frame replay reached a clean protocol terminal.
    ///
    /// `push` is intentionally incremental, so it cannot reject an otherwise-valid prefix while
    /// the network may still deliver more frames. Call this only when the complete recording (or
    /// transport) has ended. A successful finish guarantees that `message_stop` was processed and
    /// that no content block or deferred tool error remains unresolved.
    pub fn finish(&self) -> Result<(), String> {
        if !self.terminal {
            if self.building.is_some() {
                return Err("Anthropic stream ended with an unfinished content block".into());
            }
            if self.pending_tool_error.is_some() {
                return Err("Anthropic stream ended with an unresolved invalid tool call".into());
            }
            if self.pending_native_error.is_some() {
                return Err(
                    "Anthropic stream ended with unresolved native continuation state".into(),
                );
            }
            if self.stop_reason_set {
                return Err("Anthropic stream ended before message_stop".into());
            }
            return Err("Anthropic stream ended before a stop reason and message_stop".into());
        }

        if self.building.is_some()
            || self.building_index.is_some()
            || self.pending_tool_error.is_some()
            || self.pending_native_error.is_some()
            || !self.stop_reason_set
            || !self.message_start_seen
            || !self.output_usage_seen
        {
            return Err("Anthropic parser reached an inconsistent terminal state".into());
        }
        Ok(())
    }
}

fn required_index(value: &serde_json::Value) -> Result<u64, String> {
    value
        .get("index")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "Anthropic content event lacked a valid index".into())
}

fn required_event_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Anthropic content event lacked a required string".into())
}

fn required_usage_u64(
    usage: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, String> {
    optional_usage_u64(usage, field)?
        .ok_or_else(|| "Anthropic usage lacked a required token count".into())
}

fn optional_usage_u64(
    usage: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    usage
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| "Anthropic usage token count was not an unsigned integer".into())
        })
        .transpose()
}

/// Parse a full sequence of SSE frames into `StreamItem`s. Pure: same frames in, same items
/// out (this is what makes recorded-stream replay exact). Used by tests and replay; the live
/// client uses `StreamParser::push` so state survives chunk boundaries.
pub fn parse_sse_stream(frames: &[SseFrame]) -> Result<Vec<StreamItem>, String> {
    let mut p = StreamParser::new();
    let mut items = Vec::new();
    for f in frames {
        items.extend(p.push(f)?);
    }
    p.finish()?;
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(event: &str, data: serde_json::Value) -> SseFrame {
        SseFrame {
            event: event.into(),
            data: data.to_string(),
        }
    }

    fn message_start(input_tokens: u64) -> SseFrame {
        frame(
            "message_start",
            serde_json::json!({"message":{"usage":{"input_tokens":input_tokens}}}),
        )
    }

    fn message_delta(stop_reason: &str, output_tokens: u64) -> SseFrame {
        frame(
            "message_delta",
            serde_json::json!({
                "delta":{"stop_reason":stop_reason},
                "usage":{"output_tokens":output_tokens}
            }),
        )
    }

    /// A recorded turn: text, then a tool_use whose args stream in fragments, then stop.
    /// This is the exact grammar the flagship depends on.
    #[test]
    fn tool_use_completes_mid_stream_before_turn_end() {
        let frames = vec![
            frame(
                "message_start",
                serde_json::json!({"message":{"usage":{"input_tokens":10,"cache_read_input_tokens":40}}}),
            ),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"text","text":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"text_delta","text":"I'll read the file."}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":0})),
            frame(
                "content_block_start",
                serde_json::json!({"index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"read_file","input":{}}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"sr"}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":1,"delta":{"type":"input_json_delta","partial_json":"c/main.rs\"}"}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":1})),
            frame(
                "message_delta",
                serde_json::json!({"delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}),
            ),
            frame("message_stop", serde_json::json!({})),
        ];
        let items = parse_sse_stream(&frames).unwrap();

        // The tool_use completes BEFORE the turn-complete item — the whole point.
        let tool_pos = items
            .iter()
            .position(|i| matches!(i, StreamItem::ToolUseComplete(_)))
            .unwrap();
        let turn_pos = items
            .iter()
            .position(|i| matches!(i, StreamItem::TurnComplete { .. }))
            .unwrap();
        assert!(
            tool_pos < turn_pos,
            "tool_use must be dispatchable before the turn ends"
        );

        // The fragmented args reassemble into valid JSON.
        if let StreamItem::ToolUseComplete(tu) = &items[tool_pos] {
            assert_eq!(tu.name, "read_file");
            assert_eq!(tu.input["path"], "src/main.rs");
        } else {
            panic!();
        }

        // Usage is decomposed by cache class (attribution substrate).
        if let StreamItem::TurnComplete {
            usage, stop_reason, ..
        } = items.last().unwrap()
        {
            assert_eq!(usage.cache_read, 40);
            assert_eq!(usage.output, 25);
            assert_eq!(*stop_reason, StopReason::ToolUse);
        } else {
            panic!();
        }
    }

    #[test]
    fn parser_state_survives_chunk_boundaries() {
        // Regression for the 2026-07-10 bug: message_start in one chunk, blocks + message_stop
        // in later chunks. A per-chunk parser reset zeroed usage and lost blocks. A persistent
        // StreamParser must accumulate across the split.
        let mut p = StreamParser::new();
        let mut items = Vec::new();
        // chunk 1: just message_start (usage lives here)
        items.extend(p.push(&frame("message_start", serde_json::json!({"message":{"usage":{"input_tokens":7,"cache_read_input_tokens":100}}}))).unwrap());
        // chunk 2: a text block
        items.extend(
            p.push(&frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"text","text":""}}),
            ))
            .unwrap(),
        );
        items.extend(
            p.push(&frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"text_delta","text":"done."}}),
            ))
            .unwrap(),
        );
        items.extend(
            p.push(&frame("content_block_stop", serde_json::json!({"index":0})))
                .unwrap(),
        );
        // chunk 3: message_delta (stop_reason + output usage) then message_stop
        items.extend(
            p.push(&frame(
                "message_delta",
                serde_json::json!({"delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),
            ))
            .unwrap(),
        );
        items.extend(
            p.push(&frame("message_stop", serde_json::json!({})))
                .unwrap(),
        );

        let StreamItem::TurnComplete {
            blocks,
            usage,
            stop_reason,
        } = items.last().unwrap()
        else {
            panic!("expected TurnComplete");
        };
        assert_eq!(
            blocks
                .iter()
                .filter(|block| matches!(block, Block::Text { .. }))
                .count(),
            1,
            "the text block from chunk 2 must survive to message_stop"
        );
        assert!(matches!(blocks.first(), Some(Block::ProviderState(_))));
        assert_eq!(usage.input, 7, "usage from chunk 1 must survive");
        assert_eq!(usage.cache_read, 100);
        assert_eq!(
            usage.output, 3,
            "output usage from chunk 3 must be captured"
        );
        assert_eq!(*stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn truncated_tool_args_are_discarded_only_for_a_max_tokens_stop() {
        let prefix = vec![
            message_start(1),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"tool_use","id":"t","name":"edit","input":{}}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"a.rs\",\"old"}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":0})),
        ];
        let mut truncated = prefix.clone();
        truncated.push(frame(
            "message_delta",
            serde_json::json!({"delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":0}}),
        ));
        truncated.push(frame("message_stop", serde_json::json!({})));
        let items = parse_sse_stream(&truncated).unwrap();
        assert!(matches!(
            items.last(),
            Some(StreamItem::TurnComplete {
                stop_reason: StopReason::MaxTokens,
                blocks,
                ..
            }) if blocks.is_empty()
        ));

        let mut malformed = prefix;
        malformed.push(frame(
            "message_delta",
            serde_json::json!({"delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":0}}),
        ));
        malformed.push(frame("message_stop", serde_json::json!({})));
        assert!(parse_sse_stream(&malformed).is_err());
    }

    #[test]
    fn full_replay_rejects_truncated_stream_before_message_stop() {
        let frames = vec![message_start(0), message_delta("end_turn", 0)];

        let error = parse_sse_stream(&frames).unwrap_err();
        assert_eq!(error, "Anthropic stream ended before message_stop");
    }

    #[test]
    fn full_replay_rejects_truncated_open_content_block() {
        let frames = vec![
            message_start(0),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"text","text":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"text_delta","text":"partial"}}),
            ),
        ];

        let error = parse_sse_stream(&frames).unwrap_err();
        assert_eq!(
            error,
            "Anthropic stream ended with an unfinished content block"
        );
    }

    #[test]
    fn native_state_preserves_thinking_signature_and_redacted_thinking() {
        let secret_signature = "opaque-signature-secret";
        let redacted_data = "opaque-redacted-secret";
        let frames = vec![
            message_start(12),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"thinking","thinking":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"thinking_delta","thinking":"inspect carefully"}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"signature_delta","signature":secret_signature}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":0})),
            frame(
                "content_block_start",
                serde_json::json!({"index":1,"content_block":{"type":"redacted_thinking","data":redacted_data}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":1})),
            frame(
                "content_block_start",
                serde_json::json!({"index":2,"content_block":{"type":"text","text":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":2,"delta":{"type":"text_delta","text":"done"}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":2})),
            message_delta("end_turn", 7),
            frame("message_stop", serde_json::json!({})),
        ];

        let items = parse_sse_stream(&frames).unwrap();
        let Some(StreamItem::TurnComplete { blocks, .. }) = items.last() else {
            panic!("expected a complete turn");
        };
        let Block::ProviderState(state) = &blocks[0] else {
            panic!("expected route-scoped native state");
        };
        assert_eq!(state.route_scope, "anthropic-stream-parser");
        assert_eq!(state.format, ANTHROPIC_CONTENT_BLOCKS_FORMAT);
        assert_eq!(
            state.payload,
            serde_json::json!([
                {"type":"thinking","thinking":"inspect carefully","signature":secret_signature},
                {"type":"redacted_thinking","data":redacted_data},
                {"type":"text","text":"done"}
            ])
        );
        assert!(blocks.iter().any(
            |block| matches!(block, Block::Thinking { thinking } if thinking == "inspect carefully")
        ));
        assert!(
            blocks
                .iter()
                .any(|block| matches!(block, Block::Text { text } if text == "done"))
        );
        assert!(!format!("{state:?}").contains(secret_signature));
        assert!(!format!("{state:?}").contains(redacted_data));
    }

    #[test]
    fn thinking_without_signature_is_only_tolerated_for_max_token_truncation() {
        let prefix = vec![
            message_start(1),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"thinking","thinking":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"thinking_delta","thinking":"partial"}}),
            ),
            frame("content_block_stop", serde_json::json!({"index":0})),
        ];

        let mut complete = prefix.clone();
        complete.push(message_delta("end_turn", 1));
        complete.push(frame("message_stop", serde_json::json!({})));
        assert!(
            parse_sse_stream(&complete)
                .unwrap_err()
                .contains("without a provider signature")
        );

        let mut truncated = prefix;
        truncated.push(message_delta("max_tokens", 1));
        truncated.push(frame("message_stop", serde_json::json!({})));
        let items = parse_sse_stream(&truncated).unwrap();
        let Some(StreamItem::TurnComplete { blocks, .. }) = items.last() else {
            panic!("expected a complete truncated turn");
        };
        assert!(
            !blocks
                .iter()
                .any(|block| matches!(block, Block::ProviderState(_)))
        );
        assert!(
            blocks.iter().any(
                |block| matches!(block, Block::Thinking { thinking } if thinking == "partial")
            )
        );
    }

    #[test]
    fn unfinished_thinking_truncation_never_fabricates_native_state() {
        let frames = vec![
            message_start(0),
            frame(
                "content_block_start",
                serde_json::json!({"index":0,"content_block":{"type":"thinking","thinking":""}}),
            ),
            frame(
                "content_block_delta",
                serde_json::json!({"index":0,"delta":{"type":"thinking_delta","thinking":"cut off"}}),
            ),
            message_delta("max_tokens", 0),
            frame("message_stop", serde_json::json!({})),
        ];
        let items = parse_sse_stream(&frames).unwrap();
        let Some(StreamItem::TurnComplete { blocks, .. }) = items.last() else {
            panic!("expected a complete truncated turn");
        };
        assert!(
            !blocks
                .iter()
                .any(|block| matches!(block, Block::ProviderState(_)))
        );
        assert!(
            blocks.iter().any(
                |block| matches!(block, Block::Thinking { thinking } if thinking == "cut off")
            )
        );
    }

    #[test]
    fn usage_is_required_but_explicit_zero_is_valid() {
        let missing_start = vec![
            message_delta("end_turn", 0),
            frame("message_stop", serde_json::json!({})),
        ];
        assert!(
            parse_sse_stream(&missing_start)
                .unwrap_err()
                .contains("before message_start")
        );

        let missing_output = vec![
            message_start(0),
            frame(
                "message_delta",
                serde_json::json!({"delta":{"stop_reason":"end_turn"},"usage":{}}),
            ),
            frame("message_stop", serde_json::json!({})),
        ];
        assert!(
            parse_sse_stream(&missing_output)
                .unwrap_err()
                .contains("without output token usage")
        );

        let explicit_zero = vec![
            message_start(0),
            message_delta("end_turn", 0),
            frame("message_stop", serde_json::json!({})),
        ];
        let items = parse_sse_stream(&explicit_zero).unwrap();
        assert!(matches!(
            items.last(),
            Some(StreamItem::TurnComplete {
                usage: Usage {
                    input: 0,
                    output: 0,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn recorded_error_frame_is_fixed_and_does_not_leak_provider_fields() {
        let secret = "sk-\
live-secret-from-provider";
        let frames = vec![frame(
            "error",
            serde_json::json!({
                "type":"error",
                "error":{
                    "type":format!("overloaded_error-{secret}"),
                    "message":format!("request echoed credential {secret}")
                }
            }),
        )];
        let error = parse_sse_stream(&frames).unwrap_err();
        assert_eq!(error, REDACTED_PROVIDER_STREAM_ERROR);
        assert!(!error.contains(secret));
        assert!(!error.contains("overloaded_error"));
    }
}

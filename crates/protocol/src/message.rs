//! Conversation types. The transcript is append-only (ADR-002 R2): no reordering, no
//! mid-array edits. That is the prefix-cache discipline, and it is a hard constraint, not
//! a preference.

use crate::tool::{ToolResult, ToolUse};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Versioned adapter-private state format carried on the durable wire.
///
/// Known versions are typed so adapters cannot accidentally invent a near-match. Unknown future
/// strings remain byte-for-byte round-trippable: an older Core may preserve them for the owning
/// adapter/run even though it must not interpret them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ProviderStateFormat {
    AnthropicMessagesContentBlocksV1,
    OpenAiChatReasoningContentV1,
    OpenAiResponsesOutputItemsV1,
    Unknown(String),
}

impl ProviderStateFormat {
    pub const ANTHROPIC_MESSAGES_CONTENT_BLOCKS_V1: &'static str =
        "anthropic.messages.content-blocks.v1";
    pub const OPENAI_CHAT_REASONING_CONTENT_V1: &'static str = "openai.chat.reasoning-content.v1";
    pub const OPENAI_RESPONSES_OUTPUT_ITEMS_V1: &'static str = "openai.responses.output-items.v1";

    pub fn as_str(&self) -> &str {
        match self {
            Self::AnthropicMessagesContentBlocksV1 => Self::ANTHROPIC_MESSAGES_CONTENT_BLOCKS_V1,
            Self::OpenAiChatReasoningContentV1 => Self::OPENAI_CHAT_REASONING_CONTENT_V1,
            Self::OpenAiResponsesOutputItemsV1 => Self::OPENAI_RESPONSES_OUTPUT_ITEMS_V1,
            Self::Unknown(raw) => raw,
        }
    }
}

impl From<&str> for ProviderStateFormat {
    fn from(raw: &str) -> Self {
        match raw {
            Self::ANTHROPIC_MESSAGES_CONTENT_BLOCKS_V1 => Self::AnthropicMessagesContentBlocksV1,
            Self::OPENAI_CHAT_REASONING_CONTENT_V1 => Self::OpenAiChatReasoningContentV1,
            Self::OPENAI_RESPONSES_OUTPUT_ITEMS_V1 => Self::OpenAiResponsesOutputItemsV1,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl From<String> for ProviderStateFormat {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            Self::ANTHROPIC_MESSAGES_CONTENT_BLOCKS_V1 => Self::AnthropicMessagesContentBlocksV1,
            Self::OPENAI_CHAT_REASONING_CONTENT_V1 => Self::OpenAiChatReasoningContentV1,
            Self::OPENAI_RESPONSES_OUTPUT_ITEMS_V1 => Self::OpenAiResponsesOutputItemsV1,
            _ => Self::Unknown(raw),
        }
    }
}

impl std::ops::Deref for ProviderStateFormat {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<&str> for ProviderStateFormat {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Debug for ProviderStateFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ProviderStateFormat")
            .field(&self.as_str())
            .finish()
    }
}

impl Serialize for ProviderStateFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderStateFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// Adapter-private continuation data. The payload is deliberately opaque to the kernel: only an
/// adapter instance with the exact same `route_scope` and versioned `format` may interpret or
/// replay it. Portable blocks in the same message remain the cross-provider fallback.
///
/// `Debug` never exposes the payload because it can contain encrypted provider continuation state
/// and provider-returned text. The durable record still serializes it verbatim so resume/fork can
/// preserve stateless provider semantics.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderState {
    pub route_scope: String,
    pub format: ProviderStateFormat,
    pub payload: serde_json::Value,
}

impl std::fmt::Debug for ProviderState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderState")
            .field("route_scope", &self.route_scope)
            .field("format", &self.format)
            .field("payload", &"[OPAQUE]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
}

/// A content block. Anthropic's Messages API is block-structured; we mirror it because the
/// block boundary (`content_block_stop`) is exactly where pure-tool early dispatch happens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    Text {
        text: String,
    },
    /// The model's reasoning, when extended thinking is on. Kept in the transcript verbatim
    /// so the append-only cache discipline holds.
    Thinking {
        thinking: String,
    },
    /// Route-scoped, versioned provider continuation state. Never render this block and never
    /// reinterpret it on a different route; adapters must validate strict size/schema bounds.
    ProviderState(ProviderState),
    ToolUse(ToolUse),
    ToolResult(ToolResult),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<Block>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message {
            role: Role::User,
            content: vec![Block::Text { text: text.into() }],
        }
    }
    /// The tool_use blocks in this (assistant) message, in order.
    pub fn tool_uses(&self) -> impl Iterator<Item = &ToolUse> {
        self.content.iter().filter_map(|b| match b {
            Block::ToolUse(t) => Some(t),
            _ => None,
        })
    }
}

/// Maximum wire bytes retained for a provider-defined future stop-reason code.
pub const MAX_STOP_REASON_CODE_BYTES: usize = 128;

/// A bounded, exact future stop-reason code.
///
/// Keeping this value inline lets [`StopReason`] remain `Copy`, while still preserving the raw
/// provider vocabulary for a newer adapter/runtime to inspect. Debug output deliberately does not
/// reveal the provider-controlled value; callers that need to branch on it use [`Self::as_str`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StopReasonCode {
    bytes: [u8; MAX_STOP_REASON_CODE_BYTES],
    len: u8,
}

impl StopReasonCode {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.trim().is_empty()
            || raw.len() > MAX_STOP_REASON_CODE_BYTES
            || raw.chars().any(char::is_control)
        {
            return Err("stop reason code was empty, oversized, or contained control characters");
        }
        let mut bytes = [0; MAX_STOP_REASON_CODE_BYTES];
        bytes[..raw.len()].copy_from_slice(raw.as_bytes());
        Ok(Self {
            bytes,
            len: raw.len() as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)])
            .expect("StopReasonCode is constructed only from valid UTF-8")
    }
}

impl std::fmt::Debug for StopReasonCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StopReasonCode([BOUNDED PROVIDER CODE])")
    }
}

impl Serialize for StopReasonCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StopReasonCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Why the model stopped a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Natural end of the assistant turn.
    #[default]
    EndTurn,
    /// The model emitted tool calls and is waiting for results — the loop continues.
    ToolUse,
    /// Hit the output-token ceiling. May have truncated a tool argument mid-stream — guard
    /// the parse (ADR-004: `max_tokens` can cut a parameter off).
    MaxTokens,
    /// A stop sequence fired.
    StopSequence,
    /// The provider/model explicitly refused the request. This is terminal but never success.
    Refusal,
    /// The provider paused a resumable turn. The runtime may append a continuation and proceed.
    PauseTurn,
    /// A future provider stop vocabulary value, retained exactly and acted on fail-closed.
    Unknown(StopReasonCode),
}

/// Token usage by cache class. This is the attribution substrate (ADR-002): cost is
/// decomposed into these, and `obs` meters each. Not one scalar "tokens" number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
    pub thinking: u64,
}

impl Usage {
    pub fn add(&mut self, o: &Usage) {
        // Saturation is the budget-safe failure mode: a malicious/buggy provider cannot wrap a
        // cumulative counter back toward zero and reopen a cost gate.
        self.input = self.input.saturating_add(o.input);
        self.output = self.output.saturating_add(o.output);
        self.cache_creation = self.cache_creation.saturating_add(o.cache_creation);
        self.cache_read = self.cache_read.saturating_add(o.cache_read);
        self.thinking = self.thinking.saturating_add(o.thinking);
    }
    /// Fraction of input tokens served from cache — the single most important health signal
    /// for the append-only discipline (ADR-002 amendment: obs meters this per turn).
    pub fn cache_hit_ratio(&self) -> f64 {
        let denom = self.input as f64 + self.cache_read as f64 + self.cache_creation as f64;
        if denom == 0.0 {
            0.0
        } else {
            self.cache_read as f64 / denom
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, ProviderStateFormat, StopReason, StopReasonCode, Usage};

    #[test]
    fn usage_accumulation_saturates_instead_of_reopening_a_budget() {
        let mut usage = Usage {
            input: u64::MAX,
            cache_read: u64::MAX,
            ..Usage::default()
        };
        usage.add(&Usage {
            input: 1,
            cache_read: 1,
            ..Usage::default()
        });
        assert_eq!(usage.input, u64::MAX);
        assert_eq!(usage.cache_read, u64::MAX);
        assert!(usage.cache_hit_ratio().is_finite());
    }

    #[test]
    fn d9_07_provider_state_ignores_new_envelope_fields_and_preserves_future_format() {
        for (format, expected) in [
            (
                ProviderStateFormat::OPENAI_RESPONSES_OUTPUT_ITEMS_V1,
                ProviderStateFormat::OpenAiResponsesOutputItemsV1,
            ),
            (
                "openai.responses.output-items.v2",
                ProviderStateFormat::Unknown("openai.responses.output-items.v2".into()),
            ),
        ] {
            let fixture = serde_json::json!({
                "type":"provider_state",
                "route_scope":"openai/responses/model",
                "format":format,
                "payload":{"opaque":"value"},
                "added_by_newer_core":{"must":"not break resume"}
            });
            let decoded: Block = serde_json::from_value(fixture).unwrap();
            let Block::ProviderState(state) = &decoded else {
                panic!("fixture must remain provider state");
            };
            assert_eq!(state.format, expected);
            let encoded = serde_json::to_value(&decoded).unwrap();
            assert_eq!(encoded["format"], format);
            let round_trip: Block = serde_json::from_value(encoded).unwrap();
            assert_eq!(round_trip, decoded);
        }
    }

    #[test]
    fn d2_22_unknown_stop_reason_is_bounded_exact_and_debug_redacted() {
        let reason = StopReason::Unknown(StopReasonCode::parse("future_pause_v2").unwrap());
        let encoded = serde_json::to_value(reason).unwrap();
        let decoded: StopReason = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, reason);
        assert_eq!(encoded, serde_json::json!({"unknown":"future_pause_v2"}));
        let StopReason::Unknown(code) = decoded else {
            panic!("future stop reason lost its typed carrier");
        };
        assert_eq!(code.as_str(), "future_pause_v2");
        assert!(!format!("{code:?}").contains("future_pause_v2"));
        assert!(StopReasonCode::parse(&"x".repeat(129)).is_err());
        assert!(StopReasonCode::parse("bad\nreason").is_err());
    }
}

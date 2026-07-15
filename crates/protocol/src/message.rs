//! Conversation types. The transcript is append-only (ADR-002 R2): no reordering, no
//! mid-array edits. That is the prefix-cache discipline, and it is a hard constraint, not
//! a preference.

use crate::tool::{ToolResult, ToolUse};
use serde::{Deserialize, Serialize};

/// Adapter-private continuation data. The payload is deliberately opaque to the kernel: only an
/// adapter instance with the exact same `route_scope` and versioned `format` may interpret or
/// replay it. Portable blocks in the same message remain the cross-provider fallback.
///
/// `Debug` never exposes the payload because it can contain encrypted provider continuation state
/// and provider-returned text. The durable record still serializes it verbatim so resume/fork can
/// preserve stateless provider semantics.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderState {
    pub route_scope: String,
    pub format: String,
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
    use super::Usage;

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
}

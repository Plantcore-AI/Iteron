//! Sole owner of one logical provider turn's transport/timing/prefix evidence across retries.

use super::stream_progress::StreamTiming;
use iteron_provider::{RateLimitSnapshot, StreamItem};
use std::time::Instant;

const MAX_INTERRUPTED_PREFIX_BYTES: usize = 256 * 1_024;

pub(super) struct ProviderTurnEvidence {
    first_item_at: Option<Instant>,
    first_byte_observed: bool,
    semantic_output_observed: bool,
    stream_items: u32,
    text: String,
    thinking: String,
    observed_quota: Option<RateLimitSnapshot>,
    prefix_limit: usize,
}
impl ProviderTurnEvidence {
    pub fn new(prefix_limit: usize) -> Self {
        Self {
            first_item_at: None,
            first_byte_observed: false,
            semantic_output_observed: false,
            stream_items: 0,
            text: String::new(),
            thinking: String::new(),
            observed_quota: None,
            prefix_limit: prefix_limit.min(MAX_INTERRUPTED_PREFIX_BYTES),
        }
    }
    pub fn mark_first_byte(&mut self) -> bool {
        if self.first_byte_observed {
            false
        } else {
            self.first_byte_observed = true;
            true
        }
    }
    /// Metadata/header events never manufacture a semantic token or TTFT measurement.
    pub fn observe_payload(&mut self, item: &StreamItem) -> bool {
        if matches!(
            item,
            StreamItem::Accepted | StreamItem::CompatibilityNotice(_) | StreamItem::RateLimit(_)
        ) {
            return false;
        }
        let first = self.first_item_at.is_none();
        if first {
            self.first_item_at = Some(Instant::now());
        }
        self.stream_items = self.stream_items.saturating_add(1);
        self.semantic_output_observed |= matches!(
            item,
            StreamItem::TextDelta(_) | StreamItem::ToolUseComplete(_)
        );
        first
    }
    pub fn stream_items(&self) -> u32 {
        self.stream_items
    }
    pub fn semantic_output_observed(&self) -> bool {
        self.semantic_output_observed
    }
    pub fn append_text(&mut self, delta: &str) {
        append_prefix(&mut self.text, delta, self.prefix_limit);
    }
    pub fn append_thinking(&mut self, delta: &str) {
        append_prefix(&mut self.thinking, delta, self.prefix_limit);
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn thinking(&self) -> &str {
        &self.thinking
    }
    pub fn observe_quota(&mut self, quota: RateLimitSnapshot) {
        self.observed_quota = Some(quota);
    }
    pub fn take_quota(&mut self) -> Option<RateLimitSnapshot> {
        self.observed_quota.take()
    }
    pub fn timing(&self, started: Instant) -> StreamTiming {
        match self.first_item_at {
            Some(first) => StreamTiming {
                ttft_ms: Some(iteron_obs::duration_ms_ceil(
                    first.saturating_duration_since(started),
                )),
                decode_ms: Some(iteron_obs::duration_ms_ceil(first.elapsed())),
                stream_items: Some(self.stream_items),
            },
            None => StreamTiming::default(),
        }
    }
}
fn append_prefix(buffer: &mut String, delta: &str, max_bytes: usize) {
    let capacity = max_bytes.saturating_add(4);
    if buffer.len() >= capacity {
        return;
    }
    let mut end = delta.len().min(capacity - buffer.len());
    while end > 0 && !delta.is_char_boundary(end) {
        end -= 1;
    }
    buffer.push_str(&delta[..end]);
}

#[cfg(test)]
mod tests {
    use super::ProviderTurnEvidence;
    use iteron_provider::StreamItem;
    use std::time::Instant;

    #[test]
    fn accepted_metadata_is_distinct_from_observed_semantic_token() {
        let start = Instant::now();
        let mut owner = ProviderTurnEvidence::new(64);
        assert!(owner.mark_first_byte());
        assert!(!owner.mark_first_byte());
        assert!(!owner.observe_payload(&StreamItem::Accepted));
        assert_eq!(owner.timing(start).ttft_ms, None);
        assert_eq!(owner.stream_items(), 0);
        assert!(owner.observe_payload(&StreamItem::ThinkingDelta("reason".into())));
        assert!(!owner.semantic_output_observed());
        assert!(owner.timing(start).ttft_ms.is_some());
        assert!(!owner.observe_payload(&StreamItem::TextDelta("answer".into())));
        assert!(owner.semantic_output_observed());
        assert_eq!(owner.stream_items(), 2);
    }

    #[test]
    fn interrupted_prefix_remains_finite_utf8_across_many_deltas() {
        let mut owner = ProviderTurnEvidence::new(3);
        for _ in 0..100 {
            owner.append_text("中文");
            owner.append_thinking("🙂");
        }
        assert!(owner.text().len() <= 7);
        assert!(owner.thinking().len() <= 7);
        assert_eq!(owner.text(), "中文");
        assert_eq!(owner.thinking(), "🙂");
    }
}

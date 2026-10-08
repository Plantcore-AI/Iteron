//! Actual per-model-turn assistant/reasoning projection and incremental parsing/layout owner.
//! Consumers receive text/geometry views and typed reconciliation decisions, never mutable buffers.
use super::{
    live_markdown::{LiveMarkdownLayout, LiveMarkdownRenderContext},
    ui_safe_text,
};
use crate::{
    machine_projection::StreamingScrubber,
    markdown::{MarkdownDoc, StreamingParse},
};

pub(super) enum Reconciliation {
    Unchanged,
    Appended,
    Replace {
        block_ids: Vec<u64>,
        document: Option<MarkdownDoc>,
    },
}
#[derive(Default)]
pub(super) struct AssistantStream {
    text: String,
    text_nonempty: bool,
    thinking: String,
    authority: String,
    authority_chars: usize,
    block_ids: Vec<u64>,
    revision: u64,
    parsed_revision: u64,
    document: Option<MarkdownDoc>,
    parser: StreamingParse,
    layout: LiveMarkdownLayout,
    text_scrubber: StreamingScrubber,
    thinking_scrubber: StreamingScrubber,
}
impl AssistantStream {
    pub(super) fn has_text(&self) -> bool {
        self.text_nonempty
    }
    #[cfg(test)]
    pub(super) fn text(&self) -> &str {
        &self.text
    }
    pub(super) fn thinking(&self) -> &str {
        &self.thinking
    }
    pub(super) fn authority(&self) -> &str {
        &self.authority
    }
    pub(super) fn approximate_tokens(&self) -> usize {
        self.authority_chars.div_ceil(4)
    }
    pub(super) fn layout(&self) -> &LiveMarkdownLayout {
        &self.layout
    }
    pub(super) fn track_block(&mut self, id: u64) {
        self.block_ids.push(id);
    }
    pub(super) fn begin_model_turn(&mut self) {
        self.authority.clear();
        self.authority_chars = 0;
        self.block_ids.clear();
    }
    pub(super) fn reset(&mut self) {
        let revision = self.revision.wrapping_add(1);
        *self = Self {
            revision,
            parsed_revision: revision,
            ..Self::default()
        };
    }
    pub(super) fn invalidate_layout(&mut self) {
        self.layout = LiveMarkdownLayout::default();
    }
    fn append_safe_text(&mut self, text: &str) {
        self.text_nonempty |= text.chars().any(|ch| !ch.is_whitespace());
        self.text.push_str(text);
        self.authority.push_str(text);
        self.authority_chars = self.authority_chars.saturating_add(text.chars().count());
        self.revision = self.revision.wrapping_add(1);
    }
    pub(super) fn append_text(&mut self, delta: &str) -> bool {
        let Some(complete) = self.text_scrubber.push(delta) else {
            return false;
        };
        if complete.is_empty() {
            return false;
        }
        self.append_safe_text(&ui_safe_text(&complete));
        self.ensure_document();
        true
    }
    pub(super) fn append_thinking(&mut self, delta: &str) -> bool {
        let Some(complete) = self.thinking_scrubber.push(delta) else {
            return false;
        };
        if complete.is_empty() {
            return false;
        }
        self.thinking.push_str(&ui_safe_text(&complete));
        let count = self.thinking.chars().count();
        if count > 4000 {
            self.thinking = self.thinking.chars().skip(count - 4000).collect();
        }
        true
    }
    pub(super) fn finish_text_boundary(&mut self) {
        if let Some(pending) = self.text_scrubber.finish() {
            self.append_safe_text(&ui_safe_text(&pending));
        }
    }
    pub(super) fn finish_thinking_boundary(&mut self) {
        if let Some(pending) = self.thinking_scrubber.finish() {
            self.thinking.push_str(&ui_safe_text(&pending));
        }
    }
    pub(super) fn finish_boundaries(&mut self) {
        self.finish_text_boundary();
        self.finish_thinking_boundary();
    }
    pub(super) fn take_thinking(&mut self) -> Option<String> {
        self.finish_thinking_boundary();
        let text = std::mem::take(&mut self.thinking);
        (!text.trim().is_empty()).then_some(text)
    }
    pub(super) fn take_document(&mut self) -> Option<MarkdownDoc> {
        self.finish_text_boundary();
        if !self.text_nonempty {
            self.text.clear();
            self.text_nonempty = false;
            self.document = None;
            self.parsed_revision = self.revision;
            return None;
        }
        self.ensure_document();
        self.parser.finalize(
            self.document.as_mut().expect("parsed text has a document"),
            &self.text,
        );
        self.text.clear();
        self.text_nonempty = false;
        self.parsed_revision = self.revision;
        self.document.take()
    }
    pub(super) fn ensure_document(&mut self) -> bool {
        if !self.text_nonempty || self.document.is_some() && self.parsed_revision == self.revision {
            return false;
        }
        if self.document.is_none() {
            self.document = Some(MarkdownDoc {
                blocks: Vec::new(),
                source: None,
            });
            self.parser = StreamingParse::default();
        }
        self.parser.extend(
            self.document.as_mut().expect("document initialized"),
            &self.text,
        );
        self.parsed_revision = self.revision;
        true
    }
    pub(super) fn prepare_layout(&mut self, context: LiveMarkdownRenderContext<'_>) {
        self.ensure_document();
        if let Some(document) = &self.document
            && self.text_nonempty
        {
            self.layout
                .update(document, &self.parser, &self.text, context);
        }
    }
    pub(super) fn reconcile(&mut self, authoritative: &str) -> Reconciliation {
        let authoritative = ui_safe_text(authoritative);
        if authoritative == self.authority {
            return Reconciliation::Unchanged;
        }
        if let Some(missing) = authoritative.strip_prefix(&self.authority) {
            // The terminal authority supplies exact missing safe bytes; it is not another transport
            // delta and must not be held behind token-boundary heuristics.
            let missing = missing.to_owned();
            self.append_safe_text(&missing);
            self.ensure_document();
            return Reconciliation::Appended;
        }
        let block_ids = std::mem::take(&mut self.block_ids);
        self.text.clear();
        self.text_nonempty = false;
        self.document = None;
        self.parser = StreamingParse::default();
        self.parsed_revision = self.revision;
        self.authority_chars = authoritative.chars().count();
        self.authority = authoritative;
        let document =
            (!self.authority.trim().is_empty()).then(|| MarkdownDoc::parse(&self.authority));
        Reconciliation::Replace {
            block_ids,
            document,
        }
    }
    #[cfg(test)]
    pub(super) fn block_ids(&self) -> &[u64] {
        &self.block_ids
    }
    #[cfg(test)]
    pub(super) fn source_revision(&self) -> u64 {
        self.revision
    }
    #[cfg(test)]
    pub(super) fn document_revision(&self) -> u64 {
        self.parsed_revision
    }
    #[cfg(test)]
    pub(super) fn document(&self) -> Option<&MarkdownDoc> {
        self.document.as_ref()
    }
    #[cfg(test)]
    pub(super) fn parsed_source_bytes(&self) -> usize {
        self.parser.parsed_source_bytes()
    }
    #[cfg(test)]
    pub(super) fn fixture_text(&mut self, text: String) {
        self.text_nonempty = text.chars().any(|ch| !ch.is_whitespace());
        self.text = text;
        self.revision = self.revision.wrapping_add(1);
    }
    #[cfg(test)]
    pub(super) fn fixture_thinking(&mut self, text: String) {
        self.thinking = text;
    }
    #[cfg(test)]
    pub(super) fn fixture_authority(&mut self, text: String) {
        self.authority_chars = text.chars().count();
        self.authority = text;
    }
}

#[cfg(test)]
mod tests {
    use super::{AssistantStream, Reconciliation};
    #[test]
    fn adoption_resets_pending_scrubbers_and_current_turn_identity_before_new_scope() {
        let mut owner = AssistantStream::default();
        owner.append_text("old-public ");
        owner.append_thinking("old-reasoning ");
        owner.track_block(42);
        owner.append_text("old-unfinished-token");
        owner.reset();
        assert!(owner.text().is_empty());
        assert!(owner.thinking().is_empty());
        assert!(owner.authority().is_empty());
        assert!(owner.block_ids().is_empty());
        owner.append_text("new-scope ");
        owner.finish_boundaries();
        assert_eq!(owner.authority(), "new-scope ");
        assert!(!owner.text().contains("old"));
        assert_eq!(
            owner.approximate_tokens(),
            owner.authority().chars().count().div_ceil(4)
        );
    }
    #[test]
    fn typed_rewrite_returns_exact_owned_block_ids_and_unicode_counter_follows_real_bytes() {
        let mut owner = AssistantStream::default();
        owner.append_text("字节 ");
        owner.finish_text_boundary();
        owner.track_block(17);
        owner.track_block(19);
        let Reconciliation::Replace {
            block_ids,
            document,
        } = owner.reconcile("correct 界")
        else {
            panic!("exact rewrite decision")
        };
        assert_eq!(block_ids, vec![17, 19]);
        assert_eq!(document.unwrap().to_text(), "correct 界");
        assert_eq!(
            owner.approximate_tokens(),
            "correct 界".chars().count().div_ceil(4)
        );
        assert!(matches!(
            owner.reconcile("correct 界"),
            Reconciliation::Unchanged
        ));
        assert!(matches!(
            owner.reconcile("correct 界 suffix"),
            Reconciliation::Appended
        ));
        assert_eq!(
            owner.approximate_tokens(),
            owner.authority().chars().count().div_ceil(4)
        );
    }
}

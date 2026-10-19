//! Optional content-derived summaries. Keys retain actual values; classifications and authority
//! never enter this cache. The owner uses try_lock, so contention always recomputes evidence.
use iteron_ctx::{RequestEstimator, TokenizerIdentity};
use iteron_protocol::{Block, Message, ToolSpec};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_ENTRIES: usize = 128;
const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;
// JSON can encode a small value much more compactly than its allocated map/vector nodes. This
// conservative charge covers retained value trees, strings, summaries and container overhead.
const VALUE_ALLOCATION_FACTOR: usize = 128;

#[derive(Clone, Copy)]
pub(super) struct Summary {
    pub(super) digest: [u8; 32],
    pub(super) bytes: u64,
    pub(super) tokens: u64,
}
impl Summary {
    fn new(bytes: &[u8], tokens: usize) -> Self {
        Self {
            digest: Sha256::digest(bytes).into(),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            tokens: u64::try_from(tokens).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct MessageSummary {
    pub(super) whole: Option<Summary>,
    pub(super) non_results: Option<Summary>,
    results: Vec<(usize, Summary)>,
}
impl MessageSummary {
    pub(super) fn result(&self, block: usize) -> Summary {
        self.results
            .iter()
            .find(|(index, _)| *index == block)
            .expect("summary computed for actual tool result")
            .1
    }
}
struct MessageEntry {
    value: Message,
    summary: MessageSummary,
    charge: usize,
}
struct SchemaEntry {
    value: Vec<ToolSpec>,
    summary: Summary,
    charge: usize,
}

#[derive(Default)]
pub(super) struct EvidenceCache {
    identity: Option<TokenizerIdentity>,
    messages: BTreeMap<usize, MessageEntry>,
    system: Option<(String, Summary)>,
    schemas: Option<SchemaEntry>,
    retained: usize,
}
impl EvidenceCache {
    pub(super) fn bind(&mut self, identity: TokenizerIdentity) {
        if self.identity.as_ref() != Some(&identity) {
            *self = Self {
                identity: Some(identity),
                ..Self::default()
            };
        }
    }
    fn room(&mut self, charge: usize) -> bool {
        if charge > MAX_RETAINED_BYTES {
            return false;
        }
        while self.retained.saturating_add(charge) > MAX_RETAINED_BYTES {
            let Some((_, entry)) = self.messages.pop_first() else {
                return false;
            };
            self.retained = self.retained.saturating_sub(entry.charge);
        }
        true
    }
    pub(super) fn system(&mut self, text: &str, estimator: &RequestEstimator) -> Summary {
        if let Some((previous, summary)) = &self.system
            && previous == text
        {
            return *summary;
        }
        let summary = Summary::new(text.as_bytes(), estimator.estimate_text(text));
        if let Some((previous, _)) = self.system.take() {
            self.retained = self
                .retained
                .saturating_sub(previous.len().saturating_add(256));
        }
        let charge = text.len().saturating_add(256);
        if self.room(charge) {
            self.system = Some((text.to_owned(), summary));
            self.retained += charge;
        }
        summary
    }
    pub(super) fn schemas(&mut self, tools: &[ToolSpec]) -> Summary {
        if let Some(previous) = &self.schemas
            && same_tools(&previous.value, tools)
        {
            return previous.summary;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"iteron-request-tool-schemas-v1\0");
        hasher.update((tools.len() as u64).to_le_bytes());
        let mut bytes = 0u64;
        for tool in tools {
            let schema = tool.input_schema.to_string();
            for field in [&tool.name, &tool.description, &schema] {
                hasher.update((field.len() as u64).to_le_bytes());
                hasher.update(field.as_bytes());
                bytes = bytes.saturating_add(field.len() as u64);
            }
        }
        let summary = Summary {
            digest: hasher.finalize().into(),
            bytes,
            tokens: 0,
        };
        if let Some(previous) = self.schemas.take() {
            self.retained = self.retained.saturating_sub(previous.charge);
        }
        let charge = usize::try_from(bytes)
            .unwrap_or(usize::MAX)
            .saturating_mul(VALUE_ALLOCATION_FACTOR)
            .saturating_add(tools.len().saturating_mul(256))
            .saturating_add(256);
        if tools.len() <= MAX_ENTRIES && self.room(charge) {
            self.schemas = Some(SchemaEntry {
                value: tools.to_vec(),
                summary,
                charge,
            });
            self.retained += charge;
        }
        summary
    }
    pub(super) fn message(
        &mut self,
        index: usize,
        message: &Message,
        estimator: &RequestEstimator,
    ) -> MessageSummary {
        if let Some(previous) = self.messages.get(&index)
            && previous.value.role == message.role
            && previous.value.content == message.content
        {
            return previous.summary.clone();
        }
        if let Some(previous) = self.messages.remove(&index) {
            self.retained = self.retained.saturating_sub(previous.charge);
        }
        let has_results = message
            .content
            .iter()
            .any(|block| matches!(block, Block::ToolResult(_) | Block::ToolImage(_)));
        let mut summary = MessageSummary::default();
        let mut encoded_bytes = 0usize;
        if !has_results {
            let bytes = serde_json::to_vec(message).unwrap_or_default();
            encoded_bytes = bytes.len();
            summary.whole = Some(Summary::new(
                &bytes,
                estimator.estimate_text(&String::from_utf8_lossy(&bytes)),
            ));
        } else {
            let non_results = message
                .content
                .iter()
                .filter(|block| !matches!(block, Block::ToolResult(_) | Block::ToolImage(_)))
                .collect::<Vec<_>>();
            if !non_results.is_empty() {
                let bytes = serde_json::to_vec(&(message.role, non_results)).unwrap_or_default();
                encoded_bytes = bytes.len();
                summary.non_results = Some(Summary::new(
                    &bytes,
                    estimator.estimate_text(&String::from_utf8_lossy(&bytes)),
                ));
            }
            for (block_index, block) in message.content.iter().enumerate() {
                if let Block::ToolResult(result) = block {
                    let bytes = serde_json::to_vec(block).unwrap_or_default();
                    encoded_bytes = encoded_bytes.saturating_add(bytes.len());
                    summary.results.push((
                        block_index,
                        Summary::new(
                            &bytes,
                            estimator.estimate_text(&result.content).saturating_add(8),
                        ),
                    ));
                }
            }
        }
        let charge = encoded_bytes
            .saturating_mul(VALUE_ALLOCATION_FACTOR)
            .saturating_add(512);
        // Pixel payloads are never cloned into this optional cache. Indexes beyond the fixed
        // retained prefix recompute, avoiding cache churn while preserving an explicit bound.
        if index < MAX_ENTRIES
            && !message
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolImage(_)))
            && self.room(charge)
        {
            self.messages.insert(
                index,
                MessageEntry {
                    value: message.clone(),
                    summary: summary.clone(),
                    charge,
                },
            );
            self.retained += charge;
        }
        summary
    }
}

fn same_tools(left: &[ToolSpec], right: &[ToolSpec]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a.name == b.name
                && a.description == b.description
                && a.input_schema == b.input_schema
                && a.purity == b.purity
                && a.capability == b.capability
        })
}

#[cfg(test)]
mod tests;

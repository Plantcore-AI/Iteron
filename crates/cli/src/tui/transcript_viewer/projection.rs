//! Bounded viewer projection starts from the same semantic blocks as ordinary rendering/export.

use crate::block;
use serde::Serialize as _;
use std::sync::atomic::{AtomicBool, Ordering};
use unicode_normalization::UnicodeNormalization as _;

use super::{Entry, MAX_DETAIL_BYTES, MAX_INDEX_BLOCK_BYTES, MAX_QUERY_BYTES, semantic_text};

/// Ceiling on the buffer reserved before any block text is projected. The caller's byte cap can be
/// far larger than the block it is about to bound, so reserving the cap itself would charge every
/// small block for the largest one the viewer tolerates.
const PROJECTION_RESERVE_BYTES: usize = 64 * 1024;

pub(super) fn block_label(kind: &block::BlockKind) -> &'static str {
    match kind {
        block::BlockKind::User(_) => "user",
        block::BlockKind::Assistant(_) => "assistant",
        block::BlockKind::Thinking { .. } => "thinking",
        block::BlockKind::Tool(_) => "tool",
        block::BlockKind::Workflow(_) => "workflow",
        block::BlockKind::WorkflowRun(_) => "workflow-run",
        block::BlockKind::Notice { .. } => "notice",
        block::BlockKind::Error { .. } => "error",
        block::BlockKind::Diff(_) => "diff",
        block::BlockKind::Panel { .. } => "panel",
        block::BlockKind::Welcome { .. } => "welcome",
    }
}

#[derive(Debug)]
pub(super) struct DetailProjection {
    pub(super) text: String,
    pub(super) truncated: bool,
}

pub(super) fn index_block(
    block: &block::Block,
    remaining: usize,
    cancelled: &AtomicBool,
) -> Result<Entry, ()> {
    let Some((source, source_truncated)) =
        semantic_text::block_text(block, MAX_INDEX_BLOCK_BYTES, cancelled)
    else {
        return Err(());
    };
    if source_truncated {
        return Ok(oversized_block(block));
    }
    let Some((safe, safe_truncated)) =
        bounded_safe_cancelled(&source, MAX_INDEX_BLOCK_BYTES, cancelled)
    else {
        return Err(());
    };
    if safe_truncated {
        return Ok(oversized_block(block));
    }
    let (folded, fold_truncated) =
        fold_bounded(&safe, MAX_INDEX_BLOCK_BYTES, cancelled).ok_or(())?;
    let within_block_limit = !fold_truncated;
    let complete = within_block_limit && folded.len() <= remaining;
    let required_bytes = (within_block_limit && !complete).then_some(folded.len());
    Ok(Entry {
        id: block.id,
        revision: block.revision,
        label: block_label(&block.kind),
        folded: if complete { folded } else { String::new() },
        complete,
        required_bytes,
        needs_projection: false,
    })
}

fn oversized_block(block: &block::Block) -> Entry {
    Entry {
        id: block.id,
        revision: block.revision,
        label: block_label(&block.kind),
        folded: String::new(),
        complete: false,
        required_bytes: None,
        needs_projection: false,
    }
}

pub(super) fn detail_block(
    block: &block::Block,
    raw: bool,
    cancelled: &AtomicBool,
) -> Result<DetailProjection, ()> {
    const MARKER: &str = "\n[detail truncated at 64 KiB]\n";
    let (mut source, source_truncated) = if raw {
        raw_text_bounded(block, MAX_DETAIL_BYTES, cancelled)?
    } else {
        semantic_text::block_text(block, MAX_DETAIL_BYTES, cancelled).ok_or(())?
    };
    if source_truncated {
        // Never scrub or display a semantic prefix whose final credential token may have been cut
        // at a field boundary. Oversized detail fails closed to the explicit truncation marker.
        source.clear();
    }
    let (mut text, safe_truncated) = bounded_safe_cancelled(
        &source,
        MAX_DETAIL_BYTES.saturating_sub(MARKER.len()),
        cancelled,
    )
    .ok_or(())?;
    let truncated = source_truncated || safe_truncated;
    if truncated {
        text.push_str(MARKER);
    }
    Ok(DetailProjection { text, truncated })
}

fn raw_text_bounded(
    block: &block::Block,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Result<(String, bool), ()> {
    match &block.kind {
        block::BlockKind::User(text)
        | block::BlockKind::Thinking { text, .. }
        | block::BlockKind::Notice { text, .. } => {
            bounded_fields(max_bytes, cancelled, [text.as_str()])
        }
        block::BlockKind::Assistant(document) => {
            semantic_text::markdown_text(document, max_bytes, cancelled).ok_or(())
        }
        block::BlockKind::Tool(card) => raw_tool_bounded(block.id, card, max_bytes, cancelled),
        block::BlockKind::Error { title, detail, .. } => bounded_fields(
            max_bytes,
            cancelled,
            [title.as_str(), "\n", detail.as_str()],
        ),
        block::BlockKind::Welcome { tagline } => {
            bounded_fields(max_bytes, cancelled, [tagline.as_str()])
        }
        _ => semantic_text::block_text(block, max_bytes, cancelled).ok_or(()),
    }
}

fn bounded_fields<const N: usize>(
    max_bytes: usize,
    cancelled: &AtomicBool,
    fields: [&str; N],
) -> Result<(String, bool), ()> {
    let mut text = String::with_capacity(max_bytes.min(PROJECTION_RESERVE_BYTES));
    for field in fields {
        if cancelled.load(Ordering::Relaxed) {
            return Err(());
        }
        if text.len().saturating_add(field.len()) > max_bytes {
            return Ok((text, true));
        }
        text.push_str(field);
    }
    Ok((text, false))
}

#[derive(serde::Serialize)]
struct RawTool<'a> {
    block_id: u64,
    kind: &'static str,
    name: &'a str,
    arguments: &'a serde_json::Value,
    status: &'static str,
    exit_code: Option<i32>,
    output: &'a str,
}

fn raw_tool_bounded(
    block_id: u64,
    card: &block::ToolCard,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Result<(String, bool), ()> {
    let value = RawTool {
        block_id,
        kind: "tool",
        name: &card.name,
        arguments: &card.args,
        status: match card.status {
            block::ToolStatus::Running => "running",
            block::ToolStatus::Ok => "ok",
            block::ToolStatus::Err => "error",
        },
        exit_code: card.exit_code,
        output: &card.output,
    };
    let mut writer = BoundedJsonWriter {
        bytes: Vec::with_capacity(max_bytes.min(PROJECTION_RESERVE_BYTES)),
        max_bytes,
        cancelled,
        truncated: false,
    };
    let result = value.serialize(&mut serde_json::Serializer::pretty(&mut writer));
    if cancelled.load(Ordering::Relaxed) {
        return Err(());
    }
    if result.is_err() {
        if writer.truncated {
            // Never expose a partial JSON token: it could be the prefix of a credential that the
            // scrubber cannot classify without its boundary. The explicit marker still tells the
            // operator why the raw projection is absent.
            return Ok((String::new(), true));
        }
        return Err(());
    }
    String::from_utf8(writer.bytes)
        .map(|text| (text, false))
        .map_err(|_| ())
}

struct BoundedJsonWriter<'a> {
    bytes: Vec<u8>,
    max_bytes: usize,
    cancelled: &'a AtomicBool,
    truncated: bool,
}

impl std::io::Write for BoundedJsonWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "projection cancelled",
            ));
        }
        if self.bytes.len().saturating_add(bytes.len()) > self.max_bytes {
            self.truncated = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "raw projection byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Metadata-only placeholder once the global budget is exhausted. It deliberately never calls
/// `Block::to_text`, redaction, normalization, or case folding.
pub(super) fn unprojected_block(block: &block::Block) -> Entry {
    Entry {
        id: block.id,
        revision: block.revision,
        label: block_label(&block.kind),
        folded: String::new(),
        complete: false,
        required_bytes: None,
        needs_projection: true,
    }
}

pub(super) fn append_query(query: &mut String, addition: &str) {
    for character in addition.chars() {
        if character.is_control() {
            continue;
        }
        if query.len().saturating_add(character.len_utf8()) > MAX_QUERY_BYTES {
            break;
        }
        query.push(character);
    }
    let scrubbed = iteron_record::redact::scrub(query);
    if scrubbed != *query {
        query.clear();
        for character in scrubbed.chars() {
            if query.len().saturating_add(character.len_utf8()) > MAX_QUERY_BYTES {
                break;
            }
            query.push(character);
        }
    }
}

pub(super) fn fold(text: &str) -> String {
    text.nfc()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .nfc()
        .collect()
}

fn fold_bounded(text: &str, max_bytes: usize, cancelled: &AtomicBool) -> Option<(String, bool)> {
    let mut lowered = String::with_capacity(text.len().min(max_bytes));
    for character in text.nfc().flat_map(char::to_lowercase) {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        if lowered.len().saturating_add(character.len_utf8()) > max_bytes {
            return Some((String::new(), true));
        }
        lowered.push(character);
    }
    let mut folded = String::with_capacity(lowered.len());
    for character in lowered.nfc() {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        if folded.len().saturating_add(character.len_utf8()) > max_bytes {
            return Some((String::new(), true));
        }
        folded.push(character);
    }
    Some((folded, false))
}

fn bounded_safe_cancelled(
    text: &str,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Option<(String, bool)> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    // `text` has already crossed the bounded semantic builder, so redaction can never scan or
    // allocate more than the caller's fixed projection cap.
    let scrubbed = iteron_record::redact::scrub(text);
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let mut safe = String::with_capacity(scrubbed.len().min(max_bytes));
    for character in scrubbed.chars() {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        let representation = match character {
            '\n' => character.to_string(),
            '\t' => "    ".to_string(),
            character if character.is_control() => character.escape_default().to_string(),
            character => character.to_string(),
        };
        if safe.len().saturating_add(representation.len()) > max_bytes {
            return Some((safe, true));
        }
        safe.push_str(&representation);
    }
    Some((safe, false))
}

pub(super) fn bounded_safe(text: &str, max_bytes: usize) -> (String, bool) {
    let scrubbed = iteron_record::redact::scrub(text);
    let mut safe = String::with_capacity(scrubbed.len().min(max_bytes));
    let mut truncated = false;
    for character in scrubbed.chars() {
        let representation = match character {
            '\n' => character.to_string(),
            '\t' => "    ".to_string(),
            character if character.is_control() => character.escape_default().to_string(),
            character => character.to_string(),
        };
        if safe.len().saturating_add(representation.len()) > max_bytes {
            truncated = true;
            break;
        }
        safe.push_str(&representation);
    }
    (safe, truncated)
}

pub(super) fn move_bounded(current: usize, delta: isize, len: usize) -> usize {
    if delta < 0 {
        current.saturating_sub(delta.unsigned_abs())
    } else {
        current
            .saturating_add(delta as usize)
            .min(len.saturating_sub(1))
    }
}

pub(super) fn move_wrapped(current: usize, delta: isize, len: usize) -> usize {
    if delta < 0 {
        (current + len - (delta.unsigned_abs() % len)) % len
    } else {
        (current + delta as usize) % len
    }
}

//! Bounded viewer projection starts from the same semantic blocks as ordinary rendering/export.

use crate::block;
use unicode_normalization::UnicodeNormalization as _;

use super::{Entry, MAX_DETAIL_BYTES, MAX_INDEX_BLOCK_BYTES, MAX_QUERY_BYTES};

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

pub(super) fn raw_text(block: &block::Block) -> String {
    match &block.kind {
        block::BlockKind::User(text) => text.clone(),
        block::BlockKind::Assistant(document) => document.to_text(),
        block::BlockKind::Thinking { text, .. } => text.clone(),
        block::BlockKind::Tool(card) => serde_json::to_string_pretty(&serde_json::json!({
            "block_id": block.id,
            "kind": "tool",
            "name": card.name,
            "arguments": card.args,
            "status": match card.status {
                block::ToolStatus::Running => "running",
                block::ToolStatus::Ok => "ok",
                block::ToolStatus::Err => "error",
            },
            "exit_code": card.exit_code,
            "output": card.output,
        }))
        .unwrap_or_else(|_| "{\"kind\":\"tool\",\"error\":\"unavailable\"}".into()),
        block::BlockKind::Notice { text, .. } => text.clone(),
        block::BlockKind::Error { title, detail, .. } => format!("{title}\n{detail}"),
        block::BlockKind::Welcome { tagline } => tagline.clone(),
        _ => block.to_text(),
    }
}

pub(super) fn index_block(block: &block::Block, remaining: usize) -> Entry {
    let source = block.to_text();
    let (safe, truncated) = bounded_safe(&source, MAX_INDEX_BLOCK_BYTES);
    let folded = if truncated {
        String::new()
    } else {
        fold(&safe)
    };
    let within_block_limit = !truncated && folded.len() <= MAX_INDEX_BLOCK_BYTES;
    let complete = within_block_limit && folded.len() <= remaining;
    let required_bytes = (within_block_limit && !complete).then_some(folded.len());
    Entry {
        id: block.id,
        revision: block.revision,
        label: block_label(&block.kind),
        folded: if complete { folded } else { String::new() },
        complete,
        required_bytes,
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
    let scrubbed = core_record::redact::scrub(query);
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

pub(super) fn bounded_safe(text: &str, max_bytes: usize) -> (String, bool) {
    let scrubbed = core_record::redact::scrub(text);
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

pub(super) fn bounded_detail(text: &str) -> (String, bool) {
    const MARKER: &str = "\n[detail truncated at 64 KiB]\n";
    let (mut safe, truncated) = bounded_safe(text, MAX_DETAIL_BYTES.saturating_sub(MARKER.len()));
    if truncated {
        safe.push_str(MARKER);
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

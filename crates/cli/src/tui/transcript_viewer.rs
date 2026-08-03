//! Fullscreen transcript inspection over a bounded, incrementally synchronized semantic index.
//!
//! The viewer owns presentation and search state only. Transcript blocks remain the authority, and
//! every synchronization reconciles stable ids plus revisions, drops evicted ids, and refreshes
//! live blocks. Rendering reuses bounded row offsets and allocates only the rows in the viewport.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};

use crate::block;

mod render;
pub(crate) use render::render;
mod projection;
use projection::{block_label, raw_text};

#[cfg(test)]
mod tests;

const MAX_INDEX_ENTRIES: usize = 1200;
const MAX_INDEX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_INDEX_BLOCK_BYTES: usize = 2 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 512;
const MAX_RESULTS: usize = 512;
const MAX_DETAIL_BYTES: usize = 64 * 1024;
const MAX_DETAIL_ROWS: usize = 64 * 1024;
const MAX_NOTICE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportScope {
    Filtered,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    Copy { text: String, subject: &'static str },
    Export(ExportScope),
}

#[derive(Debug)]
struct Entry {
    id: u64,
    revision: u64,
    live: bool,
    label: &'static str,
    folded: String,
    complete: bool,
}

#[derive(Debug)]
struct Detail {
    id: u64,
    revision: u64,
    raw: bool,
    text: String,
    truncated: bool,
    layout_width: u16,
    row_ranges: Vec<(usize, usize)>,
}

#[derive(Debug, Default)]
pub(crate) struct Viewer {
    open: bool,
    entries: Vec<Entry>,
    selected_id: Option<u64>,
    query: String,
    editing_query: bool,
    results: Vec<u64>,
    results_truncated: bool,
    incomplete_entries: usize,
    result_position: usize,
    raw: bool,
    scroll: usize,
    detail: Option<Detail>,
    notice: String,
}

impl Viewer {
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    pub(crate) fn open(&mut self, query: &str, blocks: &[block::Block]) {
        self.open = true;
        self.query.clear();
        append_query(&mut self.query, query);
        self.editing_query = !query.is_empty();
        self.raw = false;
        self.scroll = 0;
        self.notice.clear();
        self.sync(blocks);
        if self.query.is_empty() {
            self.selected_id = self.entries.last().map(|entry| entry.id);
        }
        self.refresh_results();
        self.ensure_detail(blocks);
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
        self.editing_query = false;
        self.entries.clear();
        self.results.clear();
        self.query.clear();
        self.detail = None;
        self.selected_id = None;
        self.incomplete_entries = 0;
        self.notice.clear();
    }

    /// Incrementally update changed entries, while preserving transcript order and dropping ids
    /// that block eviction or `/clear` removed. Search is complete for each admitted block; the
    /// newest blocks receive a hard 16 MiB global budget and every omitted block is surfaced.
    pub(crate) fn sync(&mut self, blocks: &[block::Block]) {
        let mut old: HashMap<u64, Entry> = self
            .entries
            .drain(..)
            .map(|entry| (entry.id, entry))
            .collect();
        let blocks = &blocks[blocks.len().saturating_sub(MAX_INDEX_ENTRIES)..];
        let mut rebuilt = Vec::with_capacity(blocks.len());
        let mut remaining = MAX_INDEX_TOTAL_BYTES;
        for block in blocks.iter().rev() {
            let live = !block.cacheable();
            let entry = match old.remove(&block.id) {
                Some(entry)
                    if entry.revision == block.revision
                        && !entry.live
                        && !live
                        && entry.complete
                        && entry.folded.len() <= remaining =>
                {
                    entry
                }
                _ => index_block(block, remaining),
            };
            remaining = remaining.saturating_sub(entry.folded.len());
            rebuilt.push(entry);
        }
        rebuilt.reverse();
        self.entries = rebuilt;
        self.incomplete_entries = self.entries.iter().filter(|entry| !entry.complete).count();
        if self
            .selected_id
            .is_some_and(|id| !self.entries.iter().any(|entry| entry.id == id))
        {
            self.selected_id = self.entries.last().map(|entry| entry.id);
            self.scroll = 0;
            self.detail = None;
        }
        self.refresh_results();
        self.ensure_detail(blocks);
    }

    pub(crate) fn handle_paste(&mut self, text: &str, blocks: &[block::Block]) {
        if !self.editing_query {
            return;
        }
        append_query(&mut self.query, text);
        self.refresh_results();
        self.scroll = 0;
        self.ensure_detail(blocks);
    }

    pub(crate) fn scroll_up(&mut self, rows: usize) {
        self.scroll = self.scroll.saturating_sub(rows);
    }

    pub(crate) fn scroll_down(&mut self, rows: usize) {
        self.scroll = self.scroll.saturating_add(rows).min(MAX_DETAIL_ROWS);
    }

    pub(crate) fn set_notice(&mut self, notice: impl AsRef<str>) {
        self.notice = bounded_safe(notice.as_ref(), MAX_NOTICE_BYTES).0;
    }

    pub(crate) fn key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        blocks: &[block::Block],
    ) -> Option<Effect> {
        if self.editing_query {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.editing_query = false,
                KeyCode::Backspace => {
                    self.query.pop();
                    self.refresh_results();
                    self.scroll = 0;
                }
                KeyCode::Char(character)
                    if !modifiers.contains(KeyModifiers::CONTROL) && !character.is_control() =>
                {
                    append_query(&mut self.query, &character.to_string());
                    self.refresh_results();
                    self.scroll = 0;
                }
                _ => {}
            }
            self.ensure_detail(blocks);
            return None;
        }

        let shift = modifiers.contains(KeyModifiers::SHIFT);
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.close(),
            KeyCode::Char('/') => self.editing_query = true,
            KeyCode::Char('f') if modifiers.contains(KeyModifiers::CONTROL) => {
                self.editing_query = true;
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('N') | KeyCode::Char('n') if shift => self.move_result(-1),
            KeyCode::Char('n') => self.move_result(1),
            KeyCode::PageUp => self.scroll_up(10),
            KeyCode::PageDown => self.scroll_down(10),
            KeyCode::Home | KeyCode::Char('g') => self.select_edge(false),
            KeyCode::End | KeyCode::Char('G') => self.select_edge(true),
            KeyCode::Char('r') => {
                self.raw = !self.raw;
                self.detail = None;
                self.scroll = 0;
            }
            KeyCode::Char('Y') | KeyCode::Char('y') if shift => {
                if let Some(text) = self.selected_result_text(blocks) {
                    return Some(Effect::Copy {
                        text,
                        subject: "matching block projection",
                    });
                }
            }
            KeyCode::Char('y') => {
                self.ensure_detail(blocks);
                if let Some(detail) = &self.detail {
                    return Some(Effect::Copy {
                        text: detail.text.clone(),
                        subject: "selected block",
                    });
                }
            }
            KeyCode::Char('E') | KeyCode::Char('e') if shift => {
                return Some(Effect::Export(ExportScope::All));
            }
            KeyCode::Char('e') => return Some(Effect::Export(ExportScope::Filtered)),
            _ => {}
        }
        self.ensure_detail(blocks);
        None
    }

    pub(crate) fn export_ids(&self, scope: ExportScope) -> Option<Vec<u64>> {
        match scope {
            ExportScope::All => None,
            ExportScope::Filtered if self.query.is_empty() => None,
            ExportScope::Filtered => Some(self.results.clone()),
        }
    }

    fn refresh_results(&mut self) {
        self.results.clear();
        self.results_truncated = false;
        let folded_query = fold(&self.query);
        if folded_query.is_empty() {
            self.result_position = 0;
            return;
        }
        for entry in &self.entries {
            if entry.folded.contains(&folded_query) {
                if self.results.len() == MAX_RESULTS {
                    self.results_truncated = true;
                    break;
                }
                self.results.push(entry.id);
            }
        }
        if self.results.is_empty() {
            self.result_position = 0;
            if self
                .selected_id
                .is_none_or(|id| !self.entries.iter().any(|entry| entry.id == id))
            {
                self.selected_id = self.entries.last().map(|entry| entry.id);
            }
            self.detail = None;
            return;
        }
        self.result_position = self
            .selected_id
            .and_then(|selected| self.results.iter().position(|id| *id == selected))
            .unwrap_or(0);
        self.selected_id = self.results.get(self.result_position).copied();
        self.detail = None;
    }

    fn move_selection(&mut self, delta: isize) {
        if !self.query.is_empty() {
            self.move_result(delta);
            return;
        }
        if self.entries.is_empty() {
            return;
        }
        let current = self
            .selected_id
            .and_then(|id| self.entries.iter().position(|entry| entry.id == id))
            .unwrap_or(self.entries.len() - 1);
        let next = move_bounded(current, delta, self.entries.len());
        self.selected_id = self.entries.get(next).map(|entry| entry.id);
        self.detail = None;
        self.scroll = 0;
    }

    fn move_result(&mut self, delta: isize) {
        if self.results.is_empty() {
            return;
        }
        self.result_position = move_wrapped(self.result_position, delta, self.results.len());
        self.selected_id = self.results.get(self.result_position).copied();
        self.detail = None;
        self.scroll = 0;
    }

    fn select_edge(&mut self, last: bool) {
        let (selected, len) = if self.query.is_empty() {
            (
                if last {
                    self.entries.last().map(|entry| entry.id)
                } else {
                    self.entries.first().map(|entry| entry.id)
                },
                self.entries.len(),
            )
        } else {
            (
                if last {
                    self.results.last().copied()
                } else {
                    self.results.first().copied()
                },
                self.results.len(),
            )
        };
        self.selected_id = selected;
        self.result_position = if last { len.saturating_sub(1) } else { 0 };
        self.detail = None;
        self.scroll = 0;
    }

    fn ensure_detail(&mut self, blocks: &[block::Block]) {
        let Some(id) = self.selected_id else {
            self.detail = None;
            return;
        };
        let Some(block) = blocks.iter().find(|block| block.id == id) else {
            self.detail = None;
            return;
        };
        let current = self.detail.as_ref().is_some_and(|detail| {
            detail.id == id && detail.revision == block.revision && detail.raw == self.raw
        });
        if current && block.cacheable() {
            return;
        }
        let source = if self.raw {
            raw_text(block)
        } else {
            block.to_text()
        };
        let (text, truncated) = bounded_detail(&source);
        self.detail = Some(Detail {
            id,
            revision: block.revision,
            raw: self.raw,
            text,
            truncated,
            layout_width: 0,
            row_ranges: Vec::new(),
        });
    }

    fn selected_result_text(&self, blocks: &[block::Block]) -> Option<String> {
        let selected = self.selected_id?;
        if self.query.is_empty() || !self.results.contains(&selected) {
            return None;
        }
        self.entries
            .iter()
            .find(|entry| entry.id == selected)
            .filter(|entry| entry.complete)?;
        let source = blocks.iter().find(|block| block.id == selected)?.to_text();
        Some(bounded_detail(&source).0)
    }
}

fn index_block(block: &block::Block, remaining: usize) -> Entry {
    let source = block.to_text();
    let (safe, truncated) = bounded_safe(&source, MAX_INDEX_BLOCK_BYTES);
    let folded = if truncated {
        String::new()
    } else {
        fold(&safe)
    };
    let complete = !truncated && folded.len() <= MAX_INDEX_BLOCK_BYTES && folded.len() <= remaining;
    Entry {
        id: block.id,
        revision: block.revision,
        live: !block.cacheable(),
        label: block_label(&block.kind),
        folded: if complete { folded } else { String::new() },
        complete,
    }
}

fn append_query(query: &mut String, addition: &str) {
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

fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

fn bounded_safe(text: &str, max_bytes: usize) -> (String, bool) {
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

fn bounded_detail(text: &str) -> (String, bool) {
    const MARKER: &str = "\n[detail truncated at 64 KiB]\n";
    let (mut safe, truncated) = bounded_safe(text, MAX_DETAIL_BYTES.saturating_sub(MARKER.len()));
    if truncated {
        safe.push_str(MARKER);
    }
    (safe, truncated)
}

fn move_bounded(current: usize, delta: isize, len: usize) -> usize {
    if delta < 0 {
        current.saturating_sub(delta.unsigned_abs())
    } else {
        current
            .saturating_add(delta as usize)
            .min(len.saturating_sub(1))
    }
}

fn move_wrapped(current: usize, delta: isize, len: usize) -> usize {
    if delta < 0 {
        (current + len - (delta.unsigned_abs() % len)) % len
    } else {
        (current + delta as usize) % len
    }
}

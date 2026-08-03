//! Fullscreen transcript inspection over a bounded, incrementally synchronized semantic index.
//!
//! The viewer owns presentation and search state only. Transcript blocks remain the authority, and
//! every synchronization reconciles stable ids plus revisions, drops evicted ids, and refreshes
//! live blocks. Rendering reuses bounded row offsets and allocates only the rows in the viewport.

use std::collections::HashMap;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyModifiers};

use crate::block;

mod render;
pub(crate) use render::render;
mod projection;
use projection::{
    append_query, bounded_detail, bounded_safe, fold, index_block, move_bounded, move_wrapped,
    raw_text,
};

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
pub(super) struct Entry {
    id: u64,
    revision: u64,
    label: &'static str,
    folded: String,
    complete: bool,
    /// Folded bytes needed by a globally budget-excluded block. `None` on complete blocks and on
    /// permanently per-block-oversized projections, which lets unrelated live updates reuse an
    /// incomplete entry without re-scrubbing megabytes.
    required_bytes: Option<usize>,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct WorkCounters {
    index_syncs: usize,
    index_projections: usize,
    result_rebuilds: usize,
    detail_rebuilds: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Viewer {
    open: bool,
    entries: Vec<Entry>,
    entry_positions: HashMap<u64, usize>,
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
    pending_effect: Option<&'static str>,
    authority_revision: Option<u64>,
    index_revision: u64,
    query_revision: u64,
    results_revision: Option<(u64, u64)>,
    work: WorkCounters,
}

impl Viewer {
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    pub(crate) fn open(
        &mut self,
        query: &str,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) {
        self.open = true;
        self.query.clear();
        append_query(&mut self.query, query);
        self.query_revision = self.query_revision.wrapping_add(1);
        self.results_revision = None;
        self.editing_query = !query.is_empty();
        self.raw = false;
        self.scroll = 0;
        self.notice.clear();
        self.pending_effect = None;
        self.authority_revision = None;
        self.sync_if_changed(blocks, authority_revision);
        if self.query.is_empty() {
            self.selected_id = self.entries.last().map(|entry| entry.id);
        }
        self.refresh_results_if_changed();
        self.ensure_detail(blocks);
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
        self.editing_query = false;
        self.entries.clear();
        self.entry_positions.clear();
        self.results.clear();
        self.query.clear();
        self.detail = None;
        self.selected_id = None;
        self.incomplete_entries = 0;
        self.notice.clear();
        self.pending_effect = None;
        self.authority_revision = None;
        self.results_revision = None;
    }

    /// Incrementally update changed entries, while preserving transcript order and dropping ids
    /// that block eviction or `/clear` removed. Search is complete for each admitted block; the
    /// newest blocks receive a hard 16 MiB global budget and every omitted block is surfaced.
    pub(crate) fn sync_if_changed(
        &mut self,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) {
        if self.authority_revision == Some(authority_revision) {
            return;
        }
        self.authority_revision = Some(authority_revision);
        self.work.index_syncs = self.work.index_syncs.saturating_add(1);
        let mut old: HashMap<u64, Entry> = self
            .entries
            .drain(..)
            .map(|entry| (entry.id, entry))
            .collect();
        let blocks = &blocks[blocks.len().saturating_sub(MAX_INDEX_ENTRIES)..];
        let mut rebuilt = Vec::with_capacity(blocks.len());
        let mut remaining = MAX_INDEX_TOTAL_BYTES;
        for block in blocks.iter().rev() {
            let entry = match old.remove(&block.id) {
                Some(mut entry) if entry.revision == block.revision && entry.complete => {
                    if entry.folded.len() <= remaining {
                        entry
                    } else {
                        entry.required_bytes = Some(entry.folded.len());
                        entry.folded.clear();
                        entry.complete = false;
                        entry
                    }
                }
                Some(entry)
                    if entry.revision == block.revision
                        && entry.required_bytes.is_none_or(|bytes| bytes > remaining) =>
                {
                    entry
                }
                _ => {
                    self.work.index_projections = self.work.index_projections.saturating_add(1);
                    index_block(block, remaining)
                }
            };
            remaining = remaining.saturating_sub(entry.folded.len());
            rebuilt.push(entry);
        }
        rebuilt.reverse();
        self.entries = rebuilt;
        self.entry_positions.clear();
        self.entry_positions.extend(
            self.entries
                .iter()
                .enumerate()
                .map(|(position, entry)| (entry.id, position)),
        );
        self.incomplete_entries = self.entries.iter().filter(|entry| !entry.complete).count();
        if self
            .selected_id
            .is_some_and(|id| !self.entry_positions.contains_key(&id))
        {
            self.selected_id = self.entries.last().map(|entry| entry.id);
            self.scroll = 0;
            self.detail = None;
        }
        self.index_revision = self.index_revision.wrapping_add(1);
        self.refresh_results_if_changed();
        self.ensure_detail(blocks);
    }

    pub(crate) fn handle_paste(&mut self, text: &str, blocks: &[Arc<block::Block>]) {
        if !self.editing_query {
            return;
        }
        let before = self.query.clone();
        append_query(&mut self.query, text);
        if self.query != before {
            self.query_revision = self.query_revision.wrapping_add(1);
        }
        self.refresh_results_if_changed();
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

    pub(crate) fn begin_effect(&mut self, label: &'static str) {
        self.pending_effect = Some(label);
        self.set_notice(format!("{label} pending…"));
    }

    pub(crate) fn finish_effect(&mut self, notice: impl AsRef<str>) {
        self.pending_effect = None;
        self.set_notice(notice);
    }

    pub(crate) fn key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        blocks: &[Arc<block::Block>],
    ) -> Option<Effect> {
        if self.editing_query {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.editing_query = false,
                KeyCode::Backspace => {
                    if self.query.pop().is_some() {
                        self.query_revision = self.query_revision.wrapping_add(1);
                        self.refresh_results_if_changed();
                        self.scroll = 0;
                    }
                }
                KeyCode::Char(character)
                    if !modifiers.contains(KeyModifiers::CONTROL) && !character.is_control() =>
                {
                    let before = self.query.len();
                    append_query(&mut self.query, &character.to_string());
                    if self.query.len() != before {
                        self.query_revision = self.query_revision.wrapping_add(1);
                    }
                    self.refresh_results_if_changed();
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

    pub(crate) fn export_ids(&self, scope: ExportScope) -> Result<Option<Vec<u64>>, String> {
        match scope {
            ExportScope::All => Ok(None),
            ExportScope::Filtered if self.query.is_empty() => Ok(None),
            ExportScope::Filtered if self.incomplete_entries > 0 => Err(format!(
                "filtered export refused: search is incomplete for {} blocks",
                self.incomplete_entries
            )),
            ExportScope::Filtered if self.results_truncated => {
                Err("filtered export refused: matching results exceed the 512-result cap".into())
            }
            ExportScope::Filtered => Ok(Some(self.results.clone())),
        }
    }

    fn refresh_results_if_changed(&mut self) {
        let revision = (self.index_revision, self.query_revision);
        if self.results_revision == Some(revision) {
            return;
        }
        self.results_revision = Some(revision);
        self.work.result_rebuilds = self.work.result_rebuilds.saturating_add(1);
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
                .is_none_or(|id| !self.entry_positions.contains_key(&id))
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
            .and_then(|id| self.entry_positions.get(&id).copied())
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

    fn ensure_detail(&mut self, blocks: &[Arc<block::Block>]) {
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
        if current {
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
        self.work.detail_rebuilds = self.work.detail_rebuilds.saturating_add(1);
    }

    fn selected_result_text(&self, blocks: &[Arc<block::Block>]) -> Option<String> {
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

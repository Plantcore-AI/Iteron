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
mod effect;
pub(crate) use effect::{Effect, ExportScope};
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
/// One projection can consume at most `MAX_INDEX_BLOCK_BYTES`; doing exactly one per loop turn
/// prevents the former 16 MiB synchronous burst from monopolizing input, effects, signals, or draw.
const MAX_INDEX_PROJECTIONS_PER_TICK: usize = 1;
const MAX_SEARCH_ENTRIES_PER_TICK: usize = 1;

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
    /// True when the global budget was already exhausted before this block was inspected. Such an
    /// entry is cheap metadata only and must be projected if a later reconciliation frees budget.
    needs_projection: bool,
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

mod index;
use index::{IndexJob, SearchJob};

#[derive(Default)]
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
    index_job: Option<IndexJob>,
    search_job: Option<SearchJob>,
    work: WorkCounters,
}

impl Viewer {
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    #[cfg(test)]
    pub(crate) fn pending_effect_label(&self) -> Option<&'static str> {
        self.pending_effect
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
        self.index_job = None;
        self.search_job = None;
    }

    pub(crate) fn handle_paste(
        &mut self,
        text: &str,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) {
        self.sync_if_changed(blocks, authority_revision);
        if !self.editing_query {
            return;
        }
        let before = self.query.clone();
        append_query(&mut self.query, text);
        if self.query != before {
            self.query_revision = self.query_revision.wrapping_add(1);
            self.query_changed();
        }
        self.scroll = 0;
        if !self.work_pending() {
            self.ensure_detail(blocks);
        }
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
        authority_revision: u64,
    ) -> Option<Effect> {
        // Input can arrive during frame coalescing after the EQ mutated the transcript but before
        // the next draw. Reconcile here as an authority gate so result ids and copied/exported Arc
        // snapshots can never come from different revisions.
        self.sync_if_changed(blocks, authority_revision);
        if self.editing_query {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.editing_query = false,
                KeyCode::Backspace => {
                    if self.query.pop().is_some() {
                        self.query_revision = self.query_revision.wrapping_add(1);
                        self.query_changed();
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
                        self.query_changed();
                    }
                    self.scroll = 0;
                }
                _ => {}
            }
            if !self.work_pending() {
                self.ensure_detail(blocks);
            }
            return None;
        }

        let shift = modifiers.contains(KeyModifiers::SHIFT);
        if self.work_pending() {
            match code {
                KeyCode::Esc | KeyCode::Char('q') => self.close(),
                KeyCode::Char('/') => self.editing_query = true,
                KeyCode::Char('f') if modifiers.contains(KeyModifiers::CONTROL) => {
                    self.editing_query = true;
                }
                _ => self.set_notice("transcript index is updating; snapshot effects are pending"),
            }
            return None;
        }
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
                        snapshot_revision: authority_revision,
                    });
                }
            }
            KeyCode::Char('y') => {
                self.ensure_detail(blocks);
                if let Some(detail) = &self.detail {
                    return Some(Effect::Copy {
                        text: detail.text.clone(),
                        subject: "selected block",
                        snapshot_revision: authority_revision,
                    });
                }
            }
            KeyCode::Char('E') | KeyCode::Char('e') if shift => {
                return Some(Effect::Export {
                    scope: ExportScope::All,
                    snapshot_revision: authority_revision,
                });
            }
            KeyCode::Char('e') => {
                return Some(Effect::Export {
                    scope: ExportScope::Filtered,
                    snapshot_revision: authority_revision,
                });
            }
            _ => {}
        }
        self.ensure_detail(blocks);
        None
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
}

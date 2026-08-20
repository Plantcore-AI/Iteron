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
use projection::{append_query, bounded_safe, fold, move_bounded, move_wrapped};
mod projection_worker;
use projection_worker::{
    DetailKey, ProjectionKey, ProjectionResult, ProjectionWorker, WorkKey, WorkerPoll,
};
mod semantic_text;

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
/// Search matching itself is cheap but still advances one entry per loop turn. Expensive block
/// projection is owned by the single background worker in `projection_worker`.
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

struct DetailRequest {
    key: DetailKey,
    block: Arc<block::Block>,
}

#[derive(Clone, Copy)]
struct PendingCopy {
    key: DetailKey,
    subject: &'static str,
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
    projection_worker: ProjectionWorker,
    desired_detail: Option<DetailRequest>,
    pending_copy: Option<PendingCopy>,
    ready_effect: Option<Effect>,
    next_index_generation: u64,
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
        self.projection_worker.close();
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
        self.desired_detail = None;
        self.pending_copy = None;
        self.ready_effect = None;
        self.sync_if_changed(blocks, authority_revision);
    }

    pub(crate) fn close(&mut self) {
        self.projection_worker.close();
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
        self.desired_detail = None;
        self.pending_copy = None;
        self.ready_effect = None;
    }

    pub(crate) fn handle_paste(
        &mut self,
        text: &str,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) {
        self.reconcile_if_changed(blocks, authority_revision);
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
        self.queue_display_detail(blocks, authority_revision);
    }

    pub(crate) fn scroll_up(&mut self, rows: usize) {
        self.scroll = self.scroll.saturating_sub(rows);
    }

    pub(crate) fn scroll_down(&mut self, rows: usize) {
        self.scroll = self
            .scroll
            .saturating_add(rows)
            .min(iteron_tunables::param_integer(
                "cli.tui.transcript_viewer.max_detail_rows",
                MAX_DETAIL_ROWS,
            ));
    }

    pub(crate) fn set_notice(&mut self, notice: impl AsRef<str>) {
        self.notice = bounded_safe(
            notice.as_ref(),
            iteron_tunables::param_integer(
                "cli.tui.transcript_viewer.max_notice_bytes",
                MAX_NOTICE_BYTES,
            ),
        )
        .0;
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
        self.reconcile_if_changed(blocks, authority_revision);
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
            self.queue_display_detail(blocks, authority_revision);
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
                // These change how the already-loaded blocks are drawn and nothing else: no
                // snapshot is read, no revision is quoted, no effect is emitted. Holding them
                // until the index settles made the viewer silently ignore a keypress on exactly
                // the machines where indexing is slow -- press `r` on a busy host and the view
                // stayed pretty while a notice claimed effects were pending, which is not what
                // `r` does. The keys that DO quote a revision (`y`, `e`, `E`) still fall through
                // to the notice below, because for those the wait is the point.
                KeyCode::Char('r') => {
                    self.raw = !self.raw;
                    self.invalidate_detail_intent();
                    self.scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
                KeyCode::PageUp => self.scroll_up(10),
                KeyCode::PageDown => self.scroll_down(10),
                KeyCode::Home | KeyCode::Char('g') => self.select_edge(false),
                KeyCode::End | KeyCode::Char('G') => self.select_edge(true),
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
                self.invalidate_detail_intent();
                self.scroll = 0;
            }
            KeyCode::Char('Y') | KeyCode::Char('y') if shift => {
                return self.request_copy(
                    false,
                    "matching block projection",
                    true,
                    blocks,
                    authority_revision,
                );
            }
            KeyCode::Char('y') => {
                return self.request_copy(
                    self.raw,
                    "selected block",
                    false,
                    blocks,
                    authority_revision,
                );
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
        self.queue_display_detail(blocks, authority_revision);
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
        self.invalidate_detail_intent();
        self.scroll = 0;
    }

    fn move_result(&mut self, delta: isize) {
        if self.results.is_empty() {
            return;
        }
        self.result_position = move_wrapped(self.result_position, delta, self.results.len());
        self.selected_id = self.results.get(self.result_position).copied();
        self.invalidate_detail_intent();
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
        self.invalidate_detail_intent();
        self.scroll = 0;
    }

    fn invalidate_detail_intent(&mut self) {
        self.detail = None;
        self.desired_detail = None;
        self.pending_copy = None;
        self.ready_effect = None;
        if matches!(
            self.projection_worker.in_flight_key(),
            Some(WorkKey::Detail(_))
        ) {
            self.projection_worker.cancel_in_flight();
        }
    }

    fn queue_display_detail(&mut self, blocks: &[Arc<block::Block>], authority_revision: u64) {
        if self.work_pending() {
            return;
        }
        let target_raw = self
            .pending_copy
            .map_or(self.raw, |pending| pending.key.raw);
        let Some(id) = self.selected_id else {
            self.detail = None;
            self.desired_detail = None;
            return;
        };
        let Some(block) = blocks.iter().find(|block| block.id == id).cloned() else {
            self.detail = None;
            self.desired_detail = None;
            return;
        };
        let key = DetailKey {
            authority_revision,
            id,
            revision: block.revision,
            raw: target_raw,
        };
        if self.detail.as_ref().is_some_and(|detail| {
            detail.id == key.id && detail.revision == key.revision && detail.raw == key.raw
        }) && self.pending_copy.is_none()
        {
            self.desired_detail = None;
            return;
        }
        if self.projection_worker.in_flight_key() == Some(WorkKey::Detail(key))
            || self
                .desired_detail
                .as_ref()
                .is_some_and(|request| request.key == key)
        {
            return;
        }
        if self.projection_worker.is_busy() {
            self.projection_worker.cancel_in_flight();
        }
        self.desired_detail = Some(DetailRequest { key, block });
    }

    fn request_copy(
        &mut self,
        raw: bool,
        subject: &'static str,
        matching_only: bool,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) -> Option<Effect> {
        let selected = self.selected_id?;
        if matching_only
            && (self.query.is_empty()
                || !self.results.contains(&selected)
                || self
                    .entries
                    .iter()
                    .find(|entry| entry.id == selected)
                    .is_none_or(|entry| !entry.complete))
        {
            return None;
        }
        let block = blocks.iter().find(|block| block.id == selected)?.clone();
        let key = DetailKey {
            authority_revision,
            id: selected,
            revision: block.revision,
            raw,
        };
        if let Some(detail) = self.detail.as_ref().filter(|detail| {
            detail.id == key.id && detail.revision == key.revision && detail.raw == key.raw
        }) {
            return Some(Effect::Copy {
                text: detail.text.clone(),
                subject,
                snapshot_revision: authority_revision,
            });
        }
        self.pending_copy = Some(PendingCopy { key, subject });
        if self.projection_worker.in_flight_key() != Some(WorkKey::Detail(key)) {
            if self.projection_worker.is_busy() {
                self.projection_worker.cancel_in_flight();
            }
            self.desired_detail = Some(DetailRequest { key, block });
        }
        self.set_notice("copy projection pending…");
        None
    }

    pub(crate) fn take_ready_effect(&mut self) -> Option<Effect> {
        self.ready_effect.take()
    }
}

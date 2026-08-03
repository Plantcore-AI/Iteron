//! Incremental revision-authoritative transcript indexing and result matching.

use super::*;

pub(super) struct IndexJob {
    authority_revision: u64,
    blocks: Vec<Arc<block::Block>>,
    reusable: HashMap<u64, Entry>,
    newest_first: Vec<Entry>,
    next: usize,
    remaining_bytes: usize,
}

impl IndexJob {
    fn progress(&self) -> (usize, usize) {
        (
            self.blocks.len().saturating_sub(self.next),
            self.blocks.len(),
        )
    }

    fn into_reusable(mut self) -> HashMap<u64, Entry> {
        self.reusable
            .extend(self.newest_first.drain(..).map(|entry| (entry.id, entry)));
        self.reusable
    }
}

#[derive(Debug)]
pub(super) struct SearchJob {
    index_revision: u64,
    query_revision: u64,
    folded_query: String,
    cursor: usize,
    results: Vec<u64>,
    truncated: bool,
}

impl SearchJob {
    fn progress(&self, total: usize) -> (usize, usize) {
        (self.cursor.min(total), total)
    }
}

impl Viewer {
    /// Schedule the newest transcript authority and perform at most one bounded work unit. Each
    /// TUI loop turn calls this once; indexing and result matching therefore cannot synchronously
    /// scan the former 16 MiB ceiling. A new authority cancels stale visible state immediately and
    /// reuses only entries whose block id and revision still match.
    pub(crate) fn sync_if_changed(
        &mut self,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) -> bool {
        let target_is_current = self.authority_revision == Some(authority_revision)
            || self
                .index_job
                .as_ref()
                .is_some_and(|job| job.authority_revision == authority_revision);
        if !target_is_current {
            let mut reusable = self
                .index_job
                .take()
                .map(IndexJob::into_reusable)
                .unwrap_or_default();
            reusable.extend(self.entries.drain(..).map(|entry| (entry.id, entry)));
            let start = blocks.len().saturating_sub(MAX_INDEX_ENTRIES);
            let target = blocks[start..].to_vec();
            let total = target.len();
            self.index_job = Some(IndexJob {
                authority_revision,
                blocks: target,
                reusable,
                newest_first: Vec::with_capacity(total),
                next: total,
                remaining_bytes: MAX_INDEX_TOTAL_BYTES,
            });
            self.authority_revision = None;
            self.search_job = None;
            self.results_revision = None;
            self.entries.clear();
            self.entry_positions.clear();
            self.results.clear();
            self.results_truncated = false;
            self.incomplete_entries = 0;
            self.detail = None;
            self.work.index_syncs = self.work.index_syncs.saturating_add(1);
        }
        self.advance_work(blocks)
    }

    fn advance_work(&mut self, live_blocks: &[Arc<block::Block>]) -> bool {
        if self.index_job.is_some() {
            for _ in 0..MAX_INDEX_PROJECTIONS_PER_TICK {
                let Some(job) = self.index_job.as_mut() else {
                    break;
                };
                if job.next == 0 {
                    break;
                }
                job.next -= 1;
                let block = &job.blocks[job.next];
                let entry = match job.reusable.remove(&block.id) {
                    Some(mut entry) if entry.revision == block.revision && entry.complete => {
                        if entry.folded.len() <= job.remaining_bytes {
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
                            && !entry.needs_projection
                            && entry
                                .required_bytes
                                .is_none_or(|bytes| bytes > job.remaining_bytes) =>
                    {
                        entry
                    }
                    Some(entry) if entry.revision == block.revision && job.remaining_bytes == 0 => {
                        entry
                    }
                    _ if job.remaining_bytes == 0 => projection::unprojected_block(block),
                    _ => {
                        self.work.index_projections = self.work.index_projections.saturating_add(1);
                        index_block(block, job.remaining_bytes)
                    }
                };
                if !entry.complete {
                    job.remaining_bytes = 0;
                } else {
                    job.remaining_bytes = job.remaining_bytes.saturating_sub(entry.folded.len());
                }
                job.newest_first.push(entry);
            }
            if self.index_job.as_ref().is_some_and(|job| job.next == 0) {
                let mut job = self.index_job.take().expect("index job was present");
                job.newest_first.reverse();
                self.entries = job.newest_first;
                self.authority_revision = Some(job.authority_revision);
                self.entry_positions.clear();
                self.entry_positions.extend(
                    self.entries
                        .iter()
                        .enumerate()
                        .map(|(position, entry)| (entry.id, position)),
                );
                self.incomplete_entries =
                    self.entries.iter().filter(|entry| !entry.complete).count();
                if self
                    .selected_id
                    .is_some_and(|id| !self.entry_positions.contains_key(&id))
                {
                    self.selected_id = None;
                    self.scroll = 0;
                }
                self.index_revision = self.index_revision.wrapping_add(1);
                self.start_search();
                if self.search_job.is_none() {
                    self.ensure_detail(live_blocks);
                }
            }
            return true;
        }

        let Some(job) = self.search_job.as_mut() else {
            return false;
        };
        for _ in 0..MAX_SEARCH_ENTRIES_PER_TICK {
            if job.cursor == self.entries.len() || job.truncated {
                break;
            }
            let entry = &self.entries[job.cursor];
            job.cursor += 1;
            if entry.complete && entry.folded.contains(&job.folded_query) {
                if job.results.len() == MAX_RESULTS {
                    job.truncated = true;
                } else {
                    job.results.push(entry.id);
                }
            }
        }
        if self
            .search_job
            .as_ref()
            .is_some_and(|job| job.cursor == self.entries.len() || job.truncated)
        {
            self.finish_search(live_blocks);
        }
        true
    }

    fn start_search(&mut self) {
        self.results.clear();
        self.results_truncated = false;
        self.results_revision = None;
        self.detail = None;
        let folded_query = fold(&self.query);
        if folded_query.is_empty() {
            self.search_job = None;
            self.results_revision = Some((self.index_revision, self.query_revision));
            self.result_position = 0;
            if self
                .selected_id
                .is_none_or(|id| !self.entry_positions.contains_key(&id))
            {
                self.selected_id = self.entries.last().map(|entry| entry.id);
            }
            return;
        }
        self.search_job = Some(SearchJob {
            index_revision: self.index_revision,
            query_revision: self.query_revision,
            folded_query,
            cursor: 0,
            results: Vec::new(),
            truncated: false,
        });
    }

    fn finish_search(&mut self, blocks: &[Arc<block::Block>]) {
        let job = self.search_job.take().expect("search job was present");
        if job.index_revision != self.index_revision || job.query_revision != self.query_revision {
            self.start_search();
            return;
        }
        self.results = job.results;
        self.results_truncated = job.truncated;
        self.results_revision = Some((job.index_revision, job.query_revision));
        self.work.result_rebuilds = self.work.result_rebuilds.saturating_add(1);
        if self.results.is_empty() {
            self.result_position = 0;
            if self
                .selected_id
                .is_none_or(|id| !self.entry_positions.contains_key(&id))
            {
                self.selected_id = self.entries.last().map(|entry| entry.id);
            }
        } else {
            self.result_position = self
                .selected_id
                .and_then(|selected| self.results.iter().position(|id| *id == selected))
                .unwrap_or(0);
            self.selected_id = self.results.get(self.result_position).copied();
        }
        self.ensure_detail(blocks);
    }

    pub(super) fn query_changed(&mut self) {
        self.results_revision = None;
        self.results.clear();
        self.results_truncated = false;
        self.detail = None;
        if self.index_job.is_none() {
            self.start_search();
        } else {
            self.search_job = None;
        }
    }

    pub(crate) fn work_pending(&self) -> bool {
        self.index_job.is_some() || self.search_job.is_some()
    }

    pub(super) fn work_progress(&self) -> Option<(&'static str, usize, usize)> {
        if let Some(job) = &self.index_job {
            let (done, total) = job.progress();
            return Some(("indexing", done, total));
        }
        self.search_job.as_ref().map(|job| {
            let (done, total) = job.progress(self.entries.len());
            ("searching", done, total)
        })
    }
}

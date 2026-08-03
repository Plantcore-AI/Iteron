//! Incremental revision-authoritative transcript indexing and result matching.

use super::*;

pub(super) struct IndexJob {
    generation: u64,
    authority_revision: u64,
    blocks: Vec<Arc<block::Block>>,
    pub(super) reusable: HashMap<u64, Entry>,
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

    fn projection_key(&self) -> Option<ProjectionKey> {
        let block = self.blocks.get(self.next.checked_sub(1)?)?;
        Some(ProjectionKey {
            generation: self.generation,
            next: self.next,
            id: block.id,
            revision: block.revision,
            remaining: self.remaining_bytes,
        })
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
    /// Schedule the newest transcript authority and perform at most one bounded unit. Expensive
    /// per-block rendering, redaction, and Unicode folding run on one persistent background worker;
    /// this method only dispatches or collects one result, never projects MiB on the TUI thread.
    pub(crate) fn sync_if_changed(
        &mut self,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) -> bool {
        let reconciled = self.reconcile_if_changed(blocks, authority_revision);
        self.advance_work(blocks) || reconciled
    }

    /// Refresh authority without advancing work. Input uses this gate after the loop's one work
    /// unit, so a key cannot accidentally double the per-turn budget while stale snapshot effects
    /// remain blocked immediately.
    pub(crate) fn reconcile_if_changed(
        &mut self,
        blocks: &[Arc<block::Block>],
        authority_revision: u64,
    ) -> bool {
        let target_is_current = self.authority_revision == Some(authority_revision)
            || self
                .index_job
                .as_ref()
                .is_some_and(|job| job.authority_revision == authority_revision);
        if target_is_current {
            return false;
        }

        self.projection_worker.cancel_in_flight();
        self.desired_detail = None;
        self.pending_copy = None;
        self.ready_effect = None;

        let mut reusable = self
            .index_job
            .take()
            .map(IndexJob::into_reusable)
            .unwrap_or_default();
        reusable.extend(self.entries.drain(..).map(|entry| (entry.id, entry)));
        let start = blocks.len().saturating_sub(MAX_INDEX_ENTRIES);
        let target = blocks[start..].to_vec();
        let retained_revisions = target
            .iter()
            .map(|block| (block.id, block.revision))
            .collect::<HashMap<_, _>>();
        // Cancellation cannot turn the reuse cache into a history store. Retain exactly the newest
        // 1200 authority ids *and revisions*; old ids and old payload revisions are dropped now.
        reusable.retain(|id, entry| retained_revisions.get(id) == Some(&entry.revision));
        let total = target.len();
        let generation = self.next_index_generation;
        self.next_index_generation = self.next_index_generation.wrapping_add(1);
        self.index_job = Some(IndexJob {
            generation,
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
        true
    }

    fn advance_work(&mut self, live_blocks: &[Arc<block::Block>]) -> bool {
        match self.projection_worker.poll() {
            WorkerPoll::Ready(ProjectionResult::Index { key, entry }) => {
                let matches_current =
                    self.index_job.as_ref().and_then(IndexJob::projection_key) == Some(key);
                if matches_current {
                    let block = self
                        .index_job
                        .as_ref()
                        .and_then(|job| job.blocks.get(job.next.saturating_sub(1)))
                        .expect("matching projection has a block")
                        .clone();
                    self.commit_index_entry(
                        entry.unwrap_or_else(|()| projection::unprojected_block(&block)),
                    );
                    self.finish_index_if_ready(live_blocks);
                }
                // A superseded or cancelled result is discarded as its one bounded unit. The next
                // loop turn can dispatch current authority/detail work without doing two units.
                return true;
            }
            WorkerPoll::Ready(ProjectionResult::Detail { key, detail }) => {
                self.commit_detail_result(key, detail, live_blocks);
                return true;
            }
            WorkerPoll::Pending => return false,
            WorkerPoll::Idle => {}
        }

        if self.index_job.is_some() {
            if self.index_job.as_ref().is_some_and(|job| job.next == 0) {
                self.finish_index_if_ready(live_blocks);
                return true;
            }

            let (key, block, reused) = {
                let job = self.index_job.as_mut().expect("index job was present");
                let key = job.projection_key().expect("unfinished job has a block");
                let block = job.blocks[job.next - 1].clone();
                let reused = match job.reusable.remove(&block.id) {
                    Some(mut entry) if entry.revision == block.revision && entry.complete => {
                        if entry.folded.len() <= job.remaining_bytes {
                            Some(entry)
                        } else {
                            entry.required_bytes = Some(entry.folded.len());
                            entry.folded.clear();
                            entry.complete = false;
                            Some(entry)
                        }
                    }
                    Some(entry)
                        if entry.revision == block.revision
                            && !entry.needs_projection
                            && entry
                                .required_bytes
                                .is_none_or(|bytes| bytes > job.remaining_bytes) =>
                    {
                        Some(entry)
                    }
                    Some(entry) if entry.revision == block.revision && job.remaining_bytes == 0 => {
                        Some(entry)
                    }
                    _ if job.remaining_bytes == 0 => Some(projection::unprojected_block(&block)),
                    _ => None,
                };
                (key, block, reused)
            };

            if let Some(entry) = reused {
                self.commit_index_entry(entry);
                self.finish_index_if_ready(live_blocks);
                return true;
            }

            self.work.index_projections = self.work.index_projections.saturating_add(1);
            if self
                .projection_worker
                .start_index(key, block.clone())
                .is_err()
            {
                self.commit_index_entry(projection::unprojected_block(&block));
                self.finish_index_if_ready(live_blocks);
                return true;
            }
            return false;
        }

        if let Some(job) = self.search_job.as_mut() {
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
            return true;
        }

        let Some(request) = self.desired_detail.take() else {
            return false;
        };
        let key = request.key;
        if self
            .projection_worker
            .start_detail(key, request.block)
            .is_err()
        {
            if self.pending_copy.is_some_and(|pending| pending.key == key) {
                self.pending_copy = None;
            }
            self.set_notice("detail projection worker is unavailable");
            return true;
        }
        false
    }

    fn commit_detail_result(
        &mut self,
        key: DetailKey,
        result: Result<projection::DetailProjection, ()>,
        live_blocks: &[Arc<block::Block>],
    ) {
        let current = self.authority_revision == Some(key.authority_revision)
            && self.selected_id == Some(key.id)
            && live_blocks
                .iter()
                .find(|block| block.id == key.id)
                .is_some_and(|block| block.revision == key.revision);
        match result {
            Ok(projected) if current => {
                if key.raw == self.raw {
                    self.detail = Some(Detail {
                        id: key.id,
                        revision: key.revision,
                        raw: key.raw,
                        text: projected.text.clone(),
                        truncated: projected.truncated,
                        layout_width: 0,
                        row_ranges: Vec::new(),
                    });
                    self.work.detail_rebuilds = self.work.detail_rebuilds.saturating_add(1);
                }
                if let Some(pending) = self.pending_copy.filter(|pending| pending.key == key) {
                    self.ready_effect = Some(Effect::Copy {
                        text: projected.text,
                        subject: pending.subject,
                        snapshot_revision: key.authority_revision,
                    });
                    self.pending_copy = None;
                }
            }
            Ok(_) => {}
            Err(()) => {
                if self.pending_copy.is_some_and(|pending| pending.key == key) {
                    self.pending_copy = None;
                    self.set_notice("detail projection was cancelled or failed");
                }
            }
        }
        self.queue_display_detail(
            live_blocks,
            self.authority_revision.unwrap_or(key.authority_revision),
        );
    }

    fn commit_index_entry(&mut self, entry: Entry) {
        let job = self.index_job.as_mut().expect("index job was present");
        job.next = job.next.checked_sub(1).expect("unfinished index job");
        if !entry.complete {
            job.remaining_bytes = 0;
        } else {
            job.remaining_bytes = job.remaining_bytes.saturating_sub(entry.folded.len());
        }
        job.newest_first.push(entry);
    }

    fn finish_index_if_ready(&mut self, live_blocks: &[Arc<block::Block>]) {
        if self.index_job.as_ref().is_none_or(|job| job.next != 0) {
            return;
        }
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
        self.incomplete_entries = self.entries.iter().filter(|entry| !entry.complete).count();
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
            self.queue_display_detail(live_blocks, job.authority_revision);
        }
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
        if let Some(authority_revision) = self.authority_revision {
            self.queue_display_detail(blocks, authority_revision);
        }
    }

    pub(super) fn query_changed(&mut self) {
        self.results_revision = None;
        self.results.clear();
        self.results_truncated = false;
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
        if self.index_job.is_none() {
            self.start_search();
        } else {
            self.search_job = None;
        }
    }

    pub(crate) fn work_pending(&self) -> bool {
        self.index_job.is_some() || self.search_job.is_some()
    }

    /// True when another loop turn can advance work without waiting for the background projection.
    pub(crate) fn work_ready(&self) -> bool {
        (self.work_pending() || self.desired_detail.is_some()) && !self.projection_worker.is_busy()
    }

    pub(crate) fn work_notification(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.projection_worker.notification()
    }

    #[cfg(test)]
    pub(super) fn background_work_pending(&self) -> bool {
        self.work_pending() || self.desired_detail.is_some() || self.projection_worker.is_busy()
    }

    pub(super) fn work_progress(&self) -> Option<(&'static str, usize, usize)> {
        if let Some(job) = &self.index_job {
            let (done, total) = job.progress();
            return Some(("indexing", done, total));
        }
        if let Some(job) = &self.search_job {
            let (done, total) = job.progress(self.entries.len());
            return Some(("searching", done, total));
        }
        (self.desired_detail.is_some() || self.projection_worker.is_busy()).then_some((
            "projecting detail",
            0,
            1,
        ))
    }
}

//! Actual settled-row cache and retained geometry. The compositor receives immutable rows;
//! semantic records and frame geometry cannot mutate the cache independently.

use super::{hyperlink, transcript_layout};
use crate::{block, render, theme};
use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::sync::Arc;

const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct GeometryContext<'a> {
    pub(super) width: u16,
    pub(super) theme_epoch: u64,
    pub(super) theme: &'a theme::Theme,
    pub(super) spin: usize,
    pub(super) hyperlinks: &'a hyperlink::Policy,
    pub(super) region_block: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReadingAnchor {
    block_id: u64,
    row_in_block: usize,
}

struct CachedBlock {
    revision: u64,
    rendered: render::RenderedLines,
    charge: usize,
}

#[derive(Default)]
pub(super) struct TranscriptGeometry {
    cache: HashMap<u64, CachedBlock>,
    cache_bytes: usize,
    cache_width: u16,
    cache_theme_epoch: u64,
    index: transcript_layout::HeightIndex,
    /// These identities belong to the previous geometry, so eviction/insertion in the records
    /// cannot rebind a reader's old row to a different block before the next layout.
    block_ids: Vec<u64>,
}

impl TranscriptGeometry {
    pub(super) fn clear(&mut self) {
        self.cache.clear();
        self.cache_bytes = 0;
        self.index = transcript_layout::HeightIndex::default();
        self.block_ids.clear();
    }
    pub(super) fn forget(&mut self, ids: &HashSet<u64>) {
        let mut removed = 0usize;
        self.cache.retain(|id, cached| {
            if ids.contains(id) {
                removed = removed.saturating_add(cached.charge);
                false
            } else {
                true
            }
        });
        self.cache_bytes = self.cache_bytes.saturating_sub(removed);
    }
    pub(super) fn layout(&self) -> &transcript_layout::HeightIndex {
        &self.index
    }
    pub(super) fn rendered(&self, id: u64) -> Option<&render::RenderedLines> {
        self.cache.get(&id).map(|cached| &cached.rendered)
    }
    pub(super) fn reading_anchor(&self, row: usize) -> Option<ReadingAnchor> {
        let entry_index = self
            .index
            .visible_range(row, row.saturating_add(1))
            .next()?;
        let entry = self.index.entry(entry_index)?;
        let block_id = *self.block_ids.get(entry.block_index)?;
        let row_in_block = if matches!(entry.source, transcript_layout::Source::Blank) {
            0
        } else {
            row.saturating_sub(self.index.row_start(entry_index))
        };
        Some(ReadingAnchor {
            block_id,
            row_in_block,
        })
    }
    /// Reflow retains the exact block, with the old rendered-row offset clamped to its new size.
    /// It does not claim character-level mapping when wrapping changes.
    pub(super) fn resolve_anchor(&self, anchor: ReadingAnchor) -> Option<usize> {
        let block_index = self
            .block_ids
            .iter()
            .position(|id| *id == anchor.block_id)?;
        let (start, rows) = self.index.block_rows(block_index)?;
        Some(start.saturating_add(anchor.row_in_block.min(rows.saturating_sub(1))))
    }
    /// Render only a changed suffix and retain finite cache bytes. A settled block that exceeds
    /// admission still contributes real geometry and is rendered on demand if it is visible.
    pub(super) fn prepare(
        &mut self,
        blocks: &[Arc<block::Block>],
        dirty_from: Option<usize>,
        context: GeometryContext<'_>,
    ) -> bool {
        let GeometryContext {
            width,
            theme_epoch,
            theme,
            spin,
            hyperlinks,
            region_block,
        } = context;
        if self.cache_width != width || self.cache_theme_epoch != theme_epoch {
            self.cache.clear();
            self.cache_bytes = 0;
            self.cache_width = width;
            self.cache_theme_epoch = theme_epoch;
        }
        let full_rebuild = !self.index.matches(width, theme_epoch, region_block);
        let Some(first) = full_rebuild.then_some(0).or(dirty_from) else {
            return false;
        };
        let first = first.min(blocks.len());
        let mut entries = Vec::new();
        let mut previous = blocks[..first]
            .iter()
            .rev()
            .find(|block| Some(block.id) != region_block)
            .map(|block| &block.kind);
        for (block_index, block) in blocks.iter().enumerate().skip(first) {
            if Some(block.id) == region_block {
                continue;
            }
            if let Some(previous) = previous {
                let gap = usize::from(block::gap_before(previous, &block.kind));
                if gap > 0 {
                    entries.push(transcript_layout::Entry::blank(gap, block_index));
                }
            }
            previous = Some(&block.kind);
            if let Some(cached) = self.cache.get(&block.id)
                && block.cacheable()
                && cached.revision == block.revision
            {
                entries.push(transcript_layout::Entry::cached(
                    block.id,
                    block_index,
                    cached.rendered.lines.len(),
                ));
                continue;
            }
            if let Some(old) = self.cache.remove(&block.id) {
                self.cache_bytes = self.cache_bytes.saturating_sub(old.charge);
            }
            let rendered = block.render_with_hyperlinks(width, theme, spin, hyperlinks);
            let rows = rendered.lines.len();
            let charge = rendered_charge(&rendered);
            if block.cacheable() && charge <= MAX_CACHE_BYTES.saturating_sub(self.cache_bytes) {
                self.cache.insert(
                    block.id,
                    CachedBlock {
                        revision: block.revision,
                        rendered,
                        charge,
                    },
                );
                self.cache_bytes = self.cache_bytes.saturating_add(charge);
                entries.push(transcript_layout::Entry::cached(
                    block.id,
                    block_index,
                    rows,
                ));
            } else {
                entries.push(transcript_layout::Entry::live(block_index, rows));
            }
        }
        if full_rebuild {
            self.index
                .rebuild(width, theme_epoch, region_block, entries);
        } else {
            self.index.rebuild_suffix(first, entries);
        }
        self.block_ids.truncate(first);
        self.block_ids
            .extend(blocks.iter().skip(first).map(|block| block.id));
        true
    }
    #[cfg(test)]
    pub(super) fn cache_len(&self) -> usize {
        self.cache.len()
    }
    #[cfg(test)]
    pub(super) fn cached_revision(&self, id: u64) -> Option<u64> {
        self.cache.get(&id).map(|cached| cached.revision)
    }
    #[cfg(test)]
    pub(super) fn cache_width(&self) -> u16 {
        self.cache_width
    }
}

fn rendered_charge(rendered: &render::RenderedLines) -> usize {
    let lines = rendered
        .lines
        .capacity()
        .saturating_mul(size_of::<ratatui::text::Line<'static>>());
    let spans = rendered.lines.iter().fold(0usize, |total, line| {
        let overhead = line
            .spans
            .capacity()
            .saturating_mul(size_of::<ratatui::text::Span<'static>>());
        line.spans
            .iter()
            .fold(total.saturating_add(overhead), |bytes, span| {
                bytes.saturating_add(match &span.content {
                    std::borrow::Cow::Owned(text) => text.capacity(),
                    std::borrow::Cow::Borrowed(text) => text.len(),
                })
            })
    });
    let links = rendered.hyperlinks.iter().fold(
        rendered
            .hyperlinks
            .capacity()
            .saturating_mul(size_of::<render::HyperlinkRegion>()),
        |bytes, link| bytes.saturating_add(link.target.capacity()),
    );
    lines
        .saturating_add(spans)
        .saturating_add(links)
        .saturating_add(size_of::<CachedBlock>() + 32)
}

#[cfg(test)]
mod tests {
    use super::{GeometryContext, MAX_CACHE_BYTES, TranscriptGeometry};
    use crate::{block, theme};
    use std::collections::HashSet;
    use std::sync::Arc;

    fn prepare(owner: &mut TranscriptGeometry, blocks: &[Arc<block::Block>], width: u16) {
        owner.prepare(
            blocks,
            Some(0),
            GeometryContext {
                width,
                theme_epoch: 0,
                theme: &theme::Theme::dark(),
                spin: 0,
                hyperlinks: &super::hyperlink::Policy::disabled(),
                region_block: None,
            },
        );
    }

    #[test]
    fn actual_block_anchor_survives_insertion_width_reflow_fold_and_refuses_evicted_identity() {
        let mut blocks = vec![
            Arc::new(block::Block::new(
                10,
                block::BlockKind::User("prefix ".repeat(80)),
            )),
            Arc::new(block::Block::new(
                20,
                block::BlockKind::Thinking {
                    text: "reading this block\n".repeat(20),
                    open: true,
                },
            )),
            Arc::new(block::Block::new(
                30,
                block::BlockKind::User("later".into()),
            )),
        ];
        let mut owner = TranscriptGeometry::default();
        prepare(&mut owner, &blocks, 100);
        let (start, rows) = owner.layout().block_rows(1).unwrap();
        assert!(rows > 4);
        let anchor = owner.reading_anchor(start + 4).unwrap();
        assert_eq!(anchor.block_id, 20);
        blocks.insert(
            0,
            Arc::new(block::Block::new(
                99,
                block::BlockKind::User("inserted".repeat(30)),
            )),
        );
        prepare(&mut owner, &blocks, 40);
        let resolved = owner.resolve_anchor(anchor).unwrap();
        assert_eq!(owner.reading_anchor(resolved).unwrap().block_id, 20);
        let folded = Arc::make_mut(&mut blocks[2]);
        if let block::BlockKind::Thinking { open, .. } = &mut folded.kind {
            *open = false;
        }
        folded.touch();
        prepare(&mut owner, &blocks, 40);
        let (start, rows) = owner.layout().block_rows(2).unwrap();
        assert_eq!(owner.resolve_anchor(anchor), Some(start + 4.min(rows - 1)));
        blocks.remove(2);
        owner.forget(&HashSet::from([20]));
        prepare(&mut owner, &blocks, 40);
        assert_eq!(owner.resolve_anchor(anchor), None);
        assert!(owner.rendered(20).is_none());
    }

    #[test]
    fn actual_rendered_byte_quota_retains_geometry_and_uncached_visible_content() {
        let blocks = (0..4)
            .map(|id| {
                Arc::new(block::Block::new(
                    id,
                    block::BlockKind::Thinking {
                        text: "a real retained row\n".repeat(40_000),
                        open: true,
                    },
                ))
            })
            .collect::<Vec<_>>();
        let mut owner = TranscriptGeometry::default();
        prepare(&mut owner, &blocks, 80);
        assert!(owner.cache_bytes <= MAX_CACHE_BYTES);
        assert!(
            owner.cache_len() < blocks.len(),
            "row storage exceeds the finite aggregate quota"
        );
        let index = blocks
            .iter()
            .position(|block| owner.rendered(block.id).is_none())
            .unwrap();
        let (first, rows) = owner.layout().block_rows(index).unwrap();
        assert!(rows > 0);
        let row = owner.reading_anchor(first).unwrap();
        assert_eq!(row.block_id, blocks[index].id);
        let rendered = blocks[index].render_with_hyperlinks(
            80,
            &theme::Theme::dark(),
            0,
            &super::hyperlink::Policy::disabled(),
        );
        assert_eq!(rendered.lines.len(), rows);
        assert!(
            rendered
                .lines
                .iter()
                .flat_map(|line| &line.spans)
                .any(|span| span.content.contains("a real retained row"))
        );
        let retained = owner.layout().rebuilds();
        assert!(!owner.prepare(
            &blocks,
            None,
            GeometryContext {
                width: 80,
                theme_epoch: 0,
                theme: &theme::Theme::dark(),
                spin: 1,
                hyperlinks: &super::hyperlink::Policy::disabled(),
                region_block: None,
            }
        ));
        assert_eq!(owner.layout().rebuilds(), retained);
    }
}

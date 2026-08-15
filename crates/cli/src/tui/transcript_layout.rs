//! Retained transcript geometry.
//!
//! Rendering rows is expensive, but locating the handful intersecting a viewport is not. This
//! index retains one prefix sum per block/gap and answers visible ranges with two binary searches;
//! an unchanged 1,200-block transcript therefore never needs a frame-time linear scan.

use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    Blank,
    Cached(u64),
    LiveBlock(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) source: Source,
    pub(super) block_index: usize,
    pub(super) rows: usize,
}

impl Entry {
    pub(super) fn blank(rows: usize, following_block_index: usize) -> Self {
        Self {
            source: Source::Blank,
            block_index: following_block_index,
            rows,
        }
    }

    pub(super) fn cached(id: u64, block_index: usize, rows: usize) -> Self {
        Self {
            source: Source::Cached(id),
            block_index,
            rows,
        }
    }

    pub(super) fn live(block_index: usize, rows: usize) -> Self {
        Self {
            source: Source::LiveBlock(block_index),
            block_index,
            rows,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    width: u16,
    theme_epoch: u64,
    region_block: Option<u64>,
}

#[derive(Default)]
pub(super) struct HeightIndex {
    key: Option<Key>,
    entries: Vec<Entry>,
    starts: Vec<usize>,
    ends: Vec<usize>,
    /// Transcript block index -> first geometry entry owned by that block (its leading gap, when
    /// present). This makes a tail mutation an O(changed suffix) splice rather than an O(N) search.
    block_entry_starts: Vec<usize>,
    total_rows: usize,
    #[cfg(test)]
    rebuilds: usize,
}

impl HeightIndex {
    pub(super) fn matches(&self, width: u16, theme_epoch: u64, region_block: Option<u64>) -> bool {
        self.key
            == Some(Key {
                width,
                theme_epoch,
                region_block,
            })
    }

    pub(super) fn rebuild(
        &mut self,
        width: u16,
        theme_epoch: u64,
        region_block: Option<u64>,
        entries: Vec<Entry>,
    ) {
        self.key = Some(Key {
            width,
            theme_epoch,
            region_block,
        });
        self.starts.clear();
        self.ends.clear();
        self.block_entry_starts.clear();
        self.starts.reserve(entries.len());
        self.ends.reserve(entries.len());
        let mut cursor = 0usize;
        for entry in &entries {
            if entry.block_index != usize::MAX {
                if self.block_entry_starts.len() <= entry.block_index {
                    self.block_entry_starts
                        .resize(entry.block_index.saturating_add(1), self.starts.len());
                }
                self.block_entry_starts[entry.block_index] = self
                    .block_entry_starts
                    .get(entry.block_index)
                    .copied()
                    .unwrap_or(self.starts.len())
                    .min(self.starts.len());
            }
            self.starts.push(cursor);
            cursor = cursor.saturating_add(entry.rows);
            self.ends.push(cursor);
        }
        self.total_rows = cursor;
        self.entries = entries;
        #[cfg(test)]
        {
            self.rebuilds += 1;
        }
    }

    /// Replace geometry from one transcript block onward while retaining the prefix sums before
    /// it. Appends and live-card updates normally touch one or two tail blocks, independent of the
    /// 1,200-block retention ceiling.
    pub(super) fn rebuild_suffix(&mut self, first_block: usize, entries: Vec<Entry>) {
        let entry_start = self
            .block_entry_starts
            .get(first_block)
            .copied()
            .unwrap_or(self.entries.len());
        self.entries.truncate(entry_start);
        self.starts.truncate(entry_start);
        self.ends.truncate(entry_start);
        self.block_entry_starts.truncate(first_block);
        let mut cursor = self.ends.last().copied().unwrap_or(0);
        for entry in entries {
            if entry.block_index != usize::MAX && self.block_entry_starts.len() <= entry.block_index
            {
                self.block_entry_starts
                    .resize(entry.block_index.saturating_add(1), self.entries.len());
            }
            self.starts.push(cursor);
            cursor = cursor.saturating_add(entry.rows);
            self.ends.push(cursor);
            self.entries.push(entry);
        }
        self.total_rows = cursor;
    }

    pub(super) fn total_rows(&self) -> usize {
        self.total_rows
    }

    pub(super) fn entry(&self, index: usize) -> Option<&Entry> {
        self.entries.get(index)
    }

    pub(super) fn row_start(&self, index: usize) -> usize {
        self.starts.get(index).copied().unwrap_or(self.total_rows)
    }

    pub(super) fn visible_range(&self, first_row: usize, last_row: usize) -> Range<usize> {
        self.visible_range_with_work(first_row, last_row).0
    }

    fn visible_range_with_work(&self, first_row: usize, last_row: usize) -> (Range<usize>, usize) {
        if first_row >= last_row || self.entries.is_empty() {
            return (0..0, 0);
        }
        let (start, first_work) = first_strictly_greater(&self.ends, first_row);
        let (end, last_work) = first_greater_or_equal(&self.starts, last_row);
        (
            start.min(end)..end.min(self.entries.len()),
            first_work + last_work,
        )
    }

    #[cfg(test)]
    pub(super) fn rebuilds(&self) -> usize {
        self.rebuilds
    }
}

fn first_strictly_greater(values: &[usize], needle: usize) -> (usize, usize) {
    binary_partition(values, |value| value <= needle)
}

fn first_greater_or_equal(values: &[usize], needle: usize) -> (usize, usize) {
    binary_partition(values, |value| value < needle)
}

fn binary_partition(values: &[usize], before: impl Fn(usize) -> bool) -> (usize, usize) {
    let mut left = 0usize;
    let mut right = values.len();
    let mut work = 0usize;
    while left < right {
        work += 1;
        let middle = left + (right - left) / 2;
        if before(values[middle]) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    (left, work)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_hundred_blocks_use_logarithmic_lookup_and_retain_geometry() {
        let entries = (0..1_200)
            .map(|index| Entry::cached(index as u64, index, 2))
            .collect();
        let mut index = HeightIndex::default();
        index.rebuild(80, 1, None, entries);
        assert_eq!(index.rebuilds(), 1);

        let (visible, work) = index.visible_range_with_work(2_360, 2_400);
        assert_eq!(visible, 1_180..1_200);
        assert!(work <= 24, "two binary searches stay logarithmic: {work}");
        assert_eq!(index.rebuilds(), 1, "lookup does not rebuild or scan");

        index.rebuild_suffix(1_199, vec![Entry::cached(1_199, 1_199, 3)]);
        assert_eq!(index.rebuilds(), 1, "one tail mutation retains the prefix");
        assert_eq!(index.total_rows(), 2_401);
    }
}

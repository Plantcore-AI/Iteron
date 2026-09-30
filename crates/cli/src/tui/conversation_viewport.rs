//! Private conversation scroll/follow state. Input requests move this owner; layout supplies actual
//! observed geometry. Output never moves a reader back to the tail until they reach it or request it.

pub(super) struct ConversationViewport {
    offset: usize,
    following: bool,
    unread: bool,
    total_rows: usize,
    height: usize,
    anchor_missing: bool,
}
impl Default for ConversationViewport {
    fn default() -> Self {
        Self {
            offset: 0,
            following: true,
            unread: false,
            total_rows: 0,
            height: 0,
            anchor_missing: false,
        }
    }
}
impl ConversationViewport {
    pub(super) fn follows_tail(&self) -> bool {
        self.following
    }
    pub(super) fn has_unread(&self) -> bool {
        self.unread
    }
    pub(super) fn observe_output(&mut self) {
        if self.following {
            self.offset = 0;
        } else {
            self.unread = true;
        }
    }
    pub(super) fn follow_latest(&mut self) {
        self.following = true;
        self.offset = 0;
        self.unread = false;
        self.anchor_missing = false;
    }
    pub(super) fn scroll_up(&mut self, rows: u16) {
        self.following = false;
        self.offset = self.offset.saturating_add(usize::from(rows));
    }
    pub(super) fn scroll_down(&mut self, rows: u16) {
        self.offset = self.offset.saturating_sub(usize::from(rows));
        if self.offset == 0 {
            self.follow_latest();
        }
    }
    /// Preserve the currently requested rendered row through appended content and shelf-height
    /// changes. This arithmetic does not provide semantic block/source-row reflow anchoring
    /// or exact source-character stability after reflow.
    pub(super) fn observe_layout(&mut self, total_rows: usize, height: u16) -> usize {
        let height = usize::from(height);
        let extent = total_rows.saturating_sub(height);
        if !self.following && self.height > 0 {
            let previous = self.total_rows.saturating_sub(self.height);
            self.offset = if extent >= previous {
                self.offset.saturating_add(extent - previous)
            } else {
                self.offset.saturating_sub(previous - extent)
            };
        }
        self.total_rows = total_rows;
        self.height = height;
        self.offset = self.offset.min(extent);
        if self.offset == 0 && !self.following {
            self.follow_latest();
        }
        extent - self.offset
    }
    pub(super) fn requested_first_row(&self) -> Option<usize> {
        (!self.following && self.height > 0).then(|| {
            self.total_rows
                .saturating_sub(self.height)
                .saturating_sub(self.offset)
        })
    }
    pub(super) fn observe_anchored_layout(
        &mut self,
        total_rows: usize,
        height: u16,
        row: usize,
    ) -> usize {
        let height = usize::from(height);
        let extent = total_rows.saturating_sub(height);
        let row = row.min(extent);
        self.total_rows = total_rows;
        self.height = height;
        self.offset = extent - row;
        self.anchor_missing = false;
        if self.offset == 0 {
            self.follow_latest();
        }
        row
    }
    pub(super) fn anchor_unavailable(&mut self) {
        self.anchor_missing = true;
    }
    pub(super) fn has_missing_anchor(&self) -> bool {
        self.anchor_missing
    }
    #[cfg(test)]
    pub(super) fn offset(&self) -> usize {
        self.offset
    }
    #[cfg(test)]
    pub(super) fn total_rows(&self) -> usize {
        self.total_rows
    }
    #[cfg(test)]
    pub(super) fn fixture_offset(&mut self, offset: usize) {
        self.offset = offset;
    }
}
#[cfg(test)]
mod tests {
    use super::ConversationViewport;
    #[test]
    fn requested_reader_position_survives_append_shelf_change_and_saturating_limits() {
        let mut viewport = ConversationViewport::default();
        assert_eq!(viewport.observe_layout(200, 20), 180);
        viewport.scroll_up(40);
        assert_eq!(viewport.observe_layout(200, 20), 140);
        viewport.observe_output();
        assert!(viewport.has_unread());
        assert_eq!(viewport.observe_layout(220, 15), 140);
        assert!(!viewport.follows_tail());
        viewport.scroll_up(u16::MAX);
        assert_eq!(viewport.observe_layout(220, 15), 0);
        viewport.follow_latest();
        assert_eq!(viewport.observe_layout(usize::MAX, 15), usize::MAX - 15);
        assert!(!viewport.has_unread());
    }
    #[test]
    fn reaching_tail_or_shrinking_to_no_scroll_reenables_following() {
        let mut viewport = ConversationViewport::default();
        viewport.observe_layout(80, 20);
        viewport.scroll_up(9);
        viewport.observe_output();
        viewport.scroll_down(9);
        assert!(viewport.follows_tail());
        assert!(!viewport.has_unread());
        viewport.scroll_up(20);
        assert_eq!(viewport.observe_layout(5, 20), 0);
        assert!(viewport.follows_tail());
    }
}

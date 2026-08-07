use super::{
    MAX_OBSERVED_OUTPUT_BYTES_PER_STREAM, POLL_OUTPUT_BYTES_PER_STREAM,
    RETAINED_OUTPUT_BYTES_PER_STREAM,
};
use serde::Serialize;
use std::collections::VecDeque;

#[derive(Debug, Serialize)]
pub(super) struct OutputFrame {
    pub(super) text: String,
    pub(super) encoding: &'static str,
    pub(super) oldest_cursor: u64,
    pub(super) next_cursor: u64,
    pub(super) observed_cursor: u64,
    pub(super) gap: bool,
    pub(super) has_more: bool,
    pub(super) closed: bool,
}

#[derive(Debug)]
pub(super) struct OutputRing {
    bytes: VecDeque<u8>,
    oldest_cursor: u64,
    observed_cursor: u64,
    retained_limit: usize,
    observed_limit: u64,
    limit_notified: bool,
    closed: bool,
}

impl Default for OutputRing {
    fn default() -> Self {
        Self {
            bytes: VecDeque::new(),
            oldest_cursor: 0,
            observed_cursor: 0,
            retained_limit: RETAINED_OUTPUT_BYTES_PER_STREAM,
            observed_limit: MAX_OBSERVED_OUTPUT_BYTES_PER_STREAM,
            limit_notified: false,
            closed: false,
        }
    }
}

impl OutputRing {
    pub(super) fn end_cursor(&self) -> u64 {
        self.observed_cursor
    }

    /// Retain a fixed tail and report exactly once when the total-observation ceiling is crossed.
    pub(super) fn push(&mut self, chunk: &[u8]) -> bool {
        self.observed_cursor = self
            .observed_cursor
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        self.bytes.extend(chunk.iter().copied());
        while self.bytes.len() > self.retained_limit {
            self.bytes.pop_front();
            self.oldest_cursor = self.oldest_cursor.saturating_add(1);
        }
        if self.observed_cursor > self.observed_limit && !self.limit_notified {
            self.limit_notified = true;
            return true;
        }
        false
    }

    #[cfg(test)]
    pub(super) fn with_limits(retained_limit: usize, observed_limit: u64) -> Self {
        Self {
            retained_limit,
            observed_limit,
            ..Self::default()
        }
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
    }

    pub(super) fn frame(&self, requested_cursor: u64) -> Result<OutputFrame, String> {
        if requested_cursor > self.observed_cursor {
            return Err(format!(
                "cursor {requested_cursor} is beyond observed output cursor {}",
                self.observed_cursor
            ));
        }
        let gap = requested_cursor < self.oldest_cursor;
        let start = requested_cursor.max(self.oldest_cursor);
        let offset = usize::try_from(start.saturating_sub(self.oldest_cursor))
            .unwrap_or(self.bytes.len())
            .min(self.bytes.len());
        let take = self
            .bytes
            .len()
            .saturating_sub(offset)
            .min(POLL_OUTPUT_BYTES_PER_STREAM);
        let page: Vec<u8> = self.bytes.iter().skip(offset).take(take).copied().collect();
        let next_cursor = start.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
        Ok(OutputFrame {
            text: String::from_utf8_lossy(&page).into_owned(),
            encoding: "utf8-lossy",
            oldest_cursor: self.oldest_cursor,
            next_cursor,
            observed_cursor: self.observed_cursor,
            gap,
            has_more: next_cursor < self.observed_cursor,
            closed: self.closed,
        })
    }
}

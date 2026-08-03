//! Bounded in-flight request registry: admission, cancellation, and deadline expiry.
//!
//! A language server may never answer. Each admitted request therefore has a mandatory bounded
//! deadline, and the injected clock is checked for monotonicity instead of silently extending that
//! deadline when a caller supplies regressed time.

use crate::{LspError, MAX_IN_FLIGHT, MAX_REQUEST_TIMEOUT_MS, MIN_REQUEST_TIMEOUT_MS};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    method: &'static str,
    issued_ms: u64,
    deadline_ms: u64,
}

/// Why an in-flight entry was removed without a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expired {
    pub id: u64,
    pub method: &'static str,
    /// Total time since admission, not merely lateness past the deadline.
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyDisposition {
    Accepted,
    Late(Expired),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDisposition {
    Cancelled,
    TimedOut(Expired),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PendingRequests {
    entries: HashMap<u64, Entry>,
    capacity: usize,
    last_now_ms: Option<u64>,
    timed_out: u64,
    cancelled: u64,
    rejected: u64,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self {
            entries: HashMap::with_capacity(MAX_IN_FLIGHT),
            capacity: MAX_IN_FLIGHT,
            last_now_ms: None,
            timed_out: 0,
            cancelled: 0,
            rejected: 0,
        }
    }
}

impl PendingRequests {
    /// Construct a tighter registry. Capacity is never silently clamped: a value outside the hard
    /// interval is a configuration failure rather than a configuration that appears to work.
    pub fn with_capacity(capacity: usize) -> Result<Self, LspError> {
        if !(1..=MAX_IN_FLIGHT).contains(&capacity) {
            return Err(LspError::InvalidPendingCapacity {
                value: capacity,
                max: MAX_IN_FLIGHT,
            });
        }
        Ok(Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            last_now_ms: None,
            timed_out: 0,
            cancelled: 0,
            rejected: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    pub fn timed_out(&self) -> u64 {
        self.timed_out
    }

    pub fn cancelled(&self) -> u64 {
        self.cancelled
    }

    /// Admit one uniquely identified request with a mandatory deadline.
    pub fn issue(
        &mut self,
        id: u64,
        method: &'static str,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<(), LspError> {
        self.observe_clock(now_ms)?;
        if !(MIN_REQUEST_TIMEOUT_MS..=MAX_REQUEST_TIMEOUT_MS).contains(&timeout_ms) {
            self.rejected = self.rejected.saturating_add(1);
            return Err(LspError::InvalidTimeout {
                kind: "request",
                value_ms: timeout_ms,
                min_ms: MIN_REQUEST_TIMEOUT_MS,
                max_ms: MAX_REQUEST_TIMEOUT_MS,
            });
        }
        // Check identity before capacity. At capacity, replacing an existing id would keep the
        // length unchanged and silently strand the first caller.
        if self.entries.contains_key(&id) {
            self.rejected = self.rejected.saturating_add(1);
            return Err(LspError::DuplicateRequestId { id });
        }
        if self.entries.len() >= self.capacity {
            self.rejected = self.rejected.saturating_add(1);
            return Err(LspError::Backpressure {
                limit: self.capacity,
            });
        }

        self.entries.insert(
            id,
            Entry {
                method,
                issued_ms: now_ms,
                deadline_ms: now_ms.saturating_add(timeout_ms),
            },
        );
        Ok(())
    }

    /// Retire a reply under the same deadline rule used by the sweeper. Requiring `now_ms` here
    /// prevents a caller from accepting a late reply merely because it forgot to sweep first.
    pub fn resolve(&mut self, id: u64, now_ms: u64) -> Result<ReplyDisposition, LspError> {
        self.observe_clock(now_ms)?;
        let Some(entry) = self.entries.remove(&id) else {
            return Ok(ReplyDisposition::Unknown);
        };
        if entry.deadline_ms <= now_ms {
            self.timed_out = self.timed_out.saturating_add(1);
            return Ok(ReplyDisposition::Late(expired(id, entry, now_ms)));
        }
        Ok(ReplyDisposition::Accepted)
    }

    pub fn cancel(&mut self, id: u64, now_ms: u64) -> Result<CancelDisposition, LspError> {
        self.observe_clock(now_ms)?;
        let Some(entry) = self.entries.remove(&id) else {
            return Ok(CancelDisposition::Unknown);
        };
        if entry.deadline_ms <= now_ms {
            self.timed_out = self.timed_out.saturating_add(1);
            return Ok(CancelDisposition::TimedOut(expired(id, entry, now_ms)));
        }
        self.cancelled = self.cancelled.saturating_add(1);
        Ok(CancelDisposition::Cancelled)
    }

    /// Remove everything whose deadline has passed, in stable id order.
    pub fn expire(&mut self, now_ms: u64) -> Result<Vec<Expired>, LspError> {
        self.observe_clock(now_ms)?;
        let mut expired: Vec<Expired> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.deadline_ms <= now_ms)
            .map(|(id, entry)| expired(*id, *entry, now_ms))
            .collect();
        expired.sort_by_key(|entry| entry.id);
        for entry in &expired {
            self.entries.remove(&entry.id);
        }
        self.timed_out = self.timed_out.saturating_add(expired.len() as u64);
        Ok(expired)
    }

    fn observe_clock(&mut self, now_ms: u64) -> Result<(), LspError> {
        if let Some(previous_ms) = self.last_now_ms
            && now_ms < previous_ms
        {
            return Err(LspError::ClockRegressed {
                previous_ms,
                current_ms: now_ms,
            });
        }
        self.last_now_ms = Some(now_ms);
        Ok(())
    }
}

fn expired(id: u64, entry: Entry, now_ms: u64) -> Expired {
    Expired {
        id,
        method: entry.method,
        elapsed_ms: now_ms.saturating_sub(entry.issued_ms),
    }
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;

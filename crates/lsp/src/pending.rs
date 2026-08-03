//! Bounded in-flight request registry: allocation, correlation, cancellation, and expiry.
//!
//! Request ids are allocated monotonically inside one explicit host/session generation.  A caller
//! cannot recycle an id after a request completes, so a delayed reply can never resolve a newer
//! request.  Cancellation keeps the request charged until the server replies or its deadline
//! expires, matching the LSP rule that `$/cancelRequest` does not suppress the response.

use crate::{LspError, MAX_IN_FLIGHT, MAX_REQUEST_TIMEOUT_MS, MIN_REQUEST_TIMEOUT_MS};
use std::collections::{HashMap, VecDeque};

/// Identity carried from admission through every terminal disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCorrelation {
    pub generation: u64,
    pub id: u64,
    pub method: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    Active,
    Cancelling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    correlation: RequestCorrelation,
    issued_ms: u64,
    deadline_ms: u64,
    state: EntryState,
}

/// Why an in-flight entry was removed without an on-time reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expired {
    pub generation: u64,
    pub id: u64,
    pub method: &'static str,
    /// Total time since admission, not merely lateness past the deadline.
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyDisposition {
    /// An ordinary request completed on time.
    Accepted(RequestCorrelation),
    /// A cancelling request produced its still-required terminal response.
    Cancelled(RequestCorrelation),
    /// The response arrived at or after the request deadline.
    Late(Expired),
    /// A second response arrived for an already-completed request retained in the tombstone set.
    Duplicate(RequestCorrelation),
    /// The id was issued and retired, but its bounded detailed tombstone has aged out.
    Retired { generation: u64, id: u64 },
    /// A response from another transport/document-session generation cannot correlate here.
    ForeignGeneration {
        expected: u64,
        received: u64,
        id: u64,
    },
    /// The id has never been allocated in this generation.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelDisposition {
    /// Cancellation was marked and must now be written to the server by the future driver.
    CancellationRequested(RequestCorrelation),
    /// Repeated cancellation is idempotent and does not change accounting.
    AlreadyCancelling(RequestCorrelation),
    /// The deadline had already elapsed; the entry was retired instead of marked cancelling.
    TimedOut(Expired),
    ForeignGeneration {
        expected: u64,
        received: u64,
        id: u64,
    },
    /// The id was allocated in this generation but is no longer live.
    Retired {
        generation: u64,
        id: u64,
    },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetiredKind {
    Replied,
    TimedOut { issued_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tombstone {
    correlation: RequestCorrelation,
    kind: RetiredKind,
}

#[derive(Debug, Clone)]
pub struct PendingRequests {
    generation: u64,
    entries: HashMap<u64, Entry>,
    tombstones: VecDeque<Tombstone>,
    capacity: usize,
    next_id: Option<u64>,
    last_now_ms: Option<u64>,
    timed_out: u64,
    cancelled: u64,
    rejected: u64,
}

impl PendingRequests {
    /// Construct a registry for one explicit host/document-session generation.
    pub fn new(generation: u64) -> Self {
        Self::with_capacity(generation, MAX_IN_FLIGHT)
            .expect("the crate's maximum in-flight capacity is valid")
    }

    /// Construct a tighter registry. Capacity is never silently clamped.
    pub fn with_capacity(generation: u64, capacity: usize) -> Result<Self, LspError> {
        if !(1..=MAX_IN_FLIGHT).contains(&capacity) {
            return Err(LspError::InvalidPendingCapacity {
                value: capacity,
                max: MAX_IN_FLIGHT,
            });
        }
        Ok(Self {
            generation,
            entries: HashMap::with_capacity(capacity),
            tombstones: VecDeque::with_capacity(capacity),
            capacity,
            next_id: Some(1),
            last_now_ms: None,
            timed_out: 0,
            cancelled: 0,
            rejected: 0,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Active and cancelling requests are both charged against admission capacity.
    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }

    pub fn cancelling(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.state == EntryState::Cancelling)
            .count()
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

    /// Allocate and admit one request with a mandatory deadline.
    ///
    /// The wire id is deliberately not caller supplied. Monotonic allocation is the constant-space
    /// proof that an id cannot alias another request within this generation.
    pub fn issue(
        &mut self,
        method: &'static str,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<RequestCorrelation, LspError> {
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
        if self.entries.len() >= self.capacity {
            self.rejected = self.rejected.saturating_add(1);
            return Err(LspError::Backpressure {
                limit: self.capacity,
            });
        }
        let Some(id) = self.next_id else {
            self.rejected = self.rejected.saturating_add(1);
            return Err(LspError::RequestIdExhausted {
                generation: self.generation,
            });
        };
        self.next_id = id.checked_add(1);
        let correlation = RequestCorrelation {
            generation: self.generation,
            id,
            method,
        };
        self.entries.insert(
            id,
            Entry {
                correlation,
                issued_ms: now_ms,
                deadline_ms: now_ms.saturating_add(timeout_ms),
                state: EntryState::Active,
            },
        );
        Ok(correlation)
    }

    /// Retire a reply under the same deadline rule used by the sweeper.
    pub fn resolve(
        &mut self,
        generation: u64,
        id: u64,
        now_ms: u64,
    ) -> Result<ReplyDisposition, LspError> {
        if generation != self.generation {
            return Ok(ReplyDisposition::ForeignGeneration {
                expected: self.generation,
                received: generation,
                id,
            });
        }
        self.observe_clock(now_ms)?;
        if let Some(entry) = self.entries.remove(&id) {
            if entry.deadline_ms <= now_ms {
                let expired = expired(entry, now_ms);
                self.timed_out = self.timed_out.saturating_add(1);
                self.remember(
                    entry.correlation,
                    RetiredKind::TimedOut {
                        issued_ms: entry.issued_ms,
                    },
                );
                return Ok(ReplyDisposition::Late(expired));
            }
            self.remember(entry.correlation, RetiredKind::Replied);
            return Ok(match entry.state {
                EntryState::Active => ReplyDisposition::Accepted(entry.correlation),
                EntryState::Cancelling => ReplyDisposition::Cancelled(entry.correlation),
            });
        }
        Ok(self.retired_reply(id, now_ms))
    }

    /// Mark a request cancelling without releasing its admission slot.
    pub fn cancel(
        &mut self,
        generation: u64,
        id: u64,
        now_ms: u64,
    ) -> Result<CancelDisposition, LspError> {
        if generation != self.generation {
            return Ok(CancelDisposition::ForeignGeneration {
                expected: self.generation,
                received: generation,
                id,
            });
        }
        self.observe_clock(now_ms)?;
        let Some(entry) = self.entries.get(&id).copied() else {
            return Ok(if self.was_issued(id) {
                CancelDisposition::Retired { generation, id }
            } else {
                CancelDisposition::Unknown
            });
        };
        if entry.deadline_ms <= now_ms {
            self.entries.remove(&id);
            let expired = expired(entry, now_ms);
            self.timed_out = self.timed_out.saturating_add(1);
            self.remember(
                entry.correlation,
                RetiredKind::TimedOut {
                    issued_ms: entry.issued_ms,
                },
            );
            return Ok(CancelDisposition::TimedOut(expired));
        }
        let live = self
            .entries
            .get_mut(&id)
            .expect("entry was observed under the same exclusive borrow");
        Ok(match live.state {
            EntryState::Active => {
                live.state = EntryState::Cancelling;
                self.cancelled = self.cancelled.saturating_add(1);
                CancelDisposition::CancellationRequested(live.correlation)
            }
            EntryState::Cancelling => CancelDisposition::AlreadyCancelling(live.correlation),
        })
    }

    /// Remove everything whose deadline has passed, in stable id order.
    pub fn expire(&mut self, now_ms: u64) -> Result<Vec<Expired>, LspError> {
        self.observe_clock(now_ms)?;
        let mut ids: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.deadline_ms <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        let mut expired_entries = Vec::with_capacity(ids.len());
        for id in ids {
            let entry = self
                .entries
                .remove(&id)
                .expect("expired id came from the live map");
            let expired = expired(entry, now_ms);
            self.remember(
                entry.correlation,
                RetiredKind::TimedOut {
                    issued_ms: entry.issued_ms,
                },
            );
            expired_entries.push(expired);
        }
        self.timed_out = self.timed_out.saturating_add(expired_entries.len() as u64);
        Ok(expired_entries)
    }

    fn retired_reply(&self, id: u64, now_ms: u64) -> ReplyDisposition {
        if let Some(tombstone) = self
            .tombstones
            .iter()
            .rev()
            .find(|tombstone| tombstone.correlation.id == id)
        {
            return match tombstone.kind {
                RetiredKind::Replied => ReplyDisposition::Duplicate(tombstone.correlation),
                RetiredKind::TimedOut { issued_ms } => ReplyDisposition::Late(Expired {
                    generation: tombstone.correlation.generation,
                    id,
                    method: tombstone.correlation.method,
                    elapsed_ms: now_ms.saturating_sub(issued_ms),
                }),
            };
        }
        if self.was_issued(id) {
            ReplyDisposition::Retired {
                generation: self.generation,
                id,
            }
        } else {
            ReplyDisposition::Unknown
        }
    }

    fn was_issued(&self, id: u64) -> bool {
        id != 0 && self.next_id.is_none_or(|next| id < next)
    }

    fn remember(&mut self, correlation: RequestCorrelation, kind: RetiredKind) {
        if self.tombstones.len() == self.capacity {
            self.tombstones.pop_front();
        }
        self.tombstones.push_back(Tombstone { correlation, kind });
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

fn expired(entry: Entry, now_ms: u64) -> Expired {
    Expired {
        generation: entry.correlation.generation,
        id: entry.correlation.id,
        method: entry.correlation.method,
        elapsed_ms: now_ms.saturating_sub(entry.issued_ms),
    }
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;

//! In-flight request registry: admission control, cancellation, and deadline expiry.
//!
//! A language server is allowed to simply never answer. If the agent awaits a reply with no
//! deadline it deadlocks; if it forgets the request it leaks an entry per call. Both failure modes
//! are silent, which is why the registry is bounded on admission and swept by an explicit clock.
//!
//! The clock is a parameter, not `Instant::now()`. That is what lets a test assert the exact
//! moment a request expires instead of sleeping and hoping.

use crate::{LspError, MAX_IN_FLIGHT};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    method: &'static str,
    deadline_ms: u64,
}

/// Why an in-flight entry was removed without a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expired {
    pub id: u64,
    pub method: &'static str,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PendingRequests {
    entries: HashMap<u64, Entry>,
    capacity: usize,
    timed_out: u64,
    cancelled: u64,
    rejected: u64,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::with_capacity(MAX_IN_FLIGHT)
    }
}

impl PendingRequests {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            timed_out: 0,
            cancelled: 0,
            rejected: 0,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.entries.len()
    }

    /// Requests refused because the registry was full. Reported, never silently absorbed: a
    /// caller that cannot tell admission from a lost reply cannot retry correctly.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    pub fn timed_out(&self) -> u64 {
        self.timed_out
    }

    pub fn cancelled(&self) -> u64 {
        self.cancelled
    }

    /// Admit a request. Fails closed when full rather than evicting an older entry, because
    /// evicting would strand a caller that is still waiting for that exact id.
    pub fn issue(
        &mut self,
        id: u64,
        method: &'static str,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<(), LspError> {
        if self.entries.len() >= self.capacity {
            self.rejected += 1;
            return Err(LspError::Backpressure {
                limit: self.capacity,
            });
        }
        self.entries.insert(
            id,
            Entry {
                method,
                deadline_ms: now_ms.saturating_add(timeout_ms),
            },
        );
        Ok(())
    }

    /// Retire a request because its reply arrived. Returns false for an id we are not tracking,
    /// which is how a late reply to an already-expired request is recognised and discarded.
    pub fn resolve(&mut self, id: u64) -> bool {
        self.entries.remove(&id).is_some()
    }

    pub fn cancel(&mut self, id: u64) -> bool {
        if self.entries.remove(&id).is_some() {
            self.cancelled += 1;
            true
        } else {
            false
        }
    }

    /// Remove everything whose deadline has passed.
    ///
    /// Results are sorted by id so a caller reporting them, and a test asserting on them, both see
    /// a stable order -- `HashMap` iteration order is deliberately randomised per process.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Expired> {
        let mut expired: Vec<Expired> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.deadline_ms <= now_ms)
            .map(|(id, entry)| Expired {
                id: *id,
                method: entry.method,
                elapsed_ms: now_ms.saturating_sub(entry.deadline_ms),
            })
            .collect();
        expired.sort_by_key(|e| e.id);
        for e in &expired {
            self.entries.remove(&e.id);
        }
        self.timed_out += expired.len() as u64;
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_fails_closed_when_full_and_counts_the_refusal() {
        let mut p = PendingRequests::with_capacity(2);
        p.issue(1, "definition", 0, 1_000).unwrap();
        p.issue(2, "hover", 0, 1_000).unwrap();

        assert_eq!(
            p.issue(3, "references", 0, 1_000),
            Err(LspError::Backpressure { limit: 2 })
        );
        assert_eq!(p.rejected(), 1);
        // The refused request must not have displaced a caller that is still waiting.
        assert_eq!(p.in_flight(), 2);
        assert!(p.resolve(1));
        assert!(p.resolve(2));
    }

    #[test]
    fn capacity_frees_up_after_a_reply() {
        let mut p = PendingRequests::with_capacity(1);
        p.issue(1, "hover", 0, 1_000).unwrap();
        assert!(p.issue(2, "hover", 0, 1_000).is_err());
        assert!(p.resolve(1));
        assert!(p.issue(2, "hover", 0, 1_000).is_ok());
    }

    #[test]
    fn a_request_expires_exactly_at_its_deadline() {
        let mut p = PendingRequests::default();
        p.issue(1, "definition", 1_000, 500).unwrap();

        assert!(p.expire(1_499).is_empty(), "must not expire early");
        let fired = p.expire(1_500);
        assert_eq!(
            fired,
            vec![Expired {
                id: 1,
                method: "definition",
                elapsed_ms: 0
            }]
        );
        assert_eq!(p.in_flight(), 0);
        assert_eq!(p.timed_out(), 1);
    }

    #[test]
    fn a_late_reply_to_an_expired_request_is_not_mistaken_for_a_live_one() {
        let mut p = PendingRequests::default();
        p.issue(1, "hover", 0, 10).unwrap();
        p.expire(100);
        assert!(!p.resolve(1));
    }

    #[test]
    fn expiry_is_ordered_by_id_not_by_hash_iteration() {
        let mut p = PendingRequests::default();
        for id in [30u64, 10, 20] {
            p.issue(id, "hover", 0, 5).unwrap();
        }
        let ids: Vec<u64> = p.expire(1_000).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn only_passed_deadlines_are_swept() {
        let mut p = PendingRequests::default();
        p.issue(1, "hover", 0, 100).unwrap();
        p.issue(2, "definition", 0, 5_000).unwrap();

        let fired = p.expire(200);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].id, 1);
        assert_eq!(p.in_flight(), 1);
    }

    #[test]
    fn cancellation_is_counted_separately_from_timeout() {
        let mut p = PendingRequests::default();
        p.issue(1, "hover", 0, 1_000).unwrap();
        assert!(p.cancel(1));
        assert!(!p.cancel(1));
        assert_eq!(p.cancelled(), 1);
        assert_eq!(p.timed_out(), 0);
    }

    #[test]
    fn a_deadline_far_in_the_future_does_not_overflow() {
        let mut p = PendingRequests::default();
        p.issue(1, "hover", u64::MAX - 1, u64::MAX).unwrap();
        assert!(p.expire(u64::MAX).len() == 1);
    }
}

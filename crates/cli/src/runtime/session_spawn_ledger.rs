//! Session-wide child-spawn admission.
//!
//! Workflow `RunState` deliberately remains a per-run ceiling. This owner is held by the resident
//! [`Agent`](super::Agent) and shared with every direct/workflow child spawner, so starting another
//! workflow cannot refill the session allowance.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Independent product ceiling. It is not derived from `core_workflow::RunLimits`; one session may
/// contain many workflow runs.
pub(crate) const DEFAULT_SESSION_SPAWN_CAP: usize = 4_096;

#[derive(Debug)]
pub(crate) struct SessionSpawnLedger {
    limit: usize,
    admitted: AtomicUsize,
}

impl SessionSpawnLedger {
    pub(crate) fn new(limit: usize) -> Result<Self, &'static str> {
        if limit > 100_000 {
            return Err("session spawn cap exceeds the canonical maximum");
        }
        Ok(Self {
            limit,
            admitted: AtomicUsize::new(0),
        })
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    pub(crate) fn admitted(&self) -> usize {
        self.admitted.load(Ordering::SeqCst)
    }

    pub(crate) fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.admitted())
    }

    /// Consume one permanent session slot. A failed child setup still consumed an admitted spawn
    /// attempt; returning the slot would let repeated setup/provider failures bypass the ceiling.
    pub(crate) fn admit(&self) -> Result<SessionSpawnAdmission, SessionSpawnCapReached> {
        let ordinal = self
            .admitted
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .map_err(|used| SessionSpawnCapReached {
                limit: self.limit,
                admitted: used,
            })?;
        Ok(SessionSpawnAdmission { ordinal })
    }
}

impl Default for SessionSpawnLedger {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_SPAWN_CAP).expect("built-in session spawn cap is valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionSpawnAdmission {
    /// Zero-based session-global ordinal, useful for deterministic evidence without exposing task
    /// content or relying on a workflow-local declaration index.
    pub(crate) ordinal: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session child-spawn cap reached ({admitted}/{limit})")]
pub(crate) struct SessionSpawnCapReached {
    pub(crate) limit: usize,
    pub(crate) admitted: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn one_ledger_caps_concurrent_workflow_and_direct_callers() {
        let ledger = Arc::new(SessionSpawnLedger::new(2).unwrap());
        let first = ledger.admit().unwrap();
        let second = Arc::clone(&ledger).admit().unwrap();
        assert_eq!((first.ordinal, second.ordinal), (0, 1));
        assert_eq!(ledger.remaining(), 0);
        assert_eq!(ledger.admit().unwrap_err().admitted, 2);
    }

    #[test]
    fn zero_is_a_real_deny_all_session_cap() {
        let ledger = SessionSpawnLedger::new(0).unwrap();
        assert!(ledger.admit().is_err());
    }
}

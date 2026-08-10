//! Typed, local evidence for one MCP tool dispatch.
//!
//! This is deliberately transport evidence rather than a telemetry exporter. The client measures
//! the interval itself and hands the bounded attribution to its caller; the runtime decides how to
//! fold it into its existing ledger and durable effect record.

use std::num::NonZeroU64;
use std::sync::Mutex;
use std::time::Instant;

/// Evidence for the interval from the first possibly-partial request write until the caller
/// observes an authoritative terminal response or an unknown terminal condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolCallEvidence {
    pub server_name: String,
    pub tool_name: String,
    pub dispatch_to_terminal_ms: NonZeroU64,
}

impl McpToolCallEvidence {
    pub fn new(server_name: &str, tool_name: &str, latency_ms: NonZeroU64) -> Self {
        Self {
            server_name: server_name.to_string(),
            tool_name: tool_name.to_string(),
            dispatch_to_terminal_ms: latency_ms,
        }
    }
}

/// A per-request clock. Waiting for the single-flight lock, serialization, and validation happen
/// before `mark_dispatched`, so they cannot inflate the reported transport interval.
pub(crate) struct DispatchClock {
    started: Mutex<Option<Instant>>,
    observer: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Default for DispatchClock {
    fn default() -> Self {
        Self::with_observer(None)
    }
}

impl DispatchClock {
    pub(crate) fn with_observer(observer: Option<Box<dyn FnOnce() + Send>>) -> Self {
        Self {
            started: Mutex::new(None),
            observer: Mutex::new(observer),
        }
    }

    pub(crate) fn mark_dispatched(&self) {
        let mut started = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if started.is_some() {
            return;
        }
        *started = Some(Instant::now());
        drop(started);

        let observer = self
            .observer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(observer) = observer {
            observer();
        }
    }

    pub(crate) fn elapsed_ms(&self) -> Option<NonZeroU64> {
        let started = *self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let elapsed_ns = started?.elapsed().as_nanos();
        // Millisecond observability uses ceiling semantics. A dispatched call that completes
        // inside one clock tick is still real work and must not collapse back to the old `0ms`
        // placeholder. Saturation keeps the conversion total on every supported platform.
        let elapsed_ms = elapsed_ns.saturating_add(999_999) / 1_000_000;
        let elapsed = u64::try_from(elapsed_ms).unwrap_or(u64::MAX).max(1);
        NonZeroU64::new(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undispatched_has_no_evidence_and_a_terminal_dispatch_is_non_zero() {
        let clock = DispatchClock::default();
        assert_eq!(clock.elapsed_ms(), None);
        clock.mark_dispatched();
        assert!(clock.elapsed_ms().is_some_and(|latency| latency.get() > 0));
    }
}

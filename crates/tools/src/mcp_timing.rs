//! Registry-owned timing capability for MCP effects.
//!
//! Ordinary tool implementations cannot submit a duration: the registry remains their timing
//! authority. MCP is the one transport that knows the narrower, semantically important dispatch
//! boundary, so registration hands it this opaque clock. The executor may mark dispatch once; it
//! cannot choose the measured duration.

use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Stable attribution bound to one namespaced MCP registry entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEffectAttribution {
    server_name: String,
    tool_name: String,
}

impl McpEffectAttribution {
    pub fn new(server_name: impl Into<String>, tool_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            tool_name: tool_name.into(),
        }
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub(crate) fn namespaced_name(&self) -> String {
        format!("{}__{}", self.server_name, self.tool_name)
    }
}

/// Opaque, registry-minted clock passed only to an explicitly attributed MCP executor.
#[derive(Debug, Clone)]
pub struct McpDispatchClock {
    attribution: McpEffectAttribution,
    started: Arc<Mutex<Option<Instant>>>,
}

impl McpDispatchClock {
    pub(crate) fn new(attribution: McpEffectAttribution) -> Self {
        Self {
            attribution,
            started: Arc::new(Mutex::new(None)),
        }
    }

    pub fn attribution(&self) -> &McpEffectAttribution {
        &self.attribution
    }

    /// Mark the point at which the MCP pipe write may have partially dispatched the request.
    /// Repeated marks are idempotent, so retrying a short write cannot move the start forward.
    pub fn mark_dispatched(&self) {
        let mut started = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        started.get_or_insert_with(Instant::now);
    }

    pub(crate) fn elapsed_to_terminal_ms(&self) -> Option<u64> {
        let started = *self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let elapsed_ns = started?.elapsed().as_nanos();
        let elapsed_ms = elapsed_ns.saturating_add(999_999) / 1_000_000;
        Some(u64::try_from(elapsed_ms).unwrap_or(u64::MAX).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_clock_is_absent_before_dispatch_and_non_zero_after() {
        let clock = McpDispatchClock::new(McpEffectAttribution::new("server", "tool"));
        assert_eq!(clock.elapsed_to_terminal_ms(), None);
        clock.mark_dispatched();
        assert!(clock.elapsed_to_terminal_ms().is_some_and(|ms| ms > 0));
        assert_eq!(clock.attribution().namespaced_name(), "server__tool");
    }
}

//! Deterministic lifecycle and reconnect policy for one MCP server binding.
//!
//! This module owns no process and reads no clock. A supervisor supplies explicit completion
//! events and enforces the returned delay. Every asynchronous completion carries a generation;
//! a completion from a killed or superseded process therefore cannot make a newer process ready.

use crate::McpError;

pub const MAX_RECONNECT_ATTEMPTS: u32 = 64;
pub const MAX_RECONNECT_BASE_MS: u64 = 60_000;
pub const MAX_RECONNECT_CAP_MS: u64 = 3_600_000;

/// Validated finite retry policy. `max_attempts` counts reconnects after the first lazy attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ReconnectPolicy {
    max_attempts: u32,
    base_ms: u64,
    cap_ms: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_ms: 250,
            cap_ms: 10_000,
        }
    }
}

impl ReconnectPolicy {
    pub fn new(max_attempts: u32, base_ms: u64, cap_ms: u64) -> Result<Self, McpError> {
        if max_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(McpError::InvalidReconnectPolicy {
                field: "max_attempts",
                limit: u64::from(MAX_RECONNECT_ATTEMPTS),
            });
        }
        if base_ms > MAX_RECONNECT_BASE_MS {
            return Err(McpError::InvalidReconnectPolicy {
                field: "base_milliseconds",
                limit: MAX_RECONNECT_BASE_MS,
            });
        }
        if cap_ms > MAX_RECONNECT_CAP_MS {
            return Err(McpError::InvalidReconnectPolicy {
                field: "cap_milliseconds",
                limit: MAX_RECONNECT_CAP_MS,
            });
        }
        if base_ms > cap_ms {
            return Err(McpError::InvalidReconnectBackoffOrder { base_ms, cap_ms });
        }
        Ok(Self {
            max_attempts,
            base_ms,
            cap_ms,
        })
    }

    pub fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    pub fn base_ms(self) -> u64 {
        self.base_ms
    }

    pub fn cap_ms(self) -> u64 {
        self.cap_ms
    }

    /// One-based exponential reconnect delay, saturated at the validated cap.
    pub fn delay_ms(self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let exponent = attempt.saturating_sub(1).min(63);
        self.base_ms
            .saturating_mul(1_u64 << exponent)
            .min(self.cap_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerGeneration(u64);

impl ServerGeneration {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    Deferred,
    Connecting,
    Discovering,
    Ready,
    Backoff,
    Cancelled,
    Failed,
    Exhausted,
    Stopped,
}

impl LifecyclePhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Connecting => "connecting",
            Self::Discovering => "discovering",
            Self::Ready => "ready",
            Self::Backoff => "backoff",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Exhausted => "exhausted",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFailure {
    Spawn,
    Deadline,
    Transport,
    Protocol,
    Catalog,
    Cancelled,
}

/// Lossless operator status: retained catalog size and current usability are separate fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleStatus {
    pub phase: LifecyclePhase,
    pub generation: Option<ServerGeneration>,
    pub reconnect_attempts: u32,
    pub reconnect_limit: u32,
    pub retry_after_ms: Option<u64>,
    pub retained_tools: usize,
    pub catalog_current: bool,
    pub last_failure: Option<LifecycleFailure>,
}

/// Pure generation-fenced state machine used by the stdio supervisor and deterministic fakes.
#[derive(Debug, Clone)]
pub struct LifecycleCore {
    policy: ReconnectPolicy,
    phase: LifecyclePhase,
    generation: Option<ServerGeneration>,
    reconnect_attempts: u32,
    retry_after_ms: Option<u64>,
    retained_tools: usize,
    catalog_generation: Option<ServerGeneration>,
    last_failure: Option<LifecycleFailure>,
}

impl LifecycleCore {
    pub fn deferred(policy: ReconnectPolicy) -> Self {
        Self {
            policy,
            phase: LifecyclePhase::Deferred,
            generation: None,
            reconnect_attempts: 0,
            retry_after_ms: None,
            retained_tools: 0,
            catalog_generation: None,
            last_failure: None,
        }
    }

    pub fn status(&self) -> LifecycleStatus {
        LifecycleStatus {
            phase: self.phase,
            generation: self.generation,
            reconnect_attempts: self.reconnect_attempts,
            reconnect_limit: self.policy.max_attempts,
            retry_after_ms: self.retry_after_ms,
            retained_tools: self.retained_tools,
            catalog_current: self.generation.is_some()
                && self.catalog_generation == self.generation
                && self.phase == LifecyclePhase::Ready,
            last_failure: self.last_failure,
        }
    }

    /// Begin the first lazy connection, a due reconnect, or a fresh request after cancellation.
    pub fn begin_connection(&mut self) -> Result<ServerGeneration, McpError> {
        match self.phase {
            LifecyclePhase::Deferred | LifecyclePhase::Cancelled => {}
            LifecyclePhase::Backoff => {
                if self.reconnect_attempts >= self.policy.max_attempts {
                    self.phase = LifecyclePhase::Exhausted;
                    return Err(McpError::RetryExhausted {
                        attempts: self.reconnect_attempts,
                    });
                }
                self.reconnect_attempts += 1;
            }
            LifecyclePhase::Exhausted => {
                return Err(McpError::RetryExhausted {
                    attempts: self.reconnect_attempts,
                });
            }
            LifecyclePhase::Failed => return Err(McpError::LifecycleFailed),
            LifecyclePhase::Stopped => return Err(McpError::LifecycleStopped),
            phase => return Err(transition(phase, "begin_connection")),
        }
        let next = self
            .generation
            .map_or(1, |generation| generation.0.saturating_add(1));
        if self.generation.is_some_and(|current| next <= current.0) {
            self.phase = LifecyclePhase::Failed;
            return Err(McpError::GenerationExhausted);
        }
        let generation = ServerGeneration(next);
        self.generation = Some(generation);
        self.phase = LifecyclePhase::Connecting;
        self.retry_after_ms = None;
        Ok(generation)
    }

    pub fn connected(&mut self, generation: ServerGeneration) -> Result<(), McpError> {
        self.guard(generation)?;
        if self.phase != LifecyclePhase::Connecting {
            return Err(transition(self.phase, "connected"));
        }
        self.phase = LifecyclePhase::Discovering;
        Ok(())
    }

    pub fn discovered(
        &mut self,
        generation: ServerGeneration,
        tool_count: usize,
    ) -> Result<(), McpError> {
        self.guard(generation)?;
        if self.phase != LifecyclePhase::Discovering {
            return Err(transition(self.phase, "discovered"));
        }
        if tool_count > crate::tool_filter::MAX_COMBINED_MCP_TOOLS {
            return Err(McpError::CombinedToolLimit {
                limit: crate::tool_filter::MAX_COMBINED_MCP_TOOLS,
            });
        }
        self.retained_tools = tool_count;
        self.catalog_generation = Some(generation);
        self.phase = LifecyclePhase::Ready;
        self.retry_after_ms = None;
        self.last_failure = None;
        Ok(())
    }

    /// Record a failed or lost generation. Terminal failures never enter a retry state.
    pub fn failed(
        &mut self,
        generation: ServerGeneration,
        failure: LifecycleFailure,
    ) -> Result<Option<u64>, McpError> {
        self.guard(generation)?;
        if !matches!(
            self.phase,
            LifecyclePhase::Connecting | LifecyclePhase::Discovering | LifecyclePhase::Ready
        ) {
            return Err(transition(self.phase, "failed"));
        }
        self.catalog_generation = None;
        self.last_failure = Some(failure);
        let retryable = matches!(
            failure,
            LifecycleFailure::Spawn | LifecycleFailure::Deadline | LifecycleFailure::Transport
        );
        if !retryable {
            self.phase = LifecyclePhase::Failed;
            self.retry_after_ms = None;
            Ok(None)
        } else if self.reconnect_attempts < self.policy.max_attempts {
            let delay = self.policy.delay_ms(self.reconnect_attempts + 1);
            self.phase = LifecyclePhase::Backoff;
            self.retry_after_ms = Some(delay);
            Ok(Some(delay))
        } else {
            self.phase = LifecyclePhase::Exhausted;
            self.retry_after_ms = None;
            Ok(None)
        }
    }

    pub fn cancel(&mut self, generation: ServerGeneration) -> Result<(), McpError> {
        self.guard(generation)?;
        if !matches!(
            self.phase,
            LifecyclePhase::Connecting | LifecyclePhase::Discovering | LifecyclePhase::Ready
        ) {
            return Err(transition(self.phase, "cancel"));
        }
        self.phase = LifecyclePhase::Cancelled;
        self.catalog_generation = None;
        self.retry_after_ms = None;
        self.last_failure = Some(LifecycleFailure::Cancelled);
        Ok(())
    }

    /// Retry credit is restored only after the supervisor proves a healthy interval and success
    /// count; merely completing a handshake is intentionally insufficient.
    pub fn reset_retry_budget(&mut self, generation: ServerGeneration) -> Result<(), McpError> {
        self.guard(generation)?;
        if self.phase != LifecyclePhase::Ready {
            return Err(transition(self.phase, "reset_retry_budget"));
        }
        self.reconnect_attempts = 0;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.phase = LifecyclePhase::Stopped;
        self.catalog_generation = None;
        self.retry_after_ms = None;
    }

    fn guard(&self, received: ServerGeneration) -> Result<(), McpError> {
        let expected = self.generation.map_or(0, |generation| generation.0);
        if expected != received.0 {
            return Err(McpError::StaleGeneration {
                expected,
                received: received.0,
            });
        }
        Ok(())
    }
}

fn transition(state: LifecyclePhase, event: &'static str) -> McpError {
    McpError::InvalidLifecycleTransition {
        state: state.label(),
        event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy::new(3, 100, 250).unwrap()
    }

    #[test]
    fn policy_is_finite_validated_and_saturating() {
        assert!(ReconnectPolicy::new(65, 1, 1).is_err());
        assert!(ReconnectPolicy::new(1, 2, 1).is_err());
        let policy = policy();
        assert_eq!(policy.delay_ms(0), 0);
        assert_eq!(policy.delay_ms(1), 100);
        assert_eq!(policy.delay_ms(2), 200);
        assert_eq!(policy.delay_ms(3), 250);
        assert_eq!(policy.delay_ms(u32::MAX), 250);
    }

    #[test]
    fn configured_server_is_truly_deferred() {
        let lifecycle = LifecycleCore::deferred(policy());
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Deferred);
        assert_eq!(lifecycle.status().generation, None);
        assert!(!lifecycle.status().catalog_current);
    }

    #[test]
    fn only_current_generation_can_publish_a_catalog() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let first = lifecycle.begin_connection().unwrap();
        lifecycle
            .failed(first, LifecycleFailure::Transport)
            .unwrap();
        let second = lifecycle.begin_connection().unwrap();
        lifecycle.connected(second).unwrap();
        assert!(matches!(
            lifecycle.discovered(first, 4),
            Err(McpError::StaleGeneration { .. })
        ));
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Discovering);
        lifecycle.discovered(second, 4).unwrap();
        assert!(lifecycle.status().catalog_current);
    }

    #[test]
    fn lifecycle_rejects_catalog_counts_above_the_global_bound() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let generation = lifecycle.begin_connection().unwrap();
        lifecycle.connected(generation).unwrap();
        assert!(matches!(
            lifecycle.discovered(generation, crate::tool_filter::MAX_COMBINED_MCP_TOOLS + 1),
            Err(McpError::CombinedToolLimit { .. })
        ));
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Discovering);
        assert!(!lifecycle.status().catalog_current);
    }

    #[test]
    fn reconnects_are_bounded_with_exponential_delays() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let mut generation = lifecycle.begin_connection().unwrap();
        for expected_delay in [100, 200, 250] {
            assert_eq!(
                lifecycle
                    .failed(generation, LifecycleFailure::Transport)
                    .unwrap(),
                Some(expected_delay)
            );
            generation = lifecycle.begin_connection().unwrap();
        }
        assert_eq!(
            lifecycle
                .failed(generation, LifecycleFailure::Transport)
                .unwrap(),
            None
        );
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Exhausted);
        assert_eq!(lifecycle.status().reconnect_attempts, 3);
    }

    #[test]
    fn terminal_failure_never_spends_time_retrying() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let generation = lifecycle.begin_connection().unwrap();
        assert_eq!(
            lifecycle
                .failed(generation, LifecycleFailure::Catalog)
                .unwrap(),
            None
        );
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Failed);
        assert!(matches!(
            lifecycle.begin_connection(),
            Err(McpError::LifecycleFailed)
        ));
    }

    #[test]
    fn cancellation_is_truthful_and_does_not_consume_server_retry_credit() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let first = lifecycle.begin_connection().unwrap();
        lifecycle.cancel(first).unwrap();
        assert_eq!(lifecycle.status().phase, LifecyclePhase::Cancelled);
        let second = lifecycle.begin_connection().unwrap();
        assert!(second > first);
        assert_eq!(lifecycle.status().reconnect_attempts, 0);
    }

    #[test]
    fn a_retained_catalog_is_not_reported_current_during_backoff() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let generation = lifecycle.begin_connection().unwrap();
        lifecycle.connected(generation).unwrap();
        lifecycle.discovered(generation, 7).unwrap();
        lifecycle
            .failed(generation, LifecycleFailure::Transport)
            .unwrap();
        let status = lifecycle.status();
        assert_eq!(status.retained_tools, 7);
        assert!(!status.catalog_current);
        assert_eq!(status.phase, LifecyclePhase::Backoff);
    }

    #[test]
    fn handshake_success_cannot_launder_retry_budget() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        let first = lifecycle.begin_connection().unwrap();
        lifecycle
            .failed(first, LifecycleFailure::Transport)
            .unwrap();
        let second = lifecycle.begin_connection().unwrap();
        lifecycle.connected(second).unwrap();
        lifecycle.discovered(second, 1).unwrap();
        assert_eq!(lifecycle.status().reconnect_attempts, 1);
        lifecycle.reset_retry_budget(second).unwrap();
        assert_eq!(lifecycle.status().reconnect_attempts, 0);
    }

    #[test]
    fn stopped_is_terminal() {
        let mut lifecycle = LifecycleCore::deferred(policy());
        lifecycle.stop();
        assert!(matches!(
            lifecycle.begin_connection(),
            Err(McpError::LifecycleStopped)
        ));
    }
}

//! Language-server session state and finite restart policy.
//!
//! Readiness, shutdown acknowledgement, exit notification, clean EOF, crash and restart backoff are
//! distinct states/events. This prevents an EOF before the shutdown response from being mislabeled
//! clean, and prevents a caller from scheduling a delay then immediately spawning anyway.

use crate::{
    HEALTHY_RESTART_RESET_AFTER_MS, HEALTHY_RESTART_RESET_AFTER_SUCCESSES, LspError,
    MAX_RESTART_ATTEMPTS, MAX_RESTART_BACKOFF_MS, MIN_RESTART_BACKOFF_MS,
    pending::CompletedRequest,
};
use std::collections::HashSet;

/// Where a session is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Initializing,
    Ready,
    ShuttingDown,
    Exiting,
    AwaitingExitStatus,
    AwaitingStreamClose,
    RestartBackoff,
    Exited,
    Crashed,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::ShuttingDown => "shutting down",
            Self::Exiting => "exit sent",
            Self::AwaitingExitStatus => "awaiting exit status",
            Self::AwaitingStreamClose => "awaiting stream close",
            Self::RestartBackoff => "restart backoff",
            Self::Exited => "exited",
            Self::Crashed => "crashed",
        }
    }
}

/// Inputs that move a session. The driver must distinguish a clean frame-boundary EOF from an
/// observed process failure; neither is inferred from a string or exit timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    InitializeSent,
    /// Initialize result received and `initialized` notification sent.
    Initialized,
    ShutdownSent,
    /// Shutdown result received and the one-way `exit` notification sent.
    ExitSent,
    /// Clean EOF at a frame boundary.
    StreamClosed,
    /// The supervised process exited with the protocol-required success status.
    ProcessExitedSuccessfully,
    /// Non-success process status, broken frame, or transport I/O error.
    ProcessFailed,
}

/// Validated, finite restart configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    max_attempts: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_ms: 250,
            max_backoff_ms: 10_000,
        }
    }
}

impl RestartPolicy {
    pub fn new(
        max_attempts: u32,
        base_backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, LspError> {
        if max_attempts > MAX_RESTART_ATTEMPTS {
            return Err(LspError::InvalidRestartAttempts {
                value: max_attempts,
                max: MAX_RESTART_ATTEMPTS,
            });
        }
        validate_backoff("base", base_backoff_ms)?;
        validate_backoff("maximum", max_backoff_ms)?;
        if base_backoff_ms > max_backoff_ms {
            return Err(LspError::InvalidRestartBackoffOrder {
                base_ms: base_backoff_ms,
                max_ms: max_backoff_ms,
            });
        }
        Ok(Self {
            max_attempts,
            base_backoff_ms,
            max_backoff_ms,
        })
    }

    pub fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    pub fn base_backoff_ms(self) -> u64 {
        self.base_backoff_ms
    }

    pub fn max_backoff_ms(self) -> u64 {
        self.max_backoff_ms
    }

    /// Exponential backoff, saturating at the validated maximum.
    pub fn backoff_ms(self, attempt: u32) -> u64 {
        let steps = attempt.saturating_sub(1).min(32);
        self.base_backoff_ms
            .saturating_mul(1u64 << steps)
            .min(self.max_backoff_ms)
    }
}

fn validate_backoff(field: &'static str, value_ms: u64) -> Result<(), LspError> {
    if !(MIN_RESTART_BACKOFF_MS..=MAX_RESTART_BACKOFF_MS).contains(&value_ms) {
        return Err(LspError::InvalidRestartBackoff {
            field,
            value_ms,
            min_ms: MIN_RESTART_BACKOFF_MS,
            max_ms: MAX_RESTART_BACKOFF_MS,
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Session {
    state: State,
    policy: RestartPolicy,
    restarts: u32,
    last_now_ms: Option<u64>,
    restart_not_before_ms: Option<u64>,
    ready_since_ms: Option<u64>,
    successful_requests: HashSet<(u64, u32)>,
    last_success_generation: Option<u64>,
    last_success_id: u32,
}

impl Session {
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            state: State::Uninitialized,
            policy,
            restarts: 0,
            last_now_ms: None,
            restart_not_before_ms: None,
            ready_since_ms: None,
            successful_requests: HashSet::with_capacity(
                HEALTHY_RESTART_RESET_AFTER_SUCCESSES as usize,
            ),
            last_success_generation: None,
            last_success_id: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn restarts(&self) -> u32 {
        self.restarts
    }

    pub fn accepts_requests(&self) -> bool {
        self.state == State::Ready
    }

    pub fn guard_request(&self) -> Result<(), LspError> {
        if self.accepts_requests() {
            Ok(())
        } else {
            Err(LspError::NotReady {
                state: self.state.label(),
            })
        }
    }

    /// Apply a timestamped event. Illegal peer transitions remain inert, while early restart is a
    /// typed error because it would bypass a security-relevant spawn-storm bound.
    pub fn apply(&mut self, event: Event, now_ms: u64) -> Result<State, LspError> {
        self.observe_clock(now_ms)?;
        if self.state == State::RestartBackoff && event == Event::InitializeSent {
            let not_before = self
                .restart_not_before_ms
                .expect("restart backoff state has a deadline");
            if now_ms < not_before {
                return Err(LspError::RestartBackoffActive {
                    remaining_ms: not_before - now_ms,
                });
            }
            self.state = State::Initializing;
            self.restart_not_before_ms = None;
            return Ok(self.state);
        }

        let next = match (self.state, event) {
            (State::Uninitialized, Event::InitializeSent) => State::Initializing,
            (State::Initializing, Event::Initialized) => State::Ready,
            (State::Ready, Event::ShutdownSent) => State::ShuttingDown,
            (State::ShuttingDown, Event::ExitSent) => State::Exiting,
            (State::Exiting, Event::StreamClosed) => State::AwaitingExitStatus,
            (State::Exiting, Event::ProcessExitedSuccessfully) => State::AwaitingStreamClose,
            (State::AwaitingExitStatus, Event::ProcessExitedSuccessfully)
            | (State::AwaitingStreamClose, Event::StreamClosed) => State::Exited,
            (
                State::Uninitialized | State::Initializing | State::Ready | State::ShuttingDown,
                Event::StreamClosed,
            )
            | (
                State::Uninitialized | State::Initializing | State::Ready | State::ShuttingDown,
                Event::ProcessExitedSuccessfully,
            )
            | (
                State::Uninitialized
                | State::Initializing
                | State::Ready
                | State::ShuttingDown
                | State::Exiting
                | State::AwaitingExitStatus
                | State::AwaitingStreamClose,
                Event::ProcessFailed,
            ) => State::Crashed,
            (current, _) => current,
        };
        self.set_state(next, now_ms);
        Ok(self.state)
    }

    /// Consume one restart unit and enter an enforced backoff state. The returned delay is for
    /// scheduling/telemetry; `apply(InitializeSent, ...)` independently enforces it.
    pub fn plan_restart(&mut self, now_ms: u64) -> Result<u64, LspError> {
        self.observe_clock(now_ms)?;
        if self.state != State::Crashed {
            return Err(LspError::NotReady {
                state: self.state.label(),
            });
        }
        if self.restarts >= self.policy.max_attempts {
            return Err(LspError::RestartBudgetExhausted {
                attempts: self.restarts,
            });
        }
        let next_restart = self.restarts + 1;
        let delay = self.policy.backoff_ms(next_restart);
        let not_before = now_ms.checked_add(delay).ok_or(LspError::TimeOverflow {
            operation: "restart backoff",
            base_ms: now_ms,
            delta_ms: delay,
        })?;
        self.restarts = next_restart;
        self.state = State::RestartBackoff;
        self.restart_not_before_ms = Some(not_before);
        Ok(delay)
    }

    /// Record a successfully served request. Restart credit is restored only after both a fixed
    /// healthy uptime and several successes, so one response cannot sustain an infinite crash loop.
    /// Returns true exactly when credit was restored.
    pub fn note_request_succeeded(
        &mut self,
        request: CompletedRequest,
        now_ms: u64,
    ) -> Result<bool, LspError> {
        self.observe_clock(now_ms)?;
        self.guard_request()?;
        let generation = request.generation();
        let id = request.id();
        let is_new = match self.last_success_generation {
            None => true,
            Some(previous_generation) if generation > previous_generation => true,
            Some(previous_generation) if generation == previous_generation => {
                id > self.last_success_id
            }
            Some(_) => false,
        };
        if !is_new {
            return Ok(false);
        }
        self.last_success_generation = Some(generation);
        self.last_success_id = id;
        if self.successful_requests.len() < HEALTHY_RESTART_RESET_AFTER_SUCCESSES as usize {
            self.successful_requests.insert((generation, id));
        }
        let ready_since = self.ready_since_ms.expect("ready state has an epoch");
        let stable = now_ms.saturating_sub(ready_since) >= HEALTHY_RESTART_RESET_AFTER_MS
            && self.successful_requests.len() >= HEALTHY_RESTART_RESET_AFTER_SUCCESSES as usize;
        if stable && self.restarts > 0 {
            self.restarts = 0;
            return Ok(true);
        }
        Ok(false)
    }

    fn set_state(&mut self, next: State, now_ms: u64) {
        if next == self.state {
            return;
        }
        self.state = next;
        if next == State::Ready {
            self.ready_since_ms = Some(now_ms);
            self.successful_requests.clear();
        } else {
            self.ready_since_ms = None;
            self.successful_requests.clear();
        }
        if next == State::Crashed || next == State::Exited {
            self.restart_not_before_ms = None;
        }
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

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;

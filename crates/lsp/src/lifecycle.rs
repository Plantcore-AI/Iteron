//! Server session state machine and restart policy.
//!
//! The LSP handshake has a rule that is easy to get wrong and expensive to debug: between
//! `initialize` and the `initialized` notification the server may answer *only* the initialize
//! request. Sending `textDocument/definition` into that window is a protocol violation, and real
//! servers respond by either erroring or hanging. So readiness is a state here, not a boolean that
//! a caller sets when it feels ready.
//!
//! Crash recovery is a budget rather than a retry loop. A server that dies on a malformed file in
//! the workspace dies again immediately on restart, and an unbounded loop turns one bad file into
//! a spawn storm.

use crate::LspError;

/// Where a session is in its lifecycle. `Crashed` is distinct from `Exited`: an exit we asked for
/// is success, an exit we did not ask for is a fault that consumes restart budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Initializing,
    Ready,
    ShuttingDown,
    Exited,
    Crashed,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::Uninitialized => "uninitialized",
            State::Initializing => "initializing",
            State::Ready => "ready",
            State::ShuttingDown => "shutting down",
            State::Exited => "exited",
            State::Crashed => "crashed",
        }
    }
}

/// Inputs that move a session. Everything that can change state is one of these, so a transition
/// cannot be performed by an unrelated code path reaching in and assigning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// `initialize` request sent.
    InitializeSent,
    /// `initialize` result received and `initialized` notification sent.
    Initialized,
    /// `shutdown` request sent.
    ShutdownSent,
    /// `exit` observed after a shutdown we requested.
    ExitedCleanly,
    /// Process died without a shutdown handshake, or the stream broke.
    Died,
}

#[derive(Debug, Clone, Copy)]
pub struct RestartPolicy {
    pub max_attempts: u32,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
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
    /// Exponential backoff, saturating at `max_backoff_ms`.
    ///
    /// `attempt` is 1-based: the delay before the first restart is `base_backoff_ms`. Shifting is
    /// bounded before it is applied, because `1u64 << 64` is undefined behaviour in release and a
    /// panic in debug, and a server that crashes 64 times is exactly how you would reach it.
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        let steps = attempt.saturating_sub(1).min(32);
        self.base_backoff_ms
            .saturating_mul(1u64 << steps)
            .min(self.max_backoff_ms)
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    state: State,
    policy: RestartPolicy,
    restarts: u32,
}

impl Session {
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            state: State::Uninitialized,
            policy,
            restarts: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn restarts(&self) -> u32 {
        self.restarts
    }

    /// True only in `Ready`. Callers gate every non-handshake request on this.
    pub fn accepts_requests(&self) -> bool {
        self.state == State::Ready
    }

    /// Reject a request that cannot legally be sent yet, naming the state so the failure is
    /// diagnosable without attaching a debugger to the server.
    pub fn guard_request(&self) -> Result<(), LspError> {
        if self.accepts_requests() {
            Ok(())
        } else {
            Err(LspError::NotReady {
                state: self.state.label(),
            })
        }
    }

    /// Apply an event. Illegal transitions are ignored rather than panicking: these events arrive
    /// from a peer we do not control, and a server that sends `initialized` twice must not be able
    /// to abort the agent.
    pub fn apply(&mut self, event: Event) -> State {
        self.state = match (self.state, event) {
            (State::Uninitialized, Event::InitializeSent) => State::Initializing,
            (State::Initializing, Event::Initialized) => State::Ready,
            (State::Ready, Event::ShutdownSent) => State::ShuttingDown,
            (State::ShuttingDown, Event::ExitedCleanly) => State::Exited,
            // A death in any live state is a crash. A death after we asked to shut down is the
            // clean path and is handled by the arm above.
            (
                State::Uninitialized | State::Initializing | State::Ready | State::ShuttingDown,
                Event::Died,
            ) => State::Crashed,
            (current, _) => current,
        };
        self.state
    }

    /// Consume one unit of restart budget and report how long to wait.
    ///
    /// Only a crashed session may restart. Restarting an `Exited` session would resurrect a server
    /// the caller deliberately shut down.
    pub fn plan_restart(&mut self) -> Result<u64, LspError> {
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
        self.restarts += 1;
        self.state = State::Uninitialized;
        Ok(self.policy.backoff_ms(self.restarts))
    }

    /// A session that has served a request without dying has proven the workspace is not
    /// instantly fatal, so its budget is returned. Without this, a long-lived session that
    /// crashes once a week would eventually refuse to restart for a reason a week old.
    pub fn note_healthy(&mut self) {
        if self.state == State::Ready {
            self.restarts = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Session {
        let mut s = Session::new(RestartPolicy::default());
        s.apply(Event::InitializeSent);
        s.apply(Event::Initialized);
        s
    }

    #[test]
    fn requests_are_refused_until_the_handshake_completes() {
        let mut s = Session::new(RestartPolicy::default());
        assert!(matches!(
            s.guard_request(),
            Err(LspError::NotReady {
                state: "uninitialized"
            })
        ));

        // The window the spec forbids: initialize sent, initialized not yet exchanged.
        s.apply(Event::InitializeSent);
        assert!(matches!(
            s.guard_request(),
            Err(LspError::NotReady {
                state: "initializing"
            })
        ));

        s.apply(Event::Initialized);
        assert!(s.guard_request().is_ok());
    }

    #[test]
    fn a_duplicate_initialized_does_not_move_a_ready_session() {
        let mut s = ready();
        assert_eq!(s.apply(Event::Initialized), State::Ready);
    }

    #[test]
    fn clean_shutdown_is_not_a_crash_and_costs_no_budget() {
        let mut s = ready();
        s.apply(Event::ShutdownSent);
        assert_eq!(s.apply(Event::ExitedCleanly), State::Exited);
        assert_eq!(s.restarts(), 0);
        // An exited session is not restartable; that would resurrect a deliberate shutdown.
        assert!(matches!(s.plan_restart(), Err(LspError::NotReady { .. })));
    }

    #[test]
    fn an_unrequested_death_is_a_crash_from_any_live_state() {
        for build in [
            || Session::new(RestartPolicy::default()),
            || {
                let mut s = Session::new(RestartPolicy::default());
                s.apply(Event::InitializeSent);
                s
            },
            ready,
        ] {
            let mut s = build();
            assert_eq!(s.apply(Event::Died), State::Crashed);
        }
    }

    #[test]
    fn restart_budget_is_finite_and_backoff_grows() {
        let mut s = ready();
        let mut delays = Vec::new();
        for _ in 0..3 {
            s.apply(Event::Died);
            delays.push(s.plan_restart().unwrap());
            s.apply(Event::InitializeSent);
            s.apply(Event::Initialized);
        }
        assert_eq!(delays, vec![250, 500, 1000]);

        // Fourth crash exceeds the budget rather than spawning again.
        s.apply(Event::Died);
        assert_eq!(
            s.plan_restart(),
            Err(LspError::RestartBudgetExhausted { attempts: 3 })
        );
    }

    #[test]
    fn a_healthy_session_earns_its_budget_back() {
        let mut s = ready();
        s.apply(Event::Died);
        s.plan_restart().unwrap();
        s.apply(Event::InitializeSent);
        s.apply(Event::Initialized);
        assert_eq!(s.restarts(), 1);

        s.note_healthy();
        assert_eq!(s.restarts(), 0);
    }

    #[test]
    fn backoff_saturates_instead_of_overflowing() {
        let policy = RestartPolicy::default();
        // The shift is clamped, so a pathological attempt count returns the ceiling rather than
        // panicking on overflow.
        assert_eq!(policy.backoff_ms(u32::MAX), policy.max_backoff_ms);
        assert_eq!(policy.backoff_ms(1), 250);
    }
}

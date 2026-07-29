//! The immutable state a turn is folded into, and the pinned limits it is judged against.
//!
//! Plain data, no methods that do anything but read. `reduce` takes `&TurnState` and returns a new
//! one; nothing here can be mutated in place, so "who changed this field" is never a question.

use crate::turn_protocol::{ControlSignal, HarnessFault, TurnPhase};
use core_protocol::Outcome;
use serde::{Deserialize, Serialize};

/// The ceilings a run is bound by. Pinned at admission and never re-read mid-run: a ceiling that
/// could move under a running turn is not a ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnLimits {
    /// Provider turns the run may spend.
    pub max_turns: u32,
    /// Consecutive tool-error turns before the stability floor trips.
    pub max_consecutive_tool_errors: u32,
    /// Verification attempts before the gate stops asking.
    pub max_verify_attempts: u32,
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_turns: 8,
            max_consecutive_tool_errors: 5,
            max_verify_attempts: 3,
        }
    }
}

/// Everything the loop needs to decide what happens next.
///
/// # What is deliberately absent
///
/// No clock, no deadline instant, no running cost. Those are readings, and a reading that lives in
/// the state is a reading the reducer can be tempted to take. They arrive as command fields
/// instead, sampled by the driver at a defined point, which is what makes a recorded command stream
/// a complete description of a run.
///
/// No transcript either. Messages are large, provider-shaped, and irrelevant to control flow: every
/// branch in the imperative loop turned on counters, phases and latches, never on message content.
/// `Serialize` only, for the same reason as `ActionRequest`: the frozen `Outcome` carries a
/// `&'static str`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TurnState {
    pub limits: TurnLimits,
    pub phase: TurnPhase,
    /// The turn currently being driven. Monotonic; recovery resumes from the recorded maximum.
    pub turn: u32,
    /// Provider turns that reached a terminal. The `max_turns` ceiling is judged on this.
    pub completed_turns: u32,
    /// Consecutive turns that ended with at least one tool error.
    pub consecutive_tool_errors: u32,
    /// Verification attempts consumed. Only a graded test failure consumes one.
    pub verify_attempts: u32,
    /// Whether a verification gate is configured for this run.
    pub verify_gate: bool,
    /// Latched operator control.
    pub control: ControlSignal,
    /// False once a durable append has failed.
    pub record_healthy: bool,
    /// Dispatches recovery could not prove a terminal for.
    pub unresolved_effects: usize,
    /// Set exactly once, when the run reaches a terminal state.
    pub outcome: Option<Outcome>,
    /// Set alongside `outcome` when the terminal is a harness fault rather than a clean stop.
    pub fault: Option<HarnessFault>,
}

impl TurnState {
    /// A fresh run at turn zero.
    pub fn new(limits: TurnLimits, verify_gate: bool) -> Self {
        Self {
            limits,
            phase: TurnPhase::Admitting,
            turn: 0,
            completed_turns: 0,
            consecutive_tool_errors: 0,
            verify_attempts: 0,
            verify_gate,
            control: ControlSignal::None,
            record_healthy: true,
            unresolved_effects: 0,
            outcome: None,
            fault: None,
        }
    }

    /// Resume at a recorded turn. The turn number is recovered from durable history, which is why
    /// it is a parameter rather than something the reducer could invent.
    pub fn resumed_at(limits: TurnLimits, verify_gate: bool, turn: u32) -> Self {
        Self {
            turn,
            ..Self::new(limits, verify_gate)
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.phase, TurnPhase::Finished)
    }

    /// Has the run spent its turn ceiling? Judged on completed turns, so a turn that never reached
    /// a terminal does not silently consume budget.
    pub fn turn_ceiling_reached(&self) -> bool {
        self.completed_turns >= self.limits.max_turns
    }

    /// Has the stability floor tripped?
    pub fn stuck(&self) -> bool {
        self.consecutive_tool_errors >= self.limits.max_consecutive_tool_errors
    }

    /// Has the verification gate stopped being worth asking?
    pub fn verify_ceiling_reached(&self) -> bool {
        self.verify_attempts >= self.limits.max_verify_attempts
    }

    /// The terminal form of this state.
    pub(crate) fn finished(mut self, outcome: Outcome, fault: Option<HarnessFault>) -> Self {
        self.phase = TurnPhase::Finished;
        self.outcome = Some(outcome);
        self.fault = fault;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_state_is_admitting_and_healthy() {
        let state = TurnState::new(TurnLimits::default(), false);
        assert_eq!(state.phase, TurnPhase::Admitting);
        assert!(state.record_healthy);
        assert!(state.outcome.is_none());
        assert!(!state.is_finished());
    }

    #[test]
    fn ceilings_are_judged_on_completed_turns_not_attempted_ones() {
        let limits = TurnLimits {
            max_turns: 2,
            ..TurnLimits::default()
        };
        let mut state = TurnState::new(limits, false);
        state.turn = 9;
        assert!(
            !state.turn_ceiling_reached(),
            "an attempted turn that never terminated must not consume the ceiling"
        );
        state.completed_turns = 2;
        assert!(state.turn_ceiling_reached());
    }

    #[test]
    fn a_resumed_state_keeps_the_recorded_turn_and_nothing_else() {
        let state = TurnState::resumed_at(TurnLimits::default(), true, 41);
        assert_eq!(state.turn, 41);
        assert_eq!(state.completed_turns, 0);
        assert!(state.verify_gate);
        assert_eq!(state.phase, TurnPhase::Admitting);
    }
}

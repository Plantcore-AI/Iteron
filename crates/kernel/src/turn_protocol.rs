//! The closed vocabulary the pure reducer reasons in.
//!
//! # Why the reducer does not speak `iteron_provider`
//!
//! The obvious shape for `Command::ProviderCompleted` is to carry a `iteron_provider::StopReason`
//! straight through. Issue #15 bans exactly that, and the ban is not stylistic: the moment the
//! reducer names a world type, the reducer's meaning is pinned to that world module's release
//! cadence, and "the kernel depends only on the frozen ABI" stops being checkable. So the states a
//! provider turn can end in are re-declared here as kernel-owned values, and the driver — which is
//! allowed to touch the world — translates at the seam.
//!
//! Everything here derives `Serialize` because the replay invariant is stated in bytes: the same
//! command stream must produce a byte-identical action-request sequence. A vocabulary that could
//! not be serialised could not be held to that.

use serde::{Deserialize, Serialize};

/// Where one turn currently is. Phases are explicit so that "what may happen next" is a property of
/// a value rather than of which line of an imperative procedure happens to be executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnPhase {
    /// Before any work. Nothing has been admitted yet.
    Admitting,
    /// A submission was admitted and the context port has been asked to resolve. Distinct from
    /// `Admitting` so that a second admission is a protocol violation rather than a second
    /// `SelectContext` — that request is routed to a port that appends durably, and asking twice
    /// would put a duplicate context resolution on the record.
    AwaitingContext,
    /// At a turn boundary. Every stop condition is evaluated here and nowhere else.
    Boundary,
    /// A provider request is in flight.
    AwaitingProvider,
    /// The turn's tool calls are in flight.
    AwaitingTools,
    /// The verification oracle is in flight.
    AwaitingVerify,
    /// The model says the task is done and the gate, if any, agreed. One question remains before
    /// committing: did the operator say something while the oracle was running? The imperative loop
    /// asked it too — this names the moment instead of leaving it between two statements.
    Settling,
    /// Terminal. No command changes the outcome once this is reached.
    Finished,
}

/// How a provider turn ended, as the kernel understands it.
///
/// Mirrors the adapter's terminal vocabulary without importing it. `Unknown` deliberately carries
/// no code: an unrecognised terminal is a refusal to guess, and the raw provider-controlled value
/// has no business steering a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTermination {
    /// The model finished its turn.
    EndTurn,
    /// The model asked for tools.
    ToolUse,
    /// Output hit the token ceiling mid-answer.
    MaxTokens,
    /// The provider paused a resumable turn.
    PauseTurn,
    /// An unsolicited stop sequence. Core configures none, so this is never success.
    StopSequence,
    /// The provider refused the request.
    Refusal,
    /// A terminal this build has no safe action for.
    Unknown,
}

/// Why a provider dispatch produced no usable turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailure {
    /// The run's wall-clock deadline was reached.
    DeadlineExceeded,
    /// The operator interrupted while the stream was in flight.
    Interrupted,
    /// The endpoint answered, but not with something the kernel can use.
    Rejected,
    /// The dispatch crossed the boundary and left no observable outcome.
    Unobservable,
}

/// What the verification oracle reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    Pass,
    TestFailure,
    TimedOut,
    InfrastructureFailure,
    Cancelled,
}

/// Operator control observed at a safe point.
///
/// Latched rather than sampled: once the reducer has seen `Drain`, no later `None` may un-see it.
/// The imperative loop got this right by re-reading a flag; expressing it as a latch makes it
/// impossible to get wrong by reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlSignal {
    #[default]
    None,
    /// Stop at the next safe point without a workspace checkpoint.
    Interrupt,
    /// Quiesce: checkpoint the workspace, then stop.
    Drain,
}

impl ControlSignal {
    /// Merge an observation into the latch. Drain outranks Interrupt because a drain promises a
    /// durable checkpoint and downgrading it would silently drop that promise.
    pub fn latch(self, observed: ControlSignal) -> ControlSignal {
        self.max(observed)
    }

    pub fn is_stopping(self) -> bool {
        !matches!(self, ControlSignal::None)
    }
}

/// A budget ceiling the driver sampled outside the reducer.
///
/// Every one of these is an external reading — a clock, a running cost total, a turn counter — and
/// so every one of them enters as a command field. That is the whole determinism argument: the
/// reducer decides *what a ceiling means*, never *what time it is*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetCeiling {
    MaxTurns,
    MaxWallSecs,
    MaxUsd,
    /// The route has no verified rate card, so a positive ceiling cannot be enforced honestly.
    UnpricedCeiling,
}

impl BudgetCeiling {
    /// The stable reason string recorded with `Outcome::BudgetExhausted`.
    ///
    /// Returns `&'static str` because the durable outcome carries one; a formatted string here
    /// would put an allocation on a path whose whole point is that it is reproducible.
    pub const fn reason(self) -> &'static str {
        match self {
            BudgetCeiling::MaxTurns => "max_turns",
            BudgetCeiling::MaxWallSecs => "max_wall_secs",
            BudgetCeiling::MaxUsd => "max_usd",
            BudgetCeiling::UnpricedCeiling => "unpriced_usd_ceiling",
        }
    }
}

/// Why the reducer refused to continue, for the cases that are harness faults rather than outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessFault {
    /// A durable append failed, so the audit trail no longer describes the run.
    RecordUnhealthy,
    /// Recovery found dispatches with no provable terminal.
    UnresolvedEffects,
    /// The provider terminal cannot be turned into a next step.
    UndecodableTurn,
    /// The verifier could not run, so the gate can neither pass nor fail honestly.
    VerifierUnusable,
    /// The driver sent a command the current phase cannot accept. This is a bug in the driver, and
    /// stopping loudly is the point: a silently ignored command becomes a run that skips a step.
    ProtocolViolation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_outranks_interrupt_and_neither_can_be_un_seen() {
        assert_eq!(
            ControlSignal::None.latch(ControlSignal::Interrupt),
            ControlSignal::Interrupt
        );
        assert_eq!(
            ControlSignal::Interrupt.latch(ControlSignal::Drain),
            ControlSignal::Drain
        );
        // The case the latch exists for: a later quiet observation must not clear a stop.
        assert_eq!(
            ControlSignal::Drain.latch(ControlSignal::None),
            ControlSignal::Drain
        );
        assert_eq!(
            ControlSignal::Drain.latch(ControlSignal::Interrupt),
            ControlSignal::Drain,
            "a drain's checkpoint promise must not be downgraded to a bare interrupt"
        );
    }

    #[test]
    fn every_ceiling_has_a_stable_recorded_reason() {
        for ceiling in [
            BudgetCeiling::MaxTurns,
            BudgetCeiling::MaxWallSecs,
            BudgetCeiling::MaxUsd,
            BudgetCeiling::UnpricedCeiling,
        ] {
            assert!(!ceiling.reason().is_empty());
        }
    }
}

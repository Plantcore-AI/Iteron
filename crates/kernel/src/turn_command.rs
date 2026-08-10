//! What can happen to a turn, as a closed set of values.
//!
//! A command is the *only* way information enters the reducer. That is the determinism contract in
//! one sentence: if a decision depends on the wall clock, the running cost, a process exit code or
//! an operator keystroke, that reading is collected by the driver and arrives here as a field. A
//! recorded command stream is therefore a complete, replayable description of a run.

use crate::turn_protocol::{
    BudgetCeiling, ControlSignal, ProviderFailure, ProviderTermination, VerifyOutcome,
};
use iteron_protocol::context::ContextGrant;
use serde::{Deserialize, Serialize};

/// One thing that happened, addressed to the reducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// A submission was admitted and the run may begin.
    Admitted,
    /// The context port answered, carrying the grant it produced.
    ///
    /// The reducer does not read the grant: no control-flow branch turns on what was selected, and
    /// a test pins that. It rides in the command stream anyway, because the stream is supposed to
    /// be a *complete* description of a run — a replay that had to re-read the workspace to find
    /// out what context was injected would be reconstructing the run from the world rather than
    /// from the record, which is the thing determinism is meant to rule out.
    ContextResolved { grant: Box<ContextGrant> },
    /// Budget readings, sampled by the driver immediately before a turn boundary decision.
    ///
    /// `ceiling` is `Some` when a ceiling is already spent. Passing the *decision* rather than the
    /// raw numbers is deliberate: cost arithmetic needs a rate card and a clock, both of which are
    /// world concerns, while "which ceiling was hit" is a closed value the reducer can be held to.
    BudgetSampled { ceiling: Option<BudgetCeiling> },
    /// Operator control observed at a safe point.
    ControlObserved { signal: ControlSignal },
    /// A durable append failed. The run must stop rather than proceed unrecorded.
    RecordFailed,
    /// Recovery found dispatches with no provable terminal.
    UnresolvedEffectsObserved { count: usize },
    /// A provider turn returned a usable terminal.
    ProviderCompleted {
        termination: ProviderTermination,
        /// Tool calls the model asked for. Zero means the terminal is the whole answer.
        tool_calls: u32,
    },
    /// A provider dispatch produced no usable turn.
    ProviderFailed { failure: ProviderFailure },
    /// Every tool the turn dispatched reached a terminal.
    ToolsCompleted { any_error: bool },
    /// The verification oracle answered.
    VerifyCompleted { outcome: VerifyOutcome },
    /// Operator guidance was admitted at a safe point. A steered turn is not a finished one: the
    /// loop owes the operator another pass rather than committing Done over their input.
    Steered { count: u32 },
}

impl Command {
    /// A short stable label, for transition-table tests and diagnostics.
    pub const fn label(&self) -> &'static str {
        match self {
            Command::Admitted => "admitted",
            Command::ContextResolved { .. } => "context_resolved",
            Command::BudgetSampled { .. } => "budget_sampled",
            Command::ControlObserved { .. } => "control_observed",
            Command::RecordFailed => "record_failed",
            Command::UnresolvedEffectsObserved { .. } => "unresolved_effects_observed",
            Command::ProviderCompleted { .. } => "provider_completed",
            Command::ProviderFailed { .. } => "provider_failed",
            Command::ToolsCompleted { .. } => "tools_completed",
            Command::VerifyCompleted { .. } => "verify_completed",
            Command::Steered { .. } => "steered",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_round_trip_through_their_wire_form() {
        // The replay invariant is stated in bytes, so a command that cannot survive a round trip
        // cannot be part of a recorded stream.
        let commands = [
            Command::Admitted,
            Command::ContextResolved {
                grant: Box::new(iteron_protocol::context::ContextGrant {
                    request_id: iteron_protocol::context::RequestId(1),
                    segments: Vec::new(),
                    bytes: 0,
                }),
            },
            Command::BudgetSampled {
                ceiling: Some(BudgetCeiling::MaxUsd),
            },
            Command::ControlObserved {
                signal: ControlSignal::Drain,
            },
            Command::RecordFailed,
            Command::UnresolvedEffectsObserved { count: 2 },
            Command::ProviderCompleted {
                termination: ProviderTermination::ToolUse,
                tool_calls: 3,
            },
            Command::ProviderFailed {
                failure: ProviderFailure::Interrupted,
            },
            Command::ToolsCompleted { any_error: true },
            Command::VerifyCompleted {
                outcome: VerifyOutcome::TestFailure,
            },
            Command::Steered { count: 1 },
        ];
        for command in commands {
            let wire = serde_json::to_string(&command).expect("command serialises");
            let back: Command = serde_json::from_str(&wire).expect("command decodes");
            assert_eq!(
                back,
                command,
                "{} lost information on the wire",
                command.label()
            );
        }
    }
}

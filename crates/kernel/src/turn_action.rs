//! What the reducer asks the world to do.
//!
//! An action request is a *request*, not a call: it names an operation and its arguments and hands
//! them to the driver, which owns every port and the effect boundary. Nothing here executes,
//! allocates a connection, or touches a file. That separation is what lets the same command stream
//! be replayed offline against no world at all and still produce the identical sequence.

use iteron_protocol::Outcome;
use serde::{Deserialize, Serialize};

/// One operation the reducer wants performed, in the order it wants them.
///
/// `Serialize` only, deliberately. `iteron_protocol::Outcome::BudgetExhausted` carries a
/// `&'static str`, which cannot be deserialised into an owned value, and the replay invariant is
/// stated one-way anyway: the recorded stream is *written* and compared, never read back into a
/// live action. Deriving `Deserialize` here would mean either widening the frozen `Outcome` or
/// keeping a second, subtly different action type for reading — both worse than not having it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionRequest {
    /// Resolve the durable context for this run.
    ///
    /// This is the seam W3's port inversion consumes: today the driver hands it to whatever
    /// `ContextPort` is injected, and the reducer neither knows nor can discover which selector,
    /// which files, or how many tokens came back. Declaring it as an action request rather than
    /// calling `iteron_ctx` inline is the entire reason the reducer can be replayed.
    SelectContext,
    /// Sample the budget ceilings and report back with `Command::BudgetSampled`.
    SampleBudget,
    /// Observe the ordered submission queue and report back with `Command::ControlObserved`.
    ObserveControl,
    /// Admit any operator guidance queued at this safe point and report the count back with
    /// `Command::Steered`. Separate from `ObserveControl` because they answer different questions:
    /// one asks whether to stop, the other whether there is new input worth another turn.
    AdmitSteers { turn: u32 },
    /// Dispatch one provider turn.
    CallProvider { turn: u32 },
    /// Dispatch the turn's tool calls.
    DispatchTools { turn: u32, calls: u32 },
    /// Run the verification oracle.
    RunVerify { turn: u32, attempt: u32 },
    /// Commit a durable workspace checkpoint. Only ever emitted on the drain path.
    Checkpoint { turn: u32 },
    /// Append a bounded operator-visible note.
    Notice { text: NoticeKind },
    /// Append a user-role continuation so the transcript stays valid, then take another turn.
    Continue { turn: u32, reason: ContinueReason },
    /// Close the current turn and open the next.
    AdvanceTurn { turn: u32 },
    /// The run is over.
    Finish { outcome: Outcome },
}

/// The closed set of notes the reducer can ask for.
///
/// Free text would make the action sequence depend on formatting, and the replay invariant is
/// stated on the serialised bytes — a reworded message would read as a behaviour change. The driver
/// renders these into operator-facing prose at the seam, where wording is presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    VerifyPassed,
    VerifyTestFailure,
    VerifyCeilingReached,
    VerifyTimedOut,
    VerifyInfrastructureFailure,
    VerifyCancelled,
    MaxTokensContinuation,
    ProviderPausedContinuation,
    RecordUnhealthy,
    UnresolvedEffects,
}

/// Why the loop is taking another turn rather than answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinueReason {
    /// Output hit the token ceiling; ask for the remainder.
    MaxTokens,
    /// The provider paused a resumable turn.
    ProviderPaused,
    /// A verification failure was reported back to the model.
    VerifyFeedback,
    /// The operator steered at a safe point.
    Steered,
}

impl ActionRequest {
    /// A short stable label, for transition-table tests and diagnostics.
    pub const fn label(&self) -> &'static str {
        match self {
            ActionRequest::SelectContext => "select_context",
            ActionRequest::SampleBudget => "sample_budget",
            ActionRequest::ObserveControl => "observe_control",
            ActionRequest::AdmitSteers { .. } => "admit_steers",
            ActionRequest::CallProvider { .. } => "call_provider",
            ActionRequest::DispatchTools { .. } => "dispatch_tools",
            ActionRequest::RunVerify { .. } => "run_verify",
            ActionRequest::Checkpoint { .. } => "checkpoint",
            ActionRequest::Notice { .. } => "notice",
            ActionRequest::Continue { .. } => "continue",
            ActionRequest::AdvanceTurn { .. } => "advance_turn",
            ActionRequest::Finish { .. } => "finish",
        }
    }

    /// Does this request cross the effect boundary when the driver routes it?
    ///
    /// The three that do are the three the universal broker (#16) already covers. Stating it here
    /// keeps the driver from having to decide, and lets a test assert that the reducer never asks
    /// for an effect after it has declared the run finished.
    pub const fn is_effecting(&self) -> bool {
        matches!(
            self,
            ActionRequest::CallProvider { .. }
                | ActionRequest::DispatchTools { .. }
                | ActionRequest::RunVerify { .. }
                | ActionRequest::Checkpoint { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_request_serialises_to_a_distinct_tagged_form() {
        let actions = [
            ActionRequest::SelectContext,
            ActionRequest::SampleBudget,
            ActionRequest::ObserveControl,
            ActionRequest::AdmitSteers { turn: 3 },
            ActionRequest::CallProvider { turn: 3 },
            ActionRequest::DispatchTools { turn: 3, calls: 2 },
            ActionRequest::RunVerify {
                turn: 3,
                attempt: 1,
            },
            ActionRequest::Checkpoint { turn: 3 },
            ActionRequest::Notice {
                text: NoticeKind::VerifyPassed,
            },
            ActionRequest::Continue {
                turn: 3,
                reason: ContinueReason::MaxTokens,
            },
            ActionRequest::AdvanceTurn { turn: 3 },
            ActionRequest::Finish {
                outcome: Outcome::Done,
            },
        ];
        let mut wires = std::collections::BTreeSet::new();
        for action in &actions {
            let wire = serde_json::to_string(action).expect("action serialises");
            assert!(
                wire.contains(action.label()),
                "{} must carry its own tag on the wire: {wire}",
                action.label()
            );
            assert!(
                wires.insert(wire.clone()),
                "two distinct actions serialised identically, so the replay comparison could not \
                 tell them apart: {wire}"
            );
        }
        assert_eq!(wires.len(), actions.len());
    }

    #[test]
    fn exactly_the_four_boundary_crossing_requests_are_effecting() {
        assert!(ActionRequest::CallProvider { turn: 0 }.is_effecting());
        assert!(ActionRequest::DispatchTools { turn: 0, calls: 1 }.is_effecting());
        assert!(
            ActionRequest::RunVerify {
                turn: 0,
                attempt: 0
            }
            .is_effecting()
        );
        assert!(ActionRequest::Checkpoint { turn: 0 }.is_effecting());
        assert!(!ActionRequest::SelectContext.is_effecting());
        assert!(!ActionRequest::SampleBudget.is_effecting());
        assert!(!ActionRequest::ObserveControl.is_effecting());
        assert!(!ActionRequest::AdvanceTurn { turn: 0 }.is_effecting());
        assert!(
            !ActionRequest::Finish {
                outcome: Outcome::Done
            }
            .is_effecting()
        );
    }
}

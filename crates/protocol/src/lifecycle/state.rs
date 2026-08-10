//! Closed lifecycle states and legal transitions.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycleState {
    Created,
    Configured,
    Idle,
    Running,
    Cancelling,
    Draining,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLifecycleState {
    Created,
    Admitted,
    Active,
    Cancelling,
    Completed,
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionLifecycleState {
    Created,
    Enqueued,
    Received,
    Admitted,
    Applied,
    Requeued,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnLifecycleState {
    Received,
    Admitted,
    Running,
    Cancelling,
    Completed,
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoopState {
    PreparingContext,
    AwaitingModel,
    StreamingModel,
    AwaitingTool,
    ApplyingSteer,
    Verifying,
    Settling,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectLifecycleState {
    Proposed,
    Admitted,
    Executing,
    Done,
    Failed,
    Unknown,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycleState {
    SpawnRequested,
    Spawned,
    Running,
    TermSent,
    KillSent,
    Reaped,
    ReapFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLifecycleState {
    Created,
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
    CleanupUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLifecycleState {
    Planning,
    Running,
    Reducing,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubagentLifecycleState {
    Proposed,
    Admitted,
    Running,
    Cancelling,
    Completed,
    Interrupted,
    Failed,
}

/// Controls are independent intents. Cancelling a turn does not clean background jobs, and
/// draining a session does not imply a Git checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlIntent {
    CancelTurn,
    ForceCancelTurn,
    DrainSession,
    CleanBackground,
    Quit,
}

pub trait LifecycleState: Copy + fmt::Debug + PartialEq {
    fn can_transition_to(self, next: Self) -> bool;
    fn is_terminal(self) -> bool;

    fn transition(self, next: Self) -> Result<Self, TransitionError> {
        self.can_transition_to(next)
            .then_some(next)
            .ok_or(TransitionError)
    }
}

impl LifecycleState for SessionLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use SessionLifecycleState::*;
        matches!(
            (self, next),
            (Created, Configured)
                | (Configured, Idle)
                | (Idle, Running | Stopping)
                | (Running, Idle | Cancelling | Draining | Failed)
                | (Cancelling, Idle | Draining | Failed)
                | (Draining, Idle | Stopping | Failed)
                | (Stopping, Stopped | Failed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

impl LifecycleState for RunLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use RunLifecycleState::*;
        matches!(
            (self, next),
            (Created, Admitted | Failed)
                | (Admitted, Active | Cancelling | Failed)
                | (Active, Cancelling | Completed | Interrupted | Failed)
                | (Cancelling, Interrupted | Failed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Interrupted | Self::Failed)
    }
}

impl LifecycleState for SubmissionLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use SubmissionLifecycleState::*;
        matches!(
            (self, next),
            (Created, Enqueued | Rejected)
                | (Enqueued, Received | Rejected | Expired)
                | (Received, Admitted | Requeued | Rejected | Expired)
                | (Admitted, Applied | Requeued | Rejected)
                | (Requeued, Enqueued | Rejected | Expired)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected | Self::Expired)
    }
}

impl LifecycleState for TurnLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use TurnLifecycleState::*;
        matches!(
            (self, next),
            (Received, Admitted | Failed)
                | (Admitted, Running | Cancelling | Failed)
                | (Running, Cancelling | Completed | Interrupted | Failed)
                | (Cancelling, Interrupted | Failed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Interrupted | Self::Failed)
    }
}

impl LifecycleState for AgentLoopState {
    fn can_transition_to(self, next: Self) -> bool {
        use AgentLoopState::*;
        matches!(
            (self, next),
            (PreparingContext, AwaitingModel | Settling | Terminal)
                | (AwaitingModel, StreamingModel | Settling | Terminal)
                | (
                    StreamingModel,
                    AwaitingTool | ApplyingSteer | Verifying | Settling | Terminal
                )
                | (
                    AwaitingTool,
                    PreparingContext | ApplyingSteer | Settling | Terminal
                )
                | (ApplyingSteer, PreparingContext | Settling | Terminal)
                | (Verifying, PreparingContext | Settling | Terminal)
                | (Settling, Terminal)
        )
    }

    fn is_terminal(self) -> bool {
        self == Self::Terminal
    }
}

impl LifecycleState for EffectLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use EffectLifecycleState::*;
        matches!(
            (self, next),
            (Proposed, Admitted | Failed | Cancelled)
                | (Admitted, Executing | Failed | Cancelled)
                | (Executing, Done | Failed | Unknown | Cancelled)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Failed | Self::Unknown | Self::Cancelled
        )
    }
}

impl LifecycleState for ProcessLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use ProcessLifecycleState::*;
        matches!(
            (self, next),
            (SpawnRequested, Spawned | ReapFailed)
                | (Spawned, Running | TermSent | KillSent | Reaped | ReapFailed)
                | (Running, TermSent | KillSent | Reaped | ReapFailed)
                | (TermSent, KillSent | Reaped | ReapFailed)
                | (KillSent, Reaped | ReapFailed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Reaped | Self::ReapFailed)
    }
}

impl LifecycleState for JobLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use JobLifecycleState::*;
        matches!(
            (self, next),
            (Created, Starting | Failed)
                | (Starting, Running | Failed | CleanupUnknown)
                | (Running, Stopping | Exited | Failed | CleanupUnknown)
                | (Stopping, Exited | Failed | CleanupUnknown)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Exited | Self::Failed | Self::CleanupUnknown)
    }
}

impl LifecycleState for WorkflowLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use WorkflowLifecycleState::*;
        matches!(
            (self, next),
            (Planning, Running | Cancelled | Failed)
                | (Running, Reducing | Cancelled | Failed)
                | (Reducing, Completed | Cancelled | Failed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

impl LifecycleState for SubagentLifecycleState {
    fn can_transition_to(self, next: Self) -> bool {
        use SubagentLifecycleState::*;
        matches!(
            (self, next),
            (Proposed, Admitted | Failed)
                | (Admitted, Running | Cancelling | Failed)
                | (Running, Cancelling | Completed | Interrupted | Failed)
                | (Cancelling, Interrupted | Failed)
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Interrupted | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError;

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("illegal lifecycle transition")
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_cannot_publish_a_second_terminal() {
        assert!(
            TurnLifecycleState::Running
                .transition(TurnLifecycleState::Completed)
                .is_ok()
        );
        assert!(
            TurnLifecycleState::Completed
                .transition(TurnLifecycleState::Failed)
                .is_err()
        );
        assert!(
            EffectLifecycleState::Done
                .transition(EffectLifecycleState::Unknown)
                .is_err()
        );
        assert!(
            WorkflowLifecycleState::Completed
                .transition(WorkflowLifecycleState::Cancelled)
                .is_err()
        );
        assert!(
            RunLifecycleState::Completed
                .transition(RunLifecycleState::Failed)
                .is_err()
        );
        assert!(
            ProcessLifecycleState::Reaped
                .transition(ProcessLifecycleState::ReapFailed)
                .is_err()
        );
        assert!(
            SubagentLifecycleState::Interrupted
                .transition(SubagentLifecycleState::Completed)
                .is_err()
        );
    }

    #[test]
    fn controls_are_distinct_protocol_intents() {
        let all = [
            ControlIntent::CancelTurn,
            ControlIntent::ForceCancelTurn,
            ControlIntent::DrainSession,
            ControlIntent::CleanBackground,
            ControlIntent::Quit,
        ];
        assert_eq!(
            all.into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            5
        );
    }
}

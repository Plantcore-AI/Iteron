//! Per-physical-turn agent-loop ownership.
//!
//! Session and Turn lifecycles live in the App Server. This smaller owner proves that the inner
//! model/context/tool loop also follows the closed protocol state graph, including early `?`,
//! interrupt and refusal exits. It intentionally emits no second event stream: existing owner
//! events remain the sole observability authority.

use super::KernelError;
use core_protocol::{AgentLoopState, LifecycleState, TurnId};

pub(super) struct AgentLoopGuard {
    turn: TurnId,
    state: AgentLoopState,
}

impl AgentLoopGuard {
    pub(super) fn begin(turn: TurnId) -> Self {
        Self {
            turn,
            state: AgentLoopState::PreparingContext,
        }
    }

    pub(super) fn transition(&mut self, next: AgentLoopState) -> Result<(), KernelError> {
        self.state = self.state.transition(next).map_err(|_| {
            KernelError::ContextResolution(format!(
                "agent loop turn {} attempted an illegal {:?} -> {:?} transition",
                self.turn.0, self.state, next
            ))
        })?;
        Ok(())
    }

    fn terminalize(&mut self) {
        if self.state.is_terminal() {
            return;
        }
        if self.state != AgentLoopState::Settling
            && let Ok(settling) = self.state.transition(AgentLoopState::Settling)
        {
            self.state = settling;
        }
        if let Ok(terminal) = self.state.transition(AgentLoopState::Terminal) {
            self.state = terminal;
        }
        debug_assert!(
            self.state.is_terminal(),
            "every agent-loop exit must settle a terminal state"
        );
    }
}

impl Drop for AgentLoopGuard {
    fn drop(&mut self) {
        self.terminalize();
    }
}

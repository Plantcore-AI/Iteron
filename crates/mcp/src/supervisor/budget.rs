use crate::McpError;
use std::time::Duration;
use tokio::time::Instant;

/// One absolute deadline shared by every phase and reconnect of a public MCP operation.
#[derive(Clone, Copy)]
pub(super) struct OperationBudget {
    deadline: Instant,
}

impl OperationBudget {
    pub(super) fn start(duration: Duration) -> Result<Self, McpError> {
        let deadline =
            Instant::now()
                .checked_add(duration)
                .ok_or(McpError::InvalidLaunchConfiguration {
                    field: "operation_deadline",
                    limit: super::MAX_MCP_OPERATION_DEADLINE_MS as usize,
                })?;
        Ok(Self { deadline })
    }

    pub(super) fn deadline(self) -> Instant {
        self.deadline
    }

    pub(super) fn remaining(self) -> Result<Duration, McpError> {
        let now = Instant::now();
        if now >= self.deadline {
            Err(operation_deadline())
        } else {
            Ok(self.deadline - now)
        }
    }

    pub(super) fn clamp(self, phase: Duration) -> Result<Duration, McpError> {
        Ok(phase.min(self.remaining()?))
    }

    /// Derive a nested budget without ever extending the owning public operation.
    pub(super) fn nested(self, maximum: Duration) -> Result<Self, McpError> {
        let nested =
            Instant::now()
                .checked_add(maximum)
                .ok_or(McpError::InvalidLaunchConfiguration {
                    field: "nested_operation_deadline",
                    limit: super::MAX_MCP_OPERATION_DEADLINE_MS as usize,
                })?;
        Ok(Self {
            deadline: self.deadline.min(nested),
        })
    }

    pub(super) fn is_exhausted(self) -> bool {
        Instant::now() >= self.deadline
    }
}

pub(super) fn operation_deadline() -> McpError {
    McpError::Deadline {
        operation: "managed MCP operation".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn one_absolute_budget_clamps_every_phase() {
        let budget = OperationBudget::start(Duration::from_secs(3)).unwrap();
        assert_eq!(
            budget.clamp(Duration::from_secs(60)).unwrap(),
            Duration::from_secs(3)
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            budget.clamp(Duration::from_secs(60)).unwrap(),
            Duration::from_secs(1)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(budget.remaining().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn nested_budget_never_extends_parent() {
        let parent = OperationBudget::start(Duration::from_secs(3)).unwrap();
        assert!(
            parent
                .nested(Duration::from_secs(60))
                .unwrap()
                .remaining()
                .unwrap()
                <= Duration::from_secs(3)
        );
        assert!(
            parent
                .nested(Duration::from_secs(1))
                .unwrap()
                .remaining()
                .unwrap()
                <= Duration::from_secs(1)
        );
    }
}

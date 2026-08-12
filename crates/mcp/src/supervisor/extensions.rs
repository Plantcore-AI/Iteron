use super::{McpCancellation, McpSupervisor, OperationBudget, operation_deadline};
use crate::{McpError, McpToolCallEvidence, McpToolOutcome, reconnect::LifecycleFailure};
use serde_json::Value;
use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

impl McpSupervisor {
    /// Invoke a standard resource/prompt method through the same lazy, reconnect-bounded,
    /// cancellation-aware generation owner as tools. A transport loss after dispatch is returned
    /// as `Unknown`; it is never replayed merely because reconnect is possible.
    pub async fn call_extension_observed<F>(
        &mut self,
        method: &'static str,
        params: Value,
        cancellation: &McpCancellation,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        if !matches!(
            method,
            "resources/list" | "resources/read" | "prompts/list" | "prompts/get"
        ) {
            return definite(McpError::Protocol(
                "unsupported MCP extension method".into(),
            ));
        }
        if cancellation.is_cancelled() {
            return definite(McpError::Cancelled {
                operation: "MCP extension",
            });
        }
        let budget = match OperationBudget::start(self.timeouts.tool_operation()) {
            Ok(budget) => budget,
            Err(error) => return definite(error),
        };
        let startup_budget = match budget.nested(self.timeouts.startup_operation()) {
            Ok(startup_budget) => startup_budget,
            Err(error) => return definite(error),
        };
        let generation = match self.ensure_ready(cancellation, startup_budget).await {
            Ok(generation) => generation,
            Err(error) => return definite(error),
        };
        let Some(mut client) = self.client.take() else {
            self.lifecycle.stop();
            return definite(McpError::InvalidLifecycleTransition {
                state: self.lifecycle.status().phase.label(),
                event: "extension_without_client",
            });
        };

        let dispatched_at = Arc::new(Mutex::new(None));
        let observed = dispatched_at.clone();
        enum ResultState {
            Completed(McpToolOutcome),
            Cancelled,
            TimedOut,
        }
        let state = {
            let call = client.call_extension_outcome_observed(method, params, move || {
                *observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(std::time::Instant::now());
                on_dispatch();
            });
            tokio::pin!(call);
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => ResultState::Cancelled,
                _ = tokio::time::sleep_until(budget.deadline()) => ResultState::TimedOut,
                outcome = &mut call => ResultState::Completed(outcome),
            }
        };

        match state {
            ResultState::Cancelled => {
                let dispatched_at = *dispatched_at
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                client.terminate().await;
                if self.lifecycle.cancel(generation).is_err() {
                    self.lifecycle.stop();
                }
                self.ready_since = None;
                self.healthy_calls = 0;
                match dispatched_at {
                    Some(started) => McpToolOutcome::Unknown {
                        error: McpError::Cancelled {
                            operation: "dispatched MCP extension",
                        },
                        evidence: evidence(self.server_name(), method, started.elapsed()),
                    },
                    None => definite(McpError::Cancelled {
                        operation: "MCP extension",
                    }),
                }
            }
            ResultState::TimedOut => {
                let dispatched_at = *dispatched_at
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match dispatched_at {
                    Some(started) => {
                        client.terminate().await;
                        if self
                            .record_failure(generation, LifecycleFailure::Deadline)
                            .is_err()
                        {
                            self.lifecycle.stop();
                        }
                        McpToolOutcome::Unknown {
                            error: operation_deadline(),
                            evidence: evidence(self.server_name(), method, started.elapsed()),
                        }
                    }
                    None => {
                        self.client = Some(client);
                        definite(operation_deadline())
                    }
                }
            }
            ResultState::Completed(outcome @ McpToolOutcome::Unknown { .. }) => {
                client.terminate().await;
                if self
                    .record_failure(generation, LifecycleFailure::Transport)
                    .is_err()
                {
                    self.lifecycle.stop();
                }
                outcome
            }
            ResultState::Completed(outcome) => {
                self.client = Some(client);
                if matches!(outcome, McpToolOutcome::Completed { .. }) {
                    self.note_healthy_call(generation);
                }
                outcome
            }
        }
    }
}

fn evidence(server: &str, method: &str, elapsed: std::time::Duration) -> McpToolCallEvidence {
    let milliseconds = elapsed.as_nanos().saturating_add(999_999) / 1_000_000;
    McpToolCallEvidence::new(
        server,
        method,
        NonZeroU64::new(u64::try_from(milliseconds).unwrap_or(u64::MAX).max(1))
            .expect("milliseconds were clamped to one"),
    )
}

fn definite(error: McpError) -> McpToolOutcome {
    McpToolOutcome::FailedDefinite {
        error,
        evidence: None,
    }
}

use super::{
    ManagedCatalog, McpCancellation, McpSupervisor, OperationBudget, classify_failure,
    operation_deadline,
};
use crate::{
    McpClient, McpError,
    reconnect::{LifecycleFailure, LifecyclePhase, ServerGeneration},
};
use std::time::Duration;
use tokio::time::Instant;

const POST_DISCOVERY_LIVENESS_SETTLE_MS: u64 = 10;

impl McpSupervisor {
    pub(super) async fn ensure_ready(
        &mut self,
        cancellation: &McpCancellation,
        budget: OperationBudget,
    ) -> Result<ServerGeneration, McpError> {
        loop {
            budget.remaining()?;
            let status = self.lifecycle.status();
            match status.phase {
                LifecyclePhase::Ready => {
                    let generation =
                        status
                            .generation
                            .ok_or(McpError::InvalidLifecycleTransition {
                                state: "ready",
                                event: "missing_generation",
                            })?;
                    if self.reconcile_ready_liveness()? {
                        return Ok(generation);
                    }
                    continue;
                }
                LifecyclePhase::Backoff => self.wait_for_retry(cancellation, budget).await?,
                LifecyclePhase::Exhausted => {
                    return Err(McpError::RetryExhausted {
                        attempts: status.reconnect_attempts,
                    });
                }
                LifecyclePhase::Failed => return Err(McpError::LifecycleFailed),
                LifecyclePhase::Stopped => return Err(McpError::LifecycleStopped),
                LifecyclePhase::Deferred | LifecyclePhase::Cancelled => {}
                phase => {
                    return Err(McpError::InvalidLifecycleTransition {
                        state: phase.label(),
                        event: "ensure_ready",
                    });
                }
            }
            if cancellation.is_cancelled() {
                return Err(McpError::Cancelled {
                    operation: "lazy MCP startup",
                });
            }
            let generation = self.lifecycle.begin_connection()?;
            let handshake_timeout = budget.clamp(self.timeouts.handshake())?;
            let connected = McpClient::connect_managed(
                self.launch.command(),
                self.launch.args(),
                self.launch.server_name(),
                handshake_timeout,
                self.timeouts.request(),
                self.launch.sensitive_env_names(),
                cancellation,
            )
            .await;
            let mut client = match connected {
                Ok(client) => client,
                Err(error @ McpError::Cancelled { .. }) => {
                    if self.lifecycle.cancel(generation).is_err() {
                        self.lifecycle.stop();
                    }
                    return Err(error);
                }
                Err(error) => {
                    let failure = classify_failure(&error);
                    self.record_failure(generation, failure)?;
                    if budget.is_exhausted() {
                        return Err(operation_deadline());
                    }
                    if self.lifecycle.status().phase != LifecyclePhase::Backoff {
                        return Err(error);
                    }
                    continue;
                }
            };
            client.set_result_policy(self.result_policy);
            if budget.is_exhausted() {
                client.terminate().await;
                self.record_failure(generation, LifecycleFailure::Deadline)?;
                return Err(operation_deadline());
            }
            if let Err(error) = self.lifecycle.connected(generation) {
                client.terminate().await;
                self.lifecycle.stop();
                return Err(error);
            }

            enum DiscoveryResult {
                Completed(Result<Vec<iteron_protocol::ToolSpec>, McpError>),
                TimedOut,
                OperationTimedOut,
                Cancelled,
            }
            let discovery = {
                let list =
                    client.list_tools_governed(&self.filter, &self.policy, self.host_ceiling);
                tokio::pin!(list);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => DiscoveryResult::Cancelled,
                    _ = tokio::time::sleep_until(budget.deadline()) => DiscoveryResult::OperationTimedOut,
                    result = tokio::time::timeout(self.timeouts.discovery(), &mut list) => {
                        match result {
                            Ok(result) => DiscoveryResult::Completed(result),
                            Err(_) => DiscoveryResult::TimedOut,
                        }
                    }
                }
            };
            let specs = match discovery {
                DiscoveryResult::Completed(Ok(specs)) => specs,
                DiscoveryResult::Completed(Err(error)) => {
                    client.terminate().await;
                    let failure = classify_failure(&error);
                    self.record_failure(generation, failure)?;
                    if budget.is_exhausted() {
                        return Err(operation_deadline());
                    }
                    if self.lifecycle.status().phase != LifecyclePhase::Backoff {
                        return Err(error);
                    }
                    continue;
                }
                DiscoveryResult::TimedOut => {
                    client.terminate().await;
                    let error = McpError::Deadline {
                        operation: "tool discovery".into(),
                    };
                    self.record_failure(generation, LifecycleFailure::Deadline)?;
                    if self.lifecycle.status().phase != LifecyclePhase::Backoff {
                        return Err(error);
                    }
                    continue;
                }
                DiscoveryResult::OperationTimedOut => {
                    client.terminate().await;
                    self.record_failure(generation, LifecycleFailure::Deadline)?;
                    return Err(operation_deadline());
                }
                DiscoveryResult::Cancelled => {
                    client.terminate().await;
                    if self.lifecycle.cancel(generation).is_err() {
                        self.lifecycle.stop();
                    }
                    return Err(McpError::Cancelled {
                        operation: "tool discovery",
                    });
                }
            };
            let protocol_version = client.negotiated_protocol_version().to_owned();
            let catalog = match ManagedCatalog::admit(
                self.server_name(),
                self.identity.binding().clone(),
                &protocol_version,
                specs,
            ) {
                Ok(catalog) => catalog,
                Err(error) => {
                    client.terminate().await;
                    self.record_failure(generation, LifecycleFailure::Catalog)?;
                    return Err(error);
                }
            };
            if let Err(error) = self.lifecycle.discovered(generation, catalog.len()) {
                client.terminate().await;
                self.lifecycle.stop();
                return Err(error);
            }
            self.client = Some(client);
            self.catalog = catalog;
            self.retry_not_before = None;
            self.ready_since = Some(Instant::now());
            self.healthy_calls = 0;
            // Require a short post-discovery stability observation before publishing Ready. This
            // catches a server that flushes tools/list and immediately exits; the wait is charged
            // to the one aggregate operation budget and remains cancellation-aware.
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(McpError::Cancelled { operation: "post-discovery liveness" });
                }
                _ = tokio::time::sleep_until(budget.deadline()) => {
                    if let Some(mut client) = self.client.take() {
                        client.terminate().await;
                    }
                    self.record_failure(generation, LifecycleFailure::Deadline)?;
                    return Err(operation_deadline());
                }
                _ = tokio::time::sleep(Duration::from_millis(POST_DISCOVERY_LIVENESS_SETTLE_MS)) => {}
            }
            if self.reconcile_ready_liveness()? {
                return Ok(generation);
            }
        }
    }

    async fn wait_for_retry(
        &mut self,
        cancellation: &McpCancellation,
        budget: OperationBudget,
    ) -> Result<(), McpError> {
        let deadline = self.retry_not_before.unwrap_or_else(Instant::now);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(McpError::Cancelled { operation: "reconnect backoff" }),
            _ = tokio::time::sleep_until(budget.deadline()) => Err(operation_deadline()),
            _ = tokio::time::sleep_until(deadline) => {
                self.retry_not_before = None;
                Ok(())
            }
        }
    }

    /// Return true only when the current Ready generation still owns a live direct child. A
    /// naturally exited child is group-cleaned and reaped before the lifecycle leaves Ready.
    pub(super) fn reconcile_ready_liveness(&mut self) -> Result<bool, McpError> {
        let status = self.lifecycle.status();
        if status.phase != LifecyclePhase::Ready {
            return Ok(false);
        }
        let generation = status
            .generation
            .ok_or(McpError::InvalidLifecycleTransition {
                state: "ready",
                event: "reconcile_missing_generation",
            })?;
        let liveness = match self.client.as_mut() {
            Some(client) => client.reconcile_liveness(),
            None => Ok(false),
        };
        match liveness {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => {
                if let Some(mut client) = self.client.take() {
                    // The process token was quarantined by the failed observer. Clean only the
                    // direct handle, stop the lifecycle, and never retry from uncertain ownership.
                    client.terminate_sync();
                }
                self.lifecycle.stop();
                return Err(error);
            }
        }
        if let Some(mut client) = self.client.take() {
            // The dead-path observer spent process-group authority before reaping.
            client.terminate_sync();
        }
        self.record_failure(generation, LifecycleFailure::Transport)?;
        Ok(false)
    }

    pub(super) fn record_failure(
        &mut self,
        generation: ServerGeneration,
        failure: LifecycleFailure,
    ) -> Result<(), McpError> {
        let delay = self.lifecycle.failed(generation, failure)?;
        self.retry_not_before = delay.map(|delay| Instant::now() + Duration::from_millis(delay));
        self.ready_since = None;
        self.healthy_calls = 0;
        Ok(())
    }
}

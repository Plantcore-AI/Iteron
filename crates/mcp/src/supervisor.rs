//! Lazy, generation-fenced supervision for the existing stdio MCP client.
//!
//! Construction validates and retains configuration but does not spawn. The first bounded tool
//! search or exact-identity call connects and discovers. Read-only connection/discovery failures
//! may follow the finite reconnect schedule; an effecting tool call is never replayed after an
//! unknown terminal. Every process owned on a failure or cancellation path is terminated and
//! reaped before the method returns.

mod budget;
mod catalog;
mod config;
mod extensions;
mod identity;
mod ready;

pub use catalog::{
    MAX_MCP_SEARCH_DESCRIPTION_BYTES, MAX_MCP_SEARCH_OUTPUT_BYTES, MAX_MCP_SEARCH_QUERY_BYTES,
    MAX_MCP_SEARCH_RESULTS, ManagedCatalog, McpToolIdentity, McpToolMatch, McpToolSearchResult,
};
pub use config::{
    DEFAULT_MCP_OPERATION_DEADLINE_MS, MAX_MCP_COMMAND_BYTES, MAX_MCP_DEADLINE_MS,
    MAX_MCP_ENV_NAME_BYTES, MAX_MCP_LAUNCH_ARG_BYTES, MAX_MCP_LAUNCH_ARGS, MAX_MCP_LAUNCH_BYTES,
    MAX_MCP_OPERATION_DEADLINE_MS, MAX_MCP_SENSITIVE_ENV_NAMES, McpCancellation, McpLaunchConfig,
    McpTimeouts,
};
pub use identity::McpServerIdentity;

use crate::{
    McpClient, McpError, McpResultPolicy, McpServerPolicy, McpToolOutcome,
    reconnect::{
        LifecycleCore, LifecycleFailure, LifecyclePhase, LifecycleStatus, ReconnectPolicy,
        ServerGeneration,
    },
    tool_filter::McpToolFilter,
};
use budget::{OperationBudget, operation_deadline};
use iteron_protocol::capability_set::CapabilitySet;
use serde_json::Value;
use std::{num::NonZeroU64, time::Duration};
use tokio::time::Instant;

pub const HEALTHY_RETRY_RESET_AFTER_MS: u64 = 30_000;
pub const HEALTHY_RETRY_RESET_AFTER_CALLS: u32 = 3;

/// One actor-owned server. `&mut self` methods make connection/discovery/call ordering explicit;
/// runtimes that need concurrency should put this value behind one bounded mailbox.
pub struct McpSupervisor {
    launch: McpLaunchConfig,
    timeouts: McpTimeouts,
    filter: McpToolFilter,
    policy: McpServerPolicy,
    host_ceiling: CapabilitySet,
    result_policy: McpResultPolicy,
    identity: McpServerIdentity,
    lifecycle: LifecycleCore,
    client: Option<McpClient>,
    catalog: ManagedCatalog,
    retry_not_before: Option<Instant>,
    ready_since: Option<Instant>,
    healthy_calls: u32,
}

impl McpSupervisor {
    /// Configure a server without spawning, handshaking, or discovering it.
    pub fn deferred(
        launch: McpLaunchConfig,
        filter: McpToolFilter,
        reconnect: ReconnectPolicy,
        timeouts: McpTimeouts,
    ) -> Result<Self, McpError> {
        Self::deferred_governed(
            launch,
            filter,
            McpServerPolicy::default(),
            crate::default_host_ceiling(),
            reconnect,
            timeouts,
            McpResultPolicy::default(),
        )
    }

    /// Configure one lazy server under the exact authority and output policies compiled by the
    /// session composition root. These values are immutable for the supervisor lineage: a
    /// reconnect can replace transport state, but cannot silently widen the tool catalog or
    /// rediscover a result cap from a process-global default.
    #[allow(clippy::too_many_arguments)]
    pub fn deferred_governed(
        launch: McpLaunchConfig,
        filter: McpToolFilter,
        policy: McpServerPolicy,
        host_ceiling: CapabilitySet,
        reconnect: ReconnectPolicy,
        timeouts: McpTimeouts,
        result_policy: McpResultPolicy,
    ) -> Result<Self, McpError> {
        filter.validate()?;
        policy.validate()?;
        let identity =
            McpServerIdentity::new(launch.server_name().to_owned(), launch.binding(), &filter)?;
        Ok(Self {
            launch,
            timeouts,
            filter,
            policy,
            host_ceiling,
            result_policy,
            identity,
            lifecycle: LifecycleCore::deferred(reconnect),
            client: None,
            catalog: ManagedCatalog::default(),
            retry_not_before: None,
            ready_since: None,
            healthy_calls: 0,
        })
    }

    pub fn server_name(&self) -> &str {
        self.identity.name()
    }

    pub fn server_identity(&self) -> &McpServerIdentity {
        &self.identity
    }

    /// Protocol revision selected by the live generation's completed initialize handshake.
    /// Absence means no usable connected generation; callers must not substitute the requested
    /// client revision because that would turn negotiation into a guess.
    pub fn negotiated_protocol_version(&self) -> Option<&str> {
        self.client
            .as_ref()
            .map(McpClient::negotiated_protocol_version)
    }

    /// Reconcile direct-child liveness before reporting operator-visible status. This method may
    /// synchronously reap a server already known to have exited, but never waits for a live child.
    pub fn status(&mut self) -> LifecycleStatus {
        if self.reconcile_ready_liveness().is_err() {
            self.lifecycle.stop();
        }
        let mut status = self.lifecycle.status();
        if status.phase == LifecyclePhase::Backoff
            && let Some(not_before) = self.retry_not_before
        {
            status.retry_after_ms = Some(duration_ms_ceil(
                not_before.saturating_duration_since(Instant::now()),
            ));
        }
        status
    }

    /// Search a bounded summary catalog. Invalid search input is rejected before lazy startup.
    pub async fn search_tools(
        &mut self,
        query: &str,
        limit: usize,
        cancellation: &McpCancellation,
    ) -> Result<McpToolSearchResult, McpError> {
        catalog::validate_search_request(query, limit)?;
        if cancellation.is_cancelled() {
            return Err(McpError::Cancelled {
                operation: "tool search",
            });
        }
        let budget = OperationBudget::start(self.timeouts.startup_operation())?;
        let generation = self.ensure_ready(cancellation, budget).await?;
        let result = self.catalog.search(generation, query, limit)?;
        budget.remaining()?;
        Ok(result)
    }

    /// Dispatch only an exact tool-contract identity returned by search. Within this supervisor
    /// lineage, an unchanged identity can retain an external permission decision across reconnect;
    /// a fresh supervisor or changed schema/risk/binding cannot.
    pub async fn call_tool(
        &mut self,
        identity: &McpToolIdentity,
        arguments: Value,
        cancellation: &McpCancellation,
    ) -> McpToolOutcome {
        self.call_tool_observed(identity, arguments, cancellation, || {})
            .await
    }

    /// Call a searched tool and expose the exact conservative pipe-dispatch boundary to the
    /// composition root. The observer runs at most once and never for a local validation,
    /// cancellation, stale-identity, or pre-dispatch deadline failure.
    pub async fn call_tool_observed<F>(
        &mut self,
        identity: &McpToolIdentity,
        arguments: Value,
        cancellation: &McpCancellation,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        if cancellation.is_cancelled() {
            return McpToolOutcome::FailedDefinite {
                error: McpError::Cancelled {
                    operation: "tool call",
                },
                evidence: None,
            };
        }
        if !identity.belongs_to(self.server_name(), self.identity.binding()) {
            return McpToolOutcome::FailedDefinite {
                error: McpError::StaleToolIdentity,
                evidence: None,
            };
        }
        let budget = match OperationBudget::start(self.timeouts.tool_operation()) {
            Ok(budget) => budget,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: None,
                };
            }
        };
        let startup_budget = match budget.nested(self.timeouts.startup_operation()) {
            Ok(startup_budget) => startup_budget,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: None,
                };
            }
        };
        let generation = match self.ensure_ready(cancellation, startup_budget).await {
            Ok(generation) => generation,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: None,
                };
            }
        };
        let Some(spec) = self.catalog.spec(identity) else {
            return McpToolOutcome::FailedDefinite {
                error: McpError::StaleToolIdentity,
                evidence: None,
            };
        };
        let bare_name = identity.bare_name().to_owned();
        debug_assert_eq!(spec.name, format!("{}__{bare_name}", self.server_name()));
        let Some(mut client) = self.client.take() else {
            self.lifecycle.stop();
            return McpToolOutcome::FailedDefinite {
                error: McpError::InvalidLifecycleTransition {
                    state: self.lifecycle.status().phase.label(),
                    event: "call_without_client",
                },
                evidence: None,
            };
        };

        let dispatch_started = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observed = dispatch_started.clone();
        enum CallResult {
            Completed(McpToolOutcome),
            Cancelled,
            OperationTimedOut,
        }
        let result = {
            let call = client.call_tool_outcome_observed(&bare_name, arguments, move || {
                *observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(std::time::Instant::now());
                on_dispatch();
            });
            tokio::pin!(call);
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => CallResult::Cancelled,
                _ = tokio::time::sleep_until(budget.deadline()) => CallResult::OperationTimedOut,
                outcome = &mut call => CallResult::Completed(outcome),
            }
        };

        match result {
            CallResult::Cancelled => {
                let dispatched_at = *dispatch_started
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                client.terminate().await;
                if self.lifecycle.cancel(generation).is_err() {
                    self.lifecycle.stop();
                }
                self.ready_since = None;
                self.healthy_calls = 0;
                if let Some(dispatched_at) = dispatched_at {
                    McpToolOutcome::Unknown {
                        error: McpError::Cancelled {
                            operation: "dispatched tool call",
                        },
                        evidence: crate::McpToolCallEvidence::new(
                            self.server_name(),
                            &bare_name,
                            NonZeroU64::new(duration_ms_ceil(dispatched_at.elapsed()).max(1))
                                .expect("a value clamped to one is non-zero"),
                        ),
                    }
                } else {
                    McpToolOutcome::FailedDefinite {
                        error: McpError::Cancelled {
                            operation: "tool call",
                        },
                        evidence: None,
                    }
                }
            }
            CallResult::OperationTimedOut => {
                let dispatched_at = *dispatch_started
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(dispatched_at) = dispatched_at {
                    client.terminate().await;
                    if self
                        .record_failure(generation, LifecycleFailure::Deadline)
                        .is_err()
                    {
                        self.lifecycle.stop();
                    }
                    McpToolOutcome::Unknown {
                        error: operation_deadline(),
                        evidence: crate::McpToolCallEvidence::new(
                            self.server_name(),
                            &bare_name,
                            NonZeroU64::new(duration_ms_ceil(dispatched_at.elapsed()).max(1))
                                .expect("a value clamped to one is non-zero"),
                        ),
                    }
                } else {
                    // The dispatch observer runs before the first fallible write. Dropping the
                    // undispatched call future therefore leaves this connection reusable.
                    self.client = Some(client);
                    McpToolOutcome::FailedDefinite {
                        error: operation_deadline(),
                        evidence: None,
                    }
                }
            }
            CallResult::Completed(outcome @ McpToolOutcome::Unknown { .. }) => {
                let failure = match &outcome {
                    McpToolOutcome::Unknown { error, .. } => classify_failure(error),
                    _ => unreachable!(),
                };
                client.terminate().await;
                if self.record_failure(generation, failure).is_err() {
                    self.lifecycle.stop();
                }
                outcome
            }
            CallResult::Completed(outcome) => {
                self.client = Some(client);
                if matches!(outcome, McpToolOutcome::Completed { .. }) {
                    self.note_healthy_call(generation);
                }
                outcome
            }
        }
    }

    /// Stop and synchronously perform the bounded process-group termination/reap path.
    pub async fn stop(&mut self) {
        if let Some(mut client) = self.client.take() {
            client.terminate().await;
        }
        self.lifecycle.stop();
        self.retry_not_before = None;
        self.ready_since = None;
        self.healthy_calls = 0;
    }

    /// Apply a turn/run/session cleanup boundary to the exact connection owned by this actor.
    /// A disconnected generation has already dropped its store, so there is nothing to retain.
    pub fn cleanup_spills(&self, boundary: crate::McpSpillCleanup) -> Result<(), McpError> {
        self.client
            .as_ref()
            .map_or(Ok(()), |client| client.cleanup_spills(boundary))
    }

    fn note_healthy_call(&mut self, generation: ServerGeneration) {
        self.healthy_calls = self.healthy_calls.saturating_add(1);
        let stable = self.ready_since.is_some_and(|ready_since| {
            ready_since.elapsed()
                >= Duration::from_millis(iteron_tunables::param_integer(
                    "mcp.supervisor.healthy_retry_reset_after_ms",
                    HEALTHY_RETRY_RESET_AFTER_MS,
                ))
        });
        if stable
            && self.healthy_calls
                >= iteron_tunables::param_integer(
                    "mcp.supervisor.healthy_retry_reset_after_calls",
                    HEALTHY_RETRY_RESET_AFTER_CALLS,
                )
        {
            let _ = self.lifecycle.reset_retry_budget(generation);
        }
    }
}

fn classify_failure(error: &McpError) -> LifecycleFailure {
    match error {
        McpError::Spawn(_) => LifecycleFailure::Spawn,
        McpError::Io(_) | McpError::TransportClosed => LifecycleFailure::Transport,
        McpError::Deadline { .. } => LifecycleFailure::Deadline,
        McpError::Cancelled { .. } => LifecycleFailure::Cancelled,
        McpError::FrameTooLarge { .. }
        | McpError::ResponseTooLarge { .. }
        | McpError::TooManyFrames { .. }
        | McpError::InvalidUtf8
        | McpError::Json(_)
        | McpError::Protocol(_)
        | McpError::InvalidProtocolVersion { .. }
        | McpError::UnsupportedProtocolVersion { .. }
        | McpError::Server { .. } => LifecycleFailure::Protocol,
        _ => LifecycleFailure::Catalog,
    }
}

fn duration_ms_ceil(duration: Duration) -> u64 {
    let milliseconds = duration.as_nanos().saturating_add(999_999) / 1_000_000;
    u64::try_from(milliseconds).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "supervisor/tests.rs"]
mod tests;

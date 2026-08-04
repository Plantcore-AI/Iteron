//! Lazy, generation-fenced supervision for the existing stdio MCP client.
//!
//! Construction validates and retains configuration but does not spawn. The first bounded tool
//! search or exact-identity call connects and discovers. Read-only connection/discovery failures
//! may follow the finite reconnect schedule; an effecting tool call is never replayed after an
//! unknown terminal. Every process owned on a failure or cancellation path is terminated and
//! reaped before the method returns.

mod catalog;
mod config;
mod identity;

pub use catalog::{
    MAX_MCP_SEARCH_DESCRIPTION_BYTES, MAX_MCP_SEARCH_OUTPUT_BYTES, MAX_MCP_SEARCH_QUERY_BYTES,
    MAX_MCP_SEARCH_RESULTS, McpToolIdentity, McpToolMatch, McpToolSearchResult,
};
pub use config::{
    MAX_MCP_COMMAND_BYTES, MAX_MCP_DEADLINE_MS, MAX_MCP_ENV_NAME_BYTES, MAX_MCP_LAUNCH_ARG_BYTES,
    MAX_MCP_LAUNCH_ARGS, MAX_MCP_LAUNCH_BYTES, MAX_MCP_SENSITIVE_ENV_NAMES, McpCancellation,
    McpLaunchConfig, McpTimeouts,
};
pub use identity::McpServerIdentity;

use crate::{
    McpClient, McpError, McpToolOutcome,
    reconnect::{
        LifecycleCore, LifecycleFailure, LifecyclePhase, LifecycleStatus, ReconnectPolicy,
        ServerGeneration,
    },
    tool_filter::McpToolFilter,
};
use catalog::ManagedCatalog;
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
        filter.validate()?;
        let identity =
            McpServerIdentity::new(launch.server_name().to_owned(), launch.binding(), &filter)?;
        Ok(Self {
            launch,
            timeouts,
            filter,
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

    pub fn status(&self) -> LifecycleStatus {
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
        let generation = self.ensure_ready(cancellation).await?;
        self.catalog.search(generation, query, limit)
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
        let generation = match self.ensure_ready(cancellation).await {
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
        }
        let result = {
            let call = client.call_tool_outcome_observed(&bare_name, arguments, move || {
                *observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(std::time::Instant::now());
            });
            tokio::pin!(call);
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => CallResult::Cancelled,
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

    async fn ensure_ready(
        &mut self,
        cancellation: &McpCancellation,
    ) -> Result<ServerGeneration, McpError> {
        loop {
            let status = self.lifecycle.status();
            match status.phase {
                LifecyclePhase::Ready => {
                    return status
                        .generation
                        .ok_or(McpError::InvalidLifecycleTransition {
                            state: "ready",
                            event: "missing_generation",
                        });
                }
                LifecyclePhase::Backoff => self.wait_for_retry(cancellation).await?,
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
            let connected = McpClient::connect_managed(
                self.launch.command(),
                self.launch.args(),
                self.launch.server_name(),
                self.timeouts.handshake(),
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
                    if self.lifecycle.status().phase != LifecyclePhase::Backoff {
                        return Err(error);
                    }
                    continue;
                }
            };
            if let Err(error) = self.lifecycle.connected(generation) {
                client.terminate().await;
                self.lifecycle.stop();
                return Err(error);
            }

            enum DiscoveryResult {
                Completed(Result<Vec<core_protocol::ToolSpec>, McpError>),
                TimedOut,
                Cancelled,
            }
            let discovery = {
                let list = client.list_tools_filtered(&self.filter);
                tokio::pin!(list);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => DiscoveryResult::Cancelled,
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
            return Ok(generation);
        }
    }

    async fn wait_for_retry(&mut self, cancellation: &McpCancellation) -> Result<(), McpError> {
        let deadline = self.retry_not_before.unwrap_or_else(Instant::now);
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(McpError::Cancelled { operation: "reconnect backoff" }),
            _ = tokio::time::sleep_until(deadline) => {
                self.retry_not_before = None;
                Ok(())
            }
        }
    }

    fn record_failure(
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

    fn note_healthy_call(&mut self, generation: ServerGeneration) {
        self.healthy_calls = self.healthy_calls.saturating_add(1);
        let stable = self.ready_since.is_some_and(|ready_since| {
            ready_since.elapsed() >= Duration::from_millis(HEALTHY_RETRY_RESET_AFTER_MS)
        });
        if stable && self.healthy_calls >= HEALTHY_RETRY_RESET_AFTER_CALLS {
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

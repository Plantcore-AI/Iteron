//! Session-owned lazy stdio MCP runtime.
//!
//! Configuration registers bounded proxy schemas only. The first `tool_search`, resource, or
//! prompt request starts the configured server under the immutable families 149--152 policy.
//! Exact tool identities returned by discovery are retained in this session and generation-fenced
//! by `core_mcp::McpSupervisor`; an unknown external effect is never replayed after reconnect.

use super::{
    ConfiguredMcpClient, connect_configured_server_with_policies, host_ceiling, mcp_tool_execution,
};
use crate::{
    config::{McpServerConfig, McpTransportConfig},
    runtime_tunables::effective_mcp::EffectiveMcpSettings,
};
use core_mcp::supervisor::{
    ManagedCatalog, McpCancellation, McpLaunchConfig, McpSupervisor, McpTimeouts, McpToolIdentity,
};
use core_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};
use core_tools::{McpEffectAttribution, Registry};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone)]
pub(crate) struct McpRuntimeControl {
    servers: Arc<BTreeMap<String, Arc<ManagedServer>>>,
}

impl McpRuntimeControl {
    pub(super) fn register(
        registry: &mut Registry,
        servers: &[McpServerConfig],
        sensitive_env_names: &[String],
    ) -> anyhow::Result<Self> {
        let mut managed = BTreeMap::new();
        for config in servers {
            let server = Arc::new(match config.transport {
                McpTransportConfig::Stdio => ManagedServer::Stdio(ManagedStdioServer::new(
                    config.clone(),
                    sensitive_env_names.to_vec(),
                )?),
                McpTransportConfig::Http => ManagedServer::Http(ManagedHttpServer::new(
                    config.clone(),
                    sensitive_env_names.to_vec(),
                )?),
            });
            register_server_tools(registry, server.clone())?;
            managed.insert(config.name.clone(), server);
        }
        Ok(Self {
            servers: Arc::new(managed),
        })
    }

    /// Atomically preflight and then install the checkpoint-decoded MCP policy into every lazy
    /// server. Once a session has a policy, even an identical-looking live config cannot replace
    /// it; resume uses the bytes in the historical tunables checkpoint.
    pub(crate) fn configure(&self, policy: EffectiveMcpSettings) -> anyhow::Result<()> {
        if self.servers.values().any(|server| {
            server
                .current_policy()
                .is_some_and(|current| current != policy)
        }) {
            anyhow::bail!("MCP runtime policy is already pinned to a different checkpoint")
        }
        for server in self.servers.values() {
            server.configure(policy);
        }
        Ok(())
    }

    pub(crate) fn health(&self) -> Vec<McpServerHealth> {
        self.servers
            .values()
            .map(|server| server.health())
            .collect()
    }

    pub(crate) fn cancel(&self, name: &str) -> bool {
        self.servers.get(name).is_some_and(|server| {
            server.cancel();
            true
        })
    }

    pub(crate) async fn restart(&self, name: &str) -> Result<(), &'static str> {
        self.servers
            .get(name)
            .ok_or("unknown MCP server")?
            .restart()
            .await
    }

    pub(crate) async fn stop(&self, name: &str) -> Result<(), &'static str> {
        self.servers
            .get(name)
            .ok_or("unknown MCP server")?
            .stop()
            .await
    }

    pub(crate) async fn cleanup_spills(
        &self,
        boundary: core_mcp::McpSpillCleanup,
    ) -> Result<(), core_mcp::McpError> {
        let mut first_failure = None;
        for server in self.servers.values() {
            if let Err(error) = server.cleanup_spills(boundary).await {
                first_failure.get_or_insert(error);
            }
        }
        if let Some(error) = first_failure {
            return Err(error);
        }
        Ok(())
    }
}

enum ManagedServer {
    Stdio(ManagedStdioServer),
    Http(ManagedHttpServer),
}

impl ManagedServer {
    fn name(&self) -> &str {
        match self {
            Self::Stdio(server) => &server.config.name,
            Self::Http(server) => &server.config.name,
        }
    }

    fn current_policy(&self) -> Option<EffectiveMcpSettings> {
        match self {
            Self::Stdio(server) => server.policy.get().copied(),
            Self::Http(server) => server.policy.get().copied(),
        }
    }

    fn configure(&self, policy: EffectiveMcpSettings) {
        match self {
            Self::Stdio(server) => {
                let _ = server.policy.set(policy);
            }
            Self::Http(server) => {
                let _ = server.policy.set(policy);
            }
        }
    }

    fn cancel(&self) {
        match self {
            Self::Stdio(server) => server.cancel(),
            Self::Http(server) => server.cancel(),
        }
    }

    async fn restart(&self) -> Result<(), &'static str> {
        match self {
            Self::Stdio(server) => server.restart().await,
            Self::Http(server) => server.restart().await,
        }
    }

    async fn stop(&self) -> Result<(), &'static str> {
        match self {
            Self::Stdio(server) => server.stop().await,
            Self::Http(server) => server.stop().await,
        }
    }

    async fn cleanup_spills(
        &self,
        boundary: core_mcp::McpSpillCleanup,
    ) -> Result<(), core_mcp::McpError> {
        match self {
            Self::Stdio(server) => server.cleanup_spills(boundary).await,
            Self::Http(server) => server.cleanup_spills(boundary).await,
        }
    }

    fn health(&self) -> McpServerHealth {
        match self {
            Self::Stdio(server) => server.health(),
            Self::Http(server) => server.health(),
        }
    }

    async fn search(&self, query: &str, limit: usize) -> Result<String, core_mcp::McpError> {
        match self {
            Self::Stdio(server) => server.search(query, limit).await,
            Self::Http(server) => server.search(query, limit).await,
        }
    }

    async fn call<F>(
        &self,
        name: &str,
        arguments: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match self {
            Self::Stdio(server) => server.call(name, arguments, on_dispatch).await,
            Self::Http(server) => server.call(name, arguments, on_dispatch).await,
        }
    }

    async fn extension<F>(
        &self,
        method: &'static str,
        params: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match self {
            Self::Stdio(server) => server.extension(method, params, on_dispatch).await,
            Self::Http(server) => server.extension(method, params, on_dispatch).await,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct McpServerHealth {
    pub(crate) name: String,
    pub(crate) transport: &'static str,
    pub(crate) phase: String,
    pub(crate) generation: Option<u64>,
    pub(crate) reconnect_attempts: u32,
    pub(crate) reconnect_limit: u32,
    pub(crate) retry_after_ms: Option<u64>,
    pub(crate) retained_tools: usize,
    pub(crate) catalog_current: bool,
    pub(crate) busy: bool,
    pub(crate) negotiated_protocol_version: Option<String>,
    pub(crate) last_failure: Option<String>,
}

struct ManagedStdioServer {
    config: McpServerConfig,
    resolved_command: PathBuf,
    sensitive_env_names: Vec<String>,
    policy: OnceLock<EffectiveMcpSettings>,
    cancellation: Mutex<McpCancellation>,
    state: tokio::sync::Mutex<ManagedState>,
}

struct ManagedState {
    supervisor: Option<McpSupervisor>,
    identities: BTreeMap<String, McpToolIdentity>,
    stopped: bool,
}

impl ManagedStdioServer {
    fn new(config: McpServerConfig, sensitive_env_names: Vec<String>) -> anyhow::Result<Self> {
        // Resolve before registration so a missing executable is a startup configuration error,
        // but do not spawn it. The absolute path is part of the supervisor's immutable binding.
        let command = config.command.as_deref().ok_or_else(|| {
            anyhow::anyhow!("stdio MCP `{}` has no configured command", config.name)
        })?;
        let resolved_command = resolve_executable(command)?;
        Ok(Self {
            config,
            resolved_command,
            sensitive_env_names,
            policy: OnceLock::new(),
            cancellation: Mutex::new(McpCancellation::new()),
            state: tokio::sync::Mutex::new(ManagedState {
                supervisor: None,
                identities: BTreeMap::new(),
                stopped: false,
            }),
        })
    }

    fn operation_cancellation(&self) -> McpCancellation {
        let mut current = self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_cancelled() {
            *current = McpCancellation::new();
        }
        current.clone()
    }

    fn cancel(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel();
    }

    fn make_supervisor(&self) -> Result<McpSupervisor, core_mcp::McpError> {
        let runtime = self
            .policy
            .get()
            .copied()
            .ok_or(core_mcp::McpError::LifecycleFailed)?;
        let launch = McpLaunchConfig::new(
            self.resolved_command.to_string_lossy().into_owned(),
            self.config.args.clone(),
            self.config.name.clone(),
        )?
        .with_sensitive_env_names(self.sensitive_env_names.clone())?;
        let deadlines = runtime.deadlines.stdio();
        let timeouts = McpTimeouts::new(
            deadlines.startup(),
            deadlines.startup(),
            deadlines.tool_call(),
        )?
        .with_operation_deadlines(deadlines.startup(), deadlines.tool_call())?;
        McpSupervisor::deferred_governed(
            launch,
            self.config.tools.clone(),
            self.config.policy.clone(),
            host_ceiling(),
            runtime.reconnect,
            timeouts,
            runtime.result,
        )
    }

    async fn search(&self, query: &str, limit: usize) -> Result<String, core_mcp::McpError> {
        let cancellation = self.operation_cancellation();
        let mut state = self.state.lock().await;
        if state.stopped {
            return Err(core_mcp::McpError::LifecycleStopped);
        }
        if state.supervisor.is_none() {
            state.supervisor = Some(self.make_supervisor()?);
        }
        let result = state
            .supervisor
            .as_mut()
            .expect("initialized above")
            .search_tools(query, limit, &cancellation)
            .await?;
        for matched in &result.matches {
            state
                .identities
                .insert(matched.name.clone(), matched.identity.clone());
        }
        serde_json::to_string(&json!({
            "server": self.config.name,
            "generation": result.generation.get(),
            "tools": result.matches.iter().map(|matched| json!({
                "name": matched.name,
                "description": matched.description,
            })).collect::<Vec<_>>(),
            "total_matches": result.total_matches,
            "truncated": result.truncated,
            "note": "Call only an exact returned name through this server's tool_call proxy.",
        }))
        .map_err(core_mcp::McpError::from)
    }

    async fn call<F>(
        &self,
        name: &str,
        arguments: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        let cancellation = self.operation_cancellation();
        let mut state = self.state.lock().await;
        if state.stopped {
            return definite_mcp_error(core_mcp::McpError::LifecycleStopped);
        }
        let namespaced = if name.starts_with(&format!("{}__", self.config.name)) {
            name.to_owned()
        } else {
            format!("{}__{name}", self.config.name)
        };
        let Some(identity) = state.identities.get(&namespaced).cloned() else {
            return definite_mcp_error(core_mcp::McpError::StaleToolIdentity);
        };
        let Some(supervisor) = state.supervisor.as_mut() else {
            return definite_mcp_error(core_mcp::McpError::StaleToolIdentity);
        };
        supervisor
            .call_tool_observed(&identity, arguments, &cancellation, on_dispatch)
            .await
    }

    async fn extension<F>(
        &self,
        method: &'static str,
        params: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        let cancellation = self.operation_cancellation();
        let mut state = self.state.lock().await;
        if state.stopped {
            return definite_mcp_error(core_mcp::McpError::LifecycleStopped);
        }
        if state.supervisor.is_none() {
            match self.make_supervisor() {
                Ok(supervisor) => state.supervisor = Some(supervisor),
                Err(error) => return definite_mcp_error(error),
            }
        }
        state
            .supervisor
            .as_mut()
            .expect("initialized above")
            .call_extension_observed(method, params, &cancellation, on_dispatch)
            .await
    }

    async fn stop(&self) -> Result<(), &'static str> {
        self.cancel();
        let mut state = self.state.lock().await;
        if let Some(supervisor) = state.supervisor.as_mut() {
            supervisor.stop().await;
        }
        state.supervisor = None;
        state.identities.clear();
        state.stopped = true;
        Ok(())
    }

    async fn restart(&self) -> Result<(), &'static str> {
        self.cancel();
        let mut state = self.state.lock().await;
        if let Some(supervisor) = state.supervisor.as_mut() {
            supervisor.stop().await;
        }
        state.supervisor = None;
        state.identities.clear();
        state.stopped = false;
        let mut cancellation = self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cancellation = McpCancellation::new();
        Ok(())
    }

    async fn cleanup_spills(
        &self,
        boundary: core_mcp::McpSpillCleanup,
    ) -> Result<(), core_mcp::McpError> {
        let state = self.state.lock().await;
        state
            .supervisor
            .as_ref()
            .map_or(Ok(()), |supervisor| supervisor.cleanup_spills(boundary))
    }

    fn health(&self) -> McpServerHealth {
        let Ok(mut state) = self.state.try_lock() else {
            return McpServerHealth {
                name: self.config.name.clone(),
                transport: "stdio",
                phase: "busy".into(),
                generation: None,
                reconnect_attempts: 0,
                reconnect_limit: self.policy.get().map_or(0, |p| p.reconnect.max_attempts()),
                retry_after_ms: None,
                retained_tools: 0,
                catalog_current: false,
                busy: true,
                negotiated_protocol_version: None,
                last_failure: None,
            };
        };
        if state.stopped {
            return idle_health(&self.config.name, "stopped", self.policy.get());
        }
        let Some(supervisor) = state.supervisor.as_mut() else {
            return idle_health(&self.config.name, "deferred", self.policy.get());
        };
        let status = supervisor.status();
        McpServerHealth {
            name: self.config.name.clone(),
            transport: "stdio",
            phase: status.phase.label().into(),
            generation: status.generation.map(|generation| generation.get()),
            reconnect_attempts: status.reconnect_attempts,
            reconnect_limit: status.reconnect_limit,
            retry_after_ms: status.retry_after_ms,
            retained_tools: status.retained_tools,
            catalog_current: status.catalog_current,
            busy: false,
            negotiated_protocol_version: supervisor
                .negotiated_protocol_version()
                .map(str::to_owned),
            last_failure: status
                .last_failure
                .map(lifecycle_failure_label)
                .map(str::to_owned),
        }
    }
}

struct ManagedHttpServer {
    config: McpServerConfig,
    sensitive_env_names: Vec<String>,
    binding: Arc<[u8]>,
    policy: OnceLock<EffectiveMcpSettings>,
    cancellation: Mutex<McpCancellation>,
    state: tokio::sync::Mutex<ManagedHttpState>,
}

struct ManagedHttpState {
    lifecycle: Option<core_mcp::reconnect::LifecycleCore>,
    client: Option<Arc<ConfiguredMcpClient>>,
    catalog: ManagedCatalog,
    identities: BTreeMap<String, McpToolIdentity>,
    retry_not_before: Option<Instant>,
    ready_since: Option<Instant>,
    healthy_calls: u32,
    stopped: bool,
}

impl ManagedHttpServer {
    fn new(config: McpServerConfig, sensitive_env_names: Vec<String>) -> anyhow::Result<Self> {
        let binding = http_server_binding(&config)?;
        Ok(Self {
            config,
            sensitive_env_names,
            binding,
            policy: OnceLock::new(),
            cancellation: Mutex::new(McpCancellation::new()),
            state: tokio::sync::Mutex::new(ManagedHttpState {
                lifecycle: None,
                client: None,
                catalog: ManagedCatalog::default(),
                identities: BTreeMap::new(),
                retry_not_before: None,
                ready_since: None,
                healthy_calls: 0,
                stopped: false,
            }),
        })
    }

    fn operation_cancellation(&self) -> McpCancellation {
        let mut current = self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_cancelled() {
            *current = McpCancellation::new();
        }
        current.clone()
    }

    fn cancel(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancel();
    }

    fn runtime(&self) -> Result<EffectiveMcpSettings, core_mcp::McpError> {
        self.policy
            .get()
            .copied()
            .ok_or(core_mcp::McpError::LifecycleFailed)
    }

    fn lifecycle<'a>(
        &self,
        state: &'a mut ManagedHttpState,
    ) -> Result<&'a mut core_mcp::reconnect::LifecycleCore, core_mcp::McpError> {
        if state.lifecycle.is_none() {
            state.lifecycle = Some(core_mcp::reconnect::LifecycleCore::deferred(
                self.runtime()?.reconnect,
            ));
        }
        Ok(state.lifecycle.as_mut().expect("initialized above"))
    }

    async fn ensure_ready(
        &self,
        state: &mut ManagedHttpState,
        cancellation: &McpCancellation,
        deadline: Instant,
    ) -> Result<core_mcp::reconnect::ServerGeneration, core_mcp::McpError> {
        use core_mcp::reconnect::LifecyclePhase;
        loop {
            if cancellation.is_cancelled() {
                return Err(core_mcp::McpError::Cancelled {
                    operation: "HTTP MCP startup",
                });
            }
            if Instant::now() >= deadline {
                return Err(managed_deadline());
            }
            let status = self.lifecycle(state)?.status();
            match status.phase {
                LifecyclePhase::Ready => {
                    return status.generation.ok_or(
                        core_mcp::McpError::InvalidLifecycleTransition {
                            state: "ready",
                            event: "missing_generation",
                        },
                    );
                }
                LifecyclePhase::Backoff => {
                    let due = state.retry_not_before.unwrap_or_else(Instant::now);
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            return Err(core_mcp::McpError::Cancelled { operation: "HTTP MCP reconnect backoff" });
                        }
                        _ = tokio::time::sleep_until(deadline) => return Err(managed_deadline()),
                        _ = tokio::time::sleep_until(due) => {}
                    }
                    state.retry_not_before = None;
                }
                LifecyclePhase::Deferred | LifecyclePhase::Cancelled => {}
                LifecyclePhase::Exhausted => {
                    return Err(core_mcp::McpError::RetryExhausted {
                        attempts: status.reconnect_attempts,
                    });
                }
                LifecyclePhase::Failed => return Err(core_mcp::McpError::LifecycleFailed),
                LifecyclePhase::Stopped => return Err(core_mcp::McpError::LifecycleStopped),
                phase => {
                    return Err(core_mcp::McpError::InvalidLifecycleTransition {
                        state: phase.label(),
                        event: "http_ensure_ready",
                    });
                }
            }

            let generation = self.lifecycle(state)?.begin_connection()?;
            let runtime = self.runtime()?;
            let connection = connect_configured_server_with_policies(
                &self.config,
                &self.sensitive_env_names,
                runtime.deadlines,
                runtime.result,
            );
            let connected = tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(core_mcp::McpError::Cancelled { operation: "HTTP MCP connect" }),
                _ = tokio::time::sleep_until(deadline) => Err(managed_deadline()),
                result = connection => result,
            };
            let client = match connected {
                Ok(client @ ConfiguredMcpClient::Http(_)) => Arc::new(client),
                Ok(ConfiguredMcpClient::Stdio(_)) => {
                    self.lifecycle(state)?.stop();
                    return Err(core_mcp::McpError::InvalidLifecycleTransition {
                        state: "connecting",
                        event: "wrong_transport",
                    });
                }
                Err(error @ core_mcp::McpError::Cancelled { .. }) => {
                    let _ = self.lifecycle(state)?.cancel(generation);
                    return Err(error);
                }
                Err(error) => {
                    self.record_failure(state, generation, classify_http_failure(&error))?;
                    if self.lifecycle(state)?.status().phase == LifecyclePhase::Backoff {
                        continue;
                    }
                    return Err(error);
                }
            };
            self.lifecycle(state)?.connected(generation)?;
            let discovery =
                client.list_tools_governed(&self.config.tools, &self.config.policy, host_ceiling());
            let specs = tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(core_mcp::McpError::Cancelled { operation: "HTTP MCP discovery" }),
                _ = tokio::time::sleep_until(deadline) => Err(managed_deadline()),
                result = discovery => result,
            };
            let specs = match specs {
                Ok(specs) => specs,
                Err(error @ core_mcp::McpError::Cancelled { .. }) => {
                    let _ = self.lifecycle(state)?.cancel(generation);
                    return Err(error);
                }
                Err(error) => {
                    self.record_failure(state, generation, classify_http_failure(&error))?;
                    if self.lifecycle(state)?.status().phase == LifecyclePhase::Backoff {
                        continue;
                    }
                    return Err(error);
                }
            };
            let catalog = match ManagedCatalog::admit(
                &self.config.name,
                self.binding.clone(),
                client.negotiated_protocol_version(),
                specs,
            ) {
                Ok(catalog) => catalog,
                Err(error) => {
                    self.record_failure(
                        state,
                        generation,
                        core_mcp::reconnect::LifecycleFailure::Catalog,
                    )?;
                    return Err(error);
                }
            };
            self.lifecycle(state)?
                .discovered(generation, catalog.len())?;
            state.client = Some(client);
            state.catalog = catalog;
            state.retry_not_before = None;
            state.ready_since = Some(Instant::now());
            state.healthy_calls = 0;
            return Ok(generation);
        }
    }

    fn record_failure(
        &self,
        state: &mut ManagedHttpState,
        generation: core_mcp::reconnect::ServerGeneration,
        failure: core_mcp::reconnect::LifecycleFailure,
    ) -> Result<(), core_mcp::McpError> {
        state.client = None;
        let delay = self.lifecycle(state)?.failed(generation, failure)?;
        state.retry_not_before = delay.map(|ms| Instant::now() + Duration::from_millis(ms));
        state.ready_since = None;
        state.healthy_calls = 0;
        Ok(())
    }

    async fn search(&self, query: &str, limit: usize) -> Result<String, core_mcp::McpError> {
        let cancellation = self.operation_cancellation();
        let runtime = self.runtime()?;
        let deadline = Instant::now() + runtime.deadlines.http().startup();
        let mut state = self.state.lock().await;
        if state.stopped {
            return Err(core_mcp::McpError::LifecycleStopped);
        }
        let generation = self
            .ensure_ready(&mut state, &cancellation, deadline)
            .await?;
        let result = state.catalog.search(generation, query, limit)?;
        for matched in &result.matches {
            state
                .identities
                .insert(matched.name.clone(), matched.identity.clone());
        }
        serde_json::to_string(&json!({
            "server": self.config.name,
            "generation": generation.get(),
            "tools": result.matches.iter().map(|matched| json!({
                "name": matched.name,
                "description": matched.description,
            })).collect::<Vec<_>>(),
            "total_matches": result.total_matches,
            "truncated": result.truncated,
            "note": "Call only an exact returned name through this server's tool_call proxy.",
        }))
        .map_err(core_mcp::McpError::from)
    }

    async fn call<F>(
        &self,
        name: &str,
        arguments: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        let cancellation = self.operation_cancellation();
        let runtime = match self.runtime() {
            Ok(runtime) => runtime,
            Err(error) => return definite_mcp_error(error),
        };
        let started = Instant::now();
        let deadline = started + runtime.deadlines.http().tool_call();
        let startup_deadline = deadline.min(started + runtime.deadlines.http().startup());
        let mut state = self.state.lock().await;
        if state.stopped {
            return definite_mcp_error(core_mcp::McpError::LifecycleStopped);
        }
        let generation = match self
            .ensure_ready(&mut state, &cancellation, startup_deadline)
            .await
        {
            Ok(generation) => generation,
            Err(error) => return definite_mcp_error(error),
        };
        let namespaced = if name.starts_with(&format!("{}__", self.config.name)) {
            name.to_owned()
        } else {
            format!("{}__{name}", self.config.name)
        };
        let Some(identity) = state.identities.get(&namespaced).cloned() else {
            return definite_mcp_error(core_mcp::McpError::StaleToolIdentity);
        };
        let Some(spec) = state.catalog.spec(&identity) else {
            return definite_mcp_error(core_mcp::McpError::StaleToolIdentity);
        };
        let bare = identity.bare_name().to_owned();
        debug_assert_eq!(spec.name, namespaced);
        let Some(client) = state.client.clone() else {
            return definite_mcp_error(core_mcp::McpError::LifecycleFailed);
        };
        let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = dispatched.clone();
        let call = client.call_tool_outcome_observed(&bare, arguments, move || {
            observed.store(true, Ordering::Release);
            on_dispatch();
        });
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => cancellation_outcome(&self.config.name, &bare, dispatched.load(Ordering::Acquire)),
            _ = tokio::time::sleep_until(deadline) => timeout_outcome(&self.config.name, &bare, dispatched.load(Ordering::Acquire)),
            outcome = call => outcome,
        };
        self.settle_http_outcome(&mut state, generation, &outcome);
        if matches!(outcome, core_mcp::McpToolOutcome::Completed { .. }) {
            self.note_http_healthy(&mut state, generation);
        }
        outcome
    }

    async fn extension<F>(
        &self,
        method: &'static str,
        params: Value,
        on_dispatch: F,
    ) -> core_mcp::McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        let cancellation = self.operation_cancellation();
        let runtime = match self.runtime() {
            Ok(runtime) => runtime,
            Err(error) => return definite_mcp_error(error),
        };
        let started = Instant::now();
        let deadline = started + runtime.deadlines.http().tool_call();
        let startup_deadline = deadline.min(started + runtime.deadlines.http().startup());
        let mut state = self.state.lock().await;
        if state.stopped {
            return definite_mcp_error(core_mcp::McpError::LifecycleStopped);
        }
        let generation = match self
            .ensure_ready(&mut state, &cancellation, startup_deadline)
            .await
        {
            Ok(generation) => generation,
            Err(error) => return definite_mcp_error(error),
        };
        let Some(client) = state.client.clone() else {
            return definite_mcp_error(core_mcp::McpError::LifecycleFailed);
        };
        let dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = dispatched.clone();
        let call = client.call_extension_outcome_observed(method, params, move || {
            observed.store(true, Ordering::Release);
            on_dispatch();
        });
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => cancellation_outcome(&self.config.name, method, dispatched.load(Ordering::Acquire)),
            _ = tokio::time::sleep_until(deadline) => timeout_outcome(&self.config.name, method, dispatched.load(Ordering::Acquire)),
            outcome = call => outcome,
        };
        self.settle_http_outcome(&mut state, generation, &outcome);
        if matches!(outcome, core_mcp::McpToolOutcome::Completed { .. }) {
            self.note_http_healthy(&mut state, generation);
        }
        outcome
    }

    fn settle_http_outcome(
        &self,
        state: &mut ManagedHttpState,
        generation: core_mcp::reconnect::ServerGeneration,
        outcome: &core_mcp::McpToolOutcome,
    ) {
        if let core_mcp::McpToolOutcome::Unknown { error, .. } = outcome {
            let result = if matches!(error, core_mcp::McpError::Cancelled { .. }) {
                state.client = None;
                state.retry_not_before = None;
                match self.lifecycle(state) {
                    Ok(lifecycle) => lifecycle.cancel(generation),
                    Err(error) => Err(error),
                }
            } else {
                self.record_failure(state, generation, classify_http_failure(error))
            };
            if result.is_err() {
                state.client = None;
                state.retry_not_before = None;
                if let Some(lifecycle) = state.lifecycle.as_mut() {
                    lifecycle.stop();
                }
            }
        }
    }

    fn note_http_healthy(
        &self,
        state: &mut ManagedHttpState,
        generation: core_mcp::reconnect::ServerGeneration,
    ) {
        state.healthy_calls = state.healthy_calls.saturating_add(1);
        let stable = state.ready_since.is_some_and(|ready_since| {
            ready_since.elapsed()
                >= Duration::from_millis(core_mcp::supervisor::HEALTHY_RETRY_RESET_AFTER_MS)
        });
        if stable
            && state.healthy_calls >= core_mcp::supervisor::HEALTHY_RETRY_RESET_AFTER_CALLS
            && let Some(lifecycle) = state.lifecycle.as_mut()
        {
            let _ = lifecycle.reset_retry_budget(generation);
        }
    }

    async fn stop(&self) -> Result<(), &'static str> {
        self.cancel();
        let mut state = self.state.lock().await;
        if let Some(lifecycle) = state.lifecycle.as_mut() {
            lifecycle.stop();
        }
        state.client = None;
        state.identities.clear();
        state.ready_since = None;
        state.healthy_calls = 0;
        state.stopped = true;
        Ok(())
    }

    async fn restart(&self) -> Result<(), &'static str> {
        self.cancel();
        let mut state = self.state.lock().await;
        state.lifecycle = self
            .policy
            .get()
            .map(|policy| core_mcp::reconnect::LifecycleCore::deferred(policy.reconnect));
        state.client = None;
        state.catalog = ManagedCatalog::default();
        state.identities.clear();
        state.retry_not_before = None;
        state.ready_since = None;
        state.healthy_calls = 0;
        state.stopped = false;
        *self
            .cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = McpCancellation::new();
        Ok(())
    }

    async fn cleanup_spills(
        &self,
        boundary: core_mcp::McpSpillCleanup,
    ) -> Result<(), core_mcp::McpError> {
        let state = self.state.lock().await;
        state
            .client
            .as_ref()
            .map_or(Ok(()), |client| client.cleanup_spills(boundary))
    }

    fn health(&self) -> McpServerHealth {
        let Ok(state) = self.state.try_lock() else {
            return McpServerHealth {
                name: self.config.name.clone(),
                transport: "http",
                phase: "busy".into(),
                generation: None,
                reconnect_attempts: 0,
                reconnect_limit: self.policy.get().map_or(0, |p| p.reconnect.max_attempts()),
                retry_after_ms: None,
                retained_tools: 0,
                catalog_current: false,
                busy: true,
                negotiated_protocol_version: None,
                last_failure: None,
            };
        };
        if state.stopped {
            return http_idle_health(&self.config.name, "stopped", self.policy.get());
        }
        let Some(lifecycle) = state.lifecycle.as_ref() else {
            return http_idle_health(&self.config.name, "deferred", self.policy.get());
        };
        let status = lifecycle.status();
        McpServerHealth {
            name: self.config.name.clone(),
            transport: "http",
            phase: status.phase.label().into(),
            generation: status.generation.map(|generation| generation.get()),
            reconnect_attempts: status.reconnect_attempts,
            reconnect_limit: status.reconnect_limit,
            retry_after_ms: state
                .retry_not_before
                .map(|due| duration_ms(due.saturating_duration_since(Instant::now()))),
            retained_tools: status.retained_tools,
            catalog_current: status.catalog_current,
            busy: false,
            negotiated_protocol_version: state
                .client
                .as_ref()
                .map(|client| client.negotiated_protocol_version().to_owned()),
            last_failure: status
                .last_failure
                .map(lifecycle_failure_label)
                .map(str::to_owned),
        }
    }
}

fn http_idle_health(
    name: &str,
    phase: &str,
    policy: Option<&EffectiveMcpSettings>,
) -> McpServerHealth {
    McpServerHealth {
        name: name.into(),
        transport: "http",
        phase: phase.into(),
        generation: None,
        reconnect_attempts: 0,
        reconnect_limit: policy.map_or(0, |policy| policy.reconnect.max_attempts()),
        retry_after_ms: None,
        retained_tools: 0,
        catalog_current: false,
        busy: false,
        negotiated_protocol_version: None,
        last_failure: None,
    }
}

fn classify_http_failure(error: &core_mcp::McpError) -> core_mcp::reconnect::LifecycleFailure {
    use core_mcp::reconnect::LifecycleFailure;
    match error {
        core_mcp::McpError::Deadline { .. } => LifecycleFailure::Deadline,
        core_mcp::McpError::Spawn(_)
        | core_mcp::McpError::Io(_)
        | core_mcp::McpError::TransportClosed
        | core_mcp::McpError::HttpStatus {
            status: 408 | 425 | 429 | 500..=599,
        } => LifecycleFailure::Transport,
        core_mcp::McpError::Cancelled { .. } => LifecycleFailure::Cancelled,
        _ => LifecycleFailure::Protocol,
    }
}

fn managed_deadline() -> core_mcp::McpError {
    core_mcp::McpError::Deadline {
        operation: "managed HTTP MCP operation".into(),
    }
}

fn cancellation_outcome(
    server: &str,
    operation: &str,
    dispatched: bool,
) -> core_mcp::McpToolOutcome {
    if dispatched {
        core_mcp::McpToolOutcome::Unknown {
            error: core_mcp::McpError::Cancelled {
                operation: "dispatched HTTP MCP request",
            },
            evidence: synthetic_evidence(server, operation),
        }
    } else {
        definite_mcp_error(core_mcp::McpError::Cancelled {
            operation: "HTTP MCP request",
        })
    }
}

fn timeout_outcome(server: &str, operation: &str, dispatched: bool) -> core_mcp::McpToolOutcome {
    if dispatched {
        core_mcp::McpToolOutcome::Unknown {
            error: managed_deadline(),
            evidence: synthetic_evidence(server, operation),
        }
    } else {
        definite_mcp_error(managed_deadline())
    }
}

fn synthetic_evidence(server: &str, operation: &str) -> core_mcp::McpToolCallEvidence {
    core_mcp::McpToolCallEvidence::new(
        server,
        operation,
        std::num::NonZeroU64::new(1).expect("one is non-zero"),
    )
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos().saturating_add(999_999) / 1_000_000).unwrap_or(u64::MAX)
}

fn http_server_binding(config: &McpServerConfig) -> anyhow::Result<Arc<[u8]>> {
    static NEXT_LINEAGE: AtomicU64 = AtomicU64::new(1);
    let lineage = NEXT_LINEAGE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| anyhow::anyhow!("HTTP MCP lineage exhausted"))?;
    let encoded = serde_json::to_vec(config)?;
    let mut hasher = Sha256::new();
    hasher.update(b"core-http-mcp-session-binding-v1\0");
    hasher.update(lineage.to_be_bytes());
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(Arc::from(hasher.finalize().to_vec()))
}

fn idle_health(name: &str, phase: &str, policy: Option<&EffectiveMcpSettings>) -> McpServerHealth {
    McpServerHealth {
        name: name.into(),
        transport: "stdio",
        phase: phase.into(),
        generation: None,
        reconnect_attempts: 0,
        reconnect_limit: policy.map_or(0, |policy| policy.reconnect.max_attempts()),
        retry_after_ms: None,
        retained_tools: 0,
        catalog_current: false,
        busy: false,
        negotiated_protocol_version: None,
        last_failure: None,
    }
}

fn lifecycle_failure_label(failure: core_mcp::reconnect::LifecycleFailure) -> &'static str {
    match failure {
        core_mcp::reconnect::LifecycleFailure::Spawn => "spawn",
        core_mcp::reconnect::LifecycleFailure::Deadline => "deadline",
        core_mcp::reconnect::LifecycleFailure::Transport => "transport",
        core_mcp::reconnect::LifecycleFailure::Protocol => "protocol",
        core_mcp::reconnect::LifecycleFailure::Catalog => "catalog",
        core_mcp::reconnect::LifecycleFailure::Cancelled => "cancelled",
    }
}

fn register_server_tools(
    registry: &mut Registry,
    server: Arc<ManagedServer>,
) -> Result<(), core_tools::ToolError> {
    let name = server.name().to_owned();
    let search_name = format!("{name}__tool_search");
    let search_server = server.clone();
    registry.register_external_effect(
        ToolSpec {
            name: search_name,
            description: format!(
                "Lazily connect to `{name}` and search its authority-admitted MCP tool catalog."
            ),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "query":{"type":"string"},
                    "limit":{"type":"integer"}
                },
                "required":["query"]
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, _root| {
            let server = search_server.clone();
            core_tools::effectfut::box_it(async move {
                let query = call
                    .input
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let limit = call
                    .input
                    .get("limit")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(8);
                match server.search(query, limit).await {
                    Ok(content) => definite_result(call.id, content, false),
                    Err(error) => definite_result(
                        call.id,
                        format!("mcp error: {}", error.public_summary()),
                        true,
                    ),
                }
            })
        },
    )?;

    let call_server = server.clone();
    registry.register_mcp_effect(
        ToolSpec {
            name: format!("{name}__tool_call"),
            description: format!(
                "Call one exact `{name}` MCP tool name returned by `{name}__tool_search`."
            ),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "name":{"type":"string"},
                    "arguments":{"type":"object"}
                },
                "required":["name", "arguments"]
            }),
            purity: Purity::Effecting,
            capability: Capability::IrreversibleExternal,
        },
        McpEffectAttribution::new(&name, "tool_call"),
        move |call, _root, dispatch_clock| {
            let server = call_server.clone();
            core_tools::effectfut::box_it(async move {
                let tool = call.input.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = call
                    .input
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let outcome = server
                    .call(tool, arguments, move || dispatch_clock.mark_dispatched())
                    .await;
                mcp_tool_execution(call.id, outcome)
            })
        },
    )?;

    for (suffix, method, description, schema) in extension_tools(&name) {
        let extension_server = server.clone();
        registry.register_mcp_effect(
            ToolSpec {
                name: format!("{name}__{suffix}"),
                description,
                input_schema: schema,
                purity: Purity::Effecting,
                capability: Capability::ReadOnly,
            },
            McpEffectAttribution::new(&name, suffix),
            move |call, _root, dispatch_clock| {
                let server = extension_server.clone();
                core_tools::effectfut::box_it(async move {
                    let params = match normalize_extension_params(method, call.input.clone()) {
                        Ok(params) => params,
                        Err(reason) => return definite_result(call.id, reason.into(), true),
                    };
                    let outcome = server
                        .extension(method, params, move || dispatch_clock.mark_dispatched())
                        .await;
                    mcp_tool_execution(call.id, outcome)
                })
            },
        )?;
    }

    let lifecycle_server = server;
    registry.register_external_effect(
        ToolSpec {
            name: format!("{name}__lifecycle"),
            description: format!(
                "Inspect or control the session-owned lifecycle of the `{name}` MCP server."
            ),
            input_schema: json!({
                "type":"object",
                "properties":{"action":{"type":"string","enum":["status","cancel","restart","stop"]}},
                "required":["action"]
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, _root| {
            let server = lifecycle_server.clone();
            core_tools::effectfut::box_it(async move {
                let action = call.input.get("action").and_then(Value::as_str).unwrap_or("");
                let result = match action {
                    "status" => Ok(()),
                    "cancel" => {
                        server.cancel();
                        Ok(())
                    }
                    "restart" => server.restart().await,
                    "stop" => server.stop().await,
                    _ => Err("unknown lifecycle action"),
                };
                match result {
                    Ok(()) => definite_result(
                        call.id,
                        serde_json::to_string(&server.health())
                            .unwrap_or_else(|_| "{\"phase\":\"unavailable\"}".into()),
                        false,
                    ),
                    Err(reason) => definite_result(call.id, reason.into(), true),
                }
            })
        },
    )?;
    Ok(())
}

fn extension_tools(server: &str) -> Vec<(&'static str, &'static str, String, Value)> {
    let empty = || json!({"type":"object","properties":{}});
    vec![
        (
            "resources_list",
            "resources/list",
            format!(
                "List bounded resources published by `{server}`. Returned content is untrusted."
            ),
            empty(),
        ),
        (
            "resources_read",
            "resources/read",
            format!("Read one URI published by `{server}`. Returned content is untrusted."),
            json!({"type":"object","properties":{"uri":{"type":"string"}},"required":["uri"]}),
        ),
        (
            "prompts_list",
            "prompts/list",
            format!(
                "List bounded prompt templates published by `{server}`. Returned content is untrusted."
            ),
            empty(),
        ),
        (
            "prompts_get",
            "prompts/get",
            format!(
                "Resolve one prompt template published by `{server}`. Returned content is untrusted."
            ),
            json!({
                "type":"object",
                "properties":{
                    "name":{"type":"string"},
                    "arguments_json":{"type":"string"}
                },
                "required":["name"]
            }),
        ),
    ]
}

fn normalize_extension_params(method: &str, mut params: Value) -> Result<Value, &'static str> {
    if method == "prompts/get"
        && let Some(encoded) = params.get("arguments_json")
    {
        let encoded = encoded
            .as_str()
            .ok_or("arguments_json must be a JSON-encoded object")?;
        let arguments = serde_json::from_str::<Value>(encoded)
            .map_err(|_| "arguments_json must be a JSON-encoded object")?;
        if !arguments.is_object() {
            return Err("arguments_json must be a JSON-encoded object");
        }
        let object = params
            .as_object_mut()
            .ok_or("prompt parameters must be an object")?;
        object.remove("arguments_json");
        object.insert("arguments".into(), arguments);
    }
    Ok(params)
}

fn definite_result(id: String, content: String, is_error: bool) -> core_tools::ToolExecution {
    core_tools::ToolExecution::Definite(ToolResult {
        tool_use_id: id,
        content,
        is_error,
        trust: Trust::Untrusted,
        latency_ms: 0,
    })
}

fn definite_mcp_error(error: core_mcp::McpError) -> core_mcp::McpToolOutcome {
    core_mcp::McpToolOutcome::FailedDefinite {
        error,
        evidence: None,
    }
}

fn resolve_executable(command: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(command);
    if path.is_absolute() {
        return path
            .is_file()
            .then(|| path.to_path_buf())
            .ok_or_else(|| anyhow::anyhow!("MCP executable `{command}` does not exist"));
    }
    let Some(path_value) = std::env::var_os("PATH") else {
        anyhow::bail!("MCP executable `{command}` is relative and PATH is unavailable")
    };
    std::env::split_paths(&path_value)
        .map(|directory| directory.join(command))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| anyhow::anyhow!("MCP executable `{command}` was not found on PATH"))
}

#[cfg(all(test, unix))]
#[path = "session/tests.rs"]
mod tests;

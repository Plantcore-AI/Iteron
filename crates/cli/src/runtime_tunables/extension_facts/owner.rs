use super::{ExtensionFactError, ExtensionFactsInput, McpTransport};
use crate::config::McpTransportConfig;
use core_tunables::CapabilityRequirement;
use serde::Serialize;
use std::collections::BTreeSet;

/// Secret-free snapshot of the concrete owners used by activation evidence. Configuration URLs,
/// commands, arguments, environment-variable names, OAuth material and conversation content never
/// enter this object.
#[derive(Debug, Serialize)]
pub(super) struct OwnerSnapshot {
    route_attestation_digest_sha256: String,
    route_capabilities: BTreeSet<CapabilityRequirement>,
    model_effort_attested: Option<bool>,
    child_overlay: Option<super::ChildOverlayObservation>,
    run_max_concurrency: usize,
    run_max_agent_calls: usize,
    session_spawn_limit: usize,
    session_spawns_admitted: usize,
    registered_tool_names: BTreeSet<String>,
    configured_mcp_count: usize,
    configured_transports: BTreeSet<McpTransport>,
    oauth_server_count: usize,
    mcp_reconnect: core_mcp::reconnect::ReconnectPolicy,
    mcp_deadlines: core_mcp::McpDeadlinePolicy,
    mcp_result_policy: core_mcp::McpResultPolicy,
    early_stop_quorum: core_workflow::EarlyStopQuorumPolicy,
    speculative_siblings: core_workflow::SpeculativeSiblingPolicy,
    task_retry: core_workflow::TaskRetryPolicy,
    writer_merge: core_workflow::WriterMergePolicy,
    live_mcp_server_count: usize,
    resource_prompt_surface: bool,
    session_profile: super::SessionIsolationProfile,
    replay_owner: super::ReplayOwnerObservation,
}

impl OwnerSnapshot {
    pub(super) fn capture(input: &ExtensionFactsInput<'_>) -> Result<Self, ExtensionFactError> {
        let registered_tool_names = input
            .registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let configured_transports = input
            .configured_mcp
            .iter()
            .map(|server| match server.transport {
                McpTransportConfig::Stdio => McpTransport::Stdio,
                McpTransportConfig::Http => McpTransport::Http,
            })
            .collect::<BTreeSet<_>>();
        let live_mcp_server_count = input
            .configured_mcp
            .iter()
            .filter(|server| {
                let prefix = format!("{}__", server.name);
                registered_tool_names
                    .iter()
                    .any(|tool| tool.starts_with(&prefix))
            })
            .count();
        let resource_prompt_surface = registered_tool_names.iter().any(|name| {
            name.ends_with("__resources_list")
                || name.ends_with("__resources_read")
                || name.ends_with("__prompts_list")
                || name.ends_with("__prompts_get")
        });

        Ok(Self {
            route_attestation_digest_sha256: input.route.attestation_digest_sha256.clone(),
            route_capabilities: input.route.capabilities.clone(),
            model_effort_attested: input.model_capabilities.semantic_effort,
            child_overlay: input.child_overlay.cloned(),
            run_max_concurrency: input.run_limits.max_concurrency(),
            run_max_agent_calls: input.run_limits.max_agent_calls(),
            session_spawn_limit: input.session_spawn_ledger.limit(),
            session_spawns_admitted: input.session_spawn_ledger.admitted(),
            registered_tool_names,
            configured_mcp_count: input.configured_mcp.len(),
            configured_transports,
            oauth_server_count: input
                .configured_mcp
                .iter()
                .filter(|server| server.oauth.is_some())
                .count(),
            mcp_reconnect: input.mcp_reconnect,
            mcp_deadlines: input.mcp_deadlines,
            mcp_result_policy: input.mcp_result_policy,
            early_stop_quorum: input.early_stop_quorum,
            speculative_siblings: input.speculative_siblings,
            task_retry: input.task_retry,
            writer_merge: input.writer_merge,
            live_mcp_server_count,
            resource_prompt_surface,
            session_profile: input.session_profile,
            replay_owner: input.replay_owner,
        })
    }

    pub(super) fn collaboration_active(&self) -> bool {
        self.route_capabilities
            .contains(&CapabilityRequirement::AgentSpawn)
    }

    pub(super) fn configured_mcp(&self) -> bool {
        self.configured_mcp_count > 0
    }

    pub(super) fn tool_search_surface(&self) -> bool {
        self.registered_tool_names.contains("tool_search")
    }

    pub(super) fn live_mcp(&self) -> bool {
        self.live_mcp_server_count > 0
    }

    pub(super) fn oauth_configured(&self) -> bool {
        self.oauth_server_count > 0
    }

    pub(super) fn resource_prompt_surface(&self) -> bool {
        self.resource_prompt_surface
    }

    pub(super) fn digest_for(
        &self,
        family: &'static str,
        state: &'static str,
    ) -> Result<String, ExtensionFactError> {
        super::value::owner_digest("extension-activation-v1", &(family, state, self))
    }
}

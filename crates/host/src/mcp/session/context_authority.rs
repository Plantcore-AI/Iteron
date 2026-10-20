//! Scoped operator authority; never derived from tool content, annotations or permission prose.
use super::*;
use iteron_protocol::ToolUse;

pub(crate) struct ContextEgressAuthority {
    pub(crate) binding: String,
    pub(crate) preapproved_gateway: bool,
}

#[cfg(feature = "legacy-plantcore")]
pub(super) struct ManagedGatewayDelegation {
    binding: String,
    gate: Arc<crate::runtime::DispatchGate>,
}

impl McpRuntimeControl {
    /// Return the content-free checkpoint binding only for an explicitly granted, already
    /// searched ordinary MCP tool. Busy/stopped/unconfigured/legacy sessions fail closed.
    /// The actual executor still verifies the searched identity and generation before dispatch.
    pub(crate) fn context_egress_binding(&self, call: &ToolUse) -> Option<ContextEgressAuthority> {
        let server_name = call.name.strip_suffix("__tool_call")?;
        let server = self.servers.get(server_name)?;
        let config = server.config();
        config.validate_context_egress().ok()?;
        let exposure = self.exposure.get()?;
        if exposure.server_binding_ids.is_empty()
            || !server_identity_admitted(&self.exposure, server)
        {
            return None;
        }
        #[cfg(feature = "legacy-plantcore")]
        let managed = if server_name == "plantcore-run-gateway" {
            let grant = self.managed_gateway.get()?;
            if grant.binding != config.runtime_binding_id().ok()?.as_str()
                || grant.gate.submit_if_admitted(|| Ok::<_, ()>(())).is_err()
            {
                return None;
            }
            true
        } else {
            false
        };
        #[cfg(not(feature = "legacy-plantcore"))]
        let managed = false;
        let name = call
            .input
            .get(if managed { "handle" } else { "name" })?
            .as_str()?;
        let prefix = format!("{server_name}__");
        let bare = name.strip_prefix(&prefix).unwrap_or(name);
        if (!managed
            && !config
                .context_egress_tools
                .iter()
                .any(|grant| grant == bare))
            || !config
                .policy
                .admits(host_ceiling(), bare, Capability::IrreversibleExternal)
        {
            return None;
        }
        let namespaced = format!("{prefix}{bare}");
        let searched = match server.as_ref() {
            ManagedServer::Stdio(server) => {
                let state = server.state.try_lock().ok()?;
                !state.stopped
                    && server.dispatch_admitted()
                    && state.identities.contains_key(&namespaced)
            }
            ManagedServer::Http(server) => {
                let state = server.state.try_lock().ok()?;
                !state.stopped
                    && server.dispatch_admitted()
                    && state.identities.contains_key(&namespaced)
            }
        };
        searched
            .then(|| {
                config
                    .runtime_binding_id()
                    .ok()
                    .map(|id| ContextEgressAuthority {
                        binding: id.as_str().to_owned(),
                        preapproved_gateway: managed,
                    })
            })
            .flatten()
    }

    /// Only the verified resident bootstrap calls this seam. User MCP configuration, tool
    /// annotations and model text cannot mint a managed delegation. Gateway/Connector still
    /// enforce Run identity, package scope and any action approval; this is not a write grant.
    #[cfg(feature = "legacy-plantcore")]
    pub(crate) fn delegate_plantcore_gateway(
        &self,
        gate: Arc<crate::runtime::DispatchGate>,
    ) -> Result<(), &'static str> {
        if !self.is_exact_plantcore_run_gateway(
            "http://127.0.0.1:43171/mcp",
            "PLANTCORE_RUN_GATEWAY_AUTHORIZATION",
        ) {
            return Err("managed delegation requires the exact resident gateway");
        }
        let server = self
            .servers
            .get("plantcore-run-gateway")
            .ok_or("missing gateway")?;
        if server.config().origin.label() != "operator" {
            return Err("managed delegation cannot originate from a plugin");
        }
        if self
            .exposure
            .get()
            .is_none_or(|exposure| exposure.server_binding_ids.is_empty())
            || !server_identity_admitted(&self.exposure, server)
        {
            return Err("managed delegation requires a checkpoint-bound gateway");
        }
        let binding = server
            .config()
            .runtime_binding_id()
            .map_err(|_| "invalid gateway binding")?
            .as_str()
            .to_owned();
        self.managed_gateway
            .set(ManagedGatewayDelegation { binding, gate })
            .map_err(|_| "managed delegation is immutable")
    }
}

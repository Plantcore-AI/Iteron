//! Scoped operator authority; never derived from tool content, annotations or permission prose.
use super::*;
use iteron_protocol::ToolUse;

impl McpRuntimeControl {
    /// Return the content-free checkpoint binding only for an explicitly granted, already
    /// searched ordinary MCP tool. Busy/stopped/unconfigured/legacy sessions fail closed.
    /// The actual executor still verifies the searched identity and generation before dispatch.
    pub(crate) fn context_egress_binding(&self, call: &ToolUse) -> Option<String> {
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
        let name = call.input.get("name")?.as_str()?;
        let prefix = format!("{server_name}__");
        let bare = name.strip_prefix(&prefix).unwrap_or(name);
        if !config
            .context_egress_tools
            .iter()
            .any(|grant| grant == bare)
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
                    .map(|id| id.as_str().to_owned())
            })
            .flatten()
    }
}

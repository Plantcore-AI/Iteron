use super::Agent;

impl Agent {
    /// Install the one MCP runtime composed alongside this agent's registry.
    ///
    /// The handle is clone-backed, so the app server can retain an immediate control port while a
    /// turn holds `&mut Agent`; every clone still addresses the same per-session server actors.
    pub(crate) fn install_mcp_runtime(
        &mut self,
        runtime: crate::mcp::McpRuntimeControl,
    ) -> Result<(), &'static str> {
        if self.mcp_runtime.is_some() {
            return Err("MCP runtime is already installed for this session");
        }
        self.mcp_runtime = Some(runtime);
        Ok(())
    }

    pub(crate) fn mcp_runtime_control(&self) -> Option<crate::mcp::McpRuntimeControl> {
        self.mcp_runtime.clone()
    }

    pub(crate) fn mcp_health(&self) -> Vec<crate::mcp::McpServerHealth> {
        self.mcp_runtime
            .as_ref()
            .map_or_else(Vec::new, crate::mcp::McpRuntimeControl::health)
    }

    pub(crate) async fn cleanup_mcp_spills(
        &self,
        boundary: core_mcp::McpSpillCleanup,
    ) -> Result<(), super::KernelError> {
        match &self.mcp_runtime {
            Some(runtime) => runtime
                .cleanup_spills(boundary)
                .await
                .map_err(|_| super::KernelError::McpLifecycle("private spill cleanup failed")),
            None => Ok(()),
        }
    }
}

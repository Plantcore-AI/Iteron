//! One host-installed plugin management/mask port is shared by all inherited runtime surfaces.
use super::{Agent,KernelError};
use crate::plugin_runtime::PluginManagementOwner;
use iteron_protocol::extension_dispatch::{ExtensionDispatchPolicy,ExtensionSurfaceV1};
use std::sync::Arc;
impl Agent {
    pub(crate) fn install_plugin_management(&mut self, owner:Arc<PluginManagementOwner>)->Result<(),KernelError> {
        if let Some(current)=&self.plugin_management {
            if Arc::ptr_eq(current,&owner) { return Ok(()); }
            return Err(KernelError::ContextResolution("plugin management owner already installed".into()));
        }
        let policy=owner.dispatch_policy();
        self.hooks.install_extension_dispatch_policy(policy.clone()).map_err(|reason|KernelError::ContextResolution(reason.into()))?;
        if let Some(mcp)=self.mcp_runtime_control() {mcp.install_extension_dispatch_policy(policy.clone()).map_err(|reason|KernelError::ContextResolution(reason.into()))?;}
        if let Some(lsp)=self.registry.lsp_control() {lsp.install_extension_dispatch_policy(policy).map_err(|_|KernelError::ContextResolution("language-server extension dispatch policy refused".into()))?;}
        self.plugin_management=Some(owner);Ok(())
    }
    pub(crate) fn plugin_management_port(&self)->Option<Arc<PluginManagementOwner>> {self.plugin_management.clone()}
    pub(crate) fn extension_dispatch_policy(&self)->Option<Arc<dyn ExtensionDispatchPolicy>> {self.plugin_management.as_ref().map(|owner|owner.dispatch_policy())}
    pub(super) fn eligible_dependency_skill_dirs(&self)->Option<Vec<(std::path::PathBuf,std::path::PathBuf)>> {
        let policy=self.extension_dispatch_policy()?;
        Some(self.dependency_skill_dirs.iter().filter(|(_,directory)| directory.file_name().and_then(|name|name.to_str()).is_some_and(|name|policy.admits(ExtensionSurfaceV1::Skill,name))).cloned().collect())
    }
}

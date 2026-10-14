//! Verified materialization owns a finite binding table and irreversible current-generation revocations.
use iteron_protocol::extension_dispatch::{ExtensionDispatchPolicy, ExtensionSurfaceV1};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Default, Debug)]
pub(crate) struct DispatchMask {
    bindings: BTreeMap<(ExtensionSurfaceV1, String), BTreeSet<String>>,
    plugins: BTreeSet<String>,
    revoked: Mutex<BTreeSet<String>>,
}
impl DispatchMask {
    pub(super) fn register_plugin(&mut self, plugin: &str) -> Result<(), &'static str> {
        if self.plugins.len() >= 128 && !self.plugins.contains(plugin) {
            return Err("plugin_dispatch_capacity");
        }
        self.plugins.insert(plugin.into());
        Ok(())
    }
    pub(super) fn bind(
        &mut self,
        plugin: &str,
        surface: ExtensionSurfaceV1,
        key: &str,
    ) -> Result<(), &'static str> {
        if !self.plugins.contains(plugin) {
            return Err("unverified_plugin_binding");
        }
        if self.bindings.len() >= 1024 && !self.bindings.contains_key(&(surface, key.to_string())) {
            return Err("plugin_binding_capacity");
        }
        self.bindings
            .entry((surface, key.into()))
            .or_default()
            .insert(plugin.into());
        Ok(())
    }
    pub(super) fn revoke(&self, plugin: &str) -> bool {
        if !self.plugins.contains(plugin) {
            return false;
        }
        self.revoked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(plugin.into());
        true
    }
    pub(super) fn is_revoked(&self, plugin: &str) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(plugin)
    }
}
impl ExtensionDispatchPolicy for DispatchMask {
    fn admits(&self, surface: ExtensionSurfaceV1, key: &str) -> bool {
        let Some(plugins) = self.bindings.get(&(surface, key.to_string())) else {
            return true;
        };
        let revoked = self
            .revoked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        plugins.is_disjoint(&revoked)
    }
}
pub(crate) fn hook_key(event: &str, command: &str) -> String {
    format!(
        "{event}/{}",
        hex::encode(Sha256::digest(command.as_bytes()))
    )
}
pub(super) fn surface(surface: iteron_marketplace::Surface) -> ExtensionSurfaceV1 {
    match surface {
        iteron_marketplace::Surface::Skill => ExtensionSurfaceV1::Skill,
        iteron_marketplace::Surface::Agent => ExtensionSurfaceV1::Agent,
        iteron_marketplace::Surface::Hook => ExtensionSurfaceV1::Hook,
        iteron_marketplace::Surface::McpServer => ExtensionSurfaceV1::McpServer,
        iteron_marketplace::Surface::LanguageServer => ExtensionSurfaceV1::LanguageServer,
        iteron_marketplace::Surface::Implementation => ExtensionSurfaceV1::Implementation,
        iteron_marketplace::Surface::Tool => ExtensionSurfaceV1::Tool,
        iteron_marketplace::Surface::Provider => ExtensionSurfaceV1::Provider,
        iteron_marketplace::Surface::Ui => ExtensionSurfaceV1::Ui,
        iteron_marketplace::Surface::EventSubscription => ExtensionSurfaceV1::EventSubscription,
    }
}
#[cfg(test)]
mod tests {
    use super::{DispatchMask, hook_key};
    use iteron_protocol::extension_dispatch::{ExtensionDispatchPolicy, ExtensionSurfaceV1};
    #[test]
    fn revocation_is_exact_shared_and_monotone_without_granting_unverified_bindings() {
        let mut mask = DispatchMask::default();
        mask.register_plugin("plugin").unwrap();
        let key = hook_key("PreToolUse", "true");
        mask.bind("plugin", ExtensionSurfaceV1::Hook, &key).unwrap();
        assert!(mask.admits(ExtensionSurfaceV1::Hook, &key));
        assert!(!mask.revoke("unverified"));
        assert!(mask.revoke("plugin"));
        assert!(!mask.admits(ExtensionSurfaceV1::Hook, &key));
        assert!(mask.admits(ExtensionSurfaceV1::Hook, &hook_key("Stop", "true")));
        assert!(mask.admits(ExtensionSurfaceV1::McpServer, "unrelated-user-server"));
        assert!(mask.revoke("plugin"));
    }
}

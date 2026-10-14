//! Identities captured from verified packages and successful runtime materialization.

use iteron_marketplace::{ActivePlugin, Binding, PluginScope, Surface};
use iteron_protocol::capability_set::CapabilitySet;
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_PACKAGES: usize = 128;
const MAX_BOUND_SURFACES: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimePluginIdentity {
    pub plugin_id: String,
    pub version: String,
    pub source: &'static str,
    pub scope: PluginScope,
    pub operator_precedence: u32,
    pub manifest_requested_capabilities: CapabilitySet,
    pub manifest_digest_sha256: String,
    /// SHA-256 of serde JSON for the verified parsed manifest; not the raw package-file hash.
    pub digest_kind: &'static str,
    pub bound_surfaces: Vec<RuntimePluginBinding>,
    pub context_cost: serde_json::Value,
    pub failure_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimePluginBinding {
    pub surface: Surface,
    pub key: String,
    /// The actual composed intersection; dispatch still checks operation/task ceilings.
    pub composed_capabilities: CapabilitySet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler_digest_sha256: Option<String>,
}

#[derive(Default)]
pub(super) struct PluginInventory {
    entries: Vec<RuntimePluginIdentity>,
}

impl PluginInventory {
    pub(super) fn identity(&self, plugin: &str) -> Option<&RuntimePluginIdentity> {
        self.entries
            .iter()
            .find(|identity| identity.plugin_id == plugin)
    }
    pub(super) fn register(&mut self, plugin: &ActivePlugin) -> Result<(), &'static str> {
        if self
            .entries
            .iter()
            .any(|entry| entry.plugin_id == plugin.manifest.plugin)
        {
            return Ok(());
        }
        if self.entries.len() >= MAX_PACKAGES {
            return Err("verified plugin inventory capacity exceeded");
        }
        let bytes = serde_json::to_vec(&plugin.manifest)
            .map_err(|_| "verified manifest identity unavailable")?;
        if bytes.len() > iteron_marketplace::MAX_PLUGIN_MANIFEST_BYTES {
            return Err("verified manifest identity exceeds its bound");
        }
        self.entries.push(RuntimePluginIdentity {
            plugin_id: plugin.manifest.plugin.clone(),
            version: plugin.manifest.version.to_string(),
            source: "signature_verified_plugin_store",
            scope: plugin.manifest.scope,
            operator_precedence: plugin.manifest.precedence,
            manifest_requested_capabilities: plugin.manifest.capabilities,
            manifest_digest_sha256: hex::encode(Sha256::digest(bytes)),
            digest_kind: "parsed_manifest_serde_json_sha256_v1",
            bound_surfaces: Vec::new(),
            context_cost: serde_json::json!({"charged_prompt_tokens":null,"cost_status":"not_attributed_per_package","accounting":"actual tool/provider ledgers"}),
            failure_policy: "per-surface host owner; installed hook policies available through Hooks inventory; no ordinary core-loop override",
        });
        Ok(())
    }

    pub(super) fn bound(
        &mut self,
        plugin: &str,
        surface: Surface,
        key: &str,
        capabilities: CapabilitySet,
        handler_digest_sha256: Option<String>,
    ) {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.plugin_id == plugin)
        else {
            return;
        };
        let binding = RuntimePluginBinding {
            surface,
            key: key.to_owned(),
            composed_capabilities: capabilities,
            handler_digest_sha256,
        };
        if !entry.bound_surfaces.contains(&binding)
            && entry.bound_surfaces.len() < MAX_BOUND_SURFACES
        {
            entry.bound_surfaces.push(binding);
        }
    }

    pub(super) fn bound_composed(&mut self, binding: &Binding) {
        let digest = (binding.slot.surface == Surface::Hook)
            .then(|| hex::encode(Sha256::digest(binding.detail.as_bytes())));
        self.bound(
            &binding.plugin,
            binding.slot.surface,
            &binding.slot.key,
            binding.capabilities,
            digest,
        );
    }

    pub(super) fn snapshot(&self) -> Vec<RuntimePluginIdentity> {
        self.entries.clone()
    }
}

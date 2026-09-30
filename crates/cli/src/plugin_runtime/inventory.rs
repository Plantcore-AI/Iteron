//! Identities captured from verified packages and successful runtime materialization.

use iteron_marketplace::{ActivePlugin, Surface};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_PACKAGES: usize = 128;
const MAX_BOUND_SURFACES: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimePluginIdentity {
    pub plugin_id: String,
    pub version: String,
    pub manifest_digest_sha256: String,
    /// SHA-256 of serde JSON for the verified parsed manifest; not the raw package-file hash.
    pub digest_kind: &'static str,
    pub bound_surfaces: Vec<RuntimePluginBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimePluginBinding {
    pub surface: Surface,
    pub key: String,
}

#[derive(Default)]
pub(super) struct PluginInventory {
    entries: Vec<RuntimePluginIdentity>,
}

impl PluginInventory {
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
            manifest_digest_sha256: hex::encode(Sha256::digest(bytes)),
            digest_kind: "parsed_manifest_serde_json_sha256_v1",
            bound_surfaces: Vec::new(),
        });
        Ok(())
    }

    pub(super) fn bound(&mut self, plugin: &str, surface: Surface, key: &str) {
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
        };
        if !entry.bound_surfaces.contains(&binding)
            && entry.bound_surfaces.len() < MAX_BOUND_SURFACES
        {
            entry.bound_surfaces.push(binding);
        }
    }

    pub(super) fn snapshot(&self) -> Vec<RuntimePluginIdentity> {
        self.entries.clone()
    }
}

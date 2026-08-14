use super::CandidateFile;
use iteron_marketplace::{ActivePlugin, ImplementationActivation, Surface, Wiring};
use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use std::collections::BTreeMap;

const ACTIVATION_PATH: &str = "implementations/activation.json";
const CATALOG_PATH: &str = "implementations/catalog.json";

pub(crate) struct VerifiedImplementationActivation {
    activation: ImplementationActivation,
    activation_sha256: String,
    plugin_governed: bool,
}

impl VerifiedImplementationActivation {
    pub(crate) fn from_candidate(
        candidate: &CandidateFile,
        host_ceiling: CapabilitySet,
    ) -> anyhow::Result<Self> {
        let activation = ImplementationActivation::from_json(candidate.bytes(), host_ceiling)
            .map_err(|error| anyhow::anyhow!("implementation activation refused: {error}"))?;
        if activation.is_empty() {
            anyhow::bail!("implementation activation has no verified launch plans");
        }
        Ok(Self {
            activation,
            activation_sha256: candidate.digest_sha256().to_owned(),
            plugin_governed: false,
        })
    }

    pub(crate) fn activation(&self) -> &ImplementationActivation {
        &self.activation
    }

    pub(crate) fn activation_sha256(&self) -> &str {
        &self.activation_sha256
    }

    pub(crate) fn is_plugin_governed(&self) -> bool {
        self.plugin_governed
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        activation: ImplementationActivation,
        activation_sha256: String,
    ) -> Self {
        Self {
            activation,
            activation_sha256,
            plugin_governed: true,
        }
    }
}

pub(super) fn materialize(
    wiring: &Wiring,
    roots: &BTreeMap<&str, &ActivePlugin>,
    host_ceiling: CapabilitySet,
    candidate: Option<CandidateFile>,
) -> anyhow::Result<Option<VerifiedImplementationActivation>> {
    let selected = wiring
        .slots()
        .into_iter()
        .filter(|slot| slot.surface == Surface::Implementation)
        .map(|slot| {
            let module = ModuleId::parse(&slot.key)
                .ok_or_else(|| anyhow::anyhow!("implementation slot has an unknown module"))?;
            let binding = wiring
                .implementation(module)
                .ok_or_else(|| anyhow::anyhow!("implementation slot has no winning binding"))?;
            let plugin = roots
                .get(binding.plugin.as_str())
                .copied()
                .ok_or_else(|| anyhow::anyhow!("implementation winner has no verified root"))?;
            Ok((module, binding, plugin))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if selected.is_empty() {
        if candidate.is_some() {
            anyhow::bail!("implementation candidate is not tied to a winning plugin binding");
        }
        return Ok(None);
    }
    let candidate = candidate.ok_or_else(|| {
        anyhow::anyhow!(
            "a plugin implementation won composition, but no operator-owned --implementation-candidate was supplied"
        )
    })?;
    let mut verified = VerifiedImplementationActivation::from_candidate(&candidate, host_ceiling)?;
    let activation = verified.activation();
    if activation.is_empty() || activation.len() != selected.len() {
        anyhow::bail!("implementation activation does not exactly cover the winning bindings");
    }

    for (module, binding, plugin) in selected {
        if !binding.capabilities.contains(Capability::CodeExecuting) {
            anyhow::bail!(
                "plugin {} implementation {} lacks admitted code_executing capability",
                binding.plugin,
                binding.detail
            );
        }
        if candidate.path() != plugin.artifact_root.join(ACTIVATION_PATH) {
            anyhow::bail!(
                "implementation candidate is not the fixed activation file of winning plugin {}",
                binding.plugin
            );
        }
        let plan = activation.plan(module).ok_or_else(|| {
            anyhow::anyhow!("implementation activation omits {}", module.as_str())
        })?;
        let identity = activation.identity(module).ok_or_else(|| {
            anyhow::anyhow!("implementation activation lost verified source identity")
        })?;
        if plan.implementation_id() != binding.detail
            || identity.implementation_id() != binding.detail
            || plan.module() != module
            || identity.module() != module
            || !plan
                .admitted_capabilities()
                .contains(Capability::CodeExecuting)
        {
            anyhow::bail!(
                "plugin {} implementation binding does not match its verified launch plan",
                binding.plugin
            );
        }
        let expected_catalog = plugin.artifact_root.join(CATALOG_PATH);
        let expected_root = plugin
            .artifact_root
            .join("implementations/artifacts")
            .join(plan.implementation_id());
        if identity.catalog_path() != expected_catalog || identity.artifact_root() != expected_root
        {
            anyhow::bail!(
                "plugin {} implementation source escapes the fixed catalog/artifact layout",
                binding.plugin
            );
        }
    }
    verified.plugin_governed = true;
    Ok(Some(verified))
}

//! Verified plugin composition at the CLI's trusted startup root.

#[path = "plugin_runtime/candidate.rs"]
mod candidate;
#[path = "plugin_runtime/implementation.rs"]
mod implementation;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iteron_marketplace::{
    ActivePlugin, Binding, Contribution, PluginStore, RuntimeScope, Slot, Surface, Wiring,
    compose_governed,
};

pub(crate) use candidate::CandidateFile;
pub(crate) use implementation::VerifiedImplementationActivation;
pub(crate) mod dispatch;
mod management;
#[cfg(all(test, unix))]
mod management_tests;
pub(crate) use management::PluginManagementOwner;
#[cfg(all(test, unix))]
pub(crate) use management_tests::installed_fixture;
mod inventory;
pub(crate) use inventory::RuntimePluginIdentity;

/// Capability token for minting [`crate::config::McpServerOrigin`] plugin provenance. Its fields
/// and constructor are private to this verified materialization module; config parsing and other
/// runtime callers can neither deserialize nor synthesize one.
pub(crate) struct VerifiedMcpPluginOrigin<'a> {
    plugin: &'a ActivePlugin,
}

impl<'a> VerifiedMcpPluginOrigin<'a> {
    fn new(plugin: &'a ActivePlugin) -> Self {
        Self { plugin }
    }

    pub(crate) fn plugin_id(&self) -> &str {
        &self.plugin.manifest.plugin
    }

    pub(crate) fn version(&self) -> String {
        self.plugin.manifest.version.to_string()
    }
}
use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;

use crate::config::{McpServerConfig, McpTransportConfig};

const MAX_RUNTIME_DIAGNOSTICS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentArtifact {
    pub name: String,
    pub root: PathBuf,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillArtifact {
    pub name: String,
    pub root: PathBuf,
    pub directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LspRoute {
    pub language: String,
    pub command: Vec<String>,
}

#[derive(Default)]
pub(crate) struct RuntimePlugins {
    inventory: inventory::PluginInventory,
    dispatch_mask: Option<std::sync::Arc<dispatch::DispatchMask>>,
    store_root: Option<PathBuf>,
    composition: serde_json::Value,
    captured_configuration: serde_json::Value,
    prepared_installs: BTreeMap<String, iteron_marketplace::PreparedPluginInstall>,
    management: Option<std::sync::Arc<PluginManagementOwner>>,
    pub mcp_servers: Vec<McpServerConfig>,
    pub hooks: BTreeMap<String, Vec<String>>,
    pub agents: Vec<AgentArtifact>,
    pub skills: Vec<SkillArtifact>,
    pub lsp_routes: Vec<LspRoute>,
    pub diagnostics: Vec<String>,
    pub implementation: Option<VerifiedImplementationActivation>,
}

impl RuntimePlugins {
    pub(crate) fn inventory_snapshot(&self) -> Vec<RuntimePluginIdentity> {
        self.inventory.snapshot()
    }
    /// Materialize an operator-supplied research activation without consulting ambient plugin
    /// state. The explicit CLI path and digest are the operator-intent boundary for this mode;
    /// marketplace verification still owns catalog, manifest, artifact, and capability checks.
    pub(crate) fn research(
        candidate: CandidateFile,
        host_ceiling: CapabilitySet,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            implementation: Some(VerifiedImplementationActivation::from_candidate(
                &candidate,
                host_ceiling,
            )?),
            ..Self::default()
        })
    }

    pub(crate) fn load(
        root: Option<&Path>,
        host_ceiling: CapabilitySet,
        candidate: Option<CandidateFile>,
    ) -> anyhow::Result<Self> {
        let Some(root) = root else {
            if candidate.is_some() {
                anyhow::bail!("implementation candidate has no configured plugin store");
            }
            return Ok(Self::default());
        };
        let store = PluginStore::new(root);
        let packages = match store.runtime_packages() {
            Ok(packages) => packages,
            Err(error) => {
                if candidate.is_some() {
                    anyhow::bail!("implementation candidate plugin store refused: {error}");
                }
                return Ok(Self {
                    diagnostics: vec![format!("plugin store refused: {error}")],
                    ..Self::default()
                });
            }
        };
        let manifests = packages
            .active
            .iter()
            .map(|plugin| plugin.manifest.clone())
            .collect::<Vec<_>>();
        let composition = compose_governed(&manifests, RuntimeScope::Workspace, host_ceiling);
        let binding_count = composition.wiring.slots().len().saturating_add(
            composition
                .wiring
                .events()
                .iter()
                .map(|event| composition.wiring.hooks(event).len())
                .sum::<usize>(),
        );
        if binding_count > 1024 {
            anyhow::bail!("verified plugin dispatch binding capacity exceeded");
        }
        let roots = packages
            .active
            .iter()
            .map(|plugin| (plugin.manifest.plugin.as_str(), plugin))
            .collect::<BTreeMap<_, _>>();
        let mut runtime = Self {
            store_root: Some(root.to_path_buf()),
            ..Self::default()
        };
        if !roots.is_empty() {
            runtime.dispatch_mask = Some(std::sync::Arc::new(dispatch::DispatchMask::default()));
        }
        runtime.captured_configuration = serde_json::to_value(&packages.captured_configuration)
            .map_err(|_| anyhow::anyhow!("captured plugin registry unavailable"))?;
        runtime.composition = serde_json::json!({
            "source":"actual_verified_bootstrap_composition",
            "conflicts":composition.report.contests().iter().take(256).map(|contest|serde_json::json!({"surface":contest.slot.surface,"key":contest.slot.key,"winner":contest.winner,"shadowed":contest.shadowed,"arbitration":format!("{:?}",contest.arbitration)})).collect::<Vec<_>>(),
            "refusals":composition.report.refusals().iter().take(256).map(|refusal|bounded_refusal_display(&refusal.to_string())).collect::<Vec<_>>()
        });
        for plugin in roots.values() {
            std::sync::Arc::get_mut(
                runtime
                    .dispatch_mask
                    .as_mut()
                    .expect("verified plugins own mask"),
            )
            .expect("bootstrap mask is private")
            .register_plugin(&plugin.manifest.plugin)
            .map_err(anyhow::Error::msg)?;
            runtime
                .inventory
                .register(plugin)
                .map_err(anyhow::Error::msg)?;
        }
        for quarantine in packages.quarantined {
            runtime.note(format!("plugin quarantined: {quarantine}"));
        }
        for refusal in composition.report.refusals() {
            runtime.note(format!("plugin refused: {refusal}"));
        }
        for contest in composition.report.contests() {
            runtime.note(format!(
                "plugin conflict: {} -> {} (shadowed: {})",
                contest.slot,
                contest.winner,
                contest.shadowed.join(", ")
            ));
        }
        runtime.materialize_non_implementations(&composition.wiring, &roots);
        runtime.implementation =
            implementation::materialize(&composition.wiring, &roots, host_ceiling, candidate)?;
        if runtime
            .implementation
            .as_ref()
            .is_some_and(VerifiedImplementationActivation::is_plugin_governed)
        {
            for slot in composition
                .wiring
                .slots()
                .into_iter()
                .filter(|slot| slot.surface == Surface::Implementation)
            {
                if let Some(binding) = binding_for(&composition.wiring, &slot) {
                    runtime.record_binding(&binding.plugin, slot.surface, &slot.key);
                }
            }
        }
        if let Some(implementation) = runtime.implementation.as_mut() {
            implementation.bind_dispatch_policy(runtime.dispatch_mask.as_ref().map(|mask| {
                mask.clone()
                    as std::sync::Arc<
                        dyn iteron_protocol::extension_dispatch::ExtensionDispatchPolicy,
                    >
            }));
        }
        Ok(runtime)
    }

    fn record_binding(&mut self, plugin: &str, surface: Surface, key: &str) {
        self.inventory.bound(plugin, surface, key);
        if !matches!(surface, Surface::Hook | Surface::LanguageServer) {
            std::sync::Arc::get_mut(
                self.dispatch_mask
                    .as_mut()
                    .expect("verified plugins own mask"),
            )
            .expect("bootstrap mask is private")
            .bind(plugin, dispatch::surface(surface), key)
            .expect("bounded verified materialized binding");
        }
    }
    pub(crate) fn dispatch_policy(
        &self,
    ) -> Option<std::sync::Arc<dyn iteron_protocol::extension_dispatch::ExtensionDispatchPolicy>>
    {
        self.dispatch_mask.as_ref().map(|mask| {
            mask.clone()
                as std::sync::Arc<dyn iteron_protocol::extension_dispatch::ExtensionDispatchPolicy>
        })
    }
    pub(crate) fn prepare_package_install(
        &mut self,
        operator_path: &Path,
    ) -> Result<String, &'static str> {
        if self.management.is_some() {
            return Err("plugin_bootstrap_already_captured");
        }
        if self.prepared_installs.len() >= 16 {
            return Err("prepared_install_capacity");
        }
        let root = self.store_root.as_ref().ok_or("plugin_store_unavailable")?;
        let receipt = PluginStore::new(root)
            .prepare_install(operator_path)
            .map_err(|_| "plugin_candidate_verification_refused")?;
        let digest = &receipt.artifact().digest;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("plugin_candidate_identity_refused");
        }
        let id = format!(
            "prepared-{}-{}-{}-{}",
            &digest[..16],
            &digest[16..32],
            &digest[32..48],
            &digest[48..]
        );
        self.prepared_installs.insert(id.clone(), receipt);
        Ok(id)
    }
    pub(crate) fn management_port(
        &mut self,
    ) -> Result<Option<std::sync::Arc<PluginManagementOwner>>, &'static str> {
        if let Some(owner) = &self.management {
            return Ok(Some(owner.clone()));
        }
        let Some(root) = &self.store_root else {
            return Ok(None);
        };
        if self.prepared_installs.is_empty()
            && self.captured_configuration["plugins"]
                .as_array()
                .is_none_or(Vec::is_empty)
        {
            return Ok(None);
        }
        let mask = self
            .dispatch_mask
            .get_or_insert_with(|| std::sync::Arc::new(dispatch::DispatchMask::default()))
            .clone();
        let owner = PluginManagementOwner::new(
            root,
            mask,
            self.inventory_snapshot(),
            self.composition.clone(),
            self.captured_configuration.clone(),
            std::mem::take(&mut self.prepared_installs),
        )?;
        self.management = Some(owner.clone());
        Ok(Some(owner))
    }

    fn materialize_non_implementations(
        &mut self,
        wiring: &Wiring,
        roots: &BTreeMap<&str, &ActivePlugin>,
    ) {
        for slot in wiring.slots() {
            let Some(binding) = binding_for(wiring, slot) else {
                continue;
            };
            let Some(plugin) = roots.get(binding.plugin.as_str()).copied() else {
                self.note(format!(
                    "plugin {} has no verified artifact root",
                    binding.plugin
                ));
                continue;
            };
            match slot.surface {
                Surface::Skill => self.skill(slot, binding, plugin),
                Surface::Agent => self.agent(slot, binding, plugin),
                Surface::McpServer => self.mcp(slot, binding, plugin),
                Surface::LanguageServer => self.lsp(slot, binding),
                Surface::Implementation => {}
                Surface::Hook => unreachable!("hook slots are chains"),
            }
        }
        for event in wiring.events() {
            for binding in wiring.hooks(event) {
                if !binding.capabilities.contains(Capability::CodeExecuting) {
                    self.note(format!(
                        "plugin {} hook {event:?} refused: code_executing capability not admitted",
                        binding.plugin
                    ));
                    continue;
                }
                self.hooks
                    .entry(event.to_owned())
                    .or_default()
                    .push(binding.detail.clone());
                self.record_binding(&binding.plugin, Surface::Hook, event);
                std::sync::Arc::get_mut(
                    self.dispatch_mask
                        .as_mut()
                        .expect("verified plugins own mask"),
                )
                .expect("bootstrap mask is private")
                .bind(
                    &binding.plugin,
                    iteron_protocol::extension_dispatch::ExtensionSurfaceV1::Hook,
                    &dispatch::hook_key(event, &binding.detail),
                )
                .expect("bounded verified hook binding");
            }
        }
    }

    fn skill(&mut self, slot: &Slot, binding: &Binding, plugin: &ActivePlugin) {
        if !binding.capabilities.contains(Capability::ReadOnly) {
            self.note(format!(
                "plugin {} skill {:?} refused: read_only capability not admitted",
                binding.plugin, slot.key
            ));
            return;
        }
        let directory = plugin.artifact_root.join("skills").join(&slot.key);
        if regular_file(&directory.join("SKILL.md")) {
            self.skills.push(SkillArtifact {
                name: slot.key.clone(),
                root: plugin.artifact_root.clone(),
                directory,
            });
            self.record_binding(&binding.plugin, Surface::Skill, &slot.key);
        } else {
            self.note(format!(
                "plugin {} skill {:?} refused: skills/{}/SKILL.md is missing",
                binding.plugin, slot.key, slot.key
            ));
        }
    }

    fn agent(&mut self, slot: &Slot, binding: &Binding, plugin: &ActivePlugin) {
        if !binding.capabilities.contains(Capability::ReadOnly) {
            self.note(format!(
                "plugin {} agent {:?} refused: read_only capability not admitted",
                binding.plugin, slot.key
            ));
            return;
        }
        let path = plugin
            .artifact_root
            .join("agents")
            .join(format!("{}.md", slot.key));
        if regular_file(&path) {
            self.agents.push(AgentArtifact {
                name: slot.key.clone(),
                root: plugin.artifact_root.clone(),
                path,
            });
            self.record_binding(&binding.plugin, Surface::Agent, &slot.key);
        } else {
            self.note(format!(
                "plugin {} agent {:?} refused: agents/{}.md is missing",
                binding.plugin, slot.key, slot.key
            ));
        }
    }

    fn mcp(&mut self, slot: &Slot, binding: &Binding, plugin: &ActivePlugin) {
        let parsed = serde_json::from_str::<McpServerConfig>(&binding.detail);
        match parsed {
            Ok(mut server) if server.name == slot.key => {
                let required = match server.transport {
                    McpTransportConfig::Stdio => Capability::CodeExecuting,
                    McpTransportConfig::Http => Capability::IrreversibleExternal,
                };
                if binding.capabilities.contains(required) {
                    // `origin` is serde-skipped and can therefore be minted only here, after the
                    // package signature, manifest identity, composition winner, and capability
                    // ceiling have all been verified.
                    server.origin = crate::config::McpServerOrigin::from_verified_plugin(
                        VerifiedMcpPluginOrigin::new(plugin),
                    );
                    self.mcp_servers.push(server);
                    self.record_binding(&binding.plugin, Surface::McpServer, &slot.key);
                } else {
                    self.note(format!(
                        "plugin {} MCP {:?} refused: {} capability not admitted",
                        binding.plugin,
                        slot.key,
                        match required {
                            Capability::CodeExecuting => "code_executing",
                            Capability::IrreversibleExternal => "irreversible_external",
                            _ => unreachable!("MCP transport requirement is exhaustive"),
                        }
                    ));
                }
            }
            Ok(_) => self.note(format!(
                "plugin {} MCP {:?} refused: binding name differs from its slot",
                binding.plugin, slot.key
            )),
            Err(error) => self.note(format!(
                "plugin {} MCP {:?} refused: invalid binding JSON ({error})",
                binding.plugin, slot.key
            )),
        }
    }

    fn lsp(&mut self, slot: &Slot, binding: &Binding) {
        if !binding.capabilities.contains(Capability::CodeExecuting) {
            self.note(format!(
                "plugin {} LSP {:?} refused: code_executing capability not admitted",
                binding.plugin, slot.key
            ));
            return;
        }
        match serde_json::from_str::<Vec<String>>(&binding.detail) {
            Ok(command)
                if !command.is_empty()
                    && command.len() <= 128
                    && command
                        .iter()
                        .all(|part| !part.is_empty() && part.len() <= 4096) =>
            {
                self.lsp_routes.push(LspRoute {
                    language: slot.key.clone(),
                    command,
                });
                self.record_binding(&binding.plugin, Surface::LanguageServer, &slot.key);
                let command_identity = self
                    .lsp_routes
                    .last()
                    .expect("route just materialized")
                    .command
                    .iter()
                    .map(|part| format!("'{}'", part.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                let key = iteron_protocol::extension_dispatch::language_server_dispatch_key(
                    &slot.key,
                    &command_identity,
                );
                std::sync::Arc::get_mut(
                    self.dispatch_mask
                        .as_mut()
                        .expect("verified plugins own mask"),
                )
                .expect("bootstrap mask is private")
                .bind(
                    &binding.plugin,
                    iteron_protocol::extension_dispatch::ExtensionSurfaceV1::LanguageServer,
                    &key,
                )
                .expect("bounded verified route binding");
            }
            _ => self.note(format!(
                "plugin {} LSP {:?} refused: command must be a bounded JSON argv array",
                binding.plugin, slot.key
            )),
        }
    }

    fn note(&mut self, diagnostic: String) {
        if self.diagnostics.len()
            < iteron_tunables::param_integer(
                "cli.plugin_runtime.max_runtime_diagnostics",
                MAX_RUNTIME_DIAGNOSTICS,
            )
        {
            self.diagnostics.push(diagnostic);
        }
    }
}

fn binding_for<'a>(wiring: &'a Wiring, slot: &Slot) -> Option<&'a Binding> {
    match slot.surface {
        Surface::Skill => wiring.skill(&slot.key),
        Surface::Agent => wiring.agent(&slot.key),
        Surface::McpServer => wiring.mcp_server(&slot.key),
        Surface::LanguageServer => wiring.language_server(&slot.key),
        Surface::Implementation => iteron_tunables::ModuleId::parse(&slot.key)
            .and_then(|module| wiring.implementation(module)),
        Surface::Hook => None,
    }
}

fn regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Used by package fixtures and documentation generators to keep artifact conventions exact.
#[allow(dead_code)]
fn contribution_artifact(contribution: &Contribution, root: &Path) -> Option<PathBuf> {
    match contribution {
        Contribution::Skill { name, .. } => Some(root.join("skills").join(name).join("SKILL.md")),
        Contribution::Agent { name, .. } => Some(root.join("agents").join(format!("{name}.md"))),
        Contribution::Hook { .. }
        | Contribution::McpServer { .. }
        | Contribution::LanguageServer { .. }
        | Contribution::Implementation { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_marketplace::{Manifest, compose};
    use sha2::Digest;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn every_manifest_surface_reaches_a_typed_runtime_binding() {
        let root = std::env::temp_dir().join(format!(
            "core-plugin-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("skills/review")).unwrap();
        std::fs::create_dir_all(root.join("agents")).unwrap();
        std::fs::write(root.join("skills/review/SKILL.md"), "skill").unwrap();
        std::fs::write(root.join("agents/reviewer.md"), "agent").unwrap();
        let capabilities = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]);
        let manifest = Manifest::new("complete", 10)
            .with_capabilities(capabilities)
            .with(Contribution::Skill {
                name: "review".into(),
                description: "review".into(),
            })
            .with(Contribution::Agent {
                name: "reviewer".into(),
                description: "review".into(),
            })
            .with(Contribution::Hook {
                event: "PreToolUse".into(),
                action: "check-tool".into(),
            })
            .with(Contribution::McpServer {
                name: "docs".into(),
                binding: r#"{"name":"docs","command":"docs-server","args":[]}"#.into(),
            })
            .with(Contribution::LanguageServer {
                language: "rust".into(),
                command: r#"["custom-rust-lsp","--stdio"]"#.into(),
            });
        let plugin = ActivePlugin {
            manifest: manifest.clone(),
            artifact_root: root.clone(),
        };
        let roots = BTreeMap::from([("complete", &plugin)]);
        let mut runtime = RuntimePlugins::default();
        runtime.inventory.register(&plugin).unwrap();
        runtime.dispatch_mask = Some(std::sync::Arc::new(dispatch::DispatchMask::default()));
        std::sync::Arc::get_mut(
            runtime
                .dispatch_mask
                .as_mut()
                .expect("verified plugins own mask"),
        )
        .unwrap()
        .register_plugin(&plugin.manifest.plugin)
        .unwrap();
        runtime.materialize_non_implementations(&compose(&[manifest]).wiring, &roots);
        assert_eq!(runtime.skills.len(), 1);
        assert_eq!(runtime.agents.len(), 1);
        assert_eq!(runtime.hooks["PreToolUse"], ["check-tool"]);
        assert_eq!(runtime.mcp_servers[0].name, "docs");
        assert_eq!(runtime.mcp_servers[0].origin.label(), "plugin");
        let identity = runtime.mcp_servers[0]
            .origin
            .plugin_binding_id("docs")
            .unwrap()
            .unwrap();
        assert!(identity.owns_server("docs"));
        assert_eq!(
            crate::config::PluginMcpBindingId::parse(identity.as_str()).unwrap(),
            identity
        );
        assert_eq!(runtime.lsp_routes[0].command[0], "custom-rust-lsp");
        assert!(runtime.diagnostics.is_empty(), "{:?}", runtime.diagnostics);
        let inventory = runtime.inventory_snapshot();
        assert_eq!(inventory[0].plugin_id, "complete");
        assert_eq!(inventory[0].bound_surfaces.len(), 5);
        assert_eq!(
            inventory[0].manifest_digest_sha256,
            hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&plugin.manifest).unwrap()
            ))
        );
        let metadata = serde_json::to_string(&inventory).unwrap();
        for private in ["check-tool", "custom-rust-lsp", "docs-server"] {
            assert!(!metadata.contains(private));
        }
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(
            serde_json::to_string(&runtime.inventory_snapshot()).unwrap(),
            metadata
        );
    }
}

fn bounded_refusal_display(raw: &str) -> String {
    let scrubbed = iteron_record::redact::scrub(raw);
    let mut take = scrubbed.len().min(512);
    while !scrubbed.is_char_boundary(take) {
        take -= 1;
    }
    let mut text = scrubbed[..take].to_owned();
    if take < scrubbed.len() {
        text.push_str(" [display shortened]");
    }
    text
}

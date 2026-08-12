//! Verified plugin composition at the CLI's trusted startup root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iteron_marketplace::{
    ActivePlugin, Binding, Contribution, PluginStore, RuntimeScope, Slot, Surface, Wiring,
    compose_governed,
};

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

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimePlugins {
    pub mcp_servers: Vec<McpServerConfig>,
    pub hooks: BTreeMap<String, Vec<String>>,
    pub agents: Vec<AgentArtifact>,
    pub skills: Vec<SkillArtifact>,
    pub lsp_routes: Vec<LspRoute>,
    pub diagnostics: Vec<String>,
}

impl RuntimePlugins {
    pub(crate) fn load(root: Option<&Path>, host_ceiling: CapabilitySet) -> Self {
        let Some(root) = root else {
            return Self::default();
        };
        let store = PluginStore::new(root);
        let packages = match store.runtime_packages() {
            Ok(packages) => packages,
            Err(error) => {
                return Self {
                    diagnostics: vec![format!("plugin store refused: {error}")],
                    ..Self::default()
                };
            }
        };
        let manifests = packages
            .active
            .iter()
            .map(|plugin| plugin.manifest.clone())
            .collect::<Vec<_>>();
        let composition = compose_governed(&manifests, RuntimeScope::Workspace, host_ceiling);
        let roots = packages
            .active
            .iter()
            .map(|plugin| (plugin.manifest.plugin.as_str(), plugin))
            .collect::<BTreeMap<_, _>>();
        let mut runtime = Self::default();
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
        runtime.materialize(&composition.wiring, &roots);
        runtime
    }

    fn materialize(&mut self, wiring: &Wiring, roots: &BTreeMap<&str, &ActivePlugin>) {
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
            }
            _ => self.note(format!(
                "plugin {} LSP {:?} refused: command must be a bounded JSON argv array",
                binding.plugin, slot.key
            )),
        }
    }

    fn note(&mut self, diagnostic: String) {
        if self.diagnostics.len() < MAX_RUNTIME_DIAGNOSTICS {
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
        | Contribution::LanguageServer { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_marketplace::{Manifest, compose};
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
        runtime.materialize(&compose(&[manifest]).wiring, &roots);
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
        std::fs::remove_dir_all(root).unwrap();
    }
}

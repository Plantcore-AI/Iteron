//! The machine-readable optimization surface.
//!
//! One document that answers, for an outside process with no access to this source tree: what can
//! I address, of what shape, within what bounds, and what may I not touch. Everything an optimizer
//! needs to construct a legal profile is here, and nothing that is merely internal is.
//!
//! The honesty property that matters: every entry marked addressable must actually be settable by
//! a profile the loader accepts. An export that overstates its surface is worse than no export,
//! because a tuner will spend its whole budget proposing candidates that are refused.

use crate::modules::{ModuleId, ModuleKind};
use crate::params::ParamClass;
use serde::Serialize;

/// A model-visible text surface that can be replaced by a policy artifact.
///
/// These are not families: their value is natural language, they carry no capability, and the
/// methods that optimize them are unrelated to the ones that search numbers. They are listed here
/// so a prompt optimizer can discover them the same way a numeric optimizer discovers families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PromptArtifact {
    /// Stable addressing id.
    pub id: &'static str,
    pub module: ModuleId,
    /// Where the built-in default is declared.
    pub decl: &'static str,
    /// What replacing it changes, stated so a reader need not infer it from the id.
    pub effect: &'static str,
    /// Whether a use site actually consults `artifact_override` for this id.
    ///
    /// The exposure gate requires every checked-in artifact marked `overridable` to have a
    /// production resolution site. Keeping the bit in the export lets outside harnesses verify the
    /// contract without trusting that gate implicitly.
    pub overridable: bool,
}

/// The ten legacy aggregate addressable text surfaces.
///
/// This remains a slice so adding an artifact does not require a public fixed-array type change.
/// Built-in tool descriptions are additionally published one-per-tool in `tool_descriptions`.
pub const PROMPT_ARTIFACTS: &[PromptArtifact] = &[
    PromptArtifact {
        id: "prompt/system@v1",
        overridable: true,
        module: ModuleId::PromptSystem,
        decl: "crates/cli/src/main.rs:SYSTEM_PROMPT",
        effect: "the operator-facing agent's base system prompt",
    },
    PromptArtifact {
        id: "prompt/tool_description@v1",
        overridable: true,
        module: ModuleId::PromptToolDescription,
        decl: "crates/tools/src/*.rs:ToolSpec::description",
        effect: "the model-visible description of each registered tool; never its capability",
    },
    PromptArtifact {
        id: "prompt/subagent@v1",
        overridable: true,
        module: ModuleId::PromptSubagent,
        decl: "crates/agents/src/def.rs",
        effect: "the system prompt each spawned subagent runs under",
    },
    PromptArtifact {
        id: "prompt/skill@v1",
        overridable: true,
        module: ModuleId::PromptSkill,
        decl: "crates/ctx/src/skills.rs",
        effect: "skill and instruction text injected into context",
    },
    PromptArtifact {
        id: "prompt/compaction@v1",
        overridable: true,
        module: ModuleId::PromptCompaction,
        decl: "crates/ctx/src/compact.rs",
        effect: "the instruction that produces a conversation summary",
    },
    PromptArtifact {
        id: "prompt/verification@v1",
        overridable: true,
        module: ModuleId::PromptVerification,
        decl: "crates/verify/src",
        effect: "operator-supplied model guidance appended for verification handling",
    },
    PromptArtifact {
        id: "prompt/planner@v1",
        overridable: true,
        module: ModuleId::PromptPlanner,
        decl: "crates/agents/src/decompose.rs",
        effect: "the instruction that decomposes a task into subtasks",
    },
    PromptArtifact {
        id: "prompt/reduce@v1",
        overridable: true,
        module: ModuleId::PromptReduce,
        decl: "crates/agents/src/reduce.rs",
        effect: "the instruction that merges child results",
    },
    PromptArtifact {
        id: "prompt/memory_write@v1",
        overridable: true,
        module: ModuleId::PromptMemoryWrite,
        decl: "crates/ctx/src/memory.rs",
        effect: "operator-supplied model guidance appended for memory-write decisions",
    },
    PromptArtifact {
        id: "prompt/recovery@v1",
        overridable: true,
        module: ModuleId::PromptRecovery,
        decl: "crates/workflow/src",
        effect: "the escalation text used when an assignment ends without usable evidence",
    },
];

#[derive(Debug, Serialize)]
pub struct ModuleEntry {
    pub id: &'static str,
    pub kind: ModuleKind,
    pub families: usize,
    pub params: usize,
    pub artifacts: usize,
}

#[derive(Debug, Serialize)]
pub struct FamilyEntry {
    pub ordinal: u16,
    pub id: &'static str,
    pub semantic_key: &'static str,
    pub module: ModuleId,
    pub domain: String,
    pub implementation_status: String,
    pub authority_class: String,
    pub risk_class: String,
    pub optimization_class: String,
    pub search_phase: String,
    pub pin_reason: Option<&'static str>,
    pub source_kinds: Vec<String>,
    /// Computed, never stored: does this family declare a source a profile may use. This is the
    /// live dimensionality an optimizer should treat as its search space.
    pub profile_addressable: bool,
    pub summary: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SurfaceCounts {
    pub families: usize,
    pub families_full: usize,
    pub families_fixed_hidden: usize,
    pub families_profile_addressable: usize,
    pub params: usize,
    pub params_searchable: usize,
    pub params_bounded: usize,
    pub params_structural: usize,
    /// Parameters a production use site actually consults. The exposure gate requires this to
    /// equal `params_searchable + params_bounded`; any advertised-but-inert gap fails the build.
    pub params_applied: usize,
    pub modules: usize,
    pub prompt_artifacts: usize,
    /// Artifacts a production use site actually consults. The exposure gate requires this to equal
    /// `prompt_artifacts` for the checked-in surface.
    pub prompt_artifacts_overridable: usize,
    /// Independently addressable built-in `ToolSpec::description` rows. External/MCP tools are
    /// intentionally not counted because their text is supplied by an untrusted runtime source.
    pub tool_descriptions: usize,
    pub tool_descriptions_overridable: usize,
    /// Multi-layer runtime nodes: module providers, production ports, platform services and host
    /// invariants. This is intentionally separate from the optimization-module count.
    pub runtime_service_nodes: usize,
    pub runtime_service_external: usize,
    /// Honest remainder: typed Rust seams that still lack a language-neutral external provider.
    pub runtime_service_compiled_interfaces: usize,
}

#[derive(Debug, Serialize)]
pub struct SurfaceExport {
    pub schema_version: u16,
    pub registry_id: &'static str,
    pub registry_revision: u16,
    pub registry_digest: &'static str,
    pub param_registry_id: &'static str,
    pub param_registry_digest: String,
    pub tool_text_registry_id: &'static str,
    pub tool_text_registry_digest: String,
    pub counts: SurfaceCounts,
    pub modules: Vec<ModuleEntry>,
    pub runtime_services: crate::RuntimeServiceGraph,
    pub families: Vec<FamilyEntry>,
    pub params: &'static [crate::params::Param],
    pub prompt_artifacts: &'static [PromptArtifact],
    pub tool_descriptions: &'static [crate::ToolTextArtifact],
}

/// Schema version of the export document.
pub const SURFACE_SCHEMA_VERSION: u16 = 3;

fn profile_addressable(family: &crate::Family) -> bool {
    family.is_profile_addressable()
}

/// Build the whole surface document.
pub fn surface() -> SurfaceExport {
    let families: Vec<FamilyEntry> = crate::families()
        .iter()
        .map(|family| FamilyEntry {
            ordinal: family.ordinal,
            id: family.id,
            semantic_key: family.semantic_key,
            module: crate::modules::module_for(family),
            domain: format!("{:?}", family.domain),
            implementation_status: format!("{:?}", family.implementation_status),
            authority_class: format!("{:?}", family.authority_class),
            risk_class: format!("{:?}", family.risk_class),
            optimization_class: format!("{:?}", family.optimization.class),
            search_phase: format!("{:?}", family.optimization.search_phase),
            pin_reason: family.optimization.pin_reason,
            source_kinds: {
                let mut kinds: Vec<_> = family
                    .source
                    .bindings
                    .iter()
                    .map(|binding| format!("{:?}", binding.kind))
                    .collect();
                if family
                    .profile_binding(crate::SourceKind::UserConfig)
                    .is_some()
                    && !kinds.iter().any(|kind| kind == "UserConfig")
                {
                    kinds.push("UserConfig".to_owned());
                }
                kinds
            },
            profile_addressable: profile_addressable(family),
            summary: family.summary,
        })
        .collect();

    let params = crate::params::params();
    let modules = ModuleId::ALL
        .into_iter()
        .map(|module| ModuleEntry {
            id: module.as_str(),
            kind: module.kind(),
            families: families
                .iter()
                .filter(|entry| entry.module == module)
                .count(),
            params: params.iter().filter(|param| param.module == module).count(),
            artifacts: PROMPT_ARTIFACTS
                .iter()
                .filter(|artifact| artifact.module == module)
                .count()
                + crate::TOOL_TEXT_ARTIFACTS
                    .iter()
                    .filter(|artifact| artifact.module == module)
                    .count(),
        })
        .collect();

    let runtime_services = crate::runtime_service_graph();
    debug_assert!(crate::validate_runtime_service_graph(&runtime_services).is_ok());
    let counts = SurfaceCounts {
        families: families.len(),
        families_full: families
            .iter()
            .filter(|entry| entry.implementation_status == "Full")
            .count(),
        families_fixed_hidden: families
            .iter()
            .filter(|entry| entry.implementation_status == "FixedHidden")
            .count(),
        families_profile_addressable: families
            .iter()
            .filter(|entry| entry.profile_addressable)
            .count(),
        params: params.len(),
        params_searchable: params
            .iter()
            .filter(|param| matches!(param.class, ParamClass::Searchable))
            .count(),
        params_bounded: params
            .iter()
            .filter(|param| matches!(param.class, ParamClass::Bounded))
            .count(),
        params_structural: params
            .iter()
            .filter(|param| matches!(param.class, ParamClass::Structural))
            .count(),
        params_applied: params.iter().filter(|param| param.applied).count(),
        modules: ModuleId::ALL.len(),
        prompt_artifacts: PROMPT_ARTIFACTS.len(),
        prompt_artifacts_overridable: PROMPT_ARTIFACTS
            .iter()
            .filter(|artifact| artifact.overridable)
            .count(),
        tool_descriptions: crate::TOOL_TEXT_ARTIFACTS.len(),
        tool_descriptions_overridable: crate::TOOL_TEXT_ARTIFACTS
            .iter()
            .filter(|artifact| artifact.overridable)
            .count(),
        runtime_service_nodes: runtime_services.nodes.len(),
        runtime_service_external: runtime_services
            .nodes
            .iter()
            .filter(|node| {
                matches!(
                    node.implementation_status,
                    crate::RuntimeServiceImplementationStatus::ExternalProcess
                        | crate::RuntimeServiceImplementationStatus::ExternalProtocol
                )
            })
            .count(),
        runtime_service_compiled_interfaces: runtime_services
            .nodes
            .iter()
            .filter(|node| {
                node.implementation_status
                    == crate::RuntimeServiceImplementationStatus::CompiledInterface
            })
            .count(),
    };

    SurfaceExport {
        schema_version: SURFACE_SCHEMA_VERSION,
        registry_id: crate::REGISTRY_ID,
        registry_revision: crate::REGISTRY_REVISION,
        registry_digest: crate::REGISTRY_DIGEST_SHA256,
        param_registry_id: crate::params::PARAM_REGISTRY_ID,
        param_registry_digest: crate::params::param_registry_digest_sha256(),
        tool_text_registry_id: crate::TOOL_TEXT_REGISTRY_ID,
        tool_text_registry_digest: crate::tool_text_registry_digest_sha256(),
        counts,
        modules,
        runtime_services,
        families,
        params,
        prompt_artifacts: PROMPT_ARTIFACTS,
        tool_descriptions: crate::TOOL_TEXT_ARTIFACTS,
    }
}

/// Render the surface as stable JSON.
pub fn surface_json() -> Result<String, serde_json::Error> {
    let mut json = serde_json::to_string_pretty(&surface())?;
    json.push('\n');
    Ok(json)
}

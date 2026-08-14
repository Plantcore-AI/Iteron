//! Honest multi-layer inventory of Iteron's optimization and runtime service boundaries.
//!
//! A trainable module, the production port that consumes its decision, and a platform service are
//! different things.  Keeping them in one typed graph makes raw node-count comparisons auditable
//! without pretending that credentials, durability, or process reaping are learnable choices.

use crate::{ContractRef, HostInvariant, ModuleId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RUNTIME_SERVICE_GRAPH_SCHEMA_VERSION: u16 = 2;
pub const RUNTIME_SERVICE_NODE_COUNT: usize = 66;
pub const MAX_RUNTIME_SERVICE_GRAPH_BYTES: usize = 256 * 1024;

/// Production workspace crates covered by the platform-service layer. The test below compares this
/// list with the root workspace manifest so a new runtime crate cannot silently escape the graph.
pub const RUNTIME_CRATE_IDS: [&str; 22] = [
    "agents",
    "changeset",
    "cli",
    "ctx",
    "eval",
    "evolve",
    "kernel",
    "lsp",
    "marketplace",
    "mcp",
    "obs",
    "protocol",
    "provider",
    "record",
    "sandbox",
    "sched",
    "statusline",
    "support",
    "tools",
    "tunables",
    "verify",
    "workflow",
];

const EXTERNAL_PROTOCOL_SERVICE_IDS: [&str; 6] = [
    "service/lsp.transport",
    "service/mcp.transport",
    "service/observation.export",
    "service/optimizer.runtime",
    "service/provider.adapters",
    "service/tunables.registry",
];

const CLOSED_HOST_INVARIANTS: [HostInvariant; 7] = [
    HostInvariant::ActivationAndPromotion,
    HostInvariant::CapabilityAndPermission,
    HostInvariant::BudgetAndDeadline,
    HostInvariant::CancellationAndProcessReaping,
    HostInvariant::EvidenceDurability,
    HostInvariant::ReplayAndIdentity,
    HostInvariant::TrustAndSecretHandling,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPortId {
    Context,
    ToolPolicy,
    Memory,
    Router,
    Planner,
    Collaboration,
    Scheduler,
    Verifier,
    ModelRouter,
}

impl ProductionPortId {
    pub const ALL: [Self; 9] = [
        Self::Context,
        Self::ToolPolicy,
        Self::Memory,
        Self::Router,
        Self::Planner,
        Self::Collaboration,
        Self::Scheduler,
        Self::Verifier,
        Self::ModelRouter,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::ToolPolicy => "tool_policy",
            Self::Memory => "memory",
            Self::Router => "router",
            Self::Planner => "planner",
            Self::Collaboration => "collaboration",
            Self::Scheduler => "scheduler",
            Self::Verifier => "verifier",
            Self::ModelRouter => "model_router",
        }
    }
}

/// The public one-to-one module-stage registry.  Several stages may feed one typed production
/// consumer, but no stage loses its own identity, provider contract, lifecycle, or evidence row.
pub const fn module_port(module: ModuleId) -> ProductionPortId {
    match module {
        ModuleId::PromptSystem
        | ModuleId::PromptSkill
        | ModuleId::PromptCompaction
        | ModuleId::ContextAssembly
        | ModuleId::ContextCompaction => ProductionPortId::Context,
        ModuleId::PromptToolDescription
        | ModuleId::ToolExposure
        | ModuleId::ToolArguments
        | ModuleId::ToolEditStrategy
        | ModuleId::ToolSearchStrategy => ProductionPortId::ToolPolicy,
        ModuleId::PromptMemoryWrite | ModuleId::MemoryRecall => ProductionPortId::Memory,
        ModuleId::PromptSubagent | ModuleId::BudgetAllocation | ModuleId::SessionStop => {
            ProductionPortId::Router
        }
        ModuleId::PromptPlanner | ModuleId::PlannerFanout => ProductionPortId::Planner,
        ModuleId::PromptReduce | ModuleId::SessionCheckpoint | ModuleId::SessionFork => {
            ProductionPortId::Collaboration
        }
        ModuleId::SchedulerParallelism => ProductionPortId::Scheduler,
        ModuleId::PromptVerification | ModuleId::PromptRecovery | ModuleId::VerificationQuorum => {
            ProductionPortId::Verifier
        }
        ModuleId::ProviderRouting
        | ModuleId::ProviderSampling
        | ModuleId::ProviderRetry
        | ModuleId::ProviderPromptCache => ProductionPortId::ModelRouter,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceLayer {
    OptimizationModule,
    ProductionPort,
    PlatformService,
    HostInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceDisposition {
    Trainable,
    ReplaceableOnly,
    HostFixedNonOptimization,
    ImmutableHostInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceImplementationStatus {
    ExternalProcess,
    ExternalProtocol,
    CompiledInterface,
    HostFixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeServiceNode {
    pub id: String,
    pub layer: RuntimeServiceLayer,
    pub disposition: RuntimeServiceDisposition,
    pub implementation_status: RuntimeServiceImplementationStatus,
    pub owner: String,
    /// Exact production workspace crate represented by a platform-service node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_crate: Option<String>,
    pub provider_contract: ContractRef,
    pub consumer_contract: ContractRef,
    pub dependencies: Vec<String>,
    /// Why a host-fixed platform service is execution infrastructure rather than another search
    /// dimension. Required for `HostFixedNonOptimization`; absent for every other disposition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_optimization_reason: Option<String>,
    /// Named trainable decisions consumed by a host-fixed service. These entries must agree
    /// exactly with the corresponding `module/...` dependency edges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegated_modules: Vec<ModuleId>,
    /// Closed authority/lifecycle responsibilities that cannot lawfully become optimization
    /// dimensions. These entries must agree exactly with the corresponding invariant edges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed_host_invariants: Vec<HostInvariant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub production_port: Option<ProductionPortId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeServiceGraph {
    pub schema_version: u16,
    pub nodes: Vec<RuntimeServiceNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeServiceGraphError {
    #[error("runtime service graph schema or node count is invalid")]
    Shape,
    #[error("runtime service graph exceeds its byte bound")]
    TooLarge,
    #[error("runtime service node identity or contract is invalid or duplicated")]
    Identity,
    #[error("runtime service node classification is inconsistent")]
    Classification,
    #[error("runtime service dependency is missing, duplicated, or cyclic")]
    Dependency,
}

fn contract(id: &str, role: &str) -> ContractRef {
    ContractRef {
        id: format!("iteron/runtime/{id}/{role}@v1"),
        version: 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn node(
    id: String,
    layer: RuntimeServiceLayer,
    disposition: RuntimeServiceDisposition,
    implementation_status: RuntimeServiceImplementationStatus,
    owner: &str,
    source_crate: Option<&str>,
    dependencies: Vec<String>,
    non_optimization_reason: Option<&str>,
    delegated_modules: Vec<ModuleId>,
    closed_host_invariants: Vec<HostInvariant>,
    module: Option<ModuleId>,
    production_port: Option<ProductionPortId>,
) -> RuntimeServiceNode {
    RuntimeServiceNode {
        provider_contract: contract(&id, "provider"),
        consumer_contract: contract(&id, "consumer"),
        id,
        layer,
        disposition,
        implementation_status,
        owner: owner.to_owned(),
        source_crate: source_crate.map(str::to_owned),
        dependencies,
        non_optimization_reason: non_optimization_reason.map(str::to_owned),
        delegated_modules,
        closed_host_invariants,
        module,
        production_port,
    }
}

fn port_id(port: ProductionPortId) -> String {
    format!("port/{}", port.as_str())
}

fn invariant_id(invariant: HostInvariant) -> String {
    format!("invariant/{invariant:?}").to_ascii_lowercase()
}

/// Return all currently admitted runtime capability nodes. Platform services fail closed: only a
/// real external protocol is replaceable; compiled host infrastructure is explicitly classified
/// as non-optimization and names the trainable decisions or closed invariants it depends on.
#[must_use]
pub fn runtime_service_graph() -> RuntimeServiceGraph {
    let mut nodes = Vec::with_capacity(RUNTIME_SERVICE_NODE_COUNT);
    for port in ProductionPortId::ALL {
        nodes.push(node(
            port_id(port),
            RuntimeServiceLayer::ProductionPort,
            RuntimeServiceDisposition::ImmutableHostInvariant,
            RuntimeServiceImplementationStatus::HostFixed,
            "cli-host",
            None,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            None,
            Some(port),
        ));
    }
    for module in ModuleId::ALL {
        let port = module_port(module);
        nodes.push(node(
            format!("module/{}", module.as_str()),
            RuntimeServiceLayer::OptimizationModule,
            RuntimeServiceDisposition::Trainable,
            RuntimeServiceImplementationStatus::ExternalProcess,
            "tunability-registry",
            None,
            vec![port_id(port)],
            None,
            Vec::new(),
            Vec::new(),
            Some(module),
            Some(port),
        ));
    }
    let platform = [
        (
            "agent.orchestration",
            "agent-runtime",
            "agents",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "The host executes bounded orchestration; prompts, planning, provider policy, session routing, and collaboration quality are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptSubagent,
                ModuleId::PromptPlanner,
                ModuleId::PromptReduce,
                ModuleId::ProviderRouting,
                ModuleId::ProviderSampling,
                ModuleId::ProviderRetry,
                ModuleId::ProviderPromptCache,
                ModuleId::BudgetAllocation,
                ModuleId::SessionStop,
                ModuleId::SessionCheckpoint,
                ModuleId::SessionFork,
            ],
            vec![HostInvariant::CancellationAndProcessReaping],
        ),
        (
            "changeset.store",
            "changeset-lifecycle",
            "changeset",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Atomic changeset persistence and recovery are evidence and replay guarantees, not quality choices.",
            ),
            vec![],
            vec![
                HostInvariant::EvidenceDurability,
                HostInvariant::ReplayAndIdentity,
            ],
        ),
        (
            "cli.frontend",
            "cli-host",
            "cli",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Command admission and terminal I/O stay deterministic while prompt composition quality is delegated to named modules.",
            ),
            vec![
                ModuleId::PromptSystem,
                ModuleId::PromptSkill,
                ModuleId::PromptCompaction,
            ],
            vec![HostInvariant::CapabilityAndPermission],
        ),
        (
            "context.engine",
            "context-runtime",
            "ctx",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "The host enforces context bounds and provenance; assembly and compaction quality are delegated to named modules.",
            ),
            vec![ModuleId::ContextAssembly, ModuleId::ContextCompaction],
            vec![HostInvariant::BudgetAndDeadline],
        ),
        (
            "evaluation.runner",
            "evaluation",
            "eval",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "The runner executes a fixed evaluation protocol; verification prompts, recovery, and quorum policy are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptVerification,
                ModuleId::PromptRecovery,
                ModuleId::VerificationQuorum,
            ],
            vec![HostInvariant::EvidenceDurability],
        ),
        (
            "optimizer.runtime",
            "evolution-runtime",
            "evolve",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "kernel.controller",
            "kernel-runtime",
            "kernel",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "The kernel owns the closed authority, lifecycle, budget, evidence, replay, and secret envelope and therefore cannot be an optimization candidate.",
            ),
            vec![],
            vec![
                HostInvariant::ActivationAndPromotion,
                HostInvariant::CapabilityAndPermission,
                HostInvariant::BudgetAndDeadline,
                HostInvariant::CancellationAndProcessReaping,
                HostInvariant::EvidenceDurability,
                HostInvariant::ReplayAndIdentity,
                HostInvariant::TrustAndSecretHandling,
            ],
        ),
        (
            "lsp.transport",
            "language-server-lifecycle",
            "lsp",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "marketplace.registry",
            "plugin-marketplace",
            "marketplace",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Package identity and trust checks are fixed; which admitted tools are exposed is delegated to the tool-exposure module.",
            ),
            vec![ModuleId::ToolExposure],
            vec![
                HostInvariant::CapabilityAndPermission,
                HostInvariant::TrustAndSecretHandling,
            ],
        ),
        (
            "mcp.transport",
            "mcp-interop",
            "mcp",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "observation.export",
            "telemetry-export",
            "obs",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "protocol.envelopes",
            "protocol-contracts",
            "protocol",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Wire decoding, schema validation, and identity binding are closed interoperability and replay guarantees.",
            ),
            vec![],
            vec![
                HostInvariant::CapabilityAndPermission,
                HostInvariant::ReplayAndIdentity,
            ],
        ),
        (
            "provider.adapters",
            "provider-adapters",
            "provider",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "record.store",
            "record-core",
            "record",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Record integrity and durability stay fixed while memory content, recall, and checkpoint policy are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptMemoryWrite,
                ModuleId::MemoryRecall,
                ModuleId::SessionCheckpoint,
            ],
            vec![
                HostInvariant::EvidenceDurability,
                HostInvariant::ReplayAndIdentity,
            ],
        ),
        (
            "sandbox.backend",
            "sandbox",
            "sandbox",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Isolation and effect enforcement are fixed; argument construction and edit strategy are delegated to named modules.",
            ),
            vec![ModuleId::ToolArguments, ModuleId::ToolEditStrategy],
            vec![HostInvariant::CapabilityAndPermission],
        ),
        (
            "scheduler.engine",
            "scheduler-runtime",
            "sched",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Queue, deadline, and cancellation enforcement are fixed while parallelism, fanout, budget allocation, and stopping policy are delegated to named modules.",
            ),
            vec![
                ModuleId::SchedulerParallelism,
                ModuleId::PlannerFanout,
                ModuleId::BudgetAllocation,
                ModuleId::SessionStop,
            ],
            vec![
                HostInvariant::BudgetAndDeadline,
                HostInvariant::CancellationAndProcessReaping,
            ],
        ),
        (
            "statusline.frontend",
            "statusline",
            "statusline",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "The statusline is a deterministic read-only projection of authenticated runtime state and has no decision authority or adaptable quality surface.",
            ),
            vec![],
            vec![HostInvariant::ReplayAndIdentity],
        ),
        (
            "support.io",
            "support-runtime",
            "support",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Bounded process and stream I/O implement capability and cancellation guarantees rather than agent strategy.",
            ),
            vec![],
            vec![
                HostInvariant::CapabilityAndPermission,
                HostInvariant::CancellationAndProcessReaping,
            ],
        ),
        (
            "tools.registry",
            "tools-core",
            "tools",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Tool identity and capability enforcement are fixed while descriptions, exposure, arguments, edits, and search strategy are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptToolDescription,
                ModuleId::ToolExposure,
                ModuleId::ToolArguments,
                ModuleId::ToolEditStrategy,
                ModuleId::ToolSearchStrategy,
            ],
            vec![HostInvariant::CapabilityAndPermission],
        ),
        (
            "tunables.registry",
            "tunability-registry",
            "tunables",
            RuntimeServiceImplementationStatus::ExternalProtocol,
            None,
            vec![],
            vec![],
        ),
        (
            "verification.engine",
            "verification-runtime",
            "verify",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Evidence admission remains fixed while verification prompts, recovery, and quorum quality are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptVerification,
                ModuleId::PromptRecovery,
                ModuleId::VerificationQuorum,
            ],
            vec![HostInvariant::EvidenceDurability],
        ),
        (
            "workflow.engine",
            "workflow-engine",
            "workflow",
            RuntimeServiceImplementationStatus::HostFixed,
            Some(
                "Workflow state transitions and replay are fixed while planning, reduction, fanout, parallelism, checkpoint, and fork policy are delegated to named modules.",
            ),
            vec![
                ModuleId::PromptPlanner,
                ModuleId::PromptReduce,
                ModuleId::PlannerFanout,
                ModuleId::SchedulerParallelism,
                ModuleId::SessionCheckpoint,
                ModuleId::SessionFork,
            ],
            vec![HostInvariant::ReplayAndIdentity],
        ),
    ];
    for (id, owner, source_crate, status, reason, delegated_modules, closed_host_invariants) in
        platform
    {
        let disposition = match status {
            RuntimeServiceImplementationStatus::ExternalProtocol => {
                RuntimeServiceDisposition::ReplaceableOnly
            }
            RuntimeServiceImplementationStatus::HostFixed => {
                RuntimeServiceDisposition::HostFixedNonOptimization
            }
            _ => unreachable!("platform table admits only external protocols or host-fixed rows"),
        };
        let dependencies = delegated_modules
            .iter()
            .map(|module| format!("module/{}", module.as_str()))
            .chain(
                closed_host_invariants
                    .iter()
                    .map(|invariant| invariant_id(*invariant)),
            )
            .collect();
        nodes.push(node(
            format!("service/{id}"),
            RuntimeServiceLayer::PlatformService,
            disposition,
            status,
            owner,
            Some(source_crate),
            dependencies,
            reason,
            delegated_modules,
            closed_host_invariants,
            None,
            None,
        ));
    }
    for invariant in CLOSED_HOST_INVARIANTS {
        nodes.push(node(
            invariant_id(invariant),
            RuntimeServiceLayer::HostInvariant,
            RuntimeServiceDisposition::ImmutableHostInvariant,
            RuntimeServiceImplementationStatus::HostFixed,
            "kernel-runtime",
            None,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
        ));
    }
    RuntimeServiceGraph {
        schema_version: RUNTIME_SERVICE_GRAPH_SCHEMA_VERSION,
        nodes,
    }
}

pub fn validate_runtime_service_graph(
    graph: &RuntimeServiceGraph,
) -> Result<(), RuntimeServiceGraphError> {
    if graph.schema_version != RUNTIME_SERVICE_GRAPH_SCHEMA_VERSION
        || graph.nodes.len() != RUNTIME_SERVICE_NODE_COUNT
    {
        return Err(RuntimeServiceGraphError::Shape);
    }
    if serde_json::to_vec(graph)
        .map_err(|_| RuntimeServiceGraphError::Shape)?
        .len()
        > MAX_RUNTIME_SERVICE_GRAPH_BYTES
    {
        return Err(RuntimeServiceGraphError::TooLarge);
    }
    let mut ids = BTreeSet::new();
    let mut contracts = BTreeSet::new();
    let mut by_id = BTreeMap::new();
    for candidate in &graph.nodes {
        let valid_id = !candidate.id.is_empty()
            && candidate.id.len() <= 160
            && candidate.id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-')
            });
        if !valid_id
            || !ids.insert(candidate.id.as_str())
            || !contracts.insert(candidate.provider_contract.id.as_str())
            || !contracts.insert(candidate.consumer_contract.id.as_str())
            || candidate.provider_contract.version != 1
            || candidate.consumer_contract.version != 1
        {
            return Err(RuntimeServiceGraphError::Identity);
        }
        let has_non_optimization_reason =
            candidate
                .non_optimization_reason
                .as_deref()
                .is_some_and(|reason| {
                    !reason.trim().is_empty() && reason.len() <= 512 && reason == reason.trim()
                });
        let no_non_optimization_evidence = candidate.non_optimization_reason.is_none()
            && candidate.delegated_modules.is_empty()
            && candidate.closed_host_invariants.is_empty();
        let classification_is_valid = match candidate.layer {
            RuntimeServiceLayer::OptimizationModule => candidate.module.is_some_and(|module| {
                candidate.id == format!("module/{}", module.as_str())
                    && candidate.disposition == RuntimeServiceDisposition::Trainable
                    && candidate.implementation_status
                        == RuntimeServiceImplementationStatus::ExternalProcess
                    && candidate.source_crate.is_none()
                    && candidate.production_port == Some(module_port(module))
                    && candidate.dependencies == [port_id(module_port(module))]
                    && no_non_optimization_evidence
            }),
            RuntimeServiceLayer::ProductionPort => candidate.production_port.is_some_and(|port| {
                candidate.id == port_id(port)
                    && candidate.disposition == RuntimeServiceDisposition::ImmutableHostInvariant
                    && candidate.implementation_status
                        == RuntimeServiceImplementationStatus::HostFixed
                    && candidate.source_crate.is_none()
                    && candidate.module.is_none()
                    && candidate.dependencies.is_empty()
                    && no_non_optimization_evidence
            }),
            RuntimeServiceLayer::PlatformService => {
                candidate.source_crate.is_some()
                    && candidate.module.is_none()
                    && candidate.production_port.is_none()
                    && match candidate.implementation_status {
                        RuntimeServiceImplementationStatus::ExternalProtocol => {
                            candidate.disposition == RuntimeServiceDisposition::ReplaceableOnly
                                && candidate.dependencies.is_empty()
                                && no_non_optimization_evidence
                        }
                        RuntimeServiceImplementationStatus::HostFixed => {
                            candidate.disposition
                                == RuntimeServiceDisposition::HostFixedNonOptimization
                                && has_non_optimization_reason
                                && (!candidate.delegated_modules.is_empty()
                                    || !candidate.closed_host_invariants.is_empty())
                        }
                        RuntimeServiceImplementationStatus::ExternalProcess
                        | RuntimeServiceImplementationStatus::CompiledInterface => false,
                    }
            }
            RuntimeServiceLayer::HostInvariant => {
                candidate.disposition == RuntimeServiceDisposition::ImmutableHostInvariant
                    && candidate.implementation_status
                        == RuntimeServiceImplementationStatus::HostFixed
                    && candidate.source_crate.is_none()
                    && candidate.module.is_none()
                    && candidate.production_port.is_none()
                    && candidate.dependencies.is_empty()
                    && no_non_optimization_evidence
            }
        };
        if !classification_is_valid
            || (candidate.disposition == RuntimeServiceDisposition::ReplaceableOnly
                && candidate.implementation_status
                    == RuntimeServiceImplementationStatus::CompiledInterface)
        {
            return Err(RuntimeServiceGraphError::Classification);
        }
        by_id.insert(candidate.id.as_str(), candidate);
    }
    let platform_nodes = graph
        .nodes
        .iter()
        .filter(|node| node.layer == RuntimeServiceLayer::PlatformService)
        .collect::<Vec<_>>();
    let covered_crates = platform_nodes
        .iter()
        .filter_map(|node| node.source_crate.as_deref())
        .collect::<BTreeSet<_>>();
    if covered_crates.len() != platform_nodes.len()
        || covered_crates != RUNTIME_CRATE_IDS.into_iter().collect()
    {
        return Err(RuntimeServiceGraphError::Classification);
    }
    let modules = graph
        .nodes
        .iter()
        .filter(|node| node.layer == RuntimeServiceLayer::OptimizationModule)
        .filter_map(|node| node.module)
        .collect::<Vec<_>>();
    if modules.len() != ModuleId::ALL.len()
        || modules.iter().copied().collect::<BTreeSet<_>>() != ModuleId::ALL.into_iter().collect()
    {
        return Err(RuntimeServiceGraphError::Classification);
    }
    let ports = graph
        .nodes
        .iter()
        .filter(|node| node.layer == RuntimeServiceLayer::ProductionPort)
        .filter_map(|node| node.production_port)
        .collect::<Vec<_>>();
    if ports.len() != ProductionPortId::ALL.len()
        || ports.iter().copied().collect::<BTreeSet<_>>()
            != ProductionPortId::ALL.into_iter().collect()
    {
        return Err(RuntimeServiceGraphError::Classification);
    }
    let invariant_ids = graph
        .nodes
        .iter()
        .filter(|node| node.layer == RuntimeServiceLayer::HostInvariant)
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    if invariant_ids
        != CLOSED_HOST_INVARIANTS
            .into_iter()
            .map(invariant_id)
            .collect()
    {
        return Err(RuntimeServiceGraphError::Classification);
    }
    let external_protocol_services = platform_nodes
        .iter()
        .filter(|node| {
            node.implementation_status == RuntimeServiceImplementationStatus::ExternalProtocol
        })
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    if external_protocol_services != EXTERNAL_PROTOCOL_SERVICE_IDS.into_iter().collect() {
        return Err(RuntimeServiceGraphError::Classification);
    }
    let mut host_fixed_module_coverage = BTreeSet::new();
    for candidate in platform_nodes
        .iter()
        .filter(|node| node.disposition == RuntimeServiceDisposition::HostFixedNonOptimization)
    {
        let delegated_modules = candidate
            .delegated_modules
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let closed_host_invariants = candidate
            .closed_host_invariants
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if delegated_modules.len() != candidate.delegated_modules.len()
            || closed_host_invariants.len() != candidate.closed_host_invariants.len()
        {
            return Err(RuntimeServiceGraphError::Classification);
        }
        let evidence_dependencies = delegated_modules
            .iter()
            .map(|module| format!("module/{}", module.as_str()))
            .chain(
                closed_host_invariants
                    .iter()
                    .map(|invariant| invariant_id(*invariant)),
            )
            .collect::<BTreeSet<_>>();
        if evidence_dependencies
            != candidate
                .dependencies
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        {
            return Err(RuntimeServiceGraphError::Dependency);
        }
        host_fixed_module_coverage.extend(delegated_modules);
    }
    if host_fixed_module_coverage != ModuleId::ALL.into_iter().collect() {
        return Err(RuntimeServiceGraphError::Classification);
    }
    for candidate in &graph.nodes {
        let dependencies = candidate.dependencies.iter().collect::<BTreeSet<_>>();
        if dependencies.len() != candidate.dependencies.len()
            || dependencies
                .iter()
                .any(|dependency| !by_id.contains_key(dependency.as_str()))
        {
            return Err(RuntimeServiceGraphError::Dependency);
        }
    }
    fn visit<'a>(
        id: &'a str,
        nodes: &BTreeMap<&'a str, &'a RuntimeServiceNode>,
        visiting: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> Result<(), RuntimeServiceGraphError> {
        if done.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(RuntimeServiceGraphError::Dependency);
        }
        for dependency in &nodes[id].dependencies {
            visit(dependency, nodes, visiting, done)?;
        }
        visiting.remove(id);
        done.insert(id);
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for id in by_id.keys().copied() {
        visit(id, &by_id, &mut visiting, &mut done)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_is_total_and_keeps_twenty_eight_independent_module_nodes() {
        let graph = runtime_service_graph();
        validate_runtime_service_graph(&graph).unwrap();
        let modules = graph
            .nodes
            .iter()
            .filter_map(|node| node.module)
            .collect::<Vec<_>>();
        assert_eq!(modules, ModuleId::ALL);
        assert!(
            graph
                .nodes
                .iter()
                .filter(|node| node.module.is_some())
                .all(|node| node.implementation_status
                    == RuntimeServiceImplementationStatus::ExternalProcess)
        );
        assert_eq!(ProductionPortId::ALL.len(), 9);
    }

    #[test]
    fn platform_service_graph_is_fail_closed_and_covers_every_module() {
        let graph = runtime_service_graph();
        let platform = graph
            .nodes
            .iter()
            .filter(|node| node.layer == RuntimeServiceLayer::PlatformService)
            .collect::<Vec<_>>();
        assert_eq!(platform.len(), 22);
        assert!(!platform.iter().any(|node| {
            node.disposition == RuntimeServiceDisposition::ReplaceableOnly
                && node.implementation_status
                    == RuntimeServiceImplementationStatus::CompiledInterface
        }));
        let replaceable = platform
            .iter()
            .filter(|node| node.disposition == RuntimeServiceDisposition::ReplaceableOnly)
            .collect::<Vec<_>>();
        assert_eq!(replaceable.len(), 6);
        assert!(replaceable.iter().all(|node| {
            node.implementation_status == RuntimeServiceImplementationStatus::ExternalProtocol
        }));
        assert_eq!(
            replaceable
                .iter()
                .map(|node| node.id.as_str())
                .collect::<BTreeSet<_>>(),
            EXTERNAL_PROTOCOL_SERVICE_IDS.into_iter().collect()
        );

        let host_fixed = platform
            .iter()
            .filter(|node| node.disposition == RuntimeServiceDisposition::HostFixedNonOptimization)
            .collect::<Vec<_>>();
        assert_eq!(host_fixed.len(), 16);
        assert!(host_fixed.iter().all(|node| {
            node.implementation_status == RuntimeServiceImplementationStatus::HostFixed
                && node
                    .non_optimization_reason
                    .as_deref()
                    .is_some_and(|reason| !reason.is_empty())
                && (!node.delegated_modules.is_empty() || !node.closed_host_invariants.is_empty())
        }));
        assert_eq!(
            host_fixed
                .iter()
                .flat_map(|node| node.delegated_modules.iter().copied())
                .collect::<BTreeSet<_>>(),
            ModuleId::ALL.into_iter().collect()
        );
    }

    #[test]
    fn service_graph_validation_rejects_unproved_host_classifications() {
        let mut compiled_replaceable = runtime_service_graph();
        let host = compiled_replaceable
            .nodes
            .iter_mut()
            .find(|node| node.disposition == RuntimeServiceDisposition::HostFixedNonOptimization)
            .unwrap();
        host.disposition = RuntimeServiceDisposition::ReplaceableOnly;
        host.implementation_status = RuntimeServiceImplementationStatus::CompiledInterface;
        assert_eq!(
            validate_runtime_service_graph(&compiled_replaceable),
            Err(RuntimeServiceGraphError::Classification)
        );

        let mut unexplained_host = runtime_service_graph();
        unexplained_host
            .nodes
            .iter_mut()
            .find(|node| node.disposition == RuntimeServiceDisposition::HostFixedNonOptimization)
            .unwrap()
            .non_optimization_reason = None;
        assert_eq!(
            validate_runtime_service_graph(&unexplained_host),
            Err(RuntimeServiceGraphError::Classification)
        );

        let mut missing_evidence_edge = runtime_service_graph();
        let host = missing_evidence_edge
            .nodes
            .iter_mut()
            .find(|node| !node.delegated_modules.is_empty())
            .unwrap();
        host.dependencies.remove(0);
        assert_eq!(
            validate_runtime_service_graph(&missing_evidence_edge),
            Err(RuntimeServiceGraphError::Dependency)
        );
    }

    #[test]
    fn workspace_runtime_crates_cannot_escape_the_service_graph() {
        let workspace = include_str!("../../../Cargo.toml");
        let declared = workspace
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("\"crates/")
                    .and_then(|line| line.strip_suffix("\","))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(declared, RUNTIME_CRATE_IDS.into_iter().collect());
    }
}

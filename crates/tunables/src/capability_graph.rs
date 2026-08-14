//! Versioned contracts between optimization modules and replaceable implementations.
//!
//! The graph describes seams; it does not load code or grant authority. Every implementation is
//! still subordinate to the host's permission, budget, lifecycle, evidence and promotion owners.

use crate::ModuleId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CAPABILITY_SEAM_GRAPH_SCHEMA_VERSION: u16 = 1;
pub const MAX_CAPABILITY_SEAMS: usize = 28;
pub const MAX_SEAM_DEPENDENCIES: usize = 8;
pub const MAX_CAPABILITY_SEAM_GRAPH_BYTES: usize = 128 * 1024;
const MAX_CONTRACT_ID_BYTES: usize = 160;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractRef {
    pub id: String,
    pub version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleContracts {
    pub load: ContractRef,
    pub start: ContractRef,
    pub cancel: ContractRef,
    pub stop: ContractRef,
}

/// These owners always remain outside a replaceable implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostInvariant {
    ActivationAndPromotion,
    CapabilityAndPermission,
    BudgetAndDeadline,
    CancellationAndProcessReaping,
    EvidenceDurability,
    ReplayAndIdentity,
    TrustAndSecretHandling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureSemantics {
    /// Malformed output or a provider error cannot become an effective decision.
    FailClosed,
    /// The host owns cancellation, deadline enforcement and process reaping.
    HostCancelsAndReaps,
    /// Evidence is rejected unless it validates against the declared observation schema.
    RejectInvalidEvidence,
    /// Quarantine/fallback is an explicit host decision, never a provider self-promotion.
    HostOwnsQuarantineAndFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeamNode {
    pub id: String,
    pub module: ModuleId,
    pub definition_contract: ContractRef,
    pub provider_contract: ContractRef,
    pub consumer_contract: ContractRef,
    pub dependencies: Vec<ModuleId>,
    pub lifecycle: LifecycleContracts,
    pub observation_schema: ContractRef,
    pub failure_semantics: Vec<ProviderFailureSemantics>,
    pub host_invariant_envelope: Vec<HostInvariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeamGraph {
    pub schema_version: u16,
    pub nodes: Vec<CapabilitySeamNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilitySeamGraphError {
    #[error("capability seam graph schema version {actual} is not {expected}")]
    SchemaVersion { expected: u16, actual: u16 },
    #[error("capability seam graph has {actual} nodes; exactly {expected} are required")]
    WrongNodeCount { expected: usize, actual: usize },
    #[error("capability seam graph is {actual} bytes; maximum is {max}")]
    TooLarge { actual: usize, max: usize },
    #[error("capability seam id {0:?} is invalid or duplicated")]
    InvalidOrDuplicateId(String),
    #[error("module {0:?} is missing or duplicated")]
    MissingOrDuplicateModule(ModuleId),
    #[error("seam {seam} has an invalid or empty contract")]
    InvalidContract { seam: String },
    #[error("seam {seam} has an invalid host invariant or failure envelope")]
    InvalidEnvelope { seam: String },
    #[error("seam {seam} declares too many, duplicate, self, or unresolved dependencies")]
    InvalidDependencies { seam: String },
    #[error("capability seam dependency graph contains a cycle through {0:?}")]
    DependencyCycle(ModuleId),
}

fn contract(module: ModuleId, role: &str) -> ContractRef {
    ContractRef {
        id: format!("iteron/{}/{}@v1", module.as_str(), role),
        version: 1,
    }
}

fn node(module: ModuleId, dependencies: &[ModuleId]) -> CapabilitySeamNode {
    CapabilitySeamNode {
        id: format!("seam/{}@v1", module.as_str()),
        module,
        definition_contract: contract(module, "definition"),
        provider_contract: contract(module, "provider"),
        consumer_contract: contract(module, "consumer"),
        dependencies: dependencies.to_vec(),
        lifecycle: LifecycleContracts {
            load: contract(module, "lifecycle/load"),
            start: contract(module, "lifecycle/start"),
            cancel: contract(module, "lifecycle/cancel"),
            stop: contract(module, "lifecycle/stop"),
        },
        observation_schema: contract(module, "observation"),
        failure_semantics: vec![
            ProviderFailureSemantics::FailClosed,
            ProviderFailureSemantics::HostCancelsAndReaps,
            ProviderFailureSemantics::RejectInvalidEvidence,
            ProviderFailureSemantics::HostOwnsQuarantineAndFallback,
        ],
        host_invariant_envelope: vec![
            HostInvariant::ActivationAndPromotion,
            HostInvariant::CapabilityAndPermission,
            HostInvariant::BudgetAndDeadline,
            HostInvariant::CancellationAndProcessReaping,
            HostInvariant::EvidenceDurability,
            HostInvariant::ReplayAndIdentity,
            HostInvariant::TrustAndSecretHandling,
        ],
    }
}

/// The complete public seam graph, in stable [`ModuleId::ALL`] order.
#[must_use]
pub fn capability_seam_graph() -> CapabilitySeamGraph {
    use ModuleId::*;
    let nodes = vec![
        node(PromptSystem, &[]),
        node(PromptToolDescription, &[PromptSystem]),
        node(PromptSubagent, &[PromptSystem]),
        node(PromptSkill, &[PromptSystem]),
        node(PromptCompaction, &[PromptSystem]),
        node(PromptVerification, &[PromptSystem]),
        node(PromptPlanner, &[PromptSystem]),
        node(PromptReduce, &[PromptPlanner]),
        node(PromptMemoryWrite, &[PromptSystem]),
        node(PromptRecovery, &[PromptVerification]),
        node(ContextAssembly, &[PromptSystem]),
        node(ContextCompaction, &[ContextAssembly]),
        node(MemoryRecall, &[ContextAssembly]),
        node(ToolExposure, &[PromptToolDescription]),
        node(ToolArguments, &[ToolExposure]),
        node(ToolEditStrategy, &[ToolArguments]),
        node(ToolSearchStrategy, &[ToolExposure]),
        node(ProviderRouting, &[ContextAssembly]),
        node(ProviderSampling, &[ProviderRouting]),
        node(ProviderRetry, &[ProviderRouting]),
        node(ProviderPromptCache, &[ProviderRouting]),
        node(SchedulerParallelism, &[ToolExposure]),
        node(PlannerFanout, &[PromptPlanner, SchedulerParallelism]),
        node(VerificationQuorum, &[PromptVerification]),
        node(BudgetAllocation, &[ProviderRouting]),
        node(SessionStop, &[BudgetAllocation]),
        node(SessionCheckpoint, &[SessionStop]),
        node(SessionFork, &[SessionCheckpoint]),
    ];
    CapabilitySeamGraph {
        schema_version: CAPABILITY_SEAM_GRAPH_SCHEMA_VERSION,
        nodes,
    }
}

fn valid_contract(reference: &ContractRef) -> bool {
    let version_suffix = format!("@v{}", reference.version);
    reference.version > 0
        && !reference.id.is_empty()
        && reference.id.len() <= MAX_CONTRACT_ID_BYTES
        && reference.id.ends_with(&version_suffix)
        && reference.id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'@')
        })
}

pub fn validate_capability_seam_graph(
    graph: &CapabilitySeamGraph,
) -> Result<(), CapabilitySeamGraphError> {
    if graph.schema_version != CAPABILITY_SEAM_GRAPH_SCHEMA_VERSION {
        return Err(CapabilitySeamGraphError::SchemaVersion {
            expected: CAPABILITY_SEAM_GRAPH_SCHEMA_VERSION,
            actual: graph.schema_version,
        });
    }
    if graph.nodes.len() != MAX_CAPABILITY_SEAMS {
        return Err(CapabilitySeamGraphError::WrongNodeCount {
            expected: MAX_CAPABILITY_SEAMS,
            actual: graph.nodes.len(),
        });
    }
    let bytes = serde_json::to_vec(graph).expect("capability seam graph must serialize");
    if bytes.len() > MAX_CAPABILITY_SEAM_GRAPH_BYTES {
        return Err(CapabilitySeamGraphError::TooLarge {
            actual: bytes.len(),
            max: MAX_CAPABILITY_SEAM_GRAPH_BYTES,
        });
    }

    let mut ids = BTreeSet::new();
    let mut contract_ids = BTreeSet::new();
    let mut by_module = BTreeMap::new();
    for node in &graph.nodes {
        if !valid_contract(&ContractRef {
            id: node.id.clone(),
            version: 1,
        }) || !ids.insert(node.id.as_str())
        {
            return Err(CapabilitySeamGraphError::InvalidOrDuplicateId(
                node.id.clone(),
            ));
        }
        if by_module.insert(node.module, node).is_some() {
            return Err(CapabilitySeamGraphError::MissingOrDuplicateModule(
                node.module,
            ));
        }
        let contracts = [
            &node.definition_contract,
            &node.provider_contract,
            &node.consumer_contract,
            &node.lifecycle.load,
            &node.lifecycle.start,
            &node.lifecycle.cancel,
            &node.lifecycle.stop,
            &node.observation_schema,
        ];
        for contract in contracts {
            if !valid_contract(contract) || !contract_ids.insert(contract.id.as_str()) {
                return Err(CapabilitySeamGraphError::InvalidContract {
                    seam: node.id.clone(),
                });
            }
        }
        let invariants: BTreeSet<_> = node.host_invariant_envelope.iter().copied().collect();
        let failures: BTreeSet<_> = node.failure_semantics.iter().copied().collect();
        if invariants.len() != 7 || failures.len() != 4 {
            return Err(CapabilitySeamGraphError::InvalidEnvelope {
                seam: node.id.clone(),
            });
        }
    }
    for module in ModuleId::ALL {
        if !by_module.contains_key(&module) {
            return Err(CapabilitySeamGraphError::MissingOrDuplicateModule(module));
        }
    }
    for node in &graph.nodes {
        let dependencies: BTreeSet<_> = node.dependencies.iter().copied().collect();
        if node.dependencies.len() > MAX_SEAM_DEPENDENCIES
            || dependencies.len() != node.dependencies.len()
            || dependencies.contains(&node.module)
            || dependencies.iter().any(|dep| !by_module.contains_key(dep))
        {
            return Err(CapabilitySeamGraphError::InvalidDependencies {
                seam: node.id.clone(),
            });
        }
    }

    fn visit(
        module: ModuleId,
        by_module: &BTreeMap<ModuleId, &CapabilitySeamNode>,
        visiting: &mut BTreeSet<ModuleId>,
        complete: &mut BTreeSet<ModuleId>,
    ) -> Result<(), CapabilitySeamGraphError> {
        if complete.contains(&module) {
            return Ok(());
        }
        if !visiting.insert(module) {
            return Err(CapabilitySeamGraphError::DependencyCycle(module));
        }
        for dependency in &by_module[&module].dependencies {
            visit(*dependency, by_module, visiting, complete)?;
        }
        visiting.remove(&module);
        complete.insert(module);
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut complete = BTreeSet::new();
    for module in ModuleId::ALL {
        visit(module, &by_module, &mut visiting, &mut complete)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_twenty_eight_module_seams_are_total_and_valid() {
        let graph = capability_seam_graph();
        validate_capability_seam_graph(&graph).unwrap();
        assert_eq!(
            graph
                .nodes
                .iter()
                .map(|node| node.module)
                .collect::<Vec<_>>(),
            ModuleId::ALL.to_vec()
        );
    }

    #[test]
    fn duplicate_contract_identity_is_rejected() {
        let mut graph = capability_seam_graph();
        graph.nodes[1].provider_contract = graph.nodes[0].provider_contract.clone();
        assert!(matches!(
            validate_capability_seam_graph(&graph),
            Err(CapabilitySeamGraphError::InvalidContract { .. })
        ));
    }

    #[test]
    fn dependency_cycle_is_rejected() {
        let mut graph = capability_seam_graph();
        graph.nodes[0].dependencies = vec![ModuleId::SessionFork];
        assert!(matches!(
            validate_capability_seam_graph(&graph),
            Err(CapabilitySeamGraphError::DependencyCycle(_))
        ));
    }
}

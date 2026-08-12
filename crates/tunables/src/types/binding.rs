use super::CoreStrategySlot;
use serde::Serialize;

/// Production composition adapter that owns the value before atomic resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionOwnerId {
    CoreFacts,
    ExecutionFacts,
    ProviderProcessFacts,
    ExtensionFacts,
}

/// Concrete typed owner symbol sampled by the production facts adapter. This is separate from the
/// four composition adapters so a broad ordinal range cannot masquerade as an owner locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionOwnerSymbolId {
    ProviderSelection,
    EffortPolicy,
    BudgetPolicy,
    PermissionPolicy,
    CompactionPolicy,
    VerificationPolicy,
    RetryPolicy,
    EgressPolicy,
    ProviderInstance,
    InstructionDiscoveryPolicy,
    MemoryPolicy,
    ObservationToolPolicy,
    WorkflowExecutionPolicy,
    MultimodalAdmissionPolicy,
    AppServerQueuePolicy,
    AgentCatalog,
    HookCatalog,
    WorkflowGraph,
    ProviderGovernor,
    AgentOverlayPolicy,
    ContextMaterializationPolicy,
    ProcessRuntimePolicy,
    BinaryMediaPolicy,
    LspRuntimePolicy,
    SessionSpawnLedger,
    McpRuntimePolicy,
    SessionIsolationPolicy,
}

/// Post-checkpoint getter or installer that gates production runtime construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeGetterId {
    EffectiveCore,
    EffectiveProvider,
    EffectiveMcp,
    EffectiveExecution,
    EffectiveTooling,
    EffectiveObservationTools,
    EffectiveAppServer,
    EffectiveBinaryMedia,
    EffectiveInputAdmission,
    EffectiveContent,
    VerificationFeedback,
}

/// Durable evidence surface that commits the owner's effective value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProjectionId {
    RunGenesisTunablesV2,
}

/// Typed authority for behavior that exists but is not an independently replaceable runtime
/// seam. These variants are intentionally not runtime getters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedAuthorityId {
    StrategyInvariant,
    OperatorBoundary,
    GovernedArtifactBoundary,
    RuntimeInvariant,
    KernelInvariant,
    ProviderDiscoveryBootstrap,
    OperatorPromptInput,
    GovernedCatalogMaterialization,
    ChildOverlayMaterialization,
    McpConfigurationMaterialization,
}

/// Canonical, closed binding contract. `Effective` can be accepted only when the named getter
/// actually reads the V2 checkpoint. `Fixed` carries no fake getter receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeBindingSpec {
    Effective {
        adapter: ProductionOwnerId,
        owner: ProductionOwnerSymbolId,
        getter: RuntimeGetterId,
        strategy_slot: CoreStrategySlot,
        evidence: EvidenceProjectionId,
    },
    Fixed {
        adapter: ProductionOwnerId,
        authority: FixedAuthorityId,
        evidence: EvidenceProjectionId,
    },
    /// Representable only for adversarial/non-canonical fixtures; registry validation rejects it.
    Unbound { adapter: ProductionOwnerId },
}

impl RuntimeBindingSpec {
    pub const fn adapter(self) -> ProductionOwnerId {
        match self {
            Self::Effective { adapter, .. }
            | Self::Fixed { adapter, .. }
            | Self::Unbound { adapter } => adapter,
        }
    }

    pub const fn evidence(self) -> Option<EvidenceProjectionId> {
        match self {
            Self::Effective { evidence, .. } | Self::Fixed { evidence, .. } => Some(evidence),
            Self::Unbound { .. } => None,
        }
    }
}

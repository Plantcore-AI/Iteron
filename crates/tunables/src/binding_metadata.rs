use crate::{
    AuthorityClass, EvidenceProjectionId, FixedAuthorityId, ImplementationStatus,
    ProductionOwnerId, RuntimeBindingSpec, RuntimeGetterId,
};

pub(crate) const fn runtime_binding(
    ordinal: u16,
    status: ImplementationStatus,
    authority_class: AuthorityClass,
) -> RuntimeBindingSpec {
    let adapter = adapter(ordinal);
    let evidence = EvidenceProjectionId::RunGenesisTunablesV2;
    match status {
        ImplementationStatus::Full => RuntimeBindingSpec::Effective {
            adapter,
            owner: owner_symbol(ordinal),
            getter: getter(ordinal),
            strategy_slot: crate::strategy_slots::primary_strategy_slot(ordinal),
            evidence,
        },
        ImplementationStatus::FixedHidden => RuntimeBindingSpec::Fixed {
            adapter,
            authority: fixed_authority(ordinal, authority_class),
            evidence,
        },
        ImplementationStatus::Partial | ImplementationStatus::Missing => {
            RuntimeBindingSpec::Unbound { adapter }
        }
    }
}

const fn adapter(ordinal: u16) -> ProductionOwnerId {
    match ordinal {
        1..=34 => ProductionOwnerId::CoreFacts,
        35..=85 => ProductionOwnerId::ExecutionFacts,
        86..=132 => ProductionOwnerId::ProviderProcessFacts,
        133..=160 => ProductionOwnerId::ExtensionFacts,
        _ => panic!("unknown tunable ordinal"),
    }
}

const fn owner_symbol(ordinal: u16) -> crate::ProductionOwnerSymbolId {
    use crate::ProductionOwnerSymbolId as Owner;
    match ordinal {
        1..=3 => Owner::ProviderSelection,
        4 => Owner::EffortPolicy,
        5..=8 => Owner::BudgetPolicy,
        9..=12 => Owner::PermissionPolicy,
        13 | 27 | 102..=104 => Owner::CompactionPolicy,
        14 | 49 | 123..=125 | 128..=131 => Owner::VerificationPolicy,
        15..=17 => Owner::RetryPolicy,
        18 => Owner::EgressPolicy,
        23 => Owner::ProviderInstance,
        29 => Owner::InstructionDiscoveryPolicy,
        30 | 31 | 105 | 106 => Owner::MemoryPolicy,
        39..=46 => Owner::ObservationToolPolicy,
        61 | 65 | 66 | 140..=142 | 146 => Owner::WorkflowExecutionPolicy,
        68 => Owner::MultimodalAdmissionPolicy,
        69 => Owner::AppServerQueuePolicy,
        76 => Owner::AgentCatalog,
        79 => Owner::HookCatalog,
        80 => Owner::WorkflowGraph,
        86..=92 | 155 | 157 | 158 => Owner::ProviderGovernor,
        93 | 133..=136 => Owner::AgentOverlayPolicy,
        96..=100 | 107 | 121 | 148 => Owner::ContextMaterializationPolicy,
        108..=111 | 113 | 114 | 117 | 122 => Owner::ProcessRuntimePolicy,
        118 => Owner::BinaryMediaPolicy,
        119 | 120 => Owner::LspRuntimePolicy,
        138 => Owner::SessionSpawnLedger,
        147 | 149 | 152..=154 => Owner::McpRuntimePolicy,
        159 => Owner::SessionIsolationPolicy,
        _ => panic!("full tunable has no concrete production owner symbol"),
    }
}

const fn getter(ordinal: u16) -> RuntimeGetterId {
    match ordinal {
        1..=17 | 23 | 27 | 29..=31 | 96..=107 | 121 | 123..=125 | 128..=131 | 138 | 148 | 159 => {
            RuntimeGetterId::EffectiveCore
        }
        18 | 108..=114 | 117 | 119 | 120 | 122 => RuntimeGetterId::EffectiveTooling,
        39..=46 => RuntimeGetterId::EffectiveObservationTools,
        49 => RuntimeGetterId::VerificationFeedback,
        61 | 65 | 66 | 93 | 133..=136 | 140..=142 | 146 => RuntimeGetterId::EffectiveExecution,
        68 => RuntimeGetterId::EffectiveInputAdmission,
        69 => RuntimeGetterId::EffectiveAppServer,
        76 | 79 | 80 => RuntimeGetterId::EffectiveContent,
        86..=92 | 155 | 157 | 158 => RuntimeGetterId::EffectiveProvider,
        118 => RuntimeGetterId::EffectiveBinaryMedia,
        147 | 149 | 152..=154 => RuntimeGetterId::EffectiveMcp,
        _ => panic!("full tunable has no post-checkpoint getter"),
    }
}

const fn fixed_authority(ordinal: u16, class: AuthorityClass) -> FixedAuthorityId {
    match ordinal {
        70 => FixedAuthorityId::ProviderDiscoveryBootstrap,
        71 => FixedAuthorityId::OperatorPromptInput,
        73 | 74 | 75 | 77 | 78 | 85 => FixedAuthorityId::GovernedCatalogMaterialization,
        _ => match class {
            AuthorityClass::Strategy => FixedAuthorityId::StrategyInvariant,
            AuthorityClass::Operator => FixedAuthorityId::OperatorBoundary,
            AuthorityClass::GovernedArtifact => FixedAuthorityId::GovernedArtifactBoundary,
            AuthorityClass::RuntimeInvariant => FixedAuthorityId::RuntimeInvariant,
            AuthorityClass::KernelInvariant => FixedAuthorityId::KernelInvariant,
        },
    }
}

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
        14 | 48..=50 | 123..=131 => Owner::VerificationPolicy,
        15..=17 => Owner::RetryPolicy,
        18 => Owner::EgressPolicy,
        19 | 23 => Owner::ProviderInstance,
        20..=22 => Owner::EffortPolicy,
        24..=28 => Owner::CompactionPolicy,
        29 => Owner::InstructionDiscoveryPolicy,
        30..=32 | 105 | 106 => Owner::MemoryPolicy,
        33 => Owner::InstructionDiscoveryPolicy,
        34 => Owner::BudgetPolicy,
        35..=47 => Owner::ObservationToolPolicy,
        51..=66 | 115 | 116 | 132 | 137 | 139..=146 => Owner::WorkflowExecutionPolicy,
        67 | 70 | 86..=92 | 94 | 95 | 155..=158 => Owner::ProviderGovernor,
        68 => Owner::MultimodalAdmissionPolicy,
        69 => Owner::AppServerQueuePolicy,
        71..=76 => Owner::AgentCatalog,
        79 => Owner::HookCatalog,
        80 => Owner::WorkflowGraph,
        93 | 133..=136 => Owner::AgentOverlayPolicy,
        96..=101 | 107 | 121 | 148 => Owner::ContextMaterializationPolicy,
        108..=111 | 113 | 114 | 117 | 122 => Owner::ProcessRuntimePolicy,
        118 => Owner::BinaryMediaPolicy,
        119 | 120 => Owner::LspRuntimePolicy,
        138 => Owner::SessionSpawnLedger,
        147 | 149..=154 => Owner::McpRuntimePolicy,
        159 => Owner::SessionIsolationPolicy,
        _ => panic!("full tunable has no concrete production owner symbol"),
    }
}

const fn getter(ordinal: u16) -> RuntimeGetterId {
    match ordinal {
        1..=17 | 19..=34 | 48 | 96..=107 | 121 | 123..=132 | 138 | 148 | 159 => {
            RuntimeGetterId::EffectiveCore
        }
        18 | 35..=38 | 108..=114 | 117 | 119 | 120 | 122 => RuntimeGetterId::EffectiveTooling,
        39..=47 => RuntimeGetterId::EffectiveObservationTools,
        49..=50 => RuntimeGetterId::VerificationFeedback,
        51..=66 | 93 | 115 | 116 | 133..=146 => RuntimeGetterId::EffectiveExecution,
        68 => RuntimeGetterId::EffectiveInputAdmission,
        69 => RuntimeGetterId::EffectiveAppServer,
        71..=76 | 79 | 80 => RuntimeGetterId::EffectiveContent,
        67 | 70 | 86..=95 | 155..=158 => RuntimeGetterId::EffectiveProvider,
        118 => RuntimeGetterId::EffectiveBinaryMedia,
        147 | 149..=154 => RuntimeGetterId::EffectiveMcp,
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

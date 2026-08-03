use crate::{
    ActivationPredicate, ActivationSpec, AuthorityClass, CoreStrategySlot, DefaultKind,
    DefaultResolutionSource, Domain, ImplementationStatus, OptimizationClass, OptimizationSpec,
    RiskClass, SearchPhase, SourceKind, SourceTrust, ValueKind,
};

pub(crate) use crate::requirements::requirements;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptimizationSeed {
    FixedInvariant,
    OperatorOnly,
    OfflineSearch,
    RuntimeAdaptive,
    CatalogCurated,
    Inactive,
}

const ROUTER_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Router];
const PLANNER_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Planner];
const CONTEXT_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Context];
const MEMORY_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Memory];
const SCHEDULER_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Scheduler];
const TOOL_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::ToolPolicy];
const VERIFIER_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Verifier];
const MODEL_ROUTER_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::ModelRouter];
const COLLABORATION_SLOT: &[CoreStrategySlot] = &[CoreStrategySlot::Collaboration];
const ROUTER_MODEL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Router, CoreStrategySlot::ModelRouter];
const PLANNER_MODEL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter];
const MODEL_COLLABORATION: &[CoreStrategySlot] = &[
    CoreStrategySlot::ModelRouter,
    CoreStrategySlot::Collaboration,
];
const CONTEXT_VERIFIER: &[CoreStrategySlot] =
    &[CoreStrategySlot::Context, CoreStrategySlot::Verifier];
const MEMORY_CONTEXT_SLOT: &[CoreStrategySlot] =
    &[CoreStrategySlot::Memory, CoreStrategySlot::Context];
const CONTEXT_MEMORY_SLOT: &[CoreStrategySlot] =
    &[CoreStrategySlot::Context, CoreStrategySlot::Memory];
const SCHEDULER_TOOL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy];
const ROUTER_TOOL: &[CoreStrategySlot] = &[CoreStrategySlot::Router, CoreStrategySlot::ToolPolicy];
const CONTEXT_TOOL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy];
const VERIFIER_PLANNER: &[CoreStrategySlot] =
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Planner];
const VERIFIER_TOOL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Verifier, CoreStrategySlot::ToolPolicy];
const VERIFIER_COLLABORATION: &[CoreStrategySlot] =
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Collaboration];
const PLANNER_VERIFIER: &[CoreStrategySlot] =
    &[CoreStrategySlot::Planner, CoreStrategySlot::Verifier];
const PLANNER_COLLABORATION: &[CoreStrategySlot] =
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration];
const TOOL_COLLABORATION: &[CoreStrategySlot] = &[
    CoreStrategySlot::ToolPolicy,
    CoreStrategySlot::Collaboration,
];
const MEMORY_COLLABORATION: &[CoreStrategySlot] =
    &[CoreStrategySlot::Memory, CoreStrategySlot::Collaboration];
const SCHEDULER_COLLABORATION: &[CoreStrategySlot] =
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration];
const COLLABORATION_TOOL: &[CoreStrategySlot] = &[
    CoreStrategySlot::Collaboration,
    CoreStrategySlot::ToolPolicy,
];
const COLLABORATION_VERIFIER: &[CoreStrategySlot] =
    &[CoreStrategySlot::Collaboration, CoreStrategySlot::Verifier];
const TOOL_CONTEXT_SLOT: &[CoreStrategySlot] =
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context];
const SCHEDULER_MODEL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter];
const CONTEXT_MODEL: &[CoreStrategySlot] =
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter];

pub(crate) const fn aliases(ordinal: u16) -> &'static [&'static str] {
    match ordinal {
        1 => &["provider_id"],
        2 => &["model_id"],
        4 => &["reasoning_effort"],
        8 => &["wall_timeout"],
        14 => &["verification_command"],
        39 => &["shell_execution_envelope"],
        67 => &["connect_tls_timeout", "http_connect_timeout"],
        76 => &["agent_definition_catalog"],
        94 => &["provider_request_deadline"],
        95 => &["stream_idle_timeout"],
        115 => &["effecting_tool_parallelism"],
        137 => &["agent_spawn_depth"],
        138 => &["workflow_spawn_cap"],
        150 => &["mcp_server_startup_timeout"],
        151 => &["mcp_tool_timeout"],
        _ => &[],
    }
}

pub(crate) const fn default_resolution_source(
    ordinal: u16,
    kind: DefaultKind,
) -> DefaultResolutionSource {
    match kind {
        DefaultKind::Literal => DefaultResolutionSource::Literal,
        DefaultKind::Derived => DefaultResolutionSource::BuiltinDerivation,
        DefaultKind::Catalog => DefaultResolutionSource::GovernedCatalog,
        DefaultKind::OperatorRequired => DefaultResolutionSource::Operator,
        DefaultKind::Dynamic => match ordinal {
            92 => DefaultResolutionSource::ModelMetadata,
            91 | 95 | 100 | 118 | 153 | 155 | 158 => DefaultResolutionSource::ProviderCapability,
            96 => DefaultResolutionSource::ModelMetadata,
            156 => DefaultResolutionSource::Transport,
            _ => DefaultResolutionSource::RuntimeObservation,
        },
    }
}

pub(crate) const fn source_trust(ordinal: u16, kind: SourceKind) -> SourceTrust {
    match ordinal {
        77 | 96 | 100 | 158 => SourceTrust::ProviderAttested,
        82 => SourceTrust::GovernedBundle,
        89 => SourceTrust::RuntimeObservation,
        _ => match kind {
            SourceKind::Cli | SourceKind::UserConfig | SourceKind::Environment => {
                SourceTrust::Operator
            }
            SourceKind::ProjectConfig => SourceTrust::Repository,
            SourceKind::Builtin | SourceKind::DerivedPolicy => SourceTrust::Builtin,
            SourceKind::Catalog => SourceTrust::Repository,
            SourceKind::RuntimeObservation => SourceTrust::RuntimeObservation,
            SourceKind::ExternalProvider => SourceTrust::ProviderAttested,
            SourceKind::GovernedBundle => SourceTrust::GovernedBundle,
            SourceKind::Registry => SourceTrust::RegistryDeclaration,
        },
    }
}

pub(crate) const fn activation(
    status: ImplementationStatus,
    source: SourceKind,
    locator: &'static str,
) -> ActivationSpec {
    match status {
        ImplementationStatus::Full => match source {
            SourceKind::Cli
            | SourceKind::UserConfig
            | SourceKind::ProjectConfig
            | SourceKind::Environment
            | SourceKind::GovernedBundle => ActivationSpec {
                predicate: ActivationPredicate::Configured { source },
                inactive_reason: Some("the corresponding admitted configuration is absent"),
            },
            _ => ActivationSpec {
                predicate: ActivationPredicate::Always,
                inactive_reason: None,
            },
        },
        ImplementationStatus::Partial => ActivationSpec {
            predicate: ActivationPredicate::RuntimeDerived { seam: locator },
            inactive_reason: Some(
                "independent activation is unavailable because the production seam is grouped or incomplete",
            ),
        },
        ImplementationStatus::Missing => ActivationSpec {
            predicate: ActivationPredicate::Unavailable,
            inactive_reason: Some("no independent production control is implemented"),
        },
        ImplementationStatus::FixedHidden => ActivationSpec {
            predicate: ActivationPredicate::Always,
            inactive_reason: None,
        },
    }
}

pub(crate) const fn strategy_slots(ordinal: u16, domain: Domain) -> &'static [CoreStrategySlot] {
    match ordinal {
        86 | 87 | 89 | 90 | 91 | 94 | 95 | 155 | 156 => MODEL_ROUTER_SLOT,
        88 => ROUTER_MODEL,
        92 => PLANNER_MODEL,
        93 | 133 => MODEL_COLLABORATION,
        96..=103 => CONTEXT_SLOT,
        104 => CONTEXT_VERIFIER,
        105 => MEMORY_CONTEXT_SLOT,
        106 => MEMORY_SLOT,
        107 => CONTEXT_MEMORY_SLOT,
        108 | 110 | 111 | 112 | 113 | 114 | 116 | 117 | 119 | 120 | 122 | 123 | 124 | 125 | 126
        | 128 | 130 | 147 | 149 | 150 | 151 | 153 => match ordinal {
            123 | 124 | 125 | 126 | 128 | 130 => VERIFIER_SLOT,
            _ => TOOL_SLOT,
        },
        109 | 115 => SCHEDULER_TOOL,
        118 => ROUTER_TOOL,
        121 | 148 | 152 => CONTEXT_TOOL,
        127 => VERIFIER_PLANNER,
        129 => VERIFIER_TOOL,
        131 => VERIFIER_COLLABORATION,
        132 => PLANNER_VERIFIER,
        134 => PLANNER_COLLABORATION,
        135 => TOOL_COLLABORATION,
        136 => MEMORY_COLLABORATION,
        137 | 142 | 146 => SCHEDULER_COLLABORATION,
        138..=141 => SCHEDULER_SLOT,
        143 | 159 => COLLABORATION_TOOL,
        144 | 160 => COLLABORATION_VERIFIER,
        145 => COLLABORATION_SLOT,
        154 => TOOL_CONTEXT_SLOT,
        157 => SCHEDULER_MODEL,
        158 => CONTEXT_MODEL,
        _ => match domain {
            Domain::Provider => MODEL_ROUTER_SLOT,
            Domain::Reasoning => PLANNER_SLOT,
            Domain::Budget | Domain::Runtime => SCHEDULER_SLOT,
            Domain::Context => CONTEXT_SLOT,
            Domain::Memory => MEMORY_SLOT,
            Domain::Tooling | Domain::Extensibility | Domain::Governance => TOOL_SLOT,
            Domain::Verification | Domain::Evaluation => VERIFIER_SLOT,
            Domain::Orchestration => COLLABORATION_SLOT,
            Domain::Observability | Domain::Interface => ROUTER_SLOT,
        },
    }
}

/// Explicitly reviewed optimization table. No decision here is inferred from serialized value
/// shape: Appendix F contains, for example, a P2 boolean (N-CX06) and a P1 policy (N-CX07).
pub(crate) const fn optimization(
    ordinal: u16,
    _seed: OptimizationSeed,
    _kind: ValueKind,
) -> OptimizationSpec {
    let class = optimization_class(ordinal);
    match class {
        OptimizationClass::P1 => OptimizationSpec {
            class,
            search_phase: SearchPhase::P1,
            pin_reason: None,
        },
        OptimizationClass::P2 => OptimizationSpec {
            class,
            search_phase: SearchPhase::P2,
            pin_reason: None,
        },
        OptimizationClass::CStructured
        | OptimizationClass::CArtifact
        | OptimizationClass::CComponent => OptimizationSpec {
            class,
            search_phase: SearchPhase::Conditional,
            pin_reason: None,
        },
        OptimizationClass::Pin => OptimizationSpec {
            class,
            search_phase: SearchPhase::Pinned,
            pin_reason: Some("protocol, safety, durability, replay, benchmark, or authority pin"),
        },
    }
}

const fn optimization_class(ordinal: u16) -> OptimizationClass {
    if matches!(
        ordinal,
        3 | 6
            ..=12
                | 18
                | 50
                | 60
                | 68
                | 69
                | 77
                | 78
                | 79
                | 81
                | 82
                | 83
                | 84
                | 85
                | 87
                | 112
                | 114
                | 125
                | 126
                | 130
                | 143
                | 153
                | 159
                | 160
    ) {
        OptimizationClass::Pin
    } else if matches!(ordinal, 1 | 2 | 26 | 86 | 93 | 108 | 118 | 119 | 133 | 147) {
        OptimizationClass::CComponent
    } else if matches!(ordinal, 14 | 29 | 71 | 72 | 73 | 74 | 75 | 76 | 80 | 154) {
        OptimizationClass::CArtifact
    } else if matches!(
        ordinal,
        20 | 21
            | 22
            | 27
            | 28
            | 37
            | 51
            | 52
            | 62
            | 64
            | 65
            | 89
            | 90
            | 91
            | 96
            | 100
            | 103
            | 104
            | 111
            | 113
            | 116
            | 123
            | 128
            | 129
            | 135
            | 136
            | 144
            | 145
    ) {
        OptimizationClass::CStructured
    } else if matches!(
        ordinal,
        24 | 31
            | 38
            | 39
            | 40
            | 41
            | 42
            | 43
            | 44
            | 45
            | 46
            | 61
            | 70
            | 88
            | 92
            | 101
            | 109
            | 117
            | 120
            | 122
            | 131
            | 132
            | 134
            | 137
            | 138
            | 140
            | 141
            | 142
            | 146
            | 148
            | 149
            | 150
            | 151
            | 152
            | 155
            | 156
            | 157
            | 158
    ) {
        OptimizationClass::P2
    } else {
        OptimizationClass::P1
    }
}

pub(crate) const fn authority(ordinal: u16, seed: OptimizationSeed) -> AuthorityClass {
    if ordinal == 60 {
        AuthorityClass::KernelInvariant
    } else {
        match optimization_class(ordinal) {
            OptimizationClass::Pin => match seed {
                OptimizationSeed::CatalogCurated => AuthorityClass::GovernedArtifact,
                OptimizationSeed::OperatorOnly | OptimizationSeed::Inactive => {
                    AuthorityClass::Operator
                }
                _ => AuthorityClass::RuntimeInvariant,
            },
            OptimizationClass::CArtifact | OptimizationClass::CComponent => {
                AuthorityClass::GovernedArtifact
            }
            OptimizationClass::P1 | OptimizationClass::P2 | OptimizationClass::CStructured => {
                AuthorityClass::Strategy
            }
        }
    }
}

pub(crate) const fn risk(ordinal: u16, domain: Domain, authority: AuthorityClass) -> RiskClass {
    if matches!(authority, AuthorityClass::KernelInvariant)
        || matches!(
            ordinal,
            9 | 10
                | 11
                | 12
                | 18
                | 28
                | 54
                | 60
                | 68
                | 69
                | 84
                | 87
                | 112
                | 114
                | 125
                | 126
                | 130
                | 143
                | 153
                | 159
                | 160
        )
    {
        RiskClass::Critical
    } else {
        match domain {
            Domain::Governance | Domain::Budget | Domain::Tooling | Domain::Memory => {
                RiskClass::High
            }
            Domain::Provider
            | Domain::Verification
            | Domain::Orchestration
            | Domain::Runtime
            | Domain::Extensibility => RiskClass::Medium,
            Domain::Reasoning
            | Domain::Context
            | Domain::Observability
            | Domain::Interface
            | Domain::Evaluation => RiskClass::Low,
        }
    }
}

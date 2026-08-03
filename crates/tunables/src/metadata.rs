use crate::{
    AuthorityClass, Domain, OptimizationClass, OptimizationSpec, RiskClass, SearchPhase, ValueKind,
};

pub(crate) use crate::requirements::requirements;
pub(crate) use crate::strategy_slots::strategy_slots;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptimizationSeed {
    FixedInvariant,
    OperatorOnly,
    OfflineSearch,
    RuntimeAdaptive,
    CatalogCurated,
    Inactive,
}

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
        150 => &["mcp_server_startup_timeout"],
        151 => &["mcp_tool_timeout"],
        _ => &[],
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

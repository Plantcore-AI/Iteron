use core_tunables::{
    ActivationPredicate, AuthorityClass, CapabilityRequirement, CoreStrategySlot, DefaultKind,
    DefaultResolutionSource, EXPECTED_FAMILY_COUNT, FAMILY_SCHEMA_VERSION, ImplementationStatus,
    OptimizationClass, ProviderRequirement, REFERENCED_SCHEMAS, REGISTRY_DIGEST_SHA256,
    RelevanceLevel, SearchPhase, SourceKind, SourceTrust, StructuredValueDomain, ValueKind,
    canonical_artifact_json, canonical_payload_json, families, family_semantic_digest,
    registry_digest, validate_registry,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

const EXPANSION_IDS: &[&str] = &[
    // Appendix F.1 — N-RM01..N-RM10.
    "model_fallback_chain",
    "failover_eligible_error_taxonomy",
    "route_quality_cost_latency_objective_weights",
    "provider_health_circuit_breaker_state_policy",
    "hedged_request_policy",
    "provider_service_tier",
    "response_verbosity",
    "role_specific_model_map",
    "provider_request_total_deadline",
    "stream_idle_watchdog",
    // Appendix F.2 — N-CX01..N-CX12.
    "context_window_override_reserve",
    "system_prefix_budget",
    "conversation_history_budget",
    "tool_result_history_budget",
    "multimodal_token_budget",
    "auto_compaction_enable",
    "compaction_cooldown_hysteresis",
    "multi_stage_summary_topology",
    "summary_consistency_coverage_check",
    "hybrid_retrieval_fusion_weights",
    "retrieval_recency_decay",
    "context_novelty_dedup_threshold",
    // Appendix F.3 — N-TP01..N-TP15.
    "persistent_pty_backend",
    "concurrent_background_job_cap",
    "job_idle_stall_timeout",
    "interactive_stdin_wait_policy",
    "process_signal_kill_escalation",
    "process_cwd_continuity",
    "child_process_environment_reuse",
    "effecting_tool_concurrency",
    "write_set_conflict_admission",
    "tool_output_spill_to_disk_policy",
    "binary_media_inspection_routing",
    "lsp_server_language_selection",
    "lsp_timeout_restart_policy",
    "lsp_result_context_budget",
    "tool_result_cache_ttl",
    // Appendix F.4 — N-VR01..N-VR10.
    "test_selection_strategy",
    "incremental_versus_full_verification",
    "flaky_test_detection_quarantine",
    "failure_classification_taxonomy",
    "retry_eligibility_policy",
    "rollback_on_verification_failure",
    "workspace_checkpoint_cadence",
    "selective_restore_scope",
    "verification_quorum_consensus",
    "recovery_escalation_policy",
    // Appendix F.5 — N-AG01..N-AG14.
    "per_agent_model",
    "per_agent_effort_thinking",
    "per_agent_tool_profile",
    "per_agent_memory_scope",
    "spawn_depth_control",
    "per_session_spawn_cap",
    "task_priority_scheduling",
    "speculative_sibling_count",
    "speculative_sibling_cancellation",
    "early_stop_quorum_policy",
    "writer_worktree_isolation_mode",
    "merge_conflict_arbitration",
    "inter_agent_messaging_topology",
    "task_retry_reassignment_policy",
    // Appendix F.6 — N-MP01..N-MP08.
    "mcp_transport_selection",
    "deferred_discovery_threshold",
    "mcp_reconnect_backoff",
    "per_server_startup_deadline",
    "per_tool_mcp_deadline",
    "mcp_result_cap_spill_policy",
    "oauth_auth_lifecycle_policy",
    "resource_prompt_plugin_capability_exposure",
    // Appendix F.7 — N-SR01..N-SR06.
    "request_compression_policy",
    "http_pool_keepalive_idle_policy",
    "rate_limit_aware_admission",
    "prompt_cache_ttl_breakpoint_strategy",
    "session_isolation_profile",
    "replay_divergence_detection_policy",
];

/// Exact Appendix F relevance pairs in formal order: SWE-bench Pro, Terminal-Bench 2.1.
const APPENDIX_RELEVANCE: &[(RelevanceLevel, RelevanceLevel)] = &[
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 86
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 87
    (RelevanceLevel::High, RelevanceLevel::High),     // 88
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 89
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 90
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 91
    (RelevanceLevel::Medium, RelevanceLevel::Low),    // 92
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 93
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 94
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 95
    (RelevanceLevel::High, RelevanceLevel::High),     // 96
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 97
    (RelevanceLevel::High, RelevanceLevel::High),     // 98
    (RelevanceLevel::High, RelevanceLevel::High),     // 99
    (RelevanceLevel::Low, RelevanceLevel::Medium),    // 100
    (RelevanceLevel::High, RelevanceLevel::High),     // 101
    (RelevanceLevel::High, RelevanceLevel::High),     // 102
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 103
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 104
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 105
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 106
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 107
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 108
    (RelevanceLevel::Low, RelevanceLevel::High),      // 109
    (RelevanceLevel::Low, RelevanceLevel::High),      // 110
    (RelevanceLevel::Low, RelevanceLevel::High),      // 111
    (RelevanceLevel::Low, RelevanceLevel::High),      // 112
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 113
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 114
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 115
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 116
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 117
    (RelevanceLevel::Low, RelevanceLevel::Medium),    // 118
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 119
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 120
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 121
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 122
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 123
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 124
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 125
    (RelevanceLevel::High, RelevanceLevel::High),     // 126
    (RelevanceLevel::High, RelevanceLevel::High),     // 127
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 128
    (RelevanceLevel::Medium, RelevanceLevel::Low),    // 129
    (RelevanceLevel::Medium, RelevanceLevel::Low),    // 130
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 131
    (RelevanceLevel::High, RelevanceLevel::High),     // 132
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 133
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 134
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 135
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 136
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 137
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 138
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 139
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 140
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 141
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 142
    (RelevanceLevel::High, RelevanceLevel::Low),      // 143
    (RelevanceLevel::High, RelevanceLevel::Low),      // 144
    (RelevanceLevel::High, RelevanceLevel::Medium),   // 145
    (RelevanceLevel::High, RelevanceLevel::High),     // 146
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 147
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 148
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 149
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 150
    (RelevanceLevel::Medium, RelevanceLevel::High),   // 151
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 152
    (RelevanceLevel::Low, RelevanceLevel::Low),       // 153
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 154
    (RelevanceLevel::Low, RelevanceLevel::Medium),    // 155
    (RelevanceLevel::Low, RelevanceLevel::Medium),    // 156
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 157
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 158
    (RelevanceLevel::High, RelevanceLevel::High),     // 159
    (RelevanceLevel::Medium, RelevanceLevel::Medium), // 160
];

/// Exact Appendix F StrategySlot bindings, preserving slash-separated audited order.
const APPENDIX_SLOTS: &[&[CoreStrategySlot]] = &[
    &[CoreStrategySlot::ModelRouter], // 86 RM01
    &[CoreStrategySlot::ModelRouter], // 87 RM02
    &[CoreStrategySlot::Router, CoreStrategySlot::ModelRouter], // 88 RM03
    &[CoreStrategySlot::ModelRouter], // 89 RM04
    &[CoreStrategySlot::ModelRouter], // 90 RM05
    &[CoreStrategySlot::ModelRouter], // 91 RM06
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter], // 92 RM07
    &[
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::Collaboration,
    ], // 93 RM08
    &[CoreStrategySlot::ModelRouter], // 94 RM09
    &[CoreStrategySlot::ModelRouter], // 95 RM10
    &[CoreStrategySlot::Context],     // 96 CX01
    &[CoreStrategySlot::Context],     // 97 CX02
    &[CoreStrategySlot::Context],     // 98 CX03
    &[CoreStrategySlot::Context],     // 99 CX04
    &[CoreStrategySlot::Context],     // 100 CX05
    &[CoreStrategySlot::Context],     // 101 CX06
    &[CoreStrategySlot::Context],     // 102 CX07
    &[CoreStrategySlot::Context],     // 103 CX08
    &[CoreStrategySlot::Context, CoreStrategySlot::Verifier], // 104 CX09
    &[CoreStrategySlot::Memory, CoreStrategySlot::Context], // 105 CX10
    &[CoreStrategySlot::Memory],      // 106 CX11
    &[CoreStrategySlot::Context, CoreStrategySlot::Memory], // 107 CX12
    &[CoreStrategySlot::ToolPolicy],  // 108 TP01
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy], // 109 TP02
    &[CoreStrategySlot::ToolPolicy],  // 110 TP03
    &[CoreStrategySlot::ToolPolicy],  // 111 TP04
    &[CoreStrategySlot::ToolPolicy],  // 112 TP05
    &[CoreStrategySlot::ToolPolicy],  // 113 TP06
    &[CoreStrategySlot::ToolPolicy],  // 114 TP07
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy], // 115 TP08
    &[CoreStrategySlot::ToolPolicy],  // 116 TP09
    &[CoreStrategySlot::ToolPolicy],  // 117 TP10
    &[CoreStrategySlot::Router, CoreStrategySlot::ToolPolicy], // 118 TP11
    &[CoreStrategySlot::ToolPolicy],  // 119 TP12
    &[CoreStrategySlot::ToolPolicy],  // 120 TP13
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy], // 121 TP14
    &[CoreStrategySlot::ToolPolicy],  // 122 TP15
    &[CoreStrategySlot::Verifier],    // 123 VR01
    &[CoreStrategySlot::Verifier],    // 124 VR02
    &[CoreStrategySlot::Verifier],    // 125 VR03
    &[CoreStrategySlot::Verifier],    // 126 VR04
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Planner], // 127 VR05
    &[CoreStrategySlot::Verifier],    // 128 VR06
    &[CoreStrategySlot::Verifier, CoreStrategySlot::ToolPolicy], // 129 VR07
    &[CoreStrategySlot::Verifier],    // 130 VR08
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Collaboration], // 131 VR09
    &[CoreStrategySlot::Planner, CoreStrategySlot::Verifier], // 132 VR10
    &[
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::Collaboration,
    ], // 133 AG01
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration], // 134 AG02
    &[
        CoreStrategySlot::ToolPolicy,
        CoreStrategySlot::Collaboration,
    ], // 135 AG03
    &[CoreStrategySlot::Memory, CoreStrategySlot::Collaboration], // 136 AG04
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 137 AG05
    &[CoreStrategySlot::Scheduler],   // 138 AG06
    &[CoreStrategySlot::Scheduler],   // 139 AG07
    &[CoreStrategySlot::Scheduler],   // 140 AG08
    &[CoreStrategySlot::Scheduler],   // 141 AG09
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 142 AG10
    &[
        CoreStrategySlot::Collaboration,
        CoreStrategySlot::ToolPolicy,
    ], // 143 AG11
    &[CoreStrategySlot::Collaboration, CoreStrategySlot::Verifier], // 144 AG12
    &[CoreStrategySlot::Collaboration], // 145 AG13
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 146 AG14
    &[CoreStrategySlot::ToolPolicy],  // 147 MP01
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy], // 148 MP02
    &[CoreStrategySlot::ToolPolicy],  // 149 MP03
    &[CoreStrategySlot::ToolPolicy],  // 150 MP04
    &[CoreStrategySlot::ToolPolicy],  // 151 MP05
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy], // 152 MP06
    &[CoreStrategySlot::ToolPolicy],  // 153 MP07
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context], // 154 MP08
    &[CoreStrategySlot::ModelRouter], // 155 SR01
    &[CoreStrategySlot::ModelRouter], // 156 SR02
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter], // 157 SR03
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter], // 158 SR04
    &[
        CoreStrategySlot::Collaboration,
        CoreStrategySlot::ToolPolicy,
    ], // 159 SR05
    &[CoreStrategySlot::Collaboration, CoreStrategySlot::Verifier], // 160 SR06
];

/// Exact Appendix F P1/P2/C/Pin table. Formal `C` rows are reviewed into §2.3 object classes.
const APPENDIX_OPTIMIZATION: &[OptimizationClass] = &[
    OptimizationClass::CComponent,  // 86 C: fallback component chain
    OptimizationClass::Pin,         // 87 Pin
    OptimizationClass::P2,          // 88 P2
    OptimizationClass::CStructured, // 89 C: health policy
    OptimizationClass::CStructured, // 90 C: hedge policy
    OptimizationClass::CStructured, // 91 C: capability-gated tier
    OptimizationClass::P2,          // 92 P2
    OptimizationClass::CComponent,  // 93 C: model component map
    OptimizationClass::P1,          // 94 P1
    OptimizationClass::P1,          // 95 P1
    OptimizationClass::CStructured, // 96 C
    OptimizationClass::P1,          // 97 P1
    OptimizationClass::P1,          // 98 P1
    OptimizationClass::P1,          // 99 P1
    OptimizationClass::CStructured, // 100 C
    OptimizationClass::P2,          // 101 P2 (boolean by audit)
    OptimizationClass::P1,          // 102 P1 (policy by audit)
    OptimizationClass::CStructured, // 103 C
    OptimizationClass::CStructured, // 104 C
    OptimizationClass::P1,          // 105 P1
    OptimizationClass::P1,          // 106 P1
    OptimizationClass::P1,          // 107 P1
    OptimizationClass::CComponent,  // 108 C: PTY component
    OptimizationClass::P2,          // 109 P2
    OptimizationClass::P1,          // 110 P1
    OptimizationClass::CStructured, // 111 C
    OptimizationClass::Pin,         // 112 Pin
    OptimizationClass::CStructured, // 113 C
    OptimizationClass::Pin,         // 114 Pin
    OptimizationClass::P1,          // 115 P1
    OptimizationClass::CStructured, // 116 C
    OptimizationClass::P2,          // 117 P2
    OptimizationClass::CComponent,  // 118 C: inspector component routing
    OptimizationClass::CComponent,  // 119 C: LSP component selection
    OptimizationClass::P2,          // 120 P2
    OptimizationClass::P1,          // 121 P1
    OptimizationClass::P2,          // 122 P2
    OptimizationClass::CStructured, // 123 C
    OptimizationClass::P1,          // 124 P1
    OptimizationClass::Pin,         // 125 Pin
    OptimizationClass::Pin,         // 126 Pin
    OptimizationClass::P1,          // 127 P1
    OptimizationClass::CStructured, // 128 C
    OptimizationClass::CStructured, // 129 C
    OptimizationClass::Pin,         // 130 Pin
    OptimizationClass::P2,          // 131 P2
    OptimizationClass::P2,          // 132 P2
    OptimizationClass::CComponent,  // 133 C: model component
    OptimizationClass::P2,          // 134 P2
    OptimizationClass::CStructured, // 135 C
    OptimizationClass::CStructured, // 136 C
    OptimizationClass::P2,          // 137 P2
    OptimizationClass::P2,          // 138 P2
    OptimizationClass::P1,          // 139 P1
    OptimizationClass::P2,          // 140 P2
    OptimizationClass::P2,          // 141 P2
    OptimizationClass::P2,          // 142 P2
    OptimizationClass::Pin,         // 143 Pin
    OptimizationClass::CStructured, // 144 C
    OptimizationClass::CStructured, // 145 C
    OptimizationClass::P2,          // 146 P2
    OptimizationClass::CComponent,  // 147 C: transport component
    OptimizationClass::P2,          // 148 P2
    OptimizationClass::P2,          // 149 P2
    OptimizationClass::P2,          // 150 P2
    OptimizationClass::P2,          // 151 P2
    OptimizationClass::P2,          // 152 P2
    OptimizationClass::Pin,         // 153 Pin
    OptimizationClass::CArtifact,   // 154 C: resource/prompt/plugin artifacts
    OptimizationClass::P2,          // 155 P2
    OptimizationClass::P2,          // 156 P2
    OptimizationClass::P2,          // 157 P2
    OptimizationClass::P2,          // 158 P2
    OptimizationClass::Pin,         // 159 Pin
    OptimizationClass::Pin,         // 160 Pin
];

const APPENDIX_DEFAULT_KINDS: &[DefaultKind] = &[
    DefaultKind::Literal, // 86
    DefaultKind::Literal, // 87
    DefaultKind::Derived, // 88
    DefaultKind::Derived, // 89
    DefaultKind::Literal, // 90
    DefaultKind::Dynamic, // 91
    DefaultKind::Dynamic, // 92
    DefaultKind::Derived, // 93
    DefaultKind::Derived, // 94
    DefaultKind::Dynamic, // 95
    DefaultKind::Dynamic, // 96
    DefaultKind::Derived, // 97
    DefaultKind::Derived, // 98
    DefaultKind::Derived, // 99
    DefaultKind::Dynamic, // 100
    DefaultKind::Literal, // 101
    DefaultKind::Derived, // 102
    DefaultKind::Literal, // 103
    DefaultKind::Literal, // 104
    DefaultKind::Literal, // 105
    DefaultKind::Literal, // 106
    DefaultKind::Derived, // 107
    DefaultKind::Literal, // 108
    DefaultKind::Literal, // 109
    DefaultKind::Derived, // 110
    DefaultKind::Dynamic, // 111
    DefaultKind::Literal, // 112
    DefaultKind::Literal, // 113
    DefaultKind::Literal, // 114
    DefaultKind::Literal, // 115
    DefaultKind::Literal, // 116
    DefaultKind::Derived, // 117
    DefaultKind::Dynamic, // 118
    DefaultKind::Dynamic, // 119
    DefaultKind::Derived, // 120
    DefaultKind::Derived, // 121
    DefaultKind::Derived, // 122
    DefaultKind::Derived, // 123
    DefaultKind::Derived, // 124
    DefaultKind::Literal, // 125
    DefaultKind::Catalog, // 126
    DefaultKind::Derived, // 127
    DefaultKind::Literal, // 128
    DefaultKind::Literal, // 129
    DefaultKind::Literal, // 130
    DefaultKind::Literal, // 131
    DefaultKind::Literal, // 132
    DefaultKind::Derived, // 133
    DefaultKind::Derived, // 134
    DefaultKind::Derived, // 135
    DefaultKind::Literal, // 136
    DefaultKind::Literal, // 137
    DefaultKind::Derived, // 138
    DefaultKind::Literal, // 139
    DefaultKind::Literal, // 140
    DefaultKind::Derived, // 141
    DefaultKind::Literal, // 142
    DefaultKind::Literal, // 143
    DefaultKind::Derived, // 144
    DefaultKind::Literal, // 145
    DefaultKind::Derived, // 146
    DefaultKind::Literal, // 147
    DefaultKind::Literal, // 148
    DefaultKind::Derived, // 149
    DefaultKind::Derived, // 150
    DefaultKind::Derived, // 151
    DefaultKind::Literal, // 152
    DefaultKind::Dynamic, // 153
    DefaultKind::Literal, // 154
    DefaultKind::Dynamic, // 155
    DefaultKind::Dynamic, // 156
    DefaultKind::Derived, // 157
    DefaultKind::Dynamic, // 158
    DefaultKind::Literal, // 159
    DefaultKind::Literal, // 160
];

fn family(id: &str) -> &'static core_tunables::Family {
    families()
        .iter()
        .find(|family| family.id == id)
        .unwrap_or_else(|| panic!("missing `{id}`"))
}

#[test]
fn registry_and_appendix_have_the_exact_stable_shape() {
    validate_registry().unwrap();
    let registry = families();
    assert_eq!(registry.len(), EXPECTED_FAMILY_COUNT);
    assert_eq!(registry[0].id, "provider");
    assert_eq!(registry[66].id, "provider_connect_tls_timeout");
    assert!(
        !registry
            .iter()
            .any(|family| family.id == "delegation_depth")
    );
    assert_eq!(registry[84].id, "web_search_backend_catalog");
    assert_eq!(
        registry[85..]
            .iter()
            .map(|family| family.id)
            .collect::<Vec<_>>(),
        EXPANSION_IDS
    );
    assert_eq!(EXPANSION_IDS.len(), 10 + 12 + 15 + 10 + 14 + 8 + 6);
}

#[test]
fn formal_entry_schema_is_complete_and_structured() {
    for family in families() {
        assert_eq!(
            family.schema_version, FAMILY_SCHEMA_VERSION,
            "{}",
            family.id
        );
        assert!(
            !family.requirements.capabilities.is_empty(),
            "{}",
            family.id
        );
        assert!(!family.strategy_slots.is_empty(), "{}", family.id);
        assert_eq!(
            family
                .strategy_slots
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            family.strategy_slots.len(),
            "{}",
            family.id
        );
        match family.implementation_status {
            ImplementationStatus::Missing => {
                assert!(matches!(
                    family.activation.predicate,
                    ActivationPredicate::Unavailable
                ));
                assert!(family.activation.inactive_reason.is_some());
            }
            ImplementationStatus::Partial => {
                assert!(matches!(
                    family.activation.predicate,
                    ActivationPredicate::RuntimeDerived { .. }
                ));
                assert!(family.activation.inactive_reason.is_some());
            }
            ImplementationStatus::Full | ImplementationStatus::FixedHidden => {
                assert!(!matches!(
                    family.activation.predicate,
                    ActivationPredicate::Unavailable
                ));
            }
        }
    }
}

#[test]
fn source_trust_has_audited_provider_signed_and_governed_exceptions() {
    for family in families() {
        let expected_trust = match family.ordinal {
            77 | 96 | 100 | 158 => SourceTrust::ProviderAttested,
            82 => SourceTrust::GovernedBundle,
            89 => SourceTrust::RuntimeObservation,
            _ => match family.source.kind {
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
        };
        assert_eq!(family.source.trust, expected_trust, "{}", family.id);
    }
}

#[test]
fn granular_capability_requirements_cover_provider_and_world_module_seams() {
    for (id, provider, capabilities) in [
        (
            "prompt_cache",
            ProviderRequirement::SelectedRoute,
            &[CapabilityRequirement::ProviderPromptCache][..],
        ),
        (
            "multimodal_token_budget",
            ProviderRequirement::SelectedRoute,
            &[
                CapabilityRequirement::ProviderMultimodal,
                CapabilityRequirement::ContextRead,
            ][..],
        ),
        (
            "provider_service_tier",
            ProviderRequirement::SelectedRoute,
            &[CapabilityRequirement::ProviderServiceTier][..],
        ),
        (
            "stream_idle_watchdog",
            ProviderRequirement::SelectedRoute,
            &[CapabilityRequirement::ProviderStreaming][..],
        ),
        (
            "lsp_server_language_selection",
            ProviderRequirement::None,
            &[CapabilityRequirement::LanguageServer][..],
        ),
        (
            "mcp_transport_selection",
            ProviderRequirement::None,
            &[CapabilityRequirement::McpTransport][..],
        ),
        (
            "oauth_auth_lifecycle_policy",
            ProviderRequirement::None,
            &[CapabilityRequirement::OAuth][..],
        ),
        (
            "resource_prompt_plugin_capability_exposure",
            ProviderRequirement::None,
            &[
                CapabilityRequirement::McpResource,
                CapabilityRequirement::ContextRead,
            ][..],
        ),
    ] {
        let family = family(id);
        assert_eq!(family.requirements.provider, provider, "{id}");
        assert_eq!(family.requirements.capabilities, capabilities, "{id}");
    }
}

#[test]
fn appendix_strategy_slot_bindings_are_exact_per_family() {
    assert_eq!(APPENDIX_SLOTS.len(), EXPANSION_IDS.len());
    for (family, expected) in families()[85..].iter().zip(APPENDIX_SLOTS) {
        assert_eq!(family.strategy_slots, *expected, "{}", family.id);
    }
}

#[test]
fn implementation_status_distinguishes_exposure_partial_missing_and_fixed_hidden() {
    for (status, expected) in [
        (ImplementationStatus::Full, 27),
        (ImplementationStatus::Partial, 54),
        (ImplementationStatus::Missing, 26),
        (ImplementationStatus::FixedHidden, 53),
    ] {
        assert_eq!(
            families()
                .iter()
                .filter(|family| family.implementation_status == status)
                .count(),
            expected,
            "{status:?}"
        );
    }

    let catalog = family("agent_catalog");
    assert_eq!(catalog.implementation_status, ImplementationStatus::Partial);
    assert_eq!(catalog.source.locator, "crates/agents/src/catalog.rs");

    let session_cap = family("per_session_spawn_cap");
    assert_eq!(
        session_cap.implementation_status,
        ImplementationStatus::Partial
    );
    assert!(session_cap.default.value.contains("per-workflow"));

    let connect = family("provider_connect_tls_timeout");
    assert_eq!(
        connect.implementation_status,
        ImplementationStatus::FixedHidden
    );
    assert_eq!(connect.default.kind, DefaultKind::Literal);
    assert_eq!(connect.default.value, "30 seconds");
    assert_eq!(connect.source.locator, "crates/provider/src/catalog.rs");
}

#[test]
fn defaults_are_independent_of_status_and_formal_corrections_are_pinned() {
    for kind in [
        DefaultKind::Literal,
        DefaultKind::Derived,
        DefaultKind::Dynamic,
    ] {
        assert!(families().iter().any(|family| family.default.kind == kind));
    }
    assert_eq!(APPENDIX_DEFAULT_KINDS.len(), EXPANSION_IDS.len());
    for (family, expected) in families()[85..].iter().zip(APPENDIX_DEFAULT_KINDS) {
        assert_eq!(family.default.kind, *expected, "{}", family.id);
    }
    for family in families()
        .iter()
        .filter(|family| family.implementation_status == ImplementationStatus::Missing)
    {
        assert!(
            matches!(
                family.default.kind,
                DefaultKind::Literal | DefaultKind::Derived | DefaultKind::Dynamic
            ),
            "{}",
            family.id
        );
    }

    for (id, kind, value) in [
        ("effecting_tool_concurrency", DefaultKind::Literal, "serial"),
        (
            "workspace_checkpoint_cadence",
            DefaultKind::Literal,
            "turn boundary",
        ),
        (
            "http_pool_keepalive_idle_policy",
            DefaultKind::Dynamic,
            "transport-derived",
        ),
        (
            "model_fallback_chain",
            DefaultKind::Literal,
            "empty route list",
        ),
        ("hedged_request_policy", DefaultKind::Literal, "disabled"),
        (
            "provider_service_tier",
            DefaultKind::Dynamic,
            "provider-selected tier",
        ),
        (
            "summary_consistency_coverage_check",
            DefaultKind::Literal,
            "false",
        ),
        ("persistent_pty_backend", DefaultKind::Literal, "disabled"),
        (
            "concurrent_background_job_cap",
            DefaultKind::Literal,
            "0 jobs",
        ),
        (
            "rollback_on_verification_failure",
            DefaultKind::Literal,
            "off",
        ),
        (
            "speculative_sibling_count",
            DefaultKind::Literal,
            "0 agents",
        ),
        (
            "writer_worktree_isolation_mode",
            DefaultKind::Literal,
            "false",
        ),
    ] {
        let family = family(id);
        assert_eq!(family.default.kind, kind, "{id}");
        assert_eq!(family.default.value, value, "{id}");
    }
    assert_eq!(
        family("http_pool_keepalive_idle_policy")
            .default
            .resolution_source,
        DefaultResolutionSource::Transport
    );
    assert_eq!(
        family("provider_service_tier").default.resolution_source,
        DefaultResolutionSource::ProviderCapability
    );
    assert_eq!(
        family("response_verbosity").default.resolution_source,
        DefaultResolutionSource::ModelMetadata
    );
}

#[test]
fn appendix_relevance_is_exactly_high_medium_or_low_in_swe_then_terminal_order() {
    assert_eq!(APPENDIX_RELEVANCE.len(), EXPANSION_IDS.len());
    for (family, expected) in families()[85..].iter().zip(APPENDIX_RELEVANCE) {
        assert_eq!(
            (
                family.benchmark_relevance.swe_bench_pro,
                family.benchmark_relevance.terminal_bench_2_1,
            ),
            *expected,
            "{}",
            family.id
        );
    }

    for (benchmark, expected) in [("swe", [37, 29, 9]), ("terminal", [26, 43, 6])] {
        let counts = [
            RelevanceLevel::High,
            RelevanceLevel::Medium,
            RelevanceLevel::Low,
        ]
        .map(|level| {
            families()[85..]
                .iter()
                .filter(|family| {
                    if benchmark == "swe" {
                        family.benchmark_relevance.swe_bench_pro == level
                    } else {
                        family.benchmark_relevance.terminal_bench_2_1 == level
                    }
                })
                .count()
        });
        assert_eq!(counts, expected, "{benchmark}");
    }
}

#[test]
fn value_domains_have_machine_bounds_catalog_flags_and_schema_references() {
    assert!(matches!(
        family("allow_code").value_schema.domain,
        StructuredValueDomain::Boolean
    ));
    assert!(matches!(
        family("effort").value_schema.domain,
        StructuredValueDomain::FiniteEnum {
            values: ["low", "medium", "high", "xhigh", "max", "ultracode"],
            open_catalog: false,
            ..
        }
    ));
    assert!(matches!(
        family("max_turns").value_schema.domain,
        StructuredValueDomain::Numeric {
            min: Some(1),
            unit: "turns",
            ..
        }
    ));
    assert!(matches!(
        family("provider_connect_tls_timeout").value_schema.domain,
        StructuredValueDomain::Numeric {
            min: Some(1),
            unit: "seconds",
            ..
        }
    ));
    assert!(matches!(
        family("model_fallback_chain").value_schema.domain,
        StructuredValueDomain::List {
            min_items: 0,
            max_items: Some(4_096),
            item_schema: "core://tunables/schemas/namespaced-id-v1",
            ..
        }
    ));
    assert!(matches!(
        family("permission_rules").value_schema.domain,
        StructuredValueDomain::Map {
            min_entries: 0,
            max_entries: Some(4_096),
            ..
        }
    ));
    assert!(matches!(
        family("shell_timeout_output").value_schema.domain,
        StructuredValueDomain::Composite {
            schema_ref: "core://tunables/schemas/bounded-policy-v1",
            max_bytes: 262_144,
            max_nodes: 4_096,
            max_depth: 32,
        }
    ));
    assert!(matches!(
        family("builtin_prompt_corpus").value_schema.domain,
        StructuredValueDomain::Catalog {
            min_entries: 0,
            max_entries: Some(10_000),
            open_catalog: true,
            ..
        }
    ));

    for family in families() {
        match family.value_schema.domain {
            StructuredValueDomain::Boolean => {}
            StructuredValueDomain::Numeric { min, max, .. } => {
                assert!(min.is_some() && max.is_some(), "{}", family.id);
            }
            StructuredValueDomain::FiniteEnum {
                values,
                open_catalog,
                catalog_ref,
            } => {
                assert!(
                    (!open_catalog && !values.is_empty() && catalog_ref.is_none())
                        || (open_catalog && catalog_ref.is_some()),
                    "{}",
                    family.id
                );
            }
            StructuredValueDomain::Text { max_bytes, .. } => {
                assert!(max_bytes.is_some(), "{}", family.id);
            }
            StructuredValueDomain::List { max_items, .. } => {
                assert!(max_items.is_some(), "{}", family.id);
            }
            StructuredValueDomain::Map { max_entries, .. }
            | StructuredValueDomain::Catalog { max_entries, .. } => {
                assert!(max_entries.is_some(), "{}", family.id);
            }
            StructuredValueDomain::Composite {
                max_bytes,
                max_nodes,
                max_depth,
                ..
            } => {
                assert!(
                    max_bytes > 0 && max_nodes > 0 && max_depth > 0,
                    "{}",
                    family.id
                );
            }
        }
    }

    let schema_ids = REFERENCED_SCHEMAS
        .iter()
        .map(|schema| schema.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_ids.len(), REFERENCED_SCHEMAS.len());
    for schema in REFERENCED_SCHEMAS {
        assert!(schema.max_bytes > 0);
        assert!(schema.max_nodes > 0);
        assert!(schema.max_depth > 0);
    }
}

#[test]
fn optimization_preserves_p1_p2_conditional_categories_and_pins_authority() {
    let current = &families()[..85];
    assert_eq!(
        current
            .iter()
            .filter(|family| matches!(
                family.optimization.class,
                OptimizationClass::P1 | OptimizationClass::P2
            ))
            .count(),
        41
    );
    assert_eq!(
        current
            .iter()
            .filter(|family| matches!(
                family.optimization.class,
                OptimizationClass::CStructured
                    | OptimizationClass::CArtifact
                    | OptimizationClass::CComponent
            ))
            .count(),
        23
    );
    assert_eq!(
        current
            .iter()
            .filter(|family| family.optimization.class == OptimizationClass::Pin)
            .count(),
        21
    );

    let appendix = &families()[85..];
    assert_eq!(APPENDIX_OPTIMIZATION.len(), appendix.len());
    for (family, expected) in appendix.iter().zip(APPENDIX_OPTIMIZATION) {
        assert_eq!(family.optimization.class, *expected, "{}", family.id);
    }
    assert_eq!(
        appendix
            .iter()
            .filter(|family| matches!(
                family.optimization.class,
                OptimizationClass::P1 | OptimizationClass::P2
            ))
            .count(),
        40
    );
    assert_eq!(
        appendix
            .iter()
            .filter(|family| matches!(
                family.optimization.class,
                OptimizationClass::CStructured
                    | OptimizationClass::CArtifact
                    | OptimizationClass::CComponent
            ))
            .count(),
        25
    );
    for (class, expected) in [
        (OptimizationClass::CStructured, 17),
        (OptimizationClass::CArtifact, 1),
        (OptimizationClass::CComponent, 7),
    ] {
        assert_eq!(
            appendix
                .iter()
                .filter(|family| family.optimization.class == class)
                .count(),
            expected,
            "{class:?}"
        );
    }
    assert_eq!(
        appendix
            .iter()
            .filter(|family| family.optimization.class == OptimizationClass::Pin)
            .count(),
        10
    );
    for class in [
        OptimizationClass::P1,
        OptimizationClass::P2,
        OptimizationClass::CStructured,
        OptimizationClass::CArtifact,
        OptimizationClass::CComponent,
        OptimizationClass::Pin,
    ] {
        assert!(
            families()
                .iter()
                .any(|family| family.optimization.class == class)
        );
    }

    for id in [
        "permission_mode",
        "permission_rules",
        "bypass_permissions",
        "child_ceiling",
        "process_signal_kill_escalation",
        "child_process_environment_reuse",
        "flaky_test_detection_quarantine",
        "failure_classification_taxonomy",
        "selective_restore_scope",
        "writer_worktree_isolation_mode",
        "oauth_auth_lifecycle_policy",
        "session_isolation_profile",
        "replay_divergence_detection_policy",
    ] {
        let family = family(id);
        assert_eq!(family.optimization.class, OptimizationClass::Pin, "{id}");
        assert_eq!(
            family.optimization.search_phase,
            SearchPhase::Pinned,
            "{id}"
        );
        assert!(family.optimization.pin_reason.is_some(), "{id}");
        assert_ne!(family.authority_class, AuthorityClass::Strategy, "{id}");
    }
}

#[test]
fn value_kind_and_status_counts_are_stable() {
    for (kind, expected) in [
        (ValueKind::Bool, 7),
        (ValueKind::Enum, 21),
        (ValueKind::Count, 23),
        (ValueKind::Duration, 11),
        (ValueKind::Bytes, 2),
        (ValueKind::Ratio, 5),
        (ValueKind::Decimal, 1),
        (ValueKind::String, 3),
        (ValueKind::List, 2),
        (ValueKind::Map, 13),
        (ValueKind::Policy, 58),
        (ValueKind::Catalog, 14),
    ] {
        assert_eq!(
            families()
                .iter()
                .filter(|family| family.value_schema.kind == kind)
                .count(),
            expected,
            "{kind:?}"
        );
    }
}

#[test]
fn per_entry_and_global_digests_authenticate_exact_semantics() {
    let original = *family("provider");
    let original_digest = family_semantic_digest(&original).unwrap();
    let mut changed = original;
    changed.default.value = "different provider default";
    let changed_digest = family_semantic_digest(&changed).unwrap();
    assert_ne!(original_digest.value, changed_digest.value);
    assert_eq!(original_digest.value.len(), 64);

    let payload = canonical_payload_json().unwrap();
    let digest = registry_digest().unwrap();
    assert_eq!(digest.algorithm, "sha256");
    assert_eq!(digest.value, hex::encode(Sha256::digest(payload)));
    assert_eq!(digest.value, REGISTRY_DIGEST_SHA256);

    let artifact: serde_json::Value =
        serde_json::from_slice(&canonical_artifact_json().unwrap()).unwrap();
    assert_eq!(artifact["payload"]["schema_version"], 2);
    assert_eq!(artifact["payload"]["registry_id"], "core-tunables");
    assert_eq!(artifact["payload"]["family_count"], 160);
    assert_eq!(artifact["payload"]["families"][0]["schema_version"], 1);
    assert_eq!(
        artifact["payload"]["families"][0]["semantic_digest"]["algorithm"],
        "sha256"
    );
    assert_eq!(
        artifact["payload"]["families"][0]["semantic_digest"]["value"],
        original_digest.value
    );
    assert_eq!(artifact["digest"]["value"], digest.value);
}

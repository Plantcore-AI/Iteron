use core_tunables::{
    Availability, DefaultKind, EXPECTED_FAMILY_COUNT, REGISTRY_DIGEST_SHA256, SourceKind,
    Trainability, ValueKind, canonical_artifact_json, canonical_payload_json, families,
    registry_digest, validate_registry,
};
use sha2::{Digest as _, Sha256};

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

#[test]
fn registry_has_exact_stable_shape() {
    validate_registry().unwrap();
    let registry = families();
    assert_eq!(registry.len(), EXPECTED_FAMILY_COUNT);
    assert_eq!(registry[0].id, "provider");
    assert_eq!(registry[84].id, "web_search_backend_catalog");
    assert_eq!(
        registry[85..]
            .iter()
            .map(|family| family.id)
            .collect::<Vec<_>>(),
        EXPANSION_IDS
    );
    assert_eq!(EXPANSION_IDS.len(), 10 + 12 + 15 + 10 + 14 + 8 + 6);
    for family in &registry[85..] {
        assert_eq!(
            family.default.kind == DefaultKind::Inactive,
            family.availability == Availability::Declared,
            "{}",
            family.id
        );
    }
}

#[test]
fn availability_is_explicit_for_staged_and_declared_families() {
    for id in [
        "retry_backoff_base",
        "retry_backoff_cap",
        "retry_max_attempts",
        "agent_catalog",
    ] {
        let family = families().iter().find(|family| family.id == id).unwrap();
        assert_eq!(family.availability, Availability::Partial, "`{id}`");
    }
    for id in ["provider_request_total_deadline", "stream_idle_watchdog"] {
        let family = families().iter().find(|family| family.id == id).unwrap();
        assert_eq!(family.availability, Availability::Active, "`{id}`");
    }
}

#[test]
fn appendix_f_availability_has_matching_source_evidence() {
    for family in &families()[85..] {
        match family.availability {
            Availability::Declared => assert_eq!(
                family.source.kind,
                SourceKind::Registry,
                "declared-only `{}` must point at the registry contract",
                family.id
            ),
            Availability::Active | Availability::Partial => assert_ne!(
                family.source.kind,
                SourceKind::Registry,
                "live or staged `{}` must point at production evidence",
                family.id
            ),
        }
    }
    let catalog = families()
        .iter()
        .find(|family| family.id == "agent_catalog")
        .unwrap();
    assert_eq!(catalog.source.locator, "crates/agents/src/catalog.rs");
}

#[test]
fn every_family_has_a_typed_nonblank_value_domain() {
    for family in families() {
        assert!(
            !family.value_schema.admissible.trim().is_empty(),
            "{}",
            family.id
        );
        assert!(
            !family.value_schema.constraint.trim().is_empty(),
            "{}",
            family.id
        );
        assert!(!family.value_schema.unit.trim().is_empty(), "{}", family.id);
    }
}

#[test]
fn availability_and_value_kind_counts_are_stable() {
    for (availability, expected) in [
        (Availability::Active, 81),
        (Availability::Partial, 53),
        (Availability::Declared, 26),
    ] {
        assert_eq!(
            families()
                .iter()
                .filter(|family| family.availability == availability)
                .count(),
            expected,
            "{availability:?}"
        );
    }

    for (kind, expected) in [
        (ValueKind::Bool, 7),
        (ValueKind::Enum, 21),
        (ValueKind::Count, 24),
        (ValueKind::Duration, 10),
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
fn canonical_artifact_digest_authenticates_payload() {
    let payload = canonical_payload_json().unwrap();
    let digest = registry_digest().unwrap();
    assert_eq!(digest.algorithm, "sha256");
    assert_eq!(digest.value, hex::encode(Sha256::digest(payload)));
    assert_eq!(digest.value, REGISTRY_DIGEST_SHA256);

    let artifact: serde_json::Value =
        serde_json::from_slice(&canonical_artifact_json().unwrap()).unwrap();
    assert_eq!(artifact["payload"]["schema_version"], 1);
    assert_eq!(artifact["payload"]["registry_id"], "core-tunables");
    assert_eq!(artifact["payload"]["family_count"], 160);
    assert_eq!(
        artifact["payload"]["families"][14]["value_schema"]["kind"],
        "duration"
    );
    assert_eq!(
        artifact["payload"]["families"][14]["availability"],
        "partial"
    );
    assert_eq!(artifact["digest"]["algorithm"], "sha256");
    assert_eq!(artifact["digest"]["value"], digest.value);
}

#[test]
fn safety_and_authority_families_are_not_learnable() {
    const PROTECTED: &[&str] = &[
        "permission_mode",
        "permission_rules",
        "bypass_permissions",
        "child_ceiling",
        "failover_eligible_error_taxonomy",
        "process_signal_kill_escalation",
        "child_process_environment_reuse",
        "flaky_test_detection_quarantine",
        "failure_classification_taxonomy",
        "selective_restore_scope",
        "writer_worktree_isolation_mode",
        "oauth_auth_lifecycle_policy",
        "session_isolation_profile",
        "replay_divergence_detection_policy",
    ];

    for id in PROTECTED {
        let family = families()
            .iter()
            .find(|family| family.id == *id)
            .unwrap_or_else(|| panic!("missing protected family `{id}`"));
        assert!(
            matches!(
                family.trainability,
                Trainability::FixedInvariant | Trainability::OperatorOnly
            ),
            "protected family `{id}` is marked {:?}",
            family.trainability
        );
    }
}

use super::*;

#[test]
fn discovers_declared_defaults_but_not_default_constructor_uses() {
    let source = r#"
        struct RuntimePolicy {
            #[serde(default = "default_timeout")]
            timeout: u64,
            #[arg(default_value_t = 4)]
            workers: usize,
        }
        pub fn build_policy(input: usize) { let _ = (input, RuntimePolicy::default()); }
        #[cfg(test)]
        mod tests {
            struct Hidden { #[serde(default)] field: bool }
            fn policy_test() { let _ = RuntimePolicy::default(); }
        }
    "#;
    let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert!(
        rows.iter()
            .any(|row| matches!(row.candidate_kind, CensusCandidateKind::SerdeDefault))
    );
    assert!(
        rows.iter()
            .any(|row| matches!(row.candidate_kind, CensusCandidateKind::ClapDefault))
    );
    assert!(!rows.iter().any(|row| matches!(
        row.candidate_kind,
        CensusCandidateKind::PolicyDefaultConstructor
    )));
    assert_eq!(
        rows.iter()
            .filter(|row| row.owner.symbol.contains("Hidden"))
            .count(),
        0
    );
}

#[test]
fn runtime_fact_structs_and_local_accumulators_are_observations_not_candidates() {
    let source = r#"
        struct ToolResult { is_error: bool, latency_ms: u64 }
        struct RetryPolicy { max_attempts: usize }
        fn run_policy() {
            let mut retry_index = 0u32;
            let _ = ToolResult { is_error: true, latency_ms: 0 };
            let _ = RetryPolicy { max_attempts: 3 };
            retry_index += 1;
        }
    "#;
    let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value, "3");
    assert!(rows[0].id.contains("retrypolicy"));
}

#[test]
fn exact_runtime_accumulators_and_rendering_construction_emit_no_candidates() {
    let source = r#"
        impl ImageAttachments {
            fn new_with_routing() -> Self {
                Self { file_bytes: 0, encoded_bytes: 0, next_id: 0 }
            }
        }
        impl Default for PolicyRunAggregate {
            fn default() -> Self {
                Self { terminal: Outcome::Succeeded, latency_us: 0, completed_turns: 0 }
            }
        }
        impl ReplayRing {
            fn with_limits() -> Self { Self { serialized_bytes: 0 } }
        }
        impl ToolCatalogBuilder {
            fn with_limits_and_filter() -> Self { Self { description_bytes: 0 } }
        }
        impl Default for PolicyOpportunityJoinDigest {
            fn default() -> Self { Self { count: 0 } }
        }
        impl Default for PolicyHarnessErrorJoinDigest {
            fn default() -> Self { Self { count: 0 } }
        }
    "#;
    assert!(
        discover_source("demo", "crates/demo/src/lib.rs", source)
            .unwrap()
            .is_empty()
    );
    let observations =
        source_form_observation_counts("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert!(observations[&CensusCandidateKind::BuilderQualityDefault] > 0);
    assert!(observations[&CensusCandidateKind::PolicyDefaultConstructor] > 0);

    let rendering = r#"
        impl Policy {
            fn disabled() -> Self { Self { capability: Capability::PlainText } }
        }
    "#;
    assert!(
        discover_source("cli", "crates/cli/src/tui/hyperlink.rs", rendering)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn honesty_gate_rejects_settable_without_evidence() {
    let mut rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        "struct Config { #[serde(default)] value: usize }",
    )
    .unwrap();
    rows[0].use_sites.clear();
    assert!(
        validate(&rows)
            .unwrap_err()
            .to_string()
            .contains("without production use-site")
    );
    rows[0].use_sites.push(UseSiteRow {
        path: "crates/demo/src/lib.rs".to_owned(),
        line: 1,
        evidence: "serde".to_owned(),
    });
    rows[0].behavior_oracle = None;
    assert!(
        validate(&rows)
            .unwrap_err()
            .to_string()
            .contains("without a behavior oracle")
    );
}

#[test]
fn addressability_distinguishes_profile_config_and_injection() {
    let source = r#"
        #[serde(rename_all = "camelCase")]
        struct RuntimePolicy {
            #[serde(default)]
            feature_enabled: bool,
            #[arg(long, default_value_t = 4)]
            workers: usize,
        }
        pub fn build_policy(input: usize) { let _ = (input, RuntimePolicy::default()); }
    "#;
    let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
    let counts = address_kind_counts(&rows);
    assert_eq!(counts[&ExternalAddressKind::DirectConfig], 2);
    assert_eq!(counts[&ExternalAddressKind::CallerInput], 1);
    assert_eq!(counts[&ExternalAddressKind::UnifiedProfile], 0);
    let clap = rows
        .iter()
        .find(|row| matches!(row.candidate_kind, CensusCandidateKind::ClapDefault))
        .unwrap()
        .external_address
        .as_ref()
        .unwrap();
    assert_eq!(clap.selector_kind, AddressSelectorKind::Argument);
    assert_eq!(clap.selector, "--workers");
    let serde = rows
        .iter()
        .find(|row| matches!(row.candidate_kind, CensusCandidateKind::SerdeDefault))
        .unwrap()
        .external_address
        .as_ref()
        .unwrap();
    assert_eq!(serde.selector, "RuntimePolicy.featureEnabled");
}

#[test]
fn invariant_kind_vocabulary_is_closed_and_specific() {
    let kinds = [
        InvariantKind::Identity,
        InvariantKind::WireCompatibility,
        InvariantKind::Authority,
        InvariantKind::Security,
        InvariantKind::Durability,
        InvariantKind::Replay,
        InvariantKind::HardBudget,
        InvariantKind::EffectLedger,
        InvariantKind::NonValueStructural,
    ];
    let json = serde_json::to_string(&kinds).unwrap();
    assert!(!json.contains("other"));
    assert!(!json.contains("generic"));
}

#[test]
fn quality_affecting_invariant_requires_an_explicit_override() {
    let mut row = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        "struct Policy { #[serde(default)] threshold: usize }",
    )
    .unwrap()
    .remove(0);
    row.disposition = CensusDisposition::InvariantReadOnly;
    row.external_address = None;
    row.invariant_kind = Some(InvariantKind::NonValueStructural);
    row.id = "tools.web.block_tags".to_owned();
    row.review_evidence = Some(format!(
        "closed Tier-2 disposition rule: `{}` at {} — mechanical test; observed at {}:1; mechanical source evidence only, not a claim of human review",
        row.owner.symbol, row.owner.path, row.owner.path
    ));
    row.owning_human_review = Some(OwningHumanReviewStatus::RequiredNotSourceProven);
    row.applied = false;
    row.behavior_oracle = None;
    assert!(
        validate(std::slice::from_ref(&row))
            .unwrap_err()
            .to_string()
            .contains("have no explicit override")
    );
    row.explicit_invariant_override = true;
    validate(std::slice::from_ref(&row)).unwrap();
}

#[test]
fn invariant_cannot_retain_a_writable_address_or_claim_human_approval() {
    let mut row = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        "struct Policy { #[serde(default)] threshold: usize }",
    )
    .unwrap()
    .remove(0);
    row.disposition = CensusDisposition::InvariantReadOnly;
    row.id = "tools.web.default_search_result_count".to_owned();
    row.invariant_kind = Some(InvariantKind::NonValueStructural);
    row.review_evidence = Some(format!(
        "explicit census disposition override: `{}` at {} — mechanical test; observed at {}:1; mechanical source evidence only, not a claim of human review",
        row.owner.symbol, row.owner.path, row.owner.path
    ));
    row.owning_human_review = Some(OwningHumanReviewStatus::RequiredNotSourceProven);
    row.explicit_invariant_override = true;
    row.applied = false;
    row.behavior_oracle = None;
    assert!(
        validate(std::slice::from_ref(&row))
            .unwrap_err()
            .to_string()
            .contains("carries a settable address")
    );
    row.external_address = None;
    row.owning_human_review = None;
    assert!(
        validate(std::slice::from_ref(&row))
            .unwrap_err()
            .to_string()
            .contains("owning-human review is required")
    );
}

#[test]
fn every_discovered_runtime_row_has_one_concrete_external_address() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            struct RuntimePolicy {
                #[serde(default)] enabled: bool,
                #[arg(long, default_value_t = 4)] workers: usize,
            }
            pub fn build_policy(input: usize) { let _ = (input, RuntimePolicy::default()); }
        "#,
    )
    .unwrap();
    validate(&rows).unwrap();
    assert!(rows.iter().all(|row| {
        matches!(row.disposition, CensusDisposition::RuntimeSettable)
            && row
                .external_address
                .as_ref()
                .is_some_and(|address| !address.selector.is_empty() && !address.owner.is_empty())
    }));
    assert_eq!(
        address_kind_counts(&rows).values().sum::<usize>(),
        rows.len()
    );
}

#[test]
fn caller_input_requires_a_mechanical_public_protocol_proof() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            struct RetryPolicy;
            impl RetryPolicy {
                fn new(attempts: usize) -> Self { Self }
                pub fn with_attempts(attempts: usize) -> Self { Self }
            }
            fn internal_policy() { let _ = RetryPolicy::new(3); }
        "#,
    )
    .unwrap();
    let internal = rows.iter().find(|row| row.value == "3").unwrap();
    assert_eq!(internal.disposition, CensusDisposition::BindingRequired);
    assert!(internal.external_address.is_none());
    assert!(internal.binding_requirement.is_some());
    let public = rows
        .iter()
        .find(|row| row.value.contains("attempts : usize"))
        .unwrap();
    assert_eq!(public.disposition, CensusDisposition::RuntimeSettable);
    assert!(matches!(
        public.external_address.as_ref().map(|address| address.kind),
        Some(ExternalAddressKind::CallerInput)
    ));
    assert!(matches!(
        public.caller_input_proof.as_ref().map(|proof| proof.kind),
        Some(CallerInputProofKind::PublicMethod)
    ));
}

#[test]
fn discovers_declared_builder_asset_and_dynamic_manifest_forms() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            pub struct ImplementationManifest { timeout_ms: u64 }
            pub struct RuntimePolicy;
            impl RuntimePolicy {
                pub fn with_timeout(timeout_ms: u64) -> Self { Self }
            }
            const PRELUDE: &str = include_str!("prelude.js");
        "#,
    )
    .unwrap();
    assert!(rows.iter().any(|row| matches!(
        row.candidate_kind,
        CensusCandidateKind::BuilderQualityDefault
    )));
    assert!(
        rows.iter()
            .any(|row| matches!(row.candidate_kind, CensusCandidateKind::IncludeStrAsset))
    );
    assert!(rows.iter().any(|row| matches!(
        row.candidate_kind,
        CensusCandidateKind::DynamicImplementationManifest
    )));
}

#[test]
fn unknown_quality_source_form_fails_the_closed_coverage_gate() {
    let unclassified = unclassified_source_form_count(
        "demo",
        "crates/demo/src/lib.rs",
        "fn policy() { quality_default!(42); }",
    )
    .unwrap();
    assert_eq!(unclassified, 1);
    let coverage = SourceCoverage {
        completeness_claim: "complete_for_declared_production_source_forms_not_mathematical_universe",
        production_rust_files_scanned: 1,
        source_form_counts: CensusCandidateKind::all()
            .into_iter()
            .map(|kind| (kind, 0))
            .collect(),
        candidate_row_counts: CensusCandidateKind::all()
            .into_iter()
            .map(|kind| (kind, 0))
            .collect(),
        unclassified_source_forms: unclassified,
    };
    assert!(
        validate_source_coverage(&coverage, 0)
            .unwrap_err()
            .to_string()
            .contains("unclassified declared source form")
    );
}

#[test]
fn generic_construction_and_bound_setting_uses_are_observations_not_candidates() {
    let source = r#"
        fn policy_runtime(settings: Settings) {
            let _ = Vec::new();
            let _ = Arc::new(settings.clone());
            let _ = OpenOptions::new();
            let _ = Style::default();
            let _ = LifecyclePayload::default();
            let _ = anyhow::Error::new(settings.error);
            let _ = ModelId::new("fixed-identity");
            let _ = RetryPolicy::new(settings.retry_attempts);
        }
    "#;
    let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert!(rows.is_empty(), "use sites are not independent tunables");

    let observations =
        source_form_observation_counts("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert!(observations[&CensusCandidateKind::BuilderQualityDefault] > 0);
    assert!(observations[&CensusCandidateKind::PolicyDefaultConstructor] > 0);
}

#[test]
fn private_inline_quality_value_remains_binding_required() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            struct RetryPolicy { attempts: usize }
            impl RetryPolicy { fn new(attempts: usize) -> Self { Self { attempts } } }
            impl Default for RetryPolicy {
                fn default() -> Self { Self { attempts: 5 } }
            }
            fn internal_policy() { let _ = RetryPolicy::new(3); }
        "#,
    )
    .unwrap();
    for value in ["3", "5"] {
        let inline = rows.iter().find(|row| row.value == value).unwrap();
        assert_eq!(inline.disposition, CensusDisposition::BindingRequired);
        assert!(inline.binding_requirement.is_some());
        assert!(inline.external_address.is_none());
    }
}

#[test]
fn closed_policy_fallback_declaration_remains_binding_required() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            fn internal_policy() {
                let _ = RetryPolicy::fallback(&[Action::Direct, Action::Serial]);
            }
        "#,
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].disposition, CensusDisposition::BindingRequired);
    assert!(matches!(
        rows[0].candidate_kind,
        CensusCandidateKind::PolicyFallbackCall
    ));
}

#[test]
fn public_typed_builder_parameter_is_caller_input() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            pub struct RetryPolicy;
            impl RetryPolicy {
                pub fn with_attempts(attempts: usize) -> Self { Self }
            }
        "#,
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    let parameter = &rows[0];
    assert_eq!(parameter.disposition, CensusDisposition::RuntimeSettable);
    assert!(matches!(
        parameter
            .external_address
            .as_ref()
            .map(|address| address.kind),
        Some(ExternalAddressKind::CallerInput)
    ));
    assert!(
        parameter
            .caller_input_proof
            .as_ref()
            .is_some_and(|proof| proof.evidence.contains("typed parameter `attempts`"))
    );
}

#[test]
fn source_coverage_counts_forms_independently_from_candidate_rows() {
    let source = r#"
        fn retry_policy(settings: Settings) {
            let _ = RetryPolicy::default();
            let _ = RetryPolicy::fallback(settings.retry);
            let _ = RetryPolicy::new(settings.retry);
        }
    "#;
    assert!(
        discover_source("demo", "crates/demo/src/lib.rs", source)
            .unwrap()
            .is_empty()
    );
    let observations =
        source_form_observation_counts("demo", "crates/demo/src/lib.rs", source).unwrap();
    assert!(observations[&CensusCandidateKind::PolicyDefaultConstructor] > 0);
    assert!(observations[&CensusCandidateKind::PolicyFallbackCall] > 0);
    assert!(observations[&CensusCandidateKind::BuilderQualityDefault] > 0);
    let coverage = SourceCoverage {
        completeness_claim: "complete_for_declared_production_source_forms_not_mathematical_universe",
        production_rust_files_scanned: 1,
        source_form_counts: observations,
        candidate_row_counts: CensusCandidateKind::all()
            .into_iter()
            .map(|kind| (kind, 0))
            .collect(),
        unclassified_source_forms: 0,
    };
    validate_source_coverage(&coverage, 0).unwrap();
}

#[test]
fn exact_non_optimization_values_receive_source_proven_invariant_dispositions() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            fn emit() {
                let _ = EffectiveConfigDocument {
                    kind: "runtime_effective_config",
                    runtime_bound: true,
                };
            }
            impl ExecutionRuntimePolicy {
                fn fail_closed() -> Self { Self { max_turns: 1 } }
            }
            fn effecting_tool_admission_policy() -> EffectingToolAdmissionPolicy {
                EffectingToolAdmissionPolicy {
                    declared_set_required: true,
                    overlap: "reject",
                }
            }
            impl SchemaValidator {
                fn compile() { let _ = jsonschema::options().with_draft(jsonschema::Draft::Draft202012); }
            }
            fn runner() {
                let _ = HarnessConfig { name: "verify_ON", verify_gate: true };
            }
            fn run_cli() {
                let _ = ProviderConfig { enabled: true, catalog: true };
            }
            fn control_policy() {
                let _ = StageLimits::new(10, 2, 5_000, 0, 2_000);
            }
        "#,
    )
    .unwrap();
    assert!(rows.len() >= 6);
    assert!(rows.iter().all(|row| {
        row.disposition == CensusDisposition::InvariantReadOnly
            && row.invariant_kind.is_some()
            && row
                .review_evidence
                .as_deref()
                .is_some_and(|evidence| evidence.contains("closed source-form invariant rule"))
    }));
    validate(&rows).unwrap();
}

#[test]
fn closed_runtime_owners_use_exact_invariant_kinds() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            impl RouterRoute {
                fn direct() -> Self { Self { max_leaves: 0 } }
            }
            impl RuntimeHttpClient {
                fn default_reconfigurable() -> Self { Self { default_reconfigurable: true } }
            }
            impl McpOAuthLifecyclePolicy {
                fn disabled() -> Self {
                    Self { mode: McpOAuthCredentialMode::Disabled, binding_count: 0 }
                }
                fn from_counts() -> Self { Self { revoke_access_after_forbidden: true } }
            }
            impl ReplayDivergenceDetectionPolicy {
                fn owner() -> Self {
                    Self {
                        verify_hash_chain: true,
                        verify_identity_scope: true,
                        verify_effect_terminals: true,
                        fail_closed: true,
                    }
                }
            }
            impl PureMemoCachePolicy {
                fn production_owner() -> Self { Self { generation_scoped: true } }
            }
            impl TaskPrioritySchedulingPolicy {
                fn owner() -> Self {
                    Self {
                        priority_levels: 1,
                        tie_break: ReadyTaskTieBreak::Fifo,
                        dependency_ready_only: true,
                    }
                }
            }
            impl WriterMergePolicy {
                fn isolated_writer() -> Self {
                    Self {
                        writer_worktree_isolation: true,
                        on_clean: CleanWriterDisposition::Serialize,
                        on_conflict: ConflictDisposition::Reject,
                        require_verification: true,
                    }
                }
                fn parent_only() -> Self {
                    Self {
                        writer_worktree_isolation: false,
                        on_clean: CleanWriterDisposition::Serialize,
                        on_conflict: ConflictDisposition::Reject,
                        require_verification: true,
                    }
                }
            }
        "#,
    )
    .unwrap();
    assert_eq!(rows.len(), 21);
    let count = |kind| {
        rows.iter()
            .filter(|row| row.invariant_kind == Some(kind))
            .count()
    };
    assert_eq!(count(InvariantKind::HardBudget), 1);
    assert_eq!(count(InvariantKind::Authority), 3);
    assert_eq!(count(InvariantKind::Security), 5);
    assert_eq!(count(InvariantKind::Replay), 7);
    assert_eq!(count(InvariantKind::EffectLedger), 3);
    assert_eq!(count(InvariantKind::Durability), 2);
    assert!(
        rows.iter()
            .all(|row| row.disposition == CensusDisposition::InvariantReadOnly)
    );
    validate(&rows).unwrap();
}

#[test]
fn handed_off_closed_defaults_use_exact_invariant_kinds() {
    let rows = discover_source(
        "protocol",
        "crates/protocol/src/lib.rs",
        r#"
            impl Default for MemoryRetrievalPolicy {
                fn default() -> Self {
                    Self { reranker_weight_ppm: 0, vector_weight_ppm: 0 }
                }
            }
            impl Default for ContextMaterializationPolicy {
                fn default() -> Self { Self { skill_listing_bytes: 2_000 } }
            }
            impl Default for TurnLimits {
                fn default() -> Self {
                    Self { max_consecutive_tool_errors: 5, max_turns: 8, max_verify_attempts: 3 }
                }
            }
            impl Default for Budget {
                fn default() -> Self {
                    Self { max_consecutive_tool_errors: 25, max_turns: 600, max_wall_secs: 14_400 }
                }
            }
            impl Default for HedgePolicy {
                fn default() -> Self { Self { idempotent_only: true } }
            }
            impl Default for VerificationRestorePolicy {
                fn default() -> Self { Self { mode: VerificationRollbackMode::Off } }
            }
            impl Default for VerificationRetryPolicy {
                fn default() -> Self { Self { unknown: UnknownVerificationRetryAction::Stop } }
            }
        "#,
    )
    .unwrap();
    assert_eq!(rows.len(), 12);
    let count = |kind| {
        rows.iter()
            .filter(|row| row.invariant_kind == Some(kind))
            .count()
    };
    assert_eq!(count(InvariantKind::HardBudget), 7);
    assert_eq!(count(InvariantKind::Authority), 3);
    assert_eq!(count(InvariantKind::EffectLedger), 1);
    assert_eq!(count(InvariantKind::Security), 1);
    assert!(
        rows.iter()
            .all(|row| row.disposition == CensusDisposition::InvariantReadOnly)
    );
    validate(&rows).unwrap();
}

#[test]
fn genuine_policy_literals_stay_binding_and_associated_constants_are_only_uses() {
    let rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        r#"
            fn retry_policy() {
                let _ = RetryPolicy::new(3);
                let _ = RetryPolicy::new(SecurityLimits::MAX_ATTEMPTS);
            }
        "#,
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value, "3");
    assert_eq!(rows[0].disposition, CensusDisposition::BindingRequired);
}

#[test]
fn duplicate_external_addresses_require_owner_qualification() {
    let mut rows = discover_source(
        "demo",
        "crates/demo/src/lib.rs",
        "struct Config { #[serde(default)] value: usize }",
    )
    .unwrap();
    let mut duplicate = rows[0].clone();
    duplicate.id.push_str(".duplicate");
    rows.push(duplicate);
    assert!(
        validate(&rows)
            .unwrap_err()
            .to_string()
            .contains("collides with another external address")
    );
    rows[1].external_address.as_mut().unwrap().owner = "serde::OtherConfig".to_owned();
    validate(&rows).unwrap();
}

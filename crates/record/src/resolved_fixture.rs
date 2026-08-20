//! Public-resolver fixture used to exercise record wrappers with a real `ResolvedTunableSet`.

use iteron_tunables::{
    ActivationEvidence, ActivationPredicate, CatalogSnapshot, ConstraintEvidence,
    ConstraintProjection, ConstraintRelation, ConstraintValue, CrossFieldRule, DecimalValue,
    DeclaredValue, DefaultResolver, EvidenceSubject, ExternalCeiling, FieldDomain,
    ImplementationStatus, REGISTRY_DIGEST_SHA256, REGISTRY_ID, REGISTRY_REVISION,
    RESOLUTION_SCHEMA_VERSION, ResolutionInput, ResolutionProfile, ResolutionValue,
    ResolvedTunableSet, RouteCapabilities, RouteIdentity, RuleValue, RuntimeContext,
    SCALAR_CATALOGS, ScalarDomain, SourceKind, StringFormat, StructuredValueDomain, ValueSchema,
    canonical_embedded_default, families, resolve,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTENT_FIXED_ARTIFACT_FAMILIES: &[&str] = &[
    "operator_prompt_stream",
    "builtin_prompt_corpus",
    "instruction_bundle",
    "memory_corpus",
    "skill_catalog",
    "provider_model_capability_catalog",
    "mcp_topology_tool_catalog",
    "tool_action_space",
    "rate_card_catalog",
    "router_lexicons",
    "web_search_backend_catalog",
];

pub fn resolved() -> ResolvedTunableSet {
    let resolved =
        resolve(input()).expect("registry-driven public resolver fixture must remain accepted");
    iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
        .expect("test fixture fixed-authority bindings must match canonical effective values")
}

/// Historical schema-complete fixture with synthetic fixed-authority bindings. This remains
/// test-feature-only and does not provide any live materializer receipt.
pub fn historical_resolved_with_fixed_artifacts() -> ResolvedTunableSet {
    let resolved = resolve(historical_input_with_fixed_artifacts())
        .expect("schema-complete historical fixed-artifact fixture");
    iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
        .expect("historical fixture bindings must match canonical effective values")
}

/// Complete resolver input behind [`resolved`]. Downstream integration tests may replace the
/// content-free identities owned by their binary before resolving; the record crate cannot depend
/// on those higher-layer runtimes merely to manufacture their build-specific digests.
pub fn input() -> ResolutionInput {
    let mut input = all_family_input();
    input
        .declared_values
        .retain(|value| !CONTENT_FIXED_ARTIFACT_FAMILIES.contains(&value.family.as_str()));
    input
        .constraint_evidence
        .retain(|value| !CONTENT_FIXED_ARTIFACT_FAMILIES.contains(&value.family.as_str()));
    input
}

/// Schema-complete compatibility input for testing historical checkpoints that persisted an
/// effective content-bearing fixed artifact. It is intentionally not the default fixture: a
/// production composition without the matching private materializer must keep these families
/// inactive and fail closed if an older checkpoint claims otherwise.
pub fn historical_input_with_fixed_artifacts() -> ResolutionInput {
    all_family_input()
}

fn all_family_input() -> ResolutionInput {
    let provider = families()
        .iter()
        .find(|family| family.id == "provider")
        .expect("provider family");
    let model = families()
        .iter()
        .find(|family| family.id == "model")
        .expect("model family");
    let ResolutionValue::Enum { value: provider_id } = sample_schema(provider.value_schema, 1)
    else {
        panic!("provider schema stopped being an enum")
    };
    let ResolutionValue::Enum { value: model_id } = sample_schema(model.value_schema, 2) else {
        panic!("model schema stopped being an enum")
    };
    let route = RouteIdentity {
        provider_id,
        model_id,
        route_revision: "fixture:v1".to_owned(),
        catalog_digest_sha256: DIGEST_A.to_owned(),
    };
    let capabilities: BTreeSet<_> = families()
        .iter()
        .flat_map(|family| family.requirements.capabilities.iter().copied())
        .collect();

    let mut declared_values = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .map(|family| {
            let source = match family.activation.predicate {
                ActivationPredicate::Configured { sources } => family
                    .source
                    .bindings
                    .iter()
                    .find(|binding| sources.contains(&binding.kind))
                    .unwrap_or_else(|| panic!("{} has no configuring source", family.id)),
                ActivationPredicate::Always | ActivationPredicate::RuntimeDerived { .. } => {
                    family.source.bindings.first().expect("implemented source")
                }
                ActivationPredicate::Unavailable => {
                    panic!("implemented family {} is unavailable", family.id)
                }
            };
            let value = match family.id {
                "provider" => ResolutionValue::Enum {
                    value: route.provider_id.clone(),
                },
                "model" => ResolutionValue::Enum {
                    value: route.model_id.clone(),
                },
                // A Builtin declaration of a Literal family is an attestation of the immutable
                // registry value, not a second configuration channel. Keep this shared fixture
                // on the same global equality contract enforced by the online builder and the
                // offline resolver preparation path.
                _ if source.kind == SourceKind::Builtin
                    && matches!(family.default.resolver, DefaultResolver::Literal) =>
                {
                    canonical_embedded_default(family.id)
                        .expect("literal family has one canonical embedded value")
                }
                // Catalog-backed selectors must use values that their production consumers can
                // actually install. Generic `fixture:value-N` strings prove only schema shape
                // and previously let this shared checkpoint resolve before failing in the CLI.
                "effort_reasoning_map" => effort_reasoning_map(),
                "token_estimator" => token_estimator(),
                "compaction_trigger" => compaction_trigger(),
                "compaction_keep_recent" => ResolutionValue::Integer { value: 0 },
                "compaction_adaptive" => compaction_adaptive(),
                "summary_profile" => summary_profile(),
                id @ ("route_topology"
                | "decomposition_profile"
                | "fan_breadth"
                | "admission"
                | "writer_fan_turn_split"
                | "worker_min_turns"
                | "wall_split"
                | "fan_concurrency"
                | "child_ceiling"
                | "direct_child_allocation"
                | "subagent_effort_inheritance"
                | "report_budget"
                | "workflow_aggregate"
                | "schema_retry_jitter"
                | "per_agent_model"
                | "per_agent_effort_thinking"
                | "per_agent_tool_profile"
                | "per_agent_memory_scope"
                | "spawn_depth_control"
                | "task_priority_scheduling"
                | "speculative_sibling_count"
                | "speculative_sibling_cancellation"
                | "early_stop_quorum_policy"
                | "role_specific_model_map"
                | "task_retry_reassignment_policy") => execution_runtime_owner_value(id, &route),
                id @ ("thinking_map"
                | "orchestration_map"
                | "compaction_failure"
                | "pure_overlap"
                | "pure_concurrency"
                | "failed_action_dedup"
                | "pure_memo_cache"
                | "web_search_cap"
                | "verifier_attempts"
                | "token_split"
                | "join_reduce"
                | "auto_compaction_enable"
                | "process_signal_kill_escalation"
                | "effecting_tool_concurrency"
                | "write_set_conflict_admission"
                | "retry_eligibility_policy"
                | "recovery_escalation_policy"
                | "writer_worktree_isolation_mode"
                | "merge_conflict_arbitration"
                | "inter_agent_messaging_topology"
                | "replay_divergence_detection_policy") => live_fixed_owner_value(id),
                "model_fallback_chain" => ResolutionValue::List { items: Vec::new() },
                "provider_service_tier" => ResolutionValue::Enum {
                    value: "provider_default".to_owned(),
                },
                // The shared executable fixture models the baseline adapter contract. A generic
                // enum sample selects zstd even though providers must explicitly attest request
                // compression before it can reach the wire. Keep the fixture on the universally
                // supported no-compression control; capability-specific tests install their own
                // exact route evidence.
                "request_compression_policy" => ResolutionValue::Enum {
                    value: "none".to_owned(),
                },
                // The total request deadline is a derived transport owner rather than a
                // Literal family, so the generic scalar sampler would choose 1 ms. That is
                // schema-valid but physically inconsistent with the fixed 10 s connect and
                // 60 s stream-idle owners consumed by every provider adapter.
                "provider_request_total_deadline" => ResolutionValue::Integer { value: 300_000 },
                // Verification families form one executable policy. Keep the public fixture on
                // the impacted-first owner with a valid full-workspace fallback and retry ceiling;
                // generic per-schema sampling can produce individually valid fields that the
                // physical policy correctly rejects as an inconsistent set.
                "test_selection_strategy" => verification_test_selection_strategy(),
                "incremental_versus_full_verification" => ResolutionValue::Enum {
                    value: "impacted".to_owned(),
                },
                // `ProcessRuntimePolicy` rejects a disabled backend that still admits background
                // jobs. That pairing spans two families, which a per-family value schema cannot
                // express, so the registry accepts a combination the runtime owner refuses. Pick
                // the backend that admits the sampled capacity rather than emit a set that is
                // valid on paper and unusable in practice.
                "persistent_pty_backend" => ResolutionValue::Enum {
                    value: "persistent".to_owned(),
                },
                // Process launch has cross-field production invariants that are deliberately
                // stronger than the per-field schema: the initial directory is an existing
                // absolute job root and cwd changes remain live for that job.
                "process_cwd_continuity" => process_cwd_continuity(),
                // The public fixture does not need ambient authority. An exact empty snapshot is
                // valid production behavior and keeps record fixtures content-free.
                "child_process_environment_reuse" => empty_child_environment(),
                // The resident actor reserves a fixed priority lane inside SQ, so the generic
                // object sampler's minimum `submission_entries = 1` is schema-valid but cannot
                // be installed by the production queue owner. Mirror the canonical owner-sized
                // fixture instead of weakening that runtime invariant.
                "app_server_sq_eq_backpressure" => app_server_queue_policy(),
                // The ordinary tool-result store keeps a useful inline result and spills only
                // genuinely large output. The generic five-byte boundary sample is schema-valid
                // but turns every normal `read_file` result into an error before a behavioral
                // fixture can reach its provider/tool oracle.
                "tool_output_spill_to_disk_policy" => tool_output_spill_policy(),
                // The executable owner requires an exact, total route for every raster MIME.
                // A generic map sample cannot establish that bijection and must not be allowed
                // to weaken the pre-provider inspection gate.
                "binary_media_inspection_routing" => binary_media_inspection_policy(),
                // Discovery executes before the general resolver. Its FixedHidden checkpoint
                // entry therefore attests the binary bootstrap owner exactly; a shape-valid
                // sample with different TTL/backoff values is deliberately rejected on resume.
                "provider_discovery_account_probe_cache_policy" => {
                    provider_discovery_bootstrap_policy()
                }
                // The generic decimal sampler deliberately selects each schema minimum. Runtime
                // memory admission additionally requires a usable lexical owner: BM25 k1/limit
                // and at least one fusion signal must be non-zero. Mirror that real owner rather
                // than manufacturing a resolver-valid checkpoint that every resume rejects.
                "bm25" => bm25_runtime_policy(),
                "hybrid_retrieval_fusion_weights" => lexical_memory_weights(),
                "retrieval_recency_decay" | "context_novelty_dedup_threshold" => decimal(1, 0),
                // The live LSP owner publishes its bounded route catalog inline: the runtime
                // needs the executable/argument fields to configure the session-owned pool.
                // `CatalogRef` is a valid schema representation for identity-only governed
                // catalogs, but it is deliberately not executable as an LSP policy. Keep this
                // public resolver fixture production-decodable by mirroring the live owner form.
                "lsp_server_language_selection" => lsp_language_routes(),
                // The provider runtime consumes the taxonomy entries themselves; a content-only
                // CatalogRef proves identity but cannot configure the failover gate. Keep the
                // public checkpoint fixture production-decodable with one exact built-in rule.
                "failover_eligible_error_taxonomy" => failover_taxonomy(),
                "failure_classification_taxonomy" => failure_classification_taxonomy(),
                // The provider governor admits only normalized fixed-point weights. Generic map
                // sampling chooses three zero minima, which is schema-shaped but not executable.
                "route_quality_cost_latency_objective_weights" => objective_weights(),
                // Zero duplicates is executable only while hedging is disabled. Generic object
                // sampling makes `enabled=true` and `idempotent_only=false`, which is schema-shaped
                // but correctly rejected by the provider governor.
                "hedged_request_policy" => disabled_hedge_policy(),
                // Overflow is always retained in the private CAS. The public fixture must carry
                // that fixed safety bit and the executable built-in byte/cleanup bounds.
                "mcp_result_cap_spill_policy" => mcp_result_spill_policy(),
                // This fixture has no configured MCP server. Mirror the production owner's exact
                // disabled exposure rather than combining disabled discovery with sampled IDs or
                // a non-zero visible byte budget.
                "resource_prompt_plugin_capability_exposure" => disabled_mcp_capability_exposure(),
                // An effective OAuth family represents at least one configured credential
                // binding. The generic object sampler selected `disabled` together with one
                // binding, a combination the production owner correctly refuses. Use the exact
                // single-bearer owner state; configurations with no OAuth bindings leave this
                // configured family inactive instead of serializing a synthetic disabled value.
                "oauth_auth_lifecycle_policy" => oauth_bearer_policy(),
                // Rollback and restore scope are decoded as one production policy. Keep the
                // shared fixture explicitly non-effecting; an arbitrary sampled rollback enum
                // paired with an independently sampled scope can resolve while no runtime can
                // install the contradictory pair.
                "rollback_on_verification_failure" => ResolutionValue::Enum {
                    value: "off".to_owned(),
                },
                "workspace_checkpoint_cadence" => verification_checkpoint_cadence(),
                "selective_restore_scope" => disabled_restore_scope(),
                // The public fixture selects the interactive runtime profile below. Session
                // isolation is an immutable companion policy, so it must name the matching
                // production mode rather than an arbitrary schema-valid enum member.
                "session_isolation_profile" => ResolutionValue::Enum {
                    value: "interactive".to_owned(),
                },
                _ => sample_schema(family.value_schema, family.ordinal),
            };
            DeclaredValue {
                family: family.id.to_owned(),
                source: source.kind,
                evidence_digest_sha256: DIGEST_A.to_owned(),
                value,
            }
        })
        .collect::<Vec<_>>();
    repair_resolved_set_sum_limits(&mut declared_values);

    let activation_evidence = families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            ActivationPredicate::RuntimeDerived { seam } => Some((family.id, seam)),
            ActivationPredicate::Always
            | ActivationPredicate::Configured { .. }
            | ActivationPredicate::Unavailable => None,
        })
        .map(|(family, seam)| ActivationEvidence {
            family: family.to_owned(),
            seam: seam.to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
            evidence_digest_sha256: DIGEST_B.to_owned(),
            active: true,
        })
        .collect();

    let constraint_evidence = families()
        .iter()
        .filter(|family| family.implementation_status != ImplementationStatus::Missing)
        .flat_map(|family| {
            let requested = &declared_values
                .iter()
                .find(|value| value.family == family.id)
                .expect("declared family")
                .value;
            family.value_schema.rules.iter().filter_map(|rule| {
                let CrossFieldRule::ExternalCeiling {
                    field,
                    ceiling,
                    projection,
                    relation,
                    ..
                } = *rule
                else {
                    return None;
                };
                let current = match projection {
                    ConstraintProjection::WholeValue => value_at(requested, field)?.clone(),
                    ConstraintProjection::WholeCatalog => requested.clone(),
                };
                let value = match relation {
                    ConstraintRelation::UpperBound => ConstraintValue::UpperBound {
                        value: current.clone(),
                    },
                    ConstraintRelation::Exact => ConstraintValue::Exact {
                        value: current.clone(),
                    },
                    ConstraintRelation::AttestedDomain => {
                        let scalar_verification = ceiling == ExternalCeiling::VerificationFloor
                            && matches!(
                                current,
                                ResolutionValue::Boolean { .. }
                                    | ResolutionValue::Integer { .. }
                                    | ResolutionValue::Decimal { .. }
                                    | ResolutionValue::Text { .. }
                                    | ResolutionValue::Enum { .. }
                            );
                        ConstraintValue::Domain {
                            minimum: scalar_verification.then(|| current.clone()),
                            maximum: None,
                            allowed_values: (!scalar_verification)
                                .then(|| BTreeSet::from([current.clone()])),
                            required_values: None,
                            preferred: (ceiling == ExternalCeiling::ProviderCapability)
                                .then_some(current.clone()),
                        }
                    }
                };
                Some(ConstraintEvidence {
                    family: family.id.to_owned(),
                    field: field.to_owned(),
                    ceiling,
                    subject: constraint_subject(ceiling, &route),
                    evidence_digest_sha256: DIGEST_B.to_owned(),
                    value,
                })
            })
        })
        .collect();

    let catalogs = SCALAR_CATALOGS
        .iter()
        .map(|catalog| {
            catalog_snapshot_values(catalog.id, production_catalog_values(catalog.id, &route))
        })
        .collect();

    ResolutionInput {
        schema_version: RESOLUTION_SCHEMA_VERSION,
        registry_id: REGISTRY_ID.to_owned(),
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
        profile: Some(ResolutionProfile {
            schema_version: RESOLUTION_SCHEMA_VERSION,
            profile_id: iteron_tunables::RuntimeProfile::Interactive.id().to_owned(),
            registry_revision: REGISTRY_REVISION,
            registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
            values: Vec::new(),
        }),
        declared_values,
        default_evidence: Vec::new(),
        activation_evidence,
        constraint_evidence,
        runtime: RuntimeContext {
            admitted_routes: vec![RouteCapabilities {
                route: route.clone(),
                capabilities,
                attestation_digest_sha256: DIGEST_B.to_owned(),
            }],
            selected_route: Some(route),
            catalogs,
        },
    }
}

fn effort_reasoning_map() -> ResolutionValue {
    ResolutionValue::Map {
        entries: [
            ("low", "low"),
            ("medium", "medium"),
            ("high", "high"),
            ("xhigh", "xhigh"),
            ("max", "max"),
            ("ultracode", "max"),
        ]
        .into_iter()
        .map(|(effort, reasoning)| {
            (
                effort.to_owned(),
                ResolutionValue::Enum {
                    value: reasoning.to_owned(),
                },
            )
        })
        .collect(),
    }
}

fn compaction_trigger() -> ResolutionValue {
    object([
        ("mode", enumv("adaptive")),
        ("usable_window_ratio", decimal(82, 2)),
        ("fallback_trigger_tokens", integer(120_000)),
        ("output_reserve_tokens", integer(8_192)),
    ])
}

fn compaction_adaptive() -> ResolutionValue {
    object([
        ("usable_window_ratio", decimal(82, 2)),
        ("keep_recent_messages", integer(0)),
        ("output_reserve_tokens", integer(8_192)),
    ])
}

fn summary_profile() -> ResolutionValue {
    object([
        ("max_output_tokens", integer(2_048)),
        ("effort", enumv("low")),
        ("preserve_tool_evidence", boolean(true)),
    ])
}

/// One complete executable owner used by the public V2 wrapper fixture: medium effort, the
/// protocol's default run budget, and `RunLimits::new(1, 8)`. Keeping the related families from
/// one explicit projection prevents independently schema-valid samples from forming a policy no
/// production runtime can install.
fn execution_runtime_owner_value(family: &str, route: &RouteIdentity) -> ResolutionValue {
    match family {
        "route_topology" => enumv("direct"),
        "decomposition_profile" => object([
            ("max_output_tokens", integer(4_096)),
            ("effort", enumv("low")),
            ("thinking_tokens", integer(0)),
        ]),
        "fan_breadth" => integer(8),
        "admission" => object([
            ("minimum_remaining_turns", integer(4)),
            ("minimum_remaining_wall_seconds", integer(3)),
            ("require_capability_subset", boolean(true)),
        ]),
        "writer_fan_turn_split" => object([
            ("writer_numerator", integer(1)),
            ("writer_denominator", integer(2)),
            ("minimum_writer_turns", integer(4)),
            ("strictly_dominant", boolean(true)),
        ]),
        "worker_min_turns" => integer(2),
        "wall_split" => object([
            ("fan_numerator", integer(1)),
            ("fan_denominator", integer(3)),
            ("minimum_fan_seconds", integer(1)),
        ]),
        "fan_concurrency" => integer(1),
        "child_ceiling" => child_ceiling(),
        "direct_child_allocation" => object([
            ("writer_turn_numerator", integer(1)),
            ("writer_turn_denominator", integer(2)),
            ("strictly_dominant_writer", boolean(true)),
            ("child_token_numerator", integer(1)),
            ("child_token_denominator", integer(2)),
            ("child_wall_numerator", integer(1)),
            ("child_wall_denominator", integer(3)),
            ("minimum_child_turns", integer(2)),
            ("minimum_remaining_wall_seconds", integer(3)),
        ]),
        "subagent_effort_inheritance" | "per_agent_effort_thinking" => enumv("medium"),
        "report_budget" => integer(16 * 1024),
        "workflow_aggregate" => object([
            ("max_calls", integer(8)),
            ("max_wall_seconds", integer(3_600)),
            ("max_concurrency", integer(1)),
        ]),
        "schema_retry_jitter" => object([
            ("max_attempts", integer(5)),
            ("base_milliseconds", integer(2)),
            ("cap_milliseconds", integer(20)),
        ]),
        "per_agent_model" => enumv(format!("{}:{}", route.provider_id, route.model_id)),
        "per_agent_tool_profile" | "role_specific_model_map" => ResolutionValue::Map {
            entries: Default::default(),
        },
        "per_agent_memory_scope" => isolated_child_memory(),
        "spawn_depth_control" => integer(1),
        "task_priority_scheduling" => object([
            ("priority_levels", integer(1)),
            ("tie_break", enumv("fifo")),
            ("dependency_ready_only", boolean(true)),
        ]),
        "speculative_sibling_count" => integer(2),
        "speculative_sibling_cancellation" => object([
            ("winner_evidence", enumv("first_verified")),
            ("cancel_losers", boolean(true)),
            ("cleanup_timeout_seconds", integer(5)),
            ("reconcile_unknown_effects", boolean(true)),
        ]),
        "early_stop_quorum_policy" => object([
            ("minimum_evidence", integer(1)),
            ("required_roles", integer(0)),
            ("strong_veto", boolean(true)),
        ]),
        "task_retry_reassignment_policy" => object([
            ("max_attempts", integer(2)),
            ("on_failure", enumv("reassign")),
            ("preserve_evidence", boolean(true)),
        ]),
        _ => unreachable!("caller restricts execution owner families: {family}"),
    }
}

fn live_fixed_owner_value(family: &str) -> ResolutionValue {
    match family {
        "thinking_map" => map([
            ("low", integer(0)),
            ("medium", integer(4_096)),
            ("high", integer(8_192)),
            ("xhigh", integer(16_384)),
            ("max", integer(32_768)),
            ("ultracode", integer(32_768)),
        ]),
        "orchestration_map" => map([
            ("low", enumv("direct")),
            ("medium", enumv("direct")),
            ("high", enumv("direct")),
            ("xhigh", enumv("direct")),
            ("max", enumv("direct")),
            ("ultracode", enumv("orchestrated")),
        ]),
        "compaction_failure" => enumv("retain_original"),
        "pure_overlap" => boolean(true),
        "pure_concurrency" | "effecting_tool_concurrency" => integer(16),
        "failed_action_dedup" => object([
            ("failed_only", boolean(true)),
            ("max_identities", integer(4_096)),
            ("scope", enumv("run")),
        ]),
        "pure_memo_cache" => object([
            ("max_entries", integer(256)),
            ("max_key_bytes", integer(64 * 1_024)),
            ("generation_scoped", boolean(true)),
        ]),
        "web_search_cap" => integer(10),
        "verifier_attempts" => integer(3),
        "token_split" => decimal(5, 1),
        "join_reduce" => object([
            ("join", enumv("wait_all")),
            ("order", enumv("declaration")),
            ("include_failed_evidence", boolean(false)),
        ]),
        "auto_compaction_enable" => boolean(true),
        "process_signal_kill_escalation" => enumv("term_grace_kill_reap"),
        "write_set_conflict_admission" => object([
            ("declared_set_required", boolean(true)),
            ("overlap", enumv("reject")),
            ("unknown_set", enumv("reject")),
        ]),
        "retry_eligibility_policy" => verification_retry_policy(),
        "recovery_escalation_policy" => enumv("retry_replan_stop"),
        "writer_worktree_isolation_mode" => boolean(true),
        "merge_conflict_arbitration" => object([
            ("on_clean", enumv("serialize")),
            ("on_conflict", enumv("reject")),
            ("require_verification", boolean(true)),
        ]),
        "inter_agent_messaging_topology" => enumv("parent_mediated"),
        "replay_divergence_detection_policy" => object([
            ("verify_hash_chain", boolean(true)),
            ("verify_identity_scope", boolean(true)),
            ("verify_effect_terminals", boolean(true)),
            ("on_divergence", enumv("fail_closed")),
        ]),
        _ => unreachable!("caller restricts live fixed-owner families: {family}"),
    }
}

fn failure_classification_taxonomy() -> ResolutionValue {
    const CATALOG_ID: &str = "iteron://tunables/catalogs/failure_classification_taxonomy-v1";
    #[derive(Serialize)]
    struct Entry {
        class_id: &'static str,
        outcome: &'static str,
        terminal: bool,
        version: &'static str,
    }
    #[derive(Serialize)]
    struct Catalog<'a> {
        canonicalization: &'static str,
        catalog_id: &'static str,
        entries: &'a [Entry],
    }
    let entries = [
        Entry {
            class_id: "verification.test_failure",
            outcome: "test_failure",
            terminal: false,
            version: "1.0.0",
        },
        Entry {
            class_id: "verification.timed_out",
            outcome: "timeout",
            terminal: true,
            version: "1.0.0",
        },
        Entry {
            class_id: "verification.infrastructure_failure",
            outcome: "infrastructure_failure",
            terminal: true,
            version: "1.0.0",
        },
        Entry {
            class_id: "verification.cancelled",
            outcome: "unknown",
            terminal: true,
            version: "1.0.0",
        },
    ];
    let bytes = serde_json::to_vec(&Catalog {
        canonicalization: "iteron-verification-failure-taxonomy-json-v1",
        catalog_id: CATALOG_ID,
        entries: &entries,
    })
    .expect("fixed taxonomy serializes");
    ResolutionValue::CatalogRef {
        catalog_id: CATALOG_ID.to_owned(),
        digest_sha256: hex::encode(Sha256::digest(&bytes)),
        entry_count: entries.len() as u64,
        canonical_bytes: bytes.len() as u64,
    }
}

fn object<const N: usize>(fields: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

fn map<const N: usize>(entries: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Map {
        entries: entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

const fn integer(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

fn enumv(value: impl Into<String>) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.into(),
    }
}

const fn boolean(value: bool) -> ResolutionValue {
    ResolutionValue::Boolean { value }
}

fn token_estimator() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "estimator".to_owned(),
                ResolutionValue::Enum {
                    value: "iteron.request-estimator-route-aware-v2".to_owned(),
                },
            ),
            ("safety_margin".to_owned(), decimal(0, 0)),
        ]
        .into_iter()
        .collect(),
    }
}

fn production_catalog_values(catalog_id: &str, route: &RouteIdentity) -> BTreeSet<String> {
    let values: Vec<String> = match catalog_id {
        "iteron://tunables/catalogs/providers-v1" => vec![route.provider_id.clone()],
        "iteron://tunables/catalogs/models-v1" => vec![route.model_id.clone()],
        "iteron://tunables/catalogs/provider-reasoning-levels-v1" => {
            ["low", "medium", "high", "xhigh", "max"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        "iteron://tunables/catalogs/token-estimators-v1" => [
            "iteron.request-estimator-route-aware-v2",
            "iteron.conservative-byte-upper-bound",
            "iteron.openai-bpe-approx",
            "iteron.anthropic-bpe-approx",
            "iteron.sentencepiece-approx",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "iteron://tunables/catalogs/tool-capabilities-v1" => [
            "read_only",
            "reversible_local",
            "code_executing",
            "trust_mutating",
            "irreversible_external",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "iteron://tunables/catalogs/model-routes-v1" => {
            vec![format!("{}:{}", route.provider_id, route.model_id)]
        }
        "iteron://tunables/catalogs/provider-service-tiers-v1" => {
            ["provider_default", "auto", "standard", "flex", "priority"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        "iteron://tunables/catalogs/agent-roles-v1" => vec!["generic".to_owned()],
        "iteron://tunables/catalogs/binary-inspectors-v1" => {
            return binary_inspector_ids();
        }
        other => panic!("unregistered scalar catalog `{other}`"),
    };
    values.into_iter().collect()
}

fn lsp_language_routes() -> ResolutionValue {
    ResolutionValue::List {
        items: vec![ResolutionValue::Object {
            fields: [
                (
                    "language_id".to_owned(),
                    ResolutionValue::Text {
                        value: "rust".to_owned(),
                    },
                ),
                (
                    "server_id".to_owned(),
                    ResolutionValue::Text {
                        value: "iteron:rust-analyzer".to_owned(),
                    },
                ),
                (
                    "executable".to_owned(),
                    ResolutionValue::Text {
                        value: "rust-analyzer".to_owned(),
                    },
                ),
                (
                    "arguments".to_owned(),
                    ResolutionValue::List { items: Vec::new() },
                ),
                (
                    "workspace_markers".to_owned(),
                    ResolutionValue::List { items: Vec::new() },
                ),
            ]
            .into_iter()
            .collect(),
        }],
    }
}

fn failover_taxonomy() -> ResolutionValue {
    ResolutionValue::List {
        items: vec![ResolutionValue::Object {
            fields: [
                (
                    "error_class".to_owned(),
                    ResolutionValue::Text {
                        value: "provider.rate_limited".to_owned(),
                    },
                ),
                (
                    "eligible".to_owned(),
                    ResolutionValue::Boolean { value: true },
                ),
                (
                    "dispatch_state".to_owned(),
                    ResolutionValue::Enum {
                        value: "pre_dispatch".to_owned(),
                    },
                ),
                (
                    "version".to_owned(),
                    ResolutionValue::Text {
                        value: "1.0.0".to_owned(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        }],
    }
}

fn objective_weights() -> ResolutionValue {
    ResolutionValue::Map {
        entries: [
            (
                "quality".to_owned(),
                ResolutionValue::Decimal {
                    value: DecimalValue {
                        coefficient: 1,
                        scale: 0,
                    },
                },
            ),
            (
                "cost".to_owned(),
                ResolutionValue::Decimal {
                    value: DecimalValue {
                        coefficient: 0,
                        scale: 0,
                    },
                },
            ),
            (
                "latency".to_owned(),
                ResolutionValue::Decimal {
                    value: DecimalValue {
                        coefficient: 0,
                        scale: 0,
                    },
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn disabled_hedge_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "enabled".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "delay_milliseconds".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "max_duplicates".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "idempotent_only".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn tool_output_spill_policy() -> ResolutionValue {
    object([
        ("memory_threshold_bytes", integer(64 * 1_024)),
        ("spill_max_bytes", integer(16 * 1_024 * 1_024)),
        ("cleanup", enumv("run_end")),
        ("private_storage", boolean(true)),
    ])
}

fn oauth_bearer_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "credential_mode".to_owned(),
                ResolutionValue::Enum {
                    value: "bearer".to_owned(),
                },
            ),
            (
                "binding_count".to_owned(),
                ResolutionValue::Integer { value: 1 },
            ),
            (
                "refresh_binding_count".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "revocation_binding_count".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "refresh_before_expiry_when_capable".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "retry_once_after_unauthorized_when_capable".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "revoke_access_after_forbidden".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
            (
                "expiry_skew_seconds".to_owned(),
                ResolutionValue::Integer { value: 30 },
            ),
            (
                "revocation_endpoint_configured".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn disabled_restore_scope() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [(
            "mode".to_owned(),
            ResolutionValue::Enum {
                value: "workspace".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn verification_checkpoint_cadence() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "turn_boundary".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
            (
                "before_verification".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
            (
                "before_drain".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
            (
                "minimum_turn_interval".to_owned(),
                ResolutionValue::Integer { value: 1 },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn verification_test_selection_strategy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "scope".to_owned(),
                ResolutionValue::Enum {
                    value: "workspace".to_owned(),
                },
            ),
            (
                "required_commands".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
            (
                "max_commands".to_owned(),
                ResolutionValue::Integer { value: 1 },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn verification_retry_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "eligible_classes".to_owned(),
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "verification.test_failure".to_owned(),
                    }],
                },
            ),
            (
                "max_attempts".to_owned(),
                ResolutionValue::Integer { value: 3 },
            ),
            (
                "unknown".to_owned(),
                ResolutionValue::Enum {
                    value: "stop".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn mcp_result_spill_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "visible_max_bytes".to_owned(),
                ResolutionValue::Integer { value: 1024 * 1024 },
            ),
            (
                "spill_max_bytes".to_owned(),
                ResolutionValue::Integer {
                    value: 4 * 1024 * 1024,
                },
            ),
            (
                "cleanup".to_owned(),
                ResolutionValue::Enum {
                    value: "session_end".to_owned(),
                },
            ),
            (
                "private_storage".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn disabled_mcp_capability_exposure() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "resource_discovery".to_owned(),
                ResolutionValue::Enum {
                    value: "disabled".to_owned(),
                },
            ),
            (
                "prompt_discovery".to_owned(),
                ResolutionValue::Enum {
                    value: "disabled".to_owned(),
                },
            ),
            (
                "resource_tool_ids".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
            (
                "prompt_tool_ids".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
            (
                "plugin_binding_ids".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
            (
                "server_binding_ids".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
            (
                "max_visible_bytes".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn process_cwd_continuity() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "scope".to_owned(),
                ResolutionValue::Enum {
                    value: "job".to_owned(),
                },
            ),
            (
                "initial_cwd".to_owned(),
                ResolutionValue::Text {
                    value: std::env::current_dir()
                        .expect("resolver fixture cwd")
                        .to_string_lossy()
                        .into_owned(),
                },
            ),
            (
                "preserve_changes".to_owned(),
                ResolutionValue::Boolean { value: true },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn empty_child_environment() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "reuse".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
            (
                "max_entries".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "max_bytes".to_owned(),
                ResolutionValue::Integer { value: 0 },
            ),
            (
                "blocked_names".to_owned(),
                ResolutionValue::List { items: Vec::new() },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn app_server_queue_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "submission_entries".to_owned(),
                ResolutionValue::Integer { value: 256 },
            ),
            (
                "submission_bytes".to_owned(),
                ResolutionValue::Integer { value: 34_866_176 },
            ),
            (
                "event_entries".to_owned(),
                ResolutionValue::Integer { value: 1_024 },
            ),
            (
                "cosmetic_overflow".to_owned(),
                ResolutionValue::Enum {
                    value: "coalesce".to_owned(),
                },
            ),
            (
                "authoritative_overflow".to_owned(),
                ResolutionValue::Enum {
                    value: "wait".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn binary_media_inspection_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "mime_routes".to_owned(),
                ResolutionValue::Map {
                    entries: [
                        ("image/gif", "iteron.binary.gif-v1"),
                        ("image/jpeg", "iteron.binary.jpeg-v1"),
                        ("image/png", "iteron.binary.png-v1"),
                        ("image/webp", "iteron.binary.webp-v1"),
                    ]
                    .into_iter()
                    .map(|(mime, inspector)| {
                        (
                            mime.to_owned(),
                            ResolutionValue::Enum {
                                value: inspector.to_owned(),
                            },
                        )
                    })
                    .collect(),
                },
            ),
            (
                "unknown_mime".to_owned(),
                ResolutionValue::Enum {
                    value: "reject".to_owned(),
                },
            ),
            (
                "max_input_bytes".to_owned(),
                ResolutionValue::Integer { value: 6_291_456 },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn provider_discovery_bootstrap_policy() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "eager_budget_milliseconds".to_owned(),
                ResolutionValue::Integer { value: 1_500 },
            ),
            (
                "positive_ttl_seconds".to_owned(),
                ResolutionValue::Integer { value: 15 * 60 },
            ),
            (
                "failure_backoff_base_seconds".to_owned(),
                ResolutionValue::Integer { value: 60 },
            ),
            (
                "failure_backoff_cap_seconds".to_owned(),
                ResolutionValue::Integer {
                    value: 24 * 60 * 60,
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn binary_inspector_ids() -> BTreeSet<String> {
    [
        "iteron.binary.gif-v1",
        "iteron.binary.jpeg-v1",
        "iteron.binary.png-v1",
        "iteron.binary.webp-v1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn isolated_child_memory() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "mode".to_owned(),
                ResolutionValue::Enum {
                    value: "isolated".to_owned(),
                },
            ),
            (
                "inherit_parent".to_owned(),
                ResolutionValue::Boolean { value: false },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn child_ceiling() -> ResolutionValue {
    ResolutionValue::Object {
        fields: [
            (
                "max_turns".to_owned(),
                ResolutionValue::Integer { value: 30 },
            ),
            (
                "max_wall_seconds".to_owned(),
                ResolutionValue::Integer { value: 300 },
            ),
            (
                "max_consecutive_errors".to_owned(),
                ResolutionValue::Integer { value: 3 },
            ),
            (
                "capabilities".to_owned(),
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "read_only".to_owned(),
                    }],
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn bm25_runtime_policy() -> ResolutionValue {
    ResolutionValue::Map {
        entries: [
            ("k1".to_owned(), decimal(12, 1)),
            ("b".to_owned(), decimal(75, 2)),
            ("recall_limit".to_owned(), decimal(32, 0)),
        ]
        .into_iter()
        .collect(),
    }
}

fn lexical_memory_weights() -> ResolutionValue {
    ResolutionValue::Map {
        entries: [("lexical".to_owned(), decimal(1, 0))]
            .into_iter()
            .collect(),
    }
}

const fn decimal(coefficient: i64, scale: u8) -> ResolutionValue {
    ResolutionValue::Decimal {
        value: DecimalValue { coefficient, scale },
    }
}

fn sample_schema(schema: ValueSchema, ordinal: u16) -> ResolutionValue {
    let mut value = sample_value(schema.domain, ordinal);
    for rule in schema.rules {
        match *rule {
            CrossFieldRule::LessOrEqual { left, right } => {
                // Repair only an actual violation. Copying `left` over `right` unconditionally
                // would undo a `SumLessOrEqual` that already raised `right`, which makes the
                // generated sample depend on the order the rules happen to be declared in.
                let violated = match (value_at(&value, left), value_at(&value, right)) {
                    (
                        Some(ResolutionValue::Integer { value: left_value }),
                        Some(ResolutionValue::Integer { value: right_value }),
                    ) => left_value > right_value,
                    (Some(_), Some(_)) => true,
                    _ => false,
                };
                if violated && let Some(replacement) = value_at(&value, left).cloned() {
                    replace_at(&mut value, right, replacement);
                }
            }
            CrossFieldRule::SumLessOrEqual { terms, limit } => {
                let sum = terms
                    .iter()
                    .map(|term| match value_at(&value, term) {
                        Some(ResolutionValue::Integer { value }) => i128::from(*value),
                        _ => panic!("sample sum term `{term}` is not an integer"),
                    })
                    .sum::<i128>();
                if value_at(&value, limit).is_some() {
                    replace_at(
                        &mut value,
                        limit,
                        ResolutionValue::Integer {
                            value: i64::try_from(sum).expect("sample sum"),
                        },
                    );
                }
            }
            CrossFieldRule::SumEquals { terms, total } => {
                for (index, term) in terms.iter().enumerate() {
                    replace_at(
                        &mut value,
                        term,
                        ResolutionValue::Decimal {
                            value: if index == 0 {
                                total
                            } else {
                                DecimalValue {
                                    coefficient: 0,
                                    scale: total.scale,
                                }
                            },
                        },
                    );
                }
            }
            CrossFieldRule::Requires { then_field, .. } => {
                let replacement = match value_at(&value, then_field) {
                    Some(ResolutionValue::Boolean { .. }) => {
                        ResolutionValue::Boolean { value: true }
                    }
                    Some(ResolutionValue::Integer { .. }) => ResolutionValue::Integer { value: 1 },
                    Some(ResolutionValue::Decimal { value }) => ResolutionValue::Decimal {
                        value: DecimalValue {
                            coefficient: 1,
                            scale: value.scale,
                        },
                    },
                    _ => continue,
                };
                replace_at(&mut value, then_field, replacement);
            }
            CrossFieldRule::MutuallyExclusive { .. }
            | CrossFieldRule::ResolvedSetSumLessOrEqual { .. }
            | CrossFieldRule::ExternalCeiling { .. } => {}
            CrossFieldRule::MapEntryDomain { key, domain } => {
                if value_at(&value, key).is_some() {
                    replace_at(&mut value, key, sample_scalar(domain, u64::from(ordinal)));
                }
            }
            CrossFieldRule::AtLeastOneNonZero { fields } => {
                let replacement = match value_at(&value, fields[0]) {
                    Some(ResolutionValue::Integer { .. }) => ResolutionValue::Integer { value: 1 },
                    _ => ResolutionValue::Decimal {
                        value: DecimalValue {
                            coefficient: 1,
                            scale: 0,
                        },
                    },
                };
                replace_at(&mut value, fields[0], replacement);
            }
            CrossFieldRule::Equals {
                field,
                value: expected,
            } => replace_at(&mut value, field, rule_value(expected)),
        }
    }
    value
}

fn repair_resolved_set_sum_limits(values: &mut [DeclaredValue]) {
    for family in families() {
        for rule in family.value_schema.rules {
            let CrossFieldRule::ResolvedSetSumLessOrEqual { terms, limit, .. } = *rule else {
                continue;
            };
            let sum = terms
                .iter()
                .map(|term| {
                    let value = values
                        .iter()
                        .find(|value| value.family == term.family)
                        .unwrap_or_else(|| panic!("resolved-set term family `{}`", term.family));
                    match value_at(&value.value, term.path) {
                        Some(ResolutionValue::Integer { value }) => i128::from(*value),
                        _ => panic!(
                            "resolved-set term `{}:{}` is not an integer",
                            term.family, term.path
                        ),
                    }
                })
                .try_fold(0i128, i128::checked_add)
                .expect("fixture resolved-set sum");
            let owner = values
                .iter_mut()
                .find(|value| value.family == limit.family)
                .unwrap_or_else(|| panic!("resolved-set limit family `{}`", limit.family));
            replace_at(
                &mut owner.value,
                limit.path,
                ResolutionValue::Integer {
                    value: i64::try_from(sum).expect("fixture resolved-set sum fits i64"),
                },
            );
        }
    }
}

fn sample_value(domain: StructuredValueDomain, ordinal: u16) -> ResolutionValue {
    match domain {
        StructuredValueDomain::Scalar { domain } => sample_scalar(domain, u64::from(ordinal)),
        StructuredValueDomain::List {
            min_items, item, ..
        } => ResolutionValue::List {
            items: (0..min_items)
                .map(|offset| sample_scalar(item, u64::from(ordinal) + offset))
                .collect(),
        },
        StructuredValueDomain::Map {
            min_entries,
            key,
            value,
            ..
        } => ResolutionValue::Map {
            entries: (0..min_entries)
                .map(|offset| {
                    let seed = u64::from(ordinal) + offset;
                    (sample_key(key, seed), sample_field(value, seed))
                })
                .collect(),
        },
        StructuredValueDomain::Object { fields, .. } => ResolutionValue::Object {
            fields: fields
                .iter()
                .filter(|field| field.required)
                .enumerate()
                .map(|(index, field)| {
                    (
                        field.name.to_owned(),
                        sample_field(field.domain, u64::from(ordinal) + index as u64),
                    )
                })
                .collect(),
        },
        StructuredValueDomain::Catalog {
            catalog_id,
            min_entries,
            ..
        } => ResolutionValue::CatalogRef {
            catalog_id: catalog_id.to_owned(),
            digest_sha256: DIGEST_A.to_owned(),
            entry_count: min_entries,
            canonical_bytes: 0,
        },
    }
}

fn value_at<'a>(value: &'a ResolutionValue, path: &str) -> Option<&'a ResolutionValue> {
    if path == "$" {
        return Some(value);
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let fields = match value {
        ResolutionValue::Object { fields } => fields,
        ResolutionValue::Map { entries } => entries,
        _ => return None,
    };
    let child = fields.get(head)?;
    if tail.is_empty() {
        Some(child)
    } else {
        value_at(child, tail)
    }
}

fn replace_at(value: &mut ResolutionValue, path: &str, replacement: ResolutionValue) {
    if path == "$" {
        *value = replacement;
        return;
    }
    let (head, tail) = path.split_once('.').unwrap_or((path, ""));
    let fields = match value {
        ResolutionValue::Object { fields } => fields,
        ResolutionValue::Map { entries } => entries,
        _ => panic!("sample path `{path}` does not address an object or map"),
    };
    if tail.is_empty() {
        fields.insert(head.to_owned(), replacement);
    } else {
        let child = fields
            .get_mut(head)
            .unwrap_or_else(|| panic!("sample omits `{head}`"));
        replace_at(child, tail, replacement);
    }
}

fn rule_value(value: RuleValue) -> ResolutionValue {
    match value {
        RuleValue::Boolean { value } => ResolutionValue::Boolean { value },
        RuleValue::Integer { value } => ResolutionValue::Integer { value },
        RuleValue::Decimal { value } => ResolutionValue::Decimal { value },
        RuleValue::Enum { value } => ResolutionValue::Enum {
            value: value.to_owned(),
        },
    }
}

fn sample_field(domain: FieldDomain, seed: u64) -> ResolutionValue {
    match domain {
        FieldDomain::Scalar { domain } => sample_scalar(domain, seed),
        FieldDomain::List {
            min_items, item, ..
        } => ResolutionValue::List {
            items: (0..min_items)
                .map(|offset| sample_scalar(item, seed + offset))
                .collect(),
        },
        FieldDomain::Map {
            min_entries,
            key,
            value,
            ..
        } => ResolutionValue::Map {
            entries: (0..min_entries)
                .map(|offset| {
                    let item_seed = seed + offset;
                    (sample_key(key, item_seed), sample_scalar(value, item_seed))
                })
                .collect(),
        },
        FieldDomain::Object { fields, .. } => ResolutionValue::Object {
            fields: fields
                .iter()
                .filter(|field| field.required)
                .enumerate()
                .map(|(index, field)| {
                    (
                        field.name.to_owned(),
                        sample_field(field.domain, seed + index as u64),
                    )
                })
                .collect(),
        },
    }
}

fn sample_scalar(domain: ScalarDomain, seed: u64) -> ResolutionValue {
    match domain {
        ScalarDomain::Boolean => ResolutionValue::Boolean {
            value: seed.is_multiple_of(2),
        },
        ScalarDomain::Integer { min, max, .. } => ResolutionValue::Integer {
            value: min
                .saturating_add(i64::try_from(seed % 16).expect("small seed"))
                .min(max),
        },
        ScalarDomain::Decimal { min, .. } => ResolutionValue::Decimal { value: min },
        ScalarDomain::Text {
            min_bytes,
            max_bytes,
            format,
        } => ResolutionValue::Text {
            value: sample_string(format, min_bytes, max_bytes, seed),
        },
        ScalarDomain::Enum { values, catalog_id } => ResolutionValue::Enum {
            value: if values.is_empty() {
                assert!(catalog_id.is_some());
                format!("fixture:value-{seed}")
            } else {
                values[usize::try_from(seed).expect("seed") % values.len()].to_owned()
            },
        },
    }
}

fn sample_key(domain: ScalarDomain, seed: u64) -> String {
    match sample_scalar(domain, seed) {
        ResolutionValue::Text { value } | ResolutionValue::Enum { value } => value,
        other => panic!("map key schema is not string-like: {other:?}"),
    }
}

fn sample_string(format: StringFormat, min: u64, max: u64, seed: u64) -> String {
    let mut value = match format {
        StringFormat::Utf8 | StringFormat::Identifier => format!("fixture-{seed}"),
        StringFormat::NamespacedId => format!("fixture:value-{seed}"),
        StringFormat::Uri => format!("fixture://value/{seed}"),
        StringFormat::Command => format!("fixture-command-{seed}"),
        StringFormat::Path => format!("/fixture/path/{seed}"),
        StringFormat::Regex => format!("fixture-{seed}.*"),
        StringFormat::Sha256 => format!("{seed:064x}"),
        StringFormat::Semver => format!("1.0.{seed}"),
    };
    let min = usize::try_from(min).expect("minimum");
    let max = usize::try_from(max).expect("maximum");
    while value.len() < min {
        value.push('x');
    }
    assert!(value.len() <= max, "sample string exceeds schema maximum");
    value
}

fn catalog_snapshot_values(catalog_id: &str, values: BTreeSet<String>) -> CatalogSnapshot {
    #[derive(Serialize)]
    struct Payload<'a> {
        canonicalization: &'static str,
        catalog_id: &'a str,
        value_count: usize,
        values: &'a BTreeSet<String>,
    }
    let digest_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&Payload {
            canonicalization: "iteron-tunables-catalog-snapshot-json-v1",
            catalog_id,
            value_count: values.len(),
            values: &values,
        })
        .expect("catalog encoding"),
    ));
    CatalogSnapshot {
        catalog_id: catalog_id.to_owned(),
        digest_sha256,
        values,
    }
}

fn constraint_subject(ceiling: ExternalCeiling, route: &RouteIdentity) -> EvidenceSubject {
    match ceiling {
        ExternalCeiling::OperatorAuthority => EvidenceSubject::Operator {
            authority_digest_sha256: DIGEST_A.to_owned(),
        },
        ExternalCeiling::ProviderCapability | ExternalCeiling::ContextWindow => {
            EvidenceSubject::Route {
                route: route.clone(),
            }
        }
        _ => EvidenceSubject::RuntimeSeam {
            seam: match ceiling {
                ExternalCeiling::ParentTurns => "parent_turns",
                ExternalCeiling::ParentTokens => "parent_tokens",
                ExternalCeiling::ParentWall => "parent_wall",
                ExternalCeiling::ParentCost => "parent_cost",
                ExternalCeiling::ToolBudget => "tool_budget",
                ExternalCeiling::ProcessBudget => "process_budget",
                ExternalCeiling::VerificationFloor => "verification_floor",
                ExternalCeiling::TenantScope => "tenant_scope",
                ExternalCeiling::RunBudget => "run_budget",
                ExternalCeiling::BenchmarkProtocol => "benchmark_protocol",
                ExternalCeiling::OperatorAuthority
                | ExternalCeiling::ProviderCapability
                | ExternalCeiling::ContextWindow => unreachable!(),
            }
            .to_owned(),
            subject_digest_sha256: DIGEST_A.to_owned(),
        },
    }
}

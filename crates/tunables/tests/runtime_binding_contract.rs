use iteron_tunables::{
    CatalogSnapshot, ConstraintValue, ExternalCeiling, FailureCode, ResolutionValue,
    RouteCapabilities, RouteIdentity, RuntimeAuthoritySet, RuntimeProfile,
    RuntimeResolutionBuilder, RuntimeResolutionError, SourceKind, canonical_embedded_default,
    canonical_family, runtime_activation_requirements, runtime_constraint_requirements,
    runtime_default_observations,
};
use std::collections::BTreeSet;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn route() -> RouteCapabilities {
    RouteCapabilities {
        route: RouteIdentity {
            provider_id: "glm".to_owned(),
            model_id: "glm-5.2".to_owned(),
            route_revision: "fixture:v1".to_owned(),
            catalog_digest_sha256: DIGEST_A.to_owned(),
        },
        capabilities: BTreeSet::new(),
        attestation_digest_sha256: DIGEST_B.to_owned(),
    }
}

fn builder() -> RuntimeResolutionBuilder {
    RuntimeResolutionBuilder::new(
        route(),
        Vec::new(),
        RuntimeProfile::Interactive,
        RuntimeAuthoritySet::new(DIGEST_A).unwrap(),
    )
    .unwrap()
}

#[test]
fn composition_inputs_and_authority_digests_fail_closed() {
    let mut bad_route = route();
    bad_route.attestation_digest_sha256 = "not-a-digest".to_owned();
    assert!(matches!(
        RuntimeResolutionBuilder::new(
            bad_route,
            Vec::new(),
            RuntimeProfile::Interactive,
            RuntimeAuthoritySet::new(DIGEST_A).unwrap(),
        ),
        Err(RuntimeResolutionError::InvalidAuthorityDigest(_))
    ));

    assert!(matches!(
        RuntimeAuthoritySet::new("not-a-digest"),
        Err(RuntimeResolutionError::InvalidAuthorityDigest(_))
    ));

    let unknown = CatalogSnapshot {
        catalog_id: "iteron://tunables/catalogs/not-registered-v1".to_owned(),
        digest_sha256: DIGEST_A.to_owned(),
        values: BTreeSet::new(),
    };
    assert!(matches!(
        RuntimeResolutionBuilder::new(
            route(),
            vec![unknown],
            RuntimeProfile::Benchmark,
            RuntimeAuthoritySet::new(DIGEST_A).unwrap(),
        ),
        Err(RuntimeResolutionError::UnknownCatalog(_))
    ));
}

#[test]
fn builder_never_invents_sources_defaults_constraints_or_activation() {
    let mut builder = builder();
    assert!(matches!(
        builder.declare(
            "permission_mode",
            SourceKind::ProjectConfig,
            ResolutionValue::Enum {
                value: "plan".to_owned()
            },
        ),
        Err(RuntimeResolutionError::UnauthorizedSource { .. })
    ));
    assert!(matches!(
        builder.observe_default("max_turns", ResolutionValue::Integer { value: 600 }),
        Err(RuntimeResolutionError::LiteralEvidence(_))
    ));
    assert!(matches!(
        builder.constrain(
            "max_turns",
            "$",
            ExternalCeiling::ParentTurns,
            ConstraintValue::UpperBound {
                value: ResolutionValue::Integer { value: 600 }
            },
        ),
        Err(RuntimeResolutionError::MissingConstraintAuthority(
            ExternalCeiling::ParentTurns
        ))
    ));

    assert!(matches!(
        builder.resolve(),
        Err(RuntimeResolutionError::Resolution(_))
    ));
}

#[test]
fn builtin_literal_declarations_cannot_override_the_canonical_value() {
    for (family, value) in [
        (
            "effort",
            ResolutionValue::Enum {
                value: "high".to_owned(),
            },
        ),
        (
            "model_fallback_chain",
            ResolutionValue::List {
                items: vec![ResolutionValue::Enum {
                    value: "fixture:fallback".to_owned(),
                }],
            },
        ),
    ] {
        assert!(matches!(
            builder().declare(family, SourceKind::Builtin, value),
            Err(RuntimeResolutionError::LiteralOwnerMismatch(rejected)) if rejected == family
        ));
    }

    builder()
        .declare(
            "effort",
            SourceKind::Builtin,
            ResolutionValue::Enum {
                value: "medium".to_owned(),
            },
        )
        .expect("the exact embedded effort literal remains admissible");
    builder()
        .declare(
            "model_fallback_chain",
            SourceKind::Builtin,
            ResolutionValue::List { items: Vec::new() },
        )
        .expect("the exact embedded empty fallback chain remains admissible");
    builder()
        .declare(
            "model_fallback_chain",
            SourceKind::UserConfig,
            ResolutionValue::List {
                items: vec![ResolutionValue::Enum {
                    value: "fixture:fallback".to_owned(),
                }],
            },
        )
        .expect("a non-empty fallback chain remains operator-owned");
}

#[test]
fn complete_activation_inventory_still_returns_only_an_atomic_set_or_failure() {
    let mut builder = builder();
    for requirement in runtime_activation_requirements() {
        builder
            .activate(requirement.family_id, requirement.seam, false, DIGEST_A)
            .unwrap();
    }
    let failure = builder.resolve().unwrap_err();
    let RuntimeResolutionError::Resolution(failure) = failure else {
        panic!("expected the pure resolver's atomic failure report");
    };
    assert!(matches!(
        failure.code,
        FailureCode::InvalidInput | FailureCode::ActiveResolutionFailed
    ));
}

#[test]
fn registry_inventory_is_bounded_deterministic_and_copies_no_ambient_state() {
    let activations = runtime_activation_requirements();
    // One per `RuntimeDerived` family in the registry; the rest are `Always` or `Configured`.
    assert!(activations.is_empty());
    assert!(activations.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        activations
            .iter()
            .map(|item| item.family_id)
            .collect::<BTreeSet<_>>()
            .len(),
        activations.len()
    );

    let defaults = runtime_default_observations();
    assert!(defaults.len() <= iteron_tunables::EXPECTED_FAMILY_COUNT);
    assert!(
        defaults
            .iter()
            .any(|item| item.family_id == "compaction_trigger")
    );

    let constraints = runtime_constraint_requirements();
    assert_eq!(constraints.len(), 196);
    assert!(constraints.iter().any(|item| {
        item.family_id == "max_turns" && item.ceiling == ExternalCeiling::ParentTurns
    }));

    assert_eq!(
        canonical_family("wall_timeout").unwrap().id,
        "max_wall_secs"
    );
    assert_eq!(
        canonical_embedded_default("max_turns"),
        Some(ResolutionValue::Integer { value: 600 })
    );
    assert_eq!(
        canonical_embedded_default("max_wall_secs"),
        Some(ResolutionValue::Integer { value: 14_400 })
    );
    assert_eq!(
        canonical_embedded_default("max_consecutive_tool_errors"),
        Some(ResolutionValue::Integer { value: 25 })
    );
}

#[test]
fn stale_runtime_activation_evidence_is_rejected_for_the_canonical_registry() {
    assert!(runtime_activation_requirements().is_empty());
    let mut non_runtime = builder();
    assert!(matches!(
        non_runtime.activate(
            "retry_backoff_base",
            "crates/cli/src/config/retry.rs",
            true,
            DIGEST_A
        ),
        Err(RuntimeResolutionError::NonRuntimeActivation(family))
            if family == "retry_backoff_base"
    ));

    let mut unknown = builder();
    assert!(matches!(
        unknown.activate(
            "not-a-family",
            "crates/cli/src/config/retry.rs",
            true,
            DIGEST_A
        ),
        Err(RuntimeResolutionError::UnknownFamily(family)) if family == "not-a-family"
    ));
}

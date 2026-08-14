use crate::{
    Contribution, EvidenceLimits, IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
    IMPLEMENTATION_PROCESS_PROTOCOL_VERSION, ImplementationCatalog, ImplementationDependency,
    ImplementationError, ImplementationFailurePolicy, ImplementationManifest,
    ImplementationRegistry, Manifest, Version, compose,
};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use iteron_tunables::ModuleId;
use sha2::{Digest as _, Sha256};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn manifest(id: &str, artifact: &[u8]) -> ImplementationManifest {
    ImplementationManifest {
        implementation_id: id.to_owned(),
        implementation_version: Version(1, 0, 0),
        module: ModuleId::ProviderRouting,
        artifact_sha256: digest(artifact),
        executable: "bin/provider-route".to_owned(),
        argv: vec!["--json-lines".to_owned()],
        protocol_version: IMPLEMENTATION_PROCESS_PROTOCOL_VERSION,
        requested_capabilities: CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]),
        dependencies: Vec::new(),
        runtime_deadline_ms: 30_000,
        cancellation_deadline_ms: 2_000,
        evidence_limits: EvidenceLimits {
            stdout_bytes: 64 * 1024,
            stderr_bytes: 16 * 1024,
            observations: 128,
        },
        failure_policy: ImplementationFailurePolicy::FailClosed,
    }
}

#[test]
fn bad_digest_path_protocol_and_capability_are_refused() {
    let ceiling = CapabilitySet::only(Capability::ReadOnly);

    let mut bad_digest = manifest("bad-digest", b"artifact");
    bad_digest.artifact_sha256 = "ABC".to_owned();
    assert!(matches!(
        ImplementationRegistry::new(ceiling).register(bad_digest),
        Err(ImplementationError::InvalidDigest { .. })
    ));

    for path in ["/usr/bin/plugin", "../escape", "bin\\worker"] {
        let mut bad_path = manifest("bad-path", b"artifact");
        bad_path.executable = path.to_owned();
        assert!(matches!(
            ImplementationRegistry::new(ceiling).register(bad_path),
            Err(ImplementationError::InvalidExecutable { .. })
        ));
    }

    let mut bad_protocol = manifest("bad-protocol", b"artifact");
    bad_protocol.protocol_version += 1;
    assert!(matches!(
        ImplementationRegistry::new(ceiling).register(bad_protocol),
        Err(ImplementationError::UnsupportedProtocol { .. })
    ));

    let catalog = ImplementationCatalog {
        schema_version: IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
        implementations: vec![manifest("bad-capability", b"artifact")],
    };
    let mut json = serde_json::to_value(catalog).unwrap();
    json["implementations"][0]["requested_capabilities"] =
        serde_json::json!(["read_only", "credential_stealing"]);
    let bytes = serde_json::to_vec(&json).unwrap();
    assert!(matches!(
        ImplementationRegistry::from_json(&bytes, ceiling),
        Err(ImplementationError::MalformedJson(_))
    ));
}

#[test]
fn parsed_registry_intersects_exact_ceiling_and_builds_deterministic_clean_plan() {
    let artifact = b"content-addressed implementation package";
    let catalog = ImplementationCatalog {
        schema_version: IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
        implementations: vec![manifest("route.fast", artifact)],
    };
    let bytes = serde_json::to_vec(&catalog).unwrap();
    let registry =
        ImplementationRegistry::from_json(&bytes, CapabilitySet::only(Capability::ReadOnly))
            .unwrap();
    let admitted = registry.resolve("route.fast").unwrap();
    assert_eq!(
        admitted.admitted_capabilities,
        CapabilitySet::only(Capability::ReadOnly)
    );
    assert!(
        !admitted
            .admitted_capabilities
            .contains(Capability::CodeExecuting)
    );

    assert!(matches!(
        registry.verify_artifact("route.fast", b"wrong bytes"),
        Err(ImplementationError::ArtifactDigestMismatch { .. })
    ));
    let verified = registry
        .verify_artifact("route.fast", artifact)
        .unwrap()
        .unwrap();
    assert_eq!(verified.as_str(), digest(artifact));
    let root = std::path::Path::new("/verified/content/store");
    let first = registry
        .launch_plan("route.fast", root, &verified)
        .unwrap()
        .unwrap();
    let second = registry
        .launch_plan("route.fast", root, &verified)
        .unwrap()
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.implementation_id(), "route.fast");
    assert_eq!(first.module(), ModuleId::ProviderRouting);
    assert_eq!(first.artifact_sha256(), digest(artifact));
    assert_eq!(
        first.program(),
        "/verified/content/store/bin/provider-route"
    );
    assert_eq!(first.argv().len(), 1);
    assert_eq!(
        first.argv().first().map(String::as_str),
        Some("--json-lines")
    );
    assert!(first.clears_environment());
    assert!(
        first.environment().is_empty(),
        "no ambient credentials survive"
    );
    assert_eq!(
        first.admitted_capabilities(),
        admitted.admitted_capabilities
    );
}

#[test]
fn duplicate_and_dependency_cycle_are_refused() {
    let ceiling = CapabilitySet::none();
    let mut registry = ImplementationRegistry::new(ceiling);
    registry.register(manifest("duplicate", b"one")).unwrap();
    assert!(matches!(
        registry.register(manifest("duplicate", b"two")),
        Err(ImplementationError::DuplicateImplementation(id)) if id == "duplicate"
    ));

    let mut a = manifest("cycle-a", b"a");
    let mut b = manifest("cycle-b", b"b");
    a.dependencies.push(ImplementationDependency {
        implementation_id: "cycle-b".to_owned(),
        minimum_version: Version(1, 0, 0),
    });
    b.dependencies.push(ImplementationDependency {
        implementation_id: "cycle-a".to_owned(),
        minimum_version: Version(1, 0, 0),
    });
    let bytes = serde_json::to_vec(&ImplementationCatalog {
        schema_version: IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
        implementations: vec![a, b],
    })
    .unwrap();
    assert!(matches!(
        ImplementationRegistry::from_json(&bytes, ceiling),
        Err(ImplementationError::DependencyCycle)
    ));
}

#[test]
fn composition_can_select_an_implementation_without_activating_it() {
    let contribution = Contribution::Implementation {
        module: ModuleId::ProviderRouting,
        implementation: "route.fast".to_owned(),
    };
    let composed = compose(&[Manifest::new("optimizer-pack", 7).with(contribution)]);
    let binding = composed
        .wiring
        .implementation(ModuleId::ProviderRouting)
        .unwrap();
    assert_eq!(binding.detail, "route.fast");
    assert_eq!(binding.plugin, "optimizer-pack");
}

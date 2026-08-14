use crate::{
    ActivationInput, ActivationMismatch, ActivationPathField, ActivationPathProblem,
    EvidenceLimits, IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION,
    IMPLEMENTATION_CATALOG_SCHEMA_VERSION, IMPLEMENTATION_PROCESS_PROTOCOL_VERSION,
    ImplementationActivation, ImplementationActivationDocument, ImplementationActivationError,
    ImplementationCatalog, ImplementationError, ImplementationFailurePolicy,
    ImplementationManifest, ImplementationSource, Version,
};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use iteron_tunables::ModuleId;
use sha2::Digest as _;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn candidate() -> String {
    format!("sha256:{}", "c".repeat(64))
}

struct ActivationFixture {
    base: PathBuf,
    catalog_path: PathBuf,
    artifact_root: PathBuf,
    artifact_path: PathBuf,
    source: ImplementationSource,
}

impl ActivationFixture {
    fn new(module: ModuleId, implementation_id: &str, requested: CapabilitySet) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "iteron-implementation-activation-{}-{id}",
            std::process::id()
        ));
        let artifact_root = base.join("artifact");
        fs::create_dir_all(&artifact_root).expect("create activation fixture");
        let artifact_path = artifact_root.join("provider.bin");
        let artifact_bytes = format!("provider:{implementation_id}:{}", module.as_str());
        fs::write(&artifact_path, artifact_bytes.as_bytes()).expect("write provider artifact");
        let artifact_digest = sha256(artifact_bytes.as_bytes());
        let manifest = ImplementationManifest {
            implementation_id: implementation_id.to_owned(),
            implementation_version: Version(1, 0, 0),
            module,
            artifact_sha256: artifact_digest
                .strip_prefix("sha256:")
                .expect("test digest prefix")
                .to_owned(),
            executable: "provider.bin".to_owned(),
            argv: vec!["--json-lines".to_owned()],
            protocol_version: IMPLEMENTATION_PROCESS_PROTOCOL_VERSION,
            requested_capabilities: requested,
            dependencies: Vec::new(),
            runtime_deadline_ms: 1_000,
            cancellation_deadline_ms: 100,
            evidence_limits: EvidenceLimits {
                stdout_bytes: 4096,
                stderr_bytes: 4096,
                observations: 8,
            },
            failure_policy: ImplementationFailurePolicy::FailClosed,
        };
        let manifest_digest = sha256(&serde_json::to_vec(&manifest).expect("encode manifest"));
        let catalog = ImplementationCatalog {
            schema_version: IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
            implementations: vec![manifest],
        };
        let catalog_path = base.join("catalog.json");
        fs::write(
            &catalog_path,
            serde_json::to_vec(&catalog).expect("encode catalog"),
        )
        .expect("write catalog");
        let base = base.canonicalize().expect("canonical fixture base");
        let artifact_root = artifact_root
            .canonicalize()
            .expect("canonical artifact root");
        let artifact_path = artifact_path
            .canonicalize()
            .expect("canonical artifact path");
        let catalog_path = catalog_path.canonicalize().expect("canonical catalog path");
        let source = ImplementationSource {
            module,
            implementation_id: implementation_id.to_owned(),
            catalog_path: catalog_path.to_string_lossy().into_owned(),
            artifact_root: artifact_root.to_string_lossy().into_owned(),
            manifest_sha256: manifest_digest,
            artifact_sha256: artifact_digest,
        };
        Self {
            base,
            catalog_path,
            artifact_root,
            artifact_path,
            source,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        document_bytes(vec![self.source.clone()])
    }
}

impl Drop for ActivationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn document_bytes(sources: Vec<ImplementationSource>) -> Vec<u8> {
    serde_json::to_vec(&ImplementationActivationDocument {
        schema_version: IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION,
        candidate_sha256: candidate(),
        sources,
    })
    .expect("encode activation document")
}

#[test]
fn happy_path_retains_verified_identity_and_mints_plan() {
    let fixture = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "route.external",
        CapabilitySet::only(Capability::ReadOnly),
    );
    let mut activation = ImplementationActivation::from_json(
        &fixture.bytes(),
        CapabilitySet::only(Capability::ReadOnly),
    )
    .expect("activate verified source");

    assert_eq!(activation.candidate_sha256(), candidate());
    let identity = activation
        .identity(ModuleId::ProviderRouting)
        .expect("verified identity");
    assert_eq!(identity.implementation_id(), "route.external");
    assert_eq!(identity.catalog_path(), fixture.catalog_path.as_path());
    assert_eq!(identity.artifact_root(), fixture.artifact_root.as_path());
    assert_eq!(
        activation.manifest_sha256(ModuleId::ProviderRouting),
        Some(fixture.source.manifest_sha256.as_str())
    );
    let plan = activation
        .take_plan(ModuleId::ProviderRouting)
        .expect("registry-minted plan");
    assert_eq!(plan.implementation_id(), "route.external");
    assert_eq!(plan.module(), ModuleId::ProviderRouting);
    assert_eq!(
        plan.program(),
        fixture.artifact_path.to_string_lossy().as_ref()
    );
    assert!(activation.is_empty());
    assert!(activation.identity(ModuleId::ProviderRouting).is_some());
}

#[test]
fn wrong_manifest_artifact_and_module_fail_closed() {
    let fixture = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "route.mismatch",
        CapabilitySet::none(),
    );

    let mut wrong_manifest = fixture.source.clone();
    wrong_manifest.manifest_sha256 = format!("sha256:{}", "a".repeat(64));
    assert!(matches!(
        ImplementationActivation::from_json(
            &document_bytes(vec![wrong_manifest]),
            CapabilitySet::none()
        ),
        Err(ImplementationActivationError::SourceMismatch {
            mismatch: ActivationMismatch::ManifestDigest,
            ..
        })
    ));

    let mut wrong_module = fixture.source.clone();
    wrong_module.module = ModuleId::PromptSystem;
    assert!(matches!(
        ImplementationActivation::from_json(
            &document_bytes(vec![wrong_module]),
            CapabilitySet::none()
        ),
        Err(ImplementationActivationError::SourceMismatch {
            mismatch: ActivationMismatch::Module,
            ..
        })
    ));

    fs::write(&fixture.artifact_path, b"tampered provider").expect("tamper provider");
    assert!(matches!(
        ImplementationActivation::from_json(&fixture.bytes(), CapabilitySet::none()),
        Err(ImplementationActivationError::Registry {
            error: ImplementationError::ArtifactDigestMismatch { .. },
            ..
        })
    ));
}

#[test]
fn duplicate_keys_modules_and_ids_are_rejected_before_activation() {
    let duplicate_key = format!(
        r#"{{"schema_version":1,"schema_version":1,"candidate_sha256":"{}","sources":[]}}"#,
        candidate()
    );
    assert!(matches!(
        ImplementationActivation::from_json(duplicate_key.as_bytes(), CapabilitySet::none()),
        Err(ImplementationActivationError::DuplicateJsonKey {
            input: ActivationInput::Document
        })
    ));

    let first = ActivationFixture::new(
        ModuleId::PromptSystem,
        "duplicate.module.one",
        CapabilitySet::none(),
    );
    let second = ActivationFixture::new(
        ModuleId::PromptSystem,
        "duplicate.module.two",
        CapabilitySet::none(),
    );
    assert!(matches!(
        ImplementationActivation::from_json(
            &document_bytes(vec![first.source.clone(), second.source.clone()]),
            CapabilitySet::none()
        ),
        Err(ImplementationActivationError::DuplicateModule)
    ));

    let third = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "duplicate.id",
        CapabilitySet::none(),
    );
    let fourth = ActivationFixture::new(
        ModuleId::PromptSystem,
        "duplicate.id",
        CapabilitySet::none(),
    );
    assert!(matches!(
        ImplementationActivation::from_json(
            &document_bytes(vec![third.source.clone(), fourth.source.clone()]),
            CapabilitySet::none()
        ),
        Err(ImplementationActivationError::DuplicateImplementation)
    ));
}

#[test]
fn duplicate_catalog_keys_are_rejected() {
    let fixture = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "duplicate.catalog",
        CapabilitySet::none(),
    );
    fs::write(
        &fixture.catalog_path,
        br#"{"schema_version":1,"schema_version":1,"implementations":[]}"#,
    )
    .expect("write duplicate-key catalog");
    assert!(matches!(
        ImplementationActivation::from_json(&fixture.bytes(), CapabilitySet::none()),
        Err(ImplementationActivationError::DuplicateJsonKey {
            input: ActivationInput::Catalog
        })
    ));
}

#[test]
fn relative_paths_are_rejected() {
    let fixture = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "relative.path",
        CapabilitySet::none(),
    );
    let mut source = fixture.source.clone();
    source.catalog_path = "catalog.json".to_owned();
    assert!(matches!(
        ImplementationActivation::from_json(&document_bytes(vec![source]), CapabilitySet::none()),
        Err(ImplementationActivationError::Path {
            field: ActivationPathField::Catalog,
            problem: ActivationPathProblem::Relative,
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn symlink_roots_are_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = ActivationFixture::new(
        ModuleId::ProviderRouting,
        "symlink.root",
        CapabilitySet::none(),
    );
    let link = fixture.base.join("artifact-link");
    symlink(&fixture.artifact_root, &link).expect("create artifact-root symlink");
    let mut source = fixture.source.clone();
    source.artifact_root = link.to_string_lossy().into_owned();
    assert!(matches!(
        ImplementationActivation::from_json(&document_bytes(vec![source]), CapabilitySet::none()),
        Err(ImplementationActivationError::Path {
            field: ActivationPathField::ArtifactRoot,
            problem: ActivationPathProblem::Symlink,
            ..
        })
    ));
}

#[test]
fn ceiling_is_intersected_and_plan_order_is_deterministic() {
    let broad =
        CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::CodeExecuting]);
    let later = ActivationFixture::new(ModuleId::ProviderRouting, "order.later", broad);
    let earlier = ActivationFixture::new(ModuleId::PromptSystem, "order.earlier", broad);
    let activation = ImplementationActivation::from_json(
        &document_bytes(vec![later.source.clone(), earlier.source.clone()]),
        CapabilitySet::only(Capability::ReadOnly),
    )
    .expect("activate ordered plans");

    let modules = activation
        .plans()
        .map(|(module, _)| module)
        .collect::<Vec<_>>();
    assert_eq!(
        modules,
        vec![ModuleId::PromptSystem, ModuleId::ProviderRouting]
    );
    for (_, plan) in activation.plans() {
        assert_eq!(
            plan.admitted_capabilities(),
            CapabilitySet::only(Capability::ReadOnly)
        );
        assert!(
            !plan
                .admitted_capabilities()
                .contains(Capability::CodeExecuting)
        );
    }
}

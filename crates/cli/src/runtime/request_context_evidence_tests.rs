use super::{ContextRequestObservation, RequestContextEvidenceOwner, RequestContextScope};
use iteron_ctx::{ContextSourceClass, RequestEstimator};
use iteron_protocol::{Capability, Purity, ToolSpec, Trust, TurnId};
use sha2::{Digest, Sha256};

#[test]
fn actual_frontend_capture_rebinds_only_with_its_original_admitted_run_scope() {
    let workspace = std::env::temp_dir().join(format!(
        "iteron-frontend-source-scope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("AGENTS.md"),
        "actual immutable frontend body",
    )
    .unwrap();
    let bundle = iteron_ctx::discover_hierarchy(None, &workspace, &workspace);
    let (text, captures, dropped) =
        bundle.render_with_provenance(iteron_ctx::InstructionDiscoveryPolicy::owner());
    let mut owner = RequestContextEvidenceOwner::default();
    owner
        .install_frontend_materials(&text, &captures, dropped)
        .unwrap();
    owner.bind_frontend_materials(&text, Trust::Untrusted, [1; 32], false);
    assert!(owner.materials[0].source_bytes().is_some());
    let original = owner.materials[0].view().source_version.clone();
    std::fs::write(workspace.join("AGENTS.md"), "changed current file").unwrap();
    owner.clear();
    owner.bind_frontend_materials(&text, Trust::Untrusted, [1; 32], true);
    assert_eq!(owner.materials[0].view().source_version, original);
    assert_eq!(
        owner.materials[0].source_bytes(),
        Some("actual immutable frontend body")
    );
    owner.clear();
    owner.bind_frontend_materials(&text, Trust::Untrusted, [2; 32], true);
    assert!(owner.materials[0].source_bytes().is_none());
    assert_eq!(owner.materials[0].view().source_unavailable,
        Some(iteron_ctx::context_provenance::ContextMaterialUnavailableV1::HistoricalSourceNotRetained));
    // Even matching bytes in today's new producer capture do not prove the historical run used
    // that file version. Only the original live owner's binding can retain that attribution.
    let mut cold = RequestContextEvidenceOwner::default();
    cold.install_frontend_materials(&text, &captures, dropped)
        .unwrap();
    cold.bind_frontend_materials(&text, Trust::Untrusted, [1; 32], true);
    assert!(cold.materials[0].source_bytes().is_none());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn actual_plan_reference_fits_a_full_source_owner_with_explicit_displaced_count() {
    use iteron_ctx::context_provenance::{CapturedContextMaterial, MAX_CONTEXT_MATERIALS};
    let mut owner = RequestContextEvidenceOwner::default();
    for _ in 0..MAX_CONTEXT_MATERIALS {
        owner.append_material(CapturedContextMaterial::historical(
            "recorded reference",
            Trust::Untrusted,
        ));
    }
    let plan = CapturedContextMaterial::journal_record(
        ContextSourceClass::TaskPlanReference,
        &"a".repeat(64),
        31,
        2,
        "actual captured publication JSON",
        "actual plan rendering",
        Trust::Untrusted,
    );
    let (snapshot, dropped) = owner.request_material_snapshot(Some(plan));
    assert_eq!(snapshot.len(), MAX_CONTEXT_MATERIALS);
    assert_eq!(dropped, 1);
    assert_eq!(
        snapshot.last().unwrap().view().source_class,
        ContextSourceClass::TaskPlanReference
    );
    assert_eq!(owner.materials.len(), MAX_CONTEXT_MATERIALS);
    assert_eq!(owner.materials_dropped, 0);
}

fn build(system: &str, tools: &[ToolSpec], trust: Trust) -> iteron_ctx::ContextLedger {
    let estimator = RequestEstimator::new();
    RequestContextEvidenceOwner::default()
        .build_request(
            TurnId(7),
            RequestContextScope {
                execution_window: Some(16_000),
                request_trust: trust,
                estimator: &estimator,
                file: None,
                image: None,
            },
            ContextRequestObservation {
                system,
                messages: &[],
                tools,
                images: &[],
                estimate: iteron_ctx::estimate_request_context(system, &[], tools),
                output_reserved_tokens: 200,
                elapsed_us: 0,
            },
        )
        .ledger
}

#[test]
fn effective_system_commitment_includes_injected_bytes_without_retaining_content() {
    let canary = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let effective = format!("kernel prefix\nproject facts\napi_key={canary}");
    let ledger = build(&effective, &[], Trust::Untrusted);
    let system = ledger
        .segments
        .iter()
        .find(|segment| segment.source_class == ContextSourceClass::KernelSystem)
        .unwrap();
    assert_eq!(
        system.source_digest_sha256,
        <[u8; 32]>::from(Sha256::digest(effective.as_bytes()))
    );
    assert_ne!(
        system.source_digest_sha256,
        <[u8; 32]>::from(Sha256::digest(b"kernel prefix"))
    );
    assert_eq!(system.bytes_after, effective.len() as u64);
    assert_eq!(system.trust, Trust::Untrusted);
    assert!(!serde_json::to_string(&ledger).unwrap().contains(canary));
}

#[test]
fn distinct_schema_field_boundaries_cannot_share_the_same_request_commitment() {
    let schema = serde_json::json!({"type":"object"});
    let first = [ToolSpec {
        name: "a".into(),
        description: "bc".into(),
        input_schema: schema.clone(),
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    }];
    let second = [ToolSpec {
        name: "ab".into(),
        description: "c".into(),
        input_schema: schema,
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    }];
    let identity = |tools: &[ToolSpec]| {
        build("system", tools, Trust::Trusted)
            .segments
            .into_iter()
            .find(|segment| segment.source_class == ContextSourceClass::ToolSchema)
            .unwrap()
            .source_digest_sha256
    };
    assert_ne!(identity(&first), identity(&second));
}

#[test]
fn materialization_overflow_remains_visible_and_does_not_grow_the_source_owner() {
    let estimator = RequestEstimator::new();
    let mut owner = RequestContextEvidenceOwner::default();
    owner.replace_recorded("one actual recorded context", Trust::Workspace, &estimator);
    let source = owner.segments()[0].clone();
    let audit = iteron_ctx::ContextMaterializationAudit {
        segments: vec![source; iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS + 5],
        dropped: 2,
        ..iteron_ctx::ContextMaterializationAudit::default()
    };
    owner.replace_materialized(&audit, 9);
    assert_eq!(
        owner.segments().len(),
        iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS
    );
    let request = owner.build_request(
        TurnId(8),
        RequestContextScope {
            execution_window: None,
            request_trust: Trust::Workspace,
            estimator: &estimator,
            file: None,
            image: None,
        },
        ContextRequestObservation {
            system: "system",
            messages: &[],
            tools: &[],
            images: &[],
            estimate: iteron_ctx::estimate_request_context("system", &[], &[]),
            output_reserved_tokens: 10,
            elapsed_us: 0,
        },
    );
    assert!(request.ledger.dropped >= 7);
    owner.clear();
    assert!(owner.segments().is_empty());
}

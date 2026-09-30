use super::{
    ContextMaterialRootV1, ContextMaterialUnavailableV1, ContextMaterialVersionV1, MaterialRender,
    MaterialSource, digest,
};
use crate::{
    ContextDecision, ContextPort, ContextPortInput, ContextSlotObservation, ContextSourceClass,
    ContextStrategy, DefaultContextPort, MemoryStore, memory::MemoryRecallStrategy,
};
use iteron_protocol::{
    Capability, Trust,
    capability_set::CapabilitySet,
    context::{ContextRequest, ContextSource, InstructionScope, RequestId},
};

fn workspace() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-material-provenance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn actual_world_sources_bind_immutable_versions_and_the_exact_rendered_contribution() {
    let root = workspace();
    std::fs::write(
        root.join("AGENTS.md"),
        "reference guidance\n@import imported.md",
    )
    .unwrap();
    std::fs::write(
        root.join("imported.md"),
        "imported provenance_anchor guidance",
    )
    .unwrap();
    std::fs::write(root.join("main.rs"), "pub fn provenance_anchor() {}\n").unwrap();
    let skill = root.join(".iteron/skills/provenance_anchor");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        format!(
            "---\nname: provenance_anchor\ndescription: provenance anchor reference\n---\n{}",
            "bounded body ".repeat(40000)
        ),
    )
    .unwrap();
    MemoryStore::at(&root)
        .add("provenance_anchor: a current reference memory calibration")
        .unwrap();
    let mut observation =
        ContextSlotObservation::baseline(RequestId(7), "provenance_anchor reference calibration");
    observation.max_bytes = 32000;
    observation.instruction_scopes = vec![InstructionScope::Project];
    observation.include_environment = false;
    let plan = ContextStrategy::default()
        .select(&observation, CapabilitySet::only(Capability::ReadOnly))
        .unwrap();
    let (grant, _, audit) = DefaultContextPort
        .resolve_with_decision_audit(
            &plan,
            &ContextPortInput {
                workspace: root.clone(),
                ..ContextPortInput::default()
            },
            &MemoryRecallStrategy::default(),
        )
        .unwrap();
    let instruction = audit
        .materials
        .iter()
        .find(|item| {
            item.view()
                .path
                .as_ref()
                .is_some_and(|path| path.relative_path == "AGENTS.md")
        })
        .unwrap();
    assert_eq!(
        instruction.source_bytes().unwrap(),
        "reference guidance\n@import imported.md"
    );
    assert!(matches!(
        instruction.view().source_version,
        Some(ContextMaterialVersionV1::CompleteFile { .. })
    ));
    assert!(audit.materials.iter().any(|item| {
        item.view()
            .path
            .as_ref()
            .is_some_and(|path| path.relative_path == "imported.md")
    }));
    let code = audit
        .materials
        .iter()
        .find(|item| {
            item.view().source_class == ContextSourceClass::WorkspaceOutline
                && item
                    .view()
                    .path
                    .as_ref()
                    .is_some_and(|path| path.relative_path == "main.rs")
        })
        .unwrap();
    assert_eq!(
        code.source_bytes().unwrap(),
        "pub fn provenance_anchor() {}\n"
    );
    assert!(
        code.rendered_bytes()
            .contains("1: pub fn provenance_anchor")
    );
    let memory = audit
        .materials
        .iter()
        .find(|item| {
            matches!(
                item.view().source_version,
                Some(ContextMaterialVersionV1::MemoryRecord {
                    record_revision: 1,
                    ..
                })
            )
        })
        .unwrap();
    let record: crate::memory_records::MemoryRecord =
        serde_json::from_str(memory.source_bytes().unwrap()).unwrap();
    assert_eq!(record.revision, 1);
    let skill = audit
        .materials
        .iter()
        .find(|item| item.view().source_class == ContextSourceClass::SkillIndex)
        .unwrap();
    assert!(matches!(
        skill.view().source_version,
        Some(ContextMaterialVersionV1::ReadPrefix {
            unread_tail: true,
            ..
        })
    ));
    for material in audit
        .materials
        .iter()
        .filter(|item| item.view().rendered_bytes > 0)
    {
        assert_eq!(
            digest(material.rendered_bytes().as_bytes()),
            material.view().rendered_sha256
        );
        assert!(
            grant
                .segments
                .iter()
                .any(|segment| segment.text.contains(material.rendered_bytes()))
        );
    }
    std::fs::write(root.join("AGENTS.md"), "different disk revision").unwrap();
    assert_eq!(
        instruction.source_bytes().unwrap(),
        "reference guidance\n@import imported.md",
        "historical capture must not be rebound by rereading a changed file"
    );
    assert!(!format!("{instruction:?}").contains("reference guidance"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn actual_budget_clip_retains_original_file_commitment_and_only_the_admitted_fragment() {
    let root = workspace();
    let original = "alpha ".repeat(20);
    std::fs::write(root.join("AGENTS.md"), &original).unwrap();
    let source = MaterialSource::file(
        ContextSourceClass::ProjectInstructions,
        ContextMaterialRootV1::Workspace,
        &root,
        &root.join("AGENTS.md"),
        &original,
        false,
    );
    let mut render = MaterialRender::default();
    render.append(source, &original);
    let mut request = ContextRequest::new(
        RequestId(1),
        iteron_protocol::slot::SlotId("core/context".into()),
        32,
    );
    request.trust_ceiling = Trust::Untrusted;
    let mut builder = crate::context_materialization::AuditedGrantBuilder::new(&request);
    builder.push_materialized(render, Trust::Untrusted, ContextSource::Instructions);
    let (grant, audit) = builder.finish();
    let material = &audit.materials[0];
    assert_eq!(material.view().decision, ContextDecision::Truncated);
    assert_eq!(material.source_bytes().unwrap(), original);
    assert!(
        grant.segments[0]
            .text
            .starts_with(material.rendered_bytes())
    );
    assert!(material.rendered_bytes().len() < original.len());
    let mut replacement = crate::context_materialization::AuditedGrantBuilder::new(&request);
    replacement.push(
        "custom port text".into(),
        Trust::Untrusted,
        ContextSource::Instructions,
    );
    let unavailable = replacement.finish().1.materials;
    assert_eq!(
        unavailable[0].view().source_unavailable,
        Some(ContextMaterialUnavailableV1::SourceOwnerDidNotCapture)
    );
    assert!(unavailable[0].view().path.is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn actual_refused_symlink_import_has_an_explicit_unavailable_source_without_target_bytes() {
    let root = workspace();
    std::fs::write(root.join("AGENTS.md"), "reference\n@import linked.md").unwrap();
    std::os::unix::fs::symlink("missing-private-target.md", root.join("linked.md")).unwrap();
    let bundle = crate::instructions::discover_hierarchy_with_policy(
        None,
        &root,
        &root,
        crate::InstructionDiscoveryPolicy::owner(),
    );
    let (_, materials, _) =
        bundle.render_with_provenance(crate::InstructionDiscoveryPolicy::owner());
    let refused = materials
        .iter()
        .find(|item| {
            item.view()
                .path
                .as_ref()
                .is_some_and(|path| path.relative_path == "linked.md")
        })
        .unwrap();
    assert!(matches!(
        refused.view().source_unavailable,
        Some(ContextMaterialUnavailableV1::SourceReadRefused { .. })
    ));
    assert!(refused.source_bytes().is_none());
    assert_eq!(refused.view().decision, ContextDecision::Rejected);
    std::fs::remove_dir_all(root).unwrap();
}

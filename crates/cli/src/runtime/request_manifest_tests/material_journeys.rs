//! Actual Main admission, native preparation and retained public artifact journeys.
use super::{ExactRequest, agent, agent_with_environment, read};
use crate::artifacts::DurableArtifactStore;
use crate::runtime::{Agent, Outcome, gate_integration_tests};
use iteron_ctx::instructions::{InstructionDiscoveryPolicy, discover_hierarchy};
use iteron_protocol::client_artifact::{ClientArtifactCommandV1, ClientArtifactDescriptorV1};
use iteron_protocol::{EventKind, RunId, Seq, SessionId, TenantId, ToolUse, Trust, TurnId};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

fn install_frontend(owner: &mut Agent, workspace: &Path) {
    let bundle = discover_hierarchy(None, workspace, workspace);
    let (text, materials, dropped) =
        bundle.render_with_provenance(InstructionDiscoveryPolicy::owner());
    owner
        .set_instruction_context_with_provenance(text, Trust::Untrusted, materials, dropped)
        .unwrap();
}

fn native_system(provider: &ExactRequest, index: usize) -> String {
    let request: Value = serde_json::from_slice(&provider.requests.lock().unwrap()[index]).unwrap();
    request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "system")
        .unwrap()["content"]
        .as_str()
        .unwrap()
        .into()
}

fn prepared_manifests(store: &DurableArtifactStore, thread: &SessionId) -> Vec<Value> {
    let catalog = store
        .read(
            thread,
            ClientArtifactCommandV1::List {
                thread_id: thread.clone(),
            },
        )
        .unwrap();
    catalog["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|descriptor| {
            let descriptor: ClientArtifactDescriptorV1 =
                serde_json::from_value(descriptor.clone()).unwrap();
            if descriptor.schema != "iteron.provider-request-manifest.v1" {
                return None;
            }
            let value: Value = serde_json::from_slice(&read(store, thread, &descriptor)).unwrap();
            (value["type"] == "provider_request_prepared_v1").then_some(value)
        })
        .collect()
}

fn retained_bytes(store: &DurableArtifactStore, thread: &SessionId, resolution: &Value) -> Vec<u8> {
    assert_eq!(resolution["kind"], "retained");
    let locator = &resolution["locator"];
    let descriptor: ClientArtifactDescriptorV1 =
        serde_json::from_value(locator["artifact"].clone()).unwrap();
    assert_eq!(descriptor.schema, "iteron.context-material-archive.v1");
    assert!(descriptor.complete);
    let archive = read(store, thread, &descriptor);
    let offset = locator["offset"].as_u64().unwrap() as usize;
    let length = locator["bytes"].as_u64().unwrap() as usize;
    let selected = archive[offset..offset.checked_add(length).unwrap()].to_vec();
    assert_eq!(
        locator["sha256"],
        format!("{:x}", Sha256::digest(&selected))
    );
    selected
}

#[tokio::test]
async fn actual_main_materials_reconstruct_after_source_removal_and_artifact_reopen() {
    let workspace = gate_integration_tests::temp_ws("main-material-source-reopen");
    let instructions = "permaterial_anchor original instructions\n@import imported.md";
    let imported = "permaterial_anchor exact imported reference";
    std::fs::write(workspace.join("AGENTS.md"), instructions).unwrap();
    std::fs::write(workspace.join("imported.md"), imported).unwrap();
    let skill = workspace.join(".iteron/skills/permaterial_anchor");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        format!(
            "---\nname: permaterial_anchor\ndescription: per material reference\n---\n{}",
            "large bounded reference body ".repeat(20_000)
        ),
    )
    .unwrap();
    let memory = iteron_ctx::MemoryStore::at(&workspace);
    let id = memory
        .add("permaterial_anchor current record provenance calibration")
        .unwrap();
    let run = RunId("main-material-source-reopen".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    owner.memory_workspace = Some(workspace.clone());
    install_frontend(&mut owner, &workspace);
    assert_eq!(
        owner
            .run("permaterial_anchor reference provenance calibration")
            .await
            .unwrap(),
        Outcome::Done
    );
    let system = native_system(&provider, 0);
    assert!(system.contains(imported));
    assert!(system.contains("current record provenance calibration"));
    assert!(system.contains("permaterial_anchor"));
    let record = owner.rollout.path().to_owned();
    drop(owner);
    std::fs::remove_file(workspace.join("AGENTS.md")).unwrap();
    std::fs::remove_file(workspace.join("imported.md")).unwrap();
    std::fs::remove_file(skill.join("SKILL.md")).unwrap();
    assert!(memory.remove_checked(&id).unwrap());
    let store = DurableArtifactStore::open(
        &workspace.join(".iteron/runs"),
        TenantId::default(),
        run.clone(),
        &workspace,
    )
    .unwrap();
    let thread = SessionId(run.0.clone());
    let manifests = prepared_manifests(&store, &thread);
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    let actual_intent = iteron_record::replay(&record)
        .unwrap()
        .into_iter()
        .find(
            |event| matches!(&event.kind, EventKind::EffectIntent {tool, ..} if tool == "provider"),
        )
        .unwrap();
    assert_eq!(manifest["scope"]["source_event_seq"], actual_intent.seq.0);
    let materials = manifest["per_material_resolution"].as_array().unwrap();
    for (path, expected) in [("AGENTS.md", instructions), ("imported.md", imported)] {
        let item = materials
            .iter()
            .find(|item| item["material"]["path"]["relative_path"] == path)
            .unwrap();
        assert_eq!(
            item["source"]["locator"]["representation"],
            "exact_captured_bytes"
        );
        assert_eq!(
            retained_bytes(&store, &thread, &item["source"]),
            expected.as_bytes()
        );
        let rendered = retained_bytes(&store, &thread, &item["rendered"]);
        assert!(system.contains(std::str::from_utf8(&rendered).unwrap()));
        assert_eq!(
            item["material"]["rendered_sha256"],
            format!("{:x}", Sha256::digest(&rendered))
        );
        assert_eq!(
            item["prepared_request_inclusion"]["kind"],
            "captured_rendering"
        );
    }
    let fact = materials
        .iter()
        .find(|item| item["material"]["source_version"]["kind"] == "memory_record")
        .unwrap();
    let captured: Value =
        serde_json::from_slice(&retained_bytes(&store, &thread, &fact["source"])).unwrap();
    assert_eq!(captured["id"], id);
    assert_eq!(captured["revision"], 1);
    assert!(!captured["deleted"].as_bool().unwrap());
    let metadata = materials
        .iter()
        .find(|item| item["material"]["source_class"] == "skill_index")
        .unwrap();
    assert_eq!(
        metadata["material"]["source_version"]["kind"],
        "read_prefix"
    );
    assert_eq!(metadata["material"]["source_version"]["unread_tail"], true);
    assert!(!retained_bytes(&store, &thread, &metadata["source"]).is_empty());
    drop(store);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn new_main_decision_removes_deleted_memory_and_preserves_admitted_frontend_identity() {
    let workspace = gate_integration_tests::temp_ws("main-material-refresh");
    let original = "admitted_original_frontend identity remains frozen";
    std::fs::write(workspace.join("AGENTS.md"), original).unwrap();
    let memory = iteron_ctx::MemoryStore::at(&workspace);
    let id = memory
        .add("freshness_anchor stale_memory_reference")
        .unwrap();
    let run = RunId("main-material-refresh".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent_with_environment(
        &workspace,
        &run,
        provider.clone(),
        Some(("admitted_environment_reference".into(), Trust::Untrusted)),
    );
    owner.memory_workspace = Some(workspace.clone());
    install_frontend(&mut owner, &workspace);
    assert_eq!(
        owner.run("freshness_anchor reference").await.unwrap(),
        Outcome::Done
    );
    assert!(native_system(&provider, 0).contains("stale_memory_reference"));
    assert!(memory.remove_checked(&id).unwrap());
    std::fs::write(workspace.join("AGENTS.md"), "changed_live_frontend").unwrap();
    assert_eq!(
        owner
            .follow_up("freshness_anchor second decision")
            .await
            .unwrap(),
        Outcome::Done
    );
    let second = native_system(&provider, 1);
    assert!(second.contains(original));
    assert!(second.contains("admitted_environment_reference"));
    assert!(!second.contains("changed_live_frontend"));
    assert!(!second.contains("stale_memory_reference"));
    let path = owner.rollout.path().to_owned();
    drop(owner);
    let injections = iteron_record::replay(&path)
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.kind {
            EventKind::ContextInjection {
                instructions: Some(instructions),
                ..
            } => Some(instructions),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(injections.len(), 2);
    assert_eq!(injections[0], injections[1]);
    let store = DurableArtifactStore::open(
        &workspace.join(".iteron/runs"),
        TenantId::default(),
        run.clone(),
        &workspace,
    )
    .unwrap();
    let manifests = prepared_manifests(&store, &SessionId(run.0.clone()));
    assert_eq!(manifests.len(), 2);
    for manifest in &manifests {
        let material = manifest["per_material_resolution"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["material"]["path"]["relative_path"] == "AGENTS.md")
            .unwrap();
        assert_eq!(
            material["material"]["source_version"]["sha256"],
            format!("{:x}", Sha256::digest(original))
        );
    }
    drop(store);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn cold_main_refresh_does_not_attribute_current_disk_to_old_admitted_prefix() {
    let workspace = gate_integration_tests::temp_ws("cold-material-refresh");
    let original = "cold_original_admitted_frontend";
    let current = "cold_current_disk_frontend";
    std::fs::write(workspace.join("AGENTS.md"), original).unwrap();
    let memory = iteron_ctx::MemoryStore::at(&workspace);
    let id = memory.add("coldfresh_anchor old_memory_reference").unwrap();
    let run = RunId("cold-material-refresh".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    owner.memory_workspace = Some(workspace.clone());
    install_frontend(&mut owner, &workspace);
    assert_eq!(
        owner.run("coldfresh_anchor reference").await.unwrap(),
        Outcome::Done
    );
    assert!(native_system(&provider, 0).contains("old_memory_reference"));
    let path = owner.rollout.path().to_owned();
    drop(owner);
    assert!(memory.remove_checked(&id).unwrap());
    std::fs::write(workspace.join("AGENTS.md"), current).unwrap();
    let mut resumed = agent(&workspace, &run, provider.clone());
    resumed.memory_workspace = Some(workspace.clone());
    install_frontend(&mut resumed, &workspace);
    resumed
        .set_resume(Agent::messages_from_rollout(&path).unwrap())
        .unwrap();
    // The prior turn already completed. An empty continuation advances its terminal identity
    // while keeping the frozen injection; it is not a new nonempty user memory decision.
    assert_eq!(resumed.follow_up("").await.unwrap(), Outcome::Done);
    let frozen = native_system(&provider, 1);
    assert!(frozen.contains(original));
    assert!(frozen.contains("old_memory_reference"));
    assert!(!frozen.contains(current));
    assert_eq!(
        resumed
            .follow_up("coldfresh_anchor new user decision")
            .await
            .unwrap(),
        Outcome::Done
    );
    let fresh = native_system(&provider, 2);
    assert!(fresh.contains(original));
    assert!(!fresh.contains(current));
    assert!(!fresh.contains("old_memory_reference"));
    drop(resumed);
    let store = DurableArtifactStore::open(
        &workspace.join(".iteron/runs"),
        TenantId::default(),
        run.clone(),
        &workspace,
    )
    .unwrap();
    let manifests = prepared_manifests(&store, &SessionId(run.0.clone()));
    assert_eq!(manifests.len(), 3);
    let latest = manifests
        .iter()
        .max_by_key(|manifest| manifest["scope"]["source_event_seq"].as_u64().unwrap())
        .unwrap();
    let materials = latest["per_material_resolution"].as_array().unwrap();
    assert!(
        !materials
            .iter()
            .any(|item| item["material"]["source_version"]["sha256"]
                == format!("{:x}", Sha256::digest(current)))
    );
    let old = materials
        .iter()
        .find(|item| item["material"]["source_class"] == "project_instructions")
        .unwrap();
    assert_eq!(old["source"]["kind"], "unavailable");
    assert_eq!(
        old["material"]["source_unavailable"]["kind"],
        "historical_source_not_retained"
    );
    assert_eq!(old["rendered"]["kind"], "retained");
    drop(store);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn actual_native_plan_material_resolves_exact_wal_publication_and_observation() {
    let workspace = gate_integration_tests::temp_ws("native-plan-material");
    let run = RunId("native-plan-material".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    owner.registry = iteron_tools::Registry::coding_agent_for_tests(&workspace).unwrap();
    owner
        .admit_submission("continue the multi-module refactor")
        .unwrap();
    let submission: Seq =
        serde_json::from_value(owner.task_plan_snapshot()["observed_submission_seq"].clone())
            .unwrap();
    let call = ToolUse {
        id: "actual-plan-material".into(),
        name: iteron_tools::UPDATE_PLAN.into(),
        input: serde_json::json!({"operation":"replace","expected_revision":0,
            "observed_submission_seq":submission,
            "steps":[{"description":"preserve source versions","status":"in_progress"}],
            "obligations":["retain exact reviewed reconstruction receipts"]}),
    };
    assert!(!owner.execute_task_plan(TurnId(0), &call).unwrap().is_error);
    // A real new user-message receipt changes rendered review state without changing the frozen
    // plan publication. The request material must name both receipts independently.
    owner.admit_submission("also keep compatibility").unwrap();
    let observation = owner.task_plan_snapshot()["observed_submission_seq"].clone();
    assert_eq!(owner.task_plan_snapshot()["needs_review"], true);
    assert_eq!(owner.run("").await.unwrap(), Outcome::Done);
    let system = native_system(&provider, 0);
    assert!(system.contains("Newly admitted input changed the context"));
    let record = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&record).unwrap();
    let publication = events
        .iter()
        .find(|event| matches!(event.kind, EventKind::TaskPlanUpdatedV1 { .. }))
        .unwrap();
    let exact_record = serde_json::to_vec(&publication.kind).unwrap();
    let store = DurableArtifactStore::open(
        &workspace.join(".iteron/runs"),
        TenantId::default(),
        run.clone(),
        &workspace,
    )
    .unwrap();
    let thread = SessionId(run.0.clone());
    let manifests = prepared_manifests(&store, &thread);
    assert_eq!(manifests.len(), 1);
    let plan = manifests[0]["per_material_resolution"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["material"]["source_class"] == "task_plan_reference")
        .unwrap();
    assert!(plan["material"]["path"].is_null());
    assert_eq!(plan["material"]["source_version"]["kind"], "journal_record");
    assert_eq!(
        plan["material"]["source_version"]["source_event_seq"],
        publication.seq.0
    );
    assert_eq!(
        plan["material"]["source_version"]["observation_event_seq"],
        observation
    );
    assert_eq!(
        retained_bytes(&store, &thread, &plan["source"]),
        exact_record
    );
    assert!(system.contains(
        std::str::from_utf8(&retained_bytes(&store, &thread, &plan["rendered"])).unwrap()
    ));
    assert_eq!(
        plan["prepared_request_inclusion"]["kind"],
        "captured_rendering"
    );
    drop(store);
    std::fs::remove_dir_all(workspace).unwrap();
}

//! Actual Agent/effect/artifact journeys, rather than a manufactured projection fixture.
use crate::artifacts::DurableArtifactStore;
use crate::runtime::{Agent, Outcome, gate_integration_tests};
use base64::Engine;
use iteron_protocol::client_artifact::{ClientArtifactCommandV1, ClientArtifactDescriptorV1};
use iteron_protocol::{Block, Budget, EventKind, RunId, SessionId, StopReason, TenantId, Usage};
use iteron_provider::request_capture::{ProviderRequestObserver, ProviderWireRequest};
use iteron_provider::{
    AdapterKind, Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport,
};
use iteron_record::Rollout;
use iteron_tools::Registry;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};

const CANARY: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
const ENDPOINT: &str = "https://fixture.invalid/v1?credential=private_endpoint_canary";
#[derive(Default)]
struct ExactRequest {
    requests: Mutex<Vec<Vec<u8>>>,
    exceeds_admission: bool,
    omit_context: bool,
    fail_after_preparation: bool,
    assert_first_request_has_no_archive: Option<std::path::PathBuf>,
}
#[async_trait::async_trait]
impl Provider for ExactRequest {
    fn physical_output_token_ceiling(
        &self,
        budget: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        Ok(Some(budget.requested_max_tokens))
    }
    fn provider_instance_id(&self) -> Option<&str> {
        Some("manifest-fixture")
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("actual runtime must invoke the observed physical request port")
    }
    async fn turn_observed(
        &self,
        request: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        let serialized_output_tokens = request.max_tokens + u32::from(self.exceeds_admission);
        let mut messages = vec![serde_json::json!({"role":"system","content":request.system})];
        messages.extend(
            request
                .messages
                .iter()
                .map(|message| serde_json::to_value(message).unwrap()),
        );
        if self.omit_context {
            messages = vec![serde_json::json!({"role":"user","content":"omitted context"})];
        }
        let bytes = serde_json::to_vec(&serde_json::json!({"model":request.model,"messages":messages,"max_tokens":serialized_output_tokens})).unwrap();
        observer
            .prepared(ProviderWireRequest {
                adapter: AdapterKind::OpenAiCompatibleChat,
                method: "POST",
                endpoint: ENDPOINT,
                content_type: "application/json",
                body: &bytes,
                serialized_output_tokens,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        if self.fail_after_preparation {
            self.requests.lock().unwrap().push(bytes);
            return Err(ProviderError::RequestCaptureRefusedBeforeDispatch);
        }
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        if let Some(path) = &self.assert_first_request_has_no_archive
            && self.requests.lock().unwrap().is_empty()
        {
            assert!(
                !path.exists(),
                "diagnostic publication must wait for explicit drain"
            );
        }
        self.requests.lock().unwrap().push(bytes);
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "manifest journey completed".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage::default()),
        })
    }
}

fn agent(workspace: &Path, run: &RunId, provider: Arc<dyn Provider>) -> Agent {
    agent_with_environment(workspace, run, provider, None)
}

fn agent_with_environment(
    workspace: &Path,
    run: &RunId,
    provider: Arc<dyn Provider>,
    environment: Option<(String, iteron_protocol::Trust)>,
) -> Agent {
    let rollout = Rollout::open(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        Registry::read_only(workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        // Separate the deliberate secret token from the independently admitted context bytes.
        format!("effective system\napi_key={CANARY}\n"),
        Budget::default(),
    );
    agent.workspace = workspace.to_owned();
    if let Some((text, trust)) = environment {
        agent.set_environment_context(text, trust).unwrap();
    }
    // The schema sampler's tiny memory fields cannot hold a real record's framing. These
    // journeys use the actual materializer's bounded default; deliberate budget-edge fixtures
    // continue to override the family explicitly. No production ceiling is changed here.
    let memory = agent.context_materialization_policy.memory;
    let memory_value = iteron_tunables::ResolutionValue::Object {
        fields: [
            ("index_bytes", memory.index_bytes),
            ("recall_bytes", memory.recall_bytes),
            ("instruction_bytes", memory.instr_bytes),
            (
                "fact_bytes",
                iteron_tunables::param_usize(
                    "cli.runtime_tunables.core_facts.memory_fact_bytes",
                    8_000,
                ),
            ),
            ("total_bytes", memory.total),
        ]
        .into_iter()
        .map(|(name, bytes)| {
            (
                name.into(),
                iteron_tunables::ResolutionValue::Integer {
                    value: i64::try_from(bytes).unwrap(),
                },
            )
        })
        .collect(),
    };
    if agent.rollout.next_sequence().0 == 0 {
        gate_integration_tests::record_test_genesis_with_tunable_edits(
            &mut agent,
            workspace,
            [("memory_budgets", memory_value)],
        );
    } else {
        gate_integration_tests::pin_test_tunables_with_edits(
            &mut agent,
            [("memory_budgets", memory_value)],
        );
    }
    agent
        .record_operator_model_selection(
            provider,
            "manifest-fixture".into(),
            "fixture-model".into(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
    agent
}
fn read(
    store: &DurableArtifactStore,
    thread: &SessionId,
    descriptor: &ClientArtifactDescriptorV1,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    for _ in 0..1024 {
        let reply = store
            .read(
                thread,
                ClientArtifactCommandV1::Read {
                    thread_id: thread.clone(),
                    artifact_id: descriptor.artifact_id.clone(),
                    offset,
                    max_bytes: 64 * 1024,
                },
            )
            .unwrap();
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(reply["content_base64"].as_str().unwrap())
                .unwrap(),
        );
        if reply["eof"] == true {
            return bytes;
        }
        offset = reply["next_offset"].as_u64().unwrap();
    }
    panic!("artifact fixture exceeded bounded download work")
}

#[tokio::test]
async fn physical_manifest_sources_and_scrubbed_bytes_survive_actual_writer_reopen() {
    let workspace = gate_integration_tests::temp_ws("physical-manifest-reopen");
    let run = RunId("physical-manifest-reopen".into());
    let provider = Arc::new(ExactRequest {
        assert_first_request_has_no_archive: Some(workspace.join(".iteron/runs/.public-artifacts")),
        ..Default::default()
    });
    let mut owner = agent(&workspace, &run, provider.clone());
    owner.set_request_archiving(true).unwrap();
    assert_eq!(owner.run("first request").await.unwrap(), Outcome::Done);
    assert_eq!(
        owner.follow_up("second request").await.unwrap(),
        Outcome::Done
    );
    let record = owner.rollout.path().to_owned();
    owner.flush_request_archive().unwrap();
    drop(owner);
    let events = iteron_record::replay(&record).unwrap();
    let intents = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::EffectIntent { tool, .. } if tool == "provider" => Some(event.seq.0),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(intents.len(), 2);
    let store = DurableArtifactStore::open(
        &workspace.join(".iteron/runs"),
        TenantId::default(),
        run.clone(),
        &workspace,
    )
    .unwrap();
    let thread = SessionId(run.0.clone());
    let catalog = store
        .read(
            &thread,
            ClientArtifactCommandV1::List {
                thread_id: thread.clone(),
            },
        )
        .unwrap();
    let mut prepared = Vec::new();
    for descriptor in catalog["artifacts"].as_array().unwrap() {
        let descriptor: ClientArtifactDescriptorV1 =
            serde_json::from_value(descriptor.clone()).unwrap();
        if descriptor.schema != "iteron.provider-request-manifest.v1" {
            continue;
        }
        let bytes = read(&store, &thread, &descriptor);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(CANARY));
        assert!(!text.contains("private_endpoint_canary"));
        let manifest: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(intents.contains(&manifest["scope"]["source_event_seq"].as_u64().unwrap()));
        if manifest["type"] != "provider_request_prepared_v1" {
            continue;
        }
        assert_eq!(
            manifest["serialized_output_tokens"],
            manifest["scope"]["admitted_output_tokens"]
        );
        let mut served = Vec::new();
        for chunk in manifest["served_body_chunks"].as_array().unwrap() {
            let chunk: ClientArtifactDescriptorV1 = serde_json::from_value(chunk.clone()).unwrap();
            served.extend(read(&store, &thread, &chunk));
        }
        assert!(!std::str::from_utf8(&served).unwrap().contains(CANARY));
        assert_eq!(
            manifest["served_body_sha256"],
            format!("sha256:{:x}", Sha256::digest(&served))
        );
        assert_eq!(
            manifest["served_body_bytes"].as_u64().unwrap(),
            served.len() as u64
        );
        prepared.push(manifest);
    }
    assert_eq!(prepared.len(), 2);
    let actual = provider.requests.lock().unwrap();
    for bytes in &*actual {
        assert!(!std::str::from_utf8(bytes).unwrap().contains(CANARY));
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        assert!(
            prepared
                .iter()
                .any(|manifest| manifest["wire_body_sha256"] == digest
                    && manifest["wire_body_bytes"].as_u64() == Some(bytes.len() as u64))
        );
    }
    assert_ne!(
        prepared[0]["scope"]["effect_id_sha256"],
        prepared[1]["scope"]["effect_id_sha256"]
    );
    drop(actual);
    drop(store);
    let _ = std::fs::remove_dir_all(workspace);
}

#[tokio::test]
async fn actual_manifest_refuses_serialized_output_above_the_physical_admission_before_dispatch() {
    let workspace = std::env::temp_dir().join(format!(
        "iteron-manifest-output-bound-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).unwrap();
    let run = RunId("manifest-output-bound".into());
    let provider = Arc::new(ExactRequest {
        exceeds_admission: true,
        ..Default::default()
    });
    let mut owner = agent(&workspace, &run, provider.clone());
    assert!(matches!(
        owner.run("bounded request").await,
        Err(crate::runtime::KernelError::Provider(
            ProviderError::RequestCaptureRefusedBeforeDispatch
        ))
    ));
    assert!(provider.requests.lock().unwrap().is_empty());
    let record = owner.rollout.path().to_owned();
    owner.flush_request_archive().unwrap();
    drop(owner);
    let events = iteron_record::replay(&record).unwrap();
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::EffectFailed {tool, provider_route_attempt: Some(accounting), ..}
        if tool == "provider" && matches!(accounting.usage, iteron_protocol::ProviderRouteUsageTruth::NotDispatched)
        && matches!(accounting.cost, iteron_protocol::ProviderRouteCostTruth::NotDispatched))));
    let _ = std::fs::remove_dir_all(workspace);
}

#[tokio::test]
async fn memory_used_requires_actual_serialized_inclusion_without_diagnostic_archiving() {
    for (tag, omit_context, exceeds_admission, expected_used) in [
        ("included", false, false, true),
        ("omitted", true, false, false),
        ("capture-refused", false, true, false),
    ] {
        let workspace = gate_integration_tests::temp_ws(tag);
        let run = RunId(format!("memory-manifest-{tag}"));
        let provider = Arc::new(ExactRequest {
            omit_context,
            exceeds_admission,
            ..Default::default()
        });
        let mut owner = agent(&workspace, &run, provider.clone());
        owner.memory_workspace = Some(workspace.clone());
        let store = iteron_ctx::MemoryStore::at(&workspace);
        let id = store
            .add("memory inclusion canary with exact reference bytes")
            .unwrap();
        owner
            .activate_session_memory(&id, "memory inclusion canary with exact reference bytes")
            .unwrap();
        let outcome = owner.run("consult the reference").await;
        if exceeds_admission {
            assert!(matches!(
                outcome,
                Err(crate::runtime::KernelError::Provider(
                    ProviderError::RequestCaptureRefusedBeforeDispatch
                ))
            ));
            assert!(provider.requests.lock().unwrap().is_empty());
        } else {
            assert_eq!(outcome.unwrap(), Outcome::Done);
        }
        assert_eq!(
            owner
                .session_memory_visibility
                .iter()
                .any(|evidence| evidence.state == iteron_ctx::MemoryVisibilityState::Used),
            expected_used
        );
        assert_eq!(owner.observed_trust, iteron_protocol::Trust::Untrusted);
        drop(owner);
        std::fs::remove_dir_all(workspace).unwrap();
    }
}

#[path = "request_manifest_tests/material_journeys.rs"]
mod material_journeys;

#[tokio::test]
async fn compact_request_dispatch_does_not_create_diagnostic_artifacts() {
    let workspace = gate_integration_tests::temp_ws("compact-request-no-archive");
    let run = RunId("compact-request-no-archive".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    assert_eq!(owner.request_archive_status()["enabled"], false);
    assert_eq!(owner.run("compact request").await.unwrap(), Outcome::Done);
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    assert_eq!(
        owner.request_archive_status()["availability"],
        "not_captured"
    );
    let store = DurableArtifactStore::from_rollout_writer(&owner.rollout, &workspace).unwrap();
    let thread = SessionId(run.0.clone());
    let catalog = store
        .read(
            &thread,
            ClientArtifactCommandV1::List {
                thread_id: thread.clone(),
            },
        )
        .unwrap();
    assert!(
        catalog["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|artifact| {
                !matches!(
                    artifact["schema"].as_str(),
                    Some(
                        "iteron.provider-request-manifest.v1"
                            | "iteron.provider-request-body.v1"
                            | "iteron.context-material-archive.v1"
                    )
                )
            }),
        "default dispatch must retain no diagnostic request/body/material artifacts"
    );
    owner.flush_request_archive().unwrap();
    let record = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&record).unwrap();
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::EffectDone { tool, .. } if tool == "provider")));
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn optional_archive_io_failure_does_not_refuse_provider_dispatch_and_is_reported() {
    let workspace = gate_integration_tests::temp_ws("request-archive-io-failure");
    let run = RunId("request-archive-io-failure".into());
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    let reader = owner.request_archive_reader();
    owner.set_request_archiving(true).unwrap();
    assert_eq!(reader()["enabled"], true);
    // The journal remains writable; only the independent diagnostic destination is unavailable.
    std::fs::write(workspace.join(".iteron/runs/.public-artifacts"), "occupied").unwrap();
    assert_eq!(
        owner.run("send despite archive failure").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    assert!(owner.flush_request_archive().is_err());
    let status = reader();
    assert_eq!(status["availability"], "incomplete");
    assert!(status["failed_captures"].as_u64().unwrap() > 0);
    assert_eq!(status["pending_requests"], 0);
    assert_eq!(status["pending_bytes"], 0);
    assert!(owner.set_request_archiving(false).is_err());
    assert_eq!(reader()["enabled"], false);
    drop(owner);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn compact_observer_enforces_prepare_dispatch_order_and_actual_wire_inclusion() {
    use super::{PublicationState, RequestManifestObserver};
    use iteron_provider::request_capture::RequestCaptureError;
    use std::sync::atomic::{AtomicBool, Ordering};

    let observer = || RequestManifestObserver {
        admission: Ok(()),
        admitted_output_tokens: 64,
        diagnostic: None,
        state: Mutex::new(PublicationState::Initial),
        inclusion: Arc::new(AtomicBool::new(false)),
        mailbox: None,
    };
    let request = TurnRequest {
        model: "fixture".into(),
        system: "exact admitted system".into(),
        messages: Vec::new(),
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 64,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        controls: Default::default(),
    };
    let body =
        br#"{"messages":[{"role":"system","content":"exact admitted system"}],"max_tokens":64}"#;
    let wire = || ProviderWireRequest {
        adapter: AdapterKind::OpenAiCompatibleChat,
        method: "POST",
        endpoint: ENDPOINT,
        content_type: "application/json",
        body,
        serialized_output_tokens: 64,
        request: &request,
    };
    let out_of_order = observer();
    assert_eq!(
        out_of_order.dispatching(),
        Err(RequestCaptureError::ReconciliationNeeded)
    );
    assert!(out_of_order.prepared(wire()).is_err());
    assert!(!out_of_order.inclusion.load(Ordering::Acquire));

    let valid = observer();
    valid.prepared(wire()).unwrap();
    assert!(valid.inclusion.load(Ordering::Acquire));
    valid.dispatching().unwrap();
    assert!(valid.dispatching().is_err());
    assert!(valid.prepared(wire()).is_err());

    let unavailable = observer();
    unavailable
        .unavailable("adapter_wire_capture_unavailable")
        .unwrap();
    assert!(!unavailable.inclusion.load(Ordering::Acquire));
    assert!(unavailable.dispatching().is_err());
}

#[tokio::test]
async fn failed_invocations_drain_prepared_diagnostics_while_the_agent_remains_resident() {
    for (tag, leaf, blocked_archive) in [("operator", false, false), ("leaf", true, true)] {
        let workspace = gate_integration_tests::temp_ws(&format!("failed-archive-{tag}"));
        let run = RunId(format!("failed-archive-{tag}"));
        let provider = Arc::new(ExactRequest {
            fail_after_preparation: true,
            ..Default::default()
        });
        let mut owner = agent(&workspace, &run, provider.clone());
        owner.set_request_archiving(true).unwrap();
        if blocked_archive {
            std::fs::write(workspace.join(".iteron/runs/.public-artifacts"), "occupied").unwrap();
        }
        let outcome = if leaf {
            owner.run_leaf("prepare then refuse dispatch").await
        } else {
            owner.run("prepare then refuse dispatch").await
        };
        assert!(matches!(
            outcome,
            Err(crate::runtime::KernelError::Provider(
                ProviderError::RequestCaptureRefusedBeforeDispatch
            ))
        ));
        assert_eq!(provider.requests.lock().unwrap().len(), 1);
        let status = owner.request_archive_status();
        assert_eq!(status["enabled"], true);
        assert_eq!(status["submitted_requests"], 1);
        assert_eq!(status["pending_requests"], 0);
        assert_eq!(status["pending_bytes"], 0);
        if blocked_archive {
            assert_eq!(status["availability"], "incomplete");
            assert_eq!(status["completed_requests"], 0);
            assert!(status["failed_captures"].as_u64().unwrap() > 0);
        } else {
            assert_eq!(status["availability"], "drained");
            assert_eq!(status["completed_requests"], 1);
            assert_eq!(status["failed_captures"], 0);
            let store =
                DurableArtifactStore::from_rollout_writer(&owner.rollout, &workspace).unwrap();
            let thread = SessionId(run.0.clone());
            let list = store
                .read(
                    &thread,
                    ClientArtifactCommandV1::List {
                        thread_id: thread.clone(),
                    },
                )
                .unwrap();
            let manifests: Vec<Value> = list["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| {
                    let descriptor: ClientArtifactDescriptorV1 =
                        serde_json::from_value(item.clone()).unwrap();
                    (descriptor.schema == "iteron.provider-request-manifest.v1").then(|| {
                        serde_json::from_slice(&read(&store, &thread, &descriptor)).unwrap()
                    })
                })
                .collect();
            assert_eq!(manifests.len(), 1);
            assert_eq!(manifests[0]["type"], "provider_request_prepared_v1");
        }
        drop(owner);
        std::fs::remove_dir_all(workspace).unwrap();
    }
}

#[tokio::test]
async fn enabled_archive_tracks_adopted_run_without_cross_catalog_publication() {
    let workspace = gate_integration_tests::temp_ws("request-archive-adopt");
    // Adoption restores the recorded checkpoint policy, including its real Git workspace.
    assert!(
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&workspace)
            .status()
            .expect("git must be available for checkpoint integration")
            .success()
    );
    let before = RunId("request-archive-before".into());
    let after = RunId("request-archive-after".into());
    let provider = Arc::new(ExactRequest::default());
    drop(agent(&workspace, &after, provider.clone()));
    let mut owner = agent(&workspace, &before, provider.clone());
    // The shared genesis helper persists the schema sampler's verification families while
    // this request-only fixture runs with Agent::new's actual verification controls. Preserve
    // those exact controls across adoption so both requests exercise the same fixture.
    let fixture_verify_command = owner.verify_command.clone();
    let fixture_verification_policy = owner.verification_state.policy().clone();
    assert!(fixture_verify_command.is_none());
    owner.set_request_archiving(true).unwrap();
    assert_eq!(
        owner.run("before adopting another run").await.unwrap(),
        Outcome::Done
    );
    let adopted =
        Rollout::open_existing(&workspace.join(".iteron/runs"), &after, TenantId::default())
            .unwrap();
    owner.adopt_run(adopted).unwrap();
    owner.verify_command = fixture_verify_command;
    owner
        .set_verification_policy(fixture_verification_policy)
        .unwrap();
    // Session adoption restores recorded route identity; the host must rebind the live
    // provider to the adopted governor before allowing its next request.
    owner
        .record_adopted_model_selection(
            provider.clone(),
            "manifest-fixture".into(),
            "fixture-model".into(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
    assert_eq!(
        owner.follow_up("after adopting another run").await.unwrap(),
        Outcome::Done
    );
    owner.flush_request_archive().unwrap();
    drop(owner);
    let actual = provider.requests.lock().unwrap();
    assert_eq!(actual.len(), 2);
    for (run, expected) in [(&before, &actual[0]), (&after, &actual[1])] {
        let store = DurableArtifactStore::open(
            &workspace.join(".iteron/runs"),
            TenantId::default(),
            run.clone(),
            &workspace,
        )
        .unwrap();
        let thread = SessionId(run.0.clone());
        let list = store
            .read(
                &thread,
                ClientArtifactCommandV1::List {
                    thread_id: thread.clone(),
                },
            )
            .unwrap();
        let prepared: Vec<Value> = list["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| {
                let descriptor: ClientArtifactDescriptorV1 =
                    serde_json::from_value(item.clone()).unwrap();
                if descriptor.schema != "iteron.provider-request-manifest.v1" {
                    return None;
                }
                let manifest: Value =
                    serde_json::from_slice(&read(&store, &thread, &descriptor)).unwrap();
                (manifest["type"] == "provider_request_prepared_v1").then_some(manifest)
            })
            .collect();
        assert_eq!(prepared.len(), 1, "each run owns exactly its own request");
        assert_eq!(
            prepared[0]["wire_body_sha256"],
            format!("sha256:{:x}", Sha256::digest(expected))
        );
    }
    drop(actual);
    std::fs::remove_dir_all(workspace).unwrap();
}

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
}
#[async_trait::async_trait]
impl Provider for ExactRequest {
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
        let bytes=serde_json::to_vec(&serde_json::json!({"model":request.model,"system":request.system,"messages":request.messages})).unwrap();
        observer
            .prepared(ProviderWireRequest {
                adapter: AdapterKind::OpenAiCompatibleChat,
                method: "POST",
                endpoint: ENDPOINT,
                content_type: "application/json",
                body: &bytes,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
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
    let rollout = Rollout::open(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        Registry::read_only(workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        format!("effective system\napi_key={CANARY}"),
        Budget::default(),
    );
    agent.workspace = workspace.to_owned();
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
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
    let provider = Arc::new(ExactRequest::default());
    let mut owner = agent(&workspace, &run, provider.clone());
    assert_eq!(owner.run("first request").await.unwrap(), Outcome::Done);
    assert_eq!(owner.run("second request").await.unwrap(), Outcome::Done);
    let record = owner.rollout.path().to_owned();
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

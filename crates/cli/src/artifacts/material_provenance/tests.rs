use super::*;
use base64::Engine;
use iteron_protocol::client_artifact::ClientArtifactCommandV1;
use iteron_protocol::{Effort, Event, EventKind, RunId, Seq, SessionId, TenantId, TurnId};
use iteron_provider::TurnRequest;

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-material-retention-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let mut rollout = iteron_record::Rollout::open(
            &root.join("runs"),
            &RunId("material-owner".into()),
            TenantId::default(),
        )
        .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: root.join("workspace").to_string_lossy().into_owned(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: iteron_protocol::Message::user_text("actual retained-source fixture"),
                },
            })
            .unwrap();
        Self(root)
    }
    fn store(&self) -> DurableArtifactStore {
        DurableArtifactStore::open(
            &self.0.join("runs"),
            TenantId::default(),
            RunId("material-owner".into()),
            &self.0.join("workspace"),
        )
        .unwrap()
    }
    fn download(&self, descriptor: &ClientArtifactDescriptorV1) -> Vec<u8> {
        let store = self.store();
        let thread = SessionId("material-owner".into());
        let mut out = Vec::new();
        let mut offset = 0;
        for _ in 0..1024 {
            let chunk = store
                .read(
                    &thread,
                    ClientArtifactCommandV1::Read {
                        thread_id: thread.clone(),
                        artifact_id: descriptor.artifact_id.clone(),
                        offset,
                        max_bytes: 65536,
                    },
                )
                .unwrap();
            out.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(chunk["content_base64"].as_str().unwrap())
                    .unwrap(),
            );
            if chunk["eof"] == true {
                return out;
            }
            offset = chunk["next_offset"].as_u64().unwrap();
        }
        panic!("bounded artifact reconstruction exceeded");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn request(system: String) -> TurnRequest {
    TurnRequest {
        model: "fixture".into(),
        system,
        messages: vec![iteron_protocol::Message::user_text("use current reference")],
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 16,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        controls: Default::default(),
    }
}
fn wire<'a>(request: &'a TurnRequest, bytes: &'a [u8]) -> ProviderWireRequest<'a> {
    ProviderWireRequest {
        adapter: AdapterKind::OpenAiCompatibleChat,
        method: "POST",
        endpoint: "https://fixture.invalid/request",
        content_type: "application/json",
        body: bytes,
        serialized_output_tokens: 16,
        request,
    }
}

#[test]
fn actual_source_capture_and_retained_offset_reconstruct_after_owner_restart_and_file_deletion() {
    let fixture = Fixture::new();
    let workspace = fixture.0.join("workspace");
    let original = "actual historical guidance body";
    std::fs::write(workspace.join("AGENTS.md"), original).unwrap();
    let bundle = iteron_ctx::discover_hierarchy_with_policy(
        None,
        &workspace,
        &workspace,
        iteron_ctx::InstructionDiscoveryPolicy::owner(),
    );
    let (rendered, materials, _) =
        bundle.render_with_provenance(iteron_ctx::InstructionDiscoveryPolicy::owner());
    let request = request(rendered);
    let bytes = serde_json::to_vec(
        &serde_json::json!({"messages":[{"role":"system","content":request.system}]}),
    )
    .unwrap();
    let publication = fixture
        .store()
        .publish_material_provenance(2, &materials, &wire(&request, &bytes))
        .unwrap();
    std::fs::remove_file(workspace.join("AGENTS.md")).unwrap();
    let descriptor = publication.archive.unwrap();
    let retained = fixture.download(&descriptor);
    let resolution = &publication.resolutions[0];
    let MaterialRetainedResolutionV1::Retained { locator } = &resolution.source else {
        panic!("actual complete source must be retained")
    };
    let slice = &retained[locator.offset as usize..(locator.offset + locator.bytes) as usize];
    assert_eq!(slice, original.as_bytes());
    assert_eq!(digest(slice), locator.sha256);
    assert!(matches!(
        locator.representation,
        MaterialRetainedRepresentationV1::ExactCapturedBytes
    ));
    assert!(matches!(
        resolution.prepared_request_inclusion,
        MaterialPreparedInclusionV1::CapturedRendering { .. }
    ));
}

#[test]
fn actual_secret_scrub_retains_only_a_derivative_and_missing_native_text_is_unconfirmed() {
    let fixture = Fixture::new();
    let workspace = fixture.0.join("workspace");
    let original = "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    std::fs::write(workspace.join("AGENTS.md"), original).unwrap();
    let bundle = iteron_ctx::discover_hierarchy_with_policy(
        None,
        &workspace,
        &workspace,
        iteron_ctx::InstructionDiscoveryPolicy::owner(),
    );
    let (rendered, materials, _) =
        bundle.render_with_provenance(iteron_ctx::InstructionDiscoveryPolicy::owner());
    let request = request(iteron_record::redact::scrub(&rendered));
    let absent = serde_json::to_vec(
        &serde_json::json!({"messages":[{"role":"system","content":"different system"}]}),
    )
    .unwrap();
    let publication = fixture
        .store()
        .publish_material_provenance(2, &materials, &wire(&request, &absent))
        .unwrap();
    let retained = fixture.download(&publication.archive.unwrap());
    assert!(!std::str::from_utf8(&retained).unwrap().contains(original));
    let resolution = &publication.resolutions[0];
    let MaterialRetainedResolutionV1::Retained { locator } = &resolution.source else {
        panic!("source derivative must be retained")
    };
    assert!(matches!(
        locator.representation,
        MaterialRetainedRepresentationV1::ScrubbedDerivative
    ));
    assert!(matches!(
        resolution.prepared_request_inclusion,
        MaterialPreparedInclusionV1::Unconfirmed { .. }
    ));
    let present = serde_json::to_vec(
        &serde_json::json!({"messages":[{"role":"system","content":request.system}]}),
    )
    .unwrap();
    let fields = PreparedContextFields::capture(&wire(&request, &present));
    assert!(matches!(
        fields.inclusion(&materials[0]),
        MaterialPreparedInclusionV1::ScrubbedRendering { .. }
    ));
}

#[test]
fn actual_frozen_source_without_original_owner_has_explicit_unavailability() {
    let fixture = Fixture::new();
    let request = request("frozen recorded memory reference".into());
    let material =
        CapturedContextMaterial::historical(&request.system, iteron_protocol::Trust::Untrusted);
    let bytes = serde_json::to_vec(
        &serde_json::json!({"messages":[{"role":"system","content":request.system}]}),
    )
    .unwrap();
    let publication = fixture
        .store()
        .publish_material_provenance(2, &[material], &wire(&request, &bytes))
        .unwrap();
    assert!(matches!(
        publication.resolutions[0].source,
        MaterialRetainedResolutionV1::Unavailable {
            reason: MaterialRetentionUnavailableV1::SourceUnavailable {
                reason: ContextMaterialUnavailableV1::HistoricalSourceNotRetained
            }
        }
    ));
}

#[test]
fn archive_hard_bound_and_dedup_do_not_fabricate_locator_or_source_receipt() {
    let mut archive = MaterialArchive::new();
    let text = "bounded repeated field";
    let expected = digest(text.as_bytes());
    let first = archive.retain(text, &expected);
    let bytes = archive.text.len();
    let second = archive.retain(text, &expected);
    assert_eq!(archive.text.len(), bytes);
    assert!(matches!(first, PendingResolution::Retained { .. }));
    assert!(matches!(second, PendingResolution::Retained { .. }));
    assert!(matches!(
        archive.retain("changed text", &expected),
        PendingResolution::Unavailable(MaterialRetentionUnavailableV1::CaptureCommitmentMismatch)
    ));
    let oversized = "x".repeat(MAX_ARCHIVE_BYTES);
    assert!(matches!(
        archive.retain(&oversized, &digest(oversized.as_bytes())),
        PendingResolution::Unavailable(MaterialRetentionUnavailableV1::RetentionBound)
    ));
    // A retained offset cannot become a public locator before an actual durable publication.
    assert!(archive.retain(text, &expected).resolve(None).is_err());
}

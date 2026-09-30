use super::*;
use iteron_protocol::{Effort, Event, EventKind, TurnId};

#[path = "structural_tests.rs"]
mod structural_tests;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-public-artifacts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        let mut rollout = iteron_record::Rollout::open(
            &root.join("runs"),
            &RunId("owner".into()),
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
        Self(root)
    }

    fn store(&self) -> DurableArtifactStore {
        DurableArtifactStore::open(
            &self.0.join("runs"),
            TenantId::default(),
            RunId("owner".into()),
            &self.0.join("workspace"),
        )
        .unwrap()
    }

    fn thread(&self) -> SessionId {
        SessionId("authenticated-thread".into())
    }

    fn read(&self, store: &DurableArtifactStore, id: &str, offset: u64, max_bytes: u32) -> Value {
        store
            .read(
                &self.thread(),
                ClientArtifactCommandV1::Read {
                    thread_id: self.thread(),
                    artifact_id: id.into(),
                    offset,
                    max_bytes,
                },
            )
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn complete_scrubbed_bytes_are_downloadable_after_owner_restart_with_exact_identity() {
    let fixture = Fixture::new();
    let full = format!(
        "{}\napi_key=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\nlast bytes",
        "α".repeat(200_000)
    );
    let served = iteron_record::redact::scrub(&full);
    let descriptor = fixture
        .store()
        .publish_text(37, ArtifactTextSchema::ToolOutput, &full, &[])
        .unwrap();
    assert_eq!(descriptor.bytes, served.len() as u64);
    assert!(descriptor.complete);
    assert_eq!(
        descriptor.artifact_id,
        hex::encode(Sha256::digest(served.as_bytes()))
    );
    assert_ne!(
        descriptor.artifact_id,
        hex::encode(Sha256::digest(full.as_bytes()))
    );
    let reopened = fixture.store();
    let mut downloaded = Vec::new();
    let mut offset = 0;
    loop {
        let chunk = fixture.read(&reopened, &descriptor.artifact_id, offset, 65_536);
        downloaded.extend(
            base64::engine::general_purpose::STANDARD
                .decode(chunk["content_base64"].as_str().unwrap())
                .unwrap(),
        );
        offset = chunk["next_offset"].as_u64().unwrap();
        if chunk["eof"] == true {
            break;
        }
    }
    assert_eq!(downloaded, served.as_bytes());
    assert!(
        !String::from_utf8(downloaded)
            .unwrap()
            .contains("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789")
    );
    assert_eq!(
        fixture.read(&reopened, &descriptor.artifact_id, descriptor.bytes, 1)["eof"],
        true
    );
}

#[test]
fn scope_locators_offsets_and_forged_sources_fail_closed() {
    let fixture = Fixture::new();
    assert!(
        DurableArtifactStore::open(
            &fixture.0.join("runs"),
            TenantId("foreign".into()),
            RunId("owner".into()),
            &fixture.0.join("workspace")
        )
        .is_err()
    );
    assert!(
        DurableArtifactStore::open(
            &fixture.0.join("runs"),
            TenantId::default(),
            RunId("owner".into()),
            &fixture.0.join("other")
        )
        .is_err()
    );
    assert!(
        DurableArtifactStore::open(
            &fixture.0.join("runs"),
            TenantId::default(),
            RunId("../owner".into()),
            &fixture.0.join("workspace")
        )
        .is_err()
    );
    let store = fixture.store();
    let descriptor = store
        .publish_text(1, ArtifactTextSchema::ToolOutput, "safe", &[])
        .unwrap();
    for (thread, id, offset, max_bytes) in [
        (
            SessionId("foreign".into()),
            descriptor.artifact_id.clone(),
            0,
            4,
        ),
        (fixture.thread(), "../../secret".into(), 0, 4),
        (fixture.thread(), descriptor.artifact_id.clone(), 5, 4),
        (fixture.thread(), descriptor.artifact_id.clone(), 0, 65_537),
    ] {
        assert!(
            store
                .read(
                    &fixture.thread(),
                    ClientArtifactCommandV1::Read {
                        thread_id: thread,
                        artifact_id: id,
                        offset,
                        max_bytes
                    }
                )
                .is_err()
        );
    }
    let source = PrivateContentSource {
        owner: RunId("owner".into()),
        digest: iteron_protocol::ErasureContentDigest::new(format!("sha256:{}", "a".repeat(64)))
            .unwrap(),
    };
    assert!(
        store
            .publish_text(2, ArtifactTextSchema::ToolOutput, "derived", &[source])
            .is_err()
    );
    assert!(
        store
            .publish_text(
                3,
                ArtifactTextSchema::ToolOutput,
                &"x".repeat(MAX_PRIVATE_CONTENT_BYTES + 1),
                &[]
            )
            .is_err()
    );
}

#[test]
fn incomplete_publication_and_release_intents_recover_without_republishing_stale_handles() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let discarded = store
        .publish_text(
            1,
            ArtifactTextSchema::ToolOutput,
            "interrupted publication",
            &[],
        )
        .unwrap();
    {
        let file = storage::ManifestFile::acquire(&store, false)
            .unwrap()
            .unwrap();
        let mut manifest = file.read().unwrap().unwrap();
        manifest.pending = Some(manifest.entries.pop().unwrap().content);
        file.write(&manifest).unwrap();
    }
    assert!(
        store
            .read(
                &fixture.thread(),
                ClientArtifactCommandV1::Read {
                    thread_id: fixture.thread(),
                    artifact_id: discarded.artifact_id.clone(),
                    offset: 0,
                    max_bytes: 1
                }
            )
            .is_err()
    );
    let fresh = fixture
        .store()
        .publish_text(2, ArtifactTextSchema::ToolOutput, "new publication", &[])
        .unwrap();
    {
        let file = storage::ManifestFile::acquire(&store, false)
            .unwrap()
            .unwrap();
        let mut manifest = file.read().unwrap().unwrap();
        assert!(manifest.pending.is_none());
        assert!(manifest.releasing.is_empty());
        manifest
            .releasing
            .push(manifest.entries.pop().unwrap().content);
        file.write(&manifest).unwrap();
    }
    store
        .publish_text(3, ArtifactTextSchema::ToolOutput, "after release", &[])
        .unwrap();
    for id in [discarded.artifact_id, fresh.artifact_id] {
        assert!(
            store
                .read(
                    &fixture.thread(),
                    ClientArtifactCommandV1::Read {
                        thread_id: fixture.thread(),
                        artifact_id: id,
                        offset: 0,
                        max_bytes: 1
                    }
                )
                .is_err()
        );
    }
}

fn erase(
    fixture: &Fixture,
    target: iteron_protocol::ErasureTarget,
    operation: &str,
) -> iteron_protocol::ErasureReceipt {
    let runs = fixture.0.join("runs");
    let authority = iteron_record::erasure::authorize_local_erasure(&runs).unwrap();
    iteron_record::erasure::execute_erasure(
        &runs,
        iteron_protocol::ErasureRequest {
            operation_id: iteron_protocol::ErasureOperationId::new(operation).unwrap(),
            authority_id: authority.id().clone(),
            requested_at_unix_ms: 1,
            target,
        },
    )
    .unwrap()
}

#[test]
fn real_source_revocation_reaches_scrubbed_public_derivative() {
    let fixture = Fixture::new();
    let private = PrivateContentDerivativeStore::open_registered(
        fixture.0.join("runs"),
        TenantId::default(),
        RunId("owner".into()),
        PrivateContentNamespace::ToolArtifact,
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        MAX_PRIVATE_CONTENT_BYTES,
    )
    .unwrap();
    let raw = "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\nowned result";
    let source = private.put(Seq(1_u64 << 63), raw.as_bytes()).unwrap();
    let store = fixture.store();
    let artifact = store
        .publish_text(
            8,
            ArtifactTextSchema::ToolOutput,
            raw,
            &[PrivateContentSource {
                owner: RunId("owner".into()),
                digest: source.digest.clone(),
            }],
        )
        .unwrap();
    assert!(fixture.read(&store, &artifact.artifact_id, 0, 1)["content_base64"].is_string());
    drop(private);
    let receipt = erase(
        &fixture,
        iteron_protocol::ErasureTarget::ContentRevocation {
            scope_id: iteron_protocol::ErasureScopeId::new(TenantId::default().0).unwrap(),
            content_digest: source.digest,
        },
        "public-source-revoke",
    );
    assert_eq!(receipt.state(), iteron_protocol::ErasureState::Verified);
    assert!(
        fixture
            .store()
            .read(
                &fixture.thread(),
                ClientArtifactCommandV1::Read {
                    thread_id: fixture.thread(),
                    artifact_id: artifact.artifact_id,
                    offset: 0,
                    max_bytes: 1,
                }
            )
            .is_err()
    );
}

#[test]
fn verified_session_erasure_removes_exact_public_catalog_and_revokes_restart_downloads() {
    let fixture = Fixture::new();
    fixture
        .store()
        .publish_text(1, ArtifactTextSchema::FinalAnswer, "owned answer", &[])
        .unwrap();
    let receipt = erase(
        &fixture,
        iteron_protocol::ErasureTarget::ExactSession {
            scope_id: iteron_protocol::ErasureScopeId::new(TenantId::default().0).unwrap(),
            run_id: iteron_protocol::ErasureTargetId::new("owner").unwrap(),
        },
        "public-owner-delete",
    );
    assert_eq!(receipt.state(), iteron_protocol::ErasureState::Verified);
    remove_erased_catalog(&fixture.0.join("runs"), &receipt).unwrap();
    assert_eq!(
        std::fs::read_dir(fixture.0.join("runs/.public-artifacts"))
            .unwrap()
            .count(),
        0
    );
    assert!(
        DurableArtifactStore::open(
            &fixture.0.join("runs"),
            TenantId::default(),
            RunId("owner".into()),
            &fixture.0.join("workspace")
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn symlink_namespace_and_manifest_cannot_redirect_public_artifact_storage() {
    let fixture = Fixture::new();
    let store = fixture.store();
    std::os::unix::fs::symlink(
        fixture.0.join("other"),
        fixture.0.join("runs/.public-artifacts"),
    )
    .unwrap();
    assert!(
        store
            .publish_text(1, ArtifactTextSchema::ToolOutput, "safe", &[])
            .is_err()
    );
    std::fs::remove_file(fixture.0.join("runs/.public-artifacts")).unwrap();
    store
        .publish_text(1, ArtifactTextSchema::ToolOutput, "safe", &[])
        .unwrap();
    let file = storage::ManifestFile::acquire(&store, false)
        .unwrap()
        .unwrap();
    // Locate only the owner-minted file inside this test fixture, never through a client locator.
    let root = fixture.0.join("runs/.public-artifacts");
    let owner = std::fs::read_dir(root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    drop(file);
    std::fs::remove_file(owner.join("manifest.json")).unwrap();
    std::fs::write(fixture.0.join("other/secret"), "secret").unwrap();
    std::os::unix::fs::symlink(fixture.0.join("other/secret"), owner.join("manifest.json"))
        .unwrap();
    assert!(
        store
            .read(
                &fixture.thread(),
                ClientArtifactCommandV1::List {
                    thread_id: fixture.thread()
                }
            )
            .is_err()
    );
}

#[test]
fn identical_bytes_keep_first_schema_source_and_retained_identity() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let first = store
        .publish_text(7, ArtifactTextSchema::ToolOutput, "same served bytes", &[])
        .unwrap();
    let later = store
        .publish_text(
            91,
            ArtifactTextSchema::FinalAnswer,
            "same served bytes",
            &[],
        )
        .unwrap();
    assert_eq!(later, first);
    assert_eq!(later.schema, "iteron.tool-output.v1");
    assert_eq!(later.source_event_seq, 7);
    let reopened = fixture.store();
    let listing = reopened
        .read(
            &fixture.thread(),
            ClientArtifactCommandV1::List {
                thread_id: fixture.thread(),
            },
        )
        .unwrap();
    assert_eq!(listing["artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(listing["artifacts"][0]["source_event_seq"], 7);
    assert!(
        store
            .publish_text(0, ArtifactTextSchema::ToolOutput, "unknown origin", &[])
            .is_err()
    );

    let file = storage::ManifestFile::acquire(&store, true)
        .unwrap()
        .unwrap();
    let mut manifest = file.read().unwrap().unwrap();
    let duplicate = Entry {
        descriptor: first,
        content: manifest.entries[0].content.clone(),
        dependencies: vec![],
    };
    manifest.entries.push(duplicate);
    file.write(&manifest).unwrap();
    drop(file);
    assert!(
        reopened
            .read(
                &fixture.thread(),
                ClientArtifactCommandV1::List {
                    thread_id: fixture.thread(),
                }
            )
            .is_err(),
        "conflicting duplicate references cannot redefine first origin"
    );
}

//! Real native receipts, retained structural references and quota dependency closure.

use super::{Fixture, erase};
use crate::artifacts::{ArtifactSchema, DurableArtifactStore, MAX_ARTIFACTS, storage};
use base64::Engine;
use iteron_protocol::ToolUse;
use iteron_protocol::client_artifact::{ClientArtifactCommandV1, ClientArtifactDescriptorV1};
use iteron_tools::{NativeMutationReceipt, Registry, ToolExecution};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

async fn commit(
    fixture: &Fixture,
    path: &str,
    before: Option<&[u8]>,
    after: &str,
    id: &str,
) -> NativeMutationReceipt {
    let workspace = fixture.0.join("workspace");
    if let Some(before) = before {
        std::fs::write(workspace.join(path), before).unwrap();
    }
    let mut registry = Registry::isolated_writer(&workspace).unwrap();
    // Real ordinary executor and commit guard. Process confinement is covered by the physical
    // CLI journey; this unit fixture must not self-execute the libtest binary as a helper.
    registry.set_confine_execution(false);
    let captured = registry
        .run_effect_captured(ToolUse {
            id: id.into(),
            name: "write_file".into(),
            input: json!({"path":path,"content":after}),
        })
        .await;
    assert!(
        matches!(&captured.execution, ToolExecution::Definite(result) if !result.is_error),
        "{captured:?}"
    );
    assert!(captured.capture_error.is_none());
    assert_eq!(
        std::fs::read(workspace.join(path)).unwrap(),
        after.as_bytes()
    );
    captured
        .native_mutation
        .expect("actual committed native proof")
}

fn list(fixture: &Fixture, store: &DurableArtifactStore) -> Value {
    store
        .read(
            &fixture.thread(),
            ClientArtifactCommandV1::List {
                thread_id: fixture.thread(),
            },
        )
        .unwrap()
}

fn download(
    fixture: &Fixture,
    store: &DurableArtifactStore,
    descriptor: &ClientArtifactDescriptorV1,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offset = 0;
    for _ in 0..130 {
        let chunk = fixture.read(store, &descriptor.artifact_id, offset, 65536);
        assert_eq!(chunk["type"], "artifact_chunk_v1");
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(chunk["content_base64"].as_str().unwrap())
                .unwrap(),
        );
        offset = chunk["next_offset"].as_u64().unwrap();
        if chunk["eof"] == true {
            assert_eq!(bytes.len() as u64, descriptor.bytes);
            assert_eq!(hex::encode(Sha256::digest(&bytes)), descriptor.artifact_id);
            return bytes;
        }
    }
    panic!("bounded retained download did not finish");
}

fn parsed(
    fixture: &Fixture,
    store: &DurableArtifactStore,
    descriptor: &ClientArtifactDescriptorV1,
) -> Value {
    serde_json::from_slice(&download(fixture, store, descriptor)).unwrap()
}

#[tokio::test]
async fn actual_sealed_native_receipt_preserves_structural_hashes_and_scrubs_only_display_data() {
    let fixture = Fixture::new();
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let path = format!("{secret}.txt");
    let before = format!("whole before\napi_key={secret}\noriginal tail\n");
    let after = format!("whole after\napi_key={secret}\ncommitted tail\n");
    let receipt = commit(&fixture, &path, Some(before.as_bytes()), &after, secret).await;
    let store = fixture.store();
    let descriptor = store.publish_native_diff(71, &receipt).unwrap();
    let reopened = fixture.store();
    let served = download(&fixture, &reopened, &descriptor);
    assert!(!String::from_utf8_lossy(&served).contains(secret));
    let manifest: Value = serde_json::from_slice(&served).unwrap();
    assert_eq!(manifest["basis"], "guarded_native_commit");
    assert_eq!(
        manifest["tool_use_id_display"],
        iteron_record::redact::scrub(secret)
    );
    assert!(
        manifest.get("tool_use_id").is_none(),
        "scrubbed display cannot impersonate exact provider correlation"
    );
    assert_eq!(
        manifest["files"][0]["path"],
        iteron_record::redact::scrub(&path)
    );
    for (field, raw) in [("before", before), ("after", after)] {
        let reference: ClientArtifactDescriptorV1 =
            serde_json::from_value(manifest["files"][0][field].clone()).unwrap();
        assert_eq!(reference.artifact_id.len(), 64);
        assert!(
            reference
                .artifact_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        let bytes = download(&fixture, &reopened, &reference);
        assert_eq!(bytes, iteron_record::redact::scrub(&raw).as_bytes());
        assert!(!String::from_utf8_lossy(&bytes).contains(secret));
    }
    let public = list(&fixture, &reopened);
    assert_eq!(public["artifacts"].as_array().unwrap().len(), 3);
    assert_eq!(descriptor.source_event_seq, 71);
}

#[tokio::test]
async fn arbitrary_json_and_forged_descriptor_do_not_enter_the_structural_exemption() {
    let fixture = Fixture::new();
    let receipt = commit(
        &fixture,
        "real.txt",
        None,
        "actual source bytes\n",
        "actual-call",
    )
    .await;
    let store = fixture.store();
    let native = store.publish_native_diff(1, &receipt).unwrap();
    let manifest = parsed(&fixture, &store, &native);
    let real: ClientArtifactDescriptorV1 =
        serde_json::from_value(manifest["files"][0]["after"].clone()).unwrap();
    let untrusted_json = json!({"after":real,"basis":"guarded_native_commit", "api_key":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}).to_string();
    let generic = store
        .publish_text(2, ArtifactSchema::ToolOutput, &untrusted_json, &[])
        .unwrap();
    let scrubbed = download(&fixture, &store, &generic);
    assert_eq!(
        scrubbed,
        iteron_record::redact::scrub(&untrusted_json).as_bytes()
    );
    assert!(!String::from_utf8_lossy(&scrubbed).contains(&real.artifact_id));
    let entries_before = list(&fixture, &store)["artifacts"]
        .as_array()
        .unwrap()
        .len();
    let mut forged = real.clone();
    forged.source_event_seq += 1;
    assert!(
        store
            .publish_served(
                3,
                ArtifactSchema::FileDiff,
                "a forged structural manifest",
                &[],
                &[forged]
            )
            .is_err()
    );
    assert_eq!(
        list(&fixture, &store)["artifacts"]
            .as_array()
            .unwrap()
            .len(),
        entries_before
    );
    assert_eq!(download(&fixture, &store, &real), b"actual source bytes\n");
}

#[tokio::test]
async fn receipt_from_another_canonical_workspace_is_rejected_before_retention() {
    let fixture = Fixture::new();
    let outside = fixture.0.join("other");
    let mut registry = Registry::isolated_writer(&outside).unwrap();
    registry.set_confine_execution(false);
    let captured = registry
        .run_effect_captured(ToolUse {
            id: "foreign".into(),
            name: "write_file".into(),
            input: json!({"path":"foreign.txt","content":"outside owner proof\n"}),
        })
        .await;
    assert!(matches!(&captured.execution, ToolExecution::Definite(result) if !result.is_error));
    let store = fixture.store();
    assert!(
        store
            .publish_native_diff(1, captured.native_mutation.as_ref().unwrap())
            .is_err()
    );
    assert!(
        list(&fixture, &store)["artifacts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read(outside.join("foreign.txt")).unwrap(),
        b"outside owner proof\n"
    );
}

#[tokio::test]
async fn binary_before_is_explicitly_unavailable_without_a_false_success_manifest() {
    let fixture = Fixture::new();
    let receipt = commit(
        &fixture,
        "binary.txt",
        Some(&[0xff, 0x00, 0x81]),
        "new valid text\n",
        "binary-write",
    )
    .await;
    let store = fixture.store();
    assert!(store.publish_native_diff(1, &receipt).is_err());
    assert!(
        list(&fixture, &store)["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["schema"] != "iteron.file-diff.v1")
    );
    assert_eq!(
        std::fs::read(fixture.0.join("workspace/binary.txt")).unwrap(),
        b"new valid text\n"
    );
}

#[tokio::test]
async fn quota_eviction_removes_every_manifest_that_depends_on_the_same_snapshot() {
    let fixture = Fixture::new();
    let a = commit(
        &fixture,
        "a.txt",
        Some(b"shared whole before\n"),
        "after a\n",
        "call-a",
    )
    .await;
    let b = commit(
        &fixture,
        "b.txt",
        Some(b"shared whole before\n"),
        "after b\n",
        "call-b",
    )
    .await;
    let store = fixture.store();
    let diff_a = store.publish_native_diff(11, &a).unwrap();
    let diff_b = store.publish_native_diff(12, &b).unwrap();
    let manifest_a = parsed(&fixture, &store, &diff_a);
    let manifest_b = parsed(&fixture, &store, &diff_b);
    let source_a: ClientArtifactDescriptorV1 =
        serde_json::from_value(manifest_a["files"][0]["before"].clone()).unwrap();
    let source_b: ClientArtifactDescriptorV1 =
        serde_json::from_value(manifest_b["files"][0]["before"].clone()).unwrap();
    assert_eq!(
        source_a, source_b,
        "served byte deduplication preserves first origin"
    );
    assert_eq!(source_b.source_event_seq, 11);
    let current_count = list(&fixture, &store)["artifacts"]
        .as_array()
        .unwrap()
        .len();
    for index in 0..=MAX_ARTIFACTS - current_count {
        store
            .publish_text(
                100 + index as u64,
                ArtifactSchema::ToolOutput,
                &format!("independent bounded quota item {index}\n"),
                &[],
            )
            .unwrap();
    }
    let reopened = fixture.store();
    let listing = list(&fixture, &reopened);
    assert!(listing["evicted_artifacts"].as_u64().unwrap() >= 3);
    for removed in [&source_a, &diff_a, &diff_b] {
        assert!(
            listing["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["artifact_id"] != removed.artifact_id)
        );
        assert!(
            reopened
                .read(
                    &fixture.thread(),
                    ClientArtifactCommandV1::Read {
                        thread_id: fixture.thread(),
                        artifact_id: removed.artifact_id.clone(),
                        offset: 0,
                        max_bytes: 1,
                    }
                )
                .is_err()
        );
    }
    assert!(
        store
            .publish_served(
                999,
                ArtifactSchema::FileDiff,
                "cannot restore a missing reference",
                &[],
                &[source_a]
            )
            .is_err()
    );
    for manifest in [manifest_a, manifest_b] {
        let after: ClientArtifactDescriptorV1 =
            serde_json::from_value(manifest["files"][0]["after"].clone()).unwrap();
        assert!(
            !download(&fixture, &reopened, &after).is_empty(),
            "unrelated retained snapshots remain usable"
        );
    }
}

#[tokio::test]
async fn actual_snapshot_revocation_closes_the_manifest_through_real_cas_lineage() {
    let fixture = Fixture::new();
    let receipt = commit(
        &fixture,
        "revoke.txt",
        Some(b"before owned bytes\n"),
        "after independent bytes\n",
        "revoke",
    )
    .await;
    let store = fixture.store();
    let diff = store.publish_native_diff(21, &receipt).unwrap();
    let body = parsed(&fixture, &store, &diff);
    let before: ClientArtifactDescriptorV1 =
        serde_json::from_value(body["files"][0]["before"].clone()).unwrap();
    let after: ClientArtifactDescriptorV1 =
        serde_json::from_value(body["files"][0]["after"].clone()).unwrap();
    let reference = {
        let file = storage::ManifestFile::acquire(&store, false)
            .unwrap()
            .unwrap();
        let owner = file.read().unwrap().unwrap();
        owner
            .entries
            .iter()
            .find(|entry| entry.descriptor.artifact_id == diff.artifact_id)
            .unwrap()
            .content
            .clone()
    };
    let lineage = store
        .private(reference.schema)
        .unwrap()
        .sources_at(iteron_protocol::Seq(reference.sequence), &reference.handle)
        .unwrap();
    let expected_sources = [&before, &after]
        .into_iter()
        .map(|descriptor| iteron_record::PrivateContentSource {
            owner: iteron_protocol::RunId("owner".into()),
            digest: iteron_protocol::ErasureContentDigest::new(format!(
                "sha256:{}",
                descriptor.artifact_id
            ))
            .unwrap(),
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        lineage
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_sources
    );
    let revoked = erase(
        &fixture,
        iteron_protocol::ErasureTarget::ContentRevocation {
            scope_id: iteron_protocol::ErasureScopeId::new(iteron_protocol::TenantId::default().0)
                .unwrap(),
            content_digest: iteron_protocol::ErasureContentDigest::new(format!(
                "sha256:{}",
                before.artifact_id
            ))
            .unwrap(),
        },
        "native-snapshot-revoke",
    );
    assert_eq!(revoked.state(), iteron_protocol::ErasureState::Verified);
    let reopened = fixture.store();
    let listing = list(&fixture, &reopened);
    for closed in [&before, &diff] {
        assert!(
            listing["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["artifact_id"] != closed.artifact_id)
        );
        assert!(
            reopened
                .read(
                    &fixture.thread(),
                    ClientArtifactCommandV1::Read {
                        thread_id: fixture.thread(),
                        artifact_id: closed.artifact_id.clone(),
                        offset: 0,
                        max_bytes: 1,
                    }
                )
                .is_err()
        );
    }
    assert_eq!(
        download(&fixture, &reopened, &after),
        b"after independent bytes\n"
    );
    assert_eq!(
        std::fs::read(fixture.0.join("workspace/revoke.txt")).unwrap(),
        b"after independent bytes\n"
    );
}

#[tokio::test]
async fn manifest_dependency_cycles_and_missing_references_fail_closed_on_restart() {
    for dependency in [None, Some("0".repeat(64))] {
        let fixture = Fixture::new();
        let receipt = commit(&fixture, "source.txt", None, "bounded contents\n", "source").await;
        let store = fixture.store();
        let diff = store.publish_native_diff(1, &receipt).unwrap();
        let file = storage::ManifestFile::acquire(&store, false)
            .unwrap()
            .unwrap();
        let mut owner = file.read().unwrap().unwrap();
        let entry = owner
            .entries
            .iter_mut()
            .find(|entry| entry.descriptor.artifact_id == diff.artifact_id)
            .unwrap();
        entry.dependencies = vec![dependency.unwrap_or_else(|| diff.artifact_id.clone())];
        file.write(&owner).unwrap();
        drop(file);
        assert!(
            fixture
                .store()
                .read(
                    &fixture.thread(),
                    ClientArtifactCommandV1::List {
                        thread_id: fixture.thread()
                    }
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.0.join("workspace/source.txt")).unwrap(),
            b"bounded contents\n"
        );
    }
}

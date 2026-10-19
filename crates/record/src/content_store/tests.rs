use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

#[test]
fn record_batch_reacquires_revocation_after_releasing_its_lease() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("batch-revocation".into());
    let original = serde_json::json!({"kind": {"kind": "notice", "text": "revocable batch"}});
    {
        let mut batch = EventPayloadBatch::new(&dir, &tenant, &run);
        for sequence in [0, 1] {
            batch
                .externalize(Seq(sequence), &mut original.clone())
                .unwrap();
        }
    }
    let digest = digest_bytes(b"revocable batch");
    revoke_through_verification(&dir, &tenant, digest.clone()).unwrap();
    // A new batch cannot retain the previous lease's revocation snapshot or resurrect its keys.
    {
        let mut batch = EventPayloadBatch::new(&dir, &tenant, &run);
        assert!(matches!(
            batch.externalize(Seq(2), &mut original.clone()),
            Err(ContentStoreError::Revoked { digest: actual, .. }) if actual == digest
        ));
    }
    let layout = Layout::new(&dir, &tenant);
    assert!(!layout.object_path(&layout.keys, &digest).exists());
    assert!(!layout.object_path(&layout.blobs, &digest).exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn record_batch_partial_content_failure_preserves_journal_and_releases_lease() {
    use iteron_protocol::{Event, EventKind, TurnId};
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("batch-partial-content".into());
    let notice = |text: &str| Event {
        seq: Seq::ZERO,
        turn: TurnId(1),
        kind: EventKind::Notice { text: text.into() },
    };
    let mut rollout = crate::Rollout::open(&dir, &run, tenant.clone()).unwrap();
    storage::STATE_READS.with(|reads| reads.set(0));
    rollout
        .append_batch(&[notice("first"), notice("second")])
        .unwrap();
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    let before = std::fs::read(rollout.path()).unwrap();
    let layout = Layout::new(&dir, &tenant);
    let blob_path = layout.object_path(&layout.blobs, &digest_bytes(b"second"));
    let blob = std::fs::read(&blob_path).unwrap();
    let mut corrupt = blob.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&blob_path, corrupt).unwrap();

    // The first field in this batch is published before the second encounters actual damage.
    // Nothing in the batch may be acknowledged or reach the authoritative journal on failure.
    let next = [notice("new prefix"), notice("second")];
    assert!(matches!(
        rollout.append_batch(&next),
        Err(crate::RecordError::PrivateContent(
            ContentStoreError::Unresolved {
                reason: "authentication_failed",
                ..
            }
        ))
    ));
    assert_eq!(rollout.next_sequence(), Seq(2));
    assert_eq!(std::fs::read(rollout.path()).unwrap(), before);
    drop(lock_store_shared(&layout).expect("failed preparation releases the store lease"));

    std::fs::write(&blob_path, blob).unwrap();
    assert_eq!(rollout.append_batch(&next).unwrap(), vec![Seq(2), Seq(3)]);
    let path = rollout.path().to_owned();
    drop(rollout);
    let mut reopened = crate::Rollout::open_existing(&dir, &run, tenant).unwrap();
    assert_eq!(reopened.next_sequence(), Seq(4));
    assert_eq!(reopened.append(&notice("after restart")).unwrap(), Seq(4));
    drop(reopened);
    let texts = crate::replay(&path)
        .unwrap()
        .into_iter()
        .map(|event| match event.kind {
            EventKind::Notice { text } => text,
            _ => panic!("unexpected event"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        ["first", "second", "new prefix", "second", "after restart"]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn record_batch_checkpoint_inventory_includes_only_preceding_fields() {
    use iteron_protocol::{Event, EventKind, TurnId};
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("batch-checkpoint".into());
    let mut rollout = crate::Rollout::open(&dir, &run, tenant.clone()).unwrap();
    let kinds = [
        EventKind::Notice {
            text: "preceding field".into(),
        },
        EventKind::Checkpoint {
            at: Seq(1),
            tree_ref: "checkpoint tree".into(),
        },
        EventKind::Notice {
            text: "following field".into(),
        },
    ];
    let events = kinds
        .into_iter()
        .map(|kind| Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rollout.append_batch(&events).unwrap(),
        vec![Seq(0), Seq(1), Seq(2)]
    );
    assert_eq!(crate::replay(rollout.path()).unwrap().len(), 3);
    let layout = Layout::new(&dir, &tenant);
    {
        let _lock = lock_store_shared(&layout).unwrap();
        let sources = lineage::sources_for_reference(
            &layout,
            &run,
            &digest_bytes(b"checkpoint tree"),
            Seq(1),
            ContentReferenceSurface::Checkpoint,
        )
        .unwrap();
        assert_eq!(
            sources,
            vec![PrivateContentSource {
                owner: run.clone(),
                digest: digest_bytes(b"preceding field")
            }]
        );
    }
    drop(rollout);
    let summary =
        revoke_through_verification(&dir, &tenant, digest_bytes(b"preceding field")).unwrap();
    assert!(summary.generation > 0);
    assert!(matches!(
        crate::replay(&dir.join("batch-checkpoint.jsonl")),
        Err(crate::RecordError::PrivateContent(
            ContentStoreError::Revoked { .. } | ContentStoreError::Unresolved { .. }
        ))
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn content_publication_reuses_one_revocation_snapshot_under_each_store_lease() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("one-state-per-publication".into());
    let original = serde_json::json!({"kind": {
        "kind": "effect_intent", "arguments": {"path": "."},
        "workspace": "fixture-workspace"
    }});
    for sequence in [1, 2] {
        let mut payload = original.clone();
        storage::STATE_READS.with(|reads| reads.set(0));
        externalize_event_payload(&dir, &tenant, &run, Seq(sequence), &mut payload).unwrap();
        assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
        hydrate_event_payload(&dir, &tenant, &mut payload).unwrap();
        assert_eq!(payload, original);
    }
    storage::STATE_READS.with(|reads| reads.set(0));
    storage::BLOB_READS.with(|reads| reads.set(0));
    let sources = private_content_sources_for_run(&dir, &tenant, &run).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    assert_eq!(storage::BLOB_READS.with(std::cell::Cell::get), 2);
    let derivative = PrivateContentDerivativeStore::open_registered(
        &dir,
        tenant,
        RunId("one-state-derived".into()),
        PrivateContentNamespace::ToolArtifact,
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        1024,
    )
    .unwrap();
    storage::STATE_READS.with(|reads| reads.set(0));
    let handle = derivative
        .put_derived(Seq(3), b"actual derived bytes", &sources)
        .unwrap();
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    storage::STATE_READS.with(|reads| reads.set(0));
    assert_eq!(
        derivative.read_at(Seq(3), &handle).unwrap(),
        b"actual derived bytes"
    );
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    drop(derivative);
    storage::STATE_READS.with(|reads| reads.set(0));
    assert_eq!(
        guard_private_content_for_run(
            &dir,
            &TenantId::default(),
            &RunId("one-state-derived".into())
        )
        .unwrap(),
        1
    );
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    // A new inventory still sees physical corruption; deduplication is confined to one lease.
    let layout = Layout::new(&dir, &TenantId::default());
    let blob = layout.object_path(&layout.blobs, &sources[0].digest);
    std::fs::write(blob, b"corrupt source bytes").unwrap();
    assert!(matches!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run),
        Err(ContentStoreError::Unresolved {
            reason: "authentication_failed",
            ..
        })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn repeated_content_revalidates_physical_bytes_revocation_and_format_on_reacquire() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("revalidated-content".into());
    let put = |sequence| {
        put_private_content(
            &dir,
            &tenant,
            &run,
            Seq(sequence),
            PrivateContentClass::Transcript,
            PrivateContentRetention::Session,
            b"same retained bytes",
            0,
        )
    };
    let handle = put(1).unwrap();
    storage::STATE_READS.with(|reads| reads.set(0));
    assert_eq!(put(2).unwrap(), handle);
    assert_eq!(storage::STATE_READS.with(std::cell::Cell::get), 1);
    let layout = Layout::new(&dir, &tenant);
    let key_path = layout.object_path(&layout.keys, &handle.digest);
    let blob_path = layout.object_path(&layout.blobs, &handle.digest);
    let key = std::fs::read(&key_path).unwrap();
    let blob = std::fs::read(&blob_path).unwrap();
    let mut corrupt = blob.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&blob_path, &corrupt).unwrap();
    assert!(matches!(
        put(3),
        Err(ContentStoreError::Unresolved {
            reason: "authentication_failed",
            ..
        })
    ));
    std::fs::write(&blob_path, &blob).unwrap();
    std::fs::remove_file(&key_path).unwrap();
    assert!(matches!(
        put(3),
        Err(ContentStoreError::Unresolved {
            reason: "partial_material",
            ..
        })
    ));
    std::fs::write(&key_path, key).unwrap();
    assert_eq!(put(3).unwrap(), handle);
    revoke_through_verification(&dir, &tenant, handle.digest).unwrap();
    assert!(matches!(put(4), Err(ContentStoreError::Revoked { .. })));
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&layout.state).unwrap()).unwrap();
    state["metadata_format"] = serde_json::json!(99);
    std::fs::write(&layout.state, serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(put(4), Err(ContentStoreError::Corrupt)));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn control_only_records_round_trip_without_an_available_content_store() {
    let root = test_dir();
    std::fs::create_dir_all(&root).unwrap();
    let unavailable_runs = root.join("occupied");
    std::fs::write(&unavailable_runs, b"not a directory").unwrap();
    let tenant = TenantId::default();
    let run = RunId("control-only".into());
    let original = serde_json::json!({"kind": {"kind": "turn_end"}});
    let mut payload = original.clone();
    externalize_event_payload(&unavailable_runs, &tenant, &run, Seq(1), &mut payload).unwrap();
    assert!(
        externalize_event_payload(&unavailable_runs, &tenant, &run, Seq(1), &mut payload).is_err()
    );
    hydrate_event_payload(&unavailable_runs, &tenant, &mut payload).unwrap();
    assert_eq!(payload, original);
    let mut content = serde_json::json!({"kind": {"kind": "text", "delta": "private"}});
    assert!(
        externalize_event_payload(&unavailable_runs, &tenant, &run, Seq(2), &mut content).is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_pixels_stay_out_of_jsonl_and_hydrate_only_through_owned_private_cas() {
    use iteron_protocol::{
        ImageContent, ImageMediaType, TurnId,
        tool_image::{ToolImageObservationV1, ToolImageScopeV1},
    };
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("tool-image-private-cas".into());
    let data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=";
    let image = ToolImageObservationV1 {
        version: 1,
        owner_tenant: iteron_protocol::TenantId::default(),
        owner_run: iteron_protocol::RunId("tool-image-private-cas".into()),
        tool_use_id: "vision-call".into(),
        terminal_seq: Seq(7),
        observed_unix_ms: 42,
        source_url_display: "https://example.com/".into(),
        scope: ToolImageScopeV1::IsolatedBrowserViewport,
        artifact_id: "a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),
        width: 1,
        height: 1,
        image: ImageContent::new(ImageMediaType::Png, data).unwrap(),
    };
    let event = iteron_protocol::Event {
        seq: Seq(8),
        turn: TurnId(0),
        kind: iteron_protocol::EventKind::ToolImageObservedV1 {
            observation: image.clone(),
        },
    };
    let redacted = crate::redact::redact_event(&event);
    let mut payload = serde_json::to_value(redacted).unwrap();
    externalize_event_payload(&dir, &tenant, &run, Seq(8), &mut payload).unwrap();
    let wire = serde_json::to_string(&payload).unwrap();
    assert!(!wire.contains(data));
    assert!(wire.contains(&image.artifact_id));
    let sources = private_content_sources_for_run(&dir, &tenant, &run).unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].owner, run);
    let edges = metadata::read_dir(Layout::new(&dir, &tenant).run_reference_dir(&run))
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<model::ReferenceEdge>(
                &read_limited(&entry.unwrap().path(), MAX_REFERENCE_EDGE_BYTES).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        edges
            .iter()
            .any(|edge| edge.surface == ContentReferenceSurface::ToolArtifact
                && edge.field_class == "tool_image")
    );
    hydrate_event_payload(&dir, &tenant, &mut payload).unwrap();
    let hydrated: iteron_protocol::Event = serde_json::from_value(payload).unwrap();
    let iteron_protocol::EventKind::ToolImageObservedV1 { observation } = hydrated.kind else {
        panic!()
    };
    assert_eq!(observation, image);
    observation.validate().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

fn test_dir() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "core-private-content-{}-{nonce}-{}",
        std::process::id(),
        NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn authoritative_record_waits_for_a_transient_derivative_store_writer() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("run-record-lock-contention".into());
    let layout = Layout::new(&dir, &tenant);
    ensure_layout(&layout).unwrap();
    let lock = lock_store(&layout).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(25));
        drop(lock);
    });
    let event = iteron_protocol::Event {
        seq: Seq::ZERO,
        turn: iteron_protocol::TurnId(0),
        kind: iteron_protocol::EventKind::Notice {
            text: "private record payload".into(),
        },
    };
    let mut payload = serde_json::to_value(event).unwrap();

    externalize_event_payload(&dir, &tenant, &run, Seq::ZERO, &mut payload).unwrap();
    release.join().unwrap();
    assert_eq!(
        payload.get(iteron_tunables::param_str(
            "record.content_store.model.envelope_field",
            ENVELOPE_FIELD
        )),
        Some(&serde_json::Value::from(STORE_VERSION))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn graph_readers_wait_for_incomplete_derivative_publication() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("graph-reader-publication".into());
    let source = put_private_content(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"actual record source",
        0,
    )
    .unwrap();
    let store = PrivateContentDerivativeStore::open_registered(
        &dir,
        tenant.clone(),
        run.clone(),
        PrivateContentNamespace::ToolArtifact,
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        1024,
    )
    .unwrap();
    let expected = vec![PrivateContentSource {
        owner: run.clone(),
        digest: source.digest,
    }];
    let artifact = store
        .put_derived(Seq(2), b"actual derivative", &expected)
        .unwrap();
    let layout = Layout::new(&dir, &tenant);
    let writer = lock_store(&layout).unwrap();
    // atomic_replace_private writes a scratch member in the edge directory before rename.
    // An in-progress member is not a committed reference and must never reach graph readers.
    let scratch = layout
        .run_reference_dir(&run)
        .join(".core-session-cache-pending.tmp");
    std::fs::create_dir_all(scratch.parent().unwrap()).unwrap();
    std::fs::write(&scratch, b"{").unwrap();
    // Each synchronous read exhausts only the existing finite store acquisition window.
    // A missing lease would instead parse the writer-owned scratch member as a reference.
    let guarded = guard_private_content_for_run(&dir, &tenant, &run);
    let inventoried = private_content_sources_for_run(&dir, &tenant, &run);
    // Complete publication before asserting; no failure can strand the held writer.
    std::fs::remove_file(scratch).unwrap();
    drop(writer);
    assert!(matches!(guarded, Err(ContentStoreError::Busy)));
    assert!(matches!(inventoried, Err(ContentStoreError::Busy)));
    assert_eq!(
        guard_private_content_for_run(&dir, &tenant, &run).unwrap(),
        1
    );
    assert_eq!(
        private_content_sources_for_run(&dir, &tenant, &run).unwrap(),
        expected
    );
    assert_eq!(
        store.read_at(Seq(2), &artifact).unwrap(),
        b"actual derivative"
    );
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn retained_artifact_waits_for_store_lease_and_preserves_actual_source_lineage() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("artifact-source-contention".into());
    let owner = RunId("artifact-owner-contention".into());
    let source_handle = put_private_content(
        &dir,
        &tenant,
        &source,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"actual retained source",
        0,
    )
    .unwrap();
    let store = PrivateContentDerivativeStore::open_registered(
        &dir,
        tenant.clone(),
        owner,
        PrivateContentNamespace::ToolArtifact,
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        1024,
    )
    .unwrap();
    let sources = [PrivateContentSource {
        owner: source,
        digest: source_handle.digest,
    }];
    let layout = Layout::new(&dir, &tenant);
    let lock = lock_store(&layout).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(25));
        drop(lock);
    });

    let result = store.put_derived(Seq(2), b"actual retained artifact", &sources);
    release.join().unwrap();
    let handle = result.expect("a transient record writer must not abort retained publication");
    // Hydration also races the actual background publisher. A different thread releases its
    // exclusive lease, so this blocking read never relies on its own caller to unblock it.
    let lock = lock_store(&layout).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(25));
        drop(lock);
    });
    let retained = store.read_at(Seq(2), &handle);
    release.join().unwrap();
    assert_eq!(
        retained.expect("a transient publisher must not abort retained hydration"),
        b"actual retained artifact"
    );
    // A lease which never becomes available still refuses after the same finite acquisition
    // window. It cannot return cached bytes or relabel contention as corrupt/missing content.
    let lock = lock_store(&layout).unwrap();
    assert!(matches!(
        store.read_at(Seq(2), &handle),
        Err(ContentStoreError::Busy)
    ));
    drop(lock);
    assert_eq!(store.sources_at(Seq(2), &handle).unwrap(), sources);
    assert!(matches!(
        store.read_at(Seq(3), &handle),
        Err(ContentStoreError::Unresolved { .. })
    ));
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reusable_tool_output_store_encrypts_reads_and_releases_by_run() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("run-tool-output".into());
    let bytes = b"private tool output that must not be inline";
    let handle = put_private_content(
        &dir,
        &tenant,
        &run,
        Seq(9),
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        bytes,
        12,
    )
    .unwrap();
    assert_eq!(handle.preview.as_deref(), Some("private tool"));
    assert_eq!(
        load_bytes(&Layout::new(&dir, &tenant), &handle.digest).unwrap(),
        bytes
    );

    let layout = Layout::new(&dir, &tenant);
    let encrypted = std::fs::read(layout.object_path(&layout.blobs, &handle.digest)).unwrap();
    assert!(!encrypted.windows(bytes.len()).any(|window| window == bytes));
    assert_eq!(
        release_private_content_for_run(&dir, &tenant, &run).unwrap(),
        1
    );
    assert!(matches!(
        load_bytes(&Layout::new(&dir, &tenant), &handle.digest),
        Err(ContentStoreError::Unresolved { .. })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exact_run_release_does_not_treat_equal_independent_content_as_a_derivative() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("run-source".into());
    let derivative = RunId("prompt-history-owner".into());
    let bytes = b"shared prompt";
    put_private_content(
        &dir,
        &tenant,
        &source,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        bytes,
        0,
    )
    .unwrap();
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative.clone(),
        ContentReferenceSurface::PromptHistory,
        PrivateContentClass::Transcript,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let history = store.put(Seq(0), bytes).unwrap();
    drop(store);

    ExactRunContentRelease::prepare(&dir, &tenant, &source)
        .unwrap()
        .commit()
        .unwrap();
    let history_store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative.clone(),
        ContentReferenceSurface::PromptHistory,
        PrivateContentClass::Transcript,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    assert_eq!(history_store.read_at(Seq(0), &history).unwrap(), bytes);
    drop(history_store);
    release_private_content_for_run(&dir, &tenant, &derivative).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exact_run_release_refuses_an_explicit_lineage_derivative() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("run-lineage-owner".into());
    put_private_content(
        &dir,
        &tenant,
        &source,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"source prompt",
        0,
    )
    .unwrap();
    let derivative = RunId("dataset-lineage-owner".into());
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative.clone(),
        ContentReferenceSurface::Dataset,
        PrivateContentClass::Dataset,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    store
        .put_derived_from_run(Seq(0), b"derived dataset", &source)
        .unwrap();
    drop(store);

    assert!(matches!(
        ExactRunContentRelease::prepare(&dir, &tenant, &source),
        Err(ContentStoreError::RetainedByDerivative { owners: 1, .. })
    ));
    release_private_content_for_run(&dir, &tenant, &derivative).unwrap();
    ExactRunContentRelease::prepare(&dir, &tenant, &source)
        .unwrap()
        .commit()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn derivative_read_requires_the_exact_lineage_owner_not_only_equal_content() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("lineage-exact-source".into());
    let equal_root = RunId("lineage-equal-root".into());
    let bytes = b"equal source bytes";
    for owner in [&source, &equal_root] {
        put_private_content(
            &dir,
            &tenant,
            owner,
            Seq(1),
            PrivateContentClass::Transcript,
            PrivateContentRetention::Session,
            bytes,
            0,
        )
        .unwrap();
    }
    let derivative_owner = RunId("lineage-exact-derivative".into());
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative_owner,
        ContentReferenceSurface::Dataset,
        PrivateContentClass::Dataset,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let handle = store
        .put_derived_from_run(Seq(4), b"derived bytes", &source)
        .unwrap();

    // Simulate recovery from an inconsistent legacy cleanup that removed the named source owner
    // while equal material remains under another independent owner. The read must fail closed on
    // owner authority rather than accepting content-address equality as lineage.
    release_private_content_for_run(&dir, &tenant, &source).unwrap();
    assert!(matches!(
        store.read_at(Seq(4), &handle),
        Err(ContentStoreError::Unresolved {
            reason: "lineage_source_owner_missing" | "lineage_source_reference_missing",
            ..
        })
    ));
    drop(store);
    release_private_content_for_run(&dir, &tenant, &equal_root).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn equal_content_lineage_from_another_owner_does_not_block_exact_delete() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let deleting = RunId("equal-delete-owner".into());
    let source = RunId("equal-real-source".into());
    for owner in [&deleting, &source] {
        put_private_content(
            &dir,
            &tenant,
            owner,
            Seq(1),
            PrivateContentClass::Transcript,
            PrivateContentRetention::Session,
            b"same bytes",
            0,
        )
        .unwrap();
    }
    let derivative = RunId("equal-derived-owner".into());
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative.clone(),
        ContentReferenceSurface::Dataset,
        PrivateContentClass::Dataset,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    store
        .put_derived_from_run(Seq(2), b"dataset", &source)
        .unwrap();
    drop(store);

    ExactRunContentRelease::prepare(&dir, &tenant, &deleting)
        .unwrap()
        .commit()
        .unwrap();
    release_private_content_for_run(&dir, &tenant, &derivative).unwrap();
    release_private_content_for_run(&dir, &tenant, &source).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn released_derivative_handle_cannot_read_material_retained_by_another_owner() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("run-source-shared".into());
    let derivative = RunId("run-derivative".into());
    let bytes = b"deduplicated material";
    put_private_content(
        &dir,
        &tenant,
        &source,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        bytes,
        0,
    )
    .unwrap();
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative.clone(),
        ContentReferenceSurface::Trajectory,
        PrivateContentClass::Trajectory,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let handle = store.put(Seq(7), bytes).unwrap();
    assert_eq!(store.read_at(Seq(7), &handle).unwrap(), bytes);
    drop(store);

    ExactRunContentRelease::prepare(&dir, &tenant, &derivative)
        .unwrap()
        .commit()
        .unwrap();
    let reopened = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        derivative,
        ContentReferenceSurface::Trajectory,
        PrivateContentClass::Trajectory,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    assert!(matches!(
        reopened.read_at(Seq(7), &handle),
        Err(ContentStoreError::Unresolved {
            reason: "reference_missing",
            ..
        })
    ));
    assert_eq!(
        load_bytes(&Layout::new(&dir, &tenant), &handle.digest).unwrap(),
        bytes
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn incomplete_multi_source_lineage_never_publishes_a_readable_reference() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let source = RunId("run-lineage-source".into());
    for (seq, bytes) in [(1, b"source one".as_slice()), (2, b"source two".as_slice())] {
        put_private_content(
            &dir,
            &tenant,
            &source,
            Seq(seq),
            PrivateContentClass::Transcript,
            PrivateContentRetention::Session,
            bytes,
            0,
        )
        .unwrap();
    }
    let sources = private_content_sources_for_run(&dir, &tenant, &source).unwrap();
    assert_eq!(sources.len(), 2);
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant.clone(),
        RunId("dataset-owner".into()),
        ContentReferenceSurface::Dataset,
        PrivateContentClass::Dataset,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    // First source writes both directional indexes. Fail before publishing the second source.
    lineage::fail_after_writes_for_test(Some(2));
    let bytes = b"derived dataset";
    assert!(store.put_derived(Seq(7), bytes, &sources).is_err());
    lineage::fail_after_writes_for_test(None);

    let handle = PrivateContentHandle {
        digest: private_content_digest(bytes),
        byte_len: bytes.len() as u32,
        class: PrivateContentClass::Dataset,
        preview: None,
    };
    assert!(matches!(
        store.read_at(Seq(7), &handle),
        Err(ContentStoreError::Unresolved {
            reason: "reference_missing",
            ..
        })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn derivative_lineage_refuses_a_forged_source_owner() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let real = RunId("real-source-owner".into());
    let handle = put_private_content(
        &dir,
        &tenant,
        &real,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"owned source",
        0,
    )
    .unwrap();
    let store = PrivateContentDerivativeStore::open(
        &dir,
        tenant,
        RunId("candidate-owner".into()),
        ContentReferenceSurface::CandidateStore,
        PrivateContentClass::Candidate,
        PrivateContentRetention::ExplicitRevocation,
        1024,
    )
    .unwrap();
    let forged = PrivateContentSource {
        owner: RunId("forged-source-owner".into()),
        digest: handle.digest,
    };
    assert!(matches!(
        store.put_derived(Seq(1), b"candidate", &[forged]),
        Err(ContentStoreError::Unresolved {
            reason: "lineage_source_owner_missing",
            ..
        })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

fn revoke_through_verification(
    dir: &std::path::Path,
    tenant: &TenantId,
    digest: ErasureContentDigest,
) -> Result<revocation::ContentRevocationSummary, ContentStoreError> {
    let guard =
        ContentRevocationGuard::begin(dir, tenant, digest)?.expect("the test content must exist");
    guard.tombstone(
        &iteron_protocol::ErasureOperationId::new("coverage-test").unwrap(),
        &iteron_protocol::ErasureAuthorityId::new("operator.test").unwrap(),
        1,
    )?;
    guard.shred()?;
    guard.propagate()?;
    guard.verify()
}

#[test]
fn wrong_namespace_class_cannot_mint_verified_coverage() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("wrong-class-owner".into());
    let handle = put_private_content_at_surface(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::Transcript,
        ContentReferenceSurface::CandidateStore,
        PrivateContentRetention::ExplicitRevocation,
        b"forged candidate payload",
        0,
    )
    .unwrap();
    assert!(matches!(
        revoke_through_verification(&dir, &tenant, handle.digest),
        Err(ContentStoreError::Unresolved {
            reason: "unregistered_content_writer",
            ..
        })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn content_bearing_telemetry_surface_cannot_mint_verified_coverage() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("telemetry-content-owner".into());
    let handle = put_private_content_at_surface(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::TelemetryDebug,
        ContentReferenceSurface::TelemetryDebug,
        PrivateContentRetention::ExplicitRevocation,
        b"future debug content",
        0,
    )
    .unwrap();
    let result = revoke_through_verification(&dir, &tenant, handle.digest);
    assert!(
        matches!(
            result,
            Err(ContentStoreError::Unresolved {
                reason: "unregistered_content_surface",
                ..
            })
        ),
        "unexpected telemetry coverage result: {result:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn moved_reverse_edge_cannot_mint_verified_coverage() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("moved-edge-owner".into());
    let handle = put_private_content(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"owner-bound content",
        0,
    )
    .unwrap();
    let layout = Layout::new(&dir, &tenant);
    {
        let _lock = lock_store(&layout).unwrap();
        let mut changes = Vec::new();
        for entry in metadata::read_dir(layout.run_reference_dir(&run)).unwrap() {
            let entry = entry.unwrap();
            changes.push((
                layout
                    .run_refs
                    .join("forged-owner-location")
                    .join(entry.file_name()),
                Some(read_limited(&entry.path(), MAX_REFERENCE_EDGE_BYTES).unwrap()),
            ));
            changes.push((entry.path(), None));
        }
        metadata::replace_batch(&changes).unwrap();
    }
    assert!(matches!(
        revoke_through_verification(&dir, &tenant, handle.digest),
        Err(ContentStoreError::Corrupt)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn orphaned_forward_edge_cannot_mint_an_absence_coverage_bit() {
    let dir = test_dir();
    let tenant = TenantId::default();
    let run = RunId("orphan-forward-owner".into());
    let handle = put_private_content(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"forward-only content",
        0,
    )
    .unwrap();
    let layout = Layout::new(&dir, &tenant);
    {
        let _lock = lock_store(&layout).unwrap();
        let changes = metadata::read_dir(layout.run_reference_dir(&run))
            .unwrap()
            .map(|entry| (entry.unwrap().path(), None))
            .collect::<Vec<_>>();
        metadata::replace_batch(&changes).unwrap();
    }
    assert!(matches!(
        revoke_through_verification(&dir, &tenant, handle.digest),
        Err(ContentStoreError::Corrupt)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

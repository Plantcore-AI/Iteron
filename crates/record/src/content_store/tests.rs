use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

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
    std::fs::rename(
        layout.run_reference_dir(&run),
        layout.run_refs.join("forged-owner-location"),
    )
    .unwrap();
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
    std::fs::remove_dir_all(layout.run_reference_dir(&run)).unwrap();
    assert!(matches!(
        revoke_through_verification(&dir, &tenant, handle.digest),
        Err(ContentStoreError::Corrupt)
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

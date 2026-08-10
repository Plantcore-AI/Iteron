use super::*;
use std::path::PathBuf;

fn test_dir() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "core-private-content-{}-{nonce}",
        std::process::id()
    ))
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
fn exact_run_release_refuses_an_external_derivative_owner() {
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
    store.put(Seq(0), bytes).unwrap();
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

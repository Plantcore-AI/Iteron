use super::*;
use iteron_protocol::{Event, EventKind, Seq, TenantId, TurnId};
struct Fixture {
    root: std::path::PathBuf,
    binding: ExportBinding,
    reader: ContractReader,
}
impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-native-export-owner-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let run = RunId("native-export-source".into());
        let mut record = iteron_record::Rollout::open(&root, &run, TenantId::default()).unwrap();
        record
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Notice {
                    text: "actual source graph".into(),
                },
            })
            .unwrap();
        let source = NativeExportScope::from_verified_fixture(record.path());
        let reader = ContractReader::default();
        let thread = SessionId("native-export-thread".into());
        reader.bind_identity(thread.clone(), run.clone());
        let binding = ExportBinding {
            thread,
            run,
            source,
            service: Arc::new(ExportService {
                gate: Arc::new(RwLock::new(())),
                capacity: OnceLock::new(),
                quarantine: Arc::new(ExportQuarantine::default()),
            }),
        };
        Self {
            root,
            binding,
            reader,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn strict_public_schema_refuses_native_locators_and_traversal() {
    let valid = serde_json::json!({"thread_id":"t","run_id":"r","text":"rendered transcript","requested":"reports/transcript.md","collision":"refuse"});
    assert!(
        serde_json::from_value::<TranscriptExportV1>(valid.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    for forged in [
        "workspace",
        "runs_dir",
        "tenant",
        "record_path",
        "source_seq",
        "actor",
    ] {
        let mut input = valid.clone();
        input[forged] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<TranscriptExportV1>(input).is_err());
    }
    for name in [
        "/outside",
        "../outside",
        "reports/../outside",
        "reports//outside",
        "C:\\outside",
        "",
    ] {
        let mut input = valid.clone();
        input["requested"] = serde_json::json!(name);
        assert!(
            serde_json::from_value::<TranscriptExportV1>(input)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[tokio::test]
async fn stale_scope_refuses_before_capacity_or_native_content_admission() {
    let fixture = Fixture::new("stale");
    fixture
        .reader
        .bind_identity(SessionId("new-thread".into()), RunId("new-run".into()));
    let (_cancel, cancelled) = tokio::sync::watch::channel(false);
    let result = fixture
        .binding
        .clone()
        .execute(
            fixture.reader.clone(),
            b"old transcript".to_vec(),
            "out.md".into(),
            CollisionPolicy::Refuse,
            cancelled,
        )
        .await;
    assert!(matches!(
        result.publication,
        WorkerRun::Completed(Err(WorkerFailure::KnownFailure(_)))
    ));
    assert!(fixture.binding.service.capacity.get().is_none());
    assert!(!fixture.root.join("out.md").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_observer_retains_physical_slot_and_adoption_barrier_until_real_cleanup() {
    let mut fixture = Fixture::new("lost-observer");
    let (started, start) = std::sync::mpsc::sync_channel(1);
    let (resume, release) = std::sync::mpsc::sync_channel(1);
    fixture.binding.source.pause_stage(started, release);
    let port = TranscriptExportPort::capture(
        fixture.binding.clone(),
        fixture.reader.clone(),
        &fixture.binding.run,
    )
    .unwrap();
    let (cancel, cancelled) = tokio::sync::watch::channel(false);
    let observer = tokio::spawn(async move {
        port.export_transcript(
            b"actual bounded body".to_vec(),
            "out.md".into(),
            CollisionPolicy::Refuse,
            cancelled,
        )
        .await
    });
    tokio::task::spawn_blocking(move || start.recv_timeout(std::time::Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    observer.abort();
    let _ = observer.await;
    assert_eq!(
        fixture
            .binding
            .service
            .capacity
            .get()
            .unwrap()
            .available_permits(),
        0
    );
    assert!(
        fixture
            .binding
            .service
            .gate
            .clone()
            .try_write_owned()
            .is_err()
    );
    assert!(fixture.binding.admit(&fixture.reader).is_err());
    cancel.send(true).unwrap();
    resume.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while fixture
            .binding
            .service
            .capacity
            .get()
            .unwrap()
            .available_permits()
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        fixture
            .binding
            .service
            .gate
            .clone()
            .try_write_owned()
            .is_ok()
    );
    assert!(
        !fixture.root.join("out.md").exists(),
        "cancel before file dispatch does not create an output"
    );
}

#[test]
fn opaque_port_capture_cannot_relabel_an_observed_transcript_as_another_run() {
    let fixture = Fixture::new("observed-origin");
    assert!(
        TranscriptExportPort::capture(
            fixture.binding.clone(),
            fixture.reader.clone(),
            &RunId("foreign-run".into())
        )
        .is_none()
    );
    assert!(fixture.binding.service.capacity.get().is_none());
}

#[test]
fn unknown_publication_retains_exact_scope_and_refuses_new_effects() {
    let fixture = Fixture::new("unknown");
    let lease = fixture.binding.admit(&fixture.reader).unwrap();
    fixture.binding.service.quarantine.retain(lease);
    assert!(
        fixture
            .binding
            .service
            .gate
            .clone()
            .try_write_owned()
            .is_err()
    );
    assert!(fixture.binding.admit(&fixture.reader).is_err());
    assert_eq!(
        fixture
            .binding
            .service
            .capacity
            .get()
            .unwrap()
            .available_permits(),
        0
    );
}

#[tokio::test]
async fn actual_store_open_refusal_is_not_staged_and_releases_adoption_admission() {
    let fixture = Fixture::new("pre-stage-refusal");
    let content = fixture.root.join(".content");
    let saved = fixture.root.join(".preserved-content");
    std::fs::rename(&content, &saved).unwrap();
    std::fs::write(&content, b"not a directory").unwrap();
    let (_cancel, cancelled) = tokio::sync::watch::channel(false);
    let receipt = fixture
        .binding
        .clone()
        .execute(
            fixture.reader.clone(),
            b"never staged".to_vec(),
            "not-published.md".into(),
            CollisionPolicy::Refuse,
            cancelled,
        )
        .await;
    assert!(matches!(
        receipt.publication,
        WorkerRun::Completed(Err(WorkerFailure::KnownFailure(_)))
    ));
    assert_eq!(
        receipt.private_content_cleanup,
        client_effects::ContentCleanup::NotStaged
    );
    assert!(!fixture.binding.service.quarantine.is_quarantined());
    assert!(
        fixture
            .binding
            .service
            .gate
            .clone()
            .try_write_owned()
            .is_ok()
    );
    assert_eq!(
        fixture
            .binding
            .service
            .capacity
            .get()
            .unwrap()
            .available_permits(),
        1
    );
    assert!(!fixture.root.join("not-published.md").exists());
    std::fs::remove_file(content).unwrap();
    std::fs::rename(saved, fixture.root.join(".content")).unwrap();
}

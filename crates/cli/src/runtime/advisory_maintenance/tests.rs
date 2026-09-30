use super::store::{FileJournal, MaintenanceJournal};
use super::*;

fn owner(directory: &Path) -> Arc<MaintenanceOwner> {
    MaintenanceOwner::new(directory.join("journal"), hash(b"one exact host run"))
}
fn target_path(directory: &Path) -> PathBuf {
    let parent = directory.join("cache");
    #[cfg(windows)]
    iteron_support::durable_windows_state::provision_private_directory(&parent).unwrap();
    parent.join("token-calibration-v1.json")
}
fn task(target: &Path, input: &[u8]) -> MaintenanceTask {
    MaintenanceTask {
        kind: Some(MaintenanceKindV1::TokenCalibration),
        turn: 7,
        input_sha256: hash(input),
        target_sha256: hash(target.as_os_str().as_encoded_bytes()),
        target: Some(target.to_owned()),
        queued_unix_ms: now_ms(),
        queued_at: Instant::now(),
        input: input.to_vec(),
    }
}
fn initialize() -> MaintenanceTask {
    MaintenanceTask {
        kind: None,
        turn: 0,
        input_sha256: hash(b"initialization"),
        target_sha256: hash(b"initialization"),
        target: None,
        queued_unix_ms: now_ms(),
        queued_at: Instant::now(),
        input: Vec::new(),
    }
}

#[test]
fn cache_completion_is_backed_by_separate_durable_journal_and_exact_payload() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    let target = target_path(directory.path());
    let bytes = br#"{"version":1,"samples":[]}"#;
    assert!(owner.execute(task(&target, bytes)));
    let view = owner.observe(0, 64).unwrap();
    assert_eq!(
        view.evidence_source,
        MaintenanceEvidenceSourceV1::MaintenanceJournal
    );
    assert_eq!(view.journal_revision, 4);
    assert_eq!(view.jobs[0].state, MaintenanceStateV1::Completed);
    assert_eq!(view.jobs[0].input_sha256, hash(bytes));
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    let journal_path = owner.directory.clone();
    drop(owner);
    let mut journal = FileJournal::open(&journal_path).unwrap();
    let snapshot = journal.load().unwrap().unwrap();
    assert_eq!(snapshot.jobs[0].state, MaintenanceStateV1::Completed);
    assert_eq!(
        view.journal_sha256,
        hash(&serde_json::to_vec(&snapshot).unwrap())
    );
}

struct RefuseTerminal {
    inner: Box<dyn MaintenanceJournal>,
}
impl MaintenanceJournal for RefuseTerminal {
    fn load(&mut self) -> Result<Option<Snapshot>, MaintenanceReadError> {
        self.inner.load()
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &Snapshot,
    ) -> Result<(), MaintenanceReadError> {
        if next.revision == 4 {
            Err(MaintenanceReadError::ReconciliationNeeded)
        } else {
            self.inner.commit(expected, next)
        }
    }
}
#[test]
fn failed_terminal_barrier_never_claims_complete_and_restart_never_repeats_cache_io() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    let target = target_path(directory.path());
    let Writer { store, snapshot } = owner.open_writer().unwrap();
    *owner.writer.lock().unwrap() = Some(Writer {
        snapshot,
        store: Box::new(RefuseTerminal { inner: store }),
    });
    assert!(!owner.execute(task(&target, b"exact bytes")));
    assert_eq!(
        owner.observe(0, 64),
        Err(MaintenanceReadError::ReconciliationNeeded)
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"exact bytes");
    let journal_path = owner.directory.clone();
    drop(owner);
    let restored = MaintenanceOwner::new(journal_path, hash(b"one exact host run"));
    assert!(restored.execute(initialize()));
    let view = restored.observe(0, 64).unwrap();
    assert_eq!(view.jobs[0].state, MaintenanceStateV1::ReconciliationNeeded);
    assert_eq!(
        view.jobs[0].reason_code.as_deref(),
        Some("restart_unfinished")
    );
    assert!(restored.execute(task(&target, b"must never overwrite")));
    assert_eq!(std::fs::read(&target).unwrap(), b"exact bytes");
    assert_eq!(
        restored.observe(0, 64).unwrap().jobs.last().unwrap().state,
        MaintenanceStateV1::Failed
    );
}

#[test]
fn deadline_error_does_not_forge_a_journal_state_or_revision() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    assert!(owner.execute(initialize()));
    let before = owner.observe(0, 64).unwrap();
    owner.deadline_unknown();
    assert_eq!(
        owner.observe(before.journal_revision, 64),
        Err(MaintenanceReadError::ReconciliationNeeded)
    );
    owner.deadline_finished();
    assert_eq!(owner.observe(0, 64).unwrap(), before);
}

#[test]
fn restart_scope_mismatch_and_missing_snapshot_never_create_new_genesis() {
    let directory = tempfile::tempdir().unwrap();
    let first = owner(directory.path());
    assert!(first.execute(initialize()));
    let journal_path = first.directory.clone();
    drop(first);
    let wrong = MaintenanceOwner::new(journal_path.clone(), hash(b"different run"));
    assert!(!wrong.execute(initialize()));
    assert_eq!(
        wrong.observe(0, 64),
        Err(MaintenanceReadError::ReconciliationNeeded)
    );
    drop(wrong);
    std::fs::remove_file(journal_path.join("maintenance.json")).unwrap();
    let missing = MaintenanceOwner::new(journal_path, hash(b"one exact host run"));
    assert!(!missing.execute(initialize()));
    assert_eq!(
        missing.observe(0, 64),
        Err(MaintenanceReadError::ReconciliationNeeded)
    );
}

#[cfg(unix)]
#[test]
fn target_pin_prevents_namespace_retarget_and_unknown_marker_survives_release() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("cache");
    std::fs::create_dir(&parent).unwrap();
    let target = parent.join("token-calibration-v1.json");
    let mut lease = cache::CacheLease::open(&target, MaintenanceKindV1::TokenCalibration).unwrap();
    assert!(cache::CacheLease::open(&target, MaintenanceKindV1::TokenCalibration).is_err());
    let moved = directory.path().join("pinned-original");
    std::fs::rename(&parent, &moved).unwrap();
    std::fs::create_dir(&parent).unwrap();
    std::fs::write(&target, b"unrelated replacement").unwrap();
    lease.publish(b"intended pinned write").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"unrelated replacement");
    assert_eq!(
        std::fs::read(moved.join("token-calibration-v1.json")).unwrap(),
        b"intended pinned write"
    );
    lease.quarantine().unwrap();
    drop(lease);
    assert!(
        cache::CacheLease::open(
            &moved.join("token-calibration-v1.json"),
            MaintenanceKindV1::TokenCalibration
        )
        .is_err()
    );
}

#[test]
fn observation_and_payload_bounds_do_not_admit_unbounded_native_work() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    assert!(owner.execute(initialize()));
    assert_eq!(
        owner.observe(0, 0),
        Err(MaintenanceReadError::InvalidBounds)
    );
    assert_eq!(
        owner.observe(0, 65),
        Err(MaintenanceReadError::InvalidBounds)
    );
    assert_eq!(
        owner.observe(2, 64),
        Err(MaintenanceReadError::InvalidBounds)
    );
    assert!(!owner.enqueue(
        MaintenanceKindV1::TokenCalibration,
        1,
        &vec![0; MAX_INPUT_BYTES + 1],
        &target_path(directory.path())
    ));
}

#[tokio::test]
async fn watch_returns_only_actual_barrier_state_and_rejects_unbounded_waits() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    assert!(owner.execute(initialize()));
    assert_eq!(
        owner.wait(0, 60_001).await,
        Err(MaintenanceReadError::InvalidBounds)
    );
    let port = owner.clone();
    let observed = tokio::spawn(async move { port.wait(1, 1000).await });
    assert!(owner.execute(task(
        &target_path(directory.path()),
        b"actual native publication"
    )));
    let view = observed.await.unwrap().unwrap();
    assert!(view.journal_revision > 1);
    assert_eq!(
        view.jobs.last().unwrap().state,
        MaintenanceStateV1::Completed
    );
}

struct BlockRunning {
    inner: Box<dyn MaintenanceJournal>,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
impl MaintenanceJournal for BlockRunning {
    fn load(&mut self) -> Result<Option<Snapshot>, MaintenanceReadError> {
        self.inner.load()
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &Snapshot,
    ) -> Result<(), MaintenanceReadError> {
        if next.revision == 3 {
            let _ = self.entered.send(());
            self.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        }
        self.inner.commit(expected, next)
    }
}
#[test]
fn blocked_real_writer_barrier_never_blocks_the_main_read_or_queue_port() {
    let directory = tempfile::tempdir().unwrap();
    let owner = owner(directory.path());
    let Writer { store, snapshot } = owner.open_writer().unwrap();
    let (entered, started) = std::sync::mpsc::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    *owner.writer.lock().unwrap() = Some(Writer {
        snapshot,
        store: Box::new(BlockRunning {
            inner: store,
            entered,
            release: blocked,
        }),
    });
    let target = target_path(directory.path());
    assert!(owner.enqueue(
        MaintenanceKindV1::TokenCalibration,
        1,
        b"first exact snapshot",
        &target
    ));
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    // The worker holds its disk/writer port. Reads use the last independent committed view, and
    // enqueue accepts only bounded memory work without touching that port or cache filesystem.
    let view = owner.observe(0, 64).unwrap();
    assert_eq!(view.journal_revision, 2);
    assert_eq!(view.jobs[0].state, MaintenanceStateV1::Queued);
    assert!(!target.exists());
    assert!(owner.enqueue(
        MaintenanceKindV1::TokenCalibration,
        2,
        b"second exact snapshot",
        &target
    ));
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let view = owner.observe(0, 64).unwrap();
        if view.jobs.len() >= 2
            && view.jobs.iter().all(|job| {
                matches!(
                    job.state,
                    MaintenanceStateV1::Completed | MaintenanceStateV1::Failed
                )
            })
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
}

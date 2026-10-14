use super::*;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const NOW: u64 = 1_700_000_000_000;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "iteron-turn-start-authority-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn open(&self) -> TurnStartStore {
        TurnStartStore::open(&self.0, &TenantId("synthetic".into())).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn key(thread: &str, text: &str, timestamp: u64, salt: u32) -> String {
    let mut uuid = [0u8; 16];
    uuid[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
    uuid[6] = 0x70;
    uuid[8] = 0x80;
    uuid[12..].copy_from_slice(&salt.to_be_bytes());
    let h = hex::encode(uuid);
    let prefix = format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    );
    let mut digest = Sha256::new();
    digest.update(uuid);
    digest.update((thread.len() as u64).to_be_bytes());
    digest.update(thread.as_bytes());
    digest.update((text.len() as u64).to_be_bytes());
    digest.update(text.as_bytes());
    format!("{prefix}:{}", hex::encode(digest.finalize()))
}
fn make_request(thread: &str, timestamp: u64, salt: u32) -> PreparedRequest {
    prepare(
        &key(thread, "synthetic exact text", timestamp, salt),
        &SessionId(thread.into()),
        "synthetic exact text",
    )
    .unwrap()
}
fn reserved(decision: StoreDecision) -> Reservation {
    match decision {
        StoreDecision::Reserved(r) => *r,
        other => panic!("expected reservation, got {other:?}"),
    }
}
fn receipt(decision: StoreDecision) -> StoreReceipt {
    match decision {
        StoreDecision::Receipt(r) => r,
        other => panic!("expected recovery receipt, got {other:?}"),
    }
}
fn admitted(store: &TurnStartStore, reservation: &Reservation, now: u64) -> AdmissionIdentity {
    match store.admit(
        reservation,
        AdmissionIdentity {
            run_id: reservation.target_run.clone(),
            submission_id: SubmissionId(7),
            turn_id: ProductTurnId(1),
        },
        now,
    ) {
        StoreDecision::Admitted(r) => r.identity.unwrap(),
        other => panic!("expected fresh durable admission, got {other:?}"),
    }
}
fn assert_refused(decision: StoreDecision, expected: RefusalReason, definitely: bool) {
    match decision {
        StoreDecision::Refused(r) => {
            assert_eq!(r.reason, expected);
            assert_eq!(r.definitely_unregistered, definitely);
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn exact_salted_request_identity_precedes_expiry_and_other_refusals() {
    let thread = SessionId("thread-中".into());
    let original = " original\n中 e\u{301} ";
    let k = key(&thread.0, original, NOW, 1);
    assert_eq!(k.len(), 101);
    let request = prepare(&k, &thread, original).unwrap();
    assert_eq!(
        prepare(&k, &thread, original.trim()).unwrap_err().reason,
        RefusalReason::RequestConflict
    );
    assert_eq!(
        prepare(&k, &SessionId("other".into()), original)
            .unwrap_err()
            .reason,
        RefusalReason::RequestConflict
    );
    assert_eq!(
        prepare(&k, &thread, "").unwrap_err().reason,
        RefusalReason::RequestConflict
    );
    assert_eq!(
        prepare(&k.to_uppercase(), &thread, original)
            .unwrap_err()
            .reason,
        RefusalReason::InvalidRequestKey
    );
    let fixture = Fixture::new();
    let store = fixture.open();
    assert_refused(
        store.reserve(&request, &RunId("run".into()), true, NOW + WINDOW_MS),
        RefusalReason::RequestKeyExpired,
        false,
    );
    let future = make_request("future", NOW + WINDOW_MS + FUTURE_TOLERANCE_MS + 1, 2);
    assert_refused(
        store.lookup(&future, NOW),
        RefusalReason::RequestKeyInFuture,
        false,
    );
}

#[test]
fn owned_pending_recovery_atomic_admission_and_failed_terminal_never_reexecute() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let peer = fixture.open();
    let request = make_request("thread", NOW, 1);
    let first = reserved(store.reserve(&request, &RunId("run".into()), false, NOW));
    assert_eq!(
        receipt(peer.reserve(&request, &RunId("ignored".into()), true, NOW)).state,
        StoreState::Pending
    );
    drop(first);
    assert!(matches!(peer.lookup(&request, NOW), StoreDecision::Vacant));
    let reservation = reserved(peer.reserve(&request, &RunId("run".into()), false, NOW));
    let identity = admitted(&peer, &reservation, NOW);
    let duplicate = receipt(store.admit(&reservation, identity.clone(), NOW));
    assert_eq!(duplicate.identity.as_ref(), Some(&identity));
    assert_eq!(duplicate.state, StoreState::Admitted);
    assert_eq!(
        receipt(store.mark_running(&request, &identity, NOW)).state,
        StoreState::Running
    );
    let next = make_request("thread", NOW, 2);
    assert_refused(
        store.reserve(&next, &RunId("run".into()), false, NOW),
        RefusalReason::TurnActive,
        true,
    );
    assert_eq!(
        receipt(peer.finish(&request, &identity, TerminalState::Failed, NOW)).state,
        StoreState::Failed
    );
    drop(reservation);
    drop(peer);
    let reopened = fixture.open();
    let failed = receipt(reopened.reserve(&request, &RunId("another".into()), true, NOW));
    assert_eq!(failed.state, StoreState::Failed);
    assert_eq!(failed.identity.as_ref(), Some(&identity));
    let next_reservation = reserved(reopened.reserve(&next, &RunId("run".into()), false, NOW));
    assert!(admitted(&reopened, &next_reservation, NOW).turn_id.0 > identity.turn_id.0);
    let disk = std::fs::read_to_string(store.directory.join("state.json")).unwrap();
    assert!(!disk.contains("synthetic exact text"));
    assert!(serde_json::to_vec(&failed).unwrap().len() <= MAX_ENTRY_BYTES);
}

#[test]
fn expiry_gc_clock_rollback_preserves_floor_identity_and_unknown_occupancy() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let old = make_request("completed", NOW, 1);
    let r = reserved(store.reserve(&old, &RunId("run".into()), false, NOW));
    let first = admitted(&store, &r, NOW);
    receipt(store.finish(&old, &first, TerminalState::Completed, NOW));
    drop(r);
    let unresolved = make_request("occupied", NOW, 2);
    let r = reserved(store.reserve(&unresolved, &RunId("run".into()), false, NOW));
    let uncertain = admitted(&store, &r, NOW);
    drop(r);
    assert_eq!(
        receipt(store.lookup(&unresolved, NOW)).state,
        StoreState::Unknown
    );
    let later = NOW + WINDOW_MS + 10;
    let fresh = make_request("new", later, 3);
    assert!(matches!(store.lookup(&fresh, later), StoreDecision::Vacant));
    let snapshot = read_snapshot(&store.directory, &store.tenant_digest).unwrap();
    assert!(!snapshot.entries.contains_key(old.request_key()));
    assert!(snapshot.entries.contains_key(unresolved.request_key()));
    drop(store);
    let store = fixture.open();
    assert_refused(
        store.lookup(&old, NOW),
        RefusalReason::RequestKeyExpired,
        false,
    );
    let blocked = make_request("occupied", later, 4);
    assert_refused(
        store.reserve(&blocked, &RunId("run".into()), false, NOW),
        RefusalReason::TurnActive,
        true,
    );
    receipt(store.finish(&unresolved, &uncertain, TerminalState::Interrupted, later));
    let r = reserved(store.reserve(&blocked, &RunId("run".into()), false, NOW));
    assert!(admitted(&store, &r, NOW).turn_id.0 > uncertain.turn_id.0);
}

#[test]
fn mixed_product_allocations_remain_unique_across_reopen_and_key_gc() {
    let fixture = Fixture::new();
    let tenant = TenantId("synthetic".into());
    assert!(!authority_exists(&fixture.0, &tenant).unwrap());
    assert!(
        !fixture.0.exists(),
        "the generic presence probe must remain read-only"
    );
    std::fs::create_dir(&fixture.0).unwrap();
    let malformed_namespace = fixture.0.join(".turn-start-v2");
    std::fs::write(&malformed_namespace, b"not a namespace directory").unwrap();
    assert!(authority_exists(&fixture.0, &tenant).is_err());
    std::fs::remove_file(malformed_namespace).unwrap();
    let store = fixture.open();
    assert!(authority_exists(&fixture.0, &tenant).unwrap());
    let keyed = make_request("thread", NOW, 1);
    let reservation = reserved(store.reserve(&keyed, &RunId("same-run".into()), false, NOW));
    let first = admitted(&store, &reservation, NOW);
    receipt(store.finish(&keyed, &first, TerminalState::Completed, NOW));
    drop(reservation);
    let generic = store.allocate_product_turn(ProductTurnId(1), NOW).unwrap();
    assert!(generic.0 > first.turn_id.0);
    drop(store);
    let store = fixture.open();
    let followup = store.allocate_product_turn(ProductTurnId(1), NOW).unwrap();
    assert!(
        followup.0 > generic.0,
        "reopening must not reuse a generic turn identity"
    );
    let later = NOW + WINDOW_MS + 1;
    let next = make_request("thread", later, 2);
    assert!(matches!(store.lookup(&next, later), StoreDecision::Vacant));
    assert!(
        !read_snapshot(&store.directory, &store.tenant_digest)
            .unwrap()
            .entries
            .contains_key(keyed.request_key())
    );
    drop(store);
    let store = fixture.open();
    let reservation = reserved(store.reserve(&next, &RunId("same-run".into()), false, later));
    let second = admitted(&store, &reservation, later);
    assert!(
        second.turn_id.0 > followup.0,
        "V2 after GC must not reuse a generic identity"
    );
    assert_eq!(
        store
            .allocate_product_turn(ProductTurnId(100), later)
            .unwrap(),
        ProductTurnId(100)
    );
    assert_eq!(
        store.allocate_product_turn(ProductTurnId(1), NOW).unwrap(),
        ProductTurnId(101)
    );
}

#[test]
fn uncertain_commit_and_corrupt_or_missing_authority_never_report_unregistered() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let request = make_request("thread", NOW, 1);
    let r = reserved(store.reserve(&request, &RunId("run".into()), false, NOW));
    store.fail_commit.store(1, Ordering::SeqCst);
    let attempted = AdmissionIdentity {
        run_id: RunId("run".into()),
        submission_id: SubmissionId(7),
        turn_id: ProductTurnId(1),
    };
    assert_eq!(
        receipt(store.admit(&r, attempted.clone(), NOW)).state,
        StoreState::AdmissionUnknown
    );
    assert_eq!(
        receipt(store.lookup(&request, NOW)).state,
        StoreState::Pending
    );
    store.fail_commit.store(2, Ordering::SeqCst);
    assert_eq!(
        receipt(store.admit(&r, attempted, NOW)).state,
        StoreState::AdmissionUnknown
    );
    let identity = receipt(store.lookup(&request, NOW)).identity.unwrap();
    // Lost acknowledgement: close all live execution custody; recovery cannot start it again.
    drop(r);
    drop(store);
    let store = fixture.open();
    let recovered = receipt(store.lookup(&request, NOW));
    assert_eq!(recovered.state, StoreState::Unknown);
    assert_eq!(recovered.identity, Some(identity));
    std::fs::write(store.directory.join("state.json"), b"{partial").unwrap();
    let unknown = receipt(store.lookup(&request, NOW + WINDOW_MS));
    assert_eq!(unknown.state, StoreState::AdmissionUnknown);
    assert!(unknown.identity.is_none());
    assert!(unknown.window_closed);
    assert!(TurnStartStore::open(&fixture.0, &TenantId("synthetic".into())).is_err());
    std::fs::remove_file(store.directory.join("state.json")).unwrap();
    assert!(authority_exists(&fixture.0, &TenantId("synthetic".into())).unwrap());
    assert!(TurnStartStore::open(&fixture.0, &TenantId("synthetic".into())).is_err());
}

#[test]
fn capacity_keeps_existing_recovery_and_rate_concurrency_are_authority_wide() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let peer = fixture.open();
    let current = make_request("thread", NOW, 1);
    let r = reserved(store.reserve(&current, &RunId("run".into()), false, NOW));
    let identity = admitted(&store, &r, NOW);
    receipt(store.finish(&current, &identity, TerminalState::Completed, NOW));
    drop(r);
    // Seed exact valid completed history in one durable transaction; no thousand-fsync fixture.
    let mut snapshot = read_snapshot(&store.directory, &store.tenant_digest).unwrap();
    let template = snapshot.entries.get(current.request_key()).unwrap().clone();
    for n in 2..=CAPACITY {
        let request = make_request(&format!("thread-{n}"), NOW, n as u32);
        let mut entry = template.clone();
        entry.thread_id = request.thread_id.clone();
        snapshot.entries.insert(request.request_key.clone(), entry);
    }
    replace_snapshot(&store.directory, &snapshot).unwrap();
    let additional = make_request("additional", NOW, 5000);
    assert_refused(
        peer.reserve(&additional, &RunId("run".into()), false, NOW),
        RefusalReason::CapacityFull,
        true,
    );
    assert_eq!(
        receipt(peer.lookup(&current, NOW)).state,
        StoreState::Completed
    );
    let mut held = Vec::new();
    for _ in 0..REQUEST_SLOTS {
        held.push(store.enter_request(&current, NOW).unwrap());
    }
    assert_refused(
        peer.enter_request(&current, NOW).unwrap_err(),
        RefusalReason::RateLimited,
        false,
    );
    held.clear();
    for _ in 0..32 {
        drop(peer.enter_request(&current, NOW).unwrap());
    }
    assert_refused(
        store.enter_request(&current, NOW).unwrap_err(),
        RefusalReason::RateLimited,
        false,
    );
    assert!(peer.enter_request(&current, NOW + 16).is_ok());
    assert_refused(
        store.enter_request(&current, NOW).unwrap_err(),
        RefusalReason::RateLimited,
        false,
    );
}

#[test]
fn independent_processes_share_one_admission_and_stable_lock() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let authority_lock = store.directory.join("authority.lock");
    let before = std::fs::metadata(&authority_lock).unwrap();
    let mut children = Vec::new();
    for label in ["a", "b"] {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("turn_start_store::tests::cross_process_worker")
                .env("ITERON_TURN_START_TEST_ROOT", &fixture.0)
                .env("ITERON_TURN_START_TEST_LABEL", label)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    std::fs::write(fixture.0.join("start"), b"go").unwrap();
    for child in &mut children {
        wait_bounded(child);
    }
    let results: Vec<serde_json::Value> = ["a", "b"]
        .iter()
        .map(|label| {
            serde_json::from_slice(&std::fs::read(fixture.0.join(format!("{label}.json"))).unwrap())
                .unwrap()
        })
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|value| value["new_admission"] == true)
            .count(),
        1
    );
    assert_eq!(
        receipt(store.lookup(&make_request("thread", NOW, 1), NOW)).state,
        StoreState::Unknown
    );
    assert_eq!(std::fs::read(&authority_lock).unwrap(), INITIALIZED);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            before.ino(),
            std::fs::metadata(&authority_lock).unwrap().ino()
        );
    }
    #[cfg(not(unix))]
    let _ = before;
}
fn wait_bounded(child: &mut Child) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill(); // Only this retained test-owned child, never PID discovery/tree killing.
    panic!("admission fixture child exceeded its deadline");
}
#[test]
fn cross_process_worker() {
    let Some(root) = std::env::var_os("ITERON_TURN_START_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let label = std::env::var("ITERON_TURN_START_TEST_LABEL").unwrap();
    assert!(matches!(label.as_str(), "a" | "b"));
    let store = TurnStartStore::open(&root, &TenantId("synthetic".into())).unwrap();
    let start = Instant::now();
    while !root.join("start").exists() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    let request = make_request("thread", NOW, 1);
    let mut retained = None;
    let new_admission = match store.reserve(&request, &RunId("run".into()), false, NOW) {
        StoreDecision::Reserved(r) => {
            admitted(&store, &r, NOW);
            retained = Some(r);
            true
        }
        StoreDecision::Receipt(r) => {
            assert!(matches!(
                r.state,
                StoreState::Pending | StoreState::Admitted | StoreState::Unknown
            ));
            false
        }
        other => panic!("unexpected concurrent result {other:?}"),
    };
    std::fs::write(
        root.join(format!("{label}.json")),
        serde_json::to_vec(&serde_json::json!({"new_admission": new_admission})).unwrap(),
    )
    .unwrap();
    drop(retained);
}

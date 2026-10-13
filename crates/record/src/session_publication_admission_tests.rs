//! Exercise the real publication worker and WAL with explicit synchronization, not scheduler
//! sleeps. The hooks pause admission only; every accepted publication still builds its actual
//! private sidecar/index and every foreground append still crosses the native CAS/file barriers.

use crate::session_publication_admission::{
    TestHookGuard, install_foreground_wait_hook, install_publication_hook,
};
use crate::{ContentStoreError, RecordError, Rollout, replay, session, session_maintenance};
use iteron_protocol::{Effort, Event, EventKind, Message, Outcome, RunId, Seq, TenantId, TurnId};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-publication-{tag}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn writer(&self, run: &str, tenant: &TenantId) -> Rollout {
        seed(&self.0, run, tenant)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = session_maintenance::flush();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(30))
    }

    fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    fn receive<T>(self, receiver: &Receiver<T>, stage: &str) -> T {
        receiver
            .recv_timeout(self.remaining())
            .unwrap_or_else(|error| panic!("{stage}: {error}"))
    }
}

struct ReleaseOnDrop(Option<Sender<()>>);

impl ReleaseOnDrop {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.release();
    }
}

struct PublicationPause {
    entered: Receiver<()>,
    release: ReleaseOnDrop,
    _hook: TestHookGuard,
}

impl PublicationPause {
    fn install(runs: &Path, tenant: &TenantId, deadline: Deadline) -> Self {
        let (entered, receipt) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let hook = install_publication_hook(
            runs,
            tenant,
            Box::new(move || {
                let _ = entered.send(());
                // A failed assertion releases the worker via Drop; a lost test owner also has
                // a finite deadline. Never panic on the shared publication thread.
                let _ = wait.recv_timeout(deadline.remaining());
            }),
        )
        .unwrap();
        Self {
            entered: receipt,
            release: ReleaseOnDrop(Some(release)),
            _hook: hook,
        }
    }
}

fn event(kind: EventKind) -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind,
    }
}

fn notice(text: &str) -> Event {
    event(EventKind::Notice { text: text.into() })
}

fn seed(runs: &Path, name: &str, tenant: &TenantId) -> Rollout {
    let mut writer = Rollout::open(runs, &RunId(name.into()), tenant.clone()).unwrap();
    writer
        .append(&event(EventKind::RunStart {
            cwd: runs.to_string_lossy().into_owned(),
            model: "fixture-model".into(),
            effort: Effort::Medium,
            created_at: 1000,
            environment: None,
            parent_run: None,
            forked_at: None,
            parent_hash_at_seq: None,
            config_digest: "fixture-config".into(),
            agent_definition_tag: None,
            max_usd: None,
        }))
        .unwrap();
    writer
        .append(&event(EventKind::Message {
            message: Message::user_text("publication fixture"),
        }))
        .unwrap();
    assert!(writer.refresh_session_cache().unwrap());
    writer
}

fn assert_current(writer: &Rollout) {
    let runs = writer.path().parent().unwrap();
    // Check the physical sidecar before using a reader that could fall back to replay. A
    // successful replay alone would conceal a worker that never published its latest proposal.
    assert!(session::cached_projection_is_current(runs, writer.run_id()));
    let meta = session::meta(runs, writer.run_id()).unwrap();
    assert_eq!(meta.record_tail_seq, Some(writer.seq.0 - 1));
    assert_eq!(meta.record_tail_hash, writer.last_hash);
    assert_eq!(meta.record_bytes, writer.durable_bytes);
}

#[test]
fn waiting_foreground_precedes_queued_session_publication() {
    let fixture = Fixture::new("priority");
    let tenant = TenantId::default();
    let mut writer = fixture.writer("priority", &tenant);
    let queued_meta = match &writer.session_projection {
        crate::SessionProjectionState::Ready(projection) => projection.publication_meta().clone(),
        _ => panic!("seed initialized the real durable projection"),
    };
    let deadline = Deadline::new();

    let writer = std::thread::scope(|threads| {
        let mut first = PublicationPause::install(&fixture.0, &tenant, deadline);
        assert!(writer.refresh_session_cache_async().unwrap());
        deadline.receive(&first.entered, "first real publisher acquired its permit");

        let (published, second_publication) = mpsc::channel();
        let _second_hook = install_publication_hook(
            &fixture.0,
            &tenant,
            Box::new(move || {
                let _ = published.send(());
            }),
        )
        .unwrap();
        // Requeue the already prepared, real projection through the worker's production entry.
        // Preparing another proposal takes foreground admission and must wait for this pause.
        assert!(session_maintenance::enqueue(fixture.0.clone(), queued_meta));
        let (waiting, waiter) = mpsc::channel();
        let _wait_hook = install_foreground_wait_hook(
            &fixture.0,
            &tenant,
            Box::new(move || {
                let _ = waiting.send(());
            }),
        )
        .unwrap();
        let (admitted, admission) = mpsc::channel();
        let (release, hold) = mpsc::channel();
        let mut foreground_release = ReleaseOnDrop(Some(release));
        let (returned, result) = mpsc::channel();
        threads.spawn(move || {
            let activity = writer.foreground_activity().unwrap();
            writer.append(&notice("foreground durable tail")).unwrap();
            assert!(writer.refresh_session_cache_async().unwrap());
            admitted.send(()).unwrap();
            let _ = hold.recv_timeout(deadline.remaining());
            drop(activity);
            let _ = returned.send(writer);
        });

        deadline.receive(
            &waiter,
            "foreground counted as waiting behind the publisher",
        );
        first.release.release();
        deadline.receive(
            &admission,
            "waiting foreground appended before the next publisher",
        );
        session_maintenance::flush().unwrap();
        assert!(matches!(
            second_publication.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        foreground_release.release();
        let writer = deadline.receive(&result, "foreground released its activity window");
        session_maintenance::flush().unwrap();
        deadline.receive(
            &second_publication,
            "deferred real publication resumed at idle",
        );
        assert_current(&writer);
        writer
    });
    let replayed = replay(writer.path()).unwrap();
    assert!(
        matches!(&replayed.last().unwrap().kind, EventKind::Notice { text }
        if text == "foreground durable tail")
    );
}

#[test]
fn active_scope_coalesces_latest_tail_and_reopens_exactly() {
    let fixture = Fixture::new("latest");
    let tenant = TenantId::default();
    let mut writer = fixture.writer("latest", &tenant);
    assert_eq!(session::reindex(&fixture.0).unwrap(), 1);
    assert!(session::page(&fixture.0, &tenant, None, None, Some(1)).index_ready);
    let deadline = Deadline::new();
    let outer = writer.foreground_activity().unwrap();
    let inner = writer.foreground_activity().unwrap();
    let (published, publication) = mpsc::channel();
    let _hook = install_publication_hook(
        &fixture.0,
        &tenant,
        Box::new(move || {
            let _ = published.send(());
        }),
    )
    .unwrap();

    for turn in 0..3 {
        writer
            .append(&Event {
                turn: TurnId(turn),
                ..event(EventKind::TurnStart)
            })
            .unwrap();
        assert!(writer.refresh_session_cache_async().unwrap());
    }
    writer
        .append(&event(EventKind::Done {
            outcome: "Done".into(),
        }))
        .unwrap();
    // More updates than the worker's pending-run bound must coalesce this one run, not fill a
    // per-turn queue or discard the last durable tail.
    for _ in 0..80 {
        assert!(writer.refresh_session_cache_async().unwrap());
    }
    assert!(!writer.refresh_session_cache().unwrap());
    session_maintenance::flush().unwrap();
    assert!(matches!(
        publication.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(!session::cached_projection_is_current(
        &fixture.0,
        writer.run_id()
    ));
    let active_meta = session::meta(&fixture.0, writer.run_id()).unwrap();
    assert_eq!(active_meta.turns, 3);
    assert_eq!(active_meta.last_outcome, Some(Outcome::Done));
    assert_eq!(active_meta.record_tail_seq, Some(writer.seq.0 - 1));
    assert_eq!(active_meta.record_tail_hash, writer.last_hash);
    assert!(!session::page(&fixture.0, &tenant, None, None, Some(1)).index_ready);
    drop(outer);
    session_maintenance::flush().unwrap();
    assert!(matches!(
        publication.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(inner);
    session_maintenance::flush().unwrap();
    deadline.receive(&publication, "latest coalesced publication became runnable");
    assert_current(&writer);
    let meta = session::meta(&fixture.0, writer.run_id()).unwrap();
    assert_eq!(meta.turns, 3);
    assert_eq!(meta.last_outcome, Some(Outcome::Done));
    let page = session::page(&fixture.0, &tenant, None, None, Some(1));
    assert!(page.index_ready);
    assert_eq!(page.sessions.len(), 1);
    assert_eq!(page.sessions[0].record_tail_seq, meta.record_tail_seq);
    assert_eq!(page.sessions[0].record_tail_hash, meta.record_tail_hash);
    let seq = writer.next_sequence();
    let bytes = std::fs::read(writer.path()).unwrap();
    let run = writer.run_id().clone();
    drop(writer);

    let mut reopened = Rollout::open_existing(&fixture.0, &run, tenant).unwrap();
    assert_eq!(reopened.next_sequence(), seq);
    assert_eq!(std::fs::read(reopened.path()).unwrap(), bytes);
    let activity = reopened.foreground_activity().unwrap();
    assert_eq!(reopened.append(&notice("after cold reopen")).unwrap(), seq);
    assert!(reopened.refresh_session_cache_async().unwrap());
    drop(activity);
    session_maintenance::flush().unwrap();
    assert_current(&reopened);
    let replayed = replay(reopened.path()).unwrap();
    assert_eq!(replayed.len() as u64, seq.0 + 1);
    assert!(
        matches!(&replayed.last().unwrap().kind, EventKind::Notice { text }
        if text == "after cold reopen")
    );
}

#[test]
fn publication_admission_uses_canonical_runs_and_tenant() {
    let fixture = Fixture::new("scope");
    let other = Fixture::new("other-runs");
    let tenant = TenantId::default();
    let mut publisher = fixture.writer("publisher", &tenant);
    let mut same_scope = seed(&fixture.0.join("."), "other-run", &tenant);
    let mut other_tenant = fixture.writer("other-tenant", &TenantId("other".into()));
    let mut other_runs = other.writer("other-runs", &tenant);
    let deadline = Deadline::new();
    std::thread::scope(|threads| {
        let mut pause = PublicationPause::install(&fixture.0, &tenant, deadline);
        assert!(publisher.refresh_session_cache_async().unwrap());
        deadline.receive(&pause.entered, "scoped publisher entered");
        let (waiting, receipt) = mpsc::channel();
        let _hook = install_foreground_wait_hook(
            &fixture.0,
            &tenant,
            Box::new(move || {
                let _ = waiting.send(());
            }),
        )
        .unwrap();
        let (finished, result) = mpsc::channel();
        threads.spawn(move || {
            let activity = same_scope.foreground_activity().unwrap();
            same_scope
                .append(&notice("same scope after publication"))
                .unwrap();
            drop(activity);
            let _ = finished.send(same_scope);
        });
        deadline.receive(&receipt, "canonical alias and another run share admission");

        let independent_tenant = other_tenant.foreground_activity().unwrap();
        other_tenant.append(&notice("independent tenant")).unwrap();
        let independent_runs = other_runs.foreground_activity().unwrap();
        other_runs
            .append(&notice("independent runs directory"))
            .unwrap();
        assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(independent_tenant);
        drop(independent_runs);
        pause.release.release();
        let same_scope = deadline.receive(&result, "same-scope foreground resumed");
        let first = publisher.foreground_activity().unwrap();
        let second = same_scope.foreground_activity().unwrap();
        drop(first);
        drop(second);
    });
}

#[test]
fn external_store_lock_still_returns_bounded_busy_without_advancing_wal() {
    let fixture = Fixture::new("external-lock");
    let tenant = TenantId::default();
    let mut writer = fixture.writer("external-lock", &tenant);
    let before = std::fs::read(writer.path()).unwrap();
    let seq = writer.next_sequence();
    let hash = writer.last_hash.clone();
    let lock_path = fixture
        .0
        .join(".content/v1")
        .join(hex::encode(Sha256::digest(tenant.0.as_bytes())))
        .join("store.lock");
    let deadline = Deadline::new();
    let writer = std::thread::scope(|threads| {
        // This is the actual OS file lock, outside cooperative admission. Its wait budget must
        // remain finite even when the same-process publication race has been removed.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        held.try_lock().unwrap();
        let (finished, result) = mpsc::channel();
        threads.spawn(move || {
            let activity = writer.foreground_activity().unwrap();
            let result = writer.append(&notice("blocked append"));
            drop(activity);
            let _ = finished.send((writer, result));
        });
        let (mut writer, result) = deadline.receive(&result, "external lock returned bounded Busy");
        assert!(matches!(
            result,
            Err(RecordError::PrivateContent(ContentStoreError::Busy))
        ));
        assert_eq!(std::fs::read(writer.path()).unwrap(), before);
        assert_eq!(writer.next_sequence(), seq);
        assert_eq!(writer.last_hash, hash);
        assert!(
            !writer.poisoned,
            "no WAL I/O was attempted under a refused CAS lease"
        );
        drop(held);
        assert_eq!(
            writer
                .append(&notice("after external lock release"))
                .unwrap(),
            seq
        );
        writer
    });
    let replayed = replay(writer.path()).unwrap();
    assert_eq!(replayed.len() as u64, seq.0 + 1);
    assert!(
        matches!(&replayed.last().unwrap().kind, EventKind::Notice { text }
        if text == "after external lock release")
    );
}

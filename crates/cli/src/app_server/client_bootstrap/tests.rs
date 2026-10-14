use super::*;
use iteron_protocol::{Effort, Event, EventKind, Message, Seq, SessionId, TenantId, TurnId};

struct Fixture {
    root: PathBuf,
    factory: Arc<ClientBootstrapFactory>,
}
impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-host-bootstrap-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let runs = root.join("runs");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let run = RunId("bootstrap-origin".into());
        record(&runs, &workspace, &run);
        let reader = ContractReader::default();
        reader.bind_identity(SessionId(format!("session-{}", run.0)), run);
        Self {
            root: root.clone(),
            factory: Arc::new(ClientBootstrapFactory {
                workspace,
                runs_dir: Some(runs),
                config_home: Some(root.join("home")),
                reader,
                busy: AtomicBool::new(false),
                published: AtomicBool::new(false),
                worker_pause: std::sync::Mutex::new(None),
            }),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn record(runs: &std::path::Path, workspace: &std::path::Path, run: &RunId) {
    let mut rollout = iteron_record::Rollout::open(runs, run, TenantId::default()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: workspace.to_string_lossy().into_owned(),
                model: "m".into(),
                effort: Effort::Medium,
                created_at: 1,
                environment: None,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest: "cfg".into(),
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
                message: Message::user_text("actual recorded operator source"),
            },
        })
        .unwrap();
}

#[tokio::test]
async fn actual_host_writer_uses_current_adopted_source_and_hydrates_only_private_state() {
    let fixture = Fixture::new("adopt");
    let prepared = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap()
        .install()
        .unwrap();
    assert_eq!(prepared.source_run.0, "bootstrap-origin");
    let next = RunId("bootstrap-next".into());
    record(
        fixture.factory.runs_dir.as_ref().unwrap(),
        &fixture.factory.workspace,
        &next,
    );
    fixture
        .factory
        .reader
        .bind_identity(SessionId("session-bootstrap-next".into()), next.clone());
    assert!(prepared.writer.finish_bounded(State::new(
        vec!["keep exact words".into()],
        Some("draft".into())
    )));
    assert!(
        fixture
            .factory
            .clone()
            .hydrate(PromptHistoryMode::Project)
            .await
            .is_err(),
        "one host mints one physical writer"
    );
    let store = crate::prompt_history::Store::resolve_with_runs_dir(
        PromptHistoryMode::Project,
        fixture.factory.config_home.clone().unwrap(),
        &fixture.factory.workspace,
        fixture.factory.runs_dir.clone().unwrap(),
    )
    .unwrap()
    .unwrap();
    let state = store.load(&next).unwrap();
    assert_eq!(state.history, ["keep exact words"]);
    assert_eq!(state.draft.as_deref(), Some("draft"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_observer_retains_real_worker_slot_and_stale_hydration_is_refused() {
    let fixture = Fixture::new("cancel");
    let (started, start) = std::sync::mpsc::sync_channel(1);
    let (resume, release) = std::sync::mpsc::sync_channel(1);
    *fixture.factory.worker_pause.lock().unwrap() = Some((started, release));
    let factory = fixture.factory.clone();
    let observer = tokio::spawn(async move { factory.hydrate(PromptHistoryMode::Disabled).await });
    tokio::task::spawn_blocking(move || start.recv_timeout(std::time::Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    observer.abort();
    let _ = observer.await;
    assert!(
        fixture
            .factory
            .clone()
            .hydrate(PromptHistoryMode::Disabled)
            .await
            .is_err()
    );
    fixture
        .factory
        .reader
        .bind_identity(SessionId("session-changed".into()), RunId("changed".into()));
    resume.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.factory.busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !fixture.root.join("home").exists(),
        "disabled prompt history creates no store"
    );
}

#[tokio::test]
async fn storage_refusal_is_shutdown_debt_not_a_confirmed_flush() {
    let fixture = Fixture::new("refusal");
    let prepared = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap()
        .install()
        .unwrap();
    let storage = fixture.root.join("home");
    assert!(
        !storage.exists(),
        "hydrating absent prompt history does not create its manifest namespace"
    );
    std::fs::write(&storage, b"blocked storage namespace").unwrap();
    assert!(
        !prepared
            .writer
            .finish_bounded(State::new(vec!["no invented lineage".into()], None))
    );
    assert_eq!(
        std::fs::read(storage).unwrap(),
        b"blocked storage namespace"
    );
}

#[test]
fn queue_admission_bounds_owned_capacity_before_writer_submission() {
    let mut text = String::with_capacity(1024 * 1024 + 1);
    text.push('x');
    assert!(!admissible(&State::new(vec![text], None)));
    assert!(!admissible(&State::new(vec!["x".into(); 201], None)));
    assert!(admissible(&State::new(vec!["normal".into()], None)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_observer_releases_only_after_physical_reads_and_allows_real_retry() {
    let fixture = Fixture::new("lost-observer");
    let (started, start) = std::sync::mpsc::sync_channel(1);
    let (resume, release) = std::sync::mpsc::sync_channel(1);
    *fixture.factory.worker_pause.lock().unwrap() = Some((started, release));
    let factory = fixture.factory.clone();
    let observer = tokio::spawn(async move { factory.hydrate(PromptHistoryMode::Project).await });
    tokio::task::spawn_blocking(move || start.recv_timeout(std::time::Duration::from_secs(2)))
        .await
        .unwrap()
        .unwrap();
    observer.abort();
    let _ = observer.await;
    assert!(fixture.factory.busy.load(Ordering::Acquire));
    assert!(!fixture.factory.published.load(Ordering::Acquire));
    assert!(
        fixture
            .factory
            .clone()
            .hydrate(PromptHistoryMode::Project)
            .await
            .is_err()
    );
    resume.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.factory.busy.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!fixture.factory.published.load(Ordering::Acquire));
    let installed = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap()
        .install()
        .unwrap();
    assert!(
        installed
            .writer
            .finish_bounded(State::new(vec!["retry actually persisted".into()], None))
    );
    let store = crate::prompt_history::Store::resolve_with_runs_dir(
        PromptHistoryMode::Project,
        fixture.factory.config_home.clone().unwrap(),
        &fixture.factory.workspace,
        fixture.factory.runs_dir.clone().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        store
            .load(&RunId("bootstrap-origin".into()))
            .unwrap()
            .history,
        ["retry actually persisted"]
    );
}

#[tokio::test]
async fn uninstalled_drafts_do_not_publish_and_only_one_observed_draft_installs() {
    let fixture = Fixture::new("draft-drop");
    let abandoned = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap();
    assert!(!fixture.factory.published.load(Ordering::Acquire));
    drop(abandoned);
    let first = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap();
    let second = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap();
    let installed = first.install().unwrap();
    assert!(
        second.install().is_err(),
        "second draft cannot mint a second writer"
    );
    assert!(
        installed
            .writer
            .finish_bounded(State::new(vec!["one installation".into()], None))
    );
}

#[tokio::test]
async fn observed_draft_refuses_adoption_before_writer_installation() {
    let fixture = Fixture::new("stale-install");
    let draft = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap();
    let next = RunId("bootstrap-before-install".into());
    record(
        fixture.factory.runs_dir.as_ref().unwrap(),
        &fixture.factory.workspace,
        &next,
    );
    fixture
        .factory
        .reader
        .bind_identity(SessionId("session-before-install".into()), next);
    assert!(draft.install().is_err());
    assert!(!fixture.factory.published.load(Ordering::Acquire));
    let installed = fixture
        .factory
        .clone()
        .hydrate(PromptHistoryMode::Project)
        .await
        .unwrap()
        .install()
        .unwrap();
    assert_eq!(installed.source_run.0, "bootstrap-before-install");
    assert!(
        installed
            .writer
            .finish_bounded(State::new(vec!["new actual source".into()], None))
    );
}

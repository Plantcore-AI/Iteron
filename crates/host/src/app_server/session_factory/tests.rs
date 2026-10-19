use super::{PreparationOrigin, SessionFactory, SubmissionExclusion};
use crate::app_server::{Op, navigation_agent, wire};
use iteron_protocol::{RunId, session_navigation::SessionNavigationV1};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
fn root() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-session-factory-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}
#[tokio::test]
async fn queued_sq_entry_and_cancel_refuse_before_new_record_creation() {
    let root = root();
    let agent = navigation_agent(&root);
    let (handle, mut ends) = wire().unwrap();
    ends.events.bind_lifecycle_identity(
        iteron_protocol::SessionId("fixture-thread".into()),
        agent.rollout.run_id().clone(),
    );
    let factory = SessionFactory::capture(&agent, &handle.client).unwrap();
    let scope = handle.client.thread_snapshot_v1().unwrap();
    let origin = || PreparationOrigin {
        thread: scope.thread_id.clone(),
        run: scope.run_id.clone(),
        selection: crate::providers::ModelSelection {
            provider_id: "fixture-navigation".into(),
            model_id: "m".into(),
        },
        checkpoint: agent.tunables_checkpoint().unwrap().clone(),
    };
    let command = || SessionNavigationV1::New {
        thread_id: scope.thread_id.clone(),
        run_id: scope.run_id.clone(),
    };
    let before = std::fs::read_dir(root.join(".iteron/runs"))
        .unwrap()
        .count();
    handle
        .client
        .submit(Op::Steer {
            text: "retained operator input".into(),
        })
        .unwrap();
    let error = factory
        .prepare(origin(), command(), None)
        .await
        .err()
        .unwrap();
    assert!(error.contains("pending priority"));
    assert_eq!(
        std::fs::read_dir(root.join(".iteron/runs"))
            .unwrap()
            .count(),
        before
    );
    let queued = ends.priority_submissions.recv().await.unwrap();
    assert!(
        factory.prepare(origin(), command(), None).await.is_err(),
        "dequeued safe-point entry still holds the actual slot"
    );
    drop(queued);
    let cancelled = Arc::new(AtomicBool::new(true));
    assert!(
        factory
            .prepare(origin(), command(), Some(cancelled))
            .await
            .err()
            .unwrap()
            .contains("cancelled")
    );
    assert_eq!(
        std::fs::read_dir(root.join(".iteron/runs"))
            .unwrap()
            .count(),
        before
    );
    let prepared = factory.prepare(origin(), command(), None).await.unwrap();
    let run = prepared.run_id().clone();
    assert_ne!(run, scope.run_id);
    assert!(
        handle
            .client
            .submit(Op::Steer {
                text: "during physical preparation".into()
            })
            .is_err()
    );
    assert!(
        iteron_record::Rollout::open_existing(
            &root.join(".iteron/runs"),
            &run,
            iteron_protocol::TenantId::default()
        )
        .is_err()
    );
    drop(prepared);
    let writer = iteron_record::Rollout::open_existing(
        &root.join(".iteron/runs"),
        &run,
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    drop(writer);
    assert!(
        handle
            .client
            .submit(Op::Steer {
                text: "after lease release".into()
            })
            .is_ok()
    );
    drop(factory);
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn cancellation_of_observer_retains_actual_queue_exclusion_until_physical_worker_finishes() {
    let data = Arc::new(Semaphore::new(2));
    let priority = Arc::new(Semaphore::new(1));
    let exclusion = SubmissionExclusion::capture(data.clone(), priority.clone()).unwrap();
    let admission = exclusion.try_exclude().unwrap();
    let (started, started_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let observer = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let _ = started.send(());
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        })
        .await
        .unwrap();
    });
    started_rx.await.unwrap();
    observer.abort();
    let _ = observer.await;
    assert!(data.clone().try_acquire_owned().is_err());
    assert!(priority.clone().try_acquire_owned().is_err());
    release.send(()).unwrap();
    let all = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        data.clone().acquire_many_owned(2),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(priority.try_acquire_owned().is_ok());
    drop(all);
}
#[tokio::test]
async fn captured_tenant_workspace_and_unavailable_route_never_create_a_new_run() {
    let root = root();
    let agent = navigation_agent(&root);
    let (handle, mut ends) = wire().unwrap();
    ends.events.bind_lifecycle_identity(
        iteron_protocol::SessionId("fixture-thread".into()),
        agent.rollout.run_id().clone(),
    );
    let factory = SessionFactory::capture(&agent, &handle.client).unwrap();
    let scope = handle.client.thread_snapshot_v1().unwrap();
    let other = root.join("other-workspace");
    std::fs::create_dir_all(&other).unwrap();
    let mut foreign = iteron_record::Rollout::open(
        &root.join(".iteron/runs"),
        &RunId("foreign-workspace".into()),
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    foreign
        .append(&iteron_protocol::Event {
            seq: iteron_protocol::Seq::ZERO,
            turn: iteron_protocol::TurnId(0),
            kind: iteron_protocol::EventKind::RunStart {
                cwd: other.display().to_string(),
                model: "m".into(),
                effort: iteron_protocol::Effort::Low,
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
    drop(foreign);
    let origin = || PreparationOrigin {
        thread: scope.thread_id.clone(),
        run: scope.run_id.clone(),
        selection: crate::providers::ModelSelection {
            provider_id: "missing".into(),
            model_id: "m".into(),
        },
        checkpoint: agent.tunables_checkpoint().unwrap().clone(),
    };
    let before = std::fs::read_dir(root.join(".iteron/runs"))
        .unwrap()
        .count();
    let error = factory
        .prepare(
            origin(),
            SessionNavigationV1::Resume {
                thread_id: scope.thread_id.clone(),
                run_id: scope.run_id.clone(),
                target_run_id: RunId("foreign-workspace".into()),
            },
            None,
        )
        .await
        .err()
        .unwrap();
    assert!(error.contains("another workspace"));
    assert!(
        factory
            .prepare(
                origin(),
                SessionNavigationV1::New {
                    thread_id: scope.thread_id.clone(),
                    run_id: scope.run_id.clone()
                },
                None
            )
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(root.join(".iteron/runs"))
            .unwrap()
            .count(),
        before
    );
    drop(factory);
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

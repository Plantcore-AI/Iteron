//! Actual resident Agent, durable controller epoch and current isolated-memory prefix.
use super::{
    AgentActor, AgentCommandV1, AgentStateV1, Arc, Ordering, ProviderFixture, Store, Workspace,
    setup_with_financial_and_memory, spawn, until,
};
use crate::runtime::persistent_agents::AgentControlPort;
use iteron_ctx::{
    MemoryStore,
    memory_records::{MemoryInvalidation, MemoryRecordDraft, MemoryRecordOwner},
};

async fn current_memory_after_next_epoch(delete: bool) {
    let workspace = Workspace::new();
    let memory_workspace = workspace.0.join("isolated-child-memory");
    std::fs::create_dir(&memory_workspace).unwrap();
    let store = MemoryStore::at(&memory_workspace);
    let body = "quartz_resident_memory: archive the violet calibration reference";
    let id = store.add(body).unwrap();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _port) = setup_with_financial_and_memory(
        &workspace,
        provider.clone(),
        false,
        Store::default(),
        500_000,
        true,
        Some(memory_workspace.clone()),
    );
    let child = spawn(&host, "look up quartz_resident_memory calibration");
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    assert!(provider.systems.lock().unwrap()[0].contains(body));
    let first_view = host.inspect(AgentActor::Operator, child).unwrap();
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    let run_id = resident.lock().await.rollout.run_id().clone();
    if delete {
        assert!(store.remove_checked(&id).unwrap());
    } else {
        // Publish an explicitly already-expired version. The next real epoch must decide
        // freshness from current owner metadata, without depending on a wall-clock sleep.
        let mut owner =
            MemoryRecordOwner::open(&iteron_protocol::home::path(&memory_workspace, "memory"))
                .unwrap();
        let revision = owner
            .records()
            .find(|record| record.id == id)
            .unwrap()
            .revision;
        let mut metadata =
            MemoryRecordDraft::workspace(&memory_workspace, "expiry-fixture", 10).unwrap();
        metadata.invalidation = MemoryInvalidation::ExpiresAt { unix_seconds: 20 };
        owner.update(&id, revision, body, metadata).unwrap();
    }
    host.command(
        AgentActor::Operator,
        "next-memory-epoch",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "look up quartz_resident_memory calibration again".into(),
        },
    )
    .unwrap();
    until(|| {
        provider.requests.load(Ordering::SeqCst) == 2
            && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    {
        let systems = provider.systems.lock().unwrap();
        assert!(
            !systems[1].contains(body),
            "a new epoch must not reuse the stale memory prefix"
        );
    }
    let second_view = host.inspect(AgentActor::Operator, child).unwrap();
    assert_eq!(first_view.incarnation, second_view.incarnation);
    assert_eq!(first_view.agent_id, second_view.agent_id);
    assert!(second_view.usage.turns > first_view.usage.turns);
    let retained = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    assert!(Arc::ptr_eq(&resident, &retained));
    assert_eq!(resident.lock().await.rollout.run_id(), &run_id);
}

#[tokio::test]
async fn actual_resident_child_next_epoch_excludes_deleted_memory() {
    current_memory_after_next_epoch(true).await;
}

#[tokio::test]
async fn actual_resident_child_next_epoch_excludes_expired_memory() {
    current_memory_after_next_epoch(false).await;
}

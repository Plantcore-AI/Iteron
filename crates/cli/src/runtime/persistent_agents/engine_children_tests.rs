use super::super::{AgentSettlement, LiveAgentMailbox, PersistentAgentRuntime};
use super::*;
use async_trait::async_trait;
use iteron_agents::{
    AgentController, AgentControllerConfig, AgentControllerJournal, AgentControllerSnapshot,
    AgentWorkflowTerminal, ControllerStoreError,
};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentEpochV1, AgentIdV1, AgentViewV1};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Default)]
struct Store {
    snapshot: Option<AgentControllerSnapshot>,
    delay_next: Arc<Mutex<bool>>,
}
impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.snapshot.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self
            .snapshot
            .as_ref()
            .map(AgentControllerSnapshot::revision)
            != expected
        {
            return Err(ControllerStoreError::Conflict);
        }
        if std::mem::take(&mut *self.delay_next.lock().unwrap()) {
            std::thread::sleep(Duration::from_millis(40));
        }
        self.snapshot = Some(next.clone());
        Ok(())
    }
}
struct Runtime {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}
#[async_trait]
impl PersistentAgentRuntime for Runtime {
    fn validate_spawn(&self, _: &AgentCommandV1) -> Result<(), ControllerError> {
        Ok(())
    }
    async fn execute(
        &self,
        _: AgentViewV1,
        _: AgentEpochV1,
        _: Vec<iteron_agents::AgentMailboxMessage>,
        _: LiveAgentMailbox,
    ) -> AgentSettlement {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        AgentSettlement {
            turns: 1,
            summary: "actual hosted runtime terminal".into(),
            tokens: 0,
            cost_microusd: 0,
            effects_known: true,
            terminal: AgentWorkflowTerminal::Succeeded,
        }
    }
}
fn budget() -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns: 4,
        tokens: 4000,
        cost_microusd: 0,
        wall_ms: 60000,
    }
}
fn spawn() -> AgentCommandV1 {
    AgentCommandV1::Spawn {
        parent_id: AgentIdV1(1),
        label: "actual-engine".into(),
        task: "actual child task".into(),
        capabilities: CapabilitySet::only(Capability::ReadOnly),
        budget: budget(),
        write_paths: vec![],
    }
}
fn binding(wall: u64) -> AgentWorkflowChildBinding {
    AgentWorkflowChildBinding {
        workflow_id: "actual-engine".into(),
        node_id: 1,
        attempt: 1,
        input_digest: "a".repeat(64),
        execution: None,
        deadline_unix_ms: u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + wall,
    }
}
fn host(runtime: Arc<Runtime>, delay: Arc<Mutex<bool>>) -> PersistentAgentHost<Store> {
    let controller = AgentController::open(
        Store {
            snapshot: None,
            delay_next: delay,
        },
        AgentControllerConfig {
            workspace_scope: "host-engine-fixture".into(),
            root_capabilities: CapabilitySet::only(Capability::ReadOnly),
            root_budget: AgentBudgetV1 {
                turns: 20,
                tokens: 20000,
                ..budget()
            },
            max_agents: 8,
            max_pending_per_agent: 8,
        },
    )
    .unwrap();
    PersistentAgentHost::new(controller, runtime, 1).unwrap()
}
#[tokio::test]
async fn occupied_actual_runtime_slot_does_not_refuse_exact_replayed_admission() {
    let runtime = Arc::new(Runtime {
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let host = host(runtime.clone(), Arc::new(Mutex::new(false)));
    let frozen = binding(60000);
    let first = host
        .spawn_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            "engine-replay",
            spawn(),
            frozen.clone(),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), runtime.entered.notified())
        .await
        .unwrap();
    let replayed = host
        .spawn_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            "engine-replay",
            spawn(),
            frozen,
        )
        .unwrap();
    assert!(replayed.lease.replayed);
    assert_eq!(replayed.lease.epoch, first.lease.epoch);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    runtime.release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if host
                .engine_child_completion(&first.claim)
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn absolute_deadline_expired_during_real_commit_performs_zero_runtime_dispatch() {
    let runtime = Arc::new(Runtime {
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let delay = Arc::new(Mutex::new(false));
    let host = host(runtime.clone(), delay.clone());
    *delay.lock().unwrap() = true;
    let admitted = host
        .spawn_engine_child(
            AgentActor::Agent(AgentIdV1(1)),
            "engine-expired",
            spawn(),
            binding(20),
        )
        .unwrap();
    let completion = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(done) = host.engine_child_completion(&admitted.claim).unwrap() {
                break done;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert_eq!(completion.terminal, AgentWorkflowTerminal::Failed);
    assert!(completion.effects_known);
    assert_eq!(completion.usage.cost_microusd, 0);
}

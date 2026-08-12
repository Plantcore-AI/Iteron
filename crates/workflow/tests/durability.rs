//! Public physical workflow entry points must refuse an absent durable ledger before a child can
//! be dispatched. The mock count is the effect oracle; the typed error is the caller contract.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use iteron_workflow::events::NullSink;
use iteron_workflow::{
    AgentCall, AgentOutcome, AgentSpawner, RunSpec, WorkflowDurabilityRequired, WorkflowEngine,
};

#[derive(Default)]
struct CountingSpawner(AtomicUsize);

#[async_trait]
impl AgentSpawner for CountingSpawner {
    async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        AgentOutcome::text("unexpected physical child", 0)
    }
}

fn is_durability_refusal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<WorkflowDurabilityRequired>().is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_public_physical_entry_refuses_missing_durability_before_spawn() {
    let spawner = Arc::new(CountingSpawner::default());
    let script = "return await agent('must-not-run');";

    let execute_error =
        WorkflowEngine::execute(RunSpec::new(script), spawner.clone(), Arc::new(NullSink))
            .await
            .expect_err("execute without a durable root must fail closed");
    assert!(is_durability_refusal(&execute_error));

    let launch_error =
        WorkflowEngine::launch(RunSpec::new(script), spawner.clone(), Arc::new(NullSink))
            .join()
            .await
            .expect_err("launch without a durable root must fail closed");
    assert!(is_durability_refusal(&launch_error));

    let run_error = WorkflowEngine::run(
        script,
        serde_json::Value::Null,
        spawner.clone(),
        Arc::new(NullSink),
    )
    .await
    .expect_err("legacy run cannot manufacture an in-memory physical authority");
    assert!(is_durability_refusal(&run_error));

    assert_eq!(spawner.0.load(Ordering::SeqCst), 0);
}

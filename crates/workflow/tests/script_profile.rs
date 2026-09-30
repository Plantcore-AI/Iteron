//! Default builds refuse script effects while leaving the generic live scheduler available.

#![cfg(not(feature = "script-workflows"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use iteron_workflow::{
    AgentCall, AgentOutcome, AgentSpawner, NullSink, RunSpec, ScriptWorkflowsUnavailable,
    WorkflowEngine,
};

#[derive(Default)]
struct EffectOracle(AtomicUsize);

#[async_trait]
impl AgentSpawner for EffectOracle {
    async fn spawn(&self, _: AgentCall) -> AgentOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        AgentOutcome::text("unreachable", 1)
    }
}

#[tokio::test]
async fn disabled_profile_refuses_before_directory_or_child_effect() {
    let root = std::env::temp_dir().join(format!("iteron-script-off-{}", std::process::id()));
    assert!(!root.exists());
    let spawner = Arc::new(EffectOracle::default());
    let spec = RunSpec::new("agent('must not run')").with_workflows_dir(&root);
    let error = WorkflowEngine::execute(spec.clone(), spawner.clone(), Arc::new(NullSink))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ScriptWorkflowsUnavailable>().is_some());
    let handle = WorkflowEngine::launch(spec, spawner.clone(), Arc::new(NullSink));
    let error = handle.join().await.unwrap_err();
    assert!(error.downcast_ref::<ScriptWorkflowsUnavailable>().is_some());
    assert_eq!(spawner.0.load(Ordering::SeqCst), 0);
    assert!(!root.exists());
    assert!(iteron_workflow::validate_script("while (true) {}").is_err());
    assert!(iteron_workflow::extract_meta("export const meta = {name:'no'}").is_none());
}

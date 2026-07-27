//! End-to-end proof of the vertical slice with a deterministic mock spawner (no network): a real
//! 2-agent `parallel()` runs through the QuickJS engine, streams progress, and returns a
//! declaration-ordered array. This is the CI-safe twin of the CLI's real-model run.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use core_workflow::events::{ProgressEvent, ProgressSink};
use core_workflow::{AgentCall, AgentOutcome, AgentSpawner, WorkflowEngine};

struct MockSpawner {
    delay_ms: u64,
}

#[async_trait]
impl AgentSpawner for MockSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        AgentOutcome::text(format!("result:{}", call.prompt), 7)
    }
}

#[derive(Default)]
struct VecSink {
    events: Mutex<Vec<ProgressEvent>>,
}

impl ProgressSink for VecSink {
    fn emit(&self, event: ProgressEvent) {
        self.events.lock().unwrap().push(event);
    }
}

const SCRIPT: &str = r#"export const meta = { name: 'test', description: 'parallel proof', phases: [] };
log('start');
const results = await parallel([
  () => agent('A'),
  () => agent('B'),
]);
log('done ' + JSON.stringify(results));
return results;
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_agent_parallel_runs_and_preserves_declaration_order() {
    let spawner = Arc::new(MockSpawner { delay_ms: 120 });
    let sink = Arc::new(VecSink::default());

    let value = WorkflowEngine::run(SCRIPT, serde_json::Value::Null, spawner, sink.clone())
        .await
        .expect("workflow runs");

    assert_eq!(value, serde_json::json!(["result:A", "result:B"]));

    let events = sink.events.lock().unwrap();
    let started = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::AgentStarted { .. }))
        .count();
    let finished = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::AgentFinished { .. }))
        .count();
    let logs = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::Log { .. }))
        .count();
    assert_eq!(started, 2, "both agents started");
    assert_eq!(finished, 2, "both agents finished");
    assert_eq!(logs, 2, "two log() lines");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_throwing_thunk_maps_to_null_at_its_index() {
    let spawner = Arc::new(MockSpawner { delay_ms: 5 });
    let sink = Arc::new(VecSink::default());
    let script = r#"export const meta = { name: 't', description: 'reject', phases: [] };
const r = await parallel([
  () => agent('ok'),
  () => { throw new Error('boom'); },
]);
return r;
"#;

    let value = WorkflowEngine::run(script, serde_json::Value::Null, spawner, sink)
        .await
        .expect("workflow runs");

    assert_eq!(value, serde_json::json!(["result:ok", null]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn determinism_traps_deny_entropy_and_wall_clock() {
    let spawner = Arc::new(MockSpawner { delay_ms: 1 });
    let sink = Arc::new(VecSink::default());
    let script = r#"export const meta = { name: 'd', description: 'traps', phases: [] };
let threw = false;
try { new Date(); } catch (e) { threw = true; }
return {
  mathRandom: typeof Math.random,
  dateNow: typeof Date.now,
  performance: typeof globalThis.performance,
  crypto: typeof globalThis.crypto,
  arglessNewDateThrew: threw,
};
"#;

    let value = WorkflowEngine::run(script, serde_json::Value::Null, spawner, sink)
        .await
        .expect("workflow runs");

    assert_eq!(value["mathRandom"], "undefined");
    assert_eq!(value["dateNow"], "undefined");
    assert_eq!(value["performance"], "undefined");
    assert_eq!(value["crypto"], "undefined");
    assert_eq!(value["arglessNewDateThrew"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn args_global_is_visible_to_the_script() {
    let spawner = Arc::new(MockSpawner { delay_ms: 1 });
    let sink = Arc::new(VecSink::default());
    let script = r#"export const meta = { name: 'a', description: 'args', phases: [] };
return await agent(args.who);
"#;

    let value = WorkflowEngine::run(
        script,
        serde_json::json!({ "who": "Neo" }),
        spawner,
        sink,
    )
    .await
    .expect("workflow runs");

    assert_eq!(value, serde_json::json!("result:Neo"));
}

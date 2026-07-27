//! Integration proofs for the three engine-depth features (design §2.5/§2.6 + review B2/B3), all
//! with deterministic mock spawners (no network):
//!   (a) schema-forced structured output validates + retries -> a validated object, and rejects a
//!       bad shape -> null;
//!   (b) resume replay is a 100% journal cache hit on an identical script+args, INCLUDING a
//!       null-outcome agent replayed as null (the B2 invariant);
//!   (c) `RunHandle::cancel()` stops a running 2-agent workflow.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use core_workflow::events::NullSink;
use core_workflow::{AgentCall, AgentOutcome, AgentSpawner, RunId, RunSpec, WorkflowEngine};

// ---- (a) schema-forced structured output ---------------------------------------------------------

/// Returns valid JSON for `make-good` only after 2 failed attempts (exercising retry), and always
/// invalid JSON for `make-bad` (exercising exhaustion -> null).
#[derive(Default)]
struct SchemaMock {
    good_calls: AtomicUsize,
    bad_calls: AtomicUsize,
}

#[async_trait]
impl AgentSpawner for SchemaMock {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        if call.prompt.contains("make-good") {
            let n = self.good_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let text = if n < 3 {
                r#"{"answer":"not-a-number"}"#
            } else {
                r#"{"answer":42}"#
            };
            AgentOutcome::text(text, 5)
        } else {
            self.bad_calls.fetch_add(1, Ordering::SeqCst);
            AgentOutcome::text(r#"{"answer":"never-valid"}"#, 5)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn schema_validate_retry_returns_object_and_rejects_bad_shape() {
    let spawner = Arc::new(SchemaMock::default());
    let script = r#"export const meta = { name: 'schema', description: '', phases: [] };
const good = await agent('make-good', { schema: args.schema });
const bad  = await agent('make-bad',  { schema: args.schema });
return {
  good: good,
  bad: bad,
  goodIsObject: (good !== null && typeof good === 'object'),
  badIsNull: (bad === null),
};
"#;
    let args = serde_json::json!({
        "schema": {
            "type": "object",
            "required": ["answer"],
            "properties": { "answer": { "type": "number" } },
            "additionalProperties": false
        }
    });

    let value = WorkflowEngine::run(script, args, spawner.clone(), Arc::new(NullSink))
        .await
        .expect("workflow runs");

    // A validated JSON OBJECT is returned to JS (not a string).
    assert_eq!(value["good"], serde_json::json!({ "answer": 42 }));
    assert_eq!(value["goodIsObject"], true);
    // A never-valid shape exhausts the retries and degrades to null.
    assert_eq!(value["bad"], serde_json::Value::Null);
    assert_eq!(value["badIsNull"], true);

    // 2 failed attempts + 1 success = 3 spawner calls for the good agent.
    assert_eq!(spawner.good_calls.load(Ordering::SeqCst), 3);
    // 5 attempts (RETRY_MAX) for the never-valid agent.
    assert_eq!(
        spawner.bad_calls.load(Ordering::SeqCst),
        core_workflow::RETRY_MAX as usize
    );
}

// ---- (b) journal + resume cache (B2) -------------------------------------------------------------

/// Counts every live spawn; returns text for `alpha`, a null outcome for `makenull`.
struct CountingSpawner {
    spawns: Arc<AtomicUsize>,
}

#[async_trait]
impl AgentSpawner for CountingSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        if call.prompt.contains("makenull") {
            AgentOutcome::null("makenull")
        } else {
            AgentOutcome::text(format!("text:{}", call.prompt), 7)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_is_100_percent_cache_hit_including_null_replay() {
    let dir = std::env::temp_dir().join(format!(
        "core-workflow-resume-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let spawns = Arc::new(AtomicUsize::new(0));
    let spawner = Arc::new(CountingSpawner {
        spawns: spawns.clone(),
    });

    let script = r#"export const meta = { name: 'resume', description: '', phases: [] };
const a = await agent('alpha');
const b = await agent('makenull');
return { a: a, b: b };
"#;

    // --- original run: everything is a cache MISS, ran live ---
    let run1 = RunSpec::new(script)
        .with_run_id(RunId::new("r1"))
        .with_workflows_dir(dir.clone());
    let report1 = WorkflowEngine::execute(run1, spawner.clone(), Arc::new(NullSink))
        .await
        .expect("run 1");
    assert_eq!(report1.cache_hits, 0);
    assert_eq!(report1.cache_misses, 2);
    assert_eq!(spawns.load(Ordering::SeqCst), 2, "both agents ran live");
    let expected = serde_json::json!({ "a": "text:alpha", "b": null });
    assert_eq!(report1.value, expected);

    // --- resume: identical script+args -> 100% cache HIT, ZERO live spawns ---
    let run2 = RunSpec::new(script)
        .with_run_id(RunId::new("r2"))
        .with_workflows_dir(dir.clone())
        .with_resume_from(RunId::new("r1"));
    let report2 = WorkflowEngine::execute(run2, spawner.clone(), Arc::new(NullSink))
        .await
        .expect("run 2 (resume)");
    assert_eq!(
        report2.cache_hits, 2,
        "identical script+args => 100% cache hit"
    );
    assert_eq!(report2.cache_misses, 0);
    assert_eq!(
        spawns.load(Ordering::SeqCst),
        2,
        "resume replays from the journal; no new live spawns"
    );
    // The null-outcome agent is replayed as null (B2), and the value is identical.
    assert_eq!(report2.value, expected);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- (c) background launch + cancellation (B3) ---------------------------------------------------

/// Each agent sleeps ~10s unless the run's cancel token trips first (cooperative stop); the engine
/// also aborts the in-flight child on cancel.
struct BlockingSpawner;

#[async_trait]
impl AgentSpawner for BlockingSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        tokio::select! {
            _ = call.cancel.cancelled() => AgentOutcome::null("stopped"),
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                AgentOutcome::text(format!("text:{}", call.prompt), 1)
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_stops_a_running_two_agent_workflow() {
    let script = r#"export const meta = { name: 'cancel', description: '', phases: [] };
return await parallel([() => agent('A'), () => agent('B')]);
"#;
    let spec = RunSpec::new(script);
    let handle = WorkflowEngine::launch(spec, Arc::new(BlockingSpawner), Arc::new(NullSink));

    // Let both agents get in-flight, then stop the run.
    tokio::time::sleep(Duration::from_millis(150)).await;
    handle.cancel();

    // The run resolves promptly as stopped (not after the 10s child sleep).
    let report = tokio::time::timeout(Duration::from_secs(5), handle.join())
        .await
        .expect("join resolves within 5s (children were aborted)")
        .expect("run report");

    assert!(report.stopped, "cancel resolves the run as stopped");
    assert_eq!(report.value, serde_json::Value::Null);
}

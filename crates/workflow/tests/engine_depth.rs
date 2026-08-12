//! Integration proofs for the three engine-depth features (design §2.5/§2.6 + review B2/B3), all
//! with deterministic mock spawners (no network):
//!   (a) schema-forced structured output validates + retries -> a validated object, and rejects a
//!       bad shape -> null;
//!   (b) resume replay is a 100% journal cache hit on an identical script+args, INCLUDING a
//!       null-outcome agent replayed as null (the B2 invariant);
//!   (c) `RunHandle::cancel()` stops a running 2-agent workflow.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use iteron_workflow::events::{NullSink, ProgressEvent, ProgressSink};
use iteron_workflow::{
    AgentCall, AgentOutcome, AgentSpawner, RunId, RunSpec, SchemaRetryPolicy, WorkflowEngine,
};

fn scratch(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "iteron-workflow-engine-depth-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

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

    let value = WorkflowEngine::execute(
        RunSpec::new(script)
            .with_args(args)
            .with_workflows_dir(scratch("schema-retry")),
        spawner.clone(),
        Arc::new(NullSink),
    )
    .await
    .expect("workflow runs")
    .value;

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
        iteron_workflow::RETRY_MAX as usize
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_schema_retry_policy_changes_physical_attempts() {
    let spawner = Arc::new(SchemaMock::default());
    let script = r#"return await agent('make-bad', { schema: args.schema });"#;
    let args = serde_json::json!({
        "schema": {
            "type": "object",
            "required": ["answer"],
            "properties": { "answer": { "type": "number" } },
            "additionalProperties": false
        }
    });
    let policy = SchemaRetryPolicy::new(2, 0, 0).expect("bounded policy");
    let report = WorkflowEngine::execute(
        RunSpec::new(script)
            .with_args(args)
            .with_workflows_dir(scratch("pinned-schema-retry"))
            .with_schema_retry(policy),
        spawner.clone(),
        Arc::new(NullSink),
    )
    .await
    .expect("schema exhaustion is a terminal null, not an engine error");

    assert_eq!(report.value, serde_json::Value::Null);
    assert_eq!(spawner.bad_calls.load(Ordering::SeqCst), 2);
}

// ---- (b) journal + resume cache (B2) -------------------------------------------------------------

/// Counts every live spawn; returns text for `alpha`, a null outcome for `makenull`.
struct CountingSpawner {
    spawns: Arc<AtomicUsize>,
    prompts: Arc<Mutex<Vec<String>>>,
}

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<ProgressEvent>>,
}

impl ProgressSink for RecordingSink {
    fn emit(&self, event: ProgressEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_routing_metadata_is_negative_replay_evidence_without_a_spawn() {
    let dir = std::env::temp_dir().join(format!(
        "iteron-workflow-request-metadata-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let spawns = Arc::new(AtomicUsize::new(0));
    let spawner = Arc::new(CountingSpawner {
        spawns: spawns.clone(),
        prompts: Arc::new(Mutex::new(Vec::new())),
    });
    let sink = Arc::new(RecordingSink::default());
    let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
    let oversized_agent_type = "a".repeat(iteron_workflow::spawner::MAX_AGENT_TYPE_BYTES + 1);
    let oversized_model = "m".repeat(iteron_workflow::spawner::MAX_AGENT_MODEL_BYTES + 1);
    let requests = serde_json::json!([
        {"agentType": "reviewer/child", "label": "invalid type", "phase": secret},
        {"agentType": oversized_agent_type.clone(), "label": "oversized type", "phase": secret},
        {"agentType": format!("reviewer\n{secret}\u{1b}[2J"), "label": "dead\nagent\u{1b}[31m", "phase": secret},
        {"agentType": "reviewer界", "label": "unicode type", "phase": secret},
        {"model": "", "label": "empty model", "phase": secret},
        {"model": oversized_model.clone(), "label": "oversized model", "phase": secret},
        {"model": format!("model\r{secret}\u{202e}"), "label": "control model", "phase": secret},
    ]);
    let request_count = requests.as_array().unwrap().len();
    let args = serde_json::json!({"requests": requests});
    let script = r#"export const meta = { name: 'request-metadata', description: '', phases: [] };
const results = [];
for (const request of args.requests) {
  results.push(await agent('safe prompt', request));
}
return results;
"#;

    let first = RunSpec::new(script)
        .with_args(args.clone())
        .with_run_id(RunId::new("invalid-1"))
        .with_workflows_dir(dir.clone());
    let report = WorkflowEngine::execute(first, spawner.clone(), sink.clone())
        .await
        .expect("invalid metadata settles as null");
    assert_eq!(
        report.value,
        serde_json::Value::Array(vec![serde_json::Value::Null; request_count])
    );
    assert_eq!(report.cache_hits, 0);
    assert_eq!(report.cache_misses, request_count);
    assert_eq!(report.errors, request_count);
    assert_eq!(spawns.load(Ordering::SeqCst), 0);

    {
        let events = sink.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ProgressEvent::AgentQueued { .. }))
                .count(),
            request_count
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ProgressEvent::AgentStarted { .. }))
                .count(),
            0,
            "a metadata refusal never starts a child"
        );
        let mut finished = 0;
        let mut saw_hostile_label = false;
        for event in events.iter() {
            match event {
                ProgressEvent::AgentQueued {
                    label,
                    phase,
                    model,
                    ..
                } => {
                    assert!(
                        !label.starts_with("agent "),
                        "the caller label was discarded"
                    );
                    assert!(!label.chars().any(char::is_control), "{label:?}");
                    if label.starts_with("dead agent") {
                        saw_hostile_label = true;
                        assert!(label.contains("\\u{1b}[31m"), "{label:?}");
                    }
                    assert!(phase.is_none());
                    assert!(model.is_none());
                }
                ProgressEvent::AgentFinished {
                    label,
                    error: Some(error),
                    ..
                } => {
                    finished += 1;
                    assert!(
                        !label.starts_with("agent "),
                        "the caller label was discarded"
                    );
                    assert!(!label.chars().any(char::is_control), "{label:?}");
                    assert!(error.len() <= 128, "{error}");
                    assert!(!error.chars().any(char::is_control), "{error:?}");
                    assert!(!error.contains(secret), "{error}");
                }
                _ => {}
            }
        }
        assert_eq!(finished, request_count);
        assert!(
            saw_hostile_label,
            "the hostile label was dropped rather than neutralized"
        );
    }

    let journal = std::fs::read_to_string(dir.join("invalid-1/journal.jsonl")).unwrap();
    assert!(!journal.contains(secret));
    assert!(!journal.contains(&oversized_agent_type));
    assert!(!journal.contains(&oversized_model));
    let result_reasons: Vec<String> = journal
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|line| {
            line.get("record")?
                .get("outcome")?
                .get("reason")?
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(result_reasons.len(), request_count);
    assert!(result_reasons.iter().all(|reason| {
        reason.len() <= 128 && !reason.chars().any(char::is_control) && !reason.contains(secret)
    }));

    let second = RunSpec::new(script)
        .with_args(args)
        .with_run_id(RunId::new("invalid-2"))
        .with_workflows_dir(dir.clone())
        .with_resume_from(RunId::new("invalid-1"));
    let replay = WorkflowEngine::execute(second, spawner, Arc::new(NullSink))
        .await
        .expect("negative metadata outcomes replay");
    assert_eq!(replay.cache_hits, request_count);
    assert_eq!(replay.cache_misses, 0);
    assert_eq!(replay.errors, request_count);
    assert_eq!(spawns.load(Ordering::SeqCst), 0);
    assert_eq!(replay.value, report.value);

    let _ = std::fs::remove_dir_all(&dir);
}

#[async_trait]
impl AgentSpawner for CountingSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.prompts.lock().unwrap().push(call.prompt.clone());
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
        "iteron-workflow-resume-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let spawns = Arc::new(AtomicUsize::new(0));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let spawner = Arc::new(CountingSpawner {
        spawns: spawns.clone(),
        prompts: prompts.clone(),
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
    // Three live spawns for two script calls: a null outcome is not usable evidence, so the
    // engine escalates once and re-runs that assignment independently. It stays two cache
    // entries, because the escalation belongs to the same assignment as its first attempt.
    assert_eq!(
        spawns.load(Ordering::SeqCst),
        3,
        "both agents ran live, and the null outcome escalated once"
    );
    let live = prompts.lock().unwrap().clone();
    assert_eq!(live.len(), 3);
    assert_eq!(live[0], "alpha");
    assert_eq!(live[1], "makenull");
    assert!(
        live[2].starts_with("makenull\n\nA prior read-only assignee ended without usable evidence"),
        "the third spawn must be the escalation of the null outcome, not a third assignment: {}",
        live[2]
    );
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
        3,
        "resume replays from the journal; no new live spawns beyond run 1's three"
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
    let spec = RunSpec::new(script).with_workflows_dir(scratch("cancel"));
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

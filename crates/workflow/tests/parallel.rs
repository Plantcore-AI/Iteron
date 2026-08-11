//! End-to-end proof of the vertical slice with a deterministic mock spawner (no network): a real
//! 2-agent `parallel()` runs through the QuickJS engine, streams progress, and returns a
//! declaration-ordered array. This is the CI-safe twin of the CLI's real-model run.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, path::PathBuf};

use async_trait::async_trait;
use iteron_workflow::events::{NullSink, ProgressEvent, ProgressSink};
use iteron_workflow::{
    AgentCall, AgentExecutionClass, AgentOutcome, AgentSpawner, EarlyStopQuorumPolicy, RunId,
    RunLimits, RunSpec, SpeculativeSiblingPolicy, TaskFailureAction, TaskRetryPolicy,
    WorkflowEngine,
};

fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "iteron-workflow-h07-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn dag_commands(root: &std::path::Path, run: &str) -> Vec<serde_json::Value> {
    fs::read_to_string(root.join(run).join("task-dag.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|line| line.get("entry")?.get("command").cloned())
        .collect()
}

struct MockSpawner {
    delay_ms: u64,
}

struct SelectiveFailureSpawner {
    failed_prompts: BTreeSet<String>,
}

struct SequencedSpawner {
    calls: Arc<AtomicUsize>,
    first_fails: bool,
}

#[async_trait]
impl AgentSpawner for SequencedSpawner {
    async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
        let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.first_fails && ordinal == 0 {
            return AgentOutcome::null("first assignee failed");
        }
        if ordinal == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        AgentOutcome::text(format!("winner-{ordinal}"), 1)
    }
}

#[async_trait]
impl AgentSpawner for SelectiveFailureSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        if self.failed_prompts.contains(&call.prompt) {
            AgentOutcome::null("agent died")
        } else {
            AgentOutcome::text(format!("result:{}", call.prompt), 7)
        }
    }
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

    let value = WorkflowEngine::execute(
        RunSpec::new(SCRIPT).with_workflows_dir(scratch("parallel-order")),
        spawner,
        sink.clone(),
    )
    .await
    .expect("workflow runs")
    .value;

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
async fn quorum_parallel_cancels_pending_siblings_without_stopping_the_run() {
    let spawner = Arc::new(MockSpawner { delay_ms: 250 });
    let script = r#"return await parallelQuorum([
  () => agent('A'), () => agent('B'), () => agent('C'),
]);"#;
    let spec = RunSpec::new(script)
        .with_workflows_dir(scratch("early-stop"))
        .with_limits(RunLimits::new(1, 3).unwrap())
        .with_early_stop_quorum(EarlyStopQuorumPolicy::new(1, 0, false).unwrap());
    let started = std::time::Instant::now();
    let report = WorkflowEngine::execute(spec, spawner, Arc::new(NullSink))
        .await
        .expect("quorum fan settles");

    assert!(
        !report.stopped,
        "sibling cancellation is not run cancellation"
    );
    assert!(started.elapsed() < Duration::from_millis(700));
    assert_eq!(report.value, serde_json::json!(["result:A", null, null]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_speculation_selects_a_positive_terminal_and_cleans_losers() {
    let root = scratch("speculative-receipt");
    let calls = Arc::new(AtomicUsize::new(0));
    let spawner = Arc::new(SequencedSpawner {
        calls: calls.clone(),
        first_fails: false,
    });
    let spec = RunSpec::new(r#"return await agent('inspect', { speculativeSiblings: 1 });"#)
        .with_run_id(RunId::new("speculative-receipt"))
        .with_workflows_dir(root.clone())
        .with_limits(RunLimits::new(2, 2).unwrap())
        .with_speculative_siblings(
            SpeculativeSiblingPolicy::new(1, Duration::from_secs(1)).unwrap(),
        )
        .with_task_retry(TaskRetryPolicy::new(1, TaskFailureAction::Stop, true).unwrap());
    let report = WorkflowEngine::execute(spec, spawner, Arc::new(NullSink))
        .await
        .expect("speculative call settles");
    assert_eq!(report.value, serde_json::json!("winner-1"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let commands = dag_commands(&root, "speculative-receipt");
    let selected_at = commands
        .iter()
        .position(|command| {
            command["command"] == "send_message"
                && command["message"]["payload"]
                    .as_str()
                    .is_some_and(|payload| {
                        payload.starts_with("speculative_winner:attempt=")
                            && payload.contains(":result_sha256=")
                    })
        })
        .expect("winner selection is durable before sibling cancellation");
    let loser_terminal_at = commands
        .iter()
        .position(|command| {
            command["command"] == "complete_attempt" && command["disposition"] == "loser"
        })
        .expect("losing sibling has its own durable terminal");
    assert!(selected_at < loser_terminal_at);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn definite_negative_task_is_reassigned_with_a_finite_attempt_ceiling() {
    let root = scratch("reassign-lineage");
    let calls = Arc::new(AtomicUsize::new(0));
    let spawner = Arc::new(SequencedSpawner {
        calls: calls.clone(),
        first_fails: true,
    });
    let spec = RunSpec::new(r#"return await agent('inspect');"#)
        .with_run_id(RunId::new("reassign-lineage"))
        .with_workflows_dir(root.clone())
        .with_task_retry(TaskRetryPolicy::new(2, TaskFailureAction::Reassign, true).unwrap());
    let report = WorkflowEngine::execute(spec, spawner, Arc::new(NullSink))
        .await
        .expect("reassigned task settles");
    assert_eq!(report.value, serde_json::json!("winner-1"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let attempts = dag_commands(&root, "reassign-lineage")
        .into_iter()
        .filter(|command| command["command"] == "register_attempt")
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["attempt"]["lineage_version"], 1);
    assert_eq!(attempts[0]["attempt"]["assignment"], "initial");
    assert_eq!(attempts[1]["attempt"]["assignment"], "reassigned");
    assert_eq!(attempts[1]["attempt"]["retry_of"], 1);
    assert_eq!(attempts[1]["attempt"]["retry_cause"], "negative_terminal");
    assert_eq!(
        attempts[1]["attempt"]["prior_evidence_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_dependency_and_assignment_message_are_durable_production_edges() {
    let root = scratch("dependency-message");
    let script = r#"
const first = await agent('A');
const second = await agent('B', { dependsOn: [1] });
return [first, second];
"#;
    let spec = RunSpec::new(script)
        .with_run_id(RunId::new("dependency-message"))
        .with_workflows_dir(root.clone());
    let report = WorkflowEngine::execute(
        spec,
        Arc::new(MockSpawner { delay_ms: 0 }),
        Arc::new(NullSink),
    )
    .await
    .unwrap();
    assert_eq!(report.value, serde_json::json!(["result:A", "result:B"]));

    let commands = dag_commands(&root, "dependency-message");
    let creates = commands
        .iter()
        .filter(|command| command["command"] == "create_task")
        .collect::<Vec<_>>();
    assert_eq!(creates.len(), 2);
    assert_eq!(creates[0]["spec"]["declaration_index"], 1);
    assert_eq!(creates[1]["spec"]["declaration_index"], 2);
    assert_eq!(creates[1]["spec"]["dependencies"], serde_json::json!([1]));
    let assignments = commands
        .iter()
        .filter(|command| command["command"] == "send_message")
        .collect::<Vec<_>>();
    assert_eq!(assignments.len(), 2);
    assert!(assignments.iter().all(|command| {
        command["message"]["payload"]
            .as_str()
            .is_some_and(|payload| payload.starts_with("input_sha256:") && payload.len() == 77)
    }));
    assert_eq!(
        commands
            .iter()
            .filter(|command| command["command"] == "acknowledge_message")
            .count(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

struct WriterClassSpawner {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl AgentSpawner for WriterClassSpawner {
    fn execution_class(&self, _call: &AgentCall) -> AgentExecutionClass {
        AgentExecutionClass::IsolatedWriter
    }

    async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        AgentOutcome::text("must not run", 0)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn speculative_group_refuses_writer_authority_before_physical_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let spec = RunSpec::new(r#"return await agent('write', { speculativeSiblings: 1 });"#)
        .with_workflows_dir(scratch("writer-refusal"))
        .with_limits(RunLimits::new(2, 2).unwrap())
        .with_speculative_siblings(
            SpeculativeSiblingPolicy::new(1, Duration::from_secs(1)).unwrap(),
        );
    let report = WorkflowEngine::execute(
        spec,
        Arc::new(WriterClassSpawner {
            calls: calls.clone(),
        }),
        Arc::new(NullSink),
    )
    .await
    .unwrap();
    assert_eq!(report.value, serde_json::Value::Null);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_counts_one_all_and_no_agent_failures() {
    let cases = [
        (Vec::<&str>::new(), 0usize),
        (vec!["B"], 1usize),
        (vec!["A", "B", "C"], 3usize),
    ];
    let script = r#"return await parallel([
  () => agent('A'), () => agent('B'), () => agent('C'),
]);"#;

    for (failed, expected_errors) in cases {
        let spawner = Arc::new(SelectiveFailureSpawner {
            failed_prompts: failed.into_iter().map(str::to_owned).collect(),
        });
        let spec = RunSpec::new(script)
            .with_workflows_dir(scratch("failure-accounting"))
            .with_task_retry(TaskRetryPolicy::new(1, TaskFailureAction::Stop, true).unwrap());
        let report = WorkflowEngine::execute(spec, spawner, Arc::new(NullSink))
            .await
            .expect("agent failures settle the fan-out");

        assert_eq!(report.errors, expected_errors);
        assert!(!report.stopped);
        assert_eq!(
            report
                .value
                .as_array()
                .unwrap()
                .iter()
                .filter(|value| value.is_null())
                .count(),
            expected_errors
        );
    }
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

    let value = WorkflowEngine::execute(
        RunSpec::new(script).with_workflows_dir(scratch("null-degrade")),
        spawner,
        sink,
    )
    .await
    .expect("workflow runs")
    .value;

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

    let value = WorkflowEngine::execute(
        RunSpec::new(script).with_workflows_dir(scratch("determinism")),
        spawner,
        sink,
    )
    .await
    .expect("workflow runs")
    .value;

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

    let value = WorkflowEngine::execute(
        RunSpec::new(script)
            .with_args(serde_json::json!({ "who": "Neo" }))
            .with_workflows_dir(scratch("args")),
        spawner,
        sink,
    )
    .await
    .expect("workflow runs")
    .value;

    assert_eq!(value, serde_json::json!("result:Neo"));
}

struct BoundedSpawner {
    calls: AtomicUsize,
    inflight: AtomicUsize,
    max_inflight: AtomicUsize,
}

#[async_trait]
impl AgentSpawner for BoundedSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let inflight = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_inflight.fetch_max(inflight, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        AgentOutcome::text(call.prompt, 1)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aggregate_limits_bound_real_spawns_and_concurrency() {
    let spawner = Arc::new(BoundedSpawner {
        calls: AtomicUsize::new(0),
        inflight: AtomicUsize::new(0),
        max_inflight: AtomicUsize::new(0),
    });
    let script = r#"export const meta = { name: 'bounded', description: '', phases: [] };
return await parallel([
  () => agent('A'),
  () => agent('B'),
  () => agent('C'),
  () => agent('D'),
]);"#;
    let spec = RunSpec::new(script)
        .with_workflows_dir(scratch("lifetime-cap"))
        .with_limits(RunLimits::new(2, 2).unwrap());
    let report = WorkflowEngine::execute(spec, spawner.clone(), Arc::new(NullSink))
        .await
        .expect("bounded workflow runs");

    assert_eq!(spawner.calls.load(Ordering::SeqCst), 2);
    assert!(spawner.max_inflight.load(Ordering::SeqCst) <= 2);
    assert_eq!(
        report
            .value
            .as_array()
            .unwrap()
            .iter()
            .filter(|value| !value.is_null())
            .count(),
        2
    );
}

struct WrongVersionSpawner;

#[async_trait]
impl AgentSpawner for WrongVersionSpawner {
    fn port_version(&self) -> u32 {
        99
    }

    async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
        panic!("an incompatible port must be rejected before dispatch")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_spawner_port_version_fails_before_the_script() {
    let error = WorkflowEngine::execute(
        RunSpec::new("return 'unreachable';").with_workflows_dir(scratch("wrong-spawner-version")),
        Arc::new(WrongVersionSpawner),
        Arc::new(NullSink),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("AgentSpawner port version"));
}

/// The queued half of a fan must be visible before any permit is granted. `AgentStarted` used to be
/// emitted only once the Governor admitted a call, so at concurrency 2 a six-agent run showed two
/// rows and a denominator that climbed as slots freed up. Every `AgentQueued` must therefore precede
/// every `AgentStarted`, and the run report must carry the summed tokens/tool calls + an elapsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_rows_precede_every_permit_and_the_report_carries_totals() {
    let spawner = Arc::new(MockSpawner { delay_ms: 40 });
    let sink = Arc::new(VecSink::default());
    let script = r#"export const meta = { name: 'fan', description: '', phases: ['explore'] };
return await parallel([
  () => agent('A'), () => agent('B'), () => agent('C'),
  () => agent('D'), () => agent('E'), () => agent('F'),
]);"#;
    let spec = RunSpec::new(script)
        .with_workflows_dir(scratch("progress-fan"))
        .with_limits(RunLimits::new(2, 16).unwrap());
    let report = WorkflowEngine::execute(spec, spawner, sink.clone())
        .await
        .expect("fan runs");

    let events = sink.events.lock().unwrap();
    let at = |want: fn(&ProgressEvent) -> bool| {
        events
            .iter()
            .enumerate()
            .filter(|(_, event)| want(event))
            .map(|(at, _)| at)
            .collect::<Vec<_>>()
    };
    let queued = at(|e| matches!(e, ProgressEvent::AgentQueued { .. }));
    let started = at(|e| matches!(e, ProgressEvent::AgentStarted { .. }));
    let finished = at(|e| matches!(e, ProgressEvent::AgentFinished { .. }));
    assert_eq!(queued.len(), 6, "every declared agent announces itself");
    assert_eq!(started.len(), 6, "every agent is eventually admitted");
    // No agent's first sighting is its admission: a row exists for it while it waits for a slot.
    for index in 1..=6usize {
        let queued_at = events
            .iter()
            .position(|e| matches!(e, ProgressEvent::AgentQueued { index: i, .. } if *i == index));
        let started_at = events
            .iter()
            .position(|e| matches!(e, ProgressEvent::AgentStarted { index: i, .. } if *i == index));
        assert!(
            queued_at < started_at,
            "agent #{index} was admitted before it was ever declared: {events:?}"
        );
    }
    // The denominator is FIXED before any row settles: at concurrency 2 the last two agents used to
    // appear only after the first four had finished, so `done/total` grew while it was being read.
    assert!(
        queued.iter().max() < finished.iter().min(),
        "the fan was still declaring itself after a row settled: {events:?}"
    );
    assert!(
        queued.iter().max() > started.iter().min(),
        "this run must actually contend for permits, or it proves nothing: {events:?}"
    );

    // 6 agents x 7 tokens each, summed once for the run.
    assert_eq!(report.tokens, 42);
    assert_eq!(report.tool_calls, 0);
    assert!(report.elapsed_ms > 0, "the run carries a wall clock");
}

struct WrongVersionSink;

impl ProgressSink for WrongVersionSink {
    fn port_version(&self) -> u32 {
        1
    }

    fn emit(&self, _event: ProgressEvent) {
        panic!("an incompatible sink must be rejected before dispatch")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_sink_port_version_fails_before_the_script() {
    let error = WorkflowEngine::execute(
        RunSpec::new("return 'unreachable';").with_workflows_dir(scratch("wrong-sink-version")),
        Arc::new(MockSpawner { delay_ms: 0 }),
        Arc::new(WrongVersionSink),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("ProgressSink port version"));
}

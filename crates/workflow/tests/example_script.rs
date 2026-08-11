//! The shipped example workflow script must run exactly as written.
//!
//! A repository whose documentation points at an example nobody executes is how the docs drifted in
//! the first place. This drives `examples/repo-audit.js` through the real engine with a
//! deterministic spawner (no network) and asserts the header, the declared phases, the fan, the
//! schema-forced reduction, and the returned shape.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use iteron_workflow::events::{ProgressEvent, ProgressSink};
use iteron_workflow::{
    AgentCall, AgentOutcome, AgentSpawner, RunSpec, WorkflowEngine, extract_meta,
};

const EXAMPLE: &str = include_str!("../examples/repo-audit.js");

/// Answers plain prompts with text, and the schema-forced reduction with a conforming object.
struct ScriptedSpawner;

#[async_trait]
impl AgentSpawner for ScriptedSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        if call.schema.is_some() {
            return AgentOutcome::text(
                r#"{"summary":"the rollout writer owns append","references":["crates/record/src/lib.rs:1"]}"#,
                11,
            );
        }
        AgentOutcome::text(format!("evidence for: {}", call.prompt), 5)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_example_workflow_script_runs_as_written() {
    let meta = extract_meta(EXAMPLE).expect("the example declares an `export const meta`");
    assert_eq!(meta.name.as_deref(), Some("repo-audit"));
    assert_eq!(
        meta.phases.as_deref(),
        Some(&["explore".to_string(), "synthesize".to_string()][..]),
        "the declared phases are what seed the live tree's layout"
    );

    let sink = Arc::new(VecSink::default());
    let spec =
        RunSpec::new(EXAMPLE).with_args(serde_json::json!({ "topic": "the rollout writer" }));
    let report = WorkflowEngine::execute(spec, Arc::new(ScriptedSpawner), sink.clone())
        .await
        .expect("the shipped example runs");

    assert!(!report.stopped);
    assert_eq!(report.value["topic"], "the rollout writer");
    assert_eq!(report.value["investigators"], 3);
    assert_eq!(report.value["answered"], 3);
    assert_eq!(
        report.value["findings"]["summary"], "the rollout writer owns append",
        "the schema-forced reduction returns a validated object, not prose"
    );
    // 3 investigators x 5 tokens + the 11-token reduction, summed for the run.
    assert_eq!(report.tokens, 26);

    let events = sink.events.lock().unwrap();
    let phases = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::Phase { title, .. } => Some(title.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(phases, ["explore", "synthesize"]);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, ProgressEvent::AgentQueued { .. }))
            .count(),
        4,
        "three investigators plus the reducer each declare a row"
    );
}

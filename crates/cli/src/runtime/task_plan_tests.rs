use super::{TaskPlanInput, TaskPlanOwner};
use crate::runtime::{Agent, Outcome, gate_integration_tests};
use iteron_protocol::{
    Block, Budget, EventKind, RunId, Seq, StopReason, TenantId, ToolUse, TurnId, Usage,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use iteron_record::Rollout;
use std::sync::Arc;

struct Answer;
#[async_trait::async_trait]
impl Provider for Answer {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "answer".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage::default()),
        })
    }
}
fn agent(workspace: &std::path::Path, run: &RunId) -> Agent {
    let rollout = Rollout::open(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    let mut agent = Agent::new(
        Arc::new(Answer),
        iteron_tools::Registry::coding_agent_for_tests(workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        "fixture system".into(),
        Budget::default(),
    );
    agent.workspace = workspace.to_owned();
    // Submission/plan receipts require a real nonzero WAL sequence after the genesis prefix.
    gate_integration_tests::record_test_genesis(&mut agent, workspace);
    agent
}
fn replacement(revision: u64, submission: Seq) -> serde_json::Value {
    serde_json::json!({"operation":"replace","expected_revision":revision,"observed_submission_seq":submission,
        "steps":[{"description":"refactor two modules","status":"in_progress"},{"description":"verify the candidate","status":"pending"}],
        "obligations":["keep existing dirty work"]})
}
fn call(id: &str, input: serde_json::Value) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: iteron_tools::UPDATE_PLAN.into(),
        input,
    }
}

#[tokio::test]
async fn simple_actual_turn_creates_no_plan_or_plan_context() {
    let workspace = gate_integration_tests::temp_ws("simple-no-task-plan");
    let run = RunId("simple-no-task-plan".into());
    let mut owner = agent(&workspace, &run);
    assert_eq!(owner.run("a simple question").await.unwrap(), Outcome::Done);
    assert!(owner.task_plan_snapshot()["plan"].is_null());
    assert!(
        !owner
            .effective_system()
            .contains("Model-maintained task plan")
    );
    let record = owner.rollout.path().to_owned();
    drop(owner);
    assert!(
        !iteron_record::replay(&record)
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::TaskPlanUpdatedV1 { .. }))
    );
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn actual_admitted_steer_requires_plan_revision_and_survives_reopen() {
    let workspace = gate_integration_tests::temp_ws("task-plan-steer");
    let run = RunId("task-plan-steer".into());
    let mut owner = agent(&workspace, &run);
    let mut messages = owner.admit_submission("refactor two modules").unwrap();
    let submission: Seq =
        serde_json::from_value(owner.task_plan_snapshot()["observed_submission_seq"].clone())
            .unwrap();
    assert!(
        !owner
            .execute_task_plan(TurnId(0), &call("plan-one", replacement(0, submission)))
            .unwrap()
            .is_error
    );
    owner
        .inbox
        .push(crate::runtime::inbound_control::PendingSteer::user(
            "also preserve compatibility".into(),
        ))
        .unwrap();
    owner
        .admit_pending_steers(TurnId(0), &mut messages)
        .unwrap();
    assert_eq!(owner.task_plan_snapshot()["needs_review"], true);
    assert!(
        owner
            .execute_task_plan(TurnId(0), &call("stale-plan", replacement(1, submission)))
            .unwrap()
            .is_error
    );
    let current: Seq =
        serde_json::from_value(owner.task_plan_snapshot()["observed_submission_seq"].clone())
            .unwrap();
    assert!(
        !owner
            .execute_task_plan(TurnId(0), &call("plan-two", replacement(1, current)))
            .unwrap()
            .is_error
    );
    assert_eq!(owner.task_plan_snapshot()["revision"], 2);
    assert_eq!(owner.task_plan_snapshot()["needs_review"], false);
    assert!(
        owner
            .effective_system()
            .contains("keep existing dirty work")
    );
    let expected = owner.task_plan_snapshot();
    let record = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&record).unwrap();
    assert_eq!(
        TaskPlanOwner::recover(events.iter()).unwrap().inspect(),
        expected
    );
    let mut resumed = agent(&workspace, &run);
    resumed
        .set_resume(Agent::messages_from_rollout(&record).unwrap())
        .unwrap();
    assert_eq!(resumed.task_plan_snapshot(), expected);
    drop(resumed);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn rejected_publication_does_not_replace_the_actual_plan_state() {
    let mut owner = TaskPlanOwner::default();
    owner.observe_submission(Seq(4));
    let prepared = owner
        .prepare(serde_json::from_value::<TaskPlanInput>(replacement(0, Seq(4))).unwrap())
        .unwrap();
    assert!(owner.publish(prepared, Seq(4)).is_err());
    assert!(owner.inspect()["plan"].is_null());
    owner.observe_submission(Seq(8));
    assert!(
        owner
            .prepare(serde_json::from_value::<TaskPlanInput>(replacement(0, Seq(4))).unwrap())
            .is_err()
    );
}

#[test]
fn oversized_model_plan_is_refused_without_publication_or_state_change() {
    let workspace = gate_integration_tests::temp_ws("task-plan-hostile-envelope");
    let run = RunId("task-plan-hostile-envelope".into());
    let mut owner = agent(&workspace, &run);
    let initial = owner.task_plan_snapshot();
    let mut input = replacement(0, Seq(1));
    input["steps"] = serde_json::Value::Array(
        (0..33)
            .map(|_| {
                serde_json::json!({
                    "description":"request outside the allowed plan envelope", "status":"pending"
                })
            })
            .collect(),
    );
    assert!(
        owner
            .execute_task_plan(TurnId(0), &call("hostile", input))
            .unwrap()
            .is_error
    );
    assert_eq!(owner.task_plan_snapshot(), initial);
    let record = owner.rollout.path().to_owned();
    drop(owner);
    assert!(
        !iteron_record::replay(&record)
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::TaskPlanUpdatedV1 { .. }))
    );
    std::fs::remove_dir_all(workspace).unwrap();
}

//! Physical hook/deadline/WAL evidence at the real group admission boundary.
use crate::runtime::context_runtime::ContextBudgetInspection;
use crate::runtime::deferred_tools::AutoApprovedCall;
use crate::runtime::hooks::{Hooks, journal::HookEffectJournal};
use crate::runtime::{Agent, gate_integration_tests};
use iteron_protocol::{Budget, EventKind, Message, PermissionMode, RunId, TenantId, ToolUse};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
#[cfg(unix)]
use std::time::Duration;
use std::{sync::Arc, time::Instant};
struct NoTransport;
#[async_trait::async_trait]
impl Provider for NoTransport {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("batch admission owns no provider dispatch")
    }
}
fn fixture(label: &str, hook: Option<&str>) -> (Agent, Vec<AutoApprovedCall>, Vec<ToolUse>) {
    let workspace = gate_integration_tests::temp_ws(label);
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId(label.into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NoTransport),
        iteron_tools::Registry::coding_agent_for_tests(&workspace).unwrap(),
        rollout,
        "fixture".into(),
        "fixture".into(),
        Budget::default(),
    );
    agent.workspace = workspace;
    agent.permission_mode = PermissionMode::AcceptEdits;
    if let Some(command) = hook {
        let home = agent.workspace.join("operator-home");
        std::fs::create_dir_all(home.join(".iteron")).unwrap();
        std::fs::write(
            home.join(".iteron/config.json"),
            serde_json::to_vec(&serde_json::json!({"hooks":{"PreToolUse":[command]}})).unwrap(),
        )
        .unwrap();
        agent.hooks = Hooks::load_user(&home);
        agent.set_hook_effect_journal(Some(
            HookEffectJournal::open(&agent.rollout.path().with_extension("hooks.jsonl")).unwrap(),
        ));
    }
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.guard_unresolved_effects().unwrap();
    let calls=(0..2).map(|index|ToolUse{id:format!("batch-{index}"),name:"write_file".into(),input:serde_json::json!({"path":format!("batch-{index}.txt"),"content":"real physical marker"})}).collect::<Vec<_>>();
    let deferred = calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            (
                index,
                call.clone(),
                crate::runtime::strategy_runtime::propose_tool(
                    &agent.registry,
                    agent.tool_policy.as_ref(),
                    call.clone(),
                    iteron_protocol::Trust::Workspace,
                ),
            )
        })
        .collect::<Vec<_>>();
    let batch = agent
        .deferred_batch_policy(&[Message::user_text("write two independent files")])
        .select(&deferred, &Default::default())
        .unwrap();
    assert_eq!(
        batch.len(),
        2,
        "fixture must cross the real concurrent policy"
    );
    (agent, batch, calls)
}
#[tokio::test]
async fn actual_expired_group_opens_no_tool_or_hook_intent() {
    let (mut agent, batch, calls) = fixture("batch-deadline-before", None);
    agent.run_deadline = Some(Instant::now());
    let projection = agent.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        &calls,
    );
    let mut results = vec![None, None];
    let mut error = false;
    let mut images = Vec::new();
    let governor = iteron_sched::Governor::new(2);
    agent
        .deferred_batch_admission(iteron_protocol::TurnId(1), &governor, projection)
        .run(batch, &mut results, &mut error, &mut images)
        .await
        .unwrap();
    assert!(results.iter().all(Option::is_none));
    assert_eq!(agent.ledger.tool_calls, 0);
    assert!(
        !iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(&event.kind, EventKind::EffectIntent { .. }))
    );
}
#[cfg(unix)]
#[tokio::test]
async fn actual_hook_completion_after_deadline_cannot_start_group_tools() {
    let (mut agent, batch, calls) = fixture(
        "batch-deadline-after-hook",
        Some("sleep 0.2; printf actual-hook-completed"),
    );
    agent.run_deadline = Some(Instant::now() + Duration::from_millis(100));
    let projection = agent.turn_result_projection_budget(
        ContextBudgetInspection::from_policy(Default::default(), Default::default()),
        &calls,
    );
    let mut results = vec![None, None];
    let mut error = false;
    let mut images = Vec::new();
    let governor = iteron_sched::Governor::new(2);
    tokio::time::timeout(
        Duration::from_secs(5),
        agent
            .deferred_batch_admission(iteron_protocol::TurnId(1), &governor, projection)
            .run(batch, &mut results, &mut error, &mut images),
    )
    .await
    .unwrap()
    .unwrap();
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(&event.kind,EventKind::EffectIntent{tool,..} if tool=="hook"))
    );
    assert!(
        !events.iter().any(
            |event| matches!(&event.kind,EventKind::EffectIntent{tool,..} if tool=="write_file")
        )
    );
    assert!(results.iter().all(Option::is_none));
    for index in 0..2 {
        assert!(!agent.workspace.join(format!("batch-{index}.txt")).exists());
    }
    assert_eq!(agent.ledger.tool_calls, 0);
}

use super::OrderedCallAdmission;
use crate::runtime::{Agent, Budget, DurableAppendFault, KernelError};
use iteron_protocol::slot::SlotId;
use iteron_protocol::{Capability, EventKind, RunId, TenantId, ToolUse, Trust, TurnId};
use iteron_protocol::{Purity, capability_set::CapabilitySet, intent::ToolIntent};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use std::path::PathBuf;
use std::sync::Arc;

struct NoProviderDispatch;
#[async_trait::async_trait]
impl Provider for NoProviderDispatch {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("an ordered registry owner has no provider dispatch authority")
    }
}
fn fixture() -> (PathBuf, Agent, ToolUse) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "iteron-ordered-owner-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let registry = iteron_tools::Registry::coding_agent_for_tests(&directory).unwrap();
    let rollout = Rollout::open(
        &directory.join(".iteron/runs"),
        &RunId("ordered".into()),
        TenantId::default(),
    )
    .unwrap();
    let budget = Budget {
        max_turns: 5,
        max_usd: None,
        max_tokens: None,
        max_wall_secs: 30,
        max_consecutive_tool_errors: 5,
    };
    let mut agent = Agent::new(
        Arc::new(NoProviderDispatch),
        registry,
        rollout,
        "fixture".into(),
        "system".into(),
        budget,
    );
    agent.workspace = directory.clone();
    let call = ToolUse {
        id: "actual-write".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"result.txt","content":"physical owner write"}),
    };
    (directory, agent, call)
}
fn admission(call: ToolUse) -> OrderedCallAdmission {
    OrderedCallAdmission {
        index: 0,
        capability: Capability::ReversibleLocal,
        action_signature: "actual-native-write".into(),
        intent: ToolIntent {
            proposed_by: SlotId("core/tool_policy".into()),
            call,
            purity: Purity::Effecting,
            admitted: CapabilitySet::only(Capability::ReversibleLocal),
            argument_trust: Trust::Workspace,
        },
    }
}

#[tokio::test]
async fn real_native_write_and_one_confirmed_terminal_survive_reopen() {
    let (directory, mut agent, call) = fixture();
    agent
        .effect_journal
        .guard_recovery(&mut agent.rollout, &mut agent.ledger)
        .unwrap();
    agent.effect_journal.begin_operator_turn(TurnId(0));
    let estimate = agent
        .context_estimator
        .estimate_uncached("system", &[], &[]);
    let inspection = agent.inspect_context_budget(&[], &estimate);
    let projection = agent.turn_result_projection_budget(inspection, std::slice::from_ref(&call));
    let completed = agent
        .ordered_tool_call(TurnId(0), &call.name, false, projection)
        .execute(admission(call))
        .await
        .unwrap();
    assert!(!completed.result.is_error, "{}", completed.result.content);
    assert_eq!(
        std::fs::read_to_string(directory.join("result.txt")).unwrap(),
        "physical owner write"
    );
    let done = agent
        .rollout
        .append(&iteron_protocol::Event {
            seq: iteron_protocol::Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::Done {
                outcome: "Done".into(),
            },
        })
        .unwrap();
    let fact = agent
        .effect_journal
        .publish_final_evidence(&agent.rollout, TurnId(0), done, true, "tests passed")
        .unwrap();
    assert_eq!(
        fact.work_state,
        iteron_protocol::final_evidence::HostFinalWorkStateV1::ChangedUnverified
    );
    assert_eq!(fact.observed_native_file_changes, 1);
    assert!(fact.native_change_evidence_valid());
    assert!(!fact.workspace_diff_inspected && !fact.test_suite_identity_verified);
    assert!(iteron_record::replay(agent.rollout.path()).unwrap().iter().any(|event|
        Some(event.seq) == fact.native_change_source_seq
        && matches!(&event.kind, EventKind::ToolDone { result, effect_id:Some(_), .. } if !result.is_error && result.tool_use_id == "actual-write")));
    let path = agent.rollout.path().to_owned();
    drop(agent);
    let reopened = Rollout::open(
        path.parent().unwrap(),
        &RunId("ordered".into()),
        TenantId::default(),
    )
    .unwrap();
    let events = iteron_record::replay(reopened.path()).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::ToolDone { result, effect_id:Some(_), tool:Some(tool) } if tool=="write_file" && result.tool_use_id=="actual-write" && !result.is_error)).count(), 1);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectUnknown { .. }))
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn actual_intent_refusal_prevents_native_io_and_terminal_refusal_preserves_pending_effect() {
    for fault in [
        DurableAppendFault::EffectIntent,
        DurableAppendFault::ToolDone,
    ] {
        let (directory, mut agent, call) = fixture();
        agent.effect_journal.begin_operator_turn(TurnId(0));
        agent.fail_next_durable_append = Some(fault);
        let estimate = agent
            .context_estimator
            .estimate_uncached("system", &[], &[]);
        let inspection = agent.inspect_context_budget(&[], &estimate);
        let projection =
            agent.turn_result_projection_budget(inspection, std::slice::from_ref(&call));
        let result = agent
            .ordered_tool_call(TurnId(0), &call.name, false, projection)
            .execute(admission(call))
            .await;
        assert!(matches!(result, Err(KernelError::Record(_))));
        assert!(agent.record_failed);
        assert!(!agent.parent_effects_known());
        assert_eq!(
            directory.join("result.txt").exists(),
            fault == DurableAppendFault::ToolDone
        );
        let rows = iteron_record::replay(agent.rollout.path()).unwrap();
        assert!(
            !rows
                .iter()
                .any(|row| matches!(row.kind, EventKind::ToolDone { .. }))
        );
        let pending = rows
            .iter()
            .filter(|row| matches!(row.kind, EventKind::EffectIntent { .. }))
            .count();
        assert_eq!(pending, usize::from(fault == DurableAppendFault::ToolDone));
        let actual_done = agent
            .rollout
            .append(&iteron_protocol::Event {
                seq: iteron_protocol::Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "HarnessError".into(),
                },
            })
            .unwrap();
        // This fixture deliberately appends a diagnostic terminal after the injected barrier
        // failure. It is not a successful runtime recovery or a replacement ToolDone.
        let evidence = agent
            .effect_journal
            .publish_final_evidence(&agent.rollout, TurnId(0), actual_done, false, "changed")
            .unwrap();
        assert_eq!(evidence.observed_native_file_changes, 0);
        assert!(evidence.native_change_source_seq.is_none());
        assert_eq!(
            evidence.work_state,
            iteron_protocol::final_evidence::HostFinalWorkStateV1::Unverified
        );
        drop(agent);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

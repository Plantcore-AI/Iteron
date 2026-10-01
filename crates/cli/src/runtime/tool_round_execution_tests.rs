use super::{ToolRoundExecution, ToolRoundProgress};
use crate::runtime::DurableAppendFault;
use crate::runtime::candidate_workspace::CandidateWorkspaceBaseline;
use crate::runtime::early_tool_collection::EarlyToolWindow;
use crate::runtime::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};
use crate::runtime::optional_tool_round::OptionalToolRound;
use crate::runtime::tool_round_driver::ToolRoundDriver;
use crate::runtime::tool_turn::ToolTurnWork;
use iteron_protocol::{Block, EventKind, Message, PermissionMode, ToolUse, Trust, TurnId};
use std::collections::BTreeMap;
use std::sync::{Arc, atomic::AtomicUsize};
use std::time::{Duration, Instant};

fn retained<'a>(
    agent: &crate::runtime::Agent,
    declarations: &'a [ToolUse],
    projection: crate::runtime::context_runtime::TurnResultProjectionBudget,
) -> ToolRoundExecution<'a> {
    let deferred = declarations
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let proposal = crate::runtime::strategy_runtime::propose_tool(
                &agent.registry,
                agent.tool_policy.as_ref(),
                call.clone(),
                Trust::Workspace,
            );
            (index, call.clone(), proposal)
        })
        .collect();
    let (round, replayed) = ToolRoundDriver::retain(
        declarations,
        ToolTurnWork {
            early: Vec::new(),
            deferred,
            replayed: BTreeMap::new(),
        },
        EarlyToolWindow {
            stream_start: Instant::now(),
            stream_elapsed: Duration::ZERO,
            hook_gates_reads: false,
            queued: Arc::new(AtomicUsize::new(0)),
            projection,
        },
    )
    .unwrap();
    assert!(replayed.is_empty());
    ToolRoundExecution::new(round)
}

#[tokio::test]
async fn actual_ordered_read_commits_matching_intent_and_terminal_before_returning_one_result() {
    let directory = temp_ws("tool-round-ordered-read");
    std::fs::write(directory.join("source.txt"), "the physical source bytes").unwrap();
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let declarations = [ToolUse {
        id: "actual-read".into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"source.txt"}),
    }];
    let messages = [Message::user_text("read source.txt")];
    let estimate = agent
        .context_estimator
        .estimate_uncached("system", &messages, &[]);
    let inspection = agent.inspect_context_budget(&messages, &estimate);
    let projection = agent.turn_result_projection_budget(inspection, &declarations);
    let mut driver = retained(&agent, &declarations, projection);
    let progress = driver
        .pump(
            agent.tool_execution_session(TurnId(0), &messages, projection),
            &OptionalToolRound::default(),
            &mut CandidateWorkspaceBaseline::default(),
        )
        .await
        .unwrap();
    assert!(matches!(progress, ToolRoundProgress::Complete));
    let response = driver
        .into_round()
        .unwrap()
        .into_parts()
        .unwrap()
        .message
        .into_message();
    assert!(
        matches!(response.content.as_slice(), [Block::ToolResult(result)] if result.tool_use_id == "actual-read" && !result.is_error && result.content.contains("the physical source bytes"))
    );
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    let intent = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::EffectIntent { id, tool, .. } if tool == "read_file" => {
                Some((event.seq, id))
            }
            _ => None,
        })
        .expect("actual registry read needs a committed physical intent");
    let terminal = events.iter().find(|event| matches!(&event.kind,
        EventKind::ToolDone { effect_id: Some(effect_id), result, .. } if effect_id == intent.1 && result.tool_use_id == "actual-read" && !result.is_error
    )).expect("actual result has the same admitted physical identity");
    assert!(intent.0 < terminal.seq);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn a_real_intent_refusal_prevents_native_write_and_poisoned_pump_cannot_rearm() {
    let directory = temp_ws("tool-round-intent-refused");
    let mut agent = agent_for(&directory);
    agent.permission_mode = PermissionMode::AcceptEdits;
    record_test_genesis(&mut agent, &directory);
    let declarations = [ToolUse {
        id: "refused-write".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"must-not-exist.txt","content":"not dispatched"}),
    }];
    let messages = [Message::user_text("write must-not-exist.txt")];
    let estimate = agent
        .context_estimator
        .estimate_uncached("system", &messages, &[]);
    let inspection = agent.inspect_context_budget(&messages, &estimate);
    let projection = agent.turn_result_projection_budget(inspection, &declarations);
    let mut driver = retained(&agent, &declarations, projection);
    agent.fail_next_durable_append = Some(DurableAppendFault::EffectIntent);
    let refused = driver
        .pump(
            agent.tool_execution_session(TurnId(0), &messages, projection),
            &OptionalToolRound::default(),
            &mut CandidateWorkspaceBaseline::default(),
        )
        .await;
    assert!(refused.is_err());
    assert!(agent.record_failed);
    assert!(!directory.join("must-not-exist.txt").exists());
    assert!(
        driver
            .pump(
                agent.tool_execution_session(TurnId(0), &messages, projection),
                &OptionalToolRound::default(),
                &mut CandidateWorkspaceBaseline::default(),
            )
            .await
            .is_err()
    );
    assert!(!directory.join("must-not-exist.txt").exists());
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::EffectIntent { .. } | EventKind::ToolDone { .. }
    )));
    std::fs::remove_dir_all(directory).unwrap();
}

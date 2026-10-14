use super::CompletionAction;
use crate::runtime::agent_loop::AgentLoopGuard;
use crate::runtime::frontend_events::UiEvent;
use crate::runtime::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};
use crate::runtime::inbound_control::{PendingSteer, TurnSubmission};
use crate::runtime::investigation_convergence::{
    CandidateWorkspaceBaseline, InvestigationConvergence,
};
use crate::runtime::model_response::{ModelResponseInterpreter, ModelResponseScope};
use crate::runtime::session_control::InboundControl;
use crate::runtime::tool_response::ToolResponseOwner;
use crate::runtime::{DurableAppendFault, Op};
use iteron_protocol::{
    Block, EventKind, Message, StopReason, SubmissionId, ToolResult, ToolUse, Trust, TurnId,
};

#[tokio::test]
async fn an_identified_steer_commits_before_an_answer_and_wins_the_candidate_safe_point() {
    let directory = temp_ws("completion-steer");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let (ui_tx, mut ui_rx) = tokio::sync::mpsc::channel(8);
    agent.set_ui(ui_tx);
    agent.retain_pending_steer(PendingSteer::from_steer(
        "include the requested edge case".into(),
        SubmissionId(81),
    ));
    let turn = TurnId(0);
    let mut messages = vec![Message::user_text("initial")];
    let mut convergence = InvestigationConvergence::for_general_run();
    let decision = ModelResponseInterpreter {
        submitted: &mut crate::runtime::submitted_turn_state::SubmittedTurnState::default(),
        convergence: &mut convergence,
        scope: ModelResponseScope {
            exhausted: None,
            interactive: false,
            configured_verifier: false,
            task: "initial",
            answer: "implemented",
            recovered_stream: false,
        },
    }
    .decide(&StopReason::EndTurn);
    let action = agent
        .turn_completion(turn)
        .model(
            decision,
            &mut messages,
            &mut CandidateWorkspaceBaseline::default(),
            &mut convergence,
            &mut AgentLoopGuard::begin(turn),
        )
        .await
        .unwrap();
    assert!(matches!(
        action,
        CompletionAction::Continue {
            applying_steer: true
        }
    ));
    assert!(matches!(
        ui_rx.try_recv(),
        Ok(UiEvent::SteerSubmissionApplied {
            id: SubmissionId(81)
        })
    ));
    assert_eq!(agent.inbox.len(), 0);
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    let recorded = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::Message { message } => Some(message),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].content.iter().any(|block| matches!(block,
        Block::Text { text } if text.contains("include the requested edge case")
    )));
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::TurnPublicationV1 { .. }
            | EventKind::Done { .. }
            | EventKind::EffectIntent { .. }
    )));
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn message_refusal_preserves_exact_steer_for_handoff_without_an_applied_receipt() {
    let directory = temp_ws("completion-steer-refused");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let (ui_tx, mut ui_rx) = tokio::sync::mpsc::channel(8);
    agent.set_ui(ui_tx);
    agent.retain_pending_steer(PendingSteer::from_steer(
        "unchanged source".into(),
        SubmissionId(82),
    ));
    agent.fail_next_durable_append = Some(DurableAppendFault::SteerMessage);
    let refused = agent
        .turn_completion(TurnId(0))
        .model(
            crate::runtime::model_response::ModelResponseDecision::Candidate { notice: None },
            &mut vec![Message::user_text("initial")],
            &mut CandidateWorkspaceBaseline::default(),
            &mut InvestigationConvergence::for_general_run(),
            &mut AgentLoopGuard::begin(TurnId(0)),
        )
        .await;
    assert!(refused.is_err());
    assert!(agent.record_failed);
    assert!(ui_rx.try_recv().is_err());
    let (unadmitted, visible) = agent.take_unadmitted_steers_with_client_count();
    assert_eq!(visible, 1);
    assert_eq!(unadmitted.len(), 1);
    assert_eq!(unadmitted[0].submission_id, Some(SubmissionId(82)));
    assert_eq!(unadmitted[0].text, "unchanged source");
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                EventKind::Message { .. }
                    | EventKind::TurnPublicationV1 { .. }
                    | EventKind::Done { .. }
            ))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn declared_tool_response_commits_before_a_real_queued_drain_without_constructing_a_verifier()
{
    let directory = temp_ws("completion-tool-drain");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    assert!(agent.verify_command.is_none());
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    agent.set_inbound_control(rx);
    tx.send(TurnSubmission::identified(SubmissionId(83), Op::Drain))
        .await
        .unwrap();
    // This fixture exercises the committed model-message boundary, not physical tool success.
    // The finite response owner requires an exact result for every admitted declaration.
    let declarations = [ToolUse {
        id: "refused-read".into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"missing"}),
    }];
    let mut response = ToolResponseOwner::new(&declarations);
    response
        .accept(
            0,
            ToolResult {
                tool_use_id: "refused-read".into(),
                content: "read unavailable".into(),
                is_error: true,
                trust: Trust::Workspace,
                latency_ms: 0,
            },
        )
        .unwrap();
    let mut messages = vec![Message::user_text("initial")];
    let action = agent
        .turn_completion(TurnId(0))
        .tools(
            response.into_parts().unwrap().message,
            true,
            &mut messages,
            &mut CandidateWorkspaceBaseline::default(),
            &mut InvestigationConvergence::for_general_run(),
        )
        .await
        .unwrap();
    assert!(matches!(action, CompletionAction::RequestedControl));
    assert_eq!(agent.control.requested(), InboundControl::Drain);
    assert!(
        matches!(messages.last().unwrap().content.as_slice(), [Block::ToolResult(result)] if result.tool_use_id == "refused-read")
    );
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind,
        EventKind::Message { message } if matches!(message.content.as_slice(), [Block::ToolResult(result)] if result.tool_use_id == "refused-read")
    )).count(), 1);
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::EffectIntent { .. }
            | EventKind::TurnPublicationV1 { .. }
            | EventKind::Done { .. }
    )));
    std::fs::remove_dir_all(directory).unwrap();
}

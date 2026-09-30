//! Real producer/record journeys; terminal refusal occurs after the actual answer-tag append.
use super::{Agent, DurableAppendFault, EventKind, Outcome, gate_integration_tests};
use iteron_protocol::turn_publication::TurnPublicationFactV1;
use iteron_protocol::{Block, Budget, RunId, StopReason, TenantId, Usage};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use iteron_record::Rollout;
use iteron_tools::Registry;
use std::{path::Path, sync::Arc};

struct FinalAnswer;
#[async_trait::async_trait]
impl Provider for FinalAnswer {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("publication-fixture")
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "actual final answer fixture".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage::default()),
        })
    }
}

fn make_agent(workspace: &Path, run: &RunId) -> Agent {
    let provider = Arc::new(FinalAnswer);
    let rollout = Rollout::open(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        Registry::read_only(workspace).unwrap(),
        rollout,
        "model-fixture".into(),
        "system fixture".into(),
        Budget::default(),
    );
    agent.workspace = workspace.to_path_buf();
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent
        .record_operator_model_selection(
            provider,
            "publication-fixture".into(),
            "model-fixture".into(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
    agent
}

fn reopen_reader(workspace: &Path, run: &RunId) -> Agent {
    let rollout =
        Rollout::open_existing(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    Agent::new(
        Arc::new(FinalAnswer),
        Registry::read_only(workspace).unwrap(),
        rollout,
        "model-fixture".into(),
        "system fixture".into(),
        Budget::default(),
    )
}

#[tokio::test]
async fn actual_end_turn_joins_message_and_existing_done_receipts_then_reopens() {
    let workspace = gate_integration_tests::temp_ws("publication-real-end-turn");
    let run = RunId("publication-real-end-turn".into());
    let mut agent = make_agent(&workspace, &run);
    assert_eq!(
        agent.run("produce the final fixture answer").await.unwrap(),
        Outcome::Done
    );
    let path = agent.rollout.path().to_path_buf();
    let facts = agent.recovered_turn_publications_v1().unwrap();
    let record = iteron_record::replay(&path).unwrap();
    let answer = facts
        .iter()
        .find(|event| matches!(event.fact, TurnPublicationFactV1::AnswerAvailable { .. }))
        .unwrap();
    let TurnPublicationFactV1::AnswerAvailable { message_seq } = answer.fact else {
        unreachable!()
    };
    assert!(record.iter().any(|event| event.seq.0 == message_seq && event.turn == answer.turn_id && matches!(&event.kind, EventKind::Message { message } if message.role == iteron_protocol::Role::Assistant)));
    let done = record
        .iter()
        .find(|event| matches!(&event.kind, EventKind::Done { outcome } if outcome == "Done"))
        .unwrap();
    assert!(facts.iter().any(|fact| fact.source_seq == done.seq.0
        && fact.fact == TurnPublicationFactV1::finalized(&Outcome::Done).unwrap()));
    assert_eq!(
        record
            .iter()
            .filter(|event| matches!(event.kind, EventKind::TurnPublicationV1 { .. }))
            .count(),
        1,
        "finalization must not add another terminal append"
    );
    drop(agent);
    let reopened = reopen_reader(&workspace, &run);
    assert_eq!(reopened.recovered_turn_publications_v1().unwrap(), facts);
    drop(reopened);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn refused_terminal_after_actual_answer_recovers_answer_without_inventing_done() {
    let workspace = gate_integration_tests::temp_ws("publication-terminal-refused");
    let run = RunId("publication-terminal-refused".into());
    let mut agent = make_agent(&workspace, &run);
    agent.fail_next_durable_append = Some(DurableAppendFault::RunTerminal);
    assert!(agent.run("produce the final fixture answer").await.is_err());
    assert!(agent.record_failed);
    let facts = agent.recovered_turn_publications_v1().unwrap();
    assert_eq!(facts.len(), 1);
    assert!(matches!(
        facts[0].fact,
        TurnPublicationFactV1::AnswerAvailable { .. }
    ));
    assert!(
        !iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::Done { .. }))
    );
    drop(agent);
    let reopened = reopen_reader(&workspace, &run);
    assert_eq!(reopened.recovered_turn_publications_v1().unwrap(), facts);
    drop(reopened);
    std::fs::remove_dir_all(workspace).unwrap();
}

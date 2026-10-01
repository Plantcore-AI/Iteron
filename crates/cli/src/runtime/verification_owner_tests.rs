//! Actual configured-gate, WAL, task and resident ingress journeys. No test claims remote/model IO.
use super::super::gate_integration_tests;
use super::super::inbound_control::TurnSubmission;
use super::super::investigation_convergence::{CandidateDiffState, InvestigationConvergence};
use super::super::session_control::InboundControl;
use super::super::strong_verification::VerificationGateDisposition;
use super::super::{Agent, DurableAppendFault};
use iteron_protocol::{Budget, EventKind, Op, RunId, SubmissionId, TenantId, TurnId};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use iteron_verify::{Oracle, OracleStrength, Verdict, VerificationOutcome};
use std::{
    path::Path,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
struct NoProvider;
#[async_trait::async_trait]
impl Provider for NoProvider {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("verification owner must not dispatch a model");
    }
}
struct ControlledOracle {
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    outcome: VerificationOutcome,
}
#[async_trait::async_trait]
impl Oracle for ControlledOracle {
    fn strength(&self) -> OracleStrength {
        OracleStrength::Strong
    }
    async fn evaluate(&self) -> Verdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Verdict::new(
            OracleStrength::Strong,
            self.outcome,
            "observed fixture oracle verdict",
        )
    }
}
fn agent(root: &Path) -> Agent {
    let rollout = Rollout::open(
        &root.join(".iteron/runs"),
        &RunId("verification-owner".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NoProvider),
        iteron_tools::Registry::read_only(root).unwrap(),
        rollout,
        "fixture-model".into(),
        "fixture system".into(),
        Budget::default(),
    );
    agent.workspace = root.to_owned();
    agent.verify_command = Some("operator workspace command".into());
    agent
        .verification_state
        .policy
        .checkpoint
        .before_verification = false;
    agent.verification_state.policy.checkpoint.turn_boundary = false;
    agent.verification_state.policy.flaky.repeat_count = 1;
    agent
}
fn oracle(outcome: VerificationOutcome) -> Arc<ControlledOracle> {
    Arc::new(ControlledOracle {
        calls: Arc::new(AtomicUsize::new(0)),
        started: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
        outcome,
    })
}
#[tokio::test]
async fn disjoint_gate_pass_commits_one_physical_task_and_preserves_retry_state() {
    let root = gate_integration_tests::temp_ws("verification-independent-pass");
    let mut agent = agent(&root);
    let oracle = oracle(VerificationOutcome::Pass);
    oracle.release.notify_one();
    agent.verify_oracle = Some(oracle.clone());
    let mut convergence = InvestigationConvergence::for_general_run();
    let disposition = agent
        .strong_verification_gate(TurnId(0))
        .run(
            TurnId(0),
            "operator workspace command",
            CandidateDiffState::Unavailable,
            &mut convergence,
        )
        .await
        .unwrap();
    assert!(matches!(disposition, VerificationGateDisposition::Passed));
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 1);
    assert_eq!(agent.verification_state.attempts, 0);
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(
                |event| matches!(&event.kind,EventKind::EffectIntent{tool,..} if tool=="verify")
            )
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,EventKind::EffectDone{tool,..} if tool=="verify"))
            .count(),
        1
    );
    let tasks = agent.verification_tasks.list(agent.rollout.run_id());
    assert_eq!(tasks["tasks"][0]["state"], "settled");
    assert_eq!(tasks["tasks"][0]["observed_outcome"], "passed");
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn verify_drains_only_current_oracle_and_keeps_resident_steer_receiver() {
    let root = gate_integration_tests::temp_ws("verification-independent-drain");
    let mut agent = agent(&root);
    agent.verification_state.policy.quorum.verifiers = 2;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    agent.set_approvals(rx);
    let oracle = oracle(VerificationOutcome::TestFailure);
    agent.verify_oracle = Some(oracle.clone());
    let (started, release) = (oracle.started.clone(), oracle.release.clone());
    let sender = tx.clone();
    let control = tokio::spawn(async move {
        started.notified().await;
        sender
            .send(TurnSubmission::identified(
                SubmissionId(10),
                Op::Steer {
                    text: "next admitted safe point".into(),
                },
            ))
            .await
            .unwrap();
        sender
            .send(TurnSubmission::identified(SubmissionId(11), Op::Drain))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        release.notify_one();
    });
    let mut convergence = InvestigationConvergence::for_general_run();
    let mut gate = agent.strong_verification_gate(TurnId(0));
    gate.scope.deadline = Some(Instant::now() + Duration::from_secs(2));
    let result = gate
        .run(
            TurnId(0),
            "operator workspace command",
            CandidateDiffState::Unavailable,
            &mut convergence,
        )
        .await
        .unwrap();
    drop(gate);
    control.await.unwrap();
    assert!(matches!(result, VerificationGateDisposition::Drained));
    assert_eq!(
        oracle.calls.load(Ordering::SeqCst),
        1,
        "drain does not admit remaining quorum lane"
    );
    assert_eq!(
        agent.verification_state.attempts, 0,
        "drain does not consume failure repair allowance"
    );
    assert!(agent.inbox.has_receiver());
    assert_eq!(agent.control.requested(), InboundControl::Drain);
    assert_eq!(agent.inbox.pop().unwrap().text, "next admitted safe point");
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,EventKind::EffectDone{tool,..} if tool=="verify"))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectUnknown { .. }))
    );
    drop(tx);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn future_drop_retains_task_quarantine_and_receiver_recovery_never_reruns_oracle() {
    let root = gate_integration_tests::temp_ws("verification-independent-drop");
    let mut agent = agent(&root);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    agent.set_approvals(rx);
    let oracle = oracle(VerificationOutcome::Pass);
    agent.verify_oracle = Some(oracle.clone());
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        agent
            .strong_verification_gate(TurnId(0))
            .run_verify("operator workspace command"),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 1);
    assert!(
        agent.inbox.has_receiver(),
        "executor does not take the unique ingress receiver"
    );
    let tasks = agent.verification_tasks.list(agent.rollout.run_id());
    assert_eq!(tasks["tasks"][0]["state"], "reconciliation_needed");
    assert_eq!(
        tasks["tasks"][0]["observed_outcome"],
        serde_json::Value::Null
    );
    assert_eq!(agent.verification_state.attempts, 0);
    agent.effect_journal.adopt_journal();
    assert!(
        agent
            .effect_journal
            .guard_recovery(&mut agent.rollout, &mut agent.ledger)
            .is_err()
    );
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(
                |event| matches!(&event.kind,EventKind::EffectUnknown{tool,..} if tool=="verify")
            )
            .count(),
        1
    );
    assert_eq!(
        oracle.calls.load(Ordering::SeqCst),
        1,
        "WAL recovery performs no executor dispatch"
    );
    tx.send(TurnSubmission::identified(
        SubmissionId(12),
        Op::Steer {
            text: "receiver still owned".into(),
        },
    ))
    .await
    .unwrap();
    agent.collect_inbound_ops(TurnId(0));
    assert_eq!(agent.inbox.pop().unwrap().text, "receiver still owned");
    drop(tx);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn failed_intent_barrier_prevents_physical_oracle_and_task_publication() {
    let root = gate_integration_tests::temp_ws("verification-independent-intent-refusal");
    let mut agent = agent(&root);
    let oracle = oracle(VerificationOutcome::Pass);
    oracle.release.notify_one();
    agent.verify_oracle = Some(oracle.clone());
    agent.fail_next_durable_append = Some(DurableAppendFault::EffectIntent);
    assert!(
        agent
            .strong_verification_gate(TurnId(0))
            .run_verify("operator workspace command")
            .await
            .is_err()
    );
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 0);
    assert!(agent.record_failed);
    let tasks = agent.verification_tasks.list(agent.rollout.run_id());
    assert!(tasks["tasks"].as_array().unwrap().is_empty());
    assert!(
        !iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn explicit_outer_attestation_reaches_actual_native_oracle_with_one_wal_task() {
    let root = gate_integration_tests::temp_ws("verification-independent-native-command");
    let mut agent = agent(&root);
    // This fixture explicitly attests its outer boundary and runs a literal no-write command.
    // It is native process evidence, not a claim that this test exercised platform confinement.
    agent.verify_preconfined = true;
    let mut gate = agent.strong_verification_gate(TurnId(0));
    gate.scope.deadline = Some(Instant::now() + Duration::from_secs(2));
    let verdict = gate
        .run_verify("printf 'independent-native-verifier\\n'")
        .await
        .unwrap();
    drop(gate);
    assert_eq!(verdict.outcome, VerificationOutcome::Pass);
    assert!(verdict.detail.contains("independent-native-verifier"));
    let tasks = agent.verification_tasks.list(agent.rollout.run_id());
    assert_eq!(tasks["tasks"][0]["state"], "settled");
    let id = tasks["tasks"][0]["task_id"].as_str().unwrap();
    let served = agent
        .verification_tasks
        .inspect(agent.rollout.run_id(), id)
        .unwrap();
    assert!(
        served["output"]["verdict_detail"]
            .as_str()
            .unwrap()
            .contains("independent-native-verifier")
    );
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(
                |event| matches!(&event.kind,EventKind::EffectIntent{tool,..} if tool=="verify")
            )
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,EventKind::EffectDone{tool,..} if tool=="verify"))
            .count(),
        1
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

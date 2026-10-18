//! Real resident Agent/WAL/control journeys. Source fixtures await the final unified gate.
use super::super::inbound_control::{PendingSteer, TurnSubmission};
use super::super::session_control::InboundControl;
use super::super::{
    Agent, DurableAppendFault, KernelError, Outcome, UiEvent, gate_integration_tests,
};
use iteron_protocol::{
    Budget, Capability, EventKind, Op, RunId, SubmissionId, TenantId, ToolUse, TurnId, Verdict,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult};
use iteron_record::Rollout;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
struct NoProviderIo;
#[async_trait::async_trait]
impl Provider for NoProviderIo {
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("approval and terminal fixtures must not dispatch a provider");
    }
}
fn resident_agent(root: &Path) -> Agent {
    let rollout = Rollout::open(
        &root.join(".iteron/runs"),
        &RunId("terminal-owner-fixture".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(NoProviderIo),
        iteron_tools::Registry::read_only(root).unwrap(),
        rollout,
        "fixture-model".into(),
        "fixture system".into(),
        Budget::default(),
    );
    agent.workspace = root.to_owned();
    agent
        .verification_state
        .policy_for_test_mut()
        .checkpoint
        .turn_boundary = false;
    agent
        .run_deadline
        .bind_external(Some(Instant::now() + Duration::from_secs(2)));
    agent
}
fn write() -> ToolUse {
    ToolUse {
        id: "not-yet-admitted-native-write".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"f","content":"never written"}),
    }
}

#[tokio::test]
async fn first_record_failure_survives_admission_and_terminal_refusal_until_reopen() {
    let root = gate_integration_tests::temp_ws("record-first-cause");
    let mut agent = resident_agent(&root);
    let path = agent.rollout.path().to_owned();
    let before = std::fs::read(&path).unwrap();
    let max = iteron_protocol::event::MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES;
    // A real record validator rejects this observation before any WAL write. The old emit path
    // discarded EnvironmentContextTooLarge and every later guard reported generic storage_io.
    let invalid_observation = |bytes| EventKind::ContextInjection {
        text: String::new(),
        trust: iteron_protocol::Trust::Workspace,
        instructions: Some(iteron_protocol::DurableInstructionContext {
            text: String::new(),
            trust: iteron_protocol::Trust::Workspace,
            environment: Some(iteron_protocol::DurableEnvironmentContext {
                text: "x".repeat(bytes),
                trust: iteron_protocol::Trust::Workspace,
            }),
        }),
    };
    agent.emit(TurnId(0), invalid_observation(max + 1));
    assert!(agent.record_failed);
    let failure = agent.rollout.retained_failure().unwrap();
    assert_eq!(failure.kind, iteron_record::RecordFailureKind::Limit);
    assert_eq!(failure.bytes, Some((max + 1) as u64));
    assert_eq!(failure.limit, Some(max as u64));
    // A second failure must not replace the evidence of what first stopped this live run.
    agent.emit(TurnId(0), invalid_observation(max + 2));
    assert_eq!(agent.rollout.retained_failure(), Some(failure));
    for error in [
        agent.ensure_record_healthy().unwrap_err(),
        agent.finish(TurnId(0), Outcome::Done).await.unwrap_err(),
        agent
            .run("do not admit another provider request")
            .await
            .unwrap_err(),
    ] {
        assert!(error.public_summary().contains("session record [limit]"));
        assert!(matches!(
            error,
            KernelError::Record(iteron_record::RecordError::PreviousFailure(retained))
                if retained == failure
        ));
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                EventKind::Done { .. } | EventKind::EffectIntent { .. }
            ))
    );
    agent.finish_advisory_maintenance_for_test().await.unwrap();
    drop(agent);
    // Only a new writer loses the process-local failure diagnosis. Reopening still performs
    // the ordinary lock/chain/tail validation; no effects or submissions are retried here.
    let mut reopened = Rollout::open(
        path.parent().unwrap(),
        &RunId("terminal-owner-fixture".into()),
        TenantId::default(),
    )
    .unwrap();
    assert!(reopened.retained_failure().is_none());
    reopened
        .append(&iteron_protocol::Event {
            seq: iteron_protocol::Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::Notice {
                text: "reopened verified writer".into(),
            },
        })
        .unwrap();
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn force_cancel_atomic_during_approval_refuses_before_effect_and_retains_receiver() {
    let root = gate_integration_tests::temp_ws("approval-atomic-force");
    let mut agent = resident_agent(&root);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    agent.set_approvals(rx);
    let stop = Arc::new(AtomicBool::new(false));
    agent.inherit_force_cancel(stop.clone());
    let wake = stop.clone();
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        wake.store(true, Ordering::Release);
    });
    let allowed = tokio::time::timeout(
        Duration::from_secs(1),
        agent.await_approval(TurnId(0), &write(), Capability::ReversibleLocal),
    )
    .await
    .unwrap()
    .unwrap();
    task.await.unwrap();
    assert!(!allowed);
    assert!(agent.inbox.has_receiver());
    assert_eq!(agent.requested_control(), InboundControl::ForceCancel);
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.kind {
                EventKind::Approval { verdict, .. } => Some(verdict),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![Verdict::Ask, Verdict::Deny]
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    assert!(!root.join("f").exists());
    drop(tx);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn approval_pump_keeps_steer_and_wrong_response_out_of_the_durable_decision() {
    let root = gate_integration_tests::temp_ws("approval-owner-steer");
    let mut agent = resident_agent(&root);
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    agent.set_approvals(rx);
    let (ui, mut reader) = tokio::sync::mpsc::channel(8);
    agent.set_ui(ui);
    tx.try_send(TurnSubmission::identified(
        SubmissionId(7),
        Op::Steer {
            text: "next safe point".into(),
        },
    ))
    .unwrap();
    tx.try_send(TurnSubmission::identified(
        SubmissionId(8),
        Op::ApprovalResponse {
            id: SubmissionId(999),
            approved: true,
            remember: true,
        },
    ))
    .unwrap();
    tx.try_send(TurnSubmission::identified(
        SubmissionId(9),
        Op::ApprovalResponse {
            id: SubmissionId(1),
            approved: false,
            remember: false,
        },
    ))
    .unwrap();
    assert!(
        !agent
            .await_approval(TurnId(0), &write(), Capability::ReversibleLocal)
            .await
            .unwrap()
    );
    let retained = agent.inbox.pop().unwrap();
    assert_eq!(retained.text, "next safe point");
    assert_eq!(retained.submission_id, Some(SubmissionId(7)));
    assert!(
        std::iter::from_fn(|| reader.try_recv().ok()).any(|event| matches!(
            event,
            UiEvent::ApprovalResolved {
                response_submission_id: Some(SubmissionId(9)),
                ..
            }
        ))
    );
    assert!(!root.join("f").exists());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn approval_record_refusal_restores_the_actual_receiver_and_stops_execution() {
    let root = gate_integration_tests::temp_ws("approval-owner-record-refusal");
    let mut agent = resident_agent(&root);
    for _ in 0..256 {
        agent
            .inbox
            .push(PendingSteer::user("already queued".into()))
            .ok()
            .unwrap();
    }
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    agent.set_approvals(rx);
    tx.try_send(TurnSubmission::identified(
        SubmissionId(4),
        Op::Steer {
            text: "overflow".into(),
        },
    ))
    .unwrap();
    tx.try_send(TurnSubmission::identified(
        SubmissionId(5),
        Op::ApprovalResponse {
            id: SubmissionId(1),
            approved: true,
            remember: false,
        },
    ))
    .unwrap();
    agent.fail_next_durable_append = Some(DurableAppendFault::Notice);
    assert!(matches!(
        agent
            .await_approval(TurnId(0), &write(), Capability::ReversibleLocal)
            .await,
        Err(KernelError::Record(_))
    ));
    assert!(agent.record_failed);
    assert!(agent.inbox.has_receiver());
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::Approval {
            verdict: Verdict::Auto,
            ..
        } | EventKind::EffectIntent { .. }
    )));
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn terminal_refusal_preserves_stop_and_committed_terminal_preserves_inherited_owner() {
    let root = gate_integration_tests::temp_ws("terminal-owner-stop");
    let mut agent = resident_agent(&root);
    let stop = Arc::new(AtomicBool::new(true));
    agent.inherit_interrupt(stop.clone());
    agent.fail_next_durable_append = Some(DurableAppendFault::RunTerminal);
    assert!(agent.finish_requested_control(TurnId(0)).await.is_err());
    assert!(stop.load(Ordering::Acquire));
    assert_eq!(agent.requested_control(), InboundControl::Interrupt);
    assert!(
        !iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::Done { .. }))
    );
    agent.finish_advisory_maintenance_for_test().await.unwrap();
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();

    let root = gate_integration_tests::temp_ws("terminal-owner-inherited");
    let mut agent = resident_agent(&root);
    let stop = Arc::new(AtomicBool::new(true));
    agent.inherit_interrupt(stop.clone());
    assert_eq!(
        agent.finish_requested_control(TurnId(0)).await.unwrap(),
        Some(Outcome::Interrupted)
    );
    assert!(stop.load(Ordering::Acquire));
    assert!(
        iteron_record::replay(agent.rollout.path())
            .unwrap()
            .iter()
            .any(|event| matches!(&event.kind,EventKind::Done {outcome} if outcome=="Interrupted"))
    );
    agent.finish_advisory_maintenance_for_test().await.unwrap();
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn already_received_physical_reap_receipt_is_not_consumed_twice() {
    use super::super::force_cancel::{ForceCancelEvidence, ForceCancelSeam, ProcessReapProof};
    let root = gate_integration_tests::temp_ws("terminal-owner-known-reap");
    let mut agent = resident_agent(&root);
    let (requests, mut requested) = tokio::sync::mpsc::channel(1);
    let (proofs, evidence) = tokio::sync::mpsc::channel(1);
    proofs
        .try_send(ForceCancelEvidence {
            turn: TurnId(0),
            proof: ProcessReapProof::NoTrackedProcesses,
        })
        .unwrap();
    agent.force_cancel_seam = Some(ForceCancelSeam::new(requests, evidence));
    agent.control.request(InboundControl::ForceCancel);
    let (ui, mut reader) = tokio::sync::mpsc::channel(8);
    agent.set_ui(ui);
    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(100),
            agent.finish_requested_control(TurnId(0))
        )
        .await
        .unwrap()
        .unwrap(),
        Some(Outcome::Interrupted)
    );
    assert!(
        requested.try_recv().is_err(),
        "already received cleanup proof must not trigger a second process operation"
    );
    assert!(std::iter::from_fn(|| reader.try_recv().ok()).any(
        |event| matches!(event,UiEvent::Notice(text) if text.contains("Force cancel completed"))
    ));
    agent.finish_advisory_maintenance_for_test().await.unwrap();
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn dropping_approval_wait_preserves_same_resident_ingress_and_next_submission() {
    let root = gate_integration_tests::temp_ws("approval-owner-future-drop");
    let mut agent = resident_agent(&root);
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    agent.set_approvals(rx);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            agent.await_approval(TurnId(0), &write(), Capability::ReversibleLocal)
        )
        .await
        .is_err()
    );
    assert!(
        agent.inbox.has_receiver(),
        "dropping only an approval future must retain the resident inbox"
    );
    tx.try_send(TurnSubmission::identified(
        SubmissionId(17),
        Op::Steer {
            text: "after cancelled wait".into(),
        },
    ))
    .unwrap();
    tx.try_send(TurnSubmission::identified(
        SubmissionId(18),
        Op::ApprovalResponse {
            id: SubmissionId(2),
            approved: false,
            remember: false,
        },
    ))
    .unwrap();
    assert!(
        !agent
            .await_approval(TurnId(0), &write(), Capability::ReversibleLocal)
            .await
            .unwrap()
    );
    let retained = agent.inbox.pop().unwrap();
    assert_eq!(retained.text, "after cancelled wait");
    assert_eq!(retained.submission_id, Some(SubmissionId(17)));
    let verdicts = iteron_record::replay(agent.rollout.path())
        .unwrap()
        .iter()
        .filter_map(|event| match event.kind {
            EventKind::Approval { id, verdict, .. } => Some((id, verdict)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        verdicts,
        vec![
            (SubmissionId(1), Verdict::Ask),
            (SubmissionId(2), Verdict::Ask),
            (SubmissionId(2), Verdict::Deny)
        ]
    );
    assert!(!root.join("f").exists());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

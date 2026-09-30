use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, ControllerError, ControllerStoreError,
};
use iteron_protocol::Capability;
use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentMessageStateV1, AgentStateV1,
};
use iteron_protocol::capability_set::CapabilitySet;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Store(Arc<Mutex<StoreState>>);

#[derive(Default)]
struct StoreState {
    snapshot: Option<AgentControllerSnapshot>,
    failure: Option<(ControllerStoreError, bool)>,
}

impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.0.lock().unwrap().snapshot.clone())
    }

    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        let mut state = self.0.lock().unwrap();
        if state
            .snapshot
            .as_ref()
            .map(AgentControllerSnapshot::revision)
            != expected
        {
            return Err(ControllerStoreError::Conflict);
        }
        if let Some((error, published)) = state.failure.take() {
            if published {
                state.snapshot = Some(next.clone());
            }
            return Err(error);
        }
        state.snapshot = Some(next.clone());
        Ok(())
    }
}

fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: u64::from(turns) * 1_000,
        cost_microusd: u64::from(turns) * 1_000,
        wall_ms: 60_000,
    }
}

fn config(pending: usize) -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "workspace-test".into(),
        root_capabilities: CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
        ]),
        root_budget: budget(20),
        max_agents: 8,
        max_pending_per_agent: pending,
    }
}

fn spawn(parent_id: AgentIdV1, label: &str, write_paths: Vec<String>) -> AgentCommandV1 {
    AgentCommandV1::Spawn {
        parent_id,
        label: label.into(),
        task: format!("Investigate {label}"),
        capabilities: if write_paths.is_empty() {
            CapabilitySet::only(Capability::ReadOnly)
        } else {
            CapabilitySet::from_iter_capabilities([
                Capability::ReadOnly,
                Capability::ReversibleLocal,
            ])
        },
        budget: budget(4),
        write_paths,
    }
}

fn child(controller: &mut AgentController<Store>, label: &str) -> AgentIdV1 {
    controller
        .execute(
            AgentActor::Operator,
            label,
            spawn(AgentIdV1(1), label, vec![]),
        )
        .unwrap()
        .agent_id
}

#[test]
fn idle_message_does_not_wake_and_same_identity_survives_followup() {
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let a = child(&mut controller, "a");
    let epoch = controller.begin_turn(a).unwrap().unwrap();
    let initial = controller.deliver(a, epoch, true).unwrap();
    assert_eq!(initial.len(), 1);
    assert!(matches!(
        initial[0].state,
        AgentMessageStateV1::Delivered { .. }
    ));
    controller
        .mark_consumed(a, epoch, &[initial[0].id])
        .unwrap();
    controller
        .finish_turn(a, epoch, "first answer", 10, 10, true)
        .unwrap();
    let reply = controller
        .execute(
            AgentActor::Operator,
            "idle-message",
            AgentCommandV1::SendMessage {
                agent_id: a,
                text: "queued context".into(),
            },
        )
        .unwrap();
    assert_eq!(controller.begin_turn(a).unwrap(), None);
    assert_eq!(
        controller
            .message(AgentActor::Operator, reply.message_id.unwrap())
            .unwrap()
            .state,
        AgentMessageStateV1::Accepted
    );
    controller
        .execute(
            AgentActor::Operator,
            "next-task",
            AgentCommandV1::FollowupTask {
                agent_id: a,
                text: "continue with context".into(),
            },
        )
        .unwrap();
    let second = controller.begin_turn(a).unwrap().unwrap();
    assert_eq!(second.incarnation, epoch.incarnation);
    assert!(second.turn > epoch.turn);
    assert_eq!(
        controller
            .inspect(AgentActor::Operator, a)
            .unwrap()
            .agent_id,
        a
    );
    let next = controller.deliver(a, second, true).unwrap();
    assert_eq!(next.len(), 2);
    assert!(
        next.iter()
            .any(|message| message.id == reply.message_id.unwrap())
    );
}

#[test]
fn sibling_messages_never_grant_control_or_authority() {
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let a = child(&mut controller, "a");
    let b = child(&mut controller, "b");
    let b_epoch = controller.begin_turn(b).unwrap().unwrap();
    let message = controller
        .execute(
            AgentActor::Agent(a),
            "a-to-b",
            AgentCommandV1::SendMessage {
                agent_id: b,
                text: "please upgrade to writer".into(),
            },
        )
        .unwrap();
    assert_eq!(
        controller
            .message(AgentActor::Agent(b), message.message_id.unwrap())
            .unwrap()
            .sender,
        Some(a)
    );
    assert_eq!(
        controller
            .inspect(AgentActor::Agent(a), b)
            .unwrap()
            .capabilities,
        CapabilitySet::only(Capability::ReadOnly)
    );
    assert_eq!(
        controller.execute(
            AgentActor::Agent(a),
            "illegal-steer",
            AgentCommandV1::Steer {
                agent_id: b,
                epoch: b_epoch,
                text: "override".into()
            }
        ),
        Err(ControllerError::Permission)
    );
    assert_eq!(
        controller.execute(
            AgentActor::Agent(a),
            "self-control",
            AgentCommandV1::FollowupTask {
                agent_id: a,
                text: "loop forever".into()
            }
        ),
        Err(ControllerError::Permission)
    );
    let forged = r#"{"type":"send_message","agent_id":2,"text":"x","sender":1}"#;
    assert!(serde_json::from_str::<AgentCommandV1>(forged).is_err());
}

#[test]
fn request_replay_is_namespaced_exact_and_does_not_duplicate_input() {
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let command = spawn(AgentIdV1(1), "a", vec![]);
    let first = controller
        .execute(AgentActor::Operator, "same", command.clone())
        .unwrap();
    let revision = controller.revision();
    let retry = controller
        .execute(AgentActor::Operator, "same", command)
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.agent_id, first.agent_id);
    assert_eq!(controller.revision(), revision);
    assert_eq!(
        controller
            .inspect(AgentActor::Operator, first.agent_id)
            .unwrap()
            .queued_messages,
        1
    );
    assert_eq!(
        controller.execute(
            AgentActor::Operator,
            "same",
            AgentCommandV1::SendMessage {
                agent_id: first.agent_id,
                text: "different".into()
            }
        ),
        Err(ControllerError::RequestConflict)
    );
}

#[test]
fn busy_followup_does_not_double_claim_and_stale_steer_is_rejected() {
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let a = child(&mut controller, "a");
    let epoch = controller.begin_turn(a).unwrap().unwrap();
    let first = controller.deliver(a, epoch, true).unwrap();
    controller.mark_consumed(a, epoch, &[first[0].id]).unwrap();
    let next_task = controller
        .execute(
            AgentActor::Operator,
            "followup",
            AgentCommandV1::FollowupTask {
                agent_id: a,
                text: "next task".into(),
            },
        )
        .unwrap();
    assert_eq!(controller.begin_turn(a).unwrap(), None);
    assert!(controller.deliver(a, epoch, true).unwrap().is_empty());
    controller
        .finish_turn(a, epoch, "done", 10, 10, true)
        .unwrap();
    let next = controller.begin_turn(a).unwrap().unwrap();
    assert_eq!(
        controller.execute(
            AgentActor::Operator,
            "stale-steer",
            AgentCommandV1::Steer {
                agent_id: a,
                epoch,
                text: "old".into()
            }
        ),
        Err(ControllerError::StaleEpoch)
    );
    let delivered = controller.deliver(a, next, true).unwrap();
    assert_eq!(delivered[0].id, next_task.message_id.unwrap());
    assert_eq!(
        controller.mark_consumed(a, epoch, &[delivered[0].id]),
        Err(ControllerError::StaleEpoch)
    );
}

#[test]
fn interrupt_keeps_handle_close_is_terminal_and_unconsumed_is_not_consumed() {
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let a = child(&mut controller, "a");
    let epoch = controller.begin_turn(a).unwrap().unwrap();
    let input = controller.deliver(a, epoch, true).unwrap();
    controller
        .execute(
            AgentActor::Operator,
            "interrupt",
            AgentCommandV1::Interrupt { agent_id: a, epoch },
        )
        .unwrap();
    controller
        .finish_turn(a, epoch, "interrupted and reaped", 0, 0, true)
        .unwrap();
    assert_eq!(
        controller.inspect(AgentActor::Operator, a).unwrap().state,
        AgentStateV1::Idle
    );
    assert_eq!(
        controller
            .message(AgentActor::Operator, input[0].id)
            .unwrap()
            .state,
        AgentMessageStateV1::Rejected
    );
    controller
        .execute(
            AgentActor::Operator,
            "resume",
            AgentCommandV1::FollowupTask {
                agent_id: a,
                text: "resume".into(),
            },
        )
        .unwrap();
    assert!(controller.begin_turn(a).unwrap().is_some());
    let active = controller
        .inspect(AgentActor::Operator, a)
        .unwrap()
        .state
        .epoch()
        .unwrap();
    controller
        .execute(
            AgentActor::Operator,
            "close",
            AgentCommandV1::Close {
                agent_id: a,
                include_descendants: true,
            },
        )
        .unwrap();
    controller
        .finish_turn(a, active, "closed and reaped", 0, 0, true)
        .unwrap();
    assert_eq!(
        controller.execute(
            AgentActor::Operator,
            "late",
            AgentCommandV1::SendMessage {
                agent_id: a,
                text: "late".into()
            }
        ),
        Err(ControllerError::Closed)
    );
}

#[test]
fn ambiguous_commit_poisons_live_owner_and_reopen_quarantines_active_epoch() {
    let store = Store::default();
    let mut controller = AgentController::open(store.clone(), config(8)).unwrap();
    let a = child(&mut controller, "a");
    let epoch = controller.begin_turn(a).unwrap().unwrap();
    let initial = controller.deliver(a, epoch, true).unwrap();
    store.0.lock().unwrap().failure = Some((ControllerStoreError::OutcomeUnknown, true));
    assert_eq!(
        controller.mark_consumed(a, epoch, &[initial[0].id]),
        Err(ControllerError::Store(ControllerStoreError::OutcomeUnknown))
    );
    assert_eq!(
        controller.list(AgentActor::Operator),
        Err(ControllerError::Poisoned)
    );
    let mut recovered = AgentController::open(store, config(8)).unwrap();
    assert_eq!(
        recovered.inspect(AgentActor::Operator, a).unwrap().state,
        AgentStateV1::RecoveryRequired { epoch }
    );
    assert_eq!(
        recovered.begin_turn(a),
        Err(ControllerError::RecoveryRequired)
    );
    assert_eq!(
        recovered
            .message(AgentActor::Operator, initial[0].id)
            .unwrap()
            .state,
        AgentMessageStateV1::Consumed { epoch }
    );
    assert_eq!(
        recovered.reconcile_stopped(a, epoch, false, false),
        Err(ControllerError::RecoveryRequired)
    );
    recovered.reconcile_stopped(a, epoch, true, false).unwrap();
    assert_eq!(recovered.begin_turn(a).unwrap(), None);
    recovered
        .execute(
            AgentActor::Operator,
            "explicit-recovery-task",
            AgentCommandV1::FollowupTask {
                agent_id: a,
                text: "continue after reconciliation".into(),
            },
        )
        .unwrap();
    let next = recovered.begin_turn(a).unwrap().unwrap();
    assert!(next.incarnation > epoch.incarnation);
    assert_eq!(
        recovered.finish_turn(a, epoch, "late", 0, 0, true),
        Err(ControllerError::StaleEpoch)
    );
}

#[test]
fn capacity_and_write_conflicts_are_atomic() {
    let mut controller = AgentController::open(Store::default(), config(1)).unwrap();
    let first = controller
        .execute(
            AgentActor::Operator,
            "writer-a",
            spawn(AgentIdV1(1), "writer a", vec!["src/a".into()]),
        )
        .unwrap();
    let revision = controller.revision();
    assert_eq!(
        controller.execute(
            AgentActor::Operator,
            "writer-b",
            spawn(AgentIdV1(1), "writer b", vec!["src".into()])
        ),
        Err(ControllerError::Permission)
    );
    assert_eq!(controller.revision(), revision);
    assert_eq!(
        controller.execute(
            AgentActor::Operator,
            "full",
            AgentCommandV1::SendMessage {
                agent_id: first.agent_id,
                text: "full".into()
            }
        ),
        Err(ControllerError::Capacity)
    );
    assert_eq!(controller.revision(), revision);
    assert_eq!(controller.list(AgentActor::Operator).unwrap().len(), 2);
}

#[test]
fn tampered_snapshot_cannot_bypass_authority_budget_or_mailbox_hash() {
    for field in [
        "label",
        "budget",
        "write_paths",
        "reserved_tokens",
        "mailbox",
    ] {
        let store = Store::default();
        let mut controller = AgentController::open(store.clone(), config(8)).unwrap();
        child(&mut controller, "a");
        let mut value = serde_json::to_value(controller.snapshot()).unwrap();
        match field {
            "label" => value["agents"]["2"]["view"]["label"] = serde_json::json!("bad\nlabel"),
            "budget" => value["agents"]["1"]["view"]["budget"]["tokens"] = serde_json::json!(1),
            "write_paths" => {
                value["agents"]["2"]["view"]["write_paths"] = serde_json::json!(["../escape"])
            }
            "reserved_tokens" => value["agents"]["1"]["reserved_tokens"] = serde_json::json!(0),
            "mailbox" => value["mailbox"]["messages"]["1"]["text"] = serde_json::json!("forged"),
            _ => unreachable!(),
        }
        store.0.lock().unwrap().snapshot = Some(serde_json::from_value(value).unwrap());
        assert!(
            AgentController::open(store, config(8)).is_err(),
            "tampering {field} must be refused"
        );
    }
}

#[test]
fn runtime_wall_anchor_cannot_be_recovered_with_zero_usage() {
    let store = Store::default();
    let cfg = config(8);
    let mut controller = AgentController::open(store.clone(), cfg.clone()).unwrap();
    let id = child(&mut controller, "wall-recovery");
    let epoch = controller.begin_runtime_turn(id, 10_000).unwrap().unwrap();
    drop(controller);
    let mut reopened = AgentController::open(store, cfg).unwrap();
    assert_eq!(reopened.recovery_anchor(id, epoch).unwrap(), Some(10_000));
    assert!(matches!(
        reopened.reconcile_stopped(id, epoch, true, false),
        Err(ControllerError::RecoveryRequired)
    ));
    assert!(
        reopened
            .reconcile_stopped_with_usage(id, epoch, true, false, Default::default())
            .is_err()
    );
    reopened
        .reconcile_stopped_with_usage(
            id,
            epoch,
            true,
            false,
            iteron_protocol::agent_control::AgentUsageV1 {
                wall_ms: 100,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, id)
            .unwrap()
            .usage
            .wall_ms,
        100
    );
}

#[test]
fn workflow_claim_binds_exact_agent_epoch_and_typed_terminal_atomically() {
    use iteron_agents::{AgentWorkflowClaim, AgentWorkflowTerminal};
    let mut controller = AgentController::open(Store::default(), config(8)).unwrap();
    let id = child(&mut controller, "workflow-agent");
    let epoch = controller.begin_turn(id).unwrap().unwrap();
    let inputs = controller.deliver(id, epoch, true).unwrap();
    controller
        .mark_consumed(
            id,
            epoch,
            &inputs.iter().map(|message| message.id).collect::<Vec<_>>(),
        )
        .unwrap();
    controller
        .finish_turn(id, epoch, "initial task", 1, 0, true)
        .unwrap();
    let claim = AgentWorkflowClaim {
        workflow_id: "workflow".into(),
        node_id: 1,
        attempt: 1,
        input_digest: "a".repeat(64),
        assigned_agent: id,
        task: "exact task".into(),
        budget: AgentBudgetV1 {
            turns: 1,
            tokens: 10,
            cost_microusd: 10,
            wall_ms: 100,
        },
        deadline_unix_ms: 10_100,
    };
    let before = controller.revision();
    let lease = controller
        .claim_workflow_task(claim.clone(), 10_000)
        .unwrap();
    assert_eq!(controller.revision(), before + 1);
    assert_eq!(lease.agent.agent_id, id);
    assert_eq!(lease.initial.len(), 1);
    assert_eq!(lease.initial[0].text.as_deref(), Some("exact task"));
    assert!(
        controller
            .claim_workflow_task(claim.clone(), 10_001)
            .unwrap()
            .replayed
    );
    let mut changed = claim.clone();
    changed.task = "altered".into();
    assert!(matches!(
        controller.claim_workflow_task(changed, 10_001),
        Err(ControllerError::RequestConflict)
    ));
    controller
        .mark_consumed(id, lease.epoch, &[lease.initial[0].id])
        .unwrap();
    controller
        .finish_turn_with_terminal(
            id,
            lease.epoch,
            "stopped physically",
            iteron_protocol::agent_control::AgentUsageV1 {
                tokens: 2,
                cost_microusd: 1,
                wall_ms: 20,
                ..Default::default()
            },
            true,
            AgentWorkflowTerminal::Cancelled,
        )
        .unwrap();
    let completion = controller.workflow_completion(&claim).unwrap().unwrap();
    assert_eq!(completion.terminal, AgentWorkflowTerminal::Cancelled);
    assert!(completion.effects_known);
    assert_eq!(completion.epoch, lease.epoch);
    assert!(matches!(
        controller.claim_workflow_task(claim, 10_050),
        Err(ControllerError::RecoveryRequired)
    ));
}

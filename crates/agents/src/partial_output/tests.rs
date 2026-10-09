use super::*;
use crate::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, ControllerStoreError,
};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentCommandV1};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, EffectId, RunId, TenantId, TurnId};

#[derive(Clone, Default)]
struct Store(Option<AgentControllerSnapshot>);
impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.0.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self.0.as_ref().map(AgentControllerSnapshot::revision) != expected {
            return Err(ControllerStoreError::Conflict);
        }
        self.0 = Some(next.clone());
        Ok(())
    }
}
fn running() -> (
    AgentController<Store>,
    AgentViewV1,
    AgentEpochV1,
    AgentMessageIdV1,
    AgentOutputSourceV1,
) {
    let budget = AgentBudgetV1 {
        turns: 4,
        tokens: 100,
        cost_microusd: 0,
        wall_ms: 10_000,
    };
    let mut controller = AgentController::open(
        Store::default(),
        AgentControllerConfig {
            workspace_scope: "partial-scope".into(),
            root_capabilities: CapabilitySet::only(Capability::ReadOnly),
            root_budget: AgentBudgetV1 {
                turns: 20,
                tokens: 1_000,
                ..budget
            },
            max_agents: 4,
            max_pending_per_agent: 8,
        },
    )
    .unwrap();
    let receipt = controller
        .execute(
            AgentActor::Operator,
            "partial-spawn",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "worker".into(),
                task: "inspect source".into(),
                capabilities: CapabilitySet::only(Capability::ReadOnly),
                budget,
                write_paths: vec![],
            },
        )
        .unwrap();
    let epoch = controller.begin_turn(receipt.agent_id).unwrap().unwrap();
    let view = controller
        .inspect(AgentActor::Operator, receipt.agent_id)
        .unwrap();
    let source = AgentOutputSourceV1 {
        tenant: TenantId("tenant".into()),
        run_id: RunId("child-run".into()),
        turn: TurnId(1),
        provider_intent_seq: 5,
        effect_id: EffectId("turn-1-provider-1".into()),
    };
    (controller, view, epoch, receipt.message_id.unwrap(), source)
}

#[test]
fn observed_prefix_is_bounded_and_cannot_replace_terminal_or_claim_stale_epochs() {
    let (_, mut view, epoch, task, source) = running();
    let mut outputs = AgentPartialOutputOwner::new(4);
    outputs
        .append(&view, epoch, task, &source, "actual partial ")
        .unwrap();
    outputs
        .append(
            &view,
            epoch,
            task,
            &source,
            &"中".repeat(MAX_AGENT_TEXT_BYTES),
        )
        .unwrap();
    outputs.decorate(&mut view);
    let partial = view.partial_output.as_ref().unwrap();
    assert_eq!(partial.state, AgentPartialStateV1::Observed);
    assert_eq!(partial.source.as_ref(), Some(&source));
    assert_eq!(partial.task_message_id, Some(task));
    assert!(partial.text.as_ref().unwrap().len() <= MAX_AGENT_TEXT_BYTES);
    assert!(partial.truncated);
    assert!(view.last_summary.is_none());
    assert!(matches!(view.state, AgentStateV1::Running { .. }));
    assert_eq!(
        outputs.append(
            &view,
            AgentEpochV1 {
                turn: epoch.turn + 1,
                ..epoch
            },
            task,
            &source,
            "stale"
        ),
        Err(ControllerError::StaleEpoch)
    );
    let mut different = source.clone();
    different.effect_id = EffectId("foreign".into());
    assert_eq!(
        outputs.append(&view, epoch, task, &different, "wrong physical source"),
        Err(ControllerError::StaleEpoch)
    );
}

#[test]
fn actual_controller_restart_marks_partial_unknown_and_new_epoch_rejects_old_source() {
    let (mut controller, view, epoch, task, source) = running();
    let mut outputs = AgentPartialOutputOwner::new(4);
    outputs
        .append(&view, epoch, task, &source, "ephemeral output")
        .unwrap();
    let store = Store(Some(controller.snapshot().clone()));
    let restored = AgentController::open(store, controller.config().clone()).unwrap();
    let mut recovered = restored
        .inspect(AgentActor::Operator, view.agent_id)
        .unwrap();
    outputs.decorate(&mut recovered);
    let partial = recovered.partial_output.unwrap();
    assert_eq!(partial.state, AgentPartialStateV1::Unknown);
    assert!(partial.text.is_none() && partial.source.is_none());
    assert_eq!(
        outputs.append(
            &view,
            epoch,
            AgentMessageIdV1(task.0 + 1),
            &source,
            "wrong task"
        ),
        Err(ControllerError::StaleEpoch)
    );
    controller
        .finish_turn(view.agent_id, epoch, "terminal", 0, 0, true)
        .unwrap();
    controller
        .execute(
            AgentActor::Operator,
            "next-task",
            AgentCommandV1::FollowupTask {
                agent_id: view.agent_id,
                text: "new task".into(),
            },
        )
        .unwrap();
    let next = controller.begin_turn(view.agent_id).unwrap().unwrap();
    let mut current = controller
        .inspect(AgentActor::Operator, view.agent_id)
        .unwrap();
    outputs.decorate(&mut current);
    assert!(current.partial_output.is_none());
    assert_eq!(
        outputs.append(&current, epoch, task, &source, "old epoch"),
        Err(ControllerError::StaleEpoch)
    );
    assert_ne!(next, epoch);
}

#[test]
fn durable_snapshot_cannot_forge_an_ephemeral_observed_result() {
    let (controller, mut view, epoch, task, source) = running();
    let mut outputs = AgentPartialOutputOwner::new(4);
    outputs
        .append(&view, epoch, task, &source, "forged persisted partial")
        .unwrap();
    outputs.decorate(&mut view);
    let mut value = serde_json::to_value(controller.snapshot()).unwrap();
    value["agents"][view.agent_id.0.to_string()]["view"]["partial_output"] =
        serde_json::to_value(view.partial_output).unwrap();
    let snapshot = serde_json::from_value(value).unwrap();
    assert!(matches!(
        AgentController::open(Store(Some(snapshot)), controller.config().clone()),
        Err(ControllerError::Invalid(_))
    ));
}

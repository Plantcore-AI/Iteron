use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, AgentProviderBudgetRequest, AgentProviderBudgetTerminal,
    ControllerError, ControllerStoreError,
};
use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentEpochV1, AgentIdV1, AgentStateV1, AgentUsageV1,
};
use iteron_protocol::{
    Capability, ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity,
    capability_set::CapabilitySet,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Store(Arc<Mutex<Option<AgentControllerSnapshot>>>);
impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        let mut stored = self.0.lock().unwrap();
        if stored.as_ref().map(AgentControllerSnapshot::revision) != expected {
            return Err(ControllerStoreError::Conflict);
        }
        *stored = Some(next.clone());
        Ok(())
    }
}
fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: u64::from(turns) * 1000,
        cost_microusd: u64::from(turns) * 1000,
        wall_ms: 60000,
    }
}
fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "provider-budget-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: budget(6),
        max_agents: 8,
        max_pending_per_agent: 8,
    }
}
fn sha(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn request(
    id: AgentIdV1,
    epoch: Option<AgentEpochV1>,
    scope: &str,
    physical: u32,
    tokens: u64,
) -> AgentProviderBudgetRequest {
    AgentProviderBudgetRequest {
        agent_id: id,
        epoch,
        scope_sha256: scope.into(),
        effect_id: format!("provider:{physical}"),
        turn: 1,
        route: ProviderRouteAttemptIdentity {
            version: ProviderRouteAttemptAccountingVersion::V1,
            route_id: sha('a'),
            physical_attempt: physical,
            max_cost_reservation_microusd: Some(tokens),
        },
        max_tokens: tokens,
        max_cost_microusd: tokens,
    }
}
fn child(controller: &mut AgentController<Store>) -> AgentIdV1 {
    controller
        .execute(
            AgentActor::Operator,
            "child",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "child".into(),
                task: "work".into(),
                capabilities: CapabilitySet::only(Capability::ReadOnly),
                budget: budget(4),
                write_paths: vec![],
            },
        )
        .unwrap()
        .agent_id
}
fn settle(
    controller: &mut AgentController<Store>,
    request: &AgentProviderBudgetRequest,
    terminal: AgentProviderBudgetTerminal,
    c: char,
) -> Result<(), ControllerError> {
    controller.settle_provider_budget(
        request.agent_id,
        &request.scope_sha256,
        &request.effect_id,
        &request.route,
        terminal,
        &sha(c),
    )
}

#[test]
fn root_provider_and_child_lifetime_reservations_share_one_atomic_cap() {
    let mut controller = AgentController::open(Store::default(), config()).unwrap();
    let child = child(&mut controller);
    let root = controller.root_id();
    let scope = sha('b');
    controller.bind_provider_budget(root, &scope).unwrap();
    assert!(matches!(
        controller.reserve_provider_budget(request(root, None, &scope, 1, 2001)),
        Err(ControllerError::Budget)
    ));
    let first = request(root, None, &scope, 1, 2000);
    controller.reserve_provider_budget(first.clone()).unwrap();
    assert!(matches!(
        controller.reserve_provider_budget(request(root, None, &scope, 2, 1)),
        Err(ControllerError::Budget)
    ));
    settle(
        &mut controller,
        &first,
        AgentProviderBudgetTerminal::Known {
            tokens: 500,
            cost_microusd: 500,
        },
        'c',
    )
    .unwrap();
    let after = controller.inspect(AgentActor::Operator, root).unwrap();
    assert_eq!(after.usage.turns, 1);
    assert_eq!(after.usage.tokens, 500);
    assert_eq!(after.reserved.tokens, 4000);
    controller
        .reserve_provider_budget(request(root, None, &scope, 2, 1500))
        .unwrap();
    assert!(matches!(
        controller.reserve_provider_budget(request(root, None, &scope, 3, 0)),
        Err(ControllerError::Budget)
    ));
    assert_eq!(
        controller
            .inspect(AgentActor::Operator, child)
            .unwrap()
            .usage
            .turns,
        0
    );
}

#[test]
fn every_child_physical_attempt_is_admitted_before_io_and_settled_once() {
    let mut controller = AgentController::open(Store::default(), config()).unwrap();
    let id = child(&mut controller);
    let epoch = controller.begin_turn(id).unwrap().unwrap();
    let scope = sha('b');
    controller.bind_provider_budget(id, &scope).unwrap();
    for physical in 1..=4 {
        let attempt = request(id, Some(epoch), &scope, physical, 100);
        controller.reserve_provider_budget(attempt.clone()).unwrap();
        let terminal = AgentProviderBudgetTerminal::Known {
            tokens: 30,
            cost_microusd: 20,
        };
        settle(&mut controller, &attempt, terminal.clone(), 'c').unwrap();
        settle(&mut controller, &attempt, terminal, 'c').unwrap();
        assert!(matches!(
            controller.reserve_provider_budget(attempt.clone()),
            Err(ControllerError::RequestConflict)
        ));
        assert!(matches!(
            settle(
                &mut controller,
                &attempt,
                AgentProviderBudgetTerminal::Known {
                    tokens: 31,
                    cost_microusd: 20
                },
                'd'
            ),
            Err(ControllerError::RequestConflict)
        ));
    }
    assert!(matches!(
        controller.reserve_provider_budget(request(id, Some(epoch), &scope, 5, 100)),
        Err(ControllerError::Budget)
    ));
    // Runtime logical accounting cannot overwrite or double-charge actual physical receipts.
    controller
        .finish_turn_with_usage(
            id,
            epoch,
            "done",
            AgentUsageV1 {
                turns: 1,
                tokens: 999,
                cost_microusd: 999,
                wall_ms: 1,
            },
            true,
        )
        .unwrap();
    let view = controller.inspect(AgentActor::Operator, id).unwrap();
    assert_eq!(view.usage.turns, 4);
    assert_eq!(view.usage.tokens, 120);
    assert_eq!(view.usage.cost_microusd, 80);
    assert_eq!(view.state, AgentStateV1::Idle);
}

#[test]
fn restart_keeps_all_unmeasured_reservations_until_each_exact_terminal() {
    let store = Store::default();
    let scope = sha('b');
    let mut controller = AgentController::open(store.clone(), config()).unwrap();
    let root = controller.root_id();
    controller.bind_provider_budget(root, &scope).unwrap();
    let first = request(root, None, &scope, 1, 1000);
    let second = request(root, None, &scope, 2, 1000);
    controller.reserve_provider_budget(first.clone()).unwrap();
    controller.reserve_provider_budget(second.clone()).unwrap();
    drop(controller);
    let mut reopened = AgentController::open(store, config()).unwrap();
    assert!(reopened.provider_budget_recovery_required());
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, root)
            .unwrap()
            .reserved
            .tokens,
        2000
    );
    settle(
        &mut reopened,
        &first,
        AgentProviderBudgetTerminal::Known {
            tokens: 10,
            cost_microusd: 10,
        },
        'c',
    )
    .unwrap();
    assert!(reopened.provider_budget_recovery_required());
    assert!(matches!(
        reopened.reserve_provider_budget(request(root, None, &scope, 3, 1)),
        Err(ControllerError::RecoveryRequired)
    ));
    settle(
        &mut reopened,
        &second,
        AgentProviderBudgetTerminal::NotDispatched,
        'd',
    )
    .unwrap();
    assert!(!reopened.provider_budget_recovery_required());
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, root)
            .unwrap()
            .reserved
            .tokens,
        0
    );
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, root)
            .unwrap()
            .usage
            .tokens,
        10
    );
}

#[test]
fn unknown_or_overrun_terminal_quarantines_without_inventing_zero_usage() {
    let mut controller = AgentController::open(Store::default(), config()).unwrap();
    let root = controller.root_id();
    let scope = sha('b');
    controller.bind_provider_budget(root, &scope).unwrap();
    let attempt = request(root, None, &scope, 1, 100);
    controller.reserve_provider_budget(attempt.clone()).unwrap();
    assert!(matches!(
        settle(
            &mut controller,
            &attempt,
            AgentProviderBudgetTerminal::Known {
                tokens: 101,
                cost_microusd: 0
            },
            'c'
        ),
        Err(ControllerError::Budget)
    ));
    assert!(controller.provider_budget_recovery_required());
    assert_eq!(
        controller
            .inspect(AgentActor::Operator, root)
            .unwrap()
            .reserved
            .tokens,
        100
    );
    assert!(matches!(
        controller.bind_provider_budget(root, &sha('d')),
        Err(ControllerError::RequestConflict)
    ));
}

#[test]
fn snapshot_cannot_erase_provider_reservation_or_reassign_run() {
    let store = Store::default();
    let scope = sha('b');
    let mut controller = AgentController::open(store.clone(), config()).unwrap();
    let root = controller.root_id();
    controller.bind_provider_budget(root, &scope).unwrap();
    controller
        .reserve_provider_budget(request(root, None, &scope, 1, 100))
        .unwrap();
    drop(controller);
    let mut payload = serde_json::to_value(store.0.lock().unwrap().as_ref().unwrap()).unwrap();
    payload["agents"]["1"]["reserved_tokens"] = serde_json::json!(0);
    *store.0.lock().unwrap() = Some(serde_json::from_value(payload).unwrap());
    assert!(matches!(
        AgentController::open(store, config()),
        Err(ControllerError::Invalid(_))
    ));
}

#[test]
fn finite_zero_reservation_requires_exact_some_zero_identity() {
    let mut controller = AgentController::open(Store::default(), config()).unwrap();
    let root = controller.root_id();
    let scope = sha('b');
    controller.bind_provider_budget(root, &scope).unwrap();
    let mut unsigned = request(root, None, &scope, 1, 0);
    unsigned.route.max_cost_reservation_microusd = None;
    assert!(matches!(
        controller.reserve_provider_budget(unsigned),
        Err(ControllerError::Invalid(_))
    ));
    controller
        .reserve_provider_budget(request(root, None, &scope, 1, 0))
        .unwrap();
}

//! Real controller CAS and reopen, including original child reservations and physical fork scope.
use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, AgentProviderBudgetBaseline, AgentProviderBudgetRequest,
    AgentProviderBudgetTerminal, ControllerError, ControllerStoreError,
};
use iteron_protocol::agent_cohort::{AgentCohortMainRunV1, AgentCohortOriginV1, provider_scope};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentUsageV1};
use iteron_protocol::{
    Capability, ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity, RunId,
    TenantId, capability_set::CapabilitySet,
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
fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "cohort-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: budget(20),
        max_agents: 8,
        max_pending_per_agent: 8,
    }
}
fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: u64::from(turns) * 1000,
        cost_microusd: u64::from(turns) * 1000,
        wall_ms: 60_000,
    }
}
fn sha(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn setup(store: Store) -> (AgentController<Store>, AgentCohortOriginV1) {
    let mut owner = AgentController::open(store, config()).unwrap();
    let origin = AgentCohortOriginV1 {
        version: 1,
        tenant: TenantId("tenant".into()),
        run_id: RunId("owning-main".into()),
        config_sha256: owner.snapshot().cohort_config_sha256().unwrap(),
    };
    owner
        .bind_provider_budget_baseline(
            &origin.provider_scope(),
            AgentProviderBudgetBaseline {
                usage: AgentUsageV1::default(),
                through_sequence: 1,
                history_sha256: sha('a'),
                financial_room_microusd: 20_000,
            },
        )
        .unwrap();
    owner.bind_cohort_origin(origin.clone()).unwrap();
    (owner, origin)
}
fn fork(origin: &AgentCohortOriginV1, name: &str) -> AgentCohortMainRunV1 {
    let run_id = RunId(name.into());
    AgentCohortMainRunV1 {
        tenant: origin.tenant.clone(),
        scope_sha256: provider_scope(&origin.tenant, &run_id),
        run_id,
        admitted_through_sequence: 2,
        admission_sha256: sha('b'),
    }
}
fn request(scope: &str, amount: u64) -> AgentProviderBudgetRequest {
    AgentProviderBudgetRequest {
        agent_id: AgentIdV1(1),
        scope_sha256: scope.into(),
        epoch: None,
        effect_id: "physical-1".into(),
        turn: 1,
        route: ProviderRouteAttemptIdentity {
            version: ProviderRouteAttemptAccountingVersion::V1,
            route_id: sha('c'),
            physical_attempt: 1,
            max_cost_reservation_microusd: Some(amount),
        },
        max_tokens: amount,
        max_cost_microusd: amount,
    }
}

#[test]
fn same_root_fork_keeps_child_reservations_and_known_charges_across_native_reopen() {
    let store = Store::default();
    let (mut owner, origin) = setup(store.clone());
    let child = owner
        .execute(
            AgentActor::Operator,
            "child",
            AgentCommandV1::Spawn {
                parent_id: owner.root_id(),
                label: "child".into(),
                task: "remember".into(),
                capabilities: config().root_capabilities,
                budget: budget(16),
                write_paths: vec![],
            },
        )
        .unwrap()
        .agent_id;
    let original = request(&origin.provider_scope(), 1500);
    owner.reserve_provider_budget(original.clone()).unwrap();
    owner
        .settle_provider_budget(
            owner.root_id(),
            &original.scope_sha256,
            &original.effect_id,
            &original.route,
            AgentProviderBudgetTerminal::Known {
                tokens: 500,
                cost_microusd: 500,
            },
            &sha('d'),
        )
        .unwrap();
    let run = fork(&origin, "fork-main");
    owner.attach_cohort_main_run(run.clone()).unwrap();
    let before = owner
        .inspect(AgentActor::Operator, owner.root_id())
        .unwrap();
    drop(owner);
    let mut reopened = AgentController::open(store, config()).unwrap();
    assert_eq!(reopened.root_id(), AgentIdV1(1));
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, reopened.root_id())
            .unwrap()
            .reserved,
        before.reserved
    );
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, child)
            .unwrap()
            .budget,
        budget(16)
    );
    assert_eq!(reopened.snapshot().cohort_origin(), Some(&origin));
    reopened.attach_cohort_main_run(run.clone()).unwrap();
    reopened
        .bind_provider_budget(reopened.root_id(), &run.scope_sha256)
        .unwrap();
    assert_eq!(
        reopened.reserve_provider_budget(request(&run.scope_sha256, 3501)),
        Err(ControllerError::Budget)
    );
    reopened
        .reserve_provider_budget(request(&run.scope_sha256, 3500))
        .unwrap();
    assert!(
        reopened
            .bind_provider_budget(child, &run.scope_sha256)
            .is_err()
    );
    assert_eq!(
        reopened.list(AgentActor::Operator).unwrap().len(),
        2,
        "fork never constructs a second Main Agent identity"
    );
}

#[test]
fn unknown_keeps_original_reservations_and_prevents_a_new_fork_binding() {
    let store = Store::default();
    let (mut owner, origin) = setup(store.clone());
    let run = fork(&origin, "known-fork");
    owner.attach_cohort_main_run(run.clone()).unwrap();
    owner
        .reserve_provider_budget(request(&origin.provider_scope(), 1000))
        .unwrap();
    drop(owner);
    let mut reopened = AgentController::open(store, config()).unwrap();
    assert!(reopened.provider_budget_recovery_required());
    // Exact already admitted run is readable; neither a new alias nor actual IO can clear unknown.
    reopened.attach_cohort_main_run(run.clone()).unwrap();
    assert_eq!(
        reopened.attach_cohort_main_run(fork(&origin, "new-fork")),
        Err(ControllerError::RecoveryRequired)
    );
    assert_eq!(
        reopened.reserve_provider_budget(request(&run.scope_sha256, 0)),
        Err(ControllerError::RecoveryRequired)
    );
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, reopened.root_id())
            .unwrap()
            .reserved
            .cost_microusd,
        1000
    );
}

#[test]
fn tampered_origin_tenant_configuration_and_scope_are_rejected_before_live_authority() {
    for field in ["origin", "tenant", "scope", "config"] {
        let store = Store::default();
        let (mut owner, origin) = setup(store.clone());
        let run = fork(&origin, "fork-main");
        owner.attach_cohort_main_run(run.clone()).unwrap();
        drop(owner);
        let mut json = serde_json::to_value(store.0.lock().unwrap().clone().unwrap()).unwrap();
        match field {
            "origin" => json["cohort_bindings"]["origin"] = serde_json::Value::Null,
            "tenant" => {
                json["cohort_bindings"]["main_runs"][&run.scope_sha256]["tenant"] =
                    serde_json::json!("foreign")
            }
            "scope" => {
                json["cohort_bindings"]["main_runs"][&run.scope_sha256]["scope_sha256"] =
                    serde_json::json!(sha('f'))
            }
            _ => json["cohort_bindings"]["origin"]["config_sha256"] = serde_json::json!(sha('f')),
        }
        *store.0.lock().unwrap() = Some(serde_json::from_value(json).unwrap());
        assert!(
            AgentController::open(store, config()).is_err(),
            "tampered {field}"
        );
    }
}

#[test]
fn exact_admission_prefix_cannot_be_replaced_or_rebound_to_another_run() {
    let (mut owner, origin) = setup(Store::default());
    let run = fork(&origin, "fork-main");
    owner.attach_cohort_main_run(run.clone()).unwrap();
    let mut replacement = run.clone();
    replacement.admission_sha256 = sha('f');
    assert_eq!(
        owner.attach_cohort_main_run(replacement),
        Err(ControllerError::RequestConflict)
    );
    let mut replacement = run;
    replacement.run_id = RunId("another-run".into());
    assert!(owner.attach_cohort_main_run(replacement).is_err());
    let mut foreign = fork(&origin, "foreign");
    foreign.tenant = TenantId("foreign".into());
    foreign.scope_sha256 = provider_scope(&foreign.tenant, &foreign.run_id);
    assert_eq!(
        owner.attach_cohort_main_run(foreign),
        Err(ControllerError::RequestConflict)
    );
}

#[test]
fn legacy_controller_snapshot_does_not_gain_an_empty_field_during_hash_verification() {
    let owner = AgentController::open(Store::default(), config()).unwrap();
    let bytes = serde_json::to_vec(owner.snapshot()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("cohort_bindings").is_none());
    let recovered: AgentControllerSnapshot = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&recovered).unwrap(), bytes);
}

#[test]
fn advisory_allowance_retains_child_reservations_and_pending_physical_bounds() {
    let store = Store::default();
    let (mut owner, origin) = setup(store.clone());
    owner
        .execute(
            AgentActor::Operator,
            "reserved-child",
            AgentCommandV1::Spawn {
                parent_id: owner.root_id(),
                label: "child".into(),
                task: "work".into(),
                capabilities: config().root_capabilities,
                budget: budget(16),
                write_paths: vec![],
            },
        )
        .unwrap();
    let room = owner
        .provider_budget_allowance(owner.root_id(), None)
        .unwrap();
    assert_eq!(
        (room.turns, room.tokens, room.cost_microusd),
        (4, 4000, 4000)
    );
    let physical = request(&origin.provider_scope(), 1000);
    owner.reserve_provider_budget(physical.clone()).unwrap();
    let room = owner
        .provider_budget_allowance(owner.root_id(), None)
        .unwrap();
    assert_eq!(
        (room.turns, room.tokens, room.cost_microusd),
        (3, 3000, 3000)
    );
    drop(owner);
    let reopened = AgentController::open(store, config()).unwrap();
    assert_eq!(
        reopened.provider_budget_allowance(reopened.root_id(), None),
        Err(ControllerError::RecoveryRequired)
    );
}

#[test]
fn first_physical_slot_is_already_owned_but_not_dispatched_retry_still_uses_a_slot() {
    let (mut owner, _) = setup(Store::default());
    let id = owner
        .execute(
            AgentActor::Operator,
            "two-slots",
            AgentCommandV1::Spawn {
                parent_id: owner.root_id(),
                label: "child".into(),
                task: "work".into(),
                capabilities: config().root_capabilities,
                budget: budget(2),
                write_paths: vec![],
            },
        )
        .unwrap()
        .agent_id;
    let epoch = owner.begin_turn(id).unwrap().unwrap();
    let scope = sha('e');
    owner.bind_provider_budget(id, &scope).unwrap();
    assert_eq!(
        owner
            .provider_budget_allowance(id, Some(epoch))
            .unwrap()
            .turns,
        2
    );
    let mut first = request(&scope, 100);
    first.agent_id = id;
    first.epoch = Some(epoch);
    owner.reserve_provider_budget(first.clone()).unwrap();
    assert_eq!(
        owner
            .provider_budget_allowance(id, Some(epoch))
            .unwrap()
            .turns,
        1
    );
    owner
        .settle_provider_budget(
            id,
            &scope,
            &first.effect_id,
            &first.route,
            AgentProviderBudgetTerminal::NotDispatched,
            &sha('f'),
        )
        .unwrap();
    let room = owner.provider_budget_allowance(id, Some(epoch)).unwrap();
    assert_eq!(
        (room.turns, room.tokens, room.cost_microusd),
        (1, 2000, 2000)
    );
    let mut second = first.clone();
    second.effect_id = "physical-2".into();
    second.route.physical_attempt = 2;
    owner.reserve_provider_budget(second).unwrap();
    assert_eq!(
        owner
            .provider_budget_allowance(id, Some(epoch))
            .unwrap()
            .turns,
        0
    );
    assert_eq!(
        owner.provider_budget_allowance(id, None),
        Err(ControllerError::StaleEpoch)
    );
}

#[test]
fn workflow_allowance_uses_the_exact_node_envelope_including_live_reservations() {
    let (mut owner, _) = setup(Store::default());
    let id = owner
        .execute(
            AgentActor::Operator,
            "workflow-slots",
            AgentCommandV1::Spawn {
                parent_id: owner.root_id(),
                label: "child".into(),
                task: "initial".into(),
                capabilities: config().root_capabilities,
                budget: budget(3),
                write_paths: vec![],
            },
        )
        .unwrap()
        .agent_id;
    let initial = owner.begin_turn(id).unwrap().unwrap();
    owner.deliver(id, initial, true).unwrap();
    owner
        .finish_turn(id, initial, "initial finished", 1, 0, true)
        .unwrap();
    let task = iteron_agents::AgentWorkflowClaim {
        workflow_id: "funding-workflow".into(),
        node_id: 1,
        attempt: 1,
        input_digest: "a".repeat(64),
        assigned_agent: id,
        task: "one node".into(),
        budget: AgentBudgetV1 {
            turns: 1,
            tokens: 50,
            cost_microusd: 30,
            wall_ms: 1000,
        },
        deadline_unix_ms: 2000,
    };
    let lease = owner.claim_workflow_task(task, 1000).unwrap();
    let scope = sha('e');
    owner.bind_provider_budget(id, &scope).unwrap();
    let room = owner
        .provider_budget_allowance(id, Some(lease.epoch))
        .unwrap();
    assert_eq!((room.turns, room.tokens, room.cost_microusd), (1, 50, 30));
    let mut physical = request(&scope, 20);
    physical.agent_id = id;
    physical.epoch = Some(lease.epoch);
    physical.max_tokens = 40;
    owner.reserve_provider_budget(physical.clone()).unwrap();
    let room = owner
        .provider_budget_allowance(id, Some(lease.epoch))
        .unwrap();
    assert_eq!((room.turns, room.tokens, room.cost_microusd), (0, 10, 10));
    owner
        .settle_provider_budget(
            id,
            &scope,
            &physical.effect_id,
            &physical.route,
            AgentProviderBudgetTerminal::NotDispatched,
            &sha('f'),
        )
        .unwrap();
    let room = owner
        .provider_budget_allowance(id, Some(lease.epoch))
        .unwrap();
    assert_eq!((room.turns, room.tokens, room.cost_microusd), (0, 50, 30));
}

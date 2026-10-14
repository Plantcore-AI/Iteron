use super::{own_rows, reconcile};
use crate::runtime::test_tempdir as tempfile;
use crate::runtime::{persistent_provider_budget, replay_scoped_rollout, route_attempt_accounting};
use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, AgentProviderBudgetRequest, ControllerStoreError,
};
use iteron_obs::PricingPort;
use iteron_protocol::agent_control::{AgentBudgetV1, AgentStateV1};
use iteron_protocol::{
    Capability, CostProjectionIdentity, EffectId, Event, EventKind, PricingRoute,
    ProviderRouteAttemptAccounting, ProviderRouteAttemptAccountingVersion,
    ProviderRouteAttemptIdentity, ProviderRouteCostTruth, ProviderRouteUsageTruth, RunId, Seq,
    TenantId, TurnId, Usage, capability_set::CapabilitySet,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
struct Store {
    value: Arc<Mutex<Option<AgentControllerSnapshot>>>,
    refuse_next: Arc<AtomicBool>,
}
impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.value.lock().unwrap().clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self.refuse_next.swap(false, Ordering::SeqCst) {
            return Err(ControllerStoreError::Unavailable);
        }
        let mut current = self.value.lock().unwrap();
        if current.as_ref().map(AgentControllerSnapshot::revision) != expected {
            return Err(ControllerStoreError::Conflict);
        }
        *current = Some(next.clone());
        Ok(())
    }
}
fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "signed-recovery-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: AgentBudgetV1 {
            turns: 8,
            tokens: 100,
            cost_microusd: 100,
            wall_ms: 60000,
        },
        max_agents: 4,
        max_pending_per_agent: 8,
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    rollout: iteron_record::Rollout,
    pricing: iteron_obs::HmacPricingAuthority,
    request: AgentProviderBudgetRequest,
    accounting: ProviderRouteAttemptAccounting,
}
impl Fixture {
    fn new(controller: &mut AgentController<Store>, known_terminal: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let tenant = TenantId("recovery-tenant".into());
        let run = RunId("signed-provider-recovery".into());
        let mut rollout =
            iteron_record::Rollout::open(directory.path(), &run, tenant.clone()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::TurnStart,
            })
            .unwrap();
        let route = PricingRoute {
            provider_id: "test-provider".into(),
            model_id: "test-model".into(),
            catalog_digest: format!("sha256:{}", "a".repeat(64)),
            capability_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let key = [42; 32];
        let signed = iteron_obs::sign_rate_card(
            iteron_protocol::RateCard {
                version: iteron_protocol::PricingVersion::V1,
                route,
                provenance: "recovery-fixture".into(),
                issued_at_unix_secs: 1,
                expires_at_unix_secs: u64::MAX,
                rates: iteron_protocol::TokenRateCard {
                    input_microusd_per_million: 1_000_000,
                    output_microusd_per_million: 1_000_000,
                    cache_creation_microusd_per_million: 1_000_000,
                    cache_read_microusd_per_million: 1_000_000,
                    thinking_microusd_per_million: 1_000_000,
                },
            },
            "recovery-fixture-key",
            key,
        )
        .unwrap();
        let pricing = iteron_obs::HmacPricingAuthority::new(vec![(
            signed.clone(),
            iteron_obs::HmacPricingKey::from_bytes(key),
        )])
        .unwrap();
        let epoch = controller
            .begin_parent_runtime_turn("actual Main task".into(), 1)
            .unwrap();
        let request = AgentProviderBudgetRequest {
            agent_id: controller.root_id(),
            scope_sha256: persistent_provider_budget::provider_scope_for(&tenant, &run),
            epoch: Some(epoch),
            effect_id: "fx1-pv-00000001-0000".into(),
            turn: 1,
            route: ProviderRouteAttemptIdentity {
                version: ProviderRouteAttemptAccountingVersion::V1,
                route_id: route_attempt_accounting::route_accounting_id("test-provider:test-model"),
                physical_attempt: 1,
                max_cost_reservation_microusd: Some(20),
            },
            max_tokens: 20,
            max_cost_microusd: 20,
        };
        controller
            .bind_provider_budget(request.agent_id, &request.scope_sha256)
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::EffectIntent {
                    id: EffectId(request.effect_id.clone()),
                    tool_use_id: "hx1-pv-00000001-0000".into(),
                    tool: "provider".into(),
                    capability: Capability::IrreversibleExternal,
                    arguments: serde_json::json!({}),
                    workspace: "/repo".into(),
                    provider_route_attempt: Some(request.route.clone()),
                },
            })
            .unwrap();
        controller.reserve_provider_budget(request.clone()).unwrap();
        let usage = Usage {
            input: 5,
            output: 2,
            ..Usage::default()
        };
        let projection = pricing
            .project(
                &signed,
                CostProjectionIdentity {
                    tenant_id: tenant.0,
                    run_id: run.0,
                    turn_id: 1,
                    provider_attempt: 1,
                    attribution: None,
                },
                usage,
                2,
            )
            .unwrap();
        let accounting = ProviderRouteAttemptAccounting {
            version: request.route.version,
            route_id: request.route.route_id.clone(),
            physical_attempt: 1,
            max_cost_reservation_microusd: Some(20),
            usage: ProviderRouteUsageTruth::Known { usage },
            cost: ProviderRouteCostTruth::Known {
                amount_microusd: projection.amount_microusd,
                rate_card_digest: projection.rate_card_digest.clone(),
                projection: Some(Box::new(projection)),
            },
        };
        let mut fixture = Self {
            _directory: directory,
            rollout,
            pricing,
            request,
            accounting,
        };
        if known_terminal {
            fixture.append_terminal(false);
        }
        fixture
    }
    fn append_terminal(&mut self, no_io: bool) {
        if no_io {
            self.accounting.usage = ProviderRouteUsageTruth::NotDispatched;
            self.accounting.cost = ProviderRouteCostTruth::NotDispatched;
            self.accounting.max_cost_reservation_microusd = None;
        }
        // This terminal proves only the physical provider observation. The independently
        // unmeasured Main execution remains RecoveryRequired in the controller.
        let kind = if no_io {
            EventKind::EffectFailed {
                id: EffectId(self.request.effect_id.clone()),
                tool: "provider".into(),
                reason: "known refusal before provider dispatch".into(),
                duration_ms: None,
                provider_route_attempt: Some(self.accounting.clone()),
            }
        } else {
            EventKind::EffectDone {
                id: EffectId(self.request.effect_id.clone()),
                tool: "provider".into(),
                duration_ms: None,
                provider_route_attempt: Some(self.accounting.clone()),
            }
        };
        self.rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind,
            })
            .unwrap();
    }
    fn rows(&self) -> Vec<iteron_record::ScopedEvent> {
        replay_scoped_rollout(self.rollout.path()).unwrap()
    }
    fn recover(
        &self,
        controller: &mut AgentController<Store>,
    ) -> Result<(), crate::runtime::KernelError> {
        let requests = controller.pending_provider_budget_requests().unwrap();
        reconcile(
            controller,
            &self.rows(),
            self.rollout.tenant(),
            self.rollout.run_id(),
            requests,
            Some(&self.pricing),
        )
    }
}

#[test]
fn durable_signed_terminal_repairs_failed_budget_append_once_without_claiming_cleanup() {
    let store = Store::default();
    let mut controller = AgentController::open(store.clone(), config()).unwrap();
    let fixture = Fixture::new(&mut controller, true);
    store.refuse_next.store(true, Ordering::SeqCst);
    assert!(fixture.recover(&mut controller).is_err());
    drop(controller);
    let mut reopened = AgentController::open(store, config()).unwrap();
    assert!(reopened.provider_budget_recovery_required());
    fixture.recover(&mut reopened).unwrap();
    assert!(!reopened.provider_budget_recovery_required());
    let view = reopened
        .inspect(AgentActor::Operator, reopened.root_id())
        .unwrap();
    assert_eq!(
        (
            view.usage.turns,
            view.usage.tokens,
            view.usage.cost_microusd
        ),
        (1, 7, 7)
    );
    assert_eq!((view.reserved.tokens, view.reserved.cost_microusd), (0, 0));
    assert!(matches!(view.state, AgentStateV1::RecoveryRequired { .. }));
    reconcile(
        &mut reopened,
        &fixture.rows(),
        fixture.rollout.tenant(),
        fixture.rollout.run_id(),
        vec![fixture.request.clone()],
        Some(&fixture.pricing),
    )
    .unwrap();
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, reopened.root_id())
            .unwrap()
            .usage,
        view.usage
    );
    let ledger =
        route_attempt_accounting::replay_route_charges(&fixture.rows(), Some(&fixture.pricing))
            .unwrap()
            .ledger;
    assert!(
        !ledger.is_unknown(),
        "execution recovery alone does not imply unknown billing"
    );
    assert_eq!(ledger.amount_microusd(), 7);
}

#[test]
fn actual_unclosed_wal_intent_retains_budget_and_financial_unknown() {
    let store = Store::default();
    let mut controller = AgentController::open(store.clone(), config()).unwrap();
    let fixture = Fixture::new(&mut controller, false);
    drop(controller);
    let mut reopened = AgentController::open(store, config()).unwrap();
    fixture.recover(&mut reopened).unwrap();
    assert!(reopened.provider_budget_recovery_required());
    assert_eq!(reopened.pending_provider_usage().unwrap().cost_microusd, 20);
    assert!(
        route_attempt_accounting::replay_route_charges(&fixture.rows(), Some(&fixture.pricing))
            .unwrap()
            .ledger
            .is_unknown()
    );
}

#[test]
fn a_true_no_dispatch_terminal_releases_zero_charge_without_a_pricing_authority() {
    let store = Store::default();
    let mut controller = AgentController::open(store.clone(), config()).unwrap();
    let mut fixture = Fixture::new(&mut controller, false);
    fixture.append_terminal(true);
    drop(controller);
    let mut reopened = AgentController::open(store, config()).unwrap();
    reconcile(
        &mut reopened,
        &fixture.rows(),
        fixture.rollout.tenant(),
        fixture.rollout.run_id(),
        vec![fixture.request.clone()],
        None,
    )
    .unwrap();
    assert!(!reopened.provider_budget_recovery_required());
    let usage = reopened
        .inspect(AgentActor::Operator, reopened.root_id())
        .unwrap()
        .usage;
    assert_eq!((usage.turns, usage.tokens, usage.cost_microusd), (1, 0, 0));
}

#[test]
fn wrong_scope_duplicate_terminal_and_wrong_physical_claim_never_release_a_reservation() {
    for case in 0..3 {
        let store = Store::default();
        let mut controller = AgentController::open(store.clone(), config()).unwrap();
        let fixture = Fixture::new(&mut controller, true);
        drop(controller);
        let mut reopened = AgentController::open(store, config()).unwrap();
        let mut rows = fixture.rows();
        let mut request = fixture.request.clone();
        match case {
            0 => rows.last_mut().unwrap().run_id = RunId("foreign-run".into()),
            1 => rows.push(rows.last().unwrap().clone()),
            _ => request.route.physical_attempt = 2,
        }
        reconcile(
            &mut reopened,
            &rows,
            fixture.rollout.tenant(),
            fixture.rollout.run_id(),
            vec![request],
            Some(&fixture.pricing),
        )
        .unwrap();
        assert!(reopened.provider_budget_recovery_required());
        assert_eq!(reopened.pending_provider_usage().unwrap().cost_microusd, 20);
    }
}

#[test]
fn own_physical_projection_excludes_parent_prefix_and_root_baseline_only() {
    let store = Store::default();
    let mut controller = AgentController::open(store, config()).unwrap();
    let fixture = Fixture::new(&mut controller, true);
    let mut rows = fixture.rows();
    let mut inherited = rows[0].clone();
    inherited.run_id = RunId("actual-parent-prefix".into());
    rows.push(inherited);
    assert_eq!(
        own_rows(
            rows.clone(),
            fixture.rollout.tenant(),
            fixture.rollout.run_id(),
            None
        )
        .unwrap()
        .len(),
        3
    );
    assert_eq!(
        own_rows(
            rows,
            fixture.rollout.tenant(),
            fixture.rollout.run_id(),
            Some(0)
        )
        .unwrap()
        .len(),
        2
    );
}

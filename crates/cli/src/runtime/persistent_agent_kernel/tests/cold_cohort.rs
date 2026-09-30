//! Actual Main/provider/controller/file WAL journeys across a cold fork and native reopen.
use super::{
    AgentActor, AgentCommandV1, AgentControlPort, AgentIdV1, AgentStateV1, Arc, Ordering,
    ProviderFixture, Workspace, until,
};
use crate::runtime::{Agent, KernelError, gate_integration_tests};
use iteron_agents::AgentControllerConfig;
use iteron_protocol::agent_control::AgentBudgetV1;
use iteron_protocol::{
    Budget, Capability, EventKind, Outcome, RunId, TenantId, capability_set::CapabilitySet,
};
use iteron_record::Rollout;
use iteron_tools::Registry;

pub(super) fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "cold-cohort-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: AgentBudgetV1 {
            turns: 20,
            tokens: 4_000_000,
            cost_microusd: 0,
            wall_ms: 30_000,
        },
        max_agents: 8,
        max_pending_per_agent: 8,
    }
}
pub(super) fn make_main(
    workspace: &Workspace,
    run: &RunId,
    provider: Arc<ProviderFixture>,
    reopen: bool,
) -> Agent {
    let tenant = TenantId("tenant".into());
    let runs = workspace.0.join("runs");
    let rollout = if reopen {
        Rollout::open_existing(&runs, run, tenant).unwrap()
    } else {
        Rollout::open(&runs, run, tenant).unwrap()
    };
    let mut agent = Agent::new(
        provider.clone(),
        Registry::read_only(&workspace.0.join("repo")).unwrap(),
        rollout,
        "test-model".into(),
        "Main source fixture".into(),
        Budget {
            max_turns: 20,
            max_tokens: Some(10_000_000),
            max_wall_secs: 30,
            max_usd: Some(10.0),
            ..Budget::default()
        },
    );
    agent.workspace = workspace.0.join("repo");
    agent.runtime_state_dir = runs;
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    let key = [42; 32];
    let route = iteron_protocol::PricingRoute {
        provider_id: "test-provider".into(),
        model_id: "test-model".into(),
        catalog_digest: format!("sha256:{}", "a".repeat(64)),
        capability_digest: format!("sha256:{}", "b".repeat(64)),
    };
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route: route.clone(),
            provenance: "cold-cohort-fixture".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            rates: iteron_protocol::TokenRateCard {
                input_microusd_per_million: 0,
                output_microusd_per_million: 0,
                cache_creation_microusd_per_million: 0,
                cache_read_microusd_per_million: 0,
                thinking_microusd_per_million: 0,
            },
        },
        "fixture-pricing",
        key,
    )
    .unwrap();
    agent.set_pricing_port(Arc::new(
        iteron_obs::HmacPricingAuthority::new(vec![(
            signed,
            iteron_obs::HmacPricingKey::from_bytes(key),
        )])
        .unwrap(),
    ));
    if reopen {
        let messages = Agent::messages_from_rollout(agent.rollout.path()).unwrap();
        agent.set_resume(messages).unwrap();
    } else {
        agent
            .record_genesis_with_tunables(
                workspace.0.join("repo").to_string_lossy().into_owned(),
                1,
                "fixture".into(),
                None,
            )
            .unwrap();
    }
    agent
        .record_operator_model_selection(
            provider,
            "test-provider".into(),
            "test-model".into(),
            route.catalog_digest,
            route.capability_digest,
        )
        .unwrap();
    agent
}
fn child(control: &Arc<dyn AgentControlPort>) -> AgentIdV1 {
    control
        .command(
            AgentActor::Operator,
            "original-child",
            AgentCommandV1::Spawn {
                parent_id: AgentIdV1(1),
                label: "retained-child".into(),
                task: "original stable child task".into(),
                capabilities: config().root_capabilities,
                budget: AgentBudgetV1 {
                    turns: 4,
                    tokens: 1_000_000,
                    cost_microusd: 0,
                    wall_ms: 10_000,
                },
                write_paths: vec![],
            },
        )
        .unwrap()
        .agent_id
}
async fn enable_after_worker_exit(agent: &mut Agent) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for _ in 0..100 {
            match agent.enable_persistent_agents(config(), 2) {
                Ok(()) => return,
                Err(KernelError::AgentControl(iteron_agents::ControllerError::Store(
                    iteron_agents::ControllerStoreError::Conflict,
                ))) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                Err(error) => panic!("unexpected source admission refusal: {error:?}"),
            }
        }
        panic!("cohort writer lease was not released");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cold_fork_reopens_same_controller_and_original_child_journal_without_refilling_budget() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let root = RunId("cohort-owning-main".into());
    let mut main = make_main(&workspace, &root, provider.clone(), false);
    main.enable_persistent_agents(config(), 2).unwrap();
    let control = main.persistent_agents.clone().unwrap();
    let id = child(&control);
    until(|| control.inspect(AgentActor::Operator, id).unwrap().state == AgentStateV1::Idle).await;
    assert_eq!(main.run("original Main task").await.unwrap(), Outcome::Done);
    let before = control.inspect(AgentActor::Operator, AgentIdV1(1)).unwrap();
    let child_before = control.inspect(AgentActor::Operator, id).unwrap();
    let origin = main.cohort_installation.as_ref().unwrap().origin.clone();
    let path = main.rollout.path().to_owned();
    drop(control);
    drop(main);
    let at = iteron_record::replay(&path).unwrap().last().unwrap().seq;
    let fork = iteron_record::fork(
        &workspace.0.join("runs"),
        &root,
        at,
        &TenantId("tenant".into()),
    )
    .unwrap();
    let mut branch = make_main(&workspace, &fork, provider.clone(), true);
    let count = provider.requests.load(Ordering::SeqCst);
    assert!(
        branch
            .run("must not launder cohort budget as ordinary Main")
            .await
            .is_err()
    );
    assert_eq!(provider.requests.load(Ordering::SeqCst), count);
    enable_after_worker_exit(&mut branch).await;
    let control = branch.persistent_agents.clone().unwrap();
    assert_eq!(
        control
            .inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .usage,
        before.usage
    );
    assert_eq!(
        control.inspect(AgentActor::Operator, id).unwrap().usage,
        child_before.usage
    );
    assert_eq!(
        control.inspect(AgentActor::Operator, id).unwrap().budget,
        child_before.budget
    );
    assert_eq!(branch.cohort_installation.as_ref().unwrap().origin, origin);
    assert!(
        Rollout::open_existing(&workspace.0.join("runs"), &root, TenantId("tenant".into()))
            .is_err(),
        "old Main writer remains exclusively pinned while fork Main is live"
    );
    control
        .command(
            AgentActor::Operator,
            "same-child-followup",
            AgentCommandV1::FollowupTask {
                agent_id: id,
                text: "followup after real cold fork".into(),
            },
        )
        .unwrap();
    until(|| {
        control.inspect(AgentActor::Operator, id).unwrap().state == AgentStateV1::Idle
            && control
                .inspect(AgentActor::Operator, id)
                .unwrap()
                .usage
                .turns
                > child_before.usage.turns
    })
    .await;
    assert!(
        provider
            .texts
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("original stable child task")
    );
    assert_eq!(branch.run("branch Main task").await.unwrap(), Outcome::Done);
    let spent = control
        .inspect(AgentActor::Operator, AgentIdV1(1))
        .unwrap()
        .usage;
    assert!(spent.turns > before.usage.turns);
    drop(control);
    drop(branch);
    // Reopening the original root also folds the branch's physical journal, not its fork prefix.
    let mut original = make_main(&workspace, &root, provider.clone(), true);
    enable_after_worker_exit(&mut original).await;
    assert_eq!(
        original
            .persistent_agents
            .as_ref()
            .unwrap()
            .inspect(AgentActor::Operator, AgentIdV1(1))
            .unwrap()
            .usage,
        spent
    );
    assert_eq!(
        original
            .persistent_agents
            .as_ref()
            .unwrap()
            .list(AgentActor::Operator)
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn missing_installed_store_never_creates_a_replacement_cohort_or_dispatches() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let root = RunId("cohort-missing-store".into());
    let mut main = make_main(&workspace, &root, provider.clone(), false);
    main.enable_persistent_agents(config(), 2).unwrap();
    let directory = main.runtime_state_dir.join(
        main.cohort_installation
            .as_ref()
            .unwrap()
            .origin
            .directory_component(),
    );
    drop(main);
    std::fs::rename(&directory, directory.with_extension("held")).unwrap();
    let mut resumed = make_main(&workspace, &root, provider.clone(), true);
    assert!(resumed.enable_persistent_agents(config(), 2).is_err());
    assert!(!directory.exists());
    assert!(resumed.run("without the exact store").await.is_err());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    assert!(
        iteron_record::replay(resumed.rollout.path())
            .unwrap()
            .iter()
            .all(|row| !matches!(&row.kind,EventKind::EffectIntent {tool,..} if tool=="provider"))
    );
}

#[tokio::test]
async fn branch_cannot_join_after_unbound_provider_io_or_incompatible_authority_genesis() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let root = RunId("cohort-fork-conflict".into());
    let mut main = make_main(&workspace, &root, provider.clone(), false);
    main.enable_persistent_agents(config(), 2).unwrap();
    let path = main.rollout.path().to_owned();
    drop(main);
    let at = iteron_record::replay(&path).unwrap().last().unwrap().seq;
    let fork = iteron_record::fork(
        &workspace.0.join("runs"),
        &root,
        at,
        &TenantId("tenant".into()),
    )
    .unwrap();
    let mut branch = make_main(&workspace, &fork, provider.clone(), true);
    let mut altered = config();
    altered.root_budget.turns += 1;
    assert!(branch.enable_persistent_agents(altered, 2).is_err());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    // Durable legacy provider usage without an admitted scope cannot be imported as a fresh baseline.
    branch
        .emit_durable(
            iteron_protocol::TurnId(1),
            EventKind::TurnEnd {
                usage: iteron_protocol::Usage {
                    input: 1,
                    ..Default::default()
                },
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        )
        .unwrap();
    assert!(branch.enable_persistent_agents(config(), 2).is_err());
    assert!(branch.persistent_agents.is_none());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn existing_writer_constructor_cannot_skip_the_cohort_guard_by_omitting_set_resume() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let run = RunId("cohort-direct-constructor".into());
    let mut original = make_main(&workspace, &run, provider.clone(), false);
    original.enable_persistent_agents(config(), 2).unwrap();
    drop(original);
    let rollout =
        Rollout::open_existing(&workspace.0.join("runs"), &run, TenantId("tenant".into())).unwrap();
    let mut direct = Agent::new(
        provider.clone(),
        Registry::read_only(&workspace.0.join("repo")).unwrap(),
        rollout,
        "test-model".into(),
        "constructor fixture".into(),
        Budget::default(),
    );
    assert!(!direct.cohort_replay_checked);
    assert!(direct.run("no frontend resume hook").await.is_err());
    assert!(direct.cohort_replay_checked);
    assert!(direct.cohort_installation.is_some());
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
}

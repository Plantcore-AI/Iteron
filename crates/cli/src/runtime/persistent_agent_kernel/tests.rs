use super::*;
use iteron_agents::{AgentControllerJournal, AgentControllerSnapshot, ControllerStoreError};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentStateV1};
use iteron_protocol::{Block, StopReason, ToolUse, Usage};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use std::sync::atomic::{AtomicU64, AtomicUsize};

#[derive(Default)]
struct Store {
    snapshot: Option<AgentControllerSnapshot>,
    fail_consumed: bool,
}
impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.snapshot.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self
            .snapshot
            .as_ref()
            .map(AgentControllerSnapshot::revision)
            != expected
        {
            return Err(ControllerStoreError::Conflict);
        }
        if self.fail_consumed
            && serde_json::to_value(next).unwrap()["mailbox"]["messages"]
                .as_object()
                .unwrap()
                .values()
                .any(|message| {
                    serde_json::from_value::<iteron_protocol::agent_control::AgentMessageStateV1>(
                        message["state"].clone(),
                    )
                    .is_ok_and(|state| {
                        matches!(
                            state,
                            iteron_protocol::agent_control::AgentMessageStateV1::Consumed { .. }
                        )
                    })
                })
        {
            return Err(ControllerStoreError::Unavailable);
        }
        self.snapshot = Some(next.clone());
        Ok(())
    }
}

#[derive(Default)]
struct ProviderFixture {
    requests: AtomicUsize,
    texts: Mutex<Vec<String>>,
}

#[async_trait]
impl Provider for ProviderFixture {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("test-provider")
    }
    async fn turn(
        &self,
        request: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let texts = request
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|block| match block {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        self.texts.lock().unwrap().push(texts);
        let last = request
            .messages
            .last()
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        Block::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let blocking = last.contains("block-tool");
        Ok(TurnResult {
            blocks: if blocking {
                vec![Block::ToolUse(ToolUse {
                    id: "controlled-wait".into(),
                    name: "controlled_wait".into(),
                    input: serde_json::json!({}),
                })]
            } else {
                vec![Block::Text {
                    text: "resident response".into(),
                }]
            },
            stop_reason: if blocking {
                StopReason::ToolUse
            } else {
                StopReason::EndTurn
            },
            usage: UsageReport::complete(Usage {
                input: 1,
                output: 1,
                ..Usage::default()
            }),
        })
    }
}

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Workspace(std::path::PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-resident-kernel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("repo")).unwrap();
        Self(root)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: 20_000,
        cost_microusd: 500_000,
        wall_ms: 10_000,
    }
}

fn setup(
    root: &Workspace,
    provider: Arc<ProviderFixture>,
    block_tool: bool,
) -> (
    PersistentAgentHost<Store>,
    Arc<KernelPersistentRuntime>,
    Arc<AtomicUsize>,
    Arc<dyn AgentControlPort>,
) {
    setup_with_store(root, provider, block_tool, Store::default())
}

fn setup_with_store(
    root: &Workspace,
    provider: Arc<ProviderFixture>,
    block_tool: bool,
    store: Store,
) -> (
    PersistentAgentHost<Store>,
    Arc<KernelPersistentRuntime>,
    Arc<AtomicUsize>,
    Arc<dyn AgentControlPort>,
) {
    let route = iteron_protocol::PricingRoute {
        provider_id: "test-provider".into(),
        model_id: "test-model".into(),
        catalog_digest: format!("sha256:{}", "a".repeat(64)),
        capability_digest: format!("sha256:{}", "b".repeat(64)),
    };
    let key = [42; 32];
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route: route.clone(),
            provenance: "resident-kernel-fixture".into(),
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
    let pricing = Arc::new(
        iteron_obs::HmacPricingAuthority::new(vec![(
            signed,
            iteron_obs::HmacPricingKey::from_bytes(key),
        )])
        .unwrap(),
    );
    let mut context = KernelSpawnerContext::new(
        provider,
        "test-model".into(),
        "test-provider".into(),
        route.catalog_digest,
        route.capability_digest,
        root.0.join("repo"),
        root.0.join("runs"),
        iteron_protocol::TenantId("tenant".into()),
        "parent".into(),
        "resident-fixture".into(),
    );
    context.budget.max_turns = 20;
    context.budget.max_tokens = Some(100_000);
    context.budget.max_wall_secs = 30;
    context.budget.max_usd = Some(10.0);
    context.install_pricing_authority(Some(pricing)).unwrap();
    super::super::workflow_spawner::tests::pin_context(&root.0, &mut context);
    let settled = Arc::new(AtomicUsize::new(0));
    let mut runtime = KernelPersistentRuntime::new(context);
    if block_tool {
        let settled = settled.clone();
        runtime.fixture = Some(Arc::new(move |child| {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            child.set_interrupt(stop.clone());
            let settled = settled.clone();
            child.registry.register_external(ToolSpec {
                name: "controlled_wait".into(), description: "bounded cancellation fixture".into(), input_schema: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}), purity: Purity::Effecting, capability: Capability::ReadOnly,
            }, move |call, _| {
                let stop = stop.clone(); let settled = settled.clone();
                Box::pin(async move {
                    for _ in 0..1_000 {
                        if stop.load(Ordering::Acquire) { break }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    settled.fetch_add(1, Ordering::SeqCst);
                    ToolResult { tool_use_id: call.id, content: "physically stopped".into(), is_error: false, trust: Trust::Workspace, latency_ms: 0 }
                })
            }).unwrap();
        }));
    }
    let runtime = Arc::new(runtime);
    let config = AgentControllerConfig {
        workspace_scope: "resident-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: budget(20),
        max_agents: 8,
        max_pending_per_agent: 8,
    };
    let host = PersistentAgentHost::new(
        AgentController::open(store, config).unwrap(),
        runtime.clone(),
        2,
    )
    .unwrap();
    let port: Arc<dyn AgentControlPort> = Arc::new(host.clone());
    runtime.bind(&port).unwrap();
    // Keep the authenticated host port alive; the runtime itself retains only a Weak reference.
    (host, runtime, settled, port)
}

fn spawn(host: &PersistentAgentHost<Store>, task: &str) -> AgentIdV1 {
    host.command(
        AgentActor::Operator,
        "spawn",
        AgentCommandV1::Spawn {
            parent_id: AgentIdV1(1),
            label: "resident".into(),
            task: task.into(),
            capabilities: CapabilitySet::only(Capability::ReadOnly),
            budget: budget(8),
            write_paths: vec![],
        },
    )
    .unwrap()
    .agent_id
}

async fn until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..2_500 {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("runtime did not settle within its bounded deadline");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_agent_retains_context_and_exact_identity_across_followups() {
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup(&root, provider.clone(), false);
    let child = spawn(&host, "first remembered context");
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
    host.command(
        AgentActor::Operator,
        "followup",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "continue same identity".into(),
        },
    )
    .unwrap();
    until(|| {
        provider.requests.load(Ordering::SeqCst) == 2
            && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    assert_eq!(runtime.residents.lock().unwrap().len(), 1);
    let texts = provider.texts.lock().unwrap();
    assert!(texts[1].contains("first remembered context"));
    assert!(texts[1].contains("continue same identity"));
}

#[tokio::test]
async fn real_agent_interrupt_reaps_admitted_tool_before_same_id_followup() {
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, _runtime, settled, _keepalive) = setup(&root, provider.clone(), true);
    let child = spawn(&host, "block-tool");
    until(|| provider.requests.load(Ordering::SeqCst) == 1).await;
    let epoch = host
        .inspect(AgentActor::Operator, child)
        .unwrap()
        .state
        .epoch()
        .unwrap();
    host.command(
        AgentActor::Operator,
        "interrupt",
        AgentCommandV1::Interrupt {
            agent_id: child,
            epoch,
        },
    )
    .unwrap();
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    assert_eq!(settled.load(Ordering::SeqCst), 1);
    host.command(
        AgentActor::Operator,
        "followup",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "new task after physical stop".into(),
        },
    )
    .unwrap();
    until(|| {
        provider.requests.load(Ordering::SeqCst) >= 2
            && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
}

#[tokio::test]
async fn failed_mailbox_consumption_persists_not_dispatched_and_makes_zero_provider_calls() {
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup_with_store(
        &root,
        provider.clone(),
        false,
        Store {
            snapshot: None,
            fail_consumed: true,
        },
    );
    let child = spawn(&host, "refuse inclusion when storage fails");
    until(|| {
        host.inspect(AgentActor::Operator, child).is_ok_and(|view| {
            matches!(
                view.state,
                AgentStateV1::Idle | AgentStateV1::RecoveryRequired { .. }
            )
        })
    })
    .await;
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    let child = resident.lock().await;
    let events = iteron_record::replay(child.rollout.path()).unwrap();
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::EffectFailed { tool, provider_route_attempt: Some(receipt), .. }
        if tool == "provider" && matches!(receipt.usage, iteron_protocol::ProviderRouteUsageTruth::NotDispatched)
            && matches!(receipt.cost, iteron_protocol::ProviderRouteCostTruth::NotDispatched))));
}

use super::*;
use iteron_agents::{AgentControllerJournal, AgentControllerSnapshot, ControllerStoreError};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentStateV1};
use iteron_protocol::{Block, StopReason, ToolUse, Usage};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use std::sync::atomic::{AtomicU64, AtomicUsize};

#[derive(Default)]
struct Store {
    snapshot: Option<AgentControllerSnapshot>,
    // Test observers retain only the immutable value accepted by the real journal commit port.
    committed_snapshot: Option<Arc<Mutex<Option<AgentControllerSnapshot>>>>,
    fail_consumed: bool,
    fail_parent_delivery: bool,
    fail_parent_terminal: Option<Arc<std::sync::atomic::AtomicBool>>,
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
        let encoded = serde_json::to_value(next).unwrap();
        let root_state =
            serde_json::from_value::<AgentStateV1>(encoded["agents"]["1"]["view"]["state"].clone())
                .unwrap();
        if self.fail_parent_delivery
            && encoded["mailbox"]["messages"].as_object().unwrap().values().any(|message|
                message["receiver"].as_u64() == Some(1)
                && serde_json::from_value::<iteron_protocol::agent_control::AgentMessageStateV1>(
                    message["state"].clone()).is_ok_and(|state|
                        matches!(state, iteron_protocol::agent_control::AgentMessageStateV1::Delivered { .. })))
        { return Err(ControllerStoreError::Unavailable); }
        if root_state == AgentStateV1::Idle
            && self.snapshot.as_ref().is_some_and(|previous| {
                serde_json::from_value::<AgentStateV1>(
                    serde_json::to_value(previous).unwrap()["agents"]["1"]["view"]["state"].clone(),
                )
                .is_ok_and(|state| matches!(state, AgentStateV1::Running { .. }))
            })
            && self
                .fail_parent_terminal
                .as_ref()
                .is_some_and(|fault| fault.swap(false, Ordering::SeqCst))
        {
            return Err(ControllerStoreError::Unavailable);
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
        if let Some(observed) = &self.committed_snapshot {
            *observed.lock().unwrap() = Some(next.clone());
        }
        Ok(())
    }
}

#[derive(Default)]
struct ProviderFixture {
    requests: AtomicUsize,
    tool_started: AtomicUsize,
    texts: Mutex<Vec<String>>,
    systems: Mutex<Vec<String>>,
    prepared: AtomicUsize,
    serialized_caps: Mutex<Vec<u64>>,
    omit_native_user: bool,
    unsupported_capture: bool,
    stream_partial: bool,
    partial_started: AtomicUsize,
    partial_release: tokio::sync::Notify,
    child_sources: Mutex<
        Vec<(
            iteron_protocol::TenantId,
            iteron_protocol::RunId,
            std::path::PathBuf,
        )>,
    >,
}

#[async_trait]
impl Provider for ProviderFixture {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("test-provider")
    }
    fn physical_input_token_ceiling(&self, _: &str) -> Option<u64> {
        // Explicit immutable fixture contract; never reuse the runtime planning window.
        Some(100_000)
    }
    fn physical_output_token_ceiling(
        &self,
        budget: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        // This actual fixture returns at most one output token and never expands the request.
        Ok(Some(budget.requested_max_tokens))
    }
    async fn turn_observed(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn iteron_provider::request_capture::ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        if self.unsupported_capture {
            observer
                .unavailable("fixture_without_native_capture")
                .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        } else {
            let messages: Vec<_> = request
                .messages
                .iter()
                .map(|message| {
                    let role = if message.role == iteron_protocol::Role::User {
                        "user"
                    } else {
                        "assistant"
                    };
                    let content: Vec<_> = message
                        .content
                        .iter()
                        .filter_map(|block| {
                            if let Block::Text { text } = block {
                                Some(serde_json::json!({"type":"text","text":text}))
                            } else {
                                None
                            }
                        })
                        .collect();
                    serde_json::json!({"role":role,"content":content})
                })
                .collect();
            let messages = if self.omit_native_user {
                vec![
                    serde_json::json!({"role":"user","content":[{"type":"text","text":"omitted mailbox input"}]}),
                ]
            } else {
                messages
            };
            let body = serde_json::to_vec(&serde_json::json!({
                "system":request.system,"messages":messages,"max_tokens":request.max_tokens
            }))
            .unwrap();
            observer
                .prepared(iteron_provider::request_capture::ProviderWireRequest {
                    adapter: iteron_provider::AdapterKind::AnthropicMessages,
                    method: "POST",
                    endpoint: "https://fixture.invalid/v1/messages",
                    content_type: "application/json",
                    body: &body,
                    serialized_output_tokens: request.max_tokens,
                    request,
                })
                .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
            self.serialized_caps.lock().unwrap().push(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["max_tokens"]
                    .as_u64()
                    .unwrap(),
            );
            self.prepared.fetch_add(1, Ordering::SeqCst);
            observer
                .dispatching()
                .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        }
        self.turn(request, on_item).await
    }
    async fn turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.systems.lock().unwrap().push(request.system.clone());
        if self.stream_partial {
            on_item(StreamItem::TextDelta("Progress sk-an".into()));
            on_item(StreamItem::TextDelta(
                "t-abcdefghijklmnopqrstuv ready ".into(),
            ));
            self.partial_started.fetch_add(1, Ordering::SeqCst);
            self.partial_release.notified().await;
            on_item(StreamItem::TextDelta("next partial ".into()));
            self.partial_started.fetch_add(1, Ordering::SeqCst);
            self.partial_release.notified().await;
        }
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
            .iter()
            .rev()
            .find(|message| {
                message.role == iteron_protocol::Role::User
                    && message.content.iter().any(|block| {
                        matches!(block, Block::Text { text }
                            if !text.contains("Main thread task source sha256:"))
                    })
            })
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        Block::Text { text }
                            if !text.contains("Main thread task source sha256:") =>
                        {
                            Some(text.as_str())
                        }
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
        tokens: 1_000_000,
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
    setup_with_financial(root, provider, block_tool, store, 500_000, true)
}

fn setup_with_financial(
    root: &Workspace,
    provider: Arc<ProviderFixture>,
    block_tool: bool,
    store: Store,
    cost: u64,
    priced: bool,
) -> (
    PersistentAgentHost<Store>,
    Arc<KernelPersistentRuntime>,
    Arc<AtomicUsize>,
    Arc<dyn AgentControlPort>,
) {
    setup_with_financial_and_memory(root, provider, block_tool, store, cost, priced, None)
}

fn setup_with_financial_and_memory(
    root: &Workspace,
    provider: Arc<ProviderFixture>,
    block_tool: bool,
    store: Store,
    cost: u64,
    priced: bool,
    memory_workspace: Option<std::path::PathBuf>,
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
        provider.clone(),
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
    context.budget.max_tokens = Some(10_000_000);
    context.budget.max_wall_secs = 30;
    context.budget.max_usd = Some(10.0);
    if priced {
        context.install_pricing_authority(Some(pricing)).unwrap();
    }
    super::super::workflow_spawner::tests::pin_context(&root.0, &mut context);
    let settled = Arc::new(AtomicUsize::new(0));
    let mut runtime = KernelPersistentRuntime::new(context);
    if block_tool {
        let settled = settled.clone();
        let provider = provider.clone();
        runtime.fixture = Some(Arc::new(move |child| {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            child.set_interrupt(stop.clone());
            let settled = settled.clone();
            let provider = provider.clone();
            child.registry.register_external(ToolSpec {
                name: "controlled_wait".into(), description: "bounded cancellation fixture".into(), input_schema: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}), purity: Purity::Effecting, capability: Capability::ReadOnly,
            }, move |call, _| {
                let stop = stop.clone(); let settled = settled.clone(); let provider = provider.clone();
                Box::pin(async move {
                    provider.tool_started.fetch_add(1, Ordering::SeqCst);
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
    if let Some(memory_workspace) = memory_workspace {
        assert!(
            !block_tool,
            "memory fixture owns the one constructor callback"
        );
        runtime.fixture = Some(Arc::new(move |child| {
            // Explicit host-owned isolated namespace; ordinary ChildMemoryPolicy::Isolated
            // does not install parent memory or broaden the child's authority.
            child.memory_workspace = Some(memory_workspace.clone());
            child.context_home_dir = None;
        }));
    }
    let previous_fixture = runtime.fixture.take();
    let source_observer = provider.clone();
    runtime.fixture = Some(Arc::new(move |child| {
        source_observer.child_sources.lock().unwrap().push((
            child.rollout.tenant().clone(),
            child.rollout.run_id().clone(),
            child.rollout.path().to_path_buf(),
        ));
        if let Some(previous) = &previous_fixture {
            previous(child);
        }
    }));
    // Explicit compatibility for this older provider-free Main fixture only. Production never
    // accepts a missing scoped native publication, and missing child scope never uses this flag.
    runtime
        .generations
        .get_mut()
        .unwrap()
        .allow_legacy_main_fixture();
    let runtime = Arc::new(runtime);
    let config = AgentControllerConfig {
        workspace_scope: "resident-fixture".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: AgentBudgetV1 {
            cost_microusd: cost,
            tokens: 4_000_000,
            ..budget(20)
        },
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
async fn actual_agent_tools_register_and_reject_bounds_before_controller_admission() {
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, _, _, port) = setup(&root, provider.clone(), false);
    let rollout = iteron_record::Rollout::open(
        &root.0.join("operator"),
        &iteron_protocol::RunId("bounded-agent-tools".into()),
        iteron_protocol::TenantId("tenant".into()),
    )
    .unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        iteron_tools::Registry::read_only(root.0.join("repo")).unwrap(),
        rollout,
        "test-model".into(),
        "bounded registry fixture".into(),
        iteron_protocol::Budget::default(),
    );
    agent.install_persistent_agents(port, AgentIdV1(1)).unwrap();
    for name in [
        "agent_control",
        "agent_task",
        "agent_inspect",
        "agent_message_receipt",
        "agent_list",
        "agent_wait",
    ] {
        assert!(agent.registry.specs().iter().any(|spec| spec.name == name));
    }
    let before = host
        .wait(AgentActor::Operator, 0, 1)
        .await
        .unwrap()
        .revision;
    for (name, input, expected_kind) in [
        (
            "agent_control",
            serde_json::json!({"request_id":"","command":{}}),
            "string_too_short",
        ),
        (
            "agent_task",
            serde_json::json!({"request_id":"x".repeat(129),"command":{}}),
            "string_too_long",
        ),
        (
            "agent_wait",
            serde_json::json!({"after_revision":0,"timeout_ms":60001}),
            "above_maximum",
        ),
    ] {
        let result = agent
            .registry
            .dispatch(ToolUse {
                id: format!("refused-{name}"),
                name: name.into(),
                input,
            })
            .await;
        assert!(result.is_error);
        let error: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(error["error"], "invalid_tool_arguments");
        assert_eq!(error["kind"], expected_kind);
        assert_eq!(
            host.wait(AgentActor::Operator, before, 1)
                .await
                .unwrap()
                .revision,
            before
        );
    }
    let observed = agent
        .registry
        .dispatch(ToolUse {
            id: "actual-agent-list".into(),
            name: "agent_list".into(),
            input: serde_json::json!({}),
        })
        .await;
    assert!(!observed.is_error, "{}", observed.content);
    assert_eq!(observed.trust, Trust::Untrusted);
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
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
    until(|| provider.tool_started.load(Ordering::SeqCst) == 1).await;
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
            fail_consumed: true,
            ..Store::default()
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
    let view = host.inspect(AgentActor::Operator, child).unwrap();
    assert_eq!(view.reserved.tokens, 0);
    assert_eq!(view.reserved.cost_microusd, 0);
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

#[tokio::test]
async fn finite_zero_cost_requires_verified_zero_price_before_provider_io() {
    for priced in [false, true] {
        let root = Workspace::new();
        let provider = Arc::new(ProviderFixture::default());
        let (host, runtime, _, _keepalive) =
            setup_with_financial(&root, provider.clone(), false, Store::default(), 0, priced);
        let child = host
            .command(
                AgentActor::Operator,
                "zero-cost",
                AgentCommandV1::Spawn {
                    parent_id: AgentIdV1(1),
                    label: "zero".into(),
                    task: "zero-price task".into(),
                    capabilities: CapabilitySet::only(Capability::ReadOnly),
                    budget: AgentBudgetV1 {
                        cost_microusd: 0,
                        ..budget(8)
                    },
                    write_paths: vec![],
                },
            )
            .unwrap()
            .agent_id;
        until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle)
            .await;
        assert_eq!(
            provider.requests.load(Ordering::SeqCst),
            usize::from(priced)
        );
        let resident = runtime
            .residents
            .lock()
            .unwrap()
            .get(&child)
            .unwrap()
            .clone();
        let child = resident.lock().await;
        let events = iteron_record::replay(child.rollout.path()).unwrap();
        assert_eq!(events.iter().filter(|event|matches!(&event.kind,EventKind::EffectIntent { tool,.. } if tool == "provider")).count(),usize::from(priced));
    }
}

#[tokio::test]
async fn small_workflow_node_does_not_shrink_resident_lifetime_and_physical_turns_settle() {
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup(&root, provider, true);
    let child = spawn(&host, "seed lifetime context");
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    let original = resident.lock().await.budget.clone();
    for (node, task, turns) in [(1, "one request node", 1), (2, "block-tool", 2)] {
        let scheduled = iteron_workflow::live_scheduler::ScheduledTaskV1 {
            workflow_id: "resident-workflow".into(),
            node_id: node,
            attempt: 1,
            input_digest: format!("sha256:{}", "d".repeat(64)),
            assigned_agent: child.0,
            task: task.into(),
            budget: iteron_workflow::task_dag::TaskBudget {
                max_turns: turns,
                max_tokens: 500_000,
                max_cost_microusd: 50_000,
                max_wall_ms: 5_000,
            },
            deadline_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 5_000,
        };
        host.workflow_port()
            .dispatch(scheduled.clone())
            .await
            .unwrap();
        until(|| host.workflow_completion(&scheduled).unwrap().is_some()).await;
        let completion = host.workflow_completion(&scheduled).unwrap().unwrap();
        assert!(completion.effects_known);
        assert_eq!(
            completion.terminal,
            iteron_agents::AgentWorkflowTerminal::Succeeded
        );
        assert_eq!(completion.usage.turns, turns);
        assert_eq!(resident.lock().await.budget, original);
    }
    assert_eq!(
        host.inspect(AgentActor::Operator, child)
            .unwrap()
            .usage
            .turns,
        4
    );
}

mod parent_turn;

mod memory_epochs;

#[path = "tests/native_mailbox.rs"]
mod native_mailbox;

#[path = "tests/agent_input_trust.rs"]
mod agent_input_trust;

#[path = "tests/cold_cohort.rs"]
mod cold_cohort;

#[path = "tests/output_funding.rs"]
mod output_funding;

#[path = "tests/query_trust.rs"]
mod query_trust;

#[path = "tests/native_generations.rs"]
mod native_generations;

#[tokio::test]
async fn actual_resident_stream_is_shared_before_terminal_and_bound_to_physical_wal() {
    use iteron_protocol::agent_output::AgentPartialStateV1;
    let root = Workspace::new();
    let provider = Arc::new(ProviderFixture {
        stream_partial: true,
        ..Default::default()
    });
    let (host, runtime, _, port) = setup(&root, provider.clone(), false);
    let id = spawn(&host, "stream partial response");
    until(|| provider.partial_started.load(Ordering::SeqCst) == 1).await;
    let view = port.inspect(AgentActor::Operator, id).unwrap();
    let partial = view
        .partial_output
        .clone()
        .expect("actual provider delta observation");
    assert_eq!(partial.state, AgentPartialStateV1::Observed);
    assert!(matches!(view.state, AgentStateV1::Running { .. }));
    assert!(view.last_summary.is_none());
    assert_eq!(partial.agent_id, id);
    assert_eq!(partial.epoch, view.state.epoch().unwrap());
    assert_eq!(partial.trust, Trust::Untrusted);
    let text = partial.text.as_deref().unwrap();
    assert!(text.contains("Progress") && text.contains("ready"));
    assert!(!text.contains("abcdefghijklmnopqrstuv"));
    let source = partial.source.as_ref().unwrap();
    let resident = runtime.residents.lock().unwrap().get(&id).unwrap().clone();
    let child = resident.try_lock();
    assert!(
        child.is_err(),
        "live resident execution owns the real Agent"
    );
    // Read the independently fsynced WAL while the provider is blocked, using its actual scope.
    let (tenant, run, path) = provider
        .child_sources
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!((&source.tenant, &source.run_id), (&tenant, &run));
    let events = iteron_record::replay(&path).unwrap();
    assert!(events.iter().any(|event| event.seq.0 == source.provider_intent_seq
        && event.turn == source.turn
        && matches!(&event.kind, EventKind::EffectIntent { id: effect, .. } if effect == &source.effect_id)));
    assert_eq!(
        port.list(AgentActor::Operator)
            .unwrap()
            .into_iter()
            .find(|v| v.agent_id == id)
            .unwrap()
            .partial_output,
        Some(partial.clone())
    );
    let observation = port.wait(AgentActor::Operator, 0, 20).await.unwrap();
    assert!(observation.revision >= observation.durable_revision);
    assert_eq!(
        observation
            .agents
            .into_iter()
            .find(|v| v.agent_id == id)
            .unwrap()
            .partial_output,
        Some(partial)
    );
    let durable_revision = observation.durable_revision;
    let cursor = observation.revision;
    provider.partial_release.notify_one();
    until(|| provider.partial_started.load(Ordering::SeqCst) == 2).await;
    let next = port.wait(AgentActor::Operator, cursor, 20).await.unwrap();
    assert!(!next.timed_out && next.revision > cursor);
    assert_eq!(
        next.durable_revision, durable_revision,
        "partial output does not invent a WAL transition"
    );
    assert!(
        next.agents
            .iter()
            .find(|v| v.agent_id == id)
            .unwrap()
            .partial_output
            .as_ref()
            .unwrap()
            .text
            .as_ref()
            .unwrap()
            .contains("next partial")
    );
    provider.partial_release.notify_one();
    until(|| port.inspect(AgentActor::Operator, id).unwrap().state == AgentStateV1::Idle).await;
    assert!(
        port.inspect(AgentActor::Operator, id)
            .unwrap()
            .last_summary
            .is_some()
    );
}

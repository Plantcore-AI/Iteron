use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct TailWaitProvider {
    calls: Vec<ToolUse>,
    calls_completed: Arc<AtomicUsize>,
    completed: Arc<tokio::sync::Notify>,
    turn: AtomicUsize,
    wait_for_tools: bool,
}

#[async_trait::async_trait]
impl iteron_provider::Provider for TailWaitProvider {
    async fn turn(
        &self,
        _request: &iteron_provider::TurnRequest,
        on_item: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
    ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
        if self.turn.fetch_add(1, Ordering::SeqCst) > 0 {
            return Ok(iteron_provider::TurnResult {
                blocks: vec![Block::Text {
                    text: "done".into(),
                }],
                stop_reason: iteron_protocol::StopReason::EndTurn,
                usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
            });
        }
        for call in &self.calls {
            on_item(iteron_provider::StreamItem::ToolUseComplete(call.clone()));
        }
        if self.wait_for_tools {
            // Provider completion is causally impossible until both command handlers finish.
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let wake = self.completed.notified();
                    if self.calls_completed.load(Ordering::SeqCst) == self.calls.len() {
                        break;
                    }
                    wake.await;
                }
            })
            .await
            .expect("local Auto command tools must execute during the provider stream");
        } else {
            tokio::task::yield_now().await;
            assert_eq!(self.calls_completed.load(Ordering::SeqCst), 0);
        }
        Ok(iteron_provider::TurnResult {
            blocks: self.calls.iter().cloned().map(Block::ToolUse).collect(),
            stop_reason: iteron_protocol::StopReason::ToolUse,
            usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
}

async fn streaming_command_fixture(wait_for_tools: bool) {
    let workspace = super::gate_integration_tests::temp_ws("stream-command-policy");
    let run = iteron_protocol::RunId(
        if wait_for_tools {
            "auto-stream"
        } else {
            "plan-stream"
        }
        .into(),
    );
    let record_path = workspace
        .join(".iteron/runs")
        .join(format!("{}.jsonl", run.0));
    let calls_completed = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(tokio::sync::Notify::new());
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut registry = iteron_tools::Registry::coding_agent(&workspace).unwrap();
    let tool_completed = calls_completed.clone();
    let tool_notify = completed.clone();
    let journal = record_path.clone();
    registry
        .register_external(
            iteron_protocol::ToolSpec {
                name: "stream_command_probe".into(),
                description: "test-only parallel command".into(),
                input_schema: serde_json::json!({"type": "object"}),
                purity: Purity::Effecting,
                capability: Capability::CodeExecuting,
            },
            move |call, _root| {
                let counter = tool_completed.clone();
                let notify = tool_notify.clone();
                let barrier = barrier.clone();
                let journal = journal.clone();
                iteron_tools::boxfut::box_it(async move {
                    let events = iteron_record::replay(&journal).unwrap();
                    assert!(
                        events.iter().any(|event| matches!(
                            &event.kind,
                            EventKind::EffectIntent { tool_use_id, .. } if tool_use_id == &call.id
                        )),
                        "effect intent must be durable before command execution"
                    );
                    tokio::time::timeout(Duration::from_secs(2), barrier.wait())
                        .await
                        .expect("parallel command handlers must share the execution gate");
                    counter.fetch_add(1, Ordering::SeqCst);
                    notify.notify_one();
                    ToolResult {
                        tool_use_id: call.id,
                        content: "executed-before-stream-terminal".into(),
                        is_error: false,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    }
                })
            },
        )
        .unwrap();
    let calls = (0..2)
        .map(|index| ToolUse {
            id: format!("stream-command-{index}"),
            name: "stream_command_probe".into(),
            input: serde_json::json!({"index": index}),
        })
        .collect();
    let provider = Arc::new(TailWaitProvider {
        calls,
        calls_completed: calls_completed.clone(),
        completed,
        turn: AtomicUsize::new(0),
        wait_for_tools,
    });
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &run,
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        provider,
        registry,
        rollout,
        "model-a".into(),
        "sys".into(),
        Budget {
            max_turns: 3,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 10,
            max_consecutive_tool_errors: 8,
        },
    );
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.workspace = workspace.clone();
    agent.context_budget_policy.tool_schema_tokens = 20_000;
    agent.permission_mode = if wait_for_tools {
        PermissionMode::Yolo
    } else {
        PermissionMode::Plan
    };
    assert_eq!(agent.run("run two commands").await.unwrap(), Outcome::Done);
    assert_eq!(
        calls_completed.load(Ordering::SeqCst),
        if wait_for_tools { 2 } else { 0 }
    );
    if wait_for_tools {
        let events = iteron_record::replay(&record_path).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(&event.kind,
                    EventKind::ToolDone { tool: Some(tool), .. } if tool == "stream_command_probe"
                ))
                .count(),
            2,
            "each streaming command must settle exactly once"
        );
    }
    drop(agent);
    std::fs::remove_dir_all(workspace).ok();
}

#[tokio::test]
async fn auto_commands_execute_concurrently_before_stream_terminal_with_durable_intents() {
    streaming_command_fixture(true).await;
}

#[tokio::test]
async fn plan_mode_never_starts_streaming_commands() {
    streaming_command_fixture(false).await;
}

#[tokio::test]
async fn exclusive_tool_waits_for_reads_and_blocks_later_reads() {
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    let first_read = super::stream_tools::execution_guard(gate.clone(), true).await;
    let mut write = Box::pin(super::stream_tools::execution_guard(gate.clone(), false));
    assert!(futures_util::poll!(&mut write).is_pending());
    let mut later_read = Box::pin(super::stream_tools::execution_guard(gate, true));
    assert!(futures_util::poll!(&mut later_read).is_pending());
    drop(first_read);
    let write = write.await;
    assert!(futures_util::poll!(&mut later_read).is_pending());
    drop(write);
    drop(later_read.await);
}

#[tokio::test]
async fn stream_write_then_read_observes_completed_mutation() {
    let workspace = super::gate_integration_tests::temp_ws("stream-write-read");
    let run = iteron_protocol::RunId("stream-write-read".into());
    let state = Arc::new(AtomicUsize::new(0));
    let calls_completed = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(tokio::sync::Notify::new());
    let mut registry = iteron_tools::Registry::coding_agent(&workspace).unwrap();
    for (name, purity, capability) in [
        (
            "stream_write",
            Purity::Effecting,
            Capability::ReversibleLocal,
        ),
        ("stream_read", Purity::Pure, Capability::ReadOnly),
    ] {
        let state = state.clone();
        let counter = calls_completed.clone();
        let notify = completed.clone();
        registry
            .register_external(
                iteron_protocol::ToolSpec {
                    name: name.into(),
                    description: "test-only ordered observation".into(),
                    input_schema: serde_json::json!({"type": "object"}),
                    purity,
                    capability,
                },
                move |call, _root| {
                    let state = state.clone();
                    let counter = counter.clone();
                    let notify = notify.clone();
                    // A pure extension may snapshot its read while constructing its future.
                    let synchronous_read =
                        (purity == Purity::Pure).then(|| state.load(Ordering::SeqCst));
                    iteron_tools::boxfut::box_it(async move {
                        if purity == Purity::Effecting {
                            tokio::task::yield_now().await;
                            state.store(1, Ordering::SeqCst);
                        } else {
                            assert_eq!(
                                synchronous_read,
                                Some(1),
                                "the pure handler closure must be invoked after the write gate"
                            );
                            assert_eq!(
                                state.load(Ordering::SeqCst),
                                1,
                                "a read must not overtake its preceding exclusive mutation"
                            );
                        }
                        counter.fetch_add(1, Ordering::SeqCst);
                        notify.notify_one();
                        ToolResult {
                            tool_use_id: call.id,
                            content: "ordered".into(),
                            is_error: false,
                            trust: Trust::Workspace,
                            latency_ms: 0,
                        }
                    })
                },
            )
            .unwrap();
    }
    let provider = Arc::new(TailWaitProvider {
        calls: ["stream_write", "stream_read"]
            .into_iter()
            .map(|name| ToolUse {
                id: name.into(),
                name: name.into(),
                input: serde_json::json!({}),
            })
            .collect(),
        calls_completed: calls_completed.clone(),
        completed,
        turn: AtomicUsize::new(0),
        wait_for_tools: true,
    });
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &run,
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        provider,
        registry,
        rollout,
        "model-a".into(),
        "sys".into(),
        Budget {
            max_turns: 3,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 10,
            max_consecutive_tool_errors: 8,
        },
    );
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.workspace = workspace.clone();
    agent.context_budget_policy.tool_schema_tokens = 20_000;
    agent.permission_mode = PermissionMode::Yolo;
    assert_eq!(agent.run("write then read").await.unwrap(), Outcome::Done);
    assert_eq!(calls_completed.load(Ordering::SeqCst), 2);
    drop(agent);
    std::fs::remove_dir_all(workspace).ok();
}

#[tokio::test]
async fn recovered_write_repeated_with_same_call_id_executes_once() {
    struct RepeatWrite(AtomicUsize);
    #[async_trait::async_trait]
    impl iteron_provider::Provider for RepeatWrite {
        async fn turn(
            &self,
            request: &iteron_provider::TurnRequest,
            on_item: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
        ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
            let turn = self.0.fetch_add(1, Ordering::SeqCst);
            if turn < 2 {
                let call = ToolUse {
                    id: "recovered-write-id".into(),
                    name: "counted_write".into(),
                    input: serde_json::json!({}),
                };
                on_item(iteron_provider::StreamItem::ToolUseComplete(call.clone()));
                if turn == 0 {
                    return Err(iteron_provider::ProviderError::Http(
                        "connection reset by peer".into(),
                    ));
                }
                return Ok(iteron_provider::TurnResult {
                    blocks: vec![Block::ToolUse(call)],
                    stop_reason: StopReason::ToolUse,
                    usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
                });
            }
            assert!(request.messages.last().unwrap().content.iter().any(|block| matches!(block,
                Block::ToolResult(result) if result.tool_use_id == "recovered-write-id" && !result.is_error)));
            Ok(iteron_provider::TurnResult {
                blocks: vec![Block::Text {
                    text: "done".into(),
                }],
                stop_reason: StopReason::EndTurn,
                usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
            })
        }
    }
    let workspace = super::gate_integration_tests::temp_ws("recovery-write-dedup");
    let run = iteron_protocol::RunId("recovery-write-dedup".into());
    let executions = Arc::new(AtomicUsize::new(0));
    let counter = executions.clone();
    let mut registry = iteron_tools::Registry::coding_agent(&workspace).unwrap();
    registry
        .register_external(
            iteron_protocol::ToolSpec {
                name: "counted_write".into(),
                description: "test-only counted mutation".into(),
                input_schema: serde_json::json!({"type":"object"}),
                purity: Purity::Effecting,
                capability: Capability::ReversibleLocal,
            },
            move |call, _root| {
                counter.fetch_add(1, Ordering::SeqCst);
                iteron_tools::boxfut::box_it(async move {
                    ToolResult {
                        tool_use_id: call.id,
                        content: "one mutation".into(),
                        is_error: false,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    }
                })
            },
        )
        .unwrap();
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &run,
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(RepeatWrite(AtomicUsize::new(0))),
        registry,
        rollout,
        "model-a".into(),
        "sys".into(),
        Budget {
            max_turns: 4,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 10,
            max_consecutive_tool_errors: 8,
        },
    );
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.workspace = workspace.clone();
    agent.context_budget_policy.tool_schema_tokens = 20_000;
    agent.permission_mode = PermissionMode::Yolo;
    agent.set_retry_policy(iteron_sched::BackoffPolicy {
        base_ms: 1,
        cap_ms: 1,
        max_attempts: 2,
    });
    assert_eq!(
        agent.run("write once and finish").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    let events = iteron_record::replay(
        &workspace
            .join(".iteron/runs")
            .join(format!("{}.jsonl", run.0)),
    )
    .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,
        EventKind::ToolDone { tool: Some(tool), .. } if tool == "counted_write"))
            .count(),
        1
    );
    drop(agent);
    std::fs::remove_dir_all(workspace).ok();
}

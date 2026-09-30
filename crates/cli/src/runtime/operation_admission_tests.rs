use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RequestedOperations {
    calls: Vec<ToolUse>,
    turn: AtomicUsize,
}

#[async_trait::async_trait]
impl iteron_provider::Provider for RequestedOperations {
    async fn turn(
        &self,
        _request: &iteron_provider::TurnRequest,
        on_item: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
    ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
        let blocks = if self.turn.fetch_add(1, Ordering::SeqCst) == 0 {
            self.calls
                .iter()
                .cloned()
                .map(|call| {
                    on_item(iteron_provider::StreamItem::ToolUseComplete(call.clone()));
                    Block::ToolUse(call)
                })
                .collect()
        } else {
            vec![Block::Text {
                text: "finished fixture".into(),
            }]
        };
        Ok(iteron_provider::TurnResult {
            blocks,
            stop_reason: if self.turn.load(Ordering::SeqCst) == 1 {
                iteron_protocol::StopReason::ToolUse
            } else {
                iteron_protocol::StopReason::EndTurn
            },
            usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
}

fn make_agent(workspace: &std::path::Path, registry: Registry, calls: Vec<ToolUse>) -> Agent {
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &iteron_protocol::RunId("operation-gate".into()),
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        Arc::new(RequestedOperations {
            calls,
            turn: AtomicUsize::new(0),
        }),
        registry,
        rollout,
        "model-fixture".into(),
        "system".into(),
        Budget {
            max_turns: 3,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 10,
            max_consecutive_tool_errors: 8,
        },
    );
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.workspace = workspace.to_path_buf();
    agent.context_budget_policy.tool_schema_tokens = 20_000;
    agent.permission_mode = PermissionMode::Yolo;
    agent
}

#[tokio::test]
async fn a_blanket_shell_allow_cannot_start_opaque_operations_in_any_execution_path() {
    for count in [1, 2] {
        let workspace = super::gate_integration_tests::temp_ws("operation-shell-gate");
        let invoked = Arc::new(AtomicUsize::new(0));
        let seen = invoked.clone();
        let mut registry = Registry::read_only(&workspace).unwrap();
        registry
            .register_external(
                iteron_protocol::ToolSpec {
                    name: "bash".into(),
                    description: "no process fixture".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::CodeExecuting,
                },
                move |call, _| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    iteron_tools::boxfut::box_it(async move {
                        ToolResult {
                            tool_use_id: call.id,
                            content: "ran fixture".into(),
                            is_error: false,
                            trust: Trust::Workspace,
                            latency_ms: 0,
                        }
                    })
                },
            )
            .unwrap();
        let calls = (0..count).map(|index| ToolUse {
            id: format!("opaque-{index}"), name: "bash".into(),
            input: serde_json::json!({"command":format!("python untrusted-{index}.py"),"writes":[]}),
        }).collect();
        let mut agent = make_agent(&workspace, registry, calls);
        agent.permission_rules.set_tool("bash", Verdict::Auto);
        agent.permission_rules.allow_cap(Capability::CodeExecuting);
        assert_eq!(
            agent.run("exercise operation gates").await.unwrap(),
            Outcome::Done
        );
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        let events = iteron_record::replay(agent.rollout.path()).unwrap();
        assert_eq!(events.iter().filter(|event| matches!(&event.kind,
            EventKind::ToolDone { tool: Some(tool), result, .. } if tool == "bash" && result.is_error
        )).count(), count);
        assert!(!events.iter().any(|event| matches!(&event.kind,
            EventKind::EffectIntent { tool_use_id, .. } if tool_use_id.starts_with("opaque-")
        )));
        drop(agent);
        std::fs::remove_dir_all(workspace).unwrap();
    }
}

#[tokio::test]
async fn a_blanket_file_write_allow_does_not_authorize_instruction_mutation() {
    let workspace = super::gate_integration_tests::temp_ws("operation-trust-gate");
    std::fs::write(workspace.join("AGENTS.md"), "operator instructions").unwrap();
    let registry = Registry::coding_agent_for_tests(&workspace).unwrap();
    let mut agent = make_agent(
        &workspace,
        registry,
        vec![ToolUse {
            id: "trust-write".into(),
            name: "write_file".into(),
            input: serde_json::json!({"path":"AGENTS.md","content":"model-owned replacement"}),
        }],
    );
    agent.permission_mode = PermissionMode::AcceptEdits;
    agent.permission_rules.set_tool("write_file", Verdict::Auto);
    assert_eq!(
        agent.run("exercise instruction write gate").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("AGENTS.md")).unwrap(),
        "operator instructions"
    );
    let events = iteron_record::replay(agent.rollout.path()).unwrap();
    assert!(!events.iter().any(|event| matches!(&event.kind,
        EventKind::EffectIntent { tool_use_id, .. } if tool_use_id == "trust-write"
    )));
    drop(agent);
    std::fs::remove_dir_all(workspace).unwrap();
}

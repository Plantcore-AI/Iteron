//! The parent selects a published profile; children execute real registry reads with native WALs.
use super::*;
use crate::runtime::workflow_spawner::direct::DirectChildIdentity;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const EVIDENCE: &str = "restricted reader physical evidence";
#[derive(Default)]
struct ProfileJourney {
    parent: AtomicUsize,
    reader: AtomicUsize,
    generic: AtomicUsize,
    overlap: Option<tokio::sync::Barrier>,
    overlapped: AtomicBool,
}
fn answer(text: &str) -> TurnResult {
    TurnResult {
        blocks: vec![Block::Text { text: text.into() }],
        stop_reason: StopReason::EndTurn,
        usage: UsageReport::complete(Usage {
            input: 1,
            output: 1,
            ..Default::default()
        }),
    }
}
fn tool(call: ToolUse, on_item: &mut (dyn FnMut(StreamItem) + Send)) -> TurnResult {
    on_item(StreamItem::ToolUseComplete(call.clone()));
    TurnResult {
        blocks: vec![Block::ToolUse(call)],
        stop_reason: StopReason::ToolUse,
        usage: UsageReport::complete(Usage {
            input: 1,
            output: 1,
            ..Default::default()
        }),
    }
}
fn observed_result<'a>(request: &'a TurnRequest, id: &str) -> &'a iteron_protocol::ToolResult {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .find_map(|block| match block {
            Block::ToolResult(result) if result.tool_use_id == id => Some(result),
            _ => None,
        })
        .expect("the next request must contain the actual registry terminal")
}
#[async_trait::async_trait]
impl Provider for ProfileJourney {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("fixture-provider")
    }
    async fn turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        if request.system.contains("fixture system") {
            if self.parent.fetch_add(1, Ordering::SeqCst) == 0 {
                let dispatch = request
                    .tools
                    .iter()
                    .find(|spec| spec.name == iteron_tools::DISPATCH_AGENT)
                    .expect("the caller must see dispatch_agent before choosing its profile");
                let parameter = &dispatch.input_schema["properties"]["agent_type"];
                let selected = parameter["examples"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find_map(|name| {
                        (name.as_str() == Some("file-reader")).then(|| name.as_str().unwrap())
                    })
                    .expect("select the actual pinned profile advertised to this parent");
                assert!(
                    parameter["description"]
                        .as_str()
                        .unwrap()
                        .contains("tools: [read_file]")
                );
                assert!(
                    !parameter["description"]
                        .as_str()
                        .unwrap()
                        .contains("isolated-writer")
                );
                return Ok(tool(
                    ToolUse {
                        id: "selected-reader".into(),
                        name: iteron_tools::DISPATCH_AGENT.into(),
                        input: serde_json::json!({"task":"Read evidence.txt and return its content; read-only investigation.","agent_type":selected}),
                    },
                    on_item,
                ));
            }
            let result = observed_result(request, "selected-reader");
            assert!(!result.is_error, "{}", result.content);
            assert!(result.content.contains(EVIDENCE));
            return Ok(answer(&result.content));
        }
        let narrow = request.tools.len() == 1 && request.tools[0].name == "read_file";
        let (counter, id, name, input) = if narrow {
            (
                &self.reader,
                "child-read",
                "read_file",
                serde_json::json!({"path":"evidence.txt"}),
            )
        } else {
            assert!(request.tools.iter().any(|tool| tool.name == "list_dir"));
            assert!(
                !request
                    .tools
                    .iter()
                    .any(|tool| tool.name == iteron_tools::DISPATCH_AGENT)
            );
            (
                &self.generic,
                "sibling-list",
                "list_dir",
                serde_json::json!({"path":"."}),
            )
        };
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            if let Some(barrier) = &self.overlap {
                tokio::time::timeout(Duration::from_secs(5), barrier.wait())
                    .await
                    .expect("both child requests must overlap, not execute serially");
                self.overlapped.store(true, Ordering::SeqCst);
            }
            return Ok(tool(
                ToolUse {
                    id: id.into(),
                    name: name.into(),
                    input,
                },
                on_item,
            ));
        }
        let result = observed_result(request, id);
        assert!(!result.is_error, "{}", result.content);
        if narrow {
            assert!(result.content.contains(EVIDENCE));
            assert!(!request.messages.iter().flat_map(|message| &message.content)
                .any(|block| matches!(block, Block::ToolResult(result) if result.tool_use_id == "sibling-list")));
            Ok(answer(EVIDENCE))
        } else {
            assert!(result.content.contains("evidence.txt"));
            assert!(!result.content.contains(EVIDENCE));
            assert!(!request.messages.iter().flat_map(|message| &message.content)
                .any(|block| matches!(block, Block::ToolResult(result) if result.tool_use_id == "child-read")));
            Ok(answer("generic sibling listed evidence.txt"))
        }
    }
}
fn assert_read_terminal(path: &std::path::Path) {
    let events = iteron_record::replay(path).unwrap();
    let (seq, effect) = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::EffectIntent {
                id,
                tool,
                tool_use_id,
                ..
            } if tool == "read_file" && tool_use_id == "child-read" => Some((event.seq, id)),
            _ => None,
        })
        .expect("the actual selected child must commit a read intent");
    assert!(events.iter().any(|event| event.seq > seq && matches!(&event.kind,
        EventKind::ToolDone { effect_id: Some(id), tool: Some(name), result, .. }
        if id == effect && name == "read_file" && result.tool_use_id == "child-read" && !result.is_error)));
    assert!(!events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectIntent { tool, .. }
        if ["list_dir", "glob", "grep", "write_file", "bash"].contains(&tool.as_str()))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parent_dispatch_selects_pinned_reader_and_returns_physical_read_evidence() {
    // Exercise the same worker-stack boundary as the app-server parent, not block_on's thread.
    tokio::spawn(parent_dispatch_profile_journey())
        .await
        .unwrap();
}

async fn parent_dispatch_profile_journey() {
    let provider = Arc::new(ProfileJourney::default());
    let mut host = host_with_provider("caller-selected-profile", true, provider.clone());
    // This headless parent must authorize dispatch before exercising the child profile.
    host.permission_rules
        .set_tool(iteron_tools::DISPATCH_AGENT, iteron_protocol::Verdict::Auto);
    std::fs::write(host.workspace.join("evidence.txt"), EVIDENCE).unwrap();
    let snapshot = host.registry.spec_snapshot();
    let catalog = host.agent_catalog_snapshot();
    crate::runtime::Agent::configure_dispatch_profiles(&mut host.registry, &catalog);
    assert!(
        Arc::ptr_eq(&snapshot, &host.registry.spec_snapshot()),
        "unchanged pin must not invalidate the tool schema identity"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(15), host.run_leaf(
        "Use dispatch_agent with its pinned file-reader profile to read evidence.txt. Return that child's evidence. This is a read-only investigation."
    )).await.unwrap().unwrap();
    assert!(matches!(outcome, iteron_protocol::Outcome::Done));
    assert_eq!(host.last_assistant_text, EVIDENCE);
    assert_eq!(provider.parent.load(Ordering::SeqCst), 2);
    assert_eq!(provider.reader.load(Ordering::SeqCst), 2);
    assert_eq!(provider.generic.load(Ordering::SeqCst), 0);
    assert_eq!(host.session_spawn_ledger.admitted(), 1);
    let events = iteron_record::replay(host.rollout.path()).unwrap();
    let child = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::SubagentFinishedV2 {
                sub_run, metrics, ..
            } => {
                assert_eq!(metrics.tool_calls, 1);
                assert_eq!(metrics.provider_attempts, 2);
                Some(sub_run)
            }
            _ => None,
        })
        .expect("the parent must receive the child's actual terminal accounting");
    assert_read_terminal(&host.subagent_directory().join(format!("{child}.jsonl")));
    assert!(host.parent_effects_known());
    let workspace = host.workspace.clone();
    host.finish_advisory_maintenance_for_test().await.unwrap();
    drop(host);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn overlapping_children_keep_their_own_tool_catalogs_and_results() {
    let provider = Arc::new(ProfileJourney {
        overlap: Some(tokio::sync::Barrier::new(2)),
        ..Default::default()
    });
    let host = host_with_provider("overlapping-profile-children", true, provider.clone());
    // Unknown provider quota intentionally serializes requests; this fixture admits both.
    let governor = host.provider_governor.as_ref().unwrap();
    assert!(governor.policy().max_in_flight_per_route >= 2);
    let minimum = governor.policy().rate_admission;
    governor.observe_rate_limit(
        &host.governed_route_id(),
        iteron_provider::RateLimitSnapshot {
            requests_remaining: Some(minimum.minimum_remaining_requests.saturating_add(8)),
            tokens_remaining: Some(minimum.minimum_remaining_tokens.saturating_add(100_000)),
            requests_reset: None,
            tokens_reset: None,
        },
        Instant::now(),
    );
    std::fs::write(host.workspace.join("evidence.txt"), EVIDENCE).unwrap();
    let catalog_digest = host.agent_catalog_digest();
    let route = host.provider_selection.selected().unwrap().route.clone();
    let spawner = crate::runtime::KernelSpawner::new(
        host.kernel_spawner_context(&route, "profile-concurrency"),
    );
    let identity = |name: &str| DirectChildIdentity {
        run: RunId(name.into()),
        directory: host.subagent_directory(),
        depth: 1,
        effort: host.execution_policy.subagent_effort,
        deadline: Instant::now() + Duration::from_secs(15),
        diagnostics: Default::default(),
    };
    let mut reader = spawner
        .build_direct_child(&identity("restricted-child"), Some("file-reader"))
        .unwrap();
    let mut generic = spawner
        .build_direct_child(&identity("generic-child"), None)
        .unwrap();
    let (read, listed) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            reader.run_leaf("Read evidence.txt."),
            generic.run_leaf("List the current directory.")
        )
    })
    .await
    .unwrap();
    assert!(matches!(read.unwrap(), iteron_protocol::Outcome::Done));
    assert!(matches!(listed.unwrap(), iteron_protocol::Outcome::Done));
    assert!(provider.overlapped.load(Ordering::SeqCst));
    assert_eq!(provider.reader.load(Ordering::SeqCst), 2);
    assert_eq!(provider.generic.load(Ordering::SeqCst), 2);
    assert_eq!(reader.last_assistant_text, EVIDENCE);
    assert_eq!(
        generic.last_assistant_text,
        "generic sibling listed evidence.txt"
    );
    assert_eq!(
        reader
            .registry
            .specs()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["read_file"]
    );
    assert!(
        generic
            .registry
            .specs()
            .iter()
            .any(|tool| tool.name == "list_dir")
    );
    assert_eq!(host.agent_catalog_digest(), catalog_digest);
    let refused = reader
        .registry
        .run(ToolUse {
            id: "forged-sibling-tool".into(),
            name: "list_dir".into(),
            input: serde_json::json!({"path":"."}),
        })
        .await;
    assert!(
        refused.is_error,
        "a concurrent broader sibling must not expand execution authority"
    );
    assert_read_terminal(reader.rollout.path());
    assert!(reader.parent_effects_known() && generic.parent_effects_known());
    reader.finish_advisory_maintenance_for_test().await.unwrap();
    generic
        .finish_advisory_maintenance_for_test()
        .await
        .unwrap();
    host.finish_advisory_maintenance_for_test().await.unwrap();
    let workspace = host.workspace.clone();
    drop((reader, generic, spawner, host));
    std::fs::remove_dir_all(workspace).unwrap();
}

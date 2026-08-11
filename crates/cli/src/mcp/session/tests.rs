use super::*;
use iteron_protocol::ToolUse;

fn fixture(marker: &Path) -> McpServerConfig {
    let script = concat!(
        "printf 'spawned' > \"$1\"; ",
        "IFS= read -r initialize; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{},\"resources\":{},\"prompts\":{}}}}'; ",
        "IFS= read -r initialized; ",
        "IFS= read -r list; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"fixture\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
        "IFS= read -r call; ",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"pong\"}]}}'; ",
        "exec sleep 60"
    );
    McpServerConfig {
        name: "alpha".into(),
        transport: McpTransportConfig::Stdio,
        command: Some("/bin/bash".into()),
        args: vec![
            "-c".into(),
            script.into(),
            "mcp-session-fixture".into(),
            marker.to_string_lossy().into_owned(),
        ],
        url: None,
        header_env: BTreeMap::new(),
        oauth: None,
        tools: iteron_mcp::McpToolFilter::default(),
        policy: iteron_mcp::McpServerPolicy::default(),
    }
}

fn settings(cleanup: iteron_mcp::McpSpillCleanup) -> EffectiveMcpSettings {
    EffectiveMcpSettings {
        reconnect: iteron_mcp::reconnect::ReconnectPolicy::new(1, 1, 1).unwrap(),
        deadlines: iteron_mcp::McpDeadlinePolicy::default(),
        result: iteron_mcp::McpResultPolicy::new(128, 4096, cleanup).unwrap(),
    }
}

fn marker() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::env::temp_dir().join(format!(
        "iteron-cli-mcp-lazy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[tokio::test]
async fn registration_configuration_and_stale_call_do_not_spawn_then_search_does() {
    let marker = marker();
    let _ = std::fs::remove_file(&marker);
    let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
    let runtime = McpRuntimeControl::register(&mut registry, &[fixture(&marker)], &[]).unwrap();

    assert!(
        !marker.exists(),
        "registration must not start configured code"
    );
    assert_eq!(runtime.health()[0].phase, "deferred");
    runtime
        .configure(settings(iteron_mcp::McpSpillCleanup::SessionEnd))
        .unwrap();
    assert!(
        !marker.exists(),
        "checkpoint pinning must remain side-effect free"
    );

    let stale = registry
        .run_effect(ToolUse {
            id: "stale".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(stale.is_error);
    assert!(
        !marker.exists(),
        "an unsearched identity must fail before startup"
    );

    let search = registry
        .run_effect(ToolUse {
            id: "search".into(),
            name: "alpha__tool_search".into(),
            input: json!({"query":"echo","limit":4}),
        })
        .await
        .into_result();
    assert!(!search.is_error, "{}", search.content);
    assert!(search.content.contains("alpha__echo"));
    assert!(
        marker.exists(),
        "the first valid discovery request starts the server"
    );

    let call = registry
        .run_effect(ToolUse {
            id: "call".into(),
            name: "alpha__tool_call".into(),
            input: json!({"name":"alpha__echo","arguments":{}}),
        })
        .await
        .into_result();
    assert!(!call.is_error, "{}", call.content);
    assert!(call.content.contains("pong"));
    let health = &runtime.health()[0];
    assert_eq!(health.phase, "ready");
    assert_eq!(health.generation, Some(1));
    assert!(health.catalog_current);

    runtime.stop("alpha").await.unwrap();
    assert_eq!(runtime.health()[0].phase, "stopped");
    runtime.restart("alpha").await.unwrap();
    assert_eq!(runtime.health()[0].phase, "deferred");
    let _ = std::fs::remove_file(marker);
}

#[test]
fn all_declared_cleanup_scopes_are_accepted_by_the_runtime_owner() {
    for cleanup in [
        iteron_mcp::McpSpillCleanup::ToolEnd,
        iteron_mcp::McpSpillCleanup::TurnEnd,
        iteron_mcp::McpSpillCleanup::RunEnd,
        iteron_mcp::McpSpillCleanup::SessionEnd,
    ] {
        assert_eq!(settings(cleanup).result.cleanup(), cleanup);
    }
}

use super::ToolResponseOwner;
use iteron_protocol::{Block, ToolResult, ToolUse, Trust};

fn call(id: &str) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"a"}),
    }
}

fn result(id: &str, error: bool) -> ToolResult {
    ToolResult {
        tool_use_id: id.into(),
        content: id.into(),
        is_error: error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[test]
fn missing_result_cannot_build_the_next_provider_message() {
    let calls = [call("first"), call("second")];
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(0, result("first", false)).unwrap();
    assert!(response.validate_complete().is_err());
    assert!(response.into_parts().is_err());
}

#[test]
fn a_substituted_or_duplicate_result_cannot_replace_the_admitted_declaration() {
    let calls = [call("first")];
    let mut response = ToolResponseOwner::new(&calls);
    assert!(response.accept(0, result("other", false)).is_err());
    response.accept(0, result("first", false)).unwrap();
    assert!(response.accept(0, result("first", true)).is_err());
    assert!(!response.had_error());
}

#[test]
fn actual_out_of_order_completion_projects_once_in_declaration_order() {
    let calls = [call("first"), call("second")];
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(1, result("second", true)).unwrap();
    response.accept(0, result("first", false)).unwrap();
    assert!(response.had_error());
    let message = response.into_parts().unwrap().message.into_message();
    let ids = message
        .content
        .iter()
        .map(|block| match block {
            Block::ToolResult(result) => result.tool_use_id.as_str(),
            _ => panic!("unexpected model block"),
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["first", "second"]);
}

#[test]
fn model_projection_scrubs_credentials_without_replacing_the_physical_or_recovery_receipt() {
    use crate::runtime::submitted_turn_state::SubmittedTurnState;
    let calls = [call("actual-read")];
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let mut physical = result("actual-read", true);
    physical.content =
        format!("safe heading\nkey={secret}\nhttps://user:password@host.invalid/\n安全尾部");
    physical.latency_ms = 13;
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(0, physical.clone()).unwrap();
    let mut recovery = SubmittedTurnState::default();
    response.retain_recovery(&mut recovery).unwrap();
    assert_eq!(response.results()[0].as_ref().unwrap(), &physical);
    assert_eq!(recovery.recovered_tool("actual-read").unwrap().1, physical);
    let message = response.into_parts().unwrap().message.into_message();
    let [Block::ToolResult(visible)] = message.content.as_slice() else {
        panic!("one matching model result")
    };
    assert_eq!(visible.tool_use_id, physical.tool_use_id);
    assert_eq!(visible.is_error, physical.is_error);
    assert_eq!(visible.trust, physical.trust);
    assert_eq!(visible.latency_ms, physical.latency_ms);
    assert!(visible.content.contains("[REDACTED:"));
    assert!(!visible.content.contains(secret));
    assert!(!visible.content.contains("user:password@"));
    assert!(visible.content.len() <= physical.content.len());
    assert!(visible.content.contains("safe heading"));

    // Actual retained recovery uses the same outlet, without replaying an executor.
    let mut replayed = ToolResponseOwner::new(&calls);
    replayed
        .replay([(0, recovery.recovered_tool("actual-read").unwrap().1.clone())].into())
        .unwrap();
    assert_eq!(
        serde_json::to_value(replayed.into_parts().unwrap().message.into_message()).unwrap(),
        serde_json::to_value(message).unwrap()
    );
}

#[test]
fn redaction_expansion_never_enlarges_the_existing_model_result_envelope() {
    let calls = [call("short-credential")];
    let mut physical = result("short-credential", false);
    physical.content = "http://user:x@host.invalid/".into();
    assert!(iteron_record::redact::scrub(&physical.content).len() > physical.content.len());
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(0, physical.clone()).unwrap();
    let message = response.into_parts().unwrap().message.into_message();
    let [Block::ToolResult(visible)] = message.content.as_slice() else {
        panic!("one matching model result")
    };
    assert!(visible.content.len() <= physical.content.len());
    assert!(!visible.content.contains("user:x@"));
    assert_eq!(visible.tool_use_id, physical.tool_use_id);
}

#[test]
fn model_scrubbing_does_not_rewrite_a_retained_private_spill() {
    use crate::runtime::tool_output_spill::{
        ToolOutputSpillCleanup, ToolOutputSpillPolicy, ToolOutputSpillStore,
    };
    let calls = [call("private-output")];
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let raw = format!(
        "api_key={secret}\n{}\nsafe tail",
        "source line\n".repeat(100)
    );
    let mut physical = result("private-output", false);
    physical.content = raw.clone();
    let store = ToolOutputSpillStore::create(
        ToolOutputSpillPolicy::new(256, 4096, ToolOutputSpillCleanup::RunEnd).unwrap(),
    )
    .unwrap();
    let managed = store.apply(physical);
    assert!(managed.spilled);
    let start = managed.result.content.find("sha256:").unwrap();
    let handle = managed.result.content[start..start + "sha256:".len() + 64].to_owned();
    let (projection, _lease, _) = managed.into_parts();
    let visible_bound = projection.content.len();
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(0, projection).unwrap();
    let message = response.into_parts().unwrap().message.into_message();
    let [Block::ToolResult(visible)] = message.content.as_slice() else {
        panic!("one matching model result")
    };
    assert!(!visible.content.contains(secret));
    assert!(visible.content.len() <= visible_bound);
    assert_eq!(store.read_private(&handle).unwrap(), raw.as_bytes());
}

#[tokio::test]
async fn native_read_file_credentials_are_absent_from_the_actual_following_http_request() {
    use crate::runtime::gate_integration_tests::{record_test_genesis, temp_ws};
    use crate::runtime::{Agent, Outcome};
    use iteron_protocol::{Budget, EventKind, RunId, TenantId};
    use iteron_provider::OpenAiCompat;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let workspace = temp_ws("model-tool-result-credentials");
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let source = format!("safe source heading\napi_key={secret}\nsafe source tail\n");
    std::fs::write(workspace.join("source.txt"), &source).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let root = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for step in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 16 * 1024);
                socket.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let head = std::str::from_utf8(&head).unwrap();
            assert!(head.starts_with("POST /v1/chat/completions "));
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 1024 * 1024);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            requests.push(serde_json::from_slice::<serde_json::Value>(&body).unwrap());
            let (delta, finish) = if step == 0 {
                (
                    serde_json::json!({"tool_calls":[{"index":0,"id":"actual-read","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"source.txt\"}"}}]}),
                    "tool_calls",
                )
            } else {
                (
                    serde_json::json!({"content":"completed source read"}),
                    "stop",
                )
            };
            let stream = format!(
                "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                serde_json::json!({"choices":[{"index":0,"delta":delta,"finish_reason":null}]}),
                serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":finish}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}),
            );
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{stream}",
                stream.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
        }
        requests
    });
    // The native server is only an IO oracle; no custom Provider bypasses the real serializer.
    let provider =
        Arc::new(OpenAiCompat::try_new("fixture-header-only".into(), Some(root)).unwrap());
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("model-tool-result-credentials".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        iteron_tools::Registry::read_only(&workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        "read the requested source once".into(),
        Budget::default(),
    );
    agent.workspace = workspace.clone();
    record_test_genesis(&mut agent, &workspace);
    agent
        .record_operator_model_selection(
            provider,
            "tool-secret-native".into(),
            "fixture-model".into(),
            String::new(),
            String::new(),
        )
        .unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        Box::pin(agent.run("read source.txt")),
    )
    .await;
    if outcome.is_err() {
        server.abort();
    }
    assert_eq!(outcome.unwrap().unwrap(), Outcome::Done);
    let requests = tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.len(), 2);
    let visible = requests[1]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool" && message["tool_call_id"] == "actual-read")
        .unwrap();
    let content = visible["content"].as_str().unwrap();
    assert!(content.contains("safe source heading"));
    assert!(content.contains("[REDACTED:"));
    assert!(
        !serde_json::to_string(&requests[1])
            .unwrap()
            .contains(secret)
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("source.txt")).unwrap(),
        source
    );
    let path = agent.rollout.path().to_owned();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(
        events.iter().filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")).count(),
        2
    );
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::ToolDone { result, .. } if result.tool_use_id == "actual-read" && !result.is_error && result.content.contains("[REDACTED:"))));
    std::fs::remove_dir_all(workspace).unwrap();
}

//! Native file witnesses must remain usable through the actual model/record boundaries.
use super::{NativeHttpJourney, NativeHttpProgress, NativeHttpStage};
use crate::runtime::gate_integration_tests::{record_test_genesis, temp_ws};
use crate::runtime::{Agent, Outcome};
use iteron_protocol::{Budget, EventKind, PermissionMode, RunId, TenantId};
use iteron_provider::OpenAiCompat;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SECRET: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
const BODY_HEX: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[tokio::test]
async fn native_read_preimage_reaches_next_http_request_and_authorizes_exact_write() {
    native_preimage_http_round_trip(false).await;
}

#[tokio::test]
async fn native_read_preimage_survives_record_reopen_before_http_write() {
    native_preimage_http_round_trip(true).await;
}

async fn native_preimage_http_round_trip(cold: bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let progress = NativeHttpProgress::new();
    let server_progress = progress.clone();
    let workspace = temp_ws(if cold {
        "preimage-cold"
    } else {
        "preimage-live"
    });
    // The witness binds raw BOM/CRLF bytes, while ordinary body tokens remain scrubbed.
    let original = format!("\u{feff}42\r\napi_key={SECRET}\r\nraw_sha256: {BODY_HEX}\r\n");
    std::fs::write(workspace.join("target.txt"), &original).unwrap();
    let digest = format!("{:x}", Sha256::digest(original.as_bytes()));
    let expected_digest = digest.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let root = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let count = if cold { 4 } else { 3 };
        let write_step = if cold { 2 } else { 1 };
        let mut requests = Vec::new();
        for step in 0..count {
            NativeHttpProgress::record(&server_progress, step, NativeHttpStage::Accept);
            let (mut socket, _) = tokio::time::timeout_at(deadline, listener.accept())
                .await
                .unwrap()
                .unwrap();
            NativeHttpProgress::record(&server_progress, step, NativeHttpStage::Headers);
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 16 * 1024);
                tokio::time::timeout_at(deadline, socket.read_exact(&mut byte))
                    .await
                    .unwrap()
                    .unwrap();
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
            NativeHttpProgress::record(&server_progress, step, NativeHttpStage::Body);
            tokio::time::timeout_at(deadline, socket.read_exact(&mut body))
                .await
                .unwrap()
                .unwrap();
            NativeHttpProgress::record(&server_progress, step, NativeHttpStage::Reply);
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let encoded = serde_json::to_string(&request).unwrap();
            assert!(!encoded.contains(SECRET));
            assert!(!encoded.contains(BODY_HEX));
            if step == 0 {
                let read = request["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|tool| tool["function"]["name"] == "read_file")
                    .unwrap();
                let description = read["function"]["description"].as_str().unwrap();
                assert!(description.contains("raw_sha256=sha256-<64 lowercase hex digits>"));
                assert!(description.contains("pass only those 64 digits"));
                assert_eq!(
                    read["function"]["parameters"]["properties"]["include_sha256"]["type"],
                    "boolean"
                );
            }

            let witness = if step > 0 {
                let result = request["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|message| {
                        message["role"] == "tool" && message["tool_call_id"] == "preimage-read"
                    })
                    .unwrap()["content"]
                    .as_str()
                    .unwrap();
                assert!(result.contains("[REDACTED:"));
                let witness = result
                    .lines()
                    .next()
                    .unwrap()
                    .strip_prefix("raw_sha256=sha256-")
                    .unwrap();
                assert_eq!(witness, expected_digest);
                Some(witness.to_owned())
            } else {
                None
            };
            let (delta, finish) = if step == 0 {
                let arguments = serde_json::json!({"path":"target.txt","include_sha256":true});
                (
                    serde_json::json!({"tool_calls":[{"index":0,"id":"preimage-read","type":"function","function":{"name":"read_file","arguments":arguments.to_string()}}]}),
                    "tool_calls",
                )
            } else if step == write_step {
                // The model oracle copies the witness it actually received, not a digest
                // injected through the test's local registry or filesystem.
                let arguments = serde_json::json!({"path":"target.txt","content":"42\n","expected_sha256":witness.unwrap()});
                (
                    serde_json::json!({"tool_calls":[{"index":0,"id":"preimage-write","type":"function","function":{"name":"write_file","arguments":arguments.to_string()}}]}),
                    "tool_calls",
                )
            } else {
                if step > write_step {
                    let result = request["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|message| {
                            message["role"] == "tool" && message["tool_call_id"] == "preimage-write"
                        })
                        .unwrap()["content"]
                        .as_str()
                        .unwrap();
                    assert_eq!(result, "wrote target.txt (3 bytes)");
                }
                (
                    serde_json::json!({"content":"completed fixture step"}),
                    "stop",
                )
            };
            requests.push(request);
            let stream = format!(
                "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                serde_json::json!({"choices":[{"index":0,"delta":delta,"finish_reason":null}]}),
                serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":finish}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}),
            );
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{stream}",
                stream.len()
            );
            tokio::time::timeout_at(deadline, socket.write_all(reply.as_bytes()))
                .await
                .unwrap()
                .unwrap();
            NativeHttpProgress::record(&server_progress, step, NativeHttpStage::Replied);
        }
        requests
    });
    let mut journey = NativeHttpJourney {
        deadline,
        progress,
        server: Some(server),
        requests: None,
    };
    let provider =
        Arc::new(OpenAiCompat::try_new("fixture-header-only".into(), Some(root)).unwrap());
    let run_id = RunId("native-preimage".into());
    let make_agent = || {
        let rollout = iteron_record::Rollout::open(
            &workspace.join(".iteron/runs"),
            &run_id,
            TenantId::default(),
        )
        .unwrap();
        let mut registry = iteron_tools::Registry::isolated_writer(&workspace).unwrap();
        // Exercise the real native writer and commit guard in this fixture. A Linux helper
        // must not self-execute the libtest image, whose entrypoint is not the CLI main.
        registry.set_confine_execution(false);
        let mut agent = Agent::new(
            provider.clone(),
            registry,
            rollout,
            "fixture-model".into(),
            "Perform the requested local fixture step.".into(),
            Budget {
                max_turns: if cold { 4 } else { 3 },
                ..Budget::default()
            },
        );
        agent.workspace = workspace.clone();
        agent.permission_mode = PermissionMode::Yolo;
        agent
    };
    let mut agent = make_agent();
    record_test_genesis(&mut agent, &workspace);
    agent
        .record_operator_model_selection(
            provider.clone(),
            "native-preimage-http".into(),
            "fixture-model".into(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
    let path = agent.rollout.path().to_owned();
    let first = journey
        .wait(
            "read/preimage write",
            Box::pin(agent.run("Read target.txt with its raw preimage.")),
        )
        .await;
    assert_eq!(first.unwrap(), Outcome::Done);
    journey
        .wait(
            "first maintenance drain",
            agent.finish_advisory_maintenance_for_test(),
        )
        .await
        .unwrap();
    drop(agent);
    if cold {
        assert_eq!(
            std::fs::read(workspace.join("target.txt")).unwrap(),
            original.as_bytes()
        );
        let messages = Agent::messages_from_rollout(&path).unwrap();
        let mut resumed = make_agent();
        resumed.set_resume(messages).unwrap();
        let second = journey
            .wait(
                "cold preimage write",
                Box::pin(
                    resumed.run("Replace target.txt with exactly 42 followed by one newline."),
                ),
            )
            .await;
        assert_eq!(second.unwrap(), Outcome::Done);
        journey
            .wait(
                "resumed maintenance drain",
                resumed.finish_advisory_maintenance_for_test(),
            )
            .await
            .unwrap();
        drop(resumed);
    }
    let requests = journey.finish().await;
    assert_eq!(requests.len(), if cold { 4 } else { 3 });
    assert_eq!(
        std::fs::read(workspace.join("target.txt")).unwrap(),
        b"42\n"
    );
    let events = iteron_record::replay(&path).unwrap();
    let witness_header = format!("raw_sha256=sha256-{digest}\n");
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::ToolDone { result, .. } if result.tool_use_id == "preimage-read"
            && !result.is_error && result.content.starts_with(&witness_header)
            && !result.content.contains(SECRET) && !result.content.contains(BODY_HEX))));
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::ToolDone { result, .. } if result.tool_use_id == "preimage-write"
            && !result.is_error && result.content == "wrote target.txt (3 bytes)")));
    std::fs::remove_dir_all(workspace).unwrap();
}

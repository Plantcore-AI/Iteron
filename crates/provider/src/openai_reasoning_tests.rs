//! Route-scoped reasoning continuation, including answers without tool calls.
use super::*;
use iteron_protocol::{Capability, Message, Purity, ToolSpec};

const SCOPE: &str = "deepseek-replay-fixture";
const REASONING: &str = "bounded synthetic continuation";

fn tools() -> crate::PreparedToolSchemas {
    vec![ToolSpec {
        name: "read_file".into(),
        description: "Read a local file".into(),
        input_schema: serde_json::json!({"type":"object","properties":{}}),
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    }]
    .into()
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "deepseek-reasoner".into(),
        system: "stable system".into(),
        messages: vec![Message::user_text("hi")],
        input_images: vec![],
        tools: tools(),
        max_tokens: 1_024,
        cache_system: false,
        thinking_budget: 4_096,
        reasoning_effort: ReasoningEffort::Medium,
        controls: Default::default(),
    }
}

#[test]
fn deepseek_tool_requests_replay_final_answer_reasoning_only_on_matching_route() {
    let mut request = request();
    request.messages.push(Message {
        role: Role::Assistant,
        content: vec![
            Block::ProviderState(reasoning_provider_state(SCOPE, REASONING).unwrap()),
            Block::Text {
                text: "hello".into(),
            },
        ],
    });
    request.messages.push(Message::user_text("hi again"));
    for profile in [
        ErrorProfile::DeepSeek,
        ErrorProfile::Glm,
        ErrorProfile::Fireworks,
        ErrorProfile::OpenAi,
        ErrorProfile::CustomConservative,
    ] {
        let provider = OpenAiCompat::with_root(
            "synthetic-test-key".into(),
            ApiRoot::parse("https://api.deepseek.com/v1").unwrap(),
        )
        .unwrap()
        .with_error_profile(profile)
        .with_route_scope(SCOPE.into())
        .unwrap();
        let body = provider.body(&request).unwrap();
        assert_eq!(body["tools"].as_array().unwrap().len(), 1);
        let answer = &body["messages"][2];
        assert!(answer.get("tool_calls").is_none());
        assert_eq!(
            answer
                .get("reasoning_content")
                .and_then(serde_json::Value::as_str),
            (profile == ErrorProfile::DeepSeek).then_some(REASONING)
        );
        let other_route = provider.with_route_scope("other-instance".into()).unwrap();
        assert!(
            other_route.body(&request).unwrap()["messages"][2]
                .get("reasoning_content")
                .is_none()
        );
    }

    let provider = OpenAiCompat::with_root(
        "synthetic-test-key".into(),
        ApiRoot::parse("https://api.deepseek.com/v1").unwrap(),
    )
    .unwrap()
    .with_error_profile(ErrorProfile::DeepSeek)
    .with_route_scope(SCOPE.into())
    .unwrap();
    request.tools = vec![].into();
    let body = provider.body(&request).unwrap();
    assert!(body.get("tools").is_none());
    assert!(body["messages"][2].get("reasoning_content").is_none());
}

#[tokio::test]
async fn deepseek_text_only_stream_retains_continuation_for_later_tool_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let root = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).await.unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&chunk[..n]);
                assert!(bytes.len() <= 65_536);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]);
                    let length = header.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    }).unwrap();
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let delta = serde_json::json!({"choices":[{"index":0,"delta":{
                "reasoning_content":REASONING,"content":"hello"
            },"finish_reason":null}]});
            let body = format!(
                "data: {delta}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":4,\"completion_tokens\":5}}}}\n\ndata: [DONE]\n\n"
            );
            stream.write_all(format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            ).as_bytes()).await.unwrap();
        }).await.unwrap();
    });
    let provider =
        OpenAiCompat::with_root("synthetic-test-key".into(), ApiRoot::parse(&root).unwrap())
            .unwrap()
            .with_error_profile(ErrorProfile::DeepSeek)
            .with_route_scope(SCOPE.into())
            .unwrap();
    let mut request = request();
    request.tools = vec![].into();
    let result = tokio::time::timeout(Duration::from_secs(5), provider.turn(&request, &mut |_| {}))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert_eq!(result.stop_reason, StopReason::EndTurn);
    assert!(!result.blocks.iter().any(|b| matches!(b, Block::ToolUse(_))));
    assert!(
        result
            .blocks
            .iter()
            .any(|b| matches!(b, Block::ProviderState(_)))
    );
    request.messages.push(Message {
        role: Role::Assistant,
        content: result.blocks,
    });
    request.messages.push(Message::user_text("hi again"));
    request.tools = tools();
    let body = provider.body(&request).unwrap();
    assert_eq!(body["messages"][2]["reasoning_content"], REASONING);
    assert!(body["messages"][2].get("tool_calls").is_none());
}

#[test]
fn direct_minimax_and_moonshot_replay_only_exact_route_reasoning() {
    let mut request = request();
    request.tools = vec![].into();
    request.messages.push(Message {
        role: Role::Assistant,
        content: vec![
            Block::ProviderState(reasoning_provider_state(SCOPE, REASONING).unwrap()),
            Block::Thinking {
                thinking: "portable projection is not continuation".into(),
            },
            Block::Text {
                text: "<think>legacy inline content</think>hello".into(),
            },
        ],
    });
    request.messages.push(Message::user_text("continue"));
    for (root, preserves) in [
        ("https://api.minimax.io/v1", true),
        ("https://api.minimax.cn/v1", true),
        ("https://api.minimaxi.com/v1", true),
        ("https://api.moonshot.ai/v1", true),
        ("https://api.moonshot.cn/v1", true),
        ("https://api.moonshot.ai.example.org/v1", false),
        ("https://api.moonshot.ai/v1/proxy", false),
        ("https://api.minimax.io/v1/proxy", false),
        ("https://gateway.example.org/v1", false),
    ] {
        let provider =
            OpenAiCompat::with_root("synthetic-test-key".into(), ApiRoot::parse(root).unwrap())
                .unwrap()
                .with_route_scope(SCOPE.into())
                .unwrap();
        assert_eq!(
            ChatReasoningReplay::for_route(provider.error_profile, provider.api_root.as_ref())
                .retains(false),
            preserves,
            "text-only response retention: {root}"
        );
        // A vendor-like model ID cannot grant an unknown gateway a continuation contract.
        for model in ["kimi-k2.7-code", "MiniMax-M3.1-Flash-Preview"] {
            request.model = model.into();
            let body = provider.body(&request).unwrap();
            assert_eq!(
                body["messages"][2]["reasoning_content"].as_str(),
                preserves.then_some(REASONING),
                "{root} / {model}"
            );
            assert_eq!(
                body["messages"][2]["content"],
                "<think>legacy inline content</think>hello"
            );
        }
        let mut portable = request.clone();
        portable.messages[1]
            .content
            .retain(|block| !matches!(block, Block::ProviderState(_)));
        assert!(
            provider.body(&portable).unwrap()["messages"][2]
                .get("reasoning_content")
                .is_none()
        );
        let other = provider.with_route_scope("other-instance".into()).unwrap();
        assert!(
            other.body(&request).unwrap()["messages"][2]
                .get("reasoning_content")
                .is_none()
        );
    }
}

#[tokio::test]
async fn minimax_stream_retains_split_reasoning_for_tool_and_text_continuations() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for with_tool in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let root = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    assert!(bytes.len() <= 65_536);
                    if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let length = header.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        }).unwrap();
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let mut first = serde_json::json!({"reasoning_content":"bounded synthetic "});
                let mut second = serde_json::json!({"reasoning_content":"continuation","content":"hello"});
                if with_tool {
                    first["tool_calls"] = serde_json::json!([{"index":0,"id":"call-1","type":"function",
                        "function":{"name":"read_file","arguments":"{\"pa"}}]);
                    second["tool_calls"] = serde_json::json!([{"index":0,
                        "function":{"arguments":"th\":\"a.rs\"}"}}]);
                }
                let mut body = String::new();
                for delta in [first, second] {
                    let frame = serde_json::json!({"choices":[{"index":0,"delta":delta,"finish_reason":null}]});
                    body.push_str(&format!("data: {frame}\n\n"));
                }
                let terminal = serde_json::json!({"choices":[{"index":0,"delta":{},
                    "finish_reason":if with_tool { "tool_calls" } else { "stop" }}],
                    "usage":{"prompt_tokens":4,"completion_tokens":5,
                        "completion_tokens_details":{"reasoning_tokens":3}}});
                body.push_str(&format!("data: {terminal}\n\ndata: [DONE]\n\n"));
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes()).await.unwrap();
            }).await.unwrap();
        });
        let provider =
            OpenAiCompat::with_root("synthetic-test-key".into(), ApiRoot::parse(&root).unwrap())
                .unwrap()
                .with_error_profile(ErrorProfile::MiniMax)
                .with_route_scope(SCOPE.into())
                .unwrap();
        let mut request = request();
        request.model = "MiniMax-M3.1-Flash-Preview".into();
        let mut observed = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            provider.turn(&request, &mut |item| observed.push(item)),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(
            result.stop_reason,
            if with_tool {
                StopReason::ToolUse
            } else {
                StopReason::EndTurn
            }
        );
        assert_eq!(result.usage.complete_usage().unwrap().thinking, 3);
        assert!(!result.usage.cache_creation_reported());
        assert_eq!(
            observed
                .iter()
                .filter(|item| matches!(item, StreamItem::ToolUseComplete(_)))
                .count(),
            usize::from(with_tool)
        );
        request.messages.push(Message {
            role: Role::Assistant,
            content: result.blocks,
        });
        if with_tool {
            request.messages.push(Message {
                role: Role::User,
                content: vec![Block::ToolResult(iteron_protocol::ToolResult {
                    tool_use_id: "call-1".into(),
                    content: "synthetic file".into(),
                    is_error: false,
                    trust: iteron_protocol::Trust::Workspace,
                    latency_ms: 0,
                })],
            });
        } else {
            request.messages.push(Message::user_text("continue"));
        }
        let body = provider.body(&request).unwrap();
        assert_eq!(body["messages"][2]["reasoning_content"], REASONING);
        assert_eq!(body["messages"][2]["content"], "hello");
        if with_tool {
            assert_eq!(body["messages"][2]["tool_calls"][0]["id"], "call-1");
            assert_eq!(
                body["messages"][2]["tool_calls"][0]["function"]["arguments"],
                "{\"path\":\"a.rs\"}"
            );
            assert_eq!(body["messages"][3]["role"], "tool");
            assert_eq!(body["messages"][3]["tool_call_id"], "call-1");
        }
        request.tools = vec![].into();
        assert_eq!(
            provider.body(&request).unwrap()["messages"][2]["reasoning_content"],
            REASONING
        );
        let other = provider.with_route_scope("other-instance".into()).unwrap();
        assert!(
            other.body(&request).unwrap()["messages"][2]
                .get("reasoning_content")
                .is_none()
        );
    }
}

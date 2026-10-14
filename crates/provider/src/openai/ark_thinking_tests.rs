use super::*;
use crate::catalog::{HttpClient, HttpTransport};
use crate::{OpenAiCompat, Provider, ProviderTransportTimeoutPolicy, StreamItem, TurnRequest};
use iteron_protocol::{Role, StopReason, ToolResult, Trust};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "ark.cn-beijing.volces.com";
const SCOPE: &str = "synthetic-ark-instance";
const MODEL: &str = "synthetic-ark-model";
const OPAQUE: &str = "synthetic-opaque+/= \n秘密";
const REASONING: &str = "synthetic summary\n";

struct LoopbackTransport {
    address: SocketAddr,
    certificate: reqwest::Certificate,
}

impl HttpTransport for LoopbackTransport {
    fn client(&self, _: ProviderTransportTimeoutPolicy) -> Result<HttpClient, ProviderError> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .resolve(HOST, self.address)
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.certificate.clone())
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .build()
            .unwrap())
    }
}

// The adapter sees the exact official URL. Only DNS is replaced: every TCP connection stays
// on loopback, with a test-local certificate and normal TLS hostname validation.
async fn server(
    responses: Vec<String>,
    wait_for_disconnect: bool,
) -> (LoopbackTransport, tokio::task::JoinHandle<Vec<Value>>) {
    let certified = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
    let certificate = reqwest::Certificate::from_der(certified.cert.der()).unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(
        certified.key_pair.serialize_der(),
    ));
    let configuration = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(configuration));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let mut requests = Vec::new();
            for body in responses {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(socket).await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0_u8; 4096];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    assert!(bytes.len() <= 65_536);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let length = header.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        }).unwrap();
                        if bytes.len() >= end + 4 + length {
                            assert!(header.starts_with("POST /api/"));
                            requests.push(serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap());
                            break;
                        }
                    }
                }
                let length = body.len() + usize::from(wait_for_disconnect);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n{body}"
                );
                // Malformed/oversized responses may be rejected before the server finishes
                // writing. A closed connection is the expected consequence in those cases.
                let _ = stream.write_all(response.as_bytes()).await;
                if wait_for_disconnect {
                    let mut byte = [0_u8];
                    assert!(!matches!(stream.read(&mut byte).await, Ok(n) if n > 0));
                }
            }
            requests
        }).await.unwrap()
    });
    (
        LoopbackTransport {
            address,
            certificate,
        },
        task,
    )
}

fn make_provider(route: ArkRoute, transport: Option<&dyn HttpTransport>) -> OpenAiCompat {
    let root = ApiRoot::parse(route.root()).unwrap();
    match transport {
        Some(transport) => OpenAiCompat::with_transport("synthetic-key".into(), root, transport),
        None => OpenAiCompat::with_root("synthetic-key".into(), root),
    }
    .unwrap()
    .with_route_scope(SCOPE.into())
    .unwrap()
}

fn request() -> TurnRequest {
    let mut request = crate::guard_tests::request(MODEL);
    request
        .messages
        .push(Message::user_text("synthetic request"));
    request
}

fn frame(delta: Value, finish: Option<&str>) -> String {
    format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
    )
}

fn terminal() -> String {
    frame(json!({"content":"done"}), Some("stop")) + "data: [DONE]\n\n"
}

fn state_message(payload: Value) -> Message {
    Message {
        role: Role::Assistant,
        content: vec![
            Block::ProviderState(ProviderState {
                route_scope: SCOPE.into(),
                format: FORMAT.into(),
                payload,
            }),
            Block::Text {
                text: "answer".into(),
            },
        ],
    }
}

fn payload() -> Value {
    json!({"api_root":ArkRoute::AgentPlan.root(), "model":MODEL,
        "reasoning_content":REASONING, "encrypted_content":OPAQUE})
}

#[tokio::test]
async fn ark_stream_tool_continuation_survives_cold_roundtrip() {
    for route in [
        ArkRoute::Standard,
        ArkRoute::AgentPlan,
        ArkRoute::CodingPlan,
    ] {
        // Includes an independent complete encrypted value, null/empty chunks, an identical
        // repeat (which must not be concatenated), and a split tool argument string.
        let first = frame(json!({"reasoning_content":REASONING}), None)
            + &frame(json!({"encrypted_content":OPAQUE}), None)
            + &frame(json!({"encrypted_content":null}), None)
            + &frame(json!({"encrypted_content":""}), None)
            + &frame(
                json!({"encrypted_content":OPAQUE,"tool_calls":[{"index":0,"id":"call_synthetic","function":{"name":"read_file","arguments":"{\"path\":"}}]}),
                None,
            )
            + &frame(
                json!({"tool_calls":[{"index":0,"id":"","function":{"arguments":"\"fixture.txt\"}"}}]}),
                Some("tool_calls"),
            )
            + "data: [DONE]\n\n";
        let (transport, task) = server(vec![first, terminal()], false).await;
        let mut request = request();
        let mut items = Vec::new();
        let first_provider = make_provider(route, Some(&transport));
        let result = first_provider
            .turn(&request, &mut |item| items.push(item))
            .await
            .unwrap();
        assert_eq!(result.stop_reason, StopReason::ToolUse);
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(item, StreamItem::ToolUseComplete(_)))
                .count(),
            1
        );
        assert_eq!(
            items
                .iter()
                .filter(|item| matches!(item, StreamItem::TurnComplete { .. }))
                .count(),
            1
        );
        assert!(!format!("{items:?}").contains("synthetic-opaque"));
        let message = Message {
            role: Role::Assistant,
            content: result.blocks,
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        drop(first_provider);
        let restored: Message = serde_json::from_slice(&encoded).unwrap();
        request.messages.push(restored);
        request.messages.push(Message {
            role: Role::User,
            content: vec![Block::ToolResult(ToolResult {
                tool_use_id: "call_synthetic".into(),
                content: "synthetic tool result".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 0,
            })],
        });
        let fresh_provider = make_provider(route, Some(&transport));
        fresh_provider.turn(&request, &mut |_| {}).await.unwrap();
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 2);
        let assistant = &requests[1]["messages"][2];
        assert_eq!(assistant["encrypted_content"], OPAQUE);
        assert_eq!(assistant["reasoning_content"], REASONING);
        assert_eq!(assistant["tool_calls"][0]["id"], "call_synthetic");
        assert_eq!(
            assistant["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"fixture.txt\"}"
        );
        assert_eq!(requests[1]["messages"][3]["tool_call_id"], "call_synthetic");
        assert!(requests[1].get("reasoning_effort").is_none());
        assert!(requests[1].get("thinking").is_none());
    }
}

#[tokio::test]
async fn ark_plain_and_encrypted_only_streams_preserve_only_received_fields() {
    for (field, value, absent) in [
        ("reasoning_content", REASONING, "encrypted_content"),
        ("encrypted_content", OPAQUE, "reasoning_content"),
    ] {
        let mut delta = json!({});
        delta[field] = json!(value);
        let (transport, task) = server(vec![frame(delta, None) + &terminal()], false).await;
        let provider = make_provider(ArkRoute::AgentPlan, Some(&transport));
        let mut request = request();
        let result = provider.turn(&request, &mut |_| {}).await.unwrap();
        task.await.unwrap();
        assert_eq!(
            result
                .blocks
                .iter()
                .filter(|b| matches!(b, Block::Thinking { .. }))
                .count(),
            usize::from(field == "reasoning_content")
        );
        request.messages.push(Message {
            role: Role::Assistant,
            content: result.blocks,
        });
        let body = provider.body(&request).unwrap();
        assert_eq!(body["messages"][2][field], value);
        assert!(body["messages"][2].get(absent).is_none());
    }
}

#[tokio::test]
async fn ark_stream_rejects_malformed_and_oversized_state_without_echo() {
    for (field, value, code) in [
        (
            Field::ChatEncryptedContent,
            json!({(OPAQUE): "synthetic-secret"}),
            Code::InvalidType,
        ),
        (
            Field::ChatReasoningContent,
            json!([OPAQUE]),
            Code::InvalidType,
        ),
        (
            Field::ChatEncryptedContent,
            json!("x".repeat(state_limit() + 1)),
            Code::LimitExceeded,
        ),
    ] {
        let name = if field == Field::ChatEncryptedContent {
            "encrypted_content"
        } else {
            "reasoning_content"
        };
        let mut delta = json!({});
        delta[name] = value;
        let body = ": metadata\n\n".to_owned() + &frame(json!({}), None) + &frame(delta, None);
        let (transport, task) = server(vec![body], false).await;
        let provider = make_provider(ArkRoute::AgentPlan, Some(&transport));
        let mut completed = false;
        let error = provider
            .turn(&request(), &mut |item| {
                completed |= matches!(
                    item,
                    StreamItem::TurnComplete { .. } | StreamItem::ToolUseComplete(_)
                );
            })
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(!completed);
        assert_eq!(
            error.public_summary(),
            format!(
                "provider response was invalid [code={}, field={}, frame=2]",
                code.as_str(),
                field.as_str()
            )
        );
        assert_eq!(error.retry_disposition(), crate::RetryDisposition::Never);
        for text in [
            error.public_summary(),
            error.to_string(),
            format!("{error:?}"),
        ] {
            assert!(!text.contains("synthetic-opaque"));
            assert!(!text.contains("synthetic-secret"));
        }
    }
    let body = frame(json!({"encrypted_content":OPAQUE}), None)
        + &frame(
            json!({"encrypted_content":"conflicting-synthetic-secret"}),
            None,
        );
    let (transport, task) = server(vec![body], false).await;
    let provider = make_provider(ArkRoute::AgentPlan, Some(&transport));
    let mut completed = false;
    let error = provider
        .turn(&request(), &mut |item| {
            completed |= matches!(item, StreamItem::TurnComplete { .. });
        })
        .await
        .unwrap_err();
    task.await.unwrap();
    assert!(!completed);
    assert_eq!(
        error.public_summary(),
        "provider response was invalid [code=conflicting_value, field=$.choices[0].delta.encrypted_content, frame=2]"
    );
    assert!(!format!("{error:?}").contains("synthetic-secret"));
}

#[test]
fn ark_state_replay_is_bound_to_instance_endpoint_and_model() {
    let mut request = request();
    request.messages.push(state_message(payload()));
    let provider = make_provider(ArkRoute::AgentPlan, None);
    assert_eq!(
        provider.body(&request).unwrap()["messages"][2]["encrypted_content"],
        OPAQUE
    );
    request.model = "another-model".into();
    let error = provider.body(&request).unwrap_err();
    assert!(matches!(error, ProviderError::Configuration(_)));
    assert!(!error.to_string().contains("synthetic-opaque"));
    request.model = MODEL.into();
    assert!(
        make_provider(ArkRoute::CodingPlan, None)
            .body(&request)
            .is_err()
    );
    let other = provider.with_route_scope("other-instance".into()).unwrap();
    assert!(
        other.body(&request).unwrap()["messages"][2]
            .get("encrypted_content")
            .is_none()
    );
    let Block::ProviderState(state) = &mut request.messages[1].content[0] else {
        panic!()
    };
    state.format = "ark.chat.thinking.v2".into();
    state.payload = json!(["unknown payload must stay opaque"]);
    assert!(
        make_provider(ArkRoute::AgentPlan, None)
            .body(&request)
            .unwrap()["messages"][2]
            .get("encrypted_content")
            .is_none()
    );
    let Block::ProviderState(state) = &mut request.messages[1].content[0] else {
        panic!()
    };
    state.format = super::super::OPENAI_CHAT_REASONING_FORMAT.into();
    state.payload = json!({"reasoning_content":REASONING});
    assert!(matches!(
        make_provider(ArkRoute::AgentPlan, None).body(&request),
        Err(ProviderError::Configuration(_))
    ));
}

#[test]
fn ark_state_payload_limits_and_schema_fail_closed() {
    let provider = make_provider(ArkRoute::AgentPlan, None);
    for bad in [
        Value::Null,
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL}),
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL,"encrypted_content":123}),
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL,"encrypted_content":""}),
        json!({"api_root":"https://example.invalid","model":MODEL,"encrypted_content":OPAQUE}),
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":"","encrypted_content":OPAQUE}),
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL,"encrypted_content":OPAQUE,"arbitrary-secret-key":true}),
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL,"encrypted_content":"x".repeat(state_limit() + 1)}),
        // Raw bytes fit; JSON escaping expands beyond the serialized state budget.
        json!({"api_root":ArkRoute::AgentPlan.root(),"model":MODEL,"encrypted_content":"\n".repeat(state_limit() / 2)}),
    ] {
        let mut request = request();
        request.messages.push(state_message(bad));
        let error = provider.body(&request).unwrap_err();
        assert!(error.decode_diagnostic().is_some());
        assert!(!error.public_summary().contains("arbitrary-secret-key"));
        assert!(!error.to_string().contains("synthetic-opaque"));
    }
    let mut request = request();
    let mut message = state_message(payload());
    message.content.push(message.content[0].clone());
    request.messages.push(message);
    assert_eq!(
        provider
            .body(&request)
            .unwrap_err()
            .decode_diagnostic()
            .unwrap()
            .code,
        Code::ConflictingValue
    );
    let mut state = StreamState::default();
    state.append_reasoning_len(state_limit()).unwrap();
    assert!(
        state
            .observe_encrypted(Some(&json!({"encrypted_content":"x"})))
            .is_err()
    );
    assert!(
        StreamState::default()
            .finish(SCOPE, ArkRoute::AgentPlan, MODEL, "")
            .unwrap()
            .is_none()
    );
}

#[test]
fn ark_routes_do_not_infer_support_or_replay_portable_thinking() {
    for root in [
        "https://ark.cn-beijing.volces.com.evil.invalid/api/plan/v3",
        "https://ark.cn-beijing.volces.com/api/plan/v3/extra",
        "http://ark.cn-beijing.volces.com/api/plan/v3",
        "https://gateway.example.invalid/api/plan/v3",
    ] {
        let root = ApiRoot::parse(root).unwrap();
        assert!(ArkRoute::for_root(Some(&root)).is_none());
        let provider = OpenAiCompat::with_root("synthetic-key".into(), root)
            .unwrap()
            .with_route_scope(SCOPE.into())
            .unwrap();
        let mut request = request();
        request.model = "doubao-seed-evolving".into();
        request.messages.push(state_message(payload()));
        let body = provider.body(&request).unwrap();
        assert!(body["messages"][2].get("encrypted_content").is_none());
        assert!(body["messages"][2].get("reasoning_content").is_none());
    }
    let mut request = request();
    request.messages.push(Message {
        role: Role::Assistant,
        content: vec![
            Block::Thinking {
                thinking: "portable display only".into(),
            },
            Block::Text {
                text: "answer".into(),
            },
        ],
    });
    let body = make_provider(ArkRoute::AgentPlan, None)
        .body(&request)
        .unwrap();
    assert!(body["messages"][2].get("reasoning_content").is_none());
    assert!(body["messages"][2].get("encrypted_content").is_none());
}

#[tokio::test]
async fn ark_cancelled_stream_does_not_publish_or_replay_partial_state() {
    let body = frame(json!({"encrypted_content":OPAQUE}), None)
        + &frame(json!({"reasoning_content":REASONING}), None);
    let (transport, task) = server(vec![body], true).await;
    let provider = make_provider(ArkRoute::AgentPlan, Some(&transport));
    let cancel = AtomicBool::new(false);
    let mut items = Vec::new();
    let error = crate::turn_cancellable(
        &provider,
        &request(),
        &mut |item| {
            if matches!(item, StreamItem::ThinkingDelta(_)) {
                cancel.store(true, Ordering::Relaxed);
            }
            items.push(item);
        },
        Some(&cancel),
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, ProviderError::Interrupted));
    assert!(
        !items
            .iter()
            .any(|item| matches!(item, StreamItem::TurnComplete { .. }))
    );
    assert!(!format!("{items:?}").contains("synthetic-opaque"));
    assert_eq!(task.await.unwrap().len(), 1);
    let body = provider.body(&request()).unwrap();
    assert!(!body.to_string().contains("synthetic-opaque"));
}

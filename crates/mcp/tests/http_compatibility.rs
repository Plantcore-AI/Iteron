use iteron_mcp::{
    McpError, McpRemoteClient, McpServerPolicy, McpToolFilter, McpToolOutcome,
    default_host_ceiling,
    http::{McpHttpEndpoint, McpHttpHeaderPolicy},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const LEGACY_VERSION: &str = "2025-11-25";
const MODERN_VERSION: &str = "2026-07-28";

async fn read_request(socket: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = socket.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header = String::from_utf8_lossy(&request[..head_end]);
        let content_length = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        if request.len() >= head_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8(request).unwrap()
}

fn request_message(request: &str) -> Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap()
}

async fn send_json(socket: &mut TcpStream, status: u16, session: Option<&str>, body: Value) {
    let body = body.to_string();
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Response",
    };
    let session = session.map_or_else(String::new, |value| format!("mcp-session-id: {value}\r\n"));
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n{session}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
}

async fn send_empty(socket: &mut TcpStream, status: u16) {
    let reason = match status {
        202 => "Accepted",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Response",
    };
    socket
        .write_all(
            format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
}

async fn send_sse(socket: &mut TcpStream, body: Value) {
    let body = format!(": keepalive\n\nevent: message\ndata: {body}\n\n");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
}

fn result(id: &Value, value: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "result":value})
}

async fn connect_auto(url: &str) -> Result<McpRemoteClient, McpError> {
    McpRemoteClient::connect_auto(
        McpHttpEndpoint::parse(url)?,
        "blackbox".into(),
        None,
        McpHttpHeaderPolicy::default(),
        Vec::new(),
        None,
    )
    .await
}

#[tokio::test]
async fn modern_discovery_accepts_sse_and_optional_namespaced_identity() {
    for include_identity in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            let mut discovered = json!({
                "resultType":"complete",
                "supportedVersions":[MODERN_VERSION],
                "capabilities":{"tools":{}}
            });
            if include_identity {
                discovered["_meta"] = json!({
                    "io.modelcontextprotocol/serverInfo": {
                        "name":"independent-blackbox",
                        "version":"1"
                    }
                });
            }
            send_sse(&mut socket, result(&message["id"], discovered)).await;
        });
        let client = connect_auto(&format!("http://{address}/mcp"))
            .await
            .unwrap();
        assert_eq!(client.negotiated_protocol_version(), MODERN_VERSION);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_correlated_supported_version_rejection_is_retried_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            recorded.lock().unwrap().push(message.clone());
            if attempt == 0 {
                send_json(
                    &mut socket,
                    400,
                    None,
                    json!({
                        "jsonrpc":"2.0",
                        "id":message["id"],
                        "error":{
                            "code":-32022,
                            "message":"Unsupported protocol version",
                            "data":{
                                "supported":[MODERN_VERSION],
                                "requested":MODERN_VERSION
                            }
                        }
                    }),
                )
                .await;
            } else {
                send_json(
                    &mut socket,
                    200,
                    None,
                    result(
                        &message["id"],
                        json!({
                            "resultType":"complete",
                            "supportedVersions":[MODERN_VERSION],
                            "capabilities":{}
                        }),
                    ),
                )
                .await;
            }
        }
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    assert_eq!(client.negotiated_protocol_version(), MODERN_VERSION);
    server.await.unwrap();
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| {
        request["method"] == "server/discover"
            && request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
                == MODERN_VERSION
    }));
}

#[tokio::test]
async fn an_http_400_json_rpc_result_is_never_accepted_as_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        let message = request_message(&request);
        send_json(
            &mut socket,
            400,
            None,
            result(
                &message["id"],
                json!({
                    "resultType":"complete",
                    "supportedVersions":[MODERN_VERSION],
                    "capabilities":{}
                }),
            ),
        )
        .await;
    });
    assert!(matches!(
        connect_auto(&format!("http://{address}/mcp")).await,
        Err(McpError::HttpStatus { status: 400 })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn an_incomplete_sse_discovery_frame_fails_when_the_connection_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        let message = request_message(&request);
        let body = format!(
            "event: message\ndata: {}",
            result(
                &message["id"],
                json!({
                    "resultType":"complete",
                    "supportedVersions":[MODERN_VERSION],
                    "capabilities":{"tools":{}}
                })
            )
        );
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    assert!(matches!(
        connect_auto(&format!("http://{address}/mcp")).await,
        Err(McpError::TransportClosed)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn plain_404_and_405_are_the_only_http_status_fallback_evidence() {
    for status in [404, 405] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let server = tokio::spawn(async move {
            for index in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let message = request_message(&request);
                recorded
                    .lock()
                    .unwrap()
                    .push(message["method"].as_str().unwrap().to_owned());
                match index {
                    0 => send_empty(&mut socket, status).await,
                    1 => {
                        send_json(
                            &mut socket,
                            200,
                            Some("legacy-session"),
                            result(
                                &message["id"],
                                json!({
                                    "protocolVersion":LEGACY_VERSION,
                                    "capabilities":{"tools":{}},
                                    "serverInfo":{"name":"legacy","version":"1"}
                                }),
                            ),
                        )
                        .await
                    }
                    _ => send_empty(&mut socket, 202).await,
                }
            }
        });
        let client = connect_auto(&format!("http://{address}/mcp"))
            .await
            .unwrap();
        assert_eq!(client.negotiated_protocol_version(), LEGACY_VERSION);
        server.await.unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            ["server/discover", "initialize", "notifications/initialized"]
        );
    }
}

#[tokio::test]
async fn an_ordinary_discovery_400_is_not_retried_or_downgraded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        assert_eq!(request_message(&request)["method"], "server/discover");
        send_empty(&mut socket, 400).await;
    });
    assert!(matches!(
        connect_auto(&format!("http://{address}/mcp")).await,
        Err(McpError::HttpStatus { status: 400 })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn discovery_and_read_only_lists_retry_one_transient_503() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        for index in 0..4 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            recorded
                .lock()
                .unwrap()
                .push(message["method"].as_str().unwrap().to_owned());
            match index {
                0 | 2 => send_empty(&mut socket, 503).await,
                1 => {
                    send_json(
                        &mut socket,
                        200,
                        None,
                        result(
                            &message["id"],
                            json!({
                                "resultType":"complete",
                                "supportedVersions":[MODERN_VERSION],
                                "capabilities":{"tools":{}}
                            }),
                        ),
                    )
                    .await
                }
                _ => {
                    send_json(
                        &mut socket,
                        200,
                        None,
                        result(
                            &message["id"],
                            json!({
                                "resultType":"complete",
                                "tools":[{"name":"echo","inputSchema":{"type":"object"}}]
                            }),
                        ),
                    )
                    .await
                }
            }
        }
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    let tools = client
        .list_tools_governed(
            &McpToolFilter::default(),
            &McpServerPolicy::default(),
            default_host_ceiling(),
        )
        .await
        .unwrap();
    assert_eq!(tools.len(), 1);
    server.await.unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "server/discover",
            "server/discover",
            "tools/list",
            "tools/list"
        ]
    );
}

#[tokio::test]
async fn stateful_initialize_retries_one_transient_503_before_creating_a_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        for index in 0..4 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            recorded
                .lock()
                .unwrap()
                .push(message["method"].as_str().unwrap().to_owned());
            match index {
                0 => send_empty(&mut socket, 404).await,
                1 => send_empty(&mut socket, 503).await,
                2 => {
                    send_json(
                        &mut socket,
                        200,
                        Some("session-after-retry"),
                        result(
                            &message["id"],
                            json!({
                                "protocolVersion":LEGACY_VERSION,
                                "capabilities":{"tools":{}},
                                "serverInfo":{"name":"legacy","version":"1"}
                            }),
                        ),
                    )
                    .await
                }
                _ => send_empty(&mut socket, 202).await,
            }
        }
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    assert_eq!(client.negotiated_protocol_version(), LEGACY_VERSION);
    server.await.unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "server/discover",
            "initialize",
            "initialize",
            "notifications/initialized"
        ]
    );
}

#[tokio::test]
async fn a_transient_tool_failure_is_not_replayed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        for index in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            recorded
                .lock()
                .unwrap()
                .push(message["method"].as_str().unwrap().to_owned());
            if index == 0 {
                send_json(
                    &mut socket,
                    200,
                    None,
                    result(
                        &message["id"],
                        json!({
                            "resultType":"complete",
                            "supportedVersions":[MODERN_VERSION],
                            "capabilities":{"tools":{}}
                        }),
                    ),
                )
                .await;
            } else {
                send_empty(&mut socket, 503).await;
            }
        }
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    assert!(matches!(
        client
            .call_tool_outcome_observed("write", json!({}), || {})
            .await,
        McpToolOutcome::FailedDefinite {
            error: McpError::HttpStatus { status: 503 },
            ..
        }
    ));
    server.await.unwrap();
    assert_eq!(*seen.lock().unwrap(), ["server/discover", "tools/call"]);
}

#[tokio::test]
async fn an_uncorrelated_discovery_error_never_authorizes_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        send_json(
            &mut socket,
            200,
            None,
            json!({
                "jsonrpc":"2.0",
                "id":"unrelated",
                "error":{"code":-32601,"message":"method not found"}
            }),
        )
        .await;
        assert_eq!(request_message(&request)["method"], "server/discover");
    });
    assert!(matches!(
        connect_auto(&format!("http://{address}/mcp")).await,
        Err(McpError::Protocol(_))
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn resources_and_prompts_paginate_and_preserve_server_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for index in 0..8 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            let message = request_message(&request);
            let response = match index {
                0 => result(
                    &message["id"],
                    json!({
                        "resultType":"complete",
                        "supportedVersions":[MODERN_VERSION],
                        "capabilities":{"resources":{},"prompts":{}}
                    }),
                ),
                1 => result(
                    &message["id"],
                    json!({"resources":[{"uri":"test://β","name":"β"}],"nextCursor":"r2"}),
                ),
                2 => {
                    assert_eq!(message["params"]["cursor"], "r2");
                    result(
                        &message["id"],
                        json!({"resources":[{"uri":"test://alpha","name":"alpha"}],"nextCursor":null}),
                    )
                }
                3 => result(
                    &message["id"],
                    json!({"prompts":[{"name":"β","arguments":[]}],"nextCursor":"p2"}),
                ),
                4 => {
                    assert_eq!(message["params"]["cursor"], "p2");
                    result(
                        &message["id"],
                        json!({"prompts":[{"name":"alpha"}],"nextCursor":null}),
                    )
                }
                5 => result(
                    &message["id"],
                    json!({"contents":[
                        {"uri":"test://β","text":"你好","size":9007199254740993_u64},
                        {"uri":"test://β/image","blob":"AA==","mimeType":"image/png"}
                    ]}),
                ),
                6 => result(
                    &message["id"],
                    json!({"messages":[
                        {"role":"user","content":{"type":"text","text":"你好"}},
                        {"role":"assistant","content":{"type":"resource","resource":{"uri":"test://embedded","text":"内容"}}}
                    ]}),
                ),
                _ => json!({
                    "jsonrpc":"2.0",
                    "id":message["id"],
                    "error":{"code":-32042,"message":"resource unavailable"}
                }),
            };
            send_json(&mut socket, 200, None, response).await;
        }
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    let resources = client
        .call_extension("resources/list", json!({}))
        .await
        .unwrap();
    assert_eq!(resources["resources"][0]["name"], "alpha");
    assert_eq!(resources["resources"][1]["name"], "β");
    let prompts = client
        .call_extension("prompts/list", json!({}))
        .await
        .unwrap();
    assert_eq!(prompts["prompts"][0]["name"], "alpha");
    let resource = client
        .call_extension("resources/read", json!({"uri":"test://β"}))
        .await
        .unwrap();
    assert_eq!(resource["contents"][0]["text"], "你好");
    assert_eq!(resource["contents"][0]["size"], 9007199254740993_u64);
    assert_eq!(resource["contents"][1]["blob"], "AA==");
    let prompt = client
        .call_extension("prompts/get", json!({"name":"β","arguments":{}}))
        .await
        .unwrap();
    assert_eq!(prompt["messages"][0]["content"]["text"], "你好");
    assert_eq!(
        prompt["messages"][1]["content"]["resource"]["uri"],
        "test://embedded"
    );
    assert!(matches!(
        client
            .call_extension("resources/read", json!({"uri":"test://missing"}))
            .await,
        Err(McpError::Server { code: -32042, .. })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn undeclared_extension_capabilities_fail_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        let message = request_message(&request);
        send_json(
            &mut socket,
            200,
            None,
            result(
                &message["id"],
                json!({
                    "resultType":"complete",
                    "supportedVersions":[MODERN_VERSION],
                    "capabilities":{"tools":{}}
                }),
            ),
        )
        .await;
    });
    let client = connect_auto(&format!("http://{address}/mcp"))
        .await
        .unwrap();
    for method in [
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
    ] {
        assert!(matches!(
            client.call_extension(method, json!({})).await,
            Err(McpError::Protocol(_))
        ));
    }
    server.await.unwrap();
}

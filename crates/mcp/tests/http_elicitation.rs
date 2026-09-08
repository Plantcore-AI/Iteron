use iteron_mcp::http::{McpHttpEndpoint, McpHttpHeaderPolicy};
use iteron_mcp::{
    McpFuture, McpInputDecision, McpInputRequest, McpMrtrHandler, McpRemoteClient, McpToolOutcome,
    elicitation_handler_from_mrtr,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct RejectInputs;

impl McpMrtrHandler for RejectInputs {
    fn request<'a>(
        &'a self,
        _server_name: &'a str,
        _tool_name: &'a str,
        _request_state: Option<&'a str>,
        _requests: Vec<McpInputRequest>,
    ) -> McpFuture<'a, McpInputDecision> {
        Box::pin(async { Ok(McpInputDecision::Reject) })
    }
}

async fn read_request(socket: &mut TcpStream) -> Value {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        let read = socket.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "request ended before its body");
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
            return serde_json::from_slice(&request[head_end + 4..]).unwrap();
        }
    }
}

fn json_response(body: Value) -> String {
    let body = body.to_string();
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn elicitation_response(id: &Value) -> String {
    let frames = format!(
        concat!(
            "data: {{\"jsonrpc\":\"2.0\",\"id\":\"ask-1\",\"method\":\"elicitation/create\",",
            "\"params\":{{\"mode\":\"form\",\"message\":\"Continue?\",",
            "\"requestedSchema\":{{\"type\":\"object\",\"properties\":{{",
            "\"confirm\":{{\"type\":\"boolean\"}}}},\"required\":[\"confirm\"]}}}}}}\n\n",
            "data: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{",
            "\"content\":[{{\"type\":\"text\",\"text\":\"done\"}}]}}}}\n\n"
        ),
        id = id
    );
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{frames}",
        frames.len()
    )
}

async fn write_response(socket: &mut TcpStream, response: &str) {
    socket.write_all(response.as_bytes()).await.unwrap();
}

fn assert_elicitation_advertised(capabilities: &Value) {
    assert!(capabilities["elicitation"].get("form").is_some());
}

async fn assert_tool_call_completes(client: &McpRemoteClient) {
    assert!(matches!(
        client
            .call_tool_outcome_observed("echo", json!({}), || {})
            .await,
        McpToolOutcome::Completed { ref content, .. } if content == "done\n"
    ));
}

#[tokio::test]
async fn stateless_http_claim_has_a_real_inbound_elicitation_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for index in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let message = read_request(&mut socket).await;
            let response = match index {
                0 => {
                    assert_eq!(message["method"], "server/discover");
                    assert_elicitation_advertised(
                        &message["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                    );
                    json_response(json!({
                        "jsonrpc":"2.0",
                        "id":message["id"],
                        "result":{
                            "resultType":"complete",
                            "supportedVersions":[iteron_mcp::MODERN_PROTOCOL_VERSION],
                            "capabilities":{"tools":{}},
                            "serverInfo":{"name":"fixture","version":"1"}
                        }
                    }))
                }
                1 => {
                    assert_eq!(message["method"], "tools/call");
                    elicitation_response(&message["id"])
                }
                2 => {
                    assert_eq!(message["id"], "ask-1");
                    assert_eq!(message["result"]["action"], "decline");
                    "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_owned()
                }
                _ => unreachable!(),
            };
            write_response(&mut socket, &response).await;
        }
    });
    let client = McpRemoteClient::connect_auto_with_policies_and_elicitation(
        McpHttpEndpoint::parse(&format!("http://{address}/mcp")).unwrap(),
        "fixture".into(),
        None,
        McpHttpHeaderPolicy::default(),
        Vec::new(),
        None,
        Some(elicitation_handler_from_mrtr(Arc::new(RejectInputs))),
        iteron_mcp::McpDeadlinePolicy::default().http(),
        iteron_mcp::McpResultPolicy::default(),
    )
    .await
    .unwrap();

    assert_tool_call_completes(&client).await;
    server.await.unwrap();
}

#[tokio::test]
async fn stateful_http_fallback_claim_has_a_real_inbound_elicitation_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for index in 0..5 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let message = read_request(&mut socket).await;
            let response = match index {
                0 => {
                    assert_eq!(message["method"], "server/discover");
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_owned()
                }
                1 => {
                    assert_eq!(message["method"], "initialize");
                    assert_elicitation_advertised(&message["params"]["capabilities"]);
                    json_response(json!({
                        "jsonrpc":"2.0",
                        "id":message["id"],
                        "result":{
                            "protocolVersion":"2025-11-25",
                            "capabilities":{"tools":{}},
                            "serverInfo":{"name":"fixture","version":"1"}
                        }
                    }))
                }
                2 => {
                    assert_eq!(message["method"], "notifications/initialized");
                    "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_owned()
                }
                3 => {
                    assert_eq!(message["method"], "tools/call");
                    elicitation_response(&message["id"])
                }
                4 => {
                    assert_eq!(message["id"], "ask-1");
                    assert_eq!(message["result"]["action"], "decline");
                    "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_owned()
                }
                _ => unreachable!(),
            };
            write_response(&mut socket, &response).await;
        }
    });
    let client = McpRemoteClient::connect_auto_with_policies_and_elicitation(
        McpHttpEndpoint::parse(&format!("http://{address}/mcp")).unwrap(),
        "fixture".into(),
        None,
        McpHttpHeaderPolicy::default(),
        Vec::new(),
        None,
        Some(elicitation_handler_from_mrtr(Arc::new(RejectInputs))),
        iteron_mcp::McpDeadlinePolicy::default().http(),
        iteron_mcp::McpResultPolicy::default(),
    )
    .await
    .unwrap();

    assert_eq!(client.negotiated_protocol_version(), "2025-11-25");
    assert_tool_call_completes(&client).await;
    server.await.unwrap();
}

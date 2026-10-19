use super::*;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::io::{AsyncBufReadExt, BufReader};

const DESCRIPTION: &str = "Submit a nested batch: \"items\" and Unicode λ.";
const MAX_REQUEST_BYTES: usize = 16 * 1024;

fn nested_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "batch": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "minLength": 1},
                    "items": {
                        "type": "array", "minItems": 1, "maxItems": 2,
                        "items": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "enum": ["alpha", "beta"]},
                                "quantity": {"type": "integer", "minimum": 1}
                            },
                            "required": ["code", "quantity"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["label", "items"],
                "additionalProperties": false
            }
        },
        "required": ["batch"],
        "additionalProperties": false
    })
}

// Build a legal call from the returned schema, without knowing its property names.
fn arguments_from_schema(schema: &Value) -> Value {
    match schema["type"].as_str().unwrap() {
        "object" => Value::Object(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| {
                    let name = name.as_str().unwrap();
                    (
                        name.to_owned(),
                        arguments_from_schema(&schema["properties"][name]),
                    )
                })
                .collect(),
        ),
        "array" => {
            let count = schema["minItems"].as_u64().unwrap() as usize;
            assert!(count <= 2 && count as u64 <= schema["maxItems"].as_u64().unwrap());
            Value::Array(
                (0..count)
                    .map(|_| arguments_from_schema(&schema["items"]))
                    .collect(),
            )
        }
        "string" => schema
            .get("enum")
            .map(|values| values[0].clone())
            .unwrap_or_else(|| json!("fixture")),
        "integer" => schema["minimum"].clone(),
        kind => panic!("unexpected fixture schema type: {kind}"),
    }
}

fn fixture_result(index: usize, request: &Value) -> Value {
    assert_eq!(request["jsonrpc"], "2.0");
    assert!(request["id"].is_number());
    match index {
        0 => {
            assert_eq!(request["method"], "server/discover");
            json!({
                "resultType": "complete",
                "supportedVersions": [iteron_mcp::MODERN_PROTOCOL_VERSION],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nested-schema-fixture", "version": "1"}
            })
        }
        1 => {
            assert_eq!(request["method"], "tools/list");
            json!({"tools": [
                {"name": "nested_batch", "description": DESCRIPTION, "inputSchema": nested_schema()},
                {"name": "undiscovered", "description": "Separate tool", "inputSchema": {"type": "object"}},
                {"name": "hidden", "description": "Denied tool", "inputSchema": {"type": "object"}}
            ]})
        }
        2 | 3 => {
            assert_eq!(request["method"], "tools/call");
            assert_eq!(request["params"]["name"], "nested_batch");
            let validator = jsonschema::options().build(&nested_schema()).unwrap();
            let valid = validator.is_valid(&request["params"]["arguments"]);
            assert_eq!(
                valid,
                index == 2,
                "fixture validates the actual wire arguments"
            );
            json!({
                "isError": !valid,
                "content": [{"type": "text", "text": if valid {
                    "nested arguments accepted"
                } else {
                    "fixture rejected malformed nested arguments"
                }}]
            })
        }
        _ => unreachable!("fixture accepts exactly four requests"),
    }
}

async fn read_bounded_http(socket: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 1024];
        let count = socket.read(&mut chunk).await.unwrap();
        assert_ne!(count, 0, "HTTP request ended before its body");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() <= MAX_REQUEST_BYTES);
        let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        assert!(headers.starts_with("POST /mcp HTTP/1.1\r\n"));
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")?
                    .trim()
                    .parse::<usize>()
                    .ok()
            })
            .expect("bounded JSON content-length");
        assert!(length <= MAX_REQUEST_BYTES - end - 4);
        if bytes.len() >= end + 4 + length {
            assert_eq!(bytes.len(), end + 4 + length);
            return serde_json::from_slice(&bytes[end + 4..]).unwrap();
        }
    }
}

async fn serve_stdio(listener: TcpListener) {
    let (socket, _) = listener.accept().await.unwrap();
    let (read, mut write) = socket.into_split();
    let mut read = BufReader::new(read);
    for index in 0..4 {
        let mut bytes = Vec::new();
        // Take caps allocation even if a broken relay never emits a newline.
        let count = (&mut read)
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await
            .unwrap();
        assert!(count > 0 && count <= MAX_REQUEST_BYTES && bytes.last() == Some(&b'\n'));
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        let result = fixture_result(index, &request);
        let reply = json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
        write.write_all(reply.to_string().as_bytes()).await.unwrap();
        write.write_all(b"\n").await.unwrap();
    }
}

async fn serve_http(listener: TcpListener) {
    for index in 0..4 {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_bounded_http(&mut socket).await;
        let result = fixture_result(index, &request);
        write_http_result(&mut socket, &request, result).await;
    }
}

struct AbortFixture(tokio::task::JoinHandle<()>);

impl Drop for AbortFixture {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn exercise_discovery(managed: &ManagedServer) {
    let discovery: Value =
        serde_json::from_str(&managed.search("nested_batch", 8).await.unwrap()).unwrap();
    assert_eq!(discovery["kind"], "mcp_tool_search");
    assert_eq!(discovery["server"], "alpha");
    assert_eq!(discovery["generation"], 1);
    assert_eq!(managed.health().generation, Some(1));
    assert_eq!(discovery["total_matches"], 1);
    assert_eq!(discovery["truncated"], false);
    assert_eq!(discovery["status"], "complete");
    let tools = discovery["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "alpha__nested_batch");
    assert_eq!(tools[0]["description"], DESCRIPTION);
    assert_eq!(tools[0]["inputSchema"], nested_schema());

    for name in ["alpha__undiscovered", "alpha__unknown", "alpha__hidden"] {
        let outcome = managed
            .call(name, json!({}), None, || {
                panic!("unadmitted call dispatched")
            })
            .await;
        assert!(
            matches!(
                outcome,
                iteron_mcp::McpToolOutcome::FailedDefinite {
                    error: iteron_mcp::McpError::StaleToolIdentity,
                    evidence: None,
                }
            ),
            "{outcome:?}"
        );
    }
    let hidden: Value = serde_json::from_str(&managed.search("hidden", 8).await.unwrap()).unwrap();
    assert_eq!(hidden["tools"], json!([]));
    assert_eq!(hidden["total_matches"], 0);

    let name = tools[0]["name"].as_str().unwrap();
    let mut arguments = arguments_from_schema(&tools[0]["inputSchema"]);
    let accepted = managed.call(name, arguments.clone(), None, || {}).await;
    assert!(
        matches!(accepted, iteron_mcp::McpToolOutcome::Completed {
        is_error: false, ref content, ..
    } if content.contains("nested arguments accepted")),
        "{accepted:?}"
    );

    // Discovery preserves the contract; the remote fixture owns argument validation.
    arguments["batch"]["items"][0]
        .as_object_mut()
        .unwrap()
        .remove("quantity");
    let rejected = managed.call(name, arguments, None, || {}).await;
    assert!(
        matches!(rejected, iteron_mcp::McpToolOutcome::Completed {
        is_error: true, ref content, ..
    } if content.contains("fixture rejected malformed nested arguments")),
        "{rejected:?}"
    );
}

async fn run_schema_case(stdio: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = if stdio {
        serve_stdio(listener).boxed()
    } else {
        serve_http(listener).boxed()
    };
    let mut fixture = AbortFixture(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), fixture)
            .await
            .expect("fixture deadline");
    }));
    let mut config = http_fixture(None);
    config.tools.deny = vec!["hidden".into()];
    let handler = Arc::new(OnceLock::new());
    let managed = if stdio {
        config.transport = McpTransportConfig::Stdio;
        config.url = None;
        config.command = Some("/bin/bash".into());
        config.args = vec![
            "-c".into(),
            concat!(
                "exec 3<>/dev/tcp/127.0.0.1/$1 || exit 1; ",
                "for round in 1 2 3 4; do ",
                "IFS= read -r -t 10 request || exit 2; ",
                "printf '%s\\n' \"$request\" >&3; ",
                "IFS= read -r -t 10 reply <&3 || exit 3; ",
                "printf '%s\\n' \"$reply\"; done; ",
                "IFS= read -r -t 10 unexpected; exit 0"
            )
            .into(),
            "schema-discovery-fixture".into(),
            address.port().to_string(),
        ];
        ManagedServer::Stdio(ManagedStdioServer::new(config, Vec::new(), handler).unwrap())
    } else {
        config.url = Some(format!("http://{address}/mcp"));
        ManagedServer::Http(ManagedHttpServer::new(config, Vec::new(), handler).unwrap())
    };
    let deadlines = iteron_mcp::McpTransportDeadlines::new(2_000, 2_000).unwrap();
    managed.configure(EffectiveMcpSettings {
        deadlines: iteron_mcp::McpDeadlinePolicy::new(deadlines, deadlines),
        result: iteron_mcp::McpResultPolicy::new(
            4096,
            8192,
            iteron_mcp::McpSpillCleanup::SessionEnd,
        )
        .unwrap(),
        ..settings(iteron_mcp::McpSpillCleanup::SessionEnd)
    });
    // Stop the supervised process even when a regression assertion panics.
    let result = AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(15),
        exercise_discovery(&managed),
    ))
    .catch_unwind()
    .await;
    managed.cancel();
    tokio::time::timeout(Duration::from_secs(5), managed.stop())
        .await
        .unwrap()
        .unwrap();
    match result {
        Ok(result) => result.expect("discovery-to-call deadline"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
    tokio::time::timeout(Duration::from_secs(2), &mut fixture.0)
        .await
        .unwrap()
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn stdio_discovery_preserves_schema_for_nested_call() {
    run_schema_case(true).await;
}

#[tokio::test]
async fn http_discovery_preserves_schema_for_nested_call() {
    run_schema_case(false).await;
}

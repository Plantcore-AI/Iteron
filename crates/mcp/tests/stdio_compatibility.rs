#![cfg(unix)]

use iteron_mcp::{McpClient, McpError};
use std::time::Duration;

#[tokio::test]
async fn abnormal_exit_and_non_protocol_stdout_fail_within_the_startup_bound() {
    for script in ["exit 17", "printf 'not-json\\n'; sleep 30"] {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            McpClient::connect("/bin/sh", &["-c".into(), script.into()], "blackbox"),
        )
        .await
        .expect("stdio startup exceeded its outer test bound");
        let error = result
            .err()
            .expect("invalid stdio server unexpectedly connected");
        assert!(
            matches!(
                &error,
                McpError::TransportClosed | McpError::Json(_) | McpError::Io(_)
            ),
            "unexpected failure: {}",
            error.public_summary()
        );
    }
}

#[tokio::test]
async fn a_stderr_flood_cannot_block_a_valid_stdio_server() {
    let script = r#"
import json, sys
sys.stderr.write("x" * (1024 * 1024))
sys.stderr.flush()
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "flood", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": []}
    elif "id" not in message:
        continue
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"#;
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        McpClient::connect("python3", &["-c".into(), script.into()], "blackbox"),
    )
    .await
    .expect("stderr flood blocked the handshake")
    .unwrap();
    assert_eq!(client.negotiated_protocol_version(), "2025-11-25");
    assert!(client.list_tools().await.unwrap().is_empty());
}

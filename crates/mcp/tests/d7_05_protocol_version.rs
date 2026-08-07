#![cfg(unix)]

use core_mcp::{McpClient, McpError};

const CLIENT_VERSION: &str = "2025-11-25";
const NEWER_SERVER_VERSION: &str = "2099-01-01";

#[tokio::test]
async fn newer_server_version_is_refused_with_actionable_public_diagnostic() {
    let args = vec![
        "-c".to_owned(),
        concat!(
            "IFS= read -r initialize; ",
            "case \"$initialize\" in *'\"protocolVersion\":\"2025-11-25\"'*) ;; *) exit 40;; esac; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2099-01-01\"}}'; ",
            "IFS= read -r initialized"
        )
        .to_owned(),
    ];

    let error = match McpClient::connect("/bin/bash", &args, "version-test").await {
        Ok(_) => panic!("a newer, unsupported MCP protocol version unexpectedly connected"),
        Err(error) => error,
    };

    assert!(matches!(
        &error,
        McpError::UnsupportedProtocolVersion {
            client_version,
            server_version,
        } if client_version == CLIENT_VERSION && server_version == NEWER_SERVER_VERSION
    ));
    let diagnostic = error.public_summary();
    assert!(diagnostic.contains(CLIENT_VERSION), "{diagnostic}");
    assert!(diagnostic.contains(NEWER_SERVER_VERSION), "{diagnostic}");
}

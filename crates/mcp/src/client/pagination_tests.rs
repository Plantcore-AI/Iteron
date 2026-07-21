#![cfg(unix)]

use super::*;
use crate::pagination::ToolListLimits;

const FIXTURE_HANDSHAKE: &str = r#"
IFS= read -r initialize
[[ "$initialize" == *'"method":"initialize"'* ]] || exit 30
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}'
IFS= read -r initialized
[[ "$initialized" == *'"method":"notifications/initialized"'* ]] || exit 31
"#;

async fn fixture_client(body: &str) -> McpClient {
    let script = format!("{FIXTURE_HANDSHAKE}\n{body}");
    let args = vec!["-c".to_string(), script];
    McpClient::connect_with_deadlines(
        "/bin/bash",
        &args,
        "fixture",
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("fixture handshake should complete")
}

fn limits(pages: usize, tools: usize, bytes: usize) -> ToolListLimits {
    ToolListLimits {
        pages,
        tools,
        bytes,
    }
}

#[tokio::test]
async fn multiple_pages_are_fully_enumerated_in_server_order() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
[[ "$page_one" == *'"method":"tools/list"'* ]] || exit 40
[[ "$page_one" != *'"cursor"'* ]] || exit 41
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"alpha","description":"first","inputSchema":{"type":"object"}},{"name":"beta"}],"nextCursor":"page-2"}}'
IFS= read -r page_two
[[ "$page_two" == *'"cursor":"page-2"'* ]] || exit 42
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"gamma"}]}}'
"#,
    )
    .await;

    let tools = client.list_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["fixture__alpha", "fixture__beta", "fixture__gamma"]
    );
    client.terminate().await;
}

#[tokio::test]
async fn cursor_ring_is_rejected_before_it_can_repeat_a_request() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":"cursor-a"}}'
IFS= read -r page_two
[[ "$page_two" == *'"cursor":"cursor-a"'* ]] || exit 50
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[],"nextCursor":"cursor-b"}}'
IFS= read -r page_three
[[ "$page_three" == *'"cursor":"cursor-b"'* ]] || exit 51
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"tools":[],"nextCursor":"cursor-a"}}'
"#,
    )
    .await;

    let error = client
        .list_tools_with_limits(limits(8, 8, 4096))
        .await
        .unwrap_err();
    assert!(matches!(error, McpError::ToolListCursorCycle));
    client.terminate().await;
}

#[tokio::test]
async fn page_limit_is_checked_before_an_extra_request() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":"cursor-a"}}'
IFS= read -r page_two
[[ "$page_two" == *'"cursor":"cursor-a"'* ]] || exit 60
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[],"nextCursor":"cursor-b"}}'
"#,
    )
    .await;

    let error = client
        .list_tools_with_limits(limits(2, 8, 4096))
        .await
        .unwrap_err();
    assert!(matches!(error, McpError::ToolListPageLimit { limit: 2 }));
    client.terminate().await;
}

#[tokio::test]
async fn cumulative_tool_limit_rejects_the_page() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"one"},{"name":"two"}]}}'
"#,
    )
    .await;

    let error = client
        .list_tools_with_limits(limits(2, 1, 4096))
        .await
        .unwrap_err();
    assert!(matches!(error, McpError::ToolListToolLimit { limit: 1 }));
    client.terminate().await;
}

#[tokio::test]
async fn cumulative_byte_limit_counts_the_complete_result() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"large","description":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}]}}'
"#,
    )
    .await;

    let error = client
        .list_tools_with_limits(limits(2, 8, 32))
        .await
        .unwrap_err();
    assert!(matches!(error, McpError::ToolListByteLimit { limit: 32 }));
    client.terminate().await;
}

#[tokio::test]
async fn later_page_server_error_is_propagated_unchanged() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"first"}],"nextCursor":"page-2"}}'
IFS= read -r page_two
[[ "$page_two" == *'"cursor":"page-2"'* ]] || exit 70
printf '%s\n' '{"jsonrpc":"2.0","id":3,"error":{"code":-32001,"message":"fixture page failed"}}'
"#,
    )
    .await;

    let error = client.list_tools().await.unwrap_err();
    assert!(matches!(
        error,
        McpError::Server {
            code: -32001,
            ref message
        } if message == "fixture page failed"
    ));
    client.terminate().await;
}

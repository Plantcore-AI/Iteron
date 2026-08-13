#![cfg(unix)]

use super::*;
use crate::{
    MAX_MCP_TOOL_CATALOG_BYTES, MAX_MCP_TOOL_DESCRIPTION_BYTES, MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
    MAX_MCP_TOOL_NAME_BYTES, MAX_MCP_TOOL_SCHEMA_BYTES,
};

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
        Duration::from_secs(10),
    )
    .await
    .expect("fixture handshake should complete")
}

#[tokio::test]
async fn normal_name_description_and_schema_remain_compatible() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"normal","description":"Read café 写","inputSchema":{"type":"object","required":["path"]}}]}}'
"#,
    )
    .await;

    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "fixture__normal");
    assert_eq!(tools[0].description, "Read café 写");
    assert_eq!(
        tools[0].input_schema,
        json!({"type": "object", "required": ["path"]})
    );
    client.terminate().await;
}

#[tokio::test]
async fn fifty_kib_description_is_bounded_before_provider_projection() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf -v description '%*d' 51200 0
printf '%s' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"large-description","description":"'
printf '%s' "$description"
printf '%s\n' '"}]}}'
"#,
    )
    .await;

    let tools = client.list_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    let description = &tools[0].description;
    assert!(
        description.len()
            <= iteron_tunables::param_integer(
                "mcp.lib.max_mcp_tool_description_bytes",
                MAX_MCP_TOOL_DESCRIPTION_BYTES
            )
    );
    assert!(description.ends_with("[truncated]"));
    assert_ne!(description.len(), 50 * 1024);

    // ToolSpec is the exact object handed to every provider adapter. Project it through the
    // OpenAI-compatible wire shape and prove the discarded 50 KiB cannot reappear downstream.
    let provider_projection = json!({
        "type": "function",
        "function": {
            "name": &tools[0].name,
            "description": description,
            "parameters": &tools[0].input_schema
        }
    });
    assert_eq!(
        provider_projection["function"]["description"],
        description.as_str()
    );
    assert!(serde_json::to_vec(&provider_projection).unwrap().len() < 4096);
    client.terminate().await;
}

#[tokio::test]
async fn production_description_budget_rejects_a_many_tool_catalog() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf -v description '%*d' 2048 0
printf '%s' '{"jsonrpc":"2.0","id":2,"result":{"tools":['
for i in {1..33}; do
    [[ "$i" == 1 ]] || printf ','
    printf '{"name":"tool-%s","description":"%s"}' "$i" "$description"
done
printf '%s\n' ']}}'
"#,
    )
    .await;

    let error = client.list_tools().await.unwrap_err();
    assert!(matches!(
        error,
        McpError::ToolDescriptionBudgetExceeded {
            limit: MAX_MCP_TOOL_DESCRIPTIONS_BYTES
        }
    ));
    client.terminate().await;
}

#[tokio::test]
async fn oversized_name_and_schema_are_observable_rejections() {
    let mut name_client = fixture_client(
        r#"
IFS= read -r page_one
printf -v name '%0*d' 300 0
printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"%s"}]}}\n' "$name"
"#,
    )
    .await;
    let name_error = name_client.list_tools().await.unwrap_err();
    assert!(matches!(
        name_error,
        McpError::ToolNameTooLong {
            limit: MAX_MCP_TOOL_NAME_BYTES
        }
    ));
    name_client.terminate().await;

    let mut schema_client = fixture_client(
        r#"
IFS= read -r page_one
printf -v schema_text '%*d' 70000 0
printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"schema","inputSchema":{"description":"%s"}}]}}\n' "$schema_text"
"#,
    )
    .await;
    let schema_error = schema_client.list_tools().await.unwrap_err();
    assert!(matches!(
        schema_error,
        McpError::ToolSchemaTooLarge {
            limit: MAX_MCP_TOOL_SCHEMA_BYTES
        }
    ));
    schema_client.terminate().await;
}

#[tokio::test]
async fn production_catalog_budget_rejects_legal_items_that_are_too_large_together() {
    let mut client = fixture_client(
        r#"
IFS= read -r page_one
printf -v schema_text '%*d' 60000 0
printf '%s' '{"jsonrpc":"2.0","id":2,"result":{"tools":['
for i in {1..9}; do
    [[ "$i" == 1 ]] || printf ','
    printf '{"name":"schema-%s","inputSchema":{"type":"string","description":"%s"}}' "$i" "$schema_text"
done
printf '%s\n' ']}}'
"#,
    )
    .await;

    let error = client.list_tools().await.unwrap_err();
    assert!(matches!(
        error,
        McpError::ToolCatalogTooLarge {
            limit: MAX_MCP_TOOL_CATALOG_BYTES
        }
    ));
    client.terminate().await;
}

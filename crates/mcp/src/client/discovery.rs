use super::McpClient;
use crate::{
    McpError,
    pagination::{ToolListLimits, ToolListPagination},
    policy::{McpServerPolicy, default_host_ceiling},
    tool_catalog::ToolCatalogBuilder,
    tool_filter::McpToolFilter,
};
use core_protocol::{ToolSpec, capability_set::CapabilitySet};
use serde_json::json;

pub(super) async fn list_tools(
    client: &McpClient,
    limits: ToolListLimits,
    filter: McpToolFilter,
) -> Result<Vec<ToolSpec>, McpError> {
    list_tools_governed(
        client,
        limits,
        filter,
        McpServerPolicy::inherit(),
        default_host_ceiling(),
    )
    .await
}

pub(super) async fn list_tools_governed(
    client: &McpClient,
    limits: ToolListLimits,
    filter: McpToolFilter,
    policy: McpServerPolicy,
    host_ceiling: CapabilitySet,
) -> Result<Vec<ToolSpec>, McpError> {
    let mut pagination = ToolListPagination::new(limits);
    let mut catalog = ToolCatalogBuilder::governed(filter, policy, host_ceiling);
    let mut cursor = None;
    loop {
        pagination.begin_page()?;
        let params = cursor
            .take()
            .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
        let result = client.call("tools/list", params).await?;
        let next_cursor = pagination.accept_page(&result)?;
        catalog.accept_page(&client.server_name, &result)?;
        let Some(next_cursor) = next_cursor else {
            return Ok(catalog.finish());
        };
        cursor = Some(next_cursor);
    }
}

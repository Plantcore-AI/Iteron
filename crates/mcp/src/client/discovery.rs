use super::McpClient;
use crate::{
    McpError,
    pagination::{ToolListLimits, ToolListPagination},
    tool_catalog::ToolCatalogBuilder,
    tool_filter::McpToolFilter,
};
use core_protocol::ToolSpec;
use serde_json::json;

pub(super) async fn list_tools(
    client: &McpClient,
    limits: ToolListLimits,
    filter: McpToolFilter,
) -> Result<Vec<ToolSpec>, McpError> {
    let mut pagination = ToolListPagination::new(limits);
    let mut catalog = ToolCatalogBuilder::with_filter(filter);
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

use crate::{MAX_TOOL_LIST_BYTES, MAX_TOOL_LIST_PAGES, MAX_TOOL_LIST_TOOLS, McpError};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;

#[derive(Clone, Copy)]
pub(crate) struct ToolListLimits {
    pub(crate) pages: usize,
    pub(crate) tools: usize,
    pub(crate) bytes: usize,
}

impl Default for ToolListLimits {
    fn default() -> Self {
        Self {
            pages: iteron_tunables::param_integer(
                "mcp.lib.max_tool_list_pages",
                MAX_TOOL_LIST_PAGES,
            ),
            tools: iteron_tunables::param_integer(
                "mcp.lib.max_tool_list_tools",
                MAX_TOOL_LIST_TOOLS,
            ),
            bytes: iteron_tunables::param_integer(
                "mcp.lib.max_tool_list_bytes",
                MAX_TOOL_LIST_BYTES,
            ),
        }
    }
}

pub(crate) struct ToolListPagination {
    limits: ToolListLimits,
    pages: usize,
    tools: usize,
    bytes: usize,
    seen_cursors: BTreeSet<String>,
}

impl ToolListPagination {
    pub(crate) fn new(limits: ToolListLimits) -> Self {
        Self {
            limits,
            pages: 0,
            tools: 0,
            bytes: 0,
            seen_cursors: BTreeSet::new(),
        }
    }

    /// Reserve one page before issuing its request, so the page ceiling never permits an extra
    /// network exchange with a hostile server.
    pub(crate) fn begin_page(&mut self) -> Result<(), McpError> {
        if self.pages >= self.limits.pages {
            return Err(McpError::ToolListPageLimit {
                limit: self.limits.pages,
            });
        }
        self.pages += 1;
        Ok(())
    }

    /// Account for a received page and return its next cursor. The entire result is counted,
    /// including schemas and cursor bytes, before any tools from it are retained by the caller.
    pub(crate) fn accept_page(&mut self, result: &Value) -> Result<Option<String>, McpError> {
        let page_bytes = serialized_len(result)?;
        let bytes = self
            .bytes
            .checked_add(page_bytes)
            .filter(|bytes| *bytes <= self.limits.bytes)
            .ok_or(McpError::ToolListByteLimit {
                limit: self.limits.bytes,
            })?;

        let page_tools = result
            .get("tools")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let tools = self
            .tools
            .checked_add(page_tools)
            .filter(|tools| *tools <= self.limits.tools)
            .ok_or(McpError::ToolListToolLimit {
                limit: self.limits.tools,
            })?;

        let next_cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor)) => Some(cursor.clone()),
            Some(_) => {
                return Err(McpError::Protocol(
                    "tools/list nextCursor must be a string or null".into(),
                ));
            }
        };
        if let Some(cursor) = &next_cursor
            && !self.seen_cursors.insert(cursor.clone())
        {
            return Err(McpError::ToolListCursorCycle);
        }

        self.bytes = bytes;
        self.tools = tools;
        Ok(next_cursor)
    }
}

fn serialized_len(value: &Value) -> Result<usize, McpError> {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.bytes)
}

pub(crate) struct ExtensionPagination {
    key: &'static str,
    pages: usize,
    items: Vec<Value>,
    bytes: usize,
    seen_cursors: BTreeSet<String>,
}

impl ExtensionPagination {
    pub(crate) fn new(method: &str) -> Result<Self, McpError> {
        let key = match method {
            "resources/list" => "resources",
            "prompts/list" => "prompts",
            _ => return Err(McpError::Protocol("unsupported MCP list method".into())),
        };
        Ok(Self {
            key,
            pages: 0,
            items: Vec::new(),
            bytes: 0,
            seen_cursors: BTreeSet::new(),
        })
    }

    pub(crate) fn accept(&mut self, result: &Value) -> Result<Option<Value>, McpError> {
        self.pages = self.pages.saturating_add(1);
        if self.pages > MAX_TOOL_LIST_PAGES {
            return Err(McpError::Protocol(
                "MCP extension page limit exceeded".into(),
            ));
        }
        self.bytes = self.bytes.saturating_add(serialized_len(result)?);
        if self.bytes > MAX_TOOL_LIST_BYTES {
            return Err(McpError::Protocol(
                "MCP extension byte limit exceeded".into(),
            ));
        }
        let page = result
            .get(self.key)
            .and_then(Value::as_array)
            .ok_or_else(|| McpError::Protocol("MCP list result omitted its items".into()))?;
        if self.items.len().saturating_add(page.len()) > MAX_TOOL_LIST_TOOLS {
            return Err(McpError::Protocol(
                "MCP extension item limit exceeded".into(),
            ));
        }
        self.items.extend(page.iter().cloned());
        match result.get("nextCursor") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(cursor)) if !cursor.is_empty() && cursor.len() <= 4096 => {
                if !self.seen_cursors.insert(cursor.clone()) {
                    return Err(McpError::Protocol("MCP extension cursor repeated".into()));
                }
                Ok(Some(serde_json::json!({"cursor": cursor})))
            }
            _ => Err(McpError::Protocol(
                "MCP extension nextCursor is invalid".into(),
            )),
        }
    }

    pub(crate) fn finish(mut self) -> Value {
        self.items.sort_by(|left, right| {
            item_identity(left)
                .unwrap_or_default()
                .cmp(item_identity(right).unwrap_or_default())
        });
        serde_json::json!({(self.key): self.items})
    }
}

fn item_identity(value: &Value) -> Option<&str> {
    value
        .get("name")
        .or_else(|| value.get("uri"))
        .and_then(Value::as_str)
}

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extension_pages_preserve_values_and_reject_a_cursor_cycle() {
        let mut pages = ExtensionPagination::new("resources/list").unwrap();
        assert_eq!(
            pages
                .accept(&json!({
                    "resources":[{"uri":"test://β","name":null,"meta":{}}],
                    "nextCursor":"same"
                }))
                .unwrap(),
            Some(json!({"cursor":"same"}))
        );
        assert!(matches!(
            pages.accept(&json!({"resources":[],"nextCursor":"same"})),
            Err(McpError::Protocol(_))
        ));
    }

    #[test]
    fn resources_and_prompts_use_distinct_result_keys() {
        let mut resources = ExtensionPagination::new("resources/list").unwrap();
        resources
            .accept(&json!({"resources":[{"uri":"test://one"}]}))
            .unwrap();
        assert_eq!(resources.finish()["resources"].as_array().unwrap().len(), 1);

        let mut prompts = ExtensionPagination::new("prompts/list").unwrap();
        prompts
            .accept(&json!({"prompts":[{"name":"one","arguments":[]}]}))
            .unwrap();
        assert_eq!(prompts.finish()["prompts"][0]["arguments"], json!([]));
    }
}

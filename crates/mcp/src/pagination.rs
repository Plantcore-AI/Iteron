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
            pages: MAX_TOOL_LIST_PAGES,
            tools: MAX_TOOL_LIST_TOOLS,
            bytes: MAX_TOOL_LIST_BYTES,
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

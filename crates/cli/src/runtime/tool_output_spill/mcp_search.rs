//! Display-only narrowing for the owned MCP discovery envelope. The discriminator carries no
//! authority: even a forged envelope can only lose content, never gain a budget or permission.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;

const KIND: &str = "mcp_tool_search";
const MARKER: &[u8] = b"\"mcp_tool_search\"";
const CANONICAL_KIND: &str = "{\"kind\":\"mcp_tool_search\"";
const PROBE_BYTES: usize = 512;
const BUDGET_NOTE: &str = "Some tools were omitted to fit the current visible result budget. Every returned inputSchema is complete. Search an exact bare tool name with limit=1 for omitted tools.";
const EMPTY_NOTE: &str = "No complete schema fits the current visible result budget. Search an exact bare tool name with limit=1; if it still does not fit, ask the server owner for a smaller schema or split tool.";
const BUDGET_NOTICE: &str = "[MCP schema unavailable: visible result budget is too small; search an exact bare tool name with limit=1 or ask the server owner for a smaller schema.]";
const SENSITIVE_NOTICE: &str = "[MCP schema unavailable: secret redaction would alter its contract; ask the server owner to remove sensitive values from tool metadata.]";
const INVALID_NOTICE: &str = "[MCP schema unavailable: invalid or oversized discovery envelope; search again with an exact bare tool name and limit=1.]";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchResponse {
    kind: String,
    server: String,
    generation: u64,
    tools: Vec<SearchTool>,
    total_matches: usize,
    truncated: bool,
    status: String,
    note: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchTool {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

/// Run before a managed search inserts any newly discovered call identities. Never rewrite
/// constraints, keys, defaults, or enum values to make them pass the existing secret scrubber.
pub(crate) fn ensure_discovery_safe(content: &str) -> Result<(), iteron_mcp::McpError> {
    if content.len() > search_byte_limit() {
        return Err(iteron_mcp::McpError::CatalogContract {
            reason: "oversized discovery envelope",
        });
    }
    let response: SearchResponse =
        serde_json::from_str(content).map_err(|_| iteron_mcp::McpError::CatalogContract {
            reason: "invalid discovery envelope",
        })?;
    if !response_is_safe(&response, content) {
        return Err(iteron_mcp::McpError::SensitiveToolSchema);
    }
    Ok(())
}

/// None means ordinary tool text; its existing projection/redaction path remains responsible.
/// Recognized results are either exact, whole-tool subsets, or a bounded content-free notice.
pub(crate) fn project(content: &str, maximum_bytes: usize) -> Option<Cow<'_, str>> {
    let prefix = &content.as_bytes()[..content.len().min(PROBE_BYTES)];
    if !content.trim_start().starts_with('{')
        || !prefix.windows(MARKER.len()).any(|part| part == MARKER)
    {
        return None;
    }
    let canonical_kind = content.trim_start().starts_with(CANONICAL_KIND);
    let parse_limit = search_byte_limit();
    if content.len() > parse_limit {
        return canonical_kind.then(|| notice(INVALID_NOTICE, maximum_bytes));
    }
    let value: Value = match serde_json::from_str(content) {
        Ok(value) => value,
        Err(_) => return canonical_kind.then(|| notice(INVALID_NOTICE, maximum_bytes)),
    };
    if value.get("kind").and_then(Value::as_str) != Some(KIND) {
        return None;
    }
    let mut response: SearchResponse = match serde_json::from_value(value) {
        Ok(value) => value,
        Err(_) => return Some(notice(INVALID_NOTICE, maximum_bytes)),
    };
    if response.tools.len()
        > iteron_tunables::param_integer(
            "mcp.supervisor.catalog.max_mcp_search_results",
            iteron_mcp::supervisor::MAX_MCP_SEARCH_RESULTS,
        )
        || response.total_matches < response.tools.len()
        || !matches!(
            response.status.as_str(),
            "complete" | "truncated" | "schema_too_large"
        )
    {
        return Some(notice(INVALID_NOTICE, maximum_bytes));
    }
    // This is deliberately the same byte-level policy as the generic model/record outlet.
    // A historical unsafe response is withheld atomically rather than presented with a changed
    // contract and a misleading complete-schema claim.
    if !response_is_safe(&response, content) {
        return Some(notice(SENSITIVE_NOTICE, maximum_bytes));
    }
    if content.len() <= maximum_bytes {
        return Some(Cow::Borrowed(content));
    }
    while response.tools.pop().is_some() {
        response.truncated = true;
        let (status, note) = if response.tools.is_empty() {
            ("schema_too_large", EMPTY_NOTE)
        } else {
            ("truncated", BUDGET_NOTE)
        };
        response.status = status.into();
        response.note = note.into();
        let encoded = match serde_json::to_string(&response) {
            Ok(encoded) => encoded,
            Err(_) => return Some(notice(INVALID_NOTICE, maximum_bytes)),
        };
        if encoded.len() <= maximum_bytes {
            if !response_is_safe(&response, &encoded) {
                return Some(notice(SENSITIVE_NOTICE, maximum_bytes));
            }
            return Some(Cow::Owned(encoded));
        }
    }
    Some(notice(BUDGET_NOTICE, maximum_bytes))
}

fn search_byte_limit() -> usize {
    iteron_tunables::param_integer(
        "mcp.supervisor.catalog.max_mcp_search_output_bytes",
        iteron_mcp::supervisor::MAX_MCP_SEARCH_OUTPUT_BYTES,
    )
}

fn response_is_safe(response: &SearchResponse, content: &str) -> bool {
    let clean = |text: &str| iteron_record::redact::scrub(text) == text;
    if !clean(content) || !clean(&response.server) || !clean(&response.note) {
        return false;
    }
    // Decoded strings matter too: a PEM value contains escaped newlines on the wire. This
    // applies the existing advertised-schema policy without rewriting any schema semantics.
    for tool in &response.tools {
        if !clean(&tool.name) || !clean(&tool.description) {
            return false;
        }
        let mut pending = vec![&tool.input_schema];
        while let Some(value) = pending.pop() {
            match value {
                Value::String(value) if !clean(value) => return false,
                Value::Array(values) => pending.extend(values),
                Value::Object(values) => {
                    if values.keys().any(|key| !clean(key)) {
                        return false;
                    }
                    pending.extend(values.values());
                }
                _ => {}
            }
        }
    }
    true
}

fn notice(text: &'static str, maximum_bytes: usize) -> Cow<'static, str> {
    // Notices contain only fixed ASCII. A tiny or zero allowance may retain only their prefix;
    // no peer content, schema, identity, or secret can survive that fallback.
    Cow::Owned(text[..text.len().min(maximum_bytes)].to_owned())
}

#[cfg(test)]
mod tests;

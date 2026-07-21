use crate::{
    MAX_MCP_TOOL_CATALOG_BYTES, MAX_MCP_TOOL_DESCRIPTION_BYTES, MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
    MAX_MCP_TOOL_NAME_BYTES, MAX_MCP_TOOL_SCHEMA_BYTES, McpError, suspicious_unicode,
    tool_filter::{McpToolFilter, namespace_tool_name},
};
use core_protocol::{Capability, Purity, ToolSpec};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Write;

const TRUNCATED_MARKER: &str = "\n[truncated]";
const PROTOCOL_HEAD_MARKER: &str = "\n… (truncated)";
const EMPTY_CATALOG_BYTES: usize = 2;
const DEFAULT_INPUT_SCHEMA_BYTES: usize = 17;

#[derive(Clone, Copy)]
pub(crate) struct ToolCatalogLimits {
    name_bytes: usize,
    description_bytes: usize,
    schema_bytes: usize,
    descriptions_bytes: usize,
    catalog_bytes: usize,
}

impl Default for ToolCatalogLimits {
    fn default() -> Self {
        Self {
            name_bytes: MAX_MCP_TOOL_NAME_BYTES,
            description_bytes: MAX_MCP_TOOL_DESCRIPTION_BYTES,
            schema_bytes: MAX_MCP_TOOL_SCHEMA_BYTES,
            descriptions_bytes: MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
            catalog_bytes: MAX_MCP_TOOL_CATALOG_BYTES,
        }
    }
}

pub(crate) struct ToolCatalogBuilder {
    limits: ToolCatalogLimits,
    filter: McpToolFilter,
    specs: Vec<ToolSpec>,
    names: BTreeSet<String>,
    description_bytes: usize,
    catalog_bytes: usize,
}

impl ToolCatalogBuilder {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_filter(McpToolFilter::default())
    }

    pub(crate) fn with_filter(filter: McpToolFilter) -> Self {
        Self::with_limits_and_filter(ToolCatalogLimits::default(), filter)
    }

    #[cfg(test)]
    fn with_limits(limits: ToolCatalogLimits) -> Self {
        Self::with_limits_and_filter(limits, McpToolFilter::default())
    }

    fn with_limits_and_filter(limits: ToolCatalogLimits, filter: McpToolFilter) -> Self {
        Self {
            limits,
            filter,
            specs: Vec::new(),
            names: BTreeSet::new(),
            description_bytes: 0,
            catalog_bytes: EMPTY_CATALOG_BYTES,
        }
    }

    pub(crate) fn accept_page(
        &mut self,
        server_name: &str,
        result: &Value,
    ) -> Result<(), McpError> {
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for tool in tools {
            self.accept_tool(server_name, tool)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Vec<ToolSpec> {
        self.specs
    }

    fn accept_tool(&mut self, server_name: &str, tool: &Value) -> Result<(), McpError> {
        let bare_name =
            tool.get("name")
                .and_then(Value::as_str)
                .ok_or(McpError::InvalidToolName {
                    limit: crate::MAX_MCP_BARE_TOOL_NAME_BYTES,
                })?;
        // Apply the exact operator filter before parsing any excluded description or schema. A
        // filtered tool therefore cannot consume retained catalog budget or reach registration.
        if !self.filter.allows(bare_name) {
            return Ok(());
        }
        let name = namespace_tool_name(server_name, bare_name)?;
        if name.len() > self.limits.name_bytes {
            return Err(McpError::ToolNameTooLong {
                limit: self.limits.name_bytes,
            });
        }
        if self.names.contains(&name) {
            return Err(McpError::ToolNameCollision);
        }

        let source_description = tool
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        // Scan the complete inbound value before truncation. A bidi marker after the retained
        // prefix must still withhold the description instead of disappearing beyond the cut.
        let description = if suspicious_unicode(source_description).is_some() {
            "[description withheld: suspicious Unicode]".to_string()
        } else {
            truncate_description(source_description, self.limits.description_bytes)
        };

        let schema_bytes = match tool.get("inputSchema") {
            Some(schema) => serialized_len(schema)?,
            None => DEFAULT_INPUT_SCHEMA_BYTES,
        };
        if schema_bytes > self.limits.schema_bytes {
            return Err(McpError::ToolSchemaTooLarge {
                limit: self.limits.schema_bytes,
            });
        }
        let input_schema = tool
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({"type":"object"}));

        let description_bytes = self
            .description_bytes
            .checked_add(description.len())
            .filter(|bytes| *bytes <= self.limits.descriptions_bytes)
            .ok_or(McpError::ToolDescriptionBudgetExceeded {
                limit: self.limits.descriptions_bytes,
            })?;

        let spec = ToolSpec {
            name,
            description,
            input_schema,
            purity: Purity::Effecting,
            capability: Capability::IrreversibleExternal,
        };
        let spec_bytes = serialized_len(&spec)?;
        let separator_bytes = usize::from(!self.specs.is_empty());
        let catalog_bytes = self
            .catalog_bytes
            .checked_add(separator_bytes)
            .and_then(|bytes| bytes.checked_add(spec_bytes))
            .filter(|bytes| *bytes <= self.limits.catalog_bytes)
            .ok_or(McpError::ToolCatalogTooLarge {
                limit: self.limits.catalog_bytes,
            })?;

        self.description_bytes = description_bytes;
        self.catalog_bytes = catalog_bytes;
        self.names.insert(spec.name.clone());
        self.specs.push(spec);
        Ok(())
    }
}

fn truncate_description(description: &str, limit: usize) -> String {
    if description.len() <= limit {
        return description.to_string();
    }
    debug_assert!(limit >= TRUNCATED_MARKER.len());
    let prefix_budget = limit.saturating_sub(TRUNCATED_MARKER.len());
    let headed = core_protocol::text::head(description, prefix_budget);
    let prefix = headed.strip_suffix(PROTOCOL_HEAD_MARKER).unwrap_or(&headed);
    let mut truncated = String::with_capacity(prefix.len() + TRUNCATED_MARKER.len());
    truncated.push_str(prefix);
    truncated.push_str(TRUNCATED_MARKER);
    truncated
}

fn serialized_len<T: Serialize>(value: &T) -> Result<usize, McpError> {
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
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(tools: Vec<Value>) -> Value {
        json!({"tools": tools})
    }

    #[test]
    fn normal_tool_fields_are_preserved_exactly() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        });
        let mut catalog = ToolCatalogBuilder::new();
        catalog
            .accept_page(
                "server",
                &page(vec![json!({
                    "name": "read",
                    "description": "Read café 写",
                    "inputSchema": schema.clone()
                })]),
            )
            .unwrap();

        let specs = catalog.finish();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "server__read");
        assert_eq!(specs[0].description, "Read café 写");
        assert_eq!(specs[0].input_schema, schema);
    }

    #[test]
    fn description_truncation_is_utf8_safe_and_explicit() {
        let description = "写".repeat(1_000);
        let mut catalog = ToolCatalogBuilder::new();
        catalog
            .accept_page(
                "server",
                &page(vec![json!({"name": "utf8", "description": description})]),
            )
            .unwrap();

        let specs = catalog.finish();
        let description = &specs[0].description;
        assert!(description.len() <= MAX_MCP_TOOL_DESCRIPTION_BYTES);
        assert!(description.ends_with("[truncated]"));
        assert!(description.is_char_boundary(description.len()));
        assert!(!description.contains('\u{fffd}'));
    }

    #[test]
    fn suspicious_unicode_after_the_retained_prefix_still_withholds_everything() {
        let mut description = "a".repeat(MAX_MCP_TOOL_DESCRIPTION_BYTES + 32);
        description.push('\u{202e}');
        let mut catalog = ToolCatalogBuilder::new();
        catalog
            .accept_page(
                "server",
                &page(vec![json!({"name": "unsafe", "description": description})]),
            )
            .unwrap();

        assert_eq!(
            catalog.finish()[0].description,
            "[description withheld: suspicious Unicode]"
        );
    }

    #[test]
    fn filter_runs_before_untrusted_catalog_material_is_retained() {
        let filter = McpToolFilter {
            allow: vec!["visible".into()],
            deny: Vec::new(),
        };
        filter.validate().unwrap();
        let limits = ToolCatalogLimits {
            descriptions_bytes: 7,
            schema_bytes: 32,
            catalog_bytes: 512,
            ..ToolCatalogLimits::default()
        };
        let mut catalog = ToolCatalogBuilder::with_limits_and_filter(limits, filter);
        catalog
            .accept_page(
                "server",
                &page(vec![
                    json!({
                        "name": "not/a/safe/name",
                        "description": "secret-shaped excluded description".repeat(100),
                        "inputSchema": {"secret": "opaque".repeat(100)}
                    }),
                    json!({"name": "visible", "description": "shown"}),
                ]),
            )
            .unwrap();
        let specs = catalog.finish();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "server__visible");
        assert_eq!(specs[0].description, "shown");
    }

    #[test]
    fn oversized_name_and_schema_are_typed_rejections() {
        let mut catalog = ToolCatalogBuilder::new();
        let name_error = catalog
            .accept_page(
                "server",
                &page(vec![json!({"name": "n".repeat(MAX_MCP_TOOL_NAME_BYTES)})]),
            )
            .unwrap_err();
        assert!(matches!(
            name_error,
            McpError::ToolNameTooLong {
                limit: MAX_MCP_TOOL_NAME_BYTES
            }
        ));

        let mut catalog = ToolCatalogBuilder::new();
        let schema_error = catalog
            .accept_page(
                "server",
                &page(vec![json!({
                    "name": "large-schema",
                    "inputSchema": {"description": "s".repeat(MAX_MCP_TOOL_SCHEMA_BYTES)}
                })]),
            )
            .unwrap_err();
        assert!(matches!(
            schema_error,
            McpError::ToolSchemaTooLarge {
                limit: MAX_MCP_TOOL_SCHEMA_BYTES
            }
        ));
    }

    #[test]
    fn cumulative_description_and_catalog_limits_reject_without_silent_omission() {
        let description_limits = ToolCatalogLimits {
            descriptions_bytes: 7,
            ..ToolCatalogLimits::default()
        };
        let mut catalog = ToolCatalogBuilder::with_limits(description_limits);
        let description_error = catalog
            .accept_page(
                "s",
                &page(vec![
                    json!({"name": "one", "description": "1234"}),
                    json!({"name": "two", "description": "5678"}),
                ]),
            )
            .unwrap_err();
        assert!(matches!(
            description_error,
            McpError::ToolDescriptionBudgetExceeded { limit: 7 }
        ));

        let tool = json!({"name": "small", "description": "normal"});
        let mut probe = ToolCatalogBuilder::new();
        probe.accept_page("s", &page(vec![tool.clone()])).unwrap();
        let catalog_limits = ToolCatalogLimits {
            catalog_bytes: probe.catalog_bytes + 1,
            ..ToolCatalogLimits::default()
        };
        let mut catalog = ToolCatalogBuilder::with_limits(catalog_limits);
        let catalog_error = catalog
            .accept_page(
                "s",
                &page(vec![
                    tool,
                    json!({"name": "small2", "description": "normal"}),
                ]),
            )
            .unwrap_err();
        assert!(matches!(
            catalog_error,
            McpError::ToolCatalogTooLarge { .. }
        ));
    }
}

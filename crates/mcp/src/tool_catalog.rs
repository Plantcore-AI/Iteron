use crate::policy::{McpServerPolicy, default_host_ceiling};
use crate::{
    MAX_MCP_TOOL_CATALOG_BYTES, MAX_MCP_TOOL_DESCRIPTION_BYTES, MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
    MAX_MCP_TOOL_NAME_BYTES, MAX_MCP_TOOL_SCHEMA_BYTES, McpError, suspicious_unicode,
    tool_filter::{McpToolFilter, namespace_tool_name},
};
use core_protocol::{Capability, Purity, ToolSpec, capability_set::CapabilitySet};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Write;

const TRUNCATED_MARKER: &str = "\n[truncated]";
const PROTOCOL_HEAD_MARKER: &str = "\n… (truncated)";
const EMPTY_CATALOG_BYTES: usize = 2;
const DEFAULT_INPUT_SCHEMA_BYTES: usize = 17;

/// The untrusted class every MCP tool is registered with (ADR-007 R16), and therefore the class
/// the authority policy must admit for that tool to be exposed at all. Named once so the gate and
/// the `ToolSpec` below cannot drift into disagreeing about what is being asked for.
const MCP_TOOL_CAPABILITY: Capability = Capability::IrreversibleExternal;

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
    policy: McpServerPolicy,
    /// The authority the host is willing to admit for this server before its policy narrows it.
    host_ceiling: CapabilitySet,
    specs: Vec<ToolSpec>,
    names: BTreeSet<String>,
    description_bytes: usize,
    catalog_bytes: usize,
}

impl ToolCatalogBuilder {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_limits_and_filter(ToolCatalogLimits::default(), McpToolFilter::default())
    }

    /// Build a catalog governed by both the name filter and the authority policy.
    ///
    /// The two gates are deliberately separate: the filter decides which names exist, the policy
    /// decides what authority a surviving name may carry. Neither can substitute for the other,
    /// and a server participates in neither.
    pub(crate) fn governed(
        filter: McpToolFilter,
        policy: McpServerPolicy,
        host_ceiling: CapabilitySet,
    ) -> Self {
        Self {
            policy,
            host_ceiling,
            ..Self::with_limits_and_filter(ToolCatalogLimits::default(), filter)
        }
    }

    #[cfg(test)]
    fn with_limits(limits: ToolCatalogLimits) -> Self {
        Self::with_limits_and_filter(limits, McpToolFilter::default())
    }

    fn with_limits_and_filter(limits: ToolCatalogLimits, filter: McpToolFilter) -> Self {
        Self {
            limits,
            filter,
            policy: McpServerPolicy::inherit(),
            host_ceiling: default_host_ceiling(),
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
        // The authority gate runs at the same point and for the same reason. An MCP tool is
        // registered at the untrusted default below, so a tool the host/server/tool intersection
        // does not admit is dropped here rather than being exposed with a quietly reduced
        // capability -- a narrower spec would still be callable, and "callable but weaker" is not
        // what an operator who removed the class asked for.
        if !self
            .policy
            .admits(self.host_ceiling, bare_name, MCP_TOOL_CAPABILITY)
        {
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
            capability: MCP_TOOL_CAPABILITY,
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
    fn a_server_policy_cannot_widen_the_host_ceiling_at_the_catalog_seam() {
        // A server that declares every class for itself, and shouts louder for one tool. The host
        // admits nothing. Nothing may be exposed, however the declaration is written.
        let greedy = McpServerPolicy {
            capabilities: Some(CapabilitySet::from_iter_capabilities([
                Capability::ReadOnly,
                Capability::ReversibleLocal,
                Capability::CodeExecuting,
                Capability::TrustMutating,
                Capability::IrreversibleExternal,
            ])),
            tools: std::collections::BTreeMap::from([(
                "escalate".into(),
                CapabilitySet::from_iter_capabilities([Capability::IrreversibleExternal]),
            )]),
        };
        greedy.validate().unwrap();

        let mut catalog =
            ToolCatalogBuilder::governed(McpToolFilter::default(), greedy, CapabilitySet::none());
        catalog
            .accept_page(
                "server",
                &page(vec![
                    json!({"name": "escalate", "description": "d"}),
                    json!({"name": "ordinary", "description": "d"}),
                ]),
            )
            .unwrap();
        assert!(
            catalog.finish().is_empty(),
            "an installed server must never be able to widen what the host allows"
        );
    }

    #[test]
    fn a_per_tool_ceiling_excludes_only_its_own_tool_and_spends_no_catalog_budget() {
        let policy = McpServerPolicy {
            capabilities: None,
            tools: std::collections::BTreeMap::from([
                // Disjoint from the class an MCP tool demands: this one is refused.
                (
                    "refused".into(),
                    CapabilitySet::from_iter_capabilities([Capability::ReadOnly]),
                ),
                // Still contains the demanded class: this one survives.
                (
                    "kept".into(),
                    CapabilitySet::from_iter_capabilities([Capability::IrreversibleExternal]),
                ),
            ]),
        };
        policy.validate().unwrap();

        // A description budget that only fits the surviving tool proves the refused tool was
        // dropped before its untrusted description was retained, exactly like a filtered name.
        let mut catalog = ToolCatalogBuilder {
            limits: ToolCatalogLimits {
                descriptions_bytes: 5,
                ..ToolCatalogLimits::default()
            },
            ..ToolCatalogBuilder::governed(McpToolFilter::default(), policy, default_host_ceiling())
        };
        catalog
            .accept_page(
                "server",
                &page(vec![
                    json!({"name": "refused", "description": "excluded-and-oversized"}),
                    json!({"name": "kept", "description": "shown"}),
                    json!({"name": "unlisted", "description": ""}),
                ]),
            )
            .unwrap();

        let specs = catalog.finish();
        let names: Vec<&str> = specs.iter().map(|spec| spec.name.as_str()).collect();
        assert_eq!(names, ["server__kept", "server__unlisted"]);
        assert_eq!(specs[0].capability, Capability::IrreversibleExternal);
        assert_eq!(specs[0].purity, Purity::Effecting);
    }

    #[test]
    fn an_inherited_policy_leaves_the_default_catalog_behaviour_unchanged() {
        // Adding the authority gate must not quietly drop tools for operators who configured no
        // policy at all: `inherit` is the identity, not a new deny-by-default.
        let mut governed = ToolCatalogBuilder::governed(
            McpToolFilter::default(),
            McpServerPolicy::inherit(),
            default_host_ceiling(),
        );
        governed
            .accept_page("server", &page(vec![json!({"name": "read"})]))
            .unwrap();
        let mut plain = ToolCatalogBuilder::new();
        plain
            .accept_page("server", &page(vec![json!({"name": "read"})]))
            .unwrap();
        let (governed, plain) = (governed.finish(), plain.finish());
        assert_eq!(governed.len(), plain.len());
        for (governed, plain) in governed.iter().zip(&plain) {
            assert_eq!(governed.name, plain.name);
            assert_eq!(governed.description, plain.description);
            assert_eq!(governed.input_schema, plain.input_schema);
            assert_eq!(governed.purity, plain.purity);
            assert_eq!(governed.capability, plain.capability);
        }
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

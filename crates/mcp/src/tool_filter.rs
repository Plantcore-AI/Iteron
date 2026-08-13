use crate::{MAX_MCP_TOOL_NAME_BYTES, McpError};
use iteron_protocol::ToolSpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;

/// Maximum number of exact bare tool names across one server's allow and deny lists.
pub const MAX_MCP_TOOL_FILTER_ENTRIES: usize = 256;

/// Maximum bytes in an operator-owned MCP server namespace.
pub const MAX_MCP_SERVER_NAME_BYTES: usize = 64;

/// Maximum bytes in one bare MCP tool name before the server namespace is added.
pub const MAX_MCP_BARE_TOOL_NAME_BYTES: usize = MAX_MCP_TOOL_NAME_BYTES;

/// Hard ceiling for MCP tools exposed across every connected server in one Core process.
pub const MAX_COMBINED_MCP_TOOLS: usize = 128;

/// Hard serialized-byte ceiling for the model-facing catalog across every MCP server.
pub const MAX_COMBINED_MCP_CATALOG_BYTES: usize = 1024 * 1024;

const EMPTY_CATALOG_BYTES: usize = 2;

/// Exact-match filter for one server's bare tool names.
///
/// An empty `allow` list permits every safe name. A non-empty `allow` list permits only its exact
/// entries. `deny` is then applied last and always wins. Wildcards are deliberately unsupported:
/// exact names keep filtering deterministic and prevent surprising privilege expansion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpToolFilter {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl McpToolFilter {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Validate fixed collection and name-shape bounds without reflecting an entry's contents.
    pub fn validate(&self) -> Result<(), McpError> {
        let entries = self
            .allow
            .len()
            .checked_add(self.deny.len())
            .filter(|count| {
                *count
                    <= iteron_tunables::param_integer(
                        "mcp.tool_filter.max_mcp_tool_filter_entries",
                        MAX_MCP_TOOL_FILTER_ENTRIES,
                    )
            })
            .ok_or(McpError::InvalidToolFilter {
                limit: iteron_tunables::param_integer(
                    "mcp.tool_filter.max_mcp_tool_filter_entries",
                    MAX_MCP_TOOL_FILTER_ENTRIES,
                ),
            })?;
        debug_assert!(
            entries
                <= iteron_tunables::param_integer(
                    "mcp.tool_filter.max_mcp_tool_filter_entries",
                    MAX_MCP_TOOL_FILTER_ENTRIES
                )
        );

        let mut seen_allow = BTreeSet::new();
        for name in &self.allow {
            validate_bare_tool_name(name)?;
            if !seen_allow.insert(name.as_str()) {
                return Err(McpError::InvalidToolFilter {
                    limit: iteron_tunables::param_integer(
                        "mcp.tool_filter.max_mcp_tool_filter_entries",
                        MAX_MCP_TOOL_FILTER_ENTRIES,
                    ),
                });
            }
        }
        let mut seen_deny = BTreeSet::new();
        for name in &self.deny {
            validate_bare_tool_name(name)?;
            if !seen_deny.insert(name.as_str()) {
                return Err(McpError::InvalidToolFilter {
                    limit: iteron_tunables::param_integer(
                        "mcp.tool_filter.max_mcp_tool_filter_entries",
                        MAX_MCP_TOOL_FILTER_ENTRIES,
                    ),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn allows(&self, bare_name: &str) -> bool {
        let allowed = self.allow.is_empty() || self.allow.iter().any(|name| name == bare_name);
        allowed && !self.deny.iter().any(|name| name == bare_name)
    }
}

/// Accumulates names only, so the model-facing MCP catalog has one fail-closed global count bound
/// in addition to the per-server byte and pagination bounds.
pub struct CombinedToolCatalog {
    limit: usize,
    byte_limit: usize,
    names: BTreeSet<String>,
    catalog_bytes: usize,
}

impl Default for CombinedToolCatalog {
    fn default() -> Self {
        Self {
            limit: iteron_tunables::param_integer(
                "mcp.tool_filter.max_combined_mcp_tools",
                MAX_COMBINED_MCP_TOOLS,
            ),
            byte_limit: iteron_tunables::param_integer(
                "mcp.tool_filter.max_combined_mcp_catalog_bytes",
                MAX_COMBINED_MCP_CATALOG_BYTES,
            ),
            names: BTreeSet::new(),
            catalog_bytes: iteron_tunables::param_integer(
                "mcp.tool_filter.empty_catalog_bytes",
                EMPTY_CATALOG_BYTES,
            ),
        }
    }
}

impl CombinedToolCatalog {
    /// Build a catalog guard with a tighter ceiling. Production uses [`Default`]; the explicit
    /// constructor makes boundary behavior testable without manufacturing 129 processes/tools.
    pub fn with_limit(limit: usize) -> Result<Self, McpError> {
        Self::with_limits(
            limit,
            iteron_tunables::param_integer(
                "mcp.tool_filter.max_combined_mcp_catalog_bytes",
                MAX_COMBINED_MCP_CATALOG_BYTES,
            ),
        )
    }

    /// Build a guard with tighter count and serialized-byte ceilings.
    pub fn with_limits(limit: usize, byte_limit: usize) -> Result<Self, McpError> {
        if !(1..=iteron_tunables::param_integer(
            "mcp.tool_filter.max_combined_mcp_tools",
            MAX_COMBINED_MCP_TOOLS,
        ))
            .contains(&limit)
        {
            return Err(McpError::InvalidCombinedToolLimit {
                maximum: iteron_tunables::param_integer(
                    "mcp.tool_filter.max_combined_mcp_tools",
                    MAX_COMBINED_MCP_TOOLS,
                ),
            });
        }
        if !(iteron_tunables::param_integer(
            "mcp.tool_filter.empty_catalog_bytes",
            EMPTY_CATALOG_BYTES,
        )
            ..=iteron_tunables::param_integer(
                "mcp.tool_filter.max_combined_mcp_catalog_bytes",
                MAX_COMBINED_MCP_CATALOG_BYTES,
            ))
            .contains(&byte_limit)
        {
            return Err(McpError::InvalidCombinedCatalogByteLimit {
                maximum: iteron_tunables::param_integer(
                    "mcp.tool_filter.max_combined_mcp_catalog_bytes",
                    MAX_COMBINED_MCP_CATALOG_BYTES,
                ),
            });
        }
        Ok(Self {
            limit,
            byte_limit,
            names: BTreeSet::new(),
            catalog_bytes: iteron_tunables::param_integer(
                "mcp.tool_filter.empty_catalog_bytes",
                EMPTY_CATALOG_BYTES,
            ),
        })
    }

    /// Atomically admit one server's already-filtered specs. On any collision or overflow the
    /// guard is unchanged, allowing the caller to fail startup before registering a partial batch.
    pub fn admit(&mut self, specs: &[ToolSpec]) -> Result<(), McpError> {
        let combined = self
            .names
            .len()
            .checked_add(specs.len())
            .filter(|count| *count <= self.limit)
            .ok_or(McpError::CombinedToolLimit { limit: self.limit })?;
        debug_assert!(combined <= self.limit);

        let mut staged = BTreeSet::new();
        let mut catalog_bytes = self.catalog_bytes;
        for spec in specs {
            validate_namespaced_tool_name(&spec.name)?;
            if self.names.contains(&spec.name) || !staged.insert(spec.name.clone()) {
                return Err(McpError::ToolNameCollision);
            }
            let separator_bytes = usize::from(self.names.len() + staged.len() > 1);
            let spec_bytes = serialized_len(spec)?;
            catalog_bytes = catalog_bytes
                .checked_add(separator_bytes)
                .and_then(|bytes| bytes.checked_add(spec_bytes))
                .filter(|bytes| *bytes <= self.byte_limit)
                .ok_or(McpError::CombinedToolCatalogByteLimit {
                    limit: self.byte_limit,
                })?;
        }
        self.names.extend(staged);
        self.catalog_bytes = catalog_bytes;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
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

pub(crate) fn namespace_tool_name(server_name: &str, bare_name: &str) -> Result<String, McpError> {
    validate_server_name(server_name)?;
    let name_bytes = server_name
        .len()
        .checked_add(2)
        .and_then(|bytes| bytes.checked_add(bare_name.len()))
        .filter(|bytes| {
            *bytes
                <= iteron_tunables::param_integer(
                    "mcp.lib.max_mcp_tool_name_bytes",
                    MAX_MCP_TOOL_NAME_BYTES,
                )
        })
        .ok_or(McpError::ToolNameTooLong {
            limit: iteron_tunables::param_integer(
                "mcp.lib.max_mcp_tool_name_bytes",
                MAX_MCP_TOOL_NAME_BYTES,
            ),
        })?;
    validate_bare_tool_name(bare_name)?;
    let mut name = String::with_capacity(name_bytes);
    name.push_str(server_name);
    name.push_str("__");
    name.push_str(bare_name);
    Ok(name)
}

pub fn validate_server_name(name: &str) -> Result<(), McpError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(McpError::InvalidServerName {
            limit: iteron_tunables::param_integer(
                "mcp.tool_filter.max_mcp_server_name_bytes",
                MAX_MCP_SERVER_NAME_BYTES,
            ),
        });
    };
    if name.len()
        > iteron_tunables::param_integer(
            "mcp.tool_filter.max_mcp_server_name_bytes",
            MAX_MCP_SERVER_NAME_BYTES,
        )
        || !first.is_ascii_lowercase()
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(McpError::InvalidServerName {
            limit: iteron_tunables::param_integer(
                "mcp.tool_filter.max_mcp_server_name_bytes",
                MAX_MCP_SERVER_NAME_BYTES,
            ),
        });
    }
    Ok(())
}

pub(crate) fn validate_bare_tool_name(name: &str) -> Result<(), McpError> {
    if name.is_empty()
        || name.len() > MAX_MCP_BARE_TOOL_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(McpError::InvalidToolName {
            limit: MAX_MCP_BARE_TOOL_NAME_BYTES,
        });
    }
    Ok(())
}

fn validate_namespaced_tool_name(name: &str) -> Result<(), McpError> {
    let Some((server_name, bare_name)) = name.split_once("__") else {
        return Err(McpError::InvalidToolName {
            limit: iteron_tunables::param_integer(
                "mcp.lib.max_mcp_tool_name_bytes",
                MAX_MCP_TOOL_NAME_BYTES,
            ),
        });
    };
    validate_server_name(server_name)?;
    validate_bare_tool_name(bare_name)?;
    if name.len()
        > iteron_tunables::param_integer("mcp.lib.max_mcp_tool_name_bytes", MAX_MCP_TOOL_NAME_BYTES)
    {
        return Err(McpError::ToolNameTooLong {
            limit: iteron_tunables::param_integer(
                "mcp.lib.max_mcp_tool_name_bytes",
                MAX_MCP_TOOL_NAME_BYTES,
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Capability, Purity};
    use serde_json::json;

    fn spec(name: &str) -> ToolSpec {
        ToolSpec {
            name: name.into(),
            description: String::new(),
            input_schema: json!({"type":"object"}),
            purity: Purity::Effecting,
            capability: Capability::IrreversibleExternal,
        }
    }

    #[test]
    fn exact_allow_then_deny_semantics_are_deterministic() {
        let unrestricted = McpToolFilter {
            allow: Vec::new(),
            deny: vec!["blocked".into()],
        };
        unrestricted.validate().unwrap();
        assert!(unrestricted.allows("visible"));
        assert!(!unrestricted.allows("blocked"));

        let restricted = McpToolFilter {
            allow: vec!["visible".into(), "blocked".into()],
            deny: vec!["blocked".into()],
        };
        restricted.validate().unwrap();
        assert!(restricted.allows("visible"));
        assert!(!restricted.allows("absent"));
        assert!(!restricted.allows("blocked"), "deny must win");
    }

    #[test]
    fn unsafe_filter_name_fails_without_reflection() {
        let secret_shaped = "secret/path?token=opaque";
        let filter = McpToolFilter {
            allow: vec![secret_shaped.into()],
            deny: Vec::new(),
        };
        let diagnostic = filter.validate().unwrap_err().to_string();
        assert!(!diagnostic.contains(secret_shaped));
    }

    #[test]
    fn same_bare_name_in_distinct_safe_namespaces_does_not_collide() {
        let mut combined = CombinedToolCatalog::default();
        combined.admit(&[spec("alpha__shared")]).unwrap();
        combined.admit(&[spec("beta__shared")]).unwrap();
        assert_eq!(combined.len(), 2);
    }

    #[test]
    fn combined_limit_and_collision_fail_atomically_without_name_reflection() {
        let mut combined = CombinedToolCatalog::with_limit(2).unwrap();
        combined.admit(&[spec("alpha__one")]).unwrap();
        let error = combined
            .admit(&[spec("beta__two"), spec("beta__secret")])
            .unwrap_err();
        assert!(matches!(error, McpError::CombinedToolLimit { limit: 2 }));
        assert_eq!(combined.len(), 1);
        assert!(!error.to_string().contains("secret"));

        let collision = combined.admit(&[spec("alpha__one")]).unwrap_err();
        assert!(matches!(collision, McpError::ToolNameCollision));
        assert_eq!(combined.len(), 1);
        assert!(!collision.to_string().contains("one"));
    }

    #[test]
    fn combined_serialized_byte_limit_is_explicit_and_atomic() {
        let mut combined = CombinedToolCatalog::with_limits(2, EMPTY_CATALOG_BYTES).unwrap();
        let error = combined.admit(&[spec("alpha__one")]).unwrap_err();
        assert!(matches!(
            error,
            McpError::CombinedToolCatalogByteLimit {
                limit: EMPTY_CATALOG_BYTES
            }
        ));
        assert!(combined.is_empty());
    }
}

use crate::{
    MAX_MCP_TOOL_CATALOG_BYTES, MAX_MCP_TOOL_DESCRIPTION_BYTES, MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
    MAX_MCP_TOOL_SCHEMA_BYTES, McpError, suspicious_unicode,
    tool_filter::{CombinedToolCatalog, MAX_COMBINED_MCP_TOOLS},
};
use iteron_protocol::{Capability, Purity, ToolSpec};
use serde_json::Value;
use std::{collections::BTreeMap, io::Write, sync::Arc};

use crate::reconnect::ServerGeneration;

pub const MAX_MCP_SEARCH_QUERY_BYTES: usize = 256;
pub const MAX_MCP_SEARCH_RESULTS: usize = 32;
pub const MAX_MCP_SEARCH_OUTPUT_BYTES: usize = 32 * 1024;
pub const MAX_MCP_SEARCH_DESCRIPTION_BYTES: usize = 512;
const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_SCHEMA_NODES: usize = 4096;
const SUMMARY_MARKER: &str = "\n[truncated]";
/// Per-result overhead charged against the search output ceiling on top of the strings themselves,
/// covering the separators and labels the renderer adds around every entry.
const SEARCH_RESULT_FRAMING_BYTES: usize = 64;

/// Stable permission-binding identity within one owned supervisor lineage. Generation is
/// deliberately absent: an unchanged tool contract keeps its identity across that instance's
/// reconnects, while a fresh supervisor or any launch/filter/protocol/schema/risk change gets a
/// different exact binding and cannot inherit an earlier permission decision. Executable bytes at
/// the configured command path are not attested; this type cannot authorize continuity that
/// requires executable identity.
#[derive(Clone, PartialEq, Eq)]
pub struct McpToolIdentity {
    server_name: String,
    bare_name: String,
    server_binding: Arc<[u8]>,
    contract: Arc<[u8]>,
}

impl std::fmt::Debug for McpToolIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpToolIdentity")
            .field("server_name", &self.server_name)
            .field("bare_name", &self.bare_name)
            .field("contract_bytes", &self.contract.len())
            .finish_non_exhaustive()
    }
}

impl McpToolIdentity {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn bare_name(&self) -> &str {
        &self.bare_name
    }

    pub(super) fn belongs_to(&self, server_name: &str, server_binding: &[u8]) -> bool {
        self.server_name == server_name && &*self.server_binding == server_binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolMatch {
    pub identity: McpToolIdentity,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolSearchResult {
    pub generation: ServerGeneration,
    pub matches: Vec<McpToolMatch>,
    pub total_matches: usize,
    pub truncated: bool,
}

struct CatalogEntry {
    identity: McpToolIdentity,
    spec: ToolSpec,
}

#[derive(Default)]
pub struct ManagedCatalog {
    entries: BTreeMap<String, CatalogEntry>,
}

impl ManagedCatalog {
    pub fn admit(
        server_name: &str,
        server_binding: Arc<[u8]>,
        protocol_version: &str,
        specs: Vec<ToolSpec>,
    ) -> Result<Self, McpError> {
        let prefix = format!("{server_name}__");
        let mut description_bytes = 0usize;
        if specs.len() > MAX_COMBINED_MCP_TOOLS {
            return Err(McpError::CombinedToolLimit {
                limit: MAX_COMBINED_MCP_TOOLS,
            });
        }
        for spec in &specs {
            let Some(_bare_name) = spec.name.strip_prefix(&prefix) else {
                return Err(McpError::CatalogContract {
                    reason: "tool namespace does not match the immutable server binding",
                });
            };
            if spec.description.len() > MAX_MCP_TOOL_DESCRIPTION_BYTES
                || unsafe_text(&spec.description)
            {
                return Err(McpError::CatalogContract {
                    reason: "tool description is unsafe or exceeds its bound",
                });
            }
            description_bytes = description_bytes
                .checked_add(spec.description.len())
                .filter(|bytes| *bytes <= MAX_MCP_TOOL_DESCRIPTIONS_BYTES)
                .ok_or(McpError::ToolDescriptionBudgetExceeded {
                    limit: MAX_MCP_TOOL_DESCRIPTIONS_BYTES,
                })?;
            validate_schema(&spec.input_schema)?;
            if spec.purity != Purity::Effecting
                || spec.capability != Capability::IrreversibleExternal
            {
                return Err(McpError::CatalogContract {
                    reason: "MCP tools must retain effecting external-risk defaults",
                });
            }
        }

        // Structural validation runs before this serializer so even a deterministic adversarial
        // fake cannot hand the supervisor a deeply nested in-memory value and consume its stack.
        let mut combined =
            CombinedToolCatalog::with_limits(MAX_COMBINED_MCP_TOOLS, MAX_MCP_TOOL_CATALOG_BYTES)?;
        combined.admit(&specs)?;

        let mut entries = BTreeMap::new();
        for spec in specs {
            let bare_name = spec
                .name
                .strip_prefix(&prefix)
                .expect("the prevalidation pass checked the immutable namespace");
            let identity = McpToolIdentity {
                server_name: server_name.to_owned(),
                bare_name: bare_name.to_owned(),
                server_binding: server_binding.clone(),
                contract: contract_binding(protocol_version, bare_name, &spec)?,
            };
            if entries
                .insert(spec.name.clone(), CatalogEntry { identity, spec })
                .is_some()
            {
                return Err(McpError::ToolNameCollision);
            }
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn spec(&self, identity: &McpToolIdentity) -> Option<&ToolSpec> {
        self.entry(identity).map(|entry| &entry.spec)
    }

    fn entry(&self, identity: &McpToolIdentity) -> Option<&CatalogEntry> {
        let namespaced = format!("{}__{}", identity.server_name, identity.bare_name);
        self.entries
            .get(&namespaced)
            .filter(|entry| entry.identity == *identity)
    }

    pub fn search(
        &self,
        generation: ServerGeneration,
        query: &str,
        limit: usize,
    ) -> Result<McpToolSearchResult, McpError> {
        validate_search_request(query, limit)?;
        let query = query.to_lowercase();
        let terms: Vec<_> = query.split_whitespace().collect();
        let mut candidates = Vec::with_capacity(self.entries.len());
        for entry in self.entries.values() {
            if let Some(rank) = match_rank(&entry.spec, &entry.identity.bare_name, &query, &terms) {
                candidates.push((rank, entry));
            }
        }
        candidates.sort_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.spec.name.cmp(&right.spec.name))
        });

        let total_matches = candidates.len();
        let mut matches = Vec::with_capacity(limit.min(total_matches));
        let mut output_bytes = 0usize;
        for (_, entry) in candidates {
            if matches.len() >= limit {
                break;
            }
            let description = summary(&entry.spec.description);
            let bytes = entry
                .spec
                .name
                .len()
                .checked_add(description.len())
                .and_then(|bytes| bytes.checked_add(entry.identity.server_name.len()))
                .and_then(|bytes| bytes.checked_add(entry.identity.bare_name.len()))
                .and_then(|bytes| bytes.checked_add(SEARCH_RESULT_FRAMING_BYTES))
                .ok_or(McpError::InvalidToolSearch {
                    field: "output",
                    limit: MAX_MCP_SEARCH_OUTPUT_BYTES,
                })?;
            let next = output_bytes
                .checked_add(bytes)
                .filter(|total| *total <= MAX_MCP_SEARCH_OUTPUT_BYTES);
            let Some(next) = next else {
                break;
            };
            output_bytes = next;
            matches.push(McpToolMatch {
                identity: entry.identity.clone(),
                name: entry.spec.name.clone(),
                description,
            });
        }
        let truncated = matches.len() < total_matches;
        Ok(McpToolSearchResult {
            generation,
            matches,
            total_matches,
            truncated,
        })
    }
}

pub(super) fn validate_search_request(query: &str, limit: usize) -> Result<(), McpError> {
    if query.len() > MAX_MCP_SEARCH_QUERY_BYTES || unsafe_text(query) {
        return Err(McpError::InvalidToolSearch {
            field: "query",
            limit: MAX_MCP_SEARCH_QUERY_BYTES,
        });
    }
    if !(1..=MAX_MCP_SEARCH_RESULTS).contains(&limit) {
        return Err(McpError::InvalidToolSearch {
            field: "limit",
            limit: MAX_MCP_SEARCH_RESULTS,
        });
    }
    Ok(())
}

fn match_rank(spec: &ToolSpec, bare_name: &str, query: &str, terms: &[&str]) -> Option<u8> {
    if query.is_empty() {
        return Some(4);
    }
    let name = bare_name.to_lowercase();
    if name == query {
        return Some(0);
    }
    if name.starts_with(query) {
        return Some(1);
    }
    if name.contains(query) {
        return Some(2);
    }
    let description = spec.description.to_lowercase();
    terms
        .iter()
        .all(|term| name.contains(term) || description.contains(term))
        .then_some(3)
}

fn unsafe_text(text: &str) -> bool {
    suspicious_unicode(text).is_some()
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn summary(description: &str) -> String {
    if description.len() <= MAX_MCP_SEARCH_DESCRIPTION_BYTES {
        return description.to_owned();
    }
    let budget = MAX_MCP_SEARCH_DESCRIPTION_BYTES.saturating_sub(SUMMARY_MARKER.len());
    let mut boundary = budget.min(description.len());
    while !description.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    let mut result = String::with_capacity(boundary + SUMMARY_MARKER.len());
    result.push_str(&description[..boundary]);
    result.push_str(SUMMARY_MARKER);
    result
}

fn validate_schema(value: &Value) -> Result<(), McpError> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if depth > MAX_SCHEMA_DEPTH || nodes > MAX_SCHEMA_NODES {
            return Err(McpError::CatalogContract {
                reason: "tool schema exceeds structural bounds",
            });
        }
        match value {
            Value::String(text) if unsafe_text(text) => {
                return Err(McpError::CatalogContract {
                    reason: "tool schema contains unsafe control text",
                });
            }
            Value::Array(values) => {
                guard_pending_nodes(nodes, stack.len(), values.len())?;
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                guard_pending_nodes(nodes, stack.len(), values.len())?;
                for (key, value) in values {
                    if unsafe_text(key) {
                        return Err(McpError::CatalogContract {
                            reason: "tool schema contains an unsafe key",
                        });
                    }
                    stack.push((value, depth + 1));
                }
            }
            _ => {}
        }
    }
    let mut writer = BoundedCounter::new(MAX_MCP_TOOL_SCHEMA_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        if writer.exceeded {
            McpError::ToolSchemaTooLarge {
                limit: MAX_MCP_TOOL_SCHEMA_BYTES,
            }
        } else {
            McpError::Json(error)
        }
    })?;
    Ok(())
}

fn guard_pending_nodes(nodes: usize, pending: usize, adding: usize) -> Result<(), McpError> {
    if nodes
        .checked_add(pending)
        .and_then(|count| count.checked_add(adding))
        .is_none_or(|count| count > MAX_SCHEMA_NODES)
    {
        return Err(McpError::CatalogContract {
            reason: "tool schema exceeds structural bounds",
        });
    }
    Ok(())
}

fn contract_binding(
    protocol_version: &str,
    bare_name: &str,
    spec: &ToolSpec,
) -> Result<Arc<[u8]>, McpError> {
    let mut binding = b"iteron-mcp-tool-contract-v1\0".to_vec();
    append_field(&mut binding, protocol_version.as_bytes());
    append_field(&mut binding, bare_name.as_bytes());
    append_field(&mut binding, spec.description.as_bytes());
    binding.push(match spec.purity {
        Purity::Pure => 0,
        Purity::Effecting => 1,
    });
    binding.push(match spec.capability {
        Capability::ReadOnly => 0,
        Capability::ReversibleLocal => 1,
        Capability::CodeExecuting => 2,
        Capability::TrustMutating => 3,
        Capability::IrreversibleExternal => 4,
    });
    serde_json::to_writer(&mut binding, &spec.input_schema)?;
    Ok(binding.into())
}

fn append_field(binding: &mut Vec<u8>, field: &[u8]) {
    binding.extend_from_slice(&(field.len() as u64).to_be_bytes());
    binding.extend_from_slice(field);
}

struct BoundedCounter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl BoundedCounter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: 0,
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(total) = self.bytes.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("MCP schema byte count overflow"));
        };
        if total > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("MCP schema byte limit exceeded"));
        }
        self.bytes = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(name: &str, description: &str, schema: Value) -> ToolSpec {
        ToolSpec {
            name: format!("files__{name}"),
            description: description.into(),
            input_schema: schema,
            purity: Purity::Effecting,
            capability: Capability::IrreversibleExternal,
        }
    }

    fn generation() -> ServerGeneration {
        let mut lifecycle =
            crate::reconnect::LifecycleCore::deferred(crate::reconnect::ReconnectPolicy::default());
        lifecycle.begin_connection().unwrap()
    }

    #[test]
    fn only_an_exact_contract_keeps_identity() {
        let one = ManagedCatalog::admit(
            "files",
            Arc::from([7]),
            "2024-11-05",
            vec![spec("read", "first", json!({"type":"object"}))],
        )
        .unwrap();
        let unchanged = ManagedCatalog::admit(
            "files",
            Arc::from([7]),
            "2024-11-05",
            vec![spec("read", "first", json!({"type":"object"}))],
        )
        .unwrap();
        let changed_schema = ManagedCatalog::admit(
            "files",
            Arc::from([7]),
            "2024-11-05",
            vec![spec(
                "read",
                "first",
                json!({"type":"object","required":["path"]}),
            )],
        )
        .unwrap();
        let changed_description = ManagedCatalog::admit(
            "files",
            Arc::from([7]),
            "2024-11-05",
            vec![spec("read", "new wording", json!({"type":"object"}))],
        )
        .unwrap();
        let identity = &one.entries["files__read"].identity;
        assert!(unchanged.spec(identity).is_some());
        assert!(changed_schema.spec(identity).is_none());
        assert!(changed_description.spec(identity).is_none());
    }

    #[test]
    fn different_launch_binding_or_protocol_cannot_inherit_identity() {
        let original = ManagedCatalog::admit(
            "files",
            Arc::from([1]),
            "2024-11-05",
            vec![spec("read", "", json!({}))],
        )
        .unwrap();
        let other_binding = ManagedCatalog::admit(
            "files",
            Arc::from([2]),
            "2024-11-05",
            vec![spec("read", "", json!({}))],
        )
        .unwrap();
        let other_protocol = ManagedCatalog::admit(
            "files",
            Arc::from([1]),
            "2099-01-01",
            vec![spec("read", "", json!({}))],
        )
        .unwrap();
        let identity = &original.entries["files__read"].identity;
        assert!(other_binding.spec(identity).is_none());
        assert!(other_protocol.spec(identity).is_none());
    }

    #[test]
    fn adversarial_catalog_is_rejected_again_at_supervisor_boundary() {
        let unsafe_description = vec![spec("read", "escape\u{1b}[31m", json!({}))];
        assert!(
            ManagedCatalog::admit("files", Arc::from([0]), "2024-11-05", unsafe_description)
                .is_err()
        );
        assert!(
            ManagedCatalog::admit(
                "files",
                Arc::from([0]),
                "2024-11-05",
                vec![spec("read", "safe prefix\rrewritten", json!({}))]
            )
            .is_err()
        );
        let wrong_risk = ToolSpec {
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
            ..spec("read", "", json!({}))
        };
        assert!(
            ManagedCatalog::admit("files", Arc::from([0]), "2024-11-05", vec![wrong_risk]).is_err()
        );
        assert!(
            ManagedCatalog::admit(
                "files",
                Arc::from([0]),
                "2024-11-05",
                vec![spec("read", "", json!({"description":"\u{202e}"}))]
            )
            .is_err()
        );

        let mut deep = json!({});
        for _ in 0..=MAX_SCHEMA_DEPTH {
            deep = json!({"nested": deep});
        }
        assert!(
            ManagedCatalog::admit(
                "files",
                Arc::from([0]),
                "2024-11-05",
                vec![spec("deep", "", deep)]
            )
            .is_err()
        );
    }

    #[test]
    fn search_is_ranked_deterministic_and_bounded() {
        let catalog = ManagedCatalog::admit(
            "files",
            Arc::from([0]),
            "2024-11-05",
            vec![
                spec("grep", "search file text", json!({})),
                spec("read", "read a file", json!({})),
                spec("reader", "other", json!({})),
            ],
        )
        .unwrap();
        let result = catalog
            .search(generation(), "read", MAX_MCP_SEARCH_RESULTS)
            .unwrap();
        let names: Vec<_> = result
            .matches
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        assert_eq!(names, ["files__read", "files__reader"]);
        assert_eq!(result.total_matches, 2);
        assert!(!result.truncated);
        assert!(catalog.search(generation(), "x\u{1b}", 3).is_err());
    }
}

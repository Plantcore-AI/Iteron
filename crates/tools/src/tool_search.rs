//! Bounded lazy discovery for the registered tool catalog.
//!
//! The complete registry remains executable, but a large schema catalog need not be serialized
//! into every provider request. `tool_search` returns only authority-admitted schemas and marks
//! them visible for the next turn. The shared state is session-local and contains public tool
//! metadata only; arguments and results never enter it.

use crate::{Registry, ToolError, boxfut, err_result, ok_result};
use iteron_protocol::{Capability, Purity, ToolSpec};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

pub(crate) const TOOL_SEARCH: &str = "tool_search";
/// Number of task-ranked schemas shown eagerly when the complete admitted catalog is larger.
/// Every remaining schema stays reachable through [`TOOL_SEARCH`].
pub const DEFAULT_DEFERRED_TOOL_EAGER_LIMIT: usize = 4;
/// Schemas returned by one `tool_search` call when the model names no `limit`, kept well under
/// [`MAX_SEARCH_RESULTS`] so an unscoped search cannot flood the next request.
const DEFAULT_SEARCH_RESULTS: usize = 8;
const MAX_QUERY_BYTES: usize = 256;
const MAX_SEARCH_RESULTS: usize = 32;
/// The stable ordinary coding surface. Specialised schemas remain one `tool_search` away, while
/// these authority-admitted primitives never disappear between tasks and invalidate prompt-cache
/// identity merely because task-ranking changed.
const CORE_EAGER_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "edit",
    "bash",
    "grep",
    "glob",
    "list_dir",
];

#[derive(Clone, Default)]
pub(crate) struct DeferredToolCatalog {
    inner: Arc<Mutex<CatalogState>>,
}

#[derive(Default)]
struct CatalogState {
    specs: BTreeMap<String, ToolSpec>,
    admitted: BTreeSet<String>,
    exposed: BTreeSet<String>,
}

impl DeferredToolCatalog {
    fn new(specs: impl IntoIterator<Item = ToolSpec>) -> Self {
        let this = Self::default();
        for spec in specs {
            this.insert(spec);
        }
        this
    }

    pub(crate) fn insert(&self, spec: ToolSpec) {
        if let Ok(mut state) = self.inner.lock() {
            state.specs.insert(spec.name.clone(), spec);
        }
    }

    pub(crate) fn retain(&self, names: &BTreeSet<String>) {
        if let Ok(mut state) = self.inner.lock() {
            state.specs.retain(|name, _| names.contains(name));
            state.admitted.retain(|name| names.contains(name));
            state.exposed.retain(|name| names.contains(name));
        }
    }

    /// Set the exact authority-admitted search domain and choose the eager task-relevant prefix.
    pub(crate) fn visible(
        &self,
        admitted: &BTreeSet<String>,
        task: &str,
        eager_limit: usize,
    ) -> BTreeSet<String> {
        let Ok(mut state) = self.inner.lock() else {
            return admitted.clone();
        };
        state.admitted = admitted.clone();
        state.exposed.retain(|name| admitted.contains(name));

        let mut visible = state.exposed.clone();
        if admitted.contains(iteron_tunables::param_str(
            "tools.tool_search.tool_search",
            TOOL_SEARCH,
        )) {
            visible.insert(
                iteron_tunables::param_str("tools.tool_search.tool_search", TOOL_SEARCH).to_owned(),
            );
        }
        for name in CORE_EAGER_TOOLS {
            if admitted.contains(*name) {
                state.exposed.insert((*name).to_owned());
                visible.insert((*name).to_owned());
            }
        }
        let ranked = ranked_names(&state, admitted, task);
        for name in ranked.into_iter().take(eager_limit) {
            // Prompt-cache identity may grow after a discovery but must never shrink merely
            // because the next task text ranked a different prefix.
            state.exposed.insert(name.clone());
            visible.insert(name);
        }
        visible
    }

    fn search(&self, query: &str, limit: usize) -> Result<String, &'static str> {
        if query.len()
            > iteron_tunables::param_integer("tools.tool_search.max_query_bytes", MAX_QUERY_BYTES)
        {
            return Err("tool_search query exceeds 256 bytes");
        }
        let limit = limit.clamp(
            1,
            iteron_tunables::param_usize(
                "tools.tool_search.max_search_results",
                iteron_tunables::param_integer(
                    "tools.tool_search.max_search_results",
                    MAX_SEARCH_RESULTS,
                ),
            ),
        );
        let mut state = self.inner.lock().map_err(|_| "tool catalog unavailable")?;
        if state.admitted.is_empty() {
            return Err("tool catalog has not been admitted for this turn");
        }
        let names = ranked_names(&state, &state.admitted, query)
            .into_iter()
            .filter(|name| {
                name != iteron_tunables::param_str("tools.tool_search.tool_search", TOOL_SEARCH)
            })
            .take(limit)
            .collect::<Vec<_>>();
        for name in &names {
            state.exposed.insert(name.clone());
        }
        let tools = names
            .iter()
            .filter_map(|name| state.specs.get(name))
            .map(|spec| {
                serde_json::json!({
                    "name": spec.name,
                    "description": spec.description,
                    "input_schema": spec.input_schema,
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&serde_json::json!({
            "tools": tools,
            "note": "These admitted schemas are visible on the next model turn.",
        }))
        .map_err(|_| "tool catalog serialization failed")
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<DeferredToolCatalog, ToolError> {
    let catalog = DeferredToolCatalog::new(registry.specs());
    let executor_catalog = catalog.clone();
    registry.push_tool(
        ToolSpec {
            name: iteron_tunables::param_str("tools.tool_search.tool_search", TOOL_SEARCH).into(),
            description: "Search the authority-admitted tool catalog by task or capability. The returned bounded schemas become callable on the next turn; use this when the currently visible tools do not cover the task.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"}
                },
                "required": ["query"]
            }),
            // It changes only session-local catalog visibility, so it is read-only but not
            // memoizable: every execution must apply its exposure transition.
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        move |call, _root| {
            let catalog = executor_catalog.clone();
            boxfut::box_it(async move {
                let query = call
                    .input
                    .get("query")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .trim();
                let limit = call
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or_else(|| {
                        iteron_tunables::param_usize(
                            "tools.tool_search.default_search_results",
                            iteron_tunables::param_integer("tools.tool_search.default_search_results", DEFAULT_SEARCH_RESULTS),
                        )
                    });
                match catalog.search(query, limit) {
                    Ok(content) => ok_result(call.id, content),
                    Err(reason) => err_result(call.id, reason.into()),
                }
            })
        },
    )?;
    catalog.insert(
        registry
            .specs()
            .into_iter()
            .find(|spec| {
                spec.name
                    == iteron_tunables::param_str("tools.tool_search.tool_search", TOOL_SEARCH)
            })
            .expect("tool_search was just registered"),
    );
    Ok(catalog)
}

fn ranked_names(state: &CatalogState, admitted: &BTreeSet<String>, query: &str) -> Vec<String> {
    let terms = terms(query);
    let mut ranked = admitted
        .iter()
        .filter_map(|name| state.specs.get(name))
        .map(|spec| {
            let name = spec.name.to_ascii_lowercase();
            let description = spec.description.to_ascii_lowercase();
            let score = terms.iter().fold(0u32, |score, term| {
                score
                    .saturating_add(u32::from(name == *term) * 16)
                    .saturating_add(u32::from(name.contains(term)) * 8)
                    .saturating_add(u32::from(description.contains(term)) * 2)
            });
            (std::cmp::Reverse(score), spec.name.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort();
    ranked.into_iter().map(|(_, name)| name).collect()
}

fn terms(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .take(32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::ToolUse;

    #[tokio::test]
    async fn hidden_admitted_schema_becomes_visible_after_search() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let initial = registry.specs_for_task(&admitted, "inspect rust source", Some(1));
        assert!(initial.iter().any(|spec| spec.name == TOOL_SEARCH));
        let hidden = admitted
            .iter()
            .find(|name| {
                name.as_str() != TOOL_SEARCH
                    && !CORE_EAGER_TOOLS.contains(&name.as_str())
                    && !initial.iter().any(|spec| spec.name == **name)
            })
            .cloned()
            .expect("coding registry has a deferred schema");

        let result = registry
            .run(ToolUse {
                id: "search-1".into(),
                name: TOOL_SEARCH.into(),
                input: serde_json::json!({"query": hidden, "limit": 4}),
            })
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains(&format!("\"{hidden}\"")));

        let next = registry.specs_for_task(&admitted, "inspect rust source", Some(1));
        assert!(next.iter().any(|spec| spec.name == hidden));
    }

    #[tokio::test]
    async fn search_cannot_reveal_a_schema_outside_the_admitted_set() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = [TOOL_SEARCH.to_owned(), "read_file".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let _ = registry.specs_for_task(&admitted, "", Some(1));
        let result = registry
            .run(ToolUse {
                id: "search-2".into(),
                name: TOOL_SEARCH.into(),
                input: serde_json::json!({"query": "bash shell", "limit": 32}),
            })
            .await;
        assert!(!result.content.contains("\"bash\""));
        assert!(result.content.contains("read_file"));
    }

    #[test]
    fn narrowing_away_search_keeps_every_remaining_tool_eagerly_reachable() {
        let mut registry = Registry::read_only(std::env::temp_dir()).unwrap();
        registry.narrow_to(&["read_file".into(), "grep".into()]);
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let visible = registry.specs_for_task(&admitted, "unrelated", Some(1));
        assert_eq!(visible.len(), 2);
    }

    #[test]
    fn authority_admitted_core_is_visible_for_empty_and_specific_tasks() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();

        for task in ["", "inspect the context compactor"] {
            let visible = registry.specs_for_task(&admitted, task, Some(1));
            for core in CORE_EAGER_TOOLS {
                assert!(
                    visible.iter().any(|spec| spec.name == *core),
                    "{core} missing for task {task:?}"
                );
            }
        }

        let admitted = [TOOL_SEARCH.to_owned(), "read_file".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let visible = registry.specs_for_task(&admitted, "", Some(1));
        assert!(visible.iter().any(|spec| spec.name == "read_file"));
        assert!(!visible.iter().any(|spec| spec.name == "bash"));
    }
}

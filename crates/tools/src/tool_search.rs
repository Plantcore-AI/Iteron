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
const DEFAULT_SEARCH_RESULTS: usize = 4;
const MAX_QUERY_BYTES: usize = 256;
const MAX_SEARCH_RESULTS: usize = 32;
/// The stable ordinary coding surface. Specialised schemas remain one `tool_search` away, while
/// these authority-admitted primitives never disappear between tasks and invalidate prompt-cache
/// identity merely because task-ranking changed.
const CORE_EAGER_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "edit",
    "apply_patch",
    "bash",
    // `bash` may yield a live session. Its continuation/cancellation surface must already be
    // callable on the very next turn; requiring a tool-search round here invites duplicate test
    // launches and stranded child processes.
    "process_poll",
    "process_stop",
    "grep",
    "glob",
    "list_dir",
    // The base prompt requires a final diff review. Hiding that exact tool behind discovery made
    // the prompt manufacture an avoidable provider round on ordinary coding tasks.
    "git_diff",
    "git_status",
];

/// Resolve the stable coding surface through the same immutable profile table as every other
/// performance-sensitive tool policy. The compiled slice remains the safe/default candidate, but
/// it is not a protocol or authority invariant: offline evaluation may search a smaller or
/// task-specific surface without teaching the runtime about any provider.
fn core_eager_tools() -> &'static [&'static str] {
    iteron_tunables::param_str_list("tools.tool_search.core_eager_tools", CORE_EAGER_TOOLS)
}

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
        for name in core_eager_tools() {
            if admitted.contains(*name) {
                state.exposed.insert((*name).to_owned());
                visible.insert((*name).to_owned());
            }
        }
        let ranked = ranked_names(&state, admitted, task);
        for name in ranked.into_iter().take(eager_limit) {
            // Keep already-visible/core matches inside the bounded ranking prefix. Inserting them
            // is idempotent, and—critically—does not let a repeated task reveal the next page or
            // let a compiled fallback widen an installed exposure profile.
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
                    && !state.exposed.contains(name)
            })
            .take(limit)
            .collect::<Vec<_>>();
        for name in &names {
            state.exposed.insert(name.clone());
        }
        // The provider cannot call a newly exposed schema in the response that requested this
        // search. On the next turn the exact ToolSpec is advertised in the normal `tools` field,
        // so copying the full description and JSON schema into this ToolResult only duplicates it
        // in that request. Names are enough to make the transition observable and keep discovery
        // output proportional to the result count rather than schema size.
        serde_json::to_string(&serde_json::json!({
            "exposed_tools": names,
            "note": "Exact schemas are visible on the next model turn; already-visible tools are omitted.",
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
    if terms.is_empty() {
        return Vec::new();
    }
    let candidates = admitted
        .iter()
        .filter_map(|name| state.specs.get(name))
        .map(|spec| {
            let name = spec.name.to_lowercase();
            let name_terms = searchable_terms(&name);
            let description_terms = searchable_terms(&spec.description);
            (spec, name, name_terms, description_terms)
        })
        .collect::<Vec<_>>();
    let candidate_count = candidates.len();
    let document_frequency = terms
        .iter()
        .map(|term| {
            candidates
                .iter()
                .filter(|(_, _, name_terms, description_terms)| {
                    contains_term(name_terms, term) || contains_term(description_terms, term)
                })
                .count()
        })
        .collect::<Vec<_>>();
    // Task text can be much wider than an explicit `tool_search` query. Preserve the bounded
    // tokenizer above and allocate an exact-name probe only when it fits the same public query
    // ceiling; exact matching a paragraph is not useful anyway.
    let normalized_query =
        (query.trim().len() <= MAX_QUERY_BYTES).then(|| query.trim().to_lowercase());
    let mut ranked = candidates
        .into_iter()
        .filter_map(|(spec, name, name_terms, description_terms)| {
            let exact_name = normalized_query.as_deref() == Some(name.as_str());
            let score = terms.iter().zip(&document_frequency).fold(
                u32::from(exact_name).saturating_mul(128),
                |score, (term, frequency)| {
                    // A term present in most catalog entries (for example "the", "use", or
                    // "tool") cannot distinguish one schema from another. Derive that decision
                    // from the admitted catalog instead of maintaining a language/provider table.
                    if *frequency == 0
                        || frequency.saturating_mul(2) > candidate_count
                        || term.chars().count() < 2
                    {
                        return score;
                    }
                    let specificity = u32::try_from(candidate_count / frequency)
                        .unwrap_or(u32::MAX)
                        .clamp(1, 16);
                    score
                        .saturating_add(
                            u32::from(contains_term(&name_terms, term))
                                .saturating_mul(16)
                                .saturating_mul(specificity),
                        )
                        .saturating_add(
                            u32::from(contains_term(&description_terms, term))
                                .saturating_mul(2)
                                .saturating_mul(specificity),
                        )
                },
            );
            (score > 0).then(|| (std::cmp::Reverse(score), spec.name.clone()))
        })
        .collect::<Vec<_>>();
    ranked.sort();
    ranked.into_iter().map(|(_, name)| name).collect()
}

fn terms(value: &str) -> Vec<String> {
    let mut terms = value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty() && term.len() <= MAX_QUERY_BYTES)
        .map(str::to_lowercase)
        .take(32)
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    terms
}

fn searchable_terms(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty() && term.len() <= MAX_QUERY_BYTES)
        .map(str::to_lowercase)
        .take(256)
        .collect()
}

fn contains_term(terms: &[String], needle: &str) -> bool {
    terms.iter().any(|term| term == needle)
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
                    && !core_eager_tools().contains(&name.as_str())
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
        let payload: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(payload["exposed_tools"], serde_json::json!([]));
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
            for core in core_eager_tools() {
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

    #[test]
    fn eager_coding_surface_contains_continuations_and_stays_bounded() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let visible = registry.specs_for_task(&admitted, "repair a failing test", Some(1));
        for required in [
            "apply_patch",
            "bash",
            "process_poll",
            "process_stop",
            "git_diff",
            "git_status",
        ] {
            assert!(
                visible.iter().any(|spec| spec.name == required),
                "{required}"
            );
        }
        let schema_bytes = visible.iter().fold(0usize, |total, spec| {
            total
                .saturating_add(spec.name.len())
                .saturating_add(spec.description.len())
                .saturating_add(spec.input_schema.to_string().len())
        });
        assert!(schema_bytes <= 48 * 1024, "{schema_bytes}");
    }

    #[test]
    fn zero_relevance_never_fabricates_task_specific_schemas_or_tokens() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let visible = registry.specs_for_task_snapshot(&admitted, "zzzxxyy qqqvvv", Some(4));
        let visible_names = visible
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();
        let expected = core_eager_tools()
            .iter()
            .copied()
            .chain(std::iter::once(TOOL_SEARCH))
            .filter(|name| admitted.contains(*name))
            .collect::<BTreeSet<_>>();
        assert_eq!(visible_names, expected);

        let oversized_unbroken_term = "x".repeat(MAX_QUERY_BYTES.saturating_mul(4));
        let oversized = registry.specs_for_task(&admitted, &oversized_unbroken_term, Some(4));
        assert_eq!(
            oversized
                .iter()
                .map(|spec| spec.name.as_str())
                .collect::<BTreeSet<_>>(),
            expected
        );

        let all = registry.specs_for_task_snapshot(&admitted, "", None);
        assert!(
            visible.estimated_tokens().saturating_mul(100)
                <= all.estimated_tokens().saturating_mul(55),
            "zero-relevance tasks should avoid at least 45% of schema tokens: visible={} all={}",
            visible.estimated_tokens(),
            all.estimated_tokens()
        );
    }

    #[test]
    fn task_eager_limit_selects_relevant_non_core_tools_and_stays_stable() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let first =
            registry.specs_for_task(&admitted, "search the web and fetch an HTTP page", Some(1));
        let first_names = first
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();
        let selected_web_tools = ["web_fetch", "web_search"]
            .into_iter()
            .filter(|name| first_names.contains(name))
            .collect::<Vec<_>>();
        assert_eq!(selected_web_tools.len(), 1, "{first_names:?}");

        let second =
            registry.specs_for_task(&admitted, "search the web and fetch an HTTP page", Some(1));
        let second_names = second
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(second_names, first_names);
    }

    #[test]
    fn natural_task_terms_reach_each_specialized_tool_domain_without_provider_rules() {
        for (task, expected) in [
            ("show the recent commit log", "git_log"),
            ("read a remembered fact from memory", "read_memory"),
            (
                "query a definition, references, or hover from the language server",
                "lsp_query",
            ),
            (
                "map repository declarations without reading bodies",
                "repo_map",
            ),
            ("search the web for current facts", "web_search"),
        ] {
            let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
            let admitted = registry
                .specs()
                .into_iter()
                .map(|spec| spec.name)
                .collect::<BTreeSet<_>>();
            let visible = registry.specs_for_task(&admitted, task, Some(2));
            assert!(
                visible.iter().any(|spec| spec.name == expected),
                "task {task:?} did not expose {expected}: {:?}",
                visible
                    .iter()
                    .map(|spec| spec.name.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn discovery_returns_only_new_names_without_duplicating_schemas() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let initial = registry.specs_for_task(&admitted, "inspect and repair", Some(1));
        let initially_visible = initial
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();

        let first = registry
            .run(ToolUse {
                id: "compact-search-1".into(),
                name: TOOL_SEARCH.into(),
                input: serde_json::json!({
                    "query":"web memory commit language server workflow",
                    "limit":32
                }),
            })
            .await;
        let payload: serde_json::Value = serde_json::from_str(&first.content).unwrap();
        let exposed = payload["exposed_tools"].as_array().unwrap();
        assert!(!exposed.is_empty());
        assert!(
            exposed
                .iter()
                .all(|name| !initially_visible.contains(name.as_str().unwrap())),
            "an already-visible schema must not be returned again"
        );
        assert!(payload.get("tools").is_none());
        assert!(!first.content.contains("input_schema"));
        assert!(first.content.len() < 1_024, "{}", first.content.len());

        let second = registry
            .run(ToolUse {
                id: "compact-search-2".into(),
                name: TOOL_SEARCH.into(),
                input: serde_json::json!({
                    "query":"web memory commit language server workflow",
                    "limit":32
                }),
            })
            .await;
        let second: serde_json::Value = serde_json::from_str(&second.content).unwrap();
        let second = second["exposed_tools"].as_array().unwrap();
        assert!(exposed.iter().all(|first| !second.contains(first)));
    }
}

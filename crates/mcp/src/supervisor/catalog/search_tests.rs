use super::*;
use crate::reconnect::{LifecycleCore, LifecycleFailure, ReconnectPolicy};
use serde_json::json;

fn tool(name: &str, description: &str, input_schema: Value) -> ToolSpec {
    ToolSpec {
        name: format!("files__{name}"),
        description: description.into(),
        input_schema,
        purity: Purity::Effecting,
        capability: Capability::IrreversibleExternal,
    }
}

fn catalog(tools: Vec<ToolSpec>) -> ManagedCatalog {
    ManagedCatalog::admit("files", Arc::from([7]), "2025-06-18", tools).unwrap()
}

fn generation() -> ServerGeneration {
    LifecycleCore::deferred(ReconnectPolicy::default())
        .begin_connection()
        .unwrap()
}

fn schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "mode": {"enum": ["read", "inspect"]},
            "selection": {"$ref": "#/$defs/selection"}
        },
        "required": ["path"],
        "additionalProperties": false,
        "$defs": {"selection": {"oneOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[a-z]+$"}
        ]}},
        "x-server-contract": {"revision": 3, "preserve": [true, null, 1.25]}
    })
}

fn wire(result: &McpToolSearchResult) -> Value {
    let encoded = result.to_json().unwrap();
    assert!(
        encoded.len() + result.matches.len() * SEARCH_RESULT_FRAMING_BYTES
            <= MAX_MCP_SEARCH_OUTPUT_BYTES
    );
    serde_json::from_str(&encoded).unwrap()
}

#[test]
fn discovery_returns_the_exact_admitted_schema_without_serializing_identity() {
    let input_schema = schema();
    let catalog = catalog(vec![tool("read", "Read a file", input_schema.clone())]);
    let generation = generation();
    let result = catalog.search(generation, "read", 1).unwrap();

    assert_eq!(result.server_name, "files");
    assert_eq!(result.generation, generation);
    assert_eq!(result.matches[0].input_schema, input_schema);
    assert_eq!(result.matches[0].identity.server_name(), "files");
    assert_eq!(result.matches[0].identity.bare_name(), "read");
    assert_eq!(
        catalog
            .spec(&result.matches[0].identity)
            .unwrap()
            .input_schema,
        input_schema
    );
    let output = wire(&result);
    assert_eq!(output["server"], "files");
    assert_eq!(output["generation"], generation.get());
    assert_eq!(output["status"], "complete");
    assert_eq!(output["total_matches"], 1);
    assert_eq!(output["truncated"], false);
    assert_eq!(
        output["tools"],
        json!([{"name": "files__read", "description": "Read a file", "inputSchema": input_schema}])
    );
}

#[test]
fn reconnect_generation_and_changed_contract_keep_schema_and_identity_aligned() {
    let mut lifecycle = LifecycleCore::deferred(ReconnectPolicy::default());
    let first_generation = lifecycle.begin_connection().unwrap();
    let original_schema = schema();
    let original = catalog(vec![tool("read", "Read a file", original_schema.clone())]);
    let first = original.search(first_generation, "read", 1).unwrap();
    lifecycle
        .failed(first_generation, LifecycleFailure::Transport)
        .unwrap();
    let next_generation = lifecycle.begin_connection().unwrap();
    let unchanged = original.search(next_generation, "read", 1).unwrap();
    assert_ne!(first.generation, unchanged.generation);
    assert_eq!(first.matches[0].identity, unchanged.matches[0].identity);
    assert_eq!(unchanged.matches[0].input_schema, original_schema);
    assert_eq!(wire(&unchanged)["generation"], next_generation.get());

    let mut changed_schema = original_schema.clone();
    changed_schema["required"] = json!(["path", "mode"]);
    let changed = catalog(vec![tool("read", "Read a file", changed_schema.clone())]);
    let refreshed = changed.search(next_generation, "read", 1).unwrap();
    assert_ne!(first.matches[0].identity, refreshed.matches[0].identity);
    assert!(changed.spec(&first.matches[0].identity).is_none());
    assert_eq!(
        changed
            .spec(&refreshed.matches[0].identity)
            .unwrap()
            .input_schema,
        changed_schema
    );
    assert_eq!(wire(&refreshed)["tools"][0]["inputSchema"], changed_schema);
    assert_eq!(wire(&first)["tools"][0]["inputSchema"], original_schema);
}

#[test]
fn escaped_json_envelope_and_framing_reserve_share_the_exact_output_ceiling() {
    let generation = generation();
    let description = "Read 雪 with \"quotes\", \\paths, newline\n and tab\t";
    let mut input_schema = json!({
        "type": "object",
        "properties": {"雪\"\\": {"const": "雪\"\\\n\t".repeat(1000)}},
        "x-padding": ""
    });
    let baseline = catalog(vec![tool("read", description, input_schema.clone())])
        .search(generation, "read", 1)
        .unwrap();
    let base_json = baseline.to_json().unwrap();
    assert!(base_json.contains("雪"));
    assert!(base_json.contains(r#"\""#));
    assert!(base_json.contains(r#"\\"#));
    assert!(base_json.contains(r#"\n"#));
    assert!(base_json.contains(r#"\t"#));
    let padding = MAX_MCP_SEARCH_OUTPUT_BYTES - SEARCH_RESULT_FRAMING_BYTES - base_json.len();
    input_schema["x-padding"] = json!("x".repeat(padding));
    let exact = catalog(vec![tool("read", description, input_schema.clone())])
        .search(generation, "read", 1)
        .unwrap();
    assert_eq!(exact.matches.len(), 1);
    assert_eq!(
        exact.to_json().unwrap().len() + SEARCH_RESULT_FRAMING_BYTES,
        MAX_MCP_SEARCH_OUTPUT_BYTES
    );
    assert_eq!(wire(&exact)["tools"][0]["inputSchema"], input_schema);
    assert!(
        exact
            .fits_output_budget(MAX_MCP_SEARCH_OUTPUT_BYTES)
            .unwrap()
    );
    assert!(
        !exact
            .fits_output_budget(MAX_MCP_SEARCH_OUTPUT_BYTES - 1)
            .unwrap()
    );

    // The schema and even the isolated match fit; the complete response plus its reserve does not.
    input_schema["x-padding"] = json!("x".repeat(padding + 1));
    assert!(serde_json::to_vec(&input_schema).unwrap().len() < MAX_MCP_SEARCH_OUTPUT_BYTES);
    let mut over = exact.clone();
    over.matches[0].input_schema = input_schema.clone();
    assert!(
        serde_json::to_vec(&over.matches[0]).unwrap().len() + SEARCH_RESULT_FRAMING_BYTES
            < MAX_MCP_SEARCH_OUTPUT_BYTES
    );
    let omitted = catalog(vec![tool("read", description, input_schema)])
        .search(generation, "read", 1)
        .unwrap();
    assert!(omitted.matches.is_empty());
    assert_eq!(wire(&omitted)["status"], "schema_too_large");
    assert!(matches!(
        over.to_json(),
        Err(McpError::InvalidToolSearch {
            field: "output",
            ..
        })
    ));
}

#[test]
fn result_limit_keeps_complete_schemas_and_reports_omitted_matches() {
    let input_schema = schema();
    let catalog = catalog(
        ["alpha", "beta", "gamma"]
            .into_iter()
            .map(|name| tool(name, "shared discovery", input_schema.clone()))
            .collect(),
    );
    let result = catalog.search(generation(), "shared", 2).unwrap();
    assert_eq!(result.total_matches, 3);
    assert!(result.truncated);
    assert_eq!(
        result
            .matches
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["files__alpha", "files__beta"]
    );
    assert!(
        result
            .matches
            .iter()
            .all(|tool| tool.input_schema == input_schema)
    );
    let output = wire(&result);
    assert_eq!(output["status"], "truncated");
    assert!(
        output["note"]
            .as_str()
            .unwrap()
            .contains("exact bare tool name with limit=1")
    );
}

#[test]
fn byte_overflow_omits_whole_matches_and_exact_queries_retrieve_each_schema() {
    let input_schema = json!({"type": "object", "description": "x".repeat(12_000)});
    let catalog = catalog(
        ["alpha", "beta", "gamma"]
            .into_iter()
            .map(|name| tool(name, "shared discovery", input_schema.clone()))
            .collect(),
    );
    let generation = generation();
    let result = catalog.search(generation, "shared", 3).unwrap();
    assert_eq!(result.total_matches, 3);
    assert_eq!(result.matches.len(), 2);
    assert!(result.truncated);
    let output = wire(&result);
    assert_eq!(output["status"], "truncated");
    assert_eq!(output["tools"].as_array().unwrap().len(), 2);
    for (index, name) in ["alpha", "beta", "gamma"].into_iter().enumerate() {
        let single = catalog.search(generation, name, 1).unwrap();
        assert_eq!(single.matches.len(), 1);
        assert_eq!(single.matches[0].name, format!("files__{name}"));
        assert_eq!(wire(&single)["status"], "complete");
        assert_eq!(wire(&single)["tools"][0]["inputSchema"], input_schema);
        if index < result.matches.len() {
            assert_eq!(output["tools"][index]["inputSchema"], input_schema);
            assert_eq!(result.matches[index].identity, single.matches[0].identity);
        }
    }
}

#[test]
fn admitted_schema_larger_than_search_budget_is_explicitly_unavailable() {
    let input_schema = json!({
        "type": "object",
        "description": "x".repeat(MAX_MCP_SEARCH_OUTPUT_BYTES + 1024)
    });
    let schema_bytes = serde_json::to_vec(&input_schema).unwrap().len();
    assert!(schema_bytes > MAX_MCP_SEARCH_OUTPUT_BYTES);
    assert!(schema_bytes < MAX_MCP_TOOL_SCHEMA_BYTES);
    let catalog = catalog(vec![tool("large", "Large contract", input_schema.clone())]);
    let result = catalog.search(generation(), "large", 1).unwrap();
    assert_eq!(result.total_matches, 1);
    assert!(result.truncated);
    assert!(result.matches.is_empty());
    let output = wire(&result);
    assert_eq!(output["tools"], json!([]));
    assert_eq!(output["status"], "schema_too_large");
    let note = output["note"].as_str().unwrap();
    assert!(note.contains("server owner"));
    assert!(note.contains("smaller schema") || note.contains("split the tool"));
    let identity = catalog.exact_identity("files__large").unwrap();
    assert_eq!(catalog.spec(&identity).unwrap().input_schema, input_schema);
}

#[test]
fn empty_catalog_and_unmatched_query_preserve_server_and_complete_status() {
    let generation = generation();
    let empty = catalog(Vec::new()).search(generation, "", 1).unwrap();
    let populated = catalog(vec![tool("read", "Read a file", schema())]);
    let unmatched = populated.search(generation, "unrelated", 1).unwrap();
    for result in [empty, unmatched] {
        assert_eq!(result.server_name, "files");
        assert_eq!(result.generation, generation);
        assert_eq!(result.total_matches, 0);
        assert!(!result.truncated);
        let output = wire(&result);
        assert_eq!(output["server"], "files");
        assert_eq!(output["tools"], json!([]));
        assert_eq!(output["status"], "complete");
    }
    assert_eq!(
        populated.search(generation, "", 1).unwrap().matches.len(),
        1
    );
    assert_eq!(
        populated
            .search(generation, " \t\n", 1)
            .unwrap()
            .matches
            .len(),
        1
    );
}

#[test]
fn unsafe_queries_and_invalid_limits_leave_the_catalog_unchanged() {
    let catalog = catalog(vec![tool("read", "Read a file", schema())]);
    let generation = generation();
    let original = catalog.search(generation, "read", 1).unwrap();
    for query in [
        "read\0".to_owned(),
        "read\u{1b}".to_owned(),
        "read\r".to_owned(),
        "read\u{202e}".to_owned(),
        "x".repeat(MAX_MCP_SEARCH_QUERY_BYTES + 1),
        "雪".repeat(MAX_MCP_SEARCH_QUERY_BYTES / "雪".len() + 1),
    ] {
        assert!(matches!(
            catalog.search(generation, &query, 1),
            Err(McpError::InvalidToolSearch { field: "query", .. })
        ));
    }
    for limit in [0, MAX_MCP_SEARCH_RESULTS + 1] {
        assert!(matches!(
            catalog.search(generation, "read", limit),
            Err(McpError::InvalidToolSearch { field: "limit", .. })
        ));
    }
    assert!(
        catalog
            .search(generation, &"x".repeat(MAX_MCP_SEARCH_QUERY_BYTES), 1)
            .is_ok()
    );
    assert_eq!(catalog.search(generation, "read", 1).unwrap(), original);
}

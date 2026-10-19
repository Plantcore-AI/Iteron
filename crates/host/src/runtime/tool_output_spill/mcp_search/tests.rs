use super::*;
use crate::runtime::context_runtime::{ContextBudgetInspection, TurnResultProjectionBudget};
use crate::runtime::tool_output_spill::{
    ManagedToolResult, ToolOutputSpillCleanup, ToolOutputSpillPolicy, ToolOutputSpillStore,
};
use crate::runtime::{model_context_projection, tool_response::ToolResponseOwner};
use iteron_mcp::reconnect::{LifecycleCore, ReconnectPolicy};
use iteron_mcp::supervisor::ManagedCatalog;
use iteron_protocol::{
    Block, Capability, Message, Purity, Role, ToolResult, ToolSpec, ToolUse, Trust,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const SECRET: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";

fn discovery(padding: usize) -> String {
    let tools = (0..3)
        .map(|index| ToolSpec {
            name: format!("files__inspect_{index}"),
            description: "Inspect a fixture".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string", "enum": ["界\\\"", "local"]}},
                "required": ["path"],
                "additionalProperties": false,
                "x-fixture": "benign fixture ".repeat(padding),
            }),
            purity: Purity::Effecting,
            capability: Capability::IrreversibleExternal,
        })
        .collect();
    let catalog = ManagedCatalog::admit("files", Arc::from([7]), "2025-06-18", tools).unwrap();
    let generation = LifecycleCore::deferred(ReconnectPolicy::default())
        .begin_connection()
        .unwrap();
    catalog
        .search(generation, "inspect", 3)
        .unwrap()
        .to_json()
        .unwrap()
}

fn result(content: &str) -> ToolResult {
    ToolResult {
        tool_use_id: "discovery-call".into(),
        content: content.into(),
        is_error: false,
        trust: Trust::Untrusted,
        latency_ms: 7,
    }
}

fn through_response_owner(value: ToolResult) -> Message {
    let call = ToolUse {
        id: value.tool_use_id.clone(),
        name: "files__search".into(),
        input: json!({"query":"inspect"}),
    };
    let mut owner = ToolResponseOwner::new(&[call]);
    owner.accept(0, value).unwrap();
    owner.into_parts().unwrap().message.into_message()
}

fn content(message: &Message) -> &str {
    let Block::ToolResult(result) = &message.content[0] else {
        panic!("tool result expected")
    };
    assert_eq!(result.tool_use_id, "discovery-call");
    assert_eq!(result.trust, Trust::Untrusted);
    &result.content
}

fn whole_subset(raw: &str, projected: &str) -> usize {
    let original: Value = serde_json::from_str(raw).unwrap();
    let projected: Value = serde_json::from_str(projected).unwrap();
    assert_eq!(projected["kind"], KIND);
    assert_eq!(projected["total_matches"], 3);
    assert_eq!(projected["truncated"], true);
    let tools = projected["tools"].as_array().unwrap();
    for tool in tools {
        assert!(
            original["tools"].as_array().unwrap().contains(tool),
            "every schema and metadata field must remain exact"
        );
    }
    tools.len()
}

#[test]
fn real_context_allowance_preserves_whole_schemas_through_both_model_outlets() {
    let raw = discovery(450);
    let policy = iteron_ctx::ContextBudgetPolicy::default();
    let inspection = ContextBudgetInspection::from_policy(Default::default(), policy.clone());
    let budget =
        TurnResultProjectionBudget::from_component_allowances(&policy, inspection, 1, 0, 64 * 1024)
            .visible_bytes_for("files__search");
    assert!(raw.len() > budget);
    let mut managed = ManagedToolResult::unspilled(result(&raw));
    assert!(managed.project_visible(budget));
    assert!(managed.result.content.len() <= budget);
    let remaining = whole_subset(&raw, &managed.result.content);
    assert!(remaining > 0 && remaining < 3);
    let expected = managed.result.content.clone();
    let mut messages = [through_response_owner(managed.result)];
    assert!(!model_context_projection::messages(&mut messages).unwrap());
    assert_eq!(content(&messages[0]), expected);
}

#[test]
fn sensitive_discovery_is_refused_and_historical_results_are_withheld_atomically() {
    let base: Value = serde_json::from_str(&discovery(1)).unwrap();
    for sensitive_schema in [
        json!({"type":"string", "enum":[SECRET]}),
        json!({"type":"object", "properties":{(SECRET):{"type":"string"}}}),
        json!({"type":"string", "default":"-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"}),
    ] {
        let mut value = base.clone();
        value["tools"][0]["inputSchema"] = sensitive_schema;
        let raw = serde_json::to_string(&value).unwrap();
        let error = ensure_discovery_safe(&raw).unwrap_err();
        assert!(matches!(error, iteron_mcp::McpError::SensitiveToolSchema));
        assert!(!error.public_summary().contains(SECRET));
        assert!(error.public_summary().contains("server owner"));
        let live = through_response_owner(result(&raw));
        assert!(!content(&live).contains("inputSchema"));
        assert!(content(&live).contains("schema unavailable"));
        let mut recovered = [Message {
            role: Role::User,
            content: vec![Block::ToolResult(result(&raw))],
        }];
        assert!(model_context_projection::messages(&mut recovered).unwrap());
        assert_eq!(content(&recovered[0]), content(&live));
        assert!(content(&live).len() <= raw.len());
    }
}

#[test]
fn escaped_secret_cannot_materialize_during_whole_tool_projection() {
    let mut value: Value = serde_json::from_str(&discovery(100)).unwrap();
    value["tools"][0]["inputSchema"]["default"] = json!(SECRET);
    let encoded = serde_json::to_string(&value).unwrap();
    let escaped = SECRET
        .chars()
        .map(|ch| format!("\\u{:04x}", u32::from(ch)))
        .collect::<String>();
    let raw = encoded.replace(SECRET, &escaped);
    assert!(!raw.contains(SECRET));
    assert_eq!(iteron_record::redact::scrub(&raw), raw);
    let projected = project(&raw, 2_500).unwrap();
    assert!(!projected.contains(SECRET));
    assert!(!projected.contains("inputSchema"));
    assert!(projected.contains("schema unavailable"));
    assert!(matches!(
        ensure_discovery_safe(&raw),
        Err(iteron_mcp::McpError::SensitiveToolSchema)
    ));
}

#[test]
fn private_spill_and_tiny_budgets_never_slice_discovery_schemas() {
    let raw = discovery(75);
    let policy = ToolOutputSpillPolicy::new(2_048, 16_384, ToolOutputSpillCleanup::RunEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let managed = store.apply(result(&raw));
    assert!(managed.spilled);
    assert!(managed.result.content.len() <= policy.memory_threshold_bytes());
    assert_eq!(whole_subset(&raw, &managed.result.content), 1);
    assert_eq!(store.retained_count(), 1);
    assert_eq!(store.retained_bytes(), raw.len());
    let handle = format!("sha256:{:x}", Sha256::digest(raw.as_bytes()));
    assert_eq!(store.read_private(&handle).unwrap(), raw.as_bytes());
    for maximum in [0, 1, 32, 100, 512] {
        let mut managed = ManagedToolResult::unspilled(result(&raw));
        assert!(managed.project_visible(maximum));
        assert!(managed.result.content.len() <= maximum);
        assert!(!managed.result.content.contains("inputSchema"));
        if let Ok(parsed) = serde_json::from_str::<Value>(&managed.result.content) {
            assert_eq!(parsed["tools"], json!([]));
            assert_eq!(parsed["status"], "schema_too_large");
        }
    }
    let broken = "{\"kind\":\"mcp_tool_search\",\"tools\":[{\"inputSchema\":";
    assert!(!project(broken, 128).unwrap().contains("inputSchema"));
    let ordinary = "{\"kind\":\"ordinary\",\"text\":\"mcp_tool_search\"}";
    assert!(project(ordinary, 8).is_none());
}

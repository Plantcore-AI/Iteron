use super::{MAX_JSON_DEPTH, MAX_JSON_NODES, content, messages};
use iteron_protocol::{Block, Message, ProviderState, Role, ToolUse};
use iteron_provider::PreparedToolSchemas;
use serde_json::json;

const SECRET: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn projection_keeps_exact_call_and_opaque_continuation_but_removes_known_text_credentials() {
    let opaque = ProviderState {
        route_scope: "exact-provider-route".into(),
        format: "iteron.fixture-private-state.v1".into(),
        payload: json!({"opaque":"exact signed/encrypted provider payload"}),
    };
    let mut input = vec![Message {
        role: Role::Assistant,
        content: vec![
            Block::Text {
                text: format!("history api_key={SECRET}\nsafe tail"),
            },
            Block::Thinking {
                thinking: format!("portable summary {SECRET}"),
            },
            Block::ProviderState(opaque.clone()),
            Block::ToolUse(ToolUse {
                id: "exact-call".into(),
                name: "shell".into(),
                input: json!({"command":format!("echo {SECRET}"),"timeout_ms":17}),
            }),
        ],
    }];
    let mut system = format!("actual system\napi_key={SECRET}");
    assert!(content(&mut system, &mut input, &Vec::new().into()).unwrap());
    assert!(!system.contains(SECRET));
    assert!(system.contains("actual system"));
    assert!(!serde_json::to_string(&input).unwrap().contains(SECRET));
    assert_eq!(input[0].content[2], Block::ProviderState(opaque));
    let Block::ToolUse(call) = &input[0].content[3] else {
        panic!("same tool call")
    };
    assert_eq!(call.id, "exact-call");
    assert_eq!(call.name, "shell");
    assert_eq!(call.input["timeout_ms"], 17);
    assert!(
        !messages(&mut input).unwrap(),
        "clean projection is byte-idempotent"
    );
}

#[test]
fn schema_secrets_are_refused_without_reinterpreting_constraints_or_catalog_identity() {
    let spec = iteron_protocol::ToolSpec {
        name: "fixture".into(),
        description: "bounded source tool".into(),
        input_schema: json!({"type":"object","properties":{"key":{"type":"string","default":SECRET}}}),
        capability: iteron_protocol::Capability::ReadOnly,
        purity: iteron_protocol::Purity::Pure,
    };
    let tools = PreparedToolSchemas::from(vec![spec]);
    let original = tools.canonical_json().clone();
    let identity = tools.cache_identity();
    assert!(content(&mut String::new(), &mut [], &tools).is_err());
    assert_eq!(tools.canonical_json(), &original);
    assert_eq!(tools.cache_identity(), identity);
}

#[test]
fn historic_unknown_tool_name_secrets_are_refused_without_renaming_the_call() {
    let call = ToolUse {
        id: "exact-unknown-call".into(),
        name: SECRET.into(),
        input: json!({"safe": "argument"}),
    };
    let mut history = vec![Message {
        role: Role::Assistant,
        content: vec![Block::ToolUse(call.clone())],
    }];
    let refusal = messages(&mut history).unwrap_err().error();
    assert!(matches!(refusal, super::KernelError::SensitiveModelContext));
    assert_eq!(history[0].content[0], Block::ToolUse(call));
    assert!(!refusal.public_summary().contains(SECRET));
}

#[test]
fn bounded_historic_json_and_structural_secret_keys_refuse_before_transport_projection() {
    use iteron_protocol::refusal::{RefusalOriginV1, RefusalReasonV1};
    let message = |input| Message {
        role: Role::Assistant,
        content: vec![Block::ToolUse(ToolUse {
            id: "exact".into(),
            name: "shell".into(),
            input,
        })],
    };
    let mut wide = vec![message(json!([]))];
    let Block::ToolUse(call) = &mut wide[0].content[0] else {
        unreachable!()
    };
    call.input = serde_json::Value::Array(vec![json!(0); MAX_JSON_NODES]);
    let refusal = messages(&mut wide).unwrap_err().error();
    assert_eq!(refusal.refusal_reason(), RefusalReasonV1::ObservationLimit);
    assert_eq!(
        refusal.refusal_observation().origin(),
        RefusalOriginV1::ResourceLimit
    );
    let mut deep = json!("leaf");
    for _ in 0..=MAX_JSON_DEPTH {
        deep = json!([deep]);
    }
    assert!(messages(&mut [message(deep)]).is_err());
    let mut keyed = serde_json::Map::new();
    keyed.insert(SECRET.into(), json!("not renamed"));
    let refusal = messages(&mut [message(serde_json::Value::Object(keyed))])
        .unwrap_err()
        .error();
    assert_eq!(refusal.refusal_reason(), RefusalReasonV1::PermissionDenied);
    assert_eq!(
        refusal.refusal_observation().origin(),
        RefusalOriginV1::HostPolicy
    );
    assert!(!refusal.public_summary().contains(SECRET));
}

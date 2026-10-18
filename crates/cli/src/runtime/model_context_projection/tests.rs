use super::{MAX_JSON_DEPTH, MAX_JSON_NODES, content, messages};
use iteron_protocol::{Block, Message, ProviderState, Role, ToolUse};
use iteron_provider::PreparedToolSchemas;
use serde_json::json;

const SECRET: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn structural_cache_preserves_exact_names_keys_and_refusal_after_eviction() {
    super::CLEAN_TEXT.with(|cache| *cache.borrow_mut() = super::CleanTextCache::default());
    let message = |name: &str, key: &str| Message {
        role: Role::Assistant,
        content: vec![Block::ToolUse(ToolUse {
            id: "structural-cache-call".into(),
            name: name.into(),
            input: json!({(key): 7}),
        })],
    };
    let clean = "x".repeat(SECRET.len());
    for _ in 0..2 {
        let original = message(&clean, &clean);
        let mut history = [original.clone()];
        assert!(!messages(&mut history).unwrap());
        assert_eq!(history[0].role, original.role);
        assert_eq!(history[0].content, original.content);
    }
    super::CLEAN_TEXT.with(|cache| assert!(cache.borrow().values.contains(clean.as_str())));
    for original in [message(SECRET, &clean), message(&clean, SECRET)] {
        let mut history = [original.clone()];
        assert!(matches!(
            messages(&mut history),
            Err(super::ProjectionRefusal::SensitiveStructuralField)
        ));
        assert_eq!(history[0].role, original.role);
        assert_eq!(
            history[0].content, original.content,
            "structural identity must not be rewritten"
        );
    }
    super::CLEAN_TEXT.with(|cache| assert!(!cache.borrow().values.contains(SECRET)));
    for index in 0..=super::MAX_CLEAN_TEXT_ENTRIES {
        assert!(!messages(&mut [message(&format!("fixture_tool_{index}"), "key")]).unwrap());
    }
    super::CLEAN_TEXT.with(|cache| {
        let cache = cache.borrow();
        assert!(!cache.values.contains(clean.as_str()));
        assert!(cache.values.len() <= super::MAX_CLEAN_TEXT_ENTRIES);
        assert!(cache.bytes <= super::MAX_CLEAN_TEXT_BYTES);
    });
    assert!(!messages(&mut [message(&clean, &clean)]).unwrap());
    assert!(messages(&mut [message(&clean, SECRET)]).is_err());
    super::CLEAN_TEXT.with(|cache| assert!(!cache.borrow().values.contains(SECRET)));
}

#[test]
fn clean_text_cache_checks_actual_bytes_never_retains_secrets_and_stays_bounded() {
    super::CLEAN_TEXT.with(|cache| *cache.borrow_mut() = super::CleanTextCache::default());
    let mut value = "x".repeat(SECRET.len());
    assert!(!super::text(&mut value));
    assert!(!super::text(&mut value));
    value.replace_range(.., SECRET);
    assert!(super::text(&mut value));
    assert!(!value.contains(SECRET));
    super::CLEAN_TEXT.with(|cache| assert!(!cache.borrow().values.contains(SECRET)));
    for index in 0..super::MAX_CLEAN_TEXT_ENTRIES * 2 {
        assert!(!super::text(&mut format!("safe fixture text {index}")));
    }
    let benign = "safe fixture text ";
    let mut oversized = benign.repeat(super::MAX_CLEAN_TEXT_BYTES / benign.len() + 1);
    assert!(oversized.len() > super::MAX_CLEAN_TEXT_BYTES);
    assert!(!super::text(&mut oversized));
    super::CLEAN_TEXT.with(|cache| {
        let cache = cache.borrow();
        assert!(cache.values.len() <= super::MAX_CLEAN_TEXT_ENTRIES);
        assert!(cache.bytes <= super::MAX_CLEAN_TEXT_BYTES);
        assert!(!cache.values.contains(oversized.as_str()));
        assert!(cache.values.iter().all(|value| !value.contains(SECRET)));
    });
}

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
fn schema_validation_cache_binds_actual_specs_and_still_projects_request_text() {
    let clean = iteron_protocol::ToolSpec {
        name: "fixture".into(),
        description: "bounded source tool".into(),
        input_schema: json!({"type":"object","properties":{"path":{"type":"string"}}}),
        capability: iteron_protocol::Capability::ReadOnly,
        purity: iteron_protocol::Purity::Pure,
    };
    let tools = PreparedToolSchemas::from(vec![clean.clone()]);
    assert!(content(&mut String::new(), &mut [], &tools).is_ok());
    let retained = tools.clone();
    assert!(tools.shares_specs_with(&retained));

    let mut system = format!("system {SECRET}");
    let mut history = vec![Message {
        role: Role::User,
        content: vec![Block::Text {
            text: format!("task {SECRET}"),
        }],
    }];
    assert!(content(&mut system, &mut history, &retained).unwrap());
    assert!(!system.contains(SECRET));
    assert!(!serde_json::to_string(&history).unwrap().contains(SECRET));

    for malicious_schema in [
        json!({"type":"string","default":SECRET}),
        serde_json::Value::Array(vec![json!(0); MAX_JSON_NODES]),
    ] {
        let mut changed = clean.clone();
        changed.input_schema = malicious_schema;
        let forged = PreparedToolSchemas::new(
            vec![changed].into(),
            tools.canonical_json().clone(),
            tools.estimated_tokens(),
            0,
        );
        assert_eq!(forged.cache_identity(), tools.cache_identity());
        assert!(!forged.shares_specs_with(&tools));
        assert!(content(&mut String::new(), &mut [], &forged).is_err());
        assert!(super::VALIDATED_TOOL_SCHEMAS.with(|cached| {
            cached
                .borrow()
                .as_ref()
                .is_some_and(|previous| previous.shares_specs_with(&tools))
        }));
    }
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

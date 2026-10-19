use super::*;
use iteron_protocol::{Capability, Purity, Role, ToolResult, Trust};
use serde_json::json;

#[test]
fn changed_message_and_result_bytes_cannot_reuse_a_same_length_summary() {
    let estimator = RequestEstimator::new();
    let mut cache = EvidenceCache::default();
    cache.bind(estimator.tokenizer_identity());
    let first = Message::user_text("aaaa");
    let second = Message::user_text("bbbb");
    let a = cache.message(0, &first, &estimator).whole.unwrap();
    let b = cache.message(0, &second, &estimator).whole.unwrap();
    assert_eq!(a.bytes, b.bytes);
    assert_ne!(a.digest, b.digest);
    assert_eq!(
        b.digest,
        <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(&second).unwrap()))
    );

    let result = |text: &str| Message {
        role: Role::User,
        content: vec![Block::ToolResult(ToolResult {
            tool_use_id: "call".into(),
            content: text.into(),
            is_error: false,
            trust: Trust::Workspace,
            latency_ms: 0,
        })],
    };
    let a = cache.message(1, &result("aaaa"), &estimator).result(0);
    let b = cache.message(1, &result("bbbb"), &estimator).result(0);
    assert_eq!(a.bytes, b.bytes);
    assert_ne!(a.digest, b.digest);
    assert_eq!(
        b.tokens,
        estimator.estimate_text("bbbb").saturating_add(8) as u64
    );
}

#[test]
fn changed_schema_and_estimator_identity_invalidate_retained_summaries() {
    let mut cache = EvidenceCache::default();
    let estimator = RequestEstimator::new();
    cache.bind(estimator.tokenizer_identity());
    let mut tools = vec![ToolSpec {
        name: "fixture".into(),
        description: "stable".into(),
        input_schema: json!({"type":"string"}),
        capability: Capability::ReadOnly,
        purity: Purity::Pure,
    }];
    let first = cache.schemas(&tools);
    tools[0].input_schema = json!({"type":"number"});
    let second = cache.schemas(&tools);
    assert_eq!(first.bytes, second.bytes);
    assert_ne!(first.digest, second.digest);
    cache.message(0, &Message::user_text("retained"), &estimator);
    let mut changed = estimator.tokenizer_identity();
    changed.version += 1;
    cache.bind(changed);
    assert!(cache.messages.is_empty() && cache.schemas.is_none() && cache.system.is_none());
    assert_eq!(cache.retained, 0);
}

#[test]
fn summary_retention_is_bounded_even_for_many_large_messages() {
    let estimator = RequestEstimator::new();
    let mut cache = EvidenceCache::default();
    cache.bind(estimator.tokenizer_identity());
    for index in 0..MAX_ENTRIES * 2 {
        cache.message(
            index,
            &Message::user_text(format!("{index}:{}", "x".repeat(4096))),
            &estimator,
        );
        assert!(cache.retained <= MAX_RETAINED_BYTES);
        assert!(cache.messages.len() <= MAX_ENTRIES);
    }
    let oversized =
        Message::user_text("x".repeat(MAX_RETAINED_BYTES / VALUE_ALLOCATION_FACTOR + 1));
    cache.message(0, &oversized, &estimator);
    assert!(!cache.messages.contains_key(&0));
    assert!(cache.retained <= MAX_RETAINED_BYTES);
}

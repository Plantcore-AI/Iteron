use super::*;
use crate::memo::{Lookup, Memo};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

fn result(content: &str, is_error: bool) -> ToolResult {
    ToolResult {
        tool_use_id: "memo-test".into(),
        content: content.into(),
        is_error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

fn miss(memo: &Memo, tool: &str, input: serde_json::Value) -> crate::memo::PendingInsert {
    let key = Memo::key(tool, &input).unwrap();
    match memo.lookup(key) {
        Lookup::Miss(pending) => pending,
        Lookup::Hit(_) => panic!("expected a memo miss"),
    }
}

#[test]
fn d2_16_authoritative_memo_has_bounded_keys_capacity_and_error_policy() {
    let memo = Memo::with_capacity(2);
    let first = miss(&memo, "read", serde_json::json!({"path":"a"}));
    assert!(memo.complete(first, &result("a", false)));
    let second = miss(&memo, "read", serde_json::json!({"path":"b"}));
    assert!(memo.complete(second, &result("b", false)));
    assert_eq!(memo.len(), 2);

    let first_key = Memo::key("read", &serde_json::json!({"path":"a"})).unwrap();
    assert!(matches!(memo.lookup(first_key), Lookup::Hit(_)));
    let third = miss(&memo, "read", serde_json::json!({"path":"c"}));
    assert!(memo.complete(third, &result("c", false)));
    assert_eq!(memo.len(), 2, "entry count must never exceed capacity");
    assert!(
        matches!(memo.lookup(first_key), Lookup::Miss(_)),
        "fixed FIFO eviction must remove the oldest entry"
    );

    let failed = miss(&memo, "read", serde_json::json!({"path":"failure"}));
    assert!(!memo.complete(failed, &result("transient", true)));
    assert_eq!(memo.len(), 2, "error results are never cached");

    let oversized = "x".repeat(64 * 1024 + 1);
    assert!(Memo::key("read", &serde_json::json!({"path":oversized})).is_none());
    assert!(Memo::key(&"x".repeat(257), &serde_json::json!({})).is_none());
    let mut too_deep = serde_json::Value::Null;
    for _ in 0..34 {
        too_deep = serde_json::json!([too_deep]);
    }
    assert!(Memo::key("read", &too_deep).is_none());
}

#[test]
fn d2_16_generation_token_rejects_a_read_completed_after_invalidation() {
    let memo = Memo::default();
    let pending = miss(&memo, "read", serde_json::json!({"path":"a"}));
    memo.invalidate();
    assert!(
        !memo.complete(pending, &result("stale", false)),
        "a pre-write read must not repopulate the post-write generation"
    );
    assert_eq!(memo.len(), 0);
}

#[tokio::test]
async fn d2_16_concurrent_read_cannot_repopulate_after_effect_and_fresh_value_is_cached() {
    let mut registry = Registry::read_only(".").unwrap();
    let version = Arc::new(AtomicUsize::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());

    registry
        .push_tool(
            ToolSpec {
                name: "slow_pure".into(),
                description: "bounded concurrent memo test".into(),
                input_schema: serde_json::json!({"type":"object"}),
                purity: Purity::Pure,
                capability: Capability::ReadOnly,
            },
            {
                let version = version.clone();
                let calls = calls.clone();
                let started = started.clone();
                let release = release.clone();
                move |call, _| {
                    let version = version.clone();
                    let calls = calls.clone();
                    let started = started.clone();
                    let release = release.clone();
                    boxfut::box_it(async move {
                        let ordinal = calls.fetch_add(1, Ordering::SeqCst);
                        let observed = version.load(Ordering::SeqCst);
                        if ordinal == 0 {
                            started.notify_one();
                            release.notified().await;
                        }
                        ok_result(call.id, format!("v{observed}"))
                    })
                }
            },
        )
        .unwrap();
    registry
        .push_tool(
            ToolSpec {
                name: "write_version".into(),
                description: "bounded concurrent memo test effect".into(),
                input_schema: serde_json::json!({"type":"object"}),
                purity: Purity::Effecting,
                capability: Capability::ReversibleLocal,
            },
            {
                let version = version.clone();
                move |call, _| {
                    version.store(2, Ordering::SeqCst);
                    boxfut::box_it(async move { ok_result(call.id, "updated".into()) })
                }
            },
        )
        .unwrap();

    let call = |id: &str| ToolUse {
        id: id.into(),
        name: "slow_pure".into(),
        input: serde_json::json!({}),
    };
    let first = tokio::spawn(registry.dispatch(call("read-before-write")));
    tokio::time::timeout(Duration::from_secs(3), started.notified())
        .await
        .expect("the first pure call must start within the test ceiling");
    tokio::time::timeout(
        Duration::from_secs(3),
        registry.run(ToolUse {
            id: "effect".into(),
            name: "write_version".into(),
            input: serde_json::json!({}),
        }),
    )
    .await
    .expect("the effect must finish within the test ceiling");
    release.notify_waiters();
    let first = tokio::time::timeout(Duration::from_secs(3), first)
        .await
        .expect("the raced pure call must finish within the test ceiling")
        .unwrap();
    assert_eq!(first.content, "v1");

    let fresh = tokio::time::timeout(Duration::from_secs(3), registry.dispatch(call("fresh")))
        .await
        .expect("the fresh read must finish within the test ceiling");
    assert_eq!(fresh.content, "v2");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let hit = tokio::time::timeout(Duration::from_secs(3), registry.dispatch(call("hit")))
        .await
        .expect("the memo hit must finish within the test ceiling");
    assert_eq!(hit.content, "v2");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "third call must be a hit");
    assert_eq!(registry.memo_stats(), (1, 2));
}

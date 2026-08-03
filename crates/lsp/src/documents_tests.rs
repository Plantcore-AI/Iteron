use super::*;
use serde_json::json;

fn diag(message: &str) -> Value {
    json!({ "message": message })
}

fn opened(version: i32) -> DocumentStore {
    let mut store = DocumentStore::new();
    store.open("file:///a.rs", version).unwrap();
    store
}

#[test]
fn diagnostics_must_match_the_current_version_exactly() {
    let mut store = opened(2);
    assert_eq!(
        store.publish("file:///a.rs", Some(1), vec![diag("old")]),
        Ok(Publish::Stale {
            have: 2,
            incoming: 1
        })
    );
    assert_eq!(
        store.publish("file:///a.rs", Some(3), vec![diag("future")]),
        Ok(Publish::Future {
            have: 2,
            incoming: 3
        })
    );
    assert_eq!(
        store.publish("file:///a.rs", None, vec![diag("unknown")]),
        Ok(Publish::Unversioned { have: 2 })
    );
    assert!(store.diagnostics("file:///a.rs").is_empty());
    assert_eq!(store.stale_drops(), 1);
    assert_eq!(store.future_drops(), 1);
    assert_eq!(store.unversioned_drops(), 1);
}

#[test]
fn current_diagnostics_are_kept_and_an_edit_releases_them() {
    let mut store = opened(7);
    assert_eq!(
        store.publish("file:///a.rs", Some(7), vec![diag("current")]),
        Ok(Publish::Accepted)
    );
    assert_eq!(store.diagnostics("file:///a.rs").len(), 1);
    assert!(store.diagnostic_bytes() > 0);
    assert!(store.diagnostic_nodes() > 0);

    assert_eq!(store.change("file:///a.rs", 8), Ok(true));
    assert!(store.diagnostics("file:///a.rs").is_empty());
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);
}

#[test]
fn unknown_and_regressed_documents_fail_without_mutating_state() {
    let mut store = opened(5);
    assert_eq!(
        store.publish("file:///gone.rs", Some(1), vec![diag("x")]),
        Ok(Publish::Unknown)
    );
    assert_eq!(store.unknown_drops(), 1);
    assert_eq!(store.change("file:///a.rs", 4), Ok(false));
    assert_eq!(store.version("file:///a.rs"), Some(5));
}

#[test]
fn equal_version_change_cannot_make_pre_edit_results_look_fresh() {
    let mut store = opened(5);
    store
        .publish("file:///a.rs", Some(5), vec![diag("still current")])
        .unwrap();

    assert_eq!(store.change("file:///a.rs", 5), Ok(false));
    assert_eq!(store.version("file:///a.rs"), Some(5));
    assert_eq!(store.diagnostics("file:///a.rs").len(), 1);

    assert_eq!(store.change("file:///a.rs", 6), Ok(true));
    assert!(store.diagnostics("file:///a.rs").is_empty());
}

#[test]
fn close_and_reopen_release_the_previous_diagnostic_budget() {
    let mut store = opened(1);
    store
        .publish("file:///a.rs", Some(1), vec![diag("first")])
        .unwrap();
    assert!(store.diagnostic_bytes() > 0);
    store.open("file:///a.rs", 2).unwrap();
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);

    store
        .publish("file:///a.rs", Some(2), vec![diag("second")])
        .unwrap();
    assert!(store.close("file:///a.rs"));
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);
    assert!(!store.close("file:///a.rs"));
}

#[test]
fn open_document_and_uri_bounds_are_hard() {
    let mut store = DocumentStore::new();
    for index in 0..MAX_OPEN_DOCUMENTS {
        store.open(&format!("file:///{index}"), 1).unwrap();
    }
    assert_eq!(store.open_documents(), MAX_OPEN_DOCUMENTS);
    assert_eq!(
        store.open("file:///one-too-many", 1),
        Err(LspError::DocumentLimit {
            limit: MAX_OPEN_DOCUMENTS
        })
    );

    let uri = "u".repeat(MAX_DOCUMENT_URI_BYTES + 1);
    assert_eq!(
        DocumentStore::new().open(&uri, 1),
        Err(LspError::DocumentUriTooLong {
            value: MAX_DOCUMENT_URI_BYTES + 1,
            limit: MAX_DOCUMENT_URI_BYTES
        })
    );
    for invalid in ["", "not-a-uri", "1file:///a.rs", "file:///a\n.rs"] {
        assert_eq!(
            DocumentStore::new().open(invalid, 1),
            Err(LspError::InvalidDocumentUri)
        );
    }
}

#[test]
fn diagnostic_count_bytes_nodes_and_depth_are_bounded() {
    let mut store = opened(1);
    let too_many = vec![Value::Null; MAX_DIAGNOSTICS_PER_DOCUMENT + 1];
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), too_many),
        Err(LspError::DiagnosticsTooMany { .. })
    ));

    let too_large = "x".repeat(MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT + 1);
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), vec![Value::String(too_large)]),
        Err(LspError::DiagnosticsTooLarge { .. })
    ));

    let too_complex = Value::Array(vec![Value::Null; MAX_DIAGNOSTIC_JSON_NODES]);
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), vec![too_complex]),
        Err(LspError::DiagnosticsTooComplex { .. })
    ));

    let mut too_deep = Value::Null;
    for _ in 0..=MAX_DIAGNOSTIC_JSON_DEPTH {
        too_deep = Value::Array(vec![too_deep]);
    }
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), vec![too_deep]),
        Err(LspError::DiagnosticsTooDeep { .. })
    ));
    assert_eq!(store.limit_rejections(), 4);
    assert!(store.diagnostics("file:///a.rs").is_empty());
}

#[test]
fn global_diagnostic_budget_rejects_atomically() {
    let mut store = opened(1);
    store.diagnostic_bytes = MAX_DIAGNOSTIC_BYTES_TOTAL;
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), vec![diag("x")]),
        Err(LspError::DiagnosticStoreFull { .. })
    ));
    assert!(store.diagnostics("file:///a.rs").is_empty());

    store.diagnostic_bytes = 0;
    store.diagnostic_nodes = MAX_DIAGNOSTIC_JSON_NODES_TOTAL;
    assert!(matches!(
        store.publish("file:///a.rs", Some(1), vec![diag("x")]),
        Err(LspError::DiagnosticNodeStoreFull { .. })
    ));
}

#[test]
fn accepted_values_are_canonicalized_before_retention() {
    let mut oversized_capacity = String::with_capacity(MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT);
    oversized_capacity.push('x');
    assert!(oversized_capacity.capacity() > 1);

    let mut store = opened(1);
    store
        .publish(
            "file:///a.rs",
            Some(1),
            vec![Value::String(oversized_capacity)],
        )
        .unwrap();
    let Value::String(stored) = &store.diagnostics("file:///a.rs")[0] else {
        panic!("expected string diagnostic fixture");
    };
    assert!(stored.capacity() < MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT / 2);
}

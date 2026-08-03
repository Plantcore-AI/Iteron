use super::*;
use serde_json::json;

const GENERATION: u64 = 17;

fn diag(message: impl Into<String>) -> Value {
    json!({
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": 0, "character": 1 }
        },
        "message": message.into()
    })
}

fn opened(source_revision: i32) -> (DocumentStore, DocumentSnapshot) {
    let mut store = DocumentStore::new(GENERATION);
    let snapshot = store.open("file:///a.rs", source_revision).unwrap();
    (store, snapshot)
}

#[test]
fn wire_versions_are_monotonic_across_change_close_and_reopen() {
    let (mut store, first) = opened(10);
    assert_eq!(first.wire_version, 1);
    let changed = match store.change("file:///a.rs", 11).unwrap() {
        Change::Accepted(snapshot) => snapshot,
        other => panic!("unexpected change: {other:?}"),
    };
    assert_eq!(changed.wire_version, 2);
    assert!(store.close("file:///a.rs"));
    let reopened_same_source = store.open("file:///a.rs", 10).unwrap();
    assert_eq!(reopened_same_source.wire_version, 3);

    // The delayed notification carries only fields that exist in LSP: URI and old wire version.
    assert_eq!(
        store.publish("file:///a.rs", Some(first.wire_version), vec![diag("old")]),
        Ok(Publish::Stale {
            have: 3,
            incoming: 1
        })
    );
    let reopened_lower_source = store.open("file:///a.rs", 1).unwrap();
    assert_eq!(reopened_lower_source.wire_version, 4);
    assert_eq!(
        store.publish(
            "file:///a.rs",
            Some(reopened_same_source.wire_version),
            vec![diag("old reopen")]
        ),
        Ok(Publish::Stale {
            have: 4,
            incoming: 3
        })
    );
}

#[test]
fn equal_or_lower_change_desynchronizes_until_explicit_resync() {
    let (mut store, opened) = opened(5);
    store
        .publish(
            "file:///a.rs",
            Some(opened.wire_version),
            vec![diag("current")],
        )
        .unwrap();
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs").unwrap().len(),
        1
    );

    assert_eq!(
        store.change("file:///a.rs", 5),
        Ok(Change::Desynchronized {
            have: 5,
            incoming: 5
        })
    );
    assert_eq!(
        store.state("file:///a.rs"),
        Some(DocumentState::Desynchronized)
    );
    assert!(store.diagnostic_set("file:///a.rs").is_none());
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs"),
        Err(LspError::DocumentDesynchronized {
            uri: "file:///a.rs".into()
        })
    );
    assert_eq!(
        store.publish(
            "file:///a.rs",
            Some(opened.wire_version),
            vec![diag("must not pass")]
        ),
        Ok(Publish::Desynchronized)
    );
    assert_eq!(
        store.publish("file:///a.rs", None, vec![diag("also blocked")]),
        Ok(Publish::Desynchronized)
    );
    assert_eq!(store.change("file:///a.rs", 6), Ok(Change::NeedsResync));

    let resynced = store.resync("file:///a.rs", 6).unwrap();
    assert_eq!(resynced.wire_version, opened.wire_version + 1);
    assert_eq!(store.state("file:///a.rs"), Some(DocumentState::Synced));
    assert!(matches!(
        store.publish(
            "file:///a.rs",
            Some(resynced.wire_version),
            vec![diag("resynced")]
        ),
        Ok(Publish::Accepted(DiagnosticFreshness::Exact { .. }))
    ));

    assert_eq!(
        store.change("file:///a.rs", 4),
        Ok(Change::Desynchronized {
            have: 6,
            incoming: 4
        })
    );
    assert_eq!(store.desynchronized_drops(), 2);
}

#[test]
fn versionless_diagnostics_are_visible_but_never_actionable() {
    let (mut store, snapshot) = opened(1);
    assert_eq!(
        store.publish("file:///a.rs", None, vec![diag("unknown")]),
        Ok(Publish::Accepted(DiagnosticFreshness::Unknown {
            server_generation: GENERATION,
            wire_version_at_arrival: snapshot.wire_version,
            arrival: 1
        }))
    );
    let set = store.diagnostic_set("file:///a.rs").unwrap();
    assert_eq!(set.diagnostics().len(), 1);
    assert!(matches!(
        set.freshness(),
        DiagnosticFreshness::Unknown { .. }
    ));
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs"),
        Err(LspError::DiagnosticsNotActionable {
            uri: "file:///a.rs".into()
        })
    );

    store
        .publish(
            "file:///a.rs",
            Some(snapshot.wire_version),
            vec![diag("exact")],
        )
        .unwrap();
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs").unwrap().len(),
        1
    );

    store.close("file:///a.rs");
    let reopened = store.open("file:///a.rs", 1).unwrap();
    assert!(reopened.wire_version > snapshot.wire_version);
    // An old versionless notification cannot be distinguished on the wire, so it is retained only
    // as Unknown and cannot replace actionable truth.
    store
        .publish("file:///a.rs", None, vec![diag("delayed unknown")])
        .unwrap();
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs"),
        Err(LspError::DiagnosticsNotActionable {
            uri: "file:///a.rs".into()
        })
    );
    assert_eq!(store.unversioned_accepts(), 2);
}

#[test]
fn exact_diagnostics_are_actionable_and_cleared_on_every_transition() {
    let (mut store, snapshot) = opened(7);
    assert_eq!(
        store.publish(
            "file:///a.rs",
            Some(snapshot.wire_version - 1),
            vec![diag("old")]
        ),
        Ok(Publish::Stale {
            have: snapshot.wire_version,
            incoming: snapshot.wire_version - 1
        })
    );
    assert_eq!(
        store.publish(
            "file:///a.rs",
            Some(snapshot.wire_version + 1),
            vec![diag("future")]
        ),
        Ok(Publish::Future {
            have: snapshot.wire_version,
            incoming: snapshot.wire_version + 1
        })
    );
    assert!(matches!(
        store.publish(
            "file:///a.rs",
            Some(snapshot.wire_version),
            vec![diag("current")]
        ),
        Ok(Publish::Accepted(DiagnosticFreshness::Exact {
            server_generation: GENERATION,
            ..
        }))
    ));
    assert_eq!(
        store.actionable_diagnostics("file:///a.rs").unwrap().len(),
        1
    );
    assert!(store.diagnostic_bytes() > 0);

    let changed = match store.change("file:///a.rs", 8).unwrap() {
        Change::Accepted(snapshot) => snapshot,
        other => panic!("unexpected change: {other:?}"),
    };
    assert!(store.diagnostic_set("file:///a.rs").is_none());
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);
    store
        .publish(
            "file:///a.rs",
            Some(changed.wire_version),
            vec![diag("new")],
        )
        .unwrap();
    store.open("file:///a.rs", 8).unwrap();
    assert!(store.diagnostic_set("file:///a.rs").is_none());
    assert!(store.close("file:///a.rs"));
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);
}

#[test]
fn unknown_documents_are_counted_without_storage() {
    let mut store = DocumentStore::new(GENERATION);
    assert_eq!(
        store.publish("file:///gone.rs", Some(1), vec![diag("x")]),
        Ok(Publish::Unknown)
    );
    assert_eq!(store.unknown_drops(), 1);
    assert_eq!(store.change("file:///gone.rs", 2), Ok(Change::Unknown));
}

#[test]
fn open_document_and_rfc3986_uri_bounds_are_hard() {
    let mut store = DocumentStore::new(GENERATION);
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
        DocumentStore::new(GENERATION).open(&uri, 1),
        Err(LspError::DocumentUriTooLong {
            value: MAX_DOCUMENT_URI_BYTES + 1,
            limit: MAX_DOCUMENT_URI_BYTES
        })
    );
    for invalid in [
        "",
        "not-a-uri",
        "1file:///a.rs",
        "file:///a b.rs",
        "file:///a\\b.rs",
        "file:///a%",
        "file:///a%0",
        "file:///a%GG",
        "file:///a#b#c",
        "file:///中文.rs",
        "http://[bad]/a",
    ] {
        assert_eq!(
            DocumentStore::new(GENERATION).open(invalid, 1),
            Err(LspError::InvalidDocumentUri),
            "URI should be rejected: {invalid:?}"
        );
    }
    assert!(
        DocumentStore::new(GENERATION)
            .open("file:///a%20b.rs", 1)
            .is_ok()
    );
}

#[test]
fn wire_version_exhaustion_is_typed_without_reuse() {
    let mut store = DocumentStore::new(GENERATION);
    store.next_wire_version = Some(i32::MAX);
    assert_eq!(
        store.open("file:///last.rs", 1).unwrap().wire_version,
        i32::MAX
    );
    assert_eq!(
        store.open("file:///never.rs", 1),
        Err(LspError::SequenceExhausted {
            kind: "wire document version"
        })
    );

    let (mut live, snapshot) = opened(1);
    live.publish(
        "file:///a.rs",
        Some(snapshot.wire_version),
        vec![diag("old")],
    )
    .unwrap();
    live.next_wire_version = None;
    assert_eq!(
        live.change("file:///a.rs", 2),
        Err(LspError::SequenceExhausted {
            kind: "wire document version"
        })
    );
    assert_eq!(
        live.state("file:///a.rs"),
        Some(DocumentState::Desynchronized)
    );
    assert!(live.diagnostic_set("file:///a.rs").is_none());
}

#[test]
fn full_diagnostic_shape_is_validated_before_storage() {
    let (mut store, snapshot) = opened(1);
    let valid = json!({
        "range": {
            "start": {"line": MAX_LSP_POSITION, "character": 0},
            "end": {"line": MAX_LSP_POSITION, "character": 1}
        },
        "severity": 2,
        "code": "E0001",
        "codeDescription": {"href": "https://example.test/E0001"},
        "source": "rustc",
        "message": "type mismatch",
        "tags": [1, 2],
        "relatedInformation": [{
            "location": {
                "uri": "file:///b.rs",
                "range": {
                    "start": {"line": 1, "character": 0},
                    "end": {"line": 1, "character": 2}
                }
            },
            "message": "declared here"
        }],
        "data": {"vendor": true}
    });
    store
        .publish("file:///a.rs", Some(snapshot.wire_version), vec![valid])
        .unwrap();

    let bad_position = json!({
        "range": {
            "start": {"line": u64::from(MAX_LSP_POSITION) + 1, "character": 0},
            "end": {"line": u64::from(MAX_LSP_POSITION) + 1, "character": 0}
        },
        "message": "bad"
    });
    let reversed = json!({
        "range": {
            "start": {"line": 2, "character": 0},
            "end": {"line": 1, "character": 0}
        },
        "message": "bad"
    });
    let bad_related = json!({
        "range": diag("x")["range"].clone(),
        "message": "bad",
        "relatedInformation": [{
            "location": {"uri": "not-a-uri", "range": {}},
            "message": "x"
        }]
    });
    for malformed in [
        Value::Null,
        json!({"message": "missing range"}),
        json!({"range": {}, "message": "bad"}),
        bad_position,
        reversed,
        json!({"range": diag("x")["range"].clone(), "message": "x", "severity": 5}),
        json!({"range": diag("x")["range"].clone(), "message": "x", "code": true}),
        json!({"range": diag("x")["range"].clone(), "message": "x", "tags": [3]}),
        bad_related,
    ] {
        assert!(matches!(
            store.publish("file:///a.rs", Some(snapshot.wire_version), vec![malformed]),
            Err(LspError::MalformedDiagnostic { index: 0, .. })
        ));
    }
    assert_eq!(
        store
            .diagnostic_set("file:///a.rs")
            .unwrap()
            .diagnostics()
            .len(),
        1,
        "malformed replacement must be atomic"
    );
}

#[test]
fn diagnostic_count_bytes_nodes_and_depth_are_bounded() {
    let (mut store, snapshot) = opened(1);
    let too_many = vec![diag("x"); MAX_DIAGNOSTICS_PER_DOCUMENT + 1];
    assert!(matches!(
        store.publish("file:///a.rs", Some(snapshot.wire_version), too_many),
        Err(LspError::DiagnosticsTooMany { .. })
    ));
    let large_message = "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES);
    let too_large = vec![diag(large_message); 17];
    assert!(matches!(
        store.publish("file:///a.rs", Some(snapshot.wire_version), too_large),
        Err(LspError::DiagnosticsTooLarge { .. })
    ));
    let mut too_complex = diag("complex");
    too_complex["data"] = Value::Array(vec![Value::Null; MAX_DIAGNOSTIC_JSON_NODES]);
    assert!(matches!(
        store.publish(
            "file:///a.rs",
            Some(snapshot.wire_version),
            vec![too_complex]
        ),
        Err(LspError::DiagnosticsTooComplex { .. })
    ));
    let mut nested = Value::Null;
    for _ in 0..=MAX_DIAGNOSTIC_JSON_DEPTH {
        nested = Value::Array(vec![nested]);
    }
    let mut too_deep = diag("deep");
    too_deep["data"] = nested;
    assert!(matches!(
        store.publish("file:///a.rs", Some(snapshot.wire_version), vec![too_deep]),
        Err(LspError::DiagnosticsTooDeep { .. })
    ));
    assert_eq!(store.limit_rejections(), 4);
}

#[test]
fn related_information_and_diagnostic_strings_are_bounded() {
    let (mut store, snapshot) = opened(1);
    let related = json!({
        "location": {"uri": "file:///b.rs", "range": diag("x")["range"].clone()},
        "message": "here"
    });
    let mut too_many = diag("x");
    too_many["relatedInformation"] =
        Value::Array(vec![related; MAX_DIAGNOSTIC_RELATED_INFORMATION + 1]);
    let mut long_source = diag("x");
    long_source["source"] = Value::String("s".repeat(MAX_DIAGNOSTIC_SOURCE_BYTES + 1));
    let mut long_code = diag("x");
    long_code["code"] = Value::String("c".repeat(MAX_DIAGNOSTIC_CODE_BYTES + 1));
    let long_message = diag("x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1));
    let mut long_related = diag("x");
    long_related["relatedInformation"] = json!([{
        "location": {"uri": "file:///b.rs", "range": diag("x")["range"].clone()},
        "message": "m".repeat(MAX_DIAGNOSTIC_RELATED_MESSAGE_BYTES + 1)
    }]);
    for malformed in [too_many, long_source, long_code, long_message, long_related] {
        assert!(matches!(
            store.publish("file:///a.rs", Some(snapshot.wire_version), vec![malformed]),
            Err(LspError::MalformedDiagnostic { .. })
        ));
    }
}

#[test]
fn global_diagnostic_budget_rejects_atomically() {
    let (mut store, snapshot) = opened(1);
    store.diagnostic_bytes = MAX_DIAGNOSTIC_BYTES_TOTAL;
    assert!(matches!(
        store.publish("file:///a.rs", Some(snapshot.wire_version), vec![diag("x")]),
        Err(LspError::DiagnosticStoreFull { .. })
    ));
    assert!(store.diagnostic_set("file:///a.rs").is_none());
    store.diagnostic_bytes = 0;
    store.diagnostic_nodes = MAX_DIAGNOSTIC_JSON_NODES_TOTAL;
    assert!(matches!(
        store.publish("file:///a.rs", Some(snapshot.wire_version), vec![diag("x")]),
        Err(LspError::DiagnosticNodeStoreFull { .. })
    ));
}

#[test]
fn accepted_values_are_canonicalized_before_retention() {
    let mut oversized_capacity = String::with_capacity(MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT);
    oversized_capacity.push('x');
    let (mut store, snapshot) = opened(1);
    store
        .publish(
            "file:///a.rs",
            Some(snapshot.wire_version),
            vec![diag(oversized_capacity)],
        )
        .unwrap();
    let Value::String(stored) =
        &store.diagnostic_set("file:///a.rs").unwrap().diagnostics()[0]["message"]
    else {
        panic!("expected string diagnostic fixture");
    };
    assert!(stored.capacity() < MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT / 2);
}

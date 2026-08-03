use super::*;
use serde_json::json;

fn diag(message: impl Into<String>) -> Value {
    json!({
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": 0, "character": 1 }
        },
        "message": message.into()
    })
}

fn opened(version: i32) -> (DocumentStore, DocumentSnapshot) {
    let mut store = DocumentStore::new();
    let snapshot = store.open("file:///a.rs", version).unwrap();
    (store, snapshot)
}

#[test]
fn versioned_diagnostics_must_match_the_complete_current_snapshot() {
    let (mut store, snapshot) = opened(2);
    assert_eq!(
        store.publish(&snapshot, Some(1), vec![diag("old")]),
        Ok(Publish::Stale {
            have: 2,
            incoming: 1
        })
    );
    assert_eq!(
        store.publish(&snapshot, Some(3), vec![diag("future")]),
        Ok(Publish::Future {
            have: 2,
            incoming: 3
        })
    );
    let accepted = store
        .publish(&snapshot, Some(2), vec![diag("current")])
        .unwrap();
    assert_eq!(
        accepted,
        Publish::Accepted(DiagnosticProvenance::Versioned {
            snapshot: snapshot.clone()
        })
    );
    assert_eq!(store.diagnostics("file:///a.rs").len(), 1);
    assert_eq!(store.stale_drops(), 1);
    assert_eq!(store.future_drops(), 1);
}

#[test]
fn unversioned_diagnostics_have_visible_weaker_arrival_provenance() {
    let (mut store, snapshot) = opened(7);
    let first = store.publish(&snapshot, None, vec![diag("first")]).unwrap();
    assert_eq!(
        first,
        Publish::Accepted(DiagnosticProvenance::Unversioned {
            snapshot: snapshot.clone(),
            arrival: 1
        })
    );
    let second = store
        .publish(&snapshot, None, vec![diag("second")])
        .unwrap();
    assert_eq!(
        second,
        Publish::Accepted(DiagnosticProvenance::Unversioned {
            snapshot: snapshot.clone(),
            arrival: 2
        })
    );
    assert_eq!(store.unversioned_accepts(), 2);
    assert_eq!(
        store.diagnostic_provenance("file:///a.rs"),
        match &second {
            Publish::Accepted(provenance) => Some(provenance),
            _ => None,
        }
    );
}

#[test]
fn accepted_edit_releases_diagnostics_and_old_version_snapshot_is_stale() {
    let (mut store, snapshot) = opened(7);
    store
        .publish(&snapshot, Some(7), vec![diag("current")])
        .unwrap();
    assert!(store.diagnostic_bytes() > 0);
    let current = match store.change("file:///a.rs", 8).unwrap() {
        Change::Accepted(snapshot) => snapshot,
        other => panic!("unexpected change disposition: {other:?}"),
    };
    assert_eq!(current.incarnation, snapshot.incarnation);
    assert!(store.diagnostics("file:///a.rs").is_empty());
    assert_eq!(store.diagnostic_bytes(), 0);
    assert_eq!(store.diagnostic_nodes(), 0);
    assert_eq!(
        store.publish(&snapshot, Some(7), vec![diag("delayed")]),
        Ok(Publish::Stale {
            have: 8,
            incoming: 7
        })
    );
}

#[test]
fn equal_version_change_is_rejected_but_invalidates_old_truth() {
    let (mut store, before) = opened(5);
    store
        .publish(&before, Some(5), vec![diag("pre-edit")])
        .unwrap();

    let after = match store.change("file:///a.rs", 5).unwrap() {
        Change::EqualVersionInvalidated(snapshot) => snapshot,
        other => panic!("unexpected equal-version disposition: {other:?}"),
    };
    assert_eq!(after.version, 5, "strict-greater version rule is preserved");
    assert_ne!(after.incarnation, before.incarnation);
    assert!(store.diagnostics("file:///a.rs").is_empty());
    assert!(store.diagnostic_provenance("file:///a.rs").is_none());
    assert_eq!(
        store.publish(&before, Some(5), vec![diag("delayed pre-edit")]),
        Ok(Publish::PriorIncarnation {
            have: after.incarnation,
            incoming: before.incarnation
        })
    );
}

#[test]
fn close_and_reopen_same_or_lower_version_rejects_prior_incarnation() {
    let (mut store, original) = opened(9);
    assert!(store.close("file:///a.rs"));
    let same = store.open("file:///a.rs", 9).unwrap();
    assert_ne!(same.incarnation, original.incarnation);
    assert_eq!(
        store.publish(&original, Some(9), vec![diag("old same-version")]),
        Ok(Publish::PriorIncarnation {
            have: same.incarnation,
            incoming: original.incarnation
        })
    );

    let lower = store.open("file:///a.rs", 1).unwrap();
    assert_ne!(lower.incarnation, same.incarnation);
    assert_eq!(
        store.publish(&same, Some(9), vec![diag("old higher-version")]),
        Ok(Publish::PriorIncarnation {
            have: lower.incarnation,
            incoming: same.incarnation
        })
    );
    assert_eq!(
        store.publish(&same, None, vec![diag("old unversioned")]),
        Ok(Publish::PriorIncarnation {
            have: lower.incarnation,
            incoming: same.incarnation
        })
    );
    assert_eq!(store.prior_incarnation_drops(), 3);
}

#[test]
fn unknown_and_regressed_documents_do_not_mutate_state() {
    let (mut store, snapshot) = opened(5);
    let unknown = DocumentSnapshot {
        uri: "file:///gone.rs".into(),
        incarnation: snapshot.incarnation,
        version: 5,
    };
    assert_eq!(
        store.publish(&unknown, Some(5), vec![diag("x")]),
        Ok(Publish::Unknown)
    );
    assert_eq!(store.unknown_drops(), 1);
    assert_eq!(
        store.change("file:///a.rs", 4),
        Ok(Change::Stale {
            have: 5,
            incoming: 4
        })
    );
    assert_eq!(store.snapshot("file:///a.rs").unwrap(), snapshot);
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
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![valid]),
        Ok(Publish::Accepted(_))
    ));

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
        "range": {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 0}
        },
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
            store.publish(&snapshot, Some(1), vec![malformed]),
            Err(LspError::MalformedDiagnostic { index: 0, .. })
        ));
    }
    assert_eq!(
        store.diagnostics("file:///a.rs").len(),
        1,
        "malformed replacement must be atomic"
    );
}

#[test]
fn diagnostic_count_bytes_nodes_and_depth_are_bounded() {
    let (mut store, snapshot) = opened(1);
    let too_many = vec![diag("x"); MAX_DIAGNOSTICS_PER_DOCUMENT + 1];
    assert!(matches!(
        store.publish(&snapshot, Some(1), too_many),
        Err(LspError::DiagnosticsTooMany { .. })
    ));

    let large_message = "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES);
    let too_large = vec![diag(large_message); 17];
    assert!(matches!(
        store.publish(&snapshot, Some(1), too_large),
        Err(LspError::DiagnosticsTooLarge { .. })
    ));

    let mut too_complex = diag("complex");
    too_complex["data"] = Value::Array(vec![Value::Null; MAX_DIAGNOSTIC_JSON_NODES]);
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![too_complex]),
        Err(LspError::DiagnosticsTooComplex { .. })
    ));

    let mut nested = Value::Null;
    for _ in 0..=MAX_DIAGNOSTIC_JSON_DEPTH {
        nested = Value::Array(vec![nested]);
    }
    let mut too_deep = diag("deep");
    too_deep["data"] = nested;
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![too_deep]),
        Err(LspError::DiagnosticsTooDeep { .. })
    ));
    assert_eq!(store.limit_rejections(), 4);
}

#[test]
fn related_information_count_and_strings_are_bounded() {
    let (mut store, snapshot) = opened(1);
    let related = json!({
        "location": {
            "uri": "file:///b.rs",
            "range": diag("x")["range"].clone()
        },
        "message": "here"
    });
    let mut too_many = diag("x");
    too_many["relatedInformation"] =
        Value::Array(vec![related; MAX_DIAGNOSTIC_RELATED_INFORMATION + 1]);
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![too_many]),
        Err(LspError::MalformedDiagnostic { .. })
    ));

    let mut long_source = diag("x");
    long_source["source"] = Value::String("s".repeat(MAX_DIAGNOSTIC_SOURCE_BYTES + 1));
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![long_source]),
        Err(LspError::MalformedDiagnostic { .. })
    ));

    let mut long_code = diag("x");
    long_code["code"] = Value::String("c".repeat(MAX_DIAGNOSTIC_CODE_BYTES + 1));
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![long_code]),
        Err(LspError::MalformedDiagnostic { .. })
    ));

    let long_message = diag("x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1));
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![long_message]),
        Err(LspError::MalformedDiagnostic { .. })
    ));

    let mut long_related = diag("x");
    long_related["relatedInformation"] = json!([{
        "location": {
            "uri": "file:///b.rs",
            "range": diag("x")["range"].clone()
        },
        "message": "m".repeat(MAX_DIAGNOSTIC_RELATED_MESSAGE_BYTES + 1)
    }]);
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![long_related]),
        Err(LspError::MalformedDiagnostic { .. })
    ));
}

#[test]
fn global_diagnostic_budget_rejects_atomically() {
    let (mut store, snapshot) = opened(1);
    store.diagnostic_bytes = MAX_DIAGNOSTIC_BYTES_TOTAL;
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![diag("x")]),
        Err(LspError::DiagnosticStoreFull { .. })
    ));
    assert!(store.diagnostics("file:///a.rs").is_empty());

    store.diagnostic_bytes = 0;
    store.diagnostic_nodes = MAX_DIAGNOSTIC_JSON_NODES_TOTAL;
    assert!(matches!(
        store.publish(&snapshot, Some(1), vec![diag("x")]),
        Err(LspError::DiagnosticNodeStoreFull { .. })
    ));
}

#[test]
fn accepted_values_are_canonicalized_before_retention() {
    let mut oversized_capacity = String::with_capacity(MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT);
    oversized_capacity.push('x');
    assert!(oversized_capacity.capacity() > 1);
    let (mut store, snapshot) = opened(1);
    store
        .publish(&snapshot, Some(1), vec![diag(oversized_capacity)])
        .unwrap();
    let Value::String(stored) = &store.diagnostics("file:///a.rs")[0]["message"] else {
        panic!("expected string diagnostic fixture");
    };
    assert!(stored.capacity() < MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT / 2);
}

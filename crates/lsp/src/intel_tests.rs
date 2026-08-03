use super::*;
use crate::{MAX_DOCUMENT_URI_BYTES, MAX_LSP_POSITION};

fn loc(uri: &str, line: u32) -> Value {
    json!({
        "uri": uri,
        "range": {
            "start": { "line": line, "character": 0 },
            "end": { "line": line, "character": 4 }
        }
    })
}

#[test]
fn single_array_link_and_null_union_shapes_are_normalized() {
    let single = parse_locations(&loc("file:///a.rs", 3), 10).unwrap();
    assert_eq!(single.locations[0].range.start.line, 3);

    let array = json!([loc("file:///a.rs", 1), loc("file:///b.rs", 2)]);
    assert_eq!(parse_locations(&array, 10).unwrap().locations.len(), 2);

    let link = json!({
        "targetUri": "file:///a.rs",
        "targetRange": { "start": {"line": 10, "character": 0}, "end": {"line": 40, "character": 1} },
        "targetSelectionRange": { "start": {"line": 12, "character": 7}, "end": {"line": 12, "character": 15} }
    });
    assert_eq!(
        parse_locations(&link, 10).unwrap().locations[0]
            .range
            .start
            .line,
        12
    );
    assert_eq!(
        parse_locations(&Value::Null, 10).unwrap(),
        Locations::default()
    );
}

#[test]
fn location_link_requires_complete_contained_target_fields() {
    let missing_selection = json!({
        "targetUri": "file:///a.rs",
        "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} }
    });
    let parsed = parse_locations(&missing_selection, 10).unwrap();
    assert!(parsed.locations.is_empty());
    assert_eq!(parsed.malformed, 1);

    let malformed_preferred = json!({
        "targetUri": "file:///a.rs",
        "targetSelectionRange": {"bad": true},
        "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} }
    });
    let parsed = parse_locations(&malformed_preferred, 10).unwrap();
    assert!(parsed.locations.is_empty());
    assert_eq!(parsed.malformed, 1);

    let outside_target = json!({
        "targetUri": "file:///a.rs",
        "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} },
        "targetSelectionRange": { "start": {"line": 4, "character": 0}, "end": {"line": 6, "character": 0} }
    });
    assert_eq!(parse_locations(&outside_target, 10).unwrap().malformed, 1);
}

#[test]
fn sorting_deduplication_truncation_and_accounting_are_deterministic() {
    let value = json!([
        loc("file:///b.rs", 5),
        loc("file:///a.rs", 9),
        loc("file:///a.rs", 2),
        loc("file:///a.rs", 2),
        { "uri": "file:///bad.rs" }
    ]);
    let parsed = parse_locations(&value, 2).unwrap();
    let seen: Vec<_> = parsed
        .locations
        .iter()
        .map(|location| (location.uri.as_str(), location.range.start.line))
        .collect();
    assert_eq!(seen, vec![("file:///a.rs", 2), ("file:///a.rs", 9)]);
    assert_eq!(parsed.truncated, 1);
    assert_eq!(parsed.duplicates, 1);
    assert_eq!(parsed.malformed, 1);
    assert_eq!(parsed.uninspected, 0);
}

#[test]
fn output_and_input_limits_are_hard_and_observable() {
    assert_eq!(
        parse_locations(&Value::Null, 0),
        Err(LspError::InvalidLocationLimit {
            value: 0,
            max: MAX_LOCATIONS
        })
    );
    assert_eq!(
        parse_locations(&Value::Null, MAX_LOCATIONS + 1),
        Err(LspError::InvalidLocationLimit {
            value: MAX_LOCATIONS + 1,
            max: MAX_LOCATIONS
        })
    );

    let flood = Value::Array(vec![Value::Null; MAX_LOCATION_INPUTS + 7]);
    let parsed = parse_locations(&flood, 1).unwrap();
    assert_eq!(parsed.malformed, MAX_LOCATION_INPUTS);
    assert_eq!(parsed.uninspected, 7);
}

#[test]
fn bad_coordinates_ranges_and_uris_are_malformed_not_wrapped_or_retained() {
    for bad in [
        json!(-1),
        json!(1.5),
        json!(u64::from(MAX_LSP_POSITION) + 1),
    ] {
        let value = json!({
            "uri": "file:///a.rs",
            "range": { "start": {"line": bad, "character": 0}, "end": {"line": 2, "character": 0} }
        });
        assert_eq!(parse_locations(&value, 10).unwrap().malformed, 1);
    }

    let reversed = json!({
        "uri": "file:///a.rs",
        "range": { "start": {"line": 9, "character": 0}, "end": {"line": 2, "character": 0} }
    });
    assert_eq!(parse_locations(&reversed, 10).unwrap().malformed, 1);

    let long_uri = "u".repeat(MAX_DOCUMENT_URI_BYTES + 1);
    assert_eq!(
        parse_locations(&loc(&long_uri, 1), 10).unwrap().malformed,
        1
    );
}

#[test]
fn query_params_are_exact_and_uri_bounded() {
    let position = Position {
        line: 1,
        character: 2,
    };
    let refs = Query::References {
        include_declaration: true,
    }
    .params("file:///a.rs", position)
    .unwrap();
    assert_eq!(refs["context"]["includeDeclaration"], true);
    assert_eq!(refs["position"]["line"], 1);

    let definition = Query::Definition.params("file:///a.rs", position).unwrap();
    assert!(definition.get("context").is_none());
    assert_eq!(Query::Definition.method(), "textDocument/definition");

    let long_uri = "u".repeat(MAX_DOCUMENT_URI_BYTES + 1);
    assert!(matches!(
        Query::Hover.params(&long_uri, position),
        Err(LspError::DocumentUriTooLong { .. })
    ));
    assert_eq!(
        Query::Hover.params("raw/path.rs", position),
        Err(LspError::InvalidDocumentUri)
    );
    let too_large = Position {
        line: MAX_LSP_POSITION + 1,
        character: 0,
    };
    assert_eq!(
        Query::Hover.params("file:///a.rs", too_large),
        Err(LspError::InvalidPosition {
            line: MAX_LSP_POSITION + 1,
            character: 0,
            max: MAX_LSP_POSITION
        })
    );
}

#[test]
fn hover_handles_supported_union_shapes_and_reports_bad_fragments() {
    assert_eq!(
        parse_hover_text(&json!({"contents": {"kind":"markdown","value":"fn a()"}}))
            .text
            .as_deref(),
        Some("fn a()")
    );
    let mixed = parse_hover_text(&json!({"contents": [
        {"language":"rust","value":"fn a()"},
        "docs here",
        4
    ]}));
    assert_eq!(mixed.text.as_deref(), Some("fn a()\n\ndocs here"));
    assert_eq!(mixed.malformed, 1);
    assert_eq!(mixed.source_bytes, "fn a()".len() + "docs here".len());
    assert_eq!(mixed.retained_source_bytes, mixed.source_bytes);
    assert_eq!(mixed.separator_bytes, 2);
    assert_eq!(mixed.truncated_bytes, 0);
    assert!(parse_hover_text(&json!({"contents": ""})).text.is_none());
    let missing = parse_hover_text(&json!({}));
    assert!(missing.text.is_none());
    assert_eq!(missing.malformed, 1);
}

#[test]
fn hover_bytes_and_fragments_are_bounded_without_splitting_utf8() {
    let oversized = "界".repeat((MAX_HOVER_BYTES / 3) + 10);
    let parsed = parse_hover_text(&json!({"contents": oversized}));
    let text = parsed.text.unwrap();
    assert!(text.len() <= MAX_HOVER_BYTES);
    assert!(text.is_char_boundary(text.len()));
    assert!(parsed.truncated_bytes > 0);
    assert_eq!(
        parsed.retained_source_bytes + parsed.truncated_bytes,
        parsed.source_bytes
    );
    assert_eq!(
        text.len(),
        parsed.retained_source_bytes + parsed.separator_bytes
    );

    let flood = Value::Array(vec![Value::String("x".into()); MAX_HOVER_FRAGMENTS + 3]);
    let parsed = parse_hover_text(&json!({"contents": flood}));
    assert_eq!(parsed.uninspected, 3);
}

#[test]
fn hover_validates_optional_range_and_accounts_only_source_as_truncated() {
    let parsed = parse_hover_text(&json!({
        "contents": ["  a  ", "b"],
        "range": {
            "start": {"line": 1, "character": 0},
            "end": {"line": 1, "character": 2}
        }
    }));
    assert_eq!(parsed.text.as_deref(), Some("  a  \n\nb"));
    assert_eq!(parsed.source_bytes, 6);
    assert_eq!(parsed.retained_source_bytes, 6);
    assert_eq!(parsed.separator_bytes, 2);
    assert_eq!(parsed.truncated_bytes, 0);
    assert_eq!(parsed.range.unwrap().start.line, 1);

    let malformed = parse_hover_text(&json!({
        "contents": "text",
        "range": {
            "start": {"line": 2, "character": 0},
            "end": {"line": 1, "character": 0}
        }
    }));
    assert_eq!(malformed.text.as_deref(), Some("text"));
    assert!(malformed.range.is_none());
    assert_eq!(malformed.malformed, 1);

    let full = "x".repeat(MAX_HOVER_BYTES);
    let boundary = parse_hover_text(&json!({"contents": [full, "tail"]}));
    assert_eq!(boundary.retained_source_bytes, MAX_HOVER_BYTES);
    assert_eq!(boundary.truncated_bytes, 4);
    assert_eq!(boundary.separator_bytes, 0);
    assert_eq!(boundary.source_bytes, MAX_HOVER_BYTES + 4);
}

#[test]
fn answer_snapshot_must_match_uri_incarnation_and_version() {
    let mut store = DocumentStore::new();
    let issued = store.open("file:///a.rs", 2).unwrap();
    assert!(ensure_fresh(&store, &issued).is_ok());
    let stale = DocumentSnapshot {
        version: 1,
        ..issued.clone()
    };
    assert_eq!(
        ensure_fresh(&store, &stale),
        Err(LspError::StaleResult { have: 2, issued: 1 })
    );
    let future = DocumentSnapshot {
        version: 3,
        ..issued.clone()
    };
    assert_eq!(
        ensure_fresh(&store, &future),
        Err(LspError::FutureResult { have: 2, issued: 3 })
    );
    let gone = DocumentSnapshot {
        uri: "file:///gone.rs".into(),
        incarnation: 1,
        version: 1,
    };
    assert_eq!(
        ensure_fresh(&store, &gone),
        Err(LspError::UnknownDocument {
            uri: "file:///gone.rs".into()
        })
    );

    let long_uri = "u".repeat(MAX_DOCUMENT_URI_BYTES + 1);
    let invalid = DocumentSnapshot {
        uri: long_uri,
        incarnation: 1,
        version: 1,
    };
    assert!(matches!(
        ensure_fresh(&store, &invalid),
        Err(LspError::DocumentUriTooLong { .. })
    ));

    store.close("file:///a.rs");
    let reopened = store.open("file:///a.rs", 2).unwrap();
    assert_eq!(
        ensure_fresh(&store, &issued),
        Err(LspError::StaleDocumentIncarnation {
            have: reopened.incarnation,
            issued: issued.incarnation
        })
    );
}

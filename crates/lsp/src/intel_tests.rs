use super::*;
use crate::MAX_DOCUMENT_URI_BYTES;

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
fn link_without_selection_range_uses_target_range_but_bad_selection_does_not() {
    let fallback = json!({
        "targetUri": "file:///a.rs",
        "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} }
    });
    assert_eq!(
        parse_locations(&fallback, 10).unwrap().locations[0]
            .range
            .start
            .line,
        5
    );

    let malformed_preferred = json!({
        "targetUri": "file:///a.rs",
        "targetSelectionRange": {"bad": true},
        "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} }
    });
    let parsed = parse_locations(&malformed_preferred, 10).unwrap();
    assert!(parsed.locations.is_empty());
    assert_eq!(parsed.malformed, 1);
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
    for bad in [json!(-1), json!(1.5), json!(u64::from(u32::MAX) + 1)] {
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
    assert!(parse_hover_text(&json!({"contents": ""})).text.is_none());
    assert!(parse_hover_text(&json!({})).text.is_none());
}

#[test]
fn hover_bytes_and_fragments_are_bounded_without_splitting_utf8() {
    let oversized = "界".repeat((MAX_HOVER_BYTES / 3) + 10);
    let parsed = parse_hover_text(&json!({"contents": oversized}));
    let text = parsed.text.unwrap();
    assert!(text.len() <= MAX_HOVER_BYTES);
    assert!(text.is_char_boundary(text.len()));
    assert!(parsed.truncated_bytes > 0);

    let flood = Value::Array(vec![Value::String("x".into()); MAX_HOVER_FRAGMENTS + 3]);
    let parsed = parse_hover_text(&json!({"contents": flood}));
    assert_eq!(parsed.uninspected, 3);
}

#[test]
fn answer_version_must_equal_the_open_document_snapshot() {
    let mut store = DocumentStore::new();
    store.open("file:///a.rs", 2).unwrap();
    assert!(ensure_fresh(&store, "file:///a.rs", 2).is_ok());
    assert_eq!(
        ensure_fresh(&store, "file:///a.rs", 1),
        Err(LspError::StaleResult { have: 2, issued: 1 })
    );
    assert_eq!(
        ensure_fresh(&store, "file:///a.rs", 3),
        Err(LspError::FutureResult { have: 2, issued: 3 })
    );
    assert_eq!(
        ensure_fresh(&store, "file:///gone.rs", 1),
        Err(LspError::UnknownDocument {
            uri: "file:///gone.rs".into()
        })
    );

    let long_uri = "u".repeat(MAX_DOCUMENT_URI_BYTES + 1);
    assert!(matches!(
        ensure_fresh(&store, &long_uri, 1),
        Err(LspError::DocumentUriTooLong { .. })
    ));
}

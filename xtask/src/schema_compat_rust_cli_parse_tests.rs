use super::super::manifest::read_bounded;
use super::cli_parse::{
    cli_machine_record_shapes, cli_nested_literal_fields, outer_json_object_shape,
};
use super::{CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES};
use std::collections::BTreeSet;
use std::path::Path;

fn live_source() -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is directly below the repository root");
    read_bounded(root, CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES).unwrap()
}

#[test]
fn d13_14_cli_outer_json_source_binding_ignores_nested_fields_and_rejects_duplicates() {
    let source = live_source();
    let shapes = cli_machine_record_shapes(&source).unwrap();
    assert_eq!(shapes.len(), 18);
    assert_eq!(
        shapes["assistant_text"],
        BTreeSet::from([
            "delta".to_owned(),
            "schema_version".to_owned(),
            "type".to_owned(),
        ])
    );
    assert_eq!(
        shapes["turn_end"],
        BTreeSet::from([
            "cache_hit".to_owned(),
            "context".to_owned(),
            "cost_reason".to_owned(),
            "cost_status".to_owned(),
            "cost_usd".to_owned(),
            "cumulative_cost_usd".to_owned(),
            "effort".to_owned(),
            "schema_version".to_owned(),
            "turn".to_owned(),
            "type".to_owned(),
            "usage".to_owned(),
        ])
    );
    assert!(!shapes["turn_end"].contains("estimator"));
    let context = cli_nested_literal_fields(&source, "turn_end", "context").unwrap();
    assert!(context.contains("input_tokens"));
    let text = std::str::from_utf8(&source).unwrap();
    let spoofed = text.replacen("\"context\": {", "/* \"context\": { */ \"context\": {", 1);
    assert_eq!(
        cli_nested_literal_fields(spoofed.as_bytes(), "turn_end", "context").unwrap(),
        context
    );

    let nested = br#"{"type": "sample", "context": {"nested": 1}}"#;
    let (_, fields) = outer_json_object_shape(nested, 0, nested.len() - 1, "type").unwrap();
    assert_eq!(
        fields,
        BTreeSet::from(["context".to_owned(), "type".to_owned()])
    );
    let duplicate = br#"{"type": "sample", "type": "sample"}"#;
    assert!(outer_json_object_shape(duplicate, 0, duplicate.len() - 1, "type").is_err());
    let dynamic = br#"{"type": record_type}"#;
    assert!(outer_json_object_shape(dynamic, 0, dynamic.len() - 1, "type").is_err());
    let wrong_version = br#"{"schema_version": 3, "type": "sample"}"#;
    assert!(outer_json_object_shape(wrong_version, 0, wrong_version.len() - 1, "type").is_err());
    let bound_version = br#"{"schema_version": SCHEMA_VERSION, "type": "sample"}"#;
    assert!(outer_json_object_shape(bound_version, 0, bound_version.len() - 1, "type").is_ok());
}

#[test]
fn an_optional_private_machine_record_producer_is_parsed_fail_closed() {
    let source = live_source();
    let source = std::str::from_utf8(&source).unwrap();
    let producer = r#"
fn input_attachment_event() -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "type": "input_attachment",
        "ordinal": 1,
        "media_type": "image/png",
        "encoded_bytes": 12,
    })
}

"#;
    let with_attachment = source.replacen(
        "pub fn final_result(",
        &format!("{producer}pub fn final_result("),
        1,
    );
    assert_ne!(
        with_attachment, source,
        "the synthetic producer must be inserted"
    );
    let shapes = cli_machine_record_shapes(with_attachment.as_bytes()).unwrap();
    assert_eq!(
        shapes["input_attachment"],
        BTreeSet::from([
            "encoded_bytes".to_owned(),
            "media_type".to_owned(),
            "ordinal".to_owned(),
            "schema_version".to_owned(),
            "type".to_owned(),
        ])
    );

    let public = with_attachment.replacen(
        "fn input_attachment_event() -> Value",
        "pub fn input_attachment_event() -> Value",
        1,
    );
    assert!(
        cli_machine_record_shapes(public.as_bytes()).is_err(),
        "the additive producer cannot broaden its source authority"
    );
    let crate_visible = with_attachment.replacen(
        "fn input_attachment_event() -> Value",
        "pub(crate) fn input_attachment_event() -> Value",
        1,
    );
    assert!(
        cli_machine_record_shapes(crate_visible.as_bytes()).is_err(),
        "the additive producer must remain module-private"
    );
    let indirect = source.replacen(
        "pub fn final_result(",
        "fn input_attachment_event() -> Value { evil_value() }\n\npub fn final_result(",
        1,
    );
    assert_ne!(indirect, source);
    assert!(super::cli_parse::parse_cli_output_source(&indirect).is_ok());
    assert!(
        cli_machine_record_shapes(indirect.as_bytes()).is_err(),
        "the additive producer must retain a direct trusted json! object"
    );
}

#[test]
fn d13_14_cli_producer_rejects_selector_diff_and_executable_value_mutations() {
    let source = live_source();
    let text = std::str::from_utf8(&source).unwrap();

    let selector = text.replacen("match event {", "match 0 {", 1);
    assert_ne!(selector, text);
    assert!(cli_machine_record_shapes(selector.as_bytes()).is_err());

    let diff = text.replacen(
        "scrub_json(serde_json::to_value(diff).unwrap_or(Value::Null))",
        "Value::Null",
        1,
    );
    assert_ne!(diff, text);
    assert!(cli_machine_record_shapes(diff.as_bytes()).is_err());

    let side_effect = text.replacen(
        "\"delta\": scrub(&delta),",
        "\"delta\": { evil_stdout(); scrub(&delta) },",
        1,
    );
    assert_ne!(side_effect, text);
    assert!(cli_machine_record_shapes(side_effect.as_bytes()).is_err());
}

use super::super::manifest::read_bounded;
use super::cli_parse::{
    cli_machine_record_shapes, cli_nested_literal_fields, outer_json_object_shape,
};
use super::{CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES};
use quote::ToTokens;
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
    let version =
        crate::rust_source::public_decimal_const(&source, "SCHEMA_VERSION", "u32").unwrap();
    assert_eq!(
        shapes.len(),
        match version {
            6 => 19,
            8 => 23,
            _ => panic!("unknown fixture version"),
        }
    );
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
    let with_attachment = if source.contains("fn input_attachment_event(") {
        source.to_owned()
    } else {
        let with_attachment = source.replacen(
            "pub fn final_result(",
            &format!("{producer}pub fn final_result("),
            1,
        );
        assert_ne!(
            with_attachment, source,
            "the synthetic producer must be inserted"
        );
        with_attachment
    };
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
        "fn input_attachment_event(",
        "pub fn input_attachment_event(",
        1,
    );
    assert!(
        cli_machine_record_shapes(public.as_bytes()).is_err(),
        "the additive producer cannot broaden its source authority"
    );
    let crate_visible = with_attachment.replacen(
        "fn input_attachment_event(",
        "pub(crate) fn input_attachment_event(",
        1,
    );
    assert!(
        cli_machine_record_shapes(crate_visible.as_bytes()).is_err(),
        "the additive producer must remain module-private"
    );
    let without_direct_producer = with_attachment.replacen(
        "fn input_attachment_event(",
        "fn ignored_attachment_event(",
        1,
    );
    let indirect = without_direct_producer.replacen(
        "pub fn final_result(",
        "fn input_attachment_event() -> Value { evil_value() }\n\npub fn final_result(",
        1,
    );
    assert_ne!(indirect, with_attachment);
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

// A complete future source fixture, assembled from the unchanged live v6 source. Keeping these
// four arms independent of the policy witnesses makes the mutation tests exercise the trust edge.
const V8_RECEIPTS: &str = r#"
        UiEvent::SteerSubmissionApplied { id } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "steer_submission_applied",
            "submission_id": id.0,
        }),
        UiEvent::SubmissionRejected { id, reason_code } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "submission_rejected",
            "submission_id": id.0,
            "reason_code": reason_code,
        }),
        UiEvent::ControlSubmissionApplied { id, kind } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "control_submission_applied",
            "submission_id": id.0,
            "kind": kind.as_str(),
        }),
        UiEvent::ApprovalResolved {
            id,
            resolution,
            reason_code,
            response_submission_id,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "approval_resolved",
            "submission_id": id.0,
            "resolution": approval_resolution_name(resolution),
            "reason_code": reason_code,
            "response_submission_id": response_submission_id.map(|id| id.0),
        }),
"#;

const V8_RECEIPT_DOWNGRADE: &str = r#"
            if schema_version < SCHEMA_VERSION
                && matches!(
                    fields.get("type").and_then(Value::as_str),
                    Some(
                        "approval_resolved"
                            | "control_submission_applied"
                            | "steer_submission_applied"
                            | "submission_rejected"
                    )
                )
            {
                return Ok(json!({
                    "schema_version": schema_version,
                    "type": "notice",
                    "message": scrub("Submission lifecycle detail requires output schema v8."),
                }));
            }
"#;

fn staged_v8_source() -> String {
    let source = String::from_utf8(live_source()).unwrap();
    if source.contains("pub const SCHEMA_VERSION: u32 = 8;") {
        return source;
    }
    assert!(source.contains("pub const SCHEMA_VERSION: u32 = 6;"));
    let source = source
        .replace("pub const SCHEMA_VERSION: u32 = 6;", "pub const SCHEMA_VERSION: u32 = 8;")
        .replacen(
            "        UiEvent::Notice(message) =>",
            &format!("{V8_RECEIPTS}        UiEvent::Notice(message) =>"),
            1,
        )
        .replacen(
            "if schema_version < SCHEMA_VERSION",
            "if schema_version < 6",
            1,
        )
        .replacen(
            "    fields.insert(\"schema_version\".into(), Value::from(schema_version));",
            &format!("{V8_RECEIPT_DOWNGRADE}    fields.insert(\"schema_version\".into(), Value::from(schema_version));"),
            1,
        );
    format!(
        r#"{source}
        fn approval_resolution_name(resolution: crate::runtime::ApprovalResolution) -> &'static str {{
            match resolution {{
                crate::runtime::ApprovalResolution::Approved => "approved",
                crate::runtime::ApprovalResolution::Denied => "denied",
                crate::runtime::ApprovalResolution::Cancelled => "cancelled",
                crate::runtime::ApprovalResolution::TimedOut => "timed_out",
            }}
        }}"#
    )
}

fn staged_v6_source() -> String {
    let source = String::from_utf8(live_source()).unwrap();
    if source.contains("pub const SCHEMA_VERSION: u32 = 6;") {
        return source;
    }
    assert!(source.contains("pub const SCHEMA_VERSION: u32 = 8;"));
    let mut file = syn::parse_file(&with_schema_version(&source, 6)).unwrap();
    for item in &mut file.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident == "stream_event" {
            let Some(syn::Stmt::Expr(syn::Expr::Match(body), None)) =
                function.block.stmts.last_mut()
            else {
                panic!("source fixture must have a direct stream event match");
            };
            body.arms.retain(|arm| {
                let syn::Pat::Struct(pattern) = &arm.pat else {
                    return true;
                };
                !matches!(
                    pattern
                        .path
                        .segments
                        .last()
                        .unwrap()
                        .ident
                        .to_string()
                        .as_str(),
                    "ApprovalResolved"
                        | "ControlSubmissionApplied"
                        | "SteerSubmissionApplied"
                        | "SubmissionRejected"
                )
            });
        }
        if function.sig.ident == "project_schema" {
            *function = syn::parse_quote! {
                pub(crate) fn project_schema(mut value: Value, schema_version: u32) -> io::Result<Value> {
                    if !SUPPORTED_SCHEMA_VERSIONS.contains(&schema_version) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unsupported CLI output schema version {schema_version}"),
                        ));
                    }
                    let fields = value.as_object_mut().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "machine output record must be a JSON object",
                        )
                    })?;
                    fields.insert("schema_version".into(), Value::from(schema_version));
                    if schema_version < SCHEMA_VERSION
                        && fields.get("type").and_then(Value::as_str) == Some("turn_end")
                        && let Some(context) = fields.get_mut("context").and_then(Value::as_object_mut)
                    {
                        context.remove("components");
                    }
                    if schema_version == LEGACY_SCHEMA_VERSION
                        && fields.get("type").and_then(Value::as_str) == Some("result")
                    {
                        fields.remove("kernel_tax");
                    }
                    Ok(value)
                }
            };
        }
    }
    file.to_token_stream().to_string()
}

fn with_schema_version(source: &str, version: u32) -> String {
    let mut file = syn::parse_file(source).unwrap();
    let mut changed = false;
    for item in &mut file.items {
        if let syn::Item::Const(item) = item
            && item.ident == "SCHEMA_VERSION"
        {
            let literal = syn::LitInt::new(&version.to_string(), proc_macro2::Span::call_site());
            item.expr = Box::new(syn::parse_quote!(#literal));
            changed = true;
        }
    }
    assert!(
        changed,
        "the schema mutation must change the authoritative constant"
    );
    file.to_token_stream().to_string()
}

fn without_receipt_downgrade(source: &str) -> String {
    let mut file = syn::parse_file(source).unwrap();
    let mut removed = 0;
    for item in &mut file.items {
        if let syn::Item::Fn(function) = item
            && function.sig.ident == "project_schema"
        {
            function.block.stmts.retain(|statement| {
                if let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement
                    && branch
                        .cond
                        .to_token_stream()
                        .to_string()
                        .contains("approval_resolved")
                {
                    removed += 1;
                    return false;
                }
                true
            });
        }
    }
    assert_eq!(
        removed, 1,
        "the downgrade mutation must remove exactly its branch"
    );
    file.to_token_stream().to_string()
}

fn staged_output_is_valid(source: &str) -> bool {
    cli_machine_record_shapes(source.as_bytes()).is_ok()
        && super::cli_parse::parse_cli_output_source(source)
            .and_then(|file| super::cli_exact::validate(&file))
            .is_ok()
}

#[test]
fn staged_machine_stream_policy_keeps_v6_and_v8_contracts_separate() {
    let old = staged_v6_source();
    let new = staged_v8_source();
    assert!(staged_output_is_valid(&old));
    assert!(staged_output_is_valid(&new));
    assert_eq!(cli_machine_record_shapes(old.as_bytes()).unwrap().len(), 19);
    assert_eq!(cli_machine_record_shapes(new.as_bytes()).unwrap().len(), 23);

    let mislabeled = with_schema_version(&new, 6);
    assert!(
        !staged_output_is_valid(&mislabeled),
        "v6 cannot acquire new record types"
    );
    let incomplete = with_schema_version(&old, 8);
    assert!(
        !staged_output_is_valid(&incomplete),
        "v8 must carry the complete receipt contract"
    );
    let partial = new.replacen(
        "UiEvent::SubmissionRejected { id, reason_code }",
        "UiEvent::OtherRejected { id, reason_code }",
        1,
    );
    assert!(
        !staged_output_is_valid(&partial),
        "the four-record set is exact"
    );
    let old_projection = without_receipt_downgrade(&new);
    assert_ne!(old_projection, new);
    assert!(
        !staged_output_is_valid(&old_projection),
        "the v8 map needs its own projector"
    );
}

#[test]
fn staged_v8_receipts_reject_redirected_id_kind_and_approval_values() {
    let source = staged_v8_source();
    for (from, to) in [
        ("\"submission_id\": id.0,", "\"submission_id\": 99,"),
        (
            "\"reason_code\": reason_code,",
            "\"reason_code\": \"invented\",",
        ),
        ("\"kind\": kind.as_str(),", "\"kind\": \"interrupt\","),
        ("response_submission_id.map(|id| id.0)", "Some(id.0)"),
        (
            "crate::runtime::ApprovalResolution::Denied => \"denied\"",
            "crate::runtime::ApprovalResolution::Denied => \"approved\"",
        ),
        (
            "resolution: crate::runtime::ApprovalResolution",
            "resolution: crate::fake::ApprovalResolution",
        ),
    ] {
        let changed = source.replacen(from, to, 1);
        assert_ne!(changed, source, "mutation must hit {from}");
        assert!(
            !staged_output_is_valid(&changed),
            "admitted redirected receipt {from}"
        );
    }
}

#[test]
fn staged_v8_projection_keeps_v6_context_and_refuses_downgrade_bypasses() {
    let source = staged_v8_source();
    for (from, to) in [
        (
            "if schema_version < 6",
            "if schema_version < SCHEMA_VERSION",
        ),
        (
            "if schema_version < SCHEMA_VERSION",
            "if schema_version < 6",
        ),
        (
            "Submission lifecycle detail requires output schema v8.",
            "approved",
        ),
        ("context.remove(\"components\");", "context.clear();"),
        ("fields.remove(\"kernel_tax\");", "fields.clear();"),
    ] {
        let changed = source.replacen(from, to, 1);
        assert_ne!(changed, source, "mutation must hit {from}");
        assert!(
            !staged_output_is_valid(&changed),
            "admitted incompatible projection {from}"
        );
    }
}

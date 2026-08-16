use super::*;

fn record_file() -> (String, syn::File) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = std::fs::read_to_string(root.join("crates/record/src/lib.rs")).unwrap();
    let file = syn::parse_file(&source).unwrap();
    (source, file)
}

fn append_file() -> (String, syn::File) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = std::fs::read_to_string(root.join("crates/record/src/append_actor.rs")).unwrap();
    let file = syn::parse_file(&source).unwrap();
    (source, file)
}

/// Replace the first occurrence of `anchor`, and fail loudly when it is no longer there.
///
/// Every negative control in this file works by textually breaking a line in
/// `crates/record/src/lib.rs` and asserting the validator catches it. A `replacen` that matches
/// nothing returns the file unchanged, and the unchanged file is exactly what every validator
/// accepts -- so a stale anchor quietly converts the control into a test of nothing. Ordinary
/// edits to the record move these anchors, so say which one went stale rather than reporting it
/// as a validator that stopped working.
fn bypass(source: &str, anchor: &str, replacement: &str) -> syn::File {
    let patched = source.replacen(anchor, replacement, 1);
    assert_ne!(
        patched, *source,
        "negative-control anchor is no longer present in crates/record/src/lib.rs: {anchor}"
    );
    syn::parse_file(&patched).unwrap()
}

#[test]
fn append_payload_must_come_directly_from_the_event() {
    let (source, file) = append_file();
    validate_append(&file).unwrap();
    let patched = bypass(
        &source,
        "let mut payload = serde_json::to_value(&event)?;",
        "let mut payload = serde_json::Value::Null;",
    );
    assert!(validate_append(&patched).is_err());
}

#[test]
fn replay_payload_must_decode_to_the_pushed_event() {
    let (source, file) = record_file();
    validate_replay(&file).unwrap();
    // `replacen(.., 1)` hits the FIRST occurrence, and `replay_timed` is defined above `replay`
    // with the same decode line. Anchoring on the pushed type keeps each bypass aimed at exactly
    // the function under test -- and both are now validated anyway.
    let patched = bypass(
        &source,
        "let mut event: Event = serde_json::from_value(payload)?;\n        validate_event_bounds(&event)?;\n        event.seq = Seq(cl.seq);\n        events.push(TimedEvent { ts_us, event });",
        "let mut event: Event = evil(payload)?;\n        validate_event_bounds(&event)?;\n        event.seq = Seq(cl.seq);\n        events.push(TimedEvent { ts_us, event });",
    );
    assert!(validate_replay_named(&patched, "replay_timed").is_err());
    let dropped = bypass(&source, "events.push(event);", "drop(event);");
    assert!(validate_replay(&dropped).is_err());
    let timed_dropped = bypass(
        &source,
        "events.push(TimedEvent { ts_us, event });",
        "drop((ts_us, event));",
    );
    assert!(validate_replay_named(&timed_dropped, "replay_timed").is_err());
}

#[test]
fn record_serde_json_binding_cannot_be_redirected() {
    let (source, file) = record_file();
    reject_json_shadowing(&file).unwrap();
    let type_shadow = format!("{source}\nstruct serde_json;");
    assert!(reject_json_shadowing(&syn::parse_file(&type_shadow).unwrap()).is_err());
    let grouped_shadow = format!(
        "{source}\nmod evil {{ pub mod serde_json {{}} }}\nuse evil::serde_json::{{self}};"
    );
    assert!(reject_json_shadowing(&syn::parse_file(&grouped_shadow).unwrap()).is_err());
}

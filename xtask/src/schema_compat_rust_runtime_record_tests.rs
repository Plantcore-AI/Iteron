use super::*;

fn record_file() -> (String, syn::File) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = std::fs::read_to_string(root.join("crates/record/src/lib.rs")).unwrap();
    let file = syn::parse_file(&source).unwrap();
    (source, file)
}

#[test]
fn append_payload_must_come_directly_from_the_event() {
    let (source, file) = record_file();
    validate_append(&file).unwrap();
    let bypass = source.replacen(
        "let payload = serde_json::to_value(event)?;",
        "let payload = serde_json::Value::Null;",
        1,
    );
    assert!(validate_append(&syn::parse_file(&bypass).unwrap()).is_err());
}

#[test]
fn replay_payload_must_decode_to_the_pushed_event() {
    let (source, file) = record_file();
    validate_replay(&file).unwrap();
    // `replacen(.., 1)` hits the FIRST occurrence, and `replay_timed` is defined above `replay`
    // with the same decode line. Anchoring on the pushed type keeps each bypass aimed at exactly
    // the function under test -- and both are now validated anyway.
    let bypass = source.replacen(
        "let mut event: Event = serde_json::from_value(cl.payload)?;\n        validate_event_bounds(&event)?;\n        event.seq = Seq(cl.seq);\n        events.push(TimedEvent { ts_us, event });",
        "let mut event: Event = evil(cl.payload)?;\n        validate_event_bounds(&event)?;\n        event.seq = Seq(cl.seq);\n        events.push(TimedEvent { ts_us, event });",
        1,
    );
    assert!(validate_replay_named(&syn::parse_file(&bypass).unwrap(), "replay_timed").is_err());
    let dropped = source.replacen("events.push(event);", "drop(event);", 1);
    assert!(validate_replay(&syn::parse_file(&dropped).unwrap()).is_err());
    let timed_dropped = source.replacen(
        "events.push(TimedEvent { ts_us, event });",
        "drop((ts_us, event));",
        1,
    );
    assert!(
        validate_replay_named(&syn::parse_file(&timed_dropped).unwrap(), "replay_timed").is_err()
    );
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

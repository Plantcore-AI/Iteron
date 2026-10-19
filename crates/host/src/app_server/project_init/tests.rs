use super::*;
#[test]
fn initializer_input_contains_only_actual_source_identity() {
    let value = serde_json::json!({"thread_id":"t","run_id":"r"});
    assert!(
        serde_json::from_value::<ProjectInitV1>(value.clone())
            .unwrap()
            .validate()
    );
    for name in [
        "workspace",
        "content",
        "config",
        "path",
        "mode",
        "rules",
        "tenant",
        "actor",
    ] {
        let mut forged = value.clone();
        forged[name] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<ProjectInitV1>(forged).is_err());
    }
}

use super::*;
use serde_json::json;

fn overview() -> Value {
    json!({"type":"client_inventory_v1","contract_version":1,"kind":"overview",
        "available":true,"provenance":"installed_runtime_boundary","records":[{
            "run_id":"run","provider_id":"selected-provider","model_id":"selected-model",
            "effort":"low","permission_mode":"plan","bypass_permissions":false,
            "approval_channel_available":false,"workspace":"workspace display",
            "budget":Budget { max_turns:7,max_tokens:Some(19000),max_usd:Some(2.25),
                max_wall_secs:45,..Budget::default()},
            "model_context_window_tokens":32000,"model_max_output_tokens":4000}]})
}
#[test]
fn actual_inventory_record_replaces_remote_defaults_without_minting_pricing_or_readiness() {
    let mut app = App::new();
    app.telemetry.observe_remote_cost(None);
    Settings::capture(&overview(), &RunId("run".into()))
        .unwrap()
        .apply(&mut app, true);
    assert_eq!(app.route.provider_id, "selected-provider");
    assert_eq!(app.route.model_id, "selected-model");
    assert_eq!(app.mode, PermissionMode::Plan);
    assert_eq!(app.effort, Effort::Low);
    assert_eq!(app.route.limits.max_tokens, Some(19000));
    assert_eq!(app.telemetry.window(), Some(32000));
    assert!(app.telemetry.display_cost_usd().is_none());
    assert!(!app.run.running());
    let text = app.history.blocks().last().unwrap().to_text();
    assert!(text.contains("workspace display"));
    assert!(text.contains("refuses finitely"));
    assert!(text.contains("last idle/turn boundary"));
}
#[test]
fn foreign_run_unsupported_source_and_oversized_fields_cannot_replace_selected_settings() {
    for (key, value) in [
        ("run_id", json!("other")),
        ("model_id", json!("m".repeat(513))),
        ("provider_id", json!("p".repeat(513))),
        ("workspace", json!("w".repeat(4097))),
        ("effort", json!("inferred")),
        ("permission_mode", json!("unlimited")),
        ("bypass_permissions", Value::Null),
        ("approval_channel_available", json!("yes")),
        ("model_context_window_tokens", json!(-1)),
        ("model_max_output_tokens", json!(u64::MAX)),
    ] {
        let mut value_container = overview();
        value_container["records"][0][key] = value;
        assert!(Settings::capture(&value_container, &RunId("run".into())).is_err());
    }
    for (key, value) in [
        ("provenance", json!("model_claim")),
        ("available", json!(false)),
        ("contract_version", json!(2)),
        ("records", json!([])),
    ] {
        let mut observation = overview();
        observation[key] = value;
        assert!(Settings::capture(&observation, &RunId("run".into())).is_err());
    }
}

#[test]
fn actual_rebind_hides_previous_run_mode_effort_and_model_until_new_settings_arrive() {
    let mut app = App::new();
    Settings::capture(&overview(), &RunId("run".into()))
        .unwrap()
        .apply(&mut app, false);
    Settings::invalidate(&mut app);
    assert!(app.remote_settings_pending);
    assert!(app.model.is_empty());
    assert!(app.route.model_id.is_empty());
    assert!(app.telemetry.window().is_none());
    let footer =
        super::super::status_render::status_right_bits(&app, super::super::surface::Density::Wide)
            .join(" ");
    assert!(footer.contains("settings pending"));
    assert!(!footer.contains("selected-model"));
    assert!(!footer.contains("plan"));
    assert!(!footer.contains("low"));
    Settings::capture(&overview(), &RunId("run".into()))
        .unwrap()
        .apply(&mut app, false);
    assert!(!app.remote_settings_pending);
}

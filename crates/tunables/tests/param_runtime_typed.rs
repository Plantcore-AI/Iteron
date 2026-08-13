//! Every published non-integral tier-2 transport reaches a typed runtime read.

use iteron_tunables::{
    DecimalValue, ResolutionValue, install_param_overrides, param_bool, param_bytes,
    param_duration, param_f64, param_str, param_str_list, param_value,
};
use std::collections::BTreeMap;
use std::time::Duration;

fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

#[test]
fn typed_overrides_replace_every_supported_compiled_shape() {
    let generic = BTreeMap::from([
        (
            "block".to_owned(),
            ResolutionValue::List {
                items: vec![text("<!--"), text("-->")],
            },
        ),
        (
            "keywords".to_owned(),
            ResolutionValue::List {
                items: vec![text("agent")],
            },
        ),
        (
            "line_comments".to_owned(),
            ResolutionValue::List {
                items: vec![text("#")],
            },
        ),
        (
            "nest_block".to_owned(),
            ResolutionValue::Boolean { value: true },
        ),
        (
            "strings".to_owned(),
            ResolutionValue::List {
                items: vec![text("`")],
            },
        ),
        (
            "triple".to_owned(),
            ResolutionValue::Boolean { value: true },
        ),
        (
            "types_capitalized".to_owned(),
            ResolutionValue::Boolean { value: true },
        ),
    ]);
    install_param_overrides([
        (
            "cli.config.completion_notifications_default".to_owned(),
            ResolutionValue::Boolean { value: true },
        ),
        (
            "eval.statistics.z_95".to_owned(),
            ResolutionValue::Decimal {
                value: DecimalValue {
                    coefficient: 25,
                    scale: 1,
                },
            },
        ),
        (
            "cli.app_server.operator_status.lsp_status_deadline".to_owned(),
            ResolutionValue::Integer { value: 37 },
        ),
        (
            "agents.def.isolated_writer_system".to_owned(),
            text("replacement prompt"),
        ),
        (
            "agents.decompose.broad_verbs".to_owned(),
            ResolutionValue::List {
                items: vec![text("accelerate"), text("sharpen")],
            },
        ),
        (
            "cli.theme.capabilities.levels".to_owned(),
            ResolutionValue::List {
                items: [0, 48, 96, 144, 192, 240]
                    .into_iter()
                    .map(|value| ResolutionValue::Integer { value })
                    .collect(),
            },
        ),
        (
            "cli.highlight.generic".to_owned(),
            ResolutionValue::Object { fields: generic },
        ),
    ])
    .expect("all typed values satisfy their published shapes");

    assert!(param_bool(
        "cli.config.completion_notifications_default",
        false
    ));
    assert_eq!(param_f64("eval.statistics.z_95", 1.0), 2.5);
    assert_eq!(
        param_duration(
            "cli.app_server.operator_status.lsp_status_deadline",
            Duration::from_millis(100),
        ),
        Duration::from_millis(37)
    );
    assert_eq!(
        param_str("agents.def.isolated_writer_system", "compiled"),
        "replacement prompt"
    );
    assert_eq!(
        param_str_list("agents.decompose.broad_verbs", &["compiled"]),
        &["accelerate", "sharpen"]
    );
    assert_eq!(
        param_bytes("cli.theme.capabilities.levels", &[0; 6]),
        &[0, 48, 96, 144, 192, 240]
    );
    assert!(matches!(
        param_value("cli.highlight.generic"),
        Some(ResolutionValue::Object { .. })
    ));
}

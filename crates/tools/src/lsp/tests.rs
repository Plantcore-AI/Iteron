use super::{QueryKind, normalize, success};
use crate::Registry;
use core_lsp::intel::Position;
use core_protocol::{Capability, Purity, ToolUse, Trust};
use serde_json::json;

#[test]
fn live_lsp_tools_are_effecting_code_execution_not_pure_reads() {
    let registry = Registry::coding_agent("/tmp/lsp-registration-only").unwrap();
    for name in ["lsp_definition", "lsp_references", "lsp_hover"] {
        assert_eq!(registry.purity_of(name), Some(Purity::Effecting));
        assert_eq!(
            registry.capability_of(name),
            Some(Capability::CodeExecuting)
        );
    }
    let read_only = Registry::read_only("/tmp/lsp-registration-only").unwrap();
    assert!(read_only.purity_of("lsp_definition").is_none());
}

#[test]
fn location_projection_is_deterministic_bounded_and_loss_visible() {
    let position = Position::new(0, 0).unwrap();
    let input = json!([
        {"uri":"file:///repo/b.rs","range":{"start":{"line":2,"character":0},"end":{"line":2,"character":1}}},
        {"uri":"file:///repo/a.rs","range":{"start":{"line":1,"character":0},"end":{"line":1,"character":1}}},
        {"uri":"file:///repo/a.rs","range":{"start":{"line":1,"character":0},"end":{"line":1,"character":1}}},
        {"bad":true}
    ]);
    let output = normalize(
        QueryKind::Definition { position, limit: 1 },
        input,
        std::path::Path::new("/repo"),
    )
    .unwrap();
    // The fixture paths do not exist, so no absolute host URI is retained.
    assert_eq!(output["locations"].as_array().unwrap().len(), 0);
    assert_eq!(output["outside_workspace"], 1);
    assert_eq!(output["truncated"], 1);
    assert_eq!(output["duplicates"], 1);
    assert_eq!(output["malformed"], 1);
}

#[test]
fn location_projection_exposes_only_workspace_relative_paths() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let uri = url::Url::from_file_path(root.join("src/lib.rs"))
        .unwrap()
        .to_string();
    let position = Position::new(0, 0).unwrap();
    let output = normalize(
        QueryKind::Definition { position, limit: 1 },
        json!({"uri":uri,"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}}}),
        root,
    )
    .unwrap();
    assert_eq!(output["locations"][0]["path"], "src/lib.rs");
    assert!(!output.to_string().contains(env!("CARGO_MANIFEST_DIR")));
}

#[test]
fn hover_projection_preserves_truncation_accounting() {
    let position = Position::new(1, 2).unwrap();
    let output = normalize(
        QueryKind::Hover { position },
        json!({"contents":{"kind":"markdown","value":"hello /repo/src/lib.rs"}}),
        std::path::Path::new("/repo"),
    )
    .unwrap();
    assert_eq!(output["text"], "hello <workspace>/src/lib.rs");
    assert_eq!(output["peer_source_bytes"], 22);
    assert_eq!(output["peer_truncated_bytes"], 0);
}

#[test]
fn language_server_content_is_untrusted_even_when_confinement_succeeds() {
    assert_eq!(
        success("call".into(), "peer text".into()).trust,
        Trust::Untrusted
    );
}

#[tokio::test]
async fn unsupported_live_surface_refuses_without_promoting_peer_output() {
    let registry = Registry::coding_agent("/tmp/lsp-registration-only").unwrap();
    let result = registry
        .run(ToolUse {
            id: "call-1".into(),
            name: "lsp_hover".into(),
            input: json!({"path":"missing.rs","line":0,"character":0}),
        })
        .await;
    assert!(result.is_error);
    assert_eq!(result.trust, Trust::Workspace);
    assert!(!result.content.contains("/tmp/"));
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_refuses_a_real_source_before_unconfined_spawn() {
    let registry = Registry::coding_agent(env!("CARGO_MANIFEST_DIR")).unwrap();
    let result = registry
        .run(ToolUse {
            id: "call-platform".into(),
            name: "lsp_hover".into(),
            input: json!({"path":"src/lib.rs","line":0,"character":0}),
        })
        .await;
    assert!(result.is_error);
    assert_eq!(result.trust, Trust::Workspace);
    assert_eq!(
        result.content,
        "confined persistent processes are unavailable; refusing an unconfined server"
    );
}

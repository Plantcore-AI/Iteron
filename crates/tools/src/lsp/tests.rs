use super::{LSP_TOOL_CLEANUP_RESERVE, LspDeadlines, QueryKind, input_schema, normalize, success};
use crate::Registry;
use iteron_lsp::intel::Position;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use iteron_protocol::ToolUse;
use iteron_protocol::{Capability, Purity, Trust};
use serde_json::json;

#[tokio::test(start_paused = true)]
async fn forced_process_and_stderr_cleanup_share_the_reserve() {
    let started = tokio::time::Instant::now();
    let cleanup = tokio::spawn(super::session::join_cleanup(
        async {
            tokio::time::sleep(std::time::Duration::from_millis(2_250)).await;
            true
        },
        async { tokio::time::sleep(std::time::Duration::from_secs(1)).await },
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(2_249)).await;
    assert!(!cleanup.is_finished());
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    assert_eq!(cleanup.await.unwrap(), (true, ()));
    let elapsed = tokio::time::Instant::now().duration_since(started);
    assert_eq!(elapsed, std::time::Duration::from_millis(2_250));
    assert!(elapsed < LSP_TOOL_CLEANUP_RESERVE);
}

#[test]
fn active_work_and_forced_cleanup_share_one_user_visible_budget() {
    let started = tokio::time::Instant::now();
    let active = std::time::Duration::from_millis(30_000);
    let deadlines = LspDeadlines::from_start(started, 30_000);
    assert_eq!(deadlines.active, started + active);
    assert_eq!(deadlines.total, started + active + LSP_TOOL_CLEANUP_RESERVE);
    assert_eq!(deadlines.total - deadlines.active, LSP_TOOL_CLEANUP_RESERVE);
}

#[test]
fn one_tool_schema_exposes_the_three_typed_queries() {
    let schema = input_schema();
    // The schema names the three queries in prose because the registry's keyword allowlist has no
    // `enum`; the refusal of a fourth value is asserted against `parse_query_kind`, not here.
    let described = schema["properties"]["query"]["description"]
        .as_str()
        .expect("query carries a description");
    for query in ["definition", "references", "hover"] {
        assert!(
            described.contains(query),
            "{query} is not named: {described}"
        );
    }
    assert!(schema["properties"]["query"]["enum"].is_null());
    assert_eq!(
        schema["required"],
        json!(["query", "path", "line", "character"])
    );
}

#[test]
fn live_lsp_tools_are_effecting_code_execution_not_pure_reads() {
    let registry = Registry::coding_agent("/tmp/lsp-registration-only").unwrap();
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(registry.purity_of("lsp_query"), Some(Purity::Effecting));
        assert_eq!(
            registry.capability_of("lsp_query"),
            Some(Capability::CodeExecuting)
        );
    } else {
        assert!(registry.purity_of("lsp_query").is_none());
    }
    let read_only = Registry::read_only("/tmp/lsp-registration-only").unwrap();
    assert!(read_only.purity_of("lsp_query").is_none());
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
    assert_eq!(output["absolute_path_redactions"], 0);
}

#[test]
fn language_server_content_is_untrusted_even_when_confinement_succeeds() {
    assert_eq!(
        success("call".into(), "peer text".into()).trust,
        Trust::Untrusted
    );
}

#[tokio::test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn unsupported_live_surface_refuses_without_promoting_peer_output() {
    let registry = Registry::coding_agent("/tmp/lsp-registration-only").unwrap();
    let result = registry
        .run(ToolUse {
            id: "call-1".into(),
            name: "lsp_query".into(),
            input: json!({"query":"hover","path":"missing.rs","line":0,"character":0}),
        })
        .await;
    assert!(result.is_error);
    assert_eq!(result.trust, Trust::Workspace);
    assert!(!result.content.contains("/tmp/"));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[tokio::test]
async fn unsupported_platform_does_not_advertise_a_guaranteed_to_fail_tool() {
    let registry = Registry::coding_agent(env!("CARGO_MANIFEST_DIR")).unwrap();
    assert!(registry.purity_of("lsp_query").is_none());
}

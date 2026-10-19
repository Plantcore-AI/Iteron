pub use super::fixtures::*;
use super::*;
#[test]
fn actual_resolver_report_is_projected_without_raw_evidence_or_runtime_activation() {
    let view = simulate(&request_bytes()).unwrap();
    assert_eq!(view.status, "active resolution failed");
    assert_eq!(view.entries.len(), iteron_tunables::EXPECTED_FAMILY_COUNT);
    let encoded = serde_json::to_string(&view).unwrap();
    assert!(!encoded.contains(&"a".repeat(64)));
    assert!(!encoded.contains(&"b".repeat(64)));
    assert!(encoded.contains("\"redacted\":true"));
    assert!(simulate(b"{}").is_err());
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn native_request_read_is_bounded_and_preserves_exact_source() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "iteron-native-simulation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let bytes = request_bytes();
    std::fs::write(root.join("request.json"), &bytes).unwrap();
    assert_eq!(
        crate::client_effects::workspace_read::read(
            &root,
            "request.json",
            iteron_tunables::RESOLUTION_INPUT_MAX_BYTES
        )
        .unwrap(),
        bytes
    );
    assert!(
        crate::client_effects::workspace_read::read(
            &root,
            "../request.json",
            iteron_tunables::RESOLUTION_INPUT_MAX_BYTES
        )
        .is_err()
    );
    std::fs::write(
        root.join("large.json"),
        vec![b' '; iteron_tunables::RESOLUTION_INPUT_MAX_BYTES + 1],
    )
    .unwrap();
    assert!(
        crate::client_effects::workspace_read::read(
            &root,
            "large.json",
            iteron_tunables::RESOLUTION_INPUT_MAX_BYTES
        )
        .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

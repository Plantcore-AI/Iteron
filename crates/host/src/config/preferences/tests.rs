use super::*;
fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-config-default-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}
#[test]
fn actual_invalid_operator_document_is_not_installed_or_destroyed() {
    let root = scratch();
    let path = root.join("config.json");
    let original = b"{ user has an editable syntax error";
    std::fs::write(&path, original).unwrap();
    assert_eq!(
        UserPreferenceTarget(path.clone()).write_selected_model("actual-provider", "actual-model"),
        PreferenceWriteStatus::NotInstalled
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(unix, windows))]
#[test]
fn actual_default_install_preserves_operator_fields_and_returns_observed_native_result() {
    let root = scratch();
    let path = root.join("config.json");
    std::fs::write(&path, b"{\"effort\":\"low\",\"max_turns\":5}").unwrap();
    assert_eq!(
        UserPreferenceTarget(path.clone()).write_selected_model("actual-provider", "actual-model"),
        PreferenceWriteStatus::Installed
    );
    let installed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(installed["provider"], "actual-provider");
    assert_eq!(installed["model"], "actual-model");
    assert_eq!(installed["effort"], "low");
    assert_eq!(installed["max_turns"], 5);
    std::fs::remove_dir_all(root).unwrap();
}

use super::*;
fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-native-init-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    // macOS native temp roots contain a documented /var alias. Only the test fixture normalizes.
    root.canonicalize().unwrap()
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn actual_fixed_native_files_are_complete_and_existing_operator_bytes_are_preserved() {
    let root = scratch("exclusive");
    let make = || NativeProjectInit {
        workspace: root.clone(),
        run: RunId("native-init".into()),
        config: crate::config::starter_project_config(),
        admitted: true,
    };
    let first = make().execute();
    assert!(first.refusal.is_none());
    assert!(!first.unknown());
    assert!(
        first
            .entries
            .iter()
            .all(|entry| entry.status == InitStatus::Created)
    );
    assert_eq!(std::fs::read(root.join("AGENTS.md")).unwrap(), INSTRUCTIONS);
    assert_eq!(
        std::fs::read_to_string(root.join(".iteron/config.json")).unwrap(),
        crate::config::starter_project_config()
    );
    std::fs::write(root.join("AGENTS.md"), b"operator's real instructions").unwrap();
    let second = make().execute();
    assert!(
        second
            .entries
            .iter()
            .all(|entry| entry.status == InitStatus::Existing)
    );
    assert_eq!(
        std::fs::read(root.join("AGENTS.md")).unwrap(),
        b"operator's real instructions"
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn actual_linked_init_directory_cannot_redirect_or_create_external_files() {
    let root = scratch("link-root");
    let outside = scratch("link-outside");
    std::os::unix::fs::symlink(&outside, root.join(".iteron")).unwrap();
    let result = NativeProjectInit {
        workspace: root.clone(),
        run: RunId("native-init".into()),
        config: crate::config::starter_project_config(),
        admitted: true,
    }
    .execute();
    assert_eq!(result.entries[0].status, InitStatus::NotPublished);
    assert!(!outside.join("config.json").exists());
    assert!(!root.join("AGENTS.md").exists());
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}
#[test]
fn refused_actual_policy_does_not_create_even_the_directory() {
    let root = scratch("permission");
    let result = NativeProjectInit {
        workspace: root.clone(),
        run: RunId("native-init".into()),
        config: crate::config::starter_project_config(),
        admitted: false,
    }
    .execute();
    assert!(result.refusal.is_some());
    assert!(!root.join(".iteron").exists());
    assert!(!root.join("AGENTS.md").exists());
    std::fs::remove_dir_all(root).unwrap();
}

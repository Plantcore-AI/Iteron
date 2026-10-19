use super::*;
fn scratch() -> std::path::PathBuf {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "iteron-native-directory-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    root
}
#[test]
fn real_directory_has_independent_bounded_scans_and_create_only_full_bytes() {
    let root = scratch();
    let parent = NativeDirectory::open(&root).unwrap();
    assert!(parent.child("missing", false).unwrap().is_none());
    assert!(!root.join("missing").exists());
    let child = parent.child("requests", true).unwrap().unwrap();
    let bytes = vec![b'b'; 32 * 1024];
    assert_eq!(child.publish("retained.json", &bytes), Publication::Created);
    assert_eq!(
        child.publish("retained.json", b"other bytes"),
        Publication::Existing
    );
    assert_eq!(child.read("retained.json", bytes.len()).unwrap(), bytes);
    assert!(child.read("retained.json", bytes.len() - 1).is_err());
    for n in 0..12 {
        std::fs::write(root.join(format!("entry-{n}")), b"actual native entry").unwrap();
    }
    let (partial, truncated) = parent.list(2).unwrap();
    assert_eq!(partial.len(), 2);
    assert!(truncated);
    let (all, truncated) = parent.list(32).unwrap();
    assert_eq!(all.len(), 13);
    assert!(!truncated);
    assert!(all.iter().any(|row| row == &("requests".into(), true)));
    assert!(parent.child("../foreign", true).is_err());
    drop(child);
    drop(parent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn replaced_root_and_symlink_child_cannot_redirect_actual_publication() {
    let root = scratch();
    let parent = NativeDirectory::open(&root).unwrap();
    let child = parent.child("requests", true).unwrap().unwrap();
    let moved = root.with_extension("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(parent.list(8).is_err());
    assert_eq!(
        child.publish("blocked.json", b"old root"),
        Publication::NotPublished
    );
    assert!(!moved.join("requests/blocked.json").exists());
    drop(child);
    drop(parent);
    let outside = root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("requests")).unwrap();
    let parent = NativeDirectory::open(&root).unwrap();
    assert!(parent.child("requests", true).is_err());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    drop(parent);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(moved).unwrap();
}

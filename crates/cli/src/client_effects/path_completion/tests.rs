use super::*;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn actual_large_directory_scan_and_retained_cache_have_finite_byte_charges() {
    let (root, agent) = crate::client_effects::experiment_lab::tests::fixture();
    for n in 0..MAX_SCAN + 1 {
        std::fs::write(
            root.join(format!("candidate-{n:05}-{}", "x".repeat(180))),
            b"x",
        )
        .unwrap();
    }
    let source = CompletionSource::capture(&agent);
    let mut cache = CompletionCache::default();
    let rows = source.complete("candidate", &mut cache).unwrap();
    assert!(rows.incomplete);
    assert!(rows.items.len() <= 8);
    assert!(cache.bytes() <= MAX_CACHE_BYTES);
    assert!(
        cache
            .entries
            .iter()
            .all(|entry| entry.charge <= MAX_ENTRY_BYTES)
    );
    assert!(source.complete("../outside", &mut cache).is_err());
    assert!(source.complete("C:outside", &mut cache).is_err());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn native_bounded_lru_keeps_prefix_refinement_and_limits_distinct_directories() {
    let (root, agent) = crate::client_effects::experiment_lab::tests::fixture();
    let source = CompletionSource::capture(&agent);
    let mut cache = CompletionCache::default();
    for n in 0..MAX_ENTRIES + 3 {
        let dir = root.join(format!("dir-{n}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("native.txt"), b"x").unwrap();
        assert_eq!(
            source
                .complete(&format!("dir-{n}/na"), &mut cache)
                .unwrap()
                .items,
            vec![format!("dir-{n}/native.txt")]
        );
    }
    assert!(cache.entries.len() <= MAX_ENTRIES);
    assert!(cache.bytes() <= MAX_CACHE_BYTES);
    assert_eq!(
        source.complete("dir-34/nat", &mut cache).unwrap().items,
        vec!["dir-34/native.txt"]
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn warm_native_cache_revalidates_identity_and_never_follows_symlink_parent() {
    let (root, agent) = crate::client_effects::experiment_lab::tests::fixture();
    std::fs::create_dir(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/old.txt"), b"x").unwrap();
    let source = CompletionSource::capture(&agent);
    let mut cache = CompletionCache::default();
    assert_eq!(
        source.complete("dir/", &mut cache).unwrap().items,
        vec!["dir/old.txt"]
    );
    std::fs::rename(root.join("dir"), root.join("old-dir")).unwrap();
    std::fs::create_dir(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/current.txt"), b"x").unwrap();
    assert_eq!(
        source.complete("dir/", &mut cache).unwrap().items,
        vec!["dir/current.txt"]
    );
    std::fs::remove_dir_all(root.join("dir")).unwrap();
    std::os::unix::fs::symlink(root.join("old-dir"), root.join("dir")).unwrap();
    assert!(source.complete("dir/", &mut cache).is_err());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

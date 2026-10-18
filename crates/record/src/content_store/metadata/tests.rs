use super::*;
use crate::content_store::storage::{Layout, lock_store, lock_store_shared};
use crate::content_store::{
    ContentStoreError, PrivateContentClass, PrivateContentRetention,
    private_content_sources_for_run, put_private_content,
};
use iteron_protocol::{RunId, Seq, TenantId};

fn directory() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "iteron-compact-content-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ))
}

fn put(dir: &Path, run: &RunId, seq: u64, bytes: &[u8]) {
    put_private_content(
        dir,
        &TenantId::default(),
        run,
        Seq(seq),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        bytes,
        0,
    )
    .unwrap();
}

fn evict(scope: &Path) {
    INDEXES.get().unwrap().lock().unwrap().remove(scope);
}

// Retain the original parser as a compatibility oracle: optimization must not change which
// physical paths participate in the overlay or how its scope and normalized key are selected.
fn original_location(path: &Path) -> Option<(PathBuf, String)> {
    for root in path.ancestors() {
        if !matches!(
            root.file_name()?.to_str()?,
            "refs" | "run-refs" | "run-ref-lookup" | "lineage-from" | "lineage-to"
        ) {
            continue;
        }
        let scope = root.parent()?;
        if scope.parent()?.file_name()? != "v1"
            || scope.parent()?.parent()?.file_name()? != ".content"
        {
            continue;
        }
        let relative = path.strip_prefix(scope).ok()?;
        let parts = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        return Some((scope.to_path_buf(), parts.join("/")));
    }
    None
}

#[test]
fn metadata_location_preserves_original_path_and_scope_semantics() {
    let prefixes = ["", "/", "./", "../", "workspace/", "refs/", "目录/"];
    let scopes = [
        ".content/v1/tenant",
        ".content/./v1//tenant",
        ".content/v1/..",
        ".content/v1/.",
        ".content/v1",
        ".content/v2/tenant",
        "other/v1/tenant",
        ".content/v1/tenant/.content/v1/nested",
    ];
    let families = [
        "refs",
        "run-refs",
        "run-ref-lookup",
        "lineage-from",
        "lineage-to",
        "keys",
        "blobs",
        "revocations.json",
    ];
    let suffixes = [
        "",
        "/",
        "/owner",
        "/owner/member.json",
        "/owner/extra/member.json",
        "/owner/./member.json",
        "/owner/../member.json",
        "/../member.json",
        "/owner//member.json/",
        "/refs/member.json",
        "/所有者/成员.json",
        "/owner/.content/v1/inner/refs/other/member.json",
    ];
    for prefix in prefixes {
        for scope in scopes {
            for family in families {
                for suffix in suffixes {
                    let path = PathBuf::from(format!("{prefix}{scope}/{family}{suffix}"));
                    assert_eq!(location(&path), original_location(&path), "{path:?}");
                }
            }
        }
    }
    for path in ["", ".", "..", "/", "refs", "refs/member", "v1/tenant/refs"] {
        let path = Path::new(path);
        assert_eq!(location(path), original_location(path), "{path:?}");
    }
    let path = Path::new(".content/v1/tenant/refs/owner/member.json");
    assert_eq!(
        location(path),
        Some((
            PathBuf::from(".content/v1/tenant"),
            "refs/owner/member.json".into()
        ))
    );
    assert_eq!(location(Path::new(".content/v1/tenant/keys/digest")), None);
}

#[cfg(unix)]
#[test]
fn metadata_location_preserves_non_utf8_prefix_and_suffix_behavior() {
    use std::os::unix::ffi::OsStringExt;
    for bytes in [
        b"workspace/\xff/.content/v1/tenant/refs/owner/member".as_slice(),
        b".content/v1/\xff/refs/owner/member",
        b".content/v1/tenant/refs/\xff/member",
        b".content/v1/tenant/refs/owner/\xff",
        b".content/v1/tenant/refs/owner/deeper/\xff",
        b".content/\xff/tenant/refs/owner/member",
        b".content/v1/tenant/\xff/owner/member",
    ] {
        let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        assert_eq!(location(&path), original_location(&path), "{path:?}");
    }
}

#[cfg(windows)]
#[test]
fn metadata_location_preserves_windows_roots_and_separators() {
    for path in [
        r"C:\workspace\.content\v1\tenant\refs\owner\member",
        r"C:.content\v1\tenant\refs\owner\member",
        r"\\host\share\.content\v1\tenant\refs\owner\member",
        r"\\?\C:\workspace\.content\v1\tenant\refs\owner\member",
        r"C:\workspace/.content\v1/tenant\refs/owner\member",
    ] {
        let path = Path::new(path);
        assert_eq!(location(path), original_location(path), "{path:?}");
    }
}

#[test]
fn committed_reference_frame_succeeds_when_optional_stamp_is_unavailable() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let lease = lock_store(&layout).unwrap();
    let member = layout
        .run_reference_dir(&RunId("committed-stamp".into()))
        .join("edge.json");
    FAIL_COMMITTED_STAMP.with(|fail| fail.set(true));
    let result = replace_batch(&[(member.clone(), Some(b"committed member".to_vec()))]);
    drop(lease);
    FAIL_COMMITTED_STAMP.with(|fail| fail.set(false));
    result.unwrap();
    assert_eq!(read(&member, 64).unwrap(), b"committed member");
    // Reacquiring validates the on-disk prefix even though the optional write stamp was lost.
    let _lease = lock_store(&layout).unwrap();
    let mut reopened = Index::default();
    let (scope, relative) = location(&member).unwrap();
    reopened.refresh(&scope, false).unwrap();
    assert_eq!(
        reopened.entries[&relative].as_deref(),
        Some(b"committed member".as_slice())
    );
    drop(_lease);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exclusive_metadata_lease_reuses_log_and_reopens_after_compaction() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let scope = layout.refs.parent().unwrap();
    let members = layout.run_reference_dir(&RunId("leased-log".into()));
    {
        let _lease = lock_store(&layout).unwrap();
        replace_batch(&[(members.join("seed.json"), Some(vec![0]))]).unwrap();
    }
    let lease = lock_store(&layout).unwrap();
    let cached = with_index(scope, |index| Ok(index.write_lease)).unwrap();
    let (pin, _) = acquire_index(scope).unwrap();
    LOG_OPENS.with(|opens| opens.set(0));
    for number in [1, 2] {
        replace_batch(&[(members.join(format!("{number}.json")), Some(vec![number]))]).unwrap();
    }
    // Cache pressure may select the supported uncached path; a registered leased index is pinned.
    if cached {
        assert_eq!(LOG_OPENS.with(std::cell::Cell::get), 0);
        assert!(pin.lock().unwrap().writer.is_some());
    }
    with_index(scope, |index| index.compact(scope)).unwrap();
    if cached {
        assert!(pin.lock().unwrap().writer.is_none());
    }
    replace_batch(&[(members.join("3.json"), Some(vec![3]))]).unwrap();
    if cached {
        assert_eq!(LOG_OPENS.with(std::cell::Cell::get), 1);
    }
    drop(lease);
    {
        let index = pin.lock().unwrap();
        assert!(!index.write_lease);
        assert!(index.writer.is_none());
    }
    let _lease = lock_store_shared(&layout).unwrap();
    let mut reopened = Index::default();
    reopened.refresh(scope, false).unwrap();
    for number in [0, 1, 2, 3] {
        let name = if number == 0 {
            "seed.json".into()
        } else {
            format!("{number}.json")
        };
        let (_, relative) = location(&members.join(name)).unwrap();
        assert_eq!(
            reopened.entries[&relative].as_deref(),
            Some([number].as_slice())
        );
    }
    drop(_lease);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_final_stamp_replays_and_rejects_same_length_peer_corruption() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let scope = layout.refs.parent().unwrap();
    let lease = lock_store(&layout).unwrap();
    let member = layout
        .run_reference_dir(&RunId("stamp-replay".into()))
        .join("edge.json");
    FAIL_COMMITTED_STAMP.with(|fail| fail.set(true));
    let result = replace_batch(&[(member, Some(b"valid member".to_vec()))]);
    drop(lease);
    FAIL_COMMITTED_STAMP.with(|fail| fail.set(false));
    result.unwrap();
    let log = scope.join(LOG_NAME);
    let mut bytes = std::fs::read(&log).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    // Same physical inode and length; only a checksum replay can reject this changed prefix.
    std::fs::write(&log, bytes).unwrap();
    assert!(matches!(lock_store(&layout), Err(ContentStoreError::Io(_))));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn digest_reference_counts_merge_legacy_and_increment_without_rescanning() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let members = layout.refs.join("shared-digest");
    std::fs::create_dir(&members).unwrap();
    let legacy = members.join("legacy.json");
    std::fs::write(&legacy, b"legacy").unwrap();
    let _lease = lock_store(&layout).unwrap();
    let mut local = Index::default();
    assert_eq!(
        counts::count_with_local_index(&mut local, &members).unwrap(),
        1
    );
    #[cfg(unix)]
    let rebuilds = counts::REBUILDS.with(std::cell::Cell::get);
    for number in 1..=16 {
        replace_batch(&[(members.join(format!("{number}.json")), Some(vec![1]))]).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            number + 1
        );
    }
    #[cfg(unix)]
    assert_eq!(counts::REBUILDS.with(std::cell::Cell::get), rebuilds);
    for value in [
        Some(b"override".to_vec()),
        None,
        None,
        Some(b"restored".to_vec()),
    ] {
        let expected = if value.is_some() { 17 } else { 16 };
        replace_batch(&[(legacy.clone(), value)]).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            expected
        );
        assert_eq!(reference_count(&members).unwrap(), Some(expected));
        assert_eq!(read_dir(&members).unwrap().count(), expected);
    }
    drop(_lease);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn absent_legacy_directories_are_bounded_lease_facts_and_never_hide_peer_members() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let scope = layout.refs.parent().unwrap();
    let run_dir = layout.run_reference_dir(&RunId("absence-facts".into()));
    let directories = [
        run_dir.clone(),
        layout.refs.join("digest"),
        layout.run_ref_lookup.join("lookup"),
    ];
    let lease = lock_store(&layout).unwrap();
    let cached = with_index(scope, |index| Ok(index.write_lease)).unwrap();
    DIRECTORY_PROBES.with(|probes| probes.set(0));
    LEGACY_MEMBER_PROBES.with(|probes| probes.set(0));
    for directory in &directories {
        for name in ["first.json", "second.json"] {
            assert!(!is_file(&directory.join(name)).unwrap());
        }
    }
    if cached {
        assert_eq!(DIRECTORY_PROBES.with(std::cell::Cell::get), 3);
        assert_eq!(LEGACY_MEMBER_PROBES.with(std::cell::Cell::get), 0);
    }
    let logged = run_dir.join("logged.json");
    replace_batch(&[(logged.clone(), Some(b"logical member".to_vec()))]).unwrap();
    assert!(is_file(&logged).unwrap());
    assert_eq!(reference_count(&run_dir).unwrap(), Some(1));
    for number in 0..=MAX_LEASE_DIRECTORY_FACTS {
        assert!(
            !is_file(
                &layout
                    .refs
                    .join(format!("absent-{number}"))
                    .join("member.json")
            )
            .unwrap()
        );
    }
    assert!(
        with_index(scope, |index| Ok(index.lease_directories.len())).unwrap()
            <= MAX_LEASE_DIRECTORY_FACTS
    );
    with_index(scope, |index| index.compact(scope)).unwrap();
    assert!(with_index(scope, |index| Ok(index.lease_directories.is_empty())).unwrap());
    drop(lease);
    // A different lease may see migrated legacy files even if this process previously saw none.
    std::fs::create_dir(&run_dir).unwrap();
    let peer = run_dir.join("peer.json");
    std::fs::write(&peer, b"physical member").unwrap();
    let occupied = layout.run_ref_lookup.join("occupied");
    std::fs::write(&occupied, b"not a directory").unwrap();
    let _lease = lock_store(&layout).unwrap();
    assert!(is_file(&peer).unwrap());
    assert_eq!(reference_count(&run_dir).unwrap(), Some(2));
    assert_eq!(read_dir(&run_dir).unwrap().count(), 2);
    assert!(is_file(&occupied.join("member.json")).is_err());
    drop(_lease);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_run_counts_merge_legacy_and_track_actual_membership_without_rescanning() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let scope = layout.refs.parent().unwrap();
    let members = layout.run_reference_dir(&RunId("counted-legacy".into()));
    std::fs::create_dir(&members).unwrap();
    let legacy = members.join("legacy.json");
    let untouched = members.join("untouched.json");
    std::fs::write(&legacy, b"legacy").unwrap();
    std::fs::write(&untouched, b"untouched").unwrap();
    let _lock = lock_store(&layout).unwrap();
    replace_batch(&[(members.join("seed.json"), Some(b"seed".to_vec()))]).unwrap();
    let mut local = Index::default();
    assert_eq!(
        counts::count_with_local_index(&mut local, &members).unwrap(),
        3
    );
    #[cfg(unix)]
    let rebuilds = counts::REBUILDS.with(std::cell::Cell::get);
    let fresh = members.join("fresh.json");
    for (path, value, expected) in [
        (legacy.clone(), Some(b"override".to_vec()), 3),
        (legacy.clone(), None, 2),
        (legacy.clone(), None, 2),
        (fresh.clone(), Some(b"fresh".to_vec()), 3),
        (fresh.clone(), Some(b"changed".to_vec()), 3),
        (fresh, None, 2),
        (legacy.clone(), Some(b"recreated".to_vec()), 3),
    ] {
        replace_batch(&[(path, value)]).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            expected
        );
        assert_eq!(read_dir(&members).unwrap().count(), expected);
    }
    for number in 1..=64 {
        replace_batch(&[(members.join(format!("new-{number}.json")), Some(vec![1]))]).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            3 + number
        );
    }
    #[cfg(unix)]
    assert_eq!(counts::REBUILDS.with(std::cell::Cell::get), rebuilds);

    // Physical cleanup changes the legacy baseline. A tombstone must still suppress a legacy
    // file, and deleting a never-overridden legacy member must reduce the merged count.
    replace_batch(&[(legacy.clone(), None)]).unwrap();
    std::fs::remove_file(untouched).unwrap();
    assert_eq!(
        counts::count_with_local_index(&mut local, &members).unwrap(),
        65
    );
    std::fs::remove_file(legacy).unwrap();
    with_index(scope, |index| index.compact(scope)).unwrap();
    assert_eq!(
        counts::count_with_local_index(&mut local, &members).unwrap(),
        65
    );
    assert_eq!(read_dir(&members).unwrap().count(), 65);
    local = Index::default();
    assert_eq!(
        counts::count_with_local_index(&mut local, &members).unwrap(),
        65
    );
    drop(_lock);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_run_counts_refresh_peer_appends_and_replaced_snapshots() {
    let dir = directory();
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    let scope = layout.refs.parent().unwrap();
    let members = layout.run_reference_dir(&RunId("counted-peer".into()));
    let first = members.join("first.json");
    let second = members.join("second.json");
    let mut local = Index::default();
    {
        let _lock = lock_store(&layout).unwrap();
        replace_batch(&[(first.clone(), Some(vec![1]))]).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            1
        );
    }
    #[cfg(unix)]
    let rebuilds = counts::REBUILDS.with(std::cell::Cell::get);
    // The independent writer cache publishes through the actual process-shared lease and log,
    // as a peer process does. The local reader has not observed that committed tail yet.
    {
        let _lock = lock_store(&layout).unwrap();
        replace_batch(&[(second, Some(vec![2])), (first, None)]).unwrap();
    }
    {
        let _lock = lock_store(&layout).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            1
        );
        assert_eq!(read_dir(&members).unwrap().count(), 1);
        #[cfg(unix)]
        assert_eq!(counts::REBUILDS.with(std::cell::Cell::get), rebuilds);
    }
    {
        let _lock = lock_store(&layout).unwrap();
        with_index(scope, |index| index.compact(scope)).unwrap();
    }
    {
        let _lock = lock_store(&layout).unwrap();
        assert_eq!(
            counts::count_with_local_index(&mut local, &members).unwrap(),
            1
        );
        assert_eq!(read_dir(&members).unwrap().count(), 1);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_recovers_torn_tail_without_losing_committed_references() {
    let dir = directory();
    let run = RunId("compact-crash".into());
    put(&dir, &run, 1, b"first");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    let log = scope.join(LOG_NAME);
    assert_eq!(std::fs::read_dir(&layout.refs).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&layout.run_refs).unwrap().count(), 0);
    let committed = std::fs::metadata(&log).unwrap().len();
    // A full header and truncated payload model process death during write_all.
    let mut frame = Vec::new();
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&100u32.to_le_bytes());
    frame.extend_from_slice(&[0; 32]);
    frame.extend_from_slice(b"partial");
    OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(&frame)
        .unwrap();
    evict(scope);
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        1
    );
    assert!(
        std::fs::metadata(&log).unwrap().len() > committed,
        "shared readers do not truncate"
    );
    put(&dir, &run, 2, b"second");
    evict(scope);
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        2
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_rejects_corrupt_complete_frames_and_oversized_headers() {
    let dir = directory();
    let run = RunId("compact-corruption".into());
    put(&dir, &run, 1, b"first");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    let log = scope.join(LOG_NAME);
    let original = std::fs::read(&log).unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&log, corrupt).unwrap();
    evict(scope);
    assert!(matches!(
        lock_store_shared(&layout),
        Err(ContentStoreError::Io(_))
    ));
    let mut oversized = original;
    oversized.extend_from_slice(MAGIC);
    oversized.extend_from_slice(&u32::MAX.to_le_bytes());
    oversized.extend_from_slice(&[0; 32]);
    std::fs::write(&log, oversized).unwrap();
    evict(scope);
    assert!(matches!(lock_store(&layout), Err(ContentStoreError::Io(_))));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_merges_legacy_files_and_keeps_deleted_members_deleted() {
    let dir = directory();
    let run = RunId("compact-legacy".into());
    put(&dir, &run, 1, b"legacy");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    // Materialize the old layout, then discard the new log to simulate an actual old store.
    let entries = with_index(scope, |index| Ok(index.entries.clone())).unwrap();
    for (relative, value) in entries {
        let path = scope.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value.unwrap()).unwrap();
    }
    std::fs::remove_file(scope.join(LOG_NAME)).unwrap();
    evict(scope);
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        1
    );
    put(&dir, &run, 2, b"compact");
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        2
    );
    let path = read_dir(layout.run_reference_dir(&run))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    {
        let _lock = lock_store(&layout).unwrap();
        replace_batch(&[(path.clone(), None)]).unwrap();
    }
    evict(scope);
    let _lock = lock_store_shared(&layout).unwrap();
    assert!(!is_file(&path).unwrap());
    assert_eq!(
        read(&path, 4096).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(read_dir(layout.run_reference_dir(&run)).unwrap().count(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_cross_process_writer_is_visible_to_cached_reader() {
    const CHILD_DIR: &str = "ITERON_COMPACT_METADATA_TEST_CHILD";
    let run = RunId("compact-process".into());
    if let Some(dir) = std::env::var_os(CHILD_DIR) {
        put(Path::new(&dir), &run, 2, b"child");
        return;
    }
    let dir = directory();
    put(&dir, &run, 1, b"parent");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "content_store::metadata::tests::compact_metadata_cross_process_writer_is_visible_to_cached_reader", "--test-threads=1"])
        .env(CHILD_DIR, &dir).output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        2
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_rejects_cross_tenant_and_path_escape_mutations() {
    let first = directory();
    let second = directory();
    let run = RunId("compact-scope".into());
    put(&first, &run, 1, b"one");
    put(&second, &run, 1, b"two");
    let left = Layout::new(&first, &TenantId::default());
    let right = Layout::new(&second, &TenantId::default());
    let _lock = lock_store(&left).unwrap();
    assert!(
        replace_batch(&[
            (left.run_reference_dir(&run).join("one.json"), Some(vec![1])),
            (
                right.run_reference_dir(&run).join("two.json"),
                Some(vec![2])
            ),
        ])
        .is_err()
    );
    assert!(
        replace_batch(&[(
            left.run_reference_dir(&run).join("../escape"),
            Some(vec![1])
        )])
        .is_err()
    );
    std::fs::remove_dir_all(first).unwrap();
    std::fs::remove_dir_all(second).unwrap();
}

#[cfg(unix)]
#[test]
fn compact_metadata_rejects_linked_log_files_without_touching_the_target() {
    let dir = directory();
    let run = RunId("compact-links".into());
    put(&dir, &run, 1, b"one");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    let log = scope.join(LOG_NAME);
    let original = std::fs::read(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    let target = dir.join("unrelated");
    std::fs::write(&target, &original).unwrap();
    std::os::unix::fs::symlink(&target, &log).unwrap();
    evict(scope);
    assert!(lock_store(&layout).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), original);
    std::fs::remove_file(&log).unwrap();
    std::fs::hard_link(&target, &log).unwrap();
    evict(scope);
    assert!(lock_store(&layout).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), original);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_legacy_cleanup_removes_physical_reverse_edges() {
    let dir = directory();
    let run = RunId("compact-legacy-release".into());
    put(&dir, &run, 1, b"legacy cleanup");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    let entries = with_index(scope, |index| Ok(index.entries.clone())).unwrap();
    for (relative, value) in entries {
        let path = scope.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value.unwrap()).unwrap();
    }
    std::fs::remove_file(scope.join(LOG_NAME)).unwrap();
    evict(scope);
    assert_eq!(
        crate::content_store::release_private_content_for_run(&dir, &TenantId::default(), &run)
            .unwrap(),
        1
    );
    assert!(!layout.run_reference_dir(&run).exists());
    evict(scope);
    assert!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_cache_pressure_does_not_reject_another_tenant() {
    const CHILD: &str = "ITERON_COMPACT_METADATA_PRESSURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "content_store::metadata::tests::compact_metadata_cache_pressure_does_not_reject_another_tenant", "--test-threads=1"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let run = RunId("compact-cache-pressure".into());
    let mut retained = Vec::new();
    let mut directories = Vec::new();
    for _ in 0..MAX_CACHED_STORES {
        let dir = directory();
        put(&dir, &run, 1, b"held tenant");
        let layout = Layout::new(&dir, &TenantId::default());
        let scope = layout.refs.parent().unwrap();
        retained.push(
            INDEXES
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .get(scope)
                .unwrap()
                .clone(),
        );
        directories.push(dir);
    }
    let uncached = directory();
    put(&uncached, &run, 1, b"uncached tenant");
    assert_eq!(
        private_content_sources_for_run(&uncached, &TenantId::default(), &run)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        INDEXES.get().unwrap().lock().unwrap().len(),
        MAX_CACHED_STORES
    );
    drop(retained);
    directories.push(uncached);
    for dir in directories {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn compact_metadata_migration_fences_old_decoders_before_publication() {
    use crate::content_store::model::{ContentTombstone, RevocationState};
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyState {
        version: u16,
        generation: u64,
        tombstones: Vec<ContentTombstone>,
    }
    let dir = directory();
    let run = RunId("compact-fence".into());
    let layout = Layout::new(&dir, &TenantId::default());
    crate::content_store::storage::ensure_layout(&layout).unwrap();
    std::fs::write(
        &layout.state,
        serde_json::to_vec(&RevocationState::empty()).unwrap(),
    )
    .unwrap();
    let before = std::fs::read(&layout.state).unwrap();
    let legacy: LegacyState = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        (legacy.version, legacy.generation, legacy.tombstones.len()),
        (1, 0, 0)
    );
    assert!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read(&layout.state).unwrap(),
        before,
        "legacy reads do not migrate"
    );
    {
        let _lock = lock_store(&layout).unwrap();
        assert!(!layout.refs.parent().unwrap().join(LOG_NAME).exists());
        let bytes = std::fs::read(&layout.state).unwrap();
        assert_eq!(
            serde_json::from_slice::<RevocationState>(&bytes)
                .unwrap()
                .metadata_format,
            Some(2)
        );
        assert!(serde_json::from_slice::<LegacyState>(&bytes).is_err());
    }
    put(&dir, &run, 1, b"new content");
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        1
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_reclaims_deleted_members_and_preserves_revocation_lineage() {
    use crate::content_store::{
        ContentRevocationGuard, PrivateContentDerivativeStore, PrivateContentNamespace,
        PrivateContentSource,
    };
    let dir = directory();
    let tenant = TenantId::default();
    let run = RunId("compact-retained".into());
    let source = put_private_content(
        &dir,
        &tenant,
        &run,
        Seq(1),
        PrivateContentClass::Transcript,
        PrivateContentRetention::Session,
        b"retained root",
        0,
    )
    .unwrap();
    let derivative = PrivateContentDerivativeStore::open_registered(
        &dir,
        tenant.clone(),
        RunId("compact-derived".into()),
        PrivateContentNamespace::ToolArtifact,
        PrivateContentClass::ToolOutput,
        PrivateContentRetention::Session,
        1024,
    )
    .unwrap();
    let handle = derivative
        .put_derived(
            Seq(2),
            b"retained derived",
            &[PrivateContentSource {
                owner: run.clone(),
                digest: source.digest.clone(),
            }],
        )
        .unwrap();
    let layout = Layout::new(&dir, &tenant);
    let scope = layout.refs.parent().unwrap();
    let log = scope.join(LOG_NAME);
    {
        let _lock = lock_store(&layout).unwrap();
        let changes = (0..COMPACT_DELETED_ENTRIES)
            .map(|number| {
                (
                    layout
                        .refs
                        .join("temporary-index")
                        .join(format!("{number}.json")),
                    Some(vec![b'1']),
                )
            })
            .collect::<Vec<_>>();
        replace_batch(&changes).unwrap();
        let removals = changes
            .into_iter()
            .map(|(path, _)| (path, None))
            .collect::<Vec<_>>();
        replace_batch(&removals).unwrap();
    }
    let before = std::fs::metadata(&log).unwrap().len();
    put(&dir, &run, 3, b"post-compaction");
    assert!(std::fs::metadata(&log).unwrap().len() < before / 2);
    evict(scope);
    assert_eq!(
        derivative.read_at(Seq(2), &handle).unwrap(),
        b"retained derived"
    );
    drop(derivative);
    let guard = ContentRevocationGuard::begin(&dir, &tenant, source.digest)
        .unwrap()
        .unwrap();
    guard
        .tombstone(
            &iteron_protocol::ErasureOperationId::new("compact-revoke").unwrap(),
            &iteron_protocol::ErasureAuthorityId::new("operator.test").unwrap(),
            1,
        )
        .unwrap();
    guard.shred().unwrap();
    guard.propagate().unwrap();
    assert!(guard.verify().unwrap().coverage.is_complete());
    drop(guard);
    assert!(matches!(
        crate::content_store::guard_private_content(&dir, &tenant, &handle.digest),
        Err(ContentStoreError::Revoked { .. })
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_reference_release_reclaims_its_lookup_on_snapshot() {
    let dir = directory();
    let run = RunId("compact-delete-lookup".into());
    put(&dir, &run, 1, b"released");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    assert_eq!(
        crate::content_store::release_private_content_for_run(&dir, &TenantId::default(), &run)
            .unwrap(),
        1
    );
    {
        let _lock = lock_store(&layout).unwrap();
        with_index(scope, |index| index.compact(scope)).unwrap();
    }
    evict(scope);
    assert!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        with_index(scope, |index| Ok(index.entries.len())).unwrap(),
        0
    );
    put(&dir, &run, 2, b"recreated");
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        1
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compact_metadata_snapshot_survives_process_exit_before_and_after_rename() {
    const CHILD_DIR: &str = "ITERON_COMPACT_SNAPSHOT_CHILD_DIR";
    const CHILD_AFTER: &str = "ITERON_COMPACT_SNAPSHOT_CHILD_AFTER";
    if let Some(dir) = std::env::var_os(CHILD_DIR) {
        let layout = Layout::new(Path::new(&dir), &TenantId::default());
        let _lock = lock_store(&layout).unwrap();
        let scope = layout.refs.parent().unwrap();
        snapshot::EXIT_AT_REPLACE
            .with(|exit| exit.set(Some(std::env::var_os(CHILD_AFTER).is_some())));
        with_index(scope, |index| index.compact(scope)).unwrap();
        panic!("snapshot process-exit injection did not fire");
    }
    let dir = directory();
    let run = RunId("compact-snapshot-crash".into());
    put(&dir, &run, 1, b"root");
    let layout = Layout::new(&dir, &TenantId::default());
    let scope = layout.refs.parent().unwrap();
    // Add harmless overwritten history so the replacement necessarily has a different prefix.
    let edge = read_dir(layout.run_reference_dir(&run))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    {
        let _lock = lock_store(&layout).unwrap();
        let value = read(&edge, 4096).unwrap();
        replace_batch(&[(edge, Some(value))]).unwrap();
    }
    let before = std::fs::metadata(scope.join(LOG_NAME)).unwrap().len();
    for after in [false, true] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "content_store::metadata::tests::compact_metadata_snapshot_survives_process_exit_before_and_after_rename", "--test-threads=1"])
            .env(CHILD_DIR, &dir);
        if after {
            command.env(CHILD_AFTER, "1");
        } else {
            command.env_remove(CHILD_AFTER);
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if after { 78 } else { 77 }),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            private_content_sources_for_run(&dir, &TenantId::default(), &run)
                .unwrap()
                .len(),
            1
        );
        if !after {
            assert_eq!(
                std::fs::metadata(scope.join(LOG_NAME)).unwrap().len(),
                before
            );
        }
    }
    put(&dir, &run, 2, b"resumed");
    evict(scope);
    assert_eq!(
        private_content_sources_for_run(&dir, &TenantId::default(), &run)
            .unwrap()
            .len(),
        2
    );
    std::fs::remove_dir_all(dir).unwrap();
}

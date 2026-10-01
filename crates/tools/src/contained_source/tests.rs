use super::*;
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::symlink},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
fn workspace(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-contained-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}
#[test]
fn ordinary_source_is_bounded_and_fifo_leaf_never_waits_for_writer() {
    let root = workspace("fifo");
    std::fs::write(root.join("source.js"), "return 7;").unwrap();
    assert_eq!(
        read_contained_utf8(&root, Path::new("source.js"), 64).unwrap(),
        "return 7;"
    );
    assert!(read_contained_utf8(&root, Path::new("source.js"), 2).is_err());
    let path = CString::new(root.join("fifo.js").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let now = Instant::now();
    assert!(read_contained_utf8(&root, Path::new("fifo.js"), 64).is_err());
    assert!(now.elapsed() < Duration::from_secs(1));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn symlink_parent_and_retained_root_replacement_are_refused() {
    let root = workspace("scope");
    let outside = workspace("outside");
    std::fs::write(outside.join("source.js"), "private outside").unwrap();
    symlink(&outside, root.join("link")).unwrap();
    assert!(read_contained_utf8(&root, Path::new("link/source.js"), 64).is_err());
    std::fs::write(root.join("source.js"), "admitted").unwrap();
    let held = crate::lsp::capability::RootBinding::open(&root).unwrap();
    let source = held.bind_source(Path::new("source.js")).unwrap();
    let moved = root.with_extension("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("source.js"), "replacement").unwrap();
    assert!(!source.still_visible(&held));
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(moved).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}

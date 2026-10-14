use super::{BarrierSide, pin, pin_with_barrier};
use crate::ControllerStoreError;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-cohort-namespace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn uncertain_child_or_parent_barrier_never_returns_a_live_writer_pin() {
    for failing in [BarrierSide::Child, BarrierSide::Parent] {
        let directory = Directory::new();
        let leaf = directory.0.join("new-private-state");
        let mut observed_child = false;
        let result = pin_with_barrier(&leaf, true, |file, created, side| {
            if created && side == BarrierSide::Child {
                observed_child = true;
            }
            if created && side == failing {
                return Err(std::io::Error::other("injected namespace barrier refusal"));
            }
            file.sync_all()
        });
        assert!(matches!(result, Err(ControllerStoreError::OutcomeUnknown)));
        assert!(observed_child);
        assert!(leaf.is_dir());
        assert!(!leaf.join("agents.json").exists());
        assert!(!leaf.join("agents.lock").exists());
        // A later verified existing-only open needs its own real barriers; no fabricated proof
        // escapes the uncertain call and no record/controller/model existed in that call.
        let pinned = pin(&leaf, false).unwrap();
        assert_eq!(
            pinned.directory.metadata().unwrap().ino(),
            fs::metadata(&leaf).unwrap().ino()
        );
    }
}

#[test]
fn existing_state_beneath_a_symlink_ancestor_is_rejected_without_touching_target() {
    let directory = Directory::new();
    let target = Directory::new();
    let private = target.0.join("state");
    fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
    symlink(&target.0, directory.0.join("alias")).unwrap();
    assert!(matches!(
        pin(&directory.0.join("alias/state"), false),
        Err(ControllerStoreError::Unavailable)
    ));
    assert!(matches!(
        pin(&directory.0.join("alias/new-state"), true),
        Err(ControllerStoreError::Unavailable)
    ));
    assert!(!target.0.join("new-state").exists());
    assert!(!private.join("agents.lock").exists());
}

#[test]
fn creation_is_leaf_only_and_path_work_is_bounded() {
    let directory = Directory::new();
    assert!(pin(&directory.0.join("missing-parent/state"), true).is_err());
    assert!(!directory.0.join("missing-parent").exists());
    let too_deep = directory.0.join("a/".repeat(65)).join("state");
    assert!(pin(&too_deep, true).is_err());
    assert!(!directory.0.join("a").exists());
    let parent_escape = directory.0.join("../state");
    assert!(pin(&parent_escape, true).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn native_protected_temp_alias_is_supported_without_allowing_user_aliases() {
    let directory = Directory::new();
    assert!(pin(&directory.0, false).is_ok());
    let literal = std::path::Path::new("/tmp").join(directory.0.file_name().unwrap());
    // Native temp_dir may use /var/folders, so only the matching shipped /tmp namespace is
    // asserted if this fixture actually lives under it.
    if fs::metadata(&literal).is_ok() {
        assert!(pin(&literal, false).is_ok());
    }
}

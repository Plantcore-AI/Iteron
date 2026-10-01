use super::*;
use std::path::PathBuf;
fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-workspace-publication-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    root
}
fn dacl(file: &File) -> Vec<u8> {
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: live handle, real allocated security descriptor, aligned outputs; ACL bounds supplied
    // by the native API remain live until LocalAllocation frees the returned descriptor.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let allocation = super::super::LocalAllocation(descriptor);
    assert!(!acl.is_null());
    let bytes =
        unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), usize::from((*acl).AclSize)) }
            .to_vec();
    drop(allocation);
    bytes
}
#[test]
fn exact_workspace_publication_preserves_acl_collision_and_pinned_namespace() {
    let root = scratch("exclusive");
    let moved = root.with_extension("moved");
    let publisher = WindowsWorkspacePublisher::open(&root).unwrap();
    let parent = publisher.directories.last().unwrap();
    let before = dacl(parent);
    assert!(
        std::fs::rename(&root, &moved).is_err(),
        "retained no-delete-share root refuses replacement"
    );
    publisher
        .publish("report-中文.md", b"actual complete transcript", [1; 16])
        .unwrap();
    assert_eq!(
        dacl(parent),
        before,
        "workspace DACL is not tightened or rewritten"
    );
    assert_eq!(
        std::fs::read(root.join("report-中文.md")).unwrap(),
        b"actual complete transcript"
    );
    assert_eq!(
        publisher.publish("report-中文.md", b"replacement", [2; 16]),
        Err(WorkspacePublishError::Exists)
    );
    assert_eq!(
        std::fs::read(root.join("report-中文.md")).unwrap(),
        b"actual complete transcript"
    );
    publisher.publish("empty.md", b"", [3; 16]).unwrap();
    assert_eq!(
        std::fs::read_dir(&root).unwrap().count(),
        2,
        "all exact private stages are gone"
    );
    drop(publisher);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn actual_publication_before_lost_namespace_barrier_remains_unknown_and_preserved() {
    fn refuse(_: &File) -> Result<(), WindowsStateError> {
        Err(WindowsStateError::OutcomeUnknown)
    }
    let root = scratch("lost-barrier");
    let publisher = WindowsWorkspacePublisher::open(&root).unwrap();
    assert_eq!(
        publisher.publish_with_barrier("may-remain.md", b"full actual bytes", [4; 16], refuse),
        Err(WorkspacePublishError::OutcomeUnknown)
    );
    assert_eq!(
        std::fs::read(root.join("may-remain.md")).unwrap(),
        b"full actual bytes",
        "an Unknown receipt does not delete the real published file"
    );
    drop(publisher);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn win32_namespace_aliases_refuse_before_creating_staged_content() {
    let root = scratch("aliases");
    let publisher = WindowsWorkspacePublisher::open(&root).unwrap();
    for name in [
        "../outside",
        "x:stream",
        "CON.txt",
        "tail.",
        "tail ",
        "dir\\file",
        "NUL",
        "",
    ] {
        assert_eq!(
            publisher.publish(name, b"unreachable", [5; 16]),
            Err(WorkspacePublishError::NotPublished)
        );
    }
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    drop(publisher);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ancestor_reparse_is_refused_without_rewriting_or_following_it() {
    use std::os::windows::fs::symlink_dir;
    let root = scratch("reparse");
    std::fs::create_dir(root.join("actual")).unwrap();
    symlink_dir(root.join("actual"), root.join("redirect"))
        .expect("native reparse fixture requires symlink capability");
    assert!(WindowsWorkspacePublisher::open(&root.join("redirect")).is_err());
    assert!(
        std::fs::read_dir(root.join("actual"))
            .unwrap()
            .next()
            .is_none()
    );
    std::fs::remove_dir(root.join("redirect")).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

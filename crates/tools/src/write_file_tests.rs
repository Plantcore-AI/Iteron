use super::*;
use crate::{Memo, Registry};
use core_protocol::{Capability, Purity, ToolUse};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-write-file-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn editing_only_registry(root: &Path) -> Registry {
    let mut registry = Registry {
        tools: Vec::new(),
        root: root.to_path_buf(),
        memo: std::sync::Arc::new(Memo::default()),
        sensitive_env_names: Default::default(),
        confine_execution: Default::default(),
    };
    crate::edit::register(&mut registry).unwrap();
    register(&mut registry).unwrap();
    registry
}

fn write_call(id: &str, path: &str, content: &str) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "write_file".into(),
        input: serde_json::json!({"path": path, "content": content}),
    }
}

fn transaction_files(parent: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".core-write-"))
        })
        .collect()
}

#[tokio::test]
async fn d3_01_g1_scaffolds_and_replaces_without_bash() {
    let root = TestRoot::new("scaffold");
    let registry = editing_only_registry(&root.0);
    let effecting: Vec<_> = registry
        .specs()
        .into_iter()
        .filter(|spec| spec.purity == Purity::Effecting)
        .map(|spec| spec.name)
        .collect();
    assert_eq!(effecting, ["edit", "write_file"]);
    assert!(registry.purity_of("bash").is_none());

    let created = registry
        .run(write_call(
            "create",
            "src/generated/mod.rs",
            "pub fn answer() -> u8 { 42 }\n",
        ))
        .await;
    assert!(!created.is_error, "{}", created.content);
    let canonical_file = root.0.canonicalize().unwrap().join("src/generated/mod.rs");
    assert_eq!(
        std::fs::read_to_string(&canonical_file).unwrap(),
        "pub fn answer() -> u8 { 42 }\n"
    );

    let replaced = registry
        .run(write_call(
            "replace",
            "src/generated/mod.rs",
            "pub fn answer() -> u8 { 43 }\n",
        ))
        .await;
    assert!(!replaced.is_error, "{}", replaced.content);
    assert_eq!(
        std::fs::read_to_string(&canonical_file).unwrap(),
        "pub fn answer() -> u8 { 43 }\n"
    );
    let names: Vec<_> = std::fs::read_dir(canonical_file.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from("mod.rs")]);

    let spec = registry
        .specs()
        .into_iter()
        .find(|spec| spec.name == "write_file")
        .unwrap();
    assert_eq!(spec.purity, Purity::Effecting);
    assert_eq!(spec.capability, Capability::ReversibleLocal);
    assert_eq!(
        spec.input_schema["required"],
        serde_json::json!(["path", "content"])
    );
    assert_eq!(spec.input_schema["properties"]["path"]["type"], "string");
}

#[tokio::test]
async fn d3_01_g2_parent_traversal_writes_outside_the_workspace() {
    // Owner-directed 2026-08-05: `write_file` addresses the host. This test is retained inverted
    // rather than deleted, so the surrendered guarantee stays visible in the suite — a `..` write
    // now lands on real bytes outside the workspace, and that is the accepted behaviour.
    let root = TestRoot::new("traversal-root");
    let outside = TestRoot::new("traversal-outside");
    let outside_name = outside.0.file_name().unwrap().to_string_lossy();
    let requested = format!("../{outside_name}/escaped.txt");
    let registry = editing_only_registry(&root.0);

    let result = registry
        .run(write_call("traversal", &requested, "written outside"))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(
        std::fs::read_to_string(outside.0.join("escaped.txt")).unwrap(),
        "written outside"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn d3_01_g2_symlink_out_of_the_workspace_writes_through_to_its_target() {
    // Retained inverted: a symlink committed to an untrusted repository is now a working pointer
    // out of it. That is the accepted cost of host-wide path authority (owner-directed
    // 2026-08-05), and it is asserted here rather than left as an untested consequence.
    let root = TestRoot::new("symlink-root");
    let outside = TestRoot::new("symlink-outside");
    std::os::unix::fs::symlink(&outside.0, root.0.join("escape")).unwrap();
    let registry = editing_only_registry(&root.0);

    let result = registry
        .run(write_call(
            "symlink-escape",
            "escape/escaped.txt",
            "written through the link",
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(
        std::fs::read_to_string(outside.0.join("escaped.txt")).unwrap(),
        "written through the link"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dangling_symlink_target_is_refused_instead_of_replaced() {
    let root = TestRoot::new("dangling-root");
    let outside = TestRoot::new("dangling-outside");
    let outside_target = outside.0.join("not-created.txt");
    std::os::unix::fs::symlink(&outside_target, root.0.join("dangling.txt")).unwrap();
    let registry = editing_only_registry(&root.0);

    let result = registry
        .run(write_call("dangling", "dangling.txt", "must not escape"))
        .await;

    assert!(result.is_error);
    assert!(result.content.contains("dangling symlink"));
    assert!(!outside_target.exists());
    assert!(
        std::fs::symlink_metadata(root.0.join("dangling.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[tokio::test]
async fn d3_01_g3_bidi_content_and_zero_width_path_are_refused() {
    let root = TestRoot::new("unicode");
    let registry = editing_only_registry(&root.0);

    let content_result = registry
        .run(write_call(
            "bidi-content",
            "safe.txt",
            "visible\u{202e}hidden",
        ))
        .await;
    assert!(content_result.is_error);
    assert!(content_result.content.contains("U+202E"));
    assert!(content_result.content.contains("content"));
    assert!(!root.0.join("safe.txt").exists());

    let deceptive_path = "src/zero\u{200b}width.rs";
    let path_result = registry
        .run(write_call(
            "zero-width-path",
            deceptive_path,
            "safe content",
        ))
        .await;
    assert!(path_result.is_error);
    assert!(path_result.content.contains("U+200B"));
    assert!(path_result.content.contains("path"));
    assert!(
        !root.0.join("src").exists(),
        "Unicode rejection must happen before parent directories are created"
    );
}

#[tokio::test]
async fn d3_05_g1_fault_before_rename_keeps_original_byte_identical() {
    let root = TestRoot::new("fault-before-rename");
    let target = root.0.join("state.txt");
    let original = b"original bytes\nwith a second line\n".to_vec();
    std::fs::write(&target, &original).unwrap();

    let staged = StagedWrite::prepare(&target, b"replacement bytes\n")
        .await
        .unwrap();
    let temporary = staged.temporary_path().to_path_buf();
    assert_eq!(temporary.parent(), target.parent());
    assert_eq!(std::fs::read(&temporary).unwrap(), b"replacement bytes\n");

    let failure = staged.commit_with_fault_before_rename().await.unwrap_err();

    assert!(!failure.target_replaced);
    assert!(failure.error.to_string().contains("injected fault"));
    assert_eq!(std::fs::read(&target).unwrap(), original);
    assert!(
        !temporary.exists(),
        "failed transaction must clean its temp file"
    );
}

#[tokio::test]
async fn d3_05_g2_edit_stages_same_directory_then_renames_over_target() {
    let root = TestRoot::new("edit-atomic-rename");
    let target = root.0.join("note.txt");
    let original = b"before\nkeep\n";
    std::fs::write(&target, original).unwrap();
    let canonical_target = target.canonicalize().unwrap();
    let observed_temporary = std::sync::Mutex::new(None::<PathBuf>);
    #[cfg(unix)]
    let observed_identity = std::sync::Mutex::new(None::<(u64, u64)>);

    crate::edit::edit_workspace_file_with_hook(
        &root.0,
        "note.txt",
        "before",
        "after",
        |commit_target| {
            assert_eq!(commit_target, canonical_target);
            assert_eq!(std::fs::read(commit_target).unwrap(), original);
            let temporary = transaction_files(commit_target.parent().unwrap());
            assert_eq!(temporary.len(), 1);
            assert_eq!(temporary[0].parent(), commit_target.parent());
            assert_eq!(std::fs::read(&temporary[0]).unwrap(), b"after\nkeep\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;

                let metadata = std::fs::metadata(&temporary[0]).unwrap();
                *observed_identity.lock().unwrap() = Some((metadata.dev(), metadata.ino()));
            }
            *observed_temporary.lock().unwrap() = Some(temporary[0].clone());
        },
    )
    .await
    .unwrap();

    let temporary = observed_temporary.into_inner().unwrap().unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"after\nkeep\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let expected_identity = observed_identity.into_inner().unwrap().unwrap();
        let committed = std::fs::metadata(&target).unwrap();
        assert_eq!((committed.dev(), committed.ino()), expected_identity);
    }
    assert!(!temporary.exists());
    assert!(transaction_files(&root.0).is_empty());
}

#[tokio::test]
async fn d3_05_g3_edit_refuses_change_after_anchor_snapshot() {
    let root = TestRoot::new("edit-concurrent-change");
    let target = root.0.join("note.txt");
    std::fs::write(&target, b"matched anchor\nkeep\n").unwrap();

    let error = crate::edit::edit_workspace_file_with_hook(
        &root.0,
        "note.txt",
        "matched anchor",
        "agent replacement",
        |commit_target| {
            std::fs::write(commit_target, b"operator replacement\nkeep\n").unwrap();
        },
    )
    .await
    .unwrap_err();
    let structured: serde_json::Value = serde_json::from_str(&error).unwrap();

    assert_eq!(structured["error"], "edit_failed");
    assert_eq!(structured["kind"], "file_changed");
    assert_eq!(structured["phase"], "precommit");
    assert_eq!(structured["path"], "note.txt");
    assert!(structured["message"].as_str().unwrap().contains("re-read"));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"operator replacement\nkeep\n"
    );
    assert!(transaction_files(&root.0).is_empty());
}

#[tokio::test]
async fn d3_05_g3_write_refuses_change_during_staging_window() {
    let root = TestRoot::new("write-concurrent-change");
    let target = root.0.join("note.txt");
    std::fs::write(&target, b"initial\n").unwrap();

    let error = write_workspace_file_with_hook(
        &root.0,
        "note.txt",
        "agent replacement\n",
        |commit_target| {
            std::fs::write(commit_target, b"operator replacement\n").unwrap();
        },
    )
    .await
    .unwrap_err();
    let structured: serde_json::Value = serde_json::from_str(&error).unwrap();

    assert_eq!(structured["error"], "write_file_failed");
    assert_eq!(structured["kind"], "file_changed");
    assert_eq!(structured["phase"], "precommit");
    assert_eq!(std::fs::read(&target).unwrap(), b"operator replacement\n");
    assert!(transaction_files(&root.0).is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn d3_05_g4_edit_and_write_preserve_unix_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestRoot::new("preserve-mode");
    let edit_target = root.0.join("edit.txt");
    let write_target = root.0.join("write.txt");
    std::fs::write(&edit_target, b"before\n").unwrap();
    std::fs::write(&write_target, b"before\n").unwrap();
    std::fs::set_permissions(&edit_target, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::set_permissions(&write_target, std::fs::Permissions::from_mode(0o751)).unwrap();

    crate::edit::edit_workspace_file_with_hook(&root.0, "edit.txt", "before", "after", |_| {})
        .await
        .unwrap();
    write_workspace_file_with_hook(&root.0, "write.txt", "after\n", |_| {})
        .await
        .unwrap();

    assert_eq!(
        std::fs::metadata(&edit_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        std::fs::metadata(&write_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o751
    );
}

#[tokio::test]
async fn d3_05_transaction_snapshot_is_bounded_before_staging() {
    let root = TestRoot::new("snapshot-bound");
    let target = root.0.join("large.txt");
    let oversized = vec![b'a'; MAX_FILE_TRANSACTION_BYTES + 1];
    std::fs::write(&target, &oversized).unwrap();

    let error = crate::edit::edit_workspace_file_with_hook(&root.0, "large.txt", "a", "b", |_| {
        panic!("oversized snapshots must be refused before staging")
    })
    .await
    .unwrap_err();

    assert!(error.contains("transaction limit"));
    assert_eq!(std::fs::read(&target).unwrap(), oversized);
    assert!(transaction_files(&root.0).is_empty());
}

#[tokio::test]
async fn d3_05_transaction_replacement_is_bounded_before_temp_creation() {
    let root = TestRoot::new("replacement-bound");
    let target = root.0.join("state.txt");
    std::fs::write(&target, b"original\n").unwrap();
    let oversized = vec![b'x'; MAX_FILE_TRANSACTION_BYTES + 1];

    let error = StagedWrite::prepare(&target, &oversized)
        .await
        .err()
        .expect("oversized replacement must be refused");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("transaction limit"));
    assert_eq!(std::fs::read(&target).unwrap(), b"original\n");
    assert!(transaction_files(&root.0).is_empty());
}

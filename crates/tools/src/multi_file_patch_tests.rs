use super::*;
use crate::edit::MAX_NORMALIZED_LINES;
use crate::{Memo, Registry};
use iteron_protocol::{Capability, Purity, ToolUse};
use serde_json::{Value, json};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-multi-patch-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn write(&self, path: &str, content: &str) {
        let target = self.0.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, content).unwrap();
    }

    fn read(&self, path: &str) -> Vec<u8> {
        std::fs::read(self.0.join(path)).unwrap()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn patch_only_registry(root: &Path) -> Registry {
    let mut registry = Registry {
        tools: Vec::new(),
        root: root.to_path_buf(),
        memo: std::sync::Arc::new(Memo::default()),
        sensitive_env_names: Default::default(),
        confine_execution: Default::default(),
        egress_allow_policy: Default::default(),
        observation_tool_policy: Default::default(),
        process_launch_policy: Default::default(),
        workspace_boundary: false,
        process_control: None,
        lsp_control: None,
        deferred_tool_catalog: None,
    };
    register(&mut registry).unwrap();
    registry
}

fn file_patch(path: &str, old: &str, new: &str) -> Value {
    json!({"path": path, "hunks": [{"old": old, "new": new}]})
}

fn file_patch_with_hunks(path: &str, hunks: &[(&str, &str)]) -> Value {
    json!({
        "path": path,
        "hunks": hunks
            .iter()
            .map(|(old, new)| json!({"old": old, "new": new}))
            .collect::<Vec<_>>()
    })
}

fn patch_call(id: &str, files: Vec<Value>) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "apply_patch".into(),
        input: json!({"files": files}),
    }
}

fn byte_hash(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn snapshots(root: &TestRoot, paths: &[&str]) -> Vec<(Vec<u8>, u64)> {
    paths
        .iter()
        .map(|path| {
            let bytes = root.read(path);
            let hash = byte_hash(&bytes);
            (bytes, hash)
        })
        .collect()
}

fn assert_snapshots(root: &TestRoot, paths: &[&str], expected: &[(Vec<u8>, u64)]) {
    for (path, (expected_bytes, expected_hash)) in paths.iter().zip(expected) {
        let actual = root.read(path);
        assert_eq!(&actual, expected_bytes, "{path} bytes changed");
        assert_eq!(byte_hash(&actual), *expected_hash, "{path} hash changed");
    }
}

#[tokio::test]
async fn d3_02_g1_three_file_patch_commits_in_one_call() {
    let root = TestRoot::new("three-files");
    root.write("src/a.rs", "pub const A: u8 = 1;\n");
    root.write("src/b.rs", "pub const B: u8 = 2;\n");
    root.write("tests/c.rs", "assert_eq!(A + B, 3);\n");
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "three",
            vec![
                file_patch("src/a.rs", "A: u8 = 1", "A: u8 = 10"),
                file_patch("src/b.rs", "B: u8 = 2", "B: u8 = 20"),
                file_patch("tests/c.rs", "A + B, 3", "A + B, 30"),
            ],
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content, "patched 3 files (3 hunks)");
    assert_eq!(root.read("src/a.rs"), b"pub const A: u8 = 10;\n");
    assert_eq!(root.read("src/b.rs"), b"pub const B: u8 = 20;\n");
    assert_eq!(root.read("tests/c.rs"), b"assert_eq!(A + B, 30);\n");
    for directory in [root.0.join("src"), root.0.join("tests")] {
        assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".core-write-")
        }));
    }

    let spec = registry
        .specs()
        .into_iter()
        .find(|spec| spec.name == "apply_patch")
        .unwrap();
    assert_eq!(spec.purity, Purity::Effecting);
    assert_eq!(spec.capability, Capability::TrustMutating);
    assert_eq!(
        spec.input_schema["properties"]["files"]["maxItems"],
        MAX_FILES
    );
}

#[tokio::test]
async fn d3_02_g2_failing_third_hunk_leaves_all_files_byte_identical() {
    let root = TestRoot::new("hunk-failure");
    let paths = ["one.txt", "two.txt", "three.txt"];
    root.write(paths[0], "first old\n");
    root.write(paths[1], "second old\n");
    root.write(paths[2], "third actual\n");
    let before = snapshots(&root, &paths);
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "bad-third",
            vec![
                file_patch(paths[0], "first old", "first new"),
                file_patch(paths[1], "second old", "second new"),
                file_patch(paths[2], "third missing", "third new"),
            ],
        ))
        .await;

    assert!(result.is_error);
    let error: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["error"], "multi_file_patch_failed");
    assert_eq!(error["kind"], "anchor_not_found");
    assert_eq!(error["phase"], "validate");
    assert_eq!(error["file_index"], 3);
    assert_eq!(error["hunk_index"], 1);
    assert_eq!(error["path"], paths[2]);
    assert_snapshots(&root, &paths, &before);
}

#[tokio::test]
async fn d3_02_g3_parent_path_applies_atomically_with_the_rest_of_the_patch() {
    // Owner-directed 2026-08-05: a `..` file is no longer refused. What this D-number has always
    // guarded is ALL-OR-NOTHING, and that is what is asserted now — the outside file changes with
    // the in-workspace ones, in the same transaction, rather than the patch being rejected whole.
    let root = TestRoot::new("escape-root");
    let outside = TestRoot::new("escape-outside");
    let paths = ["one.txt", "two.txt"];
    root.write(paths[0], "first old\n");
    root.write(paths[1], "second old\n");
    outside.write("outside.txt", "outside old\n");
    let outside_name = outside.0.file_name().unwrap().to_string_lossy();
    let escaped_path = format!("../{outside_name}/outside.txt");
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "escape",
            vec![
                file_patch(paths[0], "first old", "first new"),
                file_patch(paths[1], "second old", "second new"),
                file_patch(&escaped_path, "outside old", "outside new"),
            ],
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(root.read(paths[0]), b"first new\n".to_vec());
    assert_eq!(root.read(paths[1]), b"second new\n".to_vec());
    assert_eq!(outside.read("outside.txt"), b"outside new\n".to_vec());
}

#[cfg(unix)]
#[tokio::test]
async fn d3_02_g3_symlink_path_applies_atomically_with_the_rest_of_the_patch() {
    // Same inversion, same reason: a symlink leaving the workspace is followed now, and the
    // property still under test is that the whole patch lands together.
    let root = TestRoot::new("symlink-root");
    let outside = TestRoot::new("symlink-outside");
    root.write("one.txt", "first old\n");
    root.write("two.txt", "second old\n");
    outside.write("outside.txt", "outside old\n");
    std::os::unix::fs::symlink(&outside.0, root.0.join("escape")).unwrap();
    let paths = ["one.txt", "two.txt"];
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "symlink",
            vec![
                file_patch(paths[0], "first old", "first new"),
                file_patch(paths[1], "second old", "second new"),
                file_patch("escape/outside.txt", "outside old", "outside new"),
            ],
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(root.read(paths[0]), b"first new\n".to_vec());
    assert_eq!(root.read(paths[1]), b"second new\n".to_vec());
    assert_eq!(outside.read("outside.txt"), b"outside new\n".to_vec());
}

#[tokio::test]
async fn d3_02_g4_second_application_is_clear_refusal_without_reedit() {
    let root = TestRoot::new("second-application");
    let paths = ["one.txt", "two.txt", "three.txt"];
    for (index, path) in paths.iter().enumerate() {
        root.write(path, &format!("old-{index}\n"));
    }
    let files = paths
        .iter()
        .enumerate()
        .map(|(index, path)| file_patch(path, &format!("old-{index}"), &format!("new-{index}")))
        .collect::<Vec<_>>();
    let registry = patch_only_registry(&root.0);
    let first = registry
        .run(patch_call("first-application", files.clone()))
        .await;
    assert!(!first.is_error, "{}", first.content);
    let after_first = snapshots(&root, &paths);

    let second = registry.run(patch_call("second-application", files)).await;

    assert!(second.is_error);
    let error: Value = serde_json::from_str(&second.content).unwrap();
    assert_eq!(error["kind"], "anchor_not_found");
    assert_eq!(error["file_index"], 1);
    assert_eq!(error["hunk_index"], 1);
    assert!(error["message"].as_str().unwrap().contains("not found"));
    assert_snapshots(&root, &paths, &after_first);
}

#[tokio::test]
async fn d3_03_g1_three_anchors_resolve_against_one_original_snapshot() {
    let root = TestRoot::new("snapshot-three-anchors");
    root.write("single.txt", "alpha\nbeta\ngamma\n");
    let registry = patch_only_registry(&root.0);

    // Hunk 1 introduces a second `beta`. Sequential validation against updated content would make
    // hunk 2 ambiguous; snapshot planning must still resolve its one original occurrence.
    let result = registry
        .run(patch_call(
            "snapshot-three",
            vec![file_patch_with_hunks(
                "single.txt",
                &[("alpha", "beta"), ("beta", "BETA"), ("gamma", "GAMMA")],
            )],
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content, "patched 1 files (3 hunks)");
    assert_eq!(root.read("single.txt"), b"beta\nBETA\nGAMMA\n");
}

#[tokio::test]
async fn d3_03_g2_missing_anchor_leaves_single_file_byte_identical() {
    let root = TestRoot::new("snapshot-missing");
    root.write("single.txt", "alpha\nbeta\ngamma\n");
    let before = snapshots(&root, &["single.txt"]);
    let input = json!({
        "files": [file_patch_with_hunks(
            "single.txt",
            &[("alpha", "ALPHA"), ("beta", "BETA"), ("absent", "GAMMA")],
        )]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "anchor_not_found");
    assert_eq!(error["file_index"], 1);
    assert_eq!(error["hunk_index"], 3);
    assert_eq!(stats.file_reads, 1);
    assert_eq!(
        stats.file_writes, 0,
        "invalid proposal must perform no write"
    );
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_03_g2_ambiguous_anchor_leaves_single_file_byte_identical() {
    let root = TestRoot::new("snapshot-ambiguous");
    root.write("single.txt", "alpha\nbeta\nrepeat\nrepeat\n");
    let before = snapshots(&root, &["single.txt"]);
    let input = json!({
        "files": [file_patch_with_hunks(
            "single.txt",
            &[("alpha", "ALPHA"), ("beta", "BETA"), ("repeat", "REPEAT")],
        )]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "ambiguous_anchor");
    assert_eq!(error["file_index"], 1);
    assert_eq!(error["hunk_index"], 3);
    assert_eq!(stats.file_reads, 1);
    assert_eq!(
        stats.file_writes, 0,
        "invalid proposal must perform no write"
    );
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_03_g3_instrumentation_records_one_content_read_and_one_destination_write() {
    let root = TestRoot::new("snapshot-io-counts");
    root.write("single.txt", "alpha\nbeta\ngamma\n");
    let input = json!({
        "files": [file_patch_with_hunks(
            "single.txt",
            &[("alpha", "ALPHA"), ("beta", "BETA"), ("gamma", "GAMMA")],
        )]
    });
    let mut stats = PatchIoStats::default();

    let result = execute_patch(&root.0, &input, &mut stats).await;

    assert_eq!(result.unwrap(), (1, 3));
    assert_eq!(stats.file_reads, 1, "content snapshot reads");
    assert_eq!(stats.file_writes, 1, "destination replacements");
    assert_eq!(root.read("single.txt"), b"ALPHA\nBETA\nGAMMA\n");
}

#[tokio::test]
async fn d3_03_g4_overlapping_original_byte_ranges_are_structured_conflict() {
    let root = TestRoot::new("snapshot-overlap");
    root.write("single.txt", "abcdef\n");
    let before = snapshots(&root, &["single.txt"]);
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "snapshot-overlap",
            vec![file_patch_with_hunks(
                "single.txt",
                &[("abc", "ABC"), ("bcd", "BCD"), ("ef", "EF")],
            )],
        ))
        .await;

    assert!(result.is_error);
    let error: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["error"], "multi_file_patch_failed");
    assert_eq!(error["kind"], "overlapping_hunks");
    assert_eq!(error["phase"], "validate");
    assert_eq!(error["file_index"], 1);
    assert_eq!(error["hunk_index"], 2);
    assert_eq!(error["conflicting_hunk_index"], 1);
    assert_eq!(error["path"], "single.txt");
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_04_g1_indentation_trailing_space_and_eol_drift_land_without_byte_spill() {
    let root = TestRoot::new("normalized-landing");
    root.write(
        "single.txt",
        "fn demo() {\r\n\told_call();   \r\n}\r\nuntouched  \r\n",
    );
    let registry = patch_only_registry(&root.0);

    let result = registry
        .run(patch_call(
            "normalized-landing",
            vec![file_patch(
                "single.txt",
                "  old_call();\n",
                " new_call();\n",
            )],
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content, "patched 1 files (1 hunks)");
    assert_eq!(
        root.read("single.txt"),
        b"fn demo() {\r\n\tnew_call();   \r\n}\r\nuntouched  \r\n"
    );
}

#[tokio::test]
async fn d3_04_g2_two_normalized_candidates_are_refused_with_zero_writes() {
    let root = TestRoot::new("normalized-ambiguous");
    root.write("single.txt", "  target(); \r\n\ttarget();\t\r\n");
    let before = snapshots(&root, &["single.txt"]);
    let input = json!({
        "files": [file_patch("single.txt", "target();\n", "updated();\n")]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "ambiguous_anchor");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("whitespace-normalized candidates")
    );
    assert_eq!(stats.file_reads, 1);
    assert_eq!(stats.file_writes, 0);
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_04_g3_no_candidate_reports_structured_nearest_line_without_write() {
    let root = TestRoot::new("normalized-nearest");
    root.write("single.txt", "unrelated\ntarget_value = 41;\ntrailing\n");
    let before = snapshots(&root, &["single.txt"]);
    let input = json!({
        "files": [file_patch(
            "single.txt",
            " target_value = 42; \r\n",
            "target_value = 43;\n",
        )]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "anchor_not_found");
    assert_eq!(error["nearest_line"], 2);
    assert!(error["message"].as_str().unwrap().contains("line 2"));
    assert_eq!(stats.file_writes, 0);
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_04_g4_bidi_is_rejected_before_normalization_with_zero_writes() {
    let root = TestRoot::new("normalized-bidi");
    root.write("single.txt", "if admin // safe\n");
    let before = snapshots(&root, &["single.txt"]);
    let input = json!({
        "files": [file_patch(
            "single.txt",
            "  if admin \u{202E}// safe\n",
            "deny\n",
        )]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "suspicious_unicode");
    assert!(error["message"].as_str().unwrap().contains("U+202E"));
    assert_eq!(stats.file_writes, 0);
    assert_snapshots(&root, &["single.txt"], &before);
}

#[tokio::test]
async fn d3_04_g5_normalization_line_work_is_bounded_and_fail_closed() {
    let root = TestRoot::new("normalized-bound");
    let content = "\n".repeat(MAX_NORMALIZED_LINES + 1);
    root.write("single.txt", &content);
    let before_hash = byte_hash(content.as_bytes());
    let input = json!({
        "files": [file_patch("single.txt", "missing\n", "replacement\n")]
    });
    let mut stats = PatchIoStats::default();

    let failure = execute_patch(&root.0, &input, &mut stats)
        .await
        .unwrap_err();

    let error: Value = serde_json::from_str(&failure.model_json()).unwrap();
    assert_eq!(error["kind"], "normalization_limit");
    assert!(error["message"].as_str().unwrap().contains("262144"));
    assert_eq!(stats.file_reads, 1);
    assert_eq!(stats.file_writes, 0);
    assert_eq!(byte_hash(&root.read("single.txt")), before_hash);
}

#[tokio::test]
async fn array_bounds_are_rejected_at_registry_before_executor() {
    let root = TestRoot::new("bounds");
    let registry = patch_only_registry(&root.0);
    let files = (0..=MAX_FILES)
        .map(|index| file_patch(&format!("{index}.txt"), "old", "new"))
        .collect();

    let result = registry.run(patch_call("too-many", files)).await;

    assert!(result.is_error);
    let error: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(error["error"], "invalid_tool_arguments");
    assert_eq!(error["kind"], "too_many_items");
    assert_eq!(error["field"], "files");
    assert_eq!(error["maximum"], MAX_FILES);
}

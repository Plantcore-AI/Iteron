use super::*;
use iteron_protocol::ToolUse;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iteron-tools-grep-{label}-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn grep_call(id: &str, pattern: &str, regex: bool) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "grep".into(),
        input: serde_json::json!({"pattern":pattern,"regex":regex}),
    }
}

#[tokio::test]
async fn d3_08_g1_regex_finds_a_match_ten_directories_deep() {
    let root = TestRoot::new("deep-regex");
    let mut nested = root.0.clone();
    for depth in 0..10 {
        nested.push(format!("level-{depth}"));
    }
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join("deep.rs"),
        "fn ordinary() {}\nfn deeply_nested_test() {}\n",
    )
    .unwrap();
    let registry = Registry::read_only(&root.0).unwrap();

    let first = registry
        .dispatch(grep_call("regex-1", r"fn \w+_test", true))
        .await;
    let second = registry
        .dispatch(grep_call("regex-2", r"fn \w+_test", true))
        .await;

    assert!(!first.is_error, "{}", first.content);
    assert!(
        first
            .content
            .contains("level-9/deep.rs:2: fn deeply_nested_test")
    );
    assert!(!first.content.contains("ordinary"));
    assert_eq!(first.content, second.content, "search order must be stable");
}

#[tokio::test]
async fn d3_08_g2_multi_gigabyte_file_is_skipped_before_reading() {
    let root = TestRoot::new("huge");
    let huge = std::fs::File::create(root.0.join("huge.log")).unwrap();
    huge.set_len(3 * 1024 * 1024 * 1024).unwrap();
    std::fs::write(root.0.join("small.txt"), "needle stays reachable\n").unwrap();
    let registry = Registry::read_only(&root.0).unwrap();

    let result = registry.dispatch(grep_call("huge", "needle", false)).await;

    assert!(!result.is_error, "{}", result.content);
    assert!(
        result
            .content
            .contains("small.txt:1: needle stays reachable")
    );
    assert!(result.content.contains("1 files skipped"));
    assert!(result.content.contains("per-file limit"));
    assert!(result.content.len() <= MAX_GREP_OUTPUT_BYTES);
}

#[tokio::test]
async fn d3_08_g3_repo_gitignore_and_default_vendor_filters_are_honored() {
    let root = TestRoot::new("gitignore");
    std::fs::write(
        root.0.join(".gitignore"),
        "ignored-by-repo/\ntarget/\nnode_modules/\n",
    )
    .unwrap();
    for directory in ["ignored-by-repo", "target", "node_modules"] {
        std::fs::create_dir_all(root.0.join(directory)).unwrap();
        std::fs::write(
            root.0.join(directory).join("hidden.txt"),
            "forbidden-match\n",
        )
        .unwrap();
    }
    std::fs::write(root.0.join("visible.txt"), "forbidden-match visible\n").unwrap();
    let registry = Registry::read_only(&root.0).unwrap();

    let result = registry
        .dispatch(grep_call("ignore", "forbidden-match", false))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.contains("visible.txt:1"));
    assert!(!result.content.contains("ignored-by-repo"));
    assert!(!result.content.contains("target/"));
    assert!(!result.content.contains("node_modules"));
}

#[tokio::test]
async fn d3_08_g4_match_cap_is_explicit_and_output_is_bounded() {
    let root = TestRoot::new("cap");
    let content = (0..MAX_GREP_MATCHES + 20)
        .map(|index| format!("needle-{index}\n"))
        .collect::<String>();
    std::fs::write(root.0.join("many.txt"), content).unwrap();
    let registry = Registry::read_only(&root.0).unwrap();

    let result = registry
        .dispatch(grep_call("cap", r"needle-\d+", true))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(
        result.content.matches("many.txt:").count(),
        MAX_GREP_MATCHES
    );
    assert!(
        result
            .content
            .contains(&format!("results capped at {MAX_GREP_MATCHES} matches")),
        "{}",
        result.content
    );
    assert!(result.content.len() <= MAX_GREP_OUTPUT_BYTES);
}

#[tokio::test]
async fn invalid_or_unbounded_regex_is_rejected_before_traversal() {
    let root = TestRoot::new("invalid-regex");
    let registry = Registry::read_only(&root.0).unwrap();

    let invalid = registry.dispatch(grep_call("invalid", "(", true)).await;
    assert!(invalid.is_error);
    assert!(invalid.content.contains("invalid or oversized regex"));

    let oversized = registry
        .dispatch(grep_call(
            "oversized",
            &"x".repeat(MAX_GREP_PATTERN_BYTES + 1),
            false,
        ))
        .await;
    assert!(oversized.is_error);
    assert!(oversized.content.contains("pattern exceeds"));

    let ignore = std::fs::File::create(root.0.join(".gitignore")).unwrap();
    ignore.set_len(MAX_GITIGNORE_FILE_BYTES as u64 + 1).unwrap();
    let unsafe_ignore = registry
        .dispatch(grep_call("ignore-bound", "anything", false))
        .await;
    assert!(unsafe_ignore.is_error);
    assert!(unsafe_ignore.content.contains("safely read .gitignore"));
    assert!(unsafe_ignore.content.contains("byte limit"));
}

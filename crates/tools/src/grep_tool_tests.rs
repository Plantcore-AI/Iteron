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

fn registry(root: &Path) -> Registry {
    let registry = Registry::read_only(root).unwrap();
    registry
        .install_observation_tool_policy(crate::ObservationToolPolicy::default())
        .unwrap();
    registry
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
    let registry = registry(&root.0);

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
    let registry = registry(&root.0);

    let result = registry.dispatch(grep_call("huge", "needle", false)).await;

    assert!(!result.is_error, "{}", result.content);
    assert!(
        result
            .content
            .contains("small.txt:1: needle stays reachable")
    );
    assert!(result.content.contains("1 files skipped"));
    assert!(result.content.contains("per-file limit"));
    assert!(
        result.content.len()
            <= crate::ObservationToolPolicy::default()
                .grep
                .output_max_bytes
    );
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
    let registry = registry(&root.0);

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
    let max_matches = crate::ObservationToolPolicy::default().grep.max_matches;
    let content = (0..max_matches + 20)
        .map(|index| format!("needle-{index}\n"))
        .collect::<String>();
    std::fs::write(root.0.join("many.txt"), content).unwrap();
    let registry = registry(&root.0);

    let result = registry
        .dispatch(grep_call("cap", r"needle-\d+", true))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(result.content.matches("many.txt:").count(), max_matches);
    assert!(
        result
            .content
            .contains(&format!("results capped at {max_matches} matches")),
        "{}",
        result.content
    );
    assert!(
        result.content.len()
            <= crate::ObservationToolPolicy::default()
                .grep
                .output_max_bytes
    );
}

#[tokio::test]
async fn pinned_match_limit_distinguishes_exact_boundary_from_n_plus_one() {
    let root = TestRoot::new("pinned-boundary");
    std::fs::write(
        root.0.join("matches.txt"),
        "exact one\nexact two\noverflow one\noverflow two\noverflow three\n",
    )
    .unwrap();

    let unpinned = Registry::read_only(&root.0).unwrap();
    let refused = unpinned
        .dispatch(grep_call("unpinned", "exact", false))
        .await;
    assert!(refused.is_error);
    assert!(refused.content.contains("policy was not installed"));

    let pinned = Registry::read_only(&root.0).unwrap();
    let mut policy = crate::ObservationToolPolicy::default();
    policy.grep.max_matches = 2;
    pinned.install_observation_tool_policy(policy).unwrap();

    let exact = pinned.dispatch(grep_call("exact", "exact", false)).await;
    assert!(!exact.is_error, "{}", exact.content);
    assert_eq!(exact.content.matches("matches.txt:").count(), 2);
    assert!(
        !exact.content.contains("results capped"),
        "{}",
        exact.content
    );

    let overflow = pinned
        .dispatch(grep_call("overflow", "overflow", false))
        .await;
    assert!(!overflow.is_error, "{}", overflow.content);
    assert_eq!(overflow.content.matches("matches.txt:").count(), 2);
    assert!(overflow.content.contains("results capped at 2 matches"));
}

#[tokio::test]
async fn invalid_or_unbounded_regex_is_rejected_before_traversal() {
    let root = TestRoot::new("invalid-regex");
    let registry = registry(&root.0);

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

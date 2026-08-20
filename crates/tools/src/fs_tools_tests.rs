use super::*;
use iteron_protocol::ToolUse;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iteron-tools-read-file-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated read_file test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn large_fixture(lines: usize) -> String {
    (1..=lines)
        .map(|line| format!("payload-{line:05}\n"))
        .collect()
}

fn read_call(id: &str, input: serde_json::Value) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "read_file".into(),
        input,
    }
}

fn edit_call(id: &str, path: &str, old: &str, new: &str) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "edit".into(),
        input: serde_json::json!({"path":path,"old":old,"new":new}),
    }
}

fn read_only_registry(root: &std::path::Path) -> Registry {
    let registry = Registry::read_only(root).unwrap();
    registry
        .install_observation_tool_policy(ObservationToolPolicy::default())
        .unwrap();
    registry
}

fn coding_registry(root: &std::path::Path) -> Registry {
    let registry = Registry::coding_agent(root).unwrap();
    registry
        .install_observation_tool_policy(ObservationToolPolicy::default())
        .unwrap();
    registry
}

#[test]
fn glob_matches_segments_and_globstar() {
    assert!(glob_match("*.rs", "main.rs"));
    assert!(!glob_match("*.rs", "src/main.rs"));
    assert!(glob_match("src/*.rs", "src/main.rs"));
    assert!(!glob_match("src/*.rs", "src/a/b.rs"));
    assert!(glob_match("**/*.rs", "a/b/c.rs"));
    assert!(glob_match("**/*.rs", "c.rs"));
    assert!(glob_match("src/**/*.rs", "src/a/b.rs"));
    assert!(glob_match("src/**/*.rs", "src/b.rs"));
    assert!(!glob_match("src/**/*.rs", "lib/b.rs"));
    assert!(glob_match("?.txt", "a.txt"));
    assert!(!glob_match("?.txt", "ab.txt"));
    assert!(glob_match("**", "any/thing/here"));
    assert!(glob_match("Cargo.toml", "Cargo.toml"));
    assert!(!glob_match("Cargo.toml", "crates/Cargo.toml"));
}

#[tokio::test]
async fn observation_policy_is_fail_closed_pinned_and_one_shot() {
    let root = TestRoot::new("pinned-policy");
    std::fs::write(root.0.join("small.txt"), "alpha\nbeta\ngamma\n").unwrap();
    let registry = Registry::read_only(&root.0).unwrap();

    let rejected = registry
        .dispatch(read_call(
            "uninstalled",
            serde_json::json!({"path":"small.txt"}),
        ))
        .await;
    assert!(rejected.is_error);
    assert!(
        rejected
            .content
            .contains("runtime policy was not installed")
    );

    let mut pinned = ObservationToolPolicy::default();
    pinned.read_file.max_lines = 1;
    registry.install_observation_tool_policy(pinned).unwrap();
    let bounded = registry
        .dispatch(read_call(
            "installed",
            serde_json::json!({"path":"small.txt"}),
        ))
        .await;
    assert!(!bounded.is_error, "{}", bounded.content);
    assert!(bounded.content.starts_with("     1\talpha\n"));
    assert!(bounded.content.contains("truncated before line 2"));
    assert!(bounded.content.contains("continue with offset=2"));

    assert_eq!(
        registry
            .install_observation_tool_policy(ObservationToolPolicy::default())
            .unwrap_err(),
        crate::ObservationToolPolicyError::AlreadyInstalled
    );
}

#[tokio::test]
async fn traversal_count_markers_require_observing_the_item_past_the_ceiling() {
    let root = TestRoot::new("traversal-count-boundary");
    for (directory, files) in [("exact", 2), ("over", 3)] {
        std::fs::create_dir(root.0.join(directory)).unwrap();
        for index in 0..files {
            std::fs::write(root.0.join(directory).join(format!("{index}.txt")), "x").unwrap();
        }
    }
    let registry = Registry::read_only(&root.0).unwrap();
    let mut pinned = ObservationToolPolicy::default();
    pinned.list_dir.max_entries = 2;
    pinned.list_dir.output_max_bytes = 256;
    pinned.glob.max_results = 2;
    pinned.glob.output_max_bytes = 256;
    registry.install_observation_tool_policy(pinned).unwrap();

    for (tool, exact_input, over_input) in [
        (
            "list_dir",
            serde_json::json!({"path":"exact"}),
            serde_json::json!({"path":"over"}),
        ),
        (
            "glob",
            serde_json::json!({"pattern":"exact/*.txt"}),
            serde_json::json!({"pattern":"over/*.txt"}),
        ),
    ] {
        let exact = registry
            .dispatch(ToolUse {
                id: format!("{tool}-exact"),
                name: tool.into(),
                input: exact_input,
            })
            .await;
        assert!(!exact.is_error, "{}", exact.content);
        assert!(!exact.content.contains("truncated"), "{}", exact.content);
        assert!(exact.content.len() <= 256);

        let over = registry
            .dispatch(ToolUse {
                id: format!("{tool}-over"),
                name: tool.into(),
                input: over_input,
            })
            .await;
        assert!(!over.is_error, "{}", over.content);
        assert!(over.content.contains("truncated at 2"), "{}", over.content);
        assert!(over.content.len() <= 256);
    }
}

#[tokio::test]
async fn d3_06_g1_reads_exact_middle_range_with_absolute_line_numbers() {
    let root = TestRoot::new("middle-range");
    let fixture = large_fixture(8_000);
    assert!(fixture.len() >= 100_000, "fixture must be at least 100 KB");
    std::fs::write(root.0.join("large.txt"), fixture).unwrap();
    let registry = read_only_registry(&root.0);

    let result = registry
        .dispatch(read_call(
            "range",
            serde_json::json!({"path":"large.txt","offset":3999,"limit":4}),
        ))
        .await;
    assert!(!result.is_error, "{}", result.content);
    // The caller's `limit` is a pagination boundary, not EOF: the marker names the resume offset
    // so a partial read cannot be mistaken for the end of the file. It also has to name the right
    // boundary — this read stopped on the requested window, not on the output byte cap.
    assert_eq!(
        result.content,
        "  3999\tpayload-03999\n  4000\tpayload-04000\n  4001\tpayload-04001\n  4002\tpayload-04002\n\
         … (truncated before line 4003; the requested line window ended here; continue with offset=4003)"
    );
}

#[tokio::test]
async fn d3_06_g2_ranged_read_anchor_round_trips_through_edit() {
    let root = TestRoot::new("read-edit");
    let fixture = large_fixture(8_000);
    assert!(fixture.len() > 40_000);
    std::fs::write(root.0.join("large.txt"), fixture).unwrap();
    let registry = coding_registry(&root.0);
    let read = read_call(
        "before",
        serde_json::json!({"path":"large.txt","offset":5000,"limit":3}),
    );

    let before = registry.dispatch(read.clone()).await;
    assert!(!before.is_error, "{}", before.content);
    let anchor = before
        .content
        .lines()
        .nth(1)
        .and_then(|line| line.split_once('\t'))
        .map(|(_, content)| content)
        .expect("middle ranged line exposes an edit anchor")
        .to_owned();
    assert_eq!(anchor, "payload-05001");

    let edit = registry
        .run(ToolUse {
            id: "edit".into(),
            name: "edit".into(),
            input: serde_json::json!({
                "path":"large.txt",
                "old":anchor,
                "new":"payload-05001-edited"
            }),
        })
        .await;
    assert!(!edit.is_error, "{}", edit.content);
    let after = registry.dispatch(read).await;
    assert!(after.content.contains("  5001\tpayload-05001-edited"));
    assert!(!after.content.contains("  5001\tpayload-05001\n"));
}

#[tokio::test]
async fn d3_06_g3_huge_range_has_explicit_byte_bound_and_resume_marker() {
    let root = TestRoot::new("bounded-range");
    // Sized from the cap rather than a literal: each numbered line costs ~21 bytes, so this is
    // comfortably past the canonical output ceiling and stays past it if the default is raised.
    std::fs::write(
        root.0.join("large.txt"),
        large_fixture(ObservationToolPolicy::default().read_file.output_max_bytes / 16),
    )
    .unwrap();
    let registry = read_only_registry(&root.0);

    let result = registry
        .dispatch(read_call(
            "huge",
            serde_json::json!({"path":"large.txt","offset":1,"limit":u64::MAX}),
        ))
        .await;
    assert!(!result.is_error, "{}", result.content);
    assert!(result.content.len() <= ObservationToolPolicy::default().read_file.output_max_bytes);
    assert!(result.content.contains("… (truncated before line "));
    assert!(result.content.contains("continue with offset="));
}

#[tokio::test]
async fn d3_06_g4_small_whole_file_and_schema_remain_explicit() {
    let root = TestRoot::new("small-regression");
    std::fs::write(root.0.join("small.txt"), "alpha\nbeta\n").unwrap();
    let registry = read_only_registry(&root.0);

    let result = registry
        .dispatch(read_call("small", serde_json::json!({"path":"small.txt"})))
        .await;
    assert_eq!(result.content, "     1\talpha\n     2\tbeta");

    let spec = registry
        .specs()
        .into_iter()
        .find(|spec| spec.name == "read_file")
        .unwrap();
    assert!(spec.description.contains("optional 1-based first line"));
    let output_ceiling = ObservationToolPolicy::default().read_file.output_max_bytes;
    assert!(
        spec.description
            .contains(&format!("capped at {output_ceiling} bytes"))
    );
    assert_eq!(spec.input_schema["properties"]["offset"]["type"], "integer");
    assert_eq!(spec.input_schema["properties"]["offset"]["minimum"], 1);
    assert_eq!(spec.input_schema["properties"]["limit"]["type"], "integer");
    assert_eq!(spec.input_schema["properties"]["limit"]["minimum"], 1);
    assert_eq!(spec.input_schema["required"], serde_json::json!(["path"]));

    let invalid = registry
        .dispatch(read_call(
            "invalid",
            serde_json::json!({"path":"small.txt","offset":0}),
        ))
        .await;
    assert!(invalid.is_error);
    let error: serde_json::Value = serde_json::from_str(&invalid.content).unwrap();
    assert_eq!(error["error"], "invalid_tool_arguments");
    assert_eq!(error["kind"], "below_minimum");
    assert_eq!(error["field"], "offset");
    assert_eq!(error["minimum"], 1);
}

#[tokio::test]
async fn traversal_tools_report_outside_paths_instead_of_dropping_or_failing_on_them() {
    // `read_file` addressing the host was only half of it. Both traversal tools mapped every hit
    // back through `strip_prefix(root)` and treated failure as impossible: `list_dir` dropped the
    // entry silently and returned an empty listing, and `grep` failed the whole search. A silent
    // empty result is the worse of the two, which is why this is asserted rather than assumed.
    let root = TestRoot::new("traversal-outside-root");
    let outside = TestRoot::new("traversal-outside-target");
    std::fs::write(root.0.join("inside.txt"), "needle inside\n").unwrap();
    std::fs::write(outside.0.join("outside.txt"), "needle outside\n").unwrap();
    let registry = read_only_registry(&root.0);
    let outside_dir = outside.0.canonicalize().unwrap();

    let listed = registry
        .dispatch(ToolUse {
            id: "list".into(),
            name: "list_dir".into(),
            input: serde_json::json!({"path": outside_dir.to_str().unwrap()}),
        })
        .await;
    assert!(!listed.is_error, "{}", listed.content);
    assert!(
        listed.content.contains("outside.txt"),
        "an outside listing must not come back empty: {:?}",
        listed.content
    );
    assert!(
        listed.content.starts_with('/'),
        "a path outside the root is spelled absolutely: {:?}",
        listed.content
    );

    let found = registry
        .dispatch(ToolUse {
            id: "grep".into(),
            name: "grep".into(),
            input: serde_json::json!({
                "pattern": "needle",
                "path": outside_dir.to_str().unwrap(),
            }),
        })
        .await;
    assert!(!found.is_error, "{}", found.content);
    assert!(found.content.contains("outside.txt:1"), "{}", found.content);

    // And a search inside the workspace still renders the short relative form.
    let inside = registry
        .dispatch(ToolUse {
            id: "grep-inside".into(),
            name: "grep".into(),
            input: serde_json::json!({"pattern": "needle"}),
        })
        .await;
    assert!(!inside.is_error, "{}", inside.content);
    assert!(
        inside.content.contains("inside.txt:1"),
        "{}",
        inside.content
    );
    assert!(
        !inside.content.contains(root.0.to_str().unwrap()),
        "an in-workspace hit stays relative: {}",
        inside.content
    );
}

#[tokio::test]
async fn d3_16_g1_read_file_addresses_the_host_not_only_the_workspace() {
    // The inverse of the former containment test, kept under the same D-number because it covers
    // the same decision point: which paths `read_file` will resolve. Owner-directed 2026-08-05 —
    // both a relative and an absolute path resolve, and neither `..` nor an outside root refuses.
    let root = TestRoot::new("read-containment");
    std::fs::write(root.0.join("inside.txt"), "inside\n").unwrap();
    let registry = read_only_registry(&root.0);

    let inside = registry
        .dispatch(read_call(
            "inside",
            serde_json::json!({"path":"inside.txt"}),
        ))
        .await;
    assert!(!inside.is_error, "{}", inside.content);
    assert!(inside.content.contains("inside"));

    // The same file named absolutely: this is what the model actually emits, and refusing it was
    // the single largest source of tool errors before this change.
    let absolute = root.0.canonicalize().unwrap().join("inside.txt");
    let by_absolute = registry
        .dispatch(read_call(
            "absolute",
            serde_json::json!({"path": absolute.to_str().unwrap()}),
        ))
        .await;
    assert!(!by_absolute.is_error, "{}", by_absolute.content);
    assert!(by_absolute.content.contains("inside"));

    // A file genuinely outside the workspace, reached by `..`.
    let outside = TestRoot::new("read-outside");
    std::fs::write(outside.0.join("outside.txt"), "outside\n").unwrap();
    let outside_name = outside.0.file_name().unwrap().to_string_lossy();
    let traversed = registry
        .dispatch(read_call(
            "traverse",
            serde_json::json!({"path": format!("../{outside_name}/outside.txt")}),
        ))
        .await;
    assert!(!traversed.is_error, "{}", traversed.content);
    assert!(traversed.content.contains("outside"));
}

#[tokio::test]
async fn d3_07_g1_crlf_edit_changes_one_line_without_eol_conversion() {
    let root = TestRoot::new("crlf-fidelity");
    let path = root.0.join("windows.txt");
    std::fs::write(&path, b"alpha\r\nbeta\r\ngamma\r\n").unwrap();
    let registry = coding_registry(&root.0);

    let result = registry
        .run(edit_call("crlf", "windows.txt", "beta", "BETA"))
        .await;

    assert!(!result.is_error, "{}", result.content);
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes, b"alpha\r\nBETA\r\ngamma\r\n");
    assert_eq!(bytes.windows(2).filter(|pair| *pair == b"\r\n").count(), 3);
    assert!(
        bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte != b'\n' || index > 0 && bytes[index - 1] == b'\r')
    );
}

#[tokio::test]
async fn d3_07_g2_edit_preserves_bom_presence_and_absence() {
    let root = TestRoot::new("bom-fidelity");
    let with_bom = root.0.join("with-bom.txt");
    let without_bom = root.0.join("without-bom.txt");
    std::fs::write(&with_bom, b"\xef\xbb\xbfalpha\nbeta\n").unwrap();
    std::fs::write(&without_bom, b"alpha\nbeta\n").unwrap();
    let registry = coding_registry(&root.0);

    for (id, path) in [("with", "with-bom.txt"), ("without", "without-bom.txt")] {
        let result = registry.run(edit_call(id, path, "beta", "BETA")).await;
        assert!(!result.is_error, "{}", result.content);
    }

    assert_eq!(
        std::fs::read(&with_bom).unwrap(),
        b"\xef\xbb\xbfalpha\nBETA\n"
    );
    assert_eq!(std::fs::read(&without_bom).unwrap(), b"alpha\nBETA\n");
}

#[tokio::test]
async fn d3_07_g3_binary_and_oversized_reads_return_bounded_notices() {
    let root = TestRoot::new("binary-read");
    std::fs::write(
        root.0.join("image.png"),
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\xff",
    )
    .unwrap();
    let oversized = std::fs::File::create(root.0.join("oversized.txt")).unwrap();
    oversized
        .set_len(ObservationToolPolicy::default().read_file.source_max_bytes as u64 + 1)
        .unwrap();
    let registry = read_only_registry(&root.0);

    let binary = registry
        .dispatch(read_call("binary", serde_json::json!({"path":"image.png"})))
        .await;
    assert!(!binary.is_error, "{}", binary.content);
    assert!(binary.content.contains("binary"));
    assert!(binary.content.contains("not shown"));
    assert!(binary.content.len() < 256);

    let large = registry
        .dispatch(read_call(
            "oversized",
            serde_json::json!({"path":"oversized.txt"}),
        ))
        .await;
    assert!(!large.is_error, "{}", large.content);
    assert!(large.content.contains("oversized file, not shown"));
    assert!(
        large.content.contains(
            &ObservationToolPolicy::default()
                .read_file
                .source_max_bytes
                .to_string()
        )
    );
    assert!(large.content.len() < 256);
}

#[tokio::test]
async fn d3_07_g4_lf_and_trailing_newline_state_round_trip_exactly() {
    let root = TestRoot::new("lf-fidelity");
    let trailing = root.0.join("trailing.txt");
    let no_trailing = root.0.join("no-trailing.txt");
    std::fs::write(&trailing, b"alpha\nbeta\n").unwrap();
    std::fs::write(&no_trailing, b"alpha\nbeta").unwrap();
    let registry = coding_registry(&root.0);

    for (id, path) in [("trailing", "trailing.txt"), ("no", "no-trailing.txt")] {
        let result = registry.run(edit_call(id, path, "beta", "BETA")).await;
        assert!(!result.is_error, "{}", result.content);
    }

    assert_eq!(std::fs::read(trailing).unwrap(), b"alpha\nBETA\n");
    assert_eq!(std::fs::read(no_trailing).unwrap(), b"alpha\nBETA");
}

#[tokio::test]
async fn d3_07_edit_keeps_trailing_newline_state_when_replacement_disagrees() {
    let root = TestRoot::new("trailing-newline-fidelity");
    let trailing = root.0.join("trailing.txt");
    let no_trailing = root.0.join("no-trailing.txt");
    std::fs::write(&trailing, b"alpha\nbeta\n").unwrap();
    std::fs::write(&no_trailing, b"alpha\nbeta").unwrap();
    let registry = coding_registry(&root.0);

    let remove = registry
        .run(edit_call("remove", "trailing.txt", "beta\n", "BETA"))
        .await;
    let add = registry
        .run(edit_call("add", "no-trailing.txt", "beta", "BETA\n"))
        .await;

    assert!(!remove.is_error, "{}", remove.content);
    assert!(!add.is_error, "{}", add.content);
    assert_eq!(std::fs::read(trailing).unwrap(), b"alpha\nBETA\n");
    assert_eq!(std::fs::read(no_trailing).unwrap(), b"alpha\nBETA");
}

#[tokio::test]
async fn d3_07_acceptance_edit_preserves_crlf_and_bom() {
    let root = TestRoot::new("crlf-edit-fidelity");
    let path = root.0.join("windows.txt");
    std::fs::write(&path, b"\xef\xbb\xbfalpha\r\nbeta\r\ngamma\r\n").unwrap();
    let registry = coding_registry(&root.0);

    let result = registry
        .run(edit_call(
            "line-ending",
            "windows.txt",
            "beta\r\n",
            "BETA\n",
        ))
        .await;

    assert!(!result.is_error, "{}", result.content);
    assert_eq!(
        std::fs::read(path).unwrap(),
        b"\xef\xbb\xbfalpha\r\nBETA\r\ngamma\r\n",
        "edit must retain the UTF-8 BOM and encode the edited line using the target's CRLF style"
    );
}

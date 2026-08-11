use super::*;
use iteron_protocol::Trust;

fn result(content: &str) -> ToolResult {
    ToolResult {
        tool_use_id: "tool-1".into(),
        content: content.into(),
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 7,
    }
}

fn handle_from(content: &str) -> String {
    let start = content.find("sha256:").unwrap();
    content[start..start + "sha256:".len() + 64].to_owned()
}

#[test]
fn oversized_output_is_private_content_addressed_and_visibly_bounded() {
    let policy = ToolOutputSpillPolicy::new(192, 4096, ToolOutputSpillCleanup::RunEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let raw = "界".repeat(200);
    let managed = store.apply(result(&raw));

    assert!(managed.spilled);
    assert!(managed.result.content.len() <= policy.memory_threshold_bytes());
    assert!(
        managed
            .result
            .content
            .contains("[tool output spill sha256:")
    );
    assert!(managed.result.content.contains("cleanup=run_end]"));
    assert!(
        !managed
            .result
            .content
            .contains(std::env::temp_dir().to_string_lossy().as_ref())
    );
    let handle = handle_from(&managed.result.content);
    assert_eq!(store.read_private(&handle).unwrap(), raw.as_bytes());
    let other_store = ToolOutputSpillStore::create(policy).unwrap();
    assert_eq!(
        other_store.read_private(&handle),
        Err(ToolOutputSpillError::UnknownHandle),
        "opaque handles are dereferenced only by their exact session owner"
    );
    assert_eq!(store.retained_count(), 1);
    assert_eq!(store.retained_bytes(), raw.len());
}

#[test]
fn aggregate_capacity_never_writes_a_partial_or_leaks_the_rejected_tail() {
    let policy = ToolOutputSpillPolicy::new(8, 16, ToolOutputSpillCleanup::RunEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let first = store.apply(result("abcdefghijkl"));
    let second = store.apply(result("SECRET-SECOND-OUTPUT"));

    assert!(first.spilled);
    assert!(!second.spilled, "aggregate overflow is refused");
    assert_eq!(store.retained_bytes(), 12);
    assert!(!second.result.content.contains("SECRET-SECOND-OUTPUT"));
    assert_eq!(store.retained_count(), 1);
}

#[test]
fn tool_end_cleanup_is_lease_scoped_for_deduplicated_concurrent_results() {
    let policy = ToolOutputSpillPolicy::new(160, 1024, ToolOutputSpillCleanup::ToolEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let raw = "same private result".repeat(12);
    let mut first = store.apply(result(&raw));
    let mut second = store.apply(result(&raw));
    let handle = handle_from(&first.result.content);
    assert_eq!(store.retained_count(), 1);

    store.cleanup_tool(&mut first.lease).unwrap();
    assert_eq!(store.read_private(&handle).unwrap(), raw.as_bytes());
    store.cleanup_tool(&mut second.lease).unwrap();
    assert_eq!(store.retained_count(), 0);
    assert_eq!(
        store.read_private(&handle),
        Err(ToolOutputSpillError::UnknownHandle)
    );
}

#[test]
fn later_lifecycle_boundary_cleans_a_missed_earlier_boundary() {
    let policy = ToolOutputSpillPolicy::new(8, 1024, ToolOutputSpillCleanup::TurnEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let _managed = store.apply(result("private result"));

    store.cleanup(ToolOutputSpillCleanup::ToolEnd).unwrap();
    assert_eq!(store.retained_count(), 1);
    store.cleanup(ToolOutputSpillCleanup::RunEnd).unwrap();
    assert_eq!(store.retained_count(), 0);
}

#[test]
fn dropping_store_removes_private_root() {
    let policy = ToolOutputSpillPolicy::new(8, 1024, ToolOutputSpillCleanup::RunEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let root = store.root();
    let _managed = store.apply(result("private result"));
    drop(store);
    assert!(!root.exists());
}

#[cfg(unix)]
#[test]
fn store_directory_and_artifact_are_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let policy = ToolOutputSpillPolicy::new(160, 1024, ToolOutputSpillCleanup::RunEnd).unwrap();
    let store = ToolOutputSpillStore::create(policy).unwrap();
    let managed = store.apply(result(&"private result".repeat(12)));
    let handle = handle_from(&managed.result.content);
    let path = store.artifact_path(&handle).unwrap();

    assert_eq!(
        std::fs::metadata(store.root())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

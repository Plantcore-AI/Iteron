use super::*;
use crate::runtime::persistent_writer_settlement::{
    PersistentWriterConfig, PersistentWriterSettlement,
};
use crate::runtime::workflow_spawner::worktree::persistent::PersistentWriterWorktree;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(path)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "iteron-writer-proof-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let parent = root.join("repo");
    std::fs::create_dir_all(&parent).unwrap();
    git(&parent, &["init", "--quiet"]);
    git(&parent, &["config", "user.name", "Writer Fixture"]);
    git(&parent, &["config", "user.email", "writer@example.invalid"]);
    std::fs::write(parent.join("owned.txt"), "base\n").unwrap();
    git(&parent, &["add", "owned.txt"]);
    git(&parent, &["commit", "--quiet", "-m", "base"]);
    let state = root.join("state");
    (root, parent, state)
}

fn platform_prerequisite() -> bool {
    #[cfg(target_os = "linux")]
    {
        iteron_sandbox::bubblewrap::Bubblewrap::available()
    }
    #[cfg(target_os = "macos")]
    {
        Path::new("/usr/bin/sandbox-exec").is_file()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

fn report() -> AgentOutcome {
    AgentOutcome::Text {
        text: "written".into(),
        tokens: 0,
        tool_calls: 0,
        last_tool_summary: None,
    }
}

#[tokio::test]
async fn missing_operator_command_discards_actual_private_patch_and_is_known_failed() {
    let (root, parent, state) = fixture("no-command");
    let mut tree = WriterWorktree::provision(parent.clone(), state, "missing-command".into())
        .await
        .unwrap();
    let isolated = tree.path().to_owned();
    std::fs::write(isolated.join("owned.txt"), "never merge\n").unwrap();
    let activity = ActivitySink::default();
    let mut result = report();
    let proof = NativeWriterSettlement {
        activity: &activity,
        command: None,
        sensitive_env_names: &[],
        output_tail_bytes: 1024,
    }
    .run(&mut tree, true, &mut result)
    .await;
    assert_eq!(proof, WriterSettlementProof::KnownDiscarded);
    assert!(matches!(result, AgentOutcome::Null { .. }));
    assert!(!isolated.exists());
    assert_eq!(
        std::fs::read_to_string(parent.join("owned.txt")).unwrap(),
        "base\n"
    );
    drop(tree);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn actual_failing_configured_command_discards_and_does_not_invent_unknown_cleanup() {
    if !platform_prerequisite() {
        eprintln!("native writer oracle prerequisite unavailable");
        return;
    }
    let (root, parent, state) = fixture("failed-command");
    let mut tree =
        WriterWorktree::provision(parent.clone(), state.clone(), "failed-command".into())
            .await
            .unwrap();
    std::fs::write(tree.path().join("owned.txt"), "never merge\n").unwrap();
    let activity = ActivitySink::default();
    let mut result = report();
    let proof = NativeWriterSettlement {
        activity: &activity,
        command: Some("exit 1"),
        sensitive_env_names: &[],
        output_tail_bytes: 1024,
    }
    .run(&mut tree, true, &mut result)
    .await;
    assert_eq!(proof, WriterSettlementProof::KnownDiscarded);
    assert!(matches!(result, AgentOutcome::Null { .. }));
    assert_eq!(
        std::fs::read_to_string(parent.join("owned.txt")).unwrap(),
        "base\n"
    );
    drop(tree);
    let (mut resident, _) = PersistentWriterWorktree::provision(
        parent.clone(),
        state.clone(),
        "resident-failed-command".into(),
        None,
    )
    .await
    .unwrap();
    std::fs::write(resident.path().join("owned.txt"), "resident patch\n").unwrap();
    let config = PersistentWriterConfig {
        parent: parent.clone(),
        state,
        lock: Arc::new(tokio::sync::Mutex::new(())),
        verify: Some("exit 1".into()),
        env: Vec::new(),
        oracle_tail: 1024,
        admitted: true,
    };
    let terminal = PersistentWriterSettlement {
        config: &config,
        control: None,
    }
    .run(&mut resident, true)
    .await;
    assert_eq!(terminal.proof, WriterSettlementProof::KnownDiscarded);
    assert!(terminal.failure.is_some());
    assert!(!resident.path().exists());
    assert_eq!(
        std::fs::read_to_string(parent.join("owned.txt")).unwrap(),
        "base\n"
    );
    drop(resident);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn actual_verified_patch_has_known_merged_receipt_only_after_cleanup() {
    if !platform_prerequisite() {
        eprintln!("native writer oracle prerequisite unavailable");
        return;
    }
    let (root, parent, state) = fixture("merged");
    let mut tree = WriterWorktree::provision(parent.clone(), state, "merged".into())
        .await
        .unwrap();
    std::fs::write(tree.path().join("owned.txt"), "merged patch\n").unwrap();
    let activity = ActivitySink::default();
    let mut result = report();
    let proof = NativeWriterSettlement {
        activity: &activity,
        command: Some("exit 0"),
        sensitive_env_names: &[],
        output_tail_bytes: 1024,
    }
    .run(&mut tree, true, &mut result)
    .await;
    assert_eq!(proof, WriterSettlementProof::KnownMerged);
    assert!(matches!(result, AgentOutcome::Text { .. }));
    assert!(!tree.path().exists());
    assert_eq!(
        std::fs::read_to_string(parent.join("owned.txt")).unwrap(),
        "merged patch\n"
    );
    drop(tree);
    std::fs::remove_dir_all(root).unwrap();
}

use super::{overlaps, restore};
use crate::checkpoint::{checkpoint, checkpoint_excluding_runtime_state};
use iteron_protocol::{RunId, Seq};
use std::{path::PathBuf, process::Command};

struct Repository(PathBuf);
impl Repository {
    fn new(label: &str) -> Self {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "iteron-protected-restore-{label}-{}",
            hex::encode(nonce)
        ));
        std::fs::create_dir(&root).unwrap();
        let repo = Self(root);
        repo.git(&["init", "-q"]);
        repo
    }
    fn git(&self, arguments: &[&str]) {
        let result = Command::new("git")
            .current_dir(&self.0)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
impl Drop for Repository {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_restore_preserves_even_tracked_runtime_wal_and_restores_editable_files() {
    let repo = Repository::new("wal");
    let runs = repo.0.join(".iteron/runs");
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(repo.0.join("editable.txt"), "before\n").unwrap();
    let snapshot =
        checkpoint_excluding_runtime_state(&RunId("run".into()), Seq(3), &repo.0, &runs).unwrap();
    std::fs::write(repo.0.join("editable.txt"), "after\n").unwrap();
    std::fs::write(repo.0.join("later.txt"), "delete me\n").unwrap();
    std::fs::write(runs.join("live.jsonl"), "authoritative terminal\n").unwrap();
    // Even a tracked state file is outside the admitted editable tree. Git ignore is insufficient.
    repo.git(&["add", "-f", "--", ".iteron/runs/live.jsonl"]);
    restore(&snapshot, &repo.0, true, Some(&runs)).unwrap();
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt")).unwrap(),
        "before\n"
    );
    assert!(!repo.0.join("later.txt").exists());
    assert_eq!(
        std::fs::read_to_string(runs.join("live.jsonl")).unwrap(),
        "authoritative terminal\n"
    );
}

#[test]
fn historical_snapshot_containing_runtime_state_is_refused_before_any_file_changes() {
    let repo = Repository::new("old-target");
    let runs = repo.0.join(".iteron/runs");
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(repo.0.join("editable.txt"), "old\n").unwrap();
    std::fs::write(runs.join("live.jsonl"), "old terminal\n").unwrap();
    let snapshot = checkpoint(&RunId("historical".into()), Seq(2), &repo.0).unwrap();
    std::fs::write(repo.0.join("editable.txt"), "current\n").unwrap();
    std::fs::write(runs.join("live.jsonl"), "current terminal\n").unwrap();
    assert!(restore(&snapshot, &repo.0, true, Some(&runs)).is_err());
    assert_eq!(
        std::fs::read_to_string(repo.0.join("editable.txt")).unwrap(),
        "current\n"
    );
    assert_eq!(
        std::fs::read_to_string(runs.join("live.jsonl")).unwrap(),
        "current terminal\n"
    );
}

#[test]
fn protection_includes_ancestors_and_descendants_but_not_prefix_neighbours() {
    for path in [".iteron", ".iteron/runs", ".iteron/runs/live.jsonl"] {
        assert!(overlaps(path, ".iteron/runs"), "{path}");
    }
    for path in [".iteron/config.json", ".iteron/runs-old/a", ".iteron-run"] {
        assert!(!overlaps(path, ".iteron/runs"), "{path}");
    }
}

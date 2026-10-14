use super::{
    MemoryInvalidation, MemoryProvenance, MemoryRecordDraft, MemoryRecordExclusion,
    MemoryRecordOwner, MemoryRecordScope, MemorySourceKind,
};
use crate::{
    FileMemory, MemBudget, MemStore, MemTier, MemoryRecallStrategy, MemoryStore, MemoryStrategy,
};
use iteron_protocol::Trust;
use std::path::PathBuf;

fn workspace(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-memory-v1-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}
fn root(workspace: &std::path::Path) -> PathBuf {
    iteron_protocol::home::path(workspace, "memory")
}
fn draft(workspace: &std::path::Path) -> MemoryRecordDraft {
    MemoryRecordDraft::workspace(
        workspace,
        "test-operator-receipt",
        super::now_unix_seconds(),
    )
    .unwrap()
}

#[cfg(any(unix, windows))]
#[test]
fn busy_writer_is_definite_before_publication_and_release_preserves_the_snapshot() {
    let workspace = workspace("writer-busy");
    let store_root = root(&workspace);
    let mut first = MemoryRecordOwner::open(&store_root).unwrap();
    let error = match MemoryRecordOwner::open(&store_root) {
        Ok(_) => panic!("one namespace must never admit two actual writers"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(error.to_string(), "memory writer lease is busy");
    assert_eq!(first.records().count(), 0);
    let id = first
        .add("known writer owns this fact", draft(&workspace))
        .unwrap();
    drop(first);
    let mut next = MemoryRecordOwner::open(&store_root).unwrap();
    assert_eq!(next.records().count(), 1);
    assert_eq!(next.records().next().unwrap().id, id);
    next.add("released lease admits the next writer", draft(&workspace))
        .unwrap();
    drop(next);
    assert_eq!(MemoryRecordOwner::read(&store_root).unwrap().len(), 2);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn real_seed_write_recall_update_delete_and_restart_share_one_owner() {
    let workspace = workspace("journey");
    let store = MemoryStore::at(&workspace);
    let id = store
        .add("memory coding convention uses explicit receipts")
        .unwrap();
    let stores = [MemStore::new(root(&workspace), MemTier::Project, true)];
    let fact = FileMemory.read_fact(&stores, &id).unwrap();
    assert_eq!(fact.trust(), Trust::Untrusted);
    let initial = MemoryRecordOwner::read(&root(&workspace))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(initial.metadata.provenance.kind, MemorySourceKind::Operator);
    assert!(matches!(
        initial.metadata.scope,
        MemoryRecordScope::Workspace { .. }
    ));
    assert_eq!(
        store
            .update(&id, "memory coding convention uses exact physical receipts")
            .unwrap(),
        Some(id.clone())
    );
    let updated = MemoryRecordOwner::read(&root(&workspace))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert!(
        FileMemory
            .read_fact(&stores, &id)
            .unwrap()
            .body()
            .contains("physical")
    );
    assert!(store.remove_checked(&id).unwrap());
    assert!(FileMemory.read_fact(&stores, &id).is_err());
    assert!(store.load().is_empty());
    let restarted = MemoryRecordOwner::read(&root(&workspace))
        .unwrap()
        .pop()
        .unwrap();
    assert!(restarted.deleted && restarted.body.is_empty());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn confidence_expiry_private_scope_and_real_path_change_bind_actual_recall() {
    let workspace = workspace("eligibility");
    let other = workspace.join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(workspace.join("config.txt"), "old config").unwrap();
    let mut metadata = draft(&workspace);
    metadata.bind_path(&workspace, "config.txt").unwrap();
    metadata.invalidation = MemoryInvalidation::UntilPathChanges;
    metadata.confidence_ppm = 123_456;
    let mut owner = MemoryRecordOwner::open(&root(&workspace)).unwrap();
    let id = owner.add("memory bound configuration", metadata).unwrap();
    drop(owner);
    let record = MemoryRecordOwner::read(&root(&workspace))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        record.eligibility(Some(&other), super::now_unix_seconds()),
        Err(MemoryRecordExclusion::ScopeDenied)
    );
    let stores = [MemStore::new(root(&workspace), MemTier::Project, true)];
    let audit = FileMemory::audit_recall_with_slot_in_scope_and_policy_at(
        &stores,
        "memory configuration",
        &MemBudget::default(),
        &MemoryRecallStrategy::default(),
        false,
        super::now_unix_seconds(),
        crate::MemoryRetrievalPolicy::default(),
    );
    assert_eq!(audit.observation.candidates[0].confidence_ppm, 123_456);
    std::fs::write(workspace.join("config.txt"), "changed config").unwrap();
    assert!(FileMemory.read_fact(&stores, &id).is_err());
    let mut expiry = draft(&workspace);
    expiry.created_unix_seconds = 10;
    expiry.invalidation = MemoryInvalidation::ExpiresAt { unix_seconds: 20 };
    let mut owner = MemoryRecordOwner::open(&root(&workspace)).unwrap();
    owner.add("memory already expired", expiry).unwrap();
    drop(owner);
    assert!(
        FileMemory
            .recall(&stores, "memory expired", &MemBudget::default())
            .recalled()
            .is_empty()
    );
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn sealed_receipt_rejects_update_delete_and_another_workspace() {
    let workspace = workspace("receipt");
    let store = MemoryStore::at(&workspace);
    let id = store.add("actual receipt body").unwrap();
    let receipt = MemoryRecordOwner::capture_receipt(
        &root(&workspace),
        &workspace,
        &id,
        "actual receipt body",
    )
    .unwrap();
    assert!(MemoryRecordOwner::resolve_receipt(&root(&workspace), &workspace, &receipt).is_ok());
    let other = workspace.join("different");
    std::fs::create_dir(&other).unwrap();
    assert!(MemoryRecordOwner::resolve_receipt(&root(&workspace), &other, &receipt).is_err());
    store.update(&id, "new receipt body").unwrap();
    assert!(MemoryRecordOwner::resolve_receipt(&root(&workspace), &workspace, &receipt).is_err());
    assert!(store.remove_checked(&id).unwrap());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn exact_revision_cas_and_tombstones_prevent_legacy_resurrection() {
    let workspace = workspace("cas");
    let store_root = root(&workspace);
    let mut owner = MemoryRecordOwner::open(&store_root).unwrap();
    let id = owner.add("fact has provenance", draft(&workspace)).unwrap();
    assert!(
        owner
            .update(&id, 0, "lost update", draft(&workspace))
            .is_err()
    );
    assert!(owner.delete(&id, 0).is_err());
    assert_eq!(owner.revision(), 1);
    std::fs::write(store_root.join("legacy.md"), "legacy private body").unwrap();
    owner
        .replace_legacy("legacy", "legacy private body", None)
        .unwrap();
    drop(owner);
    assert!(
        FileMemory
            .read_fact(
                &[MemStore::new(store_root.clone(), MemTier::Project, true)],
                "legacy"
            )
            .is_err()
    );
    assert!(std::fs::read_to_string(store_root.join("legacy.md")).is_ok());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn explicit_global_scope_requires_versioned_record_and_legacy_user_stays_private() {
    let home = workspace("user-scope");
    let workspace = workspace("project-scope");
    let mut owner = MemoryRecordOwner::open(&root(&home)).unwrap();
    let global = MemoryRecordDraft::explicit_global(
        "explicit operator global consent",
        super::now_unix_seconds(),
    )
    .unwrap();
    let global_id = owner.add("public coding convention", global).unwrap();
    let private_id = owner
        .add("private customer identifier", draft(&home))
        .unwrap();
    drop(owner);
    std::fs::write(
        root(&home).join("legacy-private.md"),
        "private legacy customer secret",
    )
    .unwrap();
    let stores = [MemStore::user(&home).with_recall_workspace(&workspace)];
    assert!(FileMemory.read_fact(&stores, &global_id).is_ok());
    assert!(FileMemory.read_fact(&stores, &private_id).is_err());
    assert!(FileMemory.read_fact(&stores, "legacy-private").is_err());
    std::fs::remove_dir_all(home).unwrap();
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn same_title_conflicts_are_denied_inside_one_store_and_across_stores() {
    let workspace = workspace("names");
    let store = MemoryStore::at(&workspace);
    let first = store
        .add("# Coding convention\nAlways use policy A")
        .unwrap();
    let second = store
        .add("# Coding convention\nAlways use policy B")
        .unwrap();
    let stores = [MemStore::new(root(&workspace), MemTier::Project, true)];
    assert!(FileMemory.read_fact(&stores, &first).is_err());
    assert!(FileMemory.read_fact(&stores, &second).is_err());
    assert!(
        FileMemory
            .recall(&stores, "coding convention", &MemBudget::default())
            .recalled()
            .is_empty()
    );
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn bounded_fields_and_unknown_schema_never_inherit_trust() {
    let workspace = workspace("bounds");
    let mut owner = MemoryRecordOwner::open(&root(&workspace)).unwrap();
    let mut metadata = draft(&workspace);
    metadata.confidence_ppm = 1_000_001;
    assert!(owner.add("invalid confidence", metadata).is_err());
    let mut metadata = draft(&workspace);
    metadata.provenance = MemoryProvenance {
        kind: MemorySourceKind::Imported,
        reference: "x".repeat(513),
    };
    assert!(owner.add("invalid source", metadata).is_err());
    assert!(
        owner
            .add(
                &"x".repeat(super::MAX_RECORD_BODY_BYTES + 1),
                draft(&workspace)
            )
            .is_err()
    );
    owner.add("real record", draft(&workspace)).unwrap();
    drop(owner);
    let path = root(&workspace).join("records-v1.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["version"] = 99.into();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(MemoryRecordOwner::read(&root(&workspace)).is_err());
    assert!(MemoryStore::at(&workspace).load().is_empty());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[cfg(unix)]
#[test]
fn ancestor_symlink_refuses_actual_writer() {
    let workspace = workspace("symlink");
    let outside = workspace.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("linked")).unwrap();
    assert!(MemoryRecordOwner::open(&workspace.join("linked/memory")).is_err());
    assert!(!outside.join("memory").exists());
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn actual_expiry_boundary_and_stale_deleted_path_preserve_current_truth() {
    let workspace = workspace("exact-expiry");
    std::fs::write(workspace.join("source.txt"), "old evidence").unwrap();
    let now = super::now_unix_seconds();
    let mut metadata = draft(&workspace);
    metadata.invalidation = MemoryInvalidation::ExpiresAt {
        unix_seconds: now + 10,
    };
    metadata.bind_path(&workspace, "source.txt").unwrap();
    let mut owner = MemoryRecordOwner::open(&root(&workspace)).unwrap();
    let id = owner
        .add("memory expiry boundary evidence", metadata)
        .unwrap();
    drop(owner);
    let stores = [MemStore::new(root(&workspace), MemTier::Project, true)];
    let budget = MemBudget::default();
    let slot = MemoryRecallStrategy::default();
    let before = FileMemory.recall_with_slot_policy_at(
        &stores,
        "expiry boundary evidence",
        &budget,
        &slot,
        now + 9,
        crate::MemoryRetrievalPolicy::default(),
    );
    assert_eq!(before.recalled().len(), 1);
    let at = FileMemory.recall_with_slot_policy_at(
        &stores,
        "expiry boundary evidence",
        &budget,
        &slot,
        now + 10,
        crate::MemoryRetrievalPolicy::default(),
    );
    assert!(at.recalled().is_empty());
    std::fs::remove_file(workspace.join("source.txt")).unwrap();
    assert!(MemoryStore::at(&workspace).remove_checked(&id).unwrap());
    let deletion =
        MemoryRecordOwner::capture_deletion_receipt(&root(&workspace), &workspace, &id).unwrap();
    assert!(
        MemoryRecordOwner::resolve_deletion_receipt(&root(&workspace), &workspace, &deletion)
            .unwrap()
            .deleted
    );
    std::fs::remove_dir_all(workspace).unwrap();
}

// Own the actual paused fixture child through assertion/unwind failures as well as the
// bounded successful kill/reap observation below. It performs no work outside this scratch store.
#[cfg(unix)]
struct CrashChild(std::process::Child);
#[cfg(unix)]
impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[test]
fn actual_process_death_after_prepared_fsync_keeps_old_committed_memory() {
    let workspace = workspace("physical-crash");
    let store = MemoryStore::at(&workspace);
    let original = store.add("old physically committed memory").unwrap();
    let mut child = CrashChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("memory_records::tests::memory_prepared_crash_child")
            .env("ITERON_MEMORY_V1_CRASH_ROOT", &workspace)
            .env("ITERON_MEMORY_V1_CRASH_AT_PREPARED", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let ready = root(&workspace).join("crash-test-ready");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        if child.0.try_wait().unwrap().is_some() {
            panic!("crash fixture exited before prepare barrier");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let prepared = ready.exists();
    child.0.kill().unwrap();
    let reap_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut reaped = false;
    while std::time::Instant::now() < reap_deadline {
        if child.0.try_wait().unwrap().is_some() {
            reaped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        prepared && reaped,
        "physical fixture prepare/reap deadline exceeded"
    );
    let reopened = MemoryRecordOwner::open(&root(&workspace)).unwrap();
    assert_eq!(reopened.revision(), 1);
    assert_eq!(reopened.records().next().unwrap().id, original);
    assert_eq!(
        MemoryStore::at(&workspace).load()[0].text,
        "old physically committed memory"
    );
    drop(reopened);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[cfg(unix)]
#[test]
fn memory_prepared_crash_child() {
    let Some(workspace) = std::env::var_os("ITERON_MEMORY_V1_CRASH_ROOT") else {
        return;
    };
    let _ =
        MemoryStore::at(&PathBuf::from(workspace)).add("new uncommitted memory must not appear");
    panic!("physical fault fixture did not stop at prepared publication");
}

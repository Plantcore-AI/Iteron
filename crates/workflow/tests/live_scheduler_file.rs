#![cfg(any(unix, windows))]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use iteron_workflow::live_scheduler::{
    WorkflowConfigV1, WorkflowNodeV1, WorkflowPlanChangeV1, WorkflowPlanJournal, WorkflowReplanV1,
    WorkflowScheduler, WorkflowSchedulerError, file_journal::WorkflowFileJournal,
};
use iteron_workflow::task_dag::TaskBudget;

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "iteron-live-workflow-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        iteron_support::durable_windows_state::provision_private_directory(&path).unwrap();
        Self(path)
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config() -> WorkflowConfigV1 {
    WorkflowConfigV1 {
        workflow_id: "durable-plan".into(),
        budget: TaskBudget {
            max_turns: 10,
            max_tokens: 10_000,
            max_cost_microusd: 1_000,
            max_wall_ms: 10_000,
        },
        max_nodes: 10,
        max_edges: 20,
        max_concurrency: 2,
        started_at_unix_ms: 10,
        deadline_unix_ms: 10_010,
    }
}

fn add() -> WorkflowReplanV1 {
    WorkflowReplanV1 {
        expected_revision: 0,
        changes: vec![WorkflowPlanChangeV1::Add {
            node: WorkflowNodeV1 {
                id: 1,
                label: "persistent future work".into(),
                task: "inspect repository".into(),
                dependencies: vec![],
                assigned_agent: 2,
                input_digest: "f".repeat(64),
                budget: TaskBudget {
                    max_turns: 1,
                    max_tokens: 100,
                    max_cost_microusd: 10,
                    max_wall_ms: 1_000,
                },
            },
        }],
    }
}

#[test]
fn durable_plan_reopen_preserves_cas_receipt_and_single_writer_lease() {
    let directory = PrivateDirectory::new();
    let journal = WorkflowFileJournal::open(&directory.0).unwrap();
    let mut scheduler = WorkflowScheduler::open(journal, config()).unwrap();
    assert!(WorkflowFileJournal::open(&directory.0).is_err());
    let first = scheduler.replan("request-1", add()).unwrap();
    let snapshot = scheduler.snapshot().unwrap();
    drop(scheduler);
    let mut reopened =
        WorkflowScheduler::open(WorkflowFileJournal::open(&directory.0).unwrap(), config())
            .unwrap();
    assert_eq!(reopened.snapshot().unwrap(), snapshot);
    let replay = reopened.replan("request-1", add()).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.revision, first.revision);
    assert_eq!(replay.sequence, first.sequence);
    assert_eq!(reopened.ready_nodes(10).unwrap(), [1]);
}

#[test]
fn lost_durable_snapshot_and_corrupt_payload_are_never_fresh_workflows() {
    let directory = PrivateDirectory::new();
    let mut scheduler =
        WorkflowScheduler::open(WorkflowFileJournal::open(&directory.0).unwrap(), config())
            .unwrap();
    scheduler.replan("request-1", add()).unwrap();
    drop(scheduler);
    fs::remove_file(directory.0.join("workflow.json")).unwrap();
    assert!(matches!(
        WorkflowScheduler::open(WorkflowFileJournal::open(&directory.0).unwrap(), config()),
        Err(WorkflowSchedulerError::Store(_))
    ));

    let other = PrivateDirectory::new();
    let mut scheduler =
        WorkflowScheduler::open(WorkflowFileJournal::open(&other.0).unwrap(), config()).unwrap();
    scheduler.replan("request-1", add()).unwrap();
    drop(scheduler);
    let path = other.0.join("workflow.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    envelope["snapshot"]["revision"] = serde_json::json!(7);
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(WorkflowFileJournal::open(&other.0).unwrap().load().is_err());
}

#[test]
#[cfg(unix)]
fn untrusted_directory_symlink_and_hardlink_do_not_gain_storage_authority() {
    let directory = PrivateDirectory::new();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(WorkflowFileJournal::open(&directory.0).is_err());
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let outside = PrivateDirectory::new();
    let target = outside.0.join("target");
    fs::write(&target, b"company data stays outside scheduler").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, directory.0.join("workflow.json")).unwrap();
    assert!(
        WorkflowFileJournal::open(&directory.0)
            .unwrap()
            .load()
            .is_err()
    );
    fs::remove_file(directory.0.join("workflow.json")).unwrap();
    fs::hard_link(&target, directory.0.join("workflow.json")).unwrap();
    assert!(
        WorkflowFileJournal::open(&directory.0)
            .unwrap()
            .load()
            .is_err()
    );
    assert_eq!(
        fs::read(target).unwrap(),
        b"company data stays outside scheduler"
    );
}

#[test]
fn stored_config_migration_requires_explicit_matching_immutable_contract() {
    let directory = PrivateDirectory::new();
    let mut scheduler =
        WorkflowScheduler::open(WorkflowFileJournal::open(&directory.0).unwrap(), config())
            .unwrap();
    scheduler.replan("request-1", add()).unwrap();
    drop(scheduler);
    let before = fs::read(directory.0.join("workflow.json")).unwrap();
    let mut incompatible = config();
    incompatible.max_concurrency = 3;
    assert!(matches!(
        WorkflowScheduler::open(
            WorkflowFileJournal::open(&directory.0).unwrap(),
            incompatible
        ),
        Err(WorkflowSchedulerError::Invalid(_))
    ));
    assert_eq!(fs::read(directory.0.join("workflow.json")).unwrap(), before);
}

#![cfg(unix)]

use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentFileJournal, ControllerError,
    ControllerStoreError,
};
use iteron_protocol::Capability;
use iteron_protocol::agent_control::{AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentStateV1};
use iteron_protocol::capability_set::CapabilitySet;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-agent-journal-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config() -> AgentControllerConfig {
    AgentControllerConfig {
        workspace_scope: "file-journal-test".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: AgentBudgetV1 {
            turns: 10,
            tokens: 10_000,
            cost_microusd: 10_000,
            wall_ms: 60_000,
        },
        max_agents: 4,
        max_pending_per_agent: 8,
    }
}

fn spawn() -> AgentCommandV1 {
    AgentCommandV1::Spawn {
        parent_id: AgentIdV1(1),
        label: "child".into(),
        task: "Investigate safely".into(),
        capabilities: CapabilitySet::only(Capability::ReadOnly),
        budget: AgentBudgetV1 {
            turns: 3,
            tokens: 1_000,
            cost_microusd: 1_000,
            wall_ms: 10_000,
        },
        write_paths: vec![],
    }
}

#[test]
fn exclusive_lease_snapshot_integrity_and_lost_genesis_refusal() {
    let directory = Directory::new();
    let journal = AgentFileJournal::open(&directory.0).unwrap();
    assert!(matches!(
        AgentFileJournal::open(&directory.0),
        Err(ControllerStoreError::Conflict)
    ));
    let mut controller = AgentController::open(journal, config()).unwrap();
    let child = controller
        .execute(AgentActor::Operator, "spawn", spawn())
        .unwrap()
        .agent_id;
    let revision = controller.revision();
    drop(controller);
    let reopened =
        AgentController::open(AgentFileJournal::open(&directory.0).unwrap(), config()).unwrap();
    assert_eq!(reopened.revision(), revision);
    assert_eq!(
        reopened.inspect(AgentActor::Operator, child).unwrap().label,
        "child"
    );
    drop(reopened);
    let snapshot = directory.0.join("agents.json");
    fs::remove_file(&snapshot).unwrap();
    assert!(matches!(
        AgentController::open(AgentFileJournal::open(&directory.0).unwrap(), config()),
        Err(ControllerError::Store(ControllerStoreError::OutcomeUnknown))
    ));
}

#[test]
fn unsafe_directory_and_linked_state_are_refused_before_mutation() {
    let directory = Directory::new();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        AgentFileJournal::open(&directory.0),
        Err(ControllerStoreError::Unavailable)
    ));
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let outside = Directory::new();
    let target = outside.0.join("target");
    fs::write(&target, b"preserve me").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, directory.0.join("agents.lock")).unwrap();
    assert!(AgentFileJournal::open(&directory.0).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve me");
    fs::remove_file(directory.0.join("agents.lock")).unwrap();
    fs::hard_link(&target, directory.0.join("agents.lock")).unwrap();
    assert!(AgentFileJournal::open(&directory.0).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve me");
}

#[test]
fn pinned_namespace_survives_directory_replacement_and_corruption_is_refused() {
    let directory = Directory::new();
    let displaced = directory.0.with_extension("displaced");
    let mut controller =
        AgentController::open(AgentFileJournal::open(&directory.0).unwrap(), config()).unwrap();
    fs::rename(&directory.0, &displaced).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)
        .unwrap();
    controller
        .execute(AgentActor::Operator, "spawn", spawn())
        .unwrap();
    assert!(!directory.0.join("agents.json").exists());
    drop(controller);
    let snapshot = displaced.join("agents.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    value["snapshot"]["agents"]["2"]["view"]["label"] =
        serde_json::json!("changed without checksum");
    fs::write(&snapshot, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(AgentController::open(AgentFileJournal::open(&displaced).unwrap(), config()).is_err());
    fs::remove_dir_all(displaced).unwrap();
}

#[test]
fn process_kill_retains_active_ownership_and_never_blindly_restarts() {
    for boundary in ["delivered", "consumed"] {
        let directory = Directory::new();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "kill_test_helper", "--nocapture"])
            .env("ITERON_AGENT_KILL_TEST_DIRECTORY", &directory.0)
            .env("ITERON_AGENT_KILL_TEST_BOUNDARY", boundary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !directory.0.join("ready").exists() && Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "helper exited before durable checkpoint"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        if !directory.0.join("ready").exists() {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("helper did not reach bounded durable checkpoint");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let mut recovered =
            AgentController::open(AgentFileJournal::open(&directory.0).unwrap(), config()).unwrap();
        let state = recovered
            .inspect(AgentActor::Operator, AgentIdV1(2))
            .unwrap()
            .state;
        assert!(matches!(state, AgentStateV1::RecoveryRequired { .. }));
        assert_eq!(
            recovered.begin_turn(AgentIdV1(2)),
            Err(ControllerError::RecoveryRequired)
        );
        let epoch = state.epoch().unwrap();
        assert_eq!(
            recovered.reconcile_stopped(AgentIdV1(2), epoch, false, false),
            Err(ControllerError::RecoveryRequired)
        );
        recovered
            .reconcile_stopped(AgentIdV1(2), epoch, true, false)
            .unwrap();
        assert_eq!(recovered.begin_turn(AgentIdV1(2)).unwrap(), None);
    }
}

#[test]
fn kill_test_helper() {
    let Some(directory) = std::env::var_os("ITERON_AGENT_KILL_TEST_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let mut controller =
        AgentController::open(AgentFileJournal::open(&directory).unwrap(), config()).unwrap();
    let child = controller
        .execute(AgentActor::Operator, "spawn", spawn())
        .unwrap()
        .agent_id;
    let epoch = controller.begin_turn(child).unwrap().unwrap();
    let delivered = controller.deliver(child, epoch, true).unwrap();
    if std::env::var("ITERON_AGENT_KILL_TEST_BOUNDARY").unwrap() == "consumed" {
        controller
            .mark_consumed(child, epoch, &[delivered[0].id])
            .unwrap();
    }
    fs::write(directory.join("ready"), b"ready").unwrap();
    std::thread::park_timeout(Duration::from_secs(30));
    panic!("kill helper exceeded its bounded lifetime");
}

#[test]
fn fresh_leaf_namespace_and_ancestor_pins_are_the_actual_journal_writer() {
    let parent = Directory::new();
    let state = parent.0.join("fresh-private-state");
    let mut owner =
        AgentController::open(AgentFileJournal::provision(&state).unwrap(), config()).unwrap();
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let child = owner
        .execute(AgentActor::Operator, "fresh-child", spawn())
        .unwrap()
        .agent_id;
    let revision = owner.revision();
    drop(owner);
    let reopened =
        AgentController::open(AgentFileJournal::open(&state).unwrap(), config()).unwrap();
    assert_eq!(reopened.revision(), revision);
    assert_eq!(
        reopened.inspect(AgentActor::Operator, child).unwrap().label,
        "child"
    );
    drop(reopened);
    let outside = Directory::new();
    let link = parent.0.join("linked-parent");
    symlink(&outside.0, &link).unwrap();
    assert!(AgentFileJournal::provision(&link.join("state")).is_err());
    assert!(!outside.0.join("state").exists());
}

#[test]
fn replacing_an_ancestor_does_not_redirect_a_live_pinned_controller() {
    let parent = Directory::new();
    let state = parent.0.join("private-state");
    let displaced = parent.0.with_extension("ancestor-displaced");
    let mut owner =
        AgentController::open(AgentFileJournal::provision(&state).unwrap(), config()).unwrap();
    fs::rename(&parent.0, &displaced).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&parent.0).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
    owner
        .execute(AgentActor::Operator, "after-retarget", spawn())
        .unwrap();
    assert!(!state.join("agents.json").exists());
    drop(owner);
    let old_state = displaced.join("private-state");
    let reopened =
        AgentController::open(AgentFileJournal::open(&old_state).unwrap(), config()).unwrap();
    assert_eq!(
        reopened
            .inspect(AgentActor::Operator, AgentIdV1(2))
            .unwrap()
            .label,
        "child"
    );
    drop(reopened);
    fs::remove_dir_all(displaced).unwrap();
}

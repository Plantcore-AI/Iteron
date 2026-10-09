//! Native registry/supervisor journeys in the explicitly admitted unconfined posture. These
//! prove terminal and whole-Job lifecycle, not filesystem/network sandboxing. Required isolation
//! is separately admitted by the host and is never silently replaced with this posture.
use super::supervisor::Supervisor;
use super::tests::{assert_definite_error, installed_launch, temp_root, tool_use};
use super::types::{ActionError, JobState};
use crate::{Registry, ToolExecution};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

struct Workspace(std::path::PathBuf);
impl Workspace {
    fn new(label: &str) -> Self {
        Self(temp_root(label))
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn registry(root: &Path) -> Registry {
    let mut registry = Registry::coding_agent(root).unwrap();
    registry.set_confine_execution(false); // Trusted operator posture, never a tool argument.
    registry
        .install_process_launch_policy(super::ProcessLaunchPolicy::owner(root).unwrap())
        .unwrap();
    registry
}
fn value(execution: ToolExecution) -> Value {
    let ToolExecution::Definite(result) = execution else {
        panic!("native terminal outcome was uncertain: {execution:?}");
    };
    assert!(!result.is_error, "{}", result.content);
    serde_json::from_str(&result.content).unwrap()
}
async fn start(registry: &Registry, command: &str) -> Value {
    let started = value(
        registry
            .run_effect(tool_use("process_start", json!({"command":command})))
            .await,
    );
    assert_eq!(
        started["backend"],
        iteron_sandbox::PersistentBackend::WindowsJobConPty.as_str()
    );
    started
}
async fn poll(registry: &Registry, job: &str, cursor: u64, wait: u64) -> Value {
    value(
        registry
            .run_effect(tool_use(
                "process_poll",
                json!({"job_id":job,"stdout_cursor":cursor,"wait_ms":wait}),
            ))
            .await,
    )
}
async fn observe(registry: &Registry, job: &str, mut cursor: u64, marker: &str) -> (u64, String) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut text = String::new();
        loop {
            let page = poll(registry, job, cursor, 250).await;
            text.push_str(page["stdout"]["text"].as_str().unwrap());
            assert!(
                text.len() <= 256 * 1024,
                "native fixture observation overflow"
            );
            cursor = page["stdout"]["next_cursor"].as_u64().unwrap();
            if text.contains(marker) {
                return (cursor, text);
            }
            assert!(
                matches!(page["state"]["kind"].as_str(), Some("running" | "stopping")),
                "{page}"
            );
        }
    })
    .await
    .unwrap()
}
async fn terminal(registry: &Registry, job: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut cursor = 0;
        loop {
            let page = poll(registry, job, cursor, 250).await;
            if !matches!(page["state"]["kind"].as_str(), Some("running" | "stopping")) {
                assert_ne!(page["state"]["kind"], "cleanup_unknown", "{page}");
                assert_eq!(page["stdout"]["closed"], true);
                assert_eq!(page["stderr"]["closed"], true);
                return page;
            }
            cursor = page["stdout"]["next_cursor"].as_u64().unwrap();
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn native_windows_registry_terminal_stdin_eof_and_cursors() {
    let root = Workspace::new("windows-terminal");
    let registry = registry(&root.0);
    let started = start(
        &registry,
        "printf 'ready\\n'; while IFS= read -r line; do printf 'out:%s\\n' \"$line\"; done",
    )
    .await;
    let job = started["job_id"].as_str().unwrap();
    observe(&registry, job, 0, "ready").await;
    let reply = value(
        registry
            .run_effect(tool_use(
                "process_write",
                json!({"job_id":job,"input":"héllo\n","eof":true}),
            ))
            .await,
    );
    assert_eq!(reply["accepted_bytes"], "héllo\n".len());
    assert_eq!(reply["stdin_closed"], true);
    let done = terminal(&registry, job).await;
    assert_eq!(done["state"]["kind"], "exited");
    assert_eq!(done["state"]["exit_code"], 0);
    let retained = poll(&registry, job, 0, 0).await;
    assert!(
        retained["stdout"]["text"]
            .as_str()
            .unwrap()
            .contains("out:héllo")
    );
    let cursor = retained["stdout"]["next_cursor"].as_u64().unwrap();
    let duplicate = poll(&registry, job, cursor, 0).await;
    assert_eq!(duplicate["stdout"]["text"], "");
    let listed = value(
        registry
            .run_effect(tool_use("process_list", json!({})))
            .await,
    );
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["job_id"], job);
}

#[tokio::test]
async fn native_windows_registry_resize_and_authoritative_stop() {
    let root = Workspace::new("windows-resize");
    let registry = registry(&root.0);
    let started = start(&registry, "printf 'initial:'; stty size; printf 'ready\\n'; IFS= read -r line; printf 'resized:'; stty size; sleep 30").await;
    let job = started["job_id"].as_str().unwrap();
    let (cursor, text) = observe(&registry, job, 0, "ready").await;
    assert!(
        text.contains(&format!(
            "initial:{} {}",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS
        )),
        "{text:?}"
    );
    value(
        registry
            .run_effect(tool_use(
                "process_resize",
                json!({"job_id":job,"rows":41,"cols":123}),
            ))
            .await,
    );
    value(
        registry
            .run_effect(tool_use(
                "process_write",
                json!({"job_id":job,"input":"observe-size\n"}),
            ))
            .await,
    );
    let (_, text) = observe(&registry, job, cursor, "resized:41 123").await;
    assert!(text.contains("resized:41 123"));
    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_write",
                json!({"job_id":job,"input":"x".repeat(super::MAX_STDIN_BYTES+1)}),
            ))
            .await,
        "byte limit",
    );
    let stopped = value(
        registry
            .run_effect(tool_use("process_stop", json!({"job_id":job})))
            .await,
    );
    assert_eq!(stopped["state"]["kind"], "stopped");
    let again = value(
        registry
            .run_effect(tool_use("process_stop", json!({"job_id":job})))
            .await,
    );
    assert_eq!(again["state"], stopped["state"]);
    terminal(&registry, job).await;
}

#[tokio::test]
async fn native_windows_exec_yield_and_future_drop_retire_the_actual_job() {
    let root = Workspace::new("windows-yield");
    let supervisor = Supervisor::new().unwrap();
    let yielded = supervisor
        .exec_yield(
            &root.0,
            "printf 'yield-ready\\n'; sleep 30",
            installed_launch(&root.0),
            false,
            Duration::from_millis(250),
            30,
        )
        .await
        .unwrap();
    assert!(yielded.yielded);
    let job = yielded.job_id;
    let stopped = supervisor.stop(&job).await.unwrap();
    assert!(matches!(stopped.state, JobState::Stopped { .. }));
    assert!(stopped.stdout.closed && stopped.stderr.closed);
    {
        let future = supervisor.exec_yield(
            &root.0,
            "printf 'drop-ready\\n'; sleep 30",
            installed_launch(&root.0),
            false,
            Duration::from_secs(30),
            30,
        );
        tokio::pin!(future);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            tokio::select! {
                result=&mut future => panic!("future completed before drop: {result:?}"),
                _=tokio::time::sleep(Duration::from_millis(10))=>{}
            }
            let running = supervisor
                .list()
                .into_iter()
                .find(|value| matches!(value.state, JobState::Running));
            if let Some(running) = running {
                let page = supervisor.poll(&running.job_id, 0, 0, 0).await.unwrap();
                if page.stdout.text.contains("drop-ready") {
                    break;
                }
            }
            assert!(tokio::time::Instant::now() < deadline);
        }
    } // Drop the real polled exec future. Its same-Job cancellation guard performs cleanup.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if supervisor
                .list()
                .iter()
                .all(|value| !matches!(value.state, JobState::Running | JobState::Stopping))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        supervisor
            .list()
            .iter()
            .all(|value| !matches!(value.state, JobState::CleanupUnknown { .. }))
    );
}

#[tokio::test]
async fn native_windows_stop_write_race_retains_every_accepted_reply() {
    let root = Workspace::new("windows-control-race");
    let supervisor = Supervisor::new().unwrap();
    let started = supervisor
        .start(
            &root.0,
            "printf 'ready\\n'; sleep 30",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS,
            installed_launch(&root.0),
            false,
        )
        .await
        .unwrap();
    let (stop, again, write) = tokio::join!(
        supervisor.stop(&started.job_id),
        supervisor.stop(&started.job_id),
        supervisor.write(&started.job_id, b"late\n".to_vec(), false)
    );
    assert!(stop.is_ok(), "{stop:?}");
    assert!(again.is_ok(), "{again:?}");
    assert!(!matches!(write, Err(ActionError::Unknown(_))), "{write:?}");
    assert!(
        supervisor
            .list()
            .iter()
            .all(|value| !matches!(value.state, JobState::CleanupUnknown { .. }))
    );
}

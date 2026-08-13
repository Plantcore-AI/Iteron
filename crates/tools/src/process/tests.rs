#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::MAX_STDIN_BYTES;
use super::output::OutputRing;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::supervisor::Supervisor;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::types::ActionError;
use super::types::{JobState, ProcessSnapshot};
use super::{
    ChildProcessEnvironmentPolicy, InstalledProcessLaunchPolicy, MAX_COMMAND_BYTES,
    POLL_OUTPUT_BYTES_PER_STREAM, ProcessLaunchPolicy, RETAINED_OUTPUT_BYTES_PER_STREAM,
};
use crate::{Registry, ToolExecution};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use iteron_protocol::ToolResult;
use iteron_protocol::{Capability, Purity, ToolUse};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{Duration, Instant};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> PathBuf {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "core-process-{label}-{}-{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn tool_use(name: &str, input: Value) -> ToolUse {
    ToolUse {
        id: format!("call-{name}"),
        name: name.into(),
        input,
    }
}

fn installed_launch(root: &Path) -> InstalledProcessLaunchPolicy {
    let policy = ProcessLaunchPolicy::owner(root).unwrap();
    let child_environment = iteron_sandbox::bounded_child_environment(
        policy.environment.reuse,
        policy.environment.max_entries,
        policy.environment.max_bytes,
        &policy.environment.blocked_names,
        &[],
    )
    .unwrap();
    InstalledProcessLaunchPolicy {
        policy,
        child_environment,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn result(execution: ToolExecution) -> ToolResult {
    match execution {
        ToolExecution::Definite(result) | ToolExecution::Unknown(result) => result,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn success_json(execution: ToolExecution) -> Value {
    let result = result(execution);
    assert!(!result.is_error, "{}", result.content);
    serde_json::from_str(&result.content).unwrap()
}

fn assert_definite_error(execution: ToolExecution, needle: &str) {
    let ToolExecution::Definite(result) = execution else {
        panic!("pre-dispatch validation must be a definite refusal");
    };
    assert!(result.is_error);
    assert!(result.content.contains(needle), "{}", result.content);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn start(registry: &Registry, command: &str) -> Option<Value> {
    start_with_size(
        registry,
        command,
        super::DEFAULT_PTY_ROWS,
        super::DEFAULT_PTY_COLS,
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn start_with_size(
    registry: &Registry,
    command: &str,
    rows: u16,
    cols: u16,
) -> Option<Value> {
    if registry.installed_process_launch_policy().is_none() {
        registry
            .install_process_launch_policy(ProcessLaunchPolicy::owner(&registry.root).unwrap())
            .unwrap();
    }
    let execution = registry
        .run_effect(tool_use(
            "process_start",
            json!({"command":command,"rows":rows,"cols":cols}),
        ))
        .await;
    let result = result(execution);
    if result.is_error && result.content.contains("unsupported") {
        // Linux is intentionally capability-gated when trusted bwrap/user namespaces are absent.
        #[cfg(target_os = "macos")]
        panic!(
            "macOS Seatbelt PTY backend unexpectedly unavailable: {}",
            result.content
        );
        #[cfg(target_os = "linux")]
        return None;
    }
    assert!(!result.is_error, "{}", result.content);
    Some(serde_json::from_str(&result.content).unwrap())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn poll(registry: &Registry, job_id: &str, wait_ms: u64) -> Value {
    poll_from(registry, job_id, 0, 0, wait_ms).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn poll_from(
    registry: &Registry,
    job_id: &str,
    stdout_cursor: u64,
    stderr_cursor: u64,
    wait_ms: u64,
) -> Value {
    success_json(
        registry
            .run_effect(tool_use(
                "process_poll",
                json!({
                    "job_id":job_id,
                    "stdout_cursor":stdout_cursor,
                    "stderr_cursor":stderr_cursor,
                    "wait_ms":wait_ms
                }),
            ))
            .await,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_terminal(registry: &Registry, job_id: &str) -> Value {
    let mut stdout_cursor = 0;
    let mut stderr_cursor = 0;
    for _ in 0..20 {
        let value = poll_from(registry, job_id, stdout_cursor, stderr_cursor, 250).await;
        let kind = value["state"]["kind"].as_str().unwrap();
        if !matches!(kind, "running" | "stopping") {
            return poll(registry, job_id, 0).await;
        }
        stdout_cursor = value["stdout"]["next_cursor"].as_u64().unwrap();
        stderr_cursor = value["stderr"]["next_cursor"].as_u64().unwrap();
    }
    panic!("job `{job_id}` did not reach a terminal state within the fixed test budget");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_stdout_contains_from(
    registry: &Registry,
    job_id: &str,
    mut stdout_cursor: u64,
    needle: &str,
) -> (Value, String) {
    let mut last = None;
    let mut observed = String::new();
    for _ in 0..12 {
        let value = poll_from(registry, job_id, stdout_cursor, 0, 250).await;
        observed.push_str(value["stdout"]["text"].as_str().unwrap());
        stdout_cursor = value["stdout"]["next_cursor"].as_u64().unwrap();
        if observed.contains(needle) {
            return (value, observed);
        }
        last = Some(value);
    }
    panic!(
        "job `{job_id}` did not emit {needle:?} within the fixed test budget; observed: {observed:?}; last snapshot: {last:?}"
    );
}

#[cfg(target_os = "linux")]
async fn wait_supervisor_stdout_contains(
    supervisor: &Supervisor,
    job_id: &str,
    needle: &str,
) -> ProcessSnapshot {
    let mut stdout_cursor = 0;
    let mut stderr_cursor = 0;
    let mut observed = String::new();
    let mut last = None;
    for _ in 0..12 {
        let snapshot = supervisor
            .poll(job_id, stdout_cursor, stderr_cursor, 250)
            .await
            .unwrap();
        observed.push_str(&snapshot.stdout.text);
        stdout_cursor = snapshot.stdout.next_cursor;
        stderr_cursor = snapshot.stderr.next_cursor;
        if observed.contains(needle) {
            return snapshot;
        }
        last = Some(snapshot);
    }
    panic!(
        "job `{job_id}` did not emit {needle:?} within the fixed test budget; observed: {observed:?}; last snapshot: {last:?}"
    );
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn output_ring_pages_by_byte_cursor_and_discloses_retention_gaps() {
    let mut ring = OutputRing::default();
    let oversized = vec![b'x'; RETAINED_OUTPUT_BYTES_PER_STREAM + 17];
    assert!(!ring.push(&oversized));

    let first = ring.frame(0).unwrap();
    assert!(first.gap);
    assert_eq!(first.oldest_cursor, 17);
    assert_eq!(first.text.len(), super::POLL_OUTPUT_BYTES_PER_STREAM);
    assert!(first.has_more);

    let second = ring.frame(first.next_cursor).unwrap();
    assert!(!second.gap);
    assert_eq!(second.oldest_cursor, first.oldest_cursor);
    assert!(second.next_cursor > first.next_cursor);
    assert!(ring.frame(first.observed_cursor + 1).is_err());

    ring.close();
    let tail = ring.frame(first.observed_cursor).unwrap();
    assert!(tail.closed);
    assert!(tail.text.is_empty());
}

#[test]
fn output_observation_limit_notifies_once_and_serialized_pages_stay_fixed_bounded() {
    let mut small = OutputRing::with_limits(4, 8);
    assert!(small.push(b"0123456789"));
    assert!(!small.push(b"more"));
    let small_frame = small.frame(0).unwrap();
    assert!(small_frame.gap);
    assert_eq!(small_frame.text, "more");

    let mut hostile = OutputRing::default();
    assert!(!hostile.push(&vec![0_u8; POLL_OUTPUT_BYTES_PER_STREAM]));
    let stdout = hostile.frame(0).unwrap();
    let mut hostile_stderr = OutputRing::default();
    assert!(!hostile_stderr.push(&vec![0_u8; POLL_OUTPUT_BYTES_PER_STREAM]));
    let stderr = hostile_stderr.frame(0).unwrap();
    let snapshot = ProcessSnapshot {
        schema_version: 2,
        job_id: "job-0123456789abcdef-00000001".into(),
        backend: "linux-bubblewrap-pty",
        runtime_policy: super::ProcessRuntimePolicy::default(),
        awaiting_stdin: false,
        state: JobState::Running,
        stdout,
        stderr,
    };
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    assert!(
        encoded.len() <= POLL_OUTPUT_BYTES_PER_STREAM * 12 + 2_048,
        "JSON escaping must add only a fixed worst-case overhead: {} bytes",
        encoded.len()
    );
    assert!(
        !encoded.contains(&0),
        "control bytes must stay JSON escaped"
    );
}

#[test]
fn cleanup_unknown_is_terminal_for_the_caller_but_quarantines_a_capacity_slot() {
    let state = JobState::CleanupUnknown {
        trigger: "injected",
    };
    assert!(state.is_terminal());
    assert!(!state.is_reconciled_terminal());
}

#[test]
fn coding_registry_has_six_typed_process_tools_one_control_port_and_read_only_has_none() {
    let root = temp_root("registry");
    let coding = Registry::coding_agent(&root).unwrap();
    let read_only = Registry::read_only(&root).unwrap();
    let coding_names: Vec<_> = coding.specs().into_iter().map(|spec| spec.name).collect();
    let read_only_names: Vec<_> = read_only
        .specs()
        .into_iter()
        .map(|spec| spec.name)
        .collect();

    for name in [
        "process_start",
        "process_list",
        "process_poll",
        "process_write",
        "process_resize",
        "process_stop",
    ] {
        assert!(coding_names.iter().any(|candidate| candidate == name));
        assert!(!read_only_names.iter().any(|candidate| candidate == name));
        assert_eq!(coding.purity_of(name), Some(Purity::Effecting));
    }
    assert_eq!(
        coding.capability_of("process_poll"),
        Some(Capability::ReadOnly)
    );
    assert_eq!(
        coding.capability_of("process_list"),
        Some(Capability::ReadOnly)
    );
    for name in [
        "process_start",
        "process_write",
        "process_resize",
        "process_stop",
    ] {
        assert_eq!(coding.capability_of(name), Some(Capability::CodeExecuting));
    }
    assert_eq!(
        coding
            .process_control()
            .unwrap()
            .list()
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(read_only.process_control().is_none());
    cleanup(&root);
}

#[tokio::test]
async fn process_launch_policy_is_required_one_shot_and_consumed_before_spawn() {
    let root = temp_root("launch-policy");
    let other = temp_root("launch-policy-other");
    let registry = Registry::coding_agent(&root).unwrap();

    assert_definite_error(
        registry
            .run_effect(tool_use("process_start", json!({"command":"exit 0"})))
            .await,
        "launch policy was not installed",
    );

    let mut policy = ProcessLaunchPolicy::owner(&other).unwrap();
    policy.environment = ChildProcessEnvironmentPolicy {
        reuse: false,
        max_entries: 0,
        max_bytes: 0,
        blocked_names: vec!["EXACT_BLOCKED_NAME".into()],
    };
    registry
        .install_process_launch_policy(policy.clone())
        .unwrap();
    assert_eq!(registry.installed_process_launch_policy(), Some(policy));
    assert!(
        registry
            .install_process_launch_policy(ProcessLaunchPolicy::owner(&root).unwrap())
            .is_err(),
        "a resume cannot replace the session-pinned owner"
    );
    assert_definite_error(
        registry
            .run_effect(tool_use("process_start", json!({"command":"exit 0"})))
            .await,
        "absolute job workspace",
    );

    assert!(
        iteron_sandbox::bounded_child_environment(true, 0, 0, &[], &[]).is_err(),
        "reuse refuses rather than silently truncating an ambient environment"
    );
    assert_eq!(
        iteron_sandbox::bounded_child_environment(false, 0, 0, &[], &[]).unwrap(),
        Vec::new()
    );
    cleanup(&root);
    cleanup(&other);
}

#[tokio::test]
async fn malformed_and_oversized_inputs_refuse_before_process_dispatch() {
    let root = temp_root("input-bounds");
    let registry = Registry::coding_agent(&root).unwrap();

    assert_definite_error(
        registry
            .run_effect(tool_use("process_start", json!({"command":""})))
            .await,
        "non-empty",
    );
    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_start",
                json!({"command":"x".repeat(MAX_COMMAND_BYTES + 1)}),
            ))
            .await,
        "byte limit",
    );
    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_poll",
                json!({"job_id":"job-not-valid","wait_ms":0}),
            ))
            .await,
        "must match",
    );
    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_poll",
                json!({"job_id":"job-0000000000000001-00000001","wait_ms":super::MAX_STDIN_POLL_MILLISECONDS + 1}),
            ))
            .await,
        &format!("{}ms", super::MAX_STDIN_POLL_MILLISECONDS),
    );
    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_resize",
                json!({
                    "job_id":"job-0000000000000001-00000001",
                    "rows":0,
                    "cols":80
                }),
            ))
            .await,
        "at least 1",
    );
    cleanup(&root);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn pty_job_round_trip_long_poll_and_terminal_eof_have_one_typed_lifecycle() {
    let root = temp_root("round-trip");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(
        &registry,
        "while IFS= read -r line; do printf 'out:%s\\n' \"$line\"; done",
    )
    .await
    else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    assert_eq!(started["schema_version"], 2);
    assert!(started["backend"].as_str().unwrap().ends_with("-pty"));

    let written = success_json(
        registry
            .run_effect(tool_use(
                "process_write",
                json!({"job_id":job_id,"input":"héllo\n","eof":true}),
            ))
            .await,
    );
    assert_eq!(written["schema_version"], 1);
    assert_eq!(written["accepted_bytes"], "héllo\n".len());
    assert_eq!(written["stdin_closed"], true);

    let terminal = wait_terminal(&registry, job_id).await;
    assert_eq!(terminal["state"]["kind"], "exited");
    assert_eq!(terminal["state"]["exit_code"], 0);
    assert!(
        terminal["stdout"]["text"]
            .as_str()
            .unwrap()
            .contains("out:héllo")
    );
    assert_eq!(terminal["stdout"]["closed"], true);

    let next = terminal["stdout"]["next_cursor"].as_u64().unwrap();
    let no_duplicate = success_json(
        registry
            .run_effect(tool_use(
                "process_poll",
                json!({"job_id":job_id,"stdout_cursor":next,"wait_ms":0}),
            ))
            .await,
    );
    assert_eq!(no_duplicate["stdout"]["text"], "");
    cleanup(&root);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn pty_is_controlling_terminal_and_resize_notifies_foreground_group() {
    let root = temp_root("pty-resize");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start_with_size(
        &registry,
        "trap 'printf \"winch:\"; stty size' WINCH; if test -t 0 && test -t 1; then printf 'tty:yes\\n'; else printf 'tty:no\\n'; fi; printf 'initial:'; stty size; printf 'ready\\n'; while :; do sleep 1; done",
        31,
        97,
    )
    .await
    else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    assert!(started["backend"].as_str().unwrap().ends_with("-pty"));

    let (initial, initial_text) = wait_stdout_contains_from(&registry, job_id, 0, "ready").await;
    assert!(initial_text.contains("tty:yes"), "{initial_text:?}");
    assert!(initial_text.contains("initial:31 97"), "{initial_text:?}");

    let resized = success_json(
        registry
            .run_effect(tool_use(
                "process_resize",
                json!({"job_id":job_id,"rows":41,"cols":123}),
            ))
            .await,
    );
    assert_eq!(resized["schema_version"], 2);
    assert_eq!(resized["state"]["kind"], "running");

    let initial_cursor = initial["stdout"]["next_cursor"].as_u64().unwrap();
    let (_, resized_output) =
        wait_stdout_contains_from(&registry, job_id, initial_cursor, "winch:41 123").await;
    assert!(resized_output.contains("winch:41 123"));
    let stopped = success_json(
        registry
            .run_effect(tool_use("process_stop", json!({"job_id":job_id})))
            .await,
    );
    assert_eq!(stopped["state"]["kind"], "stopped");
    cleanup(&root);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn long_poll_wakes_on_output_without_a_model_side_busy_loop() {
    let root = temp_root("long-poll");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(&registry, "sleep 0.2; printf ready; sleep 30").await else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    let initial = poll(&registry, job_id, 0).await;
    let mut stdout_cursor = initial["stdout"]["next_cursor"].as_u64().unwrap();
    let mut stderr_cursor = initial["stderr"]["next_cursor"].as_u64().unwrap();
    let mut observed = initial["stdout"]["text"].as_str().unwrap().to_owned();
    let began = Instant::now();
    for _ in 0..3 {
        if observed.contains("ready") {
            break;
        }
        let value = poll_from(&registry, job_id, stdout_cursor, stderr_cursor, 2_000).await;
        observed.push_str(value["stdout"]["text"].as_str().unwrap());
        stdout_cursor = value["stdout"]["next_cursor"].as_u64().unwrap();
        stderr_cursor = value["stderr"]["next_cursor"].as_u64().unwrap();
        if observed.contains("ready") {
            break;
        }
    }
    assert!(observed.contains("ready"), "{observed:?}");
    assert!(began.elapsed() < Duration::from_secs(3));
    let _ = registry
        .run_effect(tool_use("process_stop", json!({"job_id":job_id})))
        .await;
    cleanup(&root);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn oversized_stdin_refuses_and_stop_is_authoritative_idempotent() {
    let root = temp_root("stop");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(&registry, "sleep 30").await else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();

    assert_definite_error(
        registry
            .run_effect(tool_use(
                "process_write",
                json!({"job_id":job_id,"input":"x".repeat(MAX_STDIN_BYTES + 1)}),
            ))
            .await,
        "byte limit",
    );
    let stopped = success_json(
        registry
            .run_effect(tool_use("process_stop", json!({"job_id":job_id})))
            .await,
    );
    assert_eq!(stopped["state"]["kind"], "stopped");
    let stopped_again = success_json(
        registry
            .run_effect(tool_use("process_stop", json!({"job_id":job_id})))
            .await,
    );
    assert_eq!(stopped_again["state"]["kind"], "stopped");
    cleanup(&root);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn concurrent_stop_and_write_never_drop_an_accepted_control_reply() {
    let root = temp_root("control-race");
    let supervisor = Supervisor::new().unwrap();
    let started = match supervisor
        .start(
            &root,
            "sleep 30",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS,
            installed_launch(&root),
        )
        .await
    {
        Ok(started) => started,
        Err(ActionError::Definite(error)) if error.contains("unsupported") => {
            cleanup(&root);
            return;
        }
        Err(error) => panic!("start failed: {error:?}"),
    };

    let (first_stop, second_stop, write) = tokio::join!(
        supervisor.stop(&started.job_id),
        supervisor.stop(&started.job_id),
        supervisor.write(&started.job_id, b"late".to_vec(), false),
    );
    assert!(first_stop.is_ok(), "first stop: {first_stop:?}");
    assert!(second_stop.is_ok(), "second stop: {second_stop:?}");
    assert!(
        !matches!(write, Err(ActionError::Unknown(_))),
        "accepted control reply was dropped: {write:?}"
    );
    cleanup(&root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn natural_leader_exit_kills_residual_process_group_descendants() {
    let root = temp_root("natural-orphan");
    let marker = root.join("escaped.txt");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(
        &registry,
        "(sleep 1; printf escaped > escaped.txt) & printf 'leader-done\\n'",
    )
    .await
    else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    let terminal = wait_terminal(&registry, job_id).await;
    assert_eq!(terminal["state"]["kind"], "exited");
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        !marker.exists(),
        "a background descendant escaped the job group"
    );
    cleanup(&root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn detached_session_cannot_outlive_the_reported_job_terminal() {
    let root = temp_root("detached-session");
    let session_attempted = root.join("setsid-attempted.txt");
    let group_attempted = root.join("setpgid-attempted.txt");
    let session_marker = root.join("setsid-escaped.txt");
    let group_marker = root.join("setpgid-escaped.txt");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(
        &registry,
        "/usr/bin/python3 -c 'import os,time; open(\"setsid-attempted.txt\",\"w\").write(\"yes\"); os.setsid(); [os.close(fd) for fd in (0,1,2)]; time.sleep(1); open(\"setsid-escaped.txt\",\"w\").write(\"escaped\")' & /usr/bin/python3 -c 'import os,time; open(\"setpgid-attempted.txt\",\"w\").write(\"yes\"); os.setpgid(0,0); [os.close(fd) for fd in (0,1,2)]; time.sleep(1); open(\"setpgid-escaped.txt\",\"w\").write(\"escaped\")' & i=0; while [ \"$i\" -lt 100 ] && { [ ! -f setsid-attempted.txt ] || [ ! -f setpgid-attempted.txt ]; }; do sleep 0.01; i=$((i+1)); done; test -f setsid-attempted.txt && test -f setpgid-attempted.txt && printf 'leader-done\\n'",
    )
    .await
    else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    let terminal = wait_terminal(&registry, job_id).await;
    assert_eq!(terminal["state"]["kind"], "exited");
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(session_attempted.exists(), "setsid oracle never executed");
    assert!(group_attempted.exists(), "setpgid oracle never executed");
    assert!(
        !session_marker.exists(),
        "a descendant escaped cleanup by creating a new session"
    );
    assert!(
        !group_marker.exists(),
        "a descendant escaped cleanup by creating a new process group"
    );
    cleanup(&root);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[tokio::test]
async fn unsupported_platform_refuses_detached_session_oracle_before_spawn() {
    let root = temp_root("unsupported-detached-session");
    let marker = root.join("spawned.txt");
    let registry = Registry::coding_agent(&root).unwrap();
    registry
        .install_process_launch_policy(ProcessLaunchPolicy::owner(&root).unwrap())
        .unwrap();
    let execution = registry
        .run_effect(tool_use(
            "process_start",
            json!({
                "command":"printf spawned > spawned.txt; /usr/bin/python3 -c 'import os; os.setsid()'"
            }),
        ))
        .await;
    assert_definite_error(execution, "unsupported");
    assert!(!marker.exists(), "unsupported backend spawned a child");
    cleanup(&root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn registry_drop_kills_the_owned_group_before_a_delayed_descendant_can_escape() {
    let root = temp_root("drop-cleanup");
    let marker = root.join("escaped.txt");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(
        &registry,
        "(sleep 1; printf escaped > escaped.txt) & printf armed; wait",
    )
    .await
    else {
        cleanup(&root);
        return;
    };
    let job_id = started["job_id"].as_str().unwrap();
    let (_, armed) = wait_stdout_contains_from(&registry, job_id, 0, "armed").await;
    assert!(armed.contains("armed"));
    drop(registry);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        !marker.exists(),
        "Registry drop left an orphaned descendant"
    );
    cleanup(&root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn aborted_controller_reports_cleanup_unknown_and_kills_its_group() {
    let root = temp_root("actor-abort");
    let marker = root.join("escaped.txt");
    let supervisor = Supervisor::new().unwrap();
    let started = match supervisor
        .start(
            &root,
            "(sleep 1; printf escaped > escaped.txt) & printf armed; wait",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS,
            installed_launch(&root),
        )
        .await
    {
        Ok(started) => started,
        Err(ActionError::Definite(error)) if error.contains("unsupported") => {
            cleanup(&root);
            return;
        }
        Err(error) => panic!("start failed: {error:?}"),
    };
    let armed = wait_supervisor_stdout_contains(&supervisor, &started.job_id, "armed").await;
    supervisor.abort_actor(&started.job_id).unwrap();
    let after_abort = supervisor
        .poll(
            &started.job_id,
            armed.stdout.next_cursor,
            armed.stderr.next_cursor,
            2_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        after_abort.state,
        JobState::CleanupUnknown {
            trigger: "controller_dropped"
        }
    ));
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        !marker.exists(),
        "an aborted controller leaked its process group"
    );
    cleanup(&root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn persistent_process_keeps_writes_inside_the_workspace_boundary() {
    let parent = temp_root("confinement-parent");
    let root = parent.join("workspace");
    std::fs::create_dir(&root).unwrap();
    let outside = parent.join("outside.txt");
    let registry = Registry::coding_agent(&root).unwrap();
    let Some(started) = start(
        &registry,
        "printf inside > inside.txt; printf outside > ../outside.txt",
    )
    .await
    else {
        cleanup(&parent);
        return;
    };
    let terminal = wait_terminal(&registry, started["job_id"].as_str().unwrap()).await;
    assert_eq!(terminal["state"]["kind"], "exited");
    assert_eq!(
        std::fs::read_to_string(root.join("inside.txt")).unwrap(),
        "inside"
    );
    assert!(
        !outside.exists(),
        "persistent backend wrote outside workspace"
    );
    cleanup(&parent);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn job_ids_are_nonce_scoped_monotonic_and_foreign_runtime_ids_fail_loud() {
    let root = temp_root("job-id");
    let first = Supervisor::new().unwrap();
    let second = Supervisor::new().unwrap();
    let one = match first
        .start(
            &root,
            "exit 0",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS,
            installed_launch(&root),
        )
        .await
    {
        Ok(value) => value,
        Err(ActionError::Definite(error)) if error.contains("unsupported") => {
            cleanup(&root);
            return;
        }
        Err(error) => panic!("start failed: {error:?}"),
    };
    let two = first
        .start(
            &root,
            "exit 0",
            super::DEFAULT_PTY_ROWS,
            super::DEFAULT_PTY_COLS,
            installed_launch(&root),
        )
        .await
        .unwrap();
    assert_ne!(one.job_id, two.job_id);
    assert_eq!(&one.job_id[..20], &two.job_id[..20]);
    let error = second.poll(&one.job_id, 0, 0, 0).await.unwrap_err();
    let ActionError::Definite(error) = error else {
        panic!("foreign runtime lookup must be a definite lost result");
    };
    assert!(error.contains("previous or different runtime"));
    cleanup(&root);
}

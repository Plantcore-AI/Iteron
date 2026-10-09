//! Real factory-to-native pipe journeys. Required confinement has no unavailable/unsupported
//! skip, and a transport-only Job cannot satisfy the LPAC backend assertion.
use super::*;
use crate::{OutputObservation, OutputObserver, OutputTerminalReason, PersistentBackend};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-windows-sandbox-factory-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn required_windows_pipe_factory_preserves_streams_eof_and_real_terminal_retirement() {
    let workspace = Workspace::new();
    let confinement = Confinement::egress_off(&workspace.0);
    let scratch = confinement.scratch.clone();
    let mut process = crate::spawn_confined_process(
        "IFS= read -r value; printf 'out:%s' \"$value\"; printf 'err:%s' \"$value\" >&2; printf '%s' \"$value\" > native-result.txt",
        &confinement,
    ).await.expect("the required native LPAC pipe factory must be executable");
    assert_eq!(process.backend(), PersistentBackend::WindowsLpacPipes);
    let mut input = process.take_stdin().unwrap();
    let mut stdout = process.take_stdout().unwrap();
    let mut stderr = process.take_stderr().unwrap();
    input.write_all(b"exact-value\n").await.unwrap();
    input.shutdown().await.unwrap();
    drop(input);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let (out_result, err_result, status) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err),
            process.wait()
        )
    })
    .await
    .expect("actual pipes and the retained Job must close within the fixture bound");
    out_result.unwrap();
    err_result.unwrap();
    assert!(status.unwrap().success());
    assert_eq!(out, b"out:exact-value");
    assert_eq!(err, b"err:exact-value");
    assert_eq!(
        std::fs::read(workspace.0.join("native-result.txt")).unwrap(),
        b"exact-value"
    );
    assert!(
        !scratch.try_exists().unwrap(),
        "wait includes exact profile and scratch retirement"
    );
}

#[tokio::test]
async fn required_windows_one_shot_uses_the_same_owned_scope_and_filtered_frozen_environment() {
    let workspace = Workspace::new();
    let mut confinement = Confinement::egress_off(&workspace.0);
    let mut environment =
        crate::bounded_child_environment(true, 4096, 1024 * 1024, &[], &[]).unwrap();
    environment.push(("ITERON_FACTORY_MARKER".into(), "known".into()));
    environment.push((
        "ITERON_TEST_SECRET_KEY".into(),
        "must-not-reach-child".into(),
    ));
    confinement.child_environment = Some(environment);
    confinement
        .sensitive_env_names
        .push("ITERON_TEST_SECRET_KEY".into());
    confinement.max_output_bytes = 128;
    confinement.timeout_secs = 5;
    let scratch = confinement.scratch.clone();
    let output = crate::platform_sandbox().run(
        "printf '%s:%s' \"${ITERON_FACTORY_MARKER-unset}\" \"${ITERON_TEST_SECRET_KEY-unset}\"; printf 'separate-error' >&2; exit 7",
        &confinement,
    ).await.expect("required LPAC one-shot must not downgrade to unconfined execution");
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, "known:unset");
    assert_eq!(output.stderr, "separate-error");
    assert!(!output.timed_out && !output.stdout_truncated && !output.stderr_truncated);
    assert!(!scratch.try_exists().unwrap());
}

#[tokio::test]
async fn required_windows_one_shot_timeout_retains_exact_job_and_bounded_pipe_cleanup() {
    let workspace = Workspace::new();
    let (observer, mut observations) =
        OutputObserver::bounded("owned Windows factory timeout", 1, 4);
    let observer = observer.with_owned_group_cleanup();
    let mut confinement =
        Confinement::egress_off(&workspace.0).with_output_observer(observer.clone());
    confinement.timeout_secs = 1;
    confinement.max_output_bytes = 32;
    let scratch = confinement.scratch.clone();
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        crate::platform_sandbox().run("printf 'owned-start'; sleep 30 & wait", &confinement),
    )
    .await
    .expect("native collector cleanup must remain bounded")
    .unwrap();
    assert!(output.timed_out);
    assert!(output.stdout.starts_with("owned-start"));
    let terminal = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(OutputObservation::Terminal(terminal)) = observations.recv().await {
                break terminal;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(terminal.reason, OutputTerminalReason::TimedOut);
    assert!(
        observer.owned_group_cleanup_known(),
        "only actual Job0 plus native retirement proves cleanup"
    );
    assert!(
        !scratch.try_exists().unwrap(),
        "a known timeout includes actual empty Job and scratch retirement"
    );
}

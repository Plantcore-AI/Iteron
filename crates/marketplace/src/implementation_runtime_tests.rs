#![cfg(unix)]

use crate::{
    EvidenceLimits, ImplementationFailurePolicy, ImplementationManifest, ImplementationRegistry,
    ImplementationRuntime, ImplementationRuntimeError, ProcessLaunchPlan, RuntimeState, Version,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use sha2::Digest as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

const LOADED: &str = r#"{"protocol":"iteron-implementation/1","request_id":"host-1","implementation_id":"test.impl","module":"prompt_system","payload":{"result":"loaded","provider_contract":{"id":"iteron/prompt.system/provider@v1","version":1},"observation_schema":{"id":"iteron/prompt.system/observation@v1","version":1}}}"#;
const STARTED: &str = r#"{"protocol":"iteron-implementation/1","request_id":"host-2","implementation_id":"test.impl","module":"prompt_system","payload":{"result":"started","run_id":"run-1"}}"#;
const OBSERVATION: &str = r#"{"protocol":"iteron-implementation/1","implementation_id":"test.impl","module":"prompt_system","run_id":"run-1","sequence":0,"schema":{"id":"iteron/prompt.system/observation@v1","version":1},"terminal":true,"observation":{"score":7}}"#;
const STOPPED: &str = r#"{"protocol":"iteron-implementation/1","request_id":"host-3","implementation_id":"test.impl","module":"prompt_system","payload":{"result":"stopped"}}"#;

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    digest: String,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new(body: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "iteron-implementation-runtime-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create provider fixture root");
        let path = root.join("provider.sh");
        let script = format!("#!/bin/sh\nset -eu\n{body}\n");
        let bytes = script.into_bytes();
        fs::write(&path, &bytes).expect("write provider fixture");
        let mut permissions = fs::metadata(&path).expect("fixture metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("make provider fixture executable");
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        Self {
            root,
            path,
            digest,
            bytes,
        }
    }

    fn plan(
        &self,
        runtime_ms: u64,
        cancellation_ms: u64,
        stdout_bytes: usize,
    ) -> ProcessLaunchPlan {
        let mut registry = ImplementationRegistry::new(CapabilitySet::none());
        registry
            .register(ImplementationManifest {
                implementation_id: "test.impl".to_owned(),
                implementation_version: Version(1, 0, 0),
                module: ModuleId::PromptSystem,
                artifact_sha256: self.digest.clone(),
                executable: "provider.sh".to_owned(),
                argv: Vec::new(),
                protocol_version: 1,
                requested_capabilities: CapabilitySet::none(),
                dependencies: Vec::new(),
                runtime_deadline_ms: runtime_ms,
                cancellation_deadline_ms: cancellation_ms,
                evidence_limits: EvidenceLimits {
                    stdout_bytes,
                    stderr_bytes: 4096,
                    observations: 8,
                },
                failure_policy: ImplementationFailurePolicy::FailClosed,
            })
            .expect("admit provider fixture");
        let verified = registry
            .verify_artifact("test.impl", &self.bytes)
            .expect("verify fixture bytes")
            .expect("fixture is registered");
        registry
            .launch_plan("test.impl", &self.root, &verified)
            .expect("mint launch plan")
            .expect("fixture is registered")
    }

    fn runtime(
        &self,
        runtime_ms: u64,
        cancellation_ms: u64,
        stdout_bytes: usize,
    ) -> ImplementationRuntime {
        ImplementationRuntime::launch(self.plan(runtime_ms, cancellation_ms, stdout_bytes))
            .expect("launch fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.root);
    }
}

#[test]
fn direct_process_completes_load_start_observe_stop_lifecycle() {
    let fixture = Fixture::new(&format!(
        "read -r _\nprintf '%s\\n' '{LOADED}'\nread -r _\nprintf '%s\\n' '{STARTED}'\nprintf '%s\\n' '{OBSERVATION}'\nread -r _\nprintf '%s\\n' '{STOPPED}'"
    ));
    let mut runtime = fixture.runtime(2_000, 250, 4096);

    runtime.load().expect("load response");
    runtime
        .start(
            "run-1",
            format!("sha256:{}", "b".repeat(64)),
            serde_json::json!({"candidate": 1}),
            1_000,
        )
        .expect("start response");
    let observation = runtime
        .next_observation(Duration::from_millis(500))
        .expect("terminal observation");
    assert!(observation.terminal);
    assert_eq!(observation.sequence, 0);
    runtime.stop("test complete").expect("stop and reap");

    assert_eq!(runtime.state(), RuntimeState::Stopped);
    assert!(runtime.is_reaped());
    assert_eq!(runtime.evidence().observations, 1);
    assert!(runtime.evidence().stderr.is_empty());
}

#[test]
fn bad_response_correlation_fails_closed_and_reaps() {
    let bad = LOADED.replace("host-1", "other-request");
    let fixture = Fixture::new(&format!("read -r _\nprintf '%s\\n' '{bad}'\n/bin/sleep 1"));
    let mut runtime = fixture.runtime(2_000, 50, 4096);

    assert!(matches!(
        runtime.load(),
        Err(ImplementationRuntimeError::Protocol(_))
    ));
    assert_eq!(runtime.state(), RuntimeState::Failed);
    assert!(runtime.is_reaped());
}

#[test]
fn oversized_stdout_fails_closed_and_reaps() {
    let fixture = Fixture::new(&format!(
        "read -r _\nprintf '%s\\n' '{}'\n/bin/sleep 1",
        "x".repeat(512)
    ));
    // This case owns the stdout bound, not the scheduler. Keep the independent runtime deadline
    // wide enough that a fully parallel workspace test cannot turn it into a deadline assertion.
    let mut runtime = fixture.runtime(30_000, 2_000, 128);

    let error = runtime
        .load()
        .expect_err("oversized stdout must fail closed");
    assert!(
        matches!(
            error,
            ImplementationRuntimeError::OutputTooLarge {
                stream: "stdout",
                max: 128
            }
        ),
        "unexpected oversized-stdout failure: {error:?}"
    );
    assert!(runtime.is_reaped());
}

#[test]
fn runtime_timeout_kills_and_reaps_silent_provider() {
    let fixture = Fixture::new("read -r _\n/bin/sleep 1");
    let mut runtime = fixture.runtime(40, 20, 4096);

    assert!(matches!(
        runtime.load(),
        Err(ImplementationRuntimeError::Deadline { operation: "load" })
    ));
    assert!(runtime.is_reaped());
}

#[test]
fn cancellation_timeout_kills_and_reaps_provider() {
    let fixture = Fixture::new(&format!(
        "read -r _\nprintf '%s\\n' '{LOADED}'\nread -r _\nprintf '%s\\n' '{STARTED}'\nread -r _\n/bin/sleep 1"
    ));
    let mut runtime = fixture.runtime(2_000, 40, 4096);
    runtime.load().expect("load response");
    runtime
        .start(
            "run-1",
            format!("sha256:{}", "c".repeat(64)),
            serde_json::json!({}),
            1_000,
        )
        .expect("start response");

    assert!(matches!(
        runtime.cancel("run-1", "test cancellation"),
        Err(ImplementationRuntimeError::Deadline {
            operation: "cancel"
        })
    ));
    assert!(runtime.is_reaped());
}

#[test]
fn executable_digest_mismatch_never_spawns() {
    let fixture = Fixture::new("exit 0");
    let plan = fixture.plan(100, 20, 128);
    fs::write(&fixture.path, b"tampered after verification").expect("tamper fixture");

    assert!(matches!(
        ImplementationRuntime::launch(plan),
        Err(ImplementationRuntimeError::ContentMismatch { .. })
    ));
}

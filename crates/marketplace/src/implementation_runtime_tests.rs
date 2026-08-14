#![cfg(unix)]

use crate::{
    EvidenceLimits, ImplementationFailurePolicy, ImplementationManifest,
    ImplementationProtocolError, ImplementationRegistry, ImplementationResponse,
    ImplementationResponseEnvelope, ImplementationRuntime, ImplementationRuntimeError,
    ImplementationState, ProcessLaunchPlan, RuntimeState, RuntimeStateOperation, Version,
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
        self.plan_version(runtime_ms, cancellation_ms, stdout_bytes, 1)
    }

    fn plan_version(
        &self,
        runtime_ms: u64,
        cancellation_ms: u64,
        stdout_bytes: usize,
        protocol_version: u16,
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
                protocol_version,
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

    fn runtime_version(
        &self,
        runtime_ms: u64,
        cancellation_ms: u64,
        stdout_bytes: usize,
        protocol_version: u16,
    ) -> ImplementationRuntime {
        ImplementationRuntime::launch(self.plan_version(
            runtime_ms,
            cancellation_ms,
            stdout_bytes,
            protocol_version,
        ))
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
    // This case owns the successful lifecycle, not scheduler latency. Keep enough independent
    // runtime budget that a fully parallel workspace test cannot turn it into a deadline test.
    let mut runtime = fixture.runtime(30_000, 2_000, 4096);

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
    // This case owns response correlation, not scheduler latency. Keep enough independent runtime
    // budget that a fully parallel workspace test cannot turn it into a deadline assertion.
    let mut runtime = fixture.runtime(30_000, 2_000, 4096);

    let error = runtime
        .load()
        .expect_err("wrong request id must fail closed");
    assert!(
        matches!(
            error,
            ImplementationRuntimeError::Protocol(ImplementationProtocolError::Correlation)
        ),
        "unexpected correlation failure: {error:?}"
    );
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

#[test]
fn v2_runtime_snapshots_migrates_restores_and_checks_readiness() {
    let node = iteron_tunables::capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::PromptSystem)
        .unwrap();
    let old = ImplementationState::new(
        ModuleId::PromptSystem,
        "test.impl",
        "run-state",
        1,
        node.lifecycle.snapshot.clone(),
        serde_json::json!({"counter": 7}),
    )
    .unwrap();
    let new = ImplementationState::new(
        ModuleId::PromptSystem,
        "test.impl",
        "run-state",
        2,
        node.lifecycle.snapshot,
        serde_json::json!({"counter": 8}),
    )
    .unwrap();
    let response = |request_id: &str, payload| {
        serde_json::to_string(&ImplementationResponseEnvelope {
            protocol: crate::IMPLEMENTATION_PROTOCOL.into(),
            request_id: request_id.into(),
            implementation_id: "test.impl".into(),
            module: ModuleId::PromptSystem,
            payload,
        })
        .unwrap()
    };
    let loaded = LOADED.replace("iteron-implementation/1", "iteron-implementation/2");
    let snapshotted = response(
        "host-2",
        ImplementationResponse::Snapshotted { state: old.clone() },
    );
    let migrated = response(
        "host-3",
        ImplementationResponse::Migrated { state: new.clone() },
    );
    let restored = response(
        "host-4",
        ImplementationResponse::Restored {
            run_id: new.run_id.clone(),
            generation: new.generation,
            state_schema: new.state_schema.clone(),
            state_sha256: new.state_sha256.clone(),
        },
    );
    let ready = response(
        "host-5",
        ImplementationResponse::Ready {
            run_id: new.run_id.clone(),
            generation: new.generation,
            state_schema: new.state_schema.clone(),
            state_sha256: new.state_sha256.clone(),
        },
    );
    let stopped = STOPPED
        .replace("iteron-implementation/1", "iteron-implementation/2")
        .replace("host-3", "host-6");
    let fixture = Fixture::new(&format!(
        "read -r _\nprintf '%s\\n' '{loaded}'\nread -r _\nprintf '%s\\n' '{snapshotted}'\nread -r _\nprintf '%s\\n' '{migrated}'\nread -r _\nprintf '%s\\n' '{restored}'\nread -r _\nprintf '%s\\n' '{ready}'\nread -r _\nprintf '%s\\n' '{stopped}'"
    ));
    let mut runtime = fixture.runtime_version(5_000, 500, 32 * 1024, 2);
    runtime.load().unwrap();
    let snapshot = runtime.snapshot("run-state", 1, 500).unwrap();
    let migrated = runtime.migrate(&snapshot, 2, 500).unwrap();
    runtime.restore(&migrated, 500).unwrap();
    runtime.readiness(&migrated, 500).unwrap();
    runtime.stop("stateful complete").unwrap();

    assert_eq!(runtime.evidence().state.len(), 4);
    assert_eq!(
        runtime
            .evidence()
            .state
            .iter()
            .map(|evidence| evidence.operation)
            .collect::<Vec<_>>(),
        vec![
            RuntimeStateOperation::Snapshot,
            RuntimeStateOperation::Migrate,
            RuntimeStateOperation::Restore,
            RuntimeStateOperation::Readiness,
        ]
    );
    assert!(runtime.is_reaped());
}

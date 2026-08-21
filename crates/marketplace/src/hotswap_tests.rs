#[cfg(unix)]
use crate::{
    ActiveImplementationHandle, EvidenceLimits, ImplementationFailurePolicy,
    ImplementationManifest, ImplementationResponse, ImplementationResponseEnvelope,
    ImplementationRuntime, RuntimeGenerationError, RuntimeHotSwapExecutor, Version,
    implementation_authority_sha256,
};
use crate::{
    HotSwapBlockKind, HotSwapCoordinator, HotSwapExecutor, HotSwapGeneration, HotSwapPhase,
    HotSwapRequest, HotSwapResult, HotSwapStageError, HotSwapTransaction, ImplementationState,
    replay_ledger,
};
#[cfg(unix)]
use crate::{ImplementationRegistry, ProcessLaunchPlan};
#[cfg(unix)]
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
#[cfg(unix)]
use sha2::Digest as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static LEDGER_ID: AtomicU64 = AtomicU64::new(1);

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn ledger_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iteron-hotswap-{label}-{}-{}.jsonl",
        std::process::id(),
        LEDGER_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn generation(
    number: u64,
    implementation: &str,
    artifact: char,
    state: &ImplementationState,
) -> HotSwapGeneration {
    HotSwapGeneration {
        generation: number,
        implementation_id: implementation.into(),
        artifact_sha256: digest(artifact),
        state_sha256: state.state_sha256.clone(),
    }
}

fn states() -> (ImplementationState, ImplementationState) {
    let node = iteron_tunables::capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::PromptSystem)
        .unwrap();
    (
        ImplementationState::new(
            ModuleId::PromptSystem,
            "old.impl",
            "run-1",
            1,
            node.lifecycle.snapshot.clone(),
            serde_json::json!({"counter": 1}),
        )
        .unwrap(),
        ImplementationState::new(
            ModuleId::PromptSystem,
            "new.impl",
            "run-1",
            2,
            node.lifecycle.snapshot,
            serde_json::json!({"counter": 2}),
        )
        .unwrap(),
    )
}

fn request(
    transaction: &str,
    old_state: &ImplementationState,
    new_state: &ImplementationState,
) -> HotSwapRequest {
    HotSwapRequest {
        transaction_id: transaction.into(),
        module: ModuleId::PromptSystem,
        candidate_sha256: digest('c'),
        old: generation(1, "old.impl", 'a', old_state),
        new: generation(2, "new.impl", 'b', new_state),
        authority_sha256: digest('d'),
        deadline_ms: 1_000,
    }
}

struct FakeExecutor {
    fail: Option<HotSwapPhase>,
    old: ImplementationState,
    new: ImplementationState,
    active: u64,
    switches: usize,
    rollback_count: usize,
    delay_verify: bool,
}

impl FakeExecutor {
    fn hit(&self, phase: HotSwapPhase) -> Result<(), HotSwapStageError> {
        if self.fail == Some(phase) {
            Err(HotSwapStageError::new(
                HotSwapBlockKind::Provider,
                format!("fault at {phase:?}"),
            ))
        } else {
            Ok(())
        }
    }
}

impl HotSwapExecutor for FakeExecutor {
    fn protocol_version(&self) -> u16 {
        2
    }
    fn verify(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        if self.delay_verify {
            std::thread::sleep(Duration::from_millis(4));
        }
        self.hit(HotSwapPhase::Verify)
    }
    fn shadow_load(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::ShadowLoad)
    }
    fn quiesce(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::Quiesce)
    }
    fn snapshot(
        &mut self,
        _: &HotSwapRequest,
        _: Instant,
    ) -> Result<ImplementationState, HotSwapStageError> {
        self.hit(HotSwapPhase::Snapshot)?;
        Ok(self.old.clone())
    }
    fn migrate(
        &mut self,
        _: &HotSwapRequest,
        _: &ImplementationState,
        _: Instant,
    ) -> Result<ImplementationState, HotSwapStageError> {
        self.hit(HotSwapPhase::Migrate)?;
        Ok(self.new.clone())
    }
    fn restore(
        &mut self,
        _: &HotSwapRequest,
        _: &ImplementationState,
        _: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::Restore)
    }
    fn readiness(
        &mut self,
        _: &HotSwapRequest,
        _: &ImplementationState,
        _: Instant,
    ) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::Readiness)
    }
    fn atomic_switch(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::AtomicSwitch)?;
        self.switches += 1;
        self.active = 2;
        Ok(())
    }
    fn drain(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::Drain)
    }
    fn rollback(&mut self, _: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        self.rollback_count += 1;
        self.active = 1;
        Ok(())
    }
    fn committed(&mut self, _: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        Ok(())
    }
}

fn executor(fail: Option<HotSwapPhase>) -> FakeExecutor {
    let (old, new) = states();
    FakeExecutor {
        fail,
        old,
        new,
        active: 1,
        switches: 0,
        rollback_count: 0,
        delay_verify: false,
    }
}

#[test]
fn every_stage_fault_leaves_exactly_the_old_generation_active() {
    let phases = [
        HotSwapPhase::Verify,
        HotSwapPhase::ShadowLoad,
        HotSwapPhase::Quiesce,
        HotSwapPhase::Snapshot,
        HotSwapPhase::Migrate,
        HotSwapPhase::Restore,
        HotSwapPhase::Readiness,
        HotSwapPhase::AtomicSwitch,
        HotSwapPhase::Drain,
    ];
    for (index, phase) in phases.into_iter().enumerate() {
        let path = ledger_path("fault");
        let (old_state, new_state) = states();
        let request = request(&format!("tx-{index}"), &old_state, &new_state);
        let mut coordinator =
            HotSwapCoordinator::open(&path, [(request.module, request.old.clone())]).unwrap();
        let mut executor = executor(Some(phase));
        assert!(matches!(
            coordinator
                .transact(request.clone(), &mut executor)
                .unwrap(),
            HotSwapResult::RolledBack(_)
        ));
        assert_eq!(executor.active, 1);
        assert_eq!(executor.rollback_count, 1);
        assert_eq!(
            coordinator.current_generation(request.module),
            Some(&request.old)
        );
        assert!(executor.switches <= 1);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn readiness_precedes_the_single_committed_switch_and_replay_restores_generation() {
    let path = ledger_path("commit");
    let (old_state, new_state) = states();
    let request = request("tx-commit", &old_state, &new_state);
    let mut coordinator =
        HotSwapCoordinator::open(&path, [(request.module, request.old.clone())]).unwrap();
    let mut executor = executor(None);
    let transaction = HotSwapTransaction::new(request.clone()).unwrap();
    assert_eq!(
        coordinator
            .transact_prepared(transaction, &mut executor)
            .unwrap(),
        HotSwapResult::Committed(request.new.clone())
    );
    assert_eq!(executor.active, 2);
    assert_eq!(executor.switches, 1);
    let records = replay_ledger(&path).unwrap();
    let readiness = records
        .iter()
        .position(|record| record.phase == HotSwapPhase::Readiness)
        .unwrap();
    let switch = records
        .iter()
        .position(|record| record.phase == HotSwapPhase::AtomicSwitch)
        .unwrap();
    assert!(readiness < switch);

    let reopened =
        HotSwapCoordinator::open(&path, [(request.module, request.old.clone())]).unwrap();
    assert_eq!(
        reopened.current_generation(request.module),
        Some(&request.new)
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn deadline_duplicate_event_and_replay_tamper_fail_closed() {
    let deadline_path = ledger_path("deadline");
    let (old_state, new_state) = states();
    let mut deadline_request = request("tx-deadline", &old_state, &new_state);
    deadline_request.deadline_ms = 1;
    let mut coordinator = HotSwapCoordinator::open(
        &deadline_path,
        [(deadline_request.module, deadline_request.old.clone())],
    )
    .unwrap();
    let mut deadline_executor = executor(None);
    deadline_executor.delay_verify = true;
    let HotSwapResult::RolledBack(blocked) = coordinator
        .transact(deadline_request, &mut deadline_executor)
        .unwrap()
    else {
        panic!("deadline must roll back")
    };
    assert_eq!(blocked.kind, HotSwapBlockKind::Deadline);
    fs::remove_file(deadline_path).unwrap();

    let duplicate_path = ledger_path("duplicate");
    let request = request("tx-duplicate", &old_state, &new_state);
    let mut coordinator =
        HotSwapCoordinator::open(&duplicate_path, [(request.module, request.old.clone())]).unwrap();
    let mut first = executor(Some(HotSwapPhase::ShadowLoad));
    coordinator.transact(request.clone(), &mut first).unwrap();
    let mut second = executor(None);
    assert!(coordinator.transact(request.clone(), &mut second).is_err());
    assert_eq!(second.active, 1);

    let mut bytes = fs::read(&duplicate_path).unwrap();
    let position = bytes.iter().position(|byte| *byte == b'c').unwrap();
    bytes[position] = b'e';
    fs::write(&duplicate_path, bytes).unwrap();
    assert!(replay_ledger(&duplicate_path).is_err());
    fs::remove_file(duplicate_path).unwrap();
}

#[cfg(unix)]
struct ProcessPair {
    root: PathBuf,
    old_plan: ProcessLaunchPlan,
    new_plan: ProcessLaunchPlan,
    old_state: ImplementationState,
    new_state: ImplementationState,
}

#[cfg(unix)]
impl ProcessPair {
    fn new() -> Self {
        let id = LEDGER_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "iteron-runtime-hotswap-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let node = iteron_tunables::capability_seam_graph()
            .nodes
            .into_iter()
            .find(|node| node.module == ModuleId::PromptSystem)
            .unwrap();
        let old_state = ImplementationState::new(
            ModuleId::PromptSystem,
            "old.impl",
            "run-state",
            1,
            node.lifecycle.snapshot.clone(),
            serde_json::json!({"decision": "old"}),
        )
        .unwrap();
        let new_state = ImplementationState::new(
            ModuleId::PromptSystem,
            "new.impl",
            "run-state",
            2,
            node.lifecycle.snapshot,
            serde_json::json!({"decision": "new"}),
        )
        .unwrap();
        let response = |implementation: &str, request_id: &str, payload| {
            serde_json::to_string(&ImplementationResponseEnvelope {
                protocol: crate::IMPLEMENTATION_PROTOCOL.into(),
                request_id: request_id.into(),
                implementation_id: implementation.into(),
                module: ModuleId::PromptSystem,
                payload,
            })
            .unwrap()
        };
        let loaded = |implementation: &str| {
            response(
                implementation,
                "host-1",
                ImplementationResponse::Loaded {
                    provider_contract: node.provider_contract.clone(),
                    observation_schema: node.observation_schema.clone(),
                },
            )
        };
        let old_snapshot = response(
            "old.impl",
            "host-2",
            ImplementationResponse::Snapshotted {
                state: old_state.clone(),
            },
        );
        let old_restored = response(
            "old.impl",
            "host-2",
            ImplementationResponse::Restored {
                run_id: old_state.run_id.clone(),
                generation: old_state.generation,
                state_schema: old_state.state_schema.clone(),
                state_sha256: old_state.state_sha256.clone(),
            },
        );
        let old_ready = response(
            "old.impl",
            "host-3",
            ImplementationResponse::Ready {
                run_id: old_state.run_id.clone(),
                generation: old_state.generation,
                state_schema: old_state.state_schema.clone(),
                state_sha256: old_state.state_sha256.clone(),
            },
        );
        let old_started = response(
            "old.impl",
            "host-4",
            ImplementationResponse::Started {
                run_id: "run-after-rollback".into(),
            },
        );
        let old_observation = serde_json::to_string(&crate::ImplementationObservationEnvelope {
            protocol: crate::IMPLEMENTATION_PROTOCOL.into(),
            implementation_id: "old.impl".into(),
            module: ModuleId::PromptSystem,
            run_id: "run-after-rollback".into(),
            sequence: 0,
            schema: node.observation_schema.clone(),
            terminal: true,
            observation: serde_json::json!({"decision": "old"}),
        })
        .unwrap();
        let old_stopped = response("old.impl", "host-3", ImplementationResponse::Stopped);
        let old_script = format!(
            r#"read -r _
printf '%s\n' '{old_loaded}'
read -r operation
case "$operation" in
  *'"operation":"snapshot"'*)
    printf '%s\n' '{old_snapshot}'
    read -r _
    printf '%s\n' '{old_stopped}'
    ;;
  *'"operation":"restore"'*)
    printf '%s\n' '{old_restored}'
    read -r _
    printf '%s\n' '{old_ready}'
    read -r _
    printf '%s\n' '{old_started}'
    printf '%s\n' '{old_observation}'
    ;;
  *) exit 31 ;;
esac"#,
            old_loaded = loaded("old.impl"),
        );

        let migrated = response(
            "new.impl",
            "host-2",
            ImplementationResponse::Migrated {
                state: new_state.clone(),
            },
        );
        let restored = response(
            "new.impl",
            "host-3",
            ImplementationResponse::Restored {
                run_id: new_state.run_id.clone(),
                generation: new_state.generation,
                state_schema: new_state.state_schema.clone(),
                state_sha256: new_state.state_sha256.clone(),
            },
        );
        let ready = response(
            "new.impl",
            "host-4",
            ImplementationResponse::Ready {
                run_id: new_state.run_id.clone(),
                generation: new_state.generation,
                state_schema: new_state.state_schema.clone(),
                state_sha256: new_state.state_sha256.clone(),
            },
        );
        let started = response(
            "new.impl",
            "host-5",
            ImplementationResponse::Started {
                run_id: "run-new".into(),
            },
        );
        let observation = serde_json::to_string(&crate::ImplementationObservationEnvelope {
            protocol: crate::IMPLEMENTATION_PROTOCOL.into(),
            implementation_id: "new.impl".into(),
            module: ModuleId::PromptSystem,
            run_id: "run-new".into(),
            sequence: 0,
            schema: node.observation_schema.clone(),
            terminal: true,
            observation: serde_json::json!({"decision": "new"}),
        })
        .unwrap();
        let new_stopped = response("new.impl", "host-5", ImplementationResponse::Stopped);
        let new_script = format!(
            r#"read -r _
printf '%s\n' '{new_loaded}'
read -r _
printf '%s\n' '{migrated}'
read -r _
printf '%s\n' '{restored}'
read -r _
printf '%s\n' '{ready}'
read -r operation
case "$operation" in
  *'"operation":"start"'*)
    printf '%s\n' '{started}'
    printf '%s\n' '{observation}'
    ;;
  *'"operation":"stop"'*) printf '%s\n' '{new_stopped}' ;;
  *) exit 32 ;;
esac"#,
            new_loaded = loaded("new.impl"),
        );
        let (old_bytes, old_digest) = write_provider(&root, "old.sh", &old_script);
        let (new_bytes, new_digest) = write_provider(&root, "new.sh", &new_script);
        let mut registry = ImplementationRegistry::new(CapabilitySet::none());
        register_provider(&mut registry, "old.impl", "old.sh", &old_digest);
        register_provider(&mut registry, "new.impl", "new.sh", &new_digest);
        let old_verified = registry
            .verify_artifact("old.impl", &old_bytes)
            .unwrap()
            .unwrap();
        let new_verified = registry
            .verify_artifact("new.impl", &new_bytes)
            .unwrap()
            .unwrap();
        let old_plan = registry
            .launch_plan("old.impl", &root, &old_verified)
            .unwrap()
            .unwrap();
        let new_plan = registry
            .launch_plan("new.impl", &root, &new_verified)
            .unwrap()
            .unwrap();
        Self {
            root,
            old_plan,
            new_plan,
            old_state,
            new_state,
        }
    }

    fn request(&self, transaction_id: &str) -> HotSwapRequest {
        HotSwapRequest {
            transaction_id: transaction_id.into(),
            module: ModuleId::PromptSystem,
            candidate_sha256: digest('c'),
            old: plan_generation(&self.old_plan, 1, &self.old_state),
            new: plan_generation(&self.new_plan, 2, &self.new_state),
            authority_sha256: implementation_authority_sha256(&self.new_plan).unwrap(),
            deadline_ms: 5_000,
        }
    }

    fn active(&self) -> ActiveImplementationHandle {
        let mut runtime = ImplementationRuntime::launch(self.old_plan.clone()).unwrap();
        runtime.load().unwrap();
        ActiveImplementationHandle::new(
            runtime,
            plan_generation(&self.old_plan, 1, &self.old_state),
        )
        .unwrap()
    }
}

#[cfg(unix)]
impl Drop for ProcessPair {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.root.join("old.sh"));
        let _ = fs::remove_file(self.root.join("new.sh"));
        let _ = fs::remove_dir(&self.root);
    }
}

#[cfg(unix)]
fn write_provider(root: &std::path::Path, name: &str, body: &str) -> (Vec<u8>, String) {
    let path = root.join(name);
    let bytes = format!("#!/bin/sh\nset -eu\n{body}\n").into_bytes();
    fs::write(&path, &bytes).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    let digest = hex::encode(sha2::Sha256::digest(&bytes));
    (bytes, digest)
}

#[cfg(unix)]
fn register_provider(
    registry: &mut ImplementationRegistry,
    id: &str,
    executable: &str,
    artifact_sha256: &str,
) {
    registry
        .register(ImplementationManifest {
            implementation_id: id.into(),
            implementation_version: Version(1, 0, 0),
            module: ModuleId::PromptSystem,
            artifact_sha256: artifact_sha256.into(),
            executable: executable.into(),
            argv: Vec::new(),
            protocol_version: 2,
            requested_capabilities: CapabilitySet::none(),
            dependencies: Vec::new(),
            runtime_deadline_ms: 10_000,
            cancellation_deadline_ms: 1_000,
            evidence_limits: EvidenceLimits {
                stdout_bytes: 64 * 1024,
                stderr_bytes: 4096,
                observations: 8,
            },
            failure_policy: ImplementationFailurePolicy::FailClosed,
        })
        .unwrap();
}

#[cfg(unix)]
fn plan_generation(
    plan: &ProcessLaunchPlan,
    generation: u64,
    state: &ImplementationState,
) -> HotSwapGeneration {
    HotSwapGeneration {
        generation,
        implementation_id: plan.implementation_id().into(),
        artifact_sha256: format!("sha256:{}", plan.artifact_sha256()),
        state_sha256: state.state_sha256.clone(),
    }
}

#[test]
#[cfg(unix)]
fn production_executor_commits_real_process_and_routes_only_new_observation() {
    let fixture = ProcessPair::new();
    let request = fixture.request("tx-real-commit");
    let active = fixture.active();
    let mut executor = RuntimeHotSwapExecutor::new(
        active.clone(),
        fixture.new_plan.clone(),
        fixture.old_state.clone(),
    )
    .unwrap();
    let ledger = ledger_path("real-commit");
    let mut coordinator =
        HotSwapCoordinator::open(&ledger, [(request.module, request.old.clone())]).unwrap();
    assert_eq!(
        coordinator
            .transact(request.clone(), &mut executor)
            .unwrap(),
        HotSwapResult::Committed(request.new.clone())
    );
    assert_eq!(active.current_generation().unwrap(), request.new);
    active
        .start("run-new", digest('e'), serde_json::json!({}), 1_000)
        .unwrap();
    let observation = active.next_observation(Duration::from_millis(500)).unwrap();
    assert_eq!(observation.implementation_id, "new.impl");
    assert_eq!(observation.observation["decision"], "new");
    fs::remove_file(ledger).unwrap();
}

#[test]
#[cfg(unix)]
fn production_executor_reserves_consumers_and_rebuilds_old_after_post_drain_rollback() {
    let fixture = ProcessPair::new();
    let request = fixture.request("tx-real-rollback");
    let active = fixture.active();
    let mut executor = RuntimeHotSwapExecutor::new(
        active.clone(),
        fixture.new_plan.clone(),
        fixture.old_state.clone(),
    )
    .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    executor.verify(&request, end).unwrap();
    assert!(matches!(
        active.start("blocked", digest('f'), serde_json::json!({}), 500),
        Err(RuntimeGenerationError::TransitionInProgress(_))
    ));
    executor.shadow_load(&request, end).unwrap();
    executor.quiesce(&request, end).unwrap();
    let snapshot = executor.snapshot(&request, end).unwrap();
    let migrated = executor.migrate(&request, &snapshot, end).unwrap();
    executor.restore(&request, &migrated, end).unwrap();
    executor.readiness(&request, &migrated, end).unwrap();
    executor.atomic_switch(&request, end).unwrap();
    executor.drain(&request, end).unwrap();
    executor.rollback(&request).unwrap();

    assert_eq!(active.current_generation().unwrap(), request.old);
    active
        .start(
            "run-after-rollback",
            digest('f'),
            serde_json::json!({}),
            1_000,
        )
        .unwrap();
    let observation = active.next_observation(Duration::from_millis(500)).unwrap();
    assert_eq!(observation.implementation_id, "old.impl");
    assert_eq!(observation.observation["decision"], "old");
}

#[test]
#[cfg(unix)]
fn production_executor_rejects_plan_identity_drift_before_shadow_launch() {
    let fixture = ProcessPair::new();
    let mut request = fixture.request("tx-real-drift");
    request.new.artifact_sha256 = digest('9');
    let active = fixture.active();
    let mut executor = RuntimeHotSwapExecutor::new(
        active.clone(),
        fixture.new_plan.clone(),
        fixture.old_state.clone(),
    )
    .unwrap();
    let ledger = ledger_path("real-drift");
    let mut coordinator =
        HotSwapCoordinator::open(&ledger, [(request.module, request.old.clone())]).unwrap();
    assert!(matches!(
        coordinator
            .transact(request.clone(), &mut executor)
            .unwrap(),
        HotSwapResult::RolledBack(_)
    ));
    assert_eq!(active.current_generation().unwrap(), request.old);
    assert_eq!(active.state().unwrap(), crate::RuntimeState::Loaded);
    fs::remove_file(ledger).unwrap();
}

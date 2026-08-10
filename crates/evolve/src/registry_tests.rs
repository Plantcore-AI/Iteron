use super::*;
use crate::{
    DataClass, DataGovernance, EVOLUTION_SCHEMA_VERSION, PolicyBundle, RewardVector,
    StrategyDecision, StrategySlot, TrainingConsent,
};
use iteron_protocol::{RunId, TenantId};
use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-evolve-registry-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn policy(id: &str) -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::router(),
        policy_id: id.into(),
        version: "1".into(),
        digest: "a".repeat(64),
    }
}

fn envelope(run_id: &str) -> TrajectoryEnvelope {
    TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId(run_id.into()),
        tenant_id: TenantId("tenant-a".into()),
        task_id: "task-a".into(),
        domain: "coding".into(),
        environment_digest: "b".repeat(64),
        bundle: PolicyBundle {
            bundle_id: "bundle-child".into(),
            digest: "c".repeat(64),
            policies: vec![policy("router-parent")],
            rollback_to: Some("bundle-parent".into()),
        },
        decisions: Vec::new(),
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.01,
            wall_time_ms: 10,
            human_acceptance: None,
            domain: BTreeMap::new(),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::EvaluationOnly,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "audit-30d".into(),
        },
    }
}

fn inject_torn_record(registry: &mut TrajectoryRegistry, envelope: &TrajectoryEnvelope) {
    EvidenceRecorder::new().verify_trajectory(envelope).unwrap();
    let envelope_bytes = encode_envelope(envelope).unwrap();
    let content_digest = digest_bytes(&envelope_bytes);
    let summary = registry.scan(|_| Ok(())).unwrap();
    let record = RegistryRecord {
        registry_schema_version: REGISTRY_SCHEMA_VERSION,
        sequence: summary.next_sequence,
        previous_hash: summary.last_hash.clone(),
        record_hash: hash_record(&summary.last_hash, summary.next_sequence, &content_digest),
        content_digest,
        envelope: envelope.clone(),
    };
    let mut line = encode_record(&record).unwrap();
    line.push(b'\n');
    let split = line.len() / 2;
    registry.poisoned = true;
    registry.file.write_all(&line[..split]).unwrap();
    registry.file.sync_data().unwrap();
}

#[test]
fn d14_11_g1_registry_is_content_addressed_idempotent_and_detects_tampering() {
    let root = scratch("g1");
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    let trajectory = envelope("run-a");

    let stored = registry.ingest(&trajectory).unwrap();
    let TrajectoryIngest::Stored(address) = stored else {
        panic!("first ingest must append");
    };
    assert_eq!(address.as_str().len(), 64);
    assert_eq!(
        registry.get_by_run(&trajectory.run_id).unwrap().unwrap(),
        RegisteredTrajectory {
            address: address.clone(),
            envelope: trajectory.clone(),
        }
    );
    assert_eq!(
        registry.get(&address).unwrap().unwrap().envelope,
        trajectory
    );

    let bytes_after_first = std::fs::metadata(registry.path()).unwrap().len();
    assert_eq!(
        registry.ingest(&trajectory).unwrap(),
        TrajectoryIngest::AlreadyPresent(address.clone())
    );
    assert_eq!(
        std::fs::metadata(registry.path()).unwrap().len(),
        bytes_after_first,
        "idempotent ingest must not append a duplicate record"
    );

    let mut conflicting = trajectory.clone();
    conflicting.terminal_outcome = "different".into();
    assert!(matches!(
        registry.ingest(&conflicting),
        Err(TrajectoryRegistryError::RunConflict { .. })
    ));
    assert_eq!(
        std::fs::metadata(registry.path()).unwrap().len(),
        bytes_after_first
    );

    let mut bytes = std::fs::read(registry.path()).unwrap();
    let offset = bytes
        .windows(b"completed".len())
        .position(|window| window == b"completed")
        .unwrap();
    bytes[offset..offset + b"tampered!".len()].copy_from_slice(b"tampered!");
    let mut attacker = OpenOptions::new()
        .write(true)
        .open(registry.path())
        .unwrap();
    attacker.seek(SeekFrom::Start(0)).unwrap();
    attacker.write_all(&bytes).unwrap();
    attacker.sync_all().unwrap();
    assert!(matches!(
        registry.get_by_run(&RunId("run-a".into())),
        Err(TrajectoryRegistryError::ContentDigestMismatch { sequence: 0 })
    ));
    assert_eq!(
        std::fs::metadata(registry.path()).unwrap().len(),
        bytes_after_first,
        "a complete corrupt record is evidence of tampering, never a recoverable torn tail"
    );

    drop(registry);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn d14_11_g1_unverified_envelope_is_rejected_without_append() {
    let root = scratch("invalid");
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    let mut trajectory = envelope("run-invalid");
    trajectory.decisions.push(StrategyDecision {
        decision_id: "decision-a".into(),
        ordinal: 0,
        policy: trajectory.bundle.policies[0].clone(),
        observation_digest: "d".repeat(64),
        candidate_set_digest: "e".repeat(64),
        action: serde_json::json!({"choice": "safe"}),
        action_digest: "0".repeat(64),
        propensity: Some(1.0),
    });

    assert!(matches!(
        registry.ingest(&trajectory),
        Err(TrajectoryRegistryError::InvalidEnvelope(
            EvidenceRecordError::ActionDigestMismatch { .. }
        ))
    ));
    assert_eq!(std::fs::metadata(registry.path()).unwrap().len(), 0);

    drop(registry);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn d14_11_g2_lineage_query_and_torn_append_recover_verified_prefix() {
    let root = scratch("g2");
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    let first = envelope("run-1");
    let second = envelope("run-2");
    let third = envelope("run-3");
    registry.ingest(&first).unwrap();
    registry.ingest(&second).unwrap();

    let lineage = registry.lineage_for_run(&first.run_id).unwrap().unwrap();
    assert_eq!(lineage.run_id, first.run_id);
    assert_eq!(lineage.source_bundle.bundle_id, "bundle-child");
    assert_eq!(
        lineage.source_bundle.parent_bundle_id.as_deref(),
        Some("bundle-parent")
    );
    assert_eq!(lineage.source_policies, first.bundle.policies);
    assert!(lineage.source_policies.len() <= MAX_TRAJECTORY_LINEAGE_POLICIES);

    let verified_prefix = std::fs::metadata(registry.path()).unwrap().len();
    inject_torn_record(&mut registry, &third);
    assert!(std::fs::metadata(registry.path()).unwrap().len() > verified_prefix);
    drop(registry); // equivalent crash: no writer state can repair the partial append

    let mut recovered = TrajectoryRegistry::open(&root).unwrap();
    assert_eq!(
        std::fs::metadata(recovered.path()).unwrap().len(),
        verified_prefix
    );
    assert_eq!(recovered.len().unwrap(), 2);
    assert!(recovered.get_by_run(&first.run_id).unwrap().is_some());
    assert!(recovered.get_by_run(&second.run_id).unwrap().is_some());
    assert!(recovered.get_by_run(&third.run_id).unwrap().is_none());
    assert!(matches!(
        recovered.ingest(&third).unwrap(),
        TrajectoryIngest::Stored(_)
    ));
    assert_eq!(recovered.len().unwrap(), 3);

    drop(recovered);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn registry_file_size_is_rejected_before_scan_allocation() {
    let root = scratch("size");
    let path = root.join(REGISTRY_FILE_NAME);
    let file = File::create(&path).unwrap();
    file.set_len(MAX_TRAJECTORY_REGISTRY_BYTES + 1).unwrap();
    assert!(matches!(
        TrajectoryRegistry::open(&root),
        Err(TrajectoryRegistryError::RegistryTooLarge { .. })
    ));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn registry_allows_only_one_append_writer() {
    let root = scratch("writer-lock");
    let registry = TrajectoryRegistry::open(&root).unwrap();
    assert!(matches!(
        TrajectoryRegistry::open(&root),
        Err(TrajectoryRegistryError::WriterBusy { .. })
    ));
    drop(registry);
    let reopened = TrajectoryRegistry::open(&root).unwrap();
    drop(reopened);
    std::fs::remove_dir_all(root).ok();
}

#[cfg(unix)]
#[test]
fn registry_refuses_symlink_roots_and_journals() {
    let base = scratch("symlink");
    let real_root = base.join("real");
    std::fs::create_dir_all(&real_root).unwrap();
    let linked_root = base.join("linked");
    std::os::unix::fs::symlink(&real_root, &linked_root).unwrap();
    assert!(matches!(
        TrajectoryRegistry::open(&linked_root),
        Err(TrajectoryRegistryError::SymlinkRefused { .. })
    ));

    let outside = base.join("outside.jsonl");
    File::create(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, real_root.join(REGISTRY_FILE_NAME)).unwrap();
    assert!(matches!(
        TrajectoryRegistry::open(&real_root),
        Err(TrajectoryRegistryError::SymlinkRefused { .. })
    ));
    std::fs::remove_dir_all(base).ok();
}

use super::*;
use crate::report::{aggregate, compare};
use crate::types::{
    CellKey, CellResult, CostStatus, EVAL_SCHEMA_VERSION, KernelTaxObservation, OracleStatus,
    RunStatus, SamplingControl,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-eval-tuner-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tunable_family() -> &'static str {
    iteron_tunables::families()
        .iter()
        .find(|family| family.optimization.class != iteron_tunables::OptimizationClass::Pin)
        .unwrap()
        .id
}

fn pinned_family() -> &'static str {
    iteron_tunables::families()
        .iter()
        .find(|family| family.optimization.class == iteron_tunables::OptimizationClass::Pin)
        .unwrap()
        .id
}

fn candidate(id: &str, value: &str) -> TunerCandidate {
    TunerCandidate {
        schema_version: 1,
        id: id.into(),
        values: BTreeMap::from([(tunable_family().into(), value.into())]),
        profile: None,
        implementations: Vec::new(),
        graph: None,
    }
}

fn spec(candidates: Vec<TunerCandidate>, concurrency: u16, budgets: Vec<u32>) -> TunerSpec {
    let mut count = candidates.len();
    let mut max_trials = 0;
    for _ in &budgets {
        max_trials += count;
        count = count.div_ceil(2);
    }
    TunerSpec {
        schema_version: 1,
        experiment_id: "fixture".into(),
        train_dataset_digest: format!("sha256:{}", "a".repeat(64)),
        tunables_registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: None,
        tool_text_registry_digest: None,
        trainer_bridge: None,
        max_trials: max_trials as u16,
        max_concurrency: concurrency,
        reduction_factor: 2,
        round_budgets: budgets,
        candidates,
    }
}

fn manifest(
    request: &TrialRequest,
    resolved: bool,
    purpose: EvaluationPurpose,
) -> EvaluationManifest {
    let partition = purpose.required_partition();
    let commit = "b".repeat(40);
    let mut cell = CellResult::errored(
        CellKey {
            task: "task",
            config: "arm",
            seed: 0,
            partition,
            repo_url: "https://example.invalid/repo.git",
            commit: &commit,
        },
        "fixture",
        "fixture",
    );
    cell.run_status = RunStatus::Completed;
    cell.failure_phase = None;
    cell.resolved = Some(resolved);
    cell.cost_status = CostStatus::Known;
    cell.cost_usd = Some(0.25);
    cell.cost_reason = None;
    cell.oracle_status = OracleStatus::Passed;
    cell.sampling = SamplingControl {
        requested_seed: 0,
        enforcement: "fixture".into(),
        reason: None,
    };
    cell.elapsed_ms = 10;
    let summary = aggregate(std::slice::from_ref(&cell), 1);
    EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id: request.trial_id.clone(),
        corpus_version: "train-fixture".into(),
        dataset_digest: format!("sha256:{}", "a".repeat(64)),
        model: "fixed-model".into(),
        provider: Some("fixed-provider".into()),
        bundle_digest: Some(request.candidate_digest.clone()),
        purpose,
        seeds: 1,
        minimum_seeds: 1,
        workers: 1,
        max_turns: Some(request.budget),
        core_agent_wall_secs: 1,
        core_process_grace_secs: 1,
        core_process_timeout_secs: 2,
        result_path: PathBuf::from("result.json"),
        comparison: compare(&summary, "arm", "missing"),
        aggregate: summary,
        selections: Vec::new(),
        kernel_tax: KernelTaxObservation::default(),
        cells: vec![cell],
    }
}

fn with_usage(mut manifest: EvaluationManifest, input_tokens: u64) -> EvaluationManifest {
    manifest.cells[0].agent_metrics = Some(crate::types::AgentMetrics {
        elapsed_ms: 10,
        usage: Some(iteron_protocol::Usage {
            input: input_tokens,
            output: 0,
            cache_creation: 0,
            cache_read: 0,
            thinking: 0,
        }),
    });
    manifest
}

#[test]
fn complete_token_measurements_break_equal_quality_ties_without_treating_missing_as_zero() {
    let root = TempRoot::new("token-ranking");
    let mut tuner = OfflineTuner::create(
        spec(
            vec![
                candidate("a", "x"),
                candidate("b", "y"),
                candidate("c", "z"),
            ],
            3,
            vec![1],
        ),
        &root.join("tuner.jsonl"),
    )
    .unwrap();
    let trials = tuner.issue_trials().unwrap();
    let expensive = tuner
        .record_manifest(
            &trials[0].trial_id,
            &with_usage(manifest(&trials[0], true, EvaluationPurpose::Tune), 100),
            "arm",
        )
        .unwrap();
    let efficient = tuner
        .record_manifest(
            &trials[1].trial_id,
            &with_usage(manifest(&trials[1], true, EvaluationPurpose::Tune), 50),
            "arm",
        )
        .unwrap();
    let missing = tuner
        .record_manifest(
            &trials[2].trial_id,
            &manifest(&trials[2], true, EvaluationPurpose::Tune),
            "arm",
        )
        .unwrap();
    assert_eq!(expensive.average_tokens, Some(100.0));
    assert_eq!(efficient.average_tokens, Some(50.0));
    assert_eq!(efficient.average_agent_latency_ms, Some(10.0));
    assert_eq!(missing.average_tokens, None);
    assert_eq!(missing.average_agent_latency_ms, None);
    assert_eq!(tuner.advance_round().unwrap().as_deref(), Some("b"));
}

#[test]
fn successive_halving_replays_exactly_and_selects_the_best_candidate() {
    let root = TempRoot::new("halving");
    let journal = root.join("tuner.jsonl");
    let spec = spec(
        vec![
            candidate("a", "x"),
            candidate("b", "y"),
            candidate("c", "z"),
            candidate("d", "w"),
        ],
        2,
        vec![1, 2],
    );
    let mut tuner = OfflineTuner::create(spec.clone(), &journal).unwrap();
    let first = tuner.issue_trials().unwrap();
    assert_eq!(first.len(), 2);
    tuner
        .record_manifest(
            &first[0].trial_id,
            &manifest(&first[0], true, EvaluationPurpose::Tune),
            "arm",
        )
        .unwrap();
    tuner
        .record_manifest(
            &first[1].trial_id,
            &manifest(&first[1], false, EvaluationPurpose::Tune),
            "arm",
        )
        .unwrap();
    let second = tuner.issue_trials().unwrap();
    assert_eq!(second.len(), 2);
    tuner
        .record_manifest(
            &second[0].trial_id,
            &manifest(&second[0], true, EvaluationPurpose::Tune),
            "arm",
        )
        .unwrap();
    tuner
        .record_manifest(
            &second[1].trial_id,
            &manifest(&second[1], false, EvaluationPurpose::Tune),
            "arm",
        )
        .unwrap();
    tuner.advance_round().unwrap();
    let before = tuner.snapshot();
    drop(tuner);
    let mut resumed = OfflineTuner::open(spec, &journal).unwrap();
    assert_eq!(resumed.snapshot(), before);
    let finals = resumed.issue_trials().unwrap();
    assert_eq!(finals.len(), 2);
    for request in &finals {
        resumed
            .record_manifest(
                &request.trial_id,
                &manifest(
                    request,
                    request.candidate.id == "a",
                    EvaluationPurpose::Tune,
                ),
                "arm",
            )
            .unwrap();
    }
    assert_eq!(resumed.advance_round().unwrap().as_deref(), Some("a"));
    assert_eq!(resumed.snapshot().status, TunerStatus::Completed);
}

#[test]
fn restart_preserves_unknown_inflight_and_requires_explicit_abandonment() {
    let root = TempRoot::new("resume-inflight");
    let journal = root.join("tuner.jsonl");
    let mut spec = spec(vec![candidate("a", "x")], 1, vec![1]);
    spec.max_trials = 2;
    let mut tuner = OfflineTuner::create(spec.clone(), &journal).unwrap();
    let first = tuner.issue_trials().unwrap().remove(0);
    drop(tuner);
    let mut resumed = OfflineTuner::open(spec, &journal).unwrap();
    let inflight = resumed.snapshot().inflight_trials;
    assert_eq!(inflight.len(), 1);
    assert_eq!(inflight[0], first.trial_id);
    assert!(resumed.issue_trials().unwrap().is_empty());
    resumed.abandon_inflight(&first.trial_id).unwrap();
    let replacement = resumed.issue_trials().unwrap().remove(0);
    assert_ne!(replacement.trial_id, first.trial_id);
    assert_eq!(replacement.candidate.id, first.candidate.id);
}

#[test]
fn held_out_or_wrong_candidate_evidence_cannot_feed_the_tuner() {
    let root = TempRoot::new("isolation");
    let journal = root.join("tuner.jsonl");
    let mut tuner =
        OfflineTuner::create(spec(vec![candidate("a", "x")], 1, vec![1]), &journal).unwrap();
    let request = tuner.issue_trials().unwrap().remove(0);
    let held_out = manifest(&request, true, EvaluationPurpose::Score);
    assert!(matches!(
        tuner.record_manifest(&request.trial_id, &held_out, "arm"),
        Err(TunerError::TrainIsolation(_))
    ));
    let mut wrong = manifest(&request, true, EvaluationPurpose::Tune);
    wrong.bundle_digest = Some(format!("sha256:{}", "f".repeat(64)));
    assert!(matches!(
        tuner.record_manifest(&request.trial_id, &wrong, "arm"),
        Err(TunerError::TrainIsolation(_))
    ));
    assert_eq!(tuner.snapshot().inflight_trials, [request.trial_id]);
}

#[test]
fn pinned_families_and_underfunded_schedules_are_rejected() {
    let root = TempRoot::new("pin");
    let mut pinned = candidate("pinned", "x");
    pinned.values = BTreeMap::from([(pinned_family().into(), true.into())]);
    let error = OfflineTuner::create(spec(vec![pinned], 1, vec![1]), &root.join("pin.jsonl"))
        .err()
        .expect("pinned family must be refused");
    assert!(error.to_string().contains("pinned or unknown"));

    let mut underfunded = spec(
        vec![candidate("a", "x"), candidate("b", "y")],
        1,
        vec![1, 2],
    );
    underfunded.max_trials = 2;
    assert!(OfflineTuner::create(underfunded, &root.join("underfunded.jsonl")).is_err());
}

#[test]
fn conditional_tpe_prefers_the_pending_value_seen_in_the_good_density() {
    let root = TempRoot::new("conditional-tpe");
    let candidates = vec![
        candidate("a-good", "preferred"),
        candidate("b-bad", "other-1"),
        candidate("c-bad", "other-2"),
        candidate("d-bad", "other-3"),
        candidate("e-bad-pending", "other-4"),
        candidate("z-good-pending", "preferred"),
    ];
    let mut tuner =
        OfflineTuner::create(spec(candidates, 1, vec![1]), &root.join("tuner.jsonl")).unwrap();
    for index in 0..4 {
        let request = tuner.issue_trials().unwrap().remove(0);
        let resolved = index == 0;
        tuner
            .record_manifest(
                &request.trial_id,
                &manifest(&request, resolved, EvaluationPurpose::Tune),
                "arm",
            )
            .unwrap();
    }
    let suggested = tuner.issue_trials().unwrap().remove(0);
    assert_eq!(suggested.candidate.id, "z-good-pending");
}

#[test]
fn frozen_evidence_fixture_is_inspectable_but_never_feedback_eligible() {
    let verified = crate::evidence_bundle::verify_evidence_bundle(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/evidence-bundle-v1"),
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    )
    .unwrap();
    let evidence = &verified.evidence_rows;
    let inspection = OfflineTuner::inspect_evidence_rows(evidence).unwrap();
    assert_eq!(
        inspection.provenance,
        EvidenceRowsProvenance::SyntheticFixture
    );
    assert_eq!(inspection.train_rows, 3);
    assert_eq!(inspection.held_out_rows, 1);
    assert!(!inspection.feedback_eligible);

    let root = TempRoot::new("fixture-refusal");
    let mut tuner = OfflineTuner::create(
        spec(vec![candidate("candidate-a", "x")], 1, vec![1]),
        &root.join("tuner.jsonl"),
    )
    .unwrap();
    let request = tuner.issue_trials().unwrap().remove(0);
    assert!(matches!(
        tuner.record_verified_evidence(&request.trial_id, &verified),
        Err(TunerError::TrainIsolation(_))
    ));
    assert_eq!(tuner.snapshot().inflight_trials, [request.trial_id]);
}

#[test]
fn tpe_suggestion_is_identical_after_hash_chain_replay() {
    let candidates = vec![
        candidate("a-good", "preferred"),
        candidate("b-bad", "other-1"),
        candidate("c-bad", "other-2"),
        candidate("d-bad", "other-3"),
        candidate("e-bad-pending", "other-4"),
        candidate("z-good-pending", "preferred"),
    ];
    let spec = spec(candidates, 1, vec![1]);
    let run_prefix = |tuner: &mut OfflineTuner| {
        for index in 0..4 {
            let request = tuner.issue_trials().unwrap().remove(0);
            tuner
                .record_manifest(
                    &request.trial_id,
                    &manifest(&request, index == 0, EvaluationPurpose::Tune),
                    "arm",
                )
                .unwrap();
        }
    };

    let resumed_root = TempRoot::new("tpe-resume");
    let resumed_journal = resumed_root.join("tuner.jsonl");
    let mut before_restart = OfflineTuner::create(spec.clone(), &resumed_journal).unwrap();
    run_prefix(&mut before_restart);
    let replay_snapshot = before_restart.snapshot();
    drop(before_restart);
    let mut replayed = OfflineTuner::open(spec.clone(), &resumed_journal).unwrap();
    assert_eq!(replayed.snapshot(), replay_snapshot);
    let replayed_candidate = replayed.issue_trials().unwrap().remove(0).candidate.id;

    let uninterrupted_root = TempRoot::new("tpe-uninterrupted");
    let mut uninterrupted =
        OfflineTuner::create(spec, &uninterrupted_root.join("tuner.jsonl")).unwrap();
    run_prefix(&mut uninterrupted);
    let uninterrupted_candidate = uninterrupted.issue_trials().unwrap().remove(0).candidate.id;
    assert_eq!(replayed_candidate, uninterrupted_candidate);
    assert_eq!(replayed_candidate, "z-good-pending");
}

/// A candidate must be able to name the whole registry. Pinning this to the family count rather
/// than a literal is the point: a later registry growth that left the width behind would silently
/// cap every candidate below the space it is searching, and nothing else would notice.
#[test]
fn candidate_width_tracks_the_family_count() {
    assert_eq!(
        crate::tuner::MAX_FAMILIES_PER_CANDIDATE,
        iteron_tunables::EXPECTED_FAMILY_COUNT
    );
}

fn trainer_bridge(
    experiment_id: &str,
    max_trials: u16,
) -> crate::trainer_bridge::TrainerBridgeSpec {
    use crate::trainer_bridge::*;
    TrainerBridgeSpec {
        schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
        experiment_id: experiment_id.into(),
        train: TrainerDataset {
            partition: DatasetPartition::Train,
            digest: format!("sha256:{}", "a".repeat(64)),
            schema_id: "dataset/train@v1".into(),
        },
        held_out: TrainerDataset {
            partition: DatasetPartition::HeldOut,
            digest: format!("sha256:{}", "c".repeat(64)),
            schema_id: "dataset/held-out@v1".into(),
        },
        reward: RewardContract {
            schema_id: "reward/resolved@v1".into(),
            objectives: vec![RewardObjective {
                metric: "resolved_rate".into(),
                direction: RewardDirection::Maximize,
                weight_micros: 1_000_000,
            }],
        },
        trajectory: TrajectoryContract {
            schema_id: "trajectory/iteron@v1".into(),
            max_bytes_per_trial: 1_048_576,
            max_events_per_trial: 1_000,
            content_store_required: true,
        },
        checkpoint: CheckpointContract {
            schema_id: "checkpoint/trainer@v1".into(),
            max_checkpoint_bytes: 1_048_576,
            checkpoint_every_trials: 1,
        },
        resources: TrainerResources {
            max_trials,
            max_concurrency: 1,
            max_wall_secs_per_trial: 60,
            max_memory_bytes_per_trial: 1_048_576,
            max_evidence_bytes_per_trial: 1_048_576,
        },
        distributed: DistributedTrials {
            coordinator_id: "local/coordinator".into(),
            max_workers: 1,
            lease_secs: 2,
            heartbeat_secs: 1,
            max_attempts_per_trial: 1,
        },
        capabilities: ALL_TRAINER_CAPABILITIES.to_vec(),
    }
}

fn universal_candidate(id: &str) -> TunerCandidate {
    TunerCandidate {
        schema_version: LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION,
        id: id.into(),
        values: BTreeMap::new(),
        profile: Some(iteron_tunables::ProfileDocument {
            schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
            profile_id: id.into(),
            registry_revision: iteron_tunables::REGISTRY_REVISION,
            registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
            param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
            module_scope: None,
            values: Vec::new(),
            params: vec![iteron_tunables::ParamAssignment {
                param: "eval.tuner.max_candidates".into(),
                value: iteron_tunables::ResolutionValue::Integer { value: 128 },
            }],
            artifacts: vec![iteron_tunables::ArtifactOverride {
                artifact: "prompt/system@v1".into(),
                text: "bounded candidate system prompt".into(),
            }],
        }),
        implementations: vec![CandidateImplementation {
            module: iteron_tunables::ModuleId::VerificationQuorum,
            implementation_id: "research-verifier-v1".into(),
            protocol: "iteron-implementation/1".into(),
            catalog_path: "/opt/iteron/marketplace/catalog.json".into(),
            artifact_root: "/opt/iteron/marketplace/artifacts/verifier".into(),
            manifest_sha256: format!("sha256:{}", "d".repeat(64)),
            artifact_sha256: format!("sha256:{}", "e".repeat(64)),
        }],
        graph: None,
    }
}

#[test]
fn universal_candidate_covers_params_text_and_implementations() {
    let root = TempRoot::new("universal");
    let bridge = trainer_bridge("universal-fixture", 1);
    let spec = TunerSpec {
        schema_version: 2,
        experiment_id: "universal-fixture".into(),
        train_dataset_digest: bridge.train.digest.clone(),
        tunables_registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
        tool_text_registry_digest: Some(iteron_tunables::tool_text_registry_digest_sha256()),
        trainer_bridge: Some(bridge),
        max_trials: 1,
        max_concurrency: 1,
        reduction_factor: 2,
        round_budgets: vec![1],
        candidates: vec![universal_candidate("candidate-a")],
    };
    let mut tuner = OfflineTuner::create(spec, &root.join("universal.jsonl")).unwrap();
    let request = tuner.issue_trials().unwrap().remove(0);
    assert_eq!(request.candidate.id, "candidate-a");
    assert!(request.candidate.profile.is_some());
    assert_eq!(request.candidate.implementations.len(), 1);
}

#[test]
fn tuner_features_reuse_generic_strategy_modules_across_atomic_parameters() {
    let mut candidate = universal_candidate("module-features");
    let profile = candidate.profile.as_mut().unwrap();
    profile.params.extend([
        iteron_tunables::ParamAssignment {
            param: "ctx.compact.default_trigger_tokens".into(),
            value: iteron_tunables::ResolutionValue::Integer { value: 80_000 },
        },
        iteron_tunables::ParamAssignment {
            param: "ctx.memory.header".into(),
            value: iteron_tunables::ResolutionValue::Text {
                value: "compact memory header".into(),
            },
        },
        iteron_tunables::ParamAssignment {
            param: "tools.tool_search.core_eager_tools".into(),
            value: iteron_tunables::ResolutionValue::List {
                items: vec![iteron_tunables::ResolutionValue::Text {
                    value: "tool_search".into(),
                }],
            },
        },
        iteron_tunables::ParamAssignment {
            param: "tools.grep_tool.default_grep_parallelism".into(),
            value: iteron_tunables::ResolutionValue::Integer { value: 4 },
        },
    ]);
    profile
        .params
        .sort_by(|left, right| left.param.cmp(&right.param));
    candidate.validate_universal().unwrap();

    let features = super::state_ops::candidate_features(&candidate);
    for module in [
        iteron_tunables::ModuleId::MemoryRecall,
        iteron_tunables::ModuleId::ContextCompaction,
        iteron_tunables::ModuleId::ToolExposure,
        iteron_tunables::ModuleId::ToolSearchStrategy,
        iteron_tunables::ModuleId::PromptSystem,
        iteron_tunables::ModuleId::VerificationQuorum,
    ] {
        assert!(
            features.contains_key(&format!("module/{}", module.as_str())),
            "missing generic strategy feature for {}",
            module.as_str()
        );
    }
    assert!(
        features.keys().all(|key| !key.contains("provider_id")),
        "module learning must not depend on a provider-specific branch"
    );

    let before = features["module/memory.recall"].clone();
    let memory = candidate
        .profile
        .as_mut()
        .unwrap()
        .params
        .iter_mut()
        .find(|assignment| assignment.param == "ctx.memory.header")
        .unwrap();
    memory.value = iteron_tunables::ResolutionValue::Text {
        value: "different memory header".into(),
    };
    let after = super::state_ops::candidate_features(&candidate);
    assert_ne!(before, after["module/memory.recall"]);
    assert_eq!(
        features["module/tool.exposure"], after["module/tool.exposure"],
        "changing memory must not perturb the tool-policy feature"
    );
}

#[test]
fn universal_candidate_rejects_a_second_address_space() {
    let root = TempRoot::new("universal-legacy-mix");
    let bridge = trainer_bridge("mixed-fixture", 1);
    let mut candidate = universal_candidate("mixed");
    candidate
        .values
        .insert(tunable_family().into(), true.into());
    let spec = TunerSpec {
        schema_version: 2,
        experiment_id: "mixed-fixture".into(),
        train_dataset_digest: bridge.train.digest.clone(),
        tunables_registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
        tool_text_registry_digest: Some(iteron_tunables::tool_text_registry_digest_sha256()),
        trainer_bridge: Some(bridge),
        max_trials: 1,
        max_concurrency: 1,
        reduction_factor: 2,
        round_budgets: vec![1],
        candidates: vec![candidate],
    };
    assert!(OfflineTuner::create(spec, &root.join("mixed.jsonl")).is_err());
}

#[test]
fn universal_candidate_cannot_represent_a_pin_only_family() {
    let (family, value) = iteron_tunables::families()
        .iter()
        .find_map(|family| {
            (family.optimization.class == iteron_tunables::OptimizationClass::Pin)
                .then(|| {
                    iteron_tunables::canonical_embedded_default(family.id)
                        .map(|value| (family.id, value))
                })
                .flatten()
        })
        .expect("registry has a pin with an embedded value");
    let mut candidate = universal_candidate("pin-refusal");
    candidate
        .profile
        .as_mut()
        .unwrap()
        .values
        .push(iteron_tunables::ProfileValue {
            family: family.into(),
            as_declared_source: iteron_tunables::SourceKind::UserConfig,
            value,
        });
    assert!(candidate.validate_universal().is_err());
}

#[test]
fn universal_candidate_v2_strictly_binds_executable_sources() {
    let candidate = universal_candidate("strict-source");
    candidate.validate_universal().unwrap();

    let mut old_schema = candidate.clone();
    old_schema.schema_version = 1;
    assert!(old_schema.validate_universal().is_err());

    let mut current_protocol = candidate.clone();
    current_protocol.implementations[0].protocol = "iteron-implementation/2".into();
    current_protocol.validate_universal().unwrap();

    let mut unsupported_protocol = candidate.clone();
    unsupported_protocol.implementations[0].protocol = "iteron-implementation/3".into();
    assert!(unsupported_protocol.validate_universal().is_err());

    let mut invalid_digest = candidate.clone();
    invalid_digest.implementations[0].artifact_sha256 = "sha256:not-a-digest".into();
    assert!(invalid_digest.validate_universal().is_err());

    let mut relative_source = candidate.clone();
    relative_source.implementations[0].catalog_path = "catalog.json".into();
    assert!(relative_source.validate_universal().is_err());

    let mut duplicate = candidate.clone();
    duplicate
        .implementations
        .push(candidate.implementations[0].clone());
    assert!(duplicate.validate_universal().is_err());

    let mut changed_path = candidate.clone();
    changed_path.implementations[0].artifact_root = "/opt/iteron/other-artifact".into();
    assert_ne!(
        changed_path.digest_sha256().unwrap(),
        candidate.digest_sha256().unwrap()
    );
}

fn prefixed_digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

#[test]
fn candidate_graph_v3_materializes_every_address_and_binds_identity() {
    let profile_address = CandidateAddress {
        kind: CandidateAddressKind::UnifiedProfile,
        selector_kind: CandidateSelectorKind::Key,
        selector: "eval.tuner.max_candidates".into(),
        owner_kind: CandidateOwnerKind::Schema,
        owner: "iteron_tunables::Param/ResolutionValue".into(),
    };
    let direct_address = CandidateAddress {
        kind: CandidateAddressKind::DirectConfig,
        selector_kind: CandidateSelectorKind::Path,
        selector: "runtime.max_candidates".into(),
        owner_kind: CandidateOwnerKind::Schema,
        owner: "config::Runtime".into(),
    };
    let param_value = iteron_tunables::ResolutionValue::Integer { value: 64 };
    let candidate = TunerCandidate {
        schema_version: CANDIDATE_GRAPH_SCHEMA_VERSION,
        id: "candidate-v3".into(),
        values: BTreeMap::new(),
        profile: None,
        implementations: Vec::new(),
        graph: Some(CandidateGraph {
            schema_id: CANDIDATE_GRAPH_SCHEMA_ID.into(),
            dimensions: vec![
                CandidateDimension::Param {
                    address: profile_address.clone(),
                    param: profile_address.selector.clone(),
                    value: param_value.clone(),
                },
                CandidateDimension::NativeValue {
                    address: direct_address.clone(),
                    value: iteron_tunables::ResolutionValue::Boolean { value: true },
                },
            ],
            lineage: CandidateLineage {
                parent_sha256: None,
                generation: 0,
                sparse_delta: Vec::new(),
            },
            experiment: CandidateExperiment {
                dataset_sha256: prefixed_digest('a'),
                evaluator_sha256: prefixed_digest('b'),
                environment_sha256: prefixed_digest('c'),
                resource_sha256: prefixed_digest('d'),
                fidelity_sha256: prefixed_digest('e'),
                seed: 7,
            },
            topology: vec![CandidateTopologyEdge {
                dependency: profile_address.clone(),
                dependent: direct_address,
                condition: Some(CandidateCondition {
                    address: profile_address,
                    equals: param_value,
                }),
            }],
            implementations: Vec::new(),
        }),
    };
    candidate.validate_universal().unwrap();
    let materialized = candidate.materialize().unwrap();
    assert_eq!(materialized.profile.params.len(), 1);
    assert_eq!(materialized.direct_config_patches.len(), 1);
    assert!(materialized.caller_input_patches.is_empty());
    assert_eq!(
        candidate.graph_identity().unwrap().unwrap().schema_id,
        CANDIDATE_GRAPH_SCHEMA_ID
    );
    assert_eq!(
        candidate.rendered_profile().unwrap(),
        candidate.rendered_profile().unwrap()
    );
}

#[test]
fn optimization_census_runtime_addresses_are_unique_and_roundtrip() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("governance/optimization-census.json");
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let rows = document["candidates"].as_array().unwrap();
    let mut addresses = BTreeSet::new();
    let mut runtime_rows = 0_usize;
    for row in rows {
        if row["disposition"] != "runtime_settable" {
            continue;
        }
        runtime_rows += 1;
        let address: CandidateAddress =
            serde_json::from_value(row["external_address"].clone()).unwrap();
        address.validate().unwrap();
        assert!(addresses.insert(address.clone()));
        let roundtrip: CandidateAddress =
            serde_json::from_slice(&serde_json::to_vec(&address).unwrap()).unwrap();
        assert_eq!(roundtrip, address);
    }
    assert_eq!(
        runtime_rows,
        document["runtime_settable"].as_u64().unwrap() as usize
    );
    assert_eq!(addresses.len(), runtime_rows);
    for surface in ["strategy", "tool", "compaction", "memory"] {
        assert!(
            rows.iter().any(|row| {
                row["disposition"] == "runtime_settable"
                    && row["id"].as_str().is_some_and(|id| id.contains(surface))
            }),
            "the universal candidate space must include a runtime-settable {surface} surface"
        );
    }
}

use super::*;
use crate::report::{aggregate, compare};
use crate::types::{
    CellKey, CellResult, CostStatus, EVAL_SCHEMA_VERSION, KernelTaxObservation, OracleStatus,
    SamplingControl,
};
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
            "core-eval-tuner-{label}-{}-{nonce:x}",
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
    core_tunables::families()
        .iter()
        .find(|family| family.optimization.class != core_tunables::OptimizationClass::Pin)
        .unwrap()
        .id
}

fn pinned_family() -> &'static str {
    core_tunables::families()
        .iter()
        .find(|family| family.optimization.class == core_tunables::OptimizationClass::Pin)
        .unwrap()
        .id
}

fn candidate(id: &str, value: &str) -> TunerCandidate {
    TunerCandidate {
        id: id.into(),
        values: BTreeMap::from([(tunable_family().into(), value.into())]),
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
        tunables_registry_digest: core_tunables::REGISTRY_DIGEST_SHA256.into(),
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

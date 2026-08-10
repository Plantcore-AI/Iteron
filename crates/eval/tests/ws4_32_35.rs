#![cfg(unix)]

use iteron_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use iteron_eval::measurement::{KernelTaxLine, MeasurementError, compare_manifests};
use iteron_eval::report::{aggregate, compare};
use iteron_eval::runner::score_candidate_diff;
use iteron_eval::types::EVAL_SCHEMA_VERSION;
use iteron_eval::{
    CandidateOutput, CapturedHarnessCandidate, CellResult, CorpusManifest, CorpusTask, CostStatus,
    EvaluationManifest, EvaluationPurpose, EvidenceBundleInput, EvidenceIdentityPolicy,
    EvidenceProjectionError, EvidenceSigner, InsufficientPowerReason, OracleStatus,
    ParallelEvalOptions, Partition, PromotionInvariantClaims, ReferenceHarnessAdapter,
    ReferenceHarnessSpec, RunAttestation, RunStatus, SamplingControl, StatisticalConclusion,
    TrainedBundleDescriptor, TrainedEvaluationError, attach_cross_model_transfer,
    compile_evidence_bundle, measure_kernel_tax, run_evaluation_parallel, sign_held_out_evidence,
    trained_vs_untrained_report, verify_evidence_bundle,
};
use iteron_evolve::{
    ArtifactKind, BaseModelId, EvolutionMethod, IndependentEvaluator, PolicyRef,
    PromotionAuthorityKey, StrategySlot, VerifiedCandidateInputs,
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-eval-ws4-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create temp root");
        Self(path)
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

fn fixture_repo(root: &TempRoot) -> (String, String) {
    let repo = root.join("repo");
    std::fs::create_dir(&repo).expect("repo");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("status.txt"), "bad\n").expect("status");
    std::fs::write(repo.join("stable.txt"), "stable\n").expect("stable");
    git(&repo, &["add", "status.txt", "stable.txt"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=eval",
            "-c",
            "user.email=eval@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    );
    (
        url::Url::from_file_path(repo.canonicalize().expect("canonical"))
            .expect("file URL")
            .to_string(),
        git(&repo, &["rev-parse", "HEAD"]),
    )
}

fn oracle_task(url: String, commit: String) -> CorpusTask {
    CorpusTask {
        id: "oracle-fixture".into(),
        repo_url: url,
        commit,
        prompt: "make status good without changing stable".into(),
        verify_command: "test \"$(cat status.txt)\" = good".into(),
        ground_truth_command: "test \"$(cat status.txt)\" = good".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["status becomes good".into()],
        pass_to_pass: vec!["stable stays stable".into()],
        test_cmd: BTreeMap::from([(
            "sh".into(),
            "case \"$ITERON_EVAL_TEST_SET\" in fail_to_pass) test \"$(cat status.txt)\" = good ;; pass_to_pass) test \"$(cat stable.txt)\" = stable ;; *) exit 2 ;; esac".into(),
        )]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "local two-sided oracle fixture".into(),
            task_id: "oracle-fixture".into(),
            license: Some("test-only".into()),
        },
        benchmark: None,
    }
}

const GOLD_DIFF: &str = "diff --git a/status.txt b/status.txt\n--- a/status.txt\n+++ b/status.txt\n@@ -1 +1 @@\n-bad\n+good\n";
const BREAK_P2P_DIFF: &str = "diff --git a/stable.txt b/stable.txt\n--- a/stable.txt\n+++ b/stable.txt\n@@ -1 +1 @@\n-stable\n+broken\ndiff --git a/status.txt b/status.txt\n--- a/status.txt\n+++ b/status.txt\n@@ -1 +1 @@\n-bad\n+good\n";

#[test]
fn checked_in_live_gold_receipt_binds_the_real_slice_and_two_sided_docker_oracle() {
    let record: serde_json::Value = serde_json::from_str(include_str!(
        "../corpora/records/swe-bench-pro-gold-ansible-iptables.json"
    ))
    .expect("live receipt JSON");
    assert_eq!(record["record_type"], "live_gold_patch_validation");
    assert_eq!(
        record["dataset_digest"],
        "sha256:a97b67f804b06bc3e546fc714de6eabdce2d4f75b26144482bfc774c9ce05d7a"
    );
    assert_eq!(record["source_evaluation"]["executor"], "dgx-spark");
    assert_eq!(record["source_evaluation"]["target_arch"], "aarch64");
    assert_eq!(record["cells"][0]["resolved"], true);
    let oracle = &record["cells"][0]["evidence"]["two_sided_oracle"];
    assert_eq!(oracle["fail_to_pass_before"]["status"], "test_failed");
    assert_eq!(oracle["pass_to_pass_before"]["status"], "passed");
    assert_eq!(oracle["fail_to_pass_after"]["status"], "passed");
    assert_eq!(oracle["pass_to_pass_after"]["status"], "passed");
    for name in [
        "fail_to_pass_before",
        "pass_to_pass_before",
        "fail_to_pass_after",
        "pass_to_pass_after",
    ] {
        let commands = oracle[name]["commands"]
            .as_array()
            .expect("live oracle commands");
        assert!(!commands.is_empty());
        assert!(commands.iter().all(|command| {
            command["backend"] == "docker" && command["egress_disabled"] == true
        }));
    }
}

#[tokio::test]
async fn f2p_p2p_oracle_accepts_gold_rejects_empty_and_rejects_regression() {
    let root = TempRoot::new("oracle");
    let (url, commit) = fixture_repo(&root);
    let task = oracle_task(url, commit);
    let gold = score_candidate_diff(
        &task,
        GOLD_DIFF,
        &root.join("gold"),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .await
    .expect("gold oracle");
    assert!(gold.resolved);
    assert_eq!(gold.fail_to_pass_before.status, OracleStatus::TestFailed);
    assert_eq!(gold.fail_to_pass_after.status, OracleStatus::Passed);
    assert_eq!(gold.pass_to_pass_before.status, OracleStatus::Passed);
    assert_eq!(gold.pass_to_pass_after.status, OracleStatus::Passed);

    let empty = score_candidate_diff(
        &task,
        "",
        &root.join("empty"),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .await
    .expect("empty oracle");
    assert!(!empty.resolved);
    assert_eq!(empty.fail_to_pass_after.status, OracleStatus::TestFailed);

    let regression = score_candidate_diff(
        &task,
        BREAK_P2P_DIFF,
        &root.join("regression"),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .await
    .expect("regression oracle");
    assert!(!regression.resolved);
    assert_eq!(
        regression.pass_to_pass_after.status,
        OracleStatus::TestFailed
    );
}

fn executable(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write executable");
    let mut permissions = std::fs::metadata(path).expect("stat").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("chmod");
}

#[tokio::test]
async fn pinned_open_harness_self_report_is_ignored_by_core_oracle() {
    let root = TempRoot::new("reference");
    let (url, commit) = fixture_repo(&root);
    let task = oracle_task(url, commit);
    let source = root.join("harness");
    std::fs::create_dir(&source).expect("source");
    git(&source, &["init", "--quiet"]);
    executable(
        &source.join("adapter.sh"),
        "#!/bin/sh\nprintf '%s\\n' '{\"schema_version\":1,\"candidate_diff\":\"diff --git a/status.txt b/status.txt\\n--- a/status.txt\\n+++ b/status.txt\\n@@ -1 +1 @@\\n-bad\\n+good\\n\",\"self_reported_resolved\":false}'\n",
    );
    git(&source, &["add", "adapter.sh"]);
    git(
        &source,
        &[
            "-c",
            "user.name=harness",
            "-c",
            "user.email=harness@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "pinned adapter",
        ],
    );
    git(
        &source,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/open-harness.git",
        ],
    );
    let revision = git(&source, &["rev-parse", "HEAD"]);
    let adapter = ReferenceHarnessAdapter::new(
        ReferenceHarnessSpec {
            name: "fixture-open-harness".into(),
            source_url: "https://example.invalid/open-harness.git".into(),
            revision,
            launcher: "sh".into(),
            entrypoint: "adapter.sh".into(),
            arguments: Vec::new(),
            candidate_output: Default::default(),
        },
        source,
    )
    .expect("pinned clean adapter");
    let candidate = adapter
        .capture_candidate(
            &task,
            &root.join("candidate-workspace"),
            "model-m",
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("capture candidate");
    assert_eq!(candidate.self_reported_resolved, Some(false));
    let score = adapter
        .score_candidate(
            &task,
            candidate,
            &root.join("reference-oracle"),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .await
        .expect("score with Core oracle");
    assert!(score.resolved());
    assert_eq!(score.self_reported_resolved, Some(false));
}

#[test]
fn checked_in_swe_agent_config_is_strict_and_revision_pinned() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpora/reference-harnesses/swe-agent-3ea751c.json");
    let spec = ReferenceHarnessSpec::load(&path).expect("load pinned SWE-agent config");
    assert_eq!(spec.revision, "3ea751c087f32b16e039a2233dd6eefecef325d5");
    assert_eq!(
        spec.source_url,
        "https://github.com/SWE-agent/SWE-agent.git"
    );
    assert!(matches!(
        spec.candidate_output,
        CandidateOutput::SweAgentPrediction { .. }
    ));
    assert!(
        spec.arguments
            .iter()
            .any(|argument| argument == "--env.deployment.docker_args=--network=none"),
        "the model-calling coordinator may use its provider route, but task code must not get egress"
    );
}

#[tokio::test]
async fn pinned_adapter_reads_real_swe_agent_prediction_contract() {
    let root = TempRoot::new("swe-agent-prediction");
    let (url, commit) = fixture_repo(&root);
    let task = oracle_task(url, commit);
    let source = root.join("prediction-harness");
    std::fs::create_dir(&source).expect("source");
    git(&source, &["init", "--quiet"]);
    executable(
        &source.join("adapter.sh"),
        "#!/bin/sh\nset -eu\nartifact_dir=$1\ntask=$2\nmkdir -p \"$artifact_dir/$task\"\nprintf '%s\\n' '{\"model_name_or_path\":\"model-m\",\"instance_id\":\"oracle-fixture\",\"model_patch\":\"diff --git a/status.txt b/status.txt\\n--- a/status.txt\\n+++ b/status.txt\\n@@ -1 +1 @@\\n-bad\\n+good\\n\"}' > \"$artifact_dir/$task/$task.pred\"\n",
    );
    git(&source, &["add", "adapter.sh"]);
    git(
        &source,
        &[
            "-c",
            "user.name=harness",
            "-c",
            "user.email=harness@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "pinned prediction adapter",
        ],
    );
    git(
        &source,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/prediction-harness.git",
        ],
    );
    let revision = git(&source, &["rev-parse", "HEAD"]);
    let adapter = ReferenceHarnessAdapter::new(
        ReferenceHarnessSpec {
            name: "fixture-swe-agent-contract".into(),
            source_url: "https://example.invalid/prediction-harness.git".into(),
            revision,
            launcher: "sh".into(),
            entrypoint: "adapter.sh".into(),
            arguments: vec!["{artifact_dir}".into(), "{task_id}".into()],
            candidate_output: CandidateOutput::SweAgentPrediction {
                path: "{artifact_dir}/{task_id}/{task_id}.pred".into(),
            },
        },
        source,
    )
    .expect("pinned clean adapter");
    let candidate = adapter
        .capture_candidate(
            &task,
            &root.join("candidate-workspace"),
            "model-m",
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("capture SWE-agent prediction");
    assert!(candidate.candidate_diff.contains("+good"));
    assert_eq!(candidate.self_reported_resolved, None);

    let mismatch = adapter
        .capture_candidate(
            &task,
            &root.join("mismatched-model-workspace"),
            "different-model",
            None,
            Duration::from_secs(5),
        )
        .await
        .expect_err("the prediction must bind the requested frozen model");
    assert!(mismatch.to_string().contains("does not match frozen model"));
}

fn write_corpus(root: &TempRoot, task: CorpusTask) -> PathBuf {
    let tasks = vec![task];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "parallel-fixture-v2".into(),
        dataset_digest: digest_tasks(&tasks).expect("digest"),
        tasks,
    };
    let path = root.join("corpus.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("encode"))
        .expect("write corpus");
    path
}

fn fake_core(root: &TempRoot) -> PathBuf {
    let path = root.join("fake-core");
    executable(
        &path,
        "#!/bin/sh\nset -eu\nworkspace=\nmax_turns=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -C) shift; workspace=$1 ;;\n    --max-turns) shift; max_turns=$1 ;;\n  esac\n  shift\ndone\ntest \"$max_turns\" = 250\nprintf 'good\\n' > \"$workspace/status.txt\"\nprintf '%s\\n' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"done\",\"reason\":null,\"success\":true,\"assistant_text\":\"done\",\"run_id\":\"parallel-fixture\",\"cost_usd\":0.25,\"cost_status\":\"known\",\"cost_reason\":null,\"turns\":2,\"exit_code\":0,\"error\":null}'\n",
    );
    path
}

fn uncapped_core(root: &TempRoot) -> PathBuf {
    let path = root.join("uncapped-core");
    executable(
        &path,
        "#!/bin/sh\nset -eu\nworkspace=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -C) shift; workspace=$1 ;;\n    --max-turns) exit 93 ;;\n  esac\n  shift\ndone\nprintf 'good\\n' > \"$workspace/status.txt\"\nprintf '%s\\n' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"done\",\"reason\":null,\"success\":true,\"assistant_text\":\"done\",\"run_id\":\"uncapped-fixture\",\"cost_usd\":0.25,\"cost_status\":\"known\",\"cost_reason\":null,\"turns\":2,\"exit_code\":0,\"error\":null}'\n",
    );
    path
}

fn flaky_core(root: &TempRoot) -> PathBuf {
    let path = root.join("flaky-core");
    let counter = root.join("flaky-core-count");
    executable(
        &path,
        &format!(
            "#!/bin/sh\nset -eu\nworkspace=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -C) shift; workspace=$1 ;;\n  esac\n  shift\ndone\ncount=0\ntest ! -f '{counter}' || count=$(cat '{counter}')\ncount=$((count + 1))\nprintf '%s\\n' \"$count\" > '{counter}'\nif [ \"$count\" = 1 ]; then\n  printf '%s\\n' '{{not-json}}'\n  exit 1\nfi\nprintf 'good\\n' > \"$workspace/status.txt\"\nprintf '%s\\n' '{{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"done\",\"reason\":null,\"success\":true,\"assistant_text\":\"done\",\"run_id\":\"retry-fixture\",\"cost_usd\":0.25,\"cost_status\":\"known\",\"cost_reason\":null,\"turns\":2,\"exit_code\":0,\"error\":null}}'\n",
            counter = counter.display()
        ),
    );
    path
}

fn eval_options(
    root: &TempRoot,
    corpus_path: PathBuf,
    core_bin: PathBuf,
    workers: usize,
    label: &str,
) -> ParallelEvalOptions {
    ParallelEvalOptions {
        corpus_path,
        output_path: root.join(format!("{label}.json")),
        work_root: root.join(format!("work-{label}")),
        core_bin: Some(core_bin),
        allow_local_repositories: true,
        model: "model-m".into(),
        provider: Some("fixed-provider".into()),
        credential_env: None,
        bundle_path: None,
        purpose: EvaluationPurpose::Score,
        seeds: 4,
        minimum_seeds: 3,
        run_timeout: Duration::from_secs(10),
        checkout_timeout: Duration::from_secs(10),
        oracle_timeout: Duration::from_secs(10),
        workers,
        max_turns: 250,
        uncapped: false,
        max_attempts: 1,
    }
}

#[tokio::test]
async fn one_and_thirty_two_workers_emit_identical_order_and_aggregates() {
    let root = TempRoot::new("parallel");
    let (url, commit) = fixture_repo(&root);
    let corpus = write_corpus(&root, oracle_task(url, commit));
    let core = fake_core(&root);
    let serial = run_evaluation_parallel(&eval_options(
        &root,
        corpus.clone(),
        core.clone(),
        1,
        "serial",
    ))
    .await
    .expect("serial");
    let parallel = run_evaluation_parallel(&eval_options(&root, corpus, core, 32, "parallel"))
        .await
        .expect("parallel");

    let order = |manifest: &EvaluationManifest| {
        manifest
            .cells
            .iter()
            .map(|cell| {
                (
                    cell.task.clone(),
                    cell.config.clone(),
                    cell.seed,
                    cell.resolved,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(order(&serial), order(&parallel));
    assert_eq!(
        serde_json::to_vec(&serial.aggregate).expect("serial aggregate"),
        serde_json::to_vec(&parallel.aggregate).expect("parallel aggregate")
    );
    assert_eq!(
        serde_json::to_vec(&serial.comparison).expect("serial comparison"),
        serde_json::to_vec(&parallel.comparison).expect("parallel comparison")
    );
}

#[tokio::test]
async fn explicit_uncapped_mode_omits_the_core_turn_flag_and_is_recorded() {
    let root = TempRoot::new("uncapped");
    let (url, commit) = fixture_repo(&root);
    let corpus = write_corpus(&root, oracle_task(url, commit));
    let mut options = eval_options(&root, corpus, uncapped_core(&root), 1, "uncapped");
    options.seeds = 1;
    options.minimum_seeds = 1;
    options.uncapped = true;
    let manifest = run_evaluation_parallel(&options)
        .await
        .expect("explicitly uncapped run");
    assert_eq!(manifest.max_turns, None);
    assert!(
        manifest
            .cells
            .iter()
            .all(|cell| cell.run_status == RunStatus::Completed)
    );
}

#[tokio::test]
async fn physical_retry_uses_fresh_workspaces_and_emits_verifiable_sidecars() {
    let root = TempRoot::new("physical-retry");
    let (url, commit) = fixture_repo(&root);
    let corpus = write_corpus(&root, oracle_task(url, commit));
    let mut options = eval_options(&root, corpus, flaky_core(&root), 1, "physical-retry");
    options.seeds = 1;
    options.minimum_seeds = 1;
    options.max_attempts = 2;
    let manifest = run_evaluation_parallel(&options)
        .await
        .expect("the retryable harness fault settles on a fresh second attempt");
    assert_eq!(manifest.cells.len(), 2);
    assert!(
        manifest
            .cells
            .iter()
            .all(|cell| cell.run_status == RunStatus::Completed)
    );

    let attempt_path = iteron_eval::attempts::sidecar_path(&options.output_path);
    let ledger =
        iteron_eval::AttemptLedger::open(&attempt_path).expect("verify attempt hash chain");
    assert_eq!(
        ledger.record_count(),
        9,
        "two attempts plus one normal cell"
    );
    let attestation_path = iteron_eval::attestation::sidecar_path(&options.output_path);
    let attestation: RunAttestation =
        serde_json::from_slice(&std::fs::read(&attestation_path).expect("read run attestation"))
            .expect("strict run attestation JSON");
    assert_eq!(attestation.attempt_ledger_head, ledger.head_hash());
    assert_eq!(attestation.attempt_record_count, ledger.record_count());
    attestation
        .verify_artifacts(
            options.core_bin.as_deref().expect("core path"),
            &options.corpus_path,
            &options.output_path,
            &attempt_path,
        )
        .expect("all attested bytes still match");

    let signer = EvidenceSigner::from_seed([7_u8; 32]);
    let bundle_path = root.join("signed-evidence");
    let bundle = compile_evidence_bundle(
        EvidenceBundleInput {
            destination: &bundle_path,
            baseline_result: &options.output_path,
            baseline_attestation: &attestation_path,
            baseline_arm: "verify_OFF",
            baseline_id: "baseline",
            candidate_result: &options.output_path,
            candidate_attestation: &attestation_path,
            candidate_arm: "verify_ON",
            candidate_id: "candidate",
            minimum_pairs: 1,
        },
        &signer,
    )
    .expect("compile a signed self-contained evidence bundle");
    assert_eq!(bundle.index.files.len(), 6);
    assert_eq!(bundle.paired.comparison.matched_pairs, 1);
    assert!(!bundle.pareto.frontier.is_empty());
    verify_evidence_bundle(&bundle_path, &signer.public_key_hex())
        .expect("offline verification needs only the trusted public key");
    std::fs::write(bundle_path.join("candidate.json"), b"tampered\n").expect("tamper fixture");
    assert!(verify_evidence_bundle(&bundle_path, &signer.public_key_hex()).is_err());

    let run_dirs = std::fs::read_dir(&options.work_root)
        .expect("work root")
        .next()
        .expect("run root")
        .expect("run entry")
        .path();
    let attempt_dirs = std::fs::read_dir(run_dirs)
        .expect("attempt directories")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains("-attempt-"))
        .count();
    assert!(
        attempt_dirs >= 3,
        "every physical execution gets a fresh checkout"
    );
}

#[tokio::test]
async fn production_runner_refuses_a_simulated_bundle_binding() {
    let root = TempRoot::new("bundle-binding");
    let (url, commit) = fixture_repo(&root);
    let corpus = write_corpus(&root, oracle_task(url, commit));
    let bundle = root.join("policy.bundle");
    std::fs::write(&bundle, "bundle-fixture\n").expect("bundle");
    let core = fake_core(&root);
    let mut options = eval_options(&root, corpus, core, 2, "bundle");
    options.seeds = 1;
    options.minimum_seeds = 1;
    options.bundle_path = Some(bundle);
    let error = run_evaluation_parallel(&options)
        .await
        .expect_err("a fixture-only --bundle flag must not impersonate a production binding");
    assert!(error.to_string().contains("no policy-bundle input"));
    assert!(
        !options.work_root.exists(),
        "rejection occurs before any attempt"
    );
}

fn synthetic_cell(
    task: &str,
    config: &str,
    seed: u64,
    resolved: bool,
    cost: f64,
    turns: u32,
    elapsed_ms: u64,
) -> CellResult {
    CellResult {
        task: task.into(),
        config: config.into(),
        seed,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: Some(resolved),
        run_status: RunStatus::Completed,
        failure_phase: None,
        exit_code: Some(0),
        terminal_outcome: Some("done".into()),
        cost_status: CostStatus::Known,
        cost_usd: Some(cost),
        cost_reason: None,
        turns: Some(turns),
        kernel_tax: None,
        oracle_status: if resolved {
            OracleStatus::Passed
        } else {
            OracleStatus::TestFailed
        },
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "fixed_fixture".into(),
            reason: None,
        },
        elapsed_ms,
        error: None,
        candidate_diff: Some(format!("diff-{task}-{config}-{seed}")),
    }
}

fn synthetic_manifest(
    model: &str,
    config: &str,
    outcomes: &[bool],
    bundle_digest: Option<String>,
) -> EvaluationManifest {
    let cells = outcomes
        .iter()
        .enumerate()
        .map(|(index, resolved)| {
            synthetic_cell(
                &format!("task-{}", index / 2),
                config,
                index as u64,
                *resolved,
                1.0 + index as f64 / 10.0,
                2 + index as u32,
                10 + index as u64,
            )
        })
        .collect::<Vec<_>>();
    let aggregate = aggregate(&cells, 2);
    EvaluationManifest {
        schema_version: EVAL_SCHEMA_VERSION,
        run_id: format!("run-{model}-{config}"),
        corpus_version: "held-out-suite-v2".into(),
        dataset_digest: format!("sha256:{}", "a".repeat(64)),
        model: model.into(),
        provider: Some("fixed-provider".into()),
        bundle_digest,
        purpose: EvaluationPurpose::Score,
        seeds: outcomes.len() as u64,
        minimum_seeds: 2,
        workers: 1,
        max_turns: Some(250),
        core_agent_wall_secs: 1_800,
        core_process_grace_secs: 30,
        core_process_timeout_secs: 1_830,
        result_path: PathBuf::from(format!("{config}.json")),
        comparison: compare(&aggregate, config, config),
        aggregate,
        selections: Vec::new(),
        cells,
        kernel_tax: iteron_eval::types::KernelTaxObservation::default(),
    }
}

#[test]
fn paired_bootstrap_is_reproducible_and_underpowered_inputs_are_typed() {
    let baseline = synthetic_manifest("model-m", "open_harness", &[false, true, false, true], None);
    let treatment = synthetic_manifest(
        "model-m",
        "core_untrained",
        &[true, true, false, true],
        None,
    );
    let first = compare_manifests(
        &baseline,
        "open_harness",
        &treatment,
        "core_untrained",
        2,
        "untrained_vs_open",
        KernelTaxLine::reserved(),
    )
    .expect("paired report");
    let repeated = compare_manifests(
        &baseline,
        "open_harness",
        &treatment,
        "core_untrained",
        2,
        "untrained_vs_open",
        KernelTaxLine::reserved(),
    )
    .expect("repeat");
    assert_eq!(
        first.comparison.paired_ci95.map(f64::to_bits),
        repeated.comparison.paired_ci95.map(f64::to_bits)
    );
    let underpowered = compare_manifests(
        &baseline,
        "open_harness",
        &treatment,
        "core_untrained",
        100,
        "untrained_vs_open",
        KernelTaxLine::reserved(),
    )
    .expect("underpowered report");
    assert!(matches!(
        underpowered.comparison.statistical_conclusion,
        StatisticalConclusion::InsufficientPower(_)
    ));

    let missing = compare_manifests(
        &baseline,
        "open_harness",
        &treatment,
        "absent_arm",
        2,
        "untrained_vs_open",
        KernelTaxLine::reserved(),
    )
    .expect("a missing arm is an underpowered report, not a fabricated verdict");
    assert_eq!(missing.comparison.resolved_rate_delta, 0.0);
    assert_eq!(missing.comparison.paired_ci95, [-1.0, 1.0]);
    assert_eq!(
        missing.comparison.statistical_conclusion,
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::MissingComparisonArm)
    );

    let mut partial = treatment.clone();
    partial.cells.pop();
    assert!(matches!(
        compare_manifests(
            &baseline,
            "open_harness",
            &partial,
            "core_untrained",
            2,
            "untrained_vs_open",
            KernelTaxLine::reserved(),
        ),
        Err(MeasurementError::PairingMismatch)
    ));
}

#[test]
fn golden_paired_report_uses_the_real_pro_slice_identity() {
    const TASK: &str = "instance_gravitational__teleport-0ac7334939981cf85b9591ac295c3816954e287e";
    const CORPUS: &str = "swe-bench-pro-os-ca10a60a5fcae51e6948ffe1485d4153d421e6c5-slice-v2";
    const DIGEST: &str = "sha256:a97b67f804b06bc3e546fc714de6eabdce2d4f75b26144482bfc774c9ce05d7a";
    const MODEL: &str = "fixture-frozen-model-m@sha256:1111111111111111111111111111111111111111111111111111111111111111";

    let mut open = synthetic_manifest(
        MODEL,
        "swe_agent_3ea751c",
        &[false, true, false, true],
        None,
    );
    let mut core = synthetic_manifest(MODEL, "core_untrained", &[true, true, false, true], None);
    for manifest in [&mut open, &mut core] {
        manifest.corpus_version = CORPUS.into();
        manifest.dataset_digest = DIGEST.into();
        manifest.provider = Some("recorded-fixture".into());
        for cell in &mut manifest.cells {
            cell.task = TASK.into();
        }
    }
    let report = compare_manifests(
        &open,
        "swe_agent_3ea751c",
        &core,
        "core_untrained",
        3,
        "recorded_fixture_untrained_vs_swe_agent",
        KernelTaxLine::reserved(),
    )
    .expect("paired fixture");
    let encoded = serde_json::to_string_pretty(&report).expect("encode paired fixture") + "\n";
    assert_eq!(
        encoded,
        include_str!("../corpora/records/untrained-vs-swe-agent-paired-fixture.json")
    );
}

fn bundle_descriptor(
    digest_char: char,
    producer_id: &str,
    method: EvolutionMethod,
    artifact_kind: ArtifactKind,
) -> TrainedBundleDescriptor {
    TrainedBundleDescriptor {
        bundle_digest: format!("sha256:{}", digest_char.to_string().repeat(64)),
        training_dataset_digest: format!("sha256:{}", "b".repeat(64)),
        producer_id: producer_id.into(),
        method,
        artifact_kind,
    }
}

#[test]
fn trained_cross_model_second_producer_and_kernel_tax_share_one_pipeline() {
    let untrained = synthetic_manifest(
        "model-m",
        "core_untrained",
        &[false, false, false, false],
        None,
    );
    let descriptor = bundle_descriptor(
        'c',
        "producer-search",
        EvolutionMethod::Search,
        ArtifactKind::Rules,
    );
    let trained = synthetic_manifest(
        "model-m",
        "core_trained",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    let bare_deploy = synthetic_manifest(
        "model-m",
        "bare_deploy",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    let mut governed_deploy = synthetic_manifest(
        "model-m",
        "governed_deploy",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    for cell in &mut governed_deploy.cells {
        cell.turns = cell.turns.map(|turns| turns + 1);
        cell.cost_usd = cell.cost_usd.map(|cost| cost + 0.2);
        cell.elapsed_ms += 5;
    }
    let kernel_tax = measure_kernel_tax(
        &bare_deploy,
        "bare_deploy",
        &governed_deploy,
        "governed_deploy",
    )
    .expect("kernel tax");
    assert!(!kernel_tax.included_in_resolved_rate);
    assert_eq!(kernel_tax.turns_delta, Some(1.0));
    assert_eq!(kernel_tax.latency_delta_ms, Some(5.0));
    let mut report = trained_vs_untrained_report(
        &untrained,
        "core_untrained",
        &trained,
        "core_trained",
        2,
        descriptor.clone(),
        kernel_tax,
    )
    .expect("trained report");
    let original_delta = report.trained_vs_untrained.comparison.resolved_rate_delta;

    let second_untrained = synthetic_manifest(
        "model-m2",
        "core_untrained",
        &[false, false, false, false],
        None,
    );
    let second_trained = synthetic_manifest(
        "model-m2",
        "core_trained",
        &[true, false, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    attach_cross_model_transfer(
        &mut report,
        &second_untrained,
        "core_untrained",
        &second_trained,
        "core_trained",
        2,
    )
    .expect("portable fraction");
    let transfer = report.cross_model_transfer.as_ref().expect("transfer");
    assert!(transfer.portable_fraction.is_finite());
    assert!(!transfer.applied_to_promotion_threshold);
    assert_eq!(
        report.trained_vs_untrained.comparison.resolved_rate_delta, original_delta,
        "kernel tax and transfer metadata cannot alter the capability delta"
    );

    for descriptor in [
        descriptor,
        bundle_descriptor(
            'd',
            "producer-sft",
            EvolutionMethod::SupervisedFineTune,
            ArtifactKind::ModelAdapter,
        ),
    ] {
        let arm = synthetic_manifest(
            "model-m",
            "core_trained",
            &[true, true, false, true],
            Some(descriptor.bundle_digest.clone()),
        );
        trained_vs_untrained_report(
            &untrained,
            "core_untrained",
            &arm,
            "core_trained",
            2,
            descriptor,
            KernelTaxLine::reserved(),
        )
        .expect("method-agnostic producer round-trip");
    }
}

#[test]
fn golden_trained_report_binds_bundle_transfer_and_kernel_tax_to_real_slice() {
    const TASK: &str = "instance_gravitational__teleport-0ac7334939981cf85b9591ac295c3816954e287e";
    const CORPUS: &str = "swe-bench-pro-os-ca10a60a5fcae51e6948ffe1485d4153d421e6c5-slice-v2";
    const DIGEST: &str = "sha256:a97b67f804b06bc3e546fc714de6eabdce2d4f75b26144482bfc774c9ce05d7a";
    const MODEL_M: &str = "fixture-frozen-model-m@sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const MODEL_M2: &str = "fixture-frozen-model-m2@sha256:2222222222222222222222222222222222222222222222222222222222222222";

    let descriptor = bundle_descriptor(
        'c',
        "fixture-producer-search",
        EvolutionMethod::Search,
        ArtifactKind::Rules,
    );
    let mut untrained = synthetic_manifest(
        MODEL_M,
        "core_untrained",
        &[false, false, false, false],
        None,
    );
    let mut trained = synthetic_manifest(
        MODEL_M,
        "core_trained",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    let mut bare = synthetic_manifest(
        MODEL_M,
        "bare_deploy",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    let mut governed = synthetic_manifest(
        MODEL_M,
        "governed_deploy",
        &[true, true, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    let mut second_untrained = synthetic_manifest(
        MODEL_M2,
        "core_untrained",
        &[false, false, false, false],
        None,
    );
    let mut second_trained = synthetic_manifest(
        MODEL_M2,
        "core_trained",
        &[true, false, false, true],
        Some(descriptor.bundle_digest.clone()),
    );
    for cell in &mut governed.cells {
        cell.turns = cell.turns.map(|turns| turns + 1);
        cell.cost_usd = cell.cost_usd.map(|cost| cost + 0.25);
        cell.elapsed_ms += 5;
    }
    for manifest in [
        &mut untrained,
        &mut trained,
        &mut bare,
        &mut governed,
        &mut second_untrained,
        &mut second_trained,
    ] {
        manifest.corpus_version = CORPUS.into();
        manifest.dataset_digest = DIGEST.into();
        manifest.provider = Some("recorded-fixture".into());
        for cell in &mut manifest.cells {
            cell.task = TASK.into();
        }
    }
    let kernel_tax = measure_kernel_tax(&bare, "bare_deploy", &governed, "governed_deploy")
        .expect("kernel tax fixture");
    let mut report = trained_vs_untrained_report(
        &untrained,
        "core_untrained",
        &trained,
        "core_trained",
        3,
        descriptor,
        kernel_tax,
    )
    .expect("trained fixture");
    attach_cross_model_transfer(
        &mut report,
        &second_untrained,
        "core_untrained",
        &second_trained,
        "core_trained",
        3,
    )
    .expect("transfer fixture");
    let encoded = serde_json::to_string_pretty(&report).expect("encode trained fixture") + "\n";
    assert_eq!(
        encoded,
        include_str!("../corpora/records/trained-bundle-heldout-fixture.json")
    );
}

#[test]
fn trained_scoring_refuses_train_partition() {
    let untrained = synthetic_manifest("model-m", "core_untrained", &[false, false], None);
    let descriptor = bundle_descriptor(
        'c',
        "producer",
        EvolutionMethod::Search,
        ArtifactKind::Rules,
    );
    let mut contaminated = synthetic_manifest(
        "model-m",
        "core_trained",
        &[true, true],
        Some(descriptor.bundle_digest.clone()),
    );
    contaminated.purpose = EvaluationPurpose::Tune;
    contaminated.cells[0].partition = Partition::Train;
    let error = trained_vs_untrained_report(
        &untrained,
        "core_untrained",
        &contaminated,
        "core_trained",
        1,
        descriptor,
        KernelTaxLine::reserved(),
    )
    .expect_err("train partition must be refused");
    assert!(matches!(error, TrainedEvaluationError::Contamination));
}

fn policy(id: &str, digest_char: char) -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::planner(),
        policy_id: id.into(),
        version: "v1".into(),
        digest: digest_char.to_string().repeat(64),
    }
}

fn invariant_claims() -> PromotionInvariantClaims {
    PromotionInvariantClaims {
        candidate_safety_violations: 0,
        candidate_policy_violations: 0,
        train_eval_overlap: false,
        replay_equivalence_passed: true,
        sandbox_suite_passed: true,
        invariant_suites: BTreeMap::from([("runtime".into(), true), ("security".into(), true)]),
    }
}

#[test]
fn held_out_projection_signs_with_disjoint_evaluator_and_rejects_producer_identity() {
    let baseline = synthetic_manifest("model-m", "untrained", &[false, false, false], None);
    let candidate = synthetic_manifest(
        "model-m",
        "trained",
        &[true, true, false],
        Some(format!("sha256:{}", "c".repeat(64))),
    );
    let verified = VerifiedCandidateInputs {
        artifact_digest: "c".repeat(64),
        training_dataset_digest: Some("b".repeat(64)),
        evaluation_suite_digest: "a".repeat(64),
        base_model: BaseModelId {
            model_family: "fixture".into(),
            model_id: "model-m".into(),
            model_digest: "d".repeat(64),
        },
    };
    let identities = EvidenceIdentityPolicy {
        evaluator_id: "independent-evaluator".into(),
        producer_anchor_ids: BTreeSet::from(["producer".into()]),
        promotion_anchor_ids: BTreeSet::from(["promoter".into()]),
    };
    let evaluator = IndependentEvaluator::new(
        identities.evaluator_id.clone(),
        PromotionAuthorityKey::new(vec![7_u8; 32]).expect("key"),
    )
    .expect("evaluator");
    let signed = sign_held_out_evidence(
        &baseline,
        "untrained",
        &candidate,
        "trained",
        2,
        policy("baseline", '1'),
        policy("candidate", 'c'),
        &verified,
        &evaluator,
        &identities,
        invariant_claims(),
    )
    .expect("signed held-out evidence");
    assert_eq!(signed.evaluator_id(), "independent-evaluator");
    assert_eq!(signed.report().evidence().paired_tasks, 3);

    let mut unbound_candidate = candidate.clone();
    unbound_candidate.bundle_digest = None;
    let error = sign_held_out_evidence(
        &baseline,
        "untrained",
        &unbound_candidate,
        "trained",
        2,
        policy("baseline", '1'),
        policy("candidate", 'c'),
        &verified,
        &evaluator,
        &identities,
        invariant_claims(),
    )
    .expect_err("signed evidence must bind the exact evaluated policy bundle");
    assert!(matches!(
        error,
        EvidenceProjectionError::CandidateBundleMismatch
    ));

    let producer_identities = EvidenceIdentityPolicy {
        evaluator_id: "producer".into(),
        ..identities
    };
    let producer_signer = IndependentEvaluator::new(
        "producer",
        PromotionAuthorityKey::new(vec![9_u8; 32]).expect("producer key"),
    )
    .expect("producer signer");
    let error = sign_held_out_evidence(
        &baseline,
        "untrained",
        &candidate,
        "trained",
        2,
        policy("baseline", '1'),
        policy("candidate", 'c'),
        &verified,
        &producer_signer,
        &producer_identities,
        invariant_claims(),
    )
    .expect_err("a producer identity cannot self-sign held-out evidence");
    assert!(matches!(error, EvidenceProjectionError::IdentityOverlap(_)));
}

#[test]
fn held_out_projection_refuses_tune_manifest() {
    let mut baseline = synthetic_manifest("model-m", "untrained", &[false, false], None);
    baseline.purpose = EvaluationPurpose::Tune;
    baseline.cells[0].partition = Partition::Train;
    let candidate = synthetic_manifest("model-m", "trained", &[true, true], None);
    let verified = VerifiedCandidateInputs {
        artifact_digest: "c".repeat(64),
        training_dataset_digest: Some("b".repeat(64)),
        evaluation_suite_digest: "a".repeat(64),
        base_model: BaseModelId {
            model_family: "fixture".into(),
            model_id: "model-m".into(),
            model_digest: "d".repeat(64),
        },
    };
    let identities = EvidenceIdentityPolicy {
        evaluator_id: "eval".into(),
        producer_anchor_ids: BTreeSet::new(),
        promotion_anchor_ids: BTreeSet::new(),
    };
    let evaluator = IndependentEvaluator::new(
        "eval",
        PromotionAuthorityKey::new(vec![5_u8; 32]).expect("key"),
    )
    .expect("eval");
    let error = sign_held_out_evidence(
        &baseline,
        "untrained",
        &candidate,
        "trained",
        1,
        policy("baseline", '1'),
        policy("candidate", '2'),
        &verified,
        &evaluator,
        &identities,
        invariant_claims(),
    )
    .expect_err("tune evidence is not held-out evidence");
    assert!(matches!(error, EvidenceProjectionError::NotHeldOut));
}

#[test]
fn candidate_contract_type_keeps_self_report_audit_only() {
    let candidate = CapturedHarnessCandidate {
        schema_version: 1,
        candidate_diff: GOLD_DIFF.into(),
        self_reported_resolved: Some(true),
    };
    assert_eq!(candidate.self_reported_resolved, Some(true));
    assert!(candidate.candidate_diff.contains("status.txt"));
}

//! Bounded executable coverage for the installed cross-harness qualification campaign.
//!
//! The local half deliberately produces a receipt rather than T49 proof documents: marketplace
//! process lifecycle and trainer negotiation are real outcomes, but they are not substitutes for
//! an installed Iteron task run or the official Terminal-Bench verifier. The command therefore
//! refuses qualification until the audited external Harbor campaign is available.

use crate::{
    ALL_TRAINER_CAPABILITIES, CheckpointContract, DatasetPartition, DistributedTrials,
    OptimizerCapabilityOffer, RewardContract, RewardDirection, RewardObjective,
    TRAINER_BRIDGE_SCHEMA_VERSION, TrainerBridgeSpec, TrainerCapability, TrainerDataset,
    TrainerResources, TrajectoryContract,
};
use iteron_evolve::EvolutionMethod;
use iteron_marketplace::{
    EvidenceLimits, HotSwapBlockKind, HotSwapCoordinator, HotSwapExecutor, HotSwapGeneration,
    HotSwapPhase, HotSwapRequest, HotSwapResult, HotSwapStageError, ImplementationFailurePolicy,
    ImplementationManifest, ImplementationRegistry, ImplementationResponse,
    ImplementationResponseEnvelope, ImplementationRuntime, ImplementationState, RuntimeState,
    Version, replay_ledger,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_tunables::ModuleId;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn campaign_receipt_schema() -> &'static str {
    "iteron-cross-harness-campaign-receipt/1"
}

fn harbor_version() -> &'static str {
    "0.20.0"
}

fn harbor_commit() -> &'static str {
    "5342956db1433368dd0b9b54286129ae415beebc"
}

fn terminal_bench_commit() -> &'static str {
    "5c8eadf1f393183288fa08b8f73ca9a469cc5e00"
}

fn terminal_bench_tasks_tree() -> &'static str {
    "2f0f5fdc68f0befd9b4745386eb8698264b00d8a"
}

fn terminal_bench_dataset() -> &'static str {
    "terminal-bench/terminal-bench-2-1"
}

#[derive(Debug, Clone, Serialize)]
struct CampaignReceipt {
    schema_id: &'static str,
    qualification_id: String,
    status: &'static str,
    claim_scope: &'static str,
    score_superiority_claimed: bool,
    exact_external_pin: ExternalPin,
    implemented_executable_coverage: ExecutableCoverage,
    missing_prerequisites: Vec<Prerequisite>,
    manifest_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ExternalPin {
    benchmark_id: &'static str,
    benchmark_version: &'static str,
    dataset: &'static str,
    harbor_version: &'static str,
    harbor_commit: &'static str,
    terminal_bench_commit: &'static str,
    terminal_bench_tasks_tree: &'static str,
    task_count: usize,
    attempts_per_task: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutableCoverage {
    module_matrix: ModuleMatrixCoverage,
    optimizer_negotiation: OptimizerCoverage,
    stateful_hotswap: HotSwapCoverage,
}

#[derive(Debug, Clone, Serialize)]
struct ModuleMatrixCoverage {
    outcome: &'static str,
    scope: &'static str,
    modules: usize,
    cases: usize,
    external_processes: usize,
    correlated_terminal_observations: usize,
    reaped_processes: usize,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct OptimizerCoverage {
    outcome: &'static str,
    scope: &'static str,
    families: Vec<OptimizerFamilyCoverage>,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct OptimizerFamilyCoverage {
    id: &'static str,
    method: String,
    negotiation_sha256: String,
    capabilities: Vec<TrainerCapability>,
}

#[derive(Debug, Clone, Serialize)]
struct HotSwapCoverage {
    outcome: &'static str,
    committed_records: usize,
    migrated_state_observed: bool,
    deterministic_replay_observed: bool,
    fault_phases: Vec<FaultCoverage>,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct FaultCoverage {
    phase: HotSwapPhase,
    rollback_observed: bool,
    old_generation_retained: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Prerequisite {
    code: &'static str,
    detail: String,
}

#[derive(Debug, Clone, Copy)]
enum ProviderMode {
    Swap,
    Ablation,
}

impl ProviderMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "swap" => Some(Self::Swap),
            "ablation" => Some(Self::Ablation),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Ablation => "ablation",
        }
    }
}

/// Run the operator-facing campaign command. It never emits a partial T49 manifest.
pub fn run_campaign_cli(args: &[String]) -> ExitCode {
    let qualification_id = match parse_campaign_args(args) {
        Ok(qualification_id) => qualification_id,
        Err(()) => {
            let receipt = CampaignReceipt {
                schema_id: campaign_receipt_schema(),
                qualification_id: "unassigned-campaign".to_owned(),
                status: "refused",
                claim_scope: "functional_acceptance_only",
                score_superiority_claimed: false,
                exact_external_pin: external_pin(),
                implemented_executable_coverage: empty_coverage(),
                missing_prerequisites: vec![Prerequisite {
                    code: "invalid_campaign_arguments",
                    detail: "expected no arguments or exactly --qualification-id followed by one valid identifier"
                        .into(),
                }],
                manifest_path: None,
            };
            if write_json_line(&receipt).is_err() {
                return ExitCode::from(2);
            }
            return ExitCode::from(2);
        }
    };
    let coverage = run_local_coverage();
    let receipt = match coverage {
        Ok(implemented_executable_coverage) => CampaignReceipt {
            schema_id: campaign_receipt_schema(),
            qualification_id,
            status: "refused",
            claim_scope: "functional_acceptance_only",
            score_superiority_claimed: false,
            exact_external_pin: external_pin(),
            implemented_executable_coverage,
            missing_prerequisites: vec![
                Prerequisite {
                    code: "official_harbor_runner_required",
                    detail: "install and pin Harbor 0.20.0 at the audited commit".into(),
                },
                Prerequisite {
                    code: "terminal_bench_dataset_required",
                    detail: "provide the audited terminal-bench/terminal-bench-2-1 checkout".into(),
                },
                Prerequisite {
                    code: "sandbox_provider_required",
                    detail: "provide an independently attested Harbor sandbox provider".into(),
                },
                Prerequisite {
                    code: "model_authorization_required",
                    detail: "authorize the Harbor Iteron agent outside this credential-free command".into(),
                },
                Prerequisite {
                    code: "installed_iteron_consumption_unavailable",
                    detail: "the installed CLI has no credential-free public operation that consumes all 56 implementation cells".into(),
                },
                Prerequisite {
                    code: "terminal_bench_campaign_not_run",
                    detail: "run all 89 tasks with at least five trials and retain failures and timeouts".into(),
                },
            ],
            manifest_path: None,
        },
        Err(detail) => CampaignReceipt {
            schema_id: campaign_receipt_schema(),
            qualification_id,
            status: "refused",
            claim_scope: "functional_acceptance_only",
            score_superiority_claimed: false,
            exact_external_pin: external_pin(),
            implemented_executable_coverage: empty_coverage(),
            missing_prerequisites: vec![Prerequisite {
                code: "local_executable_coverage_failed",
                detail,
            }],
            manifest_path: None,
        },
    };
    if write_json_line(&receipt).is_err() {
        return ExitCode::from(2);
    }
    ExitCode::from(2)
}

fn parse_campaign_args(args: &[String]) -> Result<String, ()> {
    match args {
        [] => Ok("unassigned-campaign".to_owned()),
        [flag, value] if flag == "--qualification-id" && valid_id(value) => Ok(value.clone()),
        _ => Err(()),
    }
}

fn external_pin() -> ExternalPin {
    ExternalPin {
        benchmark_id: "terminal-bench",
        benchmark_version: "2.1",
        dataset: terminal_bench_dataset(),
        harbor_version: harbor_version(),
        harbor_commit: harbor_commit(),
        terminal_bench_commit: terminal_bench_commit(),
        terminal_bench_tasks_tree: terminal_bench_tasks_tree(),
        task_count: 89,
        attempts_per_task: 5,
    }
}

fn write_json_line(value: &impl Serialize) -> Result<(), ()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| ())?;
    if bytes.len() + 1 > crate::MAX_PROTOCOL_REQUEST_BYTES {
        return Err(());
    }
    bytes.push(b'\n');
    io::stdout().lock().write_all(&bytes).map_err(|_| ())
}

fn run_local_coverage() -> Result<ExecutableCoverage, String> {
    Ok(ExecutableCoverage {
        module_matrix: exercise_module_matrix()?,
        optimizer_negotiation: exercise_optimizer_negotiation()?,
        stateful_hotswap: exercise_hotswap()?,
    })
}

fn empty_coverage() -> ExecutableCoverage {
    ExecutableCoverage {
        module_matrix: ModuleMatrixCoverage {
            outcome: "not_observed",
            scope: "marketplace_external_process_lifecycle",
            modules: 0,
            cases: 0,
            external_processes: 0,
            correlated_terminal_observations: 0,
            reaped_processes: 0,
            evidence_sha256: "0".repeat(64),
        },
        optimizer_negotiation: OptimizerCoverage {
            outcome: "not_observed",
            scope: "trainer_protocol_negotiation_only",
            families: Vec::new(),
            evidence_sha256: "0".repeat(64),
        },
        stateful_hotswap: HotSwapCoverage {
            outcome: "not_observed",
            committed_records: 0,
            migrated_state_observed: false,
            deterministic_replay_observed: false,
            fault_phases: Vec::new(),
            evidence_sha256: "0".repeat(64),
        },
    }
}

fn exercise_module_matrix() -> Result<ModuleMatrixCoverage, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let bytes = read_regular(&executable, 1024 * 1024 * 1024)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let root = executable
        .parent()
        .ok_or_else(|| "campaign executable has no parent directory".to_owned())?;
    let file_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "campaign executable name is not UTF-8".to_owned())?;
    let mut ledger = Vec::new();
    let mut observations = 0;
    let mut reaped = 0;
    for module in ModuleId::ALL {
        for mode in [ProviderMode::Ablation, ProviderMode::Swap] {
            let implementation_id = format!(
                "qualification.{}.{}",
                module.as_str().replace('.', "_"),
                mode.as_str()
            );
            let mut registry = ImplementationRegistry::new(CapabilitySet::none());
            registry
                .register(ImplementationManifest {
                    implementation_id: implementation_id.clone(),
                    implementation_version: Version(1, 0, 0),
                    module,
                    artifact_sha256: digest.clone(),
                    executable: file_name.to_owned(),
                    argv: vec![
                        "qualification-provider".into(),
                        "--module".into(),
                        module.as_str().into(),
                        "--implementation-id".into(),
                        implementation_id.clone(),
                        "--mode".into(),
                        mode.as_str().into(),
                    ],
                    protocol_version: 2,
                    requested_capabilities: CapabilitySet::none(),
                    dependencies: Vec::new(),
                    runtime_deadline_ms: 5_000,
                    cancellation_deadline_ms: 1_000,
                    evidence_limits: EvidenceLimits {
                        stdout_bytes: 64 * 1024,
                        stderr_bytes: 16 * 1024,
                        observations: 2,
                    },
                    failure_policy: ImplementationFailurePolicy::FailClosed,
                })
                .map_err(|error| error.to_string())?;
            let verified = registry
                .verify_artifact(&implementation_id, &bytes)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "registered campaign provider disappeared".to_owned())?;
            let plan = registry
                .launch_plan(&implementation_id, root, &verified)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "registered campaign provider has no launch plan".to_owned())?;
            let mut runtime =
                ImplementationRuntime::launch(plan).map_err(|error| error.to_string())?;
            runtime.load().map_err(|error| error.to_string())?;
            let run_id = format!("{}-{}", module.as_str().replace('.', "-"), mode.as_str());
            runtime
                .start(
                    run_id,
                    format!("sha256:{}", digest),
                    serde_json::json!({"module": module.as_str(), "mode": mode.as_str()}),
                    2_000,
                )
                .map_err(|error| error.to_string())?;
            let observation = runtime
                .next_observation(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            if !observation.terminal
                || observation
                    .observation
                    .get("mode")
                    .and_then(|value| value.as_str())
                    != Some(mode.as_str())
            {
                return Err("campaign provider terminal observation did not correlate".into());
            }
            let observation_sha256 = canonical_sha256(&observation)?;
            observations += 1;
            runtime
                .stop("qualification cell complete")
                .map_err(|error| error.to_string())?;
            if runtime.state() != RuntimeState::Stopped || !runtime.is_reaped() {
                return Err("campaign provider did not stop and reap".into());
            }
            reaped += 1;
            ledger.push(serde_json::json!({
                "module": module.as_str(),
                "mode": mode.as_str(),
                "implementation_id": implementation_id,
                "provider_binary_sha256": digest.clone(),
                "observation_sha256": observation_sha256,
                "stdout_bytes": runtime.evidence().stdout_bytes,
                "observations": runtime.evidence().observations,
                "reaped": runtime.is_reaped(),
            }));
        }
    }
    if ledger.len() != ModuleId::ALL.len() * 2 {
        return Err("campaign module matrix is incomplete".into());
    }
    Ok(ModuleMatrixCoverage {
        outcome: "observed",
        scope: "marketplace_external_process_lifecycle",
        modules: ModuleId::ALL.len(),
        cases: ledger.len(),
        external_processes: ledger.len(),
        correlated_terminal_observations: observations,
        reaped_processes: reaped,
        evidence_sha256: canonical_sha256(&ledger)?,
    })
}

fn exercise_optimizer_negotiation() -> Result<OptimizerCoverage, String> {
    let spec = trainer_spec();
    let profiles = [
        (
            "search",
            EvolutionMethod::Search,
            vec![
                TrainerCapability::Asynchronous,
                TrainerCapability::MultiObjective,
            ],
        ),
        (
            "contextual-bandit",
            EvolutionMethod::ContextualBandit,
            vec![TrainerCapability::Asynchronous, TrainerCapability::Bandit],
        ),
        (
            "preference-optimization",
            EvolutionMethod::PreferenceOptimization,
            vec![TrainerCapability::Batch, TrainerCapability::Trajectory],
        ),
        (
            "offline-rl",
            EvolutionMethod::OfflineRl,
            vec![
                TrainerCapability::Trajectory,
                TrainerCapability::CheckpointResume,
            ],
        ),
        (
            "generated-code",
            EvolutionMethod::GeneratedCode,
            vec![
                TrainerCapability::Population,
                TrainerCapability::OpaqueArtifact,
            ],
        ),
    ];
    let mut families = Vec::new();
    for (id, method, capabilities) in profiles {
        let negotiation = spec
            .negotiate(&OptimizerCapabilityOffer {
                optimizer_id: id.into(),
                capabilities: capabilities.clone(),
            })
            .map_err(|error| error.to_string())?;
        negotiation
            .validate(&spec)
            .map_err(|error| error.to_string())?;
        if negotiation.capabilities != capabilities {
            return Err("optimizer capability intersection drifted".into());
        }
        let method = serde_json::to_value(method)
            .map_err(|error| error.to_string())?
            .as_str()
            .ok_or_else(|| "evolution method did not serialize as a string".to_owned())?
            .to_owned();
        families.push(OptimizerFamilyCoverage {
            id,
            method,
            negotiation_sha256: negotiation.negotiation_sha256,
            capabilities,
        });
    }
    Ok(OptimizerCoverage {
        outcome: "observed",
        scope: "trainer_protocol_negotiation_only",
        evidence_sha256: canonical_sha256(&families)?,
        families,
    })
}

fn trainer_spec() -> TrainerBridgeSpec {
    TrainerBridgeSpec {
        schema_version: TRAINER_BRIDGE_SCHEMA_VERSION,
        experiment_id: "cross-harness-qualification".into(),
        train: TrainerDataset {
            partition: DatasetPartition::Train,
            digest: prefixed_digest('a'),
            schema_id: "qualification/train@v1".into(),
        },
        held_out: TrainerDataset {
            partition: DatasetPartition::HeldOut,
            digest: prefixed_digest('b'),
            schema_id: "qualification/held-out@v1".into(),
        },
        reward: RewardContract {
            schema_id: "qualification/reward@v1".into(),
            objectives: vec![RewardObjective {
                metric: "functional_acceptance".into(),
                direction: RewardDirection::Maximize,
                weight_micros: 1_000_000,
            }],
        },
        trajectory: TrajectoryContract {
            schema_id: "qualification/trajectory@v1".into(),
            max_bytes_per_trial: 1024 * 1024,
            max_events_per_trial: 4096,
            content_store_required: true,
        },
        checkpoint: CheckpointContract {
            schema_id: "qualification/checkpoint@v1".into(),
            max_checkpoint_bytes: 1024 * 1024,
            checkpoint_every_trials: 1,
        },
        resources: TrainerResources {
            max_trials: 56,
            max_concurrency: 1,
            max_wall_secs_per_trial: 60,
            max_memory_bytes_per_trial: 1024 * 1024 * 1024,
            max_evidence_bytes_per_trial: 16 * 1024 * 1024,
        },
        distributed: DistributedTrials {
            coordinator_id: "qualification/local".into(),
            max_workers: 1,
            lease_secs: 30,
            heartbeat_secs: 5,
            max_attempts_per_trial: 1,
        },
        capabilities: ALL_TRAINER_CAPABILITIES.to_vec(),
    }
}

fn exercise_hotswap() -> Result<HotSwapCoverage, String> {
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
    let mut faults = Vec::new();
    let mut evidence = Vec::new();
    for (index, phase) in phases.into_iter().enumerate() {
        let path = temp_path(&format!("fault-{index}"));
        let (old_state, new_state) = states()?;
        let request = hotswap_request(
            &format!("qualification-fault-{index}"),
            &old_state,
            &new_state,
        );
        let mut coordinator =
            HotSwapCoordinator::open(&path, [(request.module, request.old.clone())])
                .map_err(|error| error.to_string())?;
        let mut executor = CampaignExecutor::new(Some(phase), old_state, new_state);
        let result = coordinator
            .transact(request.clone(), &mut executor)
            .map_err(|error| error.to_string())?;
        let HotSwapResult::RolledBack(blocked) = result else {
            return Err("injected hot-swap fault did not roll back".into());
        };
        let retained = coordinator.current_generation(request.module) == Some(&request.old);
        if blocked.phase != phase
            || executor.rollback_count != 1
            || executor.active_generation != 1
            || !retained
        {
            return Err("hot-swap rollback evidence did not correlate".into());
        }
        let records = replay_ledger(&path).map_err(|error| error.to_string())?;
        evidence.push(serde_json::to_value(&records).map_err(|error| error.to_string())?);
        remove_temp(&path);
        faults.push(FaultCoverage {
            phase,
            rollback_observed: true,
            old_generation_retained: true,
        });
    }

    let path = temp_path("commit");
    let (old_state, new_state) = states()?;
    let request = hotswap_request("qualification-commit", &old_state, &new_state);
    let mut coordinator = HotSwapCoordinator::open(&path, [(request.module, request.old.clone())])
        .map_err(|error| error.to_string())?;
    let mut executor = CampaignExecutor::new(None, old_state, new_state);
    let committed = coordinator
        .transact(request.clone(), &mut executor)
        .map_err(|error| error.to_string())?;
    if committed != HotSwapResult::Committed(request.new.clone())
        || !executor.migrated
        || executor.active_generation != 2
    {
        return Err("hot-swap commit or state migration was not observed".into());
    }
    let first = replay_ledger(&path).map_err(|error| error.to_string())?;
    let second = replay_ledger(&path).map_err(|error| error.to_string())?;
    let reopened = HotSwapCoordinator::open(&path, [(request.module, request.old.clone())])
        .map_err(|error| error.to_string())?;
    let deterministic =
        first == second && reopened.current_generation(request.module) == Some(&request.new);
    if !deterministic {
        return Err("hot-swap deterministic replay was not observed".into());
    }
    evidence.push(serde_json::to_value(&first).map_err(|error| error.to_string())?);
    let records = first.len();
    remove_temp(&path);
    Ok(HotSwapCoverage {
        outcome: "observed",
        committed_records: records,
        migrated_state_observed: true,
        deterministic_replay_observed: true,
        fault_phases: faults,
        evidence_sha256: canonical_sha256(&evidence)?,
    })
}

struct CampaignExecutor {
    fail: Option<HotSwapPhase>,
    old: ImplementationState,
    new: ImplementationState,
    rollback_count: usize,
    migrated: bool,
    active_generation: u64,
}

impl CampaignExecutor {
    fn new(fail: Option<HotSwapPhase>, old: ImplementationState, new: ImplementationState) -> Self {
        Self {
            fail,
            old,
            new,
            rollback_count: 0,
            migrated: false,
            active_generation: 1,
        }
    }

    fn hit(&self, phase: HotSwapPhase) -> Result<(), HotSwapStageError> {
        if self.fail == Some(phase) {
            Err(HotSwapStageError::new(
                HotSwapBlockKind::Provider,
                format!("qualification fault at {phase:?}"),
            ))
        } else {
            Ok(())
        }
    }
}

impl HotSwapExecutor for CampaignExecutor {
    fn protocol_version(&self) -> u16 {
        2
    }

    fn verify(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
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
        self.migrated = true;
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
        self.active_generation = 2;
        Ok(())
    }

    fn drain(&mut self, _: &HotSwapRequest, _: Instant) -> Result<(), HotSwapStageError> {
        self.hit(HotSwapPhase::Drain)
    }

    fn rollback(&mut self, _: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        self.rollback_count += 1;
        self.active_generation = 1;
        Ok(())
    }

    fn committed(&mut self, _: &HotSwapRequest) -> Result<(), HotSwapStageError> {
        Ok(())
    }
}

fn states() -> Result<(ImplementationState, ImplementationState), String> {
    let node = iteron_tunables::capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::PromptSystem)
        .ok_or_else(|| "prompt.system seam is absent".to_owned())?;
    let old = ImplementationState::new(
        ModuleId::PromptSystem,
        "qualification.old",
        "qualification-run",
        1,
        node.lifecycle.snapshot.clone(),
        serde_json::json!({"counter": 1}),
    )
    .map_err(|error| error.to_string())?;
    let new = ImplementationState::new(
        ModuleId::PromptSystem,
        "qualification.new",
        "qualification-run",
        2,
        node.lifecycle.snapshot,
        serde_json::json!({"counter": 2}),
    )
    .map_err(|error| error.to_string())?;
    Ok((old, new))
}

fn hotswap_request(
    transaction_id: &str,
    old_state: &ImplementationState,
    new_state: &ImplementationState,
) -> HotSwapRequest {
    HotSwapRequest {
        transaction_id: transaction_id.into(),
        module: ModuleId::PromptSystem,
        candidate_sha256: prefixed_digest('c'),
        old: HotSwapGeneration {
            generation: 1,
            implementation_id: old_state.implementation_id.clone(),
            artifact_sha256: prefixed_digest('a'),
            state_sha256: old_state.state_sha256.clone(),
        },
        new: HotSwapGeneration {
            generation: 2,
            implementation_id: new_state.implementation_id.clone(),
            artifact_sha256: prefixed_digest('b'),
            state_sha256: new_state.state_sha256.clone(),
        },
        authority_sha256: prefixed_digest('d'),
        deadline_ms: 5_000,
    }
}

fn temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iteron-qualification-{label}-{}.jsonl",
        std::process::id()
    ))
}

fn remove_temp(path: &Path) {
    let _ = fs::remove_file(path);
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("campaign executable path is not absolute".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err("campaign executable is not a bounded regular non-symlink file".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 != metadata.len() {
        return Err("campaign executable changed while being read".into());
    }
    Ok(bytes)
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn prefixed_digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
}

/// Private child-process endpoint used only by `campaign` through a registry-minted launch plan.
pub fn run_provider_cli(args: &[String]) -> ExitCode {
    match provider_args(args).and_then(|(module, implementation_id, mode)| {
        serve_provider(module, &implementation_id, mode)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("iteron-harness qualification provider: {error}");
            ExitCode::from(2)
        }
    }
}

fn provider_args(args: &[String]) -> Result<(ModuleId, String, ProviderMode), String> {
    if args.len() != 6
        || args[0] != "--module"
        || args[2] != "--implementation-id"
        || args[4] != "--mode"
    {
        return Err("invalid provider arguments".into());
    }
    let module = ModuleId::ALL
        .into_iter()
        .find(|module| module.as_str() == args[1])
        .ok_or_else(|| "unknown module".to_owned())?;
    if !valid_id(&args[3]) {
        return Err("invalid implementation id".into());
    }
    let mode = ProviderMode::parse(&args[5]).ok_or_else(|| "unknown provider mode".to_owned())?;
    Ok((module, args[3].clone(), mode))
}

fn serve_provider(
    module: ModuleId,
    implementation_id: &str,
    mode: ProviderMode,
) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut observation_schema = None;
    loop {
        let Some(line) = read_bounded_provider_line(&mut input)? else {
            return Ok(());
        };
        let request = iteron_marketplace::parse_implementation_request(&line)
            .map_err(|error| error.to_string())?;
        if request.module != module || request.implementation_id != implementation_id {
            return Err("provider request identity drifted".into());
        }
        let response = match request.payload {
            iteron_marketplace::ImplementationRequest::Load {
                provider_contract,
                observation_schema: schema,
                ..
            } => {
                observation_schema = Some(schema.clone());
                ImplementationResponse::Loaded {
                    provider_contract,
                    observation_schema: schema,
                }
            }
            iteron_marketplace::ImplementationRequest::Start { run_id, .. } => {
                let response = ImplementationResponse::Started {
                    run_id: run_id.clone(),
                };
                write_provider_response(
                    &mut output,
                    &request.request_id,
                    implementation_id,
                    module,
                    response,
                )?;
                let schema = observation_schema
                    .clone()
                    .ok_or_else(|| "provider was started before load".to_owned())?;
                let observation = iteron_marketplace::ImplementationObservationEnvelope {
                    protocol: iteron_marketplace::IMPLEMENTATION_PROTOCOL.into(),
                    implementation_id: implementation_id.into(),
                    module,
                    run_id,
                    sequence: 0,
                    schema,
                    terminal: true,
                    observation: serde_json::json!({
                        "mode": mode.as_str(),
                        "decision": match mode {
                            ProviderMode::Swap => "applied",
                            ProviderMode::Ablation => "inherit",
                        },
                    }),
                };
                write_provider_value(&mut output, &observation)?;
                continue;
            }
            iteron_marketplace::ImplementationRequest::Stop { .. } => {
                write_provider_response(
                    &mut output,
                    &request.request_id,
                    implementation_id,
                    module,
                    ImplementationResponse::Stopped,
                )?;
                return Ok(());
            }
            _ => return Err("qualification provider received an unsupported operation".into()),
        };
        write_provider_response(
            &mut output,
            &request.request_id,
            implementation_id,
            module,
            response,
        )?;
    }
}

fn read_bounded_provider_line(input: &mut impl io::BufRead) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf().map_err(|error| error.to_string())?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err("provider request is not newline terminated".into())
            };
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let remaining =
            iteron_marketplace::MAX_IMPLEMENTATION_MESSAGE_BYTES.saturating_add(1) - line.len();
        line.extend_from_slice(&available[..consumed.min(remaining)]);
        let ended = available[..consumed].ends_with(b"\n");
        input.consume(consumed);
        if line.len() > iteron_marketplace::MAX_IMPLEMENTATION_MESSAGE_BYTES {
            return Err("provider request exceeds its line bound".into());
        }
        if ended {
            return Ok(Some(line));
        }
    }
}

fn write_provider_response(
    output: &mut impl io::Write,
    request_id: &str,
    implementation_id: &str,
    module: ModuleId,
    payload: ImplementationResponse,
) -> Result<(), String> {
    write_provider_value(
        output,
        &ImplementationResponseEnvelope {
            protocol: iteron_marketplace::IMPLEMENTATION_PROTOCOL.into(),
            request_id: request_id.into(),
            implementation_id: implementation_id.into(),
            module,
            payload,
        },
    )
}

fn write_provider_value(output: &mut impl io::Write, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() + 1 > iteron_marketplace::MAX_IMPLEMENTATION_MESSAGE_BYTES {
        return Err("provider response exceeds its line bound".into());
    }
    output
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

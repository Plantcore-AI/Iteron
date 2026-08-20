//! Trustworthy fixed-model evaluation for Iteron.
//!
//! The harness consumes a versioned external corpus, materializes pinned repositories, invokes
//! Core through its JSON process contract, and runs corpus oracles only inside the egress-off
//! sandbox. Failed harness cells are typed and censored rather than counted as wrong patches.

pub mod adapter_registry;
pub mod attempts;
pub mod attestation;
pub mod contract;
mod contract_result;
pub mod corpus;
pub mod engineering_cycle;
pub mod evidence;
pub mod evidence_bundle;
pub mod measurement;
pub mod pareto;
pub mod process;
pub mod provisioner;
pub mod qualification_campaign;
pub mod record_projection;
pub mod reference_harness;
pub mod report;
mod research_execution;
pub mod research_protocol;
pub mod runner;
pub mod scoreboard;
mod statistics;
mod strict_json;
pub mod terminal_bench;
pub mod trained;
pub mod trainer_bridge;
pub mod tuner;
pub mod types;

use research_execution::response_validation as research_validation;

pub use iteron_evolve::{
    ACTIVITY_SCHEMA_VERSION, ActivityCancellation, ActivityDelivery, ActivityError, ActivityEvent,
    ActivityPublisher, ActivityReceiver, activity_channel,
};

pub use adapter_registry::{
    AdapterOperation, AdapterPin, AdapterRegistryEntry, BenchmarkAdapterRegistry,
    EXTERNAL_NATIVE_ID, EXTERNAL_NATIVE_VERSION, ITERON_CLI_ID, ITERON_CLI_VERSION,
    ResearchExecutionMode, ResearchSession,
};
pub use attempts::{
    AttemptEvent, AttemptKey, AttemptLedger, AttemptLedgerError, MAX_PHYSICAL_ATTEMPTS,
};
pub use attestation::{
    AdapterEvidence, ArtifactDigest, AttestationError, ExecutionLimits, RunAttestation,
    RunAttestationInput,
};
pub use contract::{
    CliFinalResult, CliMachineEventKind, CliMachineRecord, ContractError, parse_final_result,
    parse_machine_record,
};
pub use corpus::{CorpusError, CorpusManifest, CorpusTask};
pub use evidence::{
    EvidenceIdentityPolicy, EvidenceProjectionError, PromotionInvariantClaims,
    paired_projection_report, sign_held_out_evidence,
};
pub use evidence_bundle::{
    BundleComparison, BundleFile, EVIDENCE_ROWS_SCHEMA_ID, EVIDENCE_ROWS_SCHEMA_VERSION,
    EvidenceBundleError, EvidenceBundleIndex, EvidenceBundleInput, EvidenceRow, EvidenceRowOutcome,
    EvidenceRowsDocument, EvidenceRowsProvenance, EvidenceSigner, MAX_EVIDENCE_ROWS,
    MAX_EVIDENCE_ROWS_BYTES, VerifiedEvidenceBundle, compile_evidence_bundle,
    emit_candidate_evidence_rows, emit_evidence_rows, parse_evidence_rows, verify_evidence_bundle,
};
pub use measurement::{
    KernelTaxLine, MEASUREMENT_SCHEMA_VERSION, MeasurementError, PairedArmSummary,
    PairedComparison, PairedEvaluationReport, PairedMetricComparison, PerformanceArmSummary,
    PerformanceDecision, PerformanceEvaluationReport, PerformanceThresholds, compare_manifest_arms,
    compare_manifests, compare_performance_manifests,
};
pub use pareto::{ParetoError, ParetoPoint, ParetoReport, pareto_frontier};
pub use provisioner::{
    Provisioner, ProvisioningBackend, TestCommandReceipt, TestSet, TestSetReceipt,
};
pub use record_projection::{
    RecordPolicyProjectionError, RecordPolicyRunProjector, RecordedPolicyRunSpec,
};
pub use reference_harness::{
    CandidateOutput, CapturedHarnessCandidate, ReferenceHarnessAdapter, ReferenceHarnessError,
    ReferenceHarnessScore, ReferenceHarnessSpec,
};
pub use report::{
    Aggregate, Comparison, InsufficientPowerReason, SelectionSummary, StatisticalConclusion,
    aggregate, compare, selection_summaries,
};
pub use research_protocol::{
    CliRunSpec, DryRunState, EXTERNAL_NATIVE_ADAPTER_PROTOCOL, EXTERNAL_NATIVE_RESULT_SCHEMA,
    ExternalNativeResult, ExternalNativeRunSpec, ImplementationCandidateRef,
    MAX_NATIVE_MATERIALIZATION_BYTES, MAX_NATIVE_RECEIPT_BYTES, MAX_PROTOCOL_REQUEST_BYTES,
    MAX_PROTOCOL_RESPONSE_BYTES, NATIVE_CONSUMPTION_SCHEMA, NATIVE_MATERIALIZATION_SCHEMA,
    NativeConsumptionReceipt, NativeImplementationConsumption, NativeMaterializationDocument,
    NativeNodeConsumption, NativePatchConsumption, RESEARCH_PROTOCOL, ResearchProtocolError,
    ResearchRequest, ResearchRequestEnvelope, ResearchResponse, ResearchResponseEnvelope,
    ResearchRunState, ResearchTerminalResult, RunSpec, parse_research_request,
    parse_research_response,
};
pub use runner::hermetic::{
    FrozenModelProviderIdentity, HERMETIC_RUN_PREVIOUS_SCHEMA_VERSION, HERMETIC_RUN_SCHEMA_VERSION,
    HermeticFixtureReceipt, HermeticRepositoryPin, HermeticRunManifest, HermeticRunPins,
    PhysicalAttemptIdentity, deterministic_hermetic_fixture, hermetic_config_sha256,
    hermetic_seed_schedule_sha256, hermetic_sidecar_path, run_evaluation_hermetic,
    run_hermetic_fixture_cli,
};
pub use runner::{
    EvalOptions, ParallelEvalOptions, run_evaluation, run_evaluation_parallel,
    run_evaluation_parallel_with_activity,
};
pub use scoreboard::{
    EvidenceScoreRow, EvidenceScoreboard, SCOREBOARD_SCHEMA_ID, SCOREBOARD_SCHEMA_VERSION,
    ScoreboardError, generate_evidence_scoreboard,
};
pub use terminal_bench::{
    AdapterCommand, ArtifactReference, BenchmarkPin, ExternalHarnessResult, ProfileIdentity,
    ResourceBounds, ResourceUsage, RunEvidence, TaskIdentity, TerminalBenchAdapterError,
    TerminalBenchRequest, TerminalOutcome, TimingEvidence, parse_external_harness_result,
    parse_terminal_bench_request,
};
pub use trained::{
    PortableFractionReport, TRAINED_REPORT_SCHEMA_VERSION, TrainedBundleDescriptor,
    TrainedEvaluationError, TrainedEvaluationReport, attach_cross_model_transfer,
    measure_kernel_tax, trained_vs_untrained_report,
};
pub use trainer_bridge::{
    ALL_TRAINER_CAPABILITIES, CheckpointContract, DatasetPartition, DistributedTrials,
    LEGACY_TRAINER_BRIDGE_SCHEMA_VERSION, MAX_BATCH_SUGGESTIONS, MAX_DISTRIBUTED_WORKERS,
    MAX_REWARD_OBJECTIVES, MAX_TRAINER_BRIDGE_MESSAGE_BYTES, OptimizerCapabilityOffer,
    RewardContract, RewardDirection, RewardObjective, TRAINER_BRIDGE_SCHEMA_VERSION,
    TrainerBridgeError, TrainerBridgeSpec, TrainerCapability, TrainerCapabilityNegotiation,
    TrainerDataset, TrainerExchange, TrainerOperation, TrainerResources, TrajectoryContract,
    parse_negotiated_trainer_exchange, parse_trainer_bridge_spec, parse_trainer_exchange,
};
pub use tuner::{
    CANDIDATE_GRAPH_SCHEMA_ID, CANDIDATE_GRAPH_SCHEMA_VERSION, CandidateAddress,
    CandidateAddressKind, CandidateCondition, CandidateDimension, CandidateExecutionDependency,
    CandidateExecutionNode, CandidateExperiment, CandidateGraph, CandidateGraphIdentity,
    CandidateImplementation, CandidateLineage, CandidateMaterialization, CandidateNodeClass,
    CandidateOwnerKind, CandidatePatch, CandidateProductionPlan, CandidateSelectorKind,
    CandidateTopologyEdge, IMPLEMENTATION_PROTOCOL, LEGACY_IMPLEMENTATION_PROTOCOL,
    LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION, MAX_CANDIDATE_TOPOLOGY_EDGES, MAX_TUNER_CONCURRENCY,
    MAX_TUNER_TRIALS, MAX_UNIVERSAL_CANDIDATE_DIMENSIONS, OfflineTuner, TrialRequest, TrialResult,
    TunerCandidate, TunerError, TunerEvidenceInspection, TunerSnapshot, TunerSpec, TunerStatus,
    UNIVERSAL_CANDIDATE_SCHEMA_VERSION,
};
pub use types::{
    AgentMetrics, BenchmarkReference, CellKey, CellResult, CostObservation, CostStatus,
    EvaluationManifest, EvaluationPurpose, KernelTaxObservation, OracleStatus, Partition,
    RunStatus, SamplingControl, TwoSidedOracleReceipt,
};

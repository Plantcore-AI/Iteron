//! Trustworthy fixed-model evaluation for Iteron.
//!
//! The harness consumes a versioned external corpus, materializes pinned repositories, invokes
//! Core through its JSON process contract, and runs corpus oracles only inside the egress-off
//! sandbox. Failed harness cells are typed and censored rather than counted as wrong patches.

pub mod attempts;
pub mod attestation;
pub mod contract;
mod contract_result;
pub mod corpus;
pub mod evidence;
pub mod evidence_bundle;
pub mod measurement;
pub mod pareto;
pub mod process;
pub mod provisioner;
pub mod reference_harness;
pub mod report;
pub mod runner;
mod statistics;
mod strict_json;
pub mod trained;
pub mod tuner;
pub mod types;

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
    BundleComparison, BundleFile, EvidenceBundleError, EvidenceBundleIndex, EvidenceBundleInput,
    EvidenceSigner, VerifiedEvidenceBundle, compile_evidence_bundle, verify_evidence_bundle,
};
pub use measurement::{
    KernelTaxLine, MEASUREMENT_SCHEMA_VERSION, MeasurementError, PairedArmSummary,
    PairedComparison, PairedEvaluationReport, compare_manifest_arms, compare_manifests,
};
pub use pareto::{ParetoError, ParetoPoint, ParetoReport, pareto_frontier};
pub use provisioner::{
    Provisioner, ProvisioningBackend, TestCommandReceipt, TestSet, TestSetReceipt,
};
pub use reference_harness::{
    CandidateOutput, CapturedHarnessCandidate, ReferenceHarnessAdapter, ReferenceHarnessError,
    ReferenceHarnessScore, ReferenceHarnessSpec,
};
pub use report::{
    Aggregate, Comparison, InsufficientPowerReason, SelectionSummary, StatisticalConclusion,
    aggregate, compare, selection_summaries,
};
pub use runner::{EvalOptions, ParallelEvalOptions, run_evaluation, run_evaluation_parallel};
pub use trained::{
    PortableFractionReport, TRAINED_REPORT_SCHEMA_VERSION, TrainedBundleDescriptor,
    TrainedEvaluationError, TrainedEvaluationReport, attach_cross_model_transfer,
    measure_kernel_tax, trained_vs_untrained_report,
};
pub use tuner::{
    MAX_TUNER_CONCURRENCY, MAX_TUNER_TRIALS, OfflineTuner, TrialRequest, TrialResult,
    TunerCandidate, TunerError, TunerSnapshot, TunerSpec, TunerStatus,
};
pub use types::{
    BenchmarkReference, CellKey, CellResult, CostObservation, CostStatus, EvaluationManifest,
    EvaluationPurpose, KernelTaxObservation, OracleStatus, Partition, RunStatus, SamplingControl,
    TwoSidedOracleReceipt,
};

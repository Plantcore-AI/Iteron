//! Trustworthy fixed-model evaluation for Core Code.
//!
//! The harness consumes a versioned external corpus, materializes pinned repositories, invokes
//! Core through its JSON process contract, and runs corpus oracles only inside the egress-off
//! sandbox. Failed harness cells are typed and censored rather than counted as wrong patches.

pub mod contract;
mod contract_result;
pub mod corpus;
pub mod process;
pub mod report;
pub mod runner;
mod statistics;
mod strict_json;
pub mod types;

pub use contract::{
    CliFinalResult, CliMachineEventKind, CliMachineRecord, ContractError, TerminalError,
    parse_final_result, parse_machine_record, parse_terminal_result,
};
pub use corpus::{CorpusError, CorpusManifest, CorpusTask};
pub use report::{
    Aggregate, Comparison, InsufficientPowerReason, SelectionSummary, StatisticalConclusion,
    aggregate, compare, selection_summaries,
};
pub use runner::{EvalOptions, run_evaluation};
pub use types::{
    BenchmarkReference, CellKey, CellResult, CostObservation, CostStatus, EvaluationManifest,
    EvaluationPurpose, OracleStatus, Partition, RunStatus, SamplingControl,
};

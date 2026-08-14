//! Host-owned direct-process runtime for admitted implementations.
//!
//! The runtime accepts only a registry-minted [`ProcessLaunchPlan`]. It re-checks the plan, binds
//! the absolute executable bytes to its verified digest, clears the environment, and owns every
//! deadline, byte limit, protocol decision, kill, and reap. Provider output remains evidence only:
//! this module has no activation, promotion, permission, or budget API.

mod process;
mod wire;

use crate::implementation::ProcessLaunchPlan;
use crate::implementation_protocol::{
    ImplementationObservationEnvelope, ImplementationProtocolError, ImplementationRequest,
    ImplementationRequestEnvelope, ImplementationResponse, ImplementationState,
    MAX_IMPLEMENTATION_MESSAGE_BYTES,
};
use iteron_tunables::{CapabilitySeamNode, ContractRef};
use std::collections::VecDeque;
use std::process::Child;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Total request bytes accepted by one provider process, including newline framing.
pub const MAX_IMPLEMENTATION_STDIN_BYTES: usize = 8 * MAX_IMPLEMENTATION_MESSAGE_BYTES;
pub const MAX_IMPLEMENTATION_STATE_EVIDENCE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStateOperation {
    Snapshot,
    Restore,
    Migrate,
    Readiness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStateEvidence {
    pub operation: RuntimeStateOperation,
    pub run_id: String,
    pub generation: u64,
    pub state_schema: ContractRef,
    pub state_sha256: String,
    pub state_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeEvidence {
    pub stdout_bytes: usize,
    pub stderr: Vec<u8>,
    pub observation_bytes: usize,
    pub observations: usize,
    /// Provider state is evidence only. It does not authorize activation or promotion.
    pub state: Vec<RuntimeStateEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Spawned,
    Loaded,
    Running,
    Stopped,
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum ImplementationRuntimeError {
    #[error("invalid implementation launch plan: {0}")]
    InvalidPlan(&'static str),
    #[error("implementation executable digest is {actual}; expected {expected}")]
    ContentMismatch { expected: String, actual: String },
    #[error("implementation {operation} I/O failed: {message}")]
    Io {
        operation: &'static str,
        message: String,
    },
    #[error(transparent)]
    Protocol(#[from] ImplementationProtocolError),
    #[error("implementation lifecycle operation {operation} is invalid in state {state:?}")]
    InvalidState {
        operation: &'static str,
        state: RuntimeState,
    },
    #[error("implementation stdin would exceed {max} bytes")]
    StdinTooLarge { max: usize },
    #[error("implementation {stream} output exceeded {max} bytes")]
    OutputTooLarge { stream: &'static str, max: usize },
    #[error("implementation observation count exceeded {max}")]
    TooManyObservations { max: usize },
    #[error("implementation state evidence count exceeded {max}")]
    TooManyStateOperations { max: usize },
    #[error("implementation {operation} deadline elapsed")]
    Deadline { operation: &'static str },
    #[error("implementation process exited before {operation} completed")]
    ProcessExited { operation: &'static str },
    #[error("implementation provider failed with {code}: {message}")]
    ProviderFailed { code: String, message: String },
}

enum Input {
    Frame(Vec<u8>),
}

enum Output {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    StdoutEof,
    StderrEof,
    TooLarge(&'static str, usize),
    Io(&'static str, String),
}

/// One directly executed, host-owned implementation process.
pub struct ImplementationRuntime {
    plan: ProcessLaunchPlan,
    seam: CapabilitySeamNode,
    child: Option<Child>,
    child_pid: Option<u32>,
    input: Option<Sender<Input>>,
    output: Receiver<Output>,
    threads: Vec<JoinHandle<()>>,
    started_at: Instant,
    next_request: u64,
    stdin_bytes: usize,
    evidence: RuntimeEvidence,
    state: RuntimeState,
    active_run: Option<String>,
    last_sequence: Option<u32>,
    pending_observations: VecDeque<ImplementationObservationEnvelope>,
    stdout_eof: bool,
    stderr_eof: bool,
}

impl ImplementationRuntime {
    pub fn load(&mut self) -> Result<(), ImplementationRuntimeError> {
        self.load_with_deadline(self.plan.runtime_deadline_ms())
    }

    pub fn load_with_deadline(
        &mut self,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_state("load", RuntimeState::Spawned)?;
        let end = self.lifecycle_end("load", deadline_ms, self.plan.runtime_deadline_ms())?;
        let request = ImplementationRequest::Load {
            lifecycle_contract: self.seam.lifecycle.load.clone(),
            definition_contract: self.seam.definition_contract.clone(),
            provider_contract: self.seam.provider_contract.clone(),
            consumer_contract: self.seam.consumer_contract.clone(),
            observation_schema: self.seam.observation_schema.clone(),
            artifact_sha256: format!("sha256:{}", self.plan.artifact_sha256()),
            admitted_capabilities: self.plan.admitted_capabilities(),
        };
        self.exchange("load", request, end)?;
        self.state = RuntimeState::Loaded;
        Ok(())
    }

    pub fn start(
        &mut self,
        run_id: impl Into<String>,
        candidate_sha256: impl Into<String>,
        input: serde_json::Value,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_state("start", RuntimeState::Loaded)?;
        if deadline_ms == 0 || deadline_ms > self.plan.runtime_deadline_ms() {
            return Err(ImplementationRuntimeError::InvalidPlan(
                "invalid start deadline",
            ));
        }
        let run_id = run_id.into();
        self.active_run = Some(run_id.clone());
        self.last_sequence = None;
        let request = ImplementationRequest::Start {
            lifecycle_contract: self.seam.lifecycle.start.clone(),
            run_id,
            candidate_sha256: candidate_sha256.into(),
            input_schema: self.seam.consumer_contract.clone(),
            input,
            deadline_ms,
        };
        let end = self
            .runtime_end()
            .min(Instant::now() + Duration::from_millis(deadline_ms));
        if let Err(error) = self.exchange("start", request, end) {
            self.active_run = None;
            return Err(error);
        }
        self.state = if self.active_run.is_some() {
            RuntimeState::Running
        } else {
            RuntimeState::Loaded
        };
        Ok(())
    }

    pub fn next_observation(
        &mut self,
        deadline: Duration,
    ) -> Result<ImplementationObservationEnvelope, ImplementationRuntimeError> {
        if let Some(observation) = self.pending_observations.pop_front() {
            return Ok(observation);
        }
        self.require_state("observe", RuntimeState::Running)?;
        let end = self.runtime_end().min(Instant::now() + deadline);
        match self.next_output("observe", end)? {
            Output::Stdout(bytes) => self.parse_observation(&bytes),
            _ => unreachable!("next_output returns only stdout frames"),
        }
    }

    pub fn cancel(
        &mut self,
        run_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), ImplementationRuntimeError> {
        self.cancel_with_deadline(run_id, reason, self.plan.cancellation_deadline_ms())
    }

    pub fn cancel_with_deadline(
        &mut self,
        run_id: impl Into<String>,
        reason: impl Into<String>,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_state("cancel", RuntimeState::Running)?;
        let end =
            self.lifecycle_end("cancel", deadline_ms, self.plan.cancellation_deadline_ms())?;
        let run_id = run_id.into();
        if self.active_run.as_deref() != Some(run_id.as_str()) {
            return self.fail(ImplementationProtocolError::Correlation.into());
        }
        let request = ImplementationRequest::Cancel {
            lifecycle_contract: self.seam.lifecycle.cancel.clone(),
            run_id,
            reason: reason.into(),
        };
        self.exchange("cancel", request, end)?;
        self.active_run = None;
        self.last_sequence = None;
        self.state = RuntimeState::Loaded;
        Ok(())
    }

    pub fn stop(&mut self, reason: impl Into<String>) -> Result<(), ImplementationRuntimeError> {
        self.stop_with_deadline(reason, self.plan.cancellation_deadline_ms())
    }

    pub fn stop_with_deadline(
        &mut self,
        reason: impl Into<String>,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        if !matches!(self.state, RuntimeState::Loaded | RuntimeState::Running) {
            return Err(ImplementationRuntimeError::InvalidState {
                operation: "stop",
                state: self.state,
            });
        }
        let end = self.lifecycle_end("stop", deadline_ms, self.plan.cancellation_deadline_ms())?;
        let request = ImplementationRequest::Stop {
            lifecycle_contract: self.seam.lifecycle.stop.clone(),
            reason: reason.into(),
        };
        self.exchange("stop", request, end)?;
        self.input.take();
        if !self.wait_for_exit(end) {
            self.terminate();
            self.state = RuntimeState::Failed;
            return Err(ImplementationRuntimeError::Deadline {
                operation: "stop/reap",
            });
        }
        if let Err(error) = self.drain_after_exit(end) {
            return self.fail(error);
        }
        self.child_pid = None;
        self.finish_threads();
        self.state = RuntimeState::Stopped;
        Ok(())
    }

    /// Reach the only state in which state transfer is legal. A running operation is cancelled
    /// through the provider protocol; a loaded provider is already quiescent.
    pub fn quiesce(
        &mut self,
        reason: impl Into<String>,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        match self.state {
            RuntimeState::Loaded => Ok(()),
            RuntimeState::Running => {
                let run_id = self
                    .active_run
                    .clone()
                    .ok_or(ImplementationProtocolError::Correlation)?;
                self.cancel_with_deadline(run_id, reason, deadline_ms)
            }
            state => Err(ImplementationRuntimeError::InvalidState {
                operation: "quiesce",
                state,
            }),
        }
    }

    /// Export bounded state from a loaded (therefore quiesced) v2 provider.
    pub fn snapshot(
        &mut self,
        run_id: impl Into<String>,
        generation: u64,
        deadline_ms: u64,
    ) -> Result<ImplementationState, ImplementationRuntimeError> {
        self.require_stateful("snapshot", deadline_ms)?;
        let request = ImplementationRequest::Snapshot {
            lifecycle_contract: self.seam.lifecycle.snapshot.clone(),
            run_id: run_id.into(),
            generation,
            state_schema: self.seam.lifecycle.snapshot.clone(),
            deadline_ms,
        };
        let end = self.stateful_end(deadline_ms);
        let response = self.exchange("snapshot", request, end)?;
        let ImplementationResponse::Snapshotted { state } = response else {
            return self.fail(ImplementationProtocolError::Operation.into());
        };
        self.record_state(RuntimeStateOperation::Snapshot, &state)?;
        Ok(state)
    }

    /// Restore compatible state into a loaded shadow provider.
    pub fn restore(
        &mut self,
        state: &ImplementationState,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_stateful("restore", deadline_ms)?;
        let request = ImplementationRequest::Restore {
            lifecycle_contract: self.seam.lifecycle.restore.clone(),
            state: state.clone(),
            deadline_ms,
        };
        let end = self.stateful_end(deadline_ms);
        let response = self.exchange("restore", request, end)?;
        if !matches!(response, ImplementationResponse::Restored { .. }) {
            return self.fail(ImplementationProtocolError::Operation.into());
        }
        self.record_state(RuntimeStateOperation::Restore, state)
    }

    /// Ask a loaded v2 provider to migrate content-addressed state to a new generation.
    pub fn migrate(
        &mut self,
        source: &ImplementationState,
        target_generation: u64,
        deadline_ms: u64,
    ) -> Result<ImplementationState, ImplementationRuntimeError> {
        self.require_stateful("migrate", deadline_ms)?;
        let request = ImplementationRequest::Migrate {
            lifecycle_contract: self.seam.lifecycle.migrate.clone(),
            source: source.clone(),
            target_generation,
            deadline_ms,
        };
        let end = self.stateful_end(deadline_ms);
        let response = self.exchange("migrate", request, end)?;
        let ImplementationResponse::Migrated { state } = response else {
            return self.fail(ImplementationProtocolError::Operation.into());
        };
        self.record_state(RuntimeStateOperation::Migrate, &state)?;
        Ok(state)
    }

    /// Require explicit readiness for the exact restored state before any host switch.
    pub fn readiness(
        &mut self,
        state: &ImplementationState,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_stateful("readiness", deadline_ms)?;
        if let Err(error) = state.validate() {
            return self.fail(error.into());
        }
        if state.module != self.plan.module()
            || state.implementation_id != self.plan.implementation_id()
        {
            return self.fail(ImplementationProtocolError::Correlation.into());
        }
        let request = ImplementationRequest::Readiness {
            lifecycle_contract: self.seam.lifecycle.readiness.clone(),
            run_id: state.run_id.clone(),
            generation: state.generation,
            state_schema: state.state_schema.clone(),
            state_sha256: state.state_sha256.clone(),
            deadline_ms,
        };
        let end = self.stateful_end(deadline_ms);
        let response = self.exchange("readiness", request, end)?;
        if !matches!(response, ImplementationResponse::Ready { .. }) {
            return self.fail(ImplementationProtocolError::Operation.into());
        }
        self.record_state(RuntimeStateOperation::Readiness, state)
    }

    #[must_use]
    pub fn state(&self) -> RuntimeState {
        self.state
    }

    #[must_use]
    pub fn evidence(&self) -> &RuntimeEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn is_reaped(&self) -> bool {
        self.child.is_none()
    }

    /// Exact registry-minted identity and bounds used by this running child.
    #[must_use]
    pub fn launch_plan(&self) -> &ProcessLaunchPlan {
        &self.plan
    }

    fn require_state(
        &self,
        operation: &'static str,
        required: RuntimeState,
    ) -> Result<(), ImplementationRuntimeError> {
        if self.state == required {
            Ok(())
        } else {
            Err(ImplementationRuntimeError::InvalidState {
                operation,
                state: self.state,
            })
        }
    }

    fn require_stateful(
        &self,
        operation: &'static str,
        deadline_ms: u64,
    ) -> Result<(), ImplementationRuntimeError> {
        self.require_state(operation, RuntimeState::Loaded)?;
        if self.plan.protocol_version() != crate::IMPLEMENTATION_PROCESS_PROTOCOL_VERSION {
            return Err(ImplementationRuntimeError::InvalidPlan(
                "stateful lifecycle requires protocol v2",
            ));
        }
        if deadline_ms == 0 || deadline_ms > self.plan.runtime_deadline_ms() {
            return Err(ImplementationRuntimeError::InvalidPlan(
                "invalid stateful deadline",
            ));
        }
        if self.evidence.state.len() >= MAX_IMPLEMENTATION_STATE_EVIDENCE {
            return Err(ImplementationRuntimeError::TooManyStateOperations {
                max: MAX_IMPLEMENTATION_STATE_EVIDENCE,
            });
        }
        Ok(())
    }

    fn stateful_end(&self, deadline_ms: u64) -> Instant {
        self.runtime_end()
            .min(Instant::now() + Duration::from_millis(deadline_ms))
    }

    fn lifecycle_end(
        &self,
        operation: &'static str,
        deadline_ms: u64,
        maximum_ms: u64,
    ) -> Result<Instant, ImplementationRuntimeError> {
        if deadline_ms == 0 || deadline_ms > maximum_ms {
            return Err(ImplementationRuntimeError::InvalidPlan(match operation {
                "load" => "invalid load deadline",
                "cancel" => "invalid cancel deadline",
                "stop" => "invalid stop deadline",
                _ => "invalid lifecycle deadline",
            }));
        }
        Ok(self
            .runtime_end()
            .min(Instant::now() + Duration::from_millis(deadline_ms)))
    }

    fn record_state(
        &mut self,
        operation: RuntimeStateOperation,
        state: &ImplementationState,
    ) -> Result<(), ImplementationRuntimeError> {
        let state_bytes = serde_json::to_vec(&state.state)
            .map_err(|error| ImplementationRuntimeError::Io {
                operation: "state evidence",
                message: error.to_string(),
            })?
            .len();
        self.evidence.state.push(RuntimeStateEvidence {
            operation,
            run_id: state.run_id.clone(),
            generation: state.generation,
            state_schema: state.state_schema.clone(),
            state_sha256: state.state_sha256.clone(),
            state_bytes,
        });
        Ok(())
    }
}

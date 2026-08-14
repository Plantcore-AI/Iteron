mod helpers;

use crate::adapter_registry::{AdapterPin, BenchmarkAdapterRegistry, ResearchExecutionMode};
use crate::research_execution::native_materialization::materialize_native_patches;
use crate::research_execution::{
    ExecutionControl, ExecutionSnapshot, materialize_candidate_profile,
    refresh_terminal_bench_result, result_sidecar_path, spawn_execution,
};
use crate::research_protocol::{
    RESEARCH_PROTOCOL, ResearchProtocolError, ResearchRequest, ResearchRequestEnvelope,
    ResearchResponse, ResearchResponseEnvelope, ResearchRunState, RunSpec, validated_candidate,
};
use crate::tuner::{MaterializedActivation, materialize_activation};
use helpers::{
    CandidateRecord, RunIdentity, candidate_validation_response, join_control,
    reap_finished_control, refresh_adapter_result,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct RunRecord {
    adapter: AdapterPin,
    candidate_id: String,
    candidate_sha256: String,
    profile_sha256: String,
    implementation_activation_sha256: Option<String>,
    candidate_graph_identity: Option<crate::tuner::CandidateGraphIdentity>,
    implementation_count: u64,
    execution_mode: ResearchExecutionMode,
    run_spec: RunSpec,
    adapter_result_path: Option<String>,
    snapshot: Arc<Mutex<ExecutionSnapshot>>,
    control: Option<ExecutionControl>,
}

#[derive(Debug)]
pub struct ResearchSession {
    registry: BenchmarkAdapterRegistry,
    execution_mode: ResearchExecutionMode,
    candidates: BTreeMap<String, CandidateRecord>,
    runs: BTreeMap<String, RunRecord>,
}

impl ResearchSession {
    pub fn new() -> Self {
        Self::with_execution_mode(ResearchExecutionMode::DryRun)
    }

    pub fn with_execution_mode(execution_mode: ResearchExecutionMode) -> Self {
        Self {
            registry: BenchmarkAdapterRegistry::builtin(),
            execution_mode,
            candidates: BTreeMap::new(),
            runs: BTreeMap::new(),
        }
    }

    pub fn handle(&mut self, request: ResearchRequestEnvelope) -> ResearchResponseEnvelope {
        let request_id = request.request_id.clone();
        let operation = request.operation();
        let payload = self
            .handle_inner(&request)
            .unwrap_or_else(|error| ResearchResponse::Error {
                failed_operation: operation,
                code: crate::research_validation::error_code(&error).into(),
                message: error.to_string(),
            });
        ResearchResponseEnvelope {
            protocol: RESEARCH_PROTOCOL.into(),
            request_id,
            payload,
        }
    }

    fn handle_inner(
        &mut self,
        envelope: &ResearchRequestEnvelope,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        envelope.validate()?;
        let request = &envelope.payload;
        self.registry
            .resolve(request.adapter(), request.operation())?;
        match request {
            ResearchRequest::Surface { .. } => self.surface(),
            ResearchRequest::CandidateValidate {
                adapter,
                candidate_sha256,
                candidate,
                implementation_candidate_path,
                native_materialization_path,
            } => self.validate_candidate(
                adapter,
                candidate_sha256,
                candidate,
                implementation_candidate_path.as_deref(),
                native_materialization_path.as_deref(),
            ),
            ResearchRequest::Run {
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                run,
            } => self.plan_run(
                RunIdentity {
                    adapter,
                    candidate_id,
                    candidate_sha256,
                    profile_sha256,
                    implementation_activation_sha256: implementation_activation_sha256.as_deref(),
                    candidate_graph_identity: candidate_graph_identity.as_ref(),
                    run_id,
                },
                run,
            ),
            ResearchRequest::Cancel {
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
            } => self.cancel_run(
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256.as_deref(),
                candidate_graph_identity.as_ref(),
                run_id,
            ),
            ResearchRequest::Result {
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
            } => self.run_result(
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256.as_deref(),
                candidate_graph_identity.as_ref(),
                run_id,
            ),
            ResearchRequest::Evidence {
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
            } => self.run_evidence(
                adapter,
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256.as_deref(),
                candidate_graph_identity.as_ref(),
                run_id,
            ),
        }
    }

    fn surface(&self) -> Result<ResearchResponse, ResearchProtocolError> {
        let surface = serde_json::from_str(
            &iteron_tunables::surface_json()
                .map_err(|error| ResearchProtocolError::Json(error.to_string()))?,
        )
        .map_err(|error| ResearchProtocolError::Json(error.to_string()))?;
        Ok(ResearchResponse::Surface {
            registry_digest_sha256: self.registry.digest_sha256(),
            adapters: self.registry.entries(),
            candidate_schemas: vec![
                "iteron-candidate/1".into(),
                "iteron-candidate/2".into(),
                crate::tuner::CANDIDATE_GRAPH_SCHEMA_ID.into(),
            ],
            candidate_capabilities: vec![
                "unified_profile".into(),
                "direct_config".into(),
                "caller_input".into(),
                "implementations".into(),
                "topology".into(),
                "lineage".into(),
                "experiment".into(),
            ],
            surface,
        })
    }

    fn validate_candidate(
        &mut self,
        adapter: &AdapterPin,
        candidate_sha256: &str,
        candidate: &crate::tuner::TunerCandidate,
        implementation_candidate_path: Option<&str>,
        native_materialization_path: Option<&str>,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        let identity = validated_candidate(candidate_sha256, candidate)?;
        let entry = self.registry.resolve(
            adapter,
            crate::adapter_registry::AdapterOperation::CandidateValidate,
        )?;
        if identity.has_native_patches
            && entry.materialization_protocol.as_deref()
                != Some(crate::research_protocol::EXTERNAL_NATIVE_ADAPTER_PROTOCOL)
        {
            return Err(ResearchProtocolError::UnsupportedCandidateMaterialization);
        }
        if let Some(existing) = self.candidates.get(&identity.candidate_id) {
            if &existing.adapter != adapter
                || existing.candidate_sha256 != identity.candidate_sha256
                || existing.profile_sha256 != identity.profile_sha256
                || existing.candidate_schema_id != identity.candidate_schema_id
                || existing.candidate_graph_identity != identity.candidate_graph_identity
                || existing.activation.as_ref().map(|item| item.path.as_str())
                    != implementation_candidate_path
                || existing
                    .native_materialization
                    .as_ref()
                    .map(|item| item.path.as_str())
                    != native_materialization_path
            {
                return Err(ResearchProtocolError::CandidateIdentity);
            }
            return Ok(candidate_validation_response(
                &identity,
                existing.activation.as_ref(),
                existing.native_materialization.as_ref(),
            ));
        }
        let activation = implementation_candidate_path
            .map(|path| {
                materialize_activation(&identity.candidate_sha256, &identity.implementations, path)
                    .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))
            })
            .transpose()?;
        let native_materialization = native_materialization_path
            .map(|path| {
                identity
                    .materialization
                    .as_ref()
                    .ok_or_else(|| {
                        ResearchProtocolError::InvalidField(
                            "native candidate has no v3 materialization".into(),
                        )
                    })
                    .and_then(|materialization| {
                        materialize_native_patches(
                            &identity.candidate_sha256,
                            materialization,
                            path,
                        )
                        .map_err(ResearchProtocolError::InvalidField)
                    })
            })
            .transpose()?;
        self.candidates.insert(
            identity.candidate_id.clone(),
            CandidateRecord {
                adapter: adapter.clone(),
                candidate_sha256: identity.candidate_sha256.clone(),
                profile_sha256: identity.profile_sha256.clone(),
                candidate_schema_id: identity.candidate_schema_id.clone(),
                candidate_graph_identity: identity.candidate_graph_identity.clone(),
                native_materialization: native_materialization.clone(),
                rendered_profile: identity.rendered_profile.clone(),
                activation: activation.clone(),
            },
        );
        Ok(candidate_validation_response(
            &identity,
            activation.as_ref(),
            native_materialization.as_ref(),
        ))
    }

    fn plan_run(
        &mut self,
        identity: RunIdentity<'_>,
        run: &RunSpec,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        let RunIdentity {
            adapter,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            run_id,
        } = identity;
        if self.runs.contains_key(run_id) {
            return Err(ResearchProtocolError::DuplicateRun);
        }
        let candidate = self
            .candidates
            .get(candidate_id)
            .ok_or(ResearchProtocolError::UnknownCandidate)?;
        if &candidate.adapter != adapter
            || candidate.candidate_sha256 != candidate_sha256
            || candidate.profile_sha256 != profile_sha256
            || candidate.profile_sha256 != run.profile_sha256()
            || candidate
                .activation
                .as_ref()
                .map(|item| item.sha256.as_str())
                != implementation_activation_sha256
            || candidate.activation.as_ref().map(|item| item.path.as_str())
                != run.implementation_candidate_path()
            || candidate
                .activation
                .as_ref()
                .map(|item| item.sha256.as_str())
                != run.implementation_candidate_digest()
            || candidate.candidate_graph_identity.as_ref() != candidate_graph_identity
            || candidate
                .native_materialization
                .as_ref()
                .map(|item| item.path.as_str())
                != run.native_materialization_path()
            || candidate
                .native_materialization
                .as_ref()
                .map(|item| item.sha256.as_str())
                != run.native_materialization_digest()
            || run.graph_identity().is_some()
                && run.graph_identity() != candidate.candidate_graph_identity.as_ref()
            || run.candidate_sha256().is_some()
                && run.candidate_sha256() != Some(candidate.candidate_sha256.as_str())
            || run.run_id().is_some() && run.run_id() != Some(run_id)
        {
            return Err(ResearchProtocolError::CandidateIdentity);
        }
        if let Some(activation) = &candidate.activation {
            activation
                .verify()
                .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
        }
        if let Some(native) = &candidate.native_materialization {
            let document = native
                .verify()
                .map_err(ResearchProtocolError::InvalidField)?;
            if document.candidate_sha256 != candidate.candidate_sha256
                || Some(&document.candidate_graph_identity)
                    != candidate.candidate_graph_identity.as_ref()
            {
                return Err(ResearchProtocolError::CandidateIdentity);
            }
        }
        let (command, executable) = if self.execution_mode == ResearchExecutionMode::Execute {
            self.registry.execution_command(adapter, run)?
        } else {
            (self.registry.command(adapter, run)?, None)
        };
        let adapter_result_path = result_sidecar_path(run);
        let snapshot = Arc::new(Mutex::new(ExecutionSnapshot::new(
            match self.execution_mode {
                ResearchExecutionMode::DryRun => ResearchRunState::Planned,
                ResearchExecutionMode::Execute => ResearchRunState::Running,
            },
        )));
        let control = if self.execution_mode == ResearchExecutionMode::Execute {
            let native_outputs_ready = match run {
                RunSpec::ExternalNative { spec } => [
                    &spec.effective_profile_path,
                    &spec.consumption_receipt_path,
                    &spec.result_path,
                    &spec.stdout_path,
                ]
                .iter()
                .all(|path| matches!(std::path::Path::new(path).try_exists(), Ok(false))),
                _ => true,
            };
            match native_outputs_ready.then_some(()).ok_or(()).and_then(|()| {
                materialize_candidate_profile(
                    run.profile_path(),
                    &candidate.rendered_profile,
                    profile_sha256,
                )
            }) {
                Ok(()) => Some(spawn_execution(
                    command.clone(),
                    executable,
                    run.clone(),
                    adapter_result_path.clone(),
                    Arc::clone(&snapshot),
                )),
                Err(()) => {
                    let mut state = snapshot.lock().unwrap_or_else(|error| error.into_inner());
                    state.state = ResearchRunState::Failed;
                    state.detail =
                        Some("candidate profile or create-new adapter outputs were unsafe".into());
                    None
                }
            }
        } else {
            None
        };
        let state = snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .state;
        self.runs.insert(
            run_id.into(),
            RunRecord {
                adapter: adapter.clone(),
                candidate_id: candidate_id.into(),
                candidate_sha256: candidate.candidate_sha256.clone(),
                profile_sha256: candidate.profile_sha256.clone(),
                implementation_activation_sha256: candidate
                    .activation
                    .as_ref()
                    .map(|item| item.sha256.clone()),
                candidate_graph_identity: candidate.candidate_graph_identity.clone(),
                implementation_count: candidate
                    .activation
                    .as_ref()
                    .map_or(0, |item| item.implementation_count),
                execution_mode: self.execution_mode,
                run_spec: run.clone(),
                adapter_result_path: adapter_result_path.clone(),
                snapshot,
                control,
            },
        );
        Ok(ResearchResponse::Run {
            execution_mode: self.execution_mode.as_str().into(),
            candidate_id: candidate_id.into(),
            candidate_sha256: candidate.candidate_sha256.clone(),
            profile_sha256: candidate.profile_sha256.clone(),
            implementation_activation_sha256: candidate
                .activation
                .as_ref()
                .map(|item| item.sha256.clone()),
            candidate_graph_identity: candidate.candidate_graph_identity.clone(),
            implementation_count: candidate
                .activation
                .as_ref()
                .map_or(0, |item| item.implementation_count),
            run_id: run_id.into(),
            state,
            command,
            adapter_result_path,
        })
    }

    // Lifecycle correlation is intentionally passed field-by-field at this protocol boundary.
    #[allow(clippy::too_many_arguments)]
    fn cancel_run(
        &mut self,
        adapter: &AdapterPin,
        candidate_id: &str,
        candidate_sha256: &str,
        profile_sha256: &str,
        implementation_activation_sha256: Option<&str>,
        candidate_graph_identity: Option<&crate::tuner::CandidateGraphIdentity>,
        run_id: &str,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        let record = self.record_mut(
            adapter,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            run_id,
        )?;
        if record.execution_mode == ResearchExecutionMode::DryRun {
            record.snapshot.lock().unwrap().state = ResearchRunState::Cancelled;
        } else {
            let state = record.snapshot.lock().unwrap().state;
            if state == ResearchRunState::Running {
                if let Some(control) = &record.control {
                    control.request_cancel();
                }
                join_control(record);
            }
            let mut snapshot = record.snapshot.lock().unwrap();
            if matches!(
                snapshot.state,
                ResearchRunState::Running | ResearchRunState::AwaitingResult
            ) {
                snapshot.state = ResearchRunState::Cancelled;
                snapshot.detail = Some("run cancelled and child process reaped".into());
            }
        }
        let state = record.snapshot.lock().unwrap().state;
        Ok(ResearchResponse::Cancel {
            execution_mode: record.execution_mode.as_str().into(),
            candidate_id: record.candidate_id.clone(),
            candidate_sha256: record.candidate_sha256.clone(),
            profile_sha256: record.profile_sha256.clone(),
            implementation_activation_sha256: record.implementation_activation_sha256.clone(),
            candidate_graph_identity: record.candidate_graph_identity.clone(),
            implementation_count: record.implementation_count,
            run_id: run_id.into(),
            state,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_result(
        &mut self,
        adapter: &AdapterPin,
        candidate_id: &str,
        candidate_sha256: &str,
        profile_sha256: &str,
        implementation_activation_sha256: Option<&str>,
        candidate_graph_identity: Option<&crate::tuner::CandidateGraphIdentity>,
        run_id: &str,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        let record = self.record_mut(
            adapter,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            run_id,
        )?;
        reap_finished_control(record);
        refresh_adapter_result(record);
        let snapshot = record.snapshot.lock().unwrap().clone();
        Ok(ResearchResponse::Result {
            execution_mode: record.execution_mode.as_str().into(),
            candidate_id: record.candidate_id.clone(),
            candidate_sha256: record.candidate_sha256.clone(),
            profile_sha256: record.profile_sha256.clone(),
            implementation_activation_sha256: record.implementation_activation_sha256.clone(),
            candidate_graph_identity: record.candidate_graph_identity.clone(),
            implementation_count: record.implementation_count,
            run_id: run_id.into(),
            state: snapshot.state,
            terminal_result_available: snapshot.terminal_result.is_some(),
            terminal_result: snapshot.terminal_result,
            detail: snapshot.detail,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_evidence(
        &mut self,
        adapter: &AdapterPin,
        candidate_id: &str,
        candidate_sha256: &str,
        profile_sha256: &str,
        implementation_activation_sha256: Option<&str>,
        candidate_graph_identity: Option<&crate::tuner::CandidateGraphIdentity>,
        run_id: &str,
    ) -> Result<ResearchResponse, ResearchProtocolError> {
        let record = self.record_mut(
            adapter,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            run_id,
        )?;
        reap_finished_control(record);
        refresh_adapter_result(record);
        let snapshot = record.snapshot.lock().unwrap().clone();
        Ok(ResearchResponse::Evidence {
            execution_mode: record.execution_mode.as_str().into(),
            candidate_id: record.candidate_id.clone(),
            candidate_sha256: record.candidate_sha256.clone(),
            profile_sha256: record.profile_sha256.clone(),
            implementation_activation_sha256: record.implementation_activation_sha256.clone(),
            candidate_graph_identity: record.candidate_graph_identity.clone(),
            implementation_count: record.implementation_count,
            run_id: run_id.into(),
            state: snapshot.state,
            evidence_available: !snapshot.artifacts.is_empty(),
            artifacts: snapshot.artifacts,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record_mut(
        &mut self,
        adapter: &AdapterPin,
        candidate_id: &str,
        candidate_sha256: &str,
        profile_sha256: &str,
        implementation_activation_sha256: Option<&str>,
        candidate_graph_identity: Option<&crate::tuner::CandidateGraphIdentity>,
        run_id: &str,
    ) -> Result<&mut RunRecord, ResearchProtocolError> {
        let record = self
            .runs
            .get_mut(run_id)
            .ok_or(ResearchProtocolError::UnknownRun)?;
        if &record.adapter != adapter
            || record.candidate_id != candidate_id
            || record.candidate_sha256 != candidate_sha256
            || record.profile_sha256 != profile_sha256
            || record.implementation_activation_sha256.as_deref()
                != implementation_activation_sha256
            || record.candidate_graph_identity.as_ref() != candidate_graph_identity
        {
            return Err(ResearchProtocolError::RunIdentity);
        }
        Ok(record)
    }
}

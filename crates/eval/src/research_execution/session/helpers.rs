use super::*;

#[derive(Debug, Clone)]
pub(super) struct CandidateRecord {
    pub(super) adapter: AdapterPin,
    pub(super) candidate_sha256: String,
    pub(super) profile_sha256: String,
    pub(super) candidate_schema_id: String,
    pub(super) candidate_graph_identity: Option<crate::tuner::CandidateGraphIdentity>,
    pub(super) native_materialization:
        Option<crate::research_execution::native_materialization::MaterializedNativePatches>,
    pub(super) rendered_profile: String,
    pub(super) activation: Option<MaterializedActivation>,
}

pub(super) struct RunIdentity<'a> {
    pub(super) adapter: &'a AdapterPin,
    pub(super) candidate_id: &'a str,
    pub(super) candidate_sha256: &'a str,
    pub(super) profile_sha256: &'a str,
    pub(super) implementation_activation_sha256: Option<&'a str>,
    pub(super) candidate_graph_identity: Option<&'a crate::tuner::CandidateGraphIdentity>,
    pub(super) run_id: &'a str,
}

impl Default for ResearchSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchSession {
    /// Construct an execute session whose Iteron adapter is bound to an operator-selected,
    /// observed executable identity. The request protocol cannot replace this pin.
    pub fn with_pinned_iteron_cli(path: &std::path::Path) -> Result<Self, ResearchProtocolError> {
        Ok(Self {
            registry: BenchmarkAdapterRegistry::with_iteron_cli_executable(path)?,
            execution_mode: ResearchExecutionMode::Execute,
            candidates: BTreeMap::new(),
            runs: BTreeMap::new(),
        })
    }

    /// Construct an execute session bound to an operator-selected native-patch adapter.
    pub fn with_pinned_native_adapter(
        path: &std::path::Path,
    ) -> Result<Self, ResearchProtocolError> {
        Ok(Self {
            registry: BenchmarkAdapterRegistry::with_external_native_executable(path)?,
            execution_mode: ResearchExecutionMode::Execute,
            candidates: BTreeMap::new(),
            runs: BTreeMap::new(),
        })
    }
}

impl Drop for ResearchSession {
    fn drop(&mut self) {
        for record in self.runs.values_mut() {
            if let Some(control) = &record.control {
                control.request_cancel();
            }
        }
        for record in self.runs.values_mut() {
            join_control(record);
        }
    }
}

pub(super) fn candidate_validation_response(
    identity: &crate::research_protocol::ValidatedCandidate,
    activation: Option<&MaterializedActivation>,
    native: Option<&crate::research_execution::native_materialization::MaterializedNativePatches>,
) -> ResearchResponse {
    ResearchResponse::CandidateValidate {
        candidate_id: identity.candidate_id.clone(),
        candidate_schema_id: identity.candidate_schema_id.clone(),
        candidate_sha256: identity.candidate_sha256.clone(),
        profile_sha256: identity.profile_sha256.clone(),
        candidate_graph_identity: identity.candidate_graph_identity.clone(),
        rendered_bytes: identity.rendered_bytes,
        implementation_count: identity.implementation_count,
        implementation_activation_sha256: activation.map(|item| item.sha256.clone()),
        implementation_activation_bytes: activation.map_or(0, |item| item.bytes),
        native_patch_count: native.map_or(0, |item| item.patch_count),
        native_materialization_sha256: native.map(|item| item.sha256.clone()),
        native_materialization_bytes: native.map_or(0, |item| item.bytes),
    }
}

pub(super) fn refresh_adapter_result(record: &mut RunRecord) {
    let current = record.snapshot.lock().unwrap().clone();
    if record.execution_mode != ResearchExecutionMode::Execute
        || current.state != ResearchRunState::AwaitingResult
    {
        return;
    }
    let Some(path) = record.adapter_result_path.as_deref() else {
        return;
    };
    match refresh_terminal_bench_result(&record.run_spec, path, &current) {
        Ok(Some(refreshed)) => *record.snapshot.lock().unwrap() = refreshed,
        Ok(None) => {}
        Err(()) => {
            let mut snapshot = record.snapshot.lock().unwrap();
            snapshot.state = ResearchRunState::Failed;
            snapshot.detail =
                Some("Terminal-Bench 2.1 result or evidence failed exact validation".into());
        }
    }
}

pub(super) fn reap_finished_control(record: &mut RunRecord) {
    if record
        .control
        .as_ref()
        .is_some_and(ExecutionControl::is_finished)
    {
        join_control(record);
    }
}

pub(super) fn join_control(record: &mut RunRecord) {
    if let Some(control) = &mut record.control {
        control.join();
    }
}

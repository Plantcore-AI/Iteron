use crate::adapter_registry::{AdapterOperation, AdapterPin, BenchmarkAdapterRegistry};
use crate::research_protocol::*;
use crate::tuner::TunerCandidate;
use std::path::{Component, Path};

impl ResearchRequestEnvelope {
    pub fn validate(&self) -> Result<(), ResearchProtocolError> {
        self.validate_shape()?;
        BenchmarkAdapterRegistry::builtin().resolve(self.payload.adapter(), self.operation())?;
        Ok(())
    }

    pub(crate) fn validate_shape(&self) -> Result<(), ResearchProtocolError> {
        if self.protocol != RESEARCH_PROTOCOL {
            return Err(ResearchProtocolError::Protocol);
        }
        validate_id(&self.request_id, "request_id")?;
        match &self.payload {
            ResearchRequest::Surface { .. } => {}
            ResearchRequest::CandidateValidate {
                candidate_sha256,
                candidate,
                implementation_candidate_path,
                native_materialization_path,
                ..
            } => {
                let validated = validated_candidate(candidate_sha256, candidate)?;
                match (
                    candidate.implementation_bindings().is_empty(),
                    implementation_candidate_path,
                ) {
                    (true, None) => {}
                    (false, Some(path)) => validate_path(path)?,
                    _ => {
                        return Err(ResearchProtocolError::InvalidField(
                            "implementation_candidate_path".into(),
                        ));
                    }
                }
                match (validated.has_native_patches, native_materialization_path) {
                    (false, None) => {}
                    (true, Some(path)) => validate_path(path)?,
                    _ => {
                        return Err(ResearchProtocolError::InvalidField(
                            "native_materialization_path".into(),
                        ));
                    }
                }
            }
            ResearchRequest::Run {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                run,
                ..
            } => {
                validate_candidate_id(candidate_id)?;
                validate_candidate_digest(candidate_sha256)?;
                validate_digest(profile_sha256, "profile_sha256")?;
                validate_id(run_id, "run_id")?;
                run.validate()?;
                validate_optional_activation_digest(implementation_activation_sha256)?;
                validate_optional_graph_identity(candidate_graph_identity.as_ref())?;
                if implementation_activation_sha256.as_deref()
                    != run.implementation_candidate_digest()
                {
                    return Err(ResearchProtocolError::InvalidField(
                        "implementation activation correlation".into(),
                    ));
                }
                if let Some(identity) = run.graph_identity()
                    && (candidate_graph_identity.as_ref() != Some(identity)
                        || run.candidate_sha256() != Some(candidate_sha256.as_str())
                        || run.run_id() != Some(run_id.as_str()))
                {
                    return Err(ResearchProtocolError::InvalidField(
                        "native materialization correlation".into(),
                    ));
                }
            }
            ResearchRequest::Cancel { run_id, .. }
            | ResearchRequest::Result { run_id, .. }
            | ResearchRequest::Evidence { run_id, .. } => validate_id(run_id, "run_id")?,
        }
        if let ResearchRequest::Cancel {
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            ..
        }
        | ResearchRequest::Result {
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            ..
        }
        | ResearchRequest::Evidence {
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            candidate_graph_identity,
            ..
        } = &self.payload
        {
            validate_candidate_id(candidate_id)?;
            validate_candidate_digest(candidate_sha256)?;
            validate_digest(profile_sha256, "profile_sha256")?;
            validate_optional_activation_digest(implementation_activation_sha256)?;
            validate_optional_graph_identity(candidate_graph_identity.as_ref())?;
        }
        Ok(())
    }

    pub fn operation(&self) -> AdapterOperation {
        self.payload.operation()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedCandidate {
    pub candidate_id: String,
    pub candidate_sha256: String,
    pub profile_sha256: String,
    pub rendered_bytes: u64,
    pub implementation_count: u64,
    pub candidate_schema_id: String,
    pub candidate_graph_identity: Option<crate::tuner::CandidateGraphIdentity>,
    pub has_native_patches: bool,
    pub materialization: Option<crate::tuner::CandidateMaterialization>,
    pub rendered_profile: String,
    pub implementations: Vec<crate::tuner::CandidateImplementation>,
}

pub(crate) fn validated_candidate(
    expected_digest: &str,
    candidate: &TunerCandidate,
) -> Result<ValidatedCandidate, ResearchProtocolError> {
    validate_candidate_digest(expected_digest)?;
    validate_candidate_id(&candidate.id)?;
    candidate
        .validate_universal()
        .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
    let actual = candidate
        .digest_sha256()
        .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
    if actual != expected_digest {
        return Err(ResearchProtocolError::InvalidField(
            "candidate digest mismatch".into(),
        ));
    }
    let (rendered, profile_sha256) = candidate
        .rendered_profile()
        .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
    if rendered.len() > iteron_tunables::MAX_PROFILE_BYTES {
        return Err(ResearchProtocolError::InvalidField(
            "profile exceeds its byte bound".into(),
        ));
    }
    let materialization = (candidate.schema_version
        == crate::tuner::CANDIDATE_GRAPH_SCHEMA_VERSION)
        .then(|| candidate.materialize())
        .transpose()
        .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
    let candidate_graph_identity = materialization
        .as_ref()
        .map(|item| item.graph_identity())
        .transpose()
        .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
    Ok(ValidatedCandidate {
        candidate_id: candidate.id.clone(),
        candidate_sha256: actual,
        profile_sha256,
        rendered_bytes: rendered.len() as u64,
        implementation_count: candidate.implementation_bindings().len() as u64,
        candidate_schema_id: candidate.candidate_schema_id().into(),
        candidate_graph_identity,
        has_native_patches: materialization
            .as_ref()
            .is_some_and(crate::tuner::CandidateMaterialization::has_native_patches),
        materialization,
        rendered_profile: rendered,
        implementations: candidate.implementation_bindings().to_vec(),
    })
}

impl ResearchRequest {
    pub fn operation(&self) -> AdapterOperation {
        match self {
            Self::Surface { .. } => AdapterOperation::Surface,
            Self::CandidateValidate { .. } => AdapterOperation::CandidateValidate,
            Self::Run { .. } => AdapterOperation::Run,
            Self::Cancel { .. } => AdapterOperation::Cancel,
            Self::Result { .. } => AdapterOperation::Result,
            Self::Evidence { .. } => AdapterOperation::Evidence,
        }
    }

    pub(crate) fn adapter(&self) -> &AdapterPin {
        match self {
            Self::Surface { adapter }
            | Self::CandidateValidate { adapter, .. }
            | Self::Run { adapter, .. }
            | Self::Cancel { adapter, .. }
            | Self::Result { adapter, .. }
            | Self::Evidence { adapter, .. } => adapter,
        }
    }
}

impl RunSpec {
    pub fn validate(&self) -> Result<(), ResearchProtocolError> {
        match self {
            Self::IteronCli { spec } => spec.validate(),
            Self::TerminalBench21 {
                request,
                implementation_candidate,
            } => {
                request
                    .validate()
                    .map_err(|error| ResearchProtocolError::InvalidField(error.to_string()))?;
                if let Some(reference) = implementation_candidate {
                    validate_path(&reference.path)?;
                    validate_digest(&reference.digest, "implementation_candidate_digest")?;
                }
                Ok(())
            }
            Self::ExternalNative { spec } => spec.validate(),
        }
    }

    pub fn profile_sha256(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.profile_sha256,
            Self::TerminalBench21 { request, .. } => &request.profile.profile_sha256,
            Self::ExternalNative { spec } => &spec.profile_sha256,
        }
    }

    pub(crate) fn max_wall_secs(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_wall_secs,
            Self::TerminalBench21 { request, .. } => request.resources.max_wall_secs,
            Self::ExternalNative { spec } => spec.max_wall_secs,
        }
    }

    pub(crate) fn max_evidence_bytes(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_evidence_bytes,
            Self::TerminalBench21 { request, .. } => request.resources.max_evidence_bytes,
            Self::ExternalNative { spec } => spec.max_evidence_bytes,
        }
    }

    pub(crate) fn max_memory_bytes(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_memory_bytes,
            Self::TerminalBench21 { request, .. } => request.resources.max_memory_bytes,
            Self::ExternalNative { spec } => spec.max_memory_bytes,
        }
    }

    pub(crate) fn profile_path(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.profile_path,
            Self::TerminalBench21 { request, .. } => &request.profile_path,
            Self::ExternalNative { spec } => &spec.profile_path,
        }
    }

    pub(crate) fn effective_profile_path(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.effective_profile_path,
            Self::TerminalBench21 { request, .. } => &request.effective_profile_path,
            Self::ExternalNative { spec } => &spec.effective_profile_path,
        }
    }

    pub(crate) fn runs_dir(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.runs_dir,
            Self::TerminalBench21 { request, .. } => &request.runs_dir,
            Self::ExternalNative { spec } => &spec.runs_dir,
        }
    }

    pub(crate) fn implementation_candidate_path(&self) -> Option<&str> {
        match self {
            Self::IteronCli { spec } => spec.implementation_candidate_path.as_deref(),
            Self::TerminalBench21 {
                implementation_candidate,
                ..
            } => implementation_candidate
                .as_ref()
                .map(|reference| reference.path.as_str()),
            Self::ExternalNative { .. } => None,
        }
    }

    pub(crate) fn implementation_candidate_digest(&self) -> Option<&str> {
        match self {
            Self::IteronCli { spec } => spec.implementation_candidate_digest.as_deref(),
            Self::TerminalBench21 {
                implementation_candidate,
                ..
            } => implementation_candidate
                .as_ref()
                .map(|reference| reference.digest.as_str()),
            Self::ExternalNative { .. } => None,
        }
    }

    pub(crate) fn native_materialization_path(&self) -> Option<&str> {
        match self {
            Self::ExternalNative { spec } => Some(&spec.native_materialization_path),
            _ => None,
        }
    }

    pub(crate) fn native_materialization_digest(&self) -> Option<&str> {
        match self {
            Self::ExternalNative { spec } => Some(&spec.native_materialization_sha256),
            _ => None,
        }
    }

    pub(crate) fn graph_identity(&self) -> Option<&crate::tuner::CandidateGraphIdentity> {
        match self {
            Self::ExternalNative { spec } => Some(&spec.candidate_graph_identity),
            _ => None,
        }
    }

    pub(crate) fn candidate_sha256(&self) -> Option<&str> {
        match self {
            Self::ExternalNative { spec } => Some(&spec.candidate_sha256),
            _ => None,
        }
    }

    pub(crate) fn run_id(&self) -> Option<&str> {
        match self {
            Self::ExternalNative { spec } => Some(&spec.run_id),
            _ => None,
        }
    }
}

impl ExternalNativeRunSpec {
    pub fn validate(&self) -> Result<(), ResearchProtocolError> {
        for path in [
            &self.binary_path,
            &self.workspace_path,
            &self.profile_path,
            &self.effective_profile_path,
            &self.native_materialization_path,
            &self.consumption_receipt_path,
            &self.result_path,
            &self.stdout_path,
            &self.runs_dir,
        ] {
            validate_path(path)?;
        }
        validate_digest(&self.profile_sha256, "profile_sha256")?;
        validate_digest(
            &self.native_materialization_sha256,
            "native_materialization_sha256",
        )?;
        validate_candidate_digest(&self.candidate_sha256)?;
        validate_optional_graph_identity(Some(&self.candidate_graph_identity))?;
        validate_id(&self.run_id, "run_id")?;
        // Fixed protocol flags consume 26 argv entries; keep the whole command under 128.
        if self.task_arguments.len() > 96
            || self.task_arguments.iter().any(|argument| {
                argument.len() > MAX_PROMPT_BYTES || argument.contains('\0') || argument == "--"
            })
            || !(1..=MAX_WALL_SECS).contains(&self.max_wall_secs)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stdout_bytes)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stderr_bytes)
            || !(1..=MAX_EVIDENCE_BYTES).contains(&self.max_evidence_bytes)
            || !(1..=MAX_MEMORY_BYTES).contains(&self.max_memory_bytes)
        {
            return Err(ResearchProtocolError::InvalidField(
                "external native run bounds".into(),
            ));
        }
        let outputs = [
            self.effective_profile_path.as_str(),
            self.consumption_receipt_path.as_str(),
            self.result_path.as_str(),
            self.stdout_path.as_str(),
        ];
        let mut sorted = outputs;
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1])
            || outputs
                .iter()
                .any(|path| *path == self.profile_path || *path == self.native_materialization_path)
        {
            return Err(ResearchProtocolError::InvalidField(
                "external native output paths".into(),
            ));
        }
        validate_credentials(&self.credential_env_names)
    }
}

impl CliRunSpec {
    pub fn validate(&self) -> Result<(), ResearchProtocolError> {
        for path in [
            &self.binary_path,
            &self.workspace_path,
            &self.profile_path,
            &self.effective_profile_path,
            &self.result_path,
            &self.runs_dir,
        ] {
            validate_path(path)?;
        }
        validate_digest(&self.profile_sha256, "profile_sha256")?;
        validate_digest(&self.registry_sha256, "registry_sha256")?;
        validate_digest(&self.param_registry_sha256, "param_registry_sha256")?;
        validate_revision(&self.iteron_revision)?;
        validate_activation_pair(
            self.implementation_candidate_path.as_deref(),
            self.implementation_candidate_digest.as_deref(),
        )?;
        if self.registry_sha256 != iteron_tunables::REGISTRY_DIGEST_SHA256
            || self.param_registry_sha256 != iteron_tunables::param_registry_digest_sha256()
        {
            return Err(ResearchProtocolError::InvalidField(
                "registry digest does not identify this Iteron build".into(),
            ));
        }
        if self.task_prompt.is_empty()
            || self.task_prompt.len() > MAX_PROMPT_BYTES
            || self.task_prompt.contains('\0')
            || !(1..=MAX_WALL_SECS).contains(&self.max_wall_secs)
            || !(1..=MAX_TURNS).contains(&self.max_turns)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stdout_bytes)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_stderr_bytes)
            || !(1..=MAX_EVIDENCE_BYTES).contains(&self.max_evidence_bytes)
            || !(1..=MAX_MEMORY_BYTES).contains(&self.max_memory_bytes)
            || self.profile_path == self.effective_profile_path
            || self.result_path == self.profile_path
            || self.result_path == self.effective_profile_path
        {
            return Err(ResearchProtocolError::InvalidField("run bounds".into()));
        }
        validate_credentials(&self.credential_env_names)
    }
}

impl ResearchResponseEnvelope {
    pub fn validate_against(
        &self,
        request: &ResearchRequestEnvelope,
    ) -> Result<(), ResearchProtocolError> {
        crate::research_validation::validate_envelope(self, request)
    }
}

impl ResearchResponse {
    pub(crate) fn operation(&self) -> AdapterOperation {
        match self {
            Self::Surface { .. } => AdapterOperation::Surface,
            Self::CandidateValidate { .. } => AdapterOperation::CandidateValidate,
            Self::Run { .. } => AdapterOperation::Run,
            Self::Cancel { .. } => AdapterOperation::Cancel,
            Self::Result { .. } => AdapterOperation::Result,
            Self::Evidence { .. } => AdapterOperation::Evidence,
            Self::Error {
                failed_operation, ..
            } => *failed_operation,
        }
    }
}

fn validate_id(value: &str, name: &str) -> Result<(), ResearchProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
        })
    {
        return Err(ResearchProtocolError::InvalidField(name.into()));
    }
    Ok(())
}

fn validate_candidate_id(value: &str) -> Result<(), ResearchProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
    {
        return Err(ResearchProtocolError::InvalidField("candidate_id".into()));
    }
    Ok(())
}

fn validate_digest(value: &str, name: &str) -> Result<(), ResearchProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ResearchProtocolError::InvalidField(name.into()));
    }
    Ok(())
}

fn validate_candidate_digest(value: &str) -> Result<(), ResearchProtocolError> {
    value.strip_prefix("sha256:").map_or_else(
        || {
            Err(ResearchProtocolError::InvalidField(
                "candidate_sha256".into(),
            ))
        },
        |digest| validate_digest(digest, "candidate_sha256"),
    )
}

fn validate_optional_activation_digest(
    value: &Option<String>,
) -> Result<(), ResearchProtocolError> {
    if let Some(value) = value {
        validate_digest(value, "implementation_activation_sha256")?;
    }
    Ok(())
}

fn validate_optional_graph_identity(
    identity: Option<&crate::tuner::CandidateGraphIdentity>,
) -> Result<(), ResearchProtocolError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    if identity.schema_id != crate::tuner::CANDIDATE_GRAPH_SCHEMA_ID {
        return Err(ResearchProtocolError::InvalidField(
            "candidate_graph_identity.schema_id".into(),
        ));
    }
    validate_candidate_digest(&identity.materialization_sha256)?;
    validate_candidate_digest(&identity.experiment_sha256)?;
    validate_candidate_digest(&identity.topology_sha256)
}

fn validate_activation_pair(
    path: Option<&str>,
    digest: Option<&str>,
) -> Result<(), ResearchProtocolError> {
    match (path, digest) {
        (None, None) => Ok(()),
        (Some(path), Some(digest)) => {
            validate_path(path)?;
            validate_digest(digest, "implementation_candidate_digest")
        }
        _ => Err(ResearchProtocolError::InvalidField(
            "implementation activation pair".into(),
        )),
    }
}

fn validate_revision(value: &str) -> Result<(), ResearchProtocolError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ResearchProtocolError::InvalidField(
            "iteron_revision".into(),
        ));
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), ResearchProtocolError> {
    let path = Path::new(value);
    if value.len() > MAX_PATH_BYTES
        || value.contains('\0')
        || !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(ResearchProtocolError::InvalidField("path".into()));
    }
    Ok(())
}

fn validate_credentials(names: &[String]) -> Result<(), ResearchProtocolError> {
    if names.len() > CREDENTIAL_NAMES.len()
        || !names.windows(2).all(|pair| pair[0] < pair[1])
        || names
            .iter()
            .any(|name| CREDENTIAL_NAMES.binary_search(&name.as_str()).is_err())
    {
        return Err(ResearchProtocolError::InvalidField(
            "credential_env_names".into(),
        ));
    }
    Ok(())
}

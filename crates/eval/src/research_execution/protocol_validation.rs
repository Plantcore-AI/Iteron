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
                ..
            } => {
                validated_candidate(candidate_sha256, candidate)?;
                match (
                    candidate.implementations.is_empty(),
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
            }
            ResearchRequest::Run {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
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
                if implementation_activation_sha256.as_deref()
                    != run.implementation_candidate_digest()
                {
                    return Err(ResearchProtocolError::InvalidField(
                        "implementation activation correlation".into(),
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
            ..
        }
        | ResearchRequest::Result {
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            ..
        }
        | ResearchRequest::Evidence {
            candidate_id,
            candidate_sha256,
            profile_sha256,
            implementation_activation_sha256,
            ..
        } = &self.payload
        {
            validate_candidate_id(candidate_id)?;
            validate_candidate_digest(candidate_sha256)?;
            validate_digest(profile_sha256, "profile_sha256")?;
            validate_optional_activation_digest(implementation_activation_sha256)?;
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
    Ok(ValidatedCandidate {
        candidate_id: candidate.id.clone(),
        candidate_sha256: actual,
        profile_sha256,
        rendered_bytes: rendered.len() as u64,
        implementation_count: candidate.implementations.len() as u64,
        rendered_profile: rendered,
        implementations: candidate.implementations.clone(),
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
        }
    }

    pub fn profile_sha256(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.profile_sha256,
            Self::TerminalBench21 { request, .. } => &request.profile.profile_sha256,
        }
    }

    pub(crate) fn max_wall_secs(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_wall_secs,
            Self::TerminalBench21 { request, .. } => request.resources.max_wall_secs,
        }
    }

    pub(crate) fn max_evidence_bytes(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_evidence_bytes,
            Self::TerminalBench21 { request, .. } => request.resources.max_evidence_bytes,
        }
    }

    pub(crate) fn max_memory_bytes(&self) -> u64 {
        match self {
            Self::IteronCli { spec } => spec.max_memory_bytes,
            Self::TerminalBench21 { request, .. } => request.resources.max_memory_bytes,
        }
    }

    pub(crate) fn profile_path(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.profile_path,
            Self::TerminalBench21 { request, .. } => &request.profile_path,
        }
    }

    pub(crate) fn effective_profile_path(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.effective_profile_path,
            Self::TerminalBench21 { request, .. } => &request.effective_profile_path,
        }
    }

    pub(crate) fn runs_dir(&self) -> &str {
        match self {
            Self::IteronCli { spec } => &spec.runs_dir,
            Self::TerminalBench21 { request, .. } => &request.runs_dir,
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
        }
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

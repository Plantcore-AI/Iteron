mod helpers;

use crate::{
    AdapterCommand, BenchmarkAdapterRegistry, RESEARCH_PROTOCOL, ResearchProtocolError,
    ResearchRequest, ResearchRequestEnvelope, ResearchResponse, ResearchResponseEnvelope,
    ResearchRunState,
};
use helpers::*;
use std::collections::BTreeMap;
use std::path::{Component, Path};

const MAX_PATH: usize = 4096;
const MAX_ARGUMENT: usize = 256 * 1024;
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;
const CREDENTIALS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "FIREWORKS_API_KEY",
    "GLM_API_KEY",
    "MINIMAX_API_KEY",
    "OPENAI_API_KEY",
];

pub(crate) fn validate_response(response: &ResearchResponse) -> Result<(), ResearchProtocolError> {
    match response {
        ResearchResponse::Surface {
            registry_digest_sha256,
            adapters,
            candidate_schemas,
            candidate_capabilities,
            ..
        } => {
            digest(registry_digest_sha256, "registry_digest_sha256")?;
            if adapters.len() > 64 {
                return invalid("adapters");
            }
            for adapter in adapters {
                text(&adapter.benchmark_id, 128, "benchmark_id")?;
                text(&adapter.benchmark_version, 64, "benchmark_version")?;
                text(&adapter.request_schema_id, 256, "request_schema_id")?;
                text(&adapter.result_schema_id, 256, "result_schema_id")?;
                if adapter
                    .implementation_protocol
                    .as_deref()
                    .is_some_and(|protocol| protocol != crate::tuner::IMPLEMENTATION_PROTOCOL)
                {
                    return invalid("implementation_protocol");
                }
                if adapter
                    .materialization_protocol
                    .as_deref()
                    .is_some_and(|protocol| {
                        protocol != crate::research_protocol::EXTERNAL_NATIVE_ADAPTER_PROTOCOL
                    })
                {
                    return invalid("materialization_protocol");
                }
                digest(&adapter.adapter_digest_sha256, "adapter_digest_sha256")?;
                if adapter.supported_operations.len() > 6 {
                    return invalid("supported_operations");
                }
            }
            let registry = BenchmarkAdapterRegistry::builtin();
            if registry_digest_sha256 != &registry.digest_sha256()
                || adapters != &registry.entries()
                || candidate_schemas
                    != &[
                        "iteron-candidate/1",
                        "iteron-candidate/2",
                        "iteron-candidate/3",
                    ]
                || candidate_capabilities
                    != &[
                        "unified_profile",
                        "direct_config",
                        "caller_input",
                        "implementations",
                        "topology",
                        "lineage",
                        "experiment",
                    ]
            {
                return invalid("adapter registry identity");
            }
        }
        ResearchResponse::CandidateValidate {
            candidate_id,
            candidate_schema_id,
            candidate_sha256,
            profile_sha256,
            candidate_graph_identity,
            rendered_bytes,
            implementation_count,
            implementation_activation_sha256,
            implementation_activation_bytes,
            native_patch_count,
            native_materialization_sha256,
            native_materialization_bytes,
        } => {
            validate_candidate_id(candidate_id)?;
            text(candidate_schema_id, 64, "candidate_schema_id")?;
            candidate_digest(candidate_sha256)?;
            digest(profile_sha256, "profile_sha256")?;
            graph_identity(candidate_graph_identity.as_ref())?;
            if !matches!(
                candidate_schema_id.as_str(),
                "iteron-candidate/2" | "iteron-candidate/3"
            ) || (candidate_schema_id == "iteron-candidate/3")
                != candidate_graph_identity.is_some()
                || *rendered_bytes == 0
                || *rendered_bytes > iteron_tunables::MAX_PROFILE_BYTES as u64
                || *implementation_count > iteron_tunables::ModuleId::ALL.len() as u64
                || (*implementation_count == 0
                    && (implementation_activation_sha256.is_some()
                        || *implementation_activation_bytes != 0))
                || (*implementation_count > 0
                    && (implementation_activation_sha256.is_none()
                        || *implementation_activation_bytes == 0
                        || *implementation_activation_bytes
                            > iteron_marketplace::MAX_IMPLEMENTATION_ACTIVATION_BYTES as u64))
                || (*native_patch_count == 0
                    && (native_materialization_sha256.is_some()
                        || *native_materialization_bytes != 0))
                || (*native_patch_count > 0
                    && (native_materialization_sha256.is_none()
                        || *native_materialization_bytes == 0
                        || *native_materialization_bytes
                            > crate::research_protocol::MAX_NATIVE_MATERIALIZATION_BYTES as u64))
            {
                return invalid("candidate validation response");
            }
            if let Some(digest_value) = implementation_activation_sha256 {
                digest(digest_value, "implementation_activation_sha256")?;
            }
            if let Some(digest_value) = native_materialization_sha256 {
                digest(digest_value, "native_materialization_sha256")?;
            }
        }
        ResearchResponse::Run {
            execution_mode,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            run_id,
            state,
            command,
            adapter_result_path,
            implementation_activation_sha256,
            candidate_graph_identity,
            implementation_count,
        } => {
            let execute = mode(execution_mode, run_id)?;
            candidate(candidate_id, candidate_sha256, profile_sha256)?;
            if (!execute && *state != ResearchRunState::Planned)
                || (execute && *state == ResearchRunState::Planned)
            {
                return invalid("run state");
            }
            command_valid(command)?;
            activation(implementation_activation_sha256, *implementation_count)?;
            graph_identity(candidate_graph_identity.as_ref())?;
            if let Some(result_path) = adapter_result_path {
                path(result_path)?;
            }
        }
        ResearchResponse::Cancel {
            execution_mode,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            run_id,
            state,
            implementation_activation_sha256,
            candidate_graph_identity,
            implementation_count,
        } => {
            let execute = mode(execution_mode, run_id)?;
            candidate(candidate_id, candidate_sha256, profile_sha256)?;
            activation(implementation_activation_sha256, *implementation_count)?;
            graph_identity(candidate_graph_identity.as_ref())?;
            if (!execute && *state != ResearchRunState::Cancelled)
                || (execute
                    && matches!(
                        state,
                        ResearchRunState::Planned
                            | ResearchRunState::Running
                            | ResearchRunState::AwaitingResult
                    ))
            {
                return invalid("cancel state");
            }
        }
        ResearchResponse::Result {
            execution_mode,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            run_id,
            state,
            terminal_result_available,
            terminal_result,
            detail,
            implementation_activation_sha256,
            candidate_graph_identity,
            implementation_count,
        } => {
            let execute = mode(execution_mode, run_id)?;
            candidate(candidate_id, candidate_sha256, profile_sha256)?;
            activation(implementation_activation_sha256, *implementation_count)?;
            graph_identity(candidate_graph_identity.as_ref())?;
            if *terminal_result_available != terminal_result.is_some()
                || (!execute
                    && (*terminal_result_available
                        || !matches!(
                            state,
                            ResearchRunState::Planned | ResearchRunState::Cancelled
                        )))
                || terminal_result.is_some() && *state != ResearchRunState::Completed
            {
                return invalid("dry-run terminal result");
            }
            if let Some(result) = terminal_result {
                text(&result.schema_id, 256, "result schema")?;
                text(&result.run_id, 4096, "terminal run id")?;
                text(&result.outcome, 64, "terminal outcome")?;
                if result.score_micros.is_some_and(|score| score > 1_000_000) {
                    return invalid("terminal score");
                }
            }
            if let Some(detail) = detail {
                text(detail, 4096, "result detail")?;
            }
        }
        ResearchResponse::Evidence {
            execution_mode,
            candidate_id,
            candidate_sha256,
            profile_sha256,
            run_id,
            evidence_available,
            artifacts,
            implementation_activation_sha256,
            candidate_graph_identity,
            implementation_count,
            ..
        } => {
            let execute = mode(execution_mode, run_id)?;
            candidate(candidate_id, candidate_sha256, profile_sha256)?;
            activation(implementation_activation_sha256, *implementation_count)?;
            graph_identity(candidate_graph_identity.as_ref())?;
            if *evidence_available == artifacts.is_empty()
                || (!execute && (*evidence_available || !artifacts.is_empty()))
                || artifacts.len() > 1024
            {
                return invalid("dry-run evidence");
            }
            for artifact in artifacts {
                path(&artifact.path)?;
                digest(&artifact.sha256, "artifact sha256")?;
                if artifact.bytes == 0 || artifact.bytes > 1024 * 1024 * 1024 {
                    return invalid("artifact bytes");
                }
            }
        }
        ResearchResponse::Error { code, message, .. } => {
            text(code, 64, "error code")?;
            text(message, 4096, "error message")?;
        }
    }
    Ok(())
}

pub(crate) fn validate_envelope(
    response: &ResearchResponseEnvelope,
    request: &ResearchRequestEnvelope,
) -> Result<(), ResearchProtocolError> {
    if response.protocol != RESEARCH_PROTOCOL
        || response.request_id != request.request_id
        || response.payload.operation() != request.operation()
    {
        return Err(ResearchProtocolError::Correlation);
    }
    id(&response.request_id, "request_id")?;
    validate_response(&response.payload)?;
    match (&request.payload, &response.payload) {
        (
            ResearchRequest::CandidateValidate {
                candidate_sha256,
                candidate,
                ..
            },
            ResearchResponse::CandidateValidate {
                candidate_id: response_id,
                candidate_schema_id: response_schema_id,
                candidate_sha256: response_candidate_digest,
                profile_sha256: response_profile_digest,
                candidate_graph_identity: response_graph_identity,
                rendered_bytes,
                implementation_count,
                implementation_activation_sha256,
                implementation_activation_bytes,
                native_patch_count,
                native_materialization_sha256,
                native_materialization_bytes,
            },
        ) if candidate.id.as_str() != response_id.as_str()
            || candidate.candidate_schema_id() != response_schema_id
            || candidate_sha256 != response_candidate_digest
            || candidate
                .graph_identity()
                .ok()
                .as_ref()
                .and_then(|item| item.as_ref())
                != response_graph_identity.as_ref()
            || *implementation_count != candidate.implementation_bindings().len() as u64
            || (candidate.implementation_bindings().is_empty()
                != implementation_activation_sha256.is_none())
            || (candidate.implementation_bindings().is_empty()
                != (*implementation_activation_bytes == 0))
            || candidate
                .materialize()
                .ok()
                .map(|item| {
                    item.direct_config_patches
                        .len()
                        .saturating_add(item.caller_input_patches.len()) as u64
                })
                .unwrap_or(0)
                != *native_patch_count
            || (*native_patch_count == 0) != native_materialization_sha256.is_none()
            || (*native_patch_count == 0) != (*native_materialization_bytes == 0)
            || candidate
                .rendered_profile()
                .map(|(rendered, digest)| {
                    digest.as_str() != response_profile_digest.as_str()
                        || rendered.len() as u64 != *rendered_bytes
                })
                .unwrap_or(true) =>
        {
            Err(ResearchProtocolError::Correlation)
        }
        (
            ResearchRequest::Run {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                run,
                ..
            },
            ResearchResponse::Run {
                candidate_id: response_candidate,
                candidate_sha256: response_candidate_digest,
                profile_sha256: response_profile_digest,
                implementation_activation_sha256: response_activation_digest,
                candidate_graph_identity: response_graph_identity,
                run_id: response_id,
                ..
            },
        ) if candidate_id != response_candidate
            || candidate_sha256 != response_candidate_digest
            || profile_sha256 != response_profile_digest
            || run.profile_sha256() != response_profile_digest
            || implementation_activation_sha256 != response_activation_digest
            || candidate_graph_identity != response_graph_identity
            || run.implementation_candidate_digest() != response_activation_digest.as_deref()
            || run_id != response_id =>
        {
            Err(ResearchProtocolError::Correlation)
        }
        (
            ResearchRequest::Cancel {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                ..
            }
            | ResearchRequest::Result {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                ..
            }
            | ResearchRequest::Evidence {
                candidate_id,
                candidate_sha256,
                profile_sha256,
                implementation_activation_sha256,
                candidate_graph_identity,
                run_id,
                ..
            },
            ResearchResponse::Cancel {
                candidate_id: response_candidate,
                candidate_sha256: response_candidate_digest,
                profile_sha256: response_profile_digest,
                implementation_activation_sha256: response_activation_digest,
                candidate_graph_identity: response_graph_identity,
                run_id: response_id,
                ..
            }
            | ResearchResponse::Result {
                candidate_id: response_candidate,
                candidate_sha256: response_candidate_digest,
                profile_sha256: response_profile_digest,
                implementation_activation_sha256: response_activation_digest,
                candidate_graph_identity: response_graph_identity,
                run_id: response_id,
                ..
            }
            | ResearchResponse::Evidence {
                candidate_id: response_candidate,
                candidate_sha256: response_candidate_digest,
                profile_sha256: response_profile_digest,
                implementation_activation_sha256: response_activation_digest,
                candidate_graph_identity: response_graph_identity,
                run_id: response_id,
                ..
            },
        ) if candidate_id != response_candidate
            || candidate_sha256 != response_candidate_digest
            || profile_sha256 != response_profile_digest
            || implementation_activation_sha256 != response_activation_digest
            || candidate_graph_identity != response_graph_identity
            || run_id != response_id =>
        {
            Err(ResearchProtocolError::Correlation)
        }
        _ => Ok(()),
    }
}

pub(crate) fn error_code(error: &ResearchProtocolError) -> &'static str {
    match error {
        ResearchProtocolError::TooLarge => "too_large",
        ResearchProtocolError::Json(_) => "invalid_json",
        ResearchProtocolError::Protocol => "unsupported_protocol",
        ResearchProtocolError::InvalidField(_) => "invalid_field",
        ResearchProtocolError::UnknownAdapter => "unknown_adapter",
        ResearchProtocolError::UnsupportedOperation => "unsupported_operation",
        ResearchProtocolError::RunSpecAdapterMismatch => "run_spec_adapter_mismatch",
        ResearchProtocolError::UnsupportedImplementationActivation => {
            "unsupported_implementation_activation"
        }
        ResearchProtocolError::Correlation => "correlation_mismatch",
        ResearchProtocolError::DuplicateRun => "duplicate_run",
        ResearchProtocolError::UnknownCandidate => "unknown_candidate",
        ResearchProtocolError::CandidateIdentity => "candidate_identity_mismatch",
        ResearchProtocolError::UnknownRun => "unknown_run",
        ResearchProtocolError::RunIdentity => "run_identity_mismatch",
        ResearchProtocolError::UnpinnedExecutable => "unpinned_executable",
        ResearchProtocolError::ExecutableIdentity => "executable_identity_mismatch",
        ResearchProtocolError::UnsupportedCandidateMaterialization => {
            "unsupported_candidate_materialization"
        }
    }
}

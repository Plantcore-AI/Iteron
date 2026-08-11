use super::{ProviderProcessFactError, ProviderProcessFactsInput, VerificationOwnerFacts};
use iteron_provider::{AccountAvailability, BalanceAvailability};
use iteron_tools::Registry;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub(super) struct OwnerSnapshot {
    route_attestation_digest_sha256: String,
    health: HealthEvidence,
    model: ModelEvidence,
    compaction: CompactionEvidence,
    registered_tools: BTreeSet<String>,
    role_model_routes: BTreeMap<String, String>,
    pub process_surface: bool,
    pub lsp_surface: bool,
    process_policy: Option<iteron_tools::ProcessRuntimePolicy>,
    process_launch_policy: Option<iteron_tools::ProcessLaunchPolicy>,
    lsp_policy: Option<iteron_tools::LspRuntimePolicy>,
    tool_result_cache_ttl_seconds: u64,
    pub checkpoint_supported: bool,
    verification: VerificationEvidence,
    verification_policy: iteron_verify::VerificationRuntimePolicy,
    binary_media_policy: crate::image_input::BinaryMediaInspectionPolicy,
}

#[derive(Debug, Serialize)]
struct HealthEvidence {
    availability: &'static str,
    balance: &'static str,
    has_error_code: bool,
    has_request_id: bool,
}

#[derive(Debug, Serialize)]
struct ModelEvidence {
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u32>,
    image_input: Option<bool>,
    image_metadata_attested: bool,
}

#[derive(Debug, Serialize)]
struct CompactionEvidence {
    trigger_tokens: usize,
    keep_recent: usize,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum VerificationEvidence {
    Configured {
        command_digests_sha256: Vec<String>,
        floor: iteron_verify::VerifierSlotObservation,
        plan: iteron_verify::VerifierPlan,
    },
    Disabled,
    GetterUnavailable,
}

impl OwnerSnapshot {
    pub(super) fn capture(
        input: &ProviderProcessFactsInput<'_>,
    ) -> Result<Self, ProviderProcessFactError> {
        let health = input.directory.health(&input.selection.provider_id);
        let registered_tools = input
            .registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        let verification = match input.verification {
            VerificationOwnerFacts::Configured { floor, plan, .. } => {
                VerificationEvidence::Configured {
                    command_digests_sha256: input
                        .verification_policy
                        .required_commands
                        .iter()
                        .map(|command| hex::encode(Sha256::digest(command.as_bytes())))
                        .collect(),
                    floor: *floor,
                    plan: *plan,
                }
            }
            VerificationOwnerFacts::Disabled => VerificationEvidence::Disabled,
            VerificationOwnerFacts::GetterUnavailable => VerificationEvidence::GetterUnavailable,
        };
        let process_policy = Some(
            input
                .registry
                .process_control()
                .map_or_else(iteron_tools::ProcessRuntimePolicy::default, |control| {
                    control.policy()
                }),
        );
        let process_launch_policy = Some(
            iteron_tools::ProcessLaunchPolicy::owner(input.workspace)
                .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?,
        );
        let lsp_policy = input.registry.lsp_control().map(|control| control.policy());
        let role_model_routes = super::super::execution_policy::admitted_role_model_routes(
            input.agent_catalog,
            &input.selection.provider_id,
            &input.selection.model_id,
        )
        .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
        Ok(Self {
            route_attestation_digest_sha256: input.route.attestation_digest_sha256.clone(),
            health: HealthEvidence {
                availability: availability(health.availability),
                balance: balance(health.balance),
                // Provider strings are deliberately not copied into tunables evidence.
                has_error_code: health.last_error_code.is_some(),
                has_request_id: health.last_request_id.is_some(),
            },
            model: ModelEvidence {
                context_window_tokens: input.model_capabilities.context_window_tokens,
                max_output_tokens: input.model_capabilities.max_output_tokens,
                image_input: input.model_capabilities.image_input,
                image_metadata_attested: input.model_capabilities.image_input_version.is_some()
                    && input.model_capabilities.image_input_source.is_some(),
            },
            compaction: CompactionEvidence {
                trigger_tokens: input.compaction.trigger_tokens,
                keep_recent: input.compaction.keep_recent,
            },
            process_surface: has_process_surface(input.registry),
            lsp_surface: registered_tools.contains("lsp_query") && lsp_policy.is_some(),
            process_policy,
            process_launch_policy,
            lsp_policy,
            role_model_routes,
            tool_result_cache_ttl_seconds: input.registry.tool_result_cache_ttl_seconds(),
            registered_tools,
            checkpoint_supported: iteron_record::checkpoint_supported(input.workspace),
            verification,
            verification_policy: input.verification_policy.clone(),
            binary_media_policy: input.binary_media_policy.clone(),
        })
    }

    pub(super) fn digest_for(
        &self,
        family: &'static str,
        state: &'static str,
    ) -> Result<String, ProviderProcessFactError> {
        super::value::owner_digest("provider-process-activation-v1", &(family, state, self))
    }
}

pub(super) fn has_tool(registry: &Registry, name: &str) -> bool {
    registry.specs().iter().any(|spec| spec.name == name)
}

pub(super) fn has_process_surface(registry: &Registry) -> bool {
    const NAMES: [&str; 6] = [
        "process_start",
        "process_list",
        "process_poll",
        "process_write",
        "process_resize",
        "process_stop",
    ];
    registry.process_control().is_some() && NAMES.into_iter().all(|name| has_tool(registry, name))
}

const fn availability(value: AccountAvailability) -> &'static str {
    match value {
        AccountAvailability::Unknown => "unknown",
        AccountAvailability::Discovering => "discovering",
        AccountAvailability::Ready => "ready",
        AccountAvailability::MissingCredential => "missing_credential",
        AccountAvailability::AuthenticationBlocked => "authentication_blocked",
        AccountAvailability::BillingBlocked => "billing_blocked",
        AccountAvailability::PermissionBlocked => "permission_blocked",
        AccountAvailability::RateLimited => "rate_limited",
        AccountAvailability::Degraded => "degraded",
        AccountAvailability::ConfigurationError => "configuration_error",
    }
}

const fn balance(value: BalanceAvailability) -> &'static str {
    match value {
        BalanceAvailability::Unknown => "unknown",
        BalanceAvailability::Sufficient => "sufficient",
        BalanceAvailability::Depleted => "depleted",
    }
}

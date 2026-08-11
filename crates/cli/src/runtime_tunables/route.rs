//! Production route-capability facts for the tunables resolver.
//!
//! This adapter only attests surfaces that are present in the already-built provider directory
//! and tool registry. It does not infer a capability from configuration text alone: failed MCP
//! discovery, an LSP tool omitted on an unsupported host, and an unavailable process supervisor
//! therefore remain absent.

use crate::config::McpServerConfig;
use crate::providers::{ModelCapabilities, ModelSelection, ProviderDirectory};
use iteron_protocol::{Capability as ToolCapability, Purity};
use iteron_provider::AdapterKind;
use iteron_tools::{DISPATCH_AGENT, Registry, WORKFLOW_TOOL};
use iteron_tunables::{CapabilityRequirement, RouteCapabilities, RouteIdentity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

const ROUTE_ATTESTATION_CANONICALIZATION: &str = "iteron-cli-route-capability-facts-v1";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteFactError {
    #[error("the selected provider is absent from the settled provider directory")]
    UnknownProvider,
    #[error("the selected route is not currently admitted: {0}")]
    RouteBlocked(String),
    #[error("the supplied model capabilities do not match the selected directory route")]
    StaleModelCapabilities,
    #[error("the supplied selection digests do not match the selected directory route")]
    StaleSelectionDigests,
    #[error("selection {0} is not a canonical SHA-256 digest")]
    InvalidDigest(&'static str),
    #[error("selection {0} cannot be represented by the tunables route identity")]
    InvalidIdentity(&'static str),
    #[error("route capability evidence could not be encoded")]
    EvidenceEncoding,
}

pub(crate) struct RouteFactInput<'a> {
    pub directory: &'a ProviderDirectory,
    pub selection: &'a ModelSelection,
    pub model_capabilities: &'a ModelCapabilities,
    pub catalog_digest: &'a str,
    pub capability_digest: &'a str,
    pub registry: &'a Registry,
    /// True only when the composition caller will install a physical child spawner. Standalone
    /// workflows own that topology without exposing `dispatch_agent` as a registry tool, so the
    /// registry alone cannot attest this capability.
    pub agent_spawn_available: bool,
    /// Trusted-user/plugin MCP declarations after composition. A declaration is considered live
    /// only when its namespaced tool or extension is present in `registry`.
    pub configured_mcp: &'a [McpServerConfig],
}

/// Build one capability attestation for the exact selected route and executable tool surface.
pub(crate) fn collect_route_capabilities(
    input: RouteFactInput<'_>,
) -> Result<RouteCapabilities, RouteFactError> {
    let entry = input
        .directory
        .entry(&input.selection.provider_id)
        .ok_or(RouteFactError::UnknownProvider)?;
    if let Some(reason) = input.directory.blocked_reason(entry).or_else(|| {
        input
            .directory
            .model_blocked_reason(&input.selection.provider_id, &input.selection.model_id)
    }) {
        return Err(RouteFactError::RouteBlocked(reason));
    }
    if input.directory.selection_capabilities(input.selection) != *input.model_capabilities {
        return Err(RouteFactError::StaleModelCapabilities);
    }
    if input.directory.selection_digests(input.selection)
        != (
            input.catalog_digest.to_owned(),
            input.capability_digest.to_owned(),
        )
    {
        return Err(RouteFactError::StaleSelectionDigests);
    }

    let catalog_hex =
        digest_hex(input.catalog_digest).ok_or(RouteFactError::InvalidDigest("catalog digest"))?;
    let capability_hex = digest_hex(input.capability_digest)
        .ok_or(RouteFactError::InvalidDigest("capability digest"))?;
    validate_identity("provider id", &input.selection.provider_id)?;
    validate_identity("model id", &input.selection.model_id)?;
    validate_identity("route revision", input.capability_digest)?;

    let specs = input.registry.specs();
    let names = specs
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<HashSet<_>>();
    let mut capabilities = provider_capabilities(entry, input.model_capabilities);
    add_registry_capabilities(&mut capabilities, input.registry, &specs, &names);
    if input.agent_spawn_available {
        capabilities.insert(CapabilityRequirement::AgentSpawn);
    }
    let active_mcp = add_mcp_capabilities(&mut capabilities, input.configured_mcp, &names);

    let registry_projection = specs
        .iter()
        .map(|spec| (spec.name.clone(), tool_capability_id(spec.capability)))
        .collect::<BTreeSet<_>>();
    let evidence = RouteAttestationEvidence {
        canonicalization: ROUTE_ATTESTATION_CANONICALIZATION,
        provider_id: &input.selection.provider_id,
        model_id: &input.selection.model_id,
        catalog_digest_sha256: catalog_hex,
        capability_digest_sha256: capability_hex,
        capabilities: &capabilities,
        registry_tools: &registry_projection,
        active_mcp_servers: &active_mcp,
    };
    let encoded = serde_json::to_vec(&evidence).map_err(|_| RouteFactError::EvidenceEncoding)?;
    let attestation_digest_sha256 = hex::encode(Sha256::digest(encoded));

    Ok(RouteCapabilities {
        route: RouteIdentity {
            provider_id: input.selection.provider_id.clone(),
            model_id: input.selection.model_id.clone(),
            // This is the provider directory's actual immutable capability revision, not a new
            // CLI-authored version label.
            route_revision: input.capability_digest.to_owned(),
            catalog_digest_sha256: catalog_hex.to_owned(),
        },
        capabilities,
        attestation_digest_sha256,
    })
}

fn provider_capabilities(
    entry: &crate::providers::ProviderEntry,
    model: &ModelCapabilities,
) -> BTreeSet<CapabilityRequirement> {
    use CapabilityRequirement as C;
    let mut capabilities = BTreeSet::from([
        C::Inference,
        C::ProviderCatalog,
        C::ProviderStreaming,
        C::ProviderTransport,
        C::ProviderHealth,
        C::RateLimitObservation,
    ]);
    if entry.catalog.is_some() && !entry.catalog_stale {
        capabilities.insert(C::ProviderDiscovery);
    }
    if model.context_window_tokens.is_some()
        || model.max_output_tokens.is_some()
        || model.tool_calling.is_some()
        || model.version.is_some()
        || model.source.is_some()
    {
        capabilities.insert(C::ProviderModelMetadata);
    }
    if model.semantic_effort == Some(true) {
        capabilities.insert(C::ProviderReasoningControl);
        capabilities.insert(C::Reasoning);
    }
    if model.image_input == Some(true) {
        capabilities.insert(C::ProviderMultimodal);
    }
    if entry.instance.adapter() == AdapterKind::AnthropicMessages && entry.instance.prompt_cache() {
        capabilities.insert(C::ProviderPromptCache);
    }
    capabilities
}

fn add_registry_capabilities(
    capabilities: &mut BTreeSet<CapabilityRequirement>,
    registry: &Registry,
    specs: &[iteron_protocol::ToolSpec],
    names: &HashSet<&str>,
) {
    use CapabilityRequirement as C;
    if !specs.is_empty() {
        capabilities.insert(C::ToolExecution);
    }
    if specs.iter().any(|spec| spec.purity == Purity::Pure) {
        capabilities.insert(C::ToolResultCache);
    }
    if names.contains("read_file") || names.contains("grep") || names.contains("repo_map") {
        capabilities.insert(C::ContextRead);
    }
    if specs.iter().any(|spec| {
        matches!(
            spec.capability,
            ToolCapability::ReversibleLocal | ToolCapability::TrustMutating
        )
    }) {
        capabilities.insert(C::FileSystemWrite);
    }
    if names.contains("lsp_query") {
        capabilities.insert(C::LanguageServer);
    }
    if names.contains(DISPATCH_AGENT) || names.contains(WORKFLOW_TOOL) {
        capabilities.insert(C::AgentSpawn);
    }
    if names.contains("use_skill") {
        capabilities.insert(C::ExtensionDiscovery);
    }
    let process_surface = [
        "process_start",
        "process_list",
        "process_poll",
        "process_write",
        "process_stop",
    ]
    .into_iter()
    .all(|name| names.contains(name));
    if process_surface && registry.process_control().is_some() {
        capabilities.extend([
            C::PersistentProcess,
            C::BackgroundJob,
            C::InteractiveStdin,
            C::ProcessSignal,
        ]);
    }
}

fn add_mcp_capabilities(
    capabilities: &mut BTreeSet<CapabilityRequirement>,
    configured: &[McpServerConfig],
    names: &HashSet<&str>,
) -> BTreeSet<String> {
    use CapabilityRequirement as C;
    let mut active = BTreeSet::new();
    for server in configured {
        let prefix = format!("{}__", server.name);
        let server_tools = names
            .iter()
            .copied()
            .filter(|name| name.starts_with(&prefix))
            .collect::<Vec<_>>();
        if server_tools.is_empty() {
            continue;
        }
        active.insert(server.name.clone());
        capabilities.insert(C::McpTransport);
        if server_tools
            .iter()
            .any(|name| name.ends_with("__resources_list") || name.ends_with("__resources_read"))
        {
            capabilities.insert(C::McpResource);
            capabilities.insert(C::ExtensionDiscovery);
        }
        if server.oauth.is_some() {
            capabilities.insert(C::OAuth);
        }
    }
    active
}

#[derive(Serialize)]
struct RouteAttestationEvidence<'a> {
    canonicalization: &'static str,
    provider_id: &'a str,
    model_id: &'a str,
    catalog_digest_sha256: &'a str,
    capability_digest_sha256: &'a str,
    capabilities: &'a BTreeSet<CapabilityRequirement>,
    registry_tools: &'a BTreeSet<(String, &'static str)>,
    active_mcp_servers: &'a BTreeSet<String>,
}

fn digest_hex(value: &str) -> Option<&str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(value)
}

fn validate_identity(field: &'static str, value: &str) -> Result<(), RouteFactError> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'+')
        });
    valid
        .then_some(())
        .ok_or(RouteFactError::InvalidIdentity(field))
}

const fn tool_capability_id(capability: ToolCapability) -> &'static str {
    match capability {
        ToolCapability::ReadOnly => "read_only",
        ToolCapability::ReversibleLocal => "reversible_local",
        ToolCapability::CodeExecuting => "code_executing",
        ToolCapability::TrustMutating => "trust_mutating",
        ToolCapability::IrreversibleExternal => "irreversible_external",
    }
}

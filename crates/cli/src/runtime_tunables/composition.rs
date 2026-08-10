//! One-shot fresh-run composition of all 160 tunable families.
//!
//! This is the only production caller of `RuntimeResolutionBuilder::resolve`. It samples every
//! typed owner before a rollout is created and returns both the immutable resolver result and the
//! decoded core settings that must drive the kernel.

use super::authorities::{AuthorityFactsInput, VerificationAuthority, collect_runtime_authorities};
use super::catalogs::{CatalogObservation, ScalarCatalogInput, collect_scalar_catalogs};
use super::core_facts::{
    BudgetOrigins, CompactionOwner, CoreFactsInput, PromptCacheOwner, RetryOrigins, Sourced,
    apply_core_facts,
};
use super::effective_core::EffectiveCoreSettings;
use super::effective_view::EffectiveTunablesView;
use super::execution_facts::{ExecutionFactsInput, apply_execution_facts};
use super::extension_facts::{
    AgentMemoryMode, AgentMemoryScopeObservation, ChildOverlayObservation, ChildToolDisposition,
    ExtensionAuthorityFacts, ExtensionFactsInput, McpTransport, MessagingTopology,
    OAuthLifecycleMode, ReplayOwnerObservation, SessionIsolationProfile, apply_extension_facts,
};
use super::provider_process_facts::{
    ProviderProcessFactsInput, VerificationOwnerFacts, apply_provider_process_facts,
};
use super::route::{RouteFactInput, collect_route_capabilities};
use crate::config::{
    ConfigOrigin, McpServerConfig, McpTransportConfig, ResolvedProviderGovernorConfig,
};
use crate::providers::{ModelCapabilities, ModelSelection, ProviderDirectory};
use core_agents::AgentCatalog;
use core_protocol::capability_set::CapabilitySet;
use core_protocol::{Budget, DurableEnvironmentContext, Effort, PermissionMode, PermissionRules};
use core_sched::BackoffPolicy;
use core_tools::Registry;
use core_tunables::{ResolvedTunableSet, RuntimeProfile, RuntimeResolutionBuilder};
use core_verify::{VerifierSlotObservation, VerifierStrategy};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

pub(crate) struct FreshCompositionInput<'a> {
    pub directory: &'a ProviderDirectory,
    pub selection: &'a ModelSelection,
    pub model_capabilities: &'a ModelCapabilities,
    pub catalog_digest: &'a str,
    pub capability_digest: &'a str,
    pub registry: &'a Registry,
    pub configured_mcp: &'a [McpServerConfig],
    pub agent_catalog: &'a AgentCatalog,
    pub profile: RuntimeProfile,
    pub tenant: &'a core_protocol::TenantId,
    pub benchmark_scope: Option<&'a str>,
    pub workspace: &'a Path,
    pub environment: Option<&'a str>,
    pub operator_prompt: Option<&'a str>,
    pub hooks_configured: bool,
    pub app_server_active: bool,
    pub provider_origin: ConfigOrigin,
    pub model_origin: ConfigOrigin,
    pub base_url: Sourced<&'a str>,
    pub effort: Sourced<Effort>,
    pub budget: &'a Budget,
    pub budget_origins: BudgetOrigins,
    pub allow_code: Sourced<bool>,
    pub permission_mode: Sourced<PermissionMode>,
    pub permission_rules_origin: Option<ConfigOrigin>,
    pub permission_rules: &'a PermissionRules,
    pub bypass_permissions: Sourced<bool>,
    pub operator_egress_allow: Option<&'a [String]>,
    pub project_egress_allow: Option<&'a [String]>,
    pub compaction: &'a core_ctx::CompactionPolicy,
    pub compaction_owner: CompactionOwner,
    pub retry: &'a BackoffPolicy,
    pub retry_origins: RetryOrigins,
    pub verify_command: Option<&'a str>,
    pub memory_enabled: bool,
    pub tenant_allows_memory: bool,
    pub prompt_cache_enabled: bool,
    pub provider_governor: &'a ResolvedProviderGovernorConfig,
    pub provider_governor_configured: bool,
    pub provider_control_capabilities: &'a core_provider::ProviderControlCapabilities,
    pub authority_ceiling: CapabilitySet,
    pub run_limits: core_workflow::RunLimits,
}

pub(crate) struct FreshComposition {
    pub resolved: Arc<ResolvedTunableSet>,
    pub settings: EffectiveCoreSettings,
    pub route_capabilities: core_tunables::RouteCapabilities,
    pub session_spawn_ledger: Arc<crate::runtime::SessionSpawnLedger>,
    pub fact_summary: FreshFactSummary,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FreshFactSummary {
    pub core_gaps: usize,
    pub execution_gaps: usize,
    pub provider_process_gaps: usize,
    pub extension_gaps: usize,
}

pub(crate) fn resolve_fresh(input: FreshCompositionInput<'_>) -> anyhow::Result<FreshComposition> {
    let route_capabilities = collect_route_capabilities(RouteFactInput {
        directory: input.directory,
        selection: input.selection,
        model_capabilities: input.model_capabilities,
        catalog_digest: input.catalog_digest,
        capability_digest: input.capability_digest,
        registry: input.registry,
        configured_mcp: input.configured_mcp,
    })?;

    let token_estimators = CatalogObservation::observed(
        "core-ctx:request-estimator-v2",
        [
            core_ctx::TokenEstimatorProfile::GenericBytesPerToken35,
            core_ctx::TokenEstimatorProfile::OpenAiBpeApprox,
            core_ctx::TokenEstimatorProfile::AnthropicBpeApprox,
            core_ctx::TokenEstimatorProfile::SentencePieceApprox,
        ]
        .map(|profile| profile.identity().catalog_id),
    );
    let service_tiers = CatalogObservation::observed(
        format!(
            "core-provider:{}:service-tiers-v1",
            input.selection.provider_id
        ),
        input
            .provider_control_capabilities
            .service_tiers
            .iter()
            .map(|tier| tier.label().to_owned()),
    );
    let binary_inspectors = CatalogObservation::observed_empty("core-tools:binary-inspectors-v1");
    let catalogs = collect_scalar_catalogs(ScalarCatalogInput {
        directory: input.directory,
        selection: input.selection,
        model_capabilities: input.model_capabilities,
        registry: input.registry,
        agent_catalog: input.agent_catalog,
        token_estimators: &token_estimators,
        provider_service_tiers: &service_tiers,
        binary_inspectors: &binary_inspectors,
    })?;

    let verifier_floor = input
        .verify_command
        .map(|_| VerifierSlotObservation::gating(false));
    let verifier_plan = verifier_floor
        .as_ref()
        .map(|floor| VerifierStrategy::default().plan(floor, input.authority_ceiling))
        .transpose()?
        .map(|proposal| proposal.plan);
    let verification_authority = match (&verifier_floor, &verifier_plan) {
        (Some(floor), Some(plan)) => VerificationAuthority::Configured { floor, plan },
        _ => VerificationAuthority::Disabled,
    };
    let benchmark_scope_digest = input.benchmark_scope.map(scope_digest);
    let authorities = collect_runtime_authorities(AuthorityFactsInput {
        operator_ceiling: input.authority_ceiling,
        permission_mode: input.permission_mode.value,
        permission_rules: input.permission_rules,
        bypass_permissions: input.bypass_permissions.value,
        budget: input.budget,
        registry: input.registry,
        verification: verification_authority,
        tenant: input.tenant,
        tenant_allows_memory: input.tenant_allows_memory,
        profile: input.profile,
        benchmark_scope_digest_sha256: benchmark_scope_digest.as_deref(),
    })?;

    let mut builder = RuntimeResolutionBuilder::new(
        route_capabilities.clone(),
        catalogs.into_snapshots(),
        input.profile,
        authorities,
    )?;
    let core = apply_core_facts(
        &mut builder,
        CoreFactsInput {
            selection: input.selection,
            provider_origin: input.provider_origin,
            model_origin: input.model_origin,
            base_url: input.base_url,
            effort: input.effort,
            budget: input.budget,
            budget_origins: input.budget_origins,
            allow_code: input.allow_code,
            permission_mode: input.permission_mode,
            permission_rules_origin: input.permission_rules_origin,
            permission_rules: input.permission_rules,
            bypass_permissions: input.bypass_permissions,
            operator_egress_allow: input.operator_egress_allow,
            project_egress_allow: input.project_egress_allow,
            compaction: input.compaction,
            compaction_owner: input.compaction_owner,
            retry: input.retry,
            retry_origins: input.retry_origins,
            verify_command: input.verify_command,
            verifier_plan_command: input.verify_command.filter(|_| verifier_plan.is_some()),
            memory_enabled: input.memory_enabled,
            tenant_allows_memory: input.tenant_allows_memory,
            model_capabilities: input.model_capabilities,
            route: &route_capabilities,
            prompt_cache_enabled: input.prompt_cache_enabled,
            prompt_cache_owner: PromptCacheOwner::RustBuilder,
        },
    )?;

    let durable_environment = input.environment.map(|text| DurableEnvironmentContext {
        text: text.to_owned(),
        trust: core_protocol::Trust::Workspace,
    });
    let execution = apply_execution_facts(
        &mut builder,
        ExecutionFactsInput {
            registry: input.registry,
            agent_catalog: input.agent_catalog,
            budget: input.budget,
            effort: input.effort.value,
            verify_command: input.verify_command,
            hooks_configured: input.hooks_configured,
            model_capabilities: input.model_capabilities,
            directory: input.directory,
            configured_mcp: input.configured_mcp,
            authority_ceiling: input.authority_ceiling,
            operator_prompt: input.operator_prompt,
            environment: durable_environment.as_ref(),
            app_server_active: input.app_server_active,
        },
    )?;

    let verification_owner = match (&verifier_floor, &verifier_plan, input.verify_command) {
        (Some(floor), Some(plan), Some(command)) => VerificationOwnerFacts::Configured {
            command,
            floor,
            plan,
        },
        _ => VerificationOwnerFacts::Disabled,
    };
    let provider_process = apply_provider_process_facts(
        &mut builder,
        ProviderProcessFactsInput {
            directory: input.directory,
            selection: input.selection,
            model_capabilities: input.model_capabilities,
            route: &route_capabilities,
            budget: input.budget,
            compaction: input.compaction,
            registry: input.registry,
            workspace: input.workspace,
            verification: verification_owner,
            provider_governor: input.provider_governor,
            provider_governor_configured: input.provider_governor_configured,
            provider_control_capabilities: input.provider_control_capabilities,
        },
    )?;

    let extension_authorities = extension_authorities(&input);
    // The default workflow leaf is not an aspirational catalog entry: `KernelSpawner::build_child`
    // resolves the built-in `generic` definition, inherits the selected route and permission
    // rules, maps an orchestration-only Ultracode effort to Max, and deliberately does not attach
    // the parent's memory workspace. Capture those exact effective defaults before resolution so
    // the per-agent families have a real owner observation instead of an ambient placeholder.
    let child_overlay = ChildOverlayObservation {
        agent_name: "generic".to_owned(),
        provider_id: input.selection.provider_id.clone(),
        model_id: input.selection.model_id.clone(),
        effort: match input.effort.value {
            Effort::Ultracode => Effort::Max,
            effort => effort,
        },
        tool_profile: extension_authorities
            .tool_profiles
            .first()
            .cloned()
            .unwrap_or_default(),
        memory_scope: Some(AgentMemoryScopeObservation {
            mode: AgentMemoryMode::Isolated,
            scope_id: None,
            inherit_parent: false,
        }),
    };
    let session_spawn_ledger = Arc::new(
        crate::runtime::SessionSpawnLedger::new(extension_authorities.session_spawn_cap)
            .map_err(anyhow::Error::msg)?,
    );
    let session_profile = session_profile(input.profile);
    let replay_owner = ReplayOwnerObservation {
        verify_hash_chain: true,
        verify_identity_scope: true,
        verify_effect_terminals: true,
        fail_closed: true,
    };
    let extension = apply_extension_facts(
        &mut builder,
        ExtensionFactsInput {
            route: &route_capabilities,
            model_capabilities: input.model_capabilities,
            budget: input.budget,
            registry: input.registry,
            run_limits: input.run_limits,
            session_spawn_ledger: &session_spawn_ledger,
            child_overlay: Some(&child_overlay),
            configured_mcp: input.configured_mcp,
            mcp_reconnect: core_mcp::reconnect::ReconnectPolicy::default(),
            mcp_deadlines: core_mcp::McpDeadlinePolicy::default(),
            mcp_result_policy: core_mcp::McpResultPolicy::default(),
            early_stop_quorum: core_workflow::EarlyStopQuorumPolicy::default(),
            speculative_siblings: core_workflow::SpeculativeSiblingPolicy::default(),
            task_retry: core_workflow::TaskRetryPolicy::default(),
            writer_merge: core_workflow::WriterMergePolicy::default(),
            session_profile,
            replay_owner,
            provider_governor: input.provider_governor,
            provider_governor_configured: input.provider_governor_configured,
            provider_control_capabilities: input.provider_control_capabilities,
            authorities: ExtensionAuthorityFacts {
                run_session_spawn_cap: Some(extension_authorities.session_spawn_cap),
                verification_minimum_evidence: Some(1),
                parent_cost_model_routes: Some(&extension_authorities.routes),
                operator_tool_profiles: Some(&extension_authorities.tool_profiles),
                tenant_memory_scope_ids: Some(&extension_authorities.memory_scopes),
                operator_messaging_topologies: Some(&extension_authorities.topologies),
                operator_mcp_transports: Some(&extension_authorities.transports),
                operator_oauth_modes: Some(&extension_authorities.oauth_modes),
                operator_session_profiles: Some(&extension_authorities.session_profiles),
                tenant_session_profiles: Some(&extension_authorities.session_profiles),
                // Hash-chain/identity/effect-terminal replay validation is a record invariant,
                // not a benchmark-only feature. Every profile is governed by the same fail-closed
                // owner; benchmark merely consumes the resulting replay evidence more often.
                benchmark_replay_policy: Some(replay_owner),
            },
        },
    )?;
    if extension.is_resolution_blocked() {
        let ids = extension
            .blocking_gaps()
            .map(|gap| gap.family_id)
            .collect::<BTreeSet<_>>();
        anyhow::bail!(
            "runtime tunables owner facts are incomplete for active families: {}",
            ids.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    let resolved = Arc::new(builder.resolve()?);
    let view = EffectiveTunablesView::from_resolved(&resolved)?;
    let settings = EffectiveCoreSettings::decode(&view)?;
    settings.verify_route(
        &input.selection.provider_id,
        &input.selection.model_id,
        input.base_url.value,
    )?;
    Ok(FreshComposition {
        resolved,
        settings,
        route_capabilities,
        session_spawn_ledger,
        fact_summary: FreshFactSummary {
            core_gaps: core.gaps.len(),
            execution_gaps: execution.gaps.len(),
            provider_process_gaps: provider_process.gaps.len(),
            extension_gaps: extension.gaps.len(),
        },
    })
}

struct ExtensionAuthorities {
    session_spawn_cap: usize,
    routes: BTreeSet<String>,
    tool_profiles: Vec<BTreeMap<String, ChildToolDisposition>>,
    memory_scopes: BTreeSet<String>,
    topologies: BTreeSet<MessagingTopology>,
    transports: BTreeSet<McpTransport>,
    oauth_modes: BTreeSet<OAuthLifecycleMode>,
    session_profiles: BTreeSet<SessionIsolationProfile>,
}

fn extension_authorities(input: &FreshCompositionInput<'_>) -> ExtensionAuthorities {
    let tool_profile = input
        .permission_rules
        .tool_rules()
        .map(|(tool, verdict)| {
            let disposition = match verdict {
                core_protocol::Verdict::Auto => ChildToolDisposition::Allow,
                core_protocol::Verdict::Ask => ChildToolDisposition::Ask,
                core_protocol::Verdict::Deny => ChildToolDisposition::Deny,
            };
            (tool.to_owned(), disposition)
        })
        .collect();
    let transports = input
        .configured_mcp
        .iter()
        .map(|server| match server.transport {
            McpTransportConfig::Stdio => McpTransport::Stdio,
            McpTransportConfig::Http => McpTransport::Http,
        })
        .collect();
    let oauth = input
        .configured_mcp
        .iter()
        .filter_map(|server| server.oauth.as_ref())
        .collect::<Vec<_>>();
    let refresh = oauth
        .iter()
        .filter(|config| config.refresh_url.is_some() && config.refresh_token_env.is_some())
        .count();
    let oauth_mode = match (oauth.len(), refresh) {
        (0, _) => OAuthLifecycleMode::Disabled,
        (_, 0) => OAuthLifecycleMode::Bearer,
        (total, refresh) if total == refresh => OAuthLifecycleMode::RefreshToken,
        _ => OAuthLifecycleMode::Mixed,
    };
    ExtensionAuthorities {
        session_spawn_cap: crate::runtime::DEFAULT_SESSION_SPAWN_CAP,
        routes: [format!(
            "{}:{}",
            input.selection.provider_id, input.selection.model_id
        )]
        .into_iter()
        .collect(),
        tool_profiles: vec![tool_profile],
        memory_scopes: [format!("tenant:sha256:{}", scope_digest(&input.tenant.0))]
            .into_iter()
            .collect(),
        topologies: [MessagingTopology::ParentMediated].into_iter().collect(),
        transports,
        oauth_modes: [oauth_mode].into_iter().collect(),
        session_profiles: [session_profile(input.profile)].into_iter().collect(),
    }
}

fn session_profile(profile: RuntimeProfile) -> SessionIsolationProfile {
    match profile {
        RuntimeProfile::Interactive => SessionIsolationProfile::Interactive,
        RuntimeProfile::Benchmark => SessionIsolationProfile::Hermetic,
        RuntimeProfile::Research => SessionIsolationProfile::Durable,
    }
}

fn scope_digest(value: &str) -> String {
    hex::encode(Sha256::digest(
        [b"core-runtime-scope-v1\0".as_slice(), value.as_bytes()].concat(),
    ))
}

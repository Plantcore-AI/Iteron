//! One-shot fresh-run composition of all 160 tunable families.
//!
//! This is the only production caller of `RuntimeResolutionBuilder::resolve`. It samples every
//! typed owner before a rollout is created and returns both the immutable resolver result and the
//! decoded iteron settings that must drive the kernel.

use super::authorities::{AuthorityFactsInput, VerificationAuthority, collect_runtime_authorities};
use super::catalogs::{CatalogObservation, ScalarCatalogInput, collect_scalar_catalogs};
use super::core_facts::{
    BudgetOrigins, CompactionOwner, CoreFactGap, CoreFactsInput, PromptCacheOwner, RetryOrigins,
    Sourced, apply_core_facts,
};
use super::effective_core::EffectiveCoreSettings;
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
use iteron_agents::AgentCatalog;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Budget, DurableEnvironmentContext, Effort, PermissionMode, PermissionRules};
use iteron_sched::BackoffPolicy;
use iteron_tools::Registry;
#[cfg(test)]
use iteron_tunables::RuntimeOwnerReceipt;
use iteron_tunables::{
    ProductionOwnerId, ResolvedTunableSet, RuntimeProfile, RuntimeResolutionBuilder,
};
use iteron_verify::{VerifierSlotObservation, VerifierStrategy};
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
    pub agent_spawn_available: bool,
    pub configured_mcp: &'a [McpServerConfig],
    pub agent_catalog: &'a AgentCatalog,
    pub profile: RuntimeProfile,
    pub tenant: &'a iteron_protocol::TenantId,
    pub benchmark_scope: Option<&'a str>,
    pub workspace: &'a Path,
    pub environment: Option<&'a str>,
    #[allow(
        dead_code,
        reason = "the composition input preserves the private prompt observation without self-attesting it"
    )]
    pub operator_prompt: Option<&'a str>,
    pub hooks_catalog: Option<crate::runtime::hooks::HookCatalogIdentity>,
    #[allow(
        dead_code,
        reason = "the caller records whether the resident app-server actor owns this composition"
    )]
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
    pub compaction: &'a iteron_ctx::CompactionPolicy,
    pub compaction_owner: CompactionOwner,
    pub retry: &'a BackoffPolicy,
    pub retry_origins: RetryOrigins,
    pub verify_command: Option<&'a str>,
    /// Trusted user configuration only. Repository configuration is deliberately excluded by the
    /// composition caller and cannot grant verifier or rollback authority.
    pub verification_config: Option<&'a crate::config::VerificationConfig>,
    pub memory_enabled: Sourced<bool>,
    pub tenant_allows_memory: bool,
    pub prompt_cache_enabled: bool,
    pub provider_governor: &'a ResolvedProviderGovernorConfig,
    pub provider_governor_configured: bool,
    pub provider_control_capabilities: &'a iteron_provider::ProviderControlCapabilities,
    pub authority_ceiling: CapabilitySet,
    pub run_limits: iteron_workflow::RunLimits,
    /// An operator-supplied tunables profile, already digest-verified and validated. Replayed
    /// through the builder's own `profile_value`, so a loaded document goes through exactly the
    /// admission checks an in-process profile would.
    pub tunables_profile: Option<&'a iteron_tunables::ProfileDocument>,
}

pub(crate) struct FreshComposition {
    pub resolved: Arc<ResolvedTunableSet>,
    pub settings: EffectiveCoreSettings,
    pub session_spawn_ledger: Arc<crate::runtime::SessionSpawnLedger>,
    pub fact_summary: FreshFactSummary,
    #[cfg(test)]
    pub owner_receipt: RuntimeOwnerReceipt,
    #[cfg(test)]
    pub binding_receipt: super::effective_view::RuntimeBindingReceipt,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FreshFactSummary {
    /// Canonical Full-family gaps are rejected before resolution; a returned composition must
    /// therefore always report zero here. FixedHidden and inactive capability gaps remain visible
    /// in the per-adapter counts below instead of being erased from the audit inventory.
    pub active_full_gaps: usize,
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
        agent_spawn_available: input.agent_spawn_available,
        configured_mcp: input.configured_mcp,
    })?;

    let token_estimators = CatalogObservation::observed(
        "iteron-ctx:request-estimator-v2",
        std::iter::once(iteron_ctx::ROUTE_AWARE_ESTIMATOR_POLICY_ID.to_owned()).chain(
            [
                iteron_ctx::TokenEstimatorProfile::GenericBytesPerToken35,
                iteron_ctx::TokenEstimatorProfile::OpenAiBpeApprox,
                iteron_ctx::TokenEstimatorProfile::AnthropicBpeApprox,
                iteron_ctx::TokenEstimatorProfile::SentencePieceApprox,
            ]
            .into_iter()
            .map(|profile| profile.identity().catalog_id),
        ),
    );
    let service_tiers = CatalogObservation::observed(
        format!(
            "iteron-provider:{}:service-tiers-v1",
            input.selection.provider_id
        ),
        input
            .provider_control_capabilities
            .service_tiers
            .iter()
            .map(|tier| tier.label().to_owned()),
    );
    let binary_media_policy = crate::image_input::BinaryMediaInspectionPolicy::owner();
    let binary_inspectors = CatalogObservation::observed(
        "iteron-cli:binary-inspectors-v1",
        binary_media_policy.inspector_ids(),
    );
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
    let default_verification_config = crate::config::VerificationConfig::default();
    let verification_config = input
        .verification_config
        .unwrap_or(&default_verification_config);
    let verification_policy = verification_config
        .resolve(
            input.workspace,
            input.verify_command,
            verifier_plan.as_ref(),
        )
        .map_err(anyhow::Error::msg)?;
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
        binary_media_policy: &binary_media_policy,
    })?;

    let mut builder = RuntimeResolutionBuilder::new(
        route_capabilities.clone(),
        catalogs.into_snapshots(),
        input.profile,
        authorities,
    )?;
    if let Some(document) = input.tunables_profile {
        for value in &document.values {
            builder
                .profile_value(&value.family, value.as_declared_source, value.value.clone())
                .map_err(|error| {
                    anyhow::anyhow!(
                        "tunables profile value for `{}` refused: {error:?}",
                        value.family
                    )
                })?;
        }
    }
    let iteron = builder.with_owner(ProductionOwnerId::CoreFacts, |builder| {
        apply_core_facts(
            builder,
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
        )
    })?;

    let durable_environment = input.environment.map(|text| DurableEnvironmentContext {
        text: text.to_owned(),
        trust: iteron_protocol::Trust::Workspace,
    });
    let execution = builder.with_owner(ProductionOwnerId::ExecutionFacts, |builder| {
        apply_execution_facts(
            builder,
            ExecutionFactsInput {
                route: &route_capabilities,
                registry: input.registry,
                agent_catalog: input.agent_catalog,
                budget: input.budget,
                run_limits: input.run_limits,
                effort: input.effort.value,
                hooks_catalog: input.hooks_catalog.clone(),
                model_capabilities: input.model_capabilities,
                directory: input.directory,
                configured_mcp: input.configured_mcp,
                authority_ceiling: input.authority_ceiling,
                environment: durable_environment.as_ref(),
            },
        )
    })?;

    let verification_owner = match (&verifier_floor, &verifier_plan, input.verify_command) {
        (Some(floor), Some(plan), Some(command)) => VerificationOwnerFacts::Configured {
            command,
            floor,
            plan,
        },
        _ => VerificationOwnerFacts::Disabled,
    };
    let provider_process =
        builder.with_owner(ProductionOwnerId::ProviderProcessFacts, |builder| {
            apply_provider_process_facts(
                builder,
                ProviderProcessFactsInput {
                    agent_catalog: input.agent_catalog,
                    directory: input.directory,
                    selection: input.selection,
                    model_capabilities: input.model_capabilities,
                    route: &route_capabilities,
                    budget: input.budget,
                    compaction: input.compaction,
                    registry: input.registry,
                    workspace: input.workspace,
                    verification: verification_owner,
                    verification_policy: &verification_policy,
                    verification_config: input.verification_config,
                    provider_governor: input.provider_governor,
                    provider_governor_configured: input.provider_governor_configured,
                    provider_control_capabilities: input.provider_control_capabilities,
                    binary_media_policy: &binary_media_policy,
                },
            )
        })?;

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
    let replay_policy = iteron_record::replay_divergence_detection_policy();
    let replay_owner = ReplayOwnerObservation {
        verify_hash_chain: replay_policy.verify_hash_chain(),
        verify_identity_scope: replay_policy.verify_identity_scope(),
        verify_effect_terminals: replay_policy.verify_effect_terminals(),
        fail_closed: replay_policy.fail_closed(),
    };
    let extension = builder.with_owner(ProductionOwnerId::ExtensionFacts, |builder| {
        apply_extension_facts(
            builder,
            ExtensionFactsInput {
                route: &route_capabilities,
                model_capabilities: input.model_capabilities,
                budget: input.budget,
                registry: input.registry,
                run_limits: input.run_limits,
                session_spawn_ledger: &session_spawn_ledger,
                child_overlay: Some(&child_overlay),
                configured_mcp: input.configured_mcp,
                mcp_reconnect: iteron_mcp::reconnect::ReconnectPolicy::default(),
                mcp_deadlines: iteron_mcp::McpDeadlinePolicy::default(),
                mcp_result_policy: iteron_mcp::McpResultPolicy::default(),
                early_stop_quorum: iteron_workflow::EarlyStopQuorumPolicy::default(),
                speculative_siblings: iteron_workflow::SpeculativeSiblingPolicy::default(),
                task_retry: iteron_workflow::TaskRetryPolicy::default(),
                writer_merge: iteron_workflow::WriterMergePolicy::default(),
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
        )
    })?;
    let mut active_gap_ids = BTreeSet::new();
    active_gap_ids.extend(
        iteron
            .gaps
            .iter()
            .filter_map(core_gap_family)
            .filter(|family| canonical_full_family(family)),
    );
    active_gap_ids.extend(
        execution
            .gaps
            .iter()
            .map(|gap| gap.family)
            .filter(|family| canonical_full_family(family)),
    );
    active_gap_ids.extend(
        provider_process
            .gaps
            .iter()
            .map(|gap| gap.family_id)
            .filter(|family| canonical_full_family(family)),
    );
    active_gap_ids.extend(extension.blocking_gaps().map(|gap| gap.family_id));
    if !active_gap_ids.is_empty() {
        // Name this as a local precondition. It reads as a credential or provider failure
        // otherwise, because it is raised on the same path and at the same moment as one, and an
        // operator staring at it reasonably concludes their key was never sent. It was not sent,
        // and neither was anything else: this binding is resolved before any request is built.
        anyhow::bail!(
            "runtime tunables owner facts are incomplete for active families: {}. \
             No provider was contacted and no credential was used: this run was refused locally, \
             before any request was built. Supply the missing fact for each family listed, or \
             select a model whose context window is already known.",
            active_gap_ids.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    let (resolved, owner_receipt) = builder.resolve_with_owner_receipt()?;
    let resolved = Arc::new(resolved);
    // A fresh owner receipt is pending until the resolver report has been projected through the
    // same validated V2 envelope used by resume. Only the complete executable getter gate may
    // turn the pair into an accepted runtime binding receipt.
    let checkpoint =
        iteron_record::TunablesCheckpoint::V2(iteron_record::snapshot_v2_from_resolved(&resolved)?);
    let effective = super::effective_runtime::decode_checkpoint(&checkpoint, Some(&owner_receipt))?;
    let settings = effective.core;
    settings.verify_route(
        &input.selection.provider_id,
        &input.selection.model_id,
        input.base_url.value,
    )?;
    Ok(FreshComposition {
        resolved,
        settings,
        session_spawn_ledger,
        fact_summary: FreshFactSummary {
            active_full_gaps: 0,
            core_gaps: iteron.gaps.len(),
            execution_gaps: execution.gaps.len(),
            provider_process_gaps: provider_process.gaps.len(),
            extension_gaps: extension.gaps.len(),
        },
        #[cfg(test)]
        owner_receipt,
        #[cfg(test)]
        binding_receipt: effective.binding,
    })
}

fn canonical_full_family(family_id: &str) -> bool {
    iteron_tunables::families().iter().any(|family| {
        family.id == family_id
            && family.implementation_status == iteron_tunables::ImplementationStatus::Full
    })
}

fn core_gap_family(gap: &CoreFactGap) -> Option<&'static str> {
    match gap {
        // No aggregate parent token ceiling means configured family 7 is honestly inactive.
        CoreFactGap::ParentTokenCeilingAbsent => None,
        CoreFactGap::ParentTokenCeilingBelowThinkingMap => Some("thinking_map"),
        CoreFactGap::MemoryInstructionBudgetNotRepresentable => Some("memory_budgets"),
        CoreFactGap::ContextWindowUnknown => Some("context_window_override_reserve"),
        // This variant is emitted only after a verify command was configured, so family 14 is
        // active even though its canonical predicate is Configured rather than Always.
        CoreFactGap::VerificationPlanAbsent => Some("verify_command"),
    }
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
                iteron_protocol::Verdict::Auto => ChildToolDisposition::Allow,
                iteron_protocol::Verdict::Ask => ChildToolDisposition::Ask,
                iteron_protocol::Verdict::Deny => ChildToolDisposition::Deny,
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
        session_spawn_cap: crate::runtime::default_session_spawn_cap(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProviderConfig, ProviderGovernorConfig, ProviderModelCapabilities};
    use iteron_protocol::{Capability, TenantId};

    fn fixture_provider() -> ProviderConfig {
        ProviderConfig {
            id: "composition-fixture".into(),
            display_name: Some("composition fixture".into()),
            adapter: "openai_chat".into(),
            error_profile: Some("openai".into()),
            api_root: "https://composition.invalid/v1".into(),
            // The local directory only records the credential source. This test never dispatches
            // a provider request and therefore never reads a credential value.
            key_env: Some("ITERON_COMPOSITION_TEST_KEY".into()),
            credential: None,
            enabled: true,
            catalog: false,
            models: vec!["fixture-model".into()],
            model_capabilities: BTreeMap::from([(
                "fixture-model".into(),
                ProviderModelCapabilities {
                    // Compatible gateways often omit this optional catalog field. Fresh
                    // composition must pin the conservative local execution ceiling instead of
                    // making the entire CLI unusable before its first request.
                    context_window_tokens: None,
                    image_input: Some(true),
                    routing_objectives: None,
                },
            )]),
        }
    }

    fn fixture_provider_with_context_window() -> ProviderConfig {
        let mut provider = fixture_provider();
        provider
            .model_capabilities
            .get_mut("fixture-model")
            .expect("fixture model capabilities exist")
            .context_window_tokens = Some(262_144);
        provider
    }

    #[test]
    fn all_runtime_profiles_project_the_exact_physical_session_isolation_owner() {
        for (profile, projected) in [
            (
                RuntimeProfile::Interactive,
                SessionIsolationProfile::Interactive,
            ),
            (RuntimeProfile::Benchmark, SessionIsolationProfile::Hermetic),
            (RuntimeProfile::Research, SessionIsolationProfile::Durable),
        ] {
            assert_eq!(session_profile(profile), projected);
            let label = match projected {
                SessionIsolationProfile::Hermetic => "hermetic",
                SessionIsolationProfile::Durable => "durable",
                SessionIsolationProfile::Interactive => "interactive",
            };
            let installed = crate::session_isolation::SessionIsolationPolicy::from_label(label)
                .expect("the resolved profile label is physically installable");
            assert_eq!(
                installed,
                crate::session_isolation::SessionIsolationPolicy::from_runtime_profile(profile)
            );
            installed
                .validate_profile(profile)
                .expect("resolver owner and physical continuation gate must agree");
        }
    }

    fn resolve_fixture(provider: ProviderConfig) -> (FreshComposition, ModelCapabilities) {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
        let directory = ProviderDirectory::inspect_local(&[provider]).unwrap();
        let selection = directory
            .resolve_model("composition-fixture:fixture-model", None)
            .unwrap();
        let model_capabilities = directory.selection_capabilities(&selection);
        let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
        let entry = directory.entry(&selection.provider_id).unwrap();
        let api_root = entry.instance.api_root().as_str().to_owned();
        // This fixture uses the conservative custom-gateway adapter surface. No provider is
        // constructed (which would read the intentionally absent test credential), and no turn
        // is dispatched.
        let provider_controls = iteron_provider::ProviderControlCapabilities::default();
        let registry = Registry::coding_agent(workspace).unwrap();
        let agent_catalog = AgentCatalog::builtin_only();
        let budget = Budget::default();
        let compaction = iteron_ctx::CompactionPolicy::default();
        let retry = BackoffPolicy::default();
        let rules = PermissionRules::default();
        let run_limits = iteron_workflow::RunLimits::new(1, 8).unwrap();
        let governor = ProviderGovernorConfig::default()
            .resolve(run_limits.max_concurrency(), false)
            .unwrap();
        let tenant = TenantId::default();

        let fresh = resolve_fresh(FreshCompositionInput {
            directory: &directory,
            selection: &selection,
            model_capabilities: &model_capabilities,
            catalog_digest: &catalog_digest,
            capability_digest: &capability_digest,
            registry: &registry,
            agent_spawn_available: true,
            configured_mcp: &[],
            agent_catalog: &agent_catalog,
            profile: RuntimeProfile::Interactive,
            tenant: &tenant,
            benchmark_scope: None,
            workspace,
            environment: None,
            operator_prompt: None,
            hooks_catalog: None,
            app_server_active: false,
            provider_origin: ConfigOrigin::UserConfig,
            model_origin: ConfigOrigin::UserConfig,
            base_url: Sourced {
                value: &api_root,
                origin: ConfigOrigin::UserConfig,
            },
            effort: Sourced {
                value: Effort::Medium,
                origin: ConfigOrigin::Builtin,
            },
            budget: &budget,
            budget_origins: BudgetOrigins {
                max_turns: ConfigOrigin::Builtin,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: ConfigOrigin::Builtin,
                max_consecutive_tool_errors: ConfigOrigin::Builtin,
            },
            allow_code: Sourced {
                value: false,
                // This fixture models the operator-selected read-only CLI posture. A Builtin
                // declaration may only attest the embedded literal `true`.
                origin: ConfigOrigin::Cli,
            },
            permission_mode: Sourced {
                value: PermissionMode::Plan,
                origin: ConfigOrigin::Cli,
            },
            permission_rules_origin: None,
            permission_rules: &rules,
            bypass_permissions: Sourced {
                value: false,
                origin: ConfigOrigin::Cli,
            },
            operator_egress_allow: None,
            project_egress_allow: None,
            compaction: &compaction,
            compaction_owner: CompactionOwner::AdaptiveDefault,
            retry: &retry,
            retry_origins: RetryOrigins {
                base_ms: ConfigOrigin::Builtin,
                cap_ms: ConfigOrigin::Builtin,
                max_attempts: ConfigOrigin::Builtin,
            },
            verify_command: None,
            verification_config: None,
            memory_enabled: Sourced {
                value: false,
                origin: ConfigOrigin::Cli,
            },
            tenant_allows_memory: true,
            prompt_cache_enabled: false,
            provider_governor: &governor,
            provider_governor_configured: false,
            provider_control_capabilities: &provider_controls,
            authority_ceiling: CapabilitySet::from_iter_capabilities([Capability::ReadOnly]),
            run_limits,
            tunables_profile: None,
        })
        .unwrap_or_else(|error| {
            panic!("fresh production composition must resolve and seal: {error:#?}")
        });

        (fresh, model_capabilities)
    }

    #[test]
    fn fresh_composition_executes_owner_and_getter_seals_before_returning() {
        let (fresh, model_capabilities) = resolve_fixture(fixture_provider());
        assert_eq!(
            model_capabilities.image_input,
            Some(true),
            "the production composition oracle exercises the image-capable custom route"
        );
        assert_eq!(
            model_capabilities.context_window_tokens, None,
            "the production composition oracle exercises the unknown-window fallback"
        );

        assert_eq!(
            fresh.binding_receipt.effective_family_count, fresh.binding_receipt.getter_count,
            "every effective Full family was read by its registered production getter"
        );
        assert_eq!(
            fresh.owner_receipt.family_count(),
            fresh.binding_receipt.effective_family_count,
            "every effective Full family was observed by its exact production owner"
        );
        assert_eq!(fresh.fact_summary.active_full_gaps, 0);
        assert!(
            fresh.settings.model_context_window.is_some(),
            "unknown provider metadata must resolve to a pinned conservative effective window"
        );
        for family_id in [
            "effort",
            "model_fallback_chain",
            "route_quality_cost_latency_objective_weights",
            "provider_health_circuit_breaker_state_policy",
            "provider_service_tier",
            "response_verbosity",
            "request_compression_policy",
            "prompt_cache_ttl_breakpoint_strategy",
            "prompt_cache",
            "allow_code",
            "permission_mode",
            "bypass_permissions",
            "memory_enable",
            "summary_profile",
            "memory_budgets",
            "multimodal_input_admission_decode_envelope",
            "multimodal_token_budget",
            "binary_media_inspection_routing",
            "per_agent_effort_thinking",
        ] {
            assert!(
                fresh.resolved.report().entries.iter().any(|entry| {
                    entry.family_id == family_id
                        && matches!(entry.outcome, iteron_tunables::EntryOutcome::Effective)
                }),
                "{family_id} must remain an effective, owner-attested Full family"
            );
        }
        assert!(fresh.resolved.report().entries.iter().any(|entry| {
            entry.family_id == "effort_reasoning_map"
                && matches!(
                    entry.outcome,
                    iteron_tunables::EntryOutcome::Inactive { .. }
                )
        }));

        // A successful fresh resolution is only a pending owner receipt until the exact V2
        // projection has passed every registered getter.  Exercise that same production decoder,
        // then remove one observed access: owner metadata and a valid snapshot alone must not be
        // enough to admit the run.
        let checkpoint = iteron_record::TunablesCheckpoint::V2(
            iteron_record::snapshot_v2_from_resolved(&fresh.resolved).unwrap(),
        );
        let view =
            super::super::effective_view::EffectiveTunablesView::from_checkpoint(&checkpoint)
                .unwrap();
        super::super::effective_runtime::consume_registered_getters(&view)
            .expect("the real fresh decoders execute");
        view.remove_getter_receipt("provider");
        assert_eq!(
            view.seal_runtime_binding_receipt(
                Some(&fresh.owner_receipt),
                &super::super::fixed_artifacts::FixedArtifactReceipts::default(),
                &super::super::fixed_artifacts::FixedAuthorityReceipts::default(),
            )
            .unwrap_err(),
            super::super::effective_view::EffectiveViewError::MissingGetterReceipt(
                "provider".into()
            )
        );
    }

    #[test]
    fn fresh_composition_uses_one_unknown_output_fallback_for_request_and_context_budget() {
        let (fresh, model_capabilities) = resolve_fixture(fixture_provider_with_context_window());
        assert_eq!(model_capabilities.context_window_tokens, Some(262_144));
        assert_eq!(model_capabilities.max_output_tokens, None);
        assert_eq!(
            fresh.settings.request_output_cap,
            Some(super::super::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS),
            "request construction must use the shared unknown-output fallback"
        );
        assert_eq!(
            fresh.settings.context_budget.output_reserve_tokens,
            super::super::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS,
            "context allocation must reserve the same resolved output value"
        );
        assert_eq!(
            fresh.settings.context_budget.transcript_tokens, 63_488,
            "the component policy must derive from the shared reservation"
        );
    }
}

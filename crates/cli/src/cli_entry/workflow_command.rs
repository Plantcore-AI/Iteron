//! Standalone workflow composition through the typed runtime spawner port.

use super::catalog::discover_agent_catalog;
use super::clocks::{UNIX_NANOS_ON_UNUSABLE_CLOCK, UNIX_SECS_ON_UNUSABLE_CLOCK};
use super::options::{Cli, WorkflowAction};
use super::permissions::initial_permission_rules;
use super::provider_bootstrap::BUILTIN_DEFAULT_PROVIDER;
use super::records::resolve_runs_dir;
use crate::config::FileConfig;
use crate::{
    bundle_adapter, config, output, plugin_runtime, pricing, providers, runtime, runtime_tunables,
    theme, workflow,
};
use iteron_protocol::{Budget, TenantId};
use iteron_tools::Registry;

/// Build the DEFAULT workflow spawner: the real [`runtime::KernelSpawner`], so every `agent()`
/// call runs a genuine child `Agent` (own context + read-only tool loop) via `run_leaf`. There is
/// deliberately no provider-only escape hatch: bypassing the child kernel would also bypass its
/// immutable governor, per-physical-attempt journal, budget, and cancellation surfaces.
///
/// The context is filled from the SAME resolved values the main agent path records
/// (`record_model_selection` inputs): provider handle + model + `provider_id` + the catalog/capability
/// digests from `ProviderDirectory::selection_digests`, the documented model window/output caps, the
/// repo as workspace, and `<runs_dir>` as the runtime-state root (child rollouts land under
/// `<runs_dir>/subagents/`). Pricing is the same operator-trusted port resolved for the exact
/// selected route; a positive USD ceiling is refused before this context exists when no active
/// card can enforce it.
// Ten parameters because this is the composition root wiring a spawner out of the provider,
// selection digests, capability caps and run paths. Grouping them into a struct would just move
// the same fields behind a name that exists only for this one call site.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_workflow_spawner(
    provider_arc: std::sync::Arc<dyn iteron_provider::Provider>,
    model: String,
    selection: &providers::ModelSelection,
    catalog_digest: String,
    capability_digest: String,
    caps: &providers::ModelCapabilities,
    provider_governor: config::ResolvedProviderGovernorConfig,
    fallback_provider_routes: Vec<runtime::GovernedProviderRoute>,
    pricing_port: Option<std::sync::Arc<dyn iteron_obs::PricingPort>>,
    otel_value: Option<&serde_json::Value>,
    repo: &std::path::Path,
    runs_dir: &std::path::Path,
    parent_run_id: &str,
    workflow_id: &str,
    compiled_policy_bundle: std::sync::Arc<bundle_adapter::CompiledPolicyBundle>,
    runtime_plugins: &plugin_runtime::RuntimePlugins,
    tunables_checkpoint: iteron_record::TunablesCheckpoint,
    effective: &runtime_tunables::effective_core::EffectiveCoreSettings,
    session_spawn_ledger: std::sync::Arc<runtime::SessionSpawnLedger>,
) -> anyhow::Result<std::sync::Arc<dyn iteron_workflow::AgentSpawner>> {
    // Standalone WorkflowEngine children intentionally receive no MCP registry/runtime owner.
    // Their immutable checkpoint must therefore say MCP is inactive too; accepting an active
    // transport/exposure here would claim a physical consumer that the child cannot possess.
    if !effective.mcp.is_disabled() || !effective.mcp_exposure.is_disabled() {
        anyhow::bail!(
            "standalone workflow checkpoint enables MCP, but workflow children have no MCP runtime owner"
        );
    }
    let mut cx = runtime::KernelSpawnerContext::new(
        provider_arc,
        model,
        selection.provider_id.clone(),
        catalog_digest,
        capability_digest,
        repo.to_path_buf(),
        runs_dir.to_path_buf(),
        TenantId::default(),
        parent_run_id.to_string(),
        workflow_id.to_string(),
    );
    effective
        .verify_model_capability_ceiling(caps.context_window_tokens, caps.max_output_tokens)?;
    cx.model_context_window = effective.model_context_window;
    cx.model_max_output_tokens = effective.request_output_cap;
    cx.standalone_mcp_policy = Some((effective.mcp, effective.mcp_exposure.clone()));
    cx.provider_controls = provider_governor.controls;
    cx.fallback_provider_routes = fallback_provider_routes;
    cx.initialize_provider_governor(provider_governor.policy)
        .map_err(anyhow::Error::msg)?;
    cx.pin_tunables_checkpoint(tunables_checkpoint)?;
    cx.install_session_spawn_ledger(session_spawn_ledger);
    cx.default_effort = effective.effort;
    cx.effort_policy = effective.effort_policy.clone();
    cx.execution_policy = effective.execution;
    cx.budget = effective.budget.clone();
    cx.install_pricing_authority(pricing_port)
        .map_err(anyhow::Error::msg)?;
    cx.retry_policy = effective.retry;
    cx.verify_command = effective.verify_command.clone();
    cx.deferred_tool_eager_limit = effective.deferred_tool_eager_limit;
    cx.context_budget_policy = effective.context_budget.with_elastic_task_context(matches!(
        effective.task_context_budget_source,
        runtime_tunables::effective_core::TaskContextBudgetSource::DefaultDerived
    ));
    cx.context_materialization_policy = effective.context_materialization;
    cx.compaction_policy = effective.compaction;
    cx.permission_mode = effective.permission_mode;
    cx.permission_rules = effective.permission_rules.clone();
    cx.bypass_permissions = effective.bypass_permissions;
    // A standalone workflow starts from a read-only host ceiling. Family 9 may only narrow that
    // ceiling; `allow_code=true` cannot mint authority the workflow composition never received.
    cx.authority_ceiling = effective.constrain_authority_ceiling(
        iteron_protocol::capability_set::CapabilitySet::only(iteron_protocol::Capability::ReadOnly),
    );
    cx.context_home_dir = config::config_home();
    cx.agent_catalog = std::sync::Arc::new(discover_agent_catalog(repo, &runtime_plugins.agents));
    cx.dependency_skill_dirs = runtime_plugins
        .skills
        .iter()
        .map(|skill| (skill.root.clone(), skill.directory.clone()))
        .collect();
    cx.install_compiled_policy_bundle(compiled_policy_bundle);
    runtime::attach_workflow_telemetry(&mut cx, otel_value);
    Ok(std::sync::Arc::new(runtime::KernelSpawner::new(cx)))
}

/// `iteron workflow <run|list|resume|watch>` — the ultracode-workflow surface. `run`/`resume`/`watch`
/// resolve a provider (trusted precedence, no rollout/pricing machinery) and drive
/// `iteron_workflow::WorkflowEngine` with the real [`runtime::KernelSpawner`]; `list` is pure
/// enumeration. Journals + re-launch sidecars (`script.js`, `run.json`, `result.json`) persist under
/// `<runs_dir>/subagents/workflows/<run_id>/`, so a run is listable + resumable by a later process.
pub(crate) async fn run_workflow_command(
    cli: &Cli,
    repo: &std::path::Path,
    user_file: &FileConfig,
    action: &WorkflowAction,
) -> anyhow::Result<u8> {
    if !iteron_workflow::SCRIPT_WORKFLOWS_ENABLED {
        return Err(iteron_workflow::ScriptWorkflowsUnavailable.into());
    }
    use std::io::IsTerminal;

    // A relative `--runs-dir` resolves under the canonicalized repo so runs land in the project
    // regardless of the invoking cwd. `<workflows_dir>` holds one directory per run.
    let runs_dir = resolve_runs_dir(cli, repo);
    let workflows_dir = runs_dir.join("subagents").join("workflows");

    // `list` — enumerate persisted runs; needs no provider or API key.
    if matches!(action, WorkflowAction::List) {
        let runs = workflow::list_runs(&workflows_dir);
        if runs.is_empty() {
            eprintln!("no workflow runs in {}", workflows_dir.display());
        } else {
            for run in &runs {
                println!(
                    "{}  {:<8} agents={:<3} model={:<24} {}",
                    run.run_id, run.status, run.agents, run.model, run.name
                );
            }
        }
        return Ok(output::EXIT_SUCCESS);
    }

    // Resolve script source + ambient args + this run's identity + resume source, per action.
    // Resume/Watch continue a prior run IN PLACE (same run_id, resume_from == that id), so the run's
    // journal both seeds the resume cache and receives new outcomes; the persisted `script.js` means
    // no `--script` is required.
    let (src, args_value, run_id, resume_from): (
        String,
        serde_json::Value,
        String,
        Option<String>,
    ) = match action {
        WorkflowAction::Run { script, args } => {
            let src = std::fs::read_to_string(script).map_err(|error| {
                anyhow::anyhow!("cannot read workflow script {}: {error}", script.display())
            })?;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.main.unix_nanos_on_unusable_clock",
                    UNIX_NANOS_ON_UNUSABLE_CLOCK,
                ));
            let run_id = format!("wf_{}_{:x}", std::process::id(), nanos);
            (src, parse_workflow_args(args)?, run_id, None)
        }
        WorkflowAction::Resume {
            run_id,
            script,
            args,
        } => {
            let src = match script {
                Some(path) => std::fs::read_to_string(path).map_err(|error| {
                    anyhow::anyhow!("cannot read workflow script {}: {error}", path.display())
                })?,
                None => workflow::load_script(&workflows_dir, run_id).ok_or_else(|| {
                    anyhow::anyhow!("run `{run_id}` has no persisted script; pass --script <path>")
                })?,
            };
            let args_value = match args {
                Some(_) => parse_workflow_args(args)?,
                None => workflow::load_manifest(&workflows_dir, run_id)
                    .map(|m| m.args)
                    .unwrap_or(serde_json::Value::Null),
            };
            (src, args_value, run_id.clone(), Some(run_id.clone()))
        }
        WorkflowAction::Watch { run_id, args } => {
            let src = workflow::load_script(&workflows_dir, run_id).ok_or_else(|| {
                anyhow::anyhow!("run `{run_id}` has no persisted script to watch")
            })?;
            let args_value = match args {
                Some(_) => parse_workflow_args(args)?,
                None => workflow::load_manifest(&workflows_dir, run_id)
                    .map(|m| m.args)
                    .unwrap_or(serde_json::Value::Null),
            };
            (src, args_value, run_id.clone(), Some(run_id.clone()))
        }
        WorkflowAction::List => unreachable!("handled above"),
    };

    // Resume/watch is governed by the exact immutable V2 runtime checkpoint written by the
    // original process. Decode it before provider selection so today's config cannot silently
    // change route, budget, retry, context, or governor policy for an existing lineage.
    let resumed_tunables_checkpoint = resume_from
        .as_deref()
        .map(|recorded_run_id| workflow::load_tunables_checkpoint(&workflows_dir, recorded_run_id))
        .transpose()?;
    let resumed_effective_settings = resumed_tunables_checkpoint
        .as_ref()
        .map(|checkpoint| {
            runtime_tunables::effective_runtime::decode_checkpoint(checkpoint, None)
                .map(|effective| effective.core)
                .map_err(anyhow::Error::from)
        })
        .transpose()?;

    // A standalone workflow is also a governed run. Fresh runs compile the trusted active bundle
    // before creating any run artifact; resume/watch reconstruct only the immutable sidecar and
    // never consult today's user configuration.
    let compiled_policy_bundle = match resume_from.as_deref() {
        Some(recorded_run_id) => {
            let snapshot = workflow::load_policy_checkpoint(&workflows_dir, recorded_run_id)?;
            bundle_adapter::compile_recorded_bundle(&snapshot).map_err(|error| {
                anyhow::anyhow!(
                    "cannot resume workflow `{recorded_run_id}`: {error}; receipt={}",
                    serde_json::to_string(&error.receipt)
                        .unwrap_or_else(|_| "<unavailable>".into())
                )
            })?
        }
        None => bundle_adapter::compile_configured_bundle(
            user_file.active_policy_bundle.as_ref(),
            config::ConfigOrigin::UserConfig,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "{error}; receipt={}",
                serde_json::to_string(&error.receipt).unwrap_or_else(|_| "<unavailable>".into())
            )
        })?,
    };

    // Provider selection with the same trusted precedence as a normal run (CLI > env > user config >
    // built-in). Routing never consults the project config (untrusted origin).
    let configured_providers = user_file.providers.clone().unwrap_or_default();
    let (provider_name, provider_origin) = match &resumed_effective_settings {
        Some(settings) => (settings.provider_id.clone(), config::ConfigOrigin::Builtin),
        None => config::pick_trusted_string(
            cli.provider.clone(),
            config::env_string("ITERON_PROVIDER"),
            user_file.provider.clone(),
            iteron_tunables::param_str(
                "cli.main.builtin_default_provider",
                BUILTIN_DEFAULT_PROVIDER,
            ),
        ),
    };
    let provider_directory = providers::ProviderDirectory::discover(&configured_providers).await?;
    let requested_model_with_origin = match &resumed_effective_settings {
        Some(settings) => Some((settings.model_id.clone(), config::ConfigOrigin::Builtin)),
        None => config::pick_model_string(
            cli.model.clone(),
            config::env_string("ITERON_MODEL"),
            user_file.model.clone(),
            None,
        ),
    };
    let requested_model = requested_model_with_origin
        .as_ref()
        .map(|(model, _)| model.as_str());
    let selection = match requested_model {
        Some(model_id) => provider_directory
            .resolve_model(model_id, Some(&provider_name))
            .map_err(|error| anyhow::anyhow!("cannot resolve model: {error}"))?,
        None => provider_directory
            .default_selection(&provider_name)
            .ok_or_else(|| anyhow::anyhow!("provider `{provider_name}` has no selectable model"))?,
    };
    let provider_arc = provider_directory
        .build(&selection)
        .map_err(|error| anyhow::anyhow!("selected provider/model is unavailable: {error}"))?;
    let model = selection.model_id.clone();
    // The exact route the children re-record (byte-for-byte the main path's `record_model_selection`
    // inputs), plus the documented window/output caps the children inherit.
    let (catalog_digest, capability_digest) = provider_directory.selection_digests(&selection);
    let caps = provider_directory.selection_capabilities(&selection);
    let workflow_pricing_route = iteron_protocol::PricingRoute {
        provider_id: selection.provider_id.clone(),
        model_id: selection.model_id.clone(),
        catalog_digest: catalog_digest.clone(),
        capability_digest: capability_digest.clone(),
    };
    // Authenticate pricing before persisting workflow sidecars or opening any child rollout. The
    // opaque port retains key material; only its exact active-card result crosses composition.
    let workflow_pricing_port =
        pricing::load_authority(user_file.rate_cards.as_deref().unwrap_or_default())?;
    let workflow_pricing_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "cli.main.unix_secs_on_unusable_clock",
            UNIX_SECS_ON_UNUSABLE_CLOCK,
        ));
    let workflow_rate_card = workflow_pricing_port
        .as_ref()
        .map(|port| port.resolve_rate_card(&workflow_pricing_route, workflow_pricing_now))
        .transpose()?
        .flatten();
    let selected_entry = provider_directory
        .entry(&selection.provider_id)
        .ok_or_else(|| anyhow::anyhow!("selected workflow provider disappeared"))?;
    let selected_api_root = selected_entry.instance.api_root().as_str().to_owned();
    let prompt_cache_enabled = selected_entry.instance.prompt_cache();
    if let Some(settings) = &resumed_effective_settings {
        settings.verify_route(
            &selection.provider_id,
            &selection.model_id,
            &selected_api_root,
        )?;
    }
    let provider_governor = match &resumed_effective_settings {
        Some(settings) => settings.provider_governor.clone(),
        None => user_file
            .provider_governor
            .clone()
            .unwrap_or_default()
            .resolve(
                iteron_workflow::RunLimits::default().max_concurrency(),
                prompt_cache_enabled,
            )
            .map_err(anyhow::Error::msg)?,
    };
    let controls_capabilities = provider_arc.control_capabilities();
    controls_capabilities
        .validate(
            &controls_capabilities.adapt_optional_cache_breakpoint(provider_governor.controls),
        )
        .map_err(|error| anyhow::anyhow!("provider request controls are not supported: {error}"))?;
    let fallback_provider_routes = provider_governor
        .fallback_routes
        .iter()
        .map(|route_id| {
            let (provider_id, model_id) = route_id
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid fallback route identity"))?;
            let fallback = providers::ModelSelection {
                provider_id: provider_id.to_owned(),
                model_id: model_id.to_owned(),
            };
            if fallback == selection {
                anyhow::bail!("the primary provider route cannot also be a fallback route");
            }
            provider_directory
                .validate_selection(&fallback, true)
                .map_err(|error| anyhow::anyhow!("fallback route is unavailable: {error}"))?;
            let provider = provider_directory
                .build(&fallback)
                .map_err(|error| anyhow::anyhow!("fallback route is unavailable: {error}"))?;
            let controls_capabilities = provider.control_capabilities();
            controls_capabilities
                .validate(
                    &controls_capabilities
                        .adapt_optional_cache_breakpoint(provider_governor.controls),
                )
                .map_err(|error| {
                    anyhow::anyhow!("fallback route request controls are unsupported: {error}")
                })?;
            let capabilities = provider_directory.selection_capabilities(&fallback);
            let (catalog_digest, capability_digest) =
                provider_directory.selection_digests(&fallback);
            Ok(runtime::GovernedProviderRoute::new(
                provider,
                iteron_protocol::PricingRoute {
                    provider_id: fallback.provider_id,
                    model_id: fallback.model_id,
                    catalog_digest,
                    capability_digest,
                },
                capabilities.image_input,
                capabilities.tool_calling,
                capabilities.context_window_tokens,
                capabilities.max_output_tokens,
                capabilities.routing_objectives,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Standalone workflows use the same complete 160-family resolver as the interactive agent.
    // The workflow engine itself has no rollout genesis, so the exact V2 checkpoint is persisted
    // beside its policy checkpoint and inherited by every child rollout.
    let runtime_profile = cli
        .harness_profile
        .map(iteron_tunables::RuntimeProfile::from)
        .unwrap_or(iteron_tunables::RuntimeProfile::Interactive);
    if resume_from.is_none()
        && runtime_profile == iteron_tunables::RuntimeProfile::Benchmark
        && cli.benchmark_attempt_scope.is_none()
    {
        anyhow::bail!("--harness-profile benchmark requires --benchmark-attempt-scope");
    }
    // The standalone workflow owns a top-level run checkpoint, so its built-in budget must be the
    // same canonical owner as every other root run. Each physical workflow child is still
    // intersected with `subagent_budget_ceiling()` by `KernelSpawner`; using that child ceiling as
    // the root's Builtin value would create a second default and fail the literal-owner seal.
    let default_budget = Budget::default();
    let (workflow_max_turns, workflow_max_turns_origin) = config::pick_with_origin(
        cli.max_turns,
        config::env_turn_limit(),
        user_file.max_turns,
        default_budget.max_turns,
    );
    let workflow_max_usd_with_origin = config::pick_optional_with_origin(
        cli.max_usd,
        config::env_f64("ITERON_MAX_USD"),
        user_file.max_usd,
    );
    let (workflow_max_usd, workflow_max_usd_origin) = workflow_max_usd_with_origin
        .map(|(value, origin)| (Some(value), Some(origin)))
        .unwrap_or((None, None));
    let workflow_max_tokens = cli.max_tokens.or(default_budget.max_tokens);
    let workflow_max_tokens_origin =
        cli.max_tokens
            .map(|_| config::ConfigOrigin::Cli)
            .or_else(|| {
                default_budget
                    .max_tokens
                    .map(|_| config::ConfigOrigin::Builtin)
            });
    let (workflow_max_wall_secs, workflow_max_wall_secs_origin) = config::pick_with_origin(
        cli.max_wall_secs,
        None,
        user_file.max_wall_secs,
        default_budget.max_wall_secs,
    );
    let (workflow_tool_errors, workflow_tool_errors_origin) = cli
        .max_consecutive_tool_errors
        .map(|value| (value, config::ConfigOrigin::Cli))
        .unwrap_or((
            default_budget.max_consecutive_tool_errors,
            config::ConfigOrigin::Builtin,
        ));
    let workflow_budget = Budget {
        max_turns: workflow_max_turns,
        max_usd: workflow_max_usd,
        max_tokens: workflow_max_tokens,
        max_wall_secs: workflow_max_wall_secs,
        max_consecutive_tool_errors: workflow_tool_errors,
    };
    workflow_budget.validate().map_err(anyhow::Error::msg)?;
    let workflow_run_limits =
        runtime::governed_workflow_limits(&workflow_budget, iteron_workflow::RunLimits::default())
            .map_err(anyhow::Error::msg)?;
    if workflow_budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) && workflow_rate_card.is_none()
    {
        anyhow::bail!(
            "cannot enforce the requested workflow USD ceiling: the exact selected route has no active verified rate card. Use `iteron pricing print-digests` and `iteron pricing sign <card.json>` before retrying."
        );
    }
    if workflow_budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) {
        let pricing = workflow_pricing_port
            .as_ref()
            .expect("an active primary workflow rate card has a pricing authority");
        pricing.verify_rate_card(
            workflow_rate_card
                .as_ref()
                .expect("positive workflow USD ceiling checked the primary card above"),
        )?;
        // Every admitted fallback is a future physical-spend authority. Resolve all of them while
        // composition is still effect-free instead of discovering an unpriced route only after a
        // primary failure has already consumed money.
        for fallback in &fallback_provider_routes {
            let Some(card) = pricing.resolve_rate_card(&fallback.route, workflow_pricing_now)?
            else {
                anyhow::bail!(
                    "cannot enforce the requested workflow USD ceiling: fallback route `{}` has no active verified rate card",
                    fallback.id()
                );
            };
            pricing.verify_rate_card(&card)?;
        }
    }
    let (workflow_effort_text, workflow_effort_origin) = config::pick_with_origin(
        cli.effort.clone(),
        config::env_string("ITERON_EFFORT"),
        user_file.effort.clone(),
        crate::runtime_tunables::core_facts::EFFORT_CANONICAL.to_owned(),
    );
    let workflow_effort =
        iteron_protocol::Effort::parse(&workflow_effort_text).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown effort `{workflow_effort_text}` (low|medium|high|xhigh|max|ultracode)"
            )
        })?;
    let retry_environment = config::load_retry_environment().map_err(anyhow::Error::msg)?;
    let retry_resolution =
        config::resolve_retry_policy(retry_environment, user_file.retry.as_ref(), None)
            .map_err(anyhow::Error::msg)?;
    let mut workflow_compaction = iteron_ctx::CompactionPolicy::default();
    let workflow_compaction_owner = if let Some(trigger) = user_file.compaction_trigger_tokens {
        workflow_compaction.set_fixed_trigger_tokens(trigger);
        runtime_tunables::core_facts::CompactionOwner::UserFixed
    } else {
        runtime_tunables::core_facts::CompactionOwner::AdaptiveDefault
    };
    let runtime_plugins = plugin_runtime::RuntimePlugins::load(
        config::config_home()
            .map(|home| iteron_protocol::home::path(&home, "plugins"))
            .as_deref(),
        iteron_protocol::capability_set::CapabilitySet::from_iter_capabilities([
            iteron_protocol::Capability::ReadOnly,
        ]),
        None,
    )?;
    let workflow_agent_catalog = discover_agent_catalog(repo, &runtime_plugins.agents);
    // Standalone workflow children have no MCP process/session owner and a read-only registry.
    // Do not activate MCP families merely because operator/plugin configuration exists on this
    // machine; the interactive session path composes those servers with its real McpRuntime.
    let workflow_registry = Registry::read_only(repo.to_path_buf())?;
    let workflow_rules = initial_permission_rules(false);
    let workflow_authority =
        iteron_protocol::capability_set::CapabilitySet::from_iter_capabilities([
            iteron_protocol::Capability::ReadOnly,
        ]);
    let provider_controls_capabilities = provider_arc.control_capabilities();
    let base_url_origin = if configured_providers
        .iter()
        .any(|provider| provider.id == selection.provider_id)
    {
        config::ConfigOrigin::UserConfig
    } else {
        config::ConfigOrigin::Builtin
    };
    let model_origin = requested_model_with_origin
        .as_ref()
        .map(|(_, origin)| *origin)
        .unwrap_or(config::ConfigOrigin::Builtin);
    let provider_governor_configured = user_file.provider_governor.is_some();
    let (tunables_checkpoint, effective_settings, workflow_spawn_ledger) = match (
        resumed_tunables_checkpoint.clone(),
        resumed_effective_settings.clone(),
    ) {
        (Some(checkpoint), Some(settings)) => {
            let ledger = std::sync::Arc::new(
                runtime::SessionSpawnLedger::new(settings.session_spawn_cap)
                    .map_err(anyhow::Error::msg)?,
            );
            (checkpoint, settings, ledger)
        }
        (None, None) => {
            let fresh = runtime_tunables::composition::resolve_fresh(
                runtime_tunables::composition::FreshCompositionInput {
                    tunables_profile: None,
                    directory: &provider_directory,
                    selection: &selection,
                    model_capabilities: &caps,
                    catalog_digest: &catalog_digest,
                    capability_digest: &capability_digest,
                    registry: &workflow_registry,
                    agent_spawn_available: true,
                    configured_mcp: &[],
                    agent_catalog: &workflow_agent_catalog,
                    profile: runtime_profile,
                    tenant: &TenantId::default(),
                    benchmark_scope: cli.benchmark_attempt_scope.as_deref(),
                    workspace: repo,
                    environment: None,
                    operator_prompt: None,
                    // Standalone workflow children do not execute operator lifecycle hooks. Their
                    // immutable checkpoint therefore records the exact empty runtime owner rather
                    // than claiming that merely configured hooks are installed here.
                    hooks_catalog: None,
                    app_server_active: false,
                    provider_origin,
                    model_origin,
                    base_url: runtime_tunables::core_facts::Sourced {
                        value: &selected_api_root,
                        origin: base_url_origin,
                    },
                    effort: runtime_tunables::core_facts::Sourced {
                        value: workflow_effort,
                        origin: workflow_effort_origin,
                    },
                    budget: &workflow_budget,
                    budget_origins: runtime_tunables::core_facts::BudgetOrigins {
                        max_turns: workflow_max_turns_origin,
                        max_usd: workflow_max_usd_origin,
                        max_tokens: workflow_max_tokens_origin,
                        max_wall_secs: workflow_max_wall_secs_origin,
                        max_consecutive_tool_errors: workflow_tool_errors_origin,
                    },
                    allow_code: runtime_tunables::core_facts::Sourced {
                        value: false,
                        // The standalone workflow CLI selects a fixed read-only posture. This is
                        // an operator-owned tightening, not a second built-in default.
                        origin: config::ConfigOrigin::Cli,
                    },
                    permission_mode: runtime_tunables::core_facts::Sourced {
                        value: iteron_protocol::PermissionMode::Plan,
                        origin: config::ConfigOrigin::Cli,
                    },
                    permission_rules_origin: None,
                    permission_rules: &workflow_rules,
                    bypass_permissions: runtime_tunables::core_facts::Sourced {
                        value: false,
                        origin: config::ConfigOrigin::Cli,
                    },
                    compaction: &workflow_compaction,
                    compaction_owner: workflow_compaction_owner,
                    retry: &retry_resolution.policy,
                    retry_origins: runtime_tunables::core_facts::RetryOrigins {
                        base_ms: retry_resolution.base_origin,
                        cap_ms: retry_resolution.cap_origin,
                        max_attempts: retry_resolution.max_attempts_origin,
                    },
                    verify_command: None,
                    verification_config: user_file.verification.as_ref(),
                    memory_enabled: runtime_tunables::core_facts::Sourced {
                        value: false,
                        origin: config::ConfigOrigin::Cli,
                    },
                    tenant_allows_memory: false,
                    prompt_cache_enabled,
                    provider_governor: &provider_governor,
                    provider_governor_configured,
                    provider_control_capabilities: &provider_controls_capabilities,
                    authority_ceiling: workflow_authority,
                    run_limits: workflow_run_limits,
                    operator_egress_allow: user_file.egress_allow.as_deref(),
                    project_egress_allow: None,
                },
            )?;
            let snapshot = iteron_record::snapshot_v2_from_resolved(&fresh.resolved)?;
            (
                iteron_record::TunablesCheckpoint::V2(snapshot),
                fresh.settings,
                fresh.session_spawn_ledger,
            )
        }
        _ => anyhow::bail!("workflow runtime checkpoint/settings state is inconsistent"),
    };
    effective_settings
        .session_isolation
        .admit_continuation(resume_from.is_some(), false)?;

    let meta = iteron_workflow::extract_meta(&src);
    let name = meta
        .as_ref()
        .and_then(|meta| meta.name.clone())
        .unwrap_or_else(|| "workflow".into());
    // The declared phases seed the live tree's layout; reading only `name`/`description` here is
    // what left the parsed `meta.phases` unused.
    let declared_phases = meta
        .as_ref()
        .and_then(|meta| meta.phases.clone())
        .unwrap_or_default();
    eprintln!(
        "workflow \u{b7} repo={} \u{b7} provider={} \u{b7} model={} \u{b7} run={run_id}",
        repo.display(),
        selection.provider_id,
        model
    );
    if let Some(meta) = &meta {
        match meta.description.as_deref() {
            Some(desc) if !desc.is_empty() => eprintln!("summary: {name} - {desc}"),
            _ => eprintln!("summary: {name}"),
        }
    }
    eprintln!("{}", "-".repeat(72));

    let spawner = build_workflow_spawner(
        provider_arc,
        model.clone(),
        &selection,
        catalog_digest,
        capability_digest,
        &caps,
        effective_settings.provider_governor.clone(),
        fallback_provider_routes,
        workflow_pricing_port,
        user_file.unknown.get("otel"),
        repo,
        &runs_dir,
        &run_id,
        &name,
        compiled_policy_bundle.clone(),
        &runtime_plugins,
        tunables_checkpoint.clone(),
        &effective_settings,
        workflow_spawn_ledger,
    )?;

    // Persist the re-launchable inputs for a FRESH run BEFORE it starts (a crash still leaves a
    // resumable record). Resume/Watch reuse the existing sidecars.
    if resume_from.is_none() {
        workflow::persist_policy_checkpoint(
            &workflows_dir,
            &run_id,
            compiled_policy_bundle.genesis_snapshot(),
        )?;
        workflow::persist_tunables_checkpoint(&workflows_dir, &run_id, &tunables_checkpoint)?;
        let manifest = workflow::RunManifest {
            run_id: run_id.clone(),
            name: name.clone(),
            args: args_value.clone(),
            provider_id: selection.provider_id.clone(),
            model: model.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.main.unix_secs_on_unusable_clock",
                    UNIX_SECS_ON_UNUSABLE_CLOCK,
                )),
        };
        workflow::persist_inputs(&workflows_dir, &manifest, &src)?;
    }

    // Assemble the persisted RunSpec (journal under `<workflows_dir>/<run_id>/journal.jsonl`).
    let effective_run_limits = iteron_workflow::RunLimits::new(
        effective_settings.execution.workflow.max_concurrency,
        effective_settings.execution.workflow.max_calls,
    )
    .map_err(anyhow::Error::msg)?;
    let mut spec = iteron_workflow::RunSpec::new(src.clone())
        .with_args(args_value.clone())
        .with_run_id(iteron_workflow::RunId::new(run_id.clone()))
        .with_workflows_dir(workflows_dir.clone())
        .with_limits(effective_run_limits)
        .with_early_stop_quorum(effective_settings.execution.early_stop_quorum)
        .with_speculative_siblings(effective_settings.execution.speculative_siblings)
        .with_task_retry(effective_settings.execution.task_retry)
        .with_schema_retry(effective_settings.execution.schema_retry);
    if let Some(prior) = &resume_from {
        spec = spec.with_resume_from(iteron_workflow::RunId::new(prior.clone()));
    }

    let is_watch = matches!(action, WorkflowAction::Watch { .. });
    let tty = std::io::stdout().is_terminal();

    // TTY → the live phase→agent tree (design §3.3); pipe/CI → the plain per-line renderer (§3.5).
    // `watch` uses the background `launch`→`RunHandle` path; `run`/`resume` use the blocking `execute`.
    let report = if tty {
        let environment = theme::capabilities::Environment::capture();
        let detected = theme::Theme::detect_with(environment, None);
        if is_watch {
            workflow::watch_live(spec, spawner, &name, &declared_phases, &detected.theme).await?
        } else {
            workflow::run_live(spec, spawner, &name, &declared_phases, &detected.theme).await?
        }
    } else {
        let sink: std::sync::Arc<dyn iteron_workflow::ProgressSink> =
            std::sync::Arc::new(workflow::StdoutProgressSink::new());
        let report = if is_watch {
            let handle = iteron_workflow::WorkflowEngine::launch(spec, spawner, sink);
            handle.join().await?
        } else {
            iteron_workflow::WorkflowEngine::execute(spec, spawner, sink).await?
        };
        eprintln!("{}", "-".repeat(72));
        report
    };

    // Record the terminal outcome (enables `list` status + shows the value to a later reader).
    workflow::persist_result(&workflows_dir, &run_id, &report)?;
    eprintln!("{}", workflow::final_status_line(&run_id, &report));

    println!("{}", serde_json::to_string_pretty(&report.value)?);
    // The exit status is a machine contract: clean, partially/all failed, and cancelled workflows
    // must remain distinguishable without parsing the human transcript.
    Ok(workflow::run_exit_code(&report))
}

pub(crate) fn parse_workflow_args(args: &Option<String>) -> anyhow::Result<serde_json::Value> {
    match args {
        Some(text) => serde_json::from_str(text)
            .map_err(|error| anyhow::anyhow!("--args is not valid JSON: {error}")),
        None => Ok(serde_json::Value::Null),
    }
}

//! Installed tool and extension assembly from trusted operator sources.
//! The result owns its registry and MCP supervisor; project sources cannot mint executable authority.
use super::Cli;
use crate::config::FileConfig;
use crate::{config, mcp, plugin_runtime, pricing, startup};
use iteron_tools::Registry;

pub(crate) struct ToolBootstrap {
    pub(crate) user_file: FileConfig,
    pub(crate) registry: Registry,
    pub(crate) runtime_plugins: plugin_runtime::RuntimePlugins,
    pub(crate) completion_notifications: config::CompletionNotificationResolution,
    pub(crate) retry_resolution: config::RetryResolution,
    pub(crate) pricing_key_env_names: Vec<String>,
    pub(crate) configured_mcp: Vec<config::McpServerConfig>,
    pub(crate) mcp_runtime: mcp::McpRuntimeControl,
    pub(crate) config_warnings: Vec<String>,
}
pub(crate) fn assemble(
    cli: &Cli,
    repo: &std::path::Path,
    file: &FileConfig,
    plantcore_serve: bool,
    startup: &mut startup::StartupTiming,
) -> anyhow::Result<ToolBootstrap> {
    // Wire configured MCP servers (P4): connect each, discover its tools, and register them so
    // the model can call them. Configuring a server is the operator's consent to run it; its
    // tool descriptions are still treated as untrusted (scanned) by the mcp client. The mcp client
    // classifies every discovered tool as the MOST-RESTRICTIVE `IrreversibleExternal` (an MCP tool
    // can reach the network / external services). We KEEP that classification — a security review
    // found that downgrading it to CodeExecuting let `--allow-code`/Yolo auto-run genuinely external,
    // un-sandboxed MCP tools, defeating the invariant-#5 carve-out. So MCP tools always prompt per
    // call (the gate never auto-approves IrreversibleExternal, any mode).
    // SECURITY (trust-by-origin, same rule as hooks): MCP servers spawn a subprocess at startup, so
    // they are loaded ONLY from the USER config `~/.iteron/config.json` — NEVER from the repo's
    // `.iteron/config.json`. Otherwise cloning a hostile repo that ships an `mcp_servers` block would be
    // RCE the moment `iteron` runs there. A project config that declares servers is ignored (with a warning).
    if file.mcp_servers.as_ref().is_some_and(|s| !s.is_empty()) {
        eprintln!(
            "warning: ignoring `mcp_servers` in the project config (untrusted origin); declare MCP servers in ~/.iteron/config.json"
        );
    }
    if file
        .providers
        .as_ref()
        .is_some_and(|providers| !providers.is_empty())
    {
        eprintln!(
            "warning: ignoring `providers` in the project config (untrusted origin); declare provider instances in ~/.iteron/config.json"
        );
    }
    if file
        .provider
        .as_ref()
        .is_some_and(|provider| !provider.trim().is_empty())
    {
        eprintln!(
            "warning: ignoring `provider` in the project config (untrusted origin); choose it with --provider, ITERON_PROVIDER, or ~/.iteron/config.json"
        );
    }
    if file
        .base_url
        .as_ref()
        .is_some_and(|base_url| !base_url.trim().is_empty())
    {
        eprintln!(
            "warning: ignoring `base_url` in the project config (untrusted origin); choose the endpoint with --base-url, ITERON_BASE_URL, or ~/.iteron/config.json"
        );
    }
    if file.allow_code == Some(true) {
        eprintln!(
            "warning: ignoring `allow_code` in the project config (untrusted origin); only --allow-code or ~/.iteron/config.json may grant code execution"
        );
    }
    if file.effort.is_some() {
        eprintln!(
            "warning: ignoring `effort` in the project config (untrusted origin); use --effort, ITERON_EFFORT, or ~/.iteron/config.json"
        );
    }
    if file.model.is_some() {
        eprintln!(
            "warning: ignoring `model` in the project config (untrusted origin); choose it with --model, ITERON_MODEL, or ~/.iteron/config.json"
        );
    }
    if file.compaction_trigger_tokens.is_some() {
        eprintln!(
            "warning: ignoring `compaction_trigger_tokens` in the project config (untrusted origin); configure it in ~/.iteron/config.json"
        );
    }
    if file
        .rate_cards
        .as_ref()
        .is_some_and(|rate_cards| !rate_cards.is_empty())
    {
        eprintln!(
            "warning: ignoring `rate_cards` in the project config (untrusted origin); declare signed rate cards in ~/.iteron/config.json"
        );
    }
    if file.active_policy_bundle.is_some() {
        eprintln!(
            "warning: ignoring `active_policy_bundle` in the project config (untrusted origin); select promoted policy identities in ~/.iteron/config.json"
        );
    }
    let (user_file, user_warnings) = FileConfig::load_user_with_warnings()?;
    let config_warnings = user_warnings;
    if plantcore_serve
        && (cli.implementation_candidate.is_some() || cli.implementation_candidate_digest.is_some())
    {
        anyhow::bail!("PlantCore resident mode does not admit implementation plugins");
    }
    let implementation_candidate = match (
        cli.implementation_candidate.as_deref(),
        cli.implementation_candidate_digest.as_deref(),
    ) {
        (Some(path), Some(digest)) => Some(plugin_runtime::CandidateFile::read(path, digest)?),
        (None, None) => None,
        _ => unreachable!("clap requires the external implementation arguments as a pair"),
    };
    let plugin_host_ceiling =
        iteron_protocol::capability_set::CapabilitySet::from_iter_capabilities([
            iteron_protocol::Capability::ReadOnly,
            iteron_protocol::Capability::ReversibleLocal,
            iteron_protocol::Capability::CodeExecuting,
            iteron_protocol::Capability::TrustMutating,
            iteron_protocol::Capability::IrreversibleExternal,
        ]);
    let mut runtime_plugins = if plantcore_serve {
        plugin_runtime::RuntimePlugins::default()
    } else if let Some(candidate) = implementation_candidate {
        // Research activation is intentionally independent of HOME, ITERON_CONFIG_HOME, and the
        // installed plugin store. The paired CLI path/digest is its operator-intent boundary.
        plugin_runtime::RuntimePlugins::research(candidate, plugin_host_ceiling)?
    } else {
        let plugin_store_root =
            config::config_home().map(|home| iteron_protocol::home::path(&home, "plugins"));
        plugin_runtime::RuntimePlugins::load(
            plugin_store_root.as_deref(),
            plugin_host_ceiling,
            None,
        )?
    };
    for diagnostic in &runtime_plugins.diagnostics {
        eprintln!("{diagnostic}");
    }
    let lsp_routes = runtime_plugins
        .lsp_routes
        .drain(..)
        .map(|route| iteron_tools::LanguageServerRoute {
            language: route.language,
            command: route.command,
        })
        .collect();
    let mut registry = Registry::coding_agent_with_lsp_routes(&repo, lsp_routes)?;
    install_browser(
        &mut registry,
        cli.browser_webdriver.as_deref(),
        &cli.browser_origin,
        plantcore_serve,
    )?;
    let completion_notifications = config::resolve_completion_notifications(
        user_file.completion_notifications,
        file.completion_notifications,
    );
    if completion_notifications.project_ignored {
        eprintln!(
            "warning: ignoring `completion_notifications` in the project config (untrusted origin); configure terminal notifications in ~/.iteron/config.json"
        );
    }
    if file.prompt_history.is_some() {
        eprintln!(
            "warning: ignoring `prompt_history` in the project config (untrusted origin); configure prompt retention in ~/.iteron/config.json"
        );
    }
    if file.tui_keymap.is_some() || file.external_editor.is_some() {
        eprintln!(
            "warning: ignoring `tui_keymap`/`external_editor` in the project config (untrusted origin); configure terminal input in ~/.iteron/config.json"
        );
    }
    // Retry tuning is resolved at the composition root with project input structurally ignored.
    // The kernel applies it around individually journaled physical attempts; opaque provider-side
    // retry decorators remain refused because their hidden attempts cannot cross our WAL boundary.
    let retry_environment = config::load_retry_environment().map_err(anyhow::Error::msg)?;
    let retry_resolution = config::resolve_retry_policy(
        retry_environment,
        user_file.retry.as_ref(),
        file.retry.as_ref(),
    )
    .map_err(anyhow::Error::msg)?;
    if retry_resolution.project_ignored {
        eprintln!(
            "warning: ignoring `retry` in the project config (untrusted origin); retry timing and paid-attempt count are operator-owned policy"
        );
    }
    if retry_resolution.trusted_override_present {
        eprintln!(
            "retry policy: base_ms={} cap_ms={} max_attempts={} (every physical attempt is journaled)",
            retry_resolution.policy.base_ms,
            retry_resolution.policy.cap_ms,
            retry_resolution.policy.max_attempts,
        );
    }
    let pricing_key_env_names =
        pricing::key_env_names(user_file.rate_cards.as_deref().unwrap_or_default());
    startup.mark(startup::StartupPhase::Config);
    let mut configured_mcp = user_file.mcp_servers.clone().unwrap_or_default();
    for server in runtime_plugins.mcp_servers.drain(..) {
        if configured_mcp
            .iter()
            .any(|existing| existing.name == server.name)
        {
            eprintln!(
                "plugin MCP `{}` shadowed by the operator's explicit user configuration",
                server.name
            );
        } else {
            configured_mcp.push(server);
        }
    }
    let mcp_runtime =
        mcp::register_configured_servers(&mut registry, &configured_mcp, &pricing_key_env_names)?;
    startup.mark(startup::StartupPhase::ToolServer);

    Ok(ToolBootstrap {
        user_file,
        registry,
        runtime_plugins,
        completion_notifications,
        retry_resolution,
        pricing_key_env_names,
        configured_mcp,
        mcp_runtime,
        config_warnings,
    })
}

fn install_browser(
    registry: &mut Registry,
    endpoint: Option<&str>,
    origins: &[String],
    plantcore_serve: bool,
) -> anyhow::Result<()> {
    match (endpoint, origins.is_empty()) {
        (None, true) => Ok(()),
        (Some(endpoint), false) if !plantcore_serve => {
            let configuration =
                iteron_tools::browser::BrowserConfig::new(endpoint, origins.to_vec())
                    .map_err(anyhow::Error::msg)?;
            iteron_tools::browser::register(registry, configuration)?;
            Ok(())
        }
        (Some(_), _) if plantcore_serve => {
            anyhow::bail!("PlantCore recording mode does not admit browser/computer execution")
        }
        _ => anyhow::bail!(
            "browser requires an explicit local driver and at least one exact operator origin"
        ),
    }
}

pub(crate) fn load_project_config(
    repo: &std::path::Path,
    plantcore_serve: bool,
) -> anyhow::Result<(FileConfig, Vec<String>)> {
    if plantcore_serve {
        Ok((FileConfig::default(), Vec::new()))
    } else {
        FileConfig::load_with_warnings(repo)
    }
}

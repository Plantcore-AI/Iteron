//! Trusted launch policy resolution and frontend/profile validation before record creation.
use super::{Cli, LocalCommand, default_permission_mode, trusted_allow_code};
use crate::config::FileConfig;
use crate::{config, image_input, runtime_tunables, session_isolation};
use iteron_protocol::Budget;

pub(crate) fn validate_serve_listen(
    listen: std::net::SocketAddr,
    plantcore: bool,
) -> anyhow::Result<()> {
    if plantcore {
        let required = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        if listen != required {
            anyhow::bail!(
                "PlantCore App Server requires the ephemeral IPv4 loopback address {required}"
            );
        }
    } else if !listen.ip().is_loopback() {
        anyhow::bail!("headless App Server refuses non-loopback listen address {listen}");
    }
    Ok(())
}

pub(crate) struct ResolvedLaunchOptions {
    pub(crate) max_turns: u32,
    pub(crate) max_turns_origin: config::ConfigOrigin,
    pub(crate) max_usd: Option<f64>,
    pub(crate) max_usd_origin: Option<config::ConfigOrigin>,
    pub(crate) max_tokens: Option<u64>,
    pub(crate) max_tokens_origin: Option<config::ConfigOrigin>,
    pub(crate) max_wall_secs: u64,
    pub(crate) max_wall_secs_origin: config::ConfigOrigin,
    pub(crate) allow_code: bool,
    pub(crate) allow_code_origin: config::ConfigOrigin,
    pub(crate) effort_runtime_override: bool,
    pub(crate) resolved_effort: iteron_protocol::Effort,
    pub(crate) effort_origin: config::ConfigOrigin,
    pub(crate) headless_serve: bool,
    pub(crate) one_shot: bool,
    pub(crate) output_format: crate::output::OutputFormat,
    pub(crate) mode_runtime_override: bool,
    pub(crate) mode: iteron_protocol::PermissionMode,
    pub(crate) mode_origin: config::ConfigOrigin,
    pub(crate) one_shot_images: image_input::ImageAttachments,
    pub(crate) runtime_profile: iteron_tunables::RuntimeProfile,
}
pub(crate) fn resolve(
    cli: &Cli,
    file: &FileConfig,
    user_file: &FileConfig,
) -> anyhow::Result<ResolvedLaunchOptions> {
    // Keep the CLI fallback identical to the protocol owner so interactive budget policy has one
    // default and repository/user configuration can only tighten or explicitly override it.
    let trusted_max_turns = config::pick_with_origin(
        cli.max_turns,
        config::env_turn_limit(),
        user_file.max_turns,
        Budget::default().max_turns,
    );
    let (max_turns, max_turns_origin) =
        config::tighten_with_origin(file.max_turns, trusted_max_turns);
    let trusted_max_usd = config::pick_optional_with_origin(
        cli.max_usd,
        config::env_f64("ITERON_MAX_USD"),
        user_file.max_usd,
    );
    let max_usd_with_origin = config::tighten_optional_with_origin(file.max_usd, trusted_max_usd);
    let (max_usd, max_usd_origin) = max_usd_with_origin
        .map(|(value, origin)| (Some(value), Some(origin)))
        .unwrap_or((None, None));
    let max_tokens = cli.max_tokens;
    let max_tokens_origin = max_tokens.map(|_| config::ConfigOrigin::Cli);
    let trusted_max_wall_secs = config::pick_with_origin(
        cli.max_wall_secs,
        None,
        user_file.max_wall_secs,
        Budget::default().max_wall_secs,
    );
    let (max_wall_secs, max_wall_secs_origin) =
        config::tighten_with_origin(file.max_wall_secs, trusted_max_wall_secs);
    // Grant-by-default (owner-directed 2026-08-05; README, SECURITY.md and
    // docs/using/permissions-and-sandbox.md are updated to state it): code execution is ON until an
    // operator-owned source turns it off. A cloned repository is still not an authorization
    // principal — a project `allow_code:false` may TIGHTEN this off and `--mode plan` hard-disables
    // it, while a project `true` stays inert.
    let trusted_allow_code = (
        trusted_allow_code(cli.allow_code, user_file.allow_code),
        if cli.allow_code {
            config::ConfigOrigin::Cli
        } else if user_file.allow_code.is_some() {
            config::ConfigOrigin::UserConfig
        } else {
            config::ConfigOrigin::Builtin
        },
    );
    let (allow_code, allow_code_origin) =
        config::tighten_grant_with_origin(file.allow_code, trusted_allow_code);

    // ---- Validate ALL purely-local arguments BEFORE opening the rollout ----
    // A rejected --verify/--effort/--mode (or a no-terminal TUI attempt) must not leave a
    // genesis-less orphan .jsonl on disk (review MEDIUM: these bailed AFTER `Rollout::open` created
    // the file, polluting `--sessions` with phantom untitled rows and poisoning `--continue`).
    // Nothing here reads the rollout or the agent.
    if cli.verify.is_some() && !allow_code {
        anyhow::bail!("--verify runs a command and requires code execution to be enabled");
    }
    // The file config already rejects a zero here; the flag must not be the one path that admits a
    // ceiling every submission breaches before its first provider call.
    if cli.max_wall_secs == Some(0) {
        anyhow::bail!("--max-wall-secs must be >= 1");
    }
    let env_effort = config::env_string("ITERON_EFFORT");
    let effort_runtime_override = cli.effort.is_some() || env_effort.is_some();
    let (effort_value, effort_origin) = config::pick_with_origin(
        cli.effort.clone(),
        env_effort,
        user_file.effort.clone(),
        crate::runtime_tunables::core_facts::EFFORT_CANONICAL.to_string(),
    );
    let resolved_effort = iteron_protocol::Effort::parse(&effort_value).ok_or_else(|| {
        anyhow::anyhow!("unknown effort `{effort_value}` (low|medium|high|xhigh|max|ultracode)")
    })?;
    use std::io::IsTerminal;
    let has_tty = std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
    let headless_serve = matches!(cli.command.as_ref(), Some(LocalCommand::Serve { .. }));
    if let Some(LocalCommand::Serve {
        listen, plantcore, ..
    }) = &cli.command
    {
        validate_serve_listen(*listen, *plantcore)?;
    }
    // One-shot only with -p/--print (which requires a task), or when there is no TTY and a task was
    // given (pipeline use). Otherwise the interactive TUI is the default (user: 默认 TUI 打开).
    let one_shot = cli.print || (!has_tty && cli.task.is_some() && !cli.tui);
    let output_format = cli.output_format;
    if output_format.is_machine() && !one_shot {
        anyhow::bail!(
            "--output-format is a one-shot option; pass -p/--print with a task (or omit it for the TUI)"
        );
    }
    // Explicit --mode wins. Fresh ordinary sessions default to bypass; --ask-permissions and
    // Plan tighten it below. A noninteractive Ask still fails closed.
    let mode_runtime_override = cli.mode.is_some() || cli.ask_permissions;
    let (mode, mode_origin) = match cli.mode.as_deref() {
        Some(s) => (
            iteron_protocol::PermissionMode::parse(s).ok_or_else(|| {
                anyhow::anyhow!("unknown --mode `{s}` (default|acceptEdits|plan|yolo)")
            })?,
            config::ConfigOrigin::Cli,
        ),
        None => {
            let default_mode = default_permission_mode(cli.ask_permissions);
            (
                default_mode,
                if cli.ask_permissions {
                    config::ConfigOrigin::Cli
                } else {
                    config::ConfigOrigin::Builtin
                },
            )
        }
    };
    // A no-terminal invocation that is NOT one-shot would fall into the interactive TUI and die in
    // raw-mode setup with a cryptic OS error (review LOW). Fail clearly, before opening a rollout.
    if !one_shot && !has_tty && !headless_serve {
        anyhow::bail!(
            "no interactive terminal detected; pass -p \"<task>\" for non-interactive use, or run in a terminal for the TUI"
        );
    }
    // `-p/--print` requires a task. Validate it HERE, before `Rollout::open` — else `iteron -p`
    // (no task) writes a genesis-bearing orphan before bailing, which (unlike the empty-cwd orphans)
    // matches `most_recent`'s cwd filter and silently poisons a later `--continue` (convergence
    // review: Fix 2 was incomplete — this was the one local validation still left after open).
    if one_shot && cli.task.is_none() {
        anyhow::bail!("-p/--print requires a task; omit -p to open the interactive TUI");
    }
    if !cli.images.is_empty() && !one_shot {
        anyhow::bail!("--image is a one-shot option; pass -p/--print with a task");
    }
    let mut one_shot_images = image_input::ImageAttachments::default();
    for path in &cli.images {
        one_shot_images.attach_path(path)?;
    }
    let runtime_profile = cli
        .harness_profile
        .map(iteron_tunables::RuntimeProfile::from)
        .unwrap_or_else(|| {
            if cli.benchmark_attempt_scope.is_some() {
                iteron_tunables::RuntimeProfile::Benchmark
            } else {
                iteron_tunables::RuntimeProfile::Interactive
            }
        });
    if runtime_profile == iteron_tunables::RuntimeProfile::Benchmark
        && cli.benchmark_attempt_scope.is_none()
    {
        anyhow::bail!("--harness-profile benchmark requires --benchmark-attempt-scope");
    }
    if runtime_profile != iteron_tunables::RuntimeProfile::Benchmark
        && cli.benchmark_attempt_scope.is_some()
    {
        anyhow::bail!(
            "--benchmark-attempt-scope requires the benchmark harness profile; omit --harness-profile or select benchmark"
        );
    }
    session_isolation::SessionIsolationPolicy::from_runtime_profile(runtime_profile)
        .admit_continuation(cli.resume.is_some(), cli.continue_recent)?;

    Ok(ResolvedLaunchOptions {
        max_turns,
        max_turns_origin,
        max_usd,
        max_usd_origin,
        max_tokens,
        max_tokens_origin,
        max_wall_secs,
        max_wall_secs_origin,
        allow_code,
        allow_code_origin,
        effort_runtime_override,
        resolved_effort,
        effort_origin,
        headless_serve,
        one_shot,
        output_format,
        mode_runtime_override,
        mode,
        mode_origin,
        one_shot_images,
        runtime_profile,
    })
}

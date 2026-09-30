//! Local machine/workspace commands route before provider and tool-server initialization.
use super::{
    AuthAction, BUILD_COMMIT, BUILD_DATE, Cli, ConfigAction, LocalCommand, print_timeline,
    run_pricing_command, run_prune_command, run_record_command, run_workflow_command,
};
use crate::config::FileConfig;
use crate::{config, maintenance, mcp, output, plugin, session_view, setup, tunables};
use iteron_protocol::{RunId, TenantId};

pub(crate) async fn machine(cli: &Cli) -> anyhow::Result<Option<u8>> {
    let code = match &cli.command {
        Some(LocalCommand::Setup {
            plan,
            byok,
            provider,
            stdin,
            expires_at,
        }) => {
            let kind = match (plan, byok) {
                (true, _) => Some(setup::SetupKind::HostedPlan),
                (false, Some(_)) => Some(setup::SetupKind::Byok),
                (false, None) => None,
            };
            Some(
                setup::run_setup(setup::SetupRequest {
                    kind,
                    provider_id: byok.clone().or_else(|| provider.clone()),
                    read_credential_from_stdin: *stdin,
                    expires_at_unix: *expires_at,
                })
                .await?,
            )
        }
        Some(LocalCommand::Auth { action }) => Some(match action {
            AuthAction::Status { provider } => setup::run_auth_status(provider.clone()).await?,
            AuthAction::Logout { provider } => setup::run_auth_logout(provider.clone()).await?,
        }),
        Some(LocalCommand::Config { action }) => match action {
            ConfigAction::Get { key } => Some(setup::run_config_get(key.clone())?),
            ConfigAction::Set { key, value } => Some(setup::run_config_set(key, value)?),
            ConfigAction::Explain { effective, .. } if !effective => {
                anyhow::bail!("`iteron config explain` requires --effective")
            }
            ConfigAction::Explain { .. } => None,
        },
        Some(LocalCommand::Tunables { action }) => Some(tunables::run(action)?),
        Some(LocalCommand::Plugin { action }) => {
            let home = config::config_home()
                .ok_or_else(|| anyhow::anyhow!("cannot resolve the operator config root"))?;
            Some(plugin::run(
                action,
                &iteron_protocol::home::path(&home, "plugins"),
            )?)
        }
        Some(LocalCommand::Mcp { action }) => Some(mcp::commands::run(action).await?),
        _ => None,
    };
    Ok(code)
}

pub(crate) async fn workspace(
    cli: &Cli,
    repo: &std::path::Path,
    runs_dir: &std::path::Path,
) -> anyhow::Result<Option<u8>> {
    if let Some(LocalCommand::Record { action }) = &cli.command {
        return run_record_command(&runs_dir, action).map(Some);
    }

    if matches!(cli.command, Some(LocalCommand::Reindex)) {
        let count = iteron_record::reindex(&runs_dir)?;
        println!(
            "reindexed {count} session{} in {}",
            if count == 1 { "" } else { "s" },
            runs_dir.display()
        );
        return Ok(Some(output::EXIT_SUCCESS));
    }

    if let Some(LocalCommand::Prune {
        older_than_days,
        keep_last,
        dry_run,
    }) = &cli.command
    {
        return run_prune_command(&runs_dir, *older_than_days, *keep_last, *dry_run).map(Some);
    }

    // `iteron workflow run <script.js>` — runs the ultracode-workflow engine directly. It needs a
    // provider but none of the rollout/agent/genesis machinery, so it branches out before that setup.
    if let Some(LocalCommand::Workflow { action }) = &cli.command {
        let user_file = FileConfig::load_user()?;
        return run_workflow_command(&cli, &repo, &user_file, action)
            .await
            .map(Some);
    }

    // `iteron pricing …` — operator tooling. It opens no rollout and admits no provider effect, so
    // it branches out before the agent machinery exactly like `workflow` does.
    if let Some(LocalCommand::Pricing { action }) = &cli.command {
        let user_file = FileConfig::load_user()?;
        return run_pricing_command(&cli, &user_file, action)
            .await
            .map(Some);
    }

    if matches!(cli.command, Some(LocalCommand::Doctor)) {
        return maintenance::run_doctor(
            &repo,
            &runs_dir,
            iteron_tunables::param_str("cli.main.build_commit", BUILD_COMMIT),
            iteron_tunables::param_str("cli.main.build_date", BUILD_DATE),
        )
        .map(Some);
    }
    if let Some(LocalCommand::Support {
        output: support_output,
    }) = &cli.command
    {
        return maintenance::run_support(
            &repo,
            &runs_dir,
            support_output.as_deref(),
            iteron_tunables::param_str("cli.main.build_commit", BUILD_COMMIT),
            iteron_tunables::param_str("cli.main.build_date", BUILD_DATE),
        )
        .await
        .map(Some);
    }

    Ok(None)
}

pub(crate) fn history(
    cli: &Cli,
    repo: &std::path::Path,
    runs_dir: &std::path::Path,
    tenant: &TenantId,
    machine_schema_version: u32,
) -> anyhow::Result<Option<u8>> {
    // Purely-local, read-only rollout subcommands exit BEFORE we construct a provider or connect any
    // MCP server — listing or forking the append-only record needs no API key and must not spawn MCP
    // subprocesses or print connection noise (review: `iteron --sessions` failed with "no api key"
    // and eagerly started MCP servers, though it never touches the model).
    if let Some(run) = cli.otel_export.clone() {
        let run = iteron_protocol::RunId(run);
        let timed = iteron_record::replay_run_timed(runs_dir, &run)?;
        let events: Vec<&iteron_protocol::Event> = timed.iter().map(|entry| &entry.event).collect();
        let timeline = iteron_obs::timeline::fold(timed.iter().map(|e| (e.ts_us, &e.event)));
        let payload = iteron_obs::otel::project(&run.0, &events, &timeline);
        println!("{}", serde_json::to_string(&payload)?);
        if payload.dropped > 0 {
            eprintln!("{} span(s) dropped at the payload bound", payload.dropped);
        }
        return Ok(Some(output::EXIT_SUCCESS));
    }

    if let Some(run) = cli.timeline.clone() {
        let run = iteron_protocol::RunId(run);
        let timed = iteron_record::replay_run_timed(&runs_dir, &run)?;
        let report = iteron_obs::timeline::fold(timed.iter().map(|t| (t.ts_us, &t.event)));
        if cli.output_format.is_machine() {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            print_timeline(&run, &report);
        }
        return Ok(Some(output::EXIT_SUCCESS));
    }

    if let Some(run) = cli.transcript.clone() {
        let run = iteron_protocol::RunId(run);
        if cli.output_schema_version.is_some() {
            let page = session_view::read_transcript_page(
                &runs_dir,
                &run,
                cli.transcript_cursor.as_deref(),
                machine_schema_version,
            )?;
            println!("{}", serde_json::to_string(&page)?);
            return Ok(Some(output::EXIT_SUCCESS));
        }
        // Name the run AND the file the read failed on, the way `--fork` already does. Propagating
        // the `RecordError` unchanged printed `io: <errno text>: <errno text>` — the `#[from]` source
        // repeated by anyhow's alternate Display — with nothing a reader could act on.
        let document = session_view::read_transcript(&runs_dir, &run).map_err(|error| {
            anyhow::anyhow!(
                "cannot read run {run} at {}: {error}",
                runs_dir.join(format!("{run}.jsonl")).display()
            )
        })?;
        if cli.output_format.is_machine() {
            println!("{}", serde_json::to_string(&document)?);
        } else {
            eprintln!(
                "{}: {} event(s){}",
                document.run_id,
                document.total_events,
                if document.truncated {
                    " (truncated at the byte ceiling)"
                } else {
                    ""
                }
            );
            for event in &document.events {
                println!("{event}");
            }
        }
        return Ok(Some(output::EXIT_SUCCESS));
    }
    if cli.sessions {
        if cli.output_schema_version.is_some() {
            let page = session_view::list_sessions_page(
                &runs_dir,
                &tenant,
                cli.agent_definition_tag.as_deref(),
                cli.session_limit,
                cli.session_cursor.as_deref(),
                machine_schema_version,
            )?;
            println!("{}", serde_json::to_string(&page)?);
            return Ok(Some(output::EXIT_SUCCESS));
        }
        // `--sessions` says "in this repo" and now means it: the same recorded-cwd scope
        // `--continue` selects on. The listing is also a page, not a linear dump — the runs dir
        // grows without bound and had no ceiling on this path at all.
        let limit = cli.limit.unwrap_or(session_view::MAX_SESSIONS_PER_PAGE);
        if cli.output_format.is_machine() {
            let document = session_view::list_sessions(&runs_dir, &tenant, Some(&repo), limit)?;
            println!("{}", serde_json::to_string(&document)?);
            return Ok(Some(output::EXIT_SUCCESS));
        }
        let page = session_view::list_session_metas(&runs_dir, &tenant, Some(&repo), limit)?;
        if page.sessions.is_empty() {
            eprintln!(
                "no sessions for {} in {}",
                repo.display(),
                runs_dir.display()
            );
        } else {
            for m in &page.sessions {
                let route = if m.provider_id.is_empty() {
                    m.model.clone()
                } else {
                    format!("{}:{}", m.provider_id, m.model)
                };
                let cost = match m.cost_usd() {
                    Some(value) => format!("${value:.4}"),
                    None => "cost=unknown".into(),
                };
                println!(
                    "{}  turns={:<3} model={}  {}  {}",
                    m.run_id, m.turns, route, cost, m.title
                );
            }
            if page.has_more {
                eprintln!(
                    "page showing the {limit} most recent sessions; raise --limit or run `iteron prune`"
                );
            }
        }
        return Ok(Some(output::EXIT_SUCCESS));
    }
    if let Some(pid) = cli.fork.clone() {
        let parent = RunId(pid.clone());
        let ppath = runs_dir.join(format!("{parent}.jsonl"));
        let events = iteron_record::replay(&ppath)
            .map_err(|e| anyhow::anyhow!("cannot read run {pid}: {e}"))?;
        let at = events
            .last()
            .map(|e| e.seq)
            .ok_or_else(|| anyhow::anyhow!("run {pid} has no events to fork from"))?;
        let child = iteron_record::fork(&runs_dir, &parent, at, &tenant)?;
        if cli.output_format.is_machine() {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema_version": machine_schema_version,
                    "type": "session_fork_result",
                    "parent_run_id": pid,
                    "child_run_id": child.to_string(),
                    "fork_point": at.0,
                    "status": "created",
                }))?
            );
        } else {
            println!("forked {pid} -> {child}  (resume with --resume {child})");
        }
        return Ok(Some(output::EXIT_SUCCESS));
    }

    Ok(None)
}

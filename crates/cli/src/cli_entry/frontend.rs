//! Client attachment and presentation after the host has admitted a complete session.
//! Consumes one Agent; runtime identity, permissions and policy are already pinned by the host.
use super::{
    Cli, LocalCommand, StderrDiagnosticDrain, agent_discovery_activity, dangerous_bypass_notice,
    erasure_now_unix_ms, report_agent_catalog_scan, safe_agent_diagnostic, scan_agent_catalog,
    submit_one_shot,
};
use crate::output::{Emitter, OutputFormat};
use crate::runtime::Agent;
use crate::{
    app_server, config, image_input, output, plugin_runtime, providers, route, runtime, startup,
    tui,
};
use iteron_protocol::{Outcome, RunId};
use std::path::PathBuf;

pub(crate) struct FrontendLaunch {
    pub(crate) agent: Agent,
    pub(crate) cli: Cli,
    pub(crate) one_shot: bool,
    pub(crate) confine_execution: bool,
    pub(crate) selected_api_root: String,
    pub(crate) recording_app_server_fault: Option<app_server::RecordingAppServerFault>,
    pub(crate) diagnostic_drain: StderrDiagnosticDrain,
    pub(crate) config_warnings: Vec<String>,
    pub(crate) provider_directory: providers::ProviderDirectory,
    pub(crate) route: route::RouteView,
    pub(crate) repo: PathBuf,
    pub(crate) refresh_agent_catalog_after_paint: bool,
    pub(crate) plugin_agents: Vec<plugin_runtime::AgentArtifact>,
    pub(crate) agent_snapshot_path: Option<PathBuf>,
    pub(crate) completion_notifications: config::CompletionNotificationResolution,
    pub(crate) user_file: crate::config::FileConfig,
    pub(crate) credential_env_names: Vec<String>,
    pub(crate) resumed_transcript_events: Option<Vec<iteron_protocol::Event>>,
    pub(crate) startup: startup::StartupTiming,
    pub(crate) run: RunId,
    pub(crate) output_format: OutputFormat,
    pub(crate) machine_schema_version: u32,
    pub(crate) one_shot_images: image_input::ImageAttachments,
}
pub(crate) async fn drive(launch: FrontendLaunch) -> anyhow::Result<u8> {
    let FrontendLaunch {
        agent,
        cli,
        one_shot,
        confine_execution,
        selected_api_root,
        recording_app_server_fault,
        diagnostic_drain,
        config_warnings,
        mut provider_directory,
        route,
        repo,
        refresh_agent_catalog_after_paint,
        plugin_agents,
        agent_snapshot_path,
        completion_notifications,
        user_file,
        credential_env_names,
        resumed_transcript_events,
        mut startup,
        run,
        output_format,
        machine_schema_version,
        one_shot_images,
    } = launch;
    if let Some(LocalCommand::Serve {
        listen, plantcore, ..
    }) = &cli.command
    {
        if let Some(fault) = recording_app_server_fault {
            fault.consume_marker()?;
        }
        let attached = if *plantcore {
            app_server::attach_plantcore(agent, false, true, selected_api_root.clone())?
        } else {
            app_server::attach(agent, false, true)?
        };
        tui::headless::serve(attached, *listen, *plantcore, recording_app_server_fault).await?;
        diagnostic_drain.flush();
        return Ok(output::EXIT_SUCCESS);
    }

    if !one_shot {
        // The alternate screen intentionally replaces the primary-screen startup transcript.
        // Replay the execution posture after the first frame so the operator never loses the
        // exact authority, effort, verification and permission facts that govern this session.
        //
        // One dot-separated line, not five notices: each fact is also permanently readable in the
        // footer, so the startup replay only has to name the posture once. A field is omitted
        // rather than printed as an empty value, so the line stays short enough not to wrap.
        let mut initial_notices = Vec::new();
        initial_notices.extend(config_warnings);
        let code_posture = match agent
            .permission_rules()
            .cap_rule(iteron_protocol::Capability::CodeExecuting)
        {
            Some(iteron_protocol::Verdict::Auto) if confine_execution => "code:on/confined",
            Some(iteron_protocol::Verdict::Auto) => "code:on",
            _ => "code:off",
        };
        let mut posture = vec![
            if agent.bypass_permissions {
                "bypass".to_owned()
            } else {
                "ask".to_owned()
            },
            code_posture.to_owned(),
            format!("effort:{}", agent.effort().label()),
        ];
        // The default mode is what the footer also stays silent about; only a mode the operator
        // chose (plan, acceptEdits, yolo) is worth a field here.
        if agent.permission_mode() != iteron_protocol::PermissionMode::AcceptEdits {
            posture.push(format!("mode:{}", agent.permission_mode().label()));
        }
        if let Some(command) = &agent.verify_command {
            posture.push(format!("verify:{command}"));
        }
        if agent.verify_preconfined {
            posture.push("verify-preconfined:outer-sandbox-attested".into());
        }
        initial_notices.push(posture.join(" · "));
        // Keep the explicit dangerous opt-in conspicuous on every affected run.
        if agent.bypass_permissions {
            initial_notices.push(dangerous_bypass_notice().to_owned());
        }
        let attached = match app_server::attach(agent, true, false) {
            Ok(attached) => attached,
            Err(error) => {
                eprintln!("app server: refusing to attach — {error}");
                return Err(anyhow::anyhow!(
                    "the App Server refused the version handshake: {error}"
                ));
            }
        };
        provider_directory.set_activity(attached.handle.activity.clone());
        let agent_refresh = if refresh_agent_catalog_after_paint {
            let repo = repo.clone();
            let plugin_agents = plugin_agents.clone();
            let snapshot_path = agent_snapshot_path
                .clone()
                .expect("post-paint refresh requires a private snapshot path");
            let activity = attached.handle.activity.clone();
            let started_at = erasure_now_unix_ms();
            let _ = activity.try_send(agent_discovery_activity(
                iteron_protocol::ActivityState::Running,
                started_at,
            ));
            Some(tokio::task::spawn_blocking(move || {
                let catalog = scan_agent_catalog(&repo, &plugin_agents);
                let stored = iteron_agents::AgentCatalogSnapshot::store(&snapshot_path, &catalog);
                let terminal = if stored.is_ok() {
                    iteron_protocol::ActivityState::Succeeded
                } else {
                    iteron_protocol::ActivityState::Failed
                };
                let _ = activity.try_send(agent_discovery_activity(terminal, started_at));
                (catalog, stored.err().map(|error| error.to_string()))
            }))
        } else {
            None
        };
        let tui_result = tui::run(
            attached,
            cli.task,
            provider_directory,
            route,
            tui::RunConfig {
                completion_notifications: completion_notifications.enabled,
                history_mode: user_file.prompt_history.unwrap_or_default(),
                keymap: user_file.tui_keymap.clone(),
                external_editor: user_file.external_editor.clone(),
                sensitive_env_names: credential_env_names,
                initial_diagnostics: diagnostic_drain.take(),
                initial_notices,
                initial_transcript_events: resumed_transcript_events,
            },
            startup,
        )
        .await;
        if let Some(mut agent_refresh) = agent_refresh {
            match tokio::time::timeout(std::time::Duration::from_millis(250), &mut agent_refresh)
                .await
            {
                Ok(Ok((catalog, store_error))) => {
                    report_agent_catalog_scan(&catalog);
                    if let Some(error) = store_error {
                        eprintln!(
                            "warning: refreshed agent catalog snapshot was not persisted ({})",
                            safe_agent_diagnostic(&error)
                        );
                    }
                }
                Ok(Err(error)) => eprintln!(
                    "warning: post-paint agent discovery worker did not finish ({})",
                    safe_agent_diagnostic(&error.to_string())
                ),
                Err(_) => {
                    // `spawn_blocking` cannot synchronously kill work already running. Aborting
                    // the join authority detaches this cache-only refresh and bounds interactive
                    // exit; it owns no terminal state and can only replace a next-run snapshot.
                    agent_refresh.abort();
                }
            }
        }
        diagnostic_drain.flush();
        tui_result?;
        return Ok(output::EXIT_SUCCESS);
    }
    // One-shot has no frame to emit at; the terminal probe never runs, so the breakdown is final
    // here, before the first paid request.
    startup.flush();

    // ---- one-shot (streaming) mode: requires a task. ----
    let task = cli.task.clone().ok_or_else(|| {
        anyhow::anyhow!("-p/--print requires a task; omit -p to open the interactive TUI")
    })?;
    // A one-shot invocation is a sibling client of the same resident App Server as the TUI. It
    // deliberately leaves interactive approvals disabled, preserving the historical fail-closed
    // behavior of non-interactive runs.
    let attached = app_server::attach(agent, false, true)?;
    let app_server::Attached {
        handle,
        task: server_task,
        interrupt,
        ..
    } = attached;
    let app_server::AppServerHandle {
        client,
        mut events,
        lifecycle: _,
        lifecycle_otel: _,
        hook_health: _,
        activity: _,
        mcp_input: _,
        control,
    } = handle;

    // Ctrl-C = graceful interrupt: the in-flight provider turn is cancelled mid-stream (D1-16),
    // then the run stops without committing a partial effect and can be resumed with
    // --resume <run>. The turn is NOT atomic with respect to the interrupt: dropping the stream
    // means the usage record never arrives, so a cancelled run reports its cost as unknown with
    // reason `billing_evidence_missing`. A second Ctrl-C hard-exits.
    {
        let interrupt = interrupt.clone();
        let run_id = run.to_string();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!(
                    "\ninterrupt: stopping at the next safe point (resume with --resume {run_id})"
                );
                interrupt.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("second interrupt: forcing exit");
                std::process::exit(130);
            }
        });
    }

    let mut emitter = Emitter::new(output_format, machine_schema_version);
    let mut output_error: Option<std::io::Error> = None;

    // Every one-shot format routes through UiEvent. This keeps human text out of the kernel's raw
    // stdout path and applies one stateful scrubber across arbitrary provider delta boundaries.
    // Keep draining after a pipe/write failure: dropping the run future mid-effect would violate
    // the turn-atomic shutdown invariant.
    let attachment_metadata = submit_one_shot(&client, task, one_shot_images)?;
    for (index, (media_type, encoded_bytes)) in attachment_metadata.into_iter().enumerate() {
        if output_error.is_none()
            && let Err(error) = emitter.input_attachment(index + 1, media_type, encoded_bytes)
        {
            output_error = Some(error);
        }
    }
    let mut last_event_seq = 0;
    let (summary, ledger_summary) = loop {
        let envelope = events
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("the App Server event queue closed before run end"))?;
        let event_seq = envelope.sequence();
        if event_seq <= last_event_seq {
            anyhow::bail!(
                "the App Server event queue reordered or duplicated live sequence {event_seq} after {last_event_seq}"
            );
        }
        last_event_seq = event_seq;
        let event = match envelope.into_current()? {
            app_server::ServerEvent::Ui(event) => event,
            app_server::ServerEvent::Notice(message) => runtime::UiEvent::Notice(message),
            app_server::ServerEvent::Lagged { dropped } => runtime::UiEvent::Notice(format!(
                "{dropped} streamed update(s) were dropped by the bounded App Server event queue"
            )),
            app_server::ServerEvent::Submission { .. } => continue,
            app_server::ServerEvent::Plantcore(_) => continue,
            // Live activity is already projected by interactive/headless frontends. The frozen
            // one-shot stream-json schema has no activity record, so never forge one here.
            app_server::ServerEvent::Activity(_) => continue,
            app_server::ServerEvent::McpInputRequested(_) => continue,
            app_server::ServerEvent::RunEnded {
                snapshot, summary, ..
            } => break (*summary, snapshot.ledger_summary),
            // ADR-0001 step 1: the QuickJS workflow tree is an interactive-TUI surface. It has no
            // record type in the frozen `stream-json` contract this loop writes, and minting one
            // would change a published schema as a side effect of a renderer change — the thing
            // ADR-0001 keeps as its own release-contract PR. The run is still announced by the
            // launch notice above it, and `iteron workflow list` still tracks it.
            app_server::ServerEvent::WorkflowRun(_) => continue,
        };
        if output_error.is_none()
            && let Err(error) = emitter.event(event)
        {
            output_error = Some(error);
        }
    };
    // `RunEnded` is the synchronisation barrier, but preserve a second nonblocking drain as a
    // schema-guarded assertion that any already-queued UI tail still passes through Emitter.
    while let Ok(envelope) = events.try_recv() {
        let event_seq = envelope.sequence();
        if event_seq <= last_event_seq {
            anyhow::bail!(
                "the App Server event queue reordered or duplicated live sequence {event_seq} after {last_event_seq}"
            );
        }
        last_event_seq = event_seq;
        let event = match envelope.into_current()? {
            app_server::ServerEvent::Ui(event) => event,
            app_server::ServerEvent::Notice(message) => runtime::UiEvent::Notice(message),
            app_server::ServerEvent::Lagged { dropped } => runtime::UiEvent::Notice(format!(
                "{dropped} streamed update(s) were dropped by the bounded App Server event queue"
            )),
            app_server::ServerEvent::Submission { .. } => continue,
            app_server::ServerEvent::Plantcore(_) => continue,
            app_server::ServerEvent::Activity(_) => continue,
            app_server::ServerEvent::McpInputRequested(_) => continue,
            app_server::ServerEvent::RunEnded { .. } => continue,
            // Same as the drain above: no `stream-json` record type exists for it yet.
            app_server::ServerEvent::WorkflowRun(_) => continue,
        };
        if output_error.is_none()
            && let Err(error) = emitter.event(event)
        {
            output_error = Some(error);
        }
    }
    drop(events);
    drop(control);
    drop(client);
    // A one-shot session owns background workflow runs too, and ending it stops them. That goes to
    // stderr, beside the interrupt notice above: stdout is the machine contract and takes no
    // additions from a runtime concern.
    for line in server_task.await?.lines {
        eprintln!("iteron: {line}");
    }
    diagnostic_drain.flush();

    let outcome: Outcome = summary.terminal.outcome();
    let run_error = summary.error.as_deref().map(iteron_record::redact::scrub);
    let cost = summary.cost;
    let turns = summary.turns;
    let kernel_tax = summary.kernel_tax;
    // UiEvent text is scrubbed at the live UI seam. Scrub the complete terminal text again so a
    // secret split across streaming deltas cannot bypass the machine-output contract.
    let assistant_text = iteron_record::redact::scrub(&summary.assistant_text);
    let run_id = summary.run_id;
    let result = output::final_result(
        &outcome,
        &assistant_text,
        &run_id,
        &cost,
        turns,
        kernel_tax,
        run_error.as_deref(),
    );
    if output_error.is_none()
        && let Err(error) = emitter.result(&result)
    {
        output_error = Some(error);
    }

    eprintln!("{}", "-".repeat(72));
    eprintln!("outcome: {outcome:?}");
    // `BudgetExhausted("max_turns")` names the ceiling and nothing else. Say what clears it.
    if let Outcome::BudgetExhausted(reason) = &outcome {
        eprintln!("remedy: {}", output::budget_remedy(reason));
    }
    if let Some(error) = &run_error {
        eprintln!("harness error: {error}");
    }
    eprintln!("{ledger_summary}");
    let memo_hits = summary.memo_hits;
    let memo_misses = summary.memo_misses;
    if memo_hits + memo_misses > 0 {
        eprintln!(
            "memo: {memo_hits} hits / {} lookups (pure-tool results reused)",
            memo_hits + memo_misses
        );
    }
    if let Some(error) = output_error {
        return Err(anyhow::anyhow!("writing machine output: {error}"));
    }
    Ok(output::outcome_exit_code(&outcome))
}

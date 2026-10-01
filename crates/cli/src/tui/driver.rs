//! Frontend event driver, terminal ownership, bounded workers and teardown.

use super::{
    App, CEvent, CatchUp, Duration, FIRST_TOKEN_SPINNER_TICK, FRAME_COALESCE, InputThreadControl,
    Instant, PromptHistoryMode, ProviderDirectory, RouteView, SPINNER_TICK, Session,
    TERMINAL_READ_SLICE, TermGuard, Terminal, TerminalOptions, VecDeque, Viewport, app_server,
    apply_server_event, apply_transcript_effect_event, block, cached_workspace_dirty,
    dispatch_slash_command, draw, finish_attachment_effect, hyperlink, input_dispatch, keymap,
    local_job_wake, next_wake, notification, product_projection, prompt_history,
    report_stopped_workflows, restore_terminal, schedule_transcript_viewer_effect,
    service_input_control, session_display_name, slash_command_body, startup,
    submit_queued_model_input, submit_turn, terminal_input, theme, transcript_effect,
    update_keymap_status, wait_for_forced_server_shutdown, wait_for_server_shutdown, wake_until,
    workflow_region, workspace_command,
};

pub(crate) struct RunConfig {
    pub(crate) completion_notifications: bool,
    pub(crate) history_mode: PromptHistoryMode,
    pub(crate) keymap: Option<keymap::Config>,
    pub(crate) external_editor: Option<Vec<String>>,
    pub(crate) sensitive_env_names: Vec<String>,
    /// Structured, content-free diagnostics emitted before alternate-screen attachment. They are
    /// replayed as notices only after the input-ready shell has painted, so startup evidence is not
    /// hidden on the primary screen.
    pub(crate) initial_diagnostics: Vec<iteron_kernel::diagnostics::KernelDiagnostic>,
    /// Human-readable, credential-free startup posture lines printed before attachment. The
    /// alternate screen hides the primary transcript, so replay them after first paint as well.
    pub(crate) initial_notices: Vec<String>,
    /// Durable transcript authority for a startup `--resume`/`--continue` invocation. The runtime
    /// already resumes full history. This bounded host projection retains physical origins and
    /// omitted counts, so rendering never hydrates or guesses a source from flattened history.
    pub(crate) initial_transcript: Option<iteron_protocol::session_navigation::SessionTranscriptV1>,
}

/// Run the TUI. The agent runs in a background task streaming `UiEvent`s; the render loop drains
/// them and redraws. For follow-ups the same agent continues via `follow_up`.
/// Enter the interactive frontend.
///
/// The composition root hands this frontend an already-attached client. Everything below this line
/// holds queue endpoints, a negotiated protocol version and immutable session facts; the TUI cannot
/// name or reclaim the runtime type.
///
/// Both the handshake and its refusal happen before ANY terminal setup. A frontend that cannot
/// speak the runtime's protocol has nothing useful to draw, and a diagnostic printed after terminal
/// modes change is easy to lose or garble: negotiate first, then let the terminal guard own every
/// mode transition until the frontend exits.
pub async fn run(
    attached: app_server::Attached,
    initial_task: Option<String>,
    mut providers: ProviderDirectory,
    route: RouteView,
    config: RunConfig,
    mut startup: startup::StartupTiming,
) -> anyhow::Result<()> {
    let RunConfig {
        completion_notifications,
        history_mode,
        keymap: keymap_config,
        external_editor: mut external_editor_command,
        sensitive_env_names,
        initial_diagnostics,
        initial_notices,
        initial_transcript,
    } = config;
    let app_server::Attached {
        handle,
        task: mut server_task,
        facts,
        initial_state,
        interrupt,
        drain,
        dispatch_gate: _,
        machine_schema_version: _,
    } = attached;
    // History/content-store hydration is independent of input readiness. Resolve it on one bounded
    // worker and adopt the result only after the shell has painted; 10,000 sessions therefore cost
    // the first frame exactly the same as an empty store.
    let history_source_run = prompt_history::source_run_from_rollout(&facts.rollout_path);
    let (history_tx, mut history_rx) = tokio::sync::mpsc::channel(1);
    let history_workspace = facts.workspace.clone();
    let history_runs_dir = facts
        .rollout_path
        .parent()
        .map(std::path::Path::to_path_buf);
    let history_config_home = crate::config::config_home();
    let history_bootstrap_run = history_source_run.clone();
    let title_rollout = facts.rollout_path.clone();
    let workflow_hydrate_dir = facts
        .rollout_path
        .parent()
        .map(|state_dir| state_dir.join("subagents").join("workflows"));
    tokio::task::spawn_blocking(move || {
        let hyperlink_policy = hyperlink::Policy::detect(&history_workspace);
        let history_started = Instant::now();
        let hydrated = prompt_history::bootstrap(
            history_mode,
            history_config_home,
            &history_workspace,
            history_runs_dir,
            history_bootstrap_run,
        );
        let history_elapsed = history_started.elapsed();
        let title_started = Instant::now();
        let title = session_display_name(&title_rollout);
        let title_elapsed = title_started.elapsed();
        let mut workflow_monitor = workflow_region::WorkflowMonitor::default();
        workflow_monitor.rehydrate(workflow_hydrate_dir.as_deref());
        let workspace_dirty = cached_workspace_dirty(&history_workspace);
        let _ = history_tx.blocking_send((
            hydrated,
            title,
            workflow_monitor,
            workspace_dirty,
            hyperlink_policy,
            history_elapsed,
            title_elapsed,
        ));
    });
    let mut history_writer = prompt_history::Writer::new(None);
    let mut history_open = true;
    let (mut active_keymap, initial_keymap_warning) =
        match keymap::Keymap::from_config(keymap_config.as_ref()) {
            Ok(keymap) => (keymap, None),
            Err(error) => (
                keymap::Keymap::default(),
                Some(format!("invalid keymap; using built-in bindings: {error}")),
            ),
        };
    let mut vim = keymap::Vim::default();
    // Drain is a runtime/session control and never depends on Git availability.
    let drain_available = true;
    let terminal_capabilities = iteron_statusline::Capabilities::detect(|name| {
        std::env::var(name).ok().filter(|value| value.len() <= 128)
    });
    // The exact title is a cache, not a reason to enumerate every session before paint. New runs
    // acquire their title from the first accepted prompt; resumed runs use their O(1) rollout id
    // until a background/session-picker projection provides a friendlier label.
    let initial_session_name = facts
        .rollout_path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("New session")
        .to_owned();
    // RAII: the terminal is restored on ANY exit path (error/panic/normal).
    let mut guard = TermGuard::new()?;
    let _ = guard.set_title(
        terminal_capabilities,
        &format!("Iteron · {initial_session_name}"),
    );
    // Catchable termination signals restore the terminal immediately, then wake the owned event
    // loop. The loop reaps any transcript helper before it performs the final process exit.
    let (termination_tx, mut termination_rx) = tokio::sync::mpsc::channel::<i32>(1);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let keyboard = guard.keyboard_restorer();
        // Preserve the frontend's existing catchable-termination contract: both routes restore and
        // exit 143 after owned cleanup.
        for (kind, exit_code) in [(SignalKind::terminate(), 143), (SignalKind::hangup(), 143)] {
            if let Ok(mut s) = signal(kind) {
                let keyboard = keyboard.clone();
                let termination_tx = termination_tx.clone();
                tokio::spawn(async move {
                    s.recv().await;
                    restore_terminal(&keyboard);
                    let _ = termination_tx.send(exit_code).await;
                });
            }
        }
    }
    // Retain one sender so unsupported platforms do not observe an immediately closed channel.
    let _termination_tx = termination_tx;
    // BOTH capability probes are deliberately deferred until after the first frame. The
    // progressive-keyboard query blocks up to 2000 ms and OSC 11 another 80 ms; running them here,
    // between raw-mode entry and the first draw, is exactly how a terminal that never answers held
    // the initial surface for two seconds. The environment alone decides the first frame's theme;
    // a background reply only repaints it.
    let environment = theme::capabilities::Environment::capture();
    let detected_theme = theme::Theme::detect_with(environment.clone(), None);
    let (terminal_writer, mut notification_writer) = notification::LiveTerminalWriter::stdout();
    let backend = ratatui::backend::CrosstermBackend::new(terminal_writer);
    // The conversation is a complete application surface: TermGuard has already entered the
    // alternate screen and captured mouse input, while Ratatui owns the entire physical frame.
    // This keeps the wheel inside the current session instead of exposing older shell scrollback.
    let mut term = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Fullscreen,
        },
    )?;
    let mut notifier = notification::TerminalNotifier::new(completion_notifications);

    let repo = facts.workspace.clone();
    let mut app = App::new_with_detected_theme(detected_theme);
    app.session_name = initial_session_name;
    if terminal_capabilities.presentation == iteron_statusline::Presentation::Semantic {
        // Screen-reader mode keeps the same keyboard-complete interaction model, but removes the
        // raster logo and colour-only distinctions from the initial surface. Later blocks already
        // carry role/status words in addition to glyphs, so monochrome preserves their semantics.
        app.set_theme(theme::Theme::mono());
        app.history.clear();
        app.history.append(block::BlockKind::Notice {
            level: block::NoticeLevel::Info,
            text: "Iteron. Ready. Screen-reader semantic presentation is active.".into(),
        });
        app.mark_transcript_changed();
    } else if !terminal_capabilities.may_use_color() {
        app.set_theme(theme::Theme::mono());
    }
    if let Some(transcript) = initial_transcript.as_ref() {
        super::session_adoption::project_host_transcript(&mut app, transcript);
    }
    if let Some(warning) = initial_keymap_warning {
        app.note(block::NoticeLevel::Warn, warning);
    }
    update_keymap_status(&mut app, &active_keymap, &vim);
    // The same derivation the kernel uses (`Agent::runtime_state_dir` is the rollout's parent), so
    // the runs this frontend restores are exactly the runs this session's own workflows land in.
    app.workflows_dir = facts
        .rollout_path
        .parent()
        .map(|state_dir| state_dir.join("subagents").join("workflows"));
    app.mode = initial_state.mode;
    app.effort = initial_state.effort;
    app.model = initial_state.model.clone();
    app.telemetry.bind_run(
        &initial_state,
        0,
        facts.initial_model_context_window,
        facts.compaction_trigger_tokens,
    );
    app.route = route;

    // Arm the response demultiplexer before the query exists, then enqueue both exact query frames
    // on the same writer Ratatui owns. `LiveTerminalWriter::flush` emits the retained shell first
    // and only then these frames, so no worker races stdout or changes its file-status flags.
    let mut terminal_input = terminal_input::TerminalInput::default();
    terminal_input.start_probes(&environment, |sequence| {
        notification_writer.admit_probe(sequence)
    });

    // Paint before probing. Everything the first frame needs is already resolved, and a terminal
    // that answers neither query must not be able to delay it. The probes are appended at this
    // frame's flush boundary, after the shell bytes are visible.
    term.draw(|f| draw(f, &mut app))?;
    startup.mark(startup::StartupPhase::FirstFrame);
    // The watcher takes its first metadata snapshot on its worker. Starting it after paint keeps
    // both thread startup and every filesystem query outside the first-frame path.
    let mut keymap_watcher = keymap::Watcher::new(crate::config::user_config_path());
    for diagnostic in initial_diagnostics {
        match diagnostic {
            iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {} => app.note(
                block::NoticeLevel::Err,
                "durable record append failed before the interface attached; review /status before continuing",
            ),
            iteron_kernel::diagnostics::KernelDiagnostic::ResumeRedactionDegraded {
                redacted_tool_results,
                count_saturated,
            } => app.note(
                block::NoticeLevel::Warn,
                format!(
                    "resumed context used redacted tool results ({redacted_tool_results}{}); the reconstructed model context differs from the original live turn",
                    if count_saturated { "+" } else { "" }
                ),
            ),
        }
    }
    for notice in initial_notices {
        app.note(block::NoticeLevel::Info, notice);
    }
    let mut session = Session::new(
        handle.client,
        handle.control,
        handle.mcp_input,
        handle.lifecycle,
        handle.lifecycle_otel,
        initial_state,
        facts,
    );
    // Provider discovery is a presentation enrichment, never an input-path prerequisite.  A clone
    // owns the deferred join after the first frame and publishes one settled immutable directory;
    // `/model` remains immediately usable with the eager/cache-backed catalog meanwhile.
    let (provider_directory_tx, mut provider_directory_rx) = tokio::sync::mpsc::channel(1);
    // Cross the post-paint boundary synchronously before the initial task can be submitted. This
    // starts no pre-paint network and prevents route admission from racing a merely scheduled
    // settler that has not yet moved Dormant discovery to Pending.
    let _ = providers.begin_settle_after_paint();
    let mut settling_providers = providers.clone();
    tokio::spawn(async move {
        settling_providers.settle().await;
        let _ = provider_directory_tx.send(settling_providers).await;
    });
    let mut provider_directory_open = true;
    let mut events = handle.events;
    let mut last_event_seq = 0;
    let startup_waits_for_initial_answer = initial_task
        .as_deref()
        .is_some_and(|task| !task.trim().is_empty());
    let mut startup_initial_finalized = !startup_waits_for_initial_answer;
    let mut startup_history_ready = false;
    let mut first_task = initial_task;
    let mut redraw = true;

    // Terminal input moves onto its own thread so the loop can wait on stdin AND the event queue at
    // the same time. The loop used to poll stdin alone for a fixed 100 ms and only afterwards drain
    // the queue, so a delta batch landing 1 ms into a poll waited out the other 99 ms — and an idle
    // session sat in a 1 s poll hole. The demultiplexer moves with the reader, so a late OSC 11 or
    // keyboard-enhancement reply is still swallowed instead of becoming synthetic operator input.
    let (input_tx, mut input_rx) =
        tokio::sync::mpsc::channel::<std::io::Result<terminal_input::ReadResult>>(256);
    // Pause/resume is a two-command protocol. Capacity two admits one complete round trip even if
    // the reader is between terminal reads, while `try_send` keeps the TUI thread non-blocking.
    let (input_control_tx, input_control_rx) =
        std::sync::mpsc::sync_channel::<InputThreadControl>(2);
    std::thread::spawn(move || {
        loop {
            if input_tx.is_closed() {
                return;
            }
            if !service_input_control(&input_control_rx) {
                return;
            }
            match terminal_input.read(TERMINAL_READ_SLICE) {
                Ok(None) => continue,
                Ok(Some(event)) => {
                    if input_tx.blocking_send(Ok(event)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = input_tx.blocking_send(Err(error));
                    return;
                }
            }
        }
    });
    startup.mark(startup::StartupPhase::TerminalProbe);
    startup.mark(startup::StartupPhase::InputReady);
    // A runtime event observed by the wait is handed back to the drain at the top of the loop, so
    // the EQ still has exactly one consumer and one ordering check.
    let mut pending_event = None;
    let mut input_open = true;
    let mut eq_open = true;
    let mut last_spin = Instant::now();
    let mut next_frame_at = Instant::now();
    let mut persisted_revision = app.editor.persistence_revision();
    let mut persisted_history_len = app.editor.history_len();
    let mut transcript_effects = transcript_effect::Supervisor::default();
    // Physical-key dispatch never waits for provider/control/filesystem work. Commands enter this
    // small FIFO after an immediate chip/status acknowledgement and are serviced one at a time.
    // The queue is deliberately tiny: an operator can always keep the unaccepted text in the
    // composer rather than creating an unbounded hidden command backlog.
    let mut pending_slash_commands: VecDeque<(String, Option<String>)> = VecDeque::new();
    let mut termination_exit = None;
    let mut terminal_session_name = app.session_name.clone();
    let mut catch_up = CatchUp::default();
    let mut product_projection = product_projection::ProductProjection::default();
    let mut eq_backlog_since: Option<Instant> = None;
    let mut resize_due: Option<Instant> = None;

    // All interactive-loop exits, including draw/input/editor/dispatch errors, flow through this
    // result boundary. Cleanup below therefore awaits the effect supervisor before the function can
    // return; relying on `Drop` would only abort the async shell and could orphan a helper process.
    let tui_result: anyhow::Result<()> = async {
    loop {
        // Kick off the initial task once the terminal is up.
        if let Some(task) = first_task.take()
            && !task.trim().is_empty()
        {
            startup.mark(startup::StartupPhase::InitialSubmission);
            submit_turn(&mut app, &session, &mut notifier, task);
            redraw = true;
        }

        // Drain the EQ (non-blocking). One long-lived subscription for the whole session: the
        // frontend used to create and retire a receiver per run, which is why there was no event
        // stream at all while idle and why the join had to double as a drain barrier.
        let eq_depth = events.len().saturating_add(usize::from(pending_event.is_some()));
        let now = Instant::now();
        if eq_depth == 0 {
            eq_backlog_since = None;
        } else {
            eq_backlog_since.get_or_insert(now);
        }
        let eq_age = eq_backlog_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default();
        catch_up.update(eq_depth, eq_age, now);
        for _ in catch_up.slots() {
            let Some(envelope) = pending_event.take().or_else(|| events.try_recv().ok()) else {
                break;
            };
            let event_seq = envelope.sequence();
            if event_seq <= last_event_seq {
                app.note(
                    block::NoticeLevel::Err,
                    format!(
                        "the runtime event stream reordered or duplicated live sequence \
                         {event_seq} after {last_event_seq}; no further updates will be shown"
                    ),
                );
                app.quit = true;
                break;
            }
            last_event_seq = event_seq;
            let event = match envelope.into_current() {
                Ok(event) => event,
                Err(error) => {
                    // Not recoverable by retrying: the runtime is emitting a shape this frontend
                    // cannot render. Say so in the transcript and stop reading the queue.
                    app.note(
                        block::NoticeLevel::Err,
                        format!("the runtime is speaking a protocol this frontend cannot read ({error}); no further updates will be shown"),
                    );
                    app.quit = true;
                    break;
                }
            };
            if let app_server::ServerEvent::Activity(activity) = &event {
                let measured = Duration::from_millis(
                    activity
                        .updated_at_unix_ms
                        .saturating_sub(activity.started_at_unix_ms),
                );
                match activity.detail_code {
                    Some(iteron_protocol::ActivityDetailCode::RequestSent) => {
                        startup.mark_duration(startup::StartupPhase::RequestSent, measured);
                    }
                    Some(iteron_protocol::ActivityDetailCode::AnswerComplete)
                        if activity.state.is_terminal() =>
                    {
                        startup.mark_duration(startup::StartupPhase::AnswerComplete, measured);
                    }
                    Some(iteron_protocol::ActivityDetailCode::Finalizing)
                        if activity.state.is_terminal() =>
                    {
                        startup.mark_duration(startup::StartupPhase::Finalization, measured);
                        startup_initial_finalized = true;
                        if startup_history_ready {
                            // End the responsiveness trace at initial-answer finalization. Waiting
                            // until TUI exit mislabeled the operator's entire session as startup.
                            startup.flush();
                        }
                    }
                    _ => {}
                }
            }
            product_projection.sync(&mut app, &session.client, event_seq);
            apply_server_event(
                &mut app,
                &mut session,
                event,
                &mut notifier,
                &mut notification_writer,
                &interrupt,
                &drain,
                Some(&providers),
            );
            redraw = true;
        }
        if let Some(update) = app.pickers.poll_page().await {
            for warning in update.warnings { app.note(block::NoticeLevel::Info, warning); }
            redraw |= update.changed;
        }
        let navigation_scope = if app.navigation.has_work() {session.client.thread_snapshot_v1()} else {None};
        if let Some(preview) = app.navigation.poll_preview(navigation_scope.as_ref()).await {
            match preview {
                Ok(preview) => {super::session_inspection::render(&mut app, &preview.inspection); app.status = "idle · session preview ready".into();}
                Err(error) => {app.note(block::NoticeLevel::Err, error); app.status = "idle · session preview failed".into();}
            }
            redraw = true;
        }
        if let Some(update)=app.navigation.poll_adoption(navigation_scope.as_ref()).await {
            match update {
                super::session_navigation::AdoptionUpdate::Ready(reply)=>super::session_adoption::apply_navigated_session(&mut app,&mut session,&providers,*reply),
                super::session_navigation::AdoptionUpdate::Failed(message)=>{app.note(block::NoticeLevel::Err,message);app.status="idle · session navigation did not complete".into();}
                super::session_navigation::AdoptionUpdate::Cancelled=>{app.status="idle · session navigation cancelled".into();}
            }
            redraw=true;
        }
        redraw |= app.completions.poll_ready(&app.editor).await;
        let workspace_scope=if app.workspace_commands.is_busy() {session.client.thread_snapshot_v1()} else {None};
        if let Some(actions)=app.workspace_commands.poll(workspace_scope.as_ref()).await {
            workspace_command::apply(&mut app,&mut session,&providers,actions);
            redraw=true;
        }
        app.completions.start_due(&app.editor, &repo, Instant::now());
        redraw |= app.attachments.poll_progress();
        if let Some(update) = app.attachments.poll_ready().await {
            match update {
                super::attachment_owner::AttachmentUpdate::Prepared(effect) => finish_attachment_effect(&mut app, &session, &mut notifier, effect),
                super::attachment_owner::AttachmentUpdate::Failed { error, origin } => {
                    super::composer_images::restore_unprepared_origin(&mut app, origin);
                    app.note(block::NoticeLevel::Warn, error);
                }
                super::attachment_owner::AttachmentUpdate::Cancelled => {}
            }
            redraw = true;
        }
        if app.transcript_viewer.is_open()
            && app
                .transcript_viewer
                .sync_if_changed(app.history.blocks(), app.history.revision())
        {
            redraw = true;
        }
        if let Some(effect) = app.transcript_viewer.take_ready_effect() {
            schedule_transcript_viewer_effect(
                &mut app,
                session.workspace(),
                session.rollout_path(),
                &mut transcript_effects,
                effect,
            );
            redraw = true;
        }
        if app.advance_tool_presentations(Instant::now()) {
            redraw = true;
        }

        if let Some((command, restore)) = pending_slash_commands.pop_front() {
            app.status = format!("running /{command}…");
            dispatch_slash_command(
                &mut app,
                &mut session,
                &providers,
                &mut transcript_effects,
                &interrupt,
                &command,
            )?;
            if let Some(draft) = restore {
                app.editor.insert_str(&draft);
            }
            redraw = true;
        }

        // A turn ends when the server says so, on the EQ, not when a handle the frontend owned
        // finishes. `apply_server_event` handles `RunEnded`; the only thing left here is the
        // follow-up queue, which is now gated on the run state the server reports rather than on
        // whether an `Option<Agent>` happens to be full.
        if !app.running && !app.input_lanes.queued().is_empty() {
            // a joined blob mis-classified `/compact`+task). Commands execute inline; the first
            // PROSE item starts a run and we stop — the remaining items dispatch on the next
            // reclaim (a run is single-writer; we cannot start two at once).
            while !app.input_lanes.queued().is_empty() && !app.running {
                let item = app.input_lanes.pop_next().expect("queue checked non-empty");
                // An item composed with chips is a submission, not a line of text: it goes out
                // through the same staging the composer uses, so the images and files it was queued
                // with are on the wire and the `[Image #N]` anchors it names still decide their
                // order. A slash command or `!bash` cannot carry attachments, so this branch owns
                // the whole classification for them.
                if item.has_attachments() {
                    if let Err(item) =
                        submit_queued_model_input(&mut app, &session, &mut notifier, item)
                    {
                        app.input_lanes.restore_next(*item);
                    }
                    break; // a run started; remaining items dispatch after it finishes
                }
                let q = item.text.trim().to_string();
                if q.is_empty() {
                    continue;
                } else if let Some(cmd) = slash_command_body(&q) {
                    if pending_slash_commands.len() < 8 {
                        pending_slash_commands.push_back((cmd.to_owned(), None));
                    } else {
                        app.input_lanes.restore_next(item);
                    }
                    break;
                } else if let Some(bash) = q.strip_prefix('!') {
                    // The runtime is resident, so these are always the live values. The old fallback to
                    // `(app.mode, PermissionRules::new())` ran `!bash` against DEFAULT-EMPTY rules
                    // whenever the `Agent` was away in a run task — a real correctness gap that
                    // inverting the ownership closes.
                    let (mode, rules) = (
                        session.permission_mode(),
                        session.permission_rules().clone(),
                    );
                    let request = transcript_effect::Request::Shell {
                        workspace: repo.clone(),
                        command: bash.trim().to_owned(),
                        sensitive_env_names: sensitive_env_names.clone(),
                        mode,
                        rules,
                    };
                    if transcript_effects.start(request).is_ok() {
                        app.note(
                            block::NoticeLevel::Info,
                            "shell running · Ctrl-C or Esc cancels it",
                        );
                    } else {
                        app.input_lanes.restore_next(item);
                        break;
                    }
                } else {
                    if let Err(item) =
                        submit_queued_model_input(&mut app, &session, &mut notifier, item)
                    {
                        app.input_lanes.restore_next(*item);
                    }
                    break; // a run started; remaining items dispatch after it finishes
                }
            }
        }

        // Attention is a client concern: a quiet live run receives one fixed notification after
        // the bounded idle interval, then rearms only when another typed EQ event arrives.
        if let Some(trigger) = notifier.poll_idle(app.running) {
            notifier.emit_transport(&mut notification_writer, trigger);
        }

        // Active animation owns a small cadence clock: 50 ms before first token makes accepted/
        // waiting state feel live, then 80 ms while streaming. Event-driven redraws remain
        // immediate; idle schedules no animation wake at all.
        let now = Instant::now();
        let activity_animation = app.running || app.activity_observations.has_active();
        let spinner_tick = if app.activity_observations.provider_wait().is_some() {
            iteron_tunables::param_duration(
                "cli.tui.driver_support.first_token_spinner_tick",
                FIRST_TOKEN_SPINNER_TICK,
            )
        } else {
            iteron_tunables::param_duration(
                "cli.tui.driver_support.spinner_tick",
                SPINNER_TICK,
            )
        };
        if resize_due.is_some_and(|due| now >= due) {
            resize_due = None;
            redraw = true;
        }
        if !activity_animation {
            last_spin = now;
        } else if now.duration_since(last_spin) >= spinner_tick {
            app.spin = app.spin.wrapping_add(1);
            last_spin = now;
            redraw = true;
        }

        // Coalescing: the first change of a burst draws immediately, and everything that arrives
        // within FRAME_COALESCE of that frame folds into the next one. A streamed burst therefore
        // costs one frame instead of one frame per delta batch.
        if redraw && now >= next_frame_at {
            if terminal_session_name != app.session_name {
                let _ = guard.replace_title(
                    terminal_capabilities,
                    &format!("Iteron · {}", app.session_name),
                );
                terminal_session_name.clone_from(&app.session_name);
            }
            term.draw(|f| draw(f, &mut app))?;
            redraw = false;
            next_frame_at = now + iteron_tunables::param_duration("cli.tui.driver_support.frame_coalesce", FRAME_COALESCE);
        }

        if !input_open && !eq_open {
            // Neither the operator's terminal nor the runtime can wake this loop again; leave
            // rather than sleep forever.
            break;
        }
        // Wait on everything that can change the frame at once. There is no fixed poll period any
        // more: a delta is visible one coalescing interval after it arrives, and an idle session
        // sleeps until something actually happens.
        // Locally cheap transcript work is an immediate loop source. A MiB-scale block projection
        // runs on the viewer's sole bounded worker and wakes this select explicitly when ready, so
        // the TUI neither executes it synchronously nor polls it in a hot loop.
        let viewer_work_notification = app.transcript_viewer.work_notification();
        let viewer_work_active = viewer_work_notification.is_some();
        let mut wake = if app.transcript_viewer.is_open() && app.transcript_viewer.work_ready() {
            Some(Instant::now())
        } else {
            next_wake(
                redraw,
                next_frame_at,
                activity_animation,
                last_spin,
                app.next_tool_reveal(),
                spinner_tick,
            )
        };
        if let Some(completion_due) = app.completions.due() {
            wake = Some(wake.map_or(completion_due, |scheduled| scheduled.min(completion_due)));
        }
        if let Some(due) = resize_due {
            wake = Some(wake.map_or(due, |scheduled| scheduled.min(due)));
        }
        let local_job_active = app.pickers.has_worker()
            || app.navigation.has_work()
            || app.completions.has_worker()
            || app.workspace_commands.is_busy()
            || app.attachments.is_busy();
        wake = local_job_wake(wake, now, local_job_active);
        let mut next_input = None;
        let effect_active = transcript_effects.is_active();
        tokio::select! {
            biased;
            // Explicit priority plus the bounded EQ phase above gives every control plane a
            // deterministic service point under a continuously refilled runtime queue. Effects
            // are single-flight, so placing their completion ahead of input cannot starve input.
            signal = termination_rx.recv() => {
                if let Some(exit_code) = signal {
                    termination_exit = Some(exit_code);
                }
            },
            effect = transcript_effects.recv(), if effect_active => {
                if let Some(effect) = effect {
                    apply_transcript_effect_event(&mut app, &mut session, &providers, effect);
                    redraw = true;
                }
            },
            hydrated = history_rx.recv(), if history_open => {
                history_open = false;
                startup_history_ready = true;
                if let Some((
                    hydrated,
                    hydrated_title,
                    hydrated_workflows,
                    workspace_dirty,
                    hyperlink_policy,
                    history_elapsed,
                    title_elapsed,
                )) = hydrated {
                    startup.mark_duration(startup::StartupPhase::HistoryHydrate, history_elapsed);
                    startup.mark_duration(startup::StartupPhase::Title, title_elapsed);
                    let current_draft = app.editor.text();
                    let has_live_chips = app.editor.chip_count() > 0;
                    if let Some(state) = hydrated.state {
                        if has_live_chips {
                            app.note(
                                block::NoticeLevel::Info,
                                "prompt history became ready after attachments were added; the live draft was preserved",
                            );
                        } else {
                            app.editor.restore_persisted(state.history, state.draft);
                            if !current_draft.is_empty() {
                                app.editor.replace_text(&current_draft);
                            }
                            persisted_revision = app.editor.persistence_revision();
                            persisted_history_len = app.editor.history_len();
                        }
                    }
                    if let Some(warning) = hydrated.warning {
                        app.note(block::NoticeLevel::Warn, warning);
                    }
                    history_writer = prompt_history::Writer::new(hydrated.store);
                    if hydrated_title != "New session" && !hydrated_title.trim().is_empty() {
                        app.session_name = hydrated_title;
                    }
                    if app.workflow_monitor.live_count() == 0 {
                        app.workflow_monitor = hydrated_workflows;
                    }
                    app.workspace_dirty = workspace_dirty;
                    app.hyperlink_policy = hyperlink_policy;
                    app.geometry.clear();
                    app.assistant.invalidate_layout();
                    app.mark_transcript_changed();
                    redraw = true;
                }
                if startup_initial_finalized {
                    startup.flush();
                }
            },
            settled = provider_directory_rx.recv(), if provider_directory_open => {
                provider_directory_open = false;
                if let Some(settled) = settled {
                    providers = settled;
                    app.note(block::NoticeLevel::Info, "provider catalog ready");
                    redraw = true;
                }
            },
            result = input_rx.recv(), if input_open => match result {
                Some(Ok(terminal_input::ReadResult::Event(event))) => next_input = Some(event),
                Some(Ok(terminal_input::ReadResult::Probe(update))) => {
                    match update {
                        terminal_input::ProbeUpdate::KeyboardEnhancement => {
                            let _ = guard.enable_keyboard_enhancement();
                        }
                        terminal_input::ProbeUpdate::Background(background) => {
                            let probed = theme::Theme::detect_with(
                                environment.clone(),
                                Some(background),
                            );
                            app.adopt_detected_theme(probed);
                        }
                    }
                    redraw = true;
                }
                Some(Err(error)) => return Err(error.into()),
                None => input_open = false,
            },
            _ = async {
                if let Some(notification) = viewer_work_notification {
                    notification.notified().await;
                }
            }, if viewer_work_active => {},
            envelope = events.recv(), if eq_open => match envelope {
                Some(envelope) => pending_event = Some(envelope),
                None => eq_open = false,
            },
            () = wake_until(wake) => {}
        }
        if termination_exit.is_some() {
            break;
        }
        if let Some(input_event) = next_input {
            if !matches!(input_event, CEvent::Resize(_, _)) {
                redraw = true;
            }
            if input_dispatch::dispatch(input_dispatch::InputContext {
                app: &mut app,
                session: &mut session,
                providers: &providers,
                transcript_effects: &mut transcript_effects,
                interrupt: &interrupt,
                drain: &drain,
                drain_available: drain_available,
                repo: &repo,
                notifier: &mut notifier,
                guard: &mut guard,
                term: &mut term,
                keymap_watcher: &mut keymap_watcher,
                active_keymap: &mut active_keymap,
                vim: &mut vim,
                external_editor_command: &mut external_editor_command,
                input_control_tx: &input_control_tx,
                sensitive_env_names: &sensitive_env_names,
                pending_slash_commands: &mut pending_slash_commands,
                resize_due: &mut resize_due,
            }, input_event).await? { continue; }
        }

        if app.quit {
            break;
        }

        // Keep writes off the key path and bounded. A submitted prompt is scheduled immediately;
        // unsent drafts are coalesced every 32 mutations and always flushed on normal teardown.
        let revision = app.editor.persistence_revision();
        let history_len = app.editor.history_len();
        if history_len != persisted_history_len || revision.wrapping_sub(persisted_revision) >= 32 {
            if let Some(active_run) =
                prompt_history::source_run_from_rollout(session.rollout_path())
            {
                history_writer.schedule(app.editor.persistence_state(), active_run);
            }
            persisted_revision = revision;
            persisted_history_len = history_len;
        }
    }
    let _ = app.pickers.close();
    app.navigation.invalidate();
    app.workspace_commands.close();
    Ok(())
    }
    .await;
    let origin = app.attachments.invalidate();
    super::composer_images::restore_unprepared_origin(&mut app, origin);
    startup.flush();

    // A repeated Ctrl-C is an emergency operator boundary. Restore the physical terminal before
    // any bounded cleanup so process/history durability work cannot look like a frozen UI. The
    // ordinary exit path still joins every local effect before restoration.
    let force_quit_requested = app.force_quit_requested;
    if force_quit_requested {
        let _ = term.show_cursor();
        restore_terminal(&guard.keyboard_restorer());
        let _ = transcript_effects.cancel();
    }
    let tui_result = if force_quit_requested {
        tui_result
    } else {
        transcript_effects.finish(tui_result).await
    };
    if termination_exit.is_none() {
        termination_exit = termination_rx.try_recv().ok();
    }
    let _ = term.show_cursor();
    let active_run = prompt_history::source_run_from_rollout(session.rollout_path());
    let history_flushed = if force_quit_requested {
        if let Some(active_run) = active_run {
            history_writer.schedule(app.editor.persistence_state(), active_run);
        }
        drop(history_writer);
        true
    } else if let Some(active_run) = active_run {
        history_writer.finish_bounded(app.editor.persistence_state(), active_run)
    } else {
        drop(history_writer);
        true
    };
    if let Some(exit_code) = termination_exit {
        drop(session);
        // A catchable termination still gives the server its shutdown: that is where a live
        // workflow run is cancelled and its terminal record written, and `process::exit` below
        // would otherwise kill the run's thread mid-flight and leave it listing as `running`
        // forever. Bounded, because a signal must not be answered by hanging — with no live run
        // this resolves immediately, so the wait exists exactly when it is earning something.
        let stopped = wait_for_server_shutdown(&mut server_task).await;
        restore_terminal(&guard.keyboard_restorer());
        if !history_flushed {
            eprintln!(
                "prompt history is still finalizing in the background; shutdown did not wait past 250ms"
            );
        }
        report_stopped_workflows(&stopped);
        std::process::exit(exit_code);
    }
    // Dropping the last SQ sender is how the server learns the session is over. Wait for it to run
    // out — the runtime's own shutdown (the final rollout flush, and cancelling any workflow run
    // the session still owned) happens in there, and returning before it completes would race the
    // process exit against the record on disk.
    drop(session);
    let stopped = if force_quit_requested {
        wait_for_forced_server_shutdown(&mut server_task).await
    } else {
        server_task.await.unwrap_or_default()
    };
    // The terminal modes go back to normal BEFORE this prints. A run the operator was never told
    // about is the failure this report exists to prevent, so cleanup and reporting stay ordered.
    drop(guard);
    if !history_flushed {
        eprintln!(
            "prompt history is still finalizing in the background; terminal shutdown did not wait past 250ms"
        );
    }
    report_stopped_workflows(&stopped);
    tui_result
}

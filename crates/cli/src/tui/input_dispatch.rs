//! Physical terminal-event dispatch owns keyboard/modal routing and bounded command admission.

use super::{
    App, ApprovalInput, Arc, AtomicBool, AttachmentFollowup, CEvent, CTRL_C_QUIT_WINDOW, Color,
    Effort, InputDestination, InputThreadControl, Instant, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind, Op, Path, PickAction, PickerEvent, ProviderDirectory,
    RESIZE_DEBOUNCE, RunningCtrlCAction, Session, SubmissionAdmission, TermGuard, Terminal,
    VecDeque, apply_theme_selection, apply_vim_action, block, bold, cancel_local_effect_then_turn,
    command_dispatch, external_edit_round_trip, force_cancel_turn, handle_composer_paste,
    input_destination, keymap, maybe_prefetch_session_page, mcp_input, notification,
    open_transcript_viewer, queue_bare_image_path, queue_clipboard_image_effect,
    queue_draft_with_chips, queue_effort, queue_model_selection, queue_permission_capability,
    queue_permission_mode, queue_workflows_panel_action, reload_operator_keymap, request_drain,
    request_interrupt, running_ctrl_c_action, schedule_transcript_viewer_effect,
    show_tunable_detail, slash_command_body, start_adopt_session, submit_composer, submit_turn,
    transcript_effect, update_keymap_status, workflow_panel_runs,
};

pub(super) struct InputContext<'a, B: ratatui::backend::Backend> {
    pub(super) app: &'a mut App,
    pub(super) session: &'a mut Session,
    pub(super) providers: &'a ProviderDirectory,
    pub(super) transcript_effects: &'a mut transcript_effect::Supervisor,
    pub(super) interrupt: &'a Arc<AtomicBool>,
    pub(super) drain: &'a Arc<AtomicBool>,
    pub(super) drain_available: bool,
    pub(super) repo: &'a Path,
    pub(super) notifier: &'a mut notification::TerminalNotifier,
    pub(super) guard: &'a mut TermGuard,
    pub(super) term: &'a mut Terminal<B>,
    pub(super) keymap_watcher: &'a mut keymap::Watcher,
    pub(super) active_keymap: &'a mut keymap::Keymap,
    pub(super) vim: &'a mut keymap::Vim,
    pub(super) external_editor_command: &'a mut Option<Vec<String>>,
    pub(super) input_control_tx: &'a std::sync::mpsc::SyncSender<InputThreadControl>,
    pub(super) sensitive_env_names: &'a Vec<String>,
    pub(super) pending_slash_commands: &'a mut VecDeque<(String, Option<String>)>,
    pub(super) resize_due: &'a mut Option<Instant>,
}

pub(super) async fn dispatch<B: ratatui::backend::Backend>(
    context: InputContext<'_, B>,
    input_event: CEvent,
) -> anyhow::Result<bool> {
    let InputContext {
        app,
        session,
        providers,
        transcript_effects,
        interrupt,
        drain,
        drain_available,
        repo,
        notifier,
        guard,
        term,
        keymap_watcher,
        active_keymap,
        vim,
        external_editor_command,
        input_control_tx,
        sensitive_env_names,
        pending_slash_commands,
        resize_due,
    } = context;
    match input_event {
        CEvent::Resize(_, _) => {
            *resize_due = Some(
                Instant::now()
                    + iteron_tunables::param_duration(
                        "cli.tui.driver_support.resize_debounce",
                        RESIZE_DEBOUNCE,
                    ),
            );
        }
        CEvent::Paste(pasted) if app.mcp_form.is_waiting() => {
            mcp_input::handle_paste(app, &pasted);
        }
        CEvent::Paste(pasted) if app.transcript_viewer.is_open() => {
            app.transcript_viewer.handle_paste(
                &pasted,
                app.history.blocks(),
                app.history.revision(),
            );
        }
        CEvent::Paste(_) if app.workflows_panel.is_open() => {
            app.workflows_panel
                .finish_action("paste is disabled in the workflow panel; press n for a new prompt");
        }
        // A modal picker owns bracketed paste as well as physical keys. Consume a bounded,
        // sanitized query here before the generic composer/image path can mutate draft
        // text, cursor, or attachments.
        CEvent::Paste(pasted) if app.pickers.is_open() => {
            let _ = app.picker_paste(&pasted);
        }
        // Bracketed paste: insert the WHOLE pasted text (incl. newlines) into the editor
        // rather than letting each pasted newline submit a partial line (review HIGH).
        CEvent::Paste(pasted) => handle_composer_paste(app, repo, &pasted),
        CEvent::Mouse(m) if app.transcript_viewer.is_open() => match m.kind {
            MouseEventKind::ScrollUp => app.transcript_viewer.scroll_up(3),
            MouseEventKind::ScrollDown => app.transcript_viewer.scroll_down(3),
            _ => {}
        },
        CEvent::Mouse(_) if app.workflows_panel.is_open() => {}
        // In app-mouse mode, wheel/trackpad input moves only this session's transcript;
        // prompt-history navigation remains a keyboard-only editor action. A left click
        // folds the transcript card under the pointer.
        CEvent::Mouse(m) if app.mouse_capture.is_captured() => match m.kind {
            MouseEventKind::ScrollUp => app.scroll_up(3),
            MouseEventKind::ScrollDown => app.scroll_down(3),
            MouseEventKind::Down(MouseButton::Left)
                if m.row >= app.view_top && m.row < app.view_top.saturating_add(app.view_h) =>
            {
                let index = usize::from(m.row - app.view_top);
                if let Some(&block_index) = app.row_map.get(index)
                    && block_index != usize::MAX
                {
                    app.toggle_fold(block_index);
                }
            }
            _ => {}
        },
        // A report can already be queued when Ctrl-T releases capture. Ignore it so native
        // selection mode cannot mutate transcript or composer state.
        CEvent::Mouse(_) => {}
        CEvent::Key(k) => {
            if k.kind != KeyEventKind::Press {
                return Ok(true);
            }
            if keymap_watcher.changed() {
                reload_operator_keymap(app, active_keymap, vim, external_editor_command);
            }
            let mapped_action = active_keymap.action_for(k.code, k.modifiers);
            let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);

            // Global even while a picker or approval owns ordinary keyboard input: Ctrl-T
            // switches between application transcript scrolling and native drag selection
            // without leaving the alternate-screen TUI.
            if k.code == KeyCode::Char('t') && ctrl {
                match guard.toggle_mouse_capture() {
                    Ok(state) => app.mouse_capture = state,
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("could not change terminal mouse capture: {error}"),
                    ),
                }
                return Ok(true);
            }

            if app.mcp_form.is_waiting() {
                if app.transcript_viewer.is_open() {
                    app.transcript_viewer.close();
                }
                if app.workflows_panel.is_open() {
                    app.workflows_panel.close();
                }
                mcp_input::handle_key(
                    app,
                    session,
                    k.code,
                    k.modifiers,
                    interrupt,
                    drain,
                    drain_available,
                );
                return Ok(true);
            }

            // Approval and lifecycle keys retain priority over optional fullscreen
            // inspection. In particular, a queued approval cannot have its first key
            // swallowed before the next draw closes the viewer, and Ctrl-C/Ctrl-D still
            // reach the kernel/teardown paths below.
            if app.permission_prompt.read().is_some() {
                if app.transcript_viewer.is_open() {
                    app.transcript_viewer.close();
                }
                if app.workflows_panel.is_open() {
                    app.workflows_panel.close();
                }
            }
            let lifecycle_key = ctrl && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('d'));
            if app.workflows_panel.is_open() && !lifecycle_key {
                let runs = workflow_panel_runs(app);
                if let Some(action) = app.workflows_panel.key(k.code, k.modifiers, &runs) {
                    queue_workflows_panel_action(
                        app,
                        session,
                        transcript_effects,
                        interrupt,
                        action,
                    );
                }
                return Ok(true);
            }
            if lifecycle_key && app.workflows_panel.is_open() {
                app.workflows_panel.close();
            }
            if app.transcript_viewer.is_open() && !lifecycle_key {
                if let Some(effect) = app.transcript_viewer.key(
                    k.code,
                    k.modifiers,
                    app.history.blocks(),
                    app.history.revision(),
                ) {
                    schedule_transcript_viewer_effect(
                        app,
                        session.workspace(),
                        session.rollout_path(),
                        transcript_effects,
                        effect,
                    );
                }
                if !app.transcript_viewer.is_open() {
                    // Inline viewport cells may have been physically cleared/reflowed by a
                    // resize while the viewer was open. Invalidate Ratatui's retained
                    // frame before returning to the composer so unchanged prompt cells are
                    // emitted again instead of being mistaken for cells still on screen.
                    term.clear()?;
                }
                return Ok(true);
            }
            if lifecycle_key && app.transcript_viewer.is_open() {
                app.transcript_viewer.close();
            }

            if mapped_action == Some(keymap::Action::TranscriptViewer)
                && app.permission_prompt.read().is_none()
            {
                open_transcript_viewer(app, &transcript_effects, "");
                return Ok(true);
            }

            // Ctrl-V asks a fixed platform clipboard adapter for image bytes. Ordinary text
            // paste continues to arrive as `CEvent::Paste`; this branch owns only bitmap
            // capture. It is available during a run for the same reason a drop is: the
            // capture lands as a chip on the draft, and a draft with chips is queued behind
            // the turn rather than steered into it.
            if k.code == KeyCode::Char('v') && ctrl {
                if queue_clipboard_image_effect(app) {
                    app.note(
                        block::NoticeLevel::Info,
                        "clipboard image queued · you can keep typing",
                    );
                }
                return Ok(true);
            }

            // Ctrl-D while active stops in-flight work immediately, checkpoints, and
            // returns a resumable Drained outcome.
            // Idle Ctrl-D retains shell-like quit/delete behavior below.
            if k.code == KeyCode::Char('d') && ctrl && app.running {
                request_drain(app, session, drain, drain_available);
                return Ok(true);
            }

            // On terminals without key-disambiguation, a standalone Esc immediately
            // followed by the next command's first printable byte arrives as Alt+char.
            // Recover it before the modal's keyboard-ownership branch consumes the byte.
            if app.recover_picker_escape_prefixed_char(k.code, k.modifiers, repo) {
                return Ok(true);
            }
            if app.recover_running_escape_prefixed_char(
                k.code,
                k.modifiers,
                repo,
                active_keymap.mode() == keymap::Mode::Standard,
                mapped_action.is_none(),
            ) {
                request_interrupt(app, session, interrupt);
                app.push(bold(Color::Yellow), "interrupting now…");
                return Ok(true);
            }

            // An open picker OWNS the keyboard (C6): route the key to it, apply on accept
            // (take-then-apply, C5), and fully consume — no fall-through to editor/history/mode.
            if app.pickers.is_open() {
                let picker_event = app.picker_key_with_modifiers(k.code, k.modifiers);
                maybe_prefetch_session_page(app);
                match picker_event {
                    Some(PickerEvent::Accept(PickAction::SetEffort(effort))) => {
                        queue_effort(app, session, transcript_effects, interrupt, effort)
                    }
                    Some(PickerEvent::Accept(PickAction::SetMode(mode))) => {
                        queue_permission_mode(app, session, transcript_effects, interrupt, mode)
                    }
                    Some(PickerEvent::Accept(PickAction::SetCap(capability, verdict))) => {
                        queue_permission_capability(
                            app,
                            session,
                            transcript_effects,
                            interrupt,
                            capability,
                            verdict,
                        )
                    }
                    Some(PickerEvent::Accept(PickAction::SetModel(selection))) => {
                        queue_model_selection(
                            app,
                            session,
                            providers,
                            transcript_effects,
                            interrupt,
                            selection,
                        )
                    }
                    Some(PickerEvent::Accept(PickAction::InspectTunable(detail))) => {
                        show_tunable_detail(app, detail)
                    }
                    Some(PickerEvent::Accept(PickAction::SetTheme(theme))) => {
                        apply_theme_selection(app, theme)
                    }
                    Some(PickerEvent::Accept(PickAction::Info)) => {}
                    Some(PickerEvent::Accept(PickAction::AdoptRun(run_id))) => {
                        start_adopt_session(app, session, providers, run_id)
                    }
                    Some(PickerEvent::Cancel) | Some(PickerEvent::Consumed) | None => {}
                }
                return Ok(true);
            }

            // While the kernel is blocked on a capability approval, y/n/a/Esc answer it and
            // arrows/Tab + Enter make it a real focusable control; nothing falls through to
            // the editor. This is the in-TUI approval UX (R5 §4.4).
            if app.running && app.permission_prompt.read().is_some() {
                if k.code == KeyCode::Char('c') && ctrl {
                    // The runtime settles the prompt; requesting an interrupt is not an
                    // approval decision and cannot clear its pending authority early.
                    request_interrupt(app, session, interrupt);
                    return Ok(true);
                }
                if let ApprovalInput::Answer { approved, remember } = app.approval_key(k.code)
                    && let Some(p) = app.permission_prompt.read()
                {
                    if app.permission_prompt.awaiting_response() {
                        app.note(
                            block::NoticeLevel::Info,
                            "approval response is awaiting its exact receipt",
                        );
                        return Ok(true);
                    }
                    if approved && !p.prompt_complete {
                        app.note(
                            block::NoticeLevel::Warn,
                            "approval prompt was truncated; approval is unavailable",
                        );
                        return Ok(true);
                    }
                    let prompt_id = p.id;
                    let result = session.submit_for_running_turn(Op::ApprovalResponse {
                        id: prompt_id,
                        approved,
                        remember,
                    });
                    match result {
                        Some(Ok(id)) => {
                            app.permission_prompt.response_queued(prompt_id, id);
                            app.status =
                                format!("approval response {} queued · awaiting runtime", id.0);
                        }
                        _ => app.note(
                            block::NoticeLevel::Warn,
                            "approval response not queued; the prompt remains pending",
                        ),
                    }
                }
                return Ok(true); // consume the key; do not fall through to normal input handling
            }

            let alt = k.modifiers.contains(KeyModifiers::ALT);
            let shift = k.modifiers.contains(KeyModifiers::SHIFT);
            let menu_open = app.completions.is_open();

            if let Some(action) = mapped_action {
                match action {
                    keymap::Action::ExternalEditor if !app.running => {
                        let original = app.editor.text();
                        match external_edit_round_trip(
                            term,
                            guard,
                            input_control_tx,
                            repo,
                            external_editor_command.clone(),
                            &original,
                            sensitive_env_names,
                        )
                        .await
                        {
                            Ok(Ok(edited)) => {
                                app.editor.replace_text(&edited);
                                app.completions.dismiss();
                                app.resume_handoff = None;
                                app.note(
                                    block::NoticeLevel::Ok,
                                    format!(
                                        "external editor applied a {}-byte draft",
                                        edited.len()
                                    ),
                                );
                                app.schedule_completion();
                            }
                            Ok(Err(error)) => app.note(block::NoticeLevel::Warn, error),
                            Err(error) => return Err(anyhow::anyhow!(error)),
                        }
                        vim.reset();
                        update_keymap_status(app, active_keymap, vim);
                        return Ok(true);
                    }
                    keymap::Action::ExternalEditor => {
                        app.note(
                            block::NoticeLevel::Info,
                            "external editing is available between turns",
                        );
                        return Ok(true);
                    }
                    keymap::Action::ToggleFold => {
                        app.toggle_last_fold();
                        return Ok(true);
                    }
                    keymap::Action::RestoreDraft if !app.running => {
                        if app.editor.restore_recently_cleared() {
                            app.resume_handoff = None;
                            app.schedule_completion();
                        }
                        return Ok(true);
                    }
                    keymap::Action::ReverseSearch if !app.running && !menu_open => {
                        if !shift
                            && app.editor.is_empty()
                            && let Some(task) = app.retryable_task.clone()
                        {
                            submit_turn(app, session, notifier, task);
                        } else if !app.editor.reverse_search_previous() {
                            app.status = "no older matching prompt".into();
                        }
                        app.schedule_completion();
                        return Ok(true);
                    }
                    keymap::Action::RestoreDraft | keymap::Action::ReverseSearch => {
                        return Ok(true);
                    }
                    keymap::Action::TranscriptViewer => unreachable!(
                        "the global transcript action is routed before modal/editor input"
                    ),
                }
            }

            // Pickers and approvals have already consumed their keys above. The completion
            // menu gets first Esc/navigation handling below; otherwise Vim normal mode owns
            // ordinary editor keys before readline insertion can see them.
            if !menu_open
                && let Some(action) = vim.route(
                    active_keymap.mode() == keymap::Mode::Vim,
                    k.code,
                    k.modifiers,
                )
            {
                apply_vim_action(app, action);
                update_keymap_status(app, active_keymap, vim);
                app.schedule_completion();
                return Ok(true);
            }

            let mut refresh = false;
            match k.code {
                KeyCode::Char('c') if ctrl => {
                    if app.running {
                        match running_ctrl_c_action(
                            app.ctrl_c_quit_deadline,
                            Instant::now(),
                            iteron_tunables::param_duration(
                                "cli.tui.ctrl_c_quit_window",
                                CTRL_C_QUIT_WINDOW,
                            ),
                        ) {
                            RunningCtrlCAction::InterruptAndArm => {
                                if transcript_effects.is_active() {
                                    let _ = transcript_effects.cancel();
                                }
                                request_interrupt(app, session, interrupt);
                                app.push(
                                    bold(Color::Yellow),
                                    "interrupting now… (Ctrl-C again to exit)",
                                );
                            }
                            RunningCtrlCAction::ForceQuit => {
                                if transcript_effects.is_active() {
                                    let _ = transcript_effects.cancel();
                                }
                                if app.interrupting {
                                    force_cancel_turn(app, session);
                                }
                                app.force_quit_requested = true;
                                app.quit = true;
                                app.status = "shutting down…".into();
                            }
                        }
                    } else if transcript_effects.is_active() {
                        let _ = transcript_effects.cancel();
                        app.note(
                            block::NoticeLevel::Warn,
                            "local transcript effect cancelled",
                        );
                    } else if app.editor.has_submission() {
                        app.editor.clear_recoverable();
                        app.completions.dismiss();
                        app.resume_handoff = None;
                    } else {
                        app.force_quit_requested =
                            app.workflow_monitor.live_count() > 0 || !app.activities.is_empty();
                        app.quit = true;
                    }
                }
                KeyCode::Char('d') if ctrl && !app.running => {
                    if !app.editor.has_submission() {
                        app.quit = true;
                    } else if app.editor.is_empty() {
                        let _ = app.editor.remove_last_attachment();
                    } else {
                        app.editor.delete();
                        refresh = true;
                    }
                }
                KeyCode::BackTab if !app.running => {
                    let next = session.permission_mode().next();
                    queue_permission_mode(app, session, transcript_effects, interrupt, next);
                }
                // ---- completion menu navigation (menu open) ----
                KeyCode::Down
                | KeyCode::Up
                | KeyCode::PageDown
                | KeyCode::PageUp
                | KeyCode::Home
                | KeyCode::End
                    if menu_open =>
                {
                    app.completions.navigate(k.code);
                }
                KeyCode::Tab if menu_open => {
                    app.accept_completion();
                    refresh = true;
                }
                KeyCode::Enter if menu_open => {
                    let submit = app.accept_completion_for_enter();
                    if submit && !app.running {
                        // Consume this physical Enter exactly once: it submits the command,
                        // but the picker opened by that command does not see the same key.
                        let line = app.editor.take_submit();
                        let trimmed = line.trim();
                        app.completions.dismiss();
                        if let Some(cmd) = trimmed.strip_prefix('/') {
                            if pending_slash_commands.len() < 8 {
                                pending_slash_commands.push_back((cmd.to_owned(), None));
                                app.status = format!("queued /{cmd}");
                            } else {
                                app.note(
                                    block::NoticeLevel::Warn,
                                    "command queue is full; draft restored",
                                );
                                app.editor.insert_str(&line);
                            }
                        }
                    } else {
                        refresh = true;
                    }
                }
                KeyCode::Esc if menu_open => {
                    app.completions.dismiss();
                }
                // ---- input history (idle, no menu) ----
                KeyCode::Up if !app.running => {
                    app.editor.history_prev();
                    refresh = true;
                }
                KeyCode::Down if !app.running => {
                    app.editor.history_next();
                    refresh = true;
                }
                // ---- cursor + readline editing (idle or composing while running) ----
                KeyCode::Left if alt => app.editor.word_left(),
                KeyCode::Right if alt => app.editor.word_right(),
                KeyCode::Char('b') if alt => app.editor.word_left(),
                KeyCode::Char('f') if alt => app.editor.word_right(),
                KeyCode::Left => {
                    app.editor.left();
                    refresh = true;
                }
                KeyCode::Right => {
                    app.editor.right();
                    refresh = true;
                }
                KeyCode::End if ctrl => app.follow_latest(),
                KeyCode::Home => app.editor.home(),
                KeyCode::End => app.editor.end(),
                KeyCode::Char('a') if ctrl => app.editor.home(),
                KeyCode::Char('e') if ctrl => app.editor.end(),
                KeyCode::Char('u') if ctrl => {
                    app.editor.kill_to_start();
                    refresh = true;
                }
                KeyCode::Char('k') if ctrl => {
                    app.editor.kill_to_end();
                    refresh = true;
                }
                KeyCode::Char('w') if ctrl => {
                    app.editor.delete_word_before();
                    refresh = true;
                }
                // Ctrl-J is the portable newline fallback on terminals that cannot report
                // Shift-Enter distinctly.
                KeyCode::Char('j') if ctrl => {
                    app.editor.newline();
                    refresh = true;
                }
                // A queued (not yet delivered) follow-up is safe to take back for editing.
                KeyCode::Up if alt && app.running => {
                    refresh = reclaim_queued_key(app, k);
                }
                KeyCode::Delete => {
                    app.editor.delete();
                    refresh = true;
                }
                KeyCode::Backspace if alt && !app.running && app.editor.chip_count() > 0 => {
                    let _ = app.editor.remove_last_attachment();
                    refresh = true;
                }
                KeyCode::Backspace => {
                    app.editor.backspace();
                    refresh = true;
                }
                // ---- multi-line (Alt/Shift+Enter, or a trailing backslash) ----
                KeyCode::Enter if alt || shift => {
                    app.editor.newline();
                    refresh = true;
                }
                // Esc clears a non-empty line first (like a shell / the leading agent); quits only
                // on an already-empty line — so typed-but-unsent input is never silently discarded.
                KeyCode::Esc if !app.running && transcript_effects.is_active() => {
                    let _ = transcript_effects.cancel();
                    app.note(block::NoticeLevel::Warn, "cancelling local effect…");
                }
                KeyCode::Esc if !app.running && app.navigation.adoption_busy() => {
                    app.navigation.cancel_adoption();
                    app.status = "idle · session loading cancelled".into();
                }
                KeyCode::Esc if !app.running && app.editor.has_submission() => {
                    app.editor.clear_recoverable();
                    app.resume_handoff = None;
                    refresh = true;
                }
                KeyCode::Esc if !app.running => app.quit = true,
                KeyCode::Enter if !app.running => {
                    if app.is_resume_handoff_draft() {
                        let command = app.editor.text();
                        app.note(
                                    block::NoticeLevel::Info,
                                    format!(
                                        "restart handoff kept for copying; run it in a new terminal: {command}"
                                    ),
                                );
                    } else if app.editor.wants_continuation() {
                        app.editor.newline();
                    } else {
                        app.resume_handoff = None;
                        let line = app.editor.text();
                        let trimmed = line.trim().to_string();
                        let has_attachments = app.editor.chip_count() > 0;
                        app.completions.dismiss();
                        if trimmed.is_empty() && !has_attachments {
                            // nothing
                        } else if !has_attachments && let Some(cmd) = slash_command_body(&trimmed) {
                            // The words outlive a bad guess: a name the registry does not
                            // serve returns to the composer after the notice, so nothing
                            // the operator typed or dropped is consumed by a misparse.
                            let restore = commands::parse(cmd).is_err().then(|| line.clone());
                            let _ = app.editor.take_submit();
                            if pending_slash_commands.len() < 8 {
                                pending_slash_commands.push_back((cmd.to_owned(), restore));
                                app.status = format!("queued /{cmd}");
                            } else {
                                app.note(
                                    block::NoticeLevel::Warn,
                                    "command queue is full; draft restored",
                                );
                                app.editor.insert_str(&line);
                            }
                        } else if !has_attachments && let Some(bash) = trimmed.strip_prefix('!') {
                            let _ = app.editor.take_submit();
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
                                app.note(
                                    block::NoticeLevel::Warn,
                                    "shell not started: another local effect is pending",
                                );
                                app.editor.insert_str(&trimmed);
                            }
                        } else {
                            // The operator may ask for multi-agent orchestration in the
                            // prompt itself, not only through `/effort ultracode`. The
                            // detector reads the DRAFT — what was typed — rather than the
                            // expanded submission: pasted blocks are inert by design (see
                            // `submit_prepared_composer`), and bytes the operator did not
                            // write must never be able to escalate a turn.
                            //
                            // What this seam can and cannot do today: the request is
                            // detected and said out loud, but the turn is NOT re-routed,
                            // because there is no per-turn orchestration hook to set.
                            // Orchestration is decided in the resident runtime from the
                            // SESSION effort (`runtime.rs`: `let orchestrate =
                            // allow_orchestration && self.effort_orchestration(self.effort)
                            // == OrchestrationMode::Orchestrated && …`), and the only lever
                            // the frontend holds is `app_server::Control::SetEffort`, which
                            // moves the operator's persisted effort for every later turn
                            // too — and would race the submission besides, since the
                            // control channel and the SQ are separate. Closing this needs
                            // one boolean carried with the submission and OR'd into that
                            // predicate, in `app_server`/`runtime`.
                            if crate::keyword_trigger::requests_orchestration(&trimmed) {
                                let already = app.effort == Effort::Ultracode;
                                app.note(
                                    block::NoticeLevel::Info,
                                    if already {
                                        "orchestration requested in the prompt · this \
                                                 session is already ultracode"
                                    } else {
                                        "orchestration requested in the prompt · this turn \
                                                 still runs at the session effort — `/effort \
                                                 ultracode` enables internal fan-out"
                                    },
                                );
                            }
                            submit_composer(app, session, notifier);
                        }
                    }
                }
                // Enter while running: STEER at the next turn-atomic safe point. Slash/shell
                // input remains a
                // post-run frontend action; it must not be injected as model prose.
                KeyCode::Enter if app.running && !app.editor.is_empty() => {
                    // A draft carrying chips has exactly one honest destination. `Op::Steer`
                    // is text — the protocol is frozen, there is no image or file field on
                    // it — so steering this draft would mean sending the words and dropping
                    // the attachment the operator just watched land. The chips are taken out
                    // of the composer WITH the text, because `take_submit` clears the stores
                    // and anything left behind would ride the next, unrelated message.
                    if queue_bare_image_path(app, repo, AttachmentFollowup::QueueRunningDraft) {
                        return Ok(true);
                    }
                    if app.editor.chip_count() > 0 {
                        // Refusal (queue bound or byte ceiling) leaves the draft, its pasted
                        // blocks and its chips exactly where they are, with the reason in
                        // the transcript.
                        queue_draft_with_chips(app);
                    } else {
                        let text = app.editor.take_submit();
                        match input_destination(app.running, app.interrupting, &text) {
                            InputDestination::ImmediateCommand => {
                                let command = slash_command_body(&text)
                                    .expect("the destination admitted a slash command");
                                if pending_slash_commands.len() < 8 {
                                    pending_slash_commands.push_back((command.to_owned(), None));
                                    app.status = format!("queued /{command}");
                                } else if let Err(text) = app.queue_after_turn(text) {
                                    app.editor.insert_str(&text);
                                }
                            }
                            InputDestination::AfterTurn => {
                                if let Err(text) = app.queue_after_turn(text) {
                                    app.editor.insert_str(&text);
                                }
                            }
                            InputDestination::SteerCurrentRun => {
                                match app.steer_admission(&text) {
                                    SubmissionAdmission::Accept => {
                                        if let Ok(id) = session
                                            .submit_for_running_turn(Op::Steer {
                                                text: text.clone(),
                                            })
                                            .ok_or(())
                                            .and_then(|result| result.map_err(|_| ()))
                                        {
                                            app.track_steer(text, id);
                                        } else {
                                            // Receiver disappeared at the run boundary:
                                            // preserve the words as an ordered follow-up.
                                            if let Err(text) = app.queue_after_turn(text) {
                                                app.editor.insert_str(&text);
                                            }
                                        }
                                    }
                                    SubmissionAdmission::IgnoreEmpty => {}
                                    SubmissionAdmission::Reject => app.editor.insert_str(&text),
                                }
                            }
                            InputDestination::StartTurn => {
                                unreachable!("the running Enter branch cannot resolve to StartTurn")
                            }
                        }
                    }
                    app.completions.dismiss();
                }
                // Codex/Claude-style explicit queue: Tab defers the text until this run ends.
                KeyCode::Tab if app.running && !app.editor.is_empty() => {
                    if queue_bare_image_path(app, repo, AttachmentFollowup::QueueRunningDraft) {
                        return Ok(true);
                    }
                    if app.editor.chip_count() > 0 {
                        queue_draft_with_chips(app);
                    } else {
                        let text = app.editor.take_submit();
                        if let Err(text) = app.queue_after_turn(text) {
                            app.editor.insert_str(&text);
                        }
                    }
                    app.completions.dismiss();
                }
                // Esc while running interrupts at the next safe point (like the leading agent).
                KeyCode::Esc if app.running => {
                    if transcript_effects.is_active() {
                        let _ = transcript_effects.cancel();
                        cancel_local_effect_then_turn(app, session, interrupt);
                    } else if app.interrupting {
                        force_cancel_turn(app, session);
                    } else {
                        let pending = app
                            .input_lanes
                            .steers()
                            .len()
                            .saturating_add(app.input_lanes.queued().len());
                        request_interrupt(app, session, interrupt);
                        app.push(bold(Color::Yellow), if pending == 0 {
                                    "interrupting now… (Esc again for stronger cancellation)".into()
                                } else {
                                    format!(
                                        "interrupting now… {pending} pending submission(s) will send next"
                                    )
                                });
                    }
                }
                KeyCode::Char('?')
                    if !app.running && !app.editor.has_submission() && !menu_open =>
                {
                    command_dispatch::show_help(app);
                }
                // ordinary typing works in both idle and running composer states.
                KeyCode::Char(c) if !ctrl && !alt => {
                    app.editor.insert(c);
                    refresh = true;
                }
                KeyCode::PageUp => app.scroll_up(10),
                KeyCode::PageDown => app.scroll_down(10),
                _ => {}
            }
            if refresh {
                // File/image discovery is deliberately not performed per key. Paste/drop
                // and submit boundaries enqueue attachment work; typing stays pure memory.
                app.schedule_completion();
            }
        } // end CEvent::Key
        _ => {} // resize etc. -> next draw handles it
    }

    Ok(false)
}

/// The exact Alt-Up branch used by physical input dispatch. A draft containing any text, paste
/// or image/file chip keeps focus and cannot be replaced by a queued value.
pub(super) fn reclaim_queued_key(app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    app.running
        && key.code == KeyCode::Up
        && key.modifiers.contains(KeyModifiers::ALT)
        && app.input_lanes.reclaim_latest(&mut app.editor)
}

use super::*;

/// Tell the operator which workflow runs the session stopped on its way out, and how to continue
/// them. Silent when there were none, which is the overwhelmingly common case.
pub(super) fn report_stopped_workflows(stopped: &crate::workflow::ShutdownReport) {
    if stopped.is_empty() {
        return;
    }
    for line in &stopped.lines {
        eprintln!("iteron: {line}");
    }
}

/// Execute one already-submitted slash command. Both ordinary Enter and Enter on a slash
/// completion use this path, so completion activation cannot drift into a second dispatch path.
/// Join deferred provider discovery for the one command that reads catalogs the launch did not
/// resolve eagerly. `/model` opens the hierarchical picker over every instance and is therefore the
/// waiter for the background handle; nothing else pays for providers this session never routes to.
pub(super) async fn settle_providers_for(providers: &mut ProviderDirectory, cmd: &str) {
    let named = commands::dispatch(cmd).is_ok_and(|routed| {
        matches!(
            routed.route,
            commands::DispatchRoute::InProcess(SlashCommand::Model)
        )
    });
    if named {
        providers.settle().await;
    }
}

pub(super) async fn dispatch_slash_command<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    session: &mut Session,
    providers: &ProviderDirectory,
    transcript_effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    cmd: &str,
) -> anyhow::Result<()> {
    app.push(bold(app.theme.accent), format!("/{cmd}"));
    let routed = match commands::dispatch(cmd) {
        Ok(routed) => routed,
        Err(unknown) => {
            app.push(
                fg(Color::Red),
                format!(
                    "unknown command /{} (try /help)",
                    ui_safe_text(unknown.name)
                ),
            );
            return Ok(());
        }
    };

    match routed.route {
        commands::DispatchRoute::InProcess(command) => {
            command_dispatch::handle_registered_command(
                app,
                session,
                providers,
                transcript_effects,
                command,
                &routed.invocation.args,
            )
            .await;
        }
        commands::DispatchRoute::NotHere(commands::TerminalIntercept::Compact) => {
            let focus = routed.invocation.args;
            app.push(dim(), "compacting…");
            term.draw(|frame| draw(frame, app))?;
            // A control request, not a `&mut Agent` held across an `.await` in the event loop.
            // The old shape blocked input, redraw and the whole event stream for the duration of
            // the compaction; this one yields, and if a turn is running the request is applied at
            // its boundary instead of racing it.
            let request = transcript_effect::Request::Control {
                sender: session.control_sender(),
                control: app_server::Control::Compact {
                    focus: (!focus.is_empty()).then_some(focus),
                },
                interrupt: interrupt.clone(),
                kind: transcript_effect::ControlKind::Compact,
            };
            if transcript_effects.start(request).is_err() {
                app.note(
                    block::NoticeLevel::Warn,
                    "compaction not started: another local effect is pending",
                );
            }
        }
        commands::DispatchRoute::NotHere(commands::TerminalIntercept::Side) => {
            let request = side_request_for(&routed.invocation.args);
            let asking = matches!(request, app_server::SideRequest::Ask(_));
            if asking {
                // Same reason compaction redraws here: this is about to await a provider call, and
                // an operator who sees nothing cannot tell a slow answer from a dead terminal.
                app.push(dim(), "asking on the side…");
                term.draw(|frame| draw(frame, app))?;
            }
            let request = transcript_effect::Request::Control {
                sender: session.control_sender(),
                control: app_server::Control::Side(request),
                interrupt: interrupt.clone(),
                kind: transcript_effect::ControlKind::Side,
            };
            if transcript_effects.start(request).is_err() {
                app.note(
                    block::NoticeLevel::Warn,
                    "side conversation not started: another local effect is pending",
                );
            }
        }
    }
    Ok(())
}

/// Resolve one `/side` argument into a control request.
///
/// Pure so the three-way split is testable without a runtime. `status` and `close` are the only
/// reserved words and they are reserved exactly: `/side status of the parser` is a question about
/// the parser, not a status request, because a bare word is the only spelling an operator can have
/// meant as a verb.
pub(super) fn side_request_for(argument: &str) -> app_server::SideRequest {
    match argument.trim() {
        "" | "status" => app_server::SideRequest::Status,
        "close" | "end" => app_server::SideRequest::Close,
        question => app_server::SideRequest::Ask(question.to_owned()),
    }
}

/// Render one side answer.
///
/// Deliberately a Panel and not an Assistant block: an Assistant block IS this session's
/// conversation, and the whole point of a side conversation is that its words are not. The books
/// travel with the answer for the same reason — a second conversation the operator is paying for
/// separately must show its own number, not silently move the session's.
pub(super) fn show_side_answer(app: &mut App, answer: &crate::runtime::SideAnswer) {
    let mut rows = vec![block::PanelRow::Note(format!(
        "side run {} · {} · {}",
        answer.status.run_id,
        block::plural(answer.status.turns as usize, "turn"),
        side_cost_text(&answer.status)
    ))];
    let text = answer.text.trim();
    if text.is_empty() {
        rows.push(block::PanelRow::Note(format!(
            "no answer ({})",
            side_outcome_label(&answer.outcome)
        )));
    } else {
        rows.extend(text.lines().map(|line| block::PanelRow::Note(line.into())));
    }
    app.panel("~", "side conversation", rows);
}

/// Render the side conversation's identity and books without an answer.
pub(super) fn show_side_status(
    app: &mut App,
    status: Option<&crate::runtime::SideStatus>,
    closed: bool,
) {
    let Some(status) = status else {
        app.note(
            block::NoticeLevel::Info,
            if closed {
                "no side conversation was open"
            } else {
                "no side conversation yet — `/side <question>` starts one with its own context, cost and record"
            },
        );
        return;
    };
    app.panel(
        "~",
        if closed {
            "side conversation · closed"
        } else {
            "side conversation"
        },
        vec![
            kv("run", &status.run_id),
            kv("record", &status.record_path.display().to_string()),
            kv("asked", &block::plural(status.asks as usize, "question")),
            kv("turns", &status.turns.to_string()),
            kv("cost", &side_cost_text(status)),
            block::PanelRow::Note(status.ledger_summary.clone()),
            block::PanelRow::Note(
                "this conversation's own context, cost and record; nothing here entered the session transcript".into(),
            ),
        ],
    );
}

/// Why a side ask produced nothing. A local label rather than `output::outcome_name`, which is a
/// frozen machine-contract token and must not grow a second, human-facing caller.
pub(super) fn side_outcome_label(outcome: &iteron_protocol::Outcome) -> &'static str {
    use iteron_protocol::Outcome;
    match outcome {
        Outcome::Done => "the model answered with nothing",
        Outcome::Drained => "drained before answering",
        Outcome::Interrupted => "interrupted before answering",
        Outcome::Stuck => "stuck before answering",
        Outcome::BudgetExhausted(_) => "the side conversation's own budget is exhausted",
        Outcome::HarnessError => "the side conversation failed",
    }
}

/// The side conversation's own money, never the session's. An unknown cost stays the word
/// "unknown": a zero would read as free.
pub(super) fn side_cost_text(status: &crate::runtime::SideStatus) -> String {
    match status.cost.usd() {
        Some(usd) => format!("${usd:.4}"),
        None => "cost unknown".into(),
    }
}

pub(super) fn request_drain(
    app: &mut App,
    session: &Session,
    drain: &Arc<AtomicBool>,
    _checkpoint_supported: bool,
) {
    if !app.running || app.draining {
        return;
    }
    if session.submit(Op::Drain).is_err() {
        app.note(
            block::NoticeLevel::Err,
            "could not request a drain because the active run is no longer reachable",
        );
        return;
    }
    // The queue event is the durable ordering source; the shared flag lets an already-admitted
    // child and provider observe it within the bounded cancellation poll interval.
    drain.store(true, Ordering::Relaxed);
    app.draining = true;
    app.status = "draining session…".into();
    if app.pending.take().is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "drain requested · stopping active work and settling the session",
        );
    } else {
        app.push(
            bold(Color::Yellow),
            "draining active work now · the session record remains resumable",
        );
    }
}

/// Admit the first cooperative interrupt through both stop surfaces: the SQ receipt is the ordered
/// control record, while the shared flag wakes provider/tool waits within their fixed poll bound.
/// Either surface alone is incomplete (headless clients have only SQ; an executing tool needs the
/// flag immediately), so every keyboard path calls this one function.
pub(super) fn request_interrupt(app: &mut App, session: &Session, interrupt: &Arc<AtomicBool>) {
    if !app.running || app.force_cancelling {
        return;
    }
    if !interrupt.swap(true, Ordering::SeqCst) && session.submit(Op::Interrupt).is_err() {
        app.note(
            block::NoticeLevel::Err,
            "interrupt reached the local executor, but its ordered session receipt could not be queued",
        );
    }
    app.interrupting = true;
    app.status = "interrupting turn…".into();
}

/// Escalate an interrupt without inventing an early turn boundary.
///
/// `RunEnded` is the sole authority that can return the frontend to idle. Clearing `running` here
/// used to make the queue driver submit its next prompt while the App Server still owned the old
/// turn; the server correctly refused that second start, and the frontend had already popped it.
pub(super) fn force_cancel_turn(app: &mut App, session: &Session) {
    if !app.running || !app.interrupting || app.force_cancelling {
        return;
    }
    if session.submit(Op::ForceCancel).is_err() {
        app.note(
            block::NoticeLevel::Err,
            "could not force-cancel because the active run is no longer reachable",
        );
        return;
    }
    app.force_cancelling = true;
    app.status = "force-cancelling turn…".into();
    app.note(
        block::NoticeLevel::Warn,
        "cooperative interrupt escalated to force-cancel; background jobs remain session-owned",
    );
}

/// Submit a turn on the SQ.
///
/// This replaces `start_run`, which took the `Agent` out of the frontend's slot, moved it into a
/// task, and handed back a `JoinHandle`. The frontend no longer decides `run` versus `follow_up`
/// either — that is session state and it belongs to the server.
///
/// A refusal is shown, never swallowed: `Busy` means the operator's input did not land, and the one
/// thing worse than a full queue is a full queue that looks like acceptance.
pub(super) fn submit_turn(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    task: String,
) -> bool {
    if submit_operation(app, session, notifier, Op::UserInput { text: task.clone() }).is_some() {
        app.retryable_task = Some(task);
        true
    } else {
        false
    }
}

/// Dispatch one model-bound queue item without consuming it on SQ refusal.
///
/// Slash commands and shell lines are classified by the queue driver before reaching this helper.
/// The caller gets the exact pending item back when the bounded runtime queue did not accept it,
/// and the transcript gains a user row only after acceptance, so neither queue state nor visible
/// conversation can claim a prompt landed when it did not.
pub(super) fn submit_queued_model_input(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    item: PendingInput,
) -> Result<(), Box<PendingInput>> {
    let retry = item.clone();
    if item.has_attachments() {
        let text = item.text.trim().to_owned();
        let anchor_order = paste_input::anchored_image_ids(&text, &item.images);
        if submit_staged_input(
            app,
            session,
            notifier,
            text,
            item.images,
            item.files,
            anchor_order,
            false,
        ) {
            Ok(())
        } else {
            Err(Box::new(retry))
        }
    } else {
        let text = item.text.trim().to_owned();
        debug_assert!(!text.is_empty());
        debug_assert!(slash_command_body(&text).is_none());
        debug_assert!(!text.starts_with('!'));
        if submit_turn(app, session, notifier, text.clone()) {
            app.push_user(text);
            Ok(())
        } else {
            Err(Box::new(retry))
        }
    }
}

pub(super) fn submit_operation(
    app: &mut App,
    session: &Session,
    notifier: &mut notification::TerminalNotifier,
    op: Op,
) -> Option<SubmissionId> {
    let first_prompt_title = match &op {
        Op::UserInput { text } => Some(iteron_record::session::title_from_text(text)),
        Op::UserInputV2 { segments } => {
            Some(iteron_record::session::title_from_text(segments.text()))
        }
        Op::UserInputV3 { text, .. } => Some(iteron_record::session::title_from_text(text)),
        _ => None,
    };
    match session.submit_identified(op) {
        Ok(submission_id) => {
            if app.session_name == "New session"
                && let Some(title) = first_prompt_title.filter(|title| !title.is_empty())
            {
                app.session_name = title;
            }
            notifier.begin_run();
            app.running = true;
            app.interrupting = false;
            app.force_cancelling = false;
            app.draining = false;
            app.status = "running…".into();
            app.run_started = Some(Instant::now());
            // A new run must not inherit the previous one's first-token clock; the next
            // `Phase(Model)` starts it honestly (I-64).
            app.awaiting_first_token_since = None;
            app.completion = None;
            Some(submission_id)
        }
        Err(app_server::SubmitError::Busy) => {
            app.note(
                block::NoticeLevel::Warn,
                "the runtime is saturated; this submission was not accepted — try again",
            );
            None
        }
        Err(app_server::SubmitError::Disconnected) => {
            app.push_block(block::BlockKind::Error {
                title: "the runtime is no longer reachable".into(),
                detail:
                    "the App Server has stopped — press Esc to quit (resume later with --resume)."
                        .into(),
                open: true,
            });
            app.status = "error (no runtime) — Esc to quit".into();
            None
        }
    }
}

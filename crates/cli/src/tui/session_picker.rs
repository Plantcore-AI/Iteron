use super::*;

pub(super) fn session_picker_items(
    mut sessions: Vec<iteron_record::SessionMeta>,
    current_run: &str,
    runs: &Path,
) -> Vec<PickItem> {
    let mut decorated = sessions
        .drain(..)
        .map(|session| {
            let view = session_management::load(runs, &session.run_id.0).unwrap_or_default();
            (session, view)
        })
        .collect::<Vec<_>>();
    decorated.sort_by(|(left, left_view), (right, right_view)| {
        right_view
            .pinned
            .cmp(&left_view.pinned)
            .then_with(|| left_view.archived.cmp(&right_view.archived))
            .then_with(|| right.updated_at.cmp(&left.updated_at))
            .then_with(|| {
                right
                    .updated_at_subsec_nanos
                    .cmp(&left.updated_at_subsec_nanos)
            })
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| left.run_id.0.cmp(&right.run_id.0))
    });
    decorated
        .into_iter()
        .map(|(session, view)| {
            let cost = session
                .cost_usd()
                .map(|value| format!("${value:.4}"))
                .unwrap_or_else(|| "cost unknown".into());
            let route = match (
                session.provider_id.trim().is_empty(),
                session.model.trim().is_empty(),
            ) {
                (false, false) => format!("{}/{}", session.provider_id, session.model),
                (false, true) => session.provider_id.clone(),
                (true, false) => session.model.clone(),
                (true, true) => "route unknown".into(),
            };
            let run_id = session.run_id.0;
            let mut flags = Vec::new();
            if view.pinned {
                flags.push("pinned");
            }
            if view.archived {
                flags.push("archived");
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" · {}", flags.join(" · "))
            };
            PickItem::flat(
                view.title.unwrap_or(session.title),
                format!(
                    "run {run_id} · {} · {cost} · {route}{flags}",
                    block::plural(session.turns as usize, "turn")
                ),
                run_id == current_run,
                PickAction::AdoptRun(run_id),
            )
        })
        .collect()
}

pub(super) fn session_display_name(rollout_path: &Path) -> String {
    let Some(runs) = rollout_path.parent() else {
        return "New session".into();
    };
    let Some(run) = rollout_path.file_stem().and_then(|stem| stem.to_str()) else {
        return "New session".into();
    };
    let renamed = session_management::load(runs, run)
        .ok()
        .and_then(|presentation| presentation.title)
        .filter(|title| !title.trim().is_empty());
    let recorded = || {
        iteron_record::list(runs, &iteron_protocol::TenantId::default())
            .into_iter()
            .find(|metadata| metadata.run_id.0 == run)
            .map(|metadata| metadata.title)
            .filter(|title| !title.trim().is_empty())
    };
    let title = renamed
        .or_else(recorded)
        .unwrap_or_else(|| "New session".into());
    title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect()
}

pub(super) fn open_session_picker(app: &mut App, session: &Session) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before browsing sessions",
        );
        return;
    }
    let runs = session
        .rollout_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current_run = session
        .rollout_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let items = session_picker_items(
        iteron_record::list(&runs, &iteron_protocol::TenantId::default()),
        current_run,
        &runs,
    );
    if items.is_empty() {
        app.note(block::NoticeLevel::Info, "no sessions recorded yet");
        return;
    }
    let sel = initial_picker_selection(&items);
    app.picker = Some(Picker {
        title: "Sessions · resume here".into(),
        items,
        sel,
        query: String::new(),
        saved_theme: None,
    });
}

pub(super) async fn handle_sessions_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    argument: &str,
) {
    let argument = argument.trim();
    if argument.is_empty() {
        open_session_picker(app, session);
        return;
    }
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before managing sessions",
        );
        return;
    }
    let runs = session
        .rollout_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current = session
        .rollout_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_owned();
    let mut words = argument.splitn(3, char::is_whitespace);
    let action = words.next().unwrap_or_default();
    let run = words.next().unwrap_or_default();
    let tail = words.next().unwrap_or_default().trim();
    match action {
        "new" => create_fresh_session(app, session, directory).await,
        "switch" | "resume" if !run.is_empty() => {
            adopt_session(app, session, directory, run).await
        }
        "preview" if !run.is_empty() => {
            let identity = iteron_protocol::RunId(run.to_owned());
            let metadata = iteron_record::list(&runs, &iteron_protocol::TenantId::default())
                .into_iter()
                .find(|metadata| metadata.run_id == identity);
            match (metadata, iteron_record::load_forked(&runs, &identity)) {
                (Some(metadata), Ok(events)) => {
                    let presentation = session_management::load(&runs, run).unwrap_or_default();
                    let mut rows = vec![
                        kv("run", run),
                        kv(
                            "title",
                            presentation.title.as_deref().unwrap_or(&metadata.title),
                        ),
                        kv("turns", &metadata.turns.to_string()),
                        kv(
                            "state",
                            if presentation.archived {
                                "archived"
                            } else if presentation.pinned {
                                "pinned"
                            } else {
                                "active"
                            },
                        ),
                    ];
                    let (blocks, total) = adopted_transcript_blocks(&events);
                    rows.push(kv("transcript", &block::plural(total, "visible block")));
                    for block in blocks.iter().rev().take(6).rev() {
                        let text = block::Block::new(0, block.clone()).to_text();
                        rows.push(block::PanelRow::Note(one_line_preview(
                            &text, 160,
                        )));
                    }
                    app.panel("◫", "session preview", rows);
                }
                (None, _) => app.note(
                    block::NoticeLevel::Err,
                    format!("no recorded session `{}`", ui_safe_text(run)),
                ),
                (_, Err(error)) => app.note(
                    block::NoticeLevel::Err,
                    format!("cannot preview session: {error}"),
                ),
            }
        }
        "rename" if !run.is_empty() && !tail.is_empty() => match session_management::update(
            &runs,
            run,
            session_management::Mutation::Rename(tail.to_owned()),
        ) {
            Ok(()) => {
                if run == current {
                    app.session_name = tail.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                app.note(block::NoticeLevel::Ok, format!("renamed session {run}"));
            }
            Err(error) => app.note(block::NoticeLevel::Err, format!("rename refused: {error}")),
        },
        "pin" | "unpin" if !run.is_empty() => {
            let value = action == "pin";
            match session_management::update(
                &runs,
                run,
                session_management::Mutation::Pin(value),
            ) {
                Ok(()) => app.note(
                    block::NoticeLevel::Ok,
                    format!("session {run} {}", if value { "pinned" } else { "unpinned" }),
                ),
                Err(error) => app.note(block::NoticeLevel::Err, format!("pin refused: {error}")),
            }
        }
        "archive" | "unarchive" if !run.is_empty() => {
            let value = action == "archive";
            match session_management::update(
                &runs,
                run,
                session_management::Mutation::Archive(value),
            ) {
                Ok(()) => app.note(
                    block::NoticeLevel::Ok,
                    format!(
                        "session {run} {}",
                        if value { "archived" } else { "restored" }
                    ),
                ),
                Err(error) => app.note(
                    block::NoticeLevel::Err,
                    format!("archive refused: {error}"),
                ),
            }
        }
        "delete" if !run.is_empty() => {
            if run == current {
                app.note(
                    block::NoticeLevel::Err,
                    "cannot delete the live session; switch away first",
                );
                return;
            }
            let operation_id = format!(
                "session.delete.{}.{}",
                std::process::id(),
                crate::erasure_now_unix_ms()
            );
            let request = iteron_record::erasure::authorize_local_erasure(&runs).and_then(|authority| {
                Ok(iteron_protocol::ErasureRequest {
                    operation_id: iteron_protocol::ErasureOperationId::new(operation_id.clone())?,
                    authority_id: authority.id().clone(),
                    requested_at_unix_ms: crate::erasure_now_unix_ms(),
                    target: iteron_protocol::ErasureTarget::ExactSession {
                        scope_id: iteron_protocol::ErasureScopeId::new(
                            iteron_protocol::TenantId::default().0,
                        )?,
                        run_id: iteron_protocol::ErasureTargetId::new(run.to_owned())?,
                    },
                })
            });
            match request.and_then(|request| iteron_record::erasure::execute_erasure(&runs, request)) {
                Ok(receipt) if receipt.state() == iteron_protocol::ErasureState::Verified => {
                    let hook_journal = runs.join(format!("{run}.hooks.jsonl"));
                    if std::fs::symlink_metadata(&hook_journal).is_ok() {
                        let _ = std::fs::remove_file(hook_journal);
                    }
                    let _ = session_management::remove(&runs, run);
                    session.record_lifecycle(
                        "session.deleted",
                        iteron_protocol::LifecyclePayload {
                            outcome_code: Some("deleted".into()),
                            reason_code: Some(operation_id),
                            ..iteron_protocol::LifecyclePayload::default()
                        },
                    );
                    app.note(block::NoticeLevel::Ok, format!("deleted session {run}"));
                }
                Ok(receipt) => app.note(
                    block::NoticeLevel::Err,
                    format!(
                        "session delete refused: operation {} ended {:?} ({:?})",
                        receipt.request().operation_id,
                        receipt.state(),
                        receipt.failure()
                    ),
                ),
                Err(error) => app.note(
                    block::NoticeLevel::Err,
                    format!("session delete refused: {error}"),
                ),
            }
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "usage: /sessions [new|switch RUN|preview RUN|rename RUN TITLE|pin RUN|unpin RUN|archive RUN|unarchive RUN|delete RUN]",
        ),
    }
}

pub(super) async fn create_fresh_session(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
) {
    if !app.queued.is_empty() || !app.steer_previews.is_empty() {
        app.note(
            block::NoticeLevel::Warn,
            "send or clear pending submissions before creating another session",
        );
        return;
    }
    let selection = ModelSelection {
        provider_id: app.route.provider_id.clone(),
        model_id: session.model().to_owned(),
    };
    let provider = match directory.build(&selection) {
        Ok(provider) => provider,
        Err(error) => {
            app.note(
                block::NoticeLevel::Err,
                format!("cannot create a session on the current route: {error}"),
            );
            return;
        }
    };
    let runs = session
        .rollout_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let run = iteron_protocol::RunId(format!("run-{}-{nanos}", std::process::id()));
    let rollout =
        match iteron_record::Rollout::open(&runs, &run, iteron_protocol::TenantId::default()) {
            Ok(rollout) => rollout,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("cannot create session: {error}"),
                );
                return;
            }
        };
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    let reply = session
        .control(app_server::Control::AdoptRun(Box::new(
            app_server::AdoptRun {
                rollout,
                fresh: true,
                route: Box::new(app_server::ModelSelection {
                    provider,
                    provider_id: selection.provider_id.clone(),
                    model_id: selection.model_id.clone(),
                    catalog_digest,
                    capability_digest,
                    context_window_tokens: capabilities.context_window_tokens,
                    max_output_tokens: capabilities.max_output_tokens,
                }),
            },
        )))
        .await;
    match reply {
        Some(app_server::ControlReply::Adopted {
            adopted,
            snapshot,
            tunables_checkpoint,
            compaction_trigger_tokens,
            blocked,
        }) => {
            clear_transcript_for_adoption(app);
            session.adopt_run(
                adopted.rollout_path.clone(),
                *tunables_checkpoint,
                compaction_trigger_tokens,
                (*snapshot).clone(),
            );
            app.session_name = "New session".into();
            app.mode = snapshot.mode;
            app.effort = snapshot.effort;
            app.model = snapshot.model.clone();
            app.cost = snapshot.cost.clone();
            app.turns = 0;
            app.model_context_window = capabilities.context_window_tokens;
            app.status = "ready".into();
            app.note(
                block::NoticeLevel::Ok,
                format!(
                    "new session {} · left {}",
                    adopted.run_id, adopted.previous_run_id
                ),
            );
            if let Some(reason) = blocked {
                app.note(block::NoticeLevel::Err, reason);
            }
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the runtime is no longer reachable",
        ),
    }
}

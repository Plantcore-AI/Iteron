use super::*;

/// Initial picker focus when no actionable, current, or enabled row exists at all. The first row is
/// always in range for a non-empty list, so focus never lands outside the rendered items.
const PICKER_FALLBACK_FOCUS: usize = 0;

pub(super) fn open_tunables_picker(app: &mut App, session: &Session, argument: &str) {
    open_tunables_picker_with_runtime_policy(app, session, argument, session.runtime_policy());
}

/// Open the runtime view with the overlay returned by the authoritative control round-trip that
/// immediately precedes `/tunables`. The frontend's terminal-event cache can lag a live USD or
/// budget transition even though the resident owner has already committed it.
pub(super) fn open_tunables_picker_with_runtime_policy(
    app: &mut App,
    session: &Session,
    argument: &str,
    runtime_policy: Option<&crate::runtime::RuntimePolicyOverlaySnapshot>,
) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before browsing tunables",
        );
        return;
    }
    let argument = argument.trim();
    let (catalog, initial_query) = if argument == "load" {
        app.note(
            block::NoticeLevel::Err,
            "usage: /tunables load <workspace-relative-request.json>",
        );
        return;
    } else if let Some(path) = argument.strip_prefix("load ") {
        match tunables_view::load_workspace_request(session.workspace(), path.trim()) {
            Ok(catalog) => (catalog, String::new()),
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("tunables simulation refused: {error}"),
                );
                return;
            }
        }
    } else if argument == "registry" {
        (tunables_view::registry_catalog(), String::new())
    } else {
        let Some(checkpoint) = session.tunables_checkpoint() else {
            app.note(
                block::NoticeLevel::Err,
                "runtime tunables are not pinned for this session",
            );
            return;
        };
        let catalog = match tunables_view::checkpoint_catalog(checkpoint, runtime_policy) {
            Ok(catalog) => catalog,
            Err(error) => {
                app.note(
                    block::NoticeLevel::Err,
                    format!("runtime tunables unavailable: {error}"),
                );
                return;
            }
        };
        (
            catalog,
            argument.chars().take(MAX_PICKER_QUERY_CHARS).collect(),
        )
    };
    let (title, entries) = catalog.into_parts();
    let items = entries
        .into_iter()
        .map(|detail| {
            PickItem::flat(
                detail.picker_label().to_owned(),
                detail.picker_hint().to_owned(),
                false,
                PickAction::InspectTunable(detail),
            )
        })
        .collect();
    let mut picker = Picker {
        title,
        items,
        sel: 0,
        query: String::new(),
        saved_theme: None,
    };
    picker.append_query_text(&initial_query);
    let visible = picker.visible_indices();
    picker.normalize_selection(&visible);
    app.picker = Some(picker);
}

/// Build a picker's items, pre-selecting the current value, and open it — refusing (with a Notice)
/// when a run/approval is in flight so accepting can never hit a taken agent (C6).
pub(super) fn open_picker(
    app: &mut App,
    session: &Session,
    directory: &ProviderDirectory,
    kind: &str,
) {
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before opening a picker",
        );
        return;
    }
    let (title, mut items): (&str, Vec<PickItem>) = match kind {
        "model" => {
            let cur = session.model().to_string();
            (
                "Model",
                model_picker_items(directory, &app.route.provider_id, &cur),
            )
        }
        "effort" => {
            let cur = session.effort();
            let items = Effort::ALL
                .iter()
                .map(|e| PickItem::flat(e.label(), e.hint(), *e == cur, PickAction::SetEffort(*e)))
                .collect();
            ("Effort", items)
        }
        "mode" => (
            "Permission mode",
            mode_picker_items(session.permission_mode(), session.permission_rules()),
        ),
        "permissions" => (
            "Permissions",
            permission_picker_items(session.permission_rules(), session.bypass_permissions()),
        ),
        "theme" => {
            let items = theme::Theme::presets()
                .into_iter()
                .map(|(name, t)| {
                    PickItem::flat(
                        name,
                        "preview: ↑↓ · Enter to keep · Esc to revert",
                        false,
                        PickAction::SetTheme(t),
                    )
                })
                .collect();
            let saved = app.theme.clone();
            app.picker = Some(Picker {
                title: "Theme".into(),
                items,
                sel: 0,
                query: String::new(),
                saved_theme: Some(saved),
            });
            return;
        }
        _ => return,
    };
    let sel = initial_picker_selection(&items);
    expand_selection_ancestors(&mut items, sel);
    app.picker = Some(Picker {
        title: title.into(),
        items,
        sel,
        query: String::new(),
        saved_theme: None,
    });
}

pub(super) fn initial_picker_selection(items: &[PickItem]) -> usize {
    items
        .iter()
        .position(|item| {
            item.is_current
                && item.enabled
                && !item.expandable
                && !matches!(&item.action, PickAction::Info)
        })
        .or_else(|| {
            items.iter().position(|item| {
                item.enabled && !item.expandable && !matches!(&item.action, PickAction::Info)
            })
        })
        // If no actionable leaf exists, retain the disabled current selection so its reason stays
        // discoverable instead of focusing an unrelated header.
        .or_else(|| {
            items
                .iter()
                .position(|item| item.is_current && !item.expandable)
        })
        .or_else(|| items.iter().position(|item| item.is_current))
        .or_else(|| items.iter().position(|item| item.enabled))
        .unwrap_or(iteron_tunables::param_integer(
            "cli.tui.command_surfaces.picker_fallback_focus",
            PICKER_FALLBACK_FOCUS,
        ))
}

/// Make an initially focused hierarchical leaf visible before the first keypress. Without this,
/// a no-current session selected a hidden model under collapsed ancestors; Enter normalized focus
/// back to the provider header and appeared to require two or three presses.
pub(super) fn expand_selection_ancestors(items: &mut [PickItem], selection: usize) {
    let mut parent = items.get(selection).and_then(|item| item.parent);
    let mut remaining = items.len();
    while let Some(index) = parent {
        if remaining == 0 {
            break;
        }
        remaining -= 1;
        let Some(item) = items.get_mut(index) else {
            break;
        };
        item.expanded = true;
        parent = item.parent;
    }
}

pub(super) fn ensure_real_workspace_dir(root: &Path, name: &str) -> Result<PathBuf, String> {
    if Path::new(name).components().count() != 1 {
        return Err("directory name must be one workspace component".into());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace is unavailable: {error}"))?;
    let path = root.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!("{} is not a real directory", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&path)
                .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
            std::fs::File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("cannot sync workspace directory: {error}"))?;
        }
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if !canonical.starts_with(&root) {
        return Err("directory escapes the workspace".into());
    }
    Ok(canonical)
}

/// Test seam retained at the composition root: viewer and slash exports share one byte projection.
#[cfg(test)]
pub(super) fn transcript_export_body(
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
) -> Result<Vec<u8>, String> {
    transcript_export::body(blocks, selected_ids)
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn export_transcript(
    workspace: &Path,
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
    requested: &str,
) -> Result<PathBuf, String> {
    let bytes = transcript_export::body(blocks, selected_ids)?;
    transcript_export::export_bytes(
        workspace,
        requested,
        &bytes,
        transcript_export::CollisionPolicy::Refuse,
    )
    .map_err(|error| error.to_string())
}

pub(super) fn schedule_transcript_viewer_effect(
    app: &mut App,
    workspace: &Path,
    rollout_path: &Path,
    supervisor: &mut transcript_effect::Supervisor,
    effect: transcript_viewer::Effect,
) {
    let snapshot_revision = effect.snapshot_revision();
    app.transcript_viewer
        .reconcile_if_changed(&app.transcript, app.transcript_revision);
    if snapshot_revision != app.transcript_revision {
        app.transcript_viewer
            .set_notice("transcript changed before the effect snapshot was captured");
        return;
    }
    if let Some(active) = supervisor.label() {
        app.transcript_viewer.set_notice(format!(
            "{active} already pending; effects are single-flight"
        ));
        return;
    }
    let request = match effect {
        transcript_viewer::Effect::Copy {
            text,
            subject,
            snapshot_revision: _,
        } => transcript_effect::Request::Copy {
            text,
            subject,
            origin: transcript_effect::Origin::Viewer,
        },
        transcript_viewer::Effect::Export {
            scope,
            snapshot_revision,
        } => {
            let ids = match app.transcript_viewer.export_ids(scope, snapshot_revision) {
                Ok(ids) => ids,
                Err(error) => {
                    app.transcript_viewer.set_notice(error);
                    return;
                }
            };
            let requested = match scope {
                transcript_viewer::ExportScope::Filtered => "core-transcript-filtered.md",
                transcript_viewer::ExportScope::All => "core-transcript.md",
            };
            transcript_effect::Request::Export {
                workspace: workspace.to_path_buf(),
                rollout_path: rollout_path.to_path_buf(),
                blocks: app.transcript.clone(),
                selected_ids: ids,
                requested: requested.into(),
                collision: transcript_export::CollisionPolicy::Versioned,
                origin: transcript_effect::Origin::Viewer,
            }
        }
    };
    let label = request.label();
    if supervisor.start(request).is_ok() {
        app.transcript_viewer.begin_effect(label);
    } else {
        app.transcript_viewer
            .set_notice("another transcript effect is already pending");
    }
}

pub(super) fn open_transcript_viewer(
    app: &mut App,
    supervisor: &transcript_effect::Supervisor,
    query: &str,
) {
    app.transcript_viewer
        .open(query, &app.transcript, app.transcript_revision);
    if let Some(label) = supervisor.label() {
        app.transcript_viewer.begin_effect(label);
    }
}

pub(super) fn schedule_slash_export(
    app: &mut App,
    workspace: &Path,
    rollout_path: &Path,
    supervisor: &mut transcript_effect::Supervisor,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
) {
    if let Some(active) = supervisor.label() {
        app.note(
            block::NoticeLevel::Warn,
            format!("export not started: {active} already pending"),
        );
        return;
    }
    let request = transcript_effect::Request::Export {
        workspace: workspace.to_path_buf(),
        rollout_path: rollout_path.to_path_buf(),
        blocks: app.transcript.clone(),
        selected_ids: None,
        requested: requested.into(),
        collision,
        origin: transcript_effect::Origin::Slash,
    };
    if supervisor.start(request).is_ok() {
        app.note(block::NoticeLevel::Info, "transcript export pending…");
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "transcript export not started: another effect is pending",
        );
    }
}

pub(super) fn apply_transcript_effect_event(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    event: transcript_effect::Event,
) {
    if let Some(shell) = event.shell {
        app.push_shell_card(&shell.command, shell.body, shell.ok, shell.code);
        return;
    }
    if let Some(control) = event.control {
        match (control.kind, control.reply) {
            (
                transcript_effect::ControlKind::Compact,
                Some(app_server::ControlReply::Compacted { report, snapshot }),
            ) => {
                app.cost = snapshot.cost.clone();
                app.last_turn_usage = snapshot.last_turn_usage;
                session.adopt(*snapshot);
                app.push(
                    fg(Color::Green),
                    format!("compacted {} -> {} messages", report.before, report.after),
                );
            }
            (
                transcript_effect::ControlKind::Side,
                Some(app_server::ControlReply::SideAnswer(answer)),
            ) => show_side_answer(app, &answer),
            (
                transcript_effect::ControlKind::Side,
                Some(app_server::ControlReply::SideStatus { status, closed }),
            ) => show_side_status(app, status.as_deref(), closed),
            (
                transcript_effect::ControlKind::Workflow,
                Some(app_server::ControlReply::Workflows(reply)),
            ) => {
                app.workflows_panel.update_inventory(reply.runs);
                app.workflows_panel.finish_action(
                    reply
                        .notice
                        .unwrap_or_else(|| "workflow owner state refreshed".into()),
                );
            }
            (
                transcript_effect::ControlKind::Effort(requested),
                Some(app_server::ControlReply::State(snapshot)),
            ) => {
                app.effort = snapshot.effort;
                clear_last_turn_telemetry_from(app, &snapshot);
                session.adopt(*snapshot);
                app.note(
                    block::NoticeLevel::Ok,
                    format!("effort set to {}", requested.label()),
                );
            }
            (
                transcript_effect::ControlKind::PermissionMode(requested),
                Some(app_server::ControlReply::State(snapshot)),
            ) => {
                app.mode = snapshot.mode;
                session.adopt(*snapshot);
                app.note(
                    block::NoticeLevel::Ok,
                    format!("mode set to {}", requested.label()),
                );
            }
            (
                transcript_effect::ControlKind::Capability {
                    capability,
                    verdict,
                },
                Some(app_server::ControlReply::State(snapshot)),
            ) => {
                app.mode = snapshot.mode;
                session.adopt(*snapshot);
                let verdict = match verdict {
                    Verdict::Auto => "allow",
                    Verdict::Ask => "ask",
                    Verdict::Deny => "deny",
                };
                app.note(
                    block::NoticeLevel::Ok,
                    format!("permission rule: {} → {verdict}", cap_label(capability)),
                );
            }
            (
                transcript_effect::ControlKind::Model {
                    selection,
                    provider_name,
                    context_window_tokens,
                    changed,
                },
                Some(app_server::ControlReply::State(snapshot)),
            ) => {
                app.model = snapshot.model.clone();
                let applied = ModelSelection {
                    provider_id: selection.provider_id.clone(),
                    model_id: snapshot.model.clone(),
                };
                app.route = app.route.reselect(directory, &applied);
                app.model_context_window = context_window_tokens;
                if changed {
                    clear_last_turn_telemetry_from(app, &snapshot);
                }
                session.adopt(*snapshot);
                let persisted_provider = applied.provider_id.clone();
                let persisted_model = applied.model_id.clone();
                std::mem::drop(tokio::task::spawn_blocking(move || {
                    crate::config::update_user_config(move |config| {
                        crate::config::apply_setting(config, "provider", &persisted_provider)?;
                        crate::config::apply_setting(config, "model", &persisted_model)
                    })
                }));
                app.note(
                    block::NoticeLevel::Ok,
                    format!(
                        "model set to {}:{} · {provider_name} backend",
                        applied.provider_id, applied.model_id
                    ),
                );
                if changed {
                    app.note(
                        block::NoticeLevel::Warn,
                        "switching model re-reads the history uncached (new prefix cache)",
                    );
                }
            }
            (
                transcript_effect::ControlKind::Adopt {
                    fresh,
                    events,
                    selection,
                    substituted,
                    context_window_tokens,
                    ..
                },
                Some(app_server::ControlReply::Adopted {
                    adopted,
                    snapshot,
                    tunables_checkpoint,
                    compaction_trigger_tokens,
                    blocked,
                }),
            ) => {
                clear_transcript_for_adoption(app);
                let (blocks, total) = adopted_transcript_blocks(&events);
                let rendered = blocks.len();
                if rendered < total {
                    app.note(
                        block::NoticeLevel::Info,
                        format!(
                            "showing the last {rendered} of {total} recorded transcript blocks; the model continues from all of them"
                        ),
                    );
                }
                for kind in blocks {
                    app.push_block(kind);
                }
                session.adopt_run(
                    adopted.rollout_path.clone(),
                    *tunables_checkpoint,
                    compaction_trigger_tokens,
                    (*snapshot).clone(),
                );
                // The exact title is hydrated off-thread elsewhere; the run id is an immediate,
                // truthful cache and avoids a record read on this completion path.
                app.session_name = if fresh {
                    "New session".into()
                } else {
                    adopted.run_id.clone()
                };
                app.mode = snapshot.mode;
                app.effort = snapshot.effort;
                app.model = snapshot.model.clone();
                app.cost = snapshot.cost.clone();
                app.turns = if fresh { 0 } else { adopted.turns };
                app.route = app.route.reselect(
                    directory,
                    &ModelSelection {
                        provider_id: selection.provider_id.clone(),
                        model_id: snapshot.model.clone(),
                    },
                );
                app.model_context_window = context_window_tokens;
                clear_last_turn_telemetry_from(app, &snapshot);
                app.status = if fresh {
                    "ready".into()
                } else {
                    format!("idle · resumed {}", adopted.run_id)
                };
                if let Some(reason) = substituted {
                    app.note(
                        block::NoticeLevel::Warn,
                        format!(
                            "{reason}; this session continues on {}:{}",
                            selection.provider_id, selection.model_id
                        ),
                    );
                }
                app.note(
                    block::NoticeLevel::Ok,
                    if fresh {
                        format!(
                            "new session {} · left {}",
                            adopted.run_id, adopted.previous_run_id
                        )
                    } else {
                        format!(
                            "resumed {} here · {} · {} · {}:{} · left {}",
                            adopted.run_id,
                            block::plural(adopted.messages, "message"),
                            block::plural(adopted.turns as usize, "turn"),
                            selection.provider_id,
                            snapshot.model,
                            adopted.previous_run_id
                        )
                    },
                );
                if let Some(reason) = blocked {
                    app.note(block::NoticeLevel::Err, reason);
                    app.prepare_resume_handoff(&adopted.run_id);
                }
            }
            (
                transcript_effect::ControlKind::Adopt { run_id, .. },
                Some(app_server::ControlReply::Refused(reason)),
            ) => {
                app.note(block::NoticeLevel::Err, reason);
                app.prepare_resume_handoff(&run_id);
            }
            (
                transcript_effect::ControlKind::OperatorStatus {
                    tunables_argument: None,
                },
                Some(app_server::ControlReply::OperatorStatus(snapshot)),
            ) => status_command::render(app, session, *snapshot),
            (
                transcript_effect::ControlKind::OperatorStatus {
                    tunables_argument: Some(argument),
                },
                Some(app_server::ControlReply::OperatorStatus(snapshot)),
            ) => open_tunables_picker_with_runtime_policy(
                app,
                session,
                &argument,
                snapshot.runtime.runtime_policy.as_ref(),
            ),
            (
                transcript_effect::ControlKind::TurnBudget { set },
                Some(app_server::ControlReply::TurnBudget(state)),
            ) => {
                if set.is_some() {
                    app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "turn ceiling is now {} ({} used, {} left this session)",
                            state.max_turns,
                            state.used,
                            state.remaining()
                        ),
                    );
                } else {
                    app.panel(
                        "◷",
                        "turn budget",
                        vec![
                            kv("ceiling", &state.max_turns.to_string()),
                            kv(
                                "used",
                                &format!("{} (this session, subagents included)", state.used),
                            ),
                            kv("remaining", &state.remaining().to_string()),
                            block::PanelRow::Note(
                                "/budget <turns> raises the ceiling without restarting".into(),
                            ),
                        ],
                    );
                }
            }
            (
                transcript_effect::ControlKind::WorkflowsInventory,
                Some(app_server::ControlReply::Workflows(reply)),
            ) => {
                app.workflows_panel.update_inventory(reply.runs);
                if let Some(notice) = reply.notice {
                    app.workflows_panel.finish_action(notice);
                }
                app.workflows_panel.open();
            }
            (transcript_effect::ControlKind::Mcp, Some(app_server::ControlReply::Mcp(reply))) => {
                mcp_command::render_reply(app, *reply)
            }
            (
                transcript_effect::ControlKind::Jobs { command },
                Some(app_server::ControlReply::Jobs(value)),
            ) => jobs::render_control_reply(app, &command, &value),
            (
                transcript_effect::ControlKind::Memory,
                Some(app_server::ControlReply::Memory(reply)),
            ) => command_dispatch::render_memory_reply(app, reply),
            (kind, Some(app_server::ControlReply::Refused(reason))) => {
                let action = kind.label();
                let prefix = if control.cancellation_requested {
                    "cancelled"
                } else {
                    "refused"
                };
                app.note(
                    block::NoticeLevel::Warn,
                    format!("{action} {prefix}: {reason}"),
                );
            }
            (_, Some(app_server::ControlReply::State(snapshot))) => session.adopt(*snapshot),
            (_, None) => app.note(block::NoticeLevel::Warn, ui_safe_text(&event.message)),
            _ => app.note(
                block::NoticeLevel::Warn,
                "runtime returned an unexpected control reply",
            ),
        }
        return;
    }
    let message = ui_safe_text(&event.message);
    if event.origin == transcript_effect::Origin::Viewer && app.transcript_viewer.is_open() {
        if event.is_final() {
            app.transcript_viewer.finish_effect(message);
        } else {
            app.transcript_viewer.set_notice(message);
        }
        return;
    }
    let level = match event.outcome {
        transcript_effect::Disposition::Success => block::NoticeLevel::Ok,
        transcript_effect::Disposition::KnownFailure
        | transcript_effect::Disposition::OutcomeUnknown => block::NoticeLevel::Warn,
    };
    app.note(level, message);
}

/// Create an initialization file without a check/write race and make its contents durable before
/// reporting success. Existing files are never overwritten.
pub(super) fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Render the catalog the resident runtime can actually execute. The session fact is captured once
/// at App Server attach, so opening this panel performs no filesystem or ambient-home discovery.
pub(super) fn show_agent_catalog(app: &mut App, session: &Session) {
    let catalog = session.agent_catalog();
    let mut rows: Vec<block::PanelRow> = catalog
        .defs()
        .iter()
        .map(|definition| item("⑂", &definition.name, &definition.description))
        .collect();
    if rows.is_empty() {
        rows.push(block::PanelRow::Note(
            "no agent definitions (built-in `generic` is normally available)".into(),
        ));
    }
    for error in catalog.errors() {
        rows.push(block::PanelRow::Note(format!(
            "rejected: {} ({})",
            error.source, error.reason
        )));
    }
    // `App::panel` applies the shared 120-row ceiling plus credential/control sanitization before
    // retaining any catalog-derived text in the transcript.
    app.panel("⑂", "agents", rows);
}

/// `/clear`: drop the conversation, keep what is still running.
///
/// The command clears the CONVERSATION; it cancels nothing. A QuickJS script run launched before it
/// is still running afterwards, still spending tokens, and still the thing the operator most needs
/// to see — so the workflow region survives `/clear`, and the card it draws survives with it. The
/// card is the region's only copy of the tree (see `workflow_region`), so dropping it would blank a
/// running workflow with nothing able to restore it; a cleared conversation that retains one block
/// the transcript never draws is the smaller lie. Nothing of that run is visible in the conversation
/// either way: the region is where a live run is watched, and its permanent record is only written
/// into the transcript when it settles.
///
/// Settled runs leave with the rest of the conversation, permanent records included — that is what
/// clearing was asked to do — and their bindings are dropped in the same breath rather than left
/// pointing at blocks that no longer exist.
pub(super) fn clear_conversation(app: &mut App) {
    let live_workflow_blocks = app.workflow_monitor.live_blocks();
    app.transcript
        .retain(|block| live_workflow_blocks.contains(&block.id));
    app.workflow_monitor.clear_finished();
    app.mark_transcript_changed();
    app.tool_index.clear();
    app.workflow_index.clear();
    app.cur_text.clear();
    app.cur_text_revision = app.cur_text_revision.wrapping_add(1);
    app.cur_doc_revision = app.cur_text_revision;
    app.cur_doc = None;
    app.cur_think.clear();
    app.render_cache.clear();
    app.push(dim(), "transcript cleared");
}

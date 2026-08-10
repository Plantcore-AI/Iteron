//! In-process slash-command dispatch.

use super::*;

pub(super) async fn handle_registered_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    transcript_effects: &mut transcript_effect::Supervisor,
    command: SlashCommand,
    arg: &str,
) {
    match command {
        SlashCommand::Help => {
            let mut rows: Vec<block::PanelRow> = commands::COMMANDS
                .iter()
                .map(|c| item("/", &format!("{} {}", c.name, c.args), c.help))
                .collect();
            rows.push(block::PanelRow::Note("keys: drag selects · wheel/trackpad scrolls transcript · ↑↓ prompt history · Ctrl-R prompt search · Ctrl-F transcript · Ctrl-G external editor · ←→/Ctrl-A/E/U/K/W edit · @file · !shell · Shift+Tab permission mode · Ctrl-C interrupt".into()));
            rows.push(block::PanelRow::Note(
                "operator config: tui_keymap supports standard/vim and five conflict-checked actions; lifecycle keys remain reserved".into(),
            ));
            rows.push(block::PanelRow::Note(
                "while running: Enter steer · Tab queue · Ctrl-J newline · Alt-Up edit queued · Ctrl-End follow".into(),
            ));
            app.panel("?", "commands", rows);
        }
        SlashCommand::Clear => clear_conversation(app),
        SlashCommand::Effort => {
            if arg.is_empty() {
                open_picker(app, session, directory, "effort"); // interactive picker (R7.a)
            } else if let Some(e) = core_protocol::Effort::parse(arg) {
                if commit_effort(app, session, e).await {
                    app.push(fg(Color::Green), format!("effort set to {}", e.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown effort (low|medium|high|xhigh|max|ultracode)",
                );
            }
        }
        SlashCommand::Model => {
            if arg.is_empty() {
                open_picker(app, session, directory, "model"); // interactive picker (R7.a)
            } else if arg == "retry" || arg.starts_with("retry ") {
                let value = arg.strip_prefix("retry").unwrap_or_default().trim();
                let selection = match model_retry_selection(
                    directory,
                    &app.route.provider_id,
                    session.model(),
                    value,
                ) {
                    Ok(selection) => selection,
                    Err(error) => {
                        app.note(
                            block::NoticeLevel::Err,
                            format!("cannot retry model: {error}"),
                        );
                        return;
                    }
                };
                match directory.clear_model_unavailable_for_retry(&selection) {
                    Ok(true) => apply_model_selection(app, session, directory, selection).await,
                    Ok(false) => app.note(
                        block::NoticeLevel::Warn,
                        "that model is not blocked; normal /model selection is unchanged",
                    ),
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("cannot retry model: {error}"),
                    ),
                }
            } else {
                match directory.resolve_model(arg, Some(&app.route.provider_id)) {
                    Ok(selection) => {
                        apply_model_selection(app, session, directory, selection).await
                    }
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("cannot select model: {error}"),
                    ),
                }
            }
        }
        SlashCommand::Theme => {
            open_picker(app, session, directory, "theme");
        }
        SlashCommand::Status => {
            status_command::handle(app, session).await;
        }
        SlashCommand::Cost => {
            app.panel(
                "$",
                "cost",
                vec![block::PanelRow::Note(session.ledger_summary().to_string())],
            );
        }
        SlashCommand::Budget => {
            // The turn ceiling counts the whole session, so it is the one budget an operator can
            // saturate mid-task with no way out except restarting the process. `/budget <turns>`
            // is that way out; the bare form shows how close the session already is.
            let requested = arg.trim();
            let set = if requested.is_empty() {
                None
            } else {
                match requested.parse::<u32>() {
                    Ok(turns) => Some(turns),
                    Err(_) => {
                        app.push(fg(Color::Red), "usage: /budget [turns]");
                        return;
                    }
                }
            };
            match session
                .control(app_server::Control::TurnBudget { set })
                .await
            {
                Some(app_server::ControlReply::TurnBudget(state)) => {
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
                Some(app_server::ControlReply::Refused(reason)) => app.note(
                    block::NoticeLevel::Err,
                    format!("the turn ceiling was not changed: {reason}"),
                ),
                _ => app.note(
                    block::NoticeLevel::Err,
                    "the runtime is no longer reachable",
                ),
            }
        }
        SlashCommand::Context => {
            if matches!(arg.trim(), "stats" | "ledger" | "decisions") {
                let snapshot = session.context_ledger_snapshot();
                let mut rows = vec![
                    kv("retained turns", &snapshot.ledgers.len().to_string()),
                    kv(
                        "store drops",
                        &format!(
                            "{} oldest · {} contention · {} unmatched",
                            snapshot.dropped_oldest,
                            snapshot.dropped_contention,
                            snapshot.dropped_unmatched
                        ),
                    ),
                ];
                if let Some(ledger) = snapshot.ledgers.last() {
                    rows.extend([
                        kv("turn", &ledger.turn_id.0.to_string()),
                        kv(
                            "tokenizer",
                            &format!(
                                "{} v{} · {}",
                                ledger.estimator.catalog_id,
                                ledger.estimator.version,
                                if ledger.estimator.exact {
                                    "exact"
                                } else {
                                    "estimated"
                                }
                            ),
                        ),
                        kv(
                            "window",
                            &format!(
                                "{} model · {} usable · {} output reserve",
                                ledger
                                    .model_context_window
                                    .map(|value| format!("{value} tok"))
                                    .unwrap_or_else(|| "unknown".into()),
                                ledger
                                    .usable_window
                                    .map(|value| format!("{value} tok"))
                                    .unwrap_or_else(|| "unknown".into()),
                                ledger.output_reserved_tokens
                            ),
                        ),
                        kv(
                            "segments",
                            &format!(
                                "{} selected · {} rejected · {} dropped",
                                ledger.totals.selected_segments,
                                ledger.totals.rejected_segments,
                                ledger.dropped
                            ),
                        ),
                        kv(
                            "tokens",
                            &match ledger.totals.actual_input_tokens {
                                Some(actual) => format!(
                                    "{} estimated · {actual} provider",
                                    ledger.totals.estimated_tokens
                                ),
                                None => format!("{} estimated", ledger.totals.estimated_tokens),
                            },
                        ),
                        kv(
                            "cache",
                            &format!(
                                "{} stable · {} read · {} write · {} uncached",
                                ledger.cache.stable_prefix_tokens,
                                ledger.cache.cache_read_tokens,
                                ledger.cache.cache_write_tokens,
                                ledger.cache.uncached_tokens
                            ),
                        ),
                        kv(
                            "token classes",
                            &format!(
                                "{} schema · {} attachment · {} duplicate · {} reclaimable",
                                ledger.totals.tool_schema_tokens,
                                ledger.totals.attachment_tokens,
                                ledger.totals.duplicate_tokens,
                                ledger.totals.reclaimable_tokens
                            ),
                        ),
                        kv("transforms", &ledger.transforms.len().to_string()),
                        kv(
                            "headroom",
                            &ledger
                                .headroom_tokens()
                                .map(|tokens| format!("{tokens} tok"))
                                .unwrap_or_else(|| "unknown".into()),
                        ),
                    ]);
                    if let Some(compaction) = &ledger.compaction {
                        rows.push(kv(
                            "compaction",
                            &format!(
                                "{} -> {} tok @ {} · obligations {} kept / {} lost · {}",
                                compaction.before_tokens,
                                compaction.after_tokens,
                                compaction.trigger_tokens,
                                compaction.obligations_preserved,
                                compaction.obligations_lost,
                                compaction.reason_code
                            ),
                        ));
                    }
                    for segment in ledger.segments.iter().take(24) {
                        rows.push(block::PanelRow::Note(format!(
                            "#{:02} {:?} · {:?} · {} tok · {} bytes · {:?}",
                            segment.ordinal,
                            segment.source_class,
                            segment.decision,
                            segment.estimated_tokens,
                            segment.bytes_after,
                            segment.cache_class
                        )));
                    }
                    if ledger.segments.len() > 24 {
                        rows.push(block::PanelRow::Note(format!(
                            "… {} more segments",
                            ledger.segments.len() - 24
                        )));
                    }
                }
                app.panel("◇", "context decision ledger", rows);
            } else {
                context_chips::handle(app, session, arg).await;
            }
        }
        SlashCommand::Telemetry => {
            let snapshot = session.lifecycle_snapshot();
            let otel = session.lifecycle_otel_snapshot();
            let hooks = session.hook_health_snapshot();
            let exporter = session.telemetry_export_health_snapshot();
            let mut by_domain = std::collections::BTreeMap::<&str, u64>::new();
            for event in &snapshot.events {
                let domain = event
                    .event_id
                    .as_str()
                    .split('.')
                    .next()
                    .unwrap_or("unknown");
                *by_domain.entry(domain).or_default() += 1;
            }
            let mut rows = vec![
                kv(
                    "catalog",
                    &format!("{} lifecycle events", core_protocol::lifecycle::EVENT_COUNT),
                ),
                kv("recorded", &snapshot.events.len().to_string()),
                kv("next ordinal", &snapshot.next_ordinal.to_string()),
                kv(
                    "recorder drops",
                    &format!(
                        "{} oldest · {} contention · {} subscriber · {} invalid",
                        snapshot.dropped_oldest,
                        snapshot.dropped_contention,
                        snapshot.dropped_subscriber,
                        snapshot.invalid
                    ),
                ),
                kv(
                    "OTel catalog",
                    &format!(
                        "{} metrics · {} logs · {} spans",
                        core_obs::otel::catalog::METRIC_INSTRUMENT_COUNT,
                        core_obs::otel::catalog::LOG_SCHEMA_COUNT,
                        core_obs::otel::catalog::SPAN_TEMPLATE_COUNT
                    ),
                ),
                kv(
                    "Hook queue",
                    &format!(
                        "{} queued · {} live · {} dropped",
                        hooks.queued, hooks.queue_depth, hooks.dropped
                    ),
                ),
                kv(
                    "Hook outcomes",
                    &format!(
                        "{} completed · {} failed · {} timed out · {} blocked",
                        hooks.completed, hooks.failed, hooks.timed_out, hooks.blocked
                    ),
                ),
                kv("Hook circuits", &format!("{} open", hooks.open_circuits)),
            ];
            for (domain, count) in by_domain {
                rows.push(kv(domain, &count.to_string()));
            }
            if let Some(last) = snapshot.events.last() {
                rows.push(block::PanelRow::Note(format!(
                    "latest: #{} {}",
                    last.ordinal, last.event_id
                )));
            }
            if let Some(otel) = otel {
                rows.push(kv(
                    "live OTel",
                    &format!(
                        "{} logs · {} metrics · {} spans · {} open",
                        otel.logs.len(),
                        otel.metrics.len(),
                        otel.spans.len(),
                        otel.open_spans
                    ),
                ));
                rows.push(kv(
                    "OTel drops",
                    &format!(
                        "{} logs · {} spans · {} open-span",
                        otel.dropped_logs, otel.dropped_spans, otel.dropped_open_spans
                    ),
                ));
            }
            if let Some(exporter) = exporter {
                rows.push(kv(
                    "exporter",
                    &format!(
                        "enabled · {} attempts · {} accepted · {} rejected · {} unknown",
                        exporter.attempts, exporter.accepted, exporter.rejected, exporter.unknown
                    ),
                ));
                if let Some(last) = exporter.last_outcome {
                    rows.push(kv("exporter last", &last));
                }
            } else {
                rows.push(kv("exporter", "off (trusted user config only)"));
            }
            app.panel("◉", "telemetry", rows);
        }
        SlashCommand::Mode => {
            if arg.is_empty() {
                open_picker(app, session, directory, "mode"); // interactive picker (Shift+Tab still cycles)
            } else if let Some(m) = PermissionMode::parse(arg) {
                if commit_permission_mode(app, session, m).await {
                    app.push(fg(Color::Green), format!("mode set to {}", m.label()));
                }
            } else {
                app.push(
                    fg(Color::Red),
                    "unknown mode (default|acceptEdits|plan|yolo)",
                );
            }
        }
        SlashCommand::Permissions => {
            let mut sub = arg.split_whitespace();
            match sub.next() {
                None => open_picker(app, session, directory, "permissions"),
                Some("show" | "list") => {
                    let mut rows = vec![kv("mode", &permission_mode_row_value(session))];
                    let rules = session.permission_rules().describe();
                    if rules.is_empty() {
                        rows.push(block::PanelRow::Note(
                            "no session rules (mode defaults apply)".into(),
                        ));
                    } else {
                        for r in rules {
                            rows.push(item("•", &r, ""));
                        }
                    }
                    app.panel("⚿", "permissions", rows);
                }
                Some(word) => {
                    let verdict = match word {
                        "allow" => Some(Verdict::Auto),
                        "ask" => Some(Verdict::Ask),
                        "deny" => Some(Verdict::Deny),
                        _ => None,
                    };
                    let cap = sub.next().and_then(parse_cap);
                    match (verdict, cap) {
                        (Some(v), Some(c)) => {
                            let verdict_label = match v {
                                Verdict::Auto => "allow",
                                Verdict::Ask => "ask",
                                Verdict::Deny => "deny",
                            };
                            if commit_permission_capability(app, session, c, v).await {
                                app.note(
                                    block::NoticeLevel::Ok,
                                    format!(
                                        "permission rule: {} → {verdict_label}",
                                        cap_label(c)
                                    ),
                                );
                            }
                        }
                        _ => app.push(fg(Color::Red), "usage: /permissions [allow|ask|deny <read_only|reversible_local|code_executing|trust_mutating|irreversible_external>]"),
                    }
                }
            }
        }
        SlashCommand::AllowCode => match arg {
            "on" | "true" | "" => {
                if commit_permission_capability(
                    app,
                    session,
                    Capability::CodeExecuting,
                    Verdict::Auto,
                )
                .await
                {
                    app.push(
                        fg(Color::Yellow),
                        "code execution ALLOWED (egress-off sandbox)",
                    );
                }
            }
            "off" | "false" => {
                if commit_permission_capability(
                    app,
                    session,
                    Capability::CodeExecuting,
                    Verdict::Ask,
                )
                .await
                {
                    app.push(fg(Color::Yellow), "code execution now asks per call");
                }
            }
            _ => app.push(fg(Color::Red), "usage: /allow-code on|off"),
        },
        SlashCommand::Memory => {
            if matches!(arg.trim(), "trace" | "stats" | "decisions") {
                let snapshot = session.memory_trace_snapshot();
                let mut rows = vec![
                    kv("retained turns", &snapshot.traces.len().to_string()),
                    kv(
                        "store drops",
                        &format!(
                            "{} oldest · {} contention · {} unmatched",
                            snapshot.dropped_oldest,
                            snapshot.dropped_contention,
                            snapshot.dropped_unmatched
                        ),
                    ),
                ];
                if let Some(trace) = snapshot.traces.last() {
                    let mut decisions = std::collections::BTreeMap::<String, u64>::new();
                    for candidate in &trace.candidates {
                        *decisions
                            .entry(format!("{:?}", candidate.decision).to_ascii_lowercase())
                            .or_default() += 1;
                    }
                    let mut visibility = std::collections::BTreeMap::<String, u64>::new();
                    for evidence in &trace.visibility {
                        *visibility
                            .entry(format!("{:?}", evidence.state).to_ascii_lowercase())
                            .or_default() += 1;
                    }
                    rows.extend([
                        kv("turn", &trace.turn_id.0.to_string()),
                        kv(
                            "query",
                            &format!(
                                "{} bytes · {} tok · {} rewrites",
                                trace.query.bytes,
                                trace.query.estimated_tokens,
                                trace.query.rewrite_count
                            ),
                        ),
                        kv(
                            "scope",
                            &format!(
                                "{:?} · isolation {} · {} parent rejects",
                                trace.scope.class,
                                if trace.scope.isolation_enabled {
                                    "on"
                                } else {
                                    "off"
                                },
                                trace.scope.parent_access_rejections
                            ),
                        ),
                        kv("stores", &trace.stores.len().to_string()),
                        kv(
                            "candidates",
                            &format!(
                                "{} observed · {} selected · {} dropped",
                                trace.candidates.len(),
                                trace.budget.selected_count,
                                trace.dropped_candidates
                            ),
                        ),
                        kv(
                            "budget",
                            &format!(
                                "{} / {} tok · {} / {} bytes",
                                trace.budget.granted_tokens,
                                trace.budget.requested_tokens,
                                trace.budget.granted_bytes,
                                trace.budget.requested_bytes
                            ),
                        ),
                        kv(
                            "injection",
                            &trace
                                .injection
                                .as_ref()
                                .map(|value| {
                                    format!(
                                        "{} facts · {} tok · {} bytes",
                                        value.fact_count, value.estimated_tokens, value.bytes
                                    )
                                })
                                .unwrap_or_else(|| "none".into()),
                        ),
                        kv(
                            "visibility",
                            &if visibility.is_empty() {
                                "none".into()
                            } else {
                                visibility
                                    .into_iter()
                                    .map(|(state, count)| format!("{count} {state}"))
                                    .collect::<Vec<_>>()
                                    .join(" · ")
                            },
                        ),
                        kv(
                            "provider exposure",
                            &format!(
                                "{} attributed · causal influence not inferred",
                                trace.attribution.len()
                            ),
                        ),
                    ]);
                    if !decisions.is_empty() {
                        rows.push(kv(
                            "candidate decisions",
                            &decisions
                                .into_iter()
                                .map(|(decision, count)| format!("{count} {decision}"))
                                .collect::<Vec<_>>()
                                .join(" · "),
                        ));
                    }
                    if let Some(contamination) = &trace.contamination {
                        rows.push(kv(
                            "contamination",
                            &format!(
                                "{} · {} checked · {} rejected · {} canary",
                                if contamination.passed {
                                    "passed"
                                } else {
                                    "failed"
                                },
                                contamination.checked_candidates,
                                contamination.rejected_candidates,
                                contamination.canary_matches
                            ),
                        ));
                    }
                    rows.push(kv(
                        "trace drops",
                        &format!(
                            "{} stores · {} candidates · {} selected · {} visibility",
                            trace.dropped_stores,
                            trace.dropped_candidates,
                            trace.dropped_selections,
                            trace.dropped_visibility
                        ),
                    ));
                }
                app.panel("◆", "memory decision trace", rows);
                return;
            }
            let ws = session.memory_workspace();
            let Some(ws) = ws else {
                app.push(fg(Color::Red), "memory not available");
                return;
            };
            let store = core_ctx::MemoryStore::at(ws);
            let mut sub = arg.split_whitespace();
            match sub.next() {
                Some("add") => {
                    let text = arg.strip_prefix("add").unwrap_or("").trim().to_string();
                    if text.is_empty() {
                        app.push(fg(Color::Red), "usage: /memory add <fact>");
                    } else {
                        match session
                            .control(app_server::Control::Memory(app_server::MemoryControl::Add(
                                text.clone(),
                            )))
                            .await
                        {
                            Some(app_server::ControlReply::Memory(
                                app_server::MemoryControlReply::Added { id },
                            )) => app.push(
                                fg(Color::Green),
                                format!("remembered ({id}) — available in this session"),
                            ),
                            Some(app_server::ControlReply::Refused(reason)) => {
                                app.push(fg(Color::Red), reason)
                            }
                            _ => app.push(
                                fg(Color::Red),
                                "the memory authority is no longer reachable",
                            ),
                        }
                    }
                }
                Some("update") => {
                    let id = sub.next().unwrap_or("").to_owned();
                    let text = arg
                        .strip_prefix("update")
                        .unwrap_or("")
                        .trim_start()
                        .strip_prefix(&id)
                        .unwrap_or("")
                        .trim_start()
                        .to_owned();
                    if id.is_empty() || text.is_empty() {
                        app.push(fg(Color::Red), "usage: /memory update <id> <fact>");
                    } else {
                        match session
                            .control(app_server::Control::Memory(
                                app_server::MemoryControl::Update {
                                    id: id.clone(),
                                    text,
                                },
                            ))
                            .await
                        {
                            Some(app_server::ControlReply::Memory(
                                app_server::MemoryControlReply::Updated { old_id, id },
                            )) => app.push(
                                fg(Color::Green),
                                format!("updated {old_id} → {id} — available in this session"),
                            ),
                            Some(app_server::ControlReply::Memory(
                                app_server::MemoryControlReply::Missing { id },
                            )) => app.push(fg(Color::Red), format!("no memory {id}")),
                            Some(app_server::ControlReply::Refused(reason)) => {
                                app.push(fg(Color::Red), reason)
                            }
                            _ => app.push(
                                fg(Color::Red),
                                "the memory authority is no longer reachable",
                            ),
                        }
                    }
                }
                Some("list") | None => {
                    let facts = store.load();
                    if facts.is_empty() {
                        app.note(
                            block::NoticeLevel::Info,
                            "no memory yet — /memory add <fact>",
                        );
                    } else {
                        let rows = facts
                            .iter()
                            .map(|f| {
                                item(
                                    "◆",
                                    f.text.lines().next().unwrap_or(""),
                                    &format!("[{}]", f.id),
                                )
                            })
                            .collect();
                        app.panel("◆", &block::plural(facts.len(), "remembered fact"), rows);
                    }
                }
                Some("forget") | Some("rm") => {
                    let id = sub.next().unwrap_or("").to_owned();
                    match session
                        .control(app_server::Control::Memory(
                            app_server::MemoryControl::Delete(id.clone()),
                        ))
                        .await
                    {
                        Some(app_server::ControlReply::Memory(
                            app_server::MemoryControlReply::Deleted { id },
                        )) => app.push(fg(Color::Green), format!("forgot {id}")),
                        Some(app_server::ControlReply::Memory(
                            app_server::MemoryControlReply::Missing { id },
                        )) => app.push(fg(Color::Red), format!("no memory {id}")),
                        Some(app_server::ControlReply::Refused(reason)) => {
                            app.push(fg(Color::Red), reason)
                        }
                        _ => app.push(
                            fg(Color::Red),
                            "the memory authority is no longer reachable",
                        ),
                    }
                }
                Some(x) => app.push(
                    fg(Color::Red),
                    format!("unknown /memory subcommand `{x}` (add|update|list|forget)"),
                ),
            }
        }
        SlashCommand::Diff => {
            let stat = arg.trim() == "stat";
            match crate::workspace_review::observe(session.workspace()).await {
                Ok(review) if review.is_empty() => {
                    app.note(block::NoticeLevel::Info, "no uncommitted changes");
                }
                Ok(review) => {
                    let mut rows = review
                        .summary()
                        .into_iter()
                        .take(120)
                        .map(block::PanelRow::Note)
                        .collect::<Vec<_>>();
                    let blind = review.changes.invisible_to_bare_diff().len();
                    rows.push(block::PanelRow::Note(format!(
                        "{} path(s) total · {blind} invisible to bare git diff",
                        review.changes.entries.len()
                    )));
                    app.panel("±", "complete change set", rows);
                    if !stat {
                        match review.verified_diffs() {
                            Ok(documents) => {
                                for document in documents {
                                    let text = core_record::redact::scrub(document);
                                    for diff in core_protocol::FileDiff::from_unified(&text) {
                                        app.push_block(block::BlockKind::Diff(diff));
                                    }
                                }
                            }
                            Err(error) => app.note(block::NoticeLevel::Err, error),
                        }
                    }
                }
                Err(error) => app.push(
                    fg(Color::Red),
                    format!("could not read complete bounded change set: {error}"),
                ),
            }
        }
        SlashCommand::Sessions => {
            handle_sessions_command(app, session, directory, arg).await;
        }
        SlashCommand::Workflows => {
            match session
                .control(app_server::Control::Workflow(
                    app_server::WorkflowControl::Inventory,
                ))
                .await
            {
                Some(app_server::ControlReply::Workflows(reply)) => {
                    app.workflows_panel.update_inventory(reply.runs);
                    if let Some(notice) = reply.notice {
                        app.workflows_panel.finish_action(notice);
                    }
                    app.workflows_panel.open();
                }
                Some(app_server::ControlReply::Refused(reason)) => {
                    app.note(block::NoticeLevel::Err, reason)
                }
                _ => app.note(
                    block::NoticeLevel::Err,
                    "the workflow owner is no longer reachable",
                ),
            }
        }
        SlashCommand::Jobs => jobs::handle(app, session, arg).await,
        SlashCommand::Fork => {
            // Fork the CURRENT session at its tail into a new branch (shared past, divergent future).
            let path = session.rollout_path().to_path_buf();
            let runs = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            match core_record::replay(&path) {
                Ok(events) if !events.is_empty() => {
                    let at = events.last().map(|e| e.seq).unwrap();
                    match core_record::fork(
                        &runs,
                        &core_protocol::RunId(stem),
                        at,
                        &core_protocol::TenantId::default(),
                    ) {
                        Ok(child) => {
                            app.note(
                                block::NoticeLevel::Ok,
                                format!("forked {child} · adopting the divergent branch"),
                            );
                            adopt_session(app, session, directory, &child.0).await;
                        }
                        Err(e) => app.push(fg(Color::Red), format!("fork failed: {e}")),
                    }
                }
                Ok(_) => app.push(fg(Color::Red), "nothing to fork yet"),
                Err(e) => app.push(fg(Color::Red), format!("cannot read this session: {e}")),
            }
        }
        SlashCommand::Agents => {
            show_agent_catalog(app, session);
        }
        SlashCommand::Skills => {
            let home = crate::config::config_home();
            let cat = core_ctx::skills::SkillCatalog::discover_for_operator_with_dependencies(
                home.as_deref(),
                session.workspace(),
                session.dependency_skill_dirs(),
            );
            let mut rows: Vec<block::PanelRow> = cat
                .defs()
                .iter()
                .map(|s| item("◇", &s.name, &s.description))
                .collect();
            if rows.is_empty() {
                rows.push(block::PanelRow::Note(
                    "no skills (add <repo>/.core/skills or <repo>/.agents/skills)".into(),
                ));
            }
            for e in cat.errors() {
                rows.push(block::PanelRow::Note(format!(
                    "rejected: {} ({})",
                    e.source, e.reason
                )));
            }
            app.panel("◇", "skills", rows);
        }
        SlashCommand::Config => {
            // `/config` used to re-read the REPOSITORY config document, so it reported what was on
            // disk instead of the layered value the kernel enforces: `core --max-turns 5` printed
            // `max_turns: default`. It reads the one resolved route and the same effective limits
            // the budget was built from (I-26).
            let mut rows: Vec<block::PanelRow> = app
                .route
                .rows()
                .iter()
                .map(|(key, value)| kv(key, value))
                .collect();
            rows.push(kv(
                "harness profile",
                session.runtime_profile_id().unwrap_or("unrecognized"),
            ));
            rows.push(kv(
                "tunables digest",
                session.tunables_effective_digest().unwrap_or("not pinned"),
            ));
            rows.push(kv("effort", session.effort().label()));
            rows.push(kv("mode", &permission_mode_row_value(session)));
            for (key, value) in app.route.limits.rows() {
                rows.push(kv(key, &value));
            }
            rows.push(block::PanelRow::Note(
                "persist a choice with `core config set <key> <value>`".into(),
            ));
            app.panel("⚙", "config", rows);
        }
        SlashCommand::Tunables => {
            open_tunables_picker(app, session, arg);
        }
        SlashCommand::Lab => {
            experiment_lab::handle(app, session, arg);
        }
        SlashCommand::Login => {
            // The credential half of the setup state machine deliberately does NOT run here. A
            // pasted key inside the TUI would land in a rendered, scrollable transcript buffer;
            // `core setup` owns collection precisely so a secret never reaches this surface.
            // What `/login` runs is the rest of the same machine: name the credential source, then
            // ask the provider whether it actually works, which is the check that used to happen
            // only on the first paid turn.
            let provider_id = if arg.trim().is_empty() {
                app.route.provider_id.clone()
            } else {
                arg.trim().to_owned()
            };
            let mut rows = vec![
                kv("provider", &provider_id),
                kv("api_root", &app.route.api_root),
                kv("credential", &app.route.credential),
            ];
            match directory.entry(&provider_id) {
                Some(entry) => {
                    rows.push(kv("state", &directory.status_label(entry)));
                    if let Some(reason) = directory.blocked_reason(entry) {
                        rows.push(kv("blocked", &reason));
                    }
                }
                None => rows.push(kv("state", &directory.resolution_error(&provider_id))),
            }
            rows.push(block::PanelRow::Note(format!(
                "sign in or replace this credential with `core setup --byok {provider_id}` (or `core setup --plan`); inspect it with `core auth status`"
            )));
            app.panel("⚿", "login", rows);
        }
        SlashCommand::Tools => {
            // Visualize every tool + its capability tier + purity (user: tool 所有能的可视化).
            let cap_glyph = |c: Capability| match c {
                Capability::ReadOnly => "read-only",
                Capability::ReversibleLocal => "edits (reversible)",
                Capability::CodeExecuting => "runs code",
                Capability::TrustMutating => "trust-mutating",
                Capability::IrreversibleExternal => "external/egress",
            };
            let mut tools: Vec<&app_server::ToolFact> = session.registry_tools().iter().collect();
            tools.sort_by(|a, b| a.name.cmp(&b.name));
            let rows: Vec<block::PanelRow> = tools
                .iter()
                .map(|tool| block::PanelRow::Item {
                    label: format!("{}  [{}]", tool.name, cap_glyph(tool.capability)),
                    hint: core_protocol::text::head(&tool.description, 70),
                })
                .collect();
            app.panel("⚙", &format!("{} tools available", rows.len()), rows);
        }
        SlashCommand::Mcp => {
            mcp_command::handle(app, session, arg).await;
        }
        SlashCommand::Hooks => {
            let hooks = core_protocol::home::operator()
                .map(|home| crate::runtime::hooks::Hooks::load_user(&home))
                .unwrap_or_default();
            if hooks.is_empty() {
                app.note(
                    block::NoticeLevel::Info,
                    "no lifecycle hooks (add a \"hooks\" block to ~/.core/config.json)",
                );
            } else {
                app.note(
                    block::NoticeLevel::Ok,
                    "lifecycle hooks loaded from ~/.core/config.json (user config)",
                );
            }
        }
        SlashCommand::Transcript => {
            open_transcript_viewer(app, transcript_effects, arg.trim());
        }
        SlashCommand::Export => {
            let (requested, collision) = if arg.trim().is_empty() {
                (
                    "core-transcript.md",
                    transcript_export::CollisionPolicy::Versioned,
                )
            } else {
                (arg.trim(), transcript_export::CollisionPolicy::Refuse)
            };
            schedule_slash_export(
                app,
                session.workspace(),
                transcript_effects,
                requested,
                collision,
            );
        }
        SlashCommand::Init => {
            let dir = match ensure_real_workspace_dir(session.workspace(), ".core") {
                Ok(dir) => dir,
                Err(error) => {
                    app.push(fg(Color::Red), format!("init refused: {error}"));
                    return;
                }
            };
            let cfg = dir.join("config.json");
            if cfg.exists() {
                app.push(
                    dim(),
                    format!("{} already exists — not overwritten", cfg.display()),
                );
            } else {
                // Repository config can only choose a bare model and tighten ceilings. Provider,
                // MCP, hooks, effort, and grants belong in trusted ~/.core/config.json.
                let starter = crate::config::starter_project_config();
                match write_new_synced(&cfg, starter.as_bytes()) {
                    Ok(_) => app.push(fg(Color::Green), format!("wrote {}", cfg.display())),
                    Err(e) => app.push(fg(Color::Red), format!("init failed: {e}")),
                }
            }
            let agents_md = session.workspace().join("AGENTS.md");
            if !agents_md.exists() {
                match write_new_synced(
                    &agents_md,
                    b"# Project instructions for coding agents\n\n- (describe build/test commands, conventions, and gotchas here)\n",
                ) {
                    Ok(()) => app.push(
                        fg(Color::Green),
                        format!("wrote {}", agents_md.display()),
                    ),
                    Err(error) => {
                        app.push(fg(Color::Red), format!("init failed: {error}"));
                    }
                }
            }
        }
        SlashCommand::Rewind => {
            let path = session.rollout_path().to_path_buf();
            let runs = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let events = match core_record::replay(&path) {
                Ok(events) if !events.is_empty() => events,
                Ok(_) => {
                    app.push(fg(Color::Red), "nothing to rewind yet");
                    return;
                }
                Err(error) => {
                    app.push(fg(Color::Red), format!("cannot read this session: {error}"));
                    return;
                }
            };
            let tail = events.last().map(|event| event.seq.0).unwrap_or_default();
            let request = match crate::workspace_review::parse_rewind_request(arg) {
                Ok(Some(request)) => request,
                Ok(None) => {
                    let mut rows = vec![block::PanelRow::Note(format!(
                        "preview: /rewind <seq> [all|code|conversation] [keep|delete] · add `apply` only after review (0..{tail})"
                    ))];
                    for event in events
                        .iter()
                        .rev()
                        .filter(|event| {
                            matches!(
                                event.kind,
                                core_protocol::EventKind::Checkpoint { .. }
                                    | core_protocol::EventKind::TurnStart
                            )
                        })
                        .take(30)
                    {
                        let kind =
                            if matches!(event.kind, core_protocol::EventKind::Checkpoint { .. }) {
                                "files + conversation"
                            } else {
                                "conversation"
                            };
                        rows.push(item(
                            "•",
                            &format!("seq {}", event.seq.0),
                            &format!("turn {} · {kind}", event.turn.0),
                        ));
                    }
                    app.panel("↩", "rewind points", rows);
                    return;
                }
                Err(error) => {
                    app.note(block::NoticeLevel::Err, error);
                    return;
                }
            };
            if request.at.0 > tail {
                app.note(
                    block::NoticeLevel::Err,
                    format!("rewind seq {} is past this run's tail {tail}", request.at.0),
                );
                return;
            }
            let run = core_protocol::RunId(stem);
            let snapshot =
                crate::workspace_review::checkpoint_at_or_before(&events, &run, request.at);
            let mut file_preview = None;
            if request.scope.touches_files() {
                let Some(snapshot) = snapshot.as_ref() else {
                    app.note(
                        block::NoticeLevel::Err,
                        "no workspace checkpoint exists at or before that sequence",
                    );
                    return;
                };
                let review = match crate::workspace_review::observe(session.workspace()).await {
                    Ok(review) => review,
                    Err(error) => {
                        app.note(block::NoticeLevel::Err, error);
                        return;
                    }
                };
                let preview = match crate::workspace_review::preview_restore(
                    &review,
                    snapshot,
                    session.workspace(),
                    request.scope,
                    request.unrecorded,
                ) {
                    Ok(preview) => preview,
                    Err(error) => {
                        app.note(block::NoticeLevel::Err, error);
                        return;
                    }
                };
                let mut rows = vec![block::PanelRow::Note(preview.describe())];
                rows.push(kv("checkpoint", &format!("seq {}", snapshot.at.0)));
                rows.push(kv(
                    "result",
                    if preview.inexact { "overlay" } else { "exact" },
                ));
                rows.push(kv(
                    "evidence",
                    if preview.is_conclusive() {
                        "complete"
                    } else {
                        "incomplete — destructive apply refused"
                    },
                ));
                for entry in preview.irrecoverable().iter().take(20) {
                    rows.push(item("−", &entry.path, "would be deleted"));
                }
                app.panel("↩", "rewind preview", rows);
                file_preview = Some(preview);
            } else {
                app.panel(
                    "↩",
                    "rewind preview",
                    vec![block::PanelRow::Note(format!(
                        "conversation branches at seq {}; no file is touched",
                        request.at.0
                    ))],
                );
            }
            if request.disposition == crate::workspace_review::RewindDisposition::Preview {
                app.note(
                    block::NoticeLevel::Info,
                    format!(
                        "preview only · repeat `/rewind {} {} {} apply` to proceed",
                        request.at.0,
                        match request.scope {
                            core_changeset::Scope::CodeAndConversation => "all",
                            core_changeset::Scope::CodeOnly => "code",
                            core_changeset::Scope::ConversationOnly => "conversation",
                        },
                        match request.unrecorded {
                            core_changeset::Unrecorded::Keep => "keep",
                            core_changeset::Unrecorded::Delete => "delete",
                        }
                    ),
                );
                return;
            }
            if request.unrecorded == core_changeset::Unrecorded::Delete
                && file_preview
                    .as_ref()
                    .is_some_and(|preview| !preview.is_conclusive())
            {
                app.note(
                    block::NoticeLevel::Err,
                    "destructive rewind refused because the preview was incomplete",
                );
                return;
            }

            // Before overwriting even one tracked path, retain an exact local safety snapshot. It
            // is a Git object/ref, not a remote backup, and is described only as rollback material.
            let safety = if request.scope.touches_files() {
                let safety_run = core_protocol::RunId(format!("rewind-safety-{}", run.0));
                match core_record::checkpoint_excluding_runtime_state(
                    &safety_run,
                    core_protocol::Seq(tail.saturating_add(1)),
                    session.workspace(),
                    &runs,
                ) {
                    Ok(snapshot) => Some(snapshot),
                    Err(error) => {
                        app.note(
                            block::NoticeLevel::Err,
                            format!("could not create pre-rewind safety checkpoint: {error}"),
                        );
                        return;
                    }
                }
            } else {
                None
            };
            if let Some(target) = snapshot.as_ref()
                && let Err(error) = core_record::rewind_workspace_with_policy(
                    target,
                    session.workspace(),
                    request.unrecorded == core_changeset::Unrecorded::Delete,
                )
            {
                let rollback = safety.as_ref().map(|safety| {
                    core_record::rewind_workspace_with_policy(safety, session.workspace(), true)
                });
                app.note(
                    block::NoticeLevel::Err,
                    format!("workspace rewind failed: {error}; safety rollback: {rollback:?}"),
                );
                return;
            }

            if request.scope.touches_conversation() {
                match core_record::fork(
                    &runs,
                    &run,
                    request.at,
                    &core_protocol::TenantId::default(),
                ) {
                    Ok(child) => {
                        app.note(
                            block::NoticeLevel::Ok,
                            format!("rewound to seq {} · adopting {child}", request.at.0),
                        );
                        adopt_session(app, session, directory, &child.0).await;
                    }
                    Err(error) => {
                        if let Some(safety) = safety.as_ref() {
                            let _ = core_record::rewind_workspace_with_policy(
                                safety,
                                session.workspace(),
                                true,
                            );
                        }
                        app.note(
                            block::NoticeLevel::Err,
                            format!("conversation rewind failed: {error}"),
                        );
                    }
                }
            } else {
                app.note(
                    block::NoticeLevel::Ok,
                    format!(
                        "workspace restored to checkpoint seq {} · conversation kept",
                        snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.at.0)
                            .unwrap_or_default()
                    ),
                );
            }
        }
        SlashCommand::Resume => {
            if arg.is_empty() {
                open_session_picker(app, session);
            } else {
                let runs = session
                    .rollout_path()
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                let exists = core_record::list(&runs, &core_protocol::TenantId::default())
                    .iter()
                    .any(|session| session.run_id.0 == arg);
                if exists {
                    adopt_session(app, session, directory, arg).await;
                } else {
                    app.note(
                        block::NoticeLevel::Err,
                        format!("no recorded session with run id `{}`", ui_safe_text(arg)),
                    );
                }
            }
        }
        SlashCommand::Quit => app.quit = true,
        SlashCommand::Compact => app.note(
            block::NoticeLevel::Err,
            "compact requires the interactive terminal dispatcher",
        ),
        SlashCommand::Side => app.note(
            block::NoticeLevel::Err,
            "side conversations require the interactive terminal dispatcher",
        ),
    }
}

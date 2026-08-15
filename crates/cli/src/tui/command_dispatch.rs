//! In-process slash-command dispatch.

use super::*;

/// Compaction-ledger segments listed by one `/context` panel. A long run accumulates far more
/// segments than a screen holds, and the totals printed above the list stay readable only if the
/// list itself stops.
const LEDGER_SEGMENT_ROWS: usize = 24;
fn queue_command_control(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    control: app_server::Control,
    kind: transcript_effect::ControlKind,
) {
    let label = kind.label();
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control,
        interrupt: interrupt.clone(),
        kind,
    };
    if effects.start(request).is_ok() {
        app.status = format!("{label} pending…");
    } else {
        app.note(
            block::NoticeLevel::Warn,
            format!("{label} not queued: another local effect is pending"),
        );
    }
}

pub(super) fn handle_registered_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    transcript_effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    command: SlashCommand,
    arg: &str,
) {
    match command {
        SlashCommand::Help => show_help(app),
        SlashCommand::Clear => clear_conversation(app),
        SlashCommand::Effort => {
            if arg.is_empty() {
                open_picker(app, session, directory, "effort"); // interactive picker (R7.a)
            } else if let Some(e) = iteron_protocol::Effort::parse(arg) {
                queue_effort(app, session, transcript_effects, interrupt, e);
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
                    Ok(true) => queue_model_selection(
                        app,
                        session,
                        directory,
                        transcript_effects,
                        interrupt,
                        selection,
                    ),
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
                    Ok(selection) => queue_model_selection(
                        app,
                        session,
                        directory,
                        transcript_effects,
                        interrupt,
                        selection,
                    ),
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
            queue_command_control(
                app,
                session,
                transcript_effects,
                interrupt,
                app_server::Control::OperatorStatus,
                transcript_effect::ControlKind::OperatorStatus {
                    tunables_argument: None,
                },
            );
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
            queue_command_control(
                app,
                session,
                transcript_effects,
                interrupt,
                app_server::Control::TurnBudget { set },
                transcript_effect::ControlKind::TurnBudget { set },
            );
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
                    for segment in ledger.segments.iter().take(iteron_tunables::param_integer(
                        "cli.tui.command_dispatch.ledger_segment_rows",
                        LEDGER_SEGMENT_ROWS,
                    )) {
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
                context_chips::handle(app, session, arg);
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
                    &format!(
                        "{} lifecycle events",
                        iteron_protocol::lifecycle::EVENT_COUNT
                    ),
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
                        iteron_obs::otel::catalog::METRIC_INSTRUMENT_COUNT,
                        iteron_obs::otel::catalog::LOG_SCHEMA_COUNT,
                        iteron_obs::otel::catalog::SPAN_TEMPLATE_COUNT
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
                queue_permission_mode(app, session, transcript_effects, interrupt, m);
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
                            queue_permission_capability(
                                app,
                                session,
                                transcript_effects,
                                interrupt,
                                c,
                                v,
                            );
                        }
                        _ => app.push(fg(Color::Red), "usage: /permissions [allow|ask|deny <read_only|reversible_local|code_executing|trust_mutating|irreversible_external>]"),
                    }
                }
            }
        }
        SlashCommand::AllowCode => match arg {
            "on" | "true" | "" => {
                queue_permission_capability(
                    app,
                    session,
                    transcript_effects,
                    interrupt,
                    Capability::CodeExecuting,
                    Verdict::Auto,
                );
            }
            "off" | "false" => {
                queue_permission_capability(
                    app,
                    session,
                    transcript_effects,
                    interrupt,
                    Capability::CodeExecuting,
                    Verdict::Ask,
                );
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
            let store = iteron_ctx::MemoryStore::at(ws);
            let mut sub = arg.split_whitespace();
            match sub.next() {
                Some("add") => {
                    let text = arg.strip_prefix("add").unwrap_or("").trim().to_string();
                    if text.is_empty() {
                        app.push(fg(Color::Red), "usage: /memory add <fact>");
                    } else {
                        queue_command_control(
                            app,
                            session,
                            transcript_effects,
                            interrupt,
                            app_server::Control::Memory(app_server::MemoryControl::Add(text)),
                            transcript_effect::ControlKind::Memory,
                        );
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
                        queue_command_control(
                            app,
                            session,
                            transcript_effects,
                            interrupt,
                            app_server::Control::Memory(app_server::MemoryControl::Update {
                                id,
                                text,
                            }),
                            transcript_effect::ControlKind::Memory,
                        );
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
                    queue_command_control(
                        app,
                        session,
                        transcript_effects,
                        interrupt,
                        app_server::Control::Memory(app_server::MemoryControl::Delete(id)),
                        transcript_effect::ControlKind::Memory,
                    );
                }
                Some(x) => app.push(
                    fg(Color::Red),
                    format!("unknown /memory subcommand `{x}` (add|update|list|forget)"),
                ),
            }
        }
        SlashCommand::Diff => {
            let stat = arg.trim() == "stat";
            workspace_command::queue_diff(app, session.workspace().to_path_buf(), stat);
        }
        SlashCommand::Sessions => {
            handle_sessions_command(app, session, directory, arg);
        }
        SlashCommand::Workflows => {
            queue_command_control(
                app,
                session,
                transcript_effects,
                interrupt,
                app_server::Control::Workflow(app_server::WorkflowControl::Inventory),
                transcript_effect::ControlKind::WorkflowsInventory,
            );
        }
        SlashCommand::Jobs => jobs::queue(app, session, transcript_effects, interrupt, arg),
        SlashCommand::Fork => {
            // Fork the CURRENT session at its tail into a new branch (shared past, divergent future).
            let path = session.rollout_path().to_path_buf();
            let runs = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            match iteron_record::replay(&path) {
                Ok(events) if !events.is_empty() => {
                    let at = events.last().map(|e| e.seq).unwrap();
                    match iteron_record::fork(
                        &runs,
                        &iteron_protocol::RunId(stem),
                        at,
                        &iteron_protocol::TenantId::default(),
                    ) {
                        Ok(child) => {
                            app.note(
                                block::NoticeLevel::Ok,
                                format!("forked {child} · adopting the divergent branch"),
                            );
                            start_adopt_session(app, session, directory, child.0);
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
            let cat = iteron_ctx::skills::SkillCatalog::discover_for_operator_with_dependencies(
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
                    "no skills (add <repo>/.iteron/skills or <repo>/.agents/skills)".into(),
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
            // disk instead of the layered value the kernel enforces: `iteron --max-turns 5` printed
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
                "persist a choice with `iteron config set <key> <value>`".into(),
            ));
            app.panel("⚙", "config", rows);
        }
        SlashCommand::Tunables => {
            let requested = arg.trim();
            if requested == "registry" || requested == "load" || requested.starts_with("load ") {
                open_tunables_picker(app, session, arg);
                return;
            }
            queue_command_control(
                app,
                session,
                transcript_effects,
                interrupt,
                app_server::Control::OperatorStatus,
                transcript_effect::ControlKind::OperatorStatus {
                    tunables_argument: Some(arg.to_owned()),
                },
            );
        }
        SlashCommand::Lab => {
            experiment_lab::handle(app, session, arg);
        }
        SlashCommand::Login => {
            // The credential half of the setup state machine deliberately does NOT run here. A
            // pasted key inside the TUI would land in a rendered, scrollable transcript buffer;
            // `iteron setup` owns collection precisely so a secret never reaches this surface.
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
                "sign in or replace this credential with `iteron setup --byok {provider_id}` (or `iteron setup --plan`); inspect it with `iteron auth status`"
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
                    hint: iteron_protocol::text::head(&tool.description, 70),
                })
                .collect();
            app.panel("⚙", &format!("{} tools available", rows.len()), rows);
        }
        SlashCommand::Mcp => {
            mcp_command::queue(app, session, transcript_effects, interrupt, arg);
        }
        SlashCommand::Hooks => {
            let hooks = iteron_protocol::home::operator()
                .map(|home| crate::runtime::hooks::Hooks::load_user(&home))
                .unwrap_or_default();
            if hooks.is_empty() {
                app.note(
                    block::NoticeLevel::Info,
                    "no lifecycle hooks (add a \"hooks\" block to ~/.iteron/config.json)",
                );
            } else {
                app.note(
                    block::NoticeLevel::Ok,
                    "lifecycle hooks loaded from ~/.iteron/config.json (user config)",
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
                session.rollout_path(),
                transcript_effects,
                requested,
                collision,
            );
        }
        SlashCommand::Init => {
            let dir = match ensure_real_workspace_dir(session.workspace(), ".iteron") {
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
                // MCP, hooks, effort, and grants belong in trusted ~/.iteron/config.json.
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
            workspace_command::queue_rewind(
                app,
                session.workspace().to_path_buf(),
                session.rollout_path().to_path_buf(),
                arg.to_owned(),
            );
        }
        SlashCommand::Resume => {
            if arg.is_empty() {
                open_session_picker(app, session);
            } else {
                // The adoption worker performs the one-run indexed lookup and reports a typed
                // miss; never enumerate every session merely to validate one id on the TUI loop.
                start_adopt_session(app, session, directory, arg.to_owned());
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

pub(super) fn show_help(app: &mut App) {
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

pub(super) fn render_memory_reply(app: &mut App, reply: app_server::MemoryControlReply) {
    match reply {
        app_server::MemoryControlReply::Added { id } => app.push(
            fg(Color::Green),
            format!("remembered ({id}) — available in this session"),
        ),
        app_server::MemoryControlReply::Updated { old_id, id } => app.push(
            fg(Color::Green),
            format!("updated {old_id} → {id} — available in this session"),
        ),
        app_server::MemoryControlReply::Deleted { id } => {
            app.push(fg(Color::Green), format!("forgot {id}"));
        }
        app_server::MemoryControlReply::Missing { id } => {
            app.push(fg(Color::Red), format!("no memory {id}"));
        }
    }
}

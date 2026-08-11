//! `/status`: the exact resolved policy identities and live bounded-owner health.

use super::*;

pub(super) async fn handle(app: &mut App, session: &mut Session) {
    let snapshot = match session.control(app_server::Control::OperatorStatus).await {
        Some(app_server::ControlReply::OperatorStatus(snapshot)) => *snapshot,
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason);
            return;
        }
        _ => {
            app.note(
                block::NoticeLevel::Err,
                "the resident runtime could not provide an authoritative status snapshot",
            );
            return;
        }
    };

    let run = session
        .rollout_path()
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("?");
    let mut rows: Vec<block::PanelRow> = app
        .route
        .rows()
        .iter()
        .map(|(key, value)| kv(key, value))
        .collect();
    rows.push(kv("effort requested", session.effort().label()));
    rows.push(kv(
        "effort applied · last observed",
        &app.effort_application
            .map_or_else(|| "not observed yet".to_owned(), effort_application_detail),
    ));
    rows.extend([
        kv("mode", &permission_mode_row_value(session)),
        kv("cwd", &session.workspace().display().to_string()),
        kv("session", &session.session_id().to_string()),
        kv("run", run),
        kv(
            "provider quota · last settled",
            session
                .rate_limit()
                .unwrap_or("not published by this route"),
        ),
    ]);

    append_policy_bundle(&mut rows, &snapshot.runtime.policy_bundle);
    append_tunables(&mut rows, snapshot.runtime.tunables.as_ref());
    append_governor(
        &mut rows,
        snapshot.runtime.governor.as_ref(),
        snapshot.runtime.governor_policy.as_ref(),
    );
    let budget = &snapshot.runtime.settled_budget;
    rows.push(kv(
        "run budget · last safe point",
        &format!(
            "turns {}/{} ({} left) · tokens {}/{} ({} left) · wall {}ms/{}s · tools {} calls/{} errors · USD ≤{}",
            budget.provider_attempts, budget.ceiling.max_turns, budget.provider_attempts_remaining,
            budget.tokens_used, optional_number(budget.ceiling.max_tokens),
            optional_number(budget.tokens_remaining), optional_number(budget.wall_remaining_ms),
            budget.ceiling.max_wall_secs, budget.tool_calls, budget.tool_errors,
            optional_number(budget.ceiling.max_usd)
        ),
    ));
    append_context(
        &mut rows,
        snapshot.runtime.context_budget,
        &snapshot.runtime.context_ledger,
    );
    append_collaboration(
        &mut rows,
        snapshot.runtime.collaboration,
        snapshot.workflows,
    );
    rows.push(block::PanelRow::Note(format!(
        "settled ledger · {}",
        session.ledger_summary()
    )));
    append_tool_health(
        &mut rows,
        snapshot.processes,
        snapshot.language_servers,
        &snapshot.mcp,
    );
    app.panel("≡", "status · authoritative runtime snapshot", rows);
}

fn append_policy_bundle(
    rows: &mut Vec<block::PanelRow>,
    bundle: &iteron_protocol::RunGenesisPolicyBundleSnapshot,
) {
    rows.push(block::PanelRow::Note(
        "policy bundle · immutable run genesis".into(),
    ));
    rows.extend([
        kv(
            "bundle",
            &format!("{} · {}", bundle.bundle_id, coverage_label(bundle.coverage)),
        ),
        kv("bundle digest", &bundle.bundle_digest_sha256),
        kv("bundle receipt", &bundle.receipt_digest_sha256),
        kv(
            "policy slots",
            &format!("{}/9 resolved", bundle.slots.len()),
        ),
    ]);
    rows.extend(bundle.slots.iter().map(|slot| block::PanelRow::Item {
        label: format!(
            "{:02} {} · {} · {}",
            slot.ordinal,
            slot.slot.as_persisted_str(),
            application_label(slot.status),
            slot.implementation
        ),
        hint: format!(
            "{}@{} · {} · requested {}",
            slot.policy.policy_id,
            slot.policy.policy_version,
            slot.policy.policy_digest_sha256,
            if slot.requested { "yes" } else { "no" }
        ),
    }));
}

fn append_tunables(
    rows: &mut Vec<block::PanelRow>,
    checkpoint: Option<&iteron_record::TunablesCheckpoint>,
) {
    rows.push(block::PanelRow::Note(
        "tunables · immutable resolution receipt".into(),
    ));
    let Some(checkpoint) = checkpoint else {
        rows.push(kv("tunables", "unavailable (no run-genesis checkpoint)"));
        return;
    };
    let (version, registry, registry_digest, resolution, profile, entries) = match checkpoint {
        iteron_record::TunablesCheckpoint::V1(snapshot) => (
            "v1 identity-only",
            format!("{} r{}", snapshot.registry_id, snapshot.registry_revision),
            snapshot.registry_digest_sha256.as_str(),
            snapshot.resolution_digest_sha256.as_str(),
            snapshot.profile_digest_sha256.as_deref(),
            snapshot.entries.len(),
        ),
        iteron_record::TunablesCheckpoint::V2(snapshot) => (
            "v2 reconstructable",
            format!("{} r{}", snapshot.registry_id, snapshot.registry_revision),
            snapshot.registry_digest_sha256.as_str(),
            snapshot.resolution_digest_sha256.as_str(),
            snapshot.profile_digest_sha256.as_deref(),
            snapshot.entries.len(),
        ),
    };
    rows.extend([
        kv(
            "tunables checkpoint",
            &format!("{version} · {entries} families"),
        ),
        kv("tunables receipt", checkpoint.snapshot_digest_sha256()),
        kv("tunables effective", checkpoint.effective_digest_sha256()),
        kv("tunables resolution", resolution),
        kv(
            "tunables registry",
            &format!("{registry} · {registry_digest}"),
        ),
        kv("tunables profile", profile.unwrap_or("not selected")),
    ]);
}

fn append_governor(
    rows: &mut Vec<block::PanelRow>,
    governor: Option<&iteron_provider::ProviderGovernorSnapshot>,
    policy: Option<&iteron_provider::GovernorPolicy>,
) {
    rows.push(block::PanelRow::Note(
        "provider governor · live admission state".into(),
    ));
    let (Some(governor), Some(policy)) = (governor, policy) else {
        rows.push(kv("governor", "not installed for this runtime"));
        return;
    };
    rows.extend([
        kv(
            "objectives q/c/l",
            &format!(
                "{} / {} / {}",
                millionths(policy.objectives.quality_millionths),
                millionths(policy.objectives.cost_millionths),
                millionths(policy.objectives.latency_millionths)
            ),
        ),
        kv(
            "route admission",
            &format!(
                "{} in flight/route · request floor {} · token floor {} · reset wait ≤{}ms",
                governor.max_in_flight_per_route,
                governor.minimum_remaining_requests,
                governor.minimum_remaining_tokens,
                governor.reset_wait_max_ms
            ),
        ),
        kv(
            "circuit",
            &format!(
                "open after {} failures for {}ms · half-open {}/{} probes/successes",
                governor.circuit_failure_threshold,
                governor.circuit_open_ms,
                governor.circuit_half_open_probes,
                governor.circuit_success_threshold
            ),
        ),
        kv(
            "hedge",
            &format!(
                "{} · {}ms delay · {} duplicates max",
                if governor.hedge_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                governor.hedge_delay_ms,
                governor.hedge_max_duplicates
            ),
        ),
        kv("failover", &failover_label(policy)),
    ]);
    rows.extend(governor.routes.iter().map(|route| block::PanelRow::Item {
        label: format!(
            "{} · {} · {} in flight",
            route.route_id,
            circuit_label(route.circuit),
            route.in_flight
        ),
        hint: if route.quota_observed {
            format!(
                "quota age {}ms · requests {} · tokens {} · reset {}ms",
                optional_number(route.quota_age_ms),
                optional_number(route.requests_remaining),
                optional_number(route.tokens_remaining),
                optional_number(route.reset_remaining_ms)
            )
        } else {
            "quota not published or not observed".into()
        },
    }));
}

fn append_context(
    rows: &mut Vec<block::PanelRow>,
    budget: iteron_ctx::ContextBudgetPolicy,
    ledger: &iteron_ctx::ContextLedgerSnapshot,
) {
    rows.push(block::PanelRow::Note(
        "context · separated ceilings and last decision ledger".into(),
    ));
    rows.extend([
        kv(
            "context iteron",
            &format!(
                "stable {} · instructions {} · task {} · memory {} · transcript {}",
                budget.stable_prefix_tokens,
                budget.instruction_tokens,
                budget.task_context_tokens,
                budget.memory_tokens,
                budget.transcript_tokens
            ),
        ),
        kv(
            "context tools",
            &format!(
                "attachments {} · schemas {} · results {} · LSP {} · multimodal {}",
                budget.attachment_tokens,
                budget.tool_schema_tokens,
                budget.tool_result_tokens,
                budget.lsp_result_tokens,
                budget.multimodal_tokens
            ),
        ),
        kv(
            "context reserves",
            &format!(
                "output {} · verification {}",
                budget.output_reserve_tokens, budget.verification_reserve_tokens
            ),
        ),
        kv(
            "context ledger store",
            &format!(
                "{} retained · drops oldest {} / contention {} / unmatched {}",
                ledger.ledgers.len(),
                ledger.dropped_oldest,
                ledger.dropped_contention,
                ledger.dropped_unmatched
            ),
        ),
    ]);
    if let Some(last) = ledger.ledgers.last() {
        rows.push(kv(
            "last context turn",
            &format!(
                "{} · selected {} / rejected {} / evidence dropped {} · estimated {} / actual {} / headroom {}",
                last.turn_id.0,
                last.totals.selected_segments,
                last.totals.rejected_segments,
                last.dropped,
                last.totals.estimated_tokens,
                optional_number(last.totals.actual_input_tokens),
                optional_number(last.headroom_tokens())
            ),
        ));
        rows.push(kv(
            "tokenizer",
            &format!(
                "{} v{} · {}",
                last.estimator.catalog_id,
                last.estimator.version,
                if last.estimator.exact {
                    "exact"
                } else {
                    "estimated"
                }
            ),
        ));
    } else {
        rows.push(kv("last context turn", "none observed yet"));
    }
}

fn append_tool_health(
    rows: &mut Vec<block::PanelRow>,
    processes: Option<iteron_tools::ProcessHealth>,
    language_servers: app_server::LanguageServerStatus,
    mcp: &[crate::mcp::McpServerHealth],
) {
    rows.push(block::PanelRow::Note(
        "tool owners · session-local live health".into(),
    ));
    if let Some(processes) = processes {
        rows.push(kv(
            "processes",
            &format!(
                "{} · {}/{} active · {} retained / {} terminal / {} cleanup unknown / {} awaiting stdin",
                processes.policy.backend.as_str(),
                processes.active_jobs,
                processes.policy.max_background_jobs,
                processes.retained_jobs,
                processes.terminal_jobs,
                processes.cleanup_unknown_jobs,
                processes.awaiting_stdin_jobs
            ),
        ));
    } else {
        rows.push(kv("processes", "supervisor unavailable"));
    }
    match language_servers {
        app_server::LanguageServerStatus::Unavailable => {
            rows.push(kv("language servers", "pool unavailable"));
        }
        app_server::LanguageServerStatus::Busy => {
            rows.push(kv(
                "language servers",
                "health snapshot busy (100ms read deadline)",
            ));
        }
        app_server::LanguageServerStatus::Available(health) => rows.push(kv(
            "language servers",
            &format!(
                "{}/{} running/slots · {} routes · {} restarts · {} unknown · freshness {}/{} attested/unattested",
                health.running_servers,
                health.pool_slots,
                health.configured_routes,
                health.restart_count,
                health.unknown_slots,
                health.freshness_attested_servers,
                health.freshness_unattested_servers
            ),
        )),
    }
    if mcp.is_empty() {
        rows.push(kv("MCP", "no servers configured"));
    } else {
        rows.push(kv(
            "MCP servers",
            &format!(
                "{} configured · {} ready · {} busy",
                mcp.len(),
                mcp.iter().filter(|s| s.phase == "ready").count(),
                mcp.iter().filter(|s| s.busy).count()
            ),
        ));
        rows.extend(mcp.iter().map(|server| block::PanelRow::Item {
            label: format!(
                "MCP {} · {} · {} · {}",
                server.name,
                server.transport,
                server.phase,
                if server.busy { "busy" } else { "idle" }
            ),
            hint: mcp_command::server_runtime_hint(server),
        }));
    }
}

fn append_collaboration(
    rows: &mut Vec<block::PanelRow>,
    collaboration: crate::runtime::CollaborationRuntimeHealth,
    workflows: app_server::WorkflowHealth,
) {
    rows.push(block::PanelRow::Note(
        "collaboration · session-owned bounded work".into(),
    ));
    rows.extend([
        kv(
            "child spawn budget",
            &format!(
                "{} admitted · {} remaining · {} ceiling",
                collaboration.session_spawns_admitted,
                collaboration.session_spawns_remaining,
                collaboration.session_spawn_limit
            ),
        ),
        kv(
            "workflow owner",
            &format!(
                "{} retained · {} running / {} cancelling / {} settled / {} failed · {} agents active",
                workflows.retained,
                workflows.running,
                workflows.cancelling,
                workflows.settled,
                workflows.failed,
                workflows.running_agents
            ),
        ),
    ]);
}

fn coverage_label(coverage: iteron_protocol::PolicyBundleCoverage) -> &'static str {
    match coverage {
        iteron_protocol::PolicyBundleCoverage::Baseline => "baseline",
        iteron_protocol::PolicyBundleCoverage::Partial => "partial",
        iteron_protocol::PolicyBundleCoverage::Full => "full",
    }
}

fn application_label(status: iteron_protocol::PolicySlotApplicationStatus) -> &'static str {
    match status {
        iteron_protocol::PolicySlotApplicationStatus::Baseline => "baseline",
        iteron_protocol::PolicySlotApplicationStatus::Applied => "applied",
    }
}

fn millionths(value: u32) -> String {
    format!("{}.{:01}%", value / 10_000, (value % 10_000) / 1_000)
}

fn circuit_label(circuit: iteron_provider::RouteCircuitSnapshot) -> String {
    match circuit {
        iteron_provider::RouteCircuitSnapshot::Closed { failures } => {
            format!("closed ({failures} failures)")
        }
        iteron_provider::RouteCircuitSnapshot::Open { remaining_ms } => {
            format!("open ({remaining_ms}ms left)")
        }
        iteron_provider::RouteCircuitSnapshot::HalfOpen { successes, probes } => {
            format!("half-open ({successes}/{probes})")
        }
    }
}

fn failover_label(policy: &iteron_provider::GovernorPolicy) -> String {
    if policy.failover.is_empty() {
        return "none".into();
    }
    policy
        .failover
        .iter()
        .map(|rule| {
            let point = match rule.point {
                iteron_provider::FailurePoint::PreDispatch => "pre-dispatch",
                iteron_provider::FailurePoint::ProvenTerminal => "proven-terminal",
            };
            format!("{}@{point}", rule.class.label())
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".into(), |value| value.to_string())
}

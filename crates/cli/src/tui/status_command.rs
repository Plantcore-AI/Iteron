//! `/status`: the exact resolved policy identities and live bounded-owner health.

use super::*;

/// Leading hex characters of a digest shown in a status row. Twelve separate every digest a single
/// run actually carries, while leaving the row wide enough for its label and value.
const STATUS_DIGEST_PREFIX_CHARS: usize = 12;

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
        kv("workspace", &status_workspace(session.workspace())),
        kv("session", &session.session_id().to_string()),
        kv("run", run),
        kv(
            "provider quota · last settled",
            session
                .rate_limit()
                .unwrap_or("not published by this route"),
        ),
    ]);

    append_authoritative_snapshot(&mut rows, &snapshot);
    rows.push(block::PanelRow::Note(format!(
        "settled ledger · {}",
        session.ledger_summary()
    )));
    app.panel("≡", "status · authoritative runtime snapshot", rows);
}

fn append_authoritative_snapshot(
    rows: &mut Vec<block::PanelRow>,
    snapshot: &app_server::OperatorStatusSnapshot,
) {
    append_policy_bundle(rows, &snapshot.runtime.policy_bundle);
    append_tunables(rows, snapshot.runtime.tunables.as_ref());
    append_runtime_policy(rows, snapshot.runtime.runtime_policy.as_ref());
    append_governor(
        rows,
        snapshot.runtime.governor.as_ref(),
        snapshot.runtime.governor_policy.as_ref(),
    );
    append_budget(rows, &snapshot.runtime.settled_budget);
    append_context(
        rows,
        snapshot.runtime.context_budget,
        &snapshot.runtime.context_ledger,
    );
    append_collaboration(rows, snapshot.runtime.collaboration, snapshot.workflows);
    append_tool_health(
        rows,
        snapshot.processes,
        snapshot.language_servers,
        &snapshot.mcp,
    );
}

fn append_runtime_policy(
    rows: &mut Vec<block::PanelRow>,
    runtime_policy: Option<&crate::runtime::RuntimePolicyOverlaySnapshot>,
) {
    rows.push(block::PanelRow::Note(
        "runtime policy · ordered current overlay beside immutable genesis".into(),
    ));
    let Some(policy) = runtime_policy else {
        rows.push(kv(
            "current effective policy",
            "unavailable (legacy or unsealed); genesis is not claimed as current",
        ));
        return;
    };
    rows.extend([
        kv(
            "current effort",
            &format_runtime_policy_value(&policy.effort, policy.effort.value.label()),
        ),
        kv(
            "current permission",
            &format_runtime_policy_value(
                &policy.permission_mode,
                policy.permission_mode.value.label(),
            ),
        ),
        kv(
            "current permission rules",
            &format!(
                "{} rules · digest {} · source={} · seq={} · observed={}",
                policy.permission_rule_count,
                short_status_digest(&policy.permission_rules_digest_sha256),
                runtime_policy_source_label(policy.permission_mode.source),
                policy.permission_mode.sequence,
                runtime_policy_observation_label(policy.permission_mode.observed_via),
            ),
        ),
        kv(
            "current turn ceiling",
            &format_runtime_policy_value(&policy.max_turns, policy.max_turns.value),
        ),
        kv(
            "current USD ceiling",
            &policy.max_usd_microusd.as_ref().map_or_else(
                || format!("none · overlay seq={}", policy.sequence),
                |value| format_runtime_policy_value(value, format_microusd(value.value)),
            ),
        ),
    ]);
}

fn format_runtime_policy_value<T>(
    value: &crate::runtime::RuntimePolicyValue<T>,
    rendered: impl std::fmt::Display,
) -> String {
    format!(
        "{} · source={} · seq={} · observed={}",
        rendered,
        runtime_policy_source_label(value.source),
        value.sequence,
        runtime_policy_observation_label(value.observed_via),
    )
}

fn runtime_policy_source_label(source: iteron_protocol::RuntimePolicySource) -> &'static str {
    match source {
        iteron_protocol::RuntimePolicySource::Startup => "startup",
        iteron_protocol::RuntimePolicySource::Operator => "operator",
        iteron_protocol::RuntimePolicySource::ApprovalRemember => "approval-remember",
        iteron_protocol::RuntimePolicySource::Harness => "harness",
        iteron_protocol::RuntimePolicySource::Fork => "fork",
    }
}

fn runtime_policy_observation_label(
    observation: crate::runtime::RuntimePolicyObservation,
) -> &'static str {
    match observation {
        crate::runtime::RuntimePolicyObservation::Genesis => "genesis",
        crate::runtime::RuntimePolicyObservation::LiveCommit => "live-commit",
        crate::runtime::RuntimePolicyObservation::ResumeReplay => "resume-replay",
    }
}

fn format_microusd(value: u64) -> String {
    format!("${}.{:06}", value / 1_000_000, value % 1_000_000)
}

fn short_status_digest(value: &str) -> &str {
    value
        .get(
            ..iteron_tunables::param_integer(
                "cli.tui.status_command.status_digest_prefix_chars",
                STATUS_DIGEST_PREFIX_CHARS,
            ),
        )
        .unwrap_or(value)
}

fn append_budget(rows: &mut Vec<block::PanelRow>, budget: &crate::runtime::RuntimeBudgetHealth) {
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

fn status_workspace(path: &std::path::Path) -> String {
    use sha2::{Digest as _, Sha256};

    let basename = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.chars().all(|character| !character.is_control())
        })
        .unwrap_or("workspace");
    let digest = Sha256::digest(path.as_os_str().to_string_lossy().as_bytes());
    format!("{basename} · sha256:{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(rows: &[block::PanelRow]) -> String {
        rows.iter()
            .map(|row| match row {
                block::PanelRow::KeyValue { key, value } => format!("{key} {value}"),
                block::PanelRow::Item { label, hint } => format!("{label} {hint}"),
                block::PanelRow::Note(note) => note.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn operator_status_workspace_is_bounded_metadata_not_a_machine_path() {
        let sentinel = "private-env-value-sentinel";
        let path = std::path::Path::new("/Users/operator/private-env-value-sentinel/repository");
        let rendered = status_workspace(path);
        assert!(rendered.starts_with("repository · sha256:"), "{rendered}");
        assert!(!rendered.contains("/Users/operator"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
    }

    #[test]
    fn complete_status_panel_is_content_and_credential_free_but_operationally_complete() {
        const PROMPT: &str = "prompt-content-sentinel";
        const TOOL: &str = "tool-argument-sentinel";
        const MEMORY: &str = "memory-content-sentinel";
        const PRIVATE_ENV: &str = "private-env-value-sentinel";
        const CREDENTIAL: &str = "credential-value-sentinel";
        const URL_SECRET: &str = "url-query-sentinel";
        const MCP_CONTENT: &str = "mcp-failure-content-sentinel";

        let route = crate::route::RouteView {
            provider_id: "gateway".into(),
            provider_display_name: "Gateway".into(),
            model_id: "vendor/model".into(),
            api_root: format!("https://user:{CREDENTIAL}@gateway.example/v1?token={URL_SECRET}"),
            adapter: "openai_chat".into(),
            error_profile: "custom".into(),
            credential: format!(
                "file /private/{PRIVATE_ENV}/{CREDENTIAL}/credential.json (present)"
            ),
            catalog_provenance: "provider catalog (fresh)".into(),
            context_window_tokens: Some(128_000),
            max_output_tokens: Some(8_192),
            capability_source: Some("signed-provider-metadata".into()),
            blocked_reason: Some(format!(
                "credential {CREDENTIAL} rejected with remote payload {PROMPT}"
            )),
            limits: crate::route::RouteLimits {
                max_turns: 12,
                max_usd: Some(2.0),
                max_tokens: Some(100_000),
                max_wall_secs: 3_600,
            },
        };
        let mut rows = route
            .rows()
            .iter()
            .map(|(key, value)| kv(key, value))
            .collect::<Vec<_>>();
        rows.push(kv(
            "workspace",
            &status_workspace(std::path::Path::new(&format!(
                "/Users/operator/{PRIVATE_ENV}/repository"
            ))),
        ));

        let bundle = crate::bundle_adapter::baseline_compiled_bundle();
        append_policy_bundle(&mut rows, bundle.genesis_snapshot());
        append_tunables(
            &mut rows,
            Some(&iteron_record::TunablesCheckpoint::V1(
                iteron_protocol::RunGenesisTunablesSnapshot {
                    version: iteron_protocol::RunGenesisTunablesVersion::V1,
                    canonicalization: "fixture".into(),
                    resolution_schema_version: 1,
                    registry_id: "iteron-tunables".into(),
                    registry_schema_version: 1,
                    family_schema_version: 1,
                    registry_revision: 10,
                    registry_digest_sha256: "a".repeat(64),
                    input_digest_sha256: "b".repeat(64),
                    effective_digest_sha256: "c".repeat(64),
                    resolution_digest_sha256: "d".repeat(64),
                    profile_digest_sha256: Some("e".repeat(64)),
                    entries: Vec::new(),
                    snapshot_digest_sha256: "f".repeat(64),
                },
            )),
        );
        append_runtime_policy(
            &mut rows,
            Some(&crate::runtime::RuntimePolicyOverlaySnapshot {
                sequence: 9,
                effort: crate::runtime::RuntimePolicyValue {
                    value: iteron_protocol::Effort::High,
                    source: iteron_protocol::RuntimePolicySource::Operator,
                    sequence: 7,
                    observed_via: crate::runtime::RuntimePolicyObservation::LiveCommit,
                },
                permission_mode: crate::runtime::RuntimePolicyValue {
                    value: iteron_protocol::PermissionMode::Plan,
                    source: iteron_protocol::RuntimePolicySource::Operator,
                    sequence: 8,
                    observed_via: crate::runtime::RuntimePolicyObservation::ResumeReplay,
                },
                permission_rule_count: 3,
                permission_rules_digest_sha256: "9".repeat(64),
                max_turns: crate::runtime::RuntimePolicyValue {
                    value: 10,
                    source: iteron_protocol::RuntimePolicySource::Harness,
                    sequence: 9,
                    observed_via: crate::runtime::RuntimePolicyObservation::LiveCommit,
                },
                max_usd_microusd: Some(crate::runtime::RuntimePolicyValue {
                    value: 1_250_000,
                    source: iteron_protocol::RuntimePolicySource::Operator,
                    sequence: 9,
                    observed_via: crate::runtime::RuntimePolicyObservation::LiveCommit,
                }),
            }),
        );
        append_governor(
            &mut rows,
            Some(&iteron_provider::ProviderGovernorSnapshot {
                max_in_flight_per_route: 1,
                minimum_remaining_requests: 1,
                minimum_remaining_tokens: 1,
                reset_wait_max_ms: 1_000,
                circuit_failure_threshold: 3,
                circuit_open_ms: 30_000,
                circuit_half_open_probes: 1,
                circuit_success_threshold: 1,
                hedge_enabled: false,
                hedge_delay_ms: 0,
                hedge_max_duplicates: 0,
                routes: vec![iteron_provider::RouteGovernorSnapshot {
                    route_id: "gateway:model".into(),
                    in_flight: 0,
                    circuit: iteron_provider::RouteCircuitSnapshot::Closed { failures: 0 },
                    quota_observed: true,
                    quota_age_ms: Some(1),
                    requests_remaining: Some(10),
                    tokens_remaining: Some(10_000),
                    reset_remaining_ms: Some(0),
                }],
            }),
            Some(&iteron_provider::GovernorPolicy::default()),
        );
        append_budget(
            &mut rows,
            &crate::runtime::RuntimeBudgetHealth {
                ceiling: iteron_protocol::Budget {
                    max_turns: 12,
                    max_usd: Some(2.0),
                    max_tokens: Some(100_000),
                    max_wall_secs: 3_600,
                    max_consecutive_tool_errors: 5,
                },
                provider_attempts: 1,
                provider_attempts_remaining: 11,
                tokens_used: 100,
                tokens_remaining: Some(99_900),
                wall_remaining_ms: Some(3_000_000),
                tool_calls: 2,
                tool_errors: 0,
            },
        );
        append_context(
            &mut rows,
            iteron_ctx::ContextBudgetPolicy::default(),
            &iteron_ctx::ContextLedgerSnapshot::default(),
        );
        append_collaboration(
            &mut rows,
            crate::runtime::CollaborationRuntimeHealth {
                session_spawn_limit: 8,
                session_spawns_admitted: 1,
                session_spawns_remaining: 7,
            },
            app_server::WorkflowHealth {
                retained: 1,
                running: 1,
                cancelling: 0,
                settled: 0,
                failed: 0,
                running_agents: 1,
            },
        );
        let mcp_failure = [PROMPT, TOOL, MEMORY, PRIVATE_ENV, CREDENTIAL, MCP_CONTENT].join(" ");
        append_tool_health(
            &mut rows,
            Some(iteron_tools::ProcessHealth {
                schema_version: 1,
                policy: iteron_tools::ProcessRuntimePolicy::default(),
                retained_jobs: 1,
                active_jobs: 1,
                terminal_jobs: 0,
                cleanup_unknown_jobs: 0,
                awaiting_stdin_jobs: 0,
            }),
            app_server::LanguageServerStatus::Available(iteron_tools::LspHealth {
                schema_version: 1,
                configured_routes: 1,
                pool_slots: 2,
                running_servers: 1,
                restart_count: 0,
                unknown_slots: 0,
                freshness_attested_servers: 1,
                freshness_unattested_servers: 0,
            }),
            &[crate::mcp::McpServerHealth {
                name: "local-tools".into(),
                origin: "operator",
                plugin_identity: None,
                transport: "stdio",
                phase: "ready".into(),
                generation: Some(1),
                reconnect_attempts: 0,
                reconnect_limit: 3,
                retry_after_ms: None,
                retained_tools: 2,
                catalog_current: true,
                busy: false,
                negotiated_protocol_version: Some("2025-06-18".into()),
                last_failure: Some(mcp_failure),
            }],
        );

        let output = rendered(&rows);
        for secret in [
            PROMPT,
            TOOL,
            MEMORY,
            PRIVATE_ENV,
            CREDENTIAL,
            URL_SECRET,
            MCP_CONTENT,
            "/Users/operator",
            "/private/",
        ] {
            assert!(!output.contains(secret), "status leaked {secret}: {output}");
        }
        for required in [
            "bundle digest",
            "policy slots 9/9 resolved",
            "tunables receipt",
            "tunables effective",
            "tunables profile",
            "runtime policy",
            "current effort high · source=operator · seq=7 · observed=live-commit",
            "current permission plan · source=operator · seq=8 · observed=resume-replay",
            "current permission rules 3 rules · digest 999999999999",
            "current turn ceiling 10 · source=harness · seq=9",
            "current USD ceiling $1.250000",
            "provider governor",
            "route admission",
            "run budget",
            "context iteron",
            "context tools",
            "child spawn budget",
            "workflow owner",
            "processes",
            "language servers",
            "MCP servers",
            "details withheld",
        ] {
            assert!(
                output.contains(required),
                "status omitted {required}: {output}"
            );
        }
    }
}

//! Offline lab intent and immutable fact presentation. Native storage belongs to the host.
use super::{App, Session, block, command_dispatch, item, kv, transcript_effect};
use crate::app_server::{Control, LabCommandV1, ScopedLabFactsV1};
use crate::client_effects::experiment_lab::{
    ComparisonViewV1, LabActionV1, LabFactsV1, RequestStatusV1, RequestViewV1,
};
use std::sync::{Arc, atomic::AtomicBool};
const USAGE: &str = "/lab [list|request FAMILY JSON|compare BUNDLE TRUSTED_KEY|promote]";
fn parse(argument: &str) -> Result<LabActionV1, &'static str> {
    if argument.len() > 33 * 1024 {
        return Err("lab command exceeds input bound");
    }
    let text = argument.trim();
    let action = if text.is_empty() || text == "list" {
        LabActionV1::List
    } else if let Some(rest) = text.strip_prefix("request ") {
        let index = rest.find(char::is_whitespace).ok_or(USAGE)?;
        LabActionV1::Request {
            family: rest[..index].into(),
            value: rest[index..].trim().into(),
        }
    } else if let Some(rest) = text.strip_prefix("compare ") {
        let words = rest.split_whitespace().take(3).collect::<Vec<_>>();
        let [bundle, key] = words.as_slice() else {
            return Err(USAGE);
        };
        LabActionV1::Compare {
            bundle_id: (*bundle).into(),
            trusted_public_key: (*key).into(),
        }
    } else {
        return Err(USAGE);
    };
    action.validate()?;
    Ok(action)
}
pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    if argument.trim() == "promote" || argument.trim().starts_with("promote ") {
        app.panel("◇","experiment lab · promotion boundary",vec![kv("status","blocked by design"),
            kv("runtime activation","unavailable from /lab"),block::PanelRow::Note(
            "The lab can create offline train-only requests and compare signed evidence. It cannot activate or promote policy.".into())]);
        return;
    }
    let Some(scope) = session.client.thread_snapshot_v1() else {
        app.note(block::NoticeLevel::Warn, "lab has no current session");
        return;
    };
    match parse(argument) {
        Ok(action) => command_dispatch::queue_command_control(
            app,
            session,
            effects,
            interrupt,
            Control::Lab(LabCommandV1 {
                thread_id: scope.thread_id,
                run_id: scope.run_id,
                action,
            }),
            transcript_effect::ControlKind::Lab,
        ),
        Err(reason) => app.note(block::NoticeLevel::Err, reason),
    }
}
pub(super) fn render(app: &mut App, session: &Session, receipt: ScopedLabFactsV1) {
    if session
        .client
        .thread_snapshot_v1()
        .is_none_or(|scope| scope.thread_id != receipt.thread_id || scope.run_id != receipt.run_id)
    {
        app.note(
            block::NoticeLevel::Warn,
            "lab observation belongs to a previous session",
        );
        return;
    }
    render_facts(app, receipt.facts);
}
fn render_facts(app: &mut App, facts: LabFactsV1) {
    match facts {
        LabFactsV1::Inventory {
            requests,
            bundles,
            incomplete,
        } => {
            let mut rows = vec![
                kv("status", "offline · train-only"),
                kv("registry", iteron_tunables::REGISTRY_DIGEST_SHA256),
                kv("requests shown", &requests.len().to_string()),
                kv("evidence directories shown", &bundles.len().to_string()),
                kv(
                    "inventory",
                    if incomplete {
                        "incomplete · bounded scan or unreadable entries"
                    } else {
                        "observed complete"
                    },
                ),
            ];
            for request in requests {
                rows.push(item(
                    "◇",
                    &request.request_id,
                    &format!("{} = {}", request.family, request.value),
                ));
            }
            for bundle in bundles {
                rows.push(item(
                    "◆",
                    &bundle,
                    "unverified local index · /lab compare ID TRUSTED_KEY",
                ));
            }
            rows.push(block::PanelRow::Note("No runtime settings change when a request is created. Listed evidence is verified only by /lab compare.".into()));
            app.panel("◇", "experiment lab", rows);
        }
        LabFactsV1::Request { receipt } => render_request(app, &receipt),
        LabFactsV1::Comparison { view } => render_comparison(app, &view),
    }
}
fn render_request(app: &mut App, receipt: &RequestViewV1) {
    let status = match receipt.status {
        RequestStatusV1::Created => "requested · new",
        RequestStatusV1::Existing => "requested · existing",
        RequestStatusV1::NotPublished => "not recorded",
        RequestStatusV1::PublicationUnknown => "publication unknown · do not retry yet",
    };
    app.panel(
        "◇",
        "experiment request",
        vec![
            kv("status", status),
            kv("request", &receipt.request_id),
            kv("family", &receipt.family),
            kv("value", &receipt.value),
            kv("evaluation", "tune · train partition only"),
            kv("runtime activation", "none"),
            kv("artifact", &receipt.relative_path),
            block::PanelRow::Note("This request does not change the active policy.".into()),
        ],
    );
}
fn render_comparison(app: &mut App, view: &ComparisonViewV1) {
    let mut rows = vec![
        kv("trust", "verified · signed bytes + recomputed reports"),
        kv(
            "result status",
            if view.synthetic {
                "synthetic fixture · acceptance only · not a performance result"
            } else {
                "measured evidence"
            },
        ),
        kv("bundle", &view.bundle),
        kv(
            "baseline",
            &format!(
                "{} · {:.1}% resolved",
                view.baseline,
                view.baseline_rate * 100.0
            ),
        ),
        kv(
            "candidate",
            &format!(
                "{} · {:.1}% resolved",
                view.candidate,
                view.candidate_rate * 100.0
            ),
        ),
        kv(
            "quality Δ",
            &format!(
                "{:+.1} pp · CI95 [{:+.1}, {:+.1}]",
                view.rate_delta * 100.0,
                view.ci95[0] * 100.0,
                view.ci95[1] * 100.0
            ),
        ),
        kv(
            "paired observations",
            &format!("{} / {} minimum", view.matched, view.minimum),
        ),
        kv("conclusion", &view.conclusion),
        kv("signer", &view.signer_display),
        kv(
            "cost Δ",
            &view
                .cost_delta_usd
                .map(|cost| format!("${cost:+.6}"))
                .unwrap_or_else(|| "unknown · not promotion-ready".into()),
        ),
        kv(
            "row provenance",
            if view.synthetic {
                "synthetic fixture · acceptance only · not a result"
            } else {
                "measured · signed and recomputed"
            },
        ),
        kv(
            "resolved denominator",
            &format!(
                "{} / {} total rows",
                view.success + view.task_failure,
                view.total_rows
            ),
        ),
        kv(
            "row outcomes",
            &format!(
                "{} success · {} task failure · {} infrastructure failure · {} censored · {} held out",
                view.success,
                view.task_failure,
                view.infrastructure_failure,
                view.censored,
                view.held_out
            ),
        ),
    ];
    for point in &view.pareto {
        rows.push(item(
            "◆",
            &format!(
                "{} · {:.1}% · ${:.4}",
                point.candidate,
                point.resolved_rate * 100.0,
                point.average_cost_usd
            ),
            &format!(
                "{:.0} ms · {} failed",
                point.average_latency_ms, point.failed
            ),
        ));
    }
    rows.push(kv("Pareto frontier", &view.frontier.join(" · ")));
    rows.push(block::PanelRow::Note(
        "Evidence comparison is read-only and cannot activate runtime policy.".into(),
    ));
    app.panel("◆", "experiment evidence", rows);
}
#[cfg(test)]
mod tests;

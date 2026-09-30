//! Ordinary SDK reads use the same authenticated host port as remote clients.
use super::{App, Session, block, command_dispatch, item, transcript_effect, ui_safe_text};
use iteron_protocol::{RunId, SessionId, ordinary_extension_control::OrdinaryExtensionReadV1};
use serde_json::Value;
use std::sync::{Arc, atomic::AtomicBool};
fn parse(
    argument: &str,
    thread_id: SessionId,
    run_id: RunId,
) -> Result<OrdinaryExtensionReadV1, &'static str> {
    if argument.len() > 1024 {
        return Err("extension query exceeds bound");
    }
    let words = argument.split_whitespace().take(5).collect::<Vec<_>>();
    let command = match words.as_slice() {
        [] | ["read"] => OrdinaryExtensionReadV1::Read {
            thread_id,
            run_id,
            offset: 0,
            limit: 8,
        },
        ["read", offset] => OrdinaryExtensionReadV1::Read {
            thread_id,
            run_id,
            offset: offset.parse().map_err(|_| "invalid extension offset")?,
            limit: 8,
        },
        ["events", name] => OrdinaryExtensionReadV1::Events {
            thread_id,
            run_id,
            name: (*name).into(),
            limit: 16,
            timeout_ms: 0,
        },
        ["events", name, limit] => OrdinaryExtensionReadV1::Events {
            thread_id,
            run_id,
            name: (*name).into(),
            limit: limit.parse().map_err(|_| "invalid event limit")?,
            timeout_ms: 0,
        },
        ["events", name, limit, wait] => OrdinaryExtensionReadV1::Events {
            thread_id,
            run_id,
            name: (*name).into(),
            limit: limit.parse().map_err(|_| "invalid event limit")?,
            timeout_ms: wait.parse().map_err(|_| "invalid event wait")?,
        },
        _ => return Err("/extensions [read OFFSET|events NAME LIMIT WAIT_MS]"),
    };
    command.validate()?;
    Ok(command)
}
pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    let Some(thread) = session.client.thread_snapshot_v1() else {
        app.note(block::NoticeLevel::Warn, "public thread unavailable");
        return;
    };
    match parse(argument, thread.thread_id, thread.run_id) {
        Ok(command) => command_dispatch::queue_command_control(
            app,
            session,
            effects,
            interrupt,
            crate::app_server::Control::OrdinaryExtensions(command),
            transcript_effect::ControlKind::OrdinaryExtensions,
        ),
        Err(reason) => app.note(block::NoticeLevel::Warn, reason),
    }
}
pub(super) fn render(app: &mut App, session: &Session, value: &Value) {
    let scope = session.client.thread_snapshot_v1();
    if scope.is_none_or(|scope| {
        value["thread_id"].as_str() != Some(scope.thread_id.0.as_str())
            || value["run_id"].as_str() != Some(scope.run_id.0.as_str())
    }) {
        app.note(
            block::NoticeLevel::Warn,
            "extension observation belongs to a previous session",
        );
        return;
    }
    render_current(app, value);
}
fn render_current(app: &mut App, value: &Value) {
    let mut rows = vec![
        item("•", "configured", &value["configured"].to_string()),
        item(
            "•",
            "availability",
            value["availability"].as_str().unwrap_or("unavailable"),
        ),
    ];
    let data = &value["data"];
    if data["events"].is_array() {
        rows.push(item(
            "•",
            "delivery",
            data["delivery"].as_str().unwrap_or("unavailable"),
        ));
        rows.push(item("•", "scanned", &data["scanned"].to_string()));
        rows.push(item(
            "•",
            "other run rows filtered",
            &data["filtered_foreign_run"].to_string(),
        ));
        rows.push(item(
            "•",
            "unattributed rows excluded",
            &data["unscoped_observations"].to_string(),
        ));
        for event in data["events"].as_array().into_iter().flatten().take(64) {
            rows.push(block::PanelRow::Note(format!(
                "{} · turn {} · source seq {} · ordinal {}",
                ui_safe_text(event["event_id"].as_str().unwrap_or("unknown")),
                event["turn_id"]
                    .as_u64()
                    .map_or_else(|| "unavailable".into(), |value| value.to_string()),
                event["durable_seq"]
                    .as_u64()
                    .map_or_else(|| "unavailable".into(), |value| value.to_string()),
                event["ordinal"]
            )));
        }
        rows.push(block::PanelRow::Note("Lifecycle delivery is lossy; an empty batch does not prove completion or the absence of activity.".into()));
    } else if value["configured"] == true && value["availability"] == "available" {
        let catalog_prefix = data["catalog_sha256"]
            .as_str()
            .unwrap_or("unavailable")
            .chars()
            .take(12)
            .collect::<String>();
        rows.push(item("•", "catalog SHA-256 prefix", &catalog_prefix));
        rows.push(item(
            "•",
            "status source",
            &ui_safe_text(data["status"]["source"].as_str().unwrap_or("unavailable")),
        ));
        for route in data["providers"]["items"]
            .as_array()
            .into_iter()
            .flatten()
            .take(8)
        {
            let name = route["name"].as_str().unwrap_or("unknown");
            rows.push(item(
                "•",
                &ui_safe_text(name),
                &format!(
                    "native {}/{}",
                    ui_safe_text(route["host_provider_id"].as_str().unwrap_or("unavailable")),
                    ui_safe_text(route["host_model_id"].as_str().unwrap_or("unavailable"))
                ),
            ));
            rows.push(block::PanelRow::Note(format!(
                "Select through /model {}:{}; the ordinary model, pricing and budget checks apply.",
                ui_safe_text(route["host_provider_id"].as_str().unwrap_or("unavailable")),
                ui_safe_text(route["host_model_id"].as_str().unwrap_or("unavailable"))
            )));
        }
        for widget in data["status"]["widgets"]["items"]
            .as_array()
            .into_iter()
            .flatten()
            .take(8)
        {
            rows.push(item(
                "•",
                &ui_safe_text(widget["name"].as_str().unwrap_or("unknown")),
                &ui_safe_text(widget["label"].as_str().unwrap_or("unavailable")),
            ));
            for (fact, value) in widget["values"].as_object().into_iter().flatten().take(8) {
                let text = if value["availability"] == "known" {
                    value["value"].as_str().unwrap_or("unavailable").to_owned()
                } else {
                    format!(
                        "unavailable: {}",
                        value["reason"].as_str().unwrap_or("unknown")
                    )
                };
                rows.push(item("•", &ui_safe_text(fact), &ui_safe_text(&text)));
            }
        }
        for name in data["event_subscriptions"]["items"]
            .as_array()
            .into_iter()
            .flatten()
            .take(8)
        {
            rows.push(block::PanelRow::Note(format!(
                "/extensions events {} · lossy lifecycle observer",
                ui_safe_text(name.as_str().unwrap_or("unavailable"))
            )));
        }
        rows.push(block::PanelRow::Note(format!("Page {} · total routes {} / widgets {} / subscriptions {}; /extensions read OFFSET pages each section.", data["page"]["offset"], data["providers"]["total"], data["status"]["widgets"]["total"], data["event_subscriptions"]["total"])));
        rows.push(block::PanelRow::Note(
            "Per-extension monetary cost is unavailable; /cost shows the actual session ledger."
                .into(),
        ));
    }
    app.panel("", "Ordinary extensions", rows);
}

#[cfg(test)]
mod tests {
    use super::{App, RunId, SessionId, parse, render_current};
    use serde_json::json;
    #[test]
    fn sdk_panel_keeps_unknown_cost_and_lossy_observation_distinct_from_completion() {
        assert!(
            parse(
                "events sample__events 64 60000",
                SessionId("thread".into()),
                RunId("run".into())
            )
            .is_ok()
        );
        assert!(
            parse(
                "events sample__events 65 60000",
                SessionId("thread".into()),
                RunId("run".into())
            )
            .is_err()
        );
        let mut app = App::new();
        render_current(
            &mut app,
            &json!({"configured":true,"availability":"available","data":{
                "catalog_sha256":"a".repeat(64),"page":{"offset":0},"providers":{"total":0,"items":[]},
                "status":{"source":"actual_host_last_settled_budget_boundary","widgets":{"total":1,"items":[{"name":"sample__status","label":"Native status","values":{"tokens_remaining":{"availability":"unavailable","reason":"no_token_ceiling_configured"}}}]}},
                "event_subscriptions":{"total":1,"items":["sample__events"]}
            }}),
        );
        let text = app.transcript.last().unwrap().to_text();
        assert!(text.contains("no_token_ceiling_configured"));
        assert!(text.contains("Per-extension monetary cost is unavailable"));
        let screen = crate::tui::tests::render_text(&mut app, 120, 30);
        assert!(screen.contains("Native status"), "{screen}");
        assert!(screen.contains("sample__events"), "{screen}");
        render_current(
            &mut app,
            &json!({"configured":true,"availability":"available","data":{
                "events":[],"scanned":0,"delivery":"lossy_content_free_lifecycle_bus_not_durable_replay"
            }}),
        );
        let text = app.transcript.last().unwrap().to_text();
        assert!(text.contains("does not prove completion"));
        assert!(!app.running);
    }
}

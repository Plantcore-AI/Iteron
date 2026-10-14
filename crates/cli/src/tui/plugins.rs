//! Plugin controls use the captured public owner, including signed host-prepared install handles.
use super::{App, Session, block, command_dispatch, item, transcript_effect, ui_safe_text};
use iteron_protocol::{RunId, SessionId, plugin_control::PluginControlV1};
use serde_json::Value;
use std::sync::{Arc, atomic::AtomicBool};

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
    let command = match parse(argument, thread.thread_id, thread.run_id) {
        Ok(command) => command,
        Err(reason) => {
            app.note(block::NoticeLevel::Warn, reason);
            return;
        }
    };
    command_dispatch::queue_command_control(
        app,
        session,
        effects,
        interrupt,
        crate::app_server::Control::PluginManagement(command),
        transcript_effect::ControlKind::PluginManagement,
    );
}

fn parse(
    argument: &str,
    thread_id: SessionId,
    run_id: RunId,
) -> Result<PluginControlV1, &'static str> {
    if argument.len() > 1024 {
        return Err("plugin command exceeds bound");
    }
    let words = argument.split_whitespace().take(5).collect::<Vec<_>>();
    let page = |text: &str| {
        text.parse::<u16>()
            .map_err(|_| "invalid plugin page offset")
    };
    let command = match words.as_slice() {
        [] | ["list"] => PluginControlV1::List {
            thread_id,
            run_id,
            offset: 0,
            limit: 16,
        },
        ["list", offset] => PluginControlV1::List {
            thread_id,
            run_id,
            offset: page(offset)?,
            limit: 16,
        },
        ["inspect", id] => PluginControlV1::Inspect {
            thread_id,
            run_id,
            plugin_id: (*id).into(),
            binding_offset: 0,
            limit: 16,
        },
        ["inspect", id, offset] => PluginControlV1::Inspect {
            thread_id,
            run_id,
            plugin_id: (*id).into(),
            binding_offset: page(offset)?,
            limit: 16,
        },
        ["disable", id] | ["enable", id] => PluginControlV1::SetEnabled {
            thread_id,
            run_id,
            plugin_id: (*id).into(),
            enabled: words[0] == "enable",
        },
        ["priority", id, rank] => PluginControlV1::SetPrecedence {
            thread_id,
            run_id,
            plugin_id: (*id).into(),
            precedence: rank.parse().map_err(|_| "invalid plugin priority")?,
        },
        ["rollback", id] => PluginControlV1::Rollback {
            thread_id,
            run_id,
            plugin_id: (*id).into(),
        },
        ["install", id] => PluginControlV1::Install {
            thread_id,
            run_id,
            receipt_id: (*id).into(),
        },
        _ => {
            return Err(
                "/plugins [list OFFSET|inspect ID OFFSET|disable ID|enable ID|priority ID RANK|rollback ID|install RECEIPT]",
            );
        }
    };
    command.validate()?;
    Ok(command)
}

pub(super) fn render(app: &mut App, value: &Value) {
    let data = &value["data"];
    let snapshot = if data["snapshot"].is_object() {
        &data["snapshot"]
    } else {
        data
    };
    let mut rows = Vec::new();
    if data["change_confirmed"].is_boolean() {
        rows.push(item(
            "•",
            "configuration persisted",
            &data["change_confirmed"].to_string(),
        ));
    }
    rows.push(item(
        "•",
        "next verified bootstrap pending",
        &snapshot["next_bootstrap_pending"].to_string(),
    ));
    if let Some(id) = snapshot["plugin_id"].as_str() {
        rows.push(item("•", "package", &ui_safe_text(id)));
        let rendered = serde_json::to_string_pretty(snapshot).unwrap_or_default();
        rows.push(block::PanelRow::Note(ui_safe_text(&rendered)));
    } else {
        rows.push(item(
            "•",
            "registry generation",
            &snapshot["configuration"]["generation"].to_string(),
        ));
        for identity in snapshot["current_generation"]["items"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = identity["plugin_id"].as_str().unwrap_or("unknown");
            rows.push(item(
                "•",
                &ui_safe_text(id),
                &format!(
                    "version {} · future dispatch revoked {}",
                    identity["version"], identity["future_dispatch_revoked"]
                ),
            ));
            rows.push(block::PanelRow::Note(format!(
                "/plugins inspect {} · /plugins disable {}",
                ui_safe_text(id),
                ui_safe_text(id)
            )));
        }
        for entry in snapshot["configuration"]["plugins"]["items"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = entry[0].as_str().unwrap_or("unknown");
            rows.push(item(
                "•",
                &format!("selection {}", ui_safe_text(id)),
                &format!(
                    "enabled {} · priority {} · rollback retained {}",
                    entry[1]["enabled"],
                    entry[1]["precedence"],
                    !entry[1]["previous"].is_null()
                ),
            ));
        }
        for receipt in snapshot["prepared_installs"]["items"]
            .as_array()
            .into_iter()
            .flatten()
        {
            rows.push(block::PanelRow::Note(format!(
                "signed prepared {} · /plugins install {}",
                ui_safe_text(receipt["plugin_id"].as_str().unwrap_or("unknown")),
                ui_safe_text(receipt["receipt_id"].as_str().unwrap_or("unavailable"))
            )));
        }
        for field in ["conflicts", "refusals"] {
            for entry in snapshot["bootstrap_composition"][field]["items"]
                .as_array()
                .into_iter()
                .flatten()
            {
                rows.push(item("•", field, &ui_safe_text(&entry.to_string())));
            }
        }
        rows.push(block::PanelRow::Note(format!(
            "page {} / limit {} · total configured {} / active {}",
            snapshot["page"]["offset"],
            snapshot["page"]["limit"],
            snapshot["configuration"]["plugins"]["total"],
            snapshot["current_generation"]["total"]
        )));
        rows.push(block::PanelRow::Note("/plugins list OFFSET pages configuration, conflicts and prepared handles; /plugins inspect ID OFFSET pages actual bindings".into()));
    }
    if let Some(error) = snapshot["last_error_code"].as_str() {
        rows.push(item("!", "configuration result", error));
    }
    rows.push(block::PanelRow::Note("Enable/install/priority take effect at the next verified bootstrap. Disable/rollback revoke future dispatch now; already executing work keeps its actual owner state. Package cost totals unavailable.".into()));
    app.panel("⋯", "plugins", rows);
}

#[cfg(test)]
mod tests {
    use super::parse;
    use iteron_protocol::{RunId, SessionId};
    #[test]
    fn receipt_and_page_commands_never_admit_package_paths_or_trust_parameters() {
        let scope = || (SessionId("thread".into()), RunId("run".into()));
        for argument in [
            "install /tmp/package",
            "install prepared-key trust",
            "list 4097",
            "inspect package 65535",
            "enable package now",
        ] {
            let (thread, run) = scope();
            assert!(parse(argument, thread, run).is_err(), "{argument}");
        }
        for argument in [
            "install prepared-1",
            "disable package",
            "enable package",
            "priority package 3",
            "rollback package",
            "inspect package 16",
            "list 16",
        ] {
            let (thread, run) = scope();
            assert!(parse(argument, thread, run).is_ok(), "{argument}");
        }
    }
}

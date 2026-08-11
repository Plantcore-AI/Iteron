//! `/mcp`: live, per-server status and lifecycle controls.

use super::*;

const USAGE: &str = "usage: /mcp [status] | /mcp restart|stop|cancel <server>";

pub(super) async fn handle(app: &mut App, session: &mut Session, argument: &str) {
    let mut words = argument.split_whitespace();
    let action = words.next().unwrap_or("status");
    let server = words.next();
    if words.next().is_some() {
        app.note(block::NoticeLevel::Err, USAGE);
        return;
    }

    let control = match (action, server) {
        ("status", None) => app_server::McpControl::Status,
        ("restart", Some(server)) => app_server::McpControl::Restart {
            server: server.to_owned(),
        },
        ("stop", Some(server)) => app_server::McpControl::Stop {
            server: server.to_owned(),
        },
        ("cancel", Some(server)) => app_server::McpControl::Cancel {
            server: server.to_owned(),
        },
        _ => {
            app.note(block::NoticeLevel::Err, USAGE);
            return;
        }
    };

    match session.control(app_server::Control::Mcp(control)).await {
        Some(app_server::ControlReply::Mcp(reply)) => render_reply(app, *reply),
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the session-owned MCP runtime is no longer reachable",
        ),
    }
}

pub(super) fn render_reply(app: &mut App, mut reply: app_server::McpControlReply) {
    if let Some(notice) = reply.notice.take() {
        app.note(block::NoticeLevel::Ok, notice);
    }
    if reply.servers.is_empty() {
        app.note(
            block::NoticeLevel::Info,
            "no MCP servers configured (add trusted user MCP configuration and restart Core)",
        );
        return;
    }

    reply.servers.sort_by(|a, b| a.name.cmp(&b.name));
    let rows = reply
        .servers
        .iter()
        .map(|server| block::PanelRow::Item {
            label: format!(
                "{}  {} · {} · {}",
                phase_mark(&server.phase, server.busy),
                server.name,
                server.transport,
                server.phase
            ),
            hint: server_runtime_hint(server),
        })
        .chain(std::iter::once(block::PanelRow::Note(
            "controls: /mcp cancel <server> · /mcp restart <server> · /mcp stop <server>".into(),
        )))
        .collect();
    app.panel(
        "◈",
        &format!("{} session-owned MCP servers", reply.servers.len()),
        rows,
    );
}

pub(super) fn server_runtime_hint(server: &crate::mcp::McpServerHealth) -> String {
    let generation = server
        .generation
        .map_or_else(|| "unknown".into(), |value| value.to_string());
    let protocol = server
        .negotiated_protocol_version
        .as_deref()
        .unwrap_or("not negotiated");
    let retry = server
        .retry_after_ms
        .map_or_else(|| "no retry wait".into(), |ms| format!("retry in {ms}ms"));
    let catalog = if server.catalog_current {
        format!("{} retained", server.retained_tools)
    } else {
        "catalog deferred".into()
    };
    let failure = server.last_failure.as_deref().map_or_else(
        || "no retained failure".into(),
        |reason| format!("last failure {reason}"),
    );
    format!(
        "protocol {protocol} · generation {generation} · reconnect {}/{} · {retry} · {failure} · {catalog} · {}",
        server.reconnect_attempts,
        server.reconnect_limit,
        if server.busy { "busy" } else { "idle" }
    )
}

fn phase_mark(phase: &str, busy: bool) -> &'static str {
    if busy {
        "◌"
    } else {
        match phase {
            "ready" => "●",
            "stopped" | "failed" => "×",
            "backoff" | "connecting" | "discovering" => "◒",
            _ => "○",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::phase_mark;

    #[test]
    fn phase_marks_distinguish_live_deferred_and_terminal_servers() {
        assert_eq!(phase_mark("ready", false), "●");
        assert_eq!(phase_mark("deferred", false), "○");
        assert_eq!(phase_mark("backoff", false), "◒");
        assert_eq!(phase_mark("stopped", false), "×");
        assert_eq!(phase_mark("ready", true), "◌");
    }
}

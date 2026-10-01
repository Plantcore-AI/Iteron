#[cfg(test)]
use super::session_management;
use super::{
    App, PickAction, PickItem, ProviderCatalogView, Session, app_server, block, command_dispatch,
    start_adopt_session, start_fresh_session, transcript_effect, ui_safe_text,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
mod native_history_fixtures;
use super::history_client::HistoryClient;
use iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1;
#[cfg(test)]
pub(super) use native_history_fixtures::{
    load_session_page, session_picker_items, spawn_session_page_load,
};

/// Characters kept from a session title in the picker row. A title longer than this wraps on a
/// conventional terminal and pushes the sessions below it off the list.
const PICKER_TITLE_MAX_CHARS: usize = 80;
const SESSION_PICKER_PAGE_SIZE: usize = 25;
const SESSION_PICKER_PREFETCH_DISTANCE: usize = 5;
pub(super) fn session_picker_page_size() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.session_picker.session_picker_page_size",
        SESSION_PICKER_PAGE_SIZE,
    )
    .clamp(1, 64)
}

pub(super) fn session_picker_prefetch_distance() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.session_picker.session_picker_prefetch_distance",
        SESSION_PICKER_PREFETCH_DISTANCE,
    )
}

pub(super) struct SessionPickerBacking {
    pub(super) runs: PathBuf,
    pub(super) current_run: String,
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
    pub(super) generation: u64,
}

pub(super) struct SessionPageResult {
    pub(super) generation: u64,
    pub(super) runs: PathBuf,
    pub(super) current_run: String,
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
    pub(super) replace: bool,
    pub(super) warning: Option<String>,
    pub(super) items: Vec<PickItem>,
}

pub(super) struct SessionPreview {
    pub(super) inspection: serde_json::Value,
}

pub(super) fn open_session_picker(app: &mut App, session: &Session) {
    if app.run.running() || app.permission_prompt.read().is_some() {
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
    app.navigation.cancel_preview();
    let Some(history) = HistoryClient::capture(session.client.clone(), session.control_sender())
    else {
        app.note(
            block::NoticeLevel::Warn,
            "history host scope is unavailable",
        );
        return;
    };
    app.pickers
        .open_sessions(history, runs, current_run.to_owned());
}

pub(super) fn failed_session_page(
    runs: PathBuf,
    current_run: String,
    generation: u64,
    reason: &str,
) -> SessionPageResult {
    let mut item = PickItem::flat("Sessions unavailable", reason, false, PickAction::Info);
    item.enabled = false;
    item.disabled_reason = Some("Esc to close; /resume to retry".into());
    SessionPageResult {
        generation,
        runs,
        current_run,
        next_cursor: None,
        has_more: false,
        replace: true,
        warning: None,
        items: vec![item],
    }
}

pub(super) fn spawn_host_session_page_load(
    history: HistoryClient,
    runs: PathBuf,
    current_run: String,
    generation: u64,
    cursor: Option<String>,
    page_size: usize,
    first: bool,
) -> tokio::task::JoinHandle<SessionPageResult> {
    tokio::spawn(async move {
        let load = async {
            let list = |cursor| ThreadLifecycleCommandV1::List {
                cursor,
                limit: page_size.clamp(1, 64) as u16,
            };
            let mut page = history.request(list(cursor)).await?;
            if page["type"] != "thread_list_v1" || !page["index_ready"].is_boolean() {
                return Err("session list lacks a host observation".into());
            }
            let mut replace = first;
            let mut warning = None;
            if page["index_ready"] != true {
                if page["rebuild_recommended"] != true {
                    return Err("session index is temporarily unavailable; reopen to retry".into());
                }
                let repaired = history.repair_index().await?;
                if repaired["type"] != "thread_reindexed_v1" {
                    return Err("session index repair lacks a host receipt".into());
                }
                if repaired["unavailable"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
                {
                    warning =
                        Some("some records were unavailable to the verified index repair".into());
                }
                page = history.request(list(None)).await?;
                replace = true;
            } else if page["cursor_stale"] == true {
                page = history.request(list(None)).await?;
                replace = true;
                warning = Some("session index changed; restarted from newest".into());
            }
            if page["type"] != "thread_list_v1" || page["index_ready"] != true {
                return Err("session index is unavailable after host repair".into());
            }
            if page["next_cursor"]
                .as_str()
                .is_some_and(|cursor| cursor.len() > 1024)
            {
                return Err("session cursor exceeds its host bound".into());
            }
            let items = host_session_picker_items(&page, &current_run)?;
            Ok(SessionPageResult {
                generation,
                runs: runs.clone(),
                current_run: current_run.clone(),
                next_cursor: page["next_cursor"].as_str().map(str::to_owned),
                has_more: page["has_more"] == true,
                replace,
                warning,
                items,
            })
        }
        .await;
        load.unwrap_or_else(|reason: String| {
            failed_session_page(runs, current_run, generation, &reason)
        })
    })
}
fn host_session_picker_items(
    page: &serde_json::Value,
    current_run: &str,
) -> Result<Vec<PickItem>, String> {
    let rows = page["threads"]
        .as_array()
        .ok_or("host session page is unavailable")?;
    if rows.len() > 64 {
        return Err("host session page exceeds its display bound".into());
    }
    let mut items = Vec::new();
    for row in rows {
        let run = row["run_id"]
            .as_str()
            .ok_or("host session identity is unavailable")?;
        ThreadLifecycleCommandV1::Read {
            run_id: iteron_protocol::RunId(run.into()),
        }
        .validate()
        .map_err(str::to_owned)?;
        let title = row["title"].as_str().unwrap_or(run);
        let provider = row["provider_id"].as_str().unwrap_or("route unknown");
        let model = row["model"].as_str().unwrap_or("model unknown");
        let workspace = row["workspace"].as_str().unwrap_or("workspace unavailable");
        if title.len() > 1024
            || provider.len() > 1024
            || model.len() > 1024
            || workspace.len() > 4096
        {
            return Err("host session display exceeds its text bound".into());
        }
        let cost = row["cost_usd"]
            .as_f64()
            .filter(|cost| cost.is_finite() && *cost >= 0.0)
            .map_or_else(|| "cost unknown".into(), |cost| format!("${cost:.4}"));
        let route = format!("{provider}/{model}");
        let outcome = match row["recorded_outcome"].as_str() {
            Some("done") => "done",
            Some("drained") => "drained",
            Some("budget_exhausted") => "budget exhausted",
            Some("interrupted") => "interrupted",
            Some("stuck") => "stuck",
            Some("harness_error") => "harness error",
            _ => "no terminal available",
        };
        let pinned = row["pinned"] == true;
        let archived = row["archived"] == true;
        let flags = format!(
            "{}{}",
            if row["pinned"] == true {
                " · pinned"
            } else {
                ""
            },
            if row["archived"] == true {
                " · archived"
            } else {
                ""
            }
        );
        let turns = row["turns"].as_u64().unwrap_or(0);
        let mut item = PickItem::flat(
            ui_safe_text(title),
            format!(
                "run {run} · {turns} turns · {cost} · {}{flags} · {} · recorded {}",
                ui_safe_text(&route),
                ui_safe_text(workspace),
                outcome
            ),
            run == current_run,
            PickAction::AdoptRun(run.into()),
        );
        if item.hint.len() > 8192 {
            return Err("host session display exceeds its text bound".into());
        }
        item.label = item
            .label
            .chars()
            .take(
                iteron_tunables::param_integer(
                    "cli.tui.session_picker.picker_title_max_chars",
                    PICKER_TITLE_MAX_CHARS,
                )
                .min(1024),
            )
            .collect();
        items.push((pinned, archived, item));
    }
    // Stable sort preserves the host's chronology among equal actual presentation flags.
    items.sort_by_key(|(pinned, archived, _)| (!pinned, *archived));
    Ok(items.into_iter().map(|(_, _, item)| item).collect())
}

#[cfg(test)]
pub(super) fn apply_session_page_result(
    app: &mut App,
    result: Result<SessionPageResult, tokio::task::JoinError>,
) -> bool {
    let update = app.pickers.apply_page(result);
    for warning in update.warnings {
        app.note(block::NoticeLevel::Info, warning);
    }
    update.changed
}

pub(super) fn maybe_prefetch_session_page(app: &mut App) {
    app.pickers.prefetch();
}

pub(super) fn start_session_preview(app: &mut App, session: &Session, run: String) {
    let Some(scope) = session.client.thread_snapshot_v1() else {
        app.note(block::NoticeLevel::Warn, "public session scope unavailable");
        return;
    };
    app.navigation
        .queue_preview(&scope, session.control_sender(), run);
}

pub(super) fn handle_sessions_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderCatalogView,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    let argument = argument.trim();
    if argument.is_empty() {
        open_session_picker(app, session);
        return;
    }
    if app.run.running() || app.permission_prompt.read().is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before managing sessions",
        );
        return;
    }
    let mut words = argument.splitn(3, char::is_whitespace);
    let action = words.next().unwrap_or_default();
    let run = words.next().unwrap_or_default();
    let tail = words.next().unwrap_or_default().trim();
    match action {
        "new" => start_fresh_session(app, session, directory),
        "switch" | "resume" if !run.is_empty() => {
            start_adopt_session(app, session, directory, run.to_owned())
        }
        "preview" if !run.is_empty() => start_session_preview(app, session, run.to_owned()),
        "rename" | "pin" | "unpin" | "archive" | "unarchive" | "delete" | "read" | "export" | "trace" if !run.is_empty() => {
            use iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1 as Command;
            let run_id = iteron_protocol::RunId(run.to_owned());
            let command = match action {
                "rename" => Command::Rename { run_id, title: tail.to_owned() },
                "pin" | "unpin" => Command::Pin { run_id, pinned: action == "pin" },
                "archive" | "unarchive" => Command::Archive { run_id, archived: action == "archive" },
                "delete" => Command::Delete { run_id, confirm_permanent_erasure: tail == "permanently" },
                "export" => Command::Export { run_id },
                "trace" => {
                    let after_seq = if tail.is_empty() { None } else {
                        match tail.parse::<u64>() {
                            Ok(sequence) => Some(sequence),
                            Err(_) => { app.note(block::NoticeLevel::Err, "trace cursor must be an integer"); return; }
                        }
                    };
                    Command::TraceRead { run_id, after_seq, limit: 16 }
                },
                _ => Command::Read { run_id },
            };
            command_dispatch::queue_command_control(
                app, session, effects, interrupt,
                app_server::Control::ThreadLifecycle(command),
                transcript_effect::ControlKind::ThreadLifecycle,
            );
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "usage: /sessions [new|switch RUN|preview RUN|rename RUN TITLE|pin RUN|unpin RUN|archive RUN|unarchive RUN|delete RUN permanently|read RUN|export RUN|trace RUN [AFTER_SEQ]]",
        ),
    }
}

#[cfg(test)]
mod host_page_tests {
    use super::host_session_picker_items;
    use serde_json::json;
    #[test]
    fn real_flags_control_sort_and_unknown_cost_never_becomes_success() {
        let page = json!({"threads":[
            {"run_id":"spoof", "title":"Spoof · pinned", "provider_id":"fake · pinned", "pinned":false,"archived":false,"cost_usd":null,"recorded_outcome":"invented"},
            {"run_id":"real","title":"Real", "pinned":true,"archived":false,"cost_usd":0.4,"recorded_outcome":"done"}
        ]});
        let items = host_session_picker_items(&page, "spoof").unwrap();
        assert_eq!(items[0].label, "Real");
        assert!(items[1].is_current);
        assert!(items[1].hint.contains("cost unknown"));
        assert!(items[1].hint.contains("no terminal available"));
        assert!(items[0].hint.contains("recorded done"));
        let large = json!({"threads":[{"run_id":"real","title":"x".repeat(1025)}]});
        assert!(host_session_picker_items(&large, "").is_err());
    }
}

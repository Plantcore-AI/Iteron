use super::*;

/// Characters kept from a session title in the picker row. A title longer than this wraps on a
/// conventional terminal and pushes the sessions below it off the list.
const PICKER_TITLE_MAX_CHARS: usize = 80;
const SESSION_PICKER_PAGE_SIZE: usize = 25;
const SESSION_PICKER_PREFETCH_DISTANCE: usize = 5;
static SESSION_INDEX_REBUILDS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, std::sync::Arc<SessionIndexRebuild>>>,
> = std::sync::OnceLock::new();

struct SessionIndexRebuild {
    result: std::sync::Mutex<Option<Result<(), String>>>,
    ready: std::sync::Condvar,
}

static SESSION_PAGE_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct SessionPageLoadSlot;

impl Drop for SessionPageLoadSlot {
    fn drop(&mut self) {
        SESSION_PAGE_LOADS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn max_background_session_index_rebuilds() -> usize {
    iteron_tunables::param_usize(
        "cli.tui.session_picker.max_background_session_index_rebuilds",
        8,
    )
    .clamp(1, 8)
}

fn session_picker_page_size() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.session_picker.session_picker_page_size",
        SESSION_PICKER_PAGE_SIZE,
    )
    .max(1)
}

fn session_picker_prefetch_distance() -> usize {
    iteron_tunables::param_integer(
        "cli.tui.session_picker.session_picker_prefetch_distance",
        SESSION_PICKER_PREFETCH_DISTANCE,
    )
}

pub(super) struct SessionPickerBacking {
    pub(super) runs: PathBuf,
    pub(super) current_run: String,
    pub(super) next_cursor: Option<iteron_record::SessionPageCursor>,
    pub(super) has_more: bool,
    pub(super) generation: u64,
}

pub(super) struct SessionPageResult {
    pub(super) generation: u64,
    pub(super) runs: PathBuf,
    pub(super) current_run: String,
    pub(super) next_cursor: Option<iteron_record::SessionPageCursor>,
    pub(super) has_more: bool,
    pub(super) replace: bool,
    pub(super) warning: Option<String>,
    pub(super) items: Vec<PickItem>,
}

pub(super) struct SessionPreview {
    pub(super) run: String,
    pub(super) title: String,
    pub(super) turns: u32,
    pub(super) state: &'static str,
    pub(super) total_blocks: usize,
    pub(super) blocks: Vec<String>,
}

pub(super) struct SessionPreviewResult {
    pub(super) generation: u64,
    pub(super) result: Result<SessionPreview, String>,
}

pub(super) fn session_picker_items(
    mut sessions: Vec<iteron_record::SessionMeta>,
    current_run: &str,
    runs: &Path,
) -> Vec<PickItem> {
    let mut decorated = sessions
        .drain(..)
        .map(|session| {
            let view = session_management::load(runs, &session.run_id.0).unwrap_or_default();
            (session, view)
        })
        .collect::<Vec<_>>();
    decorated.sort_by(|(left, left_view), (right, right_view)| {
        right_view
            .pinned
            .cmp(&left_view.pinned)
            .then_with(|| left_view.archived.cmp(&right_view.archived))
            .then_with(|| right.updated_at.cmp(&left.updated_at))
            .then_with(|| {
                right
                    .updated_at_subsec_nanos
                    .cmp(&left.updated_at_subsec_nanos)
            })
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| left.run_id.0.cmp(&right.run_id.0))
    });
    decorated
        .into_iter()
        .map(|(session, view)| {
            let cost = session
                .cost_usd()
                .map(|value| format!("${value:.4}"))
                .unwrap_or_else(|| "cost unknown".into());
            let route = match (
                session.provider_id.trim().is_empty(),
                session.model.trim().is_empty(),
            ) {
                (false, false) => format!("{}/{}", session.provider_id, session.model),
                (false, true) => session.provider_id.clone(),
                (true, false) => session.model.clone(),
                (true, true) => "route unknown".into(),
            };
            let run_id = session.run_id.0;
            let mut flags = Vec::new();
            if view.pinned {
                flags.push("pinned");
            }
            if view.archived {
                flags.push("archived");
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" · {}", flags.join(" · "))
            };
            PickItem::flat(
                view.title.unwrap_or(session.title),
                format!(
                    "run {run_id} · {} · {cost} · {route}{flags}",
                    block::plural(session.turns as usize, "turn")
                ),
                run_id == current_run,
                PickAction::AdoptRun(run_id),
            )
        })
        .collect()
}

pub(super) fn session_display_name(rollout_path: &Path) -> String {
    let Some(runs) = rollout_path.parent() else {
        return "New session".into();
    };
    let Some(run) = rollout_path.file_stem().and_then(|stem| stem.to_str()) else {
        return "New session".into();
    };
    let renamed = session_management::load(runs, run)
        .ok()
        .and_then(|presentation| presentation.title)
        .filter(|title| !title.trim().is_empty());
    let recorded = || {
        iteron_record::session::meta(runs, &iteron_protocol::RunId(run.to_owned()))
            .ok()
            .map(|metadata| metadata.title)
            .filter(|title| !title.trim().is_empty())
    };
    let title = renamed
        .or_else(recorded)
        .unwrap_or_else(|| "New session".into());
    title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(iteron_tunables::param_integer(
            "cli.tui.session_picker.picker_title_max_chars",
            PICKER_TITLE_MAX_CHARS,
        ))
        .collect()
}

pub(super) fn open_session_picker(app: &mut App, session: &Session) {
    if app.running || app.pending.is_some() {
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
    if let Some(previous) = app.session_picker_job.take() {
        previous.abort();
    }
    if let Some(previous) = app.session_preview_job.take() {
        previous.abort();
    }
    app.session_picker_backing = None;
    app.session_picker_generation = app.session_picker_generation.wrapping_add(1);
    let generation = app.session_picker_generation;
    let mut loading = PickItem::flat(
        "Loading sessions…",
        "reading your saved conversations",
        false,
        PickAction::Info,
    );
    loading.enabled = false;
    loading.disabled_reason = Some("Esc to close while sessions load".into());
    app.picker = Some(Picker {
        title: "Sessions · resume here".into(),
        items: vec![loading],
        sel: 0,
        query: String::new(),
        saved_theme: None,
    });
    let current_run = current_run.to_owned();
    app.session_picker_job = Some(spawn_session_page_load(
        runs,
        current_run,
        generation,
        None,
        session_picker_page_size(),
        true,
    ));
}

pub(super) fn load_session_page(
    runs: PathBuf,
    current_run: String,
    generation: u64,
    cursor: Option<iteron_record::SessionPageCursor>,
    page_size: usize,
    first: bool,
) -> SessionPageResult {
    let tenant = iteron_protocol::TenantId::default();
    let mut page = iteron_record::page(&runs, &tenant, None, cursor, Some(page_size));
    let mut warning = None;
    let mut replace = first;
    if !page.index_ready {
        if let Err(reason) = rebuild_session_index(&runs) {
            return failed_session_page(runs, current_run, generation, &reason);
        }
        page = iteron_record::page(&runs, &tenant, None, None, Some(page_size));
        replace = true;
        if !page.index_ready {
            return failed_session_page(
                runs,
                current_run,
                generation,
                "The session index could not be read after rebuilding. Close and reopen /resume to retry.",
            );
        }
    } else if page.cursor_stale {
        page = iteron_record::page(&runs, &tenant, None, None, Some(page_size));
        replace = true;
        warning = Some("session index changed; restarted from newest".into());
    }
    let items = session_picker_items(page.sessions, &current_run, &runs);
    SessionPageResult {
        generation,
        runs,
        current_run,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        replace,
        warning,
        items,
    }
}

/// One rebuild per directory. Its callers wait on blocking workers while the TUI stays live;
/// completion reloads the page automatically, and every failure becomes a terminal picker row.
fn rebuild_session_index(runs: &Path) -> Result<(), String> {
    let key = runs.canonicalize().unwrap_or_else(|_| runs.to_path_buf());
    let active = SESSION_INDEX_REBUILDS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let (state, start) = {
        let mut active = active
            .lock()
            .map_err(|_| "Session index worker is unavailable.")?;
        if let Some(state) = active.get(&key) {
            (state.clone(), false)
        } else {
            if active.len() >= max_background_session_index_rebuilds() {
                return Err(
                    "Session index workers are busy. Close and reopen /resume to retry.".into(),
                );
            }
            let state = std::sync::Arc::new(SessionIndexRebuild {
                result: std::sync::Mutex::new(None),
                ready: std::sync::Condvar::new(),
            });
            active.insert(key.clone(), state.clone());
            (state, true)
        }
    };
    if start {
        let thread_key = key.clone();
        let worker_state = state.clone();
        let spawned = std::thread::Builder::new()
            .name("iteron-session-picker-reindex".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(|| iteron_record::reindex(&thread_key))
                    .map_err(|_| "Session index worker failed. Reopen /resume to retry.".to_string())
                    .and_then(|result| result.map(|_| ()).map_err(|_| "Cannot rebuild the session index. Check the session directory is readable and writable, then reopen /resume.".to_string()));
                if let Ok(mut slot) = worker_state.result.lock() {
                    *slot = Some(result);
                }
                worker_state.ready.notify_all();
                if let Some(active) = SESSION_INDEX_REBUILDS.get()
                    && let Ok(mut active) = active.lock()
                {
                    active.remove(&thread_key);
                }
            });
        if spawned.is_err() {
            if let Ok(mut active) = active.lock() {
                active.remove(&key);
            }
            if let Ok(mut result) = state.result.lock() {
                *result = Some(Err(
                    "Cannot start the session index worker. Reopen /resume to retry.".into(),
                ));
            }
            state.ready.notify_all();
        }
    }
    let result = state
        .result
        .lock()
        .map_err(|_| "Session index worker failed.")?;
    let (result, _) = state
        .ready
        .wait_timeout_while(result, Duration::from_secs(10), |result| result.is_none())
        .map_err(|_| "Session index worker failed.")?;
    result.clone().unwrap_or_else(|| Err(
        "Session index rebuilding is taking longer than expected. Close and reopen /resume to retry.".into()
    ))
}

fn failed_session_page(
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

pub(super) fn spawn_session_page_load(
    runs: PathBuf,
    current_run: String,
    generation: u64,
    cursor: Option<iteron_record::SessionPageCursor>,
    page_size: usize,
    first: bool,
) -> tokio::task::JoinHandle<SessionPageResult> {
    tokio::spawn(async move {
        if SESSION_PAGE_LOADS
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |active| (active < max_background_session_index_rebuilds()).then_some(active + 1),
            )
            .is_err()
        {
            return failed_session_page(
                runs,
                current_run,
                generation,
                "Session loading is busy. Close and reopen /resume to retry.",
            );
        }
        let slot = SessionPageLoadSlot;
        let worker_runs = runs.clone();
        let worker_run = current_run.clone();
        let job = tokio::task::spawn_blocking(move || {
            // Keep admission until physical work ends, even when its picker has closed or timed out.
            let _slot = slot;
            load_session_page(
                worker_runs,
                worker_run,
                generation,
                cursor,
                page_size,
                first,
            )
        });
        match tokio::time::timeout(Duration::from_secs(15), job).await {
            Ok(Ok(page)) => page,
            Ok(Err(_)) => failed_session_page(
                runs,
                current_run,
                generation,
                "Session loading failed. Close and reopen /resume to retry.",
            ),
            Err(_) => failed_session_page(
                runs,
                current_run,
                generation,
                "Session loading timed out. Close and reopen /resume to retry.",
            ),
        }
    })
}

pub(super) fn apply_session_page_result(
    app: &mut App,
    result: Result<SessionPageResult, tokio::task::JoinError>,
) -> bool {
    if app
        .picker
        .as_ref()
        .is_none_or(|picker| picker.title != "Sessions · resume here")
    {
        return false;
    }
    let mut page = match result {
        Ok(page) if page.generation == app.session_picker_generation => page,
        Ok(_) => return false,
        Err(_) => failed_session_page(
            PathBuf::new(),
            String::new(),
            app.session_picker_generation,
            "Session loading failed. Close and reopen /resume to retry.",
        ),
    };
    if let Some(warning) = page.warning.take() {
        app.note(block::NoticeLevel::Info, warning);
    }
    if page.replace {
        if page.items.is_empty() {
            let mut empty = PickItem::flat(
                "No sessions recorded yet",
                "start a prompt to create one",
                false,
                PickAction::Info,
            );
            empty.enabled = false;
            page.items.push(empty);
        }
        if let Some(picker) = app.picker.as_mut() {
            picker.sel = initial_picker_selection(&page.items);
            picker.items = page.items;
        }
        app.session_picker_backing = Some(SessionPickerBacking {
            runs: page.runs,
            current_run: page.current_run,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
            generation: page.generation,
        });
    } else if let Some(backing) = app.session_picker_backing.as_mut()
        && backing.generation == page.generation
    {
        backing.next_cursor = page.next_cursor;
        backing.has_more = page.has_more;
        if let Some(picker) = app.picker.as_mut() {
            picker.items.extend(page.items);
        }
    }
    maybe_prefetch_session_page(app);
    true
}

/// Start the next storage page once the selection reaches the configured prefetch distance. Only
/// an opaque generation-bound byte cursor is retained; no full session list exists in the TUI.
pub(super) fn maybe_prefetch_session_page(app: &mut App) {
    if app.session_picker_job.is_some() {
        return;
    }
    let Some(picker) = app
        .picker
        .as_ref()
        .filter(|picker| picker.title == "Sessions · resume here")
    else {
        return;
    };
    let Some(backing) = app.session_picker_backing.as_ref() else {
        return;
    };
    if !backing.has_more
        || backing.next_cursor.is_none()
        || picker
            .sel
            .saturating_add(session_picker_prefetch_distance())
            < picker.items.len()
    {
        return;
    }
    let page_size = session_picker_page_size();
    let runs = backing.runs.clone();
    let current_run = backing.current_run.clone();
    let generation = backing.generation;
    let cursor = backing.next_cursor;
    app.session_picker_job = Some(spawn_session_page_load(
        runs,
        current_run,
        generation,
        cursor,
        page_size,
        false,
    ));
}

pub(super) fn start_session_preview(app: &mut App, runs: PathBuf, run: String) {
    if let Some(previous) = app.session_preview_job.take() {
        previous.abort();
    }
    app.session_preview_generation = app.session_preview_generation.wrapping_add(1);
    let generation = app.session_preview_generation;
    app.session_preview_job = Some(tokio::task::spawn_blocking(move || {
        let identity = iteron_protocol::RunId(run.clone());
        let result = (|| {
            let metadata = iteron_record::session::meta(&runs, &identity)
                .map_err(|error| format!("cannot read session metadata: {error}"))?;
            let events = iteron_record::load_forked(&runs, &identity)
                .map_err(|error| format!("cannot preview session: {error}"))?;
            let presentation = session_management::load(&runs, &run).unwrap_or_default();
            let state = if presentation.archived {
                "archived"
            } else if presentation.pinned {
                "pinned"
            } else {
                "active"
            };
            let (blocks, total_blocks) = adopted_transcript_blocks(&events);
            Ok(SessionPreview {
                run,
                title: presentation.title.unwrap_or(metadata.title),
                turns: metadata.turns,
                state,
                total_blocks,
                blocks: blocks
                    .iter()
                    .rev()
                    .take(6)
                    .rev()
                    .map(|block| block::Block::new(0, block.clone()).to_text())
                    .collect(),
            })
        })();
        SessionPreviewResult { generation, result }
    }));
}

pub(super) fn handle_sessions_command(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderDirectory,
    argument: &str,
) {
    let argument = argument.trim();
    if argument.is_empty() {
        open_session_picker(app, session);
        return;
    }
    if app.running || app.pending.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "finish the current turn before managing sessions",
        );
        return;
    }
    let runs = session
        .rollout_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let current = session
        .rollout_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_owned();
    let mut words = argument.splitn(3, char::is_whitespace);
    let action = words.next().unwrap_or_default();
    let run = words.next().unwrap_or_default();
    let tail = words.next().unwrap_or_default().trim();
    match action {
        "new" => start_fresh_session(app, session, directory),
        "switch" | "resume" if !run.is_empty() => {
            start_adopt_session(app, session, directory, run.to_owned())
        }
        "preview" if !run.is_empty() => start_session_preview(app, runs, run.to_owned()),
        "rename" if !run.is_empty() && !tail.is_empty() => match session_management::update(
            &runs,
            run,
            session_management::Mutation::Rename(tail.to_owned()),
        ) {
            Ok(()) => {
                if run == current {
                    app.session_name = tail.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                app.note(block::NoticeLevel::Ok, format!("renamed session {run}"));
            }
            Err(error) => app.note(block::NoticeLevel::Err, format!("rename refused: {error}")),
        },
        "pin" | "unpin" if !run.is_empty() => {
            let value = action == "pin";
            match session_management::update(
                &runs,
                run,
                session_management::Mutation::Pin(value),
            ) {
                Ok(()) => app.note(
                    block::NoticeLevel::Ok,
                    format!("session {run} {}", if value { "pinned" } else { "unpinned" }),
                ),
                Err(error) => app.note(block::NoticeLevel::Err, format!("pin refused: {error}")),
            }
        }
        "archive" | "unarchive" if !run.is_empty() => {
            let value = action == "archive";
            match session_management::update(
                &runs,
                run,
                session_management::Mutation::Archive(value),
            ) {
                Ok(()) => app.note(
                    block::NoticeLevel::Ok,
                    format!(
                        "session {run} {}",
                        if value { "archived" } else { "restored" }
                    ),
                ),
                Err(error) => app.note(
                    block::NoticeLevel::Err,
                    format!("archive refused: {error}"),
                ),
            }
        }
        "delete" if !run.is_empty() => {
            if run == current {
                app.note(
                    block::NoticeLevel::Err,
                    "cannot delete the live session; switch away first",
                );
                return;
            }
            let operation_id = format!(
                "session.delete.{}.{}",
                std::process::id(),
                crate::erasure_now_unix_ms()
            );
            let request = iteron_record::erasure::authorize_local_erasure(&runs).and_then(|authority| {
                Ok(iteron_protocol::ErasureRequest {
                    operation_id: iteron_protocol::ErasureOperationId::new(operation_id.clone())?,
                    authority_id: authority.id().clone(),
                    requested_at_unix_ms: crate::erasure_now_unix_ms(),
                    target: iteron_protocol::ErasureTarget::ExactSession {
                        scope_id: iteron_protocol::ErasureScopeId::new(
                            iteron_protocol::TenantId::default().0,
                        )?,
                        run_id: iteron_protocol::ErasureTargetId::new(run.to_owned())?,
                    },
                })
            });
            match request.and_then(|request| iteron_record::erasure::execute_erasure(&runs, request)) {
                Ok(receipt) if receipt.state() == iteron_protocol::ErasureState::Verified => {
                    let hook_journal = runs.join(format!("{run}.hooks.jsonl"));
                    if std::fs::symlink_metadata(&hook_journal).is_ok() {
                        let _ = std::fs::remove_file(hook_journal);
                    }
                    let _ = session_management::remove(&runs, run);
                    session.record_lifecycle(
                        "session.deleted",
                        iteron_protocol::LifecyclePayload {
                            outcome_code: Some("deleted".into()),
                            reason_code: Some(operation_id),
                            ..iteron_protocol::LifecyclePayload::default()
                        },
                    );
                    app.note(block::NoticeLevel::Ok, format!("deleted session {run}"));
                }
                Ok(receipt) => app.note(
                    block::NoticeLevel::Err,
                    format!(
                        "session delete refused: operation {} ended {:?} ({:?})",
                        receipt.request().operation_id,
                        receipt.state(),
                        receipt.failure()
                    ),
                ),
                Err(error) => app.note(
                    block::NoticeLevel::Err,
                    format!("session delete refused: {error}"),
                ),
            }
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "usage: /sessions [new|switch RUN|preview RUN|rename RUN TITLE|pin RUN|unpin RUN|archive RUN|unarchive RUN|delete RUN]",
        ),
    }
}

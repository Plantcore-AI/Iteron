use super::*;
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

pub(in crate::tui) fn session_picker_items(
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
                    "run {run_id} · {} · {cost} · {route}{flags} · {} · recorded {}",
                    block::plural(session.turns as usize, "turn"),
                    ui_safe_text(&session.cwd.to_string_lossy()),
                    crate::tui::session_inspection::recorded_outcome_label(
                        session.last_outcome.as_ref()
                    ),
                ),
                run_id == current_run,
                PickAction::AdoptRun(run_id),
            )
        })
        .collect()
}

pub(in crate::tui) fn load_session_page(
    runs: PathBuf,
    current_run: String,
    generation: u64,
    cursor: Option<String>,
    page_size: usize,
    first: bool,
) -> SessionPageResult {
    let tenant = iteron_protocol::TenantId::default();
    let mut page = iteron_record::page(
        &runs,
        &tenant,
        None,
        cursor
            .and_then(|cursor| {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, cursor).ok()
            })
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()),
        Some(page_size),
    );
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
        next_cursor: page.next_cursor.map(|cursor| {
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                serde_json::to_vec(&cursor).unwrap(),
            )
        }),
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

pub(in crate::tui) fn spawn_session_page_load(
    runs: PathBuf,
    current_run: String,
    generation: u64,
    cursor: Option<String>,
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

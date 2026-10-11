//! Attached session browsing owns only presentation generation, cursor and observation cadence.
//! The existing picker owns its rows/input; all history, activity and artifacts come from the host.
use super::{App, picker::PickAction, session_activity::Observation};
use iteron_protocol::{RunId, product_contract::ThreadSnapshotV1};
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct Sessions {
    generation: u64,
    run: Option<RunId>,
    next_cursor: Option<String>,
    has_more: bool,
    page_pending: bool,
    activity_pending: bool,
    activity_due: Option<Instant>,
    base_hint: Option<String>,
    activity: Option<Observation>,
    repaired: bool,
    restarted: bool,
}
pub(super) enum Page {
    Applied,
    Repair,
    Restart,
}
impl Sessions {
    pub(super) fn begin(&mut self, app: &mut App, run: RunId) -> u64 {
        self.clear(app);
        app.pickers.open_remote_sessions();
        self.run = Some(run);
        self.page_pending = true;
        self.generation
    }
    pub(super) fn clear(&mut self, app: &mut App) {
        if app.pickers.has_remote_sessions() {
            app.pickers.close();
        }
        self.generation = self.generation.wrapping_add(1);
        self.run = None;
        self.next_cursor = None;
        self.has_more = false;
        self.page_pending = false;
        self.activity_pending = false;
        self.activity_due = None;
        self.base_hint = None;
        self.activity = None;
        self.repaired = false;
        self.restarted = false;
    }
    pub(super) fn matches(&self, app: &App, run: &RunId, generation: u64) -> bool {
        self.run.as_ref() == Some(run)
            && self.generation == generation
            && app.pickers.has_remote_sessions()
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    pub(super) fn page(
        &mut self,
        app: &mut App,
        value: &Value,
        append: bool,
    ) -> Result<Page, &'static str> {
        self.page_pending = false;
        if value["type"] != "thread_list_v1" {
            return Err("service session page unavailable");
        }
        if value["index_ready"] != true {
            return if value["rebuild_recommended"] == true {
                if self.repaired {
                    return Err("service session index remains unavailable after one host repair");
                }
                self.repaired = true;
                self.page_pending = true;
                Ok(Page::Repair)
            } else {
                Err("service session index unavailable; reopen to retry")
            };
        }
        if value["cursor_stale"] == true {
            if self.restarted {
                return Err("service session index changed again; reopen to retry");
            }
            self.restarted = true;
            self.page_pending = true;
            return Ok(Page::Restart);
        }
        let Some(run) = self.run.as_ref() else {
            return Err("service session scope changed");
        };
        let rows = super::session_picker::host_session_picker_items(value, &run.0)
            .map_err(|_| "service session page exceeds its presentation contract")?;
        let has_more = value["has_more"]
            .as_bool()
            .ok_or("service session pagination unavailable")?;
        let cursor = match &value["next_cursor"] {
            Value::Null if !has_more => None,
            Value::String(cursor)
                if !cursor.is_empty()
                    && cursor.len() <= 1024
                    && !cursor.chars().any(char::is_control) =>
            {
                Some(cursor.clone())
            }
            _ => return Err("service session pagination exceeds its bound"),
        };
        if !app.pickers.apply_remote_session_rows(rows, append) {
            return Err("service session picker closed");
        }
        self.next_cursor = cursor;
        self.has_more = has_more;
        if !append || self.base_hint.is_none() {
            self.base_hint = app.pickers.view().and_then(|picker| {
                picker.items.iter().find_map(|row| {
                    matches!(&row.action, PickAction::AdoptRun(id) if id == &run.0)
                        .then(|| row.hint.clone())
                })
            });
        }
        app.pickers.apply_remote_session_activity(
            self.activity.as_ref(),
            &run.0,
            self.base_hint.as_deref(),
        );
        self.activity_due = Some(Instant::now());
        Ok(Page::Applied)
    }
    pub(super) fn next_page(&mut self, app: &App) -> Option<String> {
        let picker = app
            .pickers
            .view()
            .filter(|_| app.pickers.has_remote_sessions())?;
        if self.page_pending
            || !self.has_more
            || picker
                .sel
                .saturating_add(super::session_picker::session_picker_prefetch_distance())
                < picker.items.len()
        {
            return None;
        }
        let cursor = self.next_cursor.clone()?;
        self.page_pending = true;
        Some(cursor)
    }
    pub(super) fn activity_due(&self, app: &App) -> bool {
        app.pickers.has_remote_sessions()
            && !self.page_pending
            && !self.activity_pending
            && self.activity_due.is_some_and(|due| Instant::now() >= due)
    }
    pub(super) fn activity_started(&mut self) {
        self.activity_pending = true;
    }
    pub(super) fn activity(&mut self, app: &mut App, value: &Value, snapshot: &ThreadSnapshotV1) {
        self.activity = Observation::capture(value, snapshot).ok();
        app.pickers.apply_remote_session_activity(
            self.activity.as_ref(),
            &snapshot.run_id.0,
            self.base_hint.as_deref(),
        );
    }
    pub(super) fn changes(&mut self, app: &mut App, value: &Value, snapshot: &ThreadSnapshotV1) {
        if let Some(activity) = &mut self.activity {
            activity.changes(
                super::session_changes::Summary::capture(
                    value,
                    &snapshot.thread_id,
                    &snapshot.run_id,
                )
                .ok(),
            );
        }
        self.activity_finished();
        app.pickers.apply_remote_session_activity(
            self.activity.as_ref(),
            &snapshot.run_id.0,
            self.base_hint.as_deref(),
        );
    }
    pub(super) fn activity_finished(&mut self) {
        self.activity_pending = false;
        self.activity_due = Some(Instant::now() + Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests;

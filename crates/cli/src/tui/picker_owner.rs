//! Private selection modal and one session-page worker owner.
//! Physical input becomes semantic selection/theme effects. Views borrow immutable state;
//! driver polling never accesses a mutable picker, backing cursor or worker/generation bag.

use super::command_surfaces::initial_picker_selection;
use super::picker::{PickAction, PickItem, Picker, PickerEvent};
use super::session_picker::{
    SessionPageResult, SessionPickerBacking, failed_session_page, session_picker_page_size,
    session_picker_prefetch_distance, spawn_host_session_page_load,
};
use crate::semantic_text::is_unsafe_display_char;
use crate::theme;
use crossterm::event::{KeyCode, KeyModifiers};
use std::path::PathBuf;
use tokio::task::JoinHandle;

const MAX_SESSION_ROWS: usize = 512;

pub(super) struct PickerUpdate {
    pub(super) event: PickerEvent,
    pub(super) theme: Option<theme::Theme>,
}
impl PickerUpdate {
    fn event(event: PickerEvent) -> Self {
        Self { event, theme: None }
    }
}
#[derive(Default)]
pub(super) struct PickerPageUpdate {
    pub(super) changed: bool,
    pub(super) warnings: Vec<String>,
}
#[derive(Default)]
pub(super) struct PickerOwner {
    picker: Option<Picker>,
    sessions: bool,
    job: Option<JoinHandle<SessionPageResult>>,
    backing: Option<SessionPickerBacking>,
    generation: u64,
    omitted_rows: u64,
    history: Option<super::history_client::HistoryClient>,
}
impl PickerOwner {
    pub(super) fn view(&self) -> Option<&Picker> {
        self.picker.as_ref()
    }
    pub(super) fn is_open(&self) -> bool {
        self.picker.is_some()
    }
    pub(super) fn has_worker(&self) -> bool {
        self.job.is_some()
    }
    pub(super) fn omitted_rows(&self) -> u64 {
        self.omitted_rows
    }
    fn cancel_page(&mut self) {
        if let Some(job) = self.job.take() {
            job.abort();
        }
        self.backing = None;
        self.history = None;
        self.sessions = false;
        self.generation = self.generation.wrapping_add(1);
    }
    pub(super) fn open(&mut self, picker: Picker) {
        self.cancel_page();
        self.omitted_rows = 0;
        self.picker = Some(picker);
    }
    pub(super) fn close(&mut self) -> Option<theme::Theme> {
        self.cancel_page();
        self.picker.take().and_then(|picker| picker.saved_theme)
    }
    pub(super) fn open_sessions(
        &mut self,
        history: super::history_client::HistoryClient,
        runs: PathBuf,
        current_run: String,
    ) {
        let mut loading = PickItem::flat(
            "Loading sessions…",
            "reading your saved conversations",
            false,
            PickAction::Info,
        );
        loading.enabled = false;
        loading.disabled_reason = Some("Esc to close while sessions load".into());
        self.open(Picker {
            title: "Sessions · resume here".into(),
            items: vec![loading],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        self.sessions = true;
        self.history = Some(history.clone());
        self.job = Some(spawn_host_session_page_load(
            history,
            runs,
            current_run,
            self.generation,
            None,
            session_picker_page_size(),
            true,
        ));
    }
    pub(super) async fn poll_page(&mut self) -> Option<PickerPageUpdate> {
        if !self.job.as_ref().is_some_and(|job| job.is_finished()) {
            return None;
        }
        let job = self.job.take()?;
        let result = job.await;
        if self
            .history
            .as_ref()
            .is_some_and(|history| !history.is_current())
        {
            self.cancel_page();
            self.picker = None;
            return Some(PickerPageUpdate {
                changed: true,
                warnings: vec!["selected session changed; reopen the history picker".into()],
            });
        }
        Some(self.apply_page(result))
    }
    pub(super) fn apply_page(
        &mut self,
        result: Result<SessionPageResult, tokio::task::JoinError>,
    ) -> PickerPageUpdate {
        let mut warnings = Vec::new();
        if !self.sessions
            || self
                .picker
                .as_ref()
                .is_none_or(|picker| picker.title != "Sessions · resume here")
        {
            return PickerPageUpdate::default();
        }
        let mut page = match result {
            Ok(page) if page.generation == self.generation => page,
            Ok(_) => return PickerPageUpdate::default(),
            Err(_) => failed_session_page(
                PathBuf::new(),
                String::new(),
                self.generation,
                "Session loading failed. Close and reopen /resume to retry.",
            ),
        };
        if let Some(warning) = page.warning.take() {
            warnings.push(warning);
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
            if let Some(picker) = self.picker.as_mut() {
                picker.sel = initial_picker_selection(&page.items);
                picker.items = page.items;
            }
            self.backing = Some(SessionPickerBacking {
                runs: page.runs,
                current_run: page.current_run,
                next_cursor: page.next_cursor,
                has_more: page.has_more,
                generation: page.generation,
            });
        } else if let Some(backing) = self.backing.as_mut()
            && backing.generation == page.generation
        {
            backing.next_cursor = page.next_cursor;
            backing.has_more = page.has_more;
            if let Some(picker) = self.picker.as_mut() {
                picker.items.extend(page.items);
                if picker.items.len() > MAX_SESSION_ROWS {
                    let drop = picker.items.len() - MAX_SESSION_ROWS;
                    picker.items.drain(..drop);
                    picker.sel = picker.sel.saturating_sub(drop);
                    self.omitted_rows = self.omitted_rows.saturating_add(drop as u64);
                    warnings.push(format!("{drop} earlier session rows left the bounded picker window; their records remain available through /sessions read RUN"));
                }
            }
        }
        self.prefetch();
        PickerPageUpdate {
            changed: true,
            warnings,
        }
    }

    pub(super) fn prefetch(&mut self) {
        if self.job.is_some() {
            return;
        }
        let Some(picker) = self
            .picker
            .as_ref()
            .filter(|picker| picker.title == "Sessions · resume here")
        else {
            return;
        };
        let Some(backing) = self.backing.as_ref() else {
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
        let cursor = backing.next_cursor.clone();
        let Some(history) = self.history.clone() else {
            return;
        };
        self.job = Some(spawn_host_session_page_load(
            history,
            runs,
            current_run,
            generation,
            cursor,
            page_size,
            false,
        ));
    }

    pub(super) fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<PickerUpdate> {
        self.picker.as_ref()?;
        // Esc first clears an active filter. A second Esc closes and restores a live-preview theme.
        if code == KeyCode::Esc {
            if self.picker.as_ref().is_some_and(Picker::has_query) {
                let pk = self.picker.as_mut()?;
                pk.query.clear();
                let visible = pk.visible_indices();
                pk.normalize_selection(&visible);
            } else {
                let theme = self.close();
                return Some(PickerUpdate {
                    event: PickerEvent::Cancel,
                    theme,
                });
            }
        } else if code == KeyCode::Backspace {
            let pk = self.picker.as_mut()?;
            pk.query.pop();
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        } else if let KeyCode::Char(ch) = code
            && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && !is_unsafe_display_char(ch)
        {
            let pk = self.picker.as_mut()?;
            let mut encoded = [0; 4];
            pk.append_query_text(ch.encode_utf8(&mut encoded));
            let visible = pk.visible_indices();
            pk.normalize_selection(&visible);
        }

        let visible = self.picker.as_ref()?.visible_indices();
        if visible.is_empty() {
            return Some(PickerUpdate::event(PickerEvent::Consumed));
        }

        // A catalog refresh or ancestor collapse may invalidate the old selection. Normalize before
        // handling Enter so a hidden child can never be accepted accidentally.
        self.picker.as_mut()?.normalize_selection(&visible);

        let pos = self.picker.as_ref()?.visible_selection(&visible);
        match code {
            KeyCode::Up => {
                let next = (pos + visible.len() - 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::Down => {
                let next = (pos + 1) % visible.len();
                self.picker.as_mut()?.sel = visible[next];
            }
            KeyCode::PageUp => {
                self.picker.as_mut()?.sel = visible[pos.saturating_sub(8)];
            }
            KeyCode::PageDown => {
                self.picker.as_mut()?.sel = visible[(pos + 8).min(visible.len() - 1)];
            }
            KeyCode::Home => self.picker.as_mut()?.sel = visible[0],
            KeyCode::End => self.picker.as_mut()?.sel = *visible.last()?,
            KeyCode::Right => {
                let pk = self.picker.as_mut()?;
                if let Some(item) = pk.items.get_mut(pk.sel)
                    && item.expandable
                {
                    item.expanded = true;
                }
            }
            KeyCode::Left => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get(pk.sel) else {
                    return Some(PickerUpdate::event(PickerEvent::Consumed));
                };
                let (expandable, expanded, parent) = (item.expandable, item.expanded, item.parent);
                if expandable && expanded {
                    if let Some(item) = pk.items.get_mut(pk.sel) {
                        item.expanded = false;
                    }
                } else if let Some(parent) = parent
                    && visible.contains(&parent)
                {
                    pk.sel = parent;
                }
            }
            KeyCode::Enter | KeyCode::Tab => {
                let pk = self.picker.as_mut()?;
                let Some(item) = pk.items.get_mut(pk.sel) else {
                    return Some(PickerUpdate::event(PickerEvent::Consumed));
                };
                if item.expandable {
                    item.expanded = true;
                    return Some(PickerUpdate::event(PickerEvent::Consumed));
                }
                if !item.enabled {
                    return Some(PickerUpdate::event(PickerEvent::Consumed));
                }
                let action = item.action.clone();
                self.picker = None;
                self.cancel_page(); // the selected value leaves the owner before host apply
                return Some(PickerUpdate::event(PickerEvent::Accept(action)));
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char(_) => {}
            _ => return Some(PickerUpdate::event(PickerEvent::Consumed)),
        }
        // theme live-preview: apply the newly-selected theme (extract, then assign — no borrow clash)
        let preview = self.picker.as_ref().and_then(|pk| {
            if pk.saved_theme.is_some() {
                match pk.items.get(pk.sel).map(|i| &i.action) {
                    Some(PickAction::SetTheme(t)) => Some(t.clone()),
                    _ => None,
                }
            } else {
                None
            }
        });
        Some(PickerUpdate {
            event: PickerEvent::Consumed,
            theme: preview,
        })
    }

    /// Bracketed paste belongs to an open picker just like keypresses do. Returning `false` means
    /// no picker was open; returning `true` means the event was fully consumed and must never reach
    /// the composer or image-attachment parser.
    pub(super) fn paste(&mut self, pasted: &str) -> bool {
        let Some(picker) = self.picker.as_mut() else {
            return false;
        };
        picker.append_query_text(pasted);
        let visible = picker.visible_indices();
        picker.normalize_selection(&visible);
        true
    }

    #[cfg(test)]
    pub(super) fn clear_query(&mut self) {
        if let Some(picker) = self.picker.as_mut() {
            picker.query.clear();
        }
    }
    #[cfg(test)]
    pub(super) fn install_session_fixture(
        &mut self,
        picker: Picker,
        generation: u64,
        backing: Option<SessionPickerBacking>,
    ) {
        self.open(picker);
        self.sessions = true;
        self.generation = generation;
        self.backing = backing;
    }
    #[cfg(test)]
    pub(super) fn has_more(&self) -> bool {
        self.backing
            .as_ref()
            .is_some_and(|backing| backing.has_more)
    }
}
impl Drop for PickerOwner {
    fn drop(&mut self) {
        self.cancel_page();
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SESSION_ROWS, PickAction, PickItem, Picker, PickerOwner, SessionPageResult};
    use std::path::PathBuf;

    #[test]
    fn page_window_is_bounded_and_closed_catalog_rejects_stale_session_observations() {
        let mut owner = PickerOwner::default();
        owner.install_session_fixture(
            Picker {
                title: "Sessions · resume here".into(),
                items: Vec::new(),
                sel: 0,
                query: String::new(),
                saved_theme: None,
            },
            7,
            None,
        );
        for page in 0..20 {
            let update = owner.apply_page(Ok(SessionPageResult {
                generation: 7,
                runs: PathBuf::new(),
                current_run: String::new(),
                next_cursor: None,
                has_more: false,
                replace: page == 0,
                warning: None,
                items: (0..64)
                    .map(|index| {
                        PickItem::flat(
                            format!("observed-{page}-{index}"),
                            "recorded",
                            false,
                            PickAction::Info,
                        )
                    })
                    .collect(),
            }));
            assert!(update.changed);
            assert!(owner.view().unwrap().items.len() <= MAX_SESSION_ROWS);
        }
        assert_eq!(owner.omitted_rows(), 20 * 64 - MAX_SESSION_ROWS as u64);
        assert_eq!(
            owner.view().unwrap().items.last().unwrap().label,
            "observed-19-63"
        );
        owner.open(Picker {
            title: "Model".into(),
            items: vec![PickItem::flat(
                "current model",
                "native route",
                true,
                PickAction::Info,
            )],
            sel: 0,
            query: String::new(),
            saved_theme: None,
        });
        assert!(
            !owner
                .apply_page(Ok(SessionPageResult {
                    generation: 7,
                    runs: PathBuf::new(),
                    current_run: String::new(),
                    next_cursor: None,
                    has_more: false,
                    replace: true,
                    warning: None,
                    items: Vec::new(),
                }))
                .changed
        );
        assert_eq!(owner.view().unwrap().title, "Model");
        assert_eq!(owner.omitted_rows(), 0);
    }
}

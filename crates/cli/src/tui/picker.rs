//! Bounded picker state, navigation and immutable selection actions.

use super::*;

#[derive(Clone)]
pub(super) enum PickAction {
    SetModel(ModelSelection),
    SetEffort(Effort),
    SetMode(PermissionMode),
    SetCap(Capability, Verdict),
    SetTheme(theme::Theme),
    /// Take over that recorded run in THIS process: the live session adopts its journal, identity
    /// and transcript. The documented restart command remains the fallback when a run cannot be
    /// adopted here — another process holding its writer lock is the ordinary case.
    AdoptRun(String),
    /// Open one bounded, read-only L1 detail panel from the tunables L0 registry picker.
    InspectTunable(tunables_view::Detail),
    /// Informational row (agents/skills browse) — accepting does nothing.
    Info,
}

/// One row in a picker. Flat pickers leave `parent` empty and `depth` at zero; tree pickers keep
/// stable item indices and point children at their parent. A disabled leaf remains navigable (so its
/// reason is discoverable), but cannot be accepted.
pub(super) struct PickItem {
    pub(super) label: String,
    pub(super) hint: String,
    pub(super) is_current: bool,
    pub(super) action: PickAction,
    pub(super) parent: Option<usize>,
    pub(super) depth: usize,
    pub(super) expandable: bool,
    pub(super) expanded: bool,
    pub(super) enabled: bool,
    pub(super) disabled_reason: Option<String>,
}

impl PickItem {
    /// Preserve the original behaviour for all non-hierarchical pickers.
    pub(super) fn flat(
        label: impl Into<String>,
        hint: impl Into<String>,
        is_current: bool,
        action: PickAction,
    ) -> Self {
        Self {
            label: label.into(),
            hint: hint.into(),
            is_current,
            action,
            parent: None,
            depth: 0,
            expandable: false,
            expanded: false,
            enabled: true,
            disabled_reason: None,
        }
    }
}

/// A modal selection overlay — the interactive picker for model/effort/mode/permissions/theme/…
/// (R7.a). Owns the keyboard while open (C6). For a theme picker it live-previews on nav and restores
/// `saved_theme` on Esc (C1).
pub(super) struct Picker {
    pub(super) title: String,
    pub(super) items: Vec<PickItem>,
    pub(super) sel: usize,
    /// Incremental, Unicode-safe filter text. Bounded so an open picker cannot retain an
    /// arbitrarily large paste/key stream.
    pub(super) query: String,
    /// Snapshot of the theme before a theme-picker opened, so Esc restores it (C1). `Some` only for
    /// the theme picker (also the "am I a live-preview picker?" flag).
    pub(super) saved_theme: Option<theme::Theme>,
}

const MAX_PICKER_QUERY_CHARS: usize = 96;
const MAX_PICKER_QUERY_BYTES: usize = MAX_PICKER_QUERY_CHARS * 4;
const MAX_PICKER_PASTE_SCAN_BYTES: usize = 4 * 1024;

impl Picker {
    /// Append terminal text to the modal's filter without letting controls, invisible formatting,
    /// or an arbitrarily large bracketed paste enter retained UI state. Whitespace becomes one
    /// ordinary separator so a multiline paste remains a predictable multi-term query.
    pub(super) fn append_query_text(&mut self, text: &str) {
        let mut query_chars = self.query.chars().count();
        let mut scanned_bytes = 0usize;
        for source in text.chars() {
            scanned_bytes = scanned_bytes.saturating_add(source.len_utf8());
            if scanned_bytes
                > iteron_tunables::param_integer(
                    "cli.tui.max_picker_paste_scan_bytes",
                    MAX_PICKER_PASTE_SCAN_BYTES,
                )
                || query_chars
                    >= iteron_tunables::param_integer(
                        "cli.tui.max_picker_query_chars",
                        MAX_PICKER_QUERY_CHARS,
                    )
            {
                break;
            }
            let character = if source.is_whitespace() {
                if self.query.is_empty() || self.query.ends_with(' ') {
                    continue;
                }
                ' '
            } else if is_unsafe_display_char(source) {
                continue;
            } else {
                source
            };
            if self.query.len().saturating_add(character.len_utf8())
                > iteron_tunables::param_integer(
                    "cli.tui.max_picker_query_bytes",
                    MAX_PICKER_QUERY_BYTES,
                )
            {
                break;
            }
            self.query.push(character);
            query_chars += 1;
        }
    }

    /// Return stable item indices for rows whose complete ancestor chain is expanded. Invalid or
    /// cyclic parent links fail closed by hiding the affected row instead of hanging the UI.
    pub(super) fn visible_indices(&self) -> Vec<usize> {
        if !self.has_query() {
            return (0..self.items.len())
                .filter(|&index| self.item_is_visible(index))
                .collect();
        }

        // Search is a projection over the stable tree. A matching leaf brings its complete ancestor
        // path into view; a matching branch brings its descendants too, so searching a provider or
        // family does not leave a dead header with nothing selectable beneath it.
        let direct: Vec<bool> = (0..self.items.len())
            .map(|index| self.item_matches_query(index))
            .collect();
        let mut included = vec![false; self.items.len()];
        for (index, matched) in direct.iter().copied().enumerate() {
            if !matched {
                continue;
            }
            included[index] = true;
            self.include_ancestors(index, &mut included);
            if self.items.get(index).is_some_and(|item| item.expandable) {
                for (descendant, is_included) in included.iter_mut().enumerate() {
                    if self.item_descends_from(descendant, index) {
                        *is_included = true;
                    }
                }
            }
        }
        (0..self.items.len())
            .filter(|&index| included[index])
            .collect()
    }

    pub(super) fn has_query(&self) -> bool {
        !self.query.is_empty()
    }

    pub(super) fn item_matches_query(&self, index: usize) -> bool {
        let Some(item) = self.items.get(index) else {
            return false;
        };
        let haystack = format!(
            "{} {} {}",
            item.label,
            item.hint,
            item.disabled_reason.as_deref().unwrap_or_default()
        )
        .to_lowercase();
        self.query
            .to_lowercase()
            .split_whitespace()
            .all(|term| haystack.contains(term))
    }

    pub(super) fn include_ancestors(&self, index: usize, included: &mut [bool]) {
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 || parent_index >= included.len() {
                return;
            }
            remaining -= 1;
            included[parent_index] = true;
            parent = self.items.get(parent_index).and_then(|item| item.parent);
        }
    }

    pub(super) fn item_descends_from(&self, index: usize, ancestor: usize) -> bool {
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            if parent_index == ancestor {
                return true;
            }
            parent = self.items.get(parent_index).and_then(|item| item.parent);
        }
        false
    }

    pub(super) fn normalize_selection(&mut self, visible: &[usize]) {
        if visible.is_empty() {
            return;
        }
        if visible.contains(&self.sel)
            && (!self.has_query()
                || self.item_matches_query(self.sel)
                || self
                    .items
                    .get(self.sel)
                    .is_some_and(|item| item.enabled && !item.expandable))
        {
            return;
        }
        if self.has_query()
            && let Some(index) = visible.iter().copied().find(|&index| {
                self.item_matches_query(index)
                    && self
                        .items
                        .get(index)
                        .is_some_and(|item| item.enabled && !item.expandable)
            })
        {
            self.sel = index;
            return;
        }
        self.sel = visible
            .iter()
            .copied()
            .find(|&index| {
                self.items
                    .get(index)
                    .is_some_and(|item| item.enabled && !item.expandable)
            })
            .unwrap_or(visible[0]);
    }

    pub(super) fn item_is_visible(&self, index: usize) -> bool {
        let Some(item) = self.items.get(index) else {
            return false;
        };
        let mut parent = item.parent;
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return false;
            }
            remaining -= 1;
            let Some(ancestor) = self.items.get(parent_index) else {
                return false;
            };
            if !ancestor.expandable || !ancestor.expanded {
                return false;
            }
            parent = ancestor.parent;
        }
        true
    }

    pub(super) fn visible_selection(&self, visible: &[usize]) -> usize {
        visible
            .iter()
            .position(|&index| index == self.sel)
            .unwrap_or(iteron_tunables::param_integer(
                "cli.tui.selection_offscreen_row",
                SELECTION_OFFSCREEN_ROW,
            ))
    }

    pub(super) fn ancestor_breadcrumb(&self, index: usize) -> String {
        let mut labels = Vec::new();
        let mut parent = self.items.get(index).and_then(|item| item.parent);
        let mut remaining = self.items.len();
        while let Some(parent_index) = parent {
            if remaining == 0 {
                return String::new();
            }
            remaining -= 1;
            let Some(item) = self.items.get(parent_index) else {
                return String::new();
            };
            labels.push(item.label.clone());
            parent = item.parent;
        }
        labels.reverse();
        labels.join(" / ")
    }
}

/// The outcome of a keypress routed to an open picker.
pub(super) enum PickerEvent {
    /// The key was consumed (navigation/preview); redraw.
    Consumed,
    /// Enter/Tab: apply this action.
    Accept(PickAction),
    /// Esc: close (theme already restored).
    Cancel,
}

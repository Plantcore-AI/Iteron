use super::format::{
    DetailNote, DetailRow, bounded_hint, bounded_id, bounded_label, bounded_note, bounded_title,
};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tui) struct LoadError(pub(super) &'static str);

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LoadError {}

/// Every field is private to the tunables projection and enters through a streaming bounded
/// constructor or mutator. Callers cannot manufacture a raw, post-hoc-truncated Detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::tui) struct Detail {
    pub(super) family_id: String,
    pub(super) label: String,
    pub(super) hint: String,
    pub(super) rows: Vec<(String, String)>,
    pub(super) notes: Vec<String>,
}

impl Detail {
    pub(super) fn new(
        family_id: impl fmt::Display,
        label: impl fmt::Display,
        hint: impl fmt::Display,
        rows: Vec<DetailRow>,
        notes: Vec<DetailNote>,
    ) -> Self {
        Self {
            family_id: bounded_id(family_id),
            label: bounded_label(label),
            hint: bounded_hint(hint),
            rows: rows.into_iter().map(DetailRow::into_parts).collect(),
            notes: notes.into_iter().map(DetailNote::into_inner).collect(),
        }
    }

    pub(super) fn prepend_rows<const N: usize>(&mut self, rows: [DetailRow; N]) {
        self.rows
            .splice(0..0, rows.into_iter().map(DetailRow::into_parts));
    }

    pub(super) fn push_note(&mut self, note: impl fmt::Display) {
        self.notes.push(bounded_note(note).into_inner());
    }

    pub(super) fn set_hint(&mut self, hint: impl fmt::Display) {
        self.hint = bounded_hint(hint);
    }

    pub(in crate::tui) fn picker_label(&self) -> &str {
        &self.label
    }

    pub(in crate::tui) fn picker_hint(&self) -> &str {
        &self.hint
    }

    pub(in crate::tui) fn into_panel(self) -> (String, Vec<(String, String)>, Vec<String>) {
        (self.family_id, self.rows, self.notes)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::tui) struct Catalog {
    pub(super) title: String,
    pub(super) entries: Vec<Detail>,
}

impl Catalog {
    pub(super) fn new(title: impl fmt::Display, entries: Vec<Detail>) -> Self {
        Self {
            title: bounded_title(title),
            entries,
        }
    }

    pub(in crate::tui) fn into_parts(self) -> (String, Vec<Detail>) {
        (self.title, self.entries)
    }
}

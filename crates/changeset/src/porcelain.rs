//! Parse `git status --porcelain=v1 -z` into a classified, bounded change set.
//!
//! The NUL-separated form is the only safe one to parse. In the human-readable form git quotes and
//! escapes paths containing spaces, quotes or newlines, so a filename with a newline in it -- which
//! is legal on every platform this runs on -- splits into two records and desynchronises everything
//! after it. `-z` emits raw bytes with NUL terminators and never quotes, which is why the harness
//! already captures it that way.

use crate::MAX_ENTRIES;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("record {index} is shorter than the 'XY ' prefix porcelain guarantees")]
    ShortRecord { index: usize },
    #[error("rename/copy record for {path} is missing its origin path")]
    MissingOrigin { path: String },
    #[error("path was not valid utf-8")]
    InvalidUtf8,
}

/// What happened to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    /// Both sides changed and git could not resolve it. Surfaced distinctly because reviewing a
    /// conflicted file as if it were an ordinary modification hides that a merge is in progress.
    Unmerged,
    Untracked,
}

/// *Where* the change lives. This is the distinction `git diff` erases, and the reason an agent
/// can believe it changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Presence {
    /// In the index only. `git diff` does not show this; `git diff --cached` does.
    Staged,
    /// In the working tree only. This is the sole thing bare `git diff` reports.
    Unstaged,
    /// Different changes in both the index and the working tree.
    StagedAndUnstaged,
    /// Not tracked at all. No form of `git diff` shows this.
    Untracked,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub path: String,
    /// Present only for renames and copies.
    pub origin: Option<String>,
    pub status: Status,
    pub presence: Presence,
}

impl Entry {
    /// Whether a bare `git diff` would have shown this change at all.
    ///
    /// The inverse of this predicate is the blind spot: everything it excludes is a real change
    /// that an agent reviewing bare `git diff` output would not see.
    pub fn visible_to_bare_diff(&self) -> bool {
        matches!(
            self.presence,
            Presence::Unstaged | Presence::StagedAndUnstaged
        ) && self.status != Status::Untracked
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeSet {
    pub entries: Vec<Entry>,
    /// Entries dropped because the set exceeded `MAX_ENTRIES`. Reported so a caller says
    /// "1,000 of 4,812" rather than implying it saw everything.
    pub truncated: usize,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries a bare `git diff` would have missed entirely.
    pub fn invisible_to_bare_diff(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| !e.visible_to_bare_diff())
            .collect()
    }
}

fn status_from(code: u8) -> Option<Status> {
    match code {
        b'A' => Some(Status::Added),
        b'M' => Some(Status::Modified),
        b'D' => Some(Status::Deleted),
        b'R' => Some(Status::Renamed),
        b'C' => Some(Status::Copied),
        b'U' => Some(Status::Unmerged),
        b'T' => Some(Status::Modified), // typechange is a modification for review purposes
        _ => None,
    }
}

/// Parse the NUL-separated porcelain v1 stream.
///
/// Record shapes:
/// - `XY <path>\0`
/// - `XY <path>\0<origin>\0` when X or Y is `R` or `C`
/// - `?? <path>\0` untracked, `!! <path>\0` ignored (ignored is dropped: it is not a change)
pub fn parse_porcelain_v1_z(bytes: &[u8], limit: usize) -> Result<ChangeSet, ParseError> {
    let mut records = bytes.split(|b| *b == 0).peekable();
    let mut entries: Vec<Entry> = Vec::new();
    let mut index = 0usize;

    while let Some(record) = records.next() {
        // A trailing NUL yields a final empty slice; that is the terminator, not a record.
        if record.is_empty() {
            continue;
        }
        if record.len() < 3 {
            return Err(ParseError::ShortRecord { index });
        }
        let (x, y) = (record[0], record[1]);
        let path = utf8(&record[3..])?;
        index += 1;

        if x == b'!' && y == b'!' {
            continue; // ignored files are not changes
        }

        if x == b'?' && y == b'?' {
            entries.push(Entry {
                path,
                origin: None,
                status: Status::Untracked,
                presence: Presence::Untracked,
            });
            continue;
        }

        // A rename or copy on either side is followed by its origin path as a separate record.
        let origin = if matches!(x, b'R' | b'C') || matches!(y, b'R' | b'C') {
            let origin = records
                .next()
                .filter(|r| !r.is_empty())
                .ok_or_else(|| ParseError::MissingOrigin { path: path.clone() })?;
            Some(utf8(origin)?)
        } else {
            None
        };

        let staged = x != b' ' && x != b'?';
        let unstaged = y != b' ' && y != b'?';
        let presence = match (staged, unstaged) {
            (true, true) => Presence::StagedAndUnstaged,
            (true, false) => Presence::Staged,
            (false, true) => Presence::Unstaged,
            // Porcelain does not emit a record with nothing on either side.
            (false, false) => continue,
        };

        // Unmerged wins over either side's code: a conflicted file must not be reported as an
        // ordinary modification, or a reviewer will not learn a merge is in progress.
        let status =
            if x == b'U' || y == b'U' || (x == b'A' && y == b'A') || (x == b'D' && y == b'D') {
                Status::Unmerged
            } else {
                // The staged side names what happened when both are present: it is the change that is
                // already recorded, and the worktree code is usually just `M` on top of it.
                status_from(if staged { x } else { y }).unwrap_or(Status::Modified)
            };

        entries.push(Entry {
            path,
            origin,
            status,
            presence,
        });
    }

    // Sort before truncating so the bound keeps a deterministic prefix rather than whatever order
    // git happened to walk the index in.
    entries.sort();
    entries.dedup();
    let mut set = ChangeSet {
        truncated: 0,
        entries,
    };
    if set.entries.len() > limit {
        set.truncated = set.entries.len() - limit;
        set.entries.truncate(limit);
    }
    Ok(set)
}

/// Convenience wrapper at the default bound.
pub fn parse_default(bytes: &[u8]) -> Result<ChangeSet, ParseError> {
    parse_porcelain_v1_z(bytes, MAX_ENTRIES)
}

fn utf8(bytes: &[u8]) -> Result<String, ParseError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ParseError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(parts: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(p.as_bytes());
            out.push(0);
        }
        out
    }

    #[test]
    fn an_untracked_file_is_a_change_even_though_bare_diff_shows_nothing() {
        // The headline failure: agent creates a file, runs `git diff`, sees empty output,
        // reports it changed nothing.
        let set = parse_default(&rec(&["?? new.rs"])).unwrap();
        assert_eq!(set.entries.len(), 1);
        assert_eq!(set.entries[0].status, Status::Untracked);
        assert_eq!(set.entries[0].presence, Presence::Untracked);
        assert!(!set.entries[0].visible_to_bare_diff());
        assert_eq!(set.invisible_to_bare_diff().len(), 1);
    }

    #[test]
    fn a_staged_change_is_invisible_to_bare_diff_but_present_here() {
        // `git add` erases the change from bare `git diff`. A hook or sub-agent staging work must
        // not make it disappear from review.
        let set = parse_default(&rec(&["M  staged.rs"])).unwrap();
        assert_eq!(set.entries[0].presence, Presence::Staged);
        assert_eq!(set.entries[0].status, Status::Modified);
        assert!(!set.entries[0].visible_to_bare_diff());
    }

    #[test]
    fn an_unstaged_change_is_the_only_thing_bare_diff_would_have_shown() {
        let set = parse_default(&rec(&[" M work.rs"])).unwrap();
        assert_eq!(set.entries[0].presence, Presence::Unstaged);
        assert!(set.entries[0].visible_to_bare_diff());
        assert!(set.invisible_to_bare_diff().is_empty());
    }

    #[test]
    fn a_path_changed_on_both_sides_is_reported_as_both() {
        let set = parse_default(&rec(&["MM both.rs"])).unwrap();
        assert_eq!(set.entries[0].presence, Presence::StagedAndUnstaged);
    }

    #[test]
    fn a_rename_carries_its_origin_from_the_following_record() {
        let set = parse_default(&rec(&["R  new/name.rs", "old/name.rs"])).unwrap();
        assert_eq!(set.entries.len(), 1, "the origin is not a second entry");
        assert_eq!(set.entries[0].status, Status::Renamed);
        assert_eq!(set.entries[0].path, "new/name.rs");
        assert_eq!(set.entries[0].origin.as_deref(), Some("old/name.rs"));
    }

    #[test]
    fn a_rename_missing_its_origin_is_refused_rather_than_silently_halved() {
        let err = parse_default(&rec(&["R  new/name.rs"])).unwrap_err();
        assert_eq!(
            err,
            ParseError::MissingOrigin {
                path: "new/name.rs".into()
            }
        );
    }

    #[test]
    fn a_filename_containing_a_newline_survives() {
        // This is why the NUL form is the only safe one: the human-readable form would quote and
        // split this into two records and desynchronise the whole stream.
        let set = parse_default(&rec(&[" M we\nird.rs", "?? plain.rs"])).unwrap();
        let paths: Vec<&str> = set.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"we\nird.rs"), "{paths:?}");
        assert_eq!(set.entries.len(), 2);
    }

    #[test]
    fn ignored_files_are_not_changes() {
        let set = parse_default(&rec(&["!! target/debug/x", " M real.rs"])).unwrap();
        assert_eq!(set.entries.len(), 1);
        assert_eq!(set.entries[0].path, "real.rs");
    }

    #[test]
    fn conflicts_are_not_reported_as_ordinary_modifications() {
        for code in ["UU c.rs", "AA c.rs", "DD c.rs"] {
            let set = parse_default(&rec(&[code])).unwrap();
            assert_eq!(
                set.entries[0].status,
                Status::Unmerged,
                "{code} must surface as a conflict"
            );
        }
    }

    #[test]
    fn deletions_are_classified_by_the_side_they_occurred_on() {
        let staged = parse_default(&rec(&["D  gone.rs"])).unwrap();
        assert_eq!(staged.entries[0].status, Status::Deleted);
        assert_eq!(staged.entries[0].presence, Presence::Staged);

        let worktree = parse_default(&rec(&[" D gone.rs"])).unwrap();
        assert_eq!(worktree.entries[0].status, Status::Deleted);
        assert_eq!(worktree.entries[0].presence, Presence::Unstaged);
    }

    #[test]
    fn results_are_ordered_and_truncation_keeps_a_deterministic_prefix() {
        let set = parse_porcelain_v1_z(&rec(&[" M c.rs", " M a.rs", " M b.rs"]), 2).unwrap();
        assert_eq!(set.truncated, 1);
        assert_eq!(
            set.entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a.rs", "b.rs"]
        );
    }

    #[test]
    fn an_empty_status_is_an_empty_change_set_not_an_error() {
        assert!(parse_default(b"").unwrap().is_empty());
        assert!(parse_default(b"\0").unwrap().is_empty());
    }

    #[test]
    fn a_truncated_record_is_refused() {
        assert_eq!(
            parse_default(b"M\0"),
            Err(ParseError::ShortRecord { index: 0 })
        );
    }

    #[test]
    fn a_realistic_mixed_status_separates_the_three_populations() {
        let set = parse_default(&rec(&[
            "?? brand_new.rs",
            "M  staged_only.rs",
            " M worktree_only.rs",
            "MM both_sides.rs",
            "R  renamed.rs",
            "was.rs",
            "!! ignored.txt",
        ]))
        .unwrap();

        assert_eq!(set.entries.len(), 5, "ignored dropped, rename not doubled");
        // Only the two with a worktree component would have appeared in bare `git diff`.
        let invisible: Vec<&str> = set
            .invisible_to_bare_diff()
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(
            invisible,
            vec!["brand_new.rs", "renamed.rs", "staged_only.rs"],
            "these three are real changes a reviewing agent would never have seen"
        );
    }
}

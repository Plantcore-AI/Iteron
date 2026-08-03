//! The complete set of changes in a workspace, including the ones `git diff` cannot show.
//!
//! `git diff` alone reports **unstaged modifications to tracked files**. It does not report staged
//! changes, and it never reports untracked files at all. For a human at a terminal that is a
//! familiar limitation. For an agent asked "what did you change?", it is a correctness failure with
//! a uniquely bad shape: an agent that creates a new file and then runs `git diff` sees empty
//! output and concludes it changed nothing. Staged work is invisible the same way, so a hook or a
//! sub-agent that runs `git add` erases the change from the reviewing agent's view.
//!
//! This crate builds the union -- staged, unstaged, and untracked -- from a porcelain status
//! record, classifies each path by *where* the change lives, and bounds the result. It parses
//! bytes and performs no IO, so the harness that already captures git output keeps ownership of
//! the process boundary.

pub mod guard;
pub mod hunks;
pub mod porcelain;

pub use guard::{Operation, Verdict, assess, has_unrecorded_work, remediation_paths};
pub use hunks::{DiffError, FileChange, FileDiff, Hunk, parse_unified, parse_unified_default};
pub use porcelain::{
    ChangeSet, Entry, ParseError, Presence, Status, parse_default, parse_porcelain_v1_z,
};

/// Upper bound on entries carried into a review. A repository-wide reformat legitimately touches
/// thousands of files; forwarding all of them would spend the context window on the listing rather
/// than the change. The excess is counted, never silently dropped.
pub const MAX_ENTRIES: usize = 1_000;

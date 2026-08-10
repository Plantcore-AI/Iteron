//! Parse a capture taken from a real `git status --porcelain=v1 -z` run.
//!
//! The unit tests build their records by hand, which proves the parser handles the shapes it was
//! written for. This one proves it handles the bytes git actually emits -- including the exact
//! two-record rename encoding and the `AM` code, both of which are easy to get subtly wrong when
//! writing fixtures from the documentation rather than from output.
//!
//! The fixture was produced from a scratch repository holding five real changes. A bare `git diff`
//! in that repository lists exactly **one** file. That ratio is the defect this crate exists for.

use iteron_changeset::{Presence, Status, parse_default};

const CAPTURE: &[u8] = include_bytes!("fixtures/status-mixed-v1z.bin");

#[test]
fn a_real_capture_recovers_every_change_bare_diff_would_have_hidden() {
    let set = parse_default(CAPTURE).expect("real porcelain must parse");

    let seen: Vec<(&str, Status, Presence)> = set
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e.status, e.presence))
        .collect();

    assert_eq!(
        seen,
        vec![
            ("brand_new.rs", Status::Untracked, Presence::Untracked),
            ("doomed.rs", Status::Deleted, Presence::Staged),
            ("renamed_to.rs", Status::Renamed, Presence::Staged),
            ("tracked.rs", Status::Modified, Presence::Staged),
            (
                "worktree_only.rs",
                Status::Added,
                Presence::StagedAndUnstaged
            ),
        ]
    );

    // The rename kept its origin and did not become a second entry.
    let renamed = set
        .entries
        .iter()
        .find(|e| e.path == "renamed_to.rs")
        .unwrap();
    assert_eq!(renamed.origin.as_deref(), Some("renamed_from.rs"));

    // Four of the five changes are invisible to a bare `git diff`; only `worktree_only.rs` has a
    // worktree component. An agent reviewing bare diff output would report one change out of five.
    let invisible: Vec<&str> = set
        .invisible_to_bare_diff()
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(
        invisible,
        vec!["brand_new.rs", "doomed.rs", "renamed_to.rs", "tracked.rs"]
    );
    assert_eq!(set.entries.len() - invisible.len(), 1);
}

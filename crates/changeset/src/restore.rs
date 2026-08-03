//! What a checkpoint restore would actually do, previewed before it does it.
//!
//! `crates/record` already captures a workspace snapshot as a git tree, carefully. What is missing
//! is the other half: deciding *what a restore touches*, and being honest about what it cannot.
//!
//! A snapshot records the tree at a moment. Anything that entered the workspace afterwards is, by
//! construction, not in it -- so a restore has to choose between leaving those files (the workspace
//! is then not actually at the checkpoint state) and deleting them (data loss, possibly of the only
//! copy). Both are defensible; silently picking one is not. This module names the population so the
//! choice is made with it on screen.
//!
//! The sharpest case is a file written by a shell command rather than by an edit the agent
//! recorded. The agent has no memory of creating it, the snapshot has no record of it, and it is
//! untracked -- so every cheap check misses it and a restore is exactly when it disappears.

use crate::porcelain::{ChangeSet, Entry, Presence};

/// Which half of the state a restore returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Files and conversation together: the full rewind.
    CodeAndConversation,
    /// Files only. The conversation keeps its memory of work now undone, which is usually what a
    /// caller wants when retrying an approach, and is worth stating because the transcript will
    /// disagree with the tree.
    CodeOnly,
    /// Conversation only. Touches no file at all.
    ConversationOnly,
}

impl Scope {
    /// Whether this scope writes to the working tree.
    pub fn touches_files(self) -> bool {
        !matches!(self, Scope::ConversationOnly)
    }

    /// Whether this scope rewinds the transcript.
    pub fn touches_conversation(self) -> bool {
        !matches!(self, Scope::CodeOnly)
    }
}

/// How a restore should treat files the snapshot never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unrecorded {
    /// Leave them in place. The tree afterwards is *not* the checkpoint state, and the caller
    /// should be told that rather than believing the rewind was exact.
    Keep,
    /// Delete them, making the tree match the checkpoint. This destroys work that may exist
    /// nowhere else.
    Delete,
}

/// What would happen, before it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub scope: Scope,
    pub unrecorded: Unrecorded,
    /// Tracked paths the restore would overwrite with their checkpoint contents.
    pub overwritten: Vec<Entry>,
    /// Paths the snapshot cannot contain, because they were never tracked at capture time.
    pub not_in_snapshot: Vec<Entry>,
    /// True when the resulting tree will not equal the checkpoint tree.
    pub inexact: bool,
    /// Entries the change set never examined because it hit its ceiling. Non-zero means this
    /// preview is a lower bound, not a description.
    pub unexamined: usize,
    /// True when the caller supplied no snapshot inventory, so "not in the snapshot" was inferred
    /// from `Presence::Untracked` rather than known.
    ///
    /// That inference is **wrong** against `core-record`, whose snapshot captures untracked
    /// non-ignored files too: such a path *is* in the checkpoint and would be restored, not lost.
    /// Until an inventory is threaded through, a preview says so instead of asserting a
    /// classification it cannot make.
    pub inferred_membership: bool,
}

impl Preview {
    /// Whether this preview describes the outcome, as opposed to bounding it.
    pub fn is_conclusive(&self) -> bool {
        self.unexamined == 0 && !self.inferred_membership
    }
}

impl Preview {
    /// Paths that would be destroyed with no copy in the snapshot to restore them from.
    pub fn irrecoverable(&self) -> &[Entry] {
        if self.unrecorded == Unrecorded::Delete {
            &self.not_in_snapshot
        } else {
            &[]
        }
    }

    pub fn describe(&self) -> String {
        if !self.scope.touches_files() {
            return "conversation only; no file is touched".to_owned();
        }
        let mut parts = vec![format!(
            "{} tracked file(s) restored",
            self.overwritten.len()
        )];
        match self.unrecorded {
            Unrecorded::Delete if !self.not_in_snapshot.is_empty() => parts.push(format!(
                "{} file(s) deleted with no copy in the checkpoint: {}",
                self.not_in_snapshot.len(),
                self.not_in_snapshot
                    .iter()
                    .map(|e| e.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ if !self.not_in_snapshot.is_empty() => parts.push(format!(
                "{} file(s) kept, so the tree will NOT match the checkpoint",
                self.not_in_snapshot.len()
            )),
            _ => {}
        }
        parts.join("; ")
    }
}

/// Work out what a restore would do to this workspace.
///
/// `ConversationOnly` reports no file effects at all -- not "zero files changed", which would
/// invite a caller to render it beside the other scopes as though it were an unusually small
/// file restore.
pub fn preview(changes: &ChangeSet, scope: Scope, unrecorded: Unrecorded) -> Preview {
    if !scope.touches_files() {
        return Preview {
            scope,
            unrecorded,
            overwritten: Vec::new(),
            not_in_snapshot: Vec::new(),
            inexact: false,
            unexamined: changes.truncated,
            inferred_membership: false,
        };
    }

    let (not_in_snapshot, overwritten): (Vec<Entry>, Vec<Entry>) = changes
        .entries
        .iter()
        .cloned()
        .partition(|e| e.presence == Presence::Untracked);

    // Keeping unrecorded files means the tree afterwards differs from the checkpoint. That is a
    // fact about the outcome, not a warning to be suppressed once the caller has seen it.
    let inexact = unrecorded == Unrecorded::Keep && !not_in_snapshot.is_empty();

    Preview {
        scope,
        unrecorded,
        overwritten,
        not_in_snapshot,
        inexact,
        unexamined: changes.truncated,
        inferred_membership: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::porcelain::parse_default;

    fn changes(parts: &[&str]) -> ChangeSet {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(p.as_bytes());
            out.push(0);
        }
        parse_default(&out).unwrap()
    }

    #[test]
    fn conversation_only_touches_no_file_even_with_a_dirty_tree() {
        let p = preview(
            &changes(&["?? new.rs", " M old.rs"]),
            Scope::ConversationOnly,
            Unrecorded::Delete,
        );
        assert!(p.overwritten.is_empty());
        assert!(p.not_in_snapshot.is_empty());
        assert!(!p.inexact);
        assert_eq!(p.describe(), "conversation only; no file is touched");
        assert!(p.irrecoverable().is_empty());
    }

    #[test]
    fn deleting_unrecorded_files_is_named_as_irrecoverable() {
        // The file the agent created with a shell command: not in the snapshot, untracked, and
        // about to be the only copy that ever existed.
        let p = preview(
            &changes(&["?? generated.rs", " M src.rs"]),
            Scope::CodeAndConversation,
            Unrecorded::Delete,
        );
        assert_eq!(p.irrecoverable().len(), 1);
        assert_eq!(p.irrecoverable()[0].path, "generated.rs");
        assert!(
            p.describe().contains("no copy in the checkpoint"),
            "{}",
            p.describe()
        );
        assert!(p.describe().contains("generated.rs"));
    }

    #[test]
    fn keeping_unrecorded_files_makes_the_restore_inexact_and_says_so() {
        // The other defensible choice, with its own honest consequence: the tree is not the
        // checkpoint tree afterwards.
        let p = preview(
            &changes(&["?? generated.rs"]),
            Scope::CodeOnly,
            Unrecorded::Keep,
        );
        assert!(p.inexact);
        assert!(p.irrecoverable().is_empty());
        assert!(
            p.describe().contains("will NOT match the checkpoint"),
            "{}",
            p.describe()
        );
    }

    #[test]
    fn a_preview_without_a_snapshot_inventory_says_so() {
        // `Presence::Untracked` is not the same as "absent from the checkpoint": core-record's
        // snapshot captures untracked non-ignored files, so such a path would be *restored*, not
        // lost. Until an inventory is threaded through, the preview reports that it inferred.
        let p = preview(
            &changes(&["?? generated.rs"]),
            Scope::CodeAndConversation,
            Unrecorded::Delete,
        );
        assert!(p.inferred_membership);
        assert!(
            !p.is_conclusive(),
            "an inferred classification is not a conclusion"
        );
    }

    #[test]
    fn a_truncated_change_set_makes_the_preview_a_lower_bound() {
        let c = crate::porcelain::parse_porcelain_v1_z(
            &{
                let mut v = Vec::new();
                for p in [" M a.rs", " M b.rs", " M c.rs"] {
                    v.extend_from_slice(p.as_bytes());
                    v.push(0);
                }
                v
            },
            1,
        )
        .unwrap();
        let p = preview(&c, Scope::CodeOnly, Unrecorded::Keep);
        assert_eq!(p.unexamined, 2);
        assert!(!p.is_conclusive());
    }

    #[test]
    fn a_clean_tree_restores_exactly_under_either_policy() {
        for u in [Unrecorded::Keep, Unrecorded::Delete] {
            let p = preview(&changes(&[]), Scope::CodeAndConversation, u);
            assert!(!p.inexact);
            assert!(p.irrecoverable().is_empty());
        }
    }

    #[test]
    fn tracked_modifications_are_overwritten_not_reported_as_unrecoverable() {
        // These exist in the snapshot, so restoring them is a recovery rather than a loss.
        let p = preview(
            &changes(&["M  staged.rs", " M work.rs", "MM both.rs"]),
            Scope::CodeOnly,
            Unrecorded::Delete,
        );
        assert_eq!(p.overwritten.len(), 3);
        assert!(p.irrecoverable().is_empty());
        assert!(!p.inexact);
    }

    #[test]
    fn scope_flags_describe_the_two_halves_independently() {
        assert!(Scope::CodeOnly.touches_files() && !Scope::CodeOnly.touches_conversation());
        assert!(
            !Scope::ConversationOnly.touches_files()
                && Scope::ConversationOnly.touches_conversation()
        );
        assert!(
            Scope::CodeAndConversation.touches_files()
                && Scope::CodeAndConversation.touches_conversation()
        );
    }

    #[test]
    fn code_only_leaves_the_transcript_disagreeing_with_the_tree() {
        // Not a defect -- it is what a caller retrying an approach wants -- but it is a state the
        // caller should know they are entering, so the scope makes it explicit rather than implied.
        let s = Scope::CodeOnly;
        assert!(s.touches_files());
        assert!(!s.touches_conversation());
    }
}

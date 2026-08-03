//! Whether a destructive workspace operation would lose work that nobody recorded.
//!
//! An agent that writes in a worktree eventually wants to remove it, reset it, or merge over it.
//! Git's own defaults refuse when that would destroy uncommitted work -- and the standard reaction
//! to a refusal, by humans and agents alike, is to add `--force` until it stops complaining. That
//! turns a safety mechanism into a speed bump.
//!
//! This module answers the question *before* the flag gets added: given the workspace's actual
//! change set, name exactly what a given operation would destroy. Refusing with a list of the four
//! files that would be lost is actionable; refusing with "worktree is dirty" is what people
//! `--force` past.
//!
//! Untracked files get particular attention because they are the most commonly lost category and
//! the least visible: `git diff` never shows them (see [`crate::porcelain`]), so an agent that
//! checked for changes by reading a diff has already concluded the tree is clean.

use crate::porcelain::{ChangeSet, Entry, Presence, Status};

/// A destructive operation, described by what it would discard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `git worktree remove`. Deletes the directory, so *everything* uncommitted goes -- including
    /// untracked files, which no other operation here touches.
    RemoveWorktree,
    /// `git reset --hard`. Discards staged and unstaged modifications to tracked files; leaves
    /// untracked files in place.
    HardReset,
    /// `git checkout <other>` / `git switch`. Refuses on conflicting local modifications; carries
    /// non-conflicting ones across. Untracked files survive unless the target would overwrite them.
    Checkout,
    /// `git merge`. Requires a clean tree for the paths it touches.
    Merge,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Operation::RemoveWorktree => "removing this worktree",
            Operation::HardReset => "a hard reset",
            Operation::Checkout => "checking out another ref",
            Operation::Merge => "merging",
        }
    }
}

/// The answer, with its evidence attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing would be lost.
    Safe,
    /// Work would be destroyed. The entries are listed so the refusal is actionable and so a
    /// caller can offer to commit or stash exactly those paths.
    WouldLose {
        operation: Operation,
        entries: Vec<Entry>,
    },
}

impl Verdict {
    pub fn is_safe(&self) -> bool {
        matches!(self, Verdict::Safe)
    }

    /// A message naming the operation and the count, for a caller that needs one line.
    pub fn describe(&self) -> String {
        match self {
            Verdict::Safe => "no uncommitted work would be lost".to_owned(),
            Verdict::WouldLose { operation, entries } => format!(
                "{} would discard {} uncommitted change{}: {}",
                operation.label(),
                entries.len(),
                if entries.len() == 1 { "" } else { "s" },
                entries
                    .iter()
                    .map(|e| e.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// Would `operation` destroy anything in `changes`?
///
/// A deletion already recorded in the index is not "work that would be lost" for a hard reset --
/// resetting restores the file, which is a recovery rather than a loss. Treating every non-clean
/// entry as a loss would make the guard cry wolf, and a guard that cries wolf gets forced past.
pub fn assess(changes: &ChangeSet, operation: Operation) -> Verdict {
    let at_risk: Vec<Entry> = changes
        .entries
        .iter()
        .filter(|e| would_lose(e, operation))
        .cloned()
        .collect();

    if at_risk.is_empty() {
        Verdict::Safe
    } else {
        Verdict::WouldLose {
            operation,
            entries: at_risk,
        }
    }
}

fn would_lose(entry: &Entry, operation: Operation) -> bool {
    match operation {
        // The directory goes. Everything not committed goes with it, untracked included.
        Operation::RemoveWorktree => true,
        // Restores tracked files from HEAD: modifications are lost, untracked files are untouched.
        Operation::HardReset => entry.presence != Presence::Untracked,
        // These refuse or carry changes across rather than discarding them; the loss case is an
        // untracked file whose path the incoming tree also contains, which we cannot know here.
        // Reporting it as at-risk is the conservative direction, and untracked files are exactly
        // the category a diff-based check already missed.
        Operation::Checkout | Operation::Merge => entry.presence == Presence::Untracked,
    }
}

/// Paths a caller could stash or commit to make `operation` safe.
pub fn remediation_paths(changes: &ChangeSet, operation: Operation) -> Vec<&str> {
    match assess(changes, operation) {
        Verdict::Safe => Vec::new(),
        Verdict::WouldLose { .. } => changes
            .entries
            .iter()
            .filter(|e| would_lose(e, operation))
            .map(|e| e.path.as_str())
            .collect(),
    }
}

/// True when the change set contains work that exists *only* in the working tree -- never
/// committed, never staged, and invisible to `git diff`.
///
/// This is the population that gets destroyed most often, because every cheap "is it clean?" check
/// misses it.
pub fn has_unrecorded_work(changes: &ChangeSet) -> bool {
    changes
        .entries
        .iter()
        .any(|e| e.status == Status::Untracked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::porcelain::parse_default;

    fn rec(parts: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(p.as_bytes());
            out.push(0);
        }
        out
    }

    fn changes(parts: &[&str]) -> ChangeSet {
        parse_default(&rec(parts)).unwrap()
    }

    #[test]
    fn removing_a_worktree_loses_untracked_work_that_a_diff_check_would_have_missed() {
        // The headline case: agent checks `git diff`, sees nothing, removes the worktree, and the
        // file it created is gone.
        let c = changes(&["?? generated.rs"]);
        let verdict = assess(&c, Operation::RemoveWorktree);
        assert!(!verdict.is_safe());
        assert!(
            verdict.describe().contains("generated.rs"),
            "{}",
            verdict.describe()
        );
    }

    #[test]
    fn a_hard_reset_leaves_untracked_files_alone() {
        // Real behaviour: `reset --hard` does not delete untracked files, so claiming it would is
        // crying wolf -- and a guard that cries wolf gets forced past.
        let c = changes(&["?? kept.rs"]);
        assert_eq!(assess(&c, Operation::HardReset), Verdict::Safe);
    }

    #[test]
    fn a_hard_reset_does_lose_staged_and_unstaged_modifications() {
        for code in ["M  staged.rs", " M work.rs", "MM both.rs"] {
            let c = changes(&[code]);
            assert!(
                !assess(&c, Operation::HardReset).is_safe(),
                "{code} must be reported at risk"
            );
        }
    }

    #[test]
    fn checkout_and_merge_flag_untracked_files_conservatively() {
        let c = changes(&["?? new.rs", " M tracked.rs"]);
        for op in [Operation::Checkout, Operation::Merge] {
            let Verdict::WouldLose { entries, .. } = assess(&c, op) else {
                panic!("expected a refusal for {op:?}")
            };
            // Only the untracked one: a tracked modification is carried across or refused by git
            // itself, not silently destroyed.
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].path, "new.rs");
        }
    }

    #[test]
    fn a_clean_tree_is_safe_for_every_operation() {
        let c = changes(&[]);
        for op in [
            Operation::RemoveWorktree,
            Operation::HardReset,
            Operation::Checkout,
            Operation::Merge,
        ] {
            assert_eq!(assess(&c, op), Verdict::Safe, "{op:?}");
        }
    }

    #[test]
    fn removing_a_worktree_accounts_for_every_population_at_once() {
        let c = changes(&["?? untracked.rs", "M  staged.rs", " M work.rs"]);
        let Verdict::WouldLose { entries, .. } = assess(&c, Operation::RemoveWorktree) else {
            panic!("expected a refusal")
        };
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn the_refusal_names_the_files_so_it_is_actionable() {
        // "worktree is dirty" is what people --force past. A list is something a caller can act on.
        let c = changes(&["?? a.rs", "?? b.rs"]);
        let text = assess(&c, Operation::RemoveWorktree).describe();
        assert!(text.contains("a.rs") && text.contains("b.rs"), "{text}");
        assert!(text.contains("2 uncommitted changes"), "{text}");
        assert_eq!(
            remediation_paths(&c, Operation::RemoveWorktree),
            vec!["a.rs", "b.rs"]
        );
    }

    #[test]
    fn singular_and_plural_are_both_readable() {
        let one = assess(&changes(&["?? a.rs"]), Operation::RemoveWorktree).describe();
        assert!(one.contains("1 uncommitted change:"), "{one}");
    }

    #[test]
    fn unrecorded_work_is_detected_independently_of_any_operation() {
        assert!(has_unrecorded_work(&changes(&["?? x.rs"])));
        assert!(!has_unrecorded_work(&changes(&[" M x.rs", "M  y.rs"])));
    }

    #[test]
    fn a_safe_verdict_offers_no_remediation() {
        assert!(remediation_paths(&changes(&["?? x.rs"]), Operation::HardReset).is_empty());
    }
}

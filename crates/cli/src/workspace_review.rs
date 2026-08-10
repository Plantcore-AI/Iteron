//! Product binding for `iteron-changeset`: complete status, staged/unstaged diff materialisation,
//! and checkpoint restore previews.

use iteron_changeset::{ChangeSet, Inventory, Presence, Preview, Scope, Status, Unrecorded};
use iteron_protocol::{Event, EventKind, RunId, Seq};
use iteron_record::Snapshot;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RewindDisposition {
    Preview,
    Apply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RewindRequest {
    pub(crate) at: Seq,
    pub(crate) scope: Scope,
    pub(crate) unrecorded: Unrecorded,
    pub(crate) disposition: RewindDisposition,
}

pub(crate) fn parse_rewind_request(input: &str) -> Result<Option<RewindRequest>, String> {
    let mut words = input.split_whitespace();
    let Some(seq) = words.next() else {
        return Ok(None);
    };
    let at = Seq(seq.parse::<u64>().map_err(|_| {
        "rewind sequence must be an integer; use `/rewind` to list available points".to_owned()
    })?);
    let mut request = RewindRequest {
        at,
        scope: Scope::CodeAndConversation,
        unrecorded: Unrecorded::Keep,
        disposition: RewindDisposition::Preview,
    };
    let mut saw_scope = false;
    let mut saw_policy = false;
    let mut saw_disposition = false;
    for word in words {
        match word {
            "all" | "both" if !saw_scope => {
                request.scope = Scope::CodeAndConversation;
                saw_scope = true;
            }
            "code" if !saw_scope => {
                request.scope = Scope::CodeOnly;
                saw_scope = true;
            }
            "conversation" | "chat" if !saw_scope => {
                request.scope = Scope::ConversationOnly;
                saw_scope = true;
            }
            "keep" if !saw_policy => {
                request.unrecorded = Unrecorded::Keep;
                saw_policy = true;
            }
            "delete" if !saw_policy => {
                request.unrecorded = Unrecorded::Delete;
                saw_policy = true;
            }
            "preview" if !saw_disposition => {
                request.disposition = RewindDisposition::Preview;
                saw_disposition = true;
            }
            "apply" if !saw_disposition => {
                request.disposition = RewindDisposition::Apply;
                saw_disposition = true;
            }
            _ => {
                return Err(format!(
                    "unknown or repeated rewind option `{word}`; expected one of all|code|conversation, keep|delete, preview|apply"
                ));
            }
        }
    }
    Ok(Some(request))
}

#[derive(Debug)]
pub(crate) struct Review {
    pub(crate) changes: ChangeSet,
    pub(crate) unstaged_diff: String,
    pub(crate) staged_diff: String,
}

impl Review {
    pub(crate) fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub(crate) fn summary(&self) -> Vec<String> {
        let mut rows = self
            .changes
            .entries
            .iter()
            .map(|entry| {
                let population = match entry.presence {
                    Presence::Staged => "staged",
                    Presence::Unstaged => "unstaged",
                    Presence::StagedAndUnstaged => "staged + unstaged",
                    Presence::Untracked => "untracked",
                };
                let status = match entry.status {
                    Status::Added => "added",
                    Status::Modified => "modified",
                    Status::Deleted => "deleted",
                    Status::Renamed => "renamed",
                    Status::Copied => "copied",
                    Status::Unmerged => "conflict",
                    Status::Untracked => "untracked",
                };
                match &entry.origin {
                    Some(origin) => {
                        format!("{status:<9} {population:<19} {origin} → {}", entry.path)
                    }
                    None => format!("{status:<9} {population:<19} {}", entry.path),
                }
            })
            .collect::<Vec<_>>();
        if self.changes.truncated > 0 {
            rows.push(format!(
                "… {} additional path(s) beyond the review ceiling",
                self.changes.truncated
            ));
        }
        rows
    }

    /// Return every materialised text diff after the stricter change-set parser has verified hunk
    /// counts and distinguished binary/rename/mode-only entries. Untracked paths remain visible in
    /// `changes`; their content is not read merely to make a diff.
    pub(crate) fn verified_diffs(&self) -> Result<Vec<&str>, String> {
        let mut documents = Vec::new();
        for document in [&self.staged_diff, &self.unstaged_diff] {
            if document.trim().is_empty() || document.trim() == "(no uncommitted changes)" {
                continue;
            }
            iteron_changeset::parse_unified_default(document)
                .map_err(|error| format!("bounded unified diff refused: {error}"))?;
            documents.push(document.as_str());
        }
        Ok(documents)
    }
}

pub(crate) async fn observe(workspace: &Path) -> Result<Review, String> {
    // Start all independent reads together. Each child is independently deadline/output bounded;
    // the aggregate therefore remains three fixed observations, not an unbounded fan.
    let (status, staged, unstaged) = tokio::join!(
        iteron_tools::git_status_porcelain_observation(workspace),
        iteron_tools::git_index_diff_observation(workspace, false, None),
        iteron_tools::git_diff_observation(workspace, false, None),
    );
    let changes = iteron_changeset::parse_default(&status?)
        .map_err(|error| format!("Git status protocol refused: {error}"))?;
    Ok(Review {
        changes,
        staged_diff: staged?,
        unstaged_diff: unstaged?,
    })
}

pub(crate) fn checkpoint_at_or_before(
    events: &[Event],
    run: &RunId,
    requested: Seq,
) -> Option<Snapshot> {
    events.iter().rev().find_map(|event| match &event.kind {
        EventKind::Checkpoint { at, tree_ref } if *at <= requested => Some(Snapshot {
            run: run.clone(),
            at: *at,
            tree_ref: tree_ref.clone(),
            created_at: 0,
        }),
        _ => None,
    })
}

pub(crate) fn preview_restore(
    review: &Review,
    snapshot: &Snapshot,
    workspace: &Path,
    scope: Scope,
    unrecorded: Unrecorded,
) -> Result<Preview, String> {
    let paths =
        iteron_record::snapshot_inventory(snapshot, workspace, iteron_changeset::MAX_ENTRIES)
            .map_err(|error| format!("checkpoint inventory failed: {error}"))?;
    let inventory = if paths.complete {
        Inventory::complete(paths.paths)
    } else {
        Inventory::truncated(paths.paths)
    };
    Ok(iteron_changeset::preview_against(
        &review.changes,
        &inventory,
        scope,
        unrecorded,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_lookup_uses_the_latest_point_not_after_the_request() {
        let run = RunId("r".into());
        let event = |seq, tree: &str| Event {
            seq: Seq(seq),
            turn: iteron_protocol::TurnId(1),
            kind: EventKind::Checkpoint {
                at: Seq(seq),
                tree_ref: tree.into(),
            },
        };
        let events = vec![event(4, "a"), event(9, "b"), event(12, "c")];
        assert_eq!(
            checkpoint_at_or_before(&events, &run, Seq(10))
                .unwrap()
                .tree_ref,
            "b"
        );
        assert!(checkpoint_at_or_before(&events, &run, Seq(3)).is_none());
    }

    #[test]
    fn rewind_syntax_defaults_to_a_non_destructive_full_preview() {
        let request = parse_rewind_request("42").unwrap().unwrap();
        assert_eq!(request.at, Seq(42));
        assert_eq!(request.scope, Scope::CodeAndConversation);
        assert_eq!(request.unrecorded, Unrecorded::Keep);
        assert_eq!(request.disposition, RewindDisposition::Preview);
        assert_eq!(
            parse_rewind_request("42 code delete apply")
                .unwrap()
                .unwrap()
                .scope,
            Scope::CodeOnly
        );
        assert!(parse_rewind_request("42 code all").is_err());
    }
}

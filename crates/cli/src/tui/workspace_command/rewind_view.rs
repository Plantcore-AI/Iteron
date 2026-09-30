//! Bounded command parsing and immutable host receipt presentation; no filesystem work.
use super::Action;
use crate::app_server::WorkspaceRewound;
use crate::tui::{
    block::{NoticeLevel, PanelRow},
    kv, ui_safe_text,
};
use iteron_protocol::{
    RunId,
    product_contract::ThreadSnapshotV1,
    workspace_rewind::{
        RewindFilesV1, RewindScopeV1, RewindTargetV1, RewindUnrecordedV1, WorkspaceRewindCommandV1,
    },
};

pub(super) fn parse(
    scope: &ThreadSnapshotV1,
    input: &str,
) -> Result<WorkspaceRewindCommandV1, String> {
    if input.len() > 2_048 {
        return Err("rewind arguments exceed the bounded command length".into());
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(WorkspaceRewindCommandV1::List {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
        });
    }
    let (selector, options) = input.split_once(char::is_whitespace).unwrap_or((input, ""));
    let (run, seq) = match selector.rsplit_once('@') {
        Some((run, seq)) => (RunId(run.to_owned()), seq),
        None => (scope.run_id.clone(), selector),
    };
    let request = crate::workspace_review::parse_rewind_request(&format!("{seq} {options}"))?
        .ok_or("rewind target unavailable")?;
    let target = RewindTargetV1 {
        run_id: run,
        seq: request.at,
    };
    let requested_scope = match request.scope {
        iteron_changeset::Scope::CodeAndConversation => RewindScopeV1::CodeAndConversation,
        iteron_changeset::Scope::CodeOnly => RewindScopeV1::CodeOnly,
        iteron_changeset::Scope::ConversationOnly => RewindScopeV1::ConversationOnly,
    };
    let unrecorded = match request.unrecorded {
        iteron_changeset::Unrecorded::Keep => RewindUnrecordedV1::Keep,
        iteron_changeset::Unrecorded::Delete => RewindUnrecordedV1::Delete,
    };
    let command = if request.disposition == crate::workspace_review::RewindDisposition::Apply {
        WorkspaceRewindCommandV1::Apply {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
            target,
            scope: requested_scope,
            unrecorded,
        }
    } else {
        WorkspaceRewindCommandV1::Preview {
            thread_id: scope.thread_id.clone(),
            run_id: scope.run_id.clone(),
            target,
            scope: requested_scope,
            unrecorded,
        }
    };
    command.validate().map_err(str::to_owned)?;
    Ok(command)
}
pub(super) fn project(reply: WorkspaceRewound) -> Vec<Action> {
    let mut actions = Vec::new();
    let fact = reply.presentation;
    if fact.version != 1 {
        return vec![Action::Notice(
            NoticeLevel::Err,
            "unsupported workspace rewind receipt".into(),
        )];
    }
    if let Some(navigation) = reply.navigation {
        actions.push(Action::Adopt(navigation));
    }
    if !fact.points.is_empty() {
        let mut rows=vec![PanelRow::Note("preview: /rewind [RUN@]SEQ [all|code|conversation] [keep|delete] · append apply to execute".into())];
        rows.extend(fact.points.iter().take(30).map(|point| {
            kv(
                &format!(
                    "{}@{}",
                    ui_safe_text(&point.target.run_id.0),
                    point.target.seq.0
                ),
                &format!(
                    "turn {} · {}",
                    point.turn,
                    if point.file_checkpoint {
                        "files + conversation"
                    } else {
                        "conversation"
                    }
                ),
            )
        }));
        if fact.omitted_points != 0 {
            rows.push(PanelRow::Note(format!(
                "{} earlier points omitted",
                fact.omitted_points
            )));
        }
        actions.push(Action::Panel {
            glyph: "↩",
            title: "verified rewind points",
            rows,
        });
    }
    if let Some(preview) = fact.preview {
        let mut rows = vec![kv(
            "target",
            &format!(
                "{}@{}",
                ui_safe_text(&preview.target.run_id.0),
                preview.target.seq.0
            ),
        )];
        if preview.scope.touches_files() {
            rows.push(kv(
                "files",
                &format!(
                    "{} changed paths restored · {} deleted · {} later paths kept",
                    preview.overwritten_paths,
                    preview.deleted_paths,
                    preview.preserved_unrecorded_paths
                ),
            ));
            rows.push(kv(
                "result",
                if preview.overlay {
                    "overlay; later unrecorded paths preserved"
                } else {
                    "checkpoint tree outside protected runtime state"
                },
            ));
            rows.push(kv(
                "evidence",
                if preview.conclusive {
                    "complete bounded change-set and snapshot inventory"
                } else {
                    "incomplete; apply refused"
                },
            ));
            rows.extend(
                preview
                    .path_display
                    .into_iter()
                    .take(120)
                    .map(PanelRow::Note),
            );
            if preview.omitted_paths != 0 {
                rows.push(PanelRow::Note(format!(
                    "{} additional paths omitted from display",
                    preview.omitted_paths
                )));
            }
        } else {
            rows.push(PanelRow::Note(
                "conversation only; no workspace file is restored or deleted".into(),
            ));
        }
        actions.push(Action::Panel {
            glyph: "↩",
            title: "rewind preview",
            rows,
        });
    }
    if let Some(execution) = fact.execution {
        let mut rows = vec![kv(
            "files",
            match execution.files {
                RewindFilesV1::NotRequested => "not requested",
                RewindFilesV1::Restored => "native restore completed",
                RewindFilesV1::RolledBack => "restore failed; native safety rollback completed",
                RewindFilesV1::NotStarted => "working-file restore did not start",
                RewindFilesV1::ReconciliationNeeded => {
                    "outcome needs reconciliation; do not retry automatically"
                }
            },
        )];
        rows.push(kv(
            "journal",
            &format!(
                "{} · intent {} · safety {} · terminal {}",
                ui_safe_text(&fact.origin_run_id.0),
                sequence(execution.intent_seq),
                sequence(execution.safety_checkpoint_seq),
                sequence(execution.terminal_seq)
            ),
        ));
        if let Some(child) = execution.retained_child_run {
            rows.push(kv(
                if execution.conversation_adopted {
                    "selected branch"
                } else {
                    "retained unselected branch"
                },
                &ui_safe_text(&child.0),
            ));
        }
        if let Some(reason) = execution.reason {
            rows.push(PanelRow::Note(ui_safe_text(&reason)));
        }
        actions.push(Action::Panel {
            glyph: "↩",
            title: "actual rewind result",
            rows,
        });
    } else if fact.points.is_empty() {
        actions.push(Action::Notice(
            NoticeLevel::Info,
            "preview only; repeat the same target and options with apply to execute".into(),
        ));
    }
    actions
}
fn sequence(seq: Option<iteron_protocol::Seq>) -> String {
    seq.map(|seq| seq.0.to_string())
        .unwrap_or_else(|| "unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::parse;
    use iteron_protocol::{
        RunId, SessionId,
        product_contract::ThreadSnapshotV1,
        workspace_rewind::{RewindScopeV1, WorkspaceRewindCommandV1},
    };
    #[test]
    fn ancestor_selector_is_not_rebound_to_the_current_run_and_default_is_preview() {
        let scope = ThreadSnapshotV1 {
            contract_version: 1,
            thread_id: SessionId("thread".into()),
            run_id: RunId("child".into()),
            source_event_seq: 0,
            turn: None,
            submissions: Vec::new(),
            evicted_submissions: 0,
        };
        let WorkspaceRewindCommandV1::Preview {
            target,
            scope: kind,
            ..
        } = parse(&scope, "ancestor@3 conversation").unwrap()
        else {
            panic!("preview")
        };
        assert_eq!(target.run_id.0, "ancestor");
        assert_eq!(target.seq.0, 3);
        assert_eq!(kind, RewindScopeV1::ConversationOnly);
        let WorkspaceRewindCommandV1::Apply { target, .. } =
            parse(&scope, "4 code keep apply").unwrap()
        else {
            panic!("explicit apply")
        };
        assert_eq!(target.run_id.0, "child");
        assert!(parse(&scope, "../outside@4 apply").is_err());
        assert!(parse(&scope, "0 apply").is_err());
    }
}

//! Background workspace-review and rewind commands.
//!
//! These commands can traverse Git state, materialize diffs, checkpoint files, and rewrite a
//! workspace. None of that belongs on the terminal event loop. The worker returns bounded semantic
//! actions; only their cheap projection touches `App`.

use super::*;

const WORKSPACE_REVIEW_SUMMARY_ROWS: usize = 120;
const REWIND_TARGET_ROWS: usize = 30;
const IRRECOVERABLE_PREVIEW_ROWS: usize = 20;

pub(super) enum Action {
    Notice(block::NoticeLevel, String),
    Panel {
        glyph: &'static str,
        title: &'static str,
        rows: Vec<block::PanelRow>,
    },
    Diff(iteron_protocol::FileDiff),
    Adopt(String),
}

pub(super) fn queue_diff(app: &mut App, workspace: PathBuf, stat: bool) {
    queue(app, "workspace review", async move {
        match crate::workspace_review::observe(&workspace).await {
            Ok(review) if review.is_empty() => vec![Action::Notice(
                block::NoticeLevel::Info,
                "no uncommitted changes".into(),
            )],
            Ok(review) => {
                let mut rows = review
                    .summary()
                    .into_iter()
                    .take(iteron_tunables::param_integer(
                        "cli.tui.workspace_command.workspace_review_summary_rows",
                        WORKSPACE_REVIEW_SUMMARY_ROWS,
                    ))
                    .map(block::PanelRow::Note)
                    .collect::<Vec<_>>();
                let blind = review.changes.invisible_to_bare_diff().len();
                rows.push(block::PanelRow::Note(format!(
                    "{} path(s) total · {blind} invisible to bare git diff",
                    review.changes.entries.len()
                )));
                let mut actions = vec![Action::Panel {
                    glyph: "±",
                    title: "complete change set",
                    rows,
                }];
                if !stat {
                    match review.verified_diffs() {
                        Ok(documents) => {
                            for document in documents {
                                let text = iteron_record::redact::scrub(document);
                                actions.extend(
                                    iteron_protocol::FileDiff::from_unified(&text)
                                        .into_iter()
                                        .map(Action::Diff),
                                );
                            }
                        }
                        Err(error) => actions.push(Action::Notice(block::NoticeLevel::Err, error)),
                    }
                }
                actions
            }
            Err(error) => vec![Action::Notice(
                block::NoticeLevel::Err,
                format!("could not read complete bounded change set: {error}"),
            )],
        }
    });
}

pub(super) fn queue_rewind(
    app: &mut App,
    workspace: PathBuf,
    rollout_path: PathBuf,
    argument: String,
) {
    if app.workspace_command_job.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "another workspace command is already pending",
        );
        return;
    }
    app.status = "rewind pending…".into();
    let runtime = tokio::runtime::Handle::current();
    app.workspace_command_job = Some(tokio::task::spawn_blocking(move || {
        runtime.block_on(run_rewind(workspace, rollout_path, argument))
    }));
}

fn queue<F>(app: &mut App, label: &'static str, future: F)
where
    F: std::future::Future<Output = Vec<Action>> + Send + 'static,
{
    if app.workspace_command_job.is_some() {
        app.note(
            block::NoticeLevel::Warn,
            "another workspace command is already pending",
        );
        return;
    }
    app.status = format!("{label} pending…");
    app.workspace_command_job = Some(tokio::spawn(future));
}

pub(super) fn apply(
    app: &mut App,
    session: &Session,
    directory: &ProviderDirectory,
    actions: Vec<Action>,
) {
    for action in actions {
        match action {
            Action::Notice(level, message) => app.note(level, message),
            Action::Panel { glyph, title, rows } => app.panel(glyph, title, rows),
            Action::Diff(diff) => {
                app.push_block(block::BlockKind::Diff(diff));
            }
            Action::Adopt(run_id) => start_adopt_session(app, session, directory, run_id),
        }
    }
}

async fn run_rewind(workspace: PathBuf, rollout_path: PathBuf, argument: String) -> Vec<Action> {
    let _content_owner = match iteron_record::acquire_verified_rollout_owner(&rollout_path) {
        Ok(owner) => owner,
        Err(error) => {
            return vec![Action::Notice(
                block::NoticeLevel::Err,
                format!("cannot acquire checkpoint content gate: {error}"),
            )];
        }
    };
    let runs = rollout_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let stem = rollout_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_owned();
    let events = match iteron_record::load_forked(&runs, &iteron_protocol::RunId(stem.clone())) {
        Ok(events) => events,
        Err(error) => {
            return vec![Action::Notice(
                block::NoticeLevel::Err,
                format!("cannot read this session: {error}"),
            )];
        }
    };
    let request = match crate::workspace_review::parse_rewind_request(&argument) {
        Ok(Some(request)) => request,
        Ok(None) => {
            let mut rows = vec![block::PanelRow::Note(
                "preview: /rewind SEQ [all|code|conversation] [keep|delete] · add `apply` to execute"
                    .into(),
            )];
            for event in events
                .iter()
                .rev()
                .filter(|event| {
                    matches!(
                        event.kind,
                        iteron_protocol::EventKind::Checkpoint { .. }
                            | iteron_protocol::EventKind::TurnStart
                    )
                })
                .take(iteron_tunables::param_integer(
                    "cli.tui.workspace_command.rewind_target_rows",
                    REWIND_TARGET_ROWS,
                ))
            {
                let kind = if matches!(event.kind, iteron_protocol::EventKind::Checkpoint { .. }) {
                    "files + conversation"
                } else {
                    "conversation"
                };
                rows.push(item(
                    "•",
                    &format!("seq {}", event.seq.0),
                    &format!("turn {} · {kind}", event.turn.0),
                ));
            }
            return vec![Action::Panel {
                glyph: "↩",
                title: "rewind points",
                rows,
            }];
        }
        Err(error) => return vec![Action::Notice(block::NoticeLevel::Err, error)],
    };
    let tail = events.last().map(|event| event.seq.0).unwrap_or_default();
    if request.at.0 > tail {
        return vec![Action::Notice(
            block::NoticeLevel::Err,
            format!("rewind seq {} is past this run's tail {tail}", request.at.0),
        )];
    }
    let run = iteron_protocol::RunId(stem);
    let snapshot = crate::workspace_review::checkpoint_at_or_before(&events, &run, request.at);
    let mut actions = Vec::new();
    let mut file_preview = None;
    if request.scope.touches_files() {
        let Some(snapshot) = snapshot.as_ref() else {
            return vec![Action::Notice(
                block::NoticeLevel::Err,
                "no workspace checkpoint exists at or before that sequence".into(),
            )];
        };
        let review = match crate::workspace_review::observe(&workspace).await {
            Ok(review) => review,
            Err(error) => return vec![Action::Notice(block::NoticeLevel::Err, error)],
        };
        let preview = match crate::workspace_review::preview_restore(
            &review,
            snapshot,
            &workspace,
            request.scope,
            request.unrecorded,
        ) {
            Ok(preview) => preview,
            Err(error) => return vec![Action::Notice(block::NoticeLevel::Err, error)],
        };
        let mut rows = vec![block::PanelRow::Note(preview.describe())];
        rows.push(kv("checkpoint", &format!("seq {}", snapshot.at.0)));
        rows.push(kv(
            "result",
            if preview.inexact { "overlay" } else { "exact" },
        ));
        rows.push(kv(
            "evidence",
            if preview.is_conclusive() {
                "complete"
            } else {
                "incomplete — destructive apply refused"
            },
        ));
        for entry in preview
            .irrecoverable()
            .iter()
            .take(iteron_tunables::param_integer(
                "cli.tui.workspace_command.irrecoverable_preview_rows",
                IRRECOVERABLE_PREVIEW_ROWS,
            ))
        {
            rows.push(item("−", &entry.path, "would be deleted"));
        }
        actions.push(Action::Panel {
            glyph: "↩",
            title: "rewind preview",
            rows,
        });
        file_preview = Some(preview);
    } else {
        actions.push(Action::Panel {
            glyph: "↩",
            title: "rewind preview",
            rows: vec![block::PanelRow::Note(format!(
                "conversation branches at seq {}; no file is touched",
                request.at.0
            ))],
        });
    }
    if request.disposition == crate::workspace_review::RewindDisposition::Preview {
        actions.push(Action::Notice(
            block::NoticeLevel::Info,
            format!(
                "preview only · repeat `/rewind {} {} {} apply` to proceed",
                request.at.0,
                match request.scope {
                    iteron_changeset::Scope::CodeAndConversation => "all",
                    iteron_changeset::Scope::CodeOnly => "code",
                    iteron_changeset::Scope::ConversationOnly => "conversation",
                },
                match request.unrecorded {
                    iteron_changeset::Unrecorded::Keep => "keep",
                    iteron_changeset::Unrecorded::Delete => "delete",
                }
            ),
        ));
        return actions;
    }
    if request.unrecorded == iteron_changeset::Unrecorded::Delete
        && file_preview
            .as_ref()
            .is_some_and(|preview| !preview.is_conclusive())
    {
        actions.push(Action::Notice(
            block::NoticeLevel::Err,
            "destructive rewind refused because the preview was incomplete".into(),
        ));
        return actions;
    }
    let safety = if request.scope.touches_files() {
        let safety_run = iteron_protocol::RunId(format!("rewind-safety-{}", run.0));
        match iteron_record::checkpoint_excluding_runtime_state(
            &safety_run,
            iteron_protocol::Seq(tail.saturating_add(1)),
            &workspace,
            &runs,
        ) {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                actions.push(Action::Notice(
                    block::NoticeLevel::Err,
                    format!("could not create pre-rewind safety checkpoint: {error}"),
                ));
                return actions;
            }
        }
    } else {
        None
    };
    if let Some(target) = snapshot.as_ref()
        && let Err(error) = iteron_record::rewind_workspace_with_policy(
            target,
            &workspace,
            request.unrecorded == iteron_changeset::Unrecorded::Delete,
        )
    {
        let rollback = safety
            .as_ref()
            .map(|safety| iteron_record::rewind_workspace_with_policy(safety, &workspace, true));
        actions.push(Action::Notice(
            block::NoticeLevel::Err,
            format!("workspace rewind failed: {error}; safety rollback: {rollback:?}"),
        ));
        return actions;
    }
    if request.scope.touches_conversation() {
        match iteron_record::fork(
            &runs,
            &run,
            request.at,
            &iteron_protocol::TenantId::default(),
        ) {
            Ok(child) => {
                actions.push(Action::Notice(
                    block::NoticeLevel::Ok,
                    format!("rewound to seq {} · adopting {child}", request.at.0),
                ));
                actions.push(Action::Adopt(child.0));
            }
            Err(error) => {
                if let Some(safety) = safety.as_ref() {
                    let _ = iteron_record::rewind_workspace_with_policy(safety, &workspace, true);
                }
                actions.push(Action::Notice(
                    block::NoticeLevel::Err,
                    format!("conversation rewind failed: {error}"),
                ));
            }
        }
    } else {
        actions.push(Action::Notice(
            block::NoticeLevel::Ok,
            format!(
                "workspace restored to checkpoint seq {} · conversation kept",
                snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.at.0)
                    .unwrap_or_default()
            ),
        ));
    }
    actions
}

//! Private scoped workspace presentation and host restore observation.
//! Native rewind authorization, provider/record construction and file mutation belong to host.
use super::{App, ProviderCatalogView, Session, block};
use crate::app_server::{Control, ControlReply, ControlRequest, NavigatedSession};
use iteron_protocol::{RunId, SessionId, product_contract::ThreadSnapshotV1};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
mod rewind_view;

const WORKSPACE_REVIEW_SUMMARY_ROWS: usize = 120;
pub(super) enum Action {
    Notice(block::NoticeLevel, String),
    Panel {
        glyph: &'static str,
        title: &'static str,
        rows: Vec<block::PanelRow>,
    },
    Diff(iteron_protocol::FileDiff),
    Adopt(Box<NavigatedSession>),
}
#[derive(Clone)]
struct Scope {
    thread: SessionId,
    run: RunId,
}
impl Scope {
    fn capture(view: &ThreadSnapshotV1) -> Self {
        Self {
            thread: view.thread_id.clone(),
            run: view.run_id.clone(),
        }
    }
    fn matches(&self, view: &ThreadSnapshotV1) -> bool {
        self.thread == view.thread_id && self.run == view.run_id
    }
}
struct Completion {
    scope: Option<Scope>,
    actions: Vec<Action>,
}
#[derive(Default)]
pub(super) struct WorkspaceCommands {
    job: Option<JoinHandle<Completion>>,
    cancel: Option<Arc<AtomicBool>>,
}
impl WorkspaceCommands {
    pub(super) fn is_busy(&self) -> bool {
        self.job.is_some()
    }
    pub(super) fn cancel(&self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Release);
        }
    }
    pub(super) fn close(&mut self) {
        self.cancel();
        if self.cancel.is_none()
            && let Some(job) = self.job.take()
        {
            job.abort();
        }
        // A restore observer can detach; its host work still owns all admission and native leases.
        self.job = None;
        self.cancel = None;
    }
    pub(super) async fn poll(&mut self, current: Option<&ThreadSnapshotV1>) -> Option<Vec<Action>> {
        if !self.job.as_ref().is_some_and(|job| job.is_finished()) {
            return None;
        }
        let result = self.job.take().expect("finished workspace observer").await;
        self.cancel = None;
        let completion=match result {
            Ok(completion)=>completion,
            Err(_)=>return Some(vec![Action::Notice(block::NoticeLevel::Err,"workspace observer ended without a host result; inspect actual state before retrying".into())]),
        };
        if let Some(scope) = completion.scope {
            let selected = completion.actions.iter().find_map(|action| match action {
                Action::Adopt(reply) => Some(&reply.presentation),
                _ => None,
            });
            let matches = current.is_some_and(|current| match selected {
                Some(fact) => {
                    fact.version == 1
                        && fact.thread_id == scope.thread
                        && fact.origin_run_id == scope.run
                        && current.thread_id == scope.thread
                        && current.run_id == fact.run_id
                }
                None => scope.matches(current),
            });
            if !matches {
                return Some(vec![Action::Notice(block::NoticeLevel::Warn,"workspace reply belongs to a previous selection; current host state remains authoritative".into())]);
            }
        }
        Some(completion.actions)
    }
}
impl Drop for WorkspaceCommands {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) fn queue_diff(app: &mut App, session: &Session, stat: bool) {
    let Some(view) = session.client.thread_snapshot_v1() else {
        app.note(block::NoticeLevel::Err, "workspace scope unavailable");
        return;
    };
    let workspace = session.workspace().to_path_buf();
    queue(
        app,
        "workspace review",
        Some(Scope::capture(&view)),
        async move {
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
                            Err(error) => {
                                actions.push(Action::Notice(block::NoticeLevel::Err, error))
                            }
                        }
                    }
                    actions
                }
                Err(error) => vec![Action::Notice(
                    block::NoticeLevel::Err,
                    format!("could not read complete bounded change set: {error}"),
                )],
            }
        },
    );
}

pub(super) fn queue_rewind(app: &mut App, session: &Session, argument: String) {
    if app.workspace_commands.is_busy() {
        app.note(
            block::NoticeLevel::Warn,
            "another workspace command is pending",
        );
        return;
    }
    let Some(view) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Err,
            "workspace session scope unavailable",
        );
        return;
    };
    let command = match rewind_view::parse(&view, &argument) {
        Ok(command) => command,
        Err(reason) => {
            app.note(block::NoticeLevel::Err, reason);
            return;
        }
    };
    let scope = Scope::capture(&view);
    let cancel = Arc::new(AtomicBool::new(false));
    app.workspace_commands.cancel = Some(cancel.clone());
    let sender = session.control_sender();
    app.status = "rewind pending…".into();
    app.workspace_commands.job = Some(tokio::spawn(async move {
        let actions = match request(sender, command, cancel).await {
            Ok(reply) => rewind_view::project(reply),
            Err(reason) => vec![Action::Notice(block::NoticeLevel::Err, reason)],
        };
        Completion {
            scope: Some(scope),
            actions,
        }
    }));
}
async fn request(
    sender: mpsc::Sender<ControlRequest>,
    command: iteron_protocol::workspace_rewind::WorkspaceRewindCommandV1,
    cancel: Arc<AtomicBool>,
) -> Result<crate::app_server::WorkspaceRewound, String> {
    let (reply, received) = oneshot::channel();
    sender
        .send(ControlRequest {
            control: Control::WorkspaceRewind {
                command,
                cancel: Some(cancel),
            },
            reply,
        })
        .await
        .map_err(|_| "workspace host stopped before rewind admission".to_owned())?;
    match received.await.map_err(|_| {
        "workspace host ended without a rewind result; reconcile actual state before retry"
            .to_owned()
    })? {
        ControlReply::WorkspaceRewound(reply) => Ok(*reply),
        ControlReply::Refused(reason) => Err(reason),
        _ => Err("workspace host returned an incompatible rewind result".into()),
    }
}
fn queue<F>(app: &mut App, label: &'static str, scope: Option<Scope>, future: F)
where
    F: Future<Output = Vec<Action>> + Send + 'static,
{
    if app.workspace_commands.is_busy() {
        app.note(
            block::NoticeLevel::Warn,
            "another workspace command is pending",
        );
        return;
    }
    app.status = format!("{label} pending…");
    app.workspace_commands.job = Some(tokio::spawn(async move {
        Completion {
            scope,
            actions: future.await,
        }
    }));
}
pub(super) fn apply(
    app: &mut App,
    session: &mut Session,
    directory: &ProviderCatalogView,
    actions: Vec<Action>,
) {
    for action in actions {
        match action {
            Action::Notice(level, message) => app.note(level, message),
            Action::Panel { glyph, title, rows } => app.panel(glyph, title, rows),
            Action::Diff(diff) => {
                app.push_block(block::BlockKind::Diff(diff));
            }
            Action::Adopt(reply) => {
                super::session_adoption::apply_navigated_session(app, session, directory, *reply)
            }
        }
    }
}

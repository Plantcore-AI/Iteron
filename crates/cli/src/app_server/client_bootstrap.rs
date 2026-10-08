//! Trusted startup hydration. Frontends receive state and a bounded writer port, never native
//! record paths, a prompt-history Store constructor, or permission to choose source-run lineage.
use super::product_contract::ContractReader;
use crate::config::PromptHistoryMode;
use crate::prompt_history::{self, State, Store, Writer};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct ClientBootstrapFactory {
    workspace: PathBuf,
    runs_dir: Option<PathBuf>,
    config_home: Option<PathBuf>,
    reader: ContractReader,
    busy: AtomicBool,
    published: AtomicBool,
    #[cfg(test)]
    worker_pause: std::sync::Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

pub(crate) struct PreparedClientBootstrap {
    owner: Arc<ClientBootstrapFactory>,
    thread_id: SessionId,
    source_run: RunId,
    state: Option<State>,
    store: Option<Store>,
    workflows: crate::workflow::RestoredWorkflowInventory,
    warning: Option<String>,
}

pub(crate) struct InstalledClientBootstrap {
    pub(crate) source_run: RunId,
    pub(crate) state: Option<State>,
    pub(crate) writer: PromptHistoryWriterPort,
    pub(crate) workflows: crate::workflow::RestoredWorkflowInventory,
    pub(crate) warning: Option<String>,
}

pub(crate) struct PromptHistoryWriterPort {
    writer: Option<Writer>,
    reader: Option<ContractReader>,
}

impl ClientBootstrapFactory {
    pub(super) fn capture(agent: &Agent, reader: ContractReader) -> Arc<Self> {
        Arc::new(Self {
            workspace: agent.workspace.clone(),
            runs_dir: agent
                .rollout
                .path()
                .parent()
                .map(std::path::Path::to_path_buf),
            config_home: crate::config::config_home(),
            reader,
            busy: AtomicBool::new(false),
            published: AtomicBool::new(false),
            #[cfg(test)]
            worker_pause: std::sync::Mutex::new(None),
        })
    }

    pub(crate) async fn hydrate(
        self: Arc<Self>,
        mode: PromptHistoryMode,
    ) -> Result<PreparedClientBootstrap, &'static str> {
        if self.published.load(Ordering::Acquire) {
            return Err("session startup writer was already installed");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("session startup hydration is already running");
        }
        let admitted = HydrationPermit(self);
        if admitted.0.published.load(Ordering::Acquire) {
            return Err("session startup writer was already installed");
        }
        // The physical worker owns the permit. Dropping its observer cannot admit another worker
        // while a filesystem/content-store operation is still in flight.
        tokio::task::spawn_blocking(move || {
            let owner = &admitted.0;
            let scope = owner
                .reader
                .snapshot()
                .ok_or("session startup scope is unavailable")?;
            #[cfg(test)]
            if let Some((started, resume)) = owner.worker_pause.lock().unwrap().take() {
                let _ = started.send(());
                let _ = resume.recv();
            }
            let hydrated = prompt_history::bootstrap(
                mode,
                owner.config_home.clone(),
                &owner.workspace,
                owner.runs_dir.clone(),
                Some(scope.run_id.clone()),
            );
            let workflows = owner
                .runs_dir
                .as_ref()
                .map_or_else(Default::default, |runs| {
                    crate::workflow::restored_inventory(
                        &runs.join("subagents").join("workflows"),
                        iteron_tunables::param_integer("cli.tui.workflow_region.restore_limit", 16)
                            .min(16),
                    )
                });
            if owner.reader.snapshot().is_none_or(|current| {
                current.thread_id != scope.thread_id || current.run_id != scope.run_id
            }) {
                return Err(
                    "session changed during startup hydration; restored state was not adopted",
                );
            }
            Ok(PreparedClientBootstrap {
                owner: owner.clone(),
                thread_id: scope.thread_id,
                source_run: scope.run_id,
                state: hydrated.state,
                store: hydrated.store,
                workflows,
                warning: hydrated.warning,
            })
        })
        .await
        .map_err(|_| "session startup worker ended without a receipt")?
    }
}

impl PreparedClientBootstrap {
    /// Installation consumes an actually observed draft. A lost observer drops only read state;
    /// it neither starts a writer nor prevents a later hydration attempt. The projection lock
    /// serializes the final identity check with adoption and the one installation decision.
    pub(crate) fn install(self) -> Result<InstalledClientBootstrap, &'static str> {
        let Self {
            owner,
            thread_id,
            source_run,
            state,
            store,
            workflows,
            warning,
        } = self;
        let expected_run = source_run.clone();
        owner
            .reader
            .with_current_identity(&thread_id, &expected_run, || {
                if owner
                    .published
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Err("session startup writer was already installed");
                }
                let writer = match Writer::new(store) {
                    Ok(writer) => writer,
                    Err(_) => {
                        owner.published.store(false, Ordering::Release);
                        return Err("session startup writer could not be installed");
                    }
                };
                Ok(InstalledClientBootstrap {
                    source_run,
                    state,
                    writer: PromptHistoryWriterPort {
                        writer: Some(writer),
                        reader: Some(owner.reader.clone()),
                    },
                    workflows,
                    warning,
                })
            })
            .unwrap_or(Err(
                "session changed before startup installation; restored state was not adopted",
            ))
    }
}

struct HydrationPermit(Arc<ClientBootstrapFactory>);
impl Drop for HydrationPermit {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

impl PromptHistoryWriterPort {
    pub(crate) fn disabled() -> Self {
        Self {
            writer: None,
            reader: None,
        }
    }
    pub(crate) fn schedule(&self, state: State) -> bool {
        let Some(writer) = &self.writer else {
            return true;
        };
        if !admissible(&state) {
            return false;
        }
        let Some(scope) = self.reader.as_ref().and_then(ContractReader::snapshot) else {
            return false;
        };
        writer.schedule(state, scope.run_id);
        true
    }
    /// The source identity comes from the installed host projection, including actual adoption.
    /// Storage's existing bounded finish keeps a blocked writer detached and reports shutdown debt.
    pub(crate) fn finish_bounded(mut self, state: State) -> bool {
        let Some(writer) = self.writer.take() else {
            return true;
        };
        if !admissible(&state) {
            return false;
        }
        let Some(scope) = self.reader.as_ref().and_then(ContractReader::snapshot) else {
            return false;
        };
        writer.finish_bounded(state, scope.run_id)
    }
}

fn admissible(state: &State) -> bool {
    const MAX_BYTES: usize = 1024 * 1024;
    state.history.len() <= prompt_history::MAX_ENTRIES
        && state
            .history
            .capacity()
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|size| {
                state
                    .history
                    .iter()
                    .try_fold(size, |size, text| size.checked_add(text.capacity()))
            })
            .and_then(|size| size.checked_add(state.draft.as_ref().map_or(0, String::capacity)))
            .is_some_and(|bytes| bytes <= MAX_BYTES)
}

#[cfg(test)]
#[path = "client_bootstrap/tests.rs"]
mod tests;

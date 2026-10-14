//! Opaque metadata read port. Only the trusted host captures root and current read authority.
use super::{activity_control::ActivitySurface, product_contract::ContractReader};
use crate::client_effects::path_completion::{CompletionCache, CompletionRows, CompletionSource};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{RwLock, Semaphore};

struct CompletionService {
    gate: Arc<RwLock<()>>,
    capacity: OnceLock<Arc<Semaphore>>,
    cache: Mutex<(u64, CompletionCache)>,
    closed: AtomicBool,
}
#[derive(Clone)]
pub(super) struct CompletionBinding {
    thread: SessionId,
    run: RunId,
    revision: u64,
    source: CompletionSource,
    service: Arc<CompletionService>,
}
pub(crate) struct PathCompletionPort {
    binding: CompletionBinding,
    reader: ContractReader,
}
impl CompletionBinding {
    pub(super) fn capture(
        agent: &Agent,
        reader: &ContractReader,
        activity: &ActivitySurface,
    ) -> Option<Self> {
        let current = reader.snapshot()?;
        if current.run_id != *agent.rollout.run_id() {
            return None;
        }
        Some(Self {
            thread: current.thread_id,
            run: current.run_id,
            revision: 1,
            source: CompletionSource::capture(agent),
            service: Arc::new(CompletionService {
                gate: activity.client_effect_gate(),
                capacity: OnceLock::new(),
                cache: Mutex::new((0, CompletionCache::default())),
                closed: AtomicBool::new(false),
            }),
        })
    }
    pub(super) fn refreshed(&self, agent: &Agent, thread: SessionId) -> Option<Self> {
        let source = CompletionSource::capture(agent);
        let run = agent.rollout.run_id().clone();
        let revision =
            if self.thread == thread && self.run == run && self.source.equivalent(&source) {
                self.revision
            } else {
                self.revision.checked_add(1)?
            };
        Some(Self {
            thread,
            run,
            revision,
            source,
            service: self.service.clone(),
        })
    }
    pub(super) fn matches(&self, thread: &SessionId, run: &RunId, revision: u64) -> bool {
        self.thread == *thread && self.run == *run && self.revision == revision
    }
    pub(super) async fn shutdown(&self) -> bool {
        self.service.closed.store(true, Ordering::Release);
        let Some(capacity) = self.service.capacity.get() else {
            return true;
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            capacity.clone().acquire_owned(),
        )
        .await
        .is_ok_and(|permit| permit.is_ok())
    }
}
impl PathCompletionPort {
    pub(super) fn capture(
        binding: CompletionBinding,
        reader: ContractReader,
        run: &RunId,
    ) -> Option<Self> {
        (binding.run == *run).then_some(Self { binding, reader })
    }
    pub(crate) async fn complete(self, partial: String) -> Result<CompletionRows, &'static str> {
        if self.binding.service.closed.load(Ordering::Acquire) {
            return Err("completion host is closed");
        }
        if partial.len() > 1024 || partial.capacity() > 2048 {
            return Err("completion input exceeds finite bound");
        }
        let scope = self
            .binding
            .service
            .gate
            .clone()
            .try_read_owned()
            .map_err(|_| "session adoption is pending")?;
        if !self.reader.completion_is_current(
            &self.binding.thread,
            &self.binding.run,
            self.binding.revision,
        ) {
            return Err("completion source is stale");
        }
        let capacity = self
            .binding
            .service
            .capacity
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        let slot = capacity
            .try_acquire_owned()
            .map_err(|_| "physical completion read is still active")?;
        if self.binding.service.closed.load(Ordering::Acquire) {
            return Err("completion host is closed");
        }
        let (reply, observed) = tokio::sync::oneshot::channel();
        // Detached physical work owns the scope and slot even if the UI future is canceled.
        drop(tokio::task::spawn_blocking(move || {
            let result = {
                let mut cache = self
                    .binding
                    .service
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if cache.0 != self.binding.revision {
                    cache.1.clear();
                    cache.0 = self.binding.revision;
                }
                self.binding.source.complete(&partial, &mut cache.1)
            };
            let result = if self.reader.completion_is_current(
                &self.binding.thread,
                &self.binding.run,
                self.binding.revision,
            ) {
                result
            } else {
                Err("completion source changed during native read")
            };
            // The semaphore becomes available only after the physical operation and scope release.
            drop(scope);
            drop(slot);
            let _ = reply.send(result);
        }));
        observed
            .await
            .map_err(|_| "native completion read ended without observation")?
    }
}
#[cfg(test)]
pub(crate) mod tests;

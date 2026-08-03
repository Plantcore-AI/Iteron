//! Single-owner bounded worker for transcript index and detail projections.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use crate::block;

use super::projection::DetailProjection;
use super::{Entry, projection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionKey {
    pub(super) generation: u64,
    pub(super) next: usize,
    pub(super) id: u64,
    pub(super) revision: u64,
    pub(super) remaining: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DetailKey {
    pub(super) authority_revision: u64,
    pub(super) id: u64,
    pub(super) revision: u64,
    pub(super) raw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkKey {
    Index(ProjectionKey),
    Detail(DetailKey),
}

enum ProjectionRequest {
    Index {
        key: ProjectionKey,
        block: Arc<block::Block>,
        cancel: Arc<AtomicBool>,
    },
    Detail {
        key: DetailKey,
        block: Arc<block::Block>,
        cancel: Arc<AtomicBool>,
    },
}

pub(super) enum ProjectionResult {
    Index {
        key: ProjectionKey,
        entry: Result<Entry, ()>,
    },
    Detail {
        key: DetailKey,
        detail: Result<DetailProjection, ()>,
    },
}

struct Channels {
    requests: mpsc::SyncSender<ProjectionRequest>,
    results: mpsc::Receiver<ProjectionResult>,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

struct InFlight {
    key: WorkKey,
    cancel: Arc<AtomicBool>,
}

pub(super) struct ProjectionWorker {
    channels: Option<Channels>,
    in_flight: Option<InFlight>,
    notification: Arc<tokio::sync::Notify>,
}

impl Default for ProjectionWorker {
    fn default() -> Self {
        Self {
            channels: None,
            in_flight: None,
            notification: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

pub(super) enum WorkerPoll {
    Idle,
    Pending,
    Ready(ProjectionResult),
}

impl ProjectionWorker {
    fn ensure_started(&mut self) -> Result<(), ()> {
        if self.channels.is_some() {
            return Ok(());
        }
        let (request_tx, request_rx) = mpsc::sync_channel::<ProjectionRequest>(1);
        let (result_tx, result_rx) = mpsc::sync_channel::<ProjectionResult>(1);
        let notification = self.notification.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let join = std::thread::Builder::new()
            .name("core-transcript-projection".into())
            .spawn(move || {
                while !worker_shutdown.load(Ordering::Relaxed) {
                    let Ok(request) = request_rx.recv() else {
                        return;
                    };
                    let result = match request {
                        ProjectionRequest::Index { key, block, cancel } => {
                            let entry = catch_unwind(AssertUnwindSafe(|| {
                                projection::index_block(&block, key.remaining, &cancel)
                            }))
                            .unwrap_or(Err(()));
                            ProjectionResult::Index { key, entry }
                        }
                        ProjectionRequest::Detail { key, block, cancel } => {
                            let detail = catch_unwind(AssertUnwindSafe(|| {
                                projection::detail_block(&block, key.raw, &cancel)
                            }))
                            .unwrap_or(Err(()));
                            ProjectionResult::Detail { key, detail }
                        }
                    };
                    match result_tx.try_send(result) {
                        Ok(()) => notification.notify_one(),
                        // Full contradicts the one-request/one-result invariant; disconnect means
                        // close already revoked the receiver. Either way, terminate instead of
                        // blocking a join on a result nobody can consume.
                        Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => {
                            return;
                        }
                    }
                }
            })
            .map_err(|_| ())?;
        self.channels = Some(Channels {
            requests: request_tx,
            results: result_rx,
            shutdown,
            join: Some(join),
        });
        Ok(())
    }

    pub(super) fn start_index(
        &mut self,
        key: ProjectionKey,
        block: Arc<block::Block>,
    ) -> Result<(), ()> {
        self.start(WorkKey::Index(key), |cancel| ProjectionRequest::Index {
            key,
            block,
            cancel,
        })
    }

    pub(super) fn start_detail(
        &mut self,
        key: DetailKey,
        block: Arc<block::Block>,
    ) -> Result<(), ()> {
        self.start(WorkKey::Detail(key), |cancel| ProjectionRequest::Detail {
            key,
            block,
            cancel,
        })
    }

    fn start(
        &mut self,
        key: WorkKey,
        request: impl FnOnce(Arc<AtomicBool>) -> ProjectionRequest,
    ) -> Result<(), ()> {
        debug_assert!(self.in_flight.is_none());
        self.ensure_started()?;
        let cancel = Arc::new(AtomicBool::new(false));
        if self
            .channels
            .as_ref()
            .expect("worker channels were started")
            .requests
            .try_send(request(cancel.clone()))
            .is_err()
        {
            self.close();
            return Err(());
        }
        self.in_flight = Some(InFlight { key, cancel });
        Ok(())
    }

    pub(super) fn cancel_in_flight(&self) {
        if let Some(in_flight) = &self.in_flight {
            in_flight.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub(super) fn in_flight_key(&self) -> Option<WorkKey> {
        self.in_flight.as_ref().map(|in_flight| in_flight.key)
    }

    pub(super) fn poll(&mut self) -> WorkerPoll {
        let Some(in_flight) = &self.in_flight else {
            return WorkerPoll::Idle;
        };
        let result = self
            .channels
            .as_ref()
            .expect("an in-flight worker has channels")
            .results
            .try_recv();
        match result {
            Ok(result) => {
                self.in_flight = None;
                WorkerPoll::Ready(result)
            }
            Err(mpsc::TryRecvError::Empty) => WorkerPoll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => {
                let key = in_flight.key;
                self.in_flight = None;
                self.close();
                WorkerPoll::Ready(match key {
                    WorkKey::Index(key) => ProjectionResult::Index {
                        key,
                        entry: Err(()),
                    },
                    WorkKey::Detail(key) => ProjectionResult::Detail {
                        key,
                        detail: Err(()),
                    },
                })
            }
        }
    }

    pub(super) fn is_busy(&self) -> bool {
        self.in_flight.is_some()
    }

    #[cfg(test)]
    pub(super) fn owns_join_handle(&self) -> bool {
        self.channels
            .as_ref()
            .and_then(|channels| channels.join.as_ref())
            .is_some()
    }

    pub(super) fn notification(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.is_busy().then(|| self.notification.clone())
    }

    pub(super) fn close(&mut self) {
        self.cancel_in_flight();
        self.in_flight = None;
        let Some(mut channels) = self.channels.take() else {
            return;
        };
        channels.shutdown.store(true, Ordering::Relaxed);
        drop(channels.requests);
        drop(channels.results);
        if let Some(join) = channels.join.take() {
            // Every worker operation is byte-capped and observes either its request cancellation or
            // the shutdown token between collection elements. Result delivery is non-blocking, so
            // this ownership join has no channel or unbounded-source hang path.
            let _ = join.join();
        }
    }
}

impl Drop for ProjectionWorker {
    fn drop(&mut self) {
        self.close();
    }
}

//! Single bounded background worker for expensive per-block search projection.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, mpsc};

use crate::block;

use super::{Entry, projection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionKey {
    pub(super) generation: u64,
    pub(super) next: usize,
    pub(super) id: u64,
    pub(super) revision: u64,
    pub(super) remaining: usize,
}

struct ProjectionRequest {
    key: ProjectionKey,
    block: Arc<block::Block>,
}

pub(super) struct ProjectionResult {
    pub(super) key: ProjectionKey,
    pub(super) entry: Result<Entry, ()>,
}

struct Channels {
    requests: mpsc::SyncSender<ProjectionRequest>,
    results: mpsc::Receiver<ProjectionResult>,
}

pub(super) struct ProjectionWorker {
    channels: Option<Channels>,
    in_flight: Option<ProjectionKey>,
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
        std::thread::Builder::new()
            .name("core-transcript-index".into())
            .spawn(move || {
                while let Ok(request) = request_rx.recv() {
                    let entry = catch_unwind(AssertUnwindSafe(|| {
                        projection::index_block(&request.block, request.key.remaining)
                    }))
                    .map_err(|_| ());
                    if result_tx
                        .send(ProjectionResult {
                            key: request.key,
                            entry,
                        })
                        .is_err()
                    {
                        return;
                    }
                    notification.notify_one();
                }
            })
            .map_err(|_| ())?;
        self.channels = Some(Channels {
            requests: request_tx,
            results: result_rx,
        });
        Ok(())
    }

    pub(super) fn start(&mut self, key: ProjectionKey, block: Arc<block::Block>) -> Result<(), ()> {
        debug_assert!(self.in_flight.is_none());
        self.ensure_started()?;
        let request = ProjectionRequest { key, block };
        if self
            .channels
            .as_ref()
            .expect("worker channels were started")
            .requests
            .try_send(request)
            .is_err()
        {
            self.channels = None;
            return Err(());
        }
        self.in_flight = Some(key);
        Ok(())
    }

    pub(super) fn poll(&mut self) -> WorkerPoll {
        if self.in_flight.is_none() {
            return WorkerPoll::Idle;
        }
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
                let key = self.in_flight.take().expect("in-flight key");
                self.channels = None;
                WorkerPoll::Ready(ProjectionResult {
                    key,
                    entry: Err(()),
                })
            }
        }
    }

    pub(super) fn is_busy(&self) -> bool {
        self.in_flight.is_some()
    }

    pub(super) fn notification(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.is_busy().then(|| self.notification.clone())
    }
}

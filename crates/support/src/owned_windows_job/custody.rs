//! Bounded physical custody when a caller drops an unknown launch or an active future.
//! This worker publishes no model result, budget settlement, effect receipt or permission.

use super::{OwnedWindowsJob, conpty::NativeLaunchRetirement, native_process::NativeProcess};
use std::io;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

const MAX_CUSTODIES: usize = 64;
const POLL: Duration = Duration::from_millis(50);

struct Pool {
    queue: mpsc::SyncSender<Pending>,
    held: AtomicUsize,
    healthy: Arc<AtomicBool>,
    // A broken queue cannot drop still-owned native handles. Its admitted population is already
    // bounded; retain it and close all further native admission instead of fabricating cleanup.
    quarantined: Mutex<Vec<Pending>>,
}
static POOL: OnceLock<Result<Arc<Pool>, &'static str>> = OnceLock::new();

pub(super) struct Admission {
    pool: Arc<Pool>,
}

impl Admission {
    pub(super) fn acquire() -> io::Result<Self> {
        let pool = POOL
            .get_or_init(start)
            .as_ref()
            .map_err(|reason| io::Error::other(*reason))?
            .clone();
        if !pool.healthy.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "Windows physical custody worker unavailable",
            ));
        }
        pool.held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(1).filter(|count| *count <= MAX_CUSTODIES)
            })
            .map_err(|_| io::Error::other("Windows physical custody capacity exhausted"))?;
        if !pool.healthy.load(Ordering::Acquire) {
            pool.held.fetch_sub(1, Ordering::AcqRel);
            return Err(io::Error::other(
                "Windows physical custody worker unavailable",
            ));
        }
        Ok(Self { pool })
    }

    pub(super) fn defer(
        self,
        child: Option<Child>,
        job: Arc<OwnedWindowsJob>,
        wait_observed: bool,
    ) {
        let pool = self.pool.clone();
        let pending = Pending {
            child: child.map(PendingChild::Standard),
            job,
            wait_observed,
            admission: Some(self),
            closed: false,
            native_retirement: None,
        };
        if let Err(error) = pool.queue.try_send(pending) {
            pool.healthy.store(false, Ordering::Release);
            let pending = match error {
                mpsc::TrySendError::Full(pending) | mpsc::TrySendError::Disconnected(pending) => {
                    pending
                }
            };
            // All live/queued/quarantined values own the same pre-spawn admission bound. Thus
            // this vector cannot exceed 64 even if the worker fails after native dispatch.
            pool.quarantined
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(pending);
        }
    }
    pub(super) fn defer_native(
        self,
        child: Option<NativeProcess>,
        job: Arc<OwnedWindowsJob>,
        wait_observed: bool,
        native_retirement: Option<NativeLaunchRetirement>,
    ) {
        let pool = self.pool.clone();
        let pending = Pending {
            child: child.map(PendingChild::Native),
            job,
            wait_observed,
            admission: Some(self),
            closed: false,
            native_retirement,
        };
        if let Err(error) = pool.queue.try_send(pending) {
            pool.healthy.store(false, Ordering::Release);
            let pending = match error {
                mpsc::TrySendError::Full(value) | mpsc::TrySendError::Disconnected(value) => value,
            };
            pool.quarantined
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(pending);
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.pool.held.fetch_sub(1, Ordering::AcqRel);
    }
}

enum PendingChild {
    Standard(Child),
    Native(NativeProcess),
}
impl PendingChild {
    fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Standard(child) => child.kill(),
            Self::Native(child) => child.kill(),
        }
    }
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        match self {
            Self::Standard(child) => child.try_wait(),
            Self::Native(child) => child.try_wait(),
        }
    }
}

struct Pending {
    child: Option<PendingChild>,
    job: Arc<OwnedWindowsJob>,
    wait_observed: bool,
    admission: Option<Admission>,
    closed: bool,
    native_retirement: Option<NativeLaunchRetirement>,
}
impl Pending {
    fn completed(&mut self) -> bool {
        // Kill uses only the private Job or exact retained process handle. A failed assignment
        // can leave an unassigned suspended process, so Job termination alone is insufficient.
        let _ = self.job.terminate();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            if matches!(child.try_wait(), Ok(Some(_))) {
                self.wait_observed = true;
                self.child = None; // Release the actual process reference after real wait.
            }
        }
        let physical_closed = self.wait_observed
            && self.child.is_none()
            && self.job.active_processes().ok() == Some(0);
        self.closed = physical_closed
            && self.native_retirement.as_mut().is_none_or(|retirement| {
                retirement.begin_close();
                retirement.retire()
            });
        self.closed
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let _ = self.job.terminate();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
        // Panic/receiver teardown cannot silently discard an unassigned suspended process.
        // Stop new admission and move its exact still-owned handles to the bounded fallback.
        if let Some(admission) = self.admission.take() {
            let pool = admission.pool.clone();
            pool.healthy.store(false, Ordering::Release);
            let retained = Self {
                child: self.child.take(),
                job: self.job.clone(),
                wait_observed: self.wait_observed,
                admission: Some(admission),
                closed: false,
                native_retirement: self.native_retirement.take(),
            };
            pool.quarantined
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(retained);
        }
    }
}

fn start() -> Result<Arc<Pool>, &'static str> {
    let (queue, receiver) = mpsc::sync_channel(MAX_CUSTODIES);
    let healthy = Arc::new(AtomicBool::new(true));
    let pool = Arc::new(Pool {
        queue,
        healthy: healthy.clone(),
        held: AtomicUsize::new(0),
        quarantined: Mutex::new(Vec::with_capacity(MAX_CUSTODIES)),
    });
    std::thread::Builder::new()
        .name("iteron-windows-custody".into())
        .spawn(move || cleanup(receiver, healthy))
        .map_err(|_| "Windows physical custody worker could not start")?;
    Ok(pool)
}

fn cleanup(receiver: mpsc::Receiver<Pending>, healthy: Arc<AtomicBool>) {
    struct Health(Arc<AtomicBool>);
    impl Drop for Health {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _health = Health(healthy);
    let mut pending: Vec<Pending> = Vec::with_capacity(MAX_CUSTODIES);
    loop {
        // No pending custody means no periodic OS probes or idle polling. One worker waits for
        // its bounded queue. Unknown ownership remains until its real receipts can be obtained.
        let received = if pending.is_empty() {
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        } else {
            receiver.recv_timeout(POLL)
        };
        match received {
            Ok(next) => pending.push(next),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        for _ in pending.len()..MAX_CUSTODIES {
            match receiver.try_recv() {
                Ok(next) => pending.push(next),
                Err(_) => break,
            }
        }
        // Each pass has at most 64 nonblocking retained-handle polls. A persistent OS refusal
        // keeps its admission slot and handles; elapsed time alone cannot release custody.
        pending.retain_mut(|entry| !entry.completed());
    }
}

//! Actual ConPTY capability and bounded retirement workers. ClosePseudoConsole may block while
//! flushing its final frame, so no async executor or caller Drop performs that synchronous call.
//! Every admitted console owns one pre-created worker until the native close really returns.
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;
use tokio::sync::Notify;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};

const MAX_CONSOLES: usize = 64;
const MAX_DIMENSION: u16 = 4096;

struct Pool {
    held: AtomicUsize,
    healthy: AtomicBool,
    quarantined: Mutex<Vec<HPCON>>,
}
static POOL: OnceLock<Arc<Pool>> = OnceLock::new();

struct Completion {
    closed: AtomicBool,
    notify: Notify,
}

pub(super) struct Console {
    active: Mutex<Option<HPCON>>,
    close: mpsc::SyncSender<Option<HPCON>>,
    completion: Arc<Completion>,
    pool: Arc<Pool>,
}

impl Console {
    pub(super) fn create(
        input: HANDLE,
        output: HANDLE,
        rows: u16,
        cols: u16,
    ) -> io::Result<Arc<Self>> {
        let size = dimensions(rows, cols)?;
        let pool = POOL
            .get_or_init(|| {
                Arc::new(Pool {
                    held: AtomicUsize::new(0),
                    healthy: AtomicBool::new(true),
                    quarantined: Mutex::new(Vec::with_capacity(MAX_CONSOLES)),
                })
            })
            .clone();
        if !pool.healthy.load(Ordering::Acquire) {
            return Err(io::Error::other("ConPTY retirement worker unavailable"));
        }
        pool.held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1).filter(|count| *count <= MAX_CONSOLES)
            })
            .map_err(|_| io::Error::other("ConPTY physical console capacity exhausted"))?;
        if !pool.healthy.load(Ordering::Acquire) {
            pool.held.fetch_sub(1, Ordering::AcqRel);
            return Err(io::Error::other("ConPTY retirement worker unavailable"));
        }
        let completion = Arc::new(Completion {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        });
        let (close, receiver) = mpsc::sync_channel(1);
        let worker_pool = pool.clone();
        let worker_completion = completion.clone();
        if std::thread::Builder::new()
            .name("iteron-conpty-close".into())
            .spawn(move || {
                struct Health {
                    pool: Arc<Pool>,
                    armed: bool,
                }
                impl Drop for Health {
                    fn drop(&mut self) {
                        if self.armed {
                            self.pool.healthy.store(false, Ordering::Release);
                        }
                    }
                }
                let mut health = Health {
                    pool: worker_pool.clone(),
                    armed: true,
                };
                if let Ok(Some(raw)) = receiver.recv() {
                    // The native handle is moved here exactly once. An unavailable close holds this
                    // worker and its admission; elapsed time cannot release either or prove cleanup.
                    unsafe {
                        ClosePseudoConsole(raw);
                    }
                }
                worker_completion.closed.store(true, Ordering::Release);
                worker_completion.notify.notify_waiters();
                worker_pool.held.fetch_sub(1, Ordering::AcqRel);
                health.armed = false; // Normal retirement is healthy; only panic closes admission.
            })
            .is_err()
        {
            pool.held.fetch_sub(1, Ordering::AcqRel);
            return Err(io::Error::other("ConPTY retirement worker could not start"));
        }
        let mut raw = 0;
        let result = unsafe { CreatePseudoConsole(size, input, output, 0, &mut raw) };
        if result < 0 {
            let _ = close.try_send(None);
            return Err(hresult_error(result));
        }
        Ok(Arc::new(Self {
            active: Mutex::new(Some(raw)),
            close,
            completion,
            pool,
        }))
    }

    pub(super) fn raw(&self) -> io::Result<HPCON> {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ConPTY already closing"))
    }

    pub(super) fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        let size = dimensions(rows, cols)?;
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let raw = active
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ConPTY already closing"))?;
        let result = unsafe { ResizePseudoConsole(raw, size) };
        if result < 0 {
            return Err(hresult_error(result));
        }
        Ok(())
    }

    pub(super) fn begin_close(&self) {
        if let Some(raw) = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            if self.close.try_send(Some(raw)).is_err() {
                // The one worker is pre-admitted and there is exactly one close request. Failure
                // retains the actual handle under the same hard population and refuses new work.
                self.pool.healthy.store(false, Ordering::Release);
                self.pool
                    .quarantined
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(raw);
            }
        }
    }

    pub(super) async fn close_observed(&self, allowance: Duration) -> bool {
        self.begin_close();
        tokio::time::timeout(allowance, async {
            loop {
                let notified = self.completion.notify.notified();
                if self.completion.closed.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    pub(super) fn closed(&self) -> bool {
        self.completion.closed.load(Ordering::Acquire)
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.begin_close();
    }
}

fn dimensions(rows: u16, cols: u16) -> io::Result<COORD> {
    if rows == 0 || cols == 0 || rows > MAX_DIMENSION || cols > MAX_DIMENSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ConPTY dimensions exceed their fixed nonzero envelope",
        ));
    }
    Ok(COORD {
        X: cols as i16,
        Y: rows as i16,
    })
}

fn hresult_error(value: i32) -> io::Error {
    io::Error::from_raw_os_error(value)
}

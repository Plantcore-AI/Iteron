//! Best-effort maintenance, separate from the authoritative record writer.

use std::sync::{OnceLock, mpsc};

type Work = Box<dyn FnOnce() + Send + 'static>;

/// A single bounded FIFO keeps route/calibration snapshots ordered without making the next turn
/// wait for cache fsyncs. These files are advisory; saturation or shutdown may discard a refresh.
pub(super) fn enqueue(work: impl FnOnce() + Send + 'static) -> bool {
    static WORKER: OnceLock<Option<mpsc::SyncSender<Work>>> = OnceLock::new();
    let worker = WORKER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Work>(64);
        std::thread::Builder::new()
            .name("iteron-turn-maintenance".into())
            .spawn(move || {
                for work in receiver {
                    work();
                }
            })
            .ok()
            .map(|_| sender)
    });
    worker
        .as_ref()
        .is_some_and(|sender| sender.try_send(Box::new(work)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_maintenance_does_not_block_the_caller() {
        let (entered, started) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        assert!(enqueue(move || {
            entered.send(()).unwrap();
            let _ = blocked.recv();
        }));
        started
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let (finished, completion) = mpsc::channel();
        assert!(enqueue(move || {
            let _ = finished.send(());
        }));
        assert!(completion.try_recv().is_err());
        release.send(()).unwrap();
        completion
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }
}

//! Fixed physical IO capacity. A blocked native call retains its slot and target lease; no
//! replacement worker is created. Main answers never join or wait on these workers.
use super::{MaintenanceOwner, MaintenanceTask};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
use std::time::{Duration, Instant};

const QUEUE: usize = 64;
const WORKERS: usize = 2;
const TARGETS: usize = 256;
const DEADLINE: Duration = Duration::from_secs(5);
struct Running {
    owner: Weak<MaintenanceOwner>,
    started: Instant,
    reported: Mutex<bool>,
}
impl Running {
    fn inspect_deadline(&self) {
        if self.started.elapsed() < DEADLINE {
            return;
        }
        if let Ok(mut reported) = self.reported.lock()
            && !*reported
            && let Some(owner) = self.owner.upgrade()
        {
            *reported = true;
            owner.deadline_unknown();
        }
    }
    fn finish(&self) {
        if let Ok(mut reported) = self.reported.lock() {
            if *reported && let Some(owner) = self.owner.upgrade() {
                owner.deadline_finished();
            }
            // A late watcher holds an Arc; prevent it from issuing a second timeout observation.
            *reported = true;
        }
    }
}
struct Pool {
    sender: mpsc::SyncSender<(Arc<MaintenanceOwner>, MaintenanceTask)>,
}
fn pool() -> Option<&'static Pool> {
    static POOL: OnceLock<Option<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let (sender, receiver) =
            mpsc::sync_channel::<(Arc<MaintenanceOwner>, MaintenanceTask)>(QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        let targets = Arc::new(Mutex::new(BTreeSet::new()));
        let active = Arc::new(Mutex::new(Vec::<Weak<Running>>::new()));
        for _ in 0..WORKERS {
            let receiver = receiver.clone();
            let targets = targets.clone();
            let active = active.clone();
            std::thread::Builder::new()
                .name("iteron-advisory-writer".into())
                .spawn(move || {
                    loop {
                        let work = receiver
                            .lock()
                            .ok()
                            .and_then(|receiver| receiver.recv().ok());
                        let Some((owner, task)) = work else {
                            break;
                        };
                        let running = Arc::new(Running {
                            owner: Arc::downgrade(&owner),
                            started: Instant::now(),
                            reported: Mutex::new(false),
                        });
                        if let Ok(mut active) = active.lock() {
                            active.retain(|item| item.strong_count() > 0);
                            active.push(Arc::downgrade(&running));
                        }
                        let target = task.target_sha256.clone();
                        let claimed = targets.lock().is_ok_and(|mut targets| {
                            targets.len() < TARGETS && targets.insert(target.clone())
                        });
                        let known = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if !claimed {
                                owner.reject(task, "target_writer_busy");
                                true
                            } else {
                                owner.execute(task)
                            }
                        }))
                        .unwrap_or_else(|_| {
                            owner.worker_panicked();
                            false
                        });
                        if claimed
                            && known
                            && let Ok(mut targets) = targets.lock()
                        {
                            targets.remove(&target);
                        }
                        // Unknown retains its bounded target key. If a native call never returned, this
                        // point is never reached and its physical worker/cross-process lease stay live.
                        running.finish();
                        drop(running);
                    }
                })
                .ok()?;
        }
        let observed = active;
        std::thread::Builder::new()
            .name("iteron-advisory-deadline".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    let running = observed
                        .lock()
                        .map(|mut items| {
                            items.retain(|item| item.strong_count() > 0);
                            items.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    for running in running {
                        running.inspect_deadline();
                    }
                }
            })
            .ok()?;
        Some(Pool { sender })
    })
    .as_ref()
}
pub(super) fn enqueue(owner: Arc<MaintenanceOwner>, task: MaintenanceTask) -> bool {
    pool().is_some_and(|pool| pool.sender.try_send((owner, task)).is_ok())
}

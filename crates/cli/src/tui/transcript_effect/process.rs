//! Exact subprocess ownership with finite, truthful owner-drop cleanup.

use std::collections::HashMap;
use std::future::{Future as _, poll_fn};
use std::io;
use std::process::ExitStatus;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const SYNC_REAP_POLLS: usize = 64;
const SYNC_REAP_PAUSE: Duration = Duration::from_millis(1);
const CLOSE_REAP_WAIT: Duration = Duration::from_millis(100);
const CLOSE_REAP_WAKE_LIMIT: usize = 64;

#[derive(Default)]
struct ProcessState {
    closing: bool,
    next_registration: u64,
    children: HashMap<u64, tokio::process::Child>,
    active_reaps: usize,
    completed_unknown_reaps: usize,
}

#[derive(Default)]
struct ProcessRegistryInner {
    state: Mutex<ProcessState>,
    reaps_settled: Condvar,
}

/// Spawn/reap authority shared by every subprocess owned by one effect supervisor.
///
/// The registry owns each `Child`, not merely its reusable numeric pid. A caller receives an opaque
/// ticket for pipes, signalling, and waiting. Both an ordinary cancel-safe wait poll and emergency
/// owner-drop remove the exact child under the same mutex, so there is no interval in which one
/// path can reap a process and the other can signal a newly reused pid.
#[derive(Clone, Default)]
pub(in crate::tui) struct ProcessRegistry(Arc<ProcessRegistryInner>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tui) enum ReapOutcome {
    Reaped,
    AlreadySettled,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tui) struct CloseReport {
    pub(in crate::tui) claimed: usize,
    pub(in crate::tui) reaped: usize,
    pub(in crate::tui) unknown: usize,
}

/// Non-cloneable authority for one child stored in [`ProcessRegistry`]. Dropping a live ticket
/// signals and bounded-waits that exact stored `Child`; lack of exit evidence remains unknown.
pub(in crate::tui) struct RegisteredChild {
    registry: ProcessRegistry,
    registration: u64,
    #[cfg(all(test, unix))]
    pid: Option<u32>,
    active: bool,
}

impl ProcessRegistry {
    fn lock(&self) -> MutexGuard<'_, ProcessState> {
        self.0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(in crate::tui) fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> io::Result<RegisteredChild> {
        let mut state = self.lock();
        if state.closing {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "effect supervisor is closing",
            ));
        }
        let registration = state.next_registration;
        state.next_registration = state.next_registration.checked_add(1).ok_or_else(|| {
            io::Error::other("effect child registration space has been exhausted")
        })?;
        // The registry, rather than Tokio's drop guard, owns kill-and-join. This is essential: a
        // late `kill_on_drop` would contain only a numeric pid after emergency wait had reaped it.
        command.kill_on_drop(false);
        let child = command.spawn()?;
        #[cfg(all(test, unix))]
        let pid = child.id();
        state.children.insert(registration, child);
        Ok(RegisteredChild {
            registry: self.clone(),
            registration,
            #[cfg(all(test, unix))]
            pid,
            active: true,
        })
    }

    fn poll_wait(
        &self,
        registration: u64,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<ExitStatus>> {
        let mut state = self.lock();
        let polled = {
            let Some(child) = state.children.get_mut(&registration) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "effect child ownership was already settled",
                )));
            };
            let mut wait = Box::pin(child.wait());
            wait.as_mut().poll(context)
        };
        if matches!(&polled, Poll::Ready(Ok(_))) {
            state.children.remove(&registration);
        }
        polled
    }

    fn reap_registration(&self, registration: u64) -> ReapOutcome {
        let child = {
            let mut state = self.lock();
            let Some(child) = state.children.remove(&registration) else {
                return ReapOutcome::AlreadySettled;
            };
            state.active_reaps = state.active_reaps.saturating_add(1);
            child
        };
        // The exact `Child` moves out under the ownership mutex, but the bounded OS wait never
        // holds that mutex. A concurrent supervisor can observe `active_reaps` and wait on the
        // condition variable instead of deadlocking every other ticket behind a stuck syscall.
        let outcome = kill_and_reap_bounded(child);
        let mut state = self.lock();
        state.active_reaps = state.active_reaps.saturating_sub(1);
        if outcome == ReapOutcome::OutcomeUnknown {
            state.completed_unknown_reaps = state.completed_unknown_reaps.saturating_add(1);
            // A still-live exact handle may have been dropped after the finite evidence budget.
            // Refuse every later spawn so an unknown side effect can never overlap a new one.
            state.closing = true;
        }
        self.0.reaps_settled.notify_all();
        outcome
    }

    /// Close the spawn gate and make one finite cleanup attempt for every exact child handle.
    ///
    /// `unknown` is deliberately truthful: a kernel that does not confirm exit inside the fixed
    /// reap budget is never described as joined. The child handle is dropped only after the one
    /// stable-identity kill attempt and no later cleanup path retains a numeric pid that could be
    /// reused. Concurrent ticket reapers are observed through a finite condition-variable barrier;
    /// the registry mutex is never held during an OS wait.
    pub(in crate::tui) fn close_and_reap(&self) -> CloseReport {
        let (children, prior_unknown_reaps) = {
            let mut state = self.lock();
            state.closing = true;
            let children = std::mem::take(&mut state.children);
            state.active_reaps = state.active_reaps.saturating_add(children.len());
            (children, state.completed_unknown_reaps)
        };
        let count = children.len();
        let mut reaped = 0usize;
        let mut unknown = 0usize;
        for (_, child) in children {
            match kill_and_reap_bounded(child) {
                ReapOutcome::Reaped => reaped = reaped.saturating_add(1),
                ReapOutcome::OutcomeUnknown => unknown = unknown.saturating_add(1),
                ReapOutcome::AlreadySettled => unreachable!("close owned an exact child handle"),
            }
        }
        let mut state = self.lock();
        state.active_reaps = state.active_reaps.saturating_sub(count);
        self.0.reaps_settled.notify_all();
        let deadline = Instant::now() + CLOSE_REAP_WAIT;
        for _ in 0..CLOSE_REAP_WAKE_LIMIT {
            if state.active_reaps == 0 {
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let waited = self
                .0
                .reaps_settled
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = waited.0;
            if waited.1.timed_out() {
                break;
            }
        }
        unknown = unknown
            .saturating_add(
                state
                    .completed_unknown_reaps
                    .saturating_sub(prior_unknown_reaps),
            )
            .saturating_add(state.active_reaps);
        CloseReport {
            claimed: count,
            reaped,
            unknown,
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(in crate::tui) fn is_empty(&self) -> bool {
        self.lock().children.is_empty()
    }
}

impl RegisteredChild {
    #[cfg(all(test, unix))]
    pub(in crate::tui) fn id(&self) -> Option<u32> {
        self.active.then_some(self.pid).flatten()
    }

    pub(in crate::tui) fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.registry
            .lock()
            .children
            .get_mut(&self.registration)
            .and_then(|child| child.stdin.take())
    }

    #[cfg(target_os = "linux")]
    pub(in crate::tui) fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.registry
            .lock()
            .children
            .get_mut(&self.registration)
            .and_then(|child| child.stdout.take())
    }

    pub(in crate::tui) fn start_kill(&mut self) -> io::Result<()> {
        let mut state = self.registry.lock();
        match state.children.get_mut(&self.registration) {
            Some(child) => child.start_kill(),
            None => Ok(()),
        }
    }

    pub(in crate::tui) async fn wait(&mut self) -> io::Result<ExitStatus> {
        let registry = self.registry.clone();
        let registration = self.registration;
        let result = poll_fn(move |context| registry.poll_wait(registration, context)).await;
        if result.is_ok() {
            self.active = false;
        }
        result
    }

    /// Emergency ownership transfer used after an async wait deadline or wait error. Only one of
    /// this method, normal wait completion, or supervisor close can take the stored child.
    pub(in crate::tui) fn reap_sync(&mut self) -> ReapOutcome {
        if !self.active {
            return ReapOutcome::AlreadySettled;
        }
        self.active = false;
        self.registry.reap_registration(self.registration)
    }

    #[cfg(all(test, unix))]
    fn try_wait_with_ready_hook(
        &mut self,
        ready_hook: &mut dyn FnMut(),
    ) -> io::Result<Option<ExitStatus>> {
        let mut state = self.registry.lock();
        let Some(child) = state.children.get_mut(&self.registration) else {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "effect child ownership was already settled",
            ));
        };
        let status = child.try_wait()?;
        if status.is_some() {
            // The adversarial test pauses exactly after OS reap and before map removal. The mutex
            // must keep emergency cleanup from acquiring any stale numeric identity here.
            ready_hook();
            state.children.remove(&self.registration);
            self.active = false;
        }
        Ok(status)
    }
}

impl Drop for RegisteredChild {
    fn drop(&mut self) {
        self.reap_sync();
    }
}

fn kill_and_reap_bounded(mut child: tokio::process::Child) -> ReapOutcome {
    // This signal is issued while the registry still owns the exact unreaped child handle, so its
    // numeric pid cannot have been reused. After this function returns no pid or handle is retained
    // for a later signal. Failure to observe exit is therefore Unknown, never a false Reaped claim.
    let _ = child.start_kill();
    bounded_reap_poll(
        || child.try_wait().map(|status| status.is_some()),
        || std::thread::sleep(SYNC_REAP_PAUSE),
    )
}

fn bounded_reap_poll(
    mut poll: impl FnMut() -> io::Result<bool>,
    mut pause: impl FnMut(),
) -> ReapOutcome {
    for attempt in 0..SYNC_REAP_POLLS {
        match poll() {
            Ok(true) => return ReapOutcome::Reaped,
            Ok(false) => {
                if attempt + 1 < SYNC_REAP_POLLS {
                    pause();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if attempt + 1 < SYNC_REAP_POLLS {
                    pause();
                }
            }
            Err(_) => return ReapOutcome::OutcomeUnknown,
        }
    }
    ReapOutcome::OutcomeUnknown
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::{Barrier, mpsc};

    fn sleep_command(seconds: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("/bin/sleep");
        command
            .arg(seconds)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[tokio::test]
    async fn ready_wait_and_emergency_close_have_one_exclusive_child_owner() {
        let registry = ProcessRegistry::default();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 0"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = registry.spawn(&mut command).expect("spawn short child");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let mut hook = || {
                ready_tx.send(()).expect("announce exact reap gap");
                release_rx.recv().expect("release exact reap gap");
            };
            loop {
                if child
                    .try_wait_with_ready_hook(&mut hook)
                    .expect("coordinated try_wait")
                    .is_some()
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });

        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter reached post-reap critical section");
        let closer_registry = registry.clone();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            attempted_tx.send(()).expect("announce close attempt");
            closed_tx
                .send(closer_registry.close_and_reap())
                .expect("report close count");
        });
        attempted_rx
            .recv()
            .expect("closer attempted ownership lock");
        release_tx.send(()).expect("release waiter");
        waiter.join().expect("waiter thread");
        assert_eq!(
            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .claimed,
            0,
            "normal wait removed the child before emergency close acquired ownership"
        );
        closer.join().expect("closer thread");
    }

    #[tokio::test]
    async fn close_claims_one_pending_wait_child_and_joins_before_return() {
        let registry = ProcessRegistry::default();
        let mut command = sleep_command("30");
        let child = registry.spawn(&mut command).expect("spawn pending child");
        let pid = child.id().expect("pending child pid") as libc::pid_t;
        let registration = child.registration;
        let lock_registry = registry.clone();
        let (pending_tx, pending_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waiter_poll = std::thread::spawn(move || {
            let mut state = lock_registry.lock();
            assert!(
                state
                    .children
                    .get_mut(&registration)
                    .expect("registered child")
                    .try_wait()
                    .unwrap()
                    .is_none()
            );
            pending_tx.send(()).expect("announce pending poll");
            release_rx.recv().expect("release pending poll");
            drop(state);
        });
        pending_rx.recv().expect("wait poll holds ownership mutex");
        let close_registry = registry.clone();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            attempted_tx.send(()).expect("announce close attempt");
            close_registry.close_and_reap()
        });
        attempted_rx.recv().expect("close attempted ownership");
        release_tx.send(()).expect("release pending poll");
        waiter_poll.join().expect("pending poll thread");
        let report = closer.join().expect("close thread");
        assert_eq!(report.claimed, 1);
        assert_eq!(report.reaped, 1);
        assert_eq!(report.unknown, 0);
        drop(child);
        // SAFETY: signal 0 observes only whether the exact just-joined child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[tokio::test]
    async fn timeout_fallback_and_owner_close_have_exactly_one_child_claimant() {
        let registry = ProcessRegistry::default();
        let mut command = sleep_command("30");
        let mut child = registry.spawn(&mut command).expect("spawn raced child");
        let barrier = Arc::new(Barrier::new(3));
        let ticket_barrier = barrier.clone();
        let ticket = std::thread::spawn(move || {
            ticket_barrier.wait();
            child.reap_sync()
        });
        let close_registry = registry.clone();
        let close_barrier = barrier.clone();
        let closer = std::thread::spawn(move || {
            close_barrier.wait();
            close_registry.close_and_reap()
        });
        barrier.wait();
        let ticket_claimed = usize::from(matches!(
            ticket.join().expect("ticket reaper"),
            ReapOutcome::Reaped | ReapOutcome::OutcomeUnknown
        ));
        let close_claimed = closer.join().expect("owner close");
        assert_eq!(ticket_claimed + close_claimed.claimed, 1);
    }

    #[tokio::test]
    async fn stale_ticket_with_reused_diagnostic_pid_cannot_touch_new_registration() {
        let registry = ProcessRegistry::default();
        let mut first_command = tokio::process::Command::new("/bin/sh");
        first_command
            .args(["-c", "exit 0"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut first = registry
            .spawn(&mut first_command)
            .expect("spawn first registration");
        let stale_registration = first.registration;
        first.wait().await.expect("reap first registration");

        let mut second_command = sleep_command("30");
        let mut second = registry
            .spawn(&mut second_command)
            .expect("spawn second registration");
        assert_ne!(stale_registration, second.registration);
        let mut stale_ticket = RegisteredChild {
            registry: registry.clone(),
            registration: stale_registration,
            // Deliberately give the stale ticket the live child's diagnostic pid. Cleanup must
            // ignore it and authorize solely by the opaque, non-reused registration.
            pid: second.pid,
            active: true,
        };
        assert_eq!(stale_ticket.reap_sync(), ReapOutcome::AlreadySettled);
        assert!(registry.lock().children.contains_key(&second.registration));
        assert_eq!(second.reap_sync(), ReapOutcome::Reaped);
    }

    #[test]
    fn bounded_reap_poll_stops_after_the_exact_pending_budget() {
        let mut polls = 0usize;
        let mut pauses = 0usize;
        let outcome = bounded_reap_poll(
            || {
                polls += 1;
                Ok(false)
            },
            || pauses += 1,
        );
        assert_eq!(outcome, ReapOutcome::OutcomeUnknown);
        assert_eq!(polls, SYNC_REAP_POLLS);
        assert_eq!(pauses, SYNC_REAP_POLLS - 1);
    }

    #[test]
    fn bounded_reap_poll_does_not_retry_a_persistent_error() {
        let mut polls = 0usize;
        let outcome = bounded_reap_poll(
            || {
                polls += 1;
                Err(io::Error::other("persistent wait failure"))
            },
            || panic!("persistent errors have no retry sleep"),
        );
        assert_eq!(outcome, ReapOutcome::OutcomeUnknown);
        assert_eq!(polls, 1);
    }

    #[test]
    fn close_barrier_is_finite_and_truthful_for_a_stalled_concurrent_claimant() {
        let registry = ProcessRegistry::default();
        registry.lock().active_reaps = 1;
        let started = Instant::now();
        let report = registry.close_and_reap();
        assert_eq!(report.claimed, 0);
        assert_eq!(report.reaped, 0);
        assert_eq!(report.unknown, 1);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the condition-variable join barrier has a fixed deadline"
        );
    }
}
